//! Static ZIP reader (§6.2, #86): decodes members from in-memory bytes and
//! never writes them to disk. It reads both views a tool might use, the
//! central directory and a walk of local headers from the first one, and
//! decodes each distinct interpretation once, so a zip that tools read
//! differently cannot hide a member behind the view we did not read
//! (§11.8). Stored, deflate and bzip2 are decoded; anything else is a gap.
//!
//! Every gap (encryption, an unsupported method, a limit, damage, a
//! disagreement between views) is reported; none of them is a finding.
//! Hand-written per §3: every offset is bounds-checked and nothing panics.

use std::collections::{HashMap, HashSet};
use std::fmt;

use crate::budget::ShareBudget;
use crate::decode::DecodeError;
use crate::{bzip2, inflate};

const LOCAL_SIG: &[u8] = b"PK\x03\x04";
const CENTRAL_SIG: &[u8] = b"PK\x01\x02";
const END_SIG: &[u8] = b"PK\x05\x06";
const END64_SIG: &[u8] = b"PK\x06\x06";
const LOCATOR_SIG: &[u8] = b"PK\x06\x07";
const DESCRIPTOR_SIG: &[u8] = b"PK\x07\x08";

const LOCAL_LEN: usize = 30;
const CENTRAL_LEN: usize = 46;
const END_LEN: usize = 22;
const LOCATOR_LEN: usize = 20;
const END64_LEN: usize = 56;

/// How far back from the end an end-of-central-directory record can start:
/// the record plus the longest archive comment.
pub const END_SEARCH_LEN: usize = END_LEN + 0xFFFF;

const FLAG_ENCRYPTED: u16 = 1;
const FLAG_DESCRIPTOR: u16 = 1 << 3;
const FLAG_STRONG_ENCRYPTION: u16 = 1 << 6;
/// Flag bits that change how a member's data is read.
const COMPARED_FLAGS: u16 = FLAG_ENCRYPTED | FLAG_DESCRIPTOR | FLAG_STRONG_ENCRYPTION;

const STORED: u16 = 0;
const DEFLATE: u16 = 8;
const BZIP2: u16 = 12;
/// WinZip AES: the real method is inside an extra field.
const AES: u16 = 99;

const ZIP64_EXTRA: u16 = 0x0001;
const U32_MAX: u64 = 0xFFFF_FFFF;

/// Budget charged for each member started, decoded or not.
const ENTRY_COST: usize = 1024;

/// Gaps kept in [`ZipRead::gaps`]; the rest are only counted (§11.12).
const MAX_GAPS: usize = 64;
/// Characters of a member name shown; longer names keep both ends.
const MAX_NAME_CHARS: usize = 256;

/// Ceilings for one [`read`] (§6.2). Hitting any of them is a gap, never a
/// finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ZipLimits {
    /// Headers parsed across both views and every nested zip.
    pub max_entries: usize,
    /// Zip levels read, the outer one included (§6.2's recursion depth).
    pub max_depth: usize,
    /// Decoded bytes kept of one member.
    pub max_member_bytes: usize,
    /// Compressed input plus decoded output plus decode work across the
    /// whole read, nested zips included.
    pub max_read_back_bytes: usize,
    /// Decoded bytes per compressed byte of one member (§6.2's 300:1).
    pub max_ratio: usize,
}

impl Default for ZipLimits {
    fn default() -> Self {
        ZipLimits {
            max_entries: 10_000,
            max_depth: 4,
            max_member_bytes: crate::context::MAX_CONTENT_BYTES,
            max_read_back_bytes: 256 * 1024 * 1024,
            max_ratio: 300,
        }
    }
}

/// A §6.2 extraction limit that stopped part of the read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Limit {
    Entries,
    Depth,
    MemberSize,
    Ratio,
    Budget,
}

/// Damage that kept a member, or a view, from being read in full.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Damage {
    NoEndRecord,
    NoCentralDirectory,
    CentralDirectoryShort,
    LocalHeaderMissing,
    CutShort,
    Undecodable,
    CrcMismatch,
}

/// A place where tools may read the zip differently.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Disagreement {
    /// A central-directory entry and its local header differ.
    Headers,
    /// One member's data runs over another's header.
    Overlap,
    /// The walk could not find where a member ends.
    UnknownSize,
    /// A stream ends before the size the central directory gives it.
    StreamEnd,
}

/// Why part of a zip was not inspected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GapKind {
    Encrypted,
    Method(u16),
    Limit(Limit),
    Damaged(Damage),
    Disagree(Disagreement),
}

impl fmt::Display for GapKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let limit = |what| format!("extraction limit exceeded ({what})");
        let text = match self {
            GapKind::Encrypted => "encrypted member not inspected".to_string(),
            GapKind::Method(m) => format!("compression method {m} not supported"),
            GapKind::Limit(Limit::Entries) => limit("entry count"),
            GapKind::Limit(Limit::Depth) => limit("nesting depth"),
            GapKind::Limit(Limit::MemberSize) => limit("member size"),
            GapKind::Limit(Limit::Ratio) => limit("compression ratio"),
            GapKind::Limit(Limit::Budget) => limit("read budget"),
            GapKind::Damaged(d) => match d {
                Damage::NoEndRecord => "no end of central directory",
                Damage::NoCentralDirectory => "central directory not found",
                Damage::CentralDirectoryShort => "central directory cut short",
                Damage::LocalHeaderMissing => "local header missing",
                Damage::CutShort => "member cut short",
                Damage::Undecodable => "member undecodable",
                Damage::CrcMismatch => "CRC mismatch",
            }
            .to_string(),
            GapKind::Disagree(d) => match d {
                Disagreement::Headers => "central directory and local header disagree",
                Disagreement::Overlap => "entries overlap",
                Disagreement::UnknownSize => "member size unknown to a streaming reader",
                Disagreement::StreamEnd => "stream ends before its recorded size",
            }
            .to_string(),
        };
        f.write_str(&text)
    }
}

/// A gap and the member it is in: `outer.zip!inner` style, or the archive
/// path (empty for the outer zip) when it is about the archive itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Gap {
    pub member: String,
    pub kind: GapKind,
}

/// One decoded member, handed to [`read`]'s visitor.
#[derive(Debug)]
pub struct Member<'a> {
    /// Its name, with any nested zips' names before it joined by `!`.
    pub path: &'a str,
    pub bytes: Vec<u8>,
    /// `bytes` stops short of the whole member.
    pub cut: bool,
}

/// What [`read`] could not inspect, and how many members it visited.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ZipRead {
    /// The first [`MAX_GAPS`] distinct gaps.
    pub gaps: Vec<Gap>,
    /// Distinct gaps past those.
    pub more_gaps: usize,
    pub members: usize,
    /// Budget charged, at most `max_read_back_bytes`.
    pub spent: usize,
}

/// True for ZIP-format bytes: a local header at offset 0, or an end record
/// with entries whose comment ends exactly at the end of `tail`. `head` is
/// the first bytes, `tail` the last [`END_SEARCH_LEN`] (or all) bytes.
pub fn is_zip_format(head: &[u8], tail: &[u8]) -> bool {
    if head.starts_with(LOCAL_SIG) {
        return true;
    }
    if let Some(decided) = decided_by_last_end(tail) {
        return decided;
    }
    end_candidates(tail)
        .find(|&p| comment_end(tail, p) == Some(tail.len()))
        .is_some_and(|p| le_u16(tail, p + 10) != Some(0))
}

/// [`is_zip_format`]'s answer from the last [`END_LEN`] bytes of `tail`
/// alone, when they are an end record with no comment (the nearest one that
/// reaches the end); `None` when the wider search is needed.
pub fn decided_by_last_end(tail: &[u8]) -> Option<bool> {
    let pos = tail.len().checked_sub(END_LEN)?;
    (sig_at(tail, pos, END_SIG) && le_u16(tail, pos + 20) == Some(0))
        .then(|| le_u16(tail, pos + 10) != Some(0))
}

/// Reads every member of the zip in `data` under `limits`, passing each
/// decoded member to `visit`. A nested zip is read in place of being
/// visited (also visited when its zip data does not start at offset 0, or
/// when it is past the depth limit).
pub fn read(data: &[u8], limits: &ZipLimits, visit: &mut dyn FnMut(Member)) -> ZipRead {
    let mut reader = Reader {
        limits: *limits,
        entries: 0,
        gaps: Vec::new(),
        more_gaps: 0,
        seen_gaps: HashSet::new(),
        members: 0,
        visit,
    };
    let mut shares = ShareBudget::new(limits.max_read_back_bytes);
    reader.archive(data, 1, "", &mut shares);
    ZipRead {
        gaps: reader.gaps,
        more_gaps: reader.more_gaps,
        members: reader.members,
        spent: limits.max_read_back_bytes - shares.remaining(),
    }
}

/// Start offsets of `PK\x05\x06` in the last [`END_SEARCH_LEN`] bytes of
/// `data`, nearest the end first.
fn end_candidates(data: &[u8]) -> impl Iterator<Item = usize> + '_ {
    let last = data.len().checked_sub(END_LEN);
    let first = data.len().saturating_sub(END_SEARCH_LEN);
    last.into_iter()
        .flat_map(move |last| (first..=last).rev())
        .filter(move |&p| sig_at(data, p, END_SIG))
}

/// Where the end record at `pos` says its comment ends.
fn comment_end(data: &[u8], pos: usize) -> Option<usize> {
    let len = le_u16(data, pos + 20)?;
    Some(pos + END_LEN + usize::from(len))
}

/// The end record a reader uses: the last one whose comment ends at the end
/// of the data, else the last one at all (Info-ZIP tolerates trailing bytes).
fn find_end(data: &[u8]) -> Option<usize> {
    end_candidates(data)
        .find(|&p| comment_end(data, p) == Some(data.len()))
        .or_else(|| end_candidates(data).next())
}

/// What the end records say about the central directory.
struct End {
    /// Where the central directory says it starts, before any prefix shift.
    stated_start: u64,
    size: u64,
    entries: u64,
    /// Where the central directory actually ends: the (Zip64) end record.
    ends_at: usize,
}

fn end_record(data: &[u8], pos: usize) -> Option<End> {
    let mut end = End {
        entries: u64::from(le_u16(data, pos + 10)?),
        size: u64::from(le_u32(data, pos + 12)?),
        stated_start: u64::from(le_u32(data, pos + 16)?),
        ends_at: pos,
    };
    let Some(locator) = pos.checked_sub(LOCATOR_LEN) else {
        return Some(end);
    };
    if !sig_at(data, locator, LOCATOR_SIG) {
        return Some(end);
    }
    // The Zip64 record: where the locator says, else just before the locator.
    let stated = usize::try_from(le_u64(data, locator + 8)?).ok();
    let before = locator.checked_sub(END64_LEN);
    let at = [stated, before]
        .into_iter()
        .flatten()
        .find(|&p| sig_at(data, p, END64_SIG))?;
    end.entries = le_u64(data, at + 32)?;
    end.size = le_u64(data, at + 40)?;
    end.stated_start = le_u64(data, at + 48)?;
    end.ends_at = at;
    Some(end)
}

/// A local file header.
struct Local<'d> {
    name: &'d [u8],
    flags: u16,
    method: u16,
    crc: u32,
    csize: u64,
    usize: u64,
    /// Offset of the member's data.
    start: usize,
    /// It carries a Zip64 extra field, so a data descriptor has 8-byte sizes.
    zip64: bool,
}

fn local_at(data: &[u8], at: usize) -> Option<Local<'_>> {
    if !sig_at(data, at, LOCAL_SIG) {
        return None;
    }
    let name_len = usize::from(le_u16(data, at + 26)?);
    let extra_len = usize::from(le_u16(data, at + 28)?);
    let name_at = at.checked_add(LOCAL_LEN)?;
    let name = data.get(name_at..name_at.checked_add(name_len)?)?;
    let extra_at = name_at + name_len;
    let extra = data.get(extra_at..extra_at.checked_add(extra_len)?)?;
    let mut csize = u64::from(le_u32(data, at + 18)?);
    let mut usize = u64::from(le_u32(data, at + 22)?);
    let zip64 = extra_field(extra, ZIP64_EXTRA);
    if let Some(field) = zip64 {
        let mut values = Zip64Values(field);
        values.take_if(&mut usize);
        values.take_if(&mut csize);
    }
    Some(Local {
        name,
        flags: le_u16(data, at + 6)?,
        method: le_u16(data, at + 8)?,
        crc: le_u32(data, at + 14)?,
        csize,
        usize,
        start: extra_at + extra_len,
        zip64: zip64.is_some(),
    })
}

/// A central-directory entry.
struct Central {
    name: Vec<u8>,
    flags: u16,
    method: u16,
    crc: u32,
    csize: u64,
    usize: u64,
    header: u64,
    /// Bytes the record takes.
    len: usize,
}

fn central_at(data: &[u8], at: usize) -> Option<Central> {
    if !sig_at(data, at, CENTRAL_SIG) {
        return None;
    }
    let name_len = usize::from(le_u16(data, at + 28)?);
    let extra_len = usize::from(le_u16(data, at + 30)?);
    let comment_len = usize::from(le_u16(data, at + 32)?);
    let name_at = at.checked_add(CENTRAL_LEN)?;
    let name = data.get(name_at..name_at.checked_add(name_len)?)?;
    let extra_at = name_at + name_len;
    let extra = data.get(extra_at..extra_at.checked_add(extra_len)?)?;
    let len = CENTRAL_LEN + name_len + extra_len + comment_len;
    data.get(at..at.checked_add(len)?)?;
    let mut usize = u64::from(le_u32(data, at + 24)?);
    let mut csize = u64::from(le_u32(data, at + 20)?);
    let mut header = u64::from(le_u32(data, at + 42)?);
    if let Some(field) = extra_field(extra, ZIP64_EXTRA) {
        let mut values = Zip64Values(field);
        values.take_if(&mut usize);
        values.take_if(&mut csize);
        values.take_if(&mut header);
    }
    Some(Central {
        name: name.to_vec(),
        flags: le_u16(data, at + 8)?,
        method: le_u16(data, at + 10)?,
        crc: le_u32(data, at + 16)?,
        csize,
        usize,
        header,
        len,
    })
}

/// The data of the first extra field with `id`.
fn extra_field(mut extra: &[u8], id: u16) -> Option<&[u8]> {
    while extra.len() >= 4 {
        let size = usize::from(le_u16(extra, 2)?);
        let body = extra.get(4..4 + size)?;
        if le_u16(extra, 0)? == id {
            return Some(body);
        }
        extra = &extra[4 + size..];
    }
    None
}

/// A Zip64 extra field's values, each present only for a field whose 32-bit
/// value is `0xFFFFFFFF`, in field order.
struct Zip64Values<'d>(&'d [u8]);

impl Zip64Values<'_> {
    fn take_if(&mut self, value: &mut u64) {
        if *value != U32_MAX {
            return;
        }
        if let Some(v) = le_u64(self.0, 0) {
            *value = v;
            self.0 = &self.0[8..];
        }
    }
}

/// How far a member's data runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Extent {
    Known(u64),
    /// A self-terminating stream whose end the decode finds.
    Stream,
}

/// One reading of a member: where its data is and how to decode it.
#[derive(Debug, Clone)]
struct Item {
    name: Vec<u8>,
    /// Other names merged readings of the same bytes carry (§11.8).
    aliases: Vec<Vec<u8>>,
    header: usize,
    start: usize,
    method: u16,
    flags: u16,
    extent: Extent,
    /// The CRC the data must match; `None` for a stream whose descriptor
    /// gives it.
    crc: Option<u32>,
    /// The local header carries Zip64 sizes (descriptor width).
    zip64: bool,
    /// A streaming reader finds this member's end by decoding; check it
    /// matches `extent`.
    verify_end: bool,
}

/// Interpretations with equal keys decode the same bytes the same way.
type Key = (usize, u16, Extent, bool);

impl Item {
    fn encrypted(&self) -> bool {
        self.flags & (FLAG_ENCRYPTED | FLAG_STRONG_ENCRYPTION) != 0 || self.method == AES
    }

    fn key(&self) -> Key {
        (self.start, self.method, self.extent, self.encrypted())
    }

    /// Allowance to read it in full: input plus output at 1:1.
    fn cost(&self, data_len: usize) -> u64 {
        match self.extent {
            Extent::Known(n) => n,
            Extent::Stream => data_len.saturating_sub(self.start) as u64,
        }
        .saturating_mul(2)
    }

    fn from_local(header: usize, local: &Local) -> Self {
        Item {
            name: local.name.to_vec(),
            aliases: Vec::new(),
            header,
            start: local.start,
            method: local.method,
            flags: local.flags,
            extent: Extent::Known(local.csize),
            crc: Some(local.crc),
            zip64: local.zip64,
            verify_end: false,
        }
    }
}

/// Where a local-header walk resumes: at `pos`, past a data descriptor
/// first when `descriptor` is set (its value: Zip64 sizes).
#[derive(Debug, Clone, Copy)]
struct Walk {
    pos: usize,
    descriptor: Option<bool>,
}

fn decodable(method: u16) -> bool {
    matches!(method, STORED | DEFLATE | BZIP2)
}

struct Reader<'v> {
    limits: ZipLimits,
    entries: usize,
    gaps: Vec<Gap>,
    more_gaps: usize,
    /// (member, kind) already reported.
    seen_gaps: HashSet<(String, GapKind)>,
    members: usize,
    visit: &'v mut dyn FnMut(Member),
}

impl Reader<'_> {
    fn gap(&mut self, member: &str, kind: GapKind) {
        if !self.seen_gaps.insert((member.to_string(), kind)) {
            return;
        }
        if self.gaps.len() < MAX_GAPS {
            self.gaps.push(Gap {
                member: member.to_string(),
                kind,
            });
        } else {
            self.more_gaps += 1;
        }
    }

    /// Counts one header; false (and a gap) past `max_entries`.
    fn count_entry(&mut self, archive: &str) -> bool {
        if self.entries >= self.limits.max_entries {
            self.gap(archive, GapKind::Limit(Limit::Entries));
            return false;
        }
        self.entries += 1;
        true
    }

    /// Reads one zip level: both views, then every interpretation, cheapest
    /// first. `prefix` is the nesting path (`""` or `"a.zip!"`).
    fn archive(&mut self, data: &[u8], depth: usize, prefix: &str, shares: &mut ShareBudget) {
        let archive = prefix.strip_suffix('!').unwrap_or(prefix);
        let mut queue = Vec::new();
        // Local-header offset -> the central directory's sizes and CRC.
        let mut by_header: HashMap<usize, Sizes> = HashMap::new();
        match find_end(data) {
            Some(pos) => self.central(data, pos, archive, &mut queue, &mut by_header),
            None => self.gap(archive, GapKind::Damaged(Damage::NoEndRecord)),
        }
        let mut walks: Vec<Walk> = data
            .windows(4)
            .position(|w| w == LOCAL_SIG)
            .map(|pos| Walk {
                pos,
                descriptor: None,
            })
            .into_iter()
            .collect();
        let mut walked = HashSet::new();
        let mut done: HashSet<Key> = HashSet::new();
        let mut spans: Vec<(usize, usize)> = Vec::new();
        loop {
            let mut blocked = Vec::new();
            while let Some(walk) = walks.pop() {
                self.walk(
                    data,
                    walk,
                    archive,
                    &by_header,
                    &mut walked,
                    &mut queue,
                    &mut blocked,
                    shares,
                );
            }
            let round = dedup(std::mem::take(&mut queue), &done);
            let blocked = dedup(blocked, &done);
            if round.is_empty() && blocked.is_empty() {
                break;
            }
            let mut round = round;
            round.sort_by_key(|i| (i.cost(data.len()), i.header, i.method));
            let total = round.len() + blocked.len();
            let streams = blocked.len();
            for (rank, item) in round.into_iter().chain(blocked).enumerate() {
                done.insert(item.key());
                // A stream's end decides what the walk reads next: keep a part back.
                let reserve = usize::from(rank >= total - streams);
                shares.start_share(total - rank + reserve);
                if let Some(next) = self.member(data, &item, depth, prefix, shares, &mut spans) {
                    walks.push(next);
                }
            }
        }
        // The longest reading of each header is the one that can overrun the next.
        spans.sort_unstable_by_key(|&(header, end)| (header, std::cmp::Reverse(end)));
        spans.dedup_by_key(|s| s.0);
        if spans.windows(2).any(|w| w[1].0 < w[0].1) {
            self.gap(archive, GapKind::Disagree(Disagreement::Overlap));
        }
    }

    /// Queues every central-directory entry, from each place the directory
    /// may start: where the end record says, and where it actually is when a
    /// prefix shifted it (as Info-ZIP adjusts).
    fn central(
        &mut self,
        data: &[u8],
        pos: usize,
        archive: &str,
        queue: &mut Vec<Item>,
        by_header: &mut HashMap<usize, Sizes>,
    ) {
        let Some(end) = end_record(data, pos) else {
            self.gap(archive, GapKind::Damaged(Damage::NoCentralDirectory));
            return;
        };
        if end.entries == 0 && end.size == 0 {
            return;
        }
        let stated = usize::try_from(end.stated_start).unwrap_or(usize::MAX);
        let actual = usize::try_from(end.size)
            .ok()
            .and_then(|size| end.ends_at.checked_sub(size));
        let mut starts = Vec::new();
        if let Some(delta) = actual.and_then(|a| a.checked_sub(stated)) {
            starts.push((stated + delta, delta));
        }
        if !matches!(starts.first(), Some(&(_, 0))) {
            starts.push((stated, 0));
        }
        let mut found = false;
        for (start, delta) in starts {
            if !sig_at(data, start, CENTRAL_SIG) {
                continue;
            }
            found = true;
            let mut at = start;
            let mut n = 0u64;
            while n < end.entries {
                let Some(entry) = central_at(data, at) else {
                    self.gap(archive, GapKind::Damaged(Damage::CentralDirectoryShort));
                    break;
                };
                if !self.count_entry(archive) {
                    return;
                }
                at += entry.len;
                n += 1;
                self.central_entry(data, &entry, delta, archive, queue, by_header);
            }
        }
        if !found {
            self.gap(archive, GapKind::Damaged(Damage::NoCentralDirectory));
        }
    }

    /// Queues a central entry, and its local header's own reading when the
    /// two disagree.
    fn central_entry(
        &mut self,
        data: &[u8],
        entry: &Central,
        delta: usize,
        archive: &str,
        queue: &mut Vec<Item>,
        by_header: &mut HashMap<usize, Sizes>,
    ) {
        let label = member_label(archive, &entry.name);
        let local = usize::try_from(entry.header)
            .ok()
            .and_then(|h| h.checked_add(delta))
            .and_then(|h| Some((h, local_at(data, h)?)));
        let Some((header, local)) = local else {
            self.gap(&label, GapKind::Damaged(Damage::LocalHeaderMissing));
            return;
        };
        let sizes = Sizes {
            csize: entry.csize,
            usize: entry.usize,
            crc: entry.crc,
        };
        by_header.entry(header).or_insert(sizes);
        let item = Item {
            name: entry.name.clone(),
            method: entry.method,
            flags: entry.flags,
            extent: Extent::Known(entry.csize),
            crc: Some(entry.crc),
            ..Item::from_local(header, &local)
        };
        enqueue(queue, item, entry.usize);
        let streamed = local.flags & FLAG_DESCRIPTOR != 0;
        let differs = local.name != entry.name.as_slice()
            || local.method != entry.method
            || (local.flags ^ entry.flags) & COMPARED_FLAGS != 0
            || (!streamed
                && (local.crc != entry.crc
                    || local.csize != entry.csize
                    || local.usize != entry.usize));
        if differs {
            self.gap(&label, GapKind::Disagree(Disagreement::Headers));
            let mut own = Item::from_local(header, &local);
            let mut usize = local.usize;
            if streamed {
                own.extent = Extent::Known(entry.csize);
                own.crc = Some(entry.crc);
                usize = entry.usize;
            }
            enqueue(queue, own, usize);
        }
    }

    /// Walks local headers from `walk` as a streaming reader would, queueing
    /// each member. Stops at bytes that are not a local header, at a header
    /// already walked, or at a stream whose end only a decode can find
    /// (pushed to `blocked`).
    #[allow(clippy::too_many_arguments)]
    fn walk(
        &mut self,
        data: &[u8],
        walk: Walk,
        archive: &str,
        by_header: &HashMap<usize, Sizes>,
        walked: &mut HashSet<usize>,
        queue: &mut Vec<Item>,
        blocked: &mut Vec<Item>,
        shares: &mut ShareBudget,
    ) {
        let mut pos = match walk.descriptor {
            Some(zip64) => skip_descriptor(data, walk.pos, zip64),
            None => walk.pos,
        };
        while walked.insert(pos) {
            let Some(local) = local_at(data, pos) else {
                return;
            };
            // A header the central directory names was counted there.
            if !by_header.contains_key(&pos) && !self.count_entry(archive) {
                return;
            }
            let mut item = Item::from_local(pos, &local);
            let streamed = local.flags & FLAG_DESCRIPTOR != 0;
            let mut usize = local.usize;
            let extent = if !streamed {
                Some(local.csize)
            } else if let Some(sizes) = by_header.get(&pos) {
                item.verify_end = matches!(local.method, DEFLATE | BZIP2);
                item.crc = Some(sizes.crc);
                usize = sizes.usize;
                Some(sizes.csize)
            } else if local.method == STORED {
                let limit = shares.remaining();
                let (found, scanned) = find_stored_end(data, local.start, local.zip64, limit);
                shares.charge(scanned);
                let stopped = data.len().saturating_sub(local.start) > limit;
                if found.is_none() && stopped {
                    let label = member_label(archive, local.name);
                    self.gap(&label, GapKind::Limit(Limit::Budget));
                    return;
                }
                found.map(|(n, crc)| {
                    item.crc = Some(crc);
                    usize = n;
                    n
                })
            } else if decodable(local.method) && !item.encrypted() {
                item.extent = Extent::Stream;
                item.crc = None;
                blocked.push(item);
                return;
            } else {
                None
            };
            let Some(n) = extent else {
                let label = member_label(archive, local.name);
                if item.encrypted() {
                    self.gap(&label, GapKind::Encrypted);
                } else if !decodable(local.method) {
                    self.gap(&label, GapKind::Method(local.method));
                }
                self.gap(&label, GapKind::Disagree(Disagreement::UnknownSize));
                return;
            };
            item.extent = Extent::Known(n);
            enqueue(queue, item, usize);
            let Some(end) = usize::try_from(n)
                .ok()
                .and_then(|n| local.start.checked_add(n))
            else {
                return;
            };
            pos = if streamed {
                skip_descriptor(data, end, local.zip64)
            } else {
                end
            };
        }
    }

    /// Decodes one interpretation under the current share and hands it on.
    /// Returns where the walk resumes when decoding found a stream's end.
    fn member(
        &mut self,
        data: &[u8],
        item: &Item,
        depth: usize,
        prefix: &str,
        shares: &mut ShareBudget,
        spans: &mut Vec<(usize, usize)>,
    ) -> Option<Walk> {
        let label = format!("{prefix}{}", display_name(&item.name));
        shares.charge(ENTRY_COST);
        let known = match item.extent {
            Extent::Known(n) => Some(usize::try_from(n).unwrap_or(usize::MAX)),
            Extent::Stream => None,
        };
        if let Some(n) = known {
            spans.push((item.header, item.start.saturating_add(n)));
        }
        if item.encrypted() {
            self.gap(&label, GapKind::Encrypted);
            return None;
        }
        if !decodable(item.method) {
            self.gap(&label, GapKind::Method(item.method));
            return None;
        }
        let avail = data.get(item.start..).unwrap_or_default();
        let want = known.unwrap_or(avail.len());
        let present = &avail[..want.min(avail.len())];
        let missing = want > avail.len();
        let share = shares.entry_remaining() / 2;
        let input = &present[..present.len().min(share)];
        let by_share = input.len() < present.len();
        let block = if item.method == BZIP2 {
            bzip2::block_size(input).unwrap_or(0)
        } else {
            0
        };
        if share == 0 || block > share {
            self.gap(&label, GapKind::Limit(Limit::Budget));
            return None;
        }
        if known.is_some() {
            shares.charge(input.len().max(block));
        }
        let max_paid = shares.entry_remaining();
        let ratio_cap = match known {
            Some(n) => self.limits.max_ratio.saturating_mul(n.max(1)),
            None => usize::MAX,
        };
        let cap = self.limits.max_member_bytes.min(max_paid).min(ratio_cap);
        let mut bytes = Vec::new();
        let (used, work, capped, result) = match item.method {
            STORED => {
                let n = input.len().min(cap);
                bytes.extend_from_slice(&input[..n]);
                let result = if n < input.len() {
                    Err(DecodeError::BudgetExceeded)
                } else {
                    Ok(())
                };
                (n, 0, false, result)
            }
            DEFLATE => {
                let (used, paid, result) =
                    inflate::inflate_metered_to(input, cap, max_paid, &mut |b| {
                        bytes.extend_from_slice(b)
                    });
                (
                    used,
                    paid.work.saturating_sub(paid.output),
                    paid.capped,
                    result,
                )
            }
            _ => {
                let (out, used, result) = bzip2::bzip2_decompress_consumed(input, cap);
                bytes = out;
                (used, 0, false, result)
            }
        };
        if known.is_none() {
            shares.charge(used.max(block));
            spans.push((item.header, item.start.saturating_add(used)));
        }
        shares.charge(bytes.len());
        shares.charge(work);

        let mut cut = true;
        match result {
            Ok(()) if missing => self.gap(&label, GapKind::Damaged(Damage::CutShort)),
            Ok(()) if by_share && item.method == STORED => {
                self.gap(&label, GapKind::Limit(Limit::Budget))
            }
            Ok(()) => cut = false,
            Err(DecodeError::BudgetExceeded) => {
                let limit = if capped || cap == max_paid {
                    Limit::Budget
                } else if cap == self.limits.max_member_bytes {
                    Limit::MemberSize
                } else if cap == ratio_cap {
                    Limit::Ratio
                } else {
                    Limit::Budget
                };
                self.gap(&label, GapKind::Limit(limit));
            }
            Err(DecodeError::Truncated) if by_share => {
                self.gap(&label, GapKind::Limit(Limit::Budget))
            }
            Err(DecodeError::Truncated) => self.gap(&label, GapKind::Damaged(Damage::CutShort)),
            Err(DecodeError::ChecksumMismatch) => {
                self.gap(&label, GapKind::Damaged(Damage::CrcMismatch))
            }
            Err(_) => self.gap(&label, GapKind::Damaged(Damage::Undecodable)),
        }

        let end = item.start.saturating_add(used);
        let mut resume = None;
        if !cut {
            let crc = match known {
                Some(_) => item.crc,
                None => descriptor_crc(data, end),
            };
            if crc.is_some_and(|crc| inflate::crc32_extend(0, &bytes) != crc) {
                self.gap(&label, GapKind::Damaged(Damage::CrcMismatch));
            }
            // A known extent may overstate the input the decoder consumed.
            if bytes.len() > self.limits.max_ratio.saturating_mul(used.max(1)) {
                self.gap(&label, GapKind::Limit(Limit::Ratio));
            }
            let ends_early = item.verify_end && known.is_some_and(|n| n != used);
            if ends_early {
                self.gap(&label, GapKind::Disagree(Disagreement::StreamEnd));
            }
            if known.is_none() || ends_early {
                resume = Some(Walk {
                    pos: end,
                    descriptor: Some(item.zip64),
                });
            }
        }
        if !bytes.is_empty() {
            let aliases: Vec<String> = item
                .aliases
                .iter()
                .map(|name| format!("{prefix}{}", display_name(name)))
                .collect();
            self.deliver(&label, &aliases, bytes, cut, depth, shares);
        }
        resume
    }

    /// Visits a decoded member under `label` and each alias, or reads it as a
    /// nested zip once, under `label`. Each alias visit is charged
    /// [`ENTRY_COST`] plus its bytes against the entry's share.
    fn deliver(
        &mut self,
        label: &str,
        aliases: &[String],
        mut bytes: Vec<u8>,
        cut: bool,
        depth: usize,
        shares: &mut ShareBudget,
    ) {
        let tail = &bytes[bytes.len().saturating_sub(END_SEARCH_LEN)..];
        let nested = is_zip_format(&bytes, tail);
        let past_depth = nested && depth >= self.limits.max_depth;
        if past_depth {
            self.gap(label, GapKind::Limit(Limit::Depth));
        }
        let at_start = bytes.starts_with(LOCAL_SIG) || bytes.starts_with(END_SIG);
        let read_nested = nested && !past_depth;
        if !read_nested || !at_start {
            let cost = ENTRY_COST.saturating_add(bytes.len());
            let mut names = std::iter::once(label)
                .chain(aliases.iter().map(String::as_str))
                .peekable();
            let mut first = true;
            while let Some(name) = names.next() {
                if !std::mem::take(&mut first) {
                    if shares.entry_remaining() < cost {
                        self.gap(name, GapKind::Limit(Limit::Budget));
                        continue;
                    }
                    shares.charge(cost);
                }
                // No later visit fits once one alias does not: costs are equal.
                let last = names.peek().is_none() || shares.entry_remaining() < cost;
                // Only a prefixed nested zip is both visited and read.
                let bytes = if last && !read_nested {
                    std::mem::take(&mut bytes)
                } else {
                    bytes.clone()
                };
                self.members += 1;
                (self.visit)(Member {
                    path: name,
                    bytes,
                    cut,
                });
            }
        }
        if read_nested {
            let mut inner = ShareBudget::new(shares.entry_remaining());
            let before = inner.remaining();
            self.archive(&bytes, depth + 1, &format!("{label}!"), &mut inner);
            shares.charge(before - inner.remaining());
        }
    }
}

/// A member's sizes and CRC as the central directory records them.
#[derive(Debug, Clone, Copy)]
struct Sizes {
    csize: u64,
    usize: u64,
    crc: u32,
}

/// Queues `item`, and for a stored member whose uncompressed size `usize`
/// differs from its extent also the reading of that many bytes (ditto's).
fn enqueue(queue: &mut Vec<Item>, item: Item, usize: u64) {
    let alternative = match item.extent {
        Extent::Known(n) if item.method == STORED && n != usize => Some(Item {
            extent: Extent::Known(usize),
            ..item.clone()
        }),
        _ => None,
    };
    queue.push(item);
    queue.extend(alternative);
}

/// `items` without those already decoded, one per key; a merged item keeps
/// every name that displays differently and checks its stream end if any
/// copy does.
fn dedup(items: Vec<Item>, done: &HashSet<Key>) -> Vec<Item> {
    let mut index: HashMap<Key, usize> = HashMap::new();
    let mut out: Vec<Item> = Vec::new();
    let mut shown: Vec<HashSet<String>> = Vec::new();
    for item in items {
        let key = item.key();
        if done.contains(&key) {
            continue;
        }
        match index.get(&key) {
            Some(&i) => {
                let kept = &mut out[i];
                kept.verify_end |= item.verify_end;
                if shown[i].insert(display_name(&item.name)) {
                    kept.aliases.push(item.name);
                }
            }
            None => {
                index.insert(key, out.len());
                shown.push(HashSet::from([display_name(&item.name)]));
                out.push(item);
            }
        }
    }
    out
}

/// Where the next header is after a data descriptor at `at`: signature
/// optional, sizes 4 or 8 bytes. Prefers the width `zip64` gives, unless
/// only the other lands on a header.
fn skip_descriptor(data: &[u8], at: usize, zip64: bool) -> usize {
    let base = if sig_at(data, at, DESCRIPTOR_SIG) {
        at.saturating_add(4)
    } else {
        at
    };
    let after = |wide: bool| base.saturating_add(if wide { 20 } else { 12 });
    let is_header = |p: usize| sig_at(data, p, LOCAL_SIG) || sig_at(data, p, CENTRAL_SIG);
    if !is_header(after(zip64)) && is_header(after(!zip64)) {
        after(!zip64)
    } else {
        after(zip64)
    }
}

/// The CRC in a data descriptor at `at`, signature optional.
fn descriptor_crc(data: &[u8], at: usize) -> Option<u32> {
    if sig_at(data, at, DESCRIPTOR_SIG) {
        le_u32(data, at.checked_add(4)?)
    } else {
        le_u32(data, at)
    }
}

/// A stored member with a data descriptor and no central entry: the first
/// signed descriptor whose compressed size is its distance from `start`,
/// as a streaming reader finds it. Returns that size and the CRC, and the
/// bytes searched, at most `limit`.
fn find_stored_end(
    data: &[u8],
    start: usize,
    zip64: bool,
    limit: usize,
) -> (Option<(u64, u32)>, usize) {
    let Some(rest) = data.get(start..) else {
        return (None, 0);
    };
    let rest = &rest[..rest.len().min(limit)];
    let found = rest
        .windows(4)
        .enumerate()
        .filter(|(_, w)| *w == DESCRIPTOR_SIG)
        .find_map(|(n, _)| {
            let at = start + n;
            let size = if zip64 {
                le_u64(data, at + 8)?
            } else {
                u64::from(le_u32(data, at + 8)?)
            };
            (size == n as u64).then(|| (n, size, le_u32(data, at + 4).unwrap_or(0)))
        });
    match found {
        Some((n, size, crc)) => (Some((size, crc)), n + 4),
        None => (None, rest.len()),
    }
}

fn member_label(archive: &str, name: &[u8]) -> String {
    if archive.is_empty() {
        display_name(name)
    } else {
        format!("{archive}!{}", display_name(name))
    }
}

/// A member name for display: lossy UTF-8, control characters replaced, so
/// a name cannot forge report lines. Over [`MAX_NAME_CHARS`], the middle is
/// replaced by `…`, keeping the extension.
fn display_name(name: &[u8]) -> String {
    fn clean(s: &str) -> impl Iterator<Item = char> + '_ {
        s.chars().map(|c| if c.is_control() { '?' } else { c })
    }
    let text = String::from_utf8_lossy(name);
    let count = text.chars().count();
    if count <= MAX_NAME_CHARS {
        return clean(&text).collect();
    }
    let half = MAX_NAME_CHARS / 2;
    let at = |n: usize| text.char_indices().nth(n).map_or(text.len(), |(i, _)| i);
    clean(&text[..at(half)])
        .chain(['…'])
        .chain(clean(&text[at(count - half)..]))
        .collect()
}

fn sig_at(data: &[u8], at: usize, sig: &[u8]) -> bool {
    at.checked_add(sig.len())
        .and_then(|end| data.get(at..end))
        .is_some_and(|b| b == sig)
}

fn le_u16(d: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(
        d.get(at..at.checked_add(2)?)?.try_into().ok()?,
    ))
}

fn le_u32(d: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        d.get(at..at.checked_add(4)?)?.try_into().ok()?,
    ))
}

fn le_u64(d: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_le_bytes(
        d.get(at..at.checked_add(8)?)?.try_into().ok()?,
    ))
}

#[cfg(test)]
pub(crate) mod tests_support {
    //! Hand-built zips for tests: each field of both views is settable.

    use super::{CENTRAL_SIG, DESCRIPTOR_SIG, END64_SIG, END_SIG, LOCAL_SIG, LOCATOR_SIG};

    pub(crate) fn crc(data: &[u8]) -> u32 {
        crate::inflate::crc32_extend(0, data)
    }

    /// DEFLATE made of stored blocks.
    pub(crate) fn deflate_stored(data: &[u8]) -> Vec<u8> {
        let chunks: Vec<&[u8]> = if data.is_empty() {
            vec![&[]]
        } else {
            data.chunks(0xFFFF).collect()
        };
        let mut out = Vec::new();
        for (i, chunk) in chunks.iter().enumerate() {
            out.push(u8::from(i + 1 == chunks.len()));
            let len = chunk.len() as u16;
            out.extend(len.to_le_bytes());
            out.extend((!len).to_le_bytes());
            out.extend_from_slice(chunk);
        }
        out
    }

    /// LSB-first bit packing for DEFLATE.
    struct Bits {
        out: Vec<u8>,
        acc: u64,
        n: u32,
    }

    impl Bits {
        fn put(&mut self, value: u32, len: u32) {
            self.acc |= u64::from(value) << self.n;
            self.n += len;
            while self.n >= 8 {
                self.out.push(self.acc as u8);
                self.acc >>= 8;
                self.n -= 8;
            }
        }

        /// A Huffman code, most significant bit first.
        fn code(&mut self, code: u32, len: u32) {
            let reversed = code.reverse_bits() >> (32 - len);
            self.put(reversed, len);
        }

        fn finish(mut self) -> Vec<u8> {
            if self.n > 0 {
                self.out.push(self.acc as u8);
            }
            self.out
        }
    }

    /// Fixed-Huffman DEFLATE of `n` copies of `byte`: one literal, then
    /// 258-byte matches at distance 1 (about 160:1).
    pub(crate) fn deflate_run(byte: u8, n: usize) -> Vec<u8> {
        let mut bits = Bits {
            out: Vec::new(),
            acc: 0,
            n: 0,
        };
        bits.put(1, 1);
        bits.put(1, 2);
        let literal = |bits: &mut Bits, b: u8| {
            if b < 144 {
                bits.code(0x30 + u32::from(b), 8);
            } else {
                bits.code(0x190 + u32::from(b - 144), 9);
            }
        };
        if n > 0 {
            literal(&mut bits, byte);
            let rest = n - 1;
            for _ in 0..rest / 258 {
                bits.code(0xC0 + 5, 8); // length 258 (symbol 285)
                bits.code(0, 5); // distance 1
            }
            for _ in 0..rest % 258 {
                literal(&mut bits, byte);
            }
        }
        bits.code(0, 7); // end of block
        bits.finish()
    }

    /// One member as each view records it.
    #[derive(Clone, Debug)]
    pub(crate) struct Spec {
        pub name: Vec<u8>,
        pub method: u16,
        pub flags: u16,
        pub crc: u32,
        pub csize: u64,
        pub usize: u64,
        pub local_name: Vec<u8>,
        pub local_method: u16,
        pub local_flags: u16,
        pub local_crc: u32,
        pub local_csize: u64,
        pub local_usize: u64,
        /// The data as stored.
        pub payload: Vec<u8>,
        /// Write a signed data descriptor after the payload.
        pub descriptor: bool,
        /// Leave it out of the central directory.
        pub hidden: bool,
        /// Bytes written before its local header.
        pub gap_before: Vec<u8>,
    }

    impl Spec {
        fn new(name: &str, method: u16, payload: Vec<u8>, plain: &[u8]) -> Self {
            let crc = crc(plain);
            let (csize, usize) = (payload.len() as u64, plain.len() as u64);
            Spec {
                name: name.as_bytes().to_vec(),
                method,
                flags: 0,
                crc,
                csize,
                usize,
                local_name: name.as_bytes().to_vec(),
                local_method: method,
                local_flags: 0,
                local_crc: crc,
                local_csize: csize,
                local_usize: usize,
                payload,
                descriptor: false,
                hidden: false,
                gap_before: Vec::new(),
            }
        }

        pub(crate) fn stored(name: &str, data: &[u8]) -> Self {
            Spec::new(name, 0, data.to_vec(), data)
        }

        pub(crate) fn deflated(name: &str, data: &[u8]) -> Self {
            Spec::new(name, 8, deflate_stored(data), data)
        }

        /// Streamed: bit 3 in both views, zero CRC and sizes in the local
        /// header, a signed descriptor after the data.
        pub(crate) fn streamed(mut self) -> Self {
            self.flags |= 8;
            self.local_flags |= 8;
            self.local_crc = 0;
            self.local_csize = 0;
            self.local_usize = 0;
            self.descriptor = true;
            self
        }
    }

    /// How the archive around the members is written.
    #[derive(Clone, Debug, Default)]
    pub(crate) struct Layout {
        /// Bytes before the zip; offsets are not adjusted for them.
        pub prefix: Vec<u8>,
        pub comment: Vec<u8>,
        /// Sizes and offsets in Zip64 extra fields, with Zip64 end records.
        pub zip64: bool,
        /// Leave out the central directory and end record.
        pub no_end: bool,
    }

    fn u16le(v: u64) -> [u8; 2] {
        (v as u16).to_le_bytes()
    }

    fn u32le(v: u64) -> [u8; 4] {
        (v as u32).to_le_bytes()
    }

    /// The zip `specs` describe.
    pub(crate) fn build(specs: &[Spec], layout: &Layout) -> Vec<u8> {
        let mut body = Vec::new();
        let mut offsets = Vec::new();
        for s in specs {
            body.extend_from_slice(&s.gap_before);
            offsets.push(body.len() as u64);
            let big = |v: u64| if layout.zip64 { 0xFFFF_FFFF } else { v };
            let mut extra = Vec::new();
            if layout.zip64 {
                extra.extend(1u16.to_le_bytes());
                extra.extend(16u16.to_le_bytes());
                extra.extend(s.local_usize.to_le_bytes());
                extra.extend(s.local_csize.to_le_bytes());
            }
            body.extend_from_slice(LOCAL_SIG);
            body.extend(u16le(45));
            body.extend(u16le(u64::from(s.local_flags)));
            body.extend(u16le(u64::from(s.local_method)));
            body.extend([0; 4]);
            body.extend(u32le(u64::from(s.local_crc)));
            body.extend(u32le(big(s.local_csize)));
            body.extend(u32le(big(s.local_usize)));
            body.extend(u16le(s.local_name.len() as u64));
            body.extend(u16le(extra.len() as u64));
            body.extend_from_slice(&s.local_name);
            body.extend(extra);
            body.extend_from_slice(&s.payload);
            if s.descriptor {
                body.extend_from_slice(DESCRIPTOR_SIG);
                body.extend(u32le(u64::from(s.crc)));
                if layout.zip64 {
                    body.extend(s.csize.to_le_bytes());
                    body.extend(s.usize.to_le_bytes());
                } else {
                    body.extend(u32le(s.csize));
                    body.extend(u32le(s.usize));
                }
            }
        }
        if layout.no_end {
            return [layout.prefix.clone(), body].concat();
        }
        let cd_start = body.len() as u64;
        let mut count = 0u64;
        for (s, &offset) in specs.iter().zip(&offsets) {
            if s.hidden {
                continue;
            }
            count += 1;
            let big = |v: u64| if layout.zip64 { 0xFFFF_FFFF } else { v };
            let mut extra = Vec::new();
            if layout.zip64 {
                extra.extend(1u16.to_le_bytes());
                extra.extend(24u16.to_le_bytes());
                extra.extend(s.usize.to_le_bytes());
                extra.extend(s.csize.to_le_bytes());
                extra.extend(offset.to_le_bytes());
            }
            body.extend_from_slice(CENTRAL_SIG);
            body.extend(u16le(0x031E));
            body.extend(u16le(45));
            body.extend(u16le(u64::from(s.flags)));
            body.extend(u16le(u64::from(s.method)));
            body.extend([0; 4]);
            body.extend(u32le(u64::from(s.crc)));
            body.extend(u32le(big(s.csize)));
            body.extend(u32le(big(s.usize)));
            body.extend(u16le(s.name.len() as u64));
            body.extend(u16le(extra.len() as u64));
            body.extend([0; 6]);
            body.extend(u32le(0o100644 << 16));
            body.extend(u32le(big(offset)));
            body.extend_from_slice(&s.name);
            body.extend(extra);
        }
        let cd_size = body.len() as u64 - cd_start;
        if layout.zip64 {
            let at = body.len() as u64;
            body.extend_from_slice(END64_SIG);
            body.extend(44u64.to_le_bytes());
            body.extend(u16le(45));
            body.extend(u16le(45));
            body.extend([0; 8]);
            body.extend(count.to_le_bytes());
            body.extend(count.to_le_bytes());
            body.extend(cd_size.to_le_bytes());
            body.extend(cd_start.to_le_bytes());
            body.extend_from_slice(LOCATOR_SIG);
            body.extend([0; 4]);
            body.extend(at.to_le_bytes());
            body.extend(1u32.to_le_bytes());
        }
        let small = |v: u64, max: u64| if layout.zip64 { max } else { v };
        body.extend_from_slice(END_SIG);
        body.extend([0; 4]);
        body.extend(u16le(small(count, 0xFFFF)));
        body.extend(u16le(small(count, 0xFFFF)));
        body.extend(u32le(small(cd_size, 0xFFFF_FFFF)));
        body.extend(u32le(small(cd_start, 0xFFFF_FFFF)));
        body.extend(u16le(layout.comment.len() as u64));
        body.extend_from_slice(&layout.comment);
        [layout.prefix.clone(), body].concat()
    }

    pub(crate) fn plain(specs: &[Spec]) -> Vec<u8> {
        build(specs, &Layout::default())
    }
}

#[cfg(test)]
mod tests {
    use super::tests_support::*;
    use super::*;

    /// Visited members as (path, bytes, cut).
    type Seen = Vec<(String, Vec<u8>, bool)>;

    fn read_with(data: &[u8], limits: &ZipLimits) -> (Seen, ZipRead) {
        let mut seen = Vec::new();
        let result = read(data, limits, &mut |m: Member| {
            seen.push((m.path.to_string(), m.bytes, m.cut))
        });
        assert_eq!(result.members, seen.len());
        (seen, result)
    }

    fn read_all(data: &[u8]) -> (Seen, ZipRead) {
        read_with(data, &ZipLimits::default())
    }

    fn kinds(r: &ZipRead) -> Vec<GapKind> {
        r.gaps.iter().map(|g| g.kind).collect()
    }

    fn has_bytes(seen: &Seen, bytes: &[u8]) -> bool {
        seen.iter().any(|(_, b, _)| b == bytes)
    }

    fn is_zip(data: &[u8]) -> bool {
        let tail = &data[data.len().saturating_sub(END_SEARCH_LEN)..];
        is_zip_format(data, tail)
    }

    #[test]
    fn stored_and_deflated_members_are_read_once_with_no_gaps() {
        let zip = plain(&[
            Spec::stored("a.txt", b"alpha"),
            Spec::deflated("b.txt", b"bravo bravo"),
        ]);
        let (seen, r) = read_all(&zip);
        assert!(r.gaps.is_empty(), "{:?}", r.gaps);
        assert_eq!(
            seen,
            vec![
                ("a.txt".to_string(), b"alpha".to_vec(), false),
                ("b.txt".to_string(), b"bravo bravo".to_vec(), false),
            ]
        );
    }

    #[test]
    fn bzip2_member_is_decoded() {
        let packed = include_bytes!("../testdata/bzip2/all_bytes.in");
        let plain_bytes = include_bytes!("../testdata/bzip2/all_bytes.out");
        let mut spec = Spec::stored("b.bin", plain_bytes);
        spec.method = BZIP2;
        spec.local_method = BZIP2;
        spec.payload = packed.to_vec();
        spec.csize = packed.len() as u64;
        spec.local_csize = spec.csize;
        let (seen, r) = read_all(&plain(&[spec]));
        assert!(r.gaps.is_empty(), "{:?}", r.gaps);
        assert_eq!(seen[0].1, plain_bytes);
    }

    #[test]
    fn empty_members_and_archives_are_clean() {
        let (seen, r) = read_all(&plain(&[Spec::stored("dir/", b"")]));
        assert!(seen.is_empty() && r.gaps.is_empty(), "{:?}", r.gaps);
        let (seen, r) = read_all(&plain(&[]));
        assert!(seen.is_empty() && r.gaps.is_empty(), "{:?}", r.gaps);
    }

    #[test]
    fn a_prefix_shifts_offsets_as_info_zip_reads_them() {
        let specs = [Spec::stored("a", b"one"), Spec::deflated("b", b"two")];
        for comment in [&b""[..], b"a comment"] {
            let zip = build(
                &specs,
                &Layout {
                    prefix: b"#!/bin/sh\nexit 0\n".repeat(10),
                    comment: comment.to_vec(),
                    ..Layout::default()
                },
            );
            let (seen, r) = read_all(&zip);
            assert!(r.gaps.is_empty(), "{:?}", r.gaps);
            assert_eq!(seen.len(), 2);
            assert!(is_zip(&zip), "prefix and comment {comment:?}");
        }
    }

    #[test]
    fn detection_needs_a_header_at_zero_or_an_end_record_at_the_end() {
        let zip = plain(&[Spec::stored("a", b"x")]);
        assert!(is_zip(&zip));
        let mut prefixed = vec![0u8; 64];
        prefixed.extend(&zip);
        assert!(is_zip(&prefixed));
        let mut junk_after = prefixed.clone();
        junk_after.push(0);
        assert!(!is_zip(&junk_after));
        let mut empty = vec![0u8; 64];
        empty.extend(plain(&[]));
        assert!(!is_zip(&empty));
        assert!(!is_zip(b""));
        assert!(!is_zip(&crate::test_support::xorshift_bytes(70_000)));
        // A comment longer than the search window cannot be found.
        let mut far = END_SIG.to_vec();
        far.extend([0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF]);
        far.extend(vec![0u8; 0xFFFF]);
        assert!(is_zip(&far));
        far.push(0);
        let tail = &far[far.len() - END_SEARCH_LEN..];
        assert!(!is_zip_format(b"", tail));
    }

    #[test]
    fn zip64_records_and_extra_fields_are_read() {
        let zip = build(
            &[
                Spec::stored("a", b"sixty-four"),
                Spec::deflated("b", b"bits"),
            ],
            &Layout {
                zip64: true,
                prefix: vec![7; 33],
                ..Layout::default()
            },
        );
        let (seen, r) = read_all(&zip);
        assert!(r.gaps.is_empty(), "{:?}", r.gaps);
        assert_eq!(seen.len(), 2);
        assert!(has_bytes(&seen, b"sixty-four") && has_bytes(&seen, b"bits"));
    }

    #[test]
    fn streamed_members_are_read_once_with_or_without_a_directory() {
        let specs = [
            Spec::deflated("a", b"first").streamed(),
            Spec::deflated("b", b"second").streamed(),
        ];
        let (seen, r) = read_all(&plain(&specs));
        assert!(r.gaps.is_empty(), "{:?}", r.gaps);
        assert_eq!(seen.len(), 2);
        let streaming = build(
            &specs,
            &Layout {
                no_end: true,
                ..Layout::default()
            },
        );
        let (seen, r) = read_all(&streaming);
        assert_eq!(kinds(&r), vec![GapKind::Damaged(Damage::NoEndRecord)]);
        assert!(has_bytes(&seen, b"first") && has_bytes(&seen, b"second"));
    }

    #[test]
    fn stored_streamed_member_is_sized_by_its_descriptor() {
        let specs = [
            Spec::stored("a", b"stored and streamed").streamed(),
            Spec::stored("b", b"next"),
        ];
        let layout = Layout {
            no_end: true,
            ..Layout::default()
        };
        let (seen, r) = read_all(&build(&specs, &layout));
        assert_eq!(kinds(&r), vec![GapKind::Damaged(Damage::NoEndRecord)]);
        assert!(has_bytes(&seen, b"stored and streamed") && has_bytes(&seen, b"next"));

        let mut no_size = specs[0].clone();
        no_size.descriptor = false;
        let (_, r) = read_all(&build(&[no_size], &layout));
        assert!(kinds(&r).contains(&GapKind::Disagree(Disagreement::UnknownSize)));
    }

    #[test]
    fn a_name_disagreement_is_partial_and_seen_under_both_names() {
        let mut spec = Spec::stored("shown.txt", b"payload");
        spec.local_name = b"hidden.sh".to_vec();
        let (seen, r) = read_all(&plain(&[spec]));
        assert_eq!(kinds(&r), vec![GapKind::Disagree(Disagreement::Headers)]);
        let names: Vec<(&str, &[u8])> = seen.iter().map(|s| (s.0.as_str(), &s.1[..])).collect();
        assert_eq!(
            names,
            [
                ("shown.txt", &b"payload"[..]),
                ("hidden.sh", &b"payload"[..])
            ]
        );
    }

    #[test]
    fn names_that_display_alike_are_visited_once() {
        let mut spec = Spec::stored("a\x01", b"payload");
        spec.local_name = b"a\x02".to_vec();
        let (seen, r) = read_all(&plain(&[spec]));
        assert_eq!(kinds(&r), vec![GapKind::Disagree(Disagreement::Headers)]);
        assert_eq!(seen, vec![("a?".to_string(), b"payload".to_vec(), false)]);
    }

    #[test]
    fn a_method_disagreement_decodes_both_readings() {
        let mut spec = Spec::deflated("a", b"inflated text");
        spec.local_method = STORED;
        let raw = spec.payload.clone();
        let (seen, r) = read_all(&plain(&[spec]));
        assert!(kinds(&r).contains(&GapKind::Disagree(Disagreement::Headers)));
        assert!(has_bytes(&seen, b"inflated text"));
        assert!(has_bytes(&seen, &raw));
    }

    #[test]
    fn a_size_disagreement_decodes_both_extents() {
        let mut spec = Spec::stored("a", b"short|and the rest");
        spec.csize = 5;
        spec.usize = 5;
        spec.crc = crc(b"short");
        let (seen, r) = read_all(&plain(&[spec]));
        assert!(kinds(&r).contains(&GapKind::Disagree(Disagreement::Headers)));
        assert!(has_bytes(&seen, b"short"));
        assert!(has_bytes(&seen, b"short|and the rest"));
    }

    #[test]
    fn a_member_only_the_walk_reaches_is_read() {
        let mut hidden = Spec::stored("hidden.sh", b"curl x | sh");
        hidden.hidden = true;
        let (seen, r) = read_all(&plain(&[Spec::stored("a", b"a"), hidden]));
        assert!(r.gaps.is_empty(), "{:?}", r.gaps);
        assert!(has_bytes(&seen, b"curl x | sh"));
    }

    #[test]
    fn a_member_only_the_directory_reaches_is_read() {
        let mut after_junk = Spec::stored("b", b"behind junk");
        after_junk.gap_before = b"junk".to_vec();
        let (seen, r) = read_all(&plain(&[Spec::stored("a", b"a"), after_junk]));
        assert!(r.gaps.is_empty(), "{:?}", r.gaps);
        assert!(has_bytes(&seen, b"behind junk"));
    }

    #[test]
    fn a_stream_that_ends_early_resumes_the_walk() {
        // The directory sizes `a` over a hidden member a streaming reader sees.
        let inner = Spec::stored("hidden.sh", b"curl x | sh");
        let mut hidden_bytes = Vec::new();
        hidden_bytes.extend(DESCRIPTOR_SIG);
        hidden_bytes.extend(crc(b"first").to_le_bytes());
        let deflated = deflate_stored(b"first");
        hidden_bytes.extend((deflated.len() as u32).to_le_bytes());
        hidden_bytes.extend(5u32.to_le_bytes());
        hidden_bytes.extend(build(
            &[inner],
            &Layout {
                no_end: true,
                ..Layout::default()
            },
        ));
        let mut a = Spec::deflated("a", b"first").streamed();
        a.payload.extend(&hidden_bytes);
        a.csize = a.payload.len() as u64;
        let (seen, r) = read_all(&plain(&[a, Spec::stored("b", b"b")]));
        assert!(kinds(&r).contains(&GapKind::Disagree(Disagreement::StreamEnd)));
        assert!(has_bytes(&seen, b"first") && has_bytes(&seen, b"b"));
        assert!(has_bytes(&seen, b"curl x | sh"));
    }

    #[test]
    fn overlapping_entries_are_partial() {
        // a's data holds a local header; b's central entry points at it.
        let a_local = 30 + 1;
        let inner = plain(&[Spec::stored("c", b"cc")]);
        let mut zip = plain(&[Spec::stored("a", &inner), Spec::stored("b", b"bbbb")]);
        let end = zip.len() - END_LEN;
        let cd = le_u32(&zip, end + 16).unwrap() as usize;
        let second = cd + 46 + 1;
        assert_eq!(&zip[second..second + 4], CENTRAL_SIG);
        zip[second + 42..second + 46].copy_from_slice(&(a_local as u32).to_le_bytes());
        let (_, r) = read_all(&zip);
        assert!(kinds(&r).contains(&GapKind::Disagree(Disagreement::Overlap)));
    }

    #[test]
    fn a_longer_reading_of_one_header_that_overlaps_is_partial() {
        // The directory sizes `a` to its data; its local header runs into b's.
        let mut a = Spec::stored("a", b"alpha");
        a.local_csize = 15;
        a.local_usize = 15;
        let (_, r) = read_all(&plain(&[a, Spec::stored("b", b"bravo")]));
        assert!(kinds(&r).contains(&GapKind::Disagree(Disagreement::Overlap)));
    }

    #[test]
    fn encrypted_and_unsupported_members_are_gaps() {
        let mut enc = Spec::stored("e", b"secret");
        enc.flags = FLAG_ENCRYPTED;
        enc.local_flags = FLAG_ENCRYPTED;
        let mut aes = Spec::stored("aes", b"secret2");
        aes.method = AES;
        aes.local_method = AES;
        let mut lzma = Spec::stored("l", b"lzma");
        lzma.method = 14;
        lzma.local_method = 14;
        let (seen, r) = read_all(&plain(&[enc, aes, lzma]));
        assert!(seen.is_empty(), "{seen:?}");
        let k = kinds(&r);
        assert!(k.contains(&GapKind::Encrypted));
        assert!(k.contains(&GapKind::Method(14)));
        assert_eq!(
            r.gaps
                .iter()
                .filter(|g| g.kind == GapKind::Encrypted)
                .count(),
            2
        );
    }

    #[test]
    fn a_crc_mismatch_still_scans_the_bytes() {
        let mut spec = Spec::stored("a", b"tampered");
        spec.crc ^= 1;
        spec.local_crc ^= 1;
        let (seen, r) = read_all(&plain(&[spec]));
        assert_eq!(kinds(&r), vec![GapKind::Damaged(Damage::CrcMismatch)]);
        assert_eq!(seen, vec![("a".to_string(), b"tampered".to_vec(), false)]);
    }

    #[test]
    fn a_cut_short_member_is_scanned_as_a_prefix() {
        let zip = build(
            &[Spec::stored("a", b"0123456789")],
            &Layout {
                no_end: true,
                ..Layout::default()
            },
        );
        let (seen, r) = read_all(&zip[..zip.len() - 4]);
        assert!(kinds(&r).contains(&GapKind::Damaged(Damage::CutShort)));
        assert_eq!(seen, vec![("a".to_string(), b"012345".to_vec(), true)]);

        let deflated = build(
            &[Spec::deflated("d", b"0123456789")],
            &Layout {
                no_end: true,
                ..Layout::default()
            },
        );
        let (seen, r) = read_all(&deflated[..deflated.len() - 4]);
        assert!(kinds(&r).contains(&GapKind::Damaged(Damage::CutShort)));
        assert_eq!(seen[0].1, b"012345");
    }

    #[test]
    fn the_entry_limit_halts_the_read() {
        let specs: Vec<Spec> = (0..20)
            .map(|i| Spec::stored(&format!("f{i}"), b"x"))
            .collect();
        let limits = ZipLimits {
            max_entries: 5,
            ..ZipLimits::default()
        };
        let (_, r) = read_with(&plain(&specs), &limits);
        assert!(kinds(&r).contains(&GapKind::Limit(Limit::Entries)));
    }

    #[test]
    fn headers_both_views_reach_count_once() {
        let specs: Vec<Spec> = (0..5)
            .map(|i| Spec::stored(&format!("f{i}"), b"x"))
            .collect();
        let limits = ZipLimits {
            max_entries: 5,
            ..ZipLimits::default()
        };
        let (seen, r) = read_with(&plain(&specs), &limits);
        assert!(r.gaps.is_empty(), "{:?}", r.gaps);
        assert_eq!(seen.len(), 5);
    }

    #[test]
    fn member_size_and_ratio_limits_cut_the_member() {
        let limits = ZipLimits {
            max_member_bytes: 1000,
            ..ZipLimits::default()
        };
        let (seen, r) = read_with(&plain(&[Spec::stored("big", &[b'a'; 5000])]), &limits);
        assert_eq!(kinds(&r), vec![GapKind::Limit(Limit::MemberSize)]);
        assert_eq!((seen[0].1.len(), seen[0].2), (1000, true));

        let mut bomb = Spec::deflated("bomb", b"");
        bomb.payload = deflate_run(b'z', 1_000_000);
        bomb.csize = bomb.payload.len() as u64;
        bomb.local_csize = bomb.csize;
        bomb.usize = 1_000_000;
        bomb.local_usize = bomb.usize;
        bomb.crc = crc(&[b'z'; 1_000_000]);
        bomb.local_crc = bomb.crc;
        let zip = plain(&[bomb.clone()]);
        let (_, r) = read_all(&zip);
        assert!(r.gaps.is_empty(), "fixed Huffman stays under 300:1");
        let strict = ZipLimits {
            max_ratio: 100,
            ..ZipLimits::default()
        };
        let (seen, r) = read_with(&zip, &strict);
        assert_eq!(kinds(&r), vec![GapKind::Limit(Limit::Ratio)]);
        assert!(seen[0].2);
        assert_eq!(seen[0].1.len(), 100 * bomb.payload.len());
    }

    #[test]
    fn an_overstated_size_does_not_lift_the_ratio_limit() {
        let mut bomb = Spec::deflated("bomb", b"");
        let stream = deflate_run(b'z', 1_000_000);
        bomb.payload = stream.clone();
        bomb.payload.resize(stream.len() * 10, 0);
        bomb.csize = bomb.payload.len() as u64;
        bomb.local_csize = bomb.csize;
        bomb.usize = 1_000_000;
        bomb.local_usize = bomb.usize;
        bomb.crc = crc(&[b'z'; 1_000_000]);
        bomb.local_crc = bomb.crc;
        let strict = ZipLimits {
            max_ratio: 100,
            ..ZipLimits::default()
        };
        let (_, r) = read_with(&plain(&[bomb]), &strict);
        assert!(kinds(&r).contains(&GapKind::Limit(Limit::Ratio)), "{r:?}");
    }

    #[test]
    fn the_read_budget_reads_cheap_members_first() {
        let big = Spec::stored("big", &[b'b'; 40_000]);
        let small = Spec::stored("small", b"small member");
        let limits = ZipLimits {
            max_read_back_bytes: 30_000,
            ..ZipLimits::default()
        };
        let (seen, r) = read_with(&plain(&[big, small]), &limits);
        assert_eq!(kinds(&r), vec![GapKind::Limit(Limit::Budget)]);
        assert!(seen.contains(&("small".to_string(), b"small member".to_vec(), false)));
    }

    #[test]
    fn nested_zips_are_read_to_the_depth_limit() {
        let mut level = plain(&[Spec::stored("deep.txt", b"deepest")]);
        for i in (1..=5).rev() {
            level = plain(&[
                Spec::deflated(&format!("l{i}.zip"), &level),
                Spec::stored(&format!("n{i}.txt"), b"note"),
            ]);
        }
        let (seen, r) = read_all(&level);
        let paths: Vec<&str> = seen.iter().map(|(p, _, _)| p.as_str()).collect();
        assert!(paths.contains(&"l1.zip!l2.zip!l3.zip!n4.txt"), "{paths:?}");
        // Level 5 is past the default depth of 4: visited raw, not read.
        assert!(paths.contains(&"l1.zip!l2.zip!l3.zip!l4.zip"), "{paths:?}");
        assert!(!paths.iter().any(|p| p.ends_with("deep.txt")));
        assert_eq!(
            r.gaps,
            vec![Gap {
                member: "l1.zip!l2.zip!l3.zip!l4.zip".to_string(),
                kind: GapKind::Limit(Limit::Depth)
            }]
        );
    }

    #[test]
    fn a_nested_zip_with_a_prefix_is_also_visited_raw() {
        let mut inner = b"MZ-ish prefix ".to_vec();
        inner.extend(plain(&[Spec::stored("x", b"inner member")]));
        let (seen, r) = read_all(&plain(&[Spec::stored("sfx", &inner)]));
        assert!(r.gaps.is_empty(), "{:?}", r.gaps);
        assert!(has_bytes(&seen, &inner) && has_bytes(&seen, b"inner member"));
        let path = &seen.iter().find(|s| s.1 == b"inner member").unwrap().0;
        assert_eq!(path, "sfx!x");
    }

    #[test]
    fn duplicate_entries_for_one_header_decode_once() {
        let zip = plain(&[Spec::deflated("a", &[b'q'; 1000])]);
        let cd = zip.windows(4).position(|w| w == CENTRAL_SIG).unwrap();
        let end = zip.len() - END_LEN;
        let entry = zip[cd..end].to_vec();
        let mut many = zip[..end].to_vec();
        for _ in 0..50 {
            many.extend(&entry);
        }
        let mut eocd = zip[end..].to_vec();
        eocd[8..10].copy_from_slice(&51u16.to_le_bytes());
        eocd[10..12].copy_from_slice(&51u16.to_le_bytes());
        eocd[12..16].copy_from_slice(&((51 * entry.len()) as u32).to_le_bytes());
        many.extend(eocd);
        let (seen, r) = read_all(&many);
        assert!(r.gaps.is_empty(), "{:?}", r.gaps);
        assert_eq!(seen.len(), 1);
    }

    #[test]
    fn names_for_one_header_are_visited_within_the_budget() {
        let zip = plain(&[Spec::stored("a", &[b'q'; 1000])]);
        let cd = zip.windows(4).position(|w| w == CENTRAL_SIG).unwrap();
        let end = zip.len() - END_LEN;
        let entry = zip[cd..end].to_vec();
        let mut many = zip[..cd].to_vec();
        for i in 0..50u8 {
            let mut e = entry.clone();
            e[CENTRAL_LEN] = b'A' + i;
            many.extend(e);
        }
        let mut eocd = zip[end..].to_vec();
        eocd[8..10].copy_from_slice(&50u16.to_le_bytes());
        eocd[10..12].copy_from_slice(&50u16.to_le_bytes());
        eocd[12..16].copy_from_slice(&((50 * entry.len()) as u32).to_le_bytes());
        many.extend(eocd);
        let (seen, r) = read_all(&many);
        let headers = GapKind::Disagree(Disagreement::Headers);
        assert!(kinds(&r).iter().all(|&k| k == headers), "{r:?}");
        // The local name, `a`, is one of the 50.
        assert_eq!(seen.len(), 50);
        let limits = ZipLimits {
            max_read_back_bytes: 20_000,
            ..ZipLimits::default()
        };
        let (seen, r) = read_with(&many, &limits);
        assert!(kinds(&r).contains(&GapKind::Limit(Limit::Budget)), "{r:?}");
        assert!(seen.len() < 50, "{}", seen.len());
    }

    /// `zip` (whose first member has a one-byte name) with that member's
    /// directory entry repeated under `n` names, `A` onwards.
    fn with_aliases(zip: &[u8], n: u8) -> Vec<u8> {
        let cd = zip.windows(4).position(|w| w == CENTRAL_SIG).unwrap();
        let end = zip.len() - END_LEN;
        let len = CENTRAL_LEN + 1;
        let mut out = zip[..cd].to_vec();
        for i in 0..n {
            let mut e = zip[cd..cd + len].to_vec();
            e[CENTRAL_LEN] = b'A' + i;
            out.extend(e);
        }
        out.extend(&zip[cd + len..end]);
        let mut eocd = zip[end..].to_vec();
        let extra = u16::from(n) - 1;
        for at in [8, 10] {
            let count = u16::from_le_bytes([eocd[at], eocd[at + 1]]) + extra;
            eocd[at..at + 2].copy_from_slice(&count.to_le_bytes());
        }
        let size = u32::from_le_bytes(eocd[12..16].try_into().unwrap());
        let size = size + u32::from(extra) * len as u32;
        eocd[12..16].copy_from_slice(&size.to_le_bytes());
        out.extend(eocd);
        out
    }

    #[test]
    fn each_name_is_charged_the_fixed_member_cost() {
        let many = with_aliases(&plain(&[Spec::stored("a", b"q")]), 50);
        let limits = ZipLimits {
            max_read_back_bytes: 20_000,
            ..ZipLimits::default()
        };
        let (seen, r) = read_with(&many, &limits);
        assert!(kinds(&r).contains(&GapKind::Limit(Limit::Budget)), "{r:?}");
        assert!(seen.len() <= 20_000 / ENTRY_COST, "{}", seen.len());
    }

    #[test]
    fn a_members_names_cannot_spend_a_later_members_share() {
        let decoy = Spec::stored("a", &[b'q'; 1000]);
        let later = Spec::stored("z", &[b'z'; 3000]);
        let many = with_aliases(&plain(&[decoy, later]), 50);
        let limits = ZipLimits {
            max_read_back_bytes: 30_000,
            ..ZipLimits::default()
        };
        let (seen, r) = read_with(&many, &limits);
        assert!(seen.contains(&("z".to_string(), vec![b'z'; 3000], false)));
        assert!(!r.gaps.iter().any(|g| g.member == "z"), "{r:?}");
    }

    /// Crafted zips where views or readers may disagree, by name.
    fn disagreement_cases() -> Vec<(&'static str, Vec<u8>)> {
        let streaming = Layout {
            no_end: true,
            ..Layout::default()
        };
        let mut cases = vec![
            (
                "plain",
                plain(&[Spec::stored("a", b"alpha"), Spec::deflated("b", b"bravo")]),
            ),
            (
                "prefix and comment",
                build(
                    &[Spec::stored("a", b"alpha"), Spec::deflated("b", b"bravo")],
                    &Layout {
                        prefix: b"#!/bin/sh\nexit 0\n".to_vec(),
                        comment: b"comment".to_vec(),
                        ..Layout::default()
                    },
                ),
            ),
            (
                "zip64 with prefix",
                build(
                    &[Spec::deflated("a", b"sixty-four")],
                    &Layout {
                        prefix: vec![1; 40],
                        zip64: true,
                        ..Layout::default()
                    },
                ),
            ),
            (
                "streamed deflate, no directory",
                build(&[Spec::deflated("s", b"streamed").streamed()], &streaming),
            ),
            (
                "streamed stored, no directory",
                build(
                    &[Spec::stored("s", b"stored stream").streamed()],
                    &streaming,
                ),
            ),
        ];
        let mut name = Spec::stored("shown", b"named twice");
        name.local_name = b"local".to_vec();
        cases.push(("name mismatch", plain(&[name])));
        let mut method = Spec::deflated("m", b"method text");
        method.local_method = STORED;
        cases.push(("local stored, directory deflate", plain(&[method])));
        let mut method = Spec::deflated("m", b"method text");
        method.method = STORED;
        cases.push(("local deflate, directory stored", plain(&[method])));
        let mut size = Spec::stored("z", b"short|and the rest");
        size.csize = 5;
        size.usize = 5;
        size.crc = crc(b"short");
        cases.push(("directory size shorter", plain(&[size])));
        let mut size = Spec::stored("z", b"short|and the rest");
        size.local_csize = 5;
        size.local_usize = 5;
        size.local_crc = crc(b"short");
        cases.push(("local size shorter", plain(&[size])));
        let mut hidden = Spec::stored("hidden", b"walk only");
        hidden.hidden = true;
        cases.push((
            "member only the walk sees",
            plain(&[Spec::stored("a", b"a"), hidden]),
        ));
        let mut junk = Spec::stored("b", b"behind junk");
        junk.gap_before = b"junk".to_vec();
        cases.push((
            "member behind junk",
            plain(&[Spec::stored("a", b"a"), junk]),
        ));
        let mut enc = Spec::stored("e", b"plain to the local header");
        enc.flags = FLAG_ENCRYPTED;
        cases.push(("directory says encrypted", plain(&[enc])));
        let mut enc = Spec::stored("e", b"plain to the directory");
        enc.local_flags = FLAG_ENCRYPTED;
        cases.push(("local says encrypted", plain(&[enc])));
        // A deflate stream that ends inside the directory's extent, followed
        // by a descriptor and a member only a streaming reader finds.
        let mut early = Spec::deflated("a", b"first").streamed();
        let mut tail = DESCRIPTOR_SIG.to_vec();
        tail.extend(crc(b"first").to_le_bytes());
        tail.extend((early.payload.len() as u32).to_le_bytes());
        tail.extend(5u32.to_le_bytes());
        tail.extend(build(
            &[Spec::stored("smuggled", b"stream only")],
            &streaming,
        ));
        early.payload.extend(tail);
        early.csize = early.payload.len() as u64;
        cases.push((
            "stream ends early",
            plain(&[early, Spec::stored("b", b"b")]),
        ));
        // The comment ends with an empty end record that reaches the end.
        let mut fake = END_SIG.to_vec();
        fake.extend([0; 18]);
        cases.push((
            "empty end record in the comment",
            build(
                &[Spec::stored("a", b"behind a decoy end")],
                &Layout {
                    comment: fake,
                    ..Layout::default()
                },
            ),
        ));
        let mut bz = Spec::stored("b.bin", include_bytes!("../testdata/bzip2/all_bytes.out"));
        bz.method = BZIP2;
        bz.local_method = BZIP2;
        bz.payload = include_bytes!("../testdata/bzip2/all_bytes.in").to_vec();
        bz.csize = bz.payload.len() as u64;
        bz.local_csize = bz.csize;
        cases.push(("bzip2 member", plain(&[bz])));
        cases
    }

    /// Regular files under `dir`, recursively, as (relative path, bytes).
    fn files_under(dir: &std::path::Path) -> Vec<(String, Vec<u8>)> {
        let mut out = Vec::new();
        let mut stack = vec![dir.to_path_buf()];
        while let Some(d) = stack.pop() {
            let Ok(entries) = std::fs::read_dir(&d) else {
                continue;
            };
            for e in entries.flatten() {
                let Ok(meta) = std::fs::symlink_metadata(e.path()) else {
                    continue;
                };
                if meta.is_dir() {
                    stack.push(e.path());
                } else if meta.is_file() {
                    let rel = e.path().strip_prefix(dir).unwrap().display().to_string();
                    out.push((rel, std::fs::read(e.path()).unwrap_or_default()));
                }
            }
        }
        out.sort();
        out
    }

    /// Extracts `zip` with `tool` into a fresh directory; `None` if the tool
    /// is missing. Exit status is ignored: what it wrote is what counts.
    fn extract_with(tool: &str, zip: &[u8]) -> Option<Vec<(String, Vec<u8>)>> {
        let file = crate::test_support::write_temp_file("zip-diff", zip);
        let out = file.with_extension("out");
        std::fs::create_dir_all(&out).unwrap();
        let (f, o) = (file.to_str().unwrap(), out.to_str().unwrap());
        let args: Vec<&str> = match tool {
            "/usr/bin/unzip" => vec!["-o", "-qq", f, "-d", o],
            "/usr/bin/ditto" => vec!["-x", "-k", f, o],
            _ => vec!["-xf", f, "-C", o],
        };
        let ran = std::process::Command::new(tool)
            .args(args)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
        let files = ran.is_ok().then(|| files_under(&out));
        let _ = std::fs::remove_file(&file);
        let _ = std::fs::remove_dir_all(&out);
        files
    }

    /// Every file unzip, ditto or bsdtar extracts from a crafted zip is one we
    /// scanned (§11.8). Each tool is skipped where it is missing.
    #[test]
    fn every_member_a_tool_extracts_is_scanned() {
        for (case, zip) in disagreement_cases() {
            let (seen, r) = read_all(&zip);
            for tool in ["/usr/bin/unzip", "/usr/bin/ditto", "/usr/bin/bsdtar"] {
                let Some(files) = extract_with(tool, &zip) else {
                    continue;
                };
                let names: Vec<&str> = files.iter().map(|f| f.0.as_str()).collect();
                println!("{case:<34} {tool:<15} {names:?}");
                for (path, bytes) in &files {
                    let scanned = seen
                        .iter()
                        .any(|(_, b, cut)| b == bytes || (*cut && bytes.starts_with(b)));
                    // bsdtar writes zeros for a member it cannot decrypt.
                    let placeholder = bytes.iter().all(|&b| b == 0);
                    assert!(
                        scanned || placeholder,
                        "{case}: {tool} extracted {path} ({bytes:?}), not scanned; gaps {:?}",
                        r.gaps
                    );
                }
            }
            println!("{case:<34} {:<15} gaps {:?}", "ours", kinds(&r));
        }
    }

    /// `testdata/zip/` holds [`disagreement_cases`] as fuzz seeds; this keeps
    /// them in step. `UPDATE_ZIP_SEEDS=1` rewrites them.
    #[test]
    fn seed_vectors_match_the_cases() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata/zip");
        let update = std::env::var_os("UPDATE_ZIP_SEEDS").is_some();
        for (case, zip) in disagreement_cases() {
            let path = dir.join(format!("{}.zip", case.replace([' ', ','], "_")));
            if update {
                std::fs::create_dir_all(&dir).unwrap();
                std::fs::write(&path, &zip).unwrap();
            }
            let committed = std::fs::read(&path).unwrap_or_else(|e| {
                panic!("{}: {e} (run with UPDATE_ZIP_SEEDS=1)", path.display())
            });
            assert!(
                committed == zip,
                "{} is stale (run with UPDATE_ZIP_SEEDS=1)",
                path.display()
            );
        }
    }

    #[test]
    fn the_descriptor_search_is_charged_to_the_budget() {
        // A streamed stored member with no descriptor is searched to the end.
        let mut s = Spec::stored("s", &[b'p'; 4000]).streamed();
        s.descriptor = false;
        let zip = build(
            &[s],
            &Layout {
                no_end: true,
                ..Layout::default()
            },
        );
        let limits = ZipLimits {
            max_read_back_bytes: 1000,
            ..ZipLimits::default()
        };
        let (_, r) = read_with(&zip, &limits);
        assert!(kinds(&r).contains(&GapKind::Limit(Limit::Budget)), "{r:?}");
        let (_, r) = read_all(&zip);
        assert!(!kinds(&r).contains(&GapKind::Limit(Limit::Budget)), "{r:?}");
    }

    #[test]
    fn a_descriptor_search_ending_at_the_limit_is_unsized_not_budget() {
        let mut s = Spec::stored("s", &[b'p'; 4000]).streamed();
        s.descriptor = false;
        let zip = build(
            &[s],
            &Layout {
                no_end: true,
                ..Layout::default()
            },
        );
        let limits = ZipLimits {
            max_read_back_bytes: zip.len() - (LOCAL_LEN + 1),
            ..ZipLimits::default()
        };
        let (_, r) = read_with(&zip, &limits);
        assert!(!kinds(&r).contains(&GapKind::Limit(Limit::Budget)), "{r:?}");
        let unknown = GapKind::Disagree(Disagreement::UnknownSize);
        assert!(kinds(&r).contains(&unknown), "{r:?}");
    }

    #[test]
    fn long_names_and_many_gaps_are_bounded() {
        let long = format!("{}.command", "a".repeat(70_000));
        let shown = display_name(long.as_bytes());
        assert_eq!(shown.chars().count(), MAX_NAME_CHARS + 1);
        assert!(shown.starts_with("aaa") && shown.ends_with(".command"));
        let wide = format!("{}\u{1}é.sh", "é".repeat(400));
        let shown = display_name(wide.as_bytes());
        assert_eq!(shown.chars().count(), MAX_NAME_CHARS + 1);
        let half = MAX_NAME_CHARS / 2;
        let tail = format!("{}?é.sh", "é".repeat(half - 5));
        assert_eq!(shown, format!("{}…{tail}", "é".repeat(half)));
        let specs: Vec<Spec> = (0..100)
            .map(|i| {
                let mut s = Spec::stored(&format!("e{i}"), b"x");
                s.flags = FLAG_ENCRYPTED;
                s.local_flags = FLAG_ENCRYPTED;
                s
            })
            .collect();
        let (_, r) = read_all(&plain(&specs));
        assert_eq!((r.gaps.len(), r.more_gaps), (MAX_GAPS, 100 - MAX_GAPS));
    }

    #[test]
    fn garbage_never_panics() {
        let mut data = crate::test_support::xorshift_bytes(4096);
        data[0..4].copy_from_slice(LOCAL_SIG);
        for cut in [0, 1, 4, 30, 100, 4096] {
            let _ = read_all(&data[..cut]);
        }
        let zip = plain(&[Spec::deflated("a", b"hello"), Spec::stored("b", b"x")]);
        for cut in 0..zip.len() {
            let _ = read_all(&zip[..cut]);
            let mut flipped = zip.clone();
            flipped[cut] ^= 0xFF;
            let _ = read_all(&flipped);
        }
    }
}
