//! `navnotify` — NAV's per-user notification agent.
//!
//! Not implemented yet (§9.2): a background-only LaunchAgent (no Dock icon, no
//! window) that receives verdicts from `navd` and posts them via
//! UserNotifications. Minimal by design — no scanning, scoring, or monitoring.
//! Final packaging form is an open Phase 0b question (§12).

fn main() {
    eprintln!(
        "navnotify: not yet implemented (Phase 0b onward — see design doc §9.2, §12).\n\
         NAV degrades to `navctl events tail` / logs-only until this exists, per §9.2's \
         designed fallback."
    );
    std::process::exit(1);
}
