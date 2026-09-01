//! `navd` — NAV's privileged daemon.
//!
//! Not implemented yet: the daemon (event sources, correlator, socket,
//! notification relay, quarantine) is Phase 0b onward (§12), sequenced after
//! Phase 0a validates the scanner. Links `nav-core` (§2/§3 workspace wiring)
//! but runs nothing yet.

fn main() {
    // Touch nav-core so the link is real, not just declared.
    let _ = nav_core::ENGINE_VERSION;

    eprintln!(
        "navd: not yet implemented (Phase 0b onward — see design doc §12).\n\
         On-demand scanning does not need this daemon: use `navctl scan` or \
         `navctl rules test`, which link nav-core directly."
    );
    std::process::exit(1);
}
