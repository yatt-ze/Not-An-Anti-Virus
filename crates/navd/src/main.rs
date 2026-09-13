//! `navd` — NAV's privileged daemon.
//!
//! Two strictly separate process lifecycles behind one binary (§12 Phase
//! 0b A2): bare `navd` (no args) is the persistent A1 stay-alive daemon the
//! LaunchDaemon plist invokes (see [`daemon`]) — it never scans. `navd
//! scan-once <path>` is a separate short-lived invocation that runs one
//! `nav-core` scan and exits (see [`scan_once`]) — it never starts the
//! daemon loop. The subcommand is optional so the plist's zero-arg
//! invocation keeps routing to the daemon instead of erroring on a missing
//! subcommand.

mod daemon;
mod scan_once;

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "navd", version, about = "NAV's privileged daemon")]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// One-shot self-scan spike instrument for the Phase 0b B3 TCC-behavior
    /// check (§12). Temporary — not stable CLI surface (§9.1); removed once
    /// B3 is answered.
    ScanOnce {
        path: PathBuf,
        #[arg(long)]
        json: bool,
        #[arg(long)]
        recursive: bool,
    },
}

fn main() -> ExitCode {
    match Cli::parse().command {
        None => {
            daemon::run();
            ExitCode::SUCCESS
        }
        Some(Command::ScanOnce {
            path,
            json,
            recursive,
        }) => scan_once::run(&path, recursive, json),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The installed LaunchDaemon plist invokes bare `navd` with zero
    /// arguments (§12 A2 trap 1) — that must parse to no subcommand, routing
    /// to the daemon, never a clap usage error over a required subcommand.
    #[test]
    fn no_args_parses_to_no_subcommand() {
        let cli = Cli::try_parse_from(["navd"]).expect("bare `navd` must parse");
        assert!(cli.command.is_none());
    }

    #[test]
    fn scan_once_parses_its_path_and_flags() {
        let cli = Cli::try_parse_from(["navd", "scan-once", "/tmp/x", "--json", "--recursive"])
            .expect("scan-once with a path parses");
        match cli.command {
            Some(Command::ScanOnce {
                path,
                json,
                recursive,
            }) => {
                assert_eq!(path, PathBuf::from("/tmp/x"));
                assert!(json);
                assert!(recursive);
            }
            other => panic!("expected ScanOnce, got {other:?}"),
        }
    }
}
