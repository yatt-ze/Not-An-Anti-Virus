//! `navctl` — NAV's CLI.
//!
//! Phase 0a scope (§12): `scan` and `rules test`/`rules list` run in-process
//! against `nav-core` — no `navd`, root, or socket. The other §8 subcommands
//! are listed so the surface is documented, but need `navd` (Phase 0b+) and
//! say so plainly rather than pretending to work.

mod exit;
mod output;

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "navctl", version, about = "NAV — Not an Anti-Virus")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Report daemon/agent health and per-area FDA coverage. Requires navd (Phase 0b).
    Status {
        #[arg(long)]
        resource_usage: bool,
    },
    /// Grant Full Disk Access to navd. Explicitly user-invoked only — never run automatically.
    SetupFda,
    /// Scan a file or directory and print a verdict.
    Scan {
        path: PathBuf,
        #[arg(long)]
        recursive: bool,
        #[arg(long)]
        json: bool,
        #[arg(long)]
        quick: bool,
        #[arg(long)]
        full: bool,
    },
    /// Ruleset inspection and testing.
    Rules {
        #[command(subcommand)]
        command: RulesCommand,
    },
    /// Tail the live event stream. Requires navd (Phase 0b/2).
    Events {
        #[command(subcommand)]
        command: EventsCommand,
    },
    /// Quarantine management. Requires navd (Phase 3).
    Quarantine {
        #[command(subcommand)]
        command: QuarantineCommand,
    },
    /// Add a hash or path to the allowlist. Requires navd (Phase 3).
    Allowlist { hash_or_path: String },
    /// Add a hash to the denylist. Requires navd (Phase 3).
    Denylist { hash: String },
    /// Get/set config. Requires navd (Phase 3).
    Config {
        #[command(subcommand)]
        command: ConfigCommand,
    },
    /// View daemon logs. Requires navd (Phase 3).
    Logs {
        #[arg(long)]
        since: Option<String>,
        #[arg(long)]
        grep: Option<String>,
    },
    /// Enable/disable/inspect navnotify delivery. Requires navd (Phase 0b/3).
    Notify { action: Option<String> },
    /// Fully remove NAV. Requires navd (Phase 3).
    Uninstall,
}

#[derive(Subcommand)]
enum RulesCommand {
    /// Full signal breakdown for a file, directory, or `.app` bundle —
    /// dry-run, no action taken.
    Test {
        path: PathBuf,
        #[arg(long)]
        recursive: bool,
        #[arg(long)]
        json: bool,
    },
    /// List the active ruleset.
    List,
    /// Reload the ruleset. Requires navd (Phase 3).
    Reload,
    /// Revert to the previous ruleset. Requires navd (Phase 3).
    Rollback,
}

#[derive(Subcommand)]
enum EventsCommand {
    Tail {
        #[arg(long)]
        min_score: Option<i32>,
        #[arg(long)]
        signal: Option<String>,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
enum QuarantineCommand {
    List,
    Restore {
        id: String,
    },
    Purge {
        id: String,
        #[arg(long)]
        force: bool,
    },
}

#[derive(Subcommand)]
enum ConfigCommand {
    Get { key: String },
    Set { key: String, value: String },
}

fn not_yet_implemented(feature: &str, phase: &str) -> ExitCode {
    eprintln!(
        "navctl: `{feature}` requires navd, which isn't built yet ({phase}). \
         See design doc §12 for the phased roadmap."
    );
    exit::code(exit::OPERATIONAL_ERROR)
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    match cli.command {
        Command::Scan {
            path,
            json,
            recursive,
            quick: _,
            full: _,
        } => output::run_scan(&path, recursive, json),

        Command::Rules { command } => match command {
            RulesCommand::Test {
                path,
                recursive,
                json,
            } => output::run_rules_test(&path, recursive, json),
            RulesCommand::List => output::run_rules_list(),
            RulesCommand::Reload => not_yet_implemented("rules reload", "Phase 3"),
            RulesCommand::Rollback => not_yet_implemented("rules rollback", "Phase 3"),
        },

        Command::Status { .. } => not_yet_implemented("status", "Phase 0b"),
        Command::SetupFda => not_yet_implemented("setup fda", "Phase 0b"),
        Command::Events { .. } => not_yet_implemented("events tail", "Phase 2"),
        Command::Quarantine { .. } => not_yet_implemented("quarantine", "Phase 3"),
        Command::Allowlist { .. } => not_yet_implemented("allowlist", "Phase 3"),
        Command::Denylist { .. } => not_yet_implemented("denylist", "Phase 3"),
        Command::Config { .. } => not_yet_implemented("config", "Phase 3"),
        Command::Logs { .. } => not_yet_implemented("logs", "Phase 3"),
        Command::Notify { .. } => not_yet_implemented("notify", "Phase 0b/3"),
        Command::Uninstall => not_yet_implemented("uninstall", "Phase 3"),
    }
}
