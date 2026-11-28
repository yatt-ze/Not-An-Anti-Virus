//! `cargo xtask benign`: fetch, verify, prepare and survey the benign set
//! (§11.1b). Exit status: 0 ok, 2 an item is missing, unrecorded or corrupt,
//! 1 tool error. Items needing a refresh are reported, not failed.

mod fetch;
mod manifest;
mod prepare;
mod vm;

use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{Context, Result};
use clap::{Args, Subcommand};

use manifest::{Item, Manifest};

#[derive(Subcommand)]
pub enum BenignCommand {
    /// Fill the download cache from the manifest (VM only).
    Fetch(FetchArgs),
    /// Re-hash the download cache; no network (VM only).
    Verify(CommonArgs),
    /// Unpack cached items under ~/nav-benign/<id>/ for the survey script (VM only).
    Prepare(PrepareArgs),
    /// Run the survey in a throwaway clone of the golden Tart VM (host side).
    #[command(subcommand)]
    Vm(vm::VmCommand),
}

#[derive(Args)]
pub struct PrepareArgs {
    #[command(flatten)]
    common: CommonArgs,
    /// Output dir (default: ~/nav-benign).
    #[arg(long)]
    out: Option<PathBuf>,
}

#[derive(Args)]
pub struct CommonArgs {
    /// Manifest path (default: nav-core/fixtures/real-world/benign.toml).
    #[arg(long)]
    manifest: Option<PathBuf>,
    /// Cache dir (default: ~/nav-benign-cache).
    #[arg(long)]
    cache: Option<PathBuf>,
}

#[derive(Args)]
pub struct FetchArgs {
    #[command(flatten)]
    common: CommonArgs,
    /// Accept new bytes and rewrite sha256/bytes in the manifest file.
    #[arg(long)]
    record: bool,
}

impl CommonArgs {
    fn manifest_path(&self) -> PathBuf {
        self.manifest
            .clone()
            .unwrap_or_else(|| crate::malware::real_world_dir().join("benign.toml"))
    }

    fn cache_dir(&self) -> Result<PathBuf> {
        match &self.cache {
            Some(c) => Ok(c.clone()),
            None => Ok(home()?.join("nav-benign-cache")),
        }
    }
}

fn home() -> Result<PathBuf> {
    Ok(PathBuf::from(
        std::env::var_os("HOME").context("HOME is not set")?,
    ))
}

pub fn run(cmd: BenignCommand) -> Result<ExitCode> {
    match cmd {
        BenignCommand::Fetch(a) => {
            crate::vm::ensure_vm("§11.1b")?;
            let path = a.common.manifest_path();
            let manifest = Manifest::load(&path)?;
            let items: Vec<&Item> = manifest.items.iter().collect();
            let record = fetch::Record { manifest: &path };
            let cache = a.common.cache_dir()?;
            let summary = fetch::fetch(&items, &cache, &fetch::REAL, a.record.then_some(&record))?;
            Ok(summary.finish())
        }
        BenignCommand::Verify(a) => {
            crate::vm::ensure_vm("§11.1b")?;
            let manifest = Manifest::load(&a.manifest_path())?;
            let items: Vec<&Item> = manifest.items.iter().collect();
            Ok(fetch::verify(&items, &a.cache_dir()?)?.finish())
        }
        BenignCommand::Prepare(a) => {
            crate::vm::ensure_vm("§11.1b")?;
            let manifest = Manifest::load(&a.common.manifest_path())?;
            let items: Vec<&Item> = manifest.items.iter().collect();
            let out = match a.out {
                Some(o) => o,
                None => home()?.join("nav-benign"),
            };
            let report = prepare::prepare(&items, &a.common.cache_dir()?, &out)?;
            println!("{} ok, {} failed", report.ok, report.failed);
            Ok(ExitCode::from(if report.failed > 0 { 2 } else { 0 }))
        }
        BenignCommand::Vm(cmd) => vm::run(cmd),
    }
}
