//! `.app` bundle awareness (§5.8). A bundle is scanned as one target — every
//! file inside it (a trojanized `.app` hides its payload in
//! `Contents/Resources/` or a helper, not the main binary), verdict is the
//! worst single file's, and the main executable is called out for context.
//!
//! The main executable is resolved from `Contents/Info.plist`'s
//! `CFBundleExecutable` via [`crate::plist`], falling back to the
//! `Contents/MacOS/<name>` convention. Resolution only affects which member is
//! *labelled* primary; the whole bundle is scanned regardless.

use std::io::Read;
use std::path::{Component, Path, PathBuf};

/// Cap on the `Contents/Info.plist` read; a larger one is corrupt or hostile,
/// and the convention fallback covers both.
const MAX_INFO_PLIST_BYTES: u64 = 1 << 20; // 1 MiB

/// The structure of an `.app` bundle target, as far as NAV needs it.
#[derive(Debug, Clone)]
pub struct BundleLayout {
    /// The `.app` directory itself.
    pub root: PathBuf,
    /// `Contents/MacOS/<executable>`, from `CFBundleExecutable` or the naming
    /// convention. `None` = couldn't identify one; never a reason to skip the scan.
    pub main_executable: Option<PathBuf>,
}

impl BundleLayout {
    /// Recognize `path` as an `.app` bundle and resolve its main executable.
    /// Returns `None` if `path` is not a directory named `*.app` with a
    /// `Contents/` directory — callers then treat it as a plain file or
    /// directory.
    pub fn detect(path: &Path) -> Option<BundleLayout> {
        if !path.is_dir() {
            return None;
        }
        let name = path.file_name()?.to_str()?;
        if !name.to_ascii_lowercase().ends_with(".app") {
            return None;
        }
        let contents = path.join("Contents");
        if !contents.is_dir() {
            return None;
        }

        let stem = &name[..name.len() - ".app".len()];
        let main_executable = executable_from_info_plist(&contents)
            .or_else(|| resolve_main_executable(&contents, stem));

        Some(BundleLayout {
            root: path.to_path_buf(),
            main_executable,
        })
    }
}

/// `Contents/MacOS/<CFBundleExecutable>` if the plist names one and it exists.
/// The value is reduced to its final component, so a hostile
/// `../../elsewhere` can't escape `Contents/MacOS/`.
fn executable_from_info_plist(contents: &Path) -> Option<PathBuf> {
    let info = contents.join("Info.plist");
    let mut buf = Vec::new();
    std::fs::File::open(&info)
        .ok()?
        .take(MAX_INFO_PLIST_BYTES)
        .read_to_end(&mut buf)
        .ok()?;

    let name = crate::plist::parse(&buf)?
        .get("CFBundleExecutable")?
        .as_str()?
        .to_string();
    let leaf = Path::new(&name).file_name()?;
    let candidate = contents.join("MacOS").join(leaf);
    candidate.is_file().then_some(candidate)
}

/// `Contents/MacOS/<stem>` if it exists as a file; otherwise, if
/// `Contents/MacOS/` holds exactly one regular file, that file; otherwise
/// `None`.
fn resolve_main_executable(contents: &Path, stem: &str) -> Option<PathBuf> {
    let macos = contents.join("MacOS");

    let by_name = macos.join(stem);
    if by_name.is_file() {
        return Some(by_name);
    }

    let mut only_file = None;
    for entry in std::fs::read_dir(&macos).ok()? {
        let entry = entry.ok()?;
        if entry.file_type().ok()?.is_file() {
            if only_file.is_some() {
                return None; // more than one candidate — don't guess
            }
            only_file = Some(entry.path());
        }
    }
    only_file
}

/// Bundle members that are compiled UI/localization resources or the code
/// signature — never a code payload, so traversed but not *scored* (§1, §5.8).
/// Narrow on purpose: scripts, dylibs, non-`Info.plist` plists and nested apps
/// are still scanned.
pub fn is_inert_bundle_resource(path: &Path) -> bool {
    for component in path.components() {
        if let Component::Normal(c) = component {
            let c = c.to_string_lossy();
            if c == "_CodeSignature"
                || c.ends_with(".lproj")
                || c.ends_with(".storyboardc")
                || c.ends_with(".momd")
            {
                return true;
            }
        }
    }

    let file_name = match path.file_name().and_then(|n| n.to_str()) {
        Some(n) => n,
        None => return false,
    };
    if file_name == "Info.plist" || file_name == "PkgInfo" {
        return true;
    }

    matches!(
        path.extension()
            .and_then(|e| e.to_str())
            .map(|e| e.to_ascii_lowercase())
            .as_deref(),
        Some("nib" | "car" | "strings" | "xcprivacy" | "icns")
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    struct TempDir(PathBuf);
    impl TempDir {
        fn new() -> Self {
            // Process-wide counter, not just a timestamp: `as_nanos()` isn't
            // unique across threads, so parallel tests could collide on a dir.
            use std::sync::atomic::{AtomicU64, Ordering};
            static SEQ: AtomicU64 = AtomicU64::new(0);
            let p = std::env::temp_dir().join(format!(
                "nav-bundle-{}-{}-{:?}",
                std::process::id(),
                SEQ.fetch_add(1, Ordering::Relaxed),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            fs::create_dir_all(&p).unwrap();
            TempDir(p)
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn make_bundle(base: &Path, name: &str, exec: Option<&str>) -> PathBuf {
        let root = base.join(name);
        fs::create_dir_all(root.join("Contents/MacOS")).unwrap();
        fs::write(root.join("Contents/Info.plist"), b"<plist/>").unwrap();
        if let Some(exec) = exec {
            fs::write(root.join("Contents/MacOS").join(exec), b"#!/bin/sh\n").unwrap();
        }
        root
    }

    #[test]
    fn detects_bundle_and_resolves_exec_by_name() {
        let tmp = TempDir::new();
        let root = make_bundle(&tmp.0, "Foo.app", Some("Foo"));

        let layout = BundleLayout::detect(&root).expect("should detect");
        assert_eq!(
            layout.main_executable,
            Some(root.join("Contents/MacOS/Foo"))
        );
    }

    #[test]
    fn resolves_sole_exec_when_name_does_not_match() {
        let tmp = TempDir::new();
        let root = make_bundle(&tmp.0, "Foo.app", Some("launcher"));

        let layout = BundleLayout::detect(&root).unwrap();
        assert_eq!(
            layout.main_executable,
            Some(root.join("Contents/MacOS/launcher"))
        );
    }

    #[test]
    fn info_plist_cfbundleexecutable_wins_over_the_naming_convention() {
        // NamedDiff.app: a binary Info.plist with CFBundleExecutable `realmain`
        // and a `Contents/MacOS/NamedDiff` decoy the convention would pick.
        let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/benign/NamedDiff.app");
        let layout = BundleLayout::detect(&fixture).expect("should detect");
        assert_eq!(
            layout.main_executable,
            Some(fixture.join("Contents/MacOS/realmain")),
        );
    }

    #[test]
    fn ambiguous_macos_dir_leaves_exec_unresolved_but_still_a_bundle() {
        let tmp = TempDir::new();
        let root = make_bundle(&tmp.0, "Foo.app", Some("a"));
        fs::write(root.join("Contents/MacOS/b"), b"#!/bin/sh\n").unwrap();

        let layout = BundleLayout::detect(&root).unwrap();
        assert_eq!(layout.main_executable, None);
    }

    #[test]
    fn plain_directory_is_not_a_bundle() {
        let tmp = TempDir::new();
        let dir = tmp.0.join("notabundle");
        fs::create_dir_all(&dir).unwrap();
        assert!(BundleLayout::detect(&dir).is_none());

        let appish = tmp.0.join("weird.app");
        fs::create_dir_all(&appish).unwrap(); // no Contents/
        assert!(BundleLayout::detect(&appish).is_none());
    }

    #[test]
    fn inert_resources_are_recognized() {
        assert!(is_inert_bundle_resource(Path::new(
            "Foo.app/Contents/Info.plist"
        )));
        assert!(is_inert_bundle_resource(Path::new(
            "Foo.app/Contents/PkgInfo"
        )));
        assert!(is_inert_bundle_resource(Path::new(
            "Foo.app/Contents/_CodeSignature/CodeResources"
        )));
        assert!(is_inert_bundle_resource(Path::new(
            "Foo.app/Contents/Resources/en.lproj/Main.strings"
        )));
        assert!(is_inert_bundle_resource(Path::new(
            "Foo.app/Contents/Resources/Assets.car"
        )));

        assert!(!is_inert_bundle_resource(Path::new(
            "Foo.app/Contents/MacOS/Foo"
        )));
        assert!(!is_inert_bundle_resource(Path::new(
            "Foo.app/Contents/Resources/update.sh"
        )));
        assert!(!is_inert_bundle_resource(Path::new(
            "Foo.app/Contents/Library/LaunchServices/helper.plist"
        )));
    }
}
