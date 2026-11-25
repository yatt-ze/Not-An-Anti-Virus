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

use crate::beneath::ScanRoot;

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
        if !is_real_dir(&contents) {
            return None;
        }

        let stem = &name[..name.len() - ".app".len()];
        let main_executable = executable_from_info_plist(path, &contents)
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
fn executable_from_info_plist(bundle: &Path, contents: &Path) -> Option<PathBuf> {
    let mut buf = Vec::new();
    ScanRoot::open(bundle)
        .ok()?
        .open_file(Path::new("Contents/Info.plist"))
        .ok()?
        .take(MAX_INFO_PLIST_BYTES)
        .read_to_end(&mut buf)
        .ok()?;

    let info = crate::plist::parse(&buf)?;
    let key = "CFBundleExecutable";
    // CoreFoundation keeps the first of a repeated key in a binary plist and
    // the last in XML (#183); `get` is last-wins.
    let exe = if buf.starts_with(b"bplist00") {
        info.as_dict()?
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v)
    } else {
        info.get(key)
    };
    let name = exe?.as_str()?.to_string();
    let leaf = Path::new(&name).file_name()?;
    let candidate = contents.join("MacOS").join(leaf);
    is_real_file(&candidate).then_some(candidate)
}

/// `Contents/MacOS/<stem>` if it exists as a file; otherwise, if
/// `Contents/MacOS/` holds exactly one regular file, that file; otherwise
/// `None`.
fn resolve_main_executable(contents: &Path, stem: &str) -> Option<PathBuf> {
    let macos = contents.join("MacOS");
    if !is_real_dir(&macos) {
        return None;
    }

    let by_name = macos.join(stem);
    if is_real_file(&by_name) {
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

/// A directory that is not a symlink. Bundle members are never followed out
/// of the bundle, matching the walk in `target.rs`.
fn is_real_dir(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok_and(|m| m.is_dir())
}

/// A regular file that is not a symlink (so never a FIFO or device to block on).
fn is_real_file(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok_and(|m| m.is_file())
}

/// Whether a bundle member is a code-signature manifest, the one member
/// traversed but not scored (§5.8): `rel` (beneath the bundle `root`) ends in
/// `_CodeSignature/CodeResources`, and opens without following a symlink as a
/// regular file whose content starts `<?xml` or `bplist00`. Anything
/// unreadable or mismatched returns `false`, so it is scored (§11.8).
pub(crate) fn is_signature_manifest(root: &ScanRoot, rel: &Path) -> bool {
    let mut tail = rel.components().rev();
    let named = matches!(
        (tail.next(), tail.next()),
        (Some(Component::Normal(f)), Some(Component::Normal(d)))
            if f == "CodeResources" && d == "_CodeSignature"
    );
    named && starts_as_plist(root, rel)
}

fn starts_as_plist(root: &ScanRoot, rel: &Path) -> bool {
    let Ok(file) = root.open_file(rel) else {
        return false;
    };
    let mut head = Vec::with_capacity(8);
    if file.take(8).read_to_end(&mut head).is_err() {
        return false;
    }
    head.starts_with(b"<?xml") || head.starts_with(b"bplist00")
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
    fn repeated_cfbundleexecutable_resolves_as_corefoundation_does() {
        // Binary: one dict, both keys referencing a single "CFBundleExecutable"
        // string, values "a" then "b". `plutil -p` reads it as "a".
        let mut binary = b"bplist00\xd2\x01\x01\x02\x03\x5f\x10\x12".to_vec();
        binary.extend_from_slice(b"CFBundleExecutable\x51a\x51b\x08\x0d\x22\x24");
        binary.extend_from_slice(&[0, 0, 0, 0, 0, 0, 1, 1]);
        for n in [4u64, 0, 38] {
            binary.extend_from_slice(&n.to_be_bytes());
        }
        let xml = b"<plist><dict><key>CFBundleExecutable</key><string>a</string>\
            <key>CFBundleExecutable</key><string>b</string></dict></plist>";

        for (info, want) in [(&binary[..], "a"), (&xml[..], "b")] {
            let tmp = TempDir::new();
            let root = make_bundle(&tmp.0, "Foo.app", Some("a"));
            fs::write(root.join("Contents/MacOS/b"), b"#!/bin/sh\n").unwrap();
            fs::write(root.join("Contents/Info.plist"), info).unwrap();
            let layout = BundleLayout::detect(&root).unwrap();
            assert_eq!(
                layout.main_executable,
                Some(root.join("Contents/MacOS").join(want))
            );
        }
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
    fn symlinked_members_are_not_followed() {
        use std::os::unix::fs::symlink;
        let tmp = TempDir::new();
        let outside = make_bundle(&tmp.0, "Outside.app", Some("Outside"));

        let linked_contents = tmp.0.join("A.app");
        fs::create_dir_all(&linked_contents).unwrap();
        symlink(outside.join("Contents"), linked_contents.join("Contents")).unwrap();
        assert!(BundleLayout::detect(&linked_contents).is_none());

        let linked_exec = make_bundle(&tmp.0, "B.app", None);
        symlink(
            outside.join("Contents/MacOS/Outside"),
            linked_exec.join("Contents/MacOS/B"),
        )
        .unwrap();
        assert_eq!(
            BundleLayout::detect(&linked_exec).unwrap().main_executable,
            None
        );

        let linked_macos = make_bundle(&tmp.0, "C.app", None);
        fs::remove_dir(linked_macos.join("Contents/MacOS")).unwrap();
        symlink(
            outside.join("Contents/MacOS"),
            linked_macos.join("Contents/MacOS"),
        )
        .unwrap();
        assert_eq!(
            BundleLayout::detect(&linked_macos).unwrap().main_executable,
            None
        );
    }

    #[test]
    fn symlinked_info_plist_is_not_read() {
        let tmp = TempDir::new();
        let root = make_bundle(&tmp.0, "Foo.app", Some("Foo"));
        let decoy = tmp.0.join("decoy.plist");
        fs::write(
            &decoy,
            br#"<plist><dict><key>CFBundleExecutable</key><string>other</string></dict></plist>"#,
        )
        .unwrap();
        fs::write(root.join("Contents/MacOS/other"), b"#!/bin/sh\n").unwrap();
        fs::remove_file(root.join("Contents/Info.plist")).unwrap();
        std::os::unix::fs::symlink(&decoy, root.join("Contents/Info.plist")).unwrap();

        // The plist is ignored, so the naming convention picks `Foo`.
        let layout = BundleLayout::detect(&root).unwrap();
        assert_eq!(
            layout.main_executable,
            Some(root.join("Contents/MacOS/Foo"))
        );
    }

    #[test]
    fn only_a_plist_code_resources_is_a_signature_manifest() {
        let tmp = TempDir::new();
        let sig = tmp.0.join("Contents/_CodeSignature");
        fs::create_dir_all(&sig).unwrap();
        let rel = Path::new("Contents/_CodeSignature/CodeResources");
        let abs = sig.join("CodeResources");
        let root = ScanRoot::open(&tmp.0).unwrap();
        let is_manifest = |rel: &Path| is_signature_manifest(&root, rel);

        fs::write(&abs, b"<?xml version=\"1.0\"?><plist/>").unwrap();
        assert!(is_manifest(rel));
        fs::write(&abs, b"bplist00\xd0\x08").unwrap();
        assert!(is_manifest(rel));

        // Named right but not a plist: scored.
        fs::write(&abs, b"#!/bin/sh\necho hi\n").unwrap();
        assert!(!is_manifest(rel));
        fs::write(&abs, b"<?xm").unwrap();
        assert!(!is_manifest(rel));

        // A plist under any other name or directory: scored.
        let other = sig.join("CodeDirectory");
        fs::write(&other, b"<?xml version=\"1.0\"?>").unwrap();
        assert!(!is_manifest(Path::new(
            "Contents/_CodeSignature/CodeDirectory"
        )));
        fs::write(tmp.0.join("Contents/Info.plist"), b"<?xml ?>").unwrap();
        assert!(!is_manifest(Path::new("Contents/Info.plist")));

        // A symlink to a real manifest, and a missing file: scored.
        fs::write(&other, b"<?xml version=\"1.0\"?>").unwrap();
        fs::remove_file(&abs).unwrap();
        assert!(!is_manifest(rel));
        std::os::unix::fs::symlink(&other, &abs).unwrap();
        assert!(!is_manifest(rel));
    }
}
