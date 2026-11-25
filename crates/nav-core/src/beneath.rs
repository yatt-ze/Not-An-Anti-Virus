//! Opening and listing files beneath a trusted directory without following a
//! symlink in any component below it, so a path swapped mid-scan can't
//! redirect a read or a listing outside the target (§11.7).

use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};

use rustix::fs::{openat, statat, AtFlags, Dir, FileType, Mode, OFlags};

/// A directory held open as the trusted anchor for a scan. Its own path is
/// resolved once (symlinks followed — the caller named it); nothing beneath it
/// is ever resolved through a symlink. `dir` is search-only (`O_PATH` on
/// Linux): use it only as an `openat` dirfd.
#[derive(Debug)]
pub(crate) struct ScanRoot {
    dir: File,
    path: PathBuf,
}

impl ScanRoot {
    /// Canonicalize `path` and hold it open as a directory.
    pub(crate) fn open(path: &Path) -> io::Result<Self> {
        let path = path.canonicalize()?;
        let flags = search_flags() & !OFlags::NOFOLLOW;
        let fd = openat(rustix::fs::CWD, &path, flags, Mode::empty())?;
        Ok(ScanRoot {
            dir: File::from(fd),
            path,
        })
    }

    /// The canonical path of the root.
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    /// Open the regular file at `rel` beneath the root, refusing a symlink in
    /// any component. `rel` must be non-empty and hold only normal components.
    /// Errors on a symlink (`ELOOP`/`ENOTDIR`), a non-regular file, or any
    /// open failure. The open is non-blocking, so a FIFO can't hang it.
    pub(crate) fn open_file(&self, rel: &Path) -> io::Result<File> {
        let names = normal_names(rel)?;
        let Some((leaf, dirs)) = names.split_last() else {
            return Err(io::ErrorKind::InvalidInput.into());
        };
        let held = self.open_dirs(dirs)?;
        let parent = held.as_ref().unwrap_or(&self.dir);
        // O_NOCTTY: a tty swapped in must not become our controlling terminal.
        let flags =
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::NOCTTY | OFlags::CLOEXEC;
        let file = File::from(openat(parent, *leaf, flags, Mode::empty())?);
        if !file.metadata()?.is_file() {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        Ok(file)
    }

    /// List the directory at `rel` beneath the root (empty `rel` is the root),
    /// refusing a symlink in any component. Entries come unsorted, without
    /// `.`/`..`, each typed as by `lstat` (a symlink is never followed).
    pub(crate) fn list_dir(&self, rel: &Path) -> io::Result<DirList> {
        let names = normal_names(rel)?;
        let (parent, name) = match names.split_last() {
            Some((leaf, dirs)) => (self.open_dirs(dirs)?, *leaf),
            None => (None, OsStr::new(".")),
        };
        let parent = parent.as_ref().unwrap_or(&self.dir);
        let fd = openat(parent, name, list_flags(), Mode::empty())?;
        Ok(DirList(Dir::new(fd)?))
    }

    /// Open each of `dirs` in turn, search-only, beneath the root with no
    /// symlink followed. `None` when `dirs` is empty (the root itself).
    fn open_dirs(&self, dirs: &[&OsStr]) -> io::Result<Option<File>> {
        let mut held: Option<File> = None;
        for name in dirs {
            let parent = held.as_ref().unwrap_or(&self.dir);
            held = Some(File::from(openat(
                parent,
                *name,
                search_flags(),
                Mode::empty(),
            )?));
        }
        Ok(held)
    }
}

/// Flags for a directory that is listed: needs read permission.
fn list_flags() -> OFlags {
    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC
}

/// Flags for a directory only passed through: needs search permission alone,
/// so a `0711` directory on the way to a target still opens (#253).
fn search_flags() -> OFlags {
    search_mode() | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn search_mode() -> OFlags {
    OFlags::PATH
}

/// `O_EXEC`, which with `O_DIRECTORY` is Apple's `O_SEARCH`; rustix lacks it.
#[cfg(target_vendor = "apple")]
fn search_mode() -> OFlags {
    OFlags::from_bits_retain(0x4000_0000)
}

#[cfg(not(any(target_os = "linux", target_os = "android", target_vendor = "apple")))]
fn search_mode() -> OFlags {
    OFlags::RDONLY
}

/// `rel`'s components, or `InvalidInput` if any is not a normal name.
fn normal_names(rel: &Path) -> io::Result<Vec<&OsStr>> {
    rel.components()
        .map(|part| match part {
            Component::Normal(name) => Ok(name),
            _ => Err(io::ErrorKind::InvalidInput.into()),
        })
        .collect()
}

/// The entries of a directory opened by [`ScanRoot::list_dir`].
pub(crate) struct DirList(Dir);

impl Iterator for DirList {
    type Item = io::Result<(OsString, FileType)>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let entry = match self.0.read()? {
                Ok(entry) => entry,
                Err(e) => return Some(Err(e.into())),
            };
            let name = OsStr::from_bytes(entry.file_name().to_bytes());
            if name == "." || name == ".." {
                continue;
            }
            let mut kind = entry.file_type();
            if kind == FileType::Unknown {
                // No `d_type` from this filesystem: ask without following.
                kind = match self
                    .0
                    .fd()
                    .and_then(|fd| statat(fd, name, AtFlags::SYMLINK_NOFOLLOW))
                {
                    Ok(st) => FileType::from_raw_mode(st.st_mode as _),
                    Err(e) => return Some(Err(e.into())),
                };
            }
            return Some(Ok((name.to_owned(), kind)));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::symlink;

    fn temp_root(tag: &str) -> PathBuf {
        let p = crate::test_support::write_temp_file(tag, b"");
        fs::remove_file(&p).unwrap();
        fs::create_dir_all(p.join("sub")).unwrap();
        fs::write(p.join("sub/f"), b"inside").unwrap();
        p
    }

    #[test]
    fn opens_nested_file() {
        let dir = temp_root("beneath-ok");
        let root = ScanRoot::open(&dir).unwrap();
        assert!(root.open_file(Path::new("sub/f")).is_ok());
        fs::remove_dir_all(&dir).unwrap();
    }

    /// Neither a symlinked leaf nor a symlinked parent is followed.
    #[test]
    fn refuses_symlink_components() {
        let dir = temp_root("beneath-link");
        symlink(dir.join("sub/f"), dir.join("leaf")).unwrap();
        symlink(dir.join("sub"), dir.join("linkdir")).unwrap();
        let root = ScanRoot::open(&dir).unwrap();
        assert!(root.open_file(Path::new("leaf")).is_err());
        assert!(root.open_file(Path::new("linkdir/f")).is_err());
        fs::remove_dir_all(&dir).unwrap();
    }

    fn listed(root: &ScanRoot, rel: &str) -> Vec<(OsString, FileType)> {
        let mut v: Vec<_> = root
            .list_dir(Path::new(rel))
            .unwrap()
            .map(Result::unwrap)
            .collect();
        v.sort_by(|a, b| a.0.cmp(&b.0));
        v
    }

    /// Names and lstat-like types; a directory symlink is not followed.
    #[test]
    fn lists_entries() {
        let dir = temp_root("beneath-list");
        symlink(dir.join("sub"), dir.join("linkdir")).unwrap();
        let root = ScanRoot::open(&dir).unwrap();
        let want = |n: &str, t| (OsString::from(n), t);
        assert_eq!(
            listed(&root, ""),
            vec![
                want("linkdir", FileType::Symlink),
                want("sub", FileType::Directory)
            ]
        );
        assert_eq!(listed(&root, "sub"), vec![want("f", FileType::RegularFile)]);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn list_refuses_symlinks() {
        let dir = temp_root("beneath-list-link");
        fs::create_dir(dir.join("sub/deeper")).unwrap();
        symlink(dir.join("sub"), dir.join("linkdir")).unwrap();
        let root = ScanRoot::open(&dir).unwrap();
        for rel in ["linkdir", "linkdir/deeper", "sub/f", "..", "/etc"] {
            assert!(root.list_dir(Path::new(rel)).is_err(), "{rel}");
        }
        assert!(root.list_dir(Path::new("sub/deeper")).is_ok());
        fs::remove_dir_all(&dir).unwrap();
    }

    /// A search-only directory (no read bit) is passed through, as the root
    /// or below it, but not listed. Root ignores modes, hence the comparison.
    #[test]
    fn search_only_dirs() {
        use std::os::unix::fs::PermissionsExt;
        let dir = temp_root("beneath-search");
        let sub = dir.join("sub");
        fs::create_dir(sub.join("deeper")).unwrap();
        fs::set_permissions(&sub, fs::Permissions::from_mode(0o100)).unwrap();
        let root = ScanRoot::open(&dir).unwrap();
        let file_ok = root.open_file(Path::new("sub/f")).is_ok();
        let as_root = ScanRoot::open(&sub).and_then(|r| r.open_file(Path::new("f")));
        let deeper_ok = root.list_dir(Path::new("sub/deeper")).is_ok();
        let list_err = root.list_dir(Path::new("sub")).is_err();
        let std_err = fs::read_dir(&sub).is_err();
        fs::set_permissions(&sub, fs::Permissions::from_mode(0o755)).unwrap();
        fs::remove_dir_all(&dir).unwrap();
        assert!(file_ok);
        assert!(as_root.is_ok());
        assert!(deeper_ok);
        assert_eq!(list_err, std_err);
    }

    #[test]
    fn refuses_non_normal_components() {
        let dir = temp_root("beneath-dots");
        let root = ScanRoot::open(&dir.join("sub")).unwrap();
        for rel in ["../sub/f", "/etc/hosts", "", "./f"] {
            let rel = Path::new(rel);
            assert!(root.open_file(rel).is_err(), "{}", rel.display());
        }
        assert!(root.open_file(Path::new("f")).is_ok());
        fs::remove_dir_all(&dir).unwrap();
    }
}
