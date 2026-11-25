//! Opening files beneath a trusted directory without following a symlink in
//! any component below it, so a path swapped mid-scan can't redirect a read
//! outside the target (§11.7).

use std::fs::File;
use std::io;
use std::path::{Component, Path, PathBuf};

use rustix::fs::{openat, Mode, OFlags};

/// A directory held open as the trusted anchor for a scan. Its own path is
/// resolved once (symlinks followed — the caller named it); nothing beneath it
/// is ever resolved through a symlink.
#[derive(Debug)]
pub(crate) struct ScanRoot {
    dir: File,
    path: PathBuf,
}

impl ScanRoot {
    /// Canonicalize `path` and hold it open as a directory.
    pub(crate) fn open(path: &Path) -> io::Result<Self> {
        let path = path.canonicalize()?;
        let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC;
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
        let mut names = Vec::new();
        for part in rel.components() {
            match part {
                Component::Normal(name) => names.push(name),
                _ => return Err(io::ErrorKind::InvalidInput.into()),
            }
        }
        let Some((leaf, dirs)) = names.split_last() else {
            return Err(io::ErrorKind::InvalidInput.into());
        };
        let mut held: Option<File> = None;
        for name in dirs {
            let parent = held.as_ref().unwrap_or(&self.dir);
            let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
            held = Some(File::from(openat(parent, *name, flags, Mode::empty())?));
        }
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
