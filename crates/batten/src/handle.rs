//! A handle on a file or directory, for its lock or its times, on every
//! platform.

use std::path::Path;

/// `path`, file or directory, opened for its lock or its times.
///
/// WINDOWS OPENS A DIRECTORY ONLY WITH BACKUP SEMANTICS and writes times only
/// through a handle opened for writing; measured on #1132's `windows` job, a
/// plain `File::open` read every tree as held and re-armed no survivor (the
/// rule `perf.rs`'s sibling stamp records). Elsewhere a read-only handle does
/// both, and is the only handle a directory takes.
pub(crate) fn open(path: &Path) -> std::io::Result<std::fs::File> {
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt as _;
        const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
            .open(path)
    }
    #[cfg(not(windows))]
    {
        std::fs::File::open(path)
    }
}
