//! Cross-process caches: one key, one entry format, one binary identity
//! (CLOUD-2315).
//!
//! # Why one module
//!
//! The compiled-policy cache (`policy.rs`, CLOUD-2236) and the validated-config
//! cache (`config.rs`) were written as two near-copies: each hand-rolled the
//! length-prefixed key framing `identity` already owns, each its own
//! header-line entry, each keyed the binary by size and modification time, and
//! each fsynced a rebuildable entry on the per-call path. The prior art on
//! CLOUD-2315 is what this module is built from rather than re-derived.
//!
//! # The contract every cache here holds
//!
//! * **A key is every input the value is a function of, by CONTENT** — never a
//!   timestamp of an input. git's racy-index problem, PEP 552's hash-based
//!   `.pyc`, Cargo's checksum freshness and `ESLint`'s `content` strategy all moved
//!   off mtimes for the same reason: an mtime can stand still across an edit and
//!   move across no edit. Keys go through [`crate::identity::cache_key`], the
//!   crate's one framing.
//! * **The running binary is part of every key, and is identified by its CODE**
//!   ([`running_binary`]): the linker's build ID, a digest of the linked image,
//!   which Go's `cmd/go` and the `build_id` crate read for the same purpose. Size
//!   plus mtime — ccache's default, documented to miss compiler upgrades — is
//!   not used. Where an image carries no build ID, the fallback is the stat
//!   tuple Bazel settled on after a correctness bug: inode and ctime beside size
//!   and mtime.
//! * **An entry is self-validating**, so a torn or zero-filled file is a miss
//!   and never a wrong answer. That, not a durability bet, is why entries are
//!   written without `fsync` ([`crate::durable::Persist::Atomic`]): Kafka saw
//!   zero-length files after rename-without-fsync on ext4, and here such a file
//!   fails the length-and-digest check and is rebuilt.
//! * **Entries live under a `cache/` directory carrying `CACHEDIR.TAG`**, so
//!   backup and sync tools that honour the Cache Directory Tagging spec skip
//!   what can be rebuilt. The directory stays under the state root rather than
//!   `$XDG_CACHE_HOME` so a test that contains the state root contains its
//!   caches too.
//! * **Best-effort both ways**: an entry that cannot be read is a miss, and one
//!   that cannot be written is a miss next time. A cache never fails a call.

use std::io::Read as _;
use std::path::{Path, PathBuf};

/// The signature line the Cache Directory Tagging spec requires, byte for byte.
const CACHEDIR_TAG: &str = "Signature: 8a477f597d28d172789f06886806bc55\n\
     # This file is a cache directory tag created by batten.\n\
     # For information about cache directory tags, see https://bford.info/cachedir/\n";

/// How many binaries' partitions one cache directory keeps, least recently
/// used evicted first. Eight, not fewer: a binary in use refreshes its use
/// time at most a minute behind its last call ([`USE_REFRESH`]), so the
/// installed hook is evicted only by eight rebuilds since about then — and
/// then costs one cold call (code review of CLOUD-2315).
const KEPT_PARTITIONS: usize = 8;

/// The zero-byte file whose time records a partition's last use (CLOUD-2361).
///
/// A FILE, not the partition directory's own time: a directory's time also
/// moves whenever an entry is made or removed straight inside it, so it records
/// the last WRITE, not the last use. The mark moves only when a use refreshes
/// it. (The refresh this replaced also opened the directory plainly, which
/// Windows refuses, so a binary that only read — the installed hook, warm —
/// was never marked used there at all.)
const USE_MARK: &str = "used";

/// The running binary's cache directory under `parent`, or `None` when it
/// cannot be created.
///
/// # One partition per binary, because one slot per row thrashed
///
/// Every entry is keyed by the running binary, and each cache keeps one file
/// per row it answers. Two binaries on one machine — the installed one a hook
/// runs and a development build, or two checkouts pinned to different releases
/// — therefore overwrote each other's entries on every call, and neither was
/// ever served warm (CLOUD-2315, measured: every policy row recompiled while the
/// installed binary ran beside the one under test). ccache and Go's build cache
/// grow by content address instead and evict later; this keeps the per-row
/// bound and partitions it by binary, so each binary has its own slots.
///
/// The warm path pays one `stat`, of the partition's [`USE_MARK`]: the mark
/// existing proves the partition does. A new partition is the rare path: it
/// tags the directory for backup tools ([`CACHEDIR_TAG`]), marks the partition
/// and [`prune`]s, so the directory holds at most [`KEPT_PARTITIONS`] binaries,
/// least recently used evicted first. A partition without a mark — the mark was
/// lost — takes that path too, and gains one where one can be made; where none
/// can, it is served from the cold path and neither marked nor pruned.
//MUTANT partitions-never-pruned|s@^    prune(\&root, name);$@@|a_new_partition_keeps_its_neighbours_up_to_the_bound
//MUTANT partition-mark-never-made|s@^    if crate::durable::create_empty(\&mark).is_err() {$@    if true {@|a_partition_without_a_mark_gains_one
//MUTANT unmarkable-partition-prunes|s@^    if crate::durable::create_empty(\&mark).is_err() {$@    if crate::durable::create_empty(\&mark).is_err() \&\& false {@|a_partition_that_cannot_be_marked_does_not_prune
#[must_use]
pub fn root_under(parent: &Path) -> Option<PathBuf> {
    // A binary that cannot name itself has no partition, so it caches nothing
    // (code review of CLOUD-2315).
    let name = partition()?;
    let root = parent.join("cache");
    let own = root.join(name);
    let mark = own.join(USE_MARK);
    if let Ok(meta) = std::fs::metadata(&mark)
        && meta.is_file()
    {
        refresh_use(&own, &meta, std::time::SystemTime::now());
        return Some(own);
    }
    std::fs::create_dir_all(&own).ok()?;
    let tag = root.join("CACHEDIR.TAG");
    if !tag.exists() {
        let _ = crate::durable::replace_as(&tag, CACHEDIR_TAG, crate::durable::Persist::Atomic);
    }
    // A partition that cannot be marked — or that another process just marked —
    // is still served but does not prune: without a mark every call lands here,
    // and a directory scan per call is the cost the warm path exists to avoid.
    if crate::durable::create_empty(&mark).is_err() {
        return Some(own);
    }
    prune(&root, name);
    Some(own)
}

/// How stale a partition's use time may grow before a hit refreshes it: short,
/// so a binary in use ranks among the most recently used to every prune (code
/// review of CLOUD-2315 — a day let four rebuilds evict the installed hook). The
/// cost is two timestamp writes a minute, the mark's and its directory's.
const USE_REFRESH: std::time::Duration = std::time::Duration::from_mins(1);

/// Mark the partition `own` used through its [`USE_MARK`], whose time `meta`
/// holds, at most once a minute, so [`prune`] ranks partitions by LAST USE (code
/// review of CLOUD-2315): a binary that only reads — the installed hook, warm —
/// otherwise ranked as the oldest and was the one pruned.
///
/// The partition DIRECTORY's time moves too, best-effort: a release before
/// CLOUD-2361 ranks by it, and sharing a cache with one, a partition marked
/// only through its file would read to that release as never used. It can go
/// once no supported release ranks by the directory.
//MUTANT partition-use-never-refreshed|s@^    if stale {$@    if false {@|a_partition_in_use_is_refreshed_and_survives_the_prune
//MUTANT partition-directory-never-refreshed|s@^        let _ = touch(own, now);$@@|a_refresh_moves_the_partition_directory_too
///
/// `now` is the caller's, so the bound itself is a case: a mark exactly one
/// [`USE_REFRESH`] old is not yet stale.
fn refresh_use(own: &Path, meta: &std::fs::Metadata, now: std::time::SystemTime) {
    let stale = meta
        .modified()
        .ok()
        .and_then(|modified| now.duration_since(modified).ok())
        .is_some_and(|age| age > USE_REFRESH);
    if stale {
        let _ = touch(&own.join(USE_MARK), now);
        let _ = touch(own, now);
    }
}

/// Set `path`'s modification time, file or directory, through the handle
/// [`crate::durable::open_handle`] opens for exactly that on every platform.
fn touch(path: &Path, at: std::time::SystemTime) -> std::io::Result<()> {
    crate::durable::open_handle(path).and_then(|file| file.set_modified(at))
}

/// The running binary's partition name: a short digest of its identity, which
/// is filesystem-safe whatever the identity spells. `None` for a binary that
/// cannot name itself.
fn partition() -> Option<&'static str> {
    static NAME: std::sync::OnceLock<Option<String>> = std::sync::OnceLock::new();
    NAME.get_or_init(|| {
        let digest = blake3::hash(running_binary()?.as_bytes()).to_hex();
        digest.as_str().get(..16).map(str::to_owned)
    })
    .as_deref()
}

/// Whether `name` is spelled as a partition.
fn is_partition(name: &str) -> bool {
    name.len() == 16 && name.bytes().all(|byte| byte.is_ascii_hexdigit())
}

/// Keep `own` and the most recently used partitions beside it up to
/// [`KEPT_PARTITIONS`], ranked by last use — the [`USE_MARK`]'s time, or the
/// directory's where a partition has no mark yet: least recently used goes
/// first. Remove the rest, and anything that is not a partition — the
/// flat layout entries were written in before partitions existed. Best-effort:
/// another process pruning the same directory, or one writing into a partition
/// removed here, costs a miss and never a wrong answer.
//MUTANT partition-bound-off-by-one|s@^    for (_, path) in partitions.into_iter().skip(KEPT_PARTITIONS - 1) {$@    for (_, path) in partitions.into_iter().skip(KEPT_PARTITIONS) {@|a_new_partition_keeps_its_neighbours_up_to_the_bound
//MUTANT partitions-evicted-most-recent-first|s@^    partitions.sort_by_key(\x7c(made, _)\x7c std::cmp::Reverse(\*made));$@    partitions.sort_by_key(\x7c(made, _)\x7c *made);@|a_partition_in_use_is_refreshed_and_survives_the_prune
//MUTANT partitions-ranked-by-directory|s@^        let made = std::fs::metadata(path.join(USE_MARK))$@        let made = std::fs::metadata(\&path)@|a_new_partition_keeps_its_neighbours_up_to_the_bound
fn prune(root: &Path, own: &str) {
    let Ok(entries) = std::fs::read_dir(root) else {
        return;
    };
    let mut partitions = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name == "CACHEDIR.TAG" || name == own {
            continue;
        }
        let path = entry.path();
        if !is_partition(&name) {
            let _ = if path.is_dir() {
                std::fs::remove_dir_all(&path)
            } else {
                std::fs::remove_file(&path)
            };
            continue;
        }
        let made = std::fs::metadata(path.join(USE_MARK))
            .or_else(|_| entry.metadata())
            .and_then(|meta| meta.modified())
            .unwrap_or(std::time::SystemTime::UNIX_EPOCH);
        partitions.push((made, path));
    }
    partitions.sort_by_key(|(made, _)| std::cmp::Reverse(*made));
    for (_, path) in partitions.into_iter().skip(KEPT_PARTITIONS - 1) {
        let _ = std::fs::remove_dir_all(path);
    }
}

/// The key for an entry: the running binary, a format tag the caller bumps when
/// its encoding changes, and every input the value is a function of.
#[must_use]
pub fn key(format: &str, inputs: &[&[u8]]) -> String {
    // Unnamed, the binary has no partition ([`root_under`]), so no entry it
    // could read or write is ever filed under the empty spelling here.
    let binary = running_binary().unwrap_or_default();
    let mut fields: Vec<&[u8]> = Vec::with_capacity(inputs.len() + 3);
    fields.push(format.as_bytes());
    fields.push(env!("CARGO_PKG_VERSION").as_bytes());
    fields.push(binary.as_bytes());
    fields.extend_from_slice(inputs);
    crate::identity::cache_key(&fields).to_hex()
}

/// The body stored at `path` under exactly `key`, or `None`.
///
/// The entry is `<key>\n<length> <blake3(body)>\n<body>`: the key decides
/// whether the entry answers this question at all, and the length and digest
/// decide whether the bytes are the ones written.
//MUTANT torn-entry-served|s@^    if check != integrity(body).as_bytes() {$@    if false {@|a_torn_entry_is_a_miss_not_a_wrong_answer
#[must_use]
pub fn read(path: &Path, key: &str) -> Option<Vec<u8>> {
    let mut bytes = std::fs::read(path).ok()?;
    let (head, rest) = split_line(&bytes)?;
    if head != key.as_bytes() {
        return None;
    }
    let (check, body) = split_line(rest)?;
    if check != integrity(body).as_bytes() {
        return None;
    }
    // The body is the read buffer's tail: hand it back in place rather than
    // copying a whole entry on every hit.
    let at = bytes.len() - body.len();
    bytes.drain(..at);
    Some(bytes)
}

/// Store `body` at `path` under `key`, atomically and unsynced.
pub fn write(path: &Path, key: &str, body: &[u8]) {
    if let Some(parent) = path.parent()
        && std::fs::create_dir_all(parent).is_err()
    {
        return;
    }
    let check = integrity(body);
    let mut bytes = Vec::with_capacity(key.len() + check.len() + 2 + body.len());
    bytes.extend_from_slice(key.as_bytes());
    bytes.push(b'\n');
    bytes.extend_from_slice(check.as_bytes());
    bytes.push(b'\n');
    bytes.extend_from_slice(body);
    let _ = crate::durable::replace_as(path, bytes, crate::durable::Persist::Atomic);
}

/// The length and digest a body is checked against on read.
fn integrity(body: &[u8]) -> String {
    format!("{} {}", body.len(), blake3::hash(body).to_hex())
}

fn split_line(bytes: &[u8]) -> Option<(&[u8], &[u8])> {
    let at = bytes.iter().position(|byte| *byte == b'\n')?;
    Some((bytes.get(..at)?, bytes.get(at + 1..)?))
}

/// The running binary's identity: its linker build ID where the image carries
/// one, else its stat tuple. Computed once per process. `None` when neither
/// can be read: every such binary would share one empty identity, and an
/// upgrade would read its predecessor's entries (code review of CLOUD-2315).
#[must_use]
pub fn running_binary() -> Option<&'static str> {
    static IDENTITY: std::sync::OnceLock<Option<String>> = std::sync::OnceLock::new();
    IDENTITY
        .get_or_init(|| {
            let image = running_image();
            if let Some(id) = image
                .as_deref()
                .and_then(read_head)
                .and_then(|head| build_id(&head))
            {
                return Some(format!("build-id:{}", hex(&id)));
            }
            image.as_deref().and_then(stat_identity)
        })
        .as_deref()
}

/// The file the running code was mapped from. On Linux `/proc/self/exe` names
/// the running inode even after the path was replaced on disk, which
/// `current_exe` resolved to a path cannot.
fn running_image() -> Option<PathBuf> {
    let proc = Path::new("/proc/self/exe");
    if proc.exists() {
        return Some(proc.to_path_buf());
    }
    std::env::current_exe().ok()
}

/// How much of the image is read to find a build ID: the ELF program headers
/// and their notes, or the Mach-O load commands, sit at the front of the file.
const HEAD_BYTES: u64 = 64 * 1024;

fn read_head(path: &Path) -> Option<Vec<u8>> {
    let mut head = Vec::new();
    std::fs::File::open(path)
        .ok()?
        .take(HEAD_BYTES)
        .read_to_end(&mut head)
        .ok()?;
    Some(head)
}

/// The linker-inserted build ID in `head`: an ELF `NT_GNU_BUILD_ID` note or a
/// Mach-O `LC_UUID`. `None` for any other image, or one carrying neither.
#[must_use]
pub fn build_id(head: &[u8]) -> Option<Vec<u8>> {
    if head.starts_with(b"\x7fELF") {
        return elf_build_id(head);
    }
    macho_uuid(head)
}

/// Read `width` bytes at `at` as an unsigned integer in the image's byte order.
fn uint(bytes: &[u8], at: usize, width: usize, little: bool) -> Option<u64> {
    let field = bytes.get(at..at.checked_add(width)?)?;
    let mut word = [0_u8; 8];
    let low = word.get_mut(8_usize.checked_sub(width)?..)?;
    low.copy_from_slice(field);
    if little {
        low.reverse();
    }
    Some(u64::from_be_bytes(word))
}

fn elf_build_id(head: &[u8]) -> Option<Vec<u8>> {
    const PT_NOTE: u64 = 4;
    let wide = match head.get(4)? {
        1 => false,
        2 => true,
        _ => return None,
    };
    let little = match head.get(5)? {
        1 => true,
        2 => false,
        _ => return None,
    };
    let word = if wide { 8 } else { 4 };
    let (phoff_at, entsize_at, count_at) = if wide {
        (0x20, 0x36, 0x38)
    } else {
        (0x1c, 0x2a, 0x2c)
    };
    let phoff = usize::try_from(uint(head, phoff_at, word, little)?).ok()?;
    let entsize = usize::try_from(uint(head, entsize_at, 2, little)?).ok()?;
    let count = usize::try_from(uint(head, count_at, 2, little)?).ok()?;
    let (offset_at, size_at) = if wide { (8, 32) } else { (4, 16) };
    for index in 0..count {
        let header = phoff.checked_add(index.checked_mul(entsize)?)?;
        if uint(head, header, 4, little)? != PT_NOTE {
            continue;
        }
        // ONE SEGMENT AT A TIME: a note segment past the head, or a malformed
        // one, is skipped rather than ending the search, so a build-id note in a
        // later segment is still found (code review of CLOUD-2315).
        let segment = (
            usize::try_from(uint(head, header + offset_at, word, little)?).ok()?,
            usize::try_from(uint(head, header + size_at, word, little)?).ok()?,
        );
        if let Some(id) = build_id_note(head, segment, little) {
            return Some(id);
        }
    }
    None
}

/// The GNU build-id note in the note segment at `(start, size)` within `head`,
/// or `None` where the segment is outside it, malformed, or carries none.
//MUTANT build-id-search-stops-at-a-bad-segment|s@^        if let Some(id) = build_id_note(head, segment, little) {$@        if let Some(id) = Some(build_id_note(head, segment, little)?) {@|a_build_id_after_an_unreadable_note_segment_is_found
fn build_id_note(head: &[u8], (start, size): (usize, usize), little: bool) -> Option<Vec<u8>> {
    const NT_GNU_BUILD_ID: u64 = 3;
    let notes = head.get(start..start.checked_add(size)?)?;
    let mut at = 0;
    while at + 12 <= notes.len() {
        let name_len = usize::try_from(uint(notes, at, 4, little)?).ok()?;
        let desc_len = usize::try_from(uint(notes, at + 4, 4, little)?).ok()?;
        let kind = uint(notes, at + 8, 4, little)?;
        let name_at = at + 12;
        let desc_at = name_at.checked_add(align4(name_len))?;
        let name = notes.get(name_at..name_at.checked_add(name_len)?)?;
        if kind == NT_GNU_BUILD_ID && name == b"GNU\0" {
            return notes
                .get(desc_at..desc_at.checked_add(desc_len)?)
                .map(<[u8]>::to_vec);
        }
        at = desc_at.checked_add(align4(desc_len))?;
    }
    None
}

fn align4(len: usize) -> usize {
    len.div_ceil(4) * 4
}

fn macho_uuid(head: &[u8]) -> Option<Vec<u8>> {
    const LC_UUID: u64 = 0x1b;
    let little = match head.get(..4)? {
        [0xcf | 0xce, 0xfa, 0xed, 0xfe] => true,
        [0xfe, 0xed, 0xfa, 0xcf | 0xce] => false,
        _ => return None,
    };
    let wide = matches!(head.first()?, 0xcf) || matches!(head.get(3)?, 0xcf);
    let count = usize::try_from(uint(head, 16, 4, little)?).ok()?;
    let mut at = if wide { 32 } else { 28 };
    for _ in 0..count {
        let command = uint(head, at, 4, little)?;
        let size = usize::try_from(uint(head, at + 4, 4, little)?).ok()?;
        if command == LC_UUID {
            return head.get(at + 8..at + 24).map(<[u8]>::to_vec);
        }
        if size == 0 {
            return None;
        }
        at = at.checked_add(size)?;
    }
    None
}

/// One file's stat stamp, for a cache whose whole point is NOT to read the file
/// (`crate::epoch`), and for an image that carries no build ID.
///
/// `fields` is the tuple a key is built over: inode and ctime beside size and
/// mtime, the set Bazel's digest cache needed after a tar with fixed mtimes and
/// an inode-preserving `mv` read stale. ctime cannot be set from userspace, so a
/// `touch -r` or `cp -p` cannot restore it.
///
/// `changed` is the later of mtime and ctime, for [`Stamp::racily_clean`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stamp {
    /// The tuple, rendered for a key.
    pub fields: String,
    /// The later of the file's mtime and ctime, since the epoch.
    pub changed: std::time::Duration,
}

//MUTANT racy-window-unwidened|s@^        self.changed.saturating_add(TIMESTAMP_TICK) >= written$@        self.changed >= written@|a_change_within_one_coarse_tick_is_racy
impl Stamp {
    /// GIT'S RACY-TIMESTAMP RULE (`Documentation/technical/racy-git`): a file
    /// whose change time is not clearly older than the moment its entry was
    /// written may have changed again within the same timestamp tick, invisibly
    /// to every field above, so its entry must not be believed.
    ///
    /// **WIDENED BY [`TIMESTAMP_TICK`]** (code review of CLOUD-2315). `written`
    /// is a fine user-space clock and `changed` is the kernel's coarse one —
    /// jiffy-granular on Linux, 1-2 s on HFS+, FAT and some NFS — so a rewrite in
    /// the same tick can carry a `changed` EARLIER than `written`. git compares
    /// against the index file's own filesystem time to dodge that; with a
    /// user-space `written`, the window has to cover the coarsest tick instead.
    /// A file changed in the last two seconds is always re-read.
    #[must_use]
    pub fn racily_clean(&self, written: std::time::Duration) -> bool {
        self.changed.saturating_add(TIMESTAMP_TICK) >= written
    }
}

/// The coarsest file-timestamp granularity [`Stamp::racily_clean`] allows for:
/// FAT's two seconds, which also covers HFS+ and coarse NFS.
pub const TIMESTAMP_TICK: std::time::Duration = std::time::Duration::from_secs(2);

/// The stamp for `path`, or `None` when it cannot be stat'ed — a miss for every
/// caller, never a stamp that pretends.
#[must_use]
pub fn stamp(path: &Path) -> Option<Stamp> {
    let meta = std::fs::metadata(path).ok()?;
    let since = |time: std::time::SystemTime| time.duration_since(std::time::UNIX_EPOCH).ok();
    let modified = since(meta.modified().ok()?)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        let ctime = std::time::Duration::new(
            u64::try_from(meta.ctime()).ok()?,
            u32::try_from(meta.ctime_nsec()).ok()?,
        );
        Some(Stamp {
            fields: format!(
                "stat:{}:{}:{}:{}.{}:{}.{}",
                meta.dev(),
                meta.ino(),
                meta.size(),
                meta.mtime(),
                meta.mtime_nsec(),
                meta.ctime(),
                meta.ctime_nsec()
            ),
            changed: modified.max(ctime),
        })
    }
    // Without a device and inode, length and times are all a stat says, and two
    // different files can share them: the path joins them, so the fields still
    // name one file (code review of CLOUD-2315).
    #[cfg(not(unix))]
    {
        let created = meta.created().ok().and_then(since).unwrap_or_default();
        Some(Stamp {
            fields: format!(
                "stat:{}:{}:{}:{}",
                path.display(),
                meta.len(),
                modified.as_nanos(),
                created.as_nanos()
            ),
            changed: modified.max(created),
        })
    }
}

/// Now, as a duration since the epoch, for an entry's write time.
#[must_use]
pub fn now() -> std::time::Duration {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
}

/// `path`'s [`Stamp::fields`], or `None` when it cannot be stat'ed.
pub(crate) fn stat_identity(path: &Path) -> Option<String> {
    stamp(path).map(|stamp| stamp.fields)
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut out, byte| {
            let _ = write!(out, "{byte:02x}");
            out
        })
}

#[cfg(test)]
#[expect(
    clippy::expect_used,
    reason = "a fixture that cannot be written is a broken test, not a reachable path"
)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        crate::scratch::scratch(&format!("cache-{name}"))
    }

    /// An entry answers only its own key, and only with the bytes written.
    #[test]
    fn an_entry_answers_its_own_key_with_its_own_bytes() {
        let dir = scratch("roundtrip");
        let path = dir.join("entry");
        write(&path, "key-a", b"body");
        assert_eq!(read(&path, "key-a").as_deref(), Some(&b"body"[..]));
        assert!(read(&path, "key-b").is_none(), "another key is a miss");
    }

    /// THE SELF-VALIDATING ENTRY: a body cut short or overwritten in place —
    /// what an unsynced write can leave after a power failure — is a miss.
    #[test]
    fn a_torn_entry_is_a_miss_not_a_wrong_answer() {
        let dir = scratch("torn");
        let path = dir.join("entry");
        write(&path, "key", b"the whole body");
        let mut bytes = std::fs::read(&path).expect("read");
        bytes.truncate(bytes.len() - 3);
        std::fs::write(&path, &bytes).expect("tear");
        assert!(read(&path, "key").is_none(), "a truncated body is a miss");
        write(&path, "key", b"the whole body");
        let mut bytes = std::fs::read(&path).expect("read");
        let last = bytes.len() - 1;
        bytes[last] = 0;
        std::fs::write(&path, &bytes).expect("zero");
        assert!(read(&path, "key").is_none(), "a zeroed byte is a miss");
    }

    /// The key moves with every input and with the format tag.
    #[test]
    fn every_input_and_the_format_move_the_key() {
        assert_ne!(key("f", &[b"a"]), key("f", &[b"b"]), "another input");
        assert_ne!(key("f", &[b"a"]), key("g", &[b"a"]), "another format");
        assert_ne!(
            key("f", &[b"ab", b"c"]),
            key("f", &[b"a", b"bc"]),
            "framing"
        );
    }

    /// THIS BUILD'S IMAGE CARRIES A BUILD ID, and the identity is read from it
    /// rather than from a timestamp. A platform whose linker emits none falls
    /// back to the stat tuple, so the assertion is scoped to ELF and Mach-O.
    #[test]
    fn the_running_binary_is_identified_by_its_code() {
        let identity = running_binary().expect("the binary names itself");
        if cfg!(any(target_os = "linux", target_os = "macos")) {
            assert!(
                identity.starts_with("build-id:"),
                "identified by its build id, not its timestamp: {identity}"
            );
        } else {
            assert!(!identity.is_empty(), "something identifies the binary");
        }
    }

    /// A hand-built ELF note is found; an image with none answers `None`.
    #[test]
    fn an_elf_build_id_note_is_read_and_its_absence_is_none() {
        let mut image = vec![0_u8; 0x200];
        image[..4].copy_from_slice(b"\x7fELF");
        image[4] = 2;
        image[5] = 1;
        image[0x20..0x28].copy_from_slice(&64_u64.to_le_bytes());
        image[0x36..0x38].copy_from_slice(&56_u16.to_le_bytes());
        image[0x38..0x3a].copy_from_slice(&1_u16.to_le_bytes());
        image[64..68].copy_from_slice(&4_u32.to_le_bytes());
        image[72..80].copy_from_slice(&0x100_u64.to_le_bytes());
        image[96..104].copy_from_slice(&24_u64.to_le_bytes());
        image[0x100..0x104].copy_from_slice(&4_u32.to_le_bytes());
        image[0x104..0x108].copy_from_slice(&8_u32.to_le_bytes());
        image[0x108..0x10c].copy_from_slice(&3_u32.to_le_bytes());
        image[0x10c..0x110].copy_from_slice(b"GNU\0");
        image[0x110..0x118].copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(build_id(&image), Some(vec![1, 2, 3, 4, 5, 6, 7, 8]));
        image[0x108..0x10c].copy_from_slice(&1_u32.to_le_bytes());
        assert_eq!(
            build_id(&image),
            None,
            "a note of another kind is not an id"
        );
        assert_eq!(build_id(b"not an image"), None);
    }

    /// A note segment the head does not reach is skipped, not the end of the
    /// search: the build ID in the next segment is still found.
    #[test]
    fn a_build_id_after_an_unreadable_note_segment_is_found() {
        let mut image = vec![0_u8; 0x200];
        image[..4].copy_from_slice(b"\x7fELF");
        image[4] = 2;
        image[5] = 1;
        image[0x20..0x28].copy_from_slice(&64_u64.to_le_bytes());
        image[0x36..0x38].copy_from_slice(&56_u16.to_le_bytes());
        image[0x38..0x3a].copy_from_slice(&2_u16.to_le_bytes());
        // Segment one: a PT_NOTE far past the 0x200-byte head.
        image[64..68].copy_from_slice(&4_u32.to_le_bytes());
        image[72..80].copy_from_slice(&0x10_000_u64.to_le_bytes());
        image[96..104].copy_from_slice(&24_u64.to_le_bytes());
        // Segment two: a PT_NOTE carrying the build ID.
        image[120..124].copy_from_slice(&4_u32.to_le_bytes());
        image[128..136].copy_from_slice(&0x100_u64.to_le_bytes());
        image[152..160].copy_from_slice(&24_u64.to_le_bytes());
        image[0x100..0x104].copy_from_slice(&4_u32.to_le_bytes());
        image[0x104..0x108].copy_from_slice(&8_u32.to_le_bytes());
        image[0x108..0x10c].copy_from_slice(&3_u32.to_le_bytes());
        image[0x10c..0x110].copy_from_slice(b"GNU\0");
        image[0x110..0x118].copy_from_slice(&[8, 7, 6, 5, 4, 3, 2, 1]);
        assert_eq!(build_id(&image), Some(vec![8, 7, 6, 5, 4, 3, 2, 1]));
    }

    /// Fails by: a 32-bit or big-endian image's layout read as the 64-bit
    /// little-endian one's.
    #[test]
    fn a_narrow_big_endian_elf_note_is_read() {
        let mut image = vec![0_u8; 0x200];
        image[..4].copy_from_slice(b"\x7fELF");
        image[4] = 1;
        image[5] = 2;
        image[0x1c..0x20].copy_from_slice(&52_u32.to_be_bytes());
        image[0x2a..0x2c].copy_from_slice(&32_u16.to_be_bytes());
        image[0x2c..0x2e].copy_from_slice(&1_u16.to_be_bytes());
        image[52..56].copy_from_slice(&4_u32.to_be_bytes());
        image[56..60].copy_from_slice(&0x100_u32.to_be_bytes());
        image[68..72].copy_from_slice(&24_u32.to_be_bytes());
        image[0x100..0x104].copy_from_slice(&4_u32.to_be_bytes());
        image[0x104..0x108].copy_from_slice(&8_u32.to_be_bytes());
        image[0x108..0x10c].copy_from_slice(&3_u32.to_be_bytes());
        image[0x10c..0x110].copy_from_slice(b"GNU\0");
        image[0x110..0x118].copy_from_slice(&[1, 3, 5, 7, 2, 4, 6, 8]);
        assert_eq!(build_id(&image), Some(vec![1, 3, 5, 7, 2, 4, 6, 8]));
    }

    /// A Mach-O image of `magic`, its header `header` bytes long, carrying an
    /// `LC_SEGMENT_64` and then an `LC_UUID` of `uuid`.
    fn macho(magic: [u8; 4], little: bool, header: usize, uuid: [u8; 16]) -> Vec<u8> {
        let word = |value: u32| {
            if little {
                value.to_le_bytes()
            } else {
                value.to_be_bytes()
            }
        };
        let mut image = vec![0_u8; 0x100];
        image[..4].copy_from_slice(&magic);
        image[16..20].copy_from_slice(&word(2));
        image[header..header + 4].copy_from_slice(&word(0x19));
        image[header + 4..header + 8].copy_from_slice(&word(16));
        let at = header + 16;
        image[at..at + 4].copy_from_slice(&word(0x1b));
        image[at + 4..at + 8].copy_from_slice(&word(24));
        image[at + 8..at + 24].copy_from_slice(&uuid);
        image
    }

    /// Fails by: either byte order, or either header width, read wrong, or the
    /// walk past a load command stepping by anything but its size.
    #[test]
    fn a_macho_uuid_is_read_in_every_byte_order_and_width() {
        let uuid: [u8; 16] = std::array::from_fn(|n| u8::try_from(n).expect("small") + 1);
        for (magic, little, header) in [
            ([0xcf, 0xfa, 0xed, 0xfe], true, 32),
            ([0xce, 0xfa, 0xed, 0xfe], true, 28),
            ([0xfe, 0xed, 0xfa, 0xcf], false, 32),
            ([0xfe, 0xed, 0xfa, 0xce], false, 28),
        ] {
            assert_eq!(
                build_id(&macho(magic, little, header, uuid)),
                Some(uuid.to_vec()),
                "{magic:x?}"
            );
        }
    }

    /// Fails by: an identity that is not the bytes' hex, or a stat identity that
    /// is not the file's stamp.
    #[test]
    fn an_identity_spells_its_bytes_or_its_stamp() {
        assert_eq!(hex(&[0x0a, 0xff, 0x00]), "0aff00");
        let dir = scratch("stat-identity");
        let file = dir.join("image");
        std::fs::write(&file, "x").expect("write");
        let identity = stat_identity(&file).expect("a stat");
        assert!(identity.starts_with("stat:"), "{identity}");
        assert_eq!(Some(identity), stamp(&file).map(|stamp| stamp.fields));
    }

    /// Fails by: a partition name admitted at another length or with a
    /// character that is not hex, or a head read that stops short of the
    /// declared bound.
    #[test]
    fn a_partition_is_sixteen_hex_digits_and_a_head_is_the_bound() {
        assert!(is_partition("0123456789abcdef"));
        assert!(!is_partition("0123456789abcdeg"));
        assert!(!is_partition("0123456789abcde"));
        let dir = scratch("head");
        let image = dir.join("image");
        std::fs::write(&image, vec![0_u8; 70_000]).expect("write");
        // Spelled rather than read from the constant, so the bound itself is pinned.
        assert_eq!(read_head(&image).expect("a head").len(), 64 * 1024);
    }

    /// Make `partition` with its use mark, the mark's time at [`stepped`]
    /// `step` (CLOUD-2361).
    fn marked(partition: &Path, step: u64) {
        std::fs::create_dir_all(partition).expect("partition");
        std::fs::File::create(partition.join(USE_MARK))
            .and_then(|file| file.set_modified(stepped(step)))
            .expect("age the mark");
    }

    /// `step` million seconds past the epoch: a higher step is more recent.
    fn stepped(step: u64) -> std::time::SystemTime {
        std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_000_000 * step)
    }

    /// A partition a binary keeps hitting is marked used, so a later binary's
    /// prune ranks it as recent rather than by when it was first created.
    #[test]
    fn a_partition_in_use_is_refreshed_and_survives_the_prune() {
        let dir = scratch("partition-use");
        let own = root_under(&dir).expect("own partition");
        let root = own.parent().expect("the partition's directory");
        // Enough others that with `own` the directory is one past the bound.
        let others = partition_names(KEPT_PARTITIONS - 1);
        for (step, name) in (2..).zip(&others) {
            marked(&root.join(name), step);
        }
        marked(&own, 1);
        let _ = root_under(&dir).expect("a hit");
        prune(root, "ffffffffffffffff");
        assert!(own.is_dir(), "the partition in use survives a later prune");
        assert!(
            !root.join(&others[0]).exists(),
            "the least recently used partition goes instead"
        );
    }

    /// A partition whose mark was lost is answered through the cold path, which
    /// gives it one (CLOUD-2361).
    #[test]
    fn a_partition_without_a_mark_gains_one() {
        let dir = scratch("partition-unmarked");
        let own = dir
            .join("cache")
            .join(partition().expect("this binary names itself"));
        std::fs::create_dir_all(&own).expect("an unmarked partition");
        assert_eq!(root_under(&dir).as_deref(), Some(own.as_path()));
        assert!(own.join(USE_MARK).is_file(), "the partition gains its mark");
    }

    /// A partition whose mark cannot be made is served, and does not prune: a
    /// scan per call is the cost the warm path exists to avoid (CLOUD-2361).
    #[test]
    fn a_partition_that_cannot_be_marked_does_not_prune() {
        let dir = scratch("partition-unmarkable");
        let root = dir.join("cache");
        let own = root.join(partition().expect("this binary names itself"));
        // A directory where the mark belongs: no file can be made there.
        std::fs::create_dir_all(own.join(USE_MARK)).expect("an unmarkable partition");
        let others = partition_names(KEPT_PARTITIONS);
        for (step, name) in (1..).zip(&others) {
            marked(&root.join(name), step);
        }
        assert_eq!(root_under(&dir).as_deref(), Some(own.as_path()));
        assert!(
            others.iter().all(|name| root.join(name).is_dir()),
            "nothing is pruned past the bound"
        );
    }

    /// A stale hit moves the partition DIRECTORY's time as well as the mark's,
    /// so a release before CLOUD-2361, which ranks by the directory, still reads
    /// the partition as in use.
    #[test]
    fn a_refresh_moves_the_partition_directory_too() {
        let dir = scratch("partition-directory");
        let own = root_under(&dir).expect("own partition");
        marked(&own, 1);
        touch(&own, stepped(1)).expect("age the directory");
        let _ = root_under(&dir).expect("a hit");
        let moved = std::fs::metadata(&own)
            .and_then(|meta| meta.modified())
            .expect("the directory's time");
        assert!(moved > stepped(1), "the directory reads as just used");
    }

    /// A mark exactly [`USE_REFRESH`] old is not yet stale, and one a second
    /// older is: the bound is exclusive.
    #[test]
    fn a_mark_at_the_refresh_bound_is_left_alone() {
        let dir = scratch("partition-bound");
        let own = root_under(&dir).expect("own partition");
        let mark = own.join(USE_MARK);
        marked(&own, 1);
        let read = |path: &Path| {
            std::fs::metadata(path)
                .and_then(|meta| meta.modified())
                .expect("the mark's time")
        };
        let meta = std::fs::metadata(&mark).expect("the mark");
        refresh_use(&own, &meta, stepped(1) + USE_REFRESH);
        assert_eq!(read(&mark), stepped(1), "at the bound, untouched");
        let later = stepped(1) + USE_REFRESH + std::time::Duration::from_secs(1);
        refresh_use(&own, &meta, later);
        assert_eq!(read(&mark), later, "past it, refreshed to the caller's now");
    }

    /// `count` partition names, none of them this binary's.
    fn partition_names(count: usize) -> Vec<String> {
        (1..=count).map(|n| format!("{n:016x}")).collect()
    }

    /// A file whose coarse change time reads a moment BEFORE the entry's fine
    /// write time may still have changed within that tick: it is racy, and only
    /// one changed clearly earlier is believed.
    #[test]
    fn a_change_within_one_coarse_tick_is_racy() {
        let written = std::time::Duration::from_secs(1_000);
        let at = |changed: std::time::Duration| Stamp {
            fields: String::new(),
            changed,
        };
        assert!(at(std::time::Duration::from_millis(999_997)).racily_clean(written));
        assert!(!at(std::time::Duration::from_secs(940)).racily_clean(written));
    }

    /// The directory carries the tag backup tools look for, byte for byte.
    #[test]
    fn the_cache_root_is_tagged_for_backup_tools() {
        let dir = scratch("tag");
        let own = root_under(&dir).expect("root");
        let root = own
            .parent()
            .expect("the partition sits in the tagged directory");
        let tag = std::fs::read_to_string(root.join("CACHEDIR.TAG")).expect("tag");
        assert!(tag.starts_with("Signature: 8a477f597d28d172789f06886806bc55"));
    }

    /// CLOUD-2315: another binary's partition survives this one's creation, so
    /// two binaries never evict each other; partitions past the bound and the
    /// retired flat layout go.
    ///
    /// The marks are aged in the REVERSE of the order the partitions are made
    /// (CLOUD-2361), so ranking by directory and ranking by mark would evict
    /// different partitions: the one that goes is the oldest MARK, the last made.
    /// The directories' times are SET in creation order too: made microseconds
    /// apart they would tie on a coarse clock, and a tie leaves ranking by
    /// directory to `read_dir`'s order, which could evict the same partition as
    /// ranking by mark.
    #[test]
    fn a_new_partition_keeps_its_neighbours_up_to_the_bound() {
        let dir = scratch("partitions");
        let root = dir.join("cache");
        let others = partition_names(KEPT_PARTITIONS);
        // Made first to last; marked newest to oldest.
        for (made, name) in (1..).zip(&others) {
            let partition = root.join(name);
            marked(&partition, others.len() as u64 + 1 - made);
            touch(&partition, stepped(made)).expect("age the directory");
        }
        std::fs::create_dir_all(root.join("policy")).expect("flat layout");
        std::fs::write(root.join("epoch"), "flat").expect("flat layout");

        let own = root_under(&dir).expect("root");

        assert!(own.is_dir());
        assert!(!root.join("policy").exists(), "the flat layout is retired");
        assert!(!root.join("epoch").exists(), "the flat layout is retired");
        let kept = others
            .iter()
            .filter(|name| root.join(name).is_dir())
            .count();
        assert_eq!(kept, KEPT_PARTITIONS - 1, "own partition plus the bound");
        assert!(
            !root.join(&others[KEPT_PARTITIONS - 1]).exists(),
            "the least recently used partition past the bound goes"
        );
        assert!(root.join("CACHEDIR.TAG").exists());
    }
}
