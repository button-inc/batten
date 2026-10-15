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

/// How many binaries' partitions one cache directory keeps.
const KEPT_PARTITIONS: usize = 4;

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
/// The warm path pays one `stat`. A new partition is the rare path: it tags the
/// directory for backup tools ([`CACHEDIR_TAG`]) and [`prune`]s, so the
/// directory holds at most [`KEPT_PARTITIONS`] binaries.
//MUTANT partitions-never-pruned|s@^    prune(\&root, name);$@@|a_new_partition_keeps_its_neighbours_up_to_the_bound
#[must_use]
pub fn root_under(parent: &Path) -> Option<PathBuf> {
    let root = parent.join("cache");
    let name = partition();
    let own = root.join(name);
    if own.is_dir() {
        return Some(own);
    }
    std::fs::create_dir_all(&own).ok()?;
    let tag = root.join("CACHEDIR.TAG");
    if !tag.exists() {
        let _ = crate::durable::replace_as(&tag, CACHEDIR_TAG, crate::durable::Persist::Atomic);
    }
    prune(&root, name);
    Some(own)
}

/// The running binary's partition name: a short digest of its identity, which
/// is filesystem-safe whatever the identity spells.
fn partition() -> &'static str {
    static NAME: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    NAME.get_or_init(|| {
        let digest = blake3::hash(running_binary().as_bytes()).to_hex();
        digest.as_str().get(..16).unwrap_or_default().to_owned()
    })
}

/// Whether `name` is spelled as a partition.
fn is_partition(name: &str) -> bool {
    name.len() == 16 && name.bytes().all(|byte| byte.is_ascii_hexdigit())
}

/// Keep `own` and the newest partitions beside it up to [`KEPT_PARTITIONS`],
/// newest by when each was created; remove the rest, and anything that is not a
/// partition — the flat layout entries were written in before partitions
/// existed. Best-effort: another process pruning the same directory, or one
/// writing into a partition removed here, costs a miss and never a wrong answer.
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
        let made = entry
            .metadata()
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
    let binary = running_binary();
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
    let bytes = std::fs::read(path).ok()?;
    let (head, rest) = split_line(&bytes)?;
    if head != key.as_bytes() {
        return None;
    }
    let (check, body) = split_line(rest)?;
    if check != integrity(body).as_bytes() {
        return None;
    }
    Some(body.to_vec())
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
/// one, else its stat tuple. Computed once per process.
#[must_use]
pub fn running_binary() -> &'static str {
    static IDENTITY: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    IDENTITY.get_or_init(|| {
        let image = running_image();
        if let Some(id) = image
            .as_deref()
            .and_then(read_head)
            .and_then(|head| build_id(&head))
        {
            return format!("build-id:{}", hex(&id));
        }
        image.as_deref().and_then(stat_identity).unwrap_or_default()
    })
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
    let mut value: u64 = 0;
    for index in 0..width {
        let byte = if little {
            field.get(width - 1 - index)?
        } else {
            field.get(index)?
        };
        value = (value << 8) | u64::from(*byte);
    }
    Some(value)
}

fn elf_build_id(head: &[u8]) -> Option<Vec<u8>> {
    const PT_NOTE: u64 = 4;
    const NT_GNU_BUILD_ID: u64 = 3;
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
        let start = usize::try_from(uint(head, header + offset_at, word, little)?).ok()?;
        let size = usize::try_from(uint(head, header + size_at, word, little)?).ok()?;
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

impl Stamp {
    /// GIT'S RACY-TIMESTAMP RULE (`Documentation/technical/racy-git`): a file
    /// whose change time is not strictly older than the moment its entry was
    /// written may have changed again within the same timestamp tick, invisibly
    /// to every field above, so its entry must not be believed. Strict, so a
    /// filesystem with coarse timestamps errs to a recompute, never a stale hit.
    #[must_use]
    pub fn racily_clean(&self, written: std::time::Duration) -> bool {
        self.changed >= written
    }
}

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
    #[cfg(not(unix))]
    {
        let created = meta.created().ok().and_then(since).unwrap_or_default();
        Some(Stamp {
            fields: format!(
                "stat:{}:{}:{}",
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

fn stat_identity(path: &Path) -> Option<String> {
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
        let dir = std::env::temp_dir().join(format!("batten-cache-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch");
        dir
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
        let identity = running_binary();
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
    /// Compiled everywhere; AGED on unix only. Ageing a directory opens it as a
    /// file, which Windows refuses without a backup-semantics flag `std` does not
    /// expose, so there the partitions share a creation time and the case holds
    /// the bound alone — which one goes is then the platform's tie.
    #[test]
    fn a_new_partition_keeps_its_neighbours_up_to_the_bound() {
        let aged = cfg!(unix);
        let dir = scratch("partitions");
        let root = dir.join("cache");
        let others = [
            "0000000000000001",
            "0000000000000002",
            "0000000000000003",
            "0000000000000004",
        ];
        for (age, name) in others.iter().enumerate() {
            let path = root.join(name);
            std::fs::create_dir_all(&path).expect("partition");
            if aged {
                let made = std::time::SystemTime::UNIX_EPOCH
                    + std::time::Duration::from_secs(1_000_000 * (age as u64 + 1));
                std::fs::File::open(&path)
                    .and_then(|file| file.set_modified(made))
                    .expect("age the partition");
            }
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
        if aged {
            assert!(
                !root.join(others[0]).exists(),
                "the oldest partition past the bound goes"
            );
        }
        assert!(root.join("CACHEDIR.TAG").exists());
    }
}
