//! Secret-class scanning: key custody, and the adapter that keeps a matched byte
//! from ever leaving the process (CLOUD-59).
//!
//! Detection is adopted prior art — a pinned scanner, run as a child process.
//! **Containment is this module's**, and it is the reason the adapter exists at
//! all rather than a `command` rule pointed at the same binary: the scanner
//! prints the secret it matched, and Batten copies what it sees into channels
//! that retain it (`-J` documents in CI logs, captures, receipts, the findings
//! journal). A scanner wrapped carelessly turns detection into disclosure.
//!
//! Two controls, and neither is a rule anybody has to remember:
//!
//! - **The span is opaque from the parse boundary onward.** Each match is
//!   wrapped into [`crate::identity::SecretSpan`] the moment it is read off the
//!   pipe, and that type has no route back to a `&str`. The unkeyed
//!   [`crate::identity::code_fingerprint`] therefore cannot be handed one — a
//!   compile error, not a recall obligation. Routing, not hashing, is where an
//!   offline-guessing oracle would be created (CLOUD-123).
//! - **The finding has nowhere to put one.** [`crate::rules::Finding`] carries a
//!   rule, a severity, a path, a line and an identity. There is no span field, so
//!   pointer-only output is structural in text and `-J` alike rather than a
//!   property of the renderer.
//!
//! # Key custody, wave one
//!
//! The HMAC key is 32 bytes of OS randomness, minted on first need under
//! [`crate::state::repo_state_dir`] — the out-of-tree root receipts and captures
//! already use — with the file mode `0600` and its directory `0700`. It is never
//! printed, never committed, and **machine-scoped**: two clones on two machines
//! mint two keys and therefore two identities for the same secret. That is the
//! documented trade absent a secret channel to distribute one through, and it is
//! a trade rather than a defect because the alternative — a key that travels —
//! is a key in a channel that retains it.
//!
//! The key id is date-styled and hashed into every tuple, so an identity is
//! self-describing about which key generation minted it and a later dual-HMAC
//! rotation has something to name the pair by.
//!
//! **What wave one deliberately does not ship**: rotation, and the loud forced
//! re-triage on key loss (never a silent re-mint). Both act on stored records,
//! and no secret-class identity reaches the store today — `state record` scans
//! with [`crate::rules::run_static`], which refuses every spawning kind. They
//! land with the journaling that gives them something to decide (CLOUD-529).
//! What wave one protects is the keyed `-J` emission.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::identity::IdentityKey;
use crate::waiver::Date;

/// The directory the key file lives in, under the repository's state directory.
const KEY_DIR: &str = "identity";

/// The key file's name.
const KEY_FILE: &str = "secret-key";

/// The key file's mode: owner read/write, nothing for anyone else.
#[cfg(unix)]
const KEY_MODE: u32 = 0o600;

/// The key directory's mode: owner only, so the file cannot be reached by
/// listing a world-executable parent.
#[cfg(unix)]
const KEY_DIR_MODE: u32 = 0o700;

/// The number of key bytes. HMAC-SHA256's block-size-matched key length, and the
/// length [`IdentityKey`] takes.
const KEY_BYTES: usize = 32;

/// Where the secret-identity key for `repo_root` lives.
///
/// # Errors
///
/// Propagates [`crate::state::repo_state_dir`]'s failure to resolve the
/// out-of-tree state directory.
pub fn key_path(repo_root: &Path) -> Result<PathBuf> {
    Ok(crate::state::repo_state_dir(repo_root)?
        .join(KEY_DIR)
        .join(KEY_FILE))
}

/// The repository's secret-identity key, minting one on first need.
///
/// `today` is injected rather than read here, the idiom
/// [`crate::waiver::apply`] uses for the same reason: the key id is a hash
/// input, so a function that read its own clock would make the identity of a
/// finding depend on when the key happened to be minted, and §6 byte-stability
/// would hold only within a day. Injected, the whole surface stays a pure
/// function of `(repo state, date)`.
///
/// **A mint happens at most once.** The file is created with `create_new`, so two
/// concurrent scans race to create and the loser reads the winner's key rather
/// than overwriting it — which matters because an overwrite would silently
/// re-mint every identity in the store under a key nobody knows was replaced.
///
/// # Errors
///
/// Returns an error when the state directory cannot be resolved or created, when
/// the OS randomness source fails, or when an existing key file is unreadable or
/// malformed. A malformed key file is **never** repaired by re-minting: that is
/// the silent re-mint the custody contract forbids, so it is reported and the run
/// stops.
pub fn load_or_mint(repo_root: &Path, today: Date) -> Result<IdentityKey> {
    load_or_mint_at(&key_path(repo_root)?, today)
}

/// [`load_or_mint`] against an explicit key path.
///
/// Split out for the reason [`crate::resolve`] splits `resolve_with`: the
/// location is an ambient input — an OS data directory selected from
/// environment variables — and a suite that had to move it would have to mutate
/// process-wide state, which this workspace cannot do at all (`unsafe_code =
/// "forbid"`, and `set_var` is unsafe). Injecting the path keeps the custody
/// logic testable in-process; [`load_or_mint`] is the one line that resolves it,
/// and the end-to-end suite covers that line over the compiled binary with its
/// own `XDG_DATA_HOME`.
///
/// # Errors
///
/// As [`load_or_mint`], minus the state-directory resolution.
pub fn load_or_mint_at(path: &Path, today: Date) -> Result<IdentityKey> {
    if let Some(existing) = read(path)? {
        return Ok(existing);
    }
    mint(path, today)
}

/// Read an existing key file, or `None` when there is none.
///
/// Errors are pointer-only: a malformed file is named by path and by which line
/// failed, never by its contents, because its contents are key material.
fn read(path: &Path) -> Result<Option<IdentityKey>> {
    let text = match fs::read_to_string(path) {
        Ok(text) => text,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => {
            return Err(err)
                .with_context(|| format!("read the secret-identity key {}", path.display()));
        }
    };

    let mut lines = text.lines();
    let id = lines.next().unwrap_or_default().trim();
    let hex = lines.next().unwrap_or_default().trim();
    if id.is_empty() {
        anyhow::bail!(
            "{}:1 malformed secret-identity key (no key id). Refusing to re-mint: a new key \
             silently re-identifies every secret-class finding already emitted under the old one.",
            path.display()
        );
    }
    let bytes = decode_key(hex).ok_or_else(|| {
        anyhow::anyhow!(
            "{}:2 malformed secret-identity key (expected {} lowercase hex characters). Refusing \
             to re-mint: a new key silently re-identifies every secret-class finding already \
             emitted under the old one.",
            path.display(),
            KEY_BYTES * 2
        )
    })?;
    Ok(Some(IdentityKey::new(id, bytes)))
}

/// Decode the key line, or `None` if it is not exactly the expected hex.
///
/// Strict for [`crate::identity::Fingerprint::from_hex`]'s reason: one byte
/// string must have one spelling, or a file that round-trips to the same key
/// could be written two ways.
fn decode_key(hex: &str) -> Option<[u8; KEY_BYTES]> {
    if hex.len() != KEY_BYTES * 2 {
        return None;
    }
    let mut bytes = [0u8; KEY_BYTES];
    for (index, pair) in hex.as_bytes().chunks_exact(2).enumerate() {
        let high = hex_digit(pair[0])?;
        let low = hex_digit(pair[1])?;
        bytes[index] = high * 16 + low;
    }
    Some(bytes)
}

/// One lowercase hex digit's value, or `None`. Uppercase is refused for the
/// one-spelling reason above.
fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

/// Mint a key, write it `0600`, and return it.
fn mint(path: &Path, today: Date) -> Result<IdentityKey> {
    let mut bytes = [0u8; KEY_BYTES];
    getrandom::fill(&mut bytes).map_err(|err| {
        anyhow::anyhow!(
            "the OS randomness source failed, so no secret-identity key was minted: {err}. \
             This is not a reason to fall back to a weaker source — a guessable key is a key \
             an attacker can re-derive."
        )
    })?;

    let id = key_id(today);
    let parent = path.parent().unwrap_or(path);
    create_dir_private(parent)?;
    if write_private(path, &format!("{id}\n{}\n", encode_key(&bytes)))? {
        return Ok(IdentityKey::new(id, bytes));
    }

    // Lost the create race: another process minted between this call's `read`
    // and its `create_new`. The winner's key is the repository's key, and the
    // bytes just generated are discarded unused. Re-reading rather than
    // retrying is the whole reason `create_new` is used — a truncating write
    // here would re-identify every finding already emitted under the winner's
    // key, which is exactly the silent re-mint custody forbids.
    read(path)?.ok_or_else(|| {
        anyhow::anyhow!(
            "{}: the secret-identity key was created and removed while minting",
            path.display()
        )
    })
}

/// The key id for a key minted on `today`: date-styled, matching the identity
/// versions beside it, so a generation reads as an event rather than a counter.
fn key_id(today: Date) -> String {
    format!("{:04}-{:02}-{:02}", today.year, today.month, today.day)
}

/// Lowercase hex, the spelling [`decode_key`] accepts.
fn encode_key(bytes: &[u8; KEY_BYTES]) -> String {
    let mut hex = String::with_capacity(KEY_BYTES * 2);
    for byte in bytes {
        // Both nibbles are < 16, so neither conversion can fail; the fallback
        // keeps the path total without an unwrap.
        hex.push(char::from_digit(u32::from(byte >> 4), 16).unwrap_or('0'));
        hex.push(char::from_digit(u32::from(byte & 0x0f), 16).unwrap_or('0'));
    }
    hex
}

/// Create `dir` (and its parents) with the private mode where the platform has
/// one.
///
/// The mode is set **after** creation rather than through a create-time mode,
/// because `create_dir_all` has no mode argument and the intermediate state is
/// an empty directory holding nothing yet. The file below is the one that must
/// never exist world-readable even briefly, and it is created with its mode.
fn create_dir_private(dir: &Path) -> Result<()> {
    fs::create_dir_all(dir)
        .with_context(|| format!("create the secret-identity key directory {}", dir.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(dir, fs::Permissions::from_mode(KEY_DIR_MODE)).with_context(|| {
            format!(
                "restrict the secret-identity key directory {} to its owner",
                dir.display()
            )
        })?;
    }
    Ok(())
}

/// Write `contents` to a file created `0600`. `Ok(false)` means the file already
/// existed and nothing was written.
///
/// **The mode is set at creation, not after**, on unix: a file created `0644` and
/// chmod'ed afterwards is world-readable for the window in between, and the
/// contents written into that window are the key. `create_new` is what turns a
/// concurrent mint into a read rather than an overwrite — the caller handles the
/// `false`.
///
/// On a platform without unix permissions the file is created with the same
/// exclusivity and the platform's own default ACL. Stated rather than silently
/// assumed: the `0600` claim is a unix claim.
fn write_private(path: &Path, contents: &str) -> Result<bool> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(KEY_MODE);
    }
    let mut file = match options.open(path) {
        Ok(file) => file,
        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => return Ok(false),
        Err(err) => {
            return Err(err)
                .with_context(|| format!("write the secret-identity key {}", path.display()));
        }
    };
    file.write_all(contents.as_bytes())
        .with_context(|| format!("write the secret-identity key {}", path.display()))?;
    file.sync_all()
        .with_context(|| format!("flush the secret-identity key {}", path.display()))?;
    Ok(true)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn date() -> Date {
        Date {
            year: 2026,
            month: 8,
            day: 13,
        }
    }

    /// A fresh key path under the system temp dir. Unit tests cannot use
    /// `CARGO_TARGET_TMPDIR` (integration-only) and cannot move the OS data
    /// directory (that takes `set_var`, which is unsafe and forbidden here), so
    /// the path is injected through [`load_or_mint_at`] instead.
    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join("batten-secrets-tests").join(name);
        let _ = fs::remove_dir_all(&dir);
        dir.join(KEY_DIR).join(KEY_FILE)
    }

    #[test]
    fn a_mint_is_owner_only_and_a_second_load_reuses_it() {
        let path = scratch("mint");
        let first = load_or_mint_at(&path, date()).unwrap();
        assert!(path.is_file(), "the mint wrote a key file");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            // Asserting the bits we set, not an enforcement the root sandbox
            // cannot produce — `.claude/rules/rust.md`'s premise rule. The claim
            // under test is "this file is created 0600", and that is exactly what
            // the mode word answers.
            let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, KEY_MODE, "the key file is owner-only");
            let dir_mode = fs::metadata(path.parent().unwrap())
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(dir_mode, KEY_DIR_MODE, "its directory is owner-only");
        }

        // A second call reads rather than re-mints. Compared through the id and
        // through a fingerprint, because the id alone is date-derived and would
        // agree across two different keys minted on the same day.
        let second = load_or_mint_at(&path, date()).unwrap();
        assert_eq!(first.id(), second.id());
        let span = crate::identity::SecretSpan::mint("token = \"x\"");
        assert_eq!(
            crate::identity::secret_code_fingerprint(&first, "r", "a.rs", &span).unwrap(),
            crate::identity::secret_code_fingerprint(&second, "r", "a.rs", &span).unwrap(),
        );
    }

    #[test]
    fn the_key_id_is_date_styled() {
        assert_eq!(key_id(date()), "2026-08-13");
        assert_eq!(
            key_id(Date {
                year: 2026,
                month: 12,
                day: 1
            }),
            "2026-12-01",
            "single digits are padded, so ids sort lexically"
        );
    }

    #[test]
    fn a_malformed_key_is_refused_rather_than_re_minted() {
        let path = scratch("malformed");
        load_or_mint_at(&path, date()).unwrap();
        let before = fs::read_to_string(&path).unwrap();

        fs::write(&path, "2026-08-13\nnot-hex\n").unwrap();
        let err = load_or_mint_at(&path, date()).unwrap_err().to_string();
        assert!(err.contains("malformed"), "{err}");
        assert!(
            err.contains("Refusing"),
            "the refusal states why it does not repair itself: {err}"
        );
        assert!(
            !err.contains("not-hex"),
            "pointer-only: the file's bytes are key material, so no error renders them: {err}"
        );

        // And the refusal left the file alone rather than replacing it.
        fs::write(&path, before).unwrap();
        assert!(load_or_mint_at(&path, date()).is_ok());
    }

    #[test]
    fn losing_the_create_race_reads_the_winners_key() {
        // `mint` directly, not `load_or_mint_at`, because the race is exactly the
        // window between that function's `read` and its `create_new`: a test
        // going through the front door would take the read path and never reach
        // the branch under test. Pre-creating the file *is* the other process.
        let path = scratch("race");
        let winner = load_or_mint_at(&path, date()).unwrap();
        let winner_bytes = fs::read_to_string(&path).unwrap();

        let loser = mint(&path, date()).unwrap();

        assert_eq!(loser.id(), winner.id());
        assert_eq!(
            fs::read_to_string(&path).unwrap(),
            winner_bytes,
            "the loser wrote nothing; a truncating write here would re-identify \
             every finding already emitted under the winner's key"
        );
        let span = crate::identity::SecretSpan::mint("token = \"x\"");
        assert_eq!(
            crate::identity::secret_code_fingerprint(&winner, "r", "a.rs", &span).unwrap(),
            crate::identity::secret_code_fingerprint(&loser, "r", "a.rs", &span).unwrap(),
            "and it returned the winner's key, not the bytes it had just generated"
        );
    }

    #[test]
    fn the_key_bytes_reach_no_rendering() {
        let path = scratch("redaction");
        let key = load_or_mint_at(&path, date()).unwrap();
        let hex = fs::read_to_string(&path).unwrap();
        let hex = hex.lines().nth(1).unwrap().to_owned();

        let rendered = format!("{key:?}");
        assert!(!rendered.contains(&hex), "no key material in a Debug");
        // The first byte's own two nibbles, as a weaker but independent check:
        // a partial leak is a leak, and a whole-string search would miss one.
        assert!(!rendered.contains(&hex[..2]) || rendered.contains("<redacted>"));
    }

    #[test]
    fn a_round_trip_of_the_key_encoding_is_lossless_and_single_spelled() {
        let bytes = [0xABu8; KEY_BYTES];
        let hex = encode_key(&bytes);
        assert_eq!(hex.len(), KEY_BYTES * 2);
        assert_eq!(decode_key(&hex), Some(bytes));
        assert_eq!(
            decode_key(&hex.to_uppercase()),
            None,
            "uppercase is a second spelling of one key, so it is refused"
        );
        assert_eq!(decode_key(&hex[..62]), None, "a short key is not a key");
    }
}
