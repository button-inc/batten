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
//! # Key custody, wave two: rotation and loss (CLOUD-529)
//!
//! Wave one shipped mint-and-emit only, because rotation and the loud key-loss
//! event both act on **stored records** and nothing secret-class could reach the
//! store: `state record` scans with [`crate::rules::run_static`], which refuses
//! every spawning kind. The enforce surface journals now, so both have something to
//! decide.
//!
//! **This module holds the keys and reads no store**, and the split is the
//! invariant rather than a layering preference: what keying buys is that the key is
//! unreachable from the digests it protects, and a module that opened the store
//! would be one edit from spending it. So the store-side half —
//! `reconcile_secret_custody` — lives beside the store and never sees a key byte,
//! and the two meet through [`Event`], the append-only ledger beside the key file.
//!
//! The ledger exists because the key id is *inside* every identity's HMAC
//! preimage. Self-describing is not readable: no stored fingerprint can be asked
//! which generation minted it, and that is exactly the question rotation and loss
//! turn on.
//!
//! [`rotate`] holds **two** generations and opens a window rather than performing a
//! write, because the new fingerprint is an HMAC over a span and no span is stored
//! anywhere — so the dual-HMAC pair is computable only inside a scan, while both
//! keys are held. Key loss is the other branch and never a degraded rotation: its
//! predicate is [`orphaned_key_ids`], ledger against file, because "the key file is
//! missing" is indistinguishable from a repository that never scanned.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use serde::{Deserialize, Serialize};

use crate::error::UsageError;
use crate::identity::{Fingerprint, IdentityKey, SecretSpan};
use crate::provision::Provision;
use crate::refusal::{Fix, Refusal};
use crate::rules::{Finding, Rule};
use crate::waiver::Date;

/// The `[[provision]]` entry this kind runs.
///
/// A constant rather than a rule column, because the kind permits no new column
/// (CLOUD-59): a `tool = "..."` key would let one config point the secret kind at
/// an arbitrary binary and read its output as secret spans, which is a wider
/// capability than "scan for credentials" and a worse one to hand a config file.
/// The manifest still owns the version, the URL and the checksum — this only
/// fixes *which entry* is the scanner.
pub const SCANNER: &str = "ripsecrets";

/// The verb that installs the scanner, named once so the refusal and the
/// documentation cannot disagree.
const PROVISION_VERB: &str = "batten provision apply";

/// The scanner's flags, pinned here beside the parser that reads their output.
///
/// `--only-matching` is **not** an option: it is what makes the third output
/// field the matched literal alone rather than the whole source line. The span
/// this kind hashes has to be the literal, because
/// [`crate::identity::secret_code_fingerprint`] forces `Verbatim` normalization —
/// a whole-line span would fold every edit elsewhere on the line into the
/// secret's identity, re-minting a finding nobody changed.
const SCANNER_FLAGS: &[&str] = &["--only-matching"];

/// The scanner's exit codes, pinned in one place and cross-checked against the
/// parse count (CLOUD-59's fail-closed clause).
///
/// Measured against ripsecrets 0.1.11 rather than assumed:
///
/// | code | meaning |
/// | ---- | ------- |
/// | 0    | clean — no secret found |
/// | 1    | one or more secrets found |
/// | 2    | the tool itself failed |
///
/// Anything else, and any signal, is neither verdict.
const EXIT_CLEAN: i32 = 0;
const EXIT_FOUND: i32 = 1;

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
    Ok(custody_at(path, today)?.into_current())
}

/// The keys this repository holds: the one identities are minted under, and the
/// retired one a rotation in flight is still joining against (CLOUD-529).
///
/// # Two generations, because rotation has a window
///
/// A rotation re-mints: the new identity for a secret is `HMAC(new key, span)`,
/// and the old one cannot be recomputed from the new one — that is what keying
/// buys. So joining old to new requires both keys **and** the span, which only
/// comes back from a scan. Rotation is therefore an operation with a window rather
/// than a single write, and the window is a state of the key file: two generations
/// held, the old one dropped once nothing is left keyed under it.
///
/// **Never more than two.** A third would need a rule for which pair a join names,
/// and an operator rotating twice before the first window closed would silently
/// orphan the middle generation — so [`rotate`] refuses while a window is open,
/// which is a refusal an operator can see rather than a loss they cannot.
#[derive(Debug)]
pub struct Custody {
    current: IdentityKey,
    retired: Option<IdentityKey>,
}

impl Custody {
    /// The key new identities are minted under.
    #[must_use]
    pub const fn current(&self) -> &IdentityKey {
        &self.current
    }

    /// The generation a rotation in flight is still joining against.
    #[must_use]
    pub const fn retired(&self) -> Option<&IdentityKey> {
        self.retired.as_ref()
    }

    /// Every key id this repository can still reproduce an identity under.
    ///
    /// Ids, never bytes: this is what travels into a message an operator reads.
    #[must_use]
    pub fn held_ids(&self) -> Vec<String> {
        let mut ids = vec![self.current.id().to_owned()];
        if let Some(retired) = &self.retired {
            ids.push(retired.id().to_owned());
        }
        ids
    }

    /// A witness per held generation: which *keys* these are, not which labels.
    ///
    /// # The id is not enough, and the gap is a real one rather than a hypothetical
    ///
    /// A key id is `key_id`'s date, so a key deleted and re-minted **on the same
    /// day** comes back under the same id carrying different bytes. Compared by id,
    /// that re-mint is invisible: the ledger names a generation, the file holds one
    /// with that name, and every identity in the store has silently stopped being
    /// reproducible. Which is precisely the silent re-mint the whole custody
    /// contract exists to refuse, arriving through the check meant to catch it.
    ///
    /// # Errors
    ///
    /// Propagates the fingerprint's failure, which is unreachable for this input.
    pub fn witnesses(&self) -> Result<Vec<String>> {
        let mut witnesses = vec![witness(&self.current)?];
        if let Some(retired) = &self.retired {
            witnesses.push(witness(retired)?);
        }
        Ok(witnesses)
    }

    /// Take the current key, discarding the retired one.
    #[must_use]
    pub fn into_current(self) -> IdentityKey {
        self.current
    }
}

/// [`custody`] against an explicit key path, minting on first need.
///
/// # Errors
///
/// As [`load_or_mint_at`].
pub fn custody_at(path: &Path, today: Date) -> Result<Custody> {
    if let Some(existing) = read(path)? {
        return Ok(existing);
    }
    let current = mint(path, today)?;
    // The ledger's first entry, and the reason the ledger exists: the key id is
    // inside the HMAC preimage, so it is not readable back off a stored
    // fingerprint. Without a record of which generations ever minted, a key file
    // that loses a generation is indistinguishable from one that never had it,
    // and "indistinguishable" resolves to a silent re-mint.
    append_event(
        path,
        &Event::Minted {
            key_id: current.id().to_owned(),
            witness: witness(&current)?,
        },
    )?;
    Ok(Custody {
        current,
        retired: None,
    })
}

/// The keys `repo_root` holds, minting one on first need.
///
/// # Errors
///
/// As [`load_or_mint`].
pub fn custody(repo_root: &Path, today: Date) -> Result<Custody> {
    custody_at(&key_path(repo_root)?, today)
}

/// Read an existing key file, or `None` when there is none.
///
/// Errors are pointer-only: a malformed file is named by path and by which line
/// failed, never by its contents, because its contents are key material.
fn read(path: &Path) -> Result<Option<Custody>> {
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

    // The retired generation, lines 3 and 4. Absent is the ordinary case — no
    // rotation in flight — but a HALF-present pair is not: an id with no key, or a
    // key with no id, is a generation we can neither use nor honestly declare
    // lost, so it is refused on the same terms as a malformed current key rather
    // than being dropped into the absent case.
    let retired_id = lines.next().map(str::trim);
    let retired_hex = lines.next().map(str::trim);
    let retired = match (retired_id, retired_hex) {
        (None, _) | (Some(""), None) => None,
        (Some(retired_id), Some(retired_hex)) if !retired_id.is_empty() => {
            let retired_bytes = decode_key(retired_hex).ok_or_else(|| {
                anyhow::anyhow!(
                    "{}:4 malformed retired secret-identity key (expected {} lowercase hex \
                     characters). Refusing to drop it: a rotation window closed by discarding a \
                     key is the silent re-mint custody forbids.",
                    path.display(),
                    KEY_BYTES * 2
                )
            })?;
            if retired_id == id {
                anyhow::bail!(
                    "{}:3 the retired secret-identity key shares the current key's id. Refusing: \
                     the id is inside every identity's preimage, so two generations under one id \
                     are conflated and a rotation join cannot name which is which.",
                    path.display()
                );
            }
            Some(IdentityKey::new(retired_id, retired_bytes))
        }
        _ => anyhow::bail!(
            "{}:3 malformed retired secret-identity key (an id without its key, or a key without \
             its id). Refusing to re-mint or to drop it.",
            path.display()
        ),
    };

    Ok(Some(Custody {
        current: IdentityKey::new(id, bytes),
        retired,
    }))
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
    for (index, pair) in hex.as_bytes().as_chunks::<2>().0.iter().enumerate() {
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
    read(path)?.map(Custody::into_current).ok_or_else(|| {
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

/// Replace an existing key file's contents, atomically, keeping its mode.
///
/// The counterpart to [`write_private`]'s `create_new`, and the split is the
/// point: minting must never overwrite, and rotation must never half-write. A
/// truncating write of a file holding two generations that failed midway would
/// leave a file with one generation and no record of which — so the new contents
/// are staged beside it and renamed over, which is either the old file or the new
/// one and never a mixture.
fn replace_private(path: &Path, contents: &str) -> Result<()> {
    let temp = path.with_file_name(format!(
        "{}.{}.tmp",
        path.file_name().map_or_else(
            || KEY_FILE.to_owned(),
            |name| name.to_string_lossy().into_owned()
        ),
        std::process::id()
    ));
    // Removed first rather than truncated: `write_private` refuses to open an
    // existing file, which is exactly the guarantee that makes the staged copy
    // `0600` from its first byte.
    let _ = fs::remove_file(&temp);
    if !write_private(&temp, contents)? {
        anyhow::bail!(
            "{}: could not stage the secret-identity key rewrite",
            temp.display()
        );
    }
    fs::rename(&temp, path)
        .with_context(|| format!("publish the secret-identity key {}", path.display()))?;
    Ok(())
}

// --- the custody ledger -------------------------------------------------------

/// The custody ledger's file name, beside the key file it records.
const LEDGER_FILE: &str = "custody.jsonl";

/// The custody ledger for `repo_root`.
///
/// # Errors
///
/// Propagates [`key_path`]'s failure to resolve the state directory.
pub fn ledger_path(repo_root: &Path) -> Result<PathBuf> {
    Ok(ledger_beside(&key_path(repo_root)?))
}

/// The ledger beside a key file.
fn ledger_beside(key: &Path) -> PathBuf {
    key.with_file_name(LEDGER_FILE)
}

/// One custody event: what happened to a key generation, or to an identity that
/// was minted under one.
///
/// # Why a ledger exists at all
///
/// The key id is **inside** every secret-class identity's HMAC preimage, which
/// [`crate::identity::secret_code_fingerprint`] chose deliberately so an identity
/// is self-describing about its generation. Self-describing is not readable: a
/// stored fingerprint cannot be asked which key minted it — only re-derivation
/// under a candidate key can answer, and re-derivation needs the span. So the
/// store cannot look at a record and know whether the key behind it is still held,
/// which is precisely the question rotation and key loss turn on. This is that
/// question's answer, recorded when it is knowable.
///
/// It lives beside the key file, in the same out-of-tree state directory as the
/// findings store, and it holds **ids, fingerprints and counts — never key bytes**.
/// Nothing here weakens the invariant that the key is not reachable from the
/// digests it protects: a key id is a coordinate, and a fingerprint is already in
/// the store.
///
/// Append-only, and never rewritten: a custody history that could be edited to
/// remove a generation would let the silent re-mint back in through the record
/// meant to catch it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "kebab-case")]
pub enum Event {
    /// A generation was minted. The first event any repository records.
    Minted {
        /// The new generation's id.
        key_id: String,
        /// Which key that id names — see [`Custody::witnesses`] for why the id
        /// alone cannot answer it.
        witness: String,
    },
    /// A rotation opened a window: both generations are held.
    Rotated {
        /// The generation being retired.
        from: String,
        /// The generation new identities are now minted under.
        to: String,
        /// The witness of the generation now current.
        witness: String,
    },
    /// One identity was re-minted across a rotation, old paired to new by a
    /// dual-HMAC over the same span while both keys were held.
    Joined {
        /// The retired generation's id.
        from_key: String,
        /// The current generation's id.
        to_key: String,
        /// The fingerprint under the retired key, as hex.
        old: String,
        /// The fingerprint under the current key, as hex.
        new: String,
    },
    /// A rotation window closed: nothing is keyed under the retired generation
    /// any more, so it was dropped from the key file.
    Retired {
        /// The generation that was dropped.
        key_id: String,
    },
    /// A generation the ledger names is no longer held, so every identity minted
    /// under it is unreproducible and was re-opened for re-triage.
    ///
    /// **The loud half.** Recorded once per lost generation rather than per run,
    /// so the event is an event; the `reopened` count is what the operator reads.
    Orphaned {
        /// The generation that went missing.
        key_id: String,
        /// How many findings were returned to unsettled.
        reopened: usize,
    },
}

/// The label a key witness is computed over.
///
/// A fixed rule id and path, so the witness is a function of the key alone. It
/// looks like a rule but is not one and can never collide with a finding's
/// identity: a real `rule_id` comes from a config, and this one carries a colon no
/// config key may hold.
const WITNESS_LABEL: &str = "batten:key-witness";

/// A digest that identifies a key without revealing it.
///
/// Through [`crate::identity::secret_code_fingerprint`] rather than a second
/// hashing construction, which is the same reason the store's own id is minted
/// there: one authority on how bytes become an identity. The key is the HMAC key
/// and the span is a fixed label, so the value is reproducible from the key and
/// from nothing else — which is exactly the property a custody comparison needs and
/// the opposite of what a key file may contain.
fn witness(key: &IdentityKey) -> Result<String> {
    Ok(crate::identity::secret_code_fingerprint(
        key,
        WITNESS_LABEL,
        "batten",
        &SecretSpan::mint(WITNESS_LABEL),
    )?
    .to_hex())
}

/// Append one event to the ledger beside `key`.
fn append_event(key: &Path, event: &Event) -> Result<()> {
    let path = ledger_beside(key);
    let parent = path.parent().unwrap_or(&path);
    create_dir_private(parent)?;
    let line = format!("{}\n", serde_json::to_string(event)?);
    let mut options = fs::OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(KEY_MODE);
    }
    let mut file = options
        .open(&path)
        .with_context(|| format!("open the custody ledger {}", path.display()))?;
    file.write_all(line.as_bytes())
        .with_context(|| format!("append to the custody ledger {}", path.display()))?;
    file.sync_all()
        .with_context(|| format!("flush the custody ledger {}", path.display()))?;
    Ok(())
}

/// Every event the ledger holds, in the order they were recorded.
///
/// An absent ledger is an empty history — the ordinary state of a repository that
/// has never scanned for a secret. An unparseable line is skipped rather than
/// failing the read, the same way [`crate::journal`] drops a torn trailing line:
/// refusing to read the whole history over one partial append would make a crash
/// during a write into a permanent custody outage.
///
/// # Errors
///
/// Returns an error when the ledger exists and cannot be read.
pub fn events(repo_root: &Path) -> Result<Vec<Event>> {
    events_at(&ledger_path(repo_root)?)
}

/// [`events`] against an explicit ledger path.
///
/// # Errors
///
/// As [`events`].
pub fn events_at(path: &Path) -> Result<Vec<Event>> {
    let text = match fs::read_to_string(path) {
        Ok(text) => text,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => {
            return Err(err).with_context(|| format!("read the custody ledger {}", path.display()));
        }
    };
    Ok(text
        .lines()
        .filter_map(|line| serde_json::from_str::<Event>(line).ok())
        .collect())
}

/// Every rotation pair the ledger holds, oldest first, as fingerprints.
///
/// Parsed here rather than at the call site so the ledger's shape stays this
/// module's business: a caller matching on [`Event`] to pull pairs out would be a
/// second reader of the format, and the one that applies pairs to records is
/// deliberately the one that knows least about keys.
///
/// A pair whose either half is not a well-formed fingerprint is skipped rather
/// than failing the read — the same reading [`events_at`] gives a torn line.
///
/// # Errors
///
/// Returns an error when the ledger exists and cannot be read.
pub fn joins(ledger: &Path) -> Result<Vec<(Fingerprint, Fingerprint)>> {
    Ok(events_at(ledger)?
        .into_iter()
        .filter_map(|event| match event {
            Event::Joined { old, new, .. } => Some((
                Fingerprint::from_hex(&old).ok()?,
                Fingerprint::from_hex(&new).ok()?,
            )),
            _ => None,
        })
        .collect())
}

/// What a rotation opened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rotation {
    /// The generation now retired but still held.
    pub from: String,
    /// The generation new identities are minted under.
    pub to: String,
}

/// Open a rotation window: mint a new generation and retire the current one,
/// keeping both.
///
/// # What this deliberately does NOT do
///
/// It does not re-key a single stored finding, because it cannot: the new
/// fingerprint for a secret is an HMAC over that secret's span, and no span is
/// stored anywhere — that is the containment this whole module exists for. The join
/// is computed by the next scan, while both keys are held, and applied to the store
/// from the journaling seam. So this verb's whole job is to open the window and say
/// so, and a rotation is only *finished* when [`retire`] closes it.
///
/// # Errors
///
/// - There is no key to rotate. Minting one here would be a rotation that rotated
///   nothing, reported as success.
/// - A window is already open. Two retired generations cannot both be held, and
///   dropping the older one to make room would orphan every identity still keyed
///   under it — the silent re-mint, arrived at by a route the operator did not ask
///   for. Finish the open window first.
/// - The new id would equal the current one, which happens when a rotation is asked
///   for twice on one date. The id is inside every preimage, so two generations
///   sharing an id are conflated and a join cannot name which is which.
pub fn rotate(repo_root: &Path, today: Date) -> Result<Rotation> {
    rotate_at(&key_path(repo_root)?, today)
}

/// [`rotate`] against an explicit key path.
///
/// # Errors
///
/// As [`rotate`].
pub fn rotate_at(path: &Path, today: Date) -> Result<Rotation> {
    let Some(held) = read(path)? else {
        return Err(UsageError::raise(format!(
            "{}: there is no secret-identity key to rotate. A rotation that mints the first key \
             has rotated nothing, and reporting it as a rotation would claim a join that never \
             happened.",
            path.display()
        )));
    };
    if let Some(retired) = held.retired() {
        return Err(UsageError::raise(format!(
            "{}: a rotation from {} is already in flight. Refusing a second: only two generations \
             are held, so this would drop {} while identities are still keyed under it.",
            path.display(),
            retired.id(),
            retired.id()
        )));
    }
    let to = key_id(today);
    if to == held.current().id() {
        return Err(UsageError::raise(format!(
            "{}: a rotation on {} would mint a second generation under the id {} the current key \
             already carries. The id is inside every identity's preimage, so the two would be \
             indistinguishable in the tuple a join names them by.",
            path.display(),
            to,
            to
        )));
    }

    let mut bytes = [0u8; KEY_BYTES];
    getrandom::fill(&mut bytes).map_err(|err| {
        anyhow::anyhow!(
            "the OS randomness source failed, so no secret-identity key was minted: {err}. \
             This is not a reason to fall back to a weaker source — a guessable key is a key \
             an attacker can re-derive."
        )
    })?;
    let from = held.current().id().to_owned();
    let (retiring_id, retiring_hex) = generation_lines(path)?;
    // Current generation first, retired second, so the file's first two lines mean
    // what they have always meant and a binary that predates rotation reads the
    // current key correctly rather than the retired one.
    replace_private(
        path,
        &format!(
            "{to}\n{}\n{retiring_id}\n{retiring_hex}\n",
            encode_key(&bytes)
        ),
    )?;
    append_event(
        path,
        &Event::Rotated {
            from: from.clone(),
            to: to.clone(),
            witness: witness(
                read(path)?
                    .ok_or_else(|| anyhow::anyhow!("{}: the rotated key vanished", path.display()))?
                    .current(),
            )?,
        },
    )?;
    Ok(Rotation { from, to })
}

/// Record that one identity was re-minted across the open rotation window.
///
/// Called from the scan, which is the only place both keys and the span meet.
///
/// # Errors
///
/// Returns an error when the ledger cannot be appended to.
pub fn record_join(
    key: &Path,
    from_key: &str,
    to_key: &str,
    old: Fingerprint,
    new: Fingerprint,
) -> Result<()> {
    append_event(
        key,
        &Event::Joined {
            from_key: from_key.to_owned(),
            to_key: to_key.to_owned(),
            old: old.to_hex(),
            new: new.to_hex(),
        },
    )
}

/// Close an open rotation window: drop the retired generation and say so.
///
/// The caller decides *when* — it is the seam holding the store that can see
/// whether anything is still keyed under the retired generation, and this module
/// deliberately never reads the store it protects. Returns the id that was dropped,
/// or `None` when no window was open.
///
/// # Errors
///
/// Returns an error when the key file cannot be read or rewritten.
pub fn retire(path: &Path) -> Result<Option<String>> {
    let Some(held) = read(path)? else {
        return Ok(None);
    };
    let Some(retired) = held.retired() else {
        return Ok(None);
    };
    let key_id = retired.id().to_owned();
    let (current_id, current_hex) = generation_lines(path)?;
    replace_private(path, &format!("{current_id}\n{current_hex}\n"))?;
    append_event(
        path,
        &Event::Retired {
            key_id: key_id.clone(),
        },
    )?;
    Ok(Some(key_id))
}

/// Record that a generation the ledger names is gone, and how many findings that
/// re-opened.
///
/// # Errors
///
/// Returns an error when the ledger cannot be appended to.
pub fn record_orphan(key: &Path, key_id: &str, reopened: usize) -> Result<()> {
    append_event(
        key,
        &Event::Orphaned {
            key_id: key_id.to_owned(),
            reopened,
        },
    )
}

/// Generations the ledger says existed, that the key file no longer holds, and
/// that have not already been reported.
///
/// # This is the key-loss predicate, and it is deliberately not "the key file is
/// missing"
///
/// An absent key file is indistinguishable from a repository that never scanned
/// for a secret, and [`custody_at`] mints one on need — correctly, because a first
/// mint is not a re-mint. What makes a mint a *re*-mint is that a generation which
/// once existed is no longer held, and only the ledger knows that. So the
/// comparison is ledger-against-file, which catches the case the file alone cannot
/// see: a key deleted and silently re-minted under a new id.
///
/// Reported **once** per lost generation: an already-recorded orphan is filtered
/// out, so the loud event stays an event rather than becoming a line on every run.
/// Re-opening is not idempotent in the direction that matters — a finding
/// re-triaged after the loss must not be re-opened again by the next scan.
///
/// # Errors
///
/// Returns an error when the ledger or the key file cannot be read.
pub fn orphaned_key_ids(repo_root: &Path, today: Date) -> Result<Vec<String>> {
    let path = key_path(repo_root)?;
    let held = custody_at(&path, today)?.witnesses()?;
    Ok(lost_from(&events_at(&ledger_beside(&path))?, &held))
}

/// [`orphaned_key_ids`]'s decision, over values.
///
/// Split out for the reason the module splits `load_or_mint_at`: the key path is
/// ambient env-selected state a suite cannot move, so the predicate is testable
/// only if it is a function of what was read rather than of where it was read from.
fn lost_from(events: &[Event], held_witnesses: &[String]) -> Vec<String> {
    // Every generation the ledger says minted, as (id, witness). `Retired` and
    // `Orphaned` carry no witness and mint nothing, so they are read for what they
    // are: a window that closed, and a loss already announced.
    let mut minted: Vec<(String, String)> = Vec::new();
    let mut reported = Vec::new();
    for event in events.iter().cloned() {
        match event {
            Event::Minted { key_id, witness } => minted.push((key_id, witness)),
            Event::Rotated { to, witness, .. } => minted.push((to, witness)),
            Event::Orphaned { key_id, .. } => reported.push(key_id),
            Event::Retired { .. } | Event::Joined { .. } => {}
        }
    }
    let mut lost: Vec<String> = minted
        .into_iter()
        // A `Retired` generation is deliberately NOT excluded: retiring is how a
        // window closes once nothing is keyed under the generation any more, and a
        // retired id still named by a live record IS a loss. What excludes it is
        // the record check the caller does, which is the only side that can see it.
        .filter(|(id, witness)| !held_witnesses.contains(witness) && !reported.contains(id))
        .map(|(id, _)| id)
        .collect();
    lost.sort();
    lost.dedup();
    lost
}

/// The key file's first two lines, as bytes on disk.
///
/// # Why a rewrite goes through the TEXT and not through the parsed value
///
/// [`IdentityKey`] exposes no accessor for its bytes — that is the property the
/// containment claim rests on, and the redacting `Debug` is the same decision
/// applied to formatting. So a value cannot be re-serialized into a key file, and
/// widening the type to allow it would put a byte accessor on the key for the sake
/// of a file rewrite. Copying the lines the file already holds needs no accessor
/// and no new capability: the bytes move from disk to disk through one `String`
/// that is never rendered.
fn generation_lines(path: &Path) -> Result<(String, String)> {
    let text = fs::read_to_string(path)
        .with_context(|| format!("read the secret-identity key {}", path.display()))?;
    let mut lines = text.lines();
    let id = lines.next().unwrap_or_default().trim().to_owned();
    let hex = lines.next().unwrap_or_default().trim().to_owned();
    Ok((id, hex))
}

// --- the scanner adapter ------------------------------------------------------

/// One parsed match, before it becomes a [`Finding`].
///
/// The span is already opaque: [`parse_line`] wraps it at the moment it is read
/// off the pipe, so no value in this module holds a matched byte as a `&str`
/// after that point. That is the containment claim, and it is a property of the
/// types rather than of the code below being careful.
struct Match {
    path: String,
    line: usize,
    span: SecretSpan,
}

/// Run the pinned scanner over `matched` and turn every match into a pointer.
///
/// # Errors
///
/// - **exit 1** ([`UsageError`]) when the manifest declares no scanner entry, or
///   the provision cache holds no binary — the message names
///   [`PROVISION_VERB`]. Never a silent pass: a scanner that did not run is not
///   evidence of a clean tree.
/// - **exit 3** (a plain internal error) for every fail-closed case: an
///   unparseable output line, a clean exit that nonetheless produced matches, a
///   found exit that produced none, and any other exit code or signal. Clean is
///   never inferred from a stream that failed to parse.
pub fn scan(
    rule: &Rule,
    provisions: &[Provision],
    root: &Path,
    matched: &[&String],
    findings: &mut Vec<Finding>,
) -> Result<()> {
    let binary = resolve_scanner(provisions, root)?;
    // Same resolution as the scanner's cache, and for the same reason: the key
    // lives under the repository's state directory, which cannot be named from a
    // relative anchor.
    let canonical = root
        .canonicalize()
        .with_context(|| format!("resolve the repository root at {}", root.display()))?;
    let key_file = key_path(&canonical)?;
    let held = custody_at(&key_file, crate::waiver::today()?)?;
    let key = held.current();

    let mut parsed: Vec<Match> = Vec::new();
    for batch in crate::rules::batches(matched) {
        parsed.extend(run_once(rule, &binary, root, &batch)?);
    }

    for hit in parsed {
        let fingerprint =
            crate::identity::secret_code_fingerprint(key, &rule.id, &hit.path, &hit.span)?;
        // The rotation join, computed **here** because this is the only place both
        // keys and the span meet: the old fingerprint is an HMAC over this span
        // under the retired key, and no span is stored anywhere for a later pass to
        // recover. So the window a rotation opens is exactly the interval in which
        // scans can still pair the generations, and each pairing is written down as
        // it is computed. Applying the pair to the store is the journaling seam's
        // job — this module never reads the store it protects.
        if let Some(retired) = held.retired() {
            let old =
                crate::identity::secret_code_fingerprint(retired, &rule.id, &hit.path, &hit.span)?;
            record_join(
                &key_file,
                retired.id(),
                key.id(),
                discriminated(old, rule),
                discriminated(fingerprint, rule),
            )?;
        }
        findings.push(Finding {
            rule: rule.id.clone(),
            severity: rule.severity(),
            path: hit.path,
            line: Some(hit.line),
            // The override still applies, and still keeps the identity keyed:
            // `override_fingerprint` hashes the already-keyed fingerprint as a
            // field, so a discriminator can split a group and can never unkey
            // one.
            identity: crate::identity::StoredIdentity::secret(discriminated(fingerprint, rule)),
            check: rule
                .settling_check()
                .unwrap_or(crate::findings::Check::Reevaluate),
            // The rule's own column, exactly as every other kind reads it
            // (`rules::run_rule`). This was hardcoded `None` while no secret-class
            // finding could reach the store — `record` refuses a finding with no
            // remediation, so the hardcode was invisible right up to the moment
            // this surface started journalling (CLOUD-529), at which point it
            // would have silently dropped every secret finding at the store
            // boundary.
            remediation: rule.remediation(),
        });
    }
    Ok(())
}

/// The rule's identity override applied, if it declares one.
///
/// Extracted because the join needs the SAME transformation on both sides: a pair
/// recorded as (bare old, discriminated new) would name two coordinates the store
/// never holds together, and the record it was supposed to move would sit
/// untouched under a third. The override still keeps the identity keyed —
/// `override_fingerprint` hashes the already-keyed fingerprint as a field, so a
/// discriminator can split a group and can never unkey one.
fn discriminated(fingerprint: Fingerprint, rule: &Rule) -> Fingerprint {
    match rule.identity_key.as_deref() {
        Some(discriminator) => crate::identity::override_fingerprint(fingerprint, discriminator),
        None => fingerprint,
    }
}

/// Where the scanner binary is, or a refusal naming the verb that installs it.
fn resolve_scanner(provisions: &[Provision], root: &Path) -> Result<PathBuf> {
    let Some(entry) = provisions.iter().find(|entry| entry.name == SCANNER) else {
        return Err(UsageError::raise(
            Refusal::declared(
                SCANNER,
                crate::verdict::Native::ScannerUnpinned,
                &[crate::verdict::Subject::Artifact {
                    artifact: SCANNER.to_owned(),
                }],
                Fix::Run(PROVISION_VERB.to_owned()),
            )
            .render(),
        ));
    };
    // The anchor is a RELATIVE path (`.`) whenever the config sits in the cwd,
    // and the cache is keyed by the repository's own directory name — which
    // `state::derive_repo_name` cannot read off `.`. Canonicalize rather than
    // reach for `git::repo_root`: that would resolve a scratch fixture under
    // `target/` to *this* repository, so a fixture asserting "no scanner
    // installed" would start reading whichever cache the developer happened to
    // have warmed. Canonicalizing answers for the directory actually anchored,
    // which is what `provision apply` resolves to as well whenever the two run
    // from the same place.
    let repo = root
        .canonicalize()
        .with_context(|| format!("resolve the repository root at {}", root.display()))?;
    let path = crate::provision::binary_path(&repo, entry)?;
    if !path.is_file() {
        // Never a silent pass — the missing-binary posture the command kind
        // already holds, with the verb named because a refusal that says only
        // what it would not do leaves the caller guessing (CLOUD-122).
        return Err(UsageError::raise(
            Refusal::declared(
                SCANNER,
                crate::verdict::Native::ScannerUnprovisioned,
                &[crate::verdict::Subject::Artifact {
                    artifact: SCANNER.to_owned(),
                }],
                Fix::Run(PROVISION_VERB.to_owned()),
            )
            .render(),
        ));
    }
    Ok(path)
}

/// One scanner invocation over one batch of paths.
fn run_once(rule: &Rule, binary: &Path, root: &Path, batch: &[&str]) -> Result<Vec<Match>> {
    // Both streams are captured and NEITHER is forwarded. stdout carries the
    // matched bytes and is parsed here; stderr can carry a path the tool
    // failed to read, and echoing a child's stream would put output Batten
    // never shaped onto Batten's own (§6).
    #[expect(
        clippy::disallowed_types,
        reason = "stays: the scanner is a pinned third-party binary `provision` installed — adopting a scanner rather than writing one is the decision, and a library form would be writing one"
    )]
    let spawn = |program: &str, leading: &[&str]| {
        std::process::Command::new(program)
            .args(leading)
            .args(SCANNER_FLAGS)
            .args(batch)
            .current_dir(root)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .output()
    };

    // THE SAME RESOLUTION EVERY SPAWNING KIND GETS (CLOUD-617), and here for the
    // same reason: a provisioned scanner is a program someone else built, so
    // Batten does not get to assume it is a PE image. `CreateProcess` does not
    // read `#!`, and the failure surfaces as an internal error rather than as a
    // verdict — five cases in `tests/cli.rs` reported exit 3 over a stub scanner
    // that was a shell script, none of them about secrets at all.
    //
    // `root` is `None` because `binary` is the absolute path `provision` resolved:
    // there is no relative name to read against a directory, and the PATH rung
    // leaves a path-bearing program alone by construction.
    let result = match binary.to_str() {
        Some(program) => crate::rules::spawn_resolving(None, program, spawn),
        // A non-UTF-8 install path is not a reason to skip the scan: spawn it as
        // the `OsStr` it is and forgo a resolution whose two rungs both need a
        // `str`. Unreachable in practice — `provision` builds this path from the
        // config's own text — and a silent skip would be the worse failure.
        #[expect(
            clippy::disallowed_types,
            reason = "stays: the same scanner spawn as above, reached when the install path is not UTF-8 — a silent skip would be the worse failure, so the arm exists and carries the same verdict"
        )]
        None => std::process::Command::new(binary)
            .args(SCANNER_FLAGS)
            .args(batch)
            .current_dir(root)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .output(),
    };

    let output =
        result.with_context(|| format!("rule {}: run the pinned secret scanner", rule.id))?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut parsed = Vec::new();
    for (ordinal, line) in stdout.lines().enumerate() {
        if line.is_empty() {
            continue;
        }
        // Pointer-only, and this one matters most: the line that failed to parse
        // is a line the scanner emitted because it found a secret in it. The
        // error names WHICH line by ordinal and never what it said.
        let hit = parse_line(line, batch).ok_or_else(|| {
            anyhow::anyhow!(
                "rule {}: the secret scanner emitted a line this build cannot parse \
                 (output line {}); refusing to report a clean tree from a stream that \
                 failed to parse",
                rule.id,
                ordinal + 1
            )
        })?;
        parsed.push(hit);
    }

    cross_check(rule, output.status.code(), parsed.len())?;
    Ok(parsed)
}

/// The exit-status/parse-count cross-check, both directions.
///
/// Disagreement is exit 3 rather than a verdict, because each direction means
/// the parser and the tool disagree about what happened, and neither answer can
/// be trusted over the other. A clean exit with matches parsed would report
/// secrets the tool says it did not find; a found exit with nothing parsed would
/// report a clean tree the tool says is not clean — and that second one is the
/// silent false green this whole clause exists to prevent.
fn cross_check(rule: &Rule, code: Option<i32>, parsed: usize) -> Result<()> {
    match code {
        Some(EXIT_CLEAN) if parsed == 0 => Ok(()),
        Some(EXIT_FOUND) if parsed > 0 => Ok(()),
        Some(EXIT_CLEAN) => Err(anyhow::anyhow!(
            "rule {}: the secret scanner exited clean while emitting {parsed} match(es); \
             the exit status and the output disagree, so neither is a verdict",
            rule.id
        )),
        Some(EXIT_FOUND) => Err(anyhow::anyhow!(
            "rule {}: the secret scanner reported findings and emitted none this build \
             could parse; clean is never inferred from a stream that failed to parse",
            rule.id
        )),
        Some(other) => Err(anyhow::anyhow!(
            "rule {}: the secret scanner exited {other}, which is neither its clean nor \
             its found status",
            rule.id
        )),
        None => Err(anyhow::anyhow!(
            "rule {}: the secret scanner was killed by a signal, so it reached no verdict",
            rule.id
        )),
    }
}

/// Parse one `<path>:<line>:<span>` output line, given the paths this batch
/// passed in.
///
/// **Anchored on the known paths, never on separator position.** Splitting on
/// `:` is wrong twice over: a path may contain one, and so may a secret — and
/// the second is the dangerous one, because a mis-split there does not fail, it
/// silently keys a truncated span. Matching the longest known path that the line
/// starts with makes both non-events, and makes an unrecognised path a parse
/// failure (exit 3) rather than a guess.
///
/// The span is wrapped **here**, at the boundary, and the `&str` it came from
/// does not outlive this function.
fn parse_line(line: &str, batch: &[&str]) -> Option<Match> {
    // Longest first: with `a.rs` and `a.rs.bak` both in the batch, the shorter
    // is a prefix of the longer and would claim the longer's lines.
    let path = batch
        .iter()
        .filter(|path| line.len() > path.len() && line.as_bytes()[path.len()] == b':')
        .filter(|path| line.starts_with(**path))
        .max_by_key(|path| path.len())?;

    let rest = &line[path.len() + 1..];
    let (number, span) = rest.split_once(':')?;
    let line_number: usize = number.parse().ok()?;
    if line_number == 0 {
        // Line numbers are 1-based; a zero is a shape this build does not know.
        return None;
    }
    Some(Match {
        path: (*path).to_owned(),
        line: line_number,
        span: SecretSpan::mint(span),
    })
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

    // -- the parse boundary and the fail-closed cross-check -------------------

    /// The span, recovered the only way a test can: fingerprint it under a known
    /// key and compare against the fingerprint of a candidate string. There is
    /// deliberately no accessor, so this is the assertion shape the design
    /// leaves available — and that it is awkward is the containment working.
    fn span_is(hit: &Match, expected: &str) -> bool {
        let key = IdentityKey::new("k", [7u8; 32]);
        let got = crate::identity::secret_code_fingerprint(&key, "r", "p", &hit.span).unwrap();
        let want =
            crate::identity::secret_code_fingerprint(&key, "r", "p", &SecretSpan::mint(expected))
                .unwrap();
        got == want
    }

    #[test]
    fn a_line_parses_into_path_line_and_span() {
        let batch = ["src/a.rs"];
        let hit = parse_line("src/a.rs:12:tok-abc", &batch).unwrap();
        assert_eq!(hit.path, "src/a.rs");
        assert_eq!(hit.line, 12);
        assert!(span_is(&hit, "tok-abc"));
    }

    #[test]
    fn a_colon_in_the_span_is_not_a_separator() {
        // The dangerous case, and the reason the parser anchors on known paths:
        // splitting on `:` here does not fail, it silently keys a truncated
        // span — a wrong answer that looks like a right one.
        let batch = ["src/a.rs"];
        let hit = parse_line("src/a.rs:3:user:password@host", &batch).unwrap();
        assert_eq!(hit.line, 3);
        assert!(
            span_is(&hit, "user:password@host"),
            "the whole remainder is the span, colons included"
        );
    }

    #[test]
    fn a_colon_in_the_path_is_not_a_separator_either() {
        let batch = ["weird:name.rs"];
        let hit = parse_line("weird:name.rs:9:tok", &batch).unwrap();
        assert_eq!(hit.path, "weird:name.rs");
        assert_eq!(hit.line, 9);
        assert!(span_is(&hit, "tok"));
    }

    #[test]
    fn the_longest_matching_path_wins() {
        // `a.rs` is a prefix of `a.rs.bak`, so a first-match parser would credit
        // the shorter path with the longer one's findings — a pointer to the
        // wrong file, which is worse than no pointer.
        let batch = ["a.rs", "a.rs.bak"];
        let hit = parse_line("a.rs.bak:4:tok", &batch).unwrap();
        assert_eq!(hit.path, "a.rs.bak");
    }

    #[test]
    fn an_unparseable_line_is_none_rather_than_a_guess() {
        let batch = ["src/a.rs"];
        for line in [
            "src/other.rs:1:tok", // a path this batch never passed in
            "src/a.rs:notanumber:tok",
            "src/a.rs:0:tok", // line numbers are 1-based
            "src/a.rs",       // no line, no span
            "src/a.rs:1",     // no span field
            "",
            "totally unrelated output",
        ] {
            assert!(
                parse_line(line, &batch).is_none(),
                "must not parse: {line:?}"
            );
        }
    }

    /// A `secrets` row, parsed from TOML rather than built as a struct — the
    /// `identity_churn.rs` idiom, and the one that keeps a test from silently
    /// depending on a field ordering the config surface does not have.
    fn rule() -> Rule {
        toml::from_str(
            r#"
id = "no-secrets"
kind = "secrets"
glob = "**"
severity = "deny"
"#,
        )
        .expect("the fixture row loads")
    }

    #[test]
    fn the_two_agreeing_cases_are_the_only_ones_that_pass() {
        assert!(cross_check(&rule(), Some(EXIT_CLEAN), 0).is_ok());
        assert!(cross_check(&rule(), Some(EXIT_FOUND), 3).is_ok());
    }

    #[test]
    fn a_clean_exit_with_matches_is_refused() {
        // The tool says nothing was found and the stream says otherwise. Neither
        // is a verdict, so this is exit 3 rather than a report.
        let err = cross_check(&rule(), Some(EXIT_CLEAN), 2).unwrap_err();
        assert!(
            err.downcast_ref::<UsageError>().is_none(),
            "internal, not usage"
        );
        assert!(err.to_string().contains("disagree"), "{err}");
    }

    #[test]
    fn a_found_exit_with_no_matches_is_refused() {
        // The silent false green this clause exists to prevent: the tool found
        // secrets, the parser produced none, and reporting clean would be a
        // clean tree inferred from a stream that failed to parse.
        let err = cross_check(&rule(), Some(EXIT_FOUND), 0).unwrap_err();
        assert!(err.downcast_ref::<UsageError>().is_none());
        assert!(err.to_string().contains("never inferred"), "{err}");
    }

    #[test]
    fn a_tool_error_or_a_signal_is_neither_verdict() {
        let err = cross_check(&rule(), Some(2), 0).unwrap_err();
        assert!(err.to_string().contains("neither its clean nor"), "{err}");

        let err = cross_check(&rule(), None, 0).unwrap_err();
        assert!(err.to_string().contains("signal"), "{err}");
    }

    #[test]
    fn no_refusal_or_error_rendering_carries_a_span() {
        // Every message this module can emit, checked against a span that would
        // be in it if any path echoed one. Pointer-only is the rule these all
        // serve, and an error is the easiest place to break it by accident.
        const SECRET: &str = "tok-would-be-leaked";
        let batch = ["src/a.rs"];
        let rendered: Vec<String> = vec![
            cross_check(&rule(), Some(EXIT_CLEAN), 2)
                .unwrap_err()
                .to_string(),
            cross_check(&rule(), Some(EXIT_FOUND), 0)
                .unwrap_err()
                .to_string(),
            cross_check(&rule(), Some(2), 0).unwrap_err().to_string(),
            cross_check(&rule(), None, 0).unwrap_err().to_string(),
            resolve_scanner(&[], Path::new("/nowhere"))
                .unwrap_err()
                .to_string(),
        ];
        for message in &rendered {
            assert!(
                !message.contains(SECRET) && !message.contains("tok-"),
                "a message rendered a span: {message}"
            );
        }
        // And the parse failure names an ordinal, never the line — asserted at
        // the one place the line is in scope.
        assert!(parse_line(&format!("unknown.rs:1:{SECRET}"), &batch).is_none());
    }

    #[test]
    fn a_missing_scanner_entry_names_the_verb_that_installs_it() {
        let err = resolve_scanner(&[], Path::new("/nowhere")).unwrap_err();
        assert!(
            err.downcast_ref::<UsageError>().is_some(),
            "a config that cannot run its own gate is exit 1"
        );
        let text = err.to_string();
        assert!(text.contains(PROVISION_VERB), "{text}");
        assert!(text.contains(SCANNER), "{text}");
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

    // --- rotation and loss custody (CLOUD-529) -------------------------------

    /// The day after [`date`], so a rotation has a distinct id to mint under.
    fn tomorrow() -> Date {
        Date {
            year: 2026,
            month: 8,
            day: 14,
        }
    }

    // Rotation holds BOTH generations, and the order in the file is not cosmetic:
    // the current key stays on lines 1 and 2, so a binary predating rotation reads
    // the key new identities are minted under rather than the retired one.
    #[test]
    fn a_rotation_holds_both_generations_with_the_current_one_first() {
        let path = scratch("rotate-holds-both");
        let before = load_or_mint_at(&path, date()).unwrap();
        let rotation = rotate_at(&path, tomorrow()).unwrap();
        assert_eq!(rotation.from, before.id());
        assert_eq!(rotation.to, "2026-08-14");

        let held = read(&path).unwrap().unwrap();
        assert_eq!(held.current().id(), "2026-08-14");
        assert_eq!(held.retired().map(IdentityKey::id), Some(before.id()));
        assert_eq!(held.held_ids(), vec!["2026-08-14", before.id()]);
        // The pre-rotation reader's view: lines 1 and 2 are the current key.
        assert_eq!(load_or_mint_at(&path, date()).unwrap().id(), "2026-08-14");
    }

    // The retired key is the SAME key, not a re-mint of it — otherwise the join it
    // exists for could not reproduce a single old fingerprint.
    #[test]
    fn the_retired_generation_is_the_key_that_was_current() {
        let path = scratch("rotate-preserves");
        load_or_mint_at(&path, date()).unwrap();
        let span = crate::identity::SecretSpan::mint("shhh");
        let before = crate::identity::secret_code_fingerprint(
            read(&path).unwrap().unwrap().current(),
            "r",
            "src/a.rs",
            &span,
        )
        .unwrap();

        rotate_at(&path, tomorrow()).unwrap();
        let held = read(&path).unwrap().unwrap();
        let after = crate::identity::secret_code_fingerprint(
            held.retired().unwrap(),
            "r",
            "src/a.rs",
            &span,
        )
        .unwrap();
        assert_eq!(
            after, before,
            "the retired key still mints the identities it minted"
        );
        assert_ne!(
            crate::identity::secret_code_fingerprint(held.current(), "r", "src/a.rs", &span)
                .unwrap(),
            before,
            "and the new one does not, which is what a join is for"
        );
    }

    // Three refusals, each a case where proceeding would lose a generation
    // silently. They are `UsageError` (exit 1), never a verdict about the tree.
    #[test]
    fn rotation_refuses_every_case_that_would_lose_a_generation() {
        let missing = scratch("rotate-nothing");
        let err = rotate_at(&missing, date()).expect_err("nothing to rotate");
        assert!(err.to_string().contains("no secret-identity key"), "{err}");
        assert!(
            !missing.exists(),
            "a refused rotation minted nothing, or it would have rotated into existence"
        );

        let same_day = scratch("rotate-same-day");
        load_or_mint_at(&same_day, date()).unwrap();
        let err = rotate_at(&same_day, date()).expect_err("one id, two generations");
        assert!(err.to_string().contains("2026-08-13"), "{err}");

        let twice = scratch("rotate-twice");
        load_or_mint_at(&twice, date()).unwrap();
        rotate_at(&twice, tomorrow()).unwrap();
        let err = rotate_at(
            &twice,
            Date {
                year: 2026,
                month: 8,
                day: 15,
            },
        )
        .expect_err("a window is already open");
        assert!(err.to_string().contains("already in flight"), "{err}");
        // And the open window survived the refusal intact.
        let held = read(&twice).unwrap().unwrap();
        assert_eq!(held.retired().map(IdentityKey::id), Some("2026-08-13"));
    }

    // Retiring closes the window and is idempotent-safe: called with none open it
    // reports `None` rather than rewriting the file.
    #[test]
    fn retiring_closes_the_window_and_is_a_no_op_without_one() {
        let path = scratch("retire");
        load_or_mint_at(&path, date()).unwrap();
        assert_eq!(retire(&path).unwrap(), None, "no window is open");
        rotate_at(&path, tomorrow()).unwrap();
        assert_eq!(retire(&path).unwrap(), Some("2026-08-13".to_owned()));
        let held = read(&path).unwrap().unwrap();
        assert_eq!(held.current().id(), "2026-08-14");
        assert_eq!(held.retired().map(IdentityKey::id), None);
        assert_eq!(retire(&path).unwrap(), None, "and not twice");
    }

    // A rewrite must not widen the key file's permissions. The mode is set at
    // creation on the staged copy, so the published file was never world-readable
    // even for the instant a chmod-afterwards would leave open.
    #[cfg(unix)]
    #[test]
    fn a_rewritten_key_file_is_still_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let path = scratch("rotate-mode");
        load_or_mint_at(&path, date()).unwrap();
        rotate_at(&path, tomorrow()).unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, KEY_MODE, "0o{mode:o}");
    }

    // A half-present retired generation is refused rather than read as absent: an
    // id with no key is a generation we can neither use nor honestly declare lost,
    // and dropping it into the absent case is the silent path.
    #[test]
    fn a_half_present_retired_generation_is_refused() {
        let path = scratch("retired-half");
        let key = load_or_mint_at(&path, date()).unwrap();
        let (id, hex) = generation_lines(&path).unwrap();
        assert_eq!(id, key.id());

        replace_private(&path, &format!("{id}\n{hex}\n2026-08-01\n")).unwrap();
        let err = read(&path).expect_err("an id with no key");
        assert!(err.to_string().contains(":3"), "{err}");

        replace_private(&path, &format!("{id}\n{hex}\n2026-08-01\nnot-hex\n")).unwrap();
        let err = read(&path).expect_err("a key that is not one");
        assert!(err.to_string().contains(":4"), "{err}");
        assert!(
            !err.to_string().contains("not-hex"),
            "pointer-only: the file's bytes are key material, {err}"
        );
    }

    // Two generations sharing one id are conflated inside the preimage, so a join
    // could not name which is which. Refused on read, not only on rotate — a file
    // hand-edited into that shape must not be used.
    #[test]
    fn two_generations_under_one_id_are_refused_on_read() {
        let path = scratch("retired-same-id");
        load_or_mint_at(&path, date()).unwrap();
        let (id, hex) = generation_lines(&path).unwrap();
        replace_private(&path, &format!("{id}\n{hex}\n{id}\n{hex}\n")).unwrap();
        let err = read(&path).expect_err("one id, two generations");
        assert!(
            err.to_string().contains("shares the current key's id"),
            "{err}"
        );
    }

    // The ledger is the answer to a question the store cannot ask: the key id is
    // inside the preimage, so no stored fingerprint can be asked which generation
    // minted it. A first mint records itself, and a rotation records the pair.
    #[test]
    fn the_ledger_records_every_generation_that_ever_minted() {
        let path = scratch("ledger");
        load_or_mint_at(&path, date()).unwrap();
        rotate_at(&path, tomorrow()).unwrap();
        retire(&path).unwrap();
        let events = events_at(&ledger_beside(&path)).unwrap();
        assert!(
            matches!(
                events.as_slice(),
                [
                    Event::Minted { key_id, .. },
                    Event::Rotated { from, to, .. },
                    Event::Retired { key_id: retired },
                ] if key_id == "2026-08-13"
                    && from == "2026-08-13"
                    && to == "2026-08-14"
                    && retired == "2026-08-13"
            ),
            "{events:?}"
        );
        // Each mint names WHICH key, not only which label — the two witnesses
        // differ, which is what makes a same-day re-mint detectable at all.
        let witnesses: Vec<&String> = events
            .iter()
            .filter_map(|event| match event {
                Event::Minted { witness, .. } | Event::Rotated { witness, .. } => Some(witness),
                _ => None,
            })
            .collect();
        assert_eq!(witnesses.len(), 2);
        assert_ne!(witnesses[0], witnesses[1]);
    }

    // Pointer-only, structurally: the ledger holds ids, fingerprints and counts.
    // A key byte reaching it would put the key in the same directory as a digest
    // it protects, in a file that is not the key file.
    #[test]
    fn no_ledger_event_can_carry_a_key_byte() {
        let path = scratch("ledger-pointer-only");
        let key = load_or_mint_at(&path, date()).unwrap();
        let hex = generation_lines(&path).unwrap().1;
        rotate_at(&path, tomorrow()).unwrap();
        record_join(
            &path,
            "2026-08-13",
            "2026-08-14",
            crate::identity::store_fingerprint(&["old"]),
            crate::identity::store_fingerprint(&["new"]),
        )
        .unwrap();
        record_orphan(&path, "2026-08-13", 2).unwrap();

        let text = fs::read_to_string(ledger_beside(&path)).unwrap();
        assert!(!text.contains(&hex), "the ledger carries no key material");
        assert!(text.contains(key.id()), "it does carry the coordinate");
        // And the redacting `Debug` holds for the custody wrapper too, which is a
        // new value in a formatting path.
        let rendered = format!("{:?}", read(&path).unwrap().unwrap());
        assert!(!rendered.contains(&hex), "{rendered}");
        assert!(rendered.contains("redacted"), "{rendered}");
    }

    // The key-loss predicate is ledger-against-file, NOT "the key file is missing":
    // an absent file is indistinguishable from a repository that never scanned, and
    // `custody_at` mints there correctly. What makes a mint a RE-mint is that a
    // generation which once existed is no longer held.
    #[test]
    fn a_deleted_key_is_a_lost_generation_and_a_fresh_one_is_not() {
        let path = scratch("orphan-detect");
        // A first mint names one generation, and nothing is lost.
        load_or_mint_at(&path, date()).unwrap();
        assert!(lost_ids(&path, date()).is_empty());

        // The key is deleted and re-minted under a new id: the ledger still names
        // the generation the file no longer holds.
        fs::remove_file(&path).unwrap();
        load_or_mint_at(&path, tomorrow()).unwrap();
        assert_eq!(lost_ids(&path, tomorrow()), vec!["2026-08-13".to_owned()]);

        // Reported once: an already-recorded orphan drops out, so the loud event
        // stays an event rather than a line on every run.
        record_orphan(&path, "2026-08-13", 1).unwrap();
        assert!(lost_ids(&path, tomorrow()).is_empty());
    }

    // The case the id alone cannot see, and the reason a witness exists. A key
    // deleted and re-minted the SAME day comes back under the same id carrying
    // different bytes: compared by label, the ledger names a generation the file
    // appears to hold, while every identity in the store has silently stopped being
    // reproducible — the exact silent re-mint the contract refuses, arriving through
    // the check meant to catch it.
    #[test]
    fn a_same_day_re_mint_is_still_a_lost_generation() {
        let path = scratch("orphan-same-day");
        load_or_mint_at(&path, date()).unwrap();
        fs::remove_file(&path).unwrap();
        let after = load_or_mint_at(&path, date()).unwrap();
        assert_eq!(
            after.id(),
            "2026-08-13",
            "the id is the date, so it came back identical"
        );
        assert_eq!(
            lost_ids(&path, date()),
            vec!["2026-08-13".to_owned()],
            "and the witness says it is not the same key"
        );
    }

    // A generation still HELD is never lost, however many events name it — the
    // comparison is against the file, so an open rotation window is not a loss.
    #[test]
    fn an_open_rotation_window_is_not_a_loss() {
        let path = scratch("orphan-window");
        load_or_mint_at(&path, date()).unwrap();
        rotate_at(&path, tomorrow()).unwrap();
        assert!(
            lost_ids(&path, tomorrow()).is_empty(),
            "both generations are in the file"
        );
        retire(&path).unwrap();
        assert_eq!(
            lost_ids(&path, tomorrow()),
            vec!["2026-08-13".to_owned()],
            "a retired generation IS unheld; whether that matters is a question \
             about records, which is the store side's to answer"
        );
    }

    /// [`orphaned_key_ids`] against an injected key path.
    ///
    /// The public entry point resolves the path from the repository, which a unit
    /// test cannot move (`set_var` is unsafe and forbidden), so the predicate is
    /// exercised through the same split [`load_or_mint_at`] uses.
    fn lost_ids(path: &Path, today: Date) -> Vec<String> {
        let held = custody_at(path, today).unwrap().witnesses().unwrap();
        lost_from(&events_at(&ledger_beside(path)).unwrap(), &held)
    }

    // The scan reads the current key and, while a window is open, mints the pair.
    // Asserted on the fingerprints rather than through the scanner, which needs a
    // provisioned binary: what is being pinned is that the join names the identity
    // the store actually holds, override and all.
    #[test]
    fn a_join_names_the_same_identity_the_store_holds() {
        let path = scratch("join-identity");
        load_or_mint_at(&path, date()).unwrap();
        rotate_at(&path, tomorrow()).unwrap();
        let held = read(&path).unwrap().unwrap();
        let span = crate::identity::SecretSpan::mint("shhh");

        let new = crate::identity::secret_code_fingerprint(held.current(), "r", "src/a.rs", &span)
            .unwrap();
        let old = crate::identity::secret_code_fingerprint(
            held.retired().unwrap(),
            "r",
            "src/a.rs",
            &span,
        )
        .unwrap();
        // The rule declares an identity override, so BOTH halves must carry it: a
        // pair recorded as (bare old, discriminated new) names two coordinates the
        // store never holds together, and the record it was meant to move sits
        // untouched under a third.
        let split = |fingerprint| crate::identity::override_fingerprint(fingerprint, "split");
        record_join(
            &path,
            held.retired().unwrap().id(),
            held.current().id(),
            split(old),
            split(new),
        )
        .unwrap();

        let pairs = joins(&ledger_beside(&path)).unwrap();
        assert_eq!(pairs.len(), 1);
        assert_eq!(
            pairs[0].1,
            split(new),
            "the join's new half is the identity a finding carries"
        );
        assert_eq!(pairs[0].0, split(old));
        assert_ne!(pairs[0].0, pairs[0].1);
    }
}
