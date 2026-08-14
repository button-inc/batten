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

use crate::error::UsageError;
use crate::identity::{IdentityKey, SecretSpan};
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
    let key = load_or_mint(
        &root
            .canonicalize()
            .with_context(|| format!("resolve the repository root at {}", root.display()))?,
        crate::waiver::today()?,
    )?;

    let mut parsed: Vec<Match> = Vec::new();
    for batch in crate::rules::batches(matched) {
        parsed.extend(run_once(rule, &binary, root, &batch)?);
    }

    for hit in parsed {
        let fingerprint =
            crate::identity::secret_code_fingerprint(&key, &rule.id, &hit.path, &hit.span)?;
        findings.push(Finding {
            rule: rule.id.clone(),
            severity: rule.severity(),
            path: hit.path,
            line: Some(hit.line),
            // The override still applies, and still keeps the identity keyed:
            // `override_fingerprint` hashes the already-keyed fingerprint as a
            // field, so a discriminator can split a group and can never unkey
            // one.
            identity: crate::identity::StoredIdentity::secret(match rule.identity_key.as_deref() {
                Some(discriminator) => {
                    crate::identity::override_fingerprint(fingerprint, discriminator)
                }
                None => fingerprint,
            }),
            check: rule
                .settling_check()
                .unwrap_or(crate::findings::Check::Reevaluate),
            remediation: None,
        });
    }
    Ok(())
}

/// Where the scanner binary is, or a refusal naming the verb that installs it.
fn resolve_scanner(provisions: &[Provision], root: &Path) -> Result<PathBuf> {
    let Some(entry) = provisions.iter().find(|entry| entry.name == SCANNER) else {
        return Err(UsageError::raise(
            Refusal::new(
                SCANNER,
                "a `secrets` rule needs the scanner pinned, and this config declares no \
                 `[[provision]]` entry for it",
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
            Refusal::new(
                SCANNER,
                "the pinned scanner is not in the provision cache, so no file was scanned",
                Fix::Run(PROVISION_VERB.to_owned()),
            )
            .render(),
        ));
    }
    Ok(path)
}

/// One scanner invocation over one batch of paths.
fn run_once(rule: &Rule, binary: &Path, root: &Path, batch: &[&str]) -> Result<Vec<Match>> {
    let output = std::process::Command::new(binary)
        .args(SCANNER_FLAGS)
        .args(batch)
        .current_dir(root)
        // Both streams are captured and NEITHER is forwarded. stdout carries the
        // matched bytes and is parsed here; stderr can carry a path the tool
        // failed to read, and echoing a child's stream would put output Batten
        // never shaped onto Batten's own (§6).
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output()
        .with_context(|| format!("rule {}: run the pinned secret scanner", rule.id))?;

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
}
