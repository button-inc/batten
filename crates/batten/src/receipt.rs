//! Verification receipts (CLOUD-203): SHA-keyed claims that a named check
//! passed, with an expiry condition that is a git fact.
//!
//! The behavioural spec is the bash receipt system this module ports —
//! `mise.toml`'s `verify` body and `mise-tasks/linear-check` write receipts
//! keyed to the exact HEAD they validated, and `mise-tasks/ready-guard` /
//! `mise-tasks/verified` honour them only while HEAD and the recorded
//! `origin/main` still match. An amend, a rebase, or a main that moved all
//! invalidate a receipt instead of letting it silently keep counting. Port,
//! don't redesign: this module changes where a receipt lives and what shape it
//! has, never when it is valid.
//!
//! Load-bearing choices:
//!
//! * **The receipt is an in-toto Statement v1** (CLOUD-132's captured
//!   vocabulary): subject = the commit digest (`gitCommit`), predicate = the
//!   claim `{check, recordedMain, recordedGitDir, policyDigest, recordedAt,
//!   conclusion, identity}`. The envelope shape is the standard's, never an
//!   invented format; only the predicate vocabulary is Batten's.
//! * **The canonical store is the out-of-tree state dir**
//!   ([`crate::state::repo_state_dir`] — this module is its first caller):
//!   one file per check identity at `receipts/<fingerprint>.json`, updated in
//!   place. Idempotent on identity, and the persisting file is exactly what
//!   makes `stale-head` observable after HEAD moves past it.
//! * **Receipt identity is a content-keyed fingerprint**
//!   ([`crate::identity::scope_fingerprint`] — this module is its first
//!   caller): a receipt is a whole-repo condition claim keyed by the check
//!   name, never a `path:line`. The receipt-specific scope key keeps it from
//!   aliasing a future repo-scoped *finding* for a rule of the same name, and
//!   the identity version is recorded beside the hash (CLOUD-123), never
//!   inside it.
//! * **The predicate records the absolute git dir**, and validity requires it
//!   to match the current one. This ports the bash property that receipts are
//!   per-checkout facts — a receipt taken in one clone or worktree cannot
//!   authorise another; elsewhere it reads as [`Validity::Missing`]. Known
//!   residual corner: a reclone at the same path to the same HEAD revives the
//!   state-dir record while the grandfathered readers see nothing — the
//!   operative gate still denies, so the divergence is only ever conservative,
//!   and it ends when the readers migrate onto this predicate (CLOUD-202).
//! * **The grandfathered compatibility layout is also written**:
//!   `$GIT_DIR/batten-receipts/<check>.<head-sha>` containing the recorded
//!   main SHA, so `ready-guard`, `verified`, and `land` keep working
//!   unchanged while they exist.
//! * **Validity is a pure function** of the receipt and the refs the caller
//!   already has — this module never fetches. Agents fetch, gates decide
//!   (the `graph-check` pattern); `linear-check` is what refreshes
//!   `origin/main`. A receipt that cannot be read or parsed is
//!   [`Validity::Missing`], never valid — fail closed, the same posture as
//!   the bash readers' failed `cat`.
//! * **Git facts come from fixed, read-only plumbing queries** (`git
//!   rev-parse`, `git show HEAD:batten.toml`). A read-effect verb may run a
//!   fixed VCS query; what it must never reach is user-supplied code
//!   (CLOUD-170's actual invariant). These run through [`crate::git::query`],
//!   the one git-plumbing entry point (CLOUD-36) — the private copies this
//!   module used to carry are gone, and a source-level gate keeps them gone.
//! * **`policyDigest` hashes the policy committed at HEAD** (`git show
//!   HEAD:batten.toml`), never working-tree bytes: the statement's subject is
//!   a commit digest, so every byte it binds must come from that commit.

use std::io::Write;
use std::path::Path;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::UsageError;
use crate::exit::ExitCode;
use crate::{git, identity, state};

/// The in-toto Statement v1 type identifier (CLOUD-132: adopt the format).
const STATEMENT_TYPE: &str = "https://in-toto.io/Statement/v1";

/// Batten's receipt predicate type. The predicate vocabulary is Batten's own;
/// the envelope is in-toto's.
const PREDICATE_TYPE: &str = "https://batten.dev/receipt/v1";

/// The scope key of a receipt's identity tuple. Receipt-specific so a receipt
/// for check `x` can never alias a repo-scoped finding for a rule named `x`.
const RECEIPT_SCOPE_KEY: &str = "verification-receipt";

/// The one conclusion `record` writes: the bash spec writes a receipt only
/// after the named check passed, and a failed check leaves none — which is the
/// whole invalidation model. The field carries the attestation vocabulary.
const CONCLUSION_PASS: &str = "pass";

/// A verification receipt: an in-toto Statement whose subject is the commit
/// digest and whose predicate is the verification claim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Statement {
    /// The in-toto statement type, always [`STATEMENT_TYPE`].
    #[serde(rename = "_type")]
    pub statement_type: String,
    /// The artifacts the claim is about: exactly one, the verified commit.
    pub subject: Vec<Subject>,
    /// The predicate type, always [`PREDICATE_TYPE`].
    #[serde(rename = "predicateType")]
    pub predicate_type: String,
    /// The verification claim itself.
    pub predicate: Predicate,
}

/// One in-toto subject: a name plus a digest set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Subject {
    /// The repository's directory name, derived at runtime — never a baked-in
    /// identifier (rule 1).
    pub name: String,
    /// The subject digest — the commit, in in-toto's `gitCommit` algorithm key.
    pub digest: SubjectDigest,
}

/// The in-toto digest set for a subject; `gitCommit` is the standard key for
/// a git commit SHA.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubjectDigest {
    /// The full commit SHA the check passed against.
    #[serde(rename = "gitCommit")]
    pub git_commit: String,
}

/// The verification claim: which check passed, against which refs, under which
/// policy, from which checkout.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Predicate {
    /// The named check whose conclusion this receipt records.
    pub check: String,
    /// The `origin/main` SHA the check was current against; a main that moves
    /// afterwards invalidates the receipt instead of silently still counting.
    #[serde(rename = "recordedMain")]
    pub recorded_main: String,
    /// The absolute git dir the receipt was taken in — receipts are
    /// per-checkout facts, so one clone or worktree cannot authorise another.
    #[serde(rename = "recordedGitDir")]
    pub recorded_git_dir: String,
    /// Digest of the policy (`batten.toml`) committed at the subject commit.
    #[serde(rename = "policyDigest")]
    pub policy_digest: PolicyDigest,
    /// When the conclusion was recorded (RFC 3339 UTC). Informational — no
    /// validity condition reads it; expiry is a git fact, never a clock.
    #[serde(rename = "recordedAt")]
    pub recorded_at: String,
    /// The recorded conclusion, always [`CONCLUSION_PASS`]: a failed check
    /// writes no receipt.
    pub conclusion: String,
    /// The receipt's content-keyed identity, with its version beside the hash
    /// (CLOUD-123: never inside it).
    pub identity: IdentityRef,
}

/// A digest set for the policy bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyDigest {
    /// Lowercase hex SHA-256.
    pub sha256: String,
}

/// A stored fingerprint plus the identity-function version that produced it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentityRef {
    /// The fingerprint's lowercase hex form — also the receipt's filename key.
    pub fingerprint: String,
    /// The per-kind identity version ([`crate::identity::FindingKind::identity_version`]).
    pub version: String,
}

/// The receipt-validity verdict — the four states of the output contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Validity {
    /// The receipt exists, was taken in this checkout, and both recorded refs
    /// still match.
    Valid,
    /// The receipt's subject commit is no longer HEAD: an amend or a rebase
    /// produced a new commit the check never ran against.
    StaleHead,
    /// `origin/main` moved since the check ran: the branch may no longer be
    /// linear on it.
    StaleMain,
    /// No usable receipt for this check in this checkout — never recorded,
    /// unreadable, unparseable, or taken in a different clone/worktree. All
    /// fail closed to the same verdict.
    Missing,
}

impl Validity {
    /// The stable lowercase token used in machine output.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Validity::Valid => "valid",
            Validity::StaleHead => "stale-head",
            Validity::StaleMain => "stale-main",
            Validity::Missing => "missing",
        }
    }
}

/// The receipt-validity predicate, a pure function of the receipt and the git
/// facts the caller resolved: exists ∧ taken here ∧ SHA matches HEAD ∧
/// recorded main matches the current ref.
///
/// Evaluation order is the bash readers' order, made total: missing (including
/// a receipt taken in another checkout) → stale-head → stale-main → valid.
/// Fetching is the caller's job — agents fetch, gates decide.
#[must_use]
pub fn validity(
    receipt: Option<&Statement>,
    head: &str,
    current_main: &str,
    git_dir: &str,
) -> Validity {
    let Some(receipt) = receipt else {
        return Validity::Missing;
    };
    let Some(subject) = receipt.subject.first() else {
        return Validity::Missing;
    };
    if receipt.predicate.recorded_git_dir != git_dir {
        return Validity::Missing;
    }
    if subject.digest.git_commit != head {
        return Validity::StaleHead;
    }
    if receipt.predicate.recorded_main != current_main {
        return Validity::StaleMain;
    }
    Validity::Valid
}

/// The git facts both verbs resolve before deciding anything. Read from the
/// refs already on disk — never fetched here.
#[derive(Debug)]
struct RepoFacts {
    /// Full SHA of HEAD.
    head: String,
    /// Full SHA of the local `origin/main` ref.
    main: String,
    /// The absolute git dir — per-worktree by construction.
    git_dir: String,
    /// The working-tree root, from which the state dir derives.
    repo_root: String,
}

fn repo_facts() -> Result<RepoFacts> {
    let git_dir = git::query(
        Path::new("."),
        &["rev-parse", "--absolute-git-dir"],
        "not a git repository, so there is no HEAD to key a receipt to",
    )?;
    // Through the one repo-root primitive (CLOUD-34), never a second toplevel
    // query: a toplevel answers with the *worktree's* own root, so a receipt
    // written from a linked worktree would key itself to a different state
    // directory than the same repository's main checkout.
    let repo_root = git::repo_root(Path::new("."))?
        .to_str()
        .ok_or_else(|| UsageError::raise("the repository root is not valid UTF-8"))?
        .to_owned();
    let head = git::query(
        Path::new("."),
        &["rev-parse", "HEAD"],
        "HEAD does not resolve, so there is no commit to key a receipt to",
    )?;
    let main = git::query(
        Path::new("."),
        &["rev-parse", "origin/main"],
        "origin/main does not resolve, so currency cannot be judged. This is a checkout problem, not a verification failure",
    )?;
    Ok(RepoFacts {
        head,
        main,
        git_dir,
        repo_root,
    })
}

/// Validate a check name for use as an identity field and a filename
/// component: ASCII alphanumeric first, then alphanumeric plus `.`, `_`, `-`.
fn validate_check_name(check: &str) -> Result<()> {
    let mut chars = check.chars();
    let first_ok = chars.next().is_some_and(|c| c.is_ascii_alphanumeric());
    let rest_ok = chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'));
    if first_ok && rest_ok {
        Ok(())
    } else {
        Err(UsageError::raise(format!(
            "check name {check:?} is not a valid identifier (ASCII alphanumeric, then alphanumeric or `.`, `_`, `-`)"
        )))
    }
}

/// The canonical receipt path for a check: `<state>/receipts/<fingerprint>.json`.
fn receipt_path(repo_root: &str, check: &str) -> Result<std::path::PathBuf> {
    let fingerprint = identity::scope_fingerprint(check, RECEIPT_SCOPE_KEY);
    Ok(state::repo_state_dir(Path::new(repo_root))?
        .join("receipts")
        .join(format!("{}.json", fingerprint.to_hex())))
}

/// Load a statement, failing closed: an unreadable, unparseable, or
/// wrong-typed file is `None`, which the predicate reads as missing.
fn load_statement(path: &Path) -> Option<Statement> {
    let bytes = std::fs::read(path).ok()?;
    let statement: Statement = serde_json::from_slice(&bytes).ok()?;
    (statement.statement_type == STATEMENT_TYPE && statement.predicate_type == PREDICATE_TYPE)
        .then_some(statement)
}

fn hex_sha256(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut hex = String::with_capacity(digest.len() * 2);
    for byte in digest {
        // Infallible nibble pushes, the same shape as `Fingerprint::to_hex`.
        hex.push(char::from_digit(u32::from(byte >> 4), 16).unwrap_or('0'));
        hex.push(char::from_digit(u32::from(byte & 0x0f), 16).unwrap_or('0'));
    }
    hex
}

/// Format seconds since the Unix epoch as RFC 3339 UTC (`1970-01-01T00:00:00Z`).
///
/// A hand-written civil-from-days conversion (the standard era-based integer
/// algorithm), total for any post-epoch instant, so the timestamp costs no
/// dependency. The receipt's validity never reads it — expiry is a git fact.
fn rfc3339_utc(unix_seconds: u64) -> String {
    let days = unix_seconds / 86_400;
    let second_of_day = unix_seconds % 86_400;
    let (hour, minute, second) = (
        second_of_day / 3_600,
        (second_of_day % 3_600) / 60,
        second_of_day % 60,
    );
    // Shift to the era starting 0000-03-01; every quantity below is
    // non-negative, so the arithmetic stays in u64.
    let z = days + 719_468;
    let era = z / 146_097;
    let day_of_era = z % 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let mp = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = year_of_era + era * 400 + u64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

/// Record that `check` concluded pass against the current HEAD.
///
/// Writes the canonical statement into the out-of-tree state dir and the
/// grandfathered `$GIT_DIR/batten-receipts/<check>.<head>` compatibility file
/// (content: the recorded main SHA) the bash readers consume. Silent on
/// success — a clean run prints nothing (§6).
///
/// # Errors
///
/// Returns a [`UsageError`] for a bad check name or an unusable checkout (not
/// a repository, unresolvable HEAD or `origin/main`, `batten.toml` not
/// committed at HEAD), and an internal error when a write fails.
pub fn run_record(check: &str) -> Result<ExitCode> {
    validate_check_name(check)?;
    let facts = repo_facts()?;
    let policy = git::query_bytes(
        Path::new("."),
        &["show", "HEAD:batten.toml"],
        "batten.toml is not committed at HEAD, so there is no policy to digest",
    )?;
    let fingerprint = identity::scope_fingerprint(check, RECEIPT_SCOPE_KEY);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since_epoch| since_epoch.as_secs());
    let statement = Statement {
        statement_type: STATEMENT_TYPE.to_owned(),
        subject: vec![Subject {
            name: state::derive_repo_name(Path::new(&facts.repo_root))?,
            digest: SubjectDigest {
                git_commit: facts.head.clone(),
            },
        }],
        predicate_type: PREDICATE_TYPE.to_owned(),
        predicate: Predicate {
            check: check.to_owned(),
            recorded_main: facts.main.clone(),
            recorded_git_dir: facts.git_dir.clone(),
            policy_digest: PolicyDigest {
                sha256: hex_sha256(&policy),
            },
            recorded_at: rfc3339_utc(now),
            conclusion: CONCLUSION_PASS.to_owned(),
            identity: IdentityRef {
                fingerprint: fingerprint.to_hex(),
                version: identity::FindingKind::Scope.identity_version().to_owned(),
            },
        },
    };

    let canonical = receipt_path(&facts.repo_root, check)?;
    let receipts_dir = canonical
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_default();
    std::fs::create_dir_all(&receipts_dir)
        .with_context(|| format!("create the receipt store {}", receipts_dir.display()))?;
    let json = serde_json::to_string_pretty(&statement)?;
    std::fs::write(&canonical, format!("{json}\n"))
        .with_context(|| format!("write the receipt {}", canonical.display()))?;

    let compat_dir = Path::new(&facts.git_dir).join("batten-receipts");
    std::fs::create_dir_all(&compat_dir)
        .with_context(|| format!("create the compatibility store {}", compat_dir.display()))?;
    let compat = compat_dir.join(format!("{check}.{}", facts.head));
    // The recorded main, no trailing newline — the exact bytes ready-guard
    // compares against `git rev-parse origin/main`.
    std::fs::write(&compat, &facts.main)
        .with_context(|| format!("write the compatibility receipt {}", compat.display()))?;

    Ok(ExitCode::Success)
}

/// The `receipt status -J` document: the pointer line's three tokens, named.
///
/// Borrowed rather than owned, so the document is a view over the facts already
/// read and nothing is copied to be serialized.
#[derive(Debug, serde::Serialize)]
struct StatusReport<'a> {
    check: &'a str,
    head: &'a str,
    verdict: &'a str,
}

/// Judge the recorded receipt for `check` against HEAD and `origin/main`.
///
/// Prints the pointer line `<check> <head-sha> <verdict>` — byte-stable, and
/// never the receipt payload; `json` swaps it for the same three tokens as a
/// named document. Exits [`ExitCode::Success`] iff the receipt is
/// valid, [`ExitCode::Violation`] otherwise.
///
/// # Errors
///
/// Returns a [`UsageError`] for a bad check name or an unusable checkout (not
/// a repository, unresolvable HEAD or `origin/main` — a checkout problem is
/// never reported as a verification verdict), and an internal error when the
/// output stream cannot be written.
pub fn run_status(check: &str, json: bool, out: &mut dyn Write) -> Result<ExitCode> {
    validate_check_name(check)?;
    let facts = repo_facts()?;
    let statement = load_statement(&receipt_path(&facts.repo_root, check)?);
    let verdict = validity(statement.as_ref(), &facts.head, &facts.main, &facts.git_dir);
    if json {
        // The same three tokens the pointer line carries, named — so a caller
        // reading the verdict programmatically stops splitting on whitespace and
        // a fourth token could never be mistaken for the third. Emitted for a
        // valid receipt too: a document that is sometimes absent is unparseable.
        let report = StatusReport {
            check,
            head: &facts.head,
            verdict: verdict.as_str(),
        };
        writeln!(out, "{}", serde_json::to_string_pretty(&report)?)?;
    } else {
        writeln!(out, "{check} {} {}", facts.head, verdict.as_str())?;
    }
    Ok(match verdict {
        Validity::Valid => ExitCode::Success,
        Validity::StaleHead | Validity::StaleMain | Validity::Missing => ExitCode::Violation,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn statement(head: &str, main: &str, git_dir: &str) -> Statement {
        Statement {
            statement_type: STATEMENT_TYPE.to_owned(),
            subject: vec![Subject {
                name: "repo".to_owned(),
                digest: SubjectDigest {
                    git_commit: head.to_owned(),
                },
            }],
            predicate_type: PREDICATE_TYPE.to_owned(),
            predicate: Predicate {
                check: "verify".to_owned(),
                recorded_main: main.to_owned(),
                recorded_git_dir: git_dir.to_owned(),
                policy_digest: PolicyDigest {
                    sha256: "00".to_owned(),
                },
                recorded_at: "1970-01-01T00:00:00Z".to_owned(),
                conclusion: CONCLUSION_PASS.to_owned(),
                identity: IdentityRef {
                    fingerprint: "00".to_owned(),
                    version: identity::FindingKind::Scope.identity_version().to_owned(),
                },
            },
        }
    }

    // -- The predicate: all four verdicts, in the bash readers' order. --
    #[test]
    fn validity_covers_all_four_verdicts() {
        let receipt = statement("head1", "main1", "/repo/.git");
        assert_eq!(
            validity(None, "head1", "main1", "/repo/.git"),
            Validity::Missing
        );
        assert_eq!(
            validity(Some(&receipt), "head1", "main1", "/repo/.git"),
            Validity::Valid
        );
        assert_eq!(
            validity(Some(&receipt), "head2", "main1", "/repo/.git"),
            Validity::StaleHead
        );
        assert_eq!(
            validity(Some(&receipt), "head1", "main2", "/repo/.git"),
            Validity::StaleMain
        );
    }

    // -- A receipt from another checkout is missing here, before any staleness
    //    judgement: one worktree's receipt cannot authorise another. --
    #[test]
    fn a_foreign_checkouts_receipt_is_missing_not_stale() {
        let receipt = statement("head2", "main2", "/elsewhere/.git");
        assert_eq!(
            validity(Some(&receipt), "head1", "main1", "/repo/.git"),
            Validity::Missing
        );
    }

    #[test]
    fn a_subjectless_statement_is_missing() {
        let mut receipt = statement("head1", "main1", "/repo/.git");
        receipt.subject.clear();
        assert_eq!(
            validity(Some(&receipt), "head1", "main1", "/repo/.git"),
            Validity::Missing
        );
    }

    // -- Fail closed: junk bytes and foreign statement types are no receipt. --
    #[test]
    fn loading_rejects_junk_and_foreign_types() {
        let dir = std::env::temp_dir().join("batten-receipt-unit");
        std::fs::create_dir_all(&dir).unwrap();
        let junk = dir.join("junk.json");
        std::fs::write(&junk, "not json").unwrap();
        assert!(load_statement(&junk).is_none());

        let foreign = dir.join("foreign.json");
        let mut wrong = statement("h", "m", "/g");
        wrong.predicate_type = "https://example.com/other/v1".to_owned();
        std::fs::write(&foreign, serde_json::to_string(&wrong).unwrap()).unwrap();
        assert!(load_statement(&foreign).is_none());

        assert!(load_statement(&dir.join("absent.json")).is_none());
    }

    #[test]
    fn statements_round_trip_through_json() {
        let receipt = statement("head1", "main1", "/repo/.git");
        let json = serde_json::to_string_pretty(&receipt).unwrap();
        let parsed: Statement = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, receipt);
        // The wire names are the in-toto ones, not the Rust ones.
        assert!(json.contains("\"_type\""));
        assert!(json.contains("\"predicateType\""));
        assert!(json.contains("\"gitCommit\""));
    }

    #[test]
    fn check_names_are_filename_safe_identifiers() {
        assert!(validate_check_name("verify").is_ok());
        assert!(validate_check_name("linear-check").is_ok());
        assert!(validate_check_name("a.b_c-9").is_ok());
        assert!(validate_check_name("").is_err());
        assert!(validate_check_name(".hidden").is_err());
        assert!(validate_check_name("-flag").is_err());
        assert!(validate_check_name("a/b").is_err());
        assert!(validate_check_name("a b").is_err());
        assert!(validate_check_name("..").is_err());
    }

    // -- The timestamp formatter, pinned against known instants. --
    #[test]
    fn rfc3339_formats_known_instants() {
        assert_eq!(rfc3339_utc(0), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339_utc(1_000_000_000), "2001-09-09T01:46:40Z");
        // A leap day, and the day after it.
        assert_eq!(rfc3339_utc(1_709_164_800), "2024-02-29T00:00:00Z");
        assert_eq!(rfc3339_utc(1_709_251_199), "2024-02-29T23:59:59Z");
        assert_eq!(rfc3339_utc(1_709_251_200), "2024-03-01T00:00:00Z");
        // A century boundary that is not a leap year.
        assert_eq!(rfc3339_utc(4_102_444_800), "2100-01-01T00:00:00Z");
    }

    #[test]
    fn receipt_identity_is_content_keyed_per_check() {
        // Two checks are two identities; the same check is one, wherever the
        // receipt is judged from — content-keyed, never path-keyed.
        let verify = identity::scope_fingerprint("verify", RECEIPT_SCOPE_KEY);
        let linear = identity::scope_fingerprint("linear-check", RECEIPT_SCOPE_KEY);
        assert_ne!(verify, linear);
        assert_eq!(
            verify,
            identity::scope_fingerprint("verify", RECEIPT_SCOPE_KEY)
        );
    }
}
