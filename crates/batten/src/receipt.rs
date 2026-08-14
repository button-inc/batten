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
//! * **`configEpoch` binds the whole governing surface at HEAD**, not only the
//!   policy (CLOUD-581). A receipt names *which check passed* and `policyDigest`
//!   names *under which rules*; neither names **which build of the tool decided
//!   it**. For a check that delegates its clause list to an external verifier —
//!   the shape CLOUD-279 verdict 2 settles for conformance checking — the
//!   standard's *edition* lives entirely in that tool's pin, so a receipt
//!   without it cannot answer "against which edition", and claiming it could
//!   would be the overclaim CLOUD-132 bounds.
//!
//!   It is [`crate::epoch::compute`] at `HEAD`, **not** a second digest of a
//!   named lockfile, because which files govern a repository is that
//!   repository's business: a toolchain manifest is `[epoch] tracked` config in
//!   the consumer's own `batten.toml`, and naming one here would put a
//!   consumer's filename in the core (non-negotiable rule 1). It also reuses one
//!   length-prefixed construction over committed bytes instead of inventing a
//!   second, and costs no new config key — which is what CLOUD-279 verdict 2
//!   asked for.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::Path;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::UsageError;
use crate::exit::ExitCode;
use crate::rules::ReceiptKey;
use crate::{git, identity, state};

/// The in-toto Statement v1 type identifier (CLOUD-132: adopt the format).
const STATEMENT_TYPE: &str = "https://in-toto.io/Statement/v1";

/// Batten's receipt predicate type. The predicate vocabulary is Batten's own;
/// the envelope is in-toto's.
const PREDICATE_TYPE: &str = "https://batten.dev/receipt/v1";

/// The agent-context predicate type (CLOUD-579): what the harness reported about
/// itself while the check ran.
///
/// A **second predicate in the same envelope**, not a second format. The
/// `CycloneDX` Agent Bill of Materials is an open specification issue, so there is
/// nothing to emit against; the envelope choice here is reversible — a third
/// `predicateType`
/// alongside these two, whenever it standardises — while a record not taken while
/// the agent was acting cannot be reconstructed afterwards, because the facts live
/// in a session rather than in the tree. Reversible against unrecoverable settles
/// it without predicting the standard.
const AGENT_PREDICATE_TYPE: &str = "https://batten.dev/agent-context/v1";

/// The surfaces an agent-context statement does **not** cover, named in the
/// statement itself.
///
/// CLOUD-279 measured the harness surface and found the exposure partial in ways
/// no amount of engineering closes from inside Batten: `.mcp.json` declared one
/// server while the session reached three, the rest injected at runtime and
/// written to no file a gate can read. A record that omitted this list would look
/// like a complete agent bill of materials, be read as one, and silently understate
/// the composition — the overclaim CLOUD-132 bounds, in the direction that flatters.
///
/// So the bound ships **inside the record**, and [`validate_agent`] refuses a
/// statement without it. A limit stated in a doc comment is a limit the artifact
/// does not carry.
const AGENT_COVERAGE: &[&str] = &[
    "mcp-servers: exercised only; the permitted set is enumerated by no file this engine can read",
    "mcp-server-identity: the host's opaque identifier, with no published name mapping",
    "permission-mode: omitted; it is per-event and changes mid-session, so no single value is true",
    "skills-and-plugins: covered only where the consumer tracks them in `[epoch] tracked`",
];

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
    /// The config epoch at the subject commit — a hash of every file the
    /// consumer declares as governing, which is what lets a receipt name the
    /// *version* of whatever external verifier decided the check (CLOUD-581).
    ///
    /// Deliberately **not** `Option` with a `serde(default)`. A receipt written
    /// before this field existed fails to deserialize, so [`load_statement`]
    /// answers [`Validity::Missing`] and the gate denies until the check is
    /// re-run. That is the module's existing fail-closed direction — a receipt
    /// that cannot be read is never valid — and a default would instead mint an
    /// epoch-shaped hole that reads as "the surface was recorded".
    #[serde(rename = "configEpoch")]
    pub config_epoch: String,
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

/// An agent-context statement: the same in-toto envelope, a different predicate.
///
/// Written **beside** the verification receipt rather than folded into it. The
/// two answer different questions — "did this check pass" and "what was acting
/// when it did" — and only the first is a verdict. Merging them would put a
/// harness-reported fact inside the object [`validity`] decides on, so a host
/// that changed how it reports would move a gate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentStatement {
    /// The in-toto statement type, always [`STATEMENT_TYPE`].
    #[serde(rename = "_type")]
    pub statement_type: String,
    /// The artifacts the claim is about: exactly one, the same commit its
    /// sibling receipt names.
    pub subject: Vec<Subject>,
    /// The predicate type, always [`AGENT_PREDICATE_TYPE`].
    #[serde(rename = "predicateType")]
    pub predicate_type: String,
    /// The agent-context claim itself.
    pub predicate: AgentPredicate,
}

/// What the harness stated about itself while the check ran.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentPredicate {
    /// The check this context accompanies — the same name its sibling records,
    /// so the pair is joinable.
    pub check: String,
    /// The host's session id, when it reported one.
    #[serde(rename = "sessionId", skip_serializing_if = "Option::is_none")]
    pub session: Option<String>,
    /// The config epoch at the subject commit, exactly as the sibling records
    /// it — which is what covers the consumer's tracked agent config without
    /// this engine naming a single one of those files (rule 1).
    #[serde(rename = "configEpoch")]
    pub config_epoch: String,
    /// The distinct models the session recorded.
    pub models: Vec<String>,
    /// The distinct harness versions.
    #[serde(rename = "harnessVersions")]
    pub harness_versions: Vec<String>,
    /// The distinct entrypoints.
    pub entrypoints: Vec<String>,
    /// The distinct MCP servers a call was attributed to. **Exercised, not
    /// permitted** — the name is the claim's bound, and `coverage` states why.
    #[serde(rename = "exercisedMcpServers")]
    pub exercised_mcp_servers: Vec<String>,
    /// When the context was recorded (RFC 3339 UTC).
    #[serde(rename = "recordedAt")]
    pub recorded_at: String,
    /// What this statement does not cover. Never empty — [`validate_agent`]
    /// refuses a statement whose bound is missing.
    pub coverage: Vec<String>,
}

/// Refuse an agent-context statement that states no bound.
///
/// The one invariant this type has that its sibling does not, and it is a gate
/// rather than a convention: a record without `coverage` reads as a complete
/// agent bill of materials, and CLOUD-279 measured that it is not one. Enforced
/// here so removing the bound fails rather than quietly widening the claim.
///
/// # Errors
///
/// [`UsageError`] when `coverage` is empty or the envelope is not this type's.
pub fn validate_agent(statement: &AgentStatement) -> Result<()> {
    if statement.predicate_type != AGENT_PREDICATE_TYPE {
        return Err(UsageError::raise(format!(
            "an agent-context statement must carry predicateType {AGENT_PREDICATE_TYPE}"
        )));
    }
    if statement.predicate.coverage.is_empty() {
        return Err(UsageError::raise(
            "an agent-context statement with no `coverage` claims completeness it cannot have: the permitted tool set and the effective MCP composition are readable from no file, so an unbounded record understates what was in effect",
        ));
    }
    Ok(())
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

/// Resolve the verdict for each named check, for a caller that must not do I/O.
///
/// `hook::adjudicate` is contractually pure — "no I/O, no environment, no
/// clock" — so a mediated call cannot evaluate a receipt predicate itself. This
/// is the boundary half: the hook's entry point resolves the facts once and
/// hands them in as data, exactly as it already does for the bypass hatch. The
/// predicate stays [`validity`], unchanged and total, so the `hook` surface and
/// `receipt status` cannot come to disagree about what a valid receipt is.
///
/// `None` means **could not look**, not "no receipts": outside a checkout, or
/// with an `origin/main` that does not resolve, there are no git facts to judge
/// against. A caller reads that as allow — the fail-open posture every retiring
/// guard has, and the one CLOUD-312 §5 preserves end to end. It is deliberately
/// distinct from `Some(Missing)`, which is a real verdict about a real
/// repository and denies.
pub(crate) fn verdicts(
    checks: &BTreeMap<String, ReceiptKey>,
) -> Option<BTreeMap<String, Validity>> {
    let facts = repo_facts().ok()?;
    // The branch, resolved once and only when a branch-keyed row asked for it.
    // A detached HEAD has no branch to key a claim on, and that resolves the
    // whole call to "could not look" rather than to a missing receipt: denying
    // there would refuse every edit during a rebase conflict resolution, which
    // is the one moment the workflow contract says a human decision is required.
    let branch = if checks.values().any(|key| *key == ReceiptKey::Branch) {
        Some(crate::git::current_branch(Path::new(".")).ok()??)
    } else {
        None
    };
    Some(
        checks
            .iter()
            .map(|(check, key)| {
                let verdict = match key {
                    ReceiptKey::Head => {
                        let statement = receipt_path(&facts.repo_root, check)
                            .ok()
                            .and_then(|path| load_statement(&path));
                        validity(statement.as_ref(), &facts.head, &facts.main, &facts.git_dir)
                    }
                    ReceiptKey::Branch => branch.as_deref().map_or(Validity::Missing, |branch| {
                        branch_validity(&facts.git_dir, check, branch)
                    }),
                };
                (check.clone(), verdict)
            })
            .collect(),
    )
}

/// The filename a branch-keyed receipt takes: `<check>.<branch>`, with every
/// path separator replaced.
///
/// **A crate↔task contract, not an internal detail.** `mise-tasks/claim-check`
/// mints this file and this reads it, so the two spellings must agree exactly or
/// the gate silently reports a missing receipt for one that exists — a deny on a
/// claim that was made. A slash is the one character a filename cannot carry and
/// a branch name routinely does; nothing else in a branch name needs escaping
/// here. `tests::the_branch_receipt_filename_matches_the_minting_task` is what
/// stops the two halves drifting.
fn branch_receipt_name(check: &str, branch: &str) -> String {
    format!("{check}.{}", branch.replace('/', "-"))
}

/// Whether a branch-keyed receipt exists for `check` on `branch`.
///
/// Existence **is** the verdict, and only two of the four [`Validity`] states are
/// reachable: a branch-keyed receipt attests to a decision about the work rather
/// than to a set of bytes, so neither a new commit ([`Validity::StaleHead`]) nor a
/// moved trunk ([`Validity::StaleMain`]) can invalidate it. That asymmetry is the
/// whole reason the second keying exists — a SHA-keyed claim would demand a
/// re-claim per commit, which is the false-positive rate that gets a guard
/// bypassed.
///
/// Read from `--git-dir`, so it resolves per worktree and one worktree's claim
/// cannot vouch for another's.
fn branch_validity(git_dir: &str, check: &str, branch: &str) -> Validity {
    let path = Path::new(git_dir)
        .join("batten-receipts")
        .join(branch_receipt_name(check, branch));
    if path.is_file() {
        Validity::Valid
    } else {
        Validity::Missing
    }
}

/// Resolve `.` and `..` without touching the filesystem.
///
/// The lexical half of what `realpath -m` did for the bash guard this ports: the
/// target need not exist, so nothing here may require it to. A `..` above the
/// root is dropped rather than escaping into a prefix, which keeps the result a
/// path this containment test can compare.
fn lexically_normal(path: std::path::PathBuf) -> std::path::PathBuf {
    let mut normalised = std::path::PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                normalised.pop();
            }
            other => normalised.push(other),
        }
    }
    normalised
}

/// Whether a written path is one policy may judge at all (CLOUD-444).
///
/// The write-triggered receipt row's exclusion set, ported from
/// the bash guard this retires, where each exclusion is what keeps the guard's
/// false-positive rate survivable *structurally* rather than by tuning:
///
/// * **outside the repository** — not this repository's policy to enforce;
/// * **git-ignored** — the scratch-work half, closed honestly by asking git
///   rather than by guessing which paths are scratch;
/// * **inside `.git`** — receipts, hooks and index state are the machinery, not
///   the work.
///
/// An untracked-but-not-ignored path is deliberately **judged**: opening a new
/// feature file is the first edit the gate exists to catch, and exempting
/// untracked paths would leave the hole open in its commonest form.
///
/// **Every answer it cannot establish is `false`, which allows.** A path that is
/// not valid UTF-8 after canonicalisation, a repository root that does not
/// resolve, a git that will not answer — each resolves to "not judgeable", the
/// fail-open posture CLOUD-312 §5 preserves end to end.
pub(crate) fn judgeable(path: &str) -> bool {
    let Ok(root) = crate::git::repo_root(Path::new(".")) else {
        return false;
    };
    // `absolute` rather than `canonicalize`: the file need not exist yet, which
    // is exactly the new-feature-file case, and canonicalising a missing path
    // fails. Symlink resolution is deliberately not attempted — a link out of the
    // tree reads as inside it, which over-judges, and the direction that matters
    // is that nothing inside the tree escapes.
    //
    // The `..` components are then resolved LEXICALLY, and that is not
    // housekeeping. `absolute` only prepends the working directory, so
    // `../sibling.md` becomes `<root>/../sibling.md` — a path that begins with the
    // root and is therefore judged as inside it. Measured on this suite's own
    // outside-the-repository case, which failed before the normalisation existed.
    //
    // **Note the direction is opposite to `hook::normalise`'s**, which
    // deliberately leaves `..` alone: there, an unresolved traversal misses a
    // protected path and UNDER-denies, the sanctioned direction. Here it
    // OVER-denies — it refuses a write to a path outside the repository — and an
    // over-denying claim gate is the false-positive rate that gets a guard
    // switched off.
    let Ok(absolute) = std::path::absolute(Path::new(path)).map(lexically_normal) else {
        return false;
    };
    if !absolute.starts_with(&root) {
        return false;
    }
    if absolute
        .strip_prefix(&root)
        .is_ok_and(|relative| relative.starts_with(".git"))
    {
        return false;
    }
    let Some(target) = absolute.to_str() else {
        return false;
    };
    !crate::git::check_ignore(Path::new("."), target).unwrap_or(true)
}

/// Load a statement, failing closed: an unreadable, unparseable, or
/// wrong-typed file is `None`, which the predicate reads as missing.
fn load_statement(path: &Path) -> Option<Statement> {
    let bytes = std::fs::read(path).ok()?;
    let statement: Statement = serde_json::from_slice(&bytes).ok()?;
    (statement.statement_type == STATEMENT_TYPE && statement.predicate_type == PREDICATE_TYPE)
        .then_some(statement)
}

/// Lowercase hex SHA-256 over `bytes` — the value an in-toto digest set's
/// `sha256` key carries.
///
/// Public because the envelope's digest vocabulary is shared: [`crate::design`]
/// binds a capture with the same digest-set spelling, and a second hash of the
/// same bytes written in a second module is how two "sha256" fields come to
/// disagree. A *plain* digest, deliberately not [`crate::identity`]'s
/// domain-tagged construction: this value is produced by whatever attestation
/// tool wrote the record, so it must be the ordinary one anybody can reproduce.
#[must_use]
pub fn hex_sha256(bytes: &[u8]) -> String {
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
/// The date half comes from [`crate::waiver::Date::from_unix_seconds`] — one
/// hand-written civil-from-days conversion in the tree rather than two, so a date
/// still costs no dependency and cannot be right in one module and wrong in the
/// other. Only the time-of-day arithmetic is here.
///
/// **The receipt's validity never reads this timestamp — expiry is a git fact,
/// never a clock.** That is right *here* and does not generalise: a receipt's
/// claim is about a specific SHA, so a SHA comparison is the invalidator. A
/// waiver's claim is a human judgement whose warrant decays in calendar time and
/// leaves no git trace, which is why [`crate::waiver`] does evaluate a clock — at
/// its boundary, with the date threaded in as data. Different claims, different
/// invalidators (CLOUD-208).
pub(crate) fn rfc3339_utc(unix_seconds: u64) -> String {
    let date = crate::waiver::Date::from_unix_seconds(unix_seconds);
    let second_of_day = unix_seconds % 86_400;
    let (hour, minute, second) = (
        second_of_day / 3_600,
        (second_of_day % 3_600) / 60,
        second_of_day % 60,
    );
    format!("{}T{hour:02}:{minute:02}:{second:02}Z", date.text())
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
    // At HEAD, never the working tree, for the same reason the policy is: the
    // subject is a commit digest, so every byte the statement binds comes from
    // that commit. `compute` resolves BOTH the tracked list and the tracked
    // bytes from the ref, so an uncommitted edit to a governing file — a pin
    // bump included — does not move this value, and the next `record` after it
    // lands does.
    let config_epoch = crate::epoch::compute(Path::new("."), Some("HEAD"))?;
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
            config_epoch,
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

    record_agent_context(check, &facts, &statement.subject, now)?;

    Ok(ExitCode::Success)
}

/// The agent-context path of [`run_record`] (CLOUD-579).
///
/// Silent and side-effect-free when no transcript is configured: a repository
/// that never named one is not missing one, and minting an empty statement would
/// read as "nothing was in effect" rather than "nothing was stated". A configured
/// path with nothing at it is reported, for the same reason — the caller asked
/// for the record and did not get it.
fn record_agent_context(
    check: &str,
    facts: &RepoFacts,
    subject: &[Subject],
    now: u64,
) -> Result<()> {
    let config = crate::config::load(Path::new(crate::config::CONFIG_FILE))?;
    let declared = config
        .transcript
        .as_ref()
        .and_then(|declared| declared.path.as_deref());
    let agent = match crate::transcript::resolve(Path::new("."), declared)? {
        crate::transcript::Capability::Unconfigured => return Ok(()),
        crate::transcript::Capability::Absent => {
            return Err(UsageError::raise(format!(
                "{}, so no agent-context statement was written",
                crate::transcript::ABSENT_NOTICE
            )));
        }
        crate::transcript::Capability::Present(stream) => stream,
    };

    let statement = AgentStatement {
        statement_type: STATEMENT_TYPE.to_owned(),
        subject: subject.to_vec(),
        predicate_type: AGENT_PREDICATE_TYPE.to_owned(),
        predicate: AgentPredicate {
            check: check.to_owned(),
            session: agent.session.clone(),
            config_epoch: crate::epoch::compute(Path::new("."), Some("HEAD"))?,
            models: agent.agent.models.iter().cloned().collect(),
            harness_versions: agent.agent.harness_versions.iter().cloned().collect(),
            entrypoints: agent.agent.entrypoints.iter().cloned().collect(),
            exercised_mcp_servers: agent.agent.exercised_mcp_servers.iter().cloned().collect(),
            recorded_at: rfc3339_utc(now),
            coverage: AGENT_COVERAGE
                .iter()
                .map(|note| (*note).to_owned())
                .collect(),
        },
    };
    // Refused before it is written, never after: a statement that reached disk
    // without its bound is one a reader can already act on.
    validate_agent(&statement)?;

    let path = agent_path(&facts.repo_root, check)?;
    let json = serde_json::to_string_pretty(&statement)?;
    std::fs::write(&path, format!("{json}\n"))
        .with_context(|| format!("write the agent-context statement {}", path.display()))?;
    Ok(())
}

/// The agent-context statement's path: the receipt's own, with a second
/// extension, so the pair sits together and neither can overwrite the other.
fn agent_path(repo_root: &str, check: &str) -> Result<std::path::PathBuf> {
    let fingerprint = identity::scope_fingerprint(check, RECEIPT_SCOPE_KEY);
    Ok(state::repo_state_dir(Path::new(repo_root))?
        .join("receipts")
        .join(format!("{}.agent-context.json", fingerprint.to_hex())))
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
                config_epoch: "epoch1".to_owned(),
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
        assert!(json.contains("\"configEpoch\""));
    }

    fn agent_statement(coverage: Vec<String>) -> AgentStatement {
        AgentStatement {
            statement_type: STATEMENT_TYPE.to_owned(),
            subject: vec![Subject {
                name: "repo".to_owned(),
                digest: SubjectDigest {
                    git_commit: "head1".to_owned(),
                },
            }],
            predicate_type: AGENT_PREDICATE_TYPE.to_owned(),
            predicate: AgentPredicate {
                check: "verify".to_owned(),
                session: Some("s-1".to_owned()),
                config_epoch: "epoch1".to_owned(),
                models: vec!["m".to_owned()],
                harness_versions: vec![],
                entrypoints: vec![],
                exercised_mcp_servers: vec![],
                recorded_at: "1970-01-01T00:00:00Z".to_owned(),
                coverage,
            },
        }
    }

    /// CLOUD-579's second acceptance bullet: the bound is enforced, not
    /// documented. A statement with no `coverage` claims a completeness
    /// CLOUD-279 measured it cannot have.
    #[test]
    fn an_agent_statement_without_its_bound_is_refused() {
        let bounded = agent_statement(vec!["mcp-servers: exercised only".to_owned()]);
        assert!(validate_agent(&bounded).is_ok());

        let unbounded = agent_statement(Vec::new());
        let err = validate_agent(&unbounded).unwrap_err();
        assert!(
            err.to_string().contains("coverage"),
            "the refusal names the missing bound"
        );
    }

    /// The bound `run_record` actually ships is one the validator accepts, so
    /// the two cannot drift into a state where every recorded statement would
    /// be refused — or, worse, where the shipped notes are blank strings that
    /// satisfy the length check and state nothing.
    #[test]
    fn the_shipped_coverage_is_one_the_validator_accepts() {
        let shipped = agent_statement(
            AGENT_COVERAGE
                .iter()
                .map(|note| (*note).to_owned())
                .collect(),
        );
        assert!(validate_agent(&shipped).is_ok());
        assert!(
            AGENT_COVERAGE.iter().all(|note| !note.is_empty()),
            "a blank note is a bound that states nothing"
        );
    }

    /// A receipt written before `configEpoch` existed must read as
    /// [`Validity::Missing`], not as a valid receipt with an empty surface
    /// (CLOUD-581). This is the whole reason the field is not
    /// `Option`+`serde(default)`: fail closed, the same posture an unreadable
    /// receipt already gets.
    #[test]
    fn a_receipt_predating_the_epoch_field_is_missing() {
        let dir = std::env::temp_dir().join("batten-receipt-pre-epoch");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("legacy.json");

        // The exact shape `run_record` wrote before this field landed.
        let legacy = serde_json::json!({
            "_type": STATEMENT_TYPE,
            "subject": [{ "name": "repo", "digest": { "gitCommit": "head1" } }],
            "predicateType": PREDICATE_TYPE,
            "predicate": {
                "check": "verify",
                "recordedMain": "main1",
                "recordedGitDir": "/repo/.git",
                "policyDigest": { "sha256": "00" },
                "recordedAt": "1970-01-01T00:00:00Z",
                "conclusion": CONCLUSION_PASS,
                "identity": { "fingerprint": "00", "version": "1" },
            },
        });
        std::fs::write(&path, serde_json::to_string(&legacy).unwrap()).unwrap();

        let loaded = load_statement(&path);
        assert!(
            loaded.is_none(),
            "a predicate missing configEpoch is unusable"
        );
        assert_eq!(
            validity(loaded.as_ref(), "head1", "main1", "/repo/.git"),
            Validity::Missing,
            "and the verdict denies rather than passing over an unrecorded surface"
        );
        let _ = std::fs::remove_file(&path);
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
    fn the_branch_receipt_filename_matches_the_minting_task() {
        // The crate↔task contract (CLOUD-444), pinned as a grep in the
        // `hook::tests::the_redirect_pseudo_program_token_is_declared_not_implied`
        // idiom. `mise-tasks/claim-check` writes this file and this module reads
        // it; if the two spellings drift, the gate reports a missing receipt for
        // one that exists — a deny on a claim that was actually made, which no
        // in-crate test could catch on its own.
        //
        // The task interpolates the branch with bash's own substitution, so the
        // literal to look for is the prefix plus that substitution.
        let task = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../mise-tasks/claim-check"
        ))
        .expect("read the minting task");
        assert!(
            task.contains("batten-receipts/claim.${branch//\\//-}"),
            "claim-check no longer writes the filename this module reads"
        );
        assert_eq!(
            branch_receipt_name("claim", "user/cloud-444-slug"),
            "claim.user-cloud-444-slug"
        );
        // Every separator, not merely the first: a branch name may carry several.
        assert_eq!(branch_receipt_name("claim", "a/b/c"), "claim.a-b-c");
        // A name needing no substitution is unchanged.
        assert_eq!(branch_receipt_name("claim", "main"), "claim.main");
    }

    #[test]
    fn a_traversal_is_resolved_before_the_containment_test() {
        // The defect this closes, found by the end-to-end suite rather than by
        // reading the code: `absolute` only prepends the working directory, so
        // `../sibling.md` began with the repository root and was judged as inside
        // it — a deny on a write OUTSIDE the repository, which is the
        // over-denying direction a claim gate cannot afford.
        assert_eq!(
            lexically_normal(std::path::PathBuf::from("/repo/../sibling.md")),
            std::path::PathBuf::from("/sibling.md")
        );
        assert_eq!(
            lexically_normal(std::path::PathBuf::from("/repo/./src/../src/x.rs")),
            std::path::PathBuf::from("/repo/src/x.rs")
        );
        // A traversal above the root stays a path rather than escaping upward.
        assert_eq!(
            lexically_normal(std::path::PathBuf::from("/../../x")),
            std::path::PathBuf::from("/x")
        );
        // A path needing no resolution is unchanged.
        assert_eq!(
            lexically_normal(std::path::PathBuf::from("/repo/src/x.rs")),
            std::path::PathBuf::from("/repo/src/x.rs")
        );
    }

    #[test]
    fn a_branch_keyed_verdict_is_existence_and_nothing_else() {
        // Only two of the four states are reachable under a branch key: a claim
        // attests to a decision about the work, so neither a new commit nor a
        // moved trunk can invalidate it. That is the whole reason for the second
        // keying — a SHA-keyed claim would demand a re-claim per commit.
        let dir = tempdir();
        let git_dir = dir.to_str().expect("utf-8 scratch path");
        assert_eq!(
            branch_validity(git_dir, "claim", "feature"),
            Validity::Missing
        );
        let receipts = dir.join("batten-receipts");
        std::fs::create_dir_all(&receipts).expect("create the store");
        std::fs::write(receipts.join("claim.feature"), "CLOUD-444\n").expect("mint");
        assert_eq!(
            branch_validity(git_dir, "claim", "feature"),
            Validity::Valid
        );
        // A receipt for another branch does not vouch for this one.
        assert_eq!(
            branch_validity(git_dir, "claim", "other"),
            Validity::Missing
        );
        // Nor does another check's receipt on the same branch.
        assert_eq!(
            branch_validity(git_dir, "verify", "feature"),
            Validity::Missing
        );
        // A directory at the path is not a receipt: `is_file` is what makes the
        // store's own parent directory unable to answer for a check called
        // nothing.
        std::fs::create_dir_all(receipts.join("claim.dir")).expect("create a directory");
        assert_eq!(branch_validity(git_dir, "claim", "dir"), Validity::Missing);
    }

    /// A per-process scratch directory, in this crate's unit-test idiom
    /// (`drain`, `findings`): `CARGO_TARGET_TMPDIR` is integration-only, and a
    /// pid-suffixed name keeps concurrent test binaries from sharing one.
    fn tempdir() -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("batten-branch-receipt-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create the scratch dir");
        dir
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
