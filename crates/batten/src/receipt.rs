//! Verification receipts (CLOUD-203): SHA-keyed claims that a named check
//! passed, with an expiry condition that is a git fact.
//!
//! The behavioural spec is the bash receipt system this module ports —
//! `mise.toml`'s `verify` body and `mise-tasks/linear-check.sh` write receipts
//! keyed to the exact HEAD they validated, and `mise-tasks/ready-guard.sh` /
//! `mise-tasks/verified.sh` honour them only while HEAD and the recorded
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
//! * **Git facts come from named questions in one module**
//!   ([`crate::git::git_dir`], [`crate::git::head_commit`],
//!   [`crate::git::resolve_ref`], [`crate::git::commit_count`],
//!   [`crate::git::show`]). A read-effect verb may run a fixed VCS query; what
//!   it must never reach is user-supplied code (CLOUD-170's actual invariant).
//!   The private git copies this module used to carry are gone (CLOUD-36), and
//!   the argv it used to assemble itself went with them (CLOUD-742) — a
//!   source-level gate keeps both gone.
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
use crate::output::{Mode, Verbosity};
use crate::rules::ReceiptKey;
use crate::{config, git, identity, output, state};

/// The in-toto Statement v1 type identifier (CLOUD-132: adopt the format).
///
/// Public since CLOUD-1051, because [`crate::admission`]'s override record is a
/// third statement in the same envelope. One constant rather than a second
/// spelling: an envelope identifier written twice is two things that can drift,
/// and the whole point of adopting a format is that a reader recognises it.
pub const STATEMENT_TYPE: &str = "https://in-toto.io/Statement/v1";

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

/// The receipt-validity verdict — the SIX states of the output contract.
///
/// It said "four" for its whole life while six variants stood below it
/// (CLOUD-1091, fixed in passing). A count in prose beside the thing it counts
/// is the drift `.claude/rules/toolchain.md` records for its own tables, and the
/// two staleness variants are exactly the pair a reader would assume away.
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
    /// The receipt is for the right subject and still matches every recorded
    /// ref, and is older than the declaring row's `max_age` allows (CLOUD-988).
    ///
    /// Distinct from [`Validity::Missing`] because the remedy is different and a
    /// pointer that names the wrong one sends the reader looking for a step they
    /// already ran: this says *run it again*, where `Missing` says *run it*. Same
    /// reason the two staleness variants are not one.
    Expired,
    /// The receipt is otherwise good, and the field the declaring row reads says
    /// something other than what that row requires (CLOUD-1100).
    ///
    /// **This is the only variant that is a statement about what was READ rather
    /// than about the read.** Every other one answers *is there a usable receipt
    /// for this subject*; this one answers *and did it record the verdict this
    /// row needs*. It is distinct from [`Validity::Missing`] and
    /// [`Validity::Expired`] because all three have different remedies, and a
    /// pointer naming the wrong one sends the reader to run a step again when
    /// what they actually owe is a change to the subject.
    ///
    /// An **absent** field never reaches here: it is could-not-look, and it
    /// answers [`Validity::Valid`]. That direction is what lets a field bound be
    /// declared over a receipt family already on disk without invalidating a
    /// single receipt already written.
    Refuted,
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
            Validity::Expired => "expired",
            Validity::Refuted => "refuted",
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
    let git_dir = git::git_dir(Path::new("."))
        .map_err(|_| {
            UsageError::raise("not a git repository, so there is no HEAD to key a receipt to")
        })?
        .to_str()
        .ok_or_else(|| UsageError::raise("the git directory is not valid UTF-8"))?
        .to_owned();
    // Through the one repo-root primitive (CLOUD-34), never a second toplevel
    // query: a toplevel answers with the *worktree's* own root, so a receipt
    // written from a linked worktree would key itself to a different state
    // directory than the same repository's main checkout.
    let repo_root = git::repo_root(Path::new("."))?
        .to_str()
        .ok_or_else(|| UsageError::raise("the repository root is not valid UTF-8"))?
        .to_owned();
    let head = git::head_commit(Path::new(".")).map_err(|_| {
        UsageError::raise("HEAD does not resolve, so there is no commit to key a receipt to")
    })?;
    // `resolve_ref` answers `None` for a ref that is simply not there, and this
    // caller owes that case its own reading (CLOUD-51): a missing `origin/main`
    // is a checkout that cannot be judged, never a checkout that is current.
    let main = git::resolve_ref(Path::new("."), "origin/main")?.ok_or_else(|| {
        UsageError::raise(
            "origin/main does not resolve, so currency cannot be judged. This is a checkout problem, not a verification failure",
        )
    })?;
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
/// Where each agent-sourced check's record lives on this call, resolved once
/// (CLOUD-859).
///
/// **One resolution for every check, rather than one per check.** Both readers —
/// the receipt verdict and the policy input's record set — ask about the same
/// checks on the same call, and each of them used to call [`git::git_dir`]
/// per check. The subjects a declared key resolves to are facts about the
/// checkout, so they are resolved here, at the boundary, exactly as
/// [`verdicts`] resolves them for the receipt store.
pub(crate) struct SourcedStore {
    /// The absolute git dir — per-worktree by construction, as [`RepoFacts`].
    git_dir: std::path::PathBuf,
    /// The subject each check's record files under, by check name.
    subjects: BTreeMap<String, String>,
}

impl SourcedStore {
    /// Where `check`'s record lives, or `None` if no subject resolved for it.
    fn path(&self, check: &str) -> Option<std::path::PathBuf> {
        let subject = self.subjects.get(check)?;
        Some(crate::facts::sourced_path(&self.git_dir, check, subject))
    }

    /// Read one agent-sourced fact's record, if it exists and parses
    /// (CLOUD-776).
    ///
    /// The I/O half, at the boundary — the deciding half is
    /// [`crate::facts::sourced`] and is pure. Unreadable and unparseable both
    /// answer `None`, which that function turns into
    /// [`crate::facts::Look::CouldNotLook`]: fail closed to *we do not know*,
    /// never to a fact. A record filed under a DIFFERENT subject is simply
    /// absent here, and lands on that same arm — which is the whole of
    /// CLOUD-859's fix, since the existing three-valued contract already carries
    /// it and no new verdict was needed.
    pub(crate) fn record(&self, check: &str) -> Option<crate::facts::Sourced> {
        crate::facts::Sourced::parse(&std::fs::read_to_string(self.path(check)?).ok()?)
    }

    /// Whether `check`'s record is older than the declaring row's bound
    /// (CLOUD-988).
    ///
    /// Discarded on this path until CLOUD-859: `max_ages` reached
    /// `receipt_facts` and the agent-sourced loop never read it, so neither the
    /// head nor the clock bounded the evidence. Reads the file's mtime rather
    /// than the record's own `seen_at`, because [`older_than`] is already the
    /// one spelling of *how old is a receipt* and a second one is a second thing
    /// to drift.
    pub(crate) fn expired(&self, check: &str, max_age: u64, now: std::time::SystemTime) -> bool {
        self.path(check)
            .is_some_and(|path| older_than(&path, max_age, now))
    }
}

/// Resolve the subject every agent-sourced check on this call files under.
///
/// `None` is **could not look** and takes the whole agent-sourced arm with it —
/// the fail-open direction [`verdicts`] documents, and for its reason: a gate
/// that cannot see the repository must not become a gate that denies everything.
/// An empty `checks` answers an empty store having done no git work at all,
/// which is the narrowing every other fact on this path applies.
pub(crate) fn sourced_store(
    checks: &[(&String, &ReceiptKey)],
    named: Option<&str>,
) -> Option<SourcedStore> {
    if checks.is_empty() {
        return Some(SourcedStore {
            git_dir: std::path::PathBuf::new(),
            subjects: BTreeMap::new(),
        });
    }
    let git_dir = git::git_dir(Path::new(".")).ok()?;
    // Resolved once, and only where a row asked — a head-keyed caller must not
    // pay a branch lookup for a question it never asks. `current_branch` rather
    // than `branch_facts`: that one also counts this branch's own commits, which
    // `branch_validity` needs and a record filed by name does not.
    let head = if checks.iter().any(|(_, key)| **key == ReceiptKey::Head) {
        Some(git::head_commit(Path::new(".")).ok()?)
    } else {
        None
    };
    let branch = if checks.iter().any(|(_, key)| **key == ReceiptKey::Branch) {
        Some(git::current_branch(Path::new(".")).ok()??)
    } else {
        None
    };
    // `named` over an agent-sourced check is REFUSED AT LOAD
    // (`facts::validate_keying`), so this is reachable only from a policy
    // assembled in-process. Resolved anyway rather than left to a wildcard arm
    // below: `_ =>` would silently absorb a fourth keying, which is the shape
    // `facts.rs`'s own no-wildcard scan exists to refuse.
    let named = if checks.iter().any(|(_, key)| **key == ReceiptKey::Named) {
        Some(named.filter(|value| safe_subject(value))?.to_owned())
    } else {
        None
    };
    let mut subjects = BTreeMap::new();
    for (check, key) in checks {
        let subject = match key {
            ReceiptKey::Head => head.clone()?,
            ReceiptKey::Branch => branch.clone()?,
            ReceiptKey::Named => named.clone()?,
        };
        subjects.insert((*check).clone(), subject);
    }
    Some(SourcedStore { git_dir, subjects })
}

/// The subject ONE agent-sourced fact's record is written under (CLOUD-859).
///
/// The write half of [`sourced_store`], and separate from it because the two
/// sides ask on different calls: the read resolves subjects for the checks a
/// mediated call requires, and the write resolves one for the fact whose command
/// just ran. That difference is exactly why
/// [`crate::facts::validate_keying`] refuses `named` for an agent-sourced
/// check — this envelope carries no subject to project — so the third arm is
/// unreachable through a loaded config and is written out rather than wildcarded.
fn sourced_subject(key: ReceiptKey, named: Option<&str>) -> Option<String> {
    match key {
        ReceiptKey::Head => git::head_commit(Path::new(".")).ok(),
        ReceiptKey::Branch => git::current_branch(Path::new(".")).ok()?,
        ReceiptKey::Named => named
            .filter(|value| safe_subject(value))
            .map(ToOwned::to_owned),
    }
}

/// Write one agent-sourced fact's record (CLOUD-776).
///
/// The only write this channel makes, and it carries a COUNT rather than the
/// buffer it was derived from (rule 4): a command's stdout can hold anything, so
/// nothing under the state root may reproduce it.
///
/// **Filed under the key the declaring row states** (CLOUD-859), resolved here
/// because `adjudicate` may not look and the reader resolves the same subject
/// the same way. `rules::validate` refuses one check required under two keys, so
/// there is exactly one subject to file under and the two halves cannot disagree
/// about where the record is.
///
/// # Errors
///
/// Propagates a failure to locate the git dir, to resolve the key's subject, or
/// to write the record. A caller on the mediated path treats that as *could not
/// record* and allows — a hook that cannot write a fact must not become the
/// reason work stops.
pub fn record_sourced(
    name: &str,
    key: ReceiptKey,
    named: Option<&str>,
    record: &crate::facts::Sourced,
) -> Result<()> {
    let git_dir = git::git_dir(Path::new(".")).map_err(|_| {
        UsageError::raise(
            "not a git repository, so there is nowhere an agent-sourced fact could be recorded",
        )
    })?;
    let subject = sourced_subject(key, named).ok_or_else(|| {
        UsageError::raise(
            "the declared key's subject does not resolve in this checkout, so there is no subject to file an agent-sourced record under",
        )
    })?;
    let path = crate::facts::sourced_path(&git_dir, name, &subject);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, record.render())?;
    Ok(())
}

/// Whether `subject` is safe to use as one path component under the receipt
/// store (CLOUD-987).
///
/// **Refused, never rewritten.** The subject of a [`ReceiptKey::Named`] receipt
/// comes out of the mediated call's own arguments, so it is the least trusted
/// string in the envelope that this engine turns into a filename. Rewriting a bad
/// one — stripping separators, replacing `..` — would file two different subjects
/// under one receipt and let a fresh read of A authorise a stale write to B,
/// which is precisely the confusion `ReceiptKey::Named` exists to prevent. So a
/// value that is not already a single safe component is not a subject at all.
///
/// The bound is structural rather than a format: what a tracker's identifiers
/// look like is a consumer fact (non-negotiable rule 1), and a row that wants to
/// insist on a shape has `when_present` and its own selection for that. What the
/// core knows is that a path component may not be empty, may not be `.` or `..`,
/// may not contain a separator or a NUL, and may not be unboundedly long.
///
/// `pub(crate)` since CLOUD-1024: the mint that WRITES a named receipt has to
/// refuse exactly the subjects the reader refuses, or the two halves disagree
/// about which filenames exist.
pub(crate) fn safe_subject(subject: &str) -> bool {
    !subject.is_empty()
        && subject != "."
        && subject != ".."
        && subject.len() <= 128
        && !subject.contains(|ch: char| ch == '/' || ch == '\\' || ch == '\0' || ch.is_control())
}

/// Where a receipt for `check` under `key` lives, so its age can be read.
///
/// One spelling per keying, taken from the three validity functions rather than
/// invented here — a second spelling of a receipt filename is a second thing to
/// drift, and the store this reads has to be the store they read.
fn receipt_file(
    facts: &RepoFacts,
    check: &str,
    key: ReceiptKey,
    branch: Option<&str>,
    named: Option<&str>,
) -> Option<std::path::PathBuf> {
    let store = Path::new(&facts.git_dir).join("batten-receipts");
    match key {
        ReceiptKey::Head => receipt_path(&facts.repo_root, check).ok(),
        ReceiptKey::Branch => branch.map(|branch| store.join(branch_receipt_name(check, branch))),
        ReceiptKey::Named => named.map(|subject| store.join(format!("{check}.{subject}"))),
    }
}

/// Whether the receipt at `path` is older than `max_age` seconds at `now`.
///
/// **`false` on anything it cannot establish**, which is the fail-open direction
/// every other could-not-look in this module takes: a filesystem with no mtime, a
/// clock behind the file's timestamp, or an unreadable stat leaves the verdict
/// exactly as the validity functions decided it. An age nobody could measure must
/// not become a refusal — that would make a guard fail on a property of the
/// environment rather than of the work.
fn older_than(path: &Path, max_age: u64, now: std::time::SystemTime) -> bool {
    let Ok(modified) = std::fs::metadata(path).and_then(|meta| meta.modified()) else {
        return false;
    };
    now.duration_since(modified)
        .is_ok_and(|elapsed| elapsed.as_secs() > max_age)
}

/// The receipt verdicts for `checks`, one per check.
///
/// `max_ages` carries CLOUD-988's declared bounds, and `now` is the clock those
/// bounds are read against — **handed in rather than taken**, the waiver table's
/// precedent, so the decision this feeds stays a pure function of facts somebody
/// else resolved.
pub(crate) fn verdicts(
    checks: &BTreeMap<String, ReceiptKey>,
    subject: Option<&str>,
    max_ages: &BTreeMap<String, u64>,
    field_bounds: &BTreeMap<String, crate::rules::FieldBound>,
    now: std::time::SystemTime,
) -> Option<BTreeMap<String, Validity>> {
    let facts = repo_facts().ok()?;
    // Resolved once, and only when a branch-keyed row asked for it: a head-keyed
    // caller must not pay two extra git invocations for a question it never
    // asks. `None` here resolves the WHOLE call to "could not look" rather than
    // to a missing receipt — see [`branch_facts`] for why that direction is the
    // safe one.
    let branch = if checks.values().any(|key| *key == ReceiptKey::Branch) {
        Some(branch_facts(&facts.main)?)
    } else {
        None
    };
    // The same shape one line up, and the same reason (CLOUD-987): resolved only
    // when a `named`-keyed row asked, and `None` takes the WHOLE call to
    // could-not-look rather than to a missing receipt.
    //
    // A subject this engine will not file under is not a receipt verdict — it is
    // not having looked. Refusing on it would turn a judgement about the shape of
    // an argument into a judgement about the receipt, and `safe_subject` explains
    // why the bad value is refused rather than rewritten.
    let named = if checks.values().any(|key| *key == ReceiptKey::Named) {
        Some(subject.filter(|value| safe_subject(value))?.to_owned())
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
                    ReceiptKey::Branch => {
                        branch.as_ref().map_or(Validity::Missing, |(branch, own)| {
                            branch_validity(&facts.git_dir, check, branch, &facts.head, *own)
                        })
                    }
                    // Resolved once above, for `branch`'s reason, and `None` there
                    // already took the whole call to could-not-look — so by here
                    // the subject is present and safe.
                    ReceiptKey::Named => named.as_ref().map_or(Validity::Missing, |value| {
                        named_validity(&facts.git_dir, check, value)
                    }),
                };
                // THE AGE IS READ LAST, AND ONLY OVER A RECEIPT THAT WAS
                // OTHERWISE GOOD (CLOUD-988). A receipt already Missing or stale
                // has a more specific answer and a different remedy; downgrading
                // it to Expired would replace a precise pointer with a vaguer
                // one. And a repository declaring no bound pays no `stat` at all
                // — CLOUD-460's cheap-when-irrelevant, applied to the column.
                let verdict = match (verdict, max_ages.get(check)) {
                    (Validity::Valid, Some(&max_age)) => receipt_file(
                        &facts,
                        check,
                        *key,
                        branch.as_ref().map(|(branch, _)| branch.as_str()),
                        named.as_deref(),
                    )
                    .filter(|path| older_than(path, max_age, now))
                    .map_or(Validity::Valid, |_| Validity::Expired),
                    (verdict, _) => verdict,
                };
                // THE FIELD IS READ LAST, AND ONLY OVER A RECEIPT THAT SURVIVED
                // EVERYTHING ABOVE (CLOUD-1100) — the same ordering `max_age`
                // takes one arm up, for the same reason. A receipt that is
                // missing, stale or expired already has a more specific answer
                // and a different remedy, and reading a field out of it would
                // replace that pointer with a vaguer one. A repository declaring
                // no bound opens no receipt at all.
                let verdict = match (verdict, field_bounds.get(check)) {
                    (Validity::Valid, Some(bound)) => receipt_file(
                        &facts,
                        check,
                        *key,
                        branch.as_ref().map(|(branch, _)| branch.as_str()),
                        named.as_deref(),
                    )
                    .map_or(Validity::Valid, |path| {
                        if field_refutes(&path, bound) {
                            Validity::Refuted
                        } else {
                            Validity::Valid
                        }
                    }),
                    (verdict, _) => verdict,
                };
                (check.clone(), verdict)
            })
            .collect(),
    )
}

/// The two facts a branch-keyed verdict needs beyond [`repo_facts`]: which branch
/// HEAD is on, and how many commits that branch carries of its own.
///
/// **`None` is "could not look", never a missing receipt.** A detached HEAD has
/// no branch to key a claim on, and a rebase detaches — so denying there would
/// refuse every edit during a rebase conflict resolution, the one moment the
/// workflow contract says a human decision is required. Every caller must map
/// `None` to its own "cannot answer" outcome and never to a verdict.
///
/// Extracted so the mediated row ([`verdicts`]) and the CLI ([`run_status`])
/// resolve it identically (CLOUD-741). They previously could not: a `receipt`
/// rule is pinned to `RuleScope::MediatedCall`, so `verify` had re-implemented
/// the branch-keyed question in shell as a presence test — strictly weaker than
/// this, and green on the exact restart CLOUD-516 was filed for.
fn branch_facts(main: &str) -> Option<(String, usize)> {
    let branch = crate::git::current_branch(Path::new(".")).ok()??;
    let own = own_commit_count(main)?;
    Some((branch, own))
}

/// How many commits this branch carries that `origin/main` does not, or `None`
/// for "could not look".
///
/// Resolved separately from [`RepoFacts`] because a head-keyed receipt never
/// needs it and it costs a git invocation on the mediated hot path. `None`
/// propagates to the fail-open posture `verdicts` documents: a gate that cannot
/// see the repository must not become a gate that denies everything.
///
/// **A range, not a reachability verdict.** CLOUD-36 forbids deciding anything
/// by ancestry — a rebased landing is invisible to it — and leaves range forms
/// legal precisely because selecting which commits to count is a different act
/// from concluding one commit contains another. This counts; it concludes
/// nothing about whether the branch landed.
fn own_commit_count(main: &str) -> Option<usize> {
    git::commit_count(Path::new("."), &format!("{main}..HEAD")).ok()
}

/// The filename a branch-keyed receipt takes: `<check>.<branch>`, with every
/// path separator replaced.
///
/// **A crate↔task contract, not an internal detail.** `mise-tasks/claim-check.sh`
/// mints this file and this reads it, so the two spellings must agree exactly or
/// the gate silently reports a missing receipt for one that exists — a deny on a
/// claim that was made. A slash is the one character a filename cannot carry and
/// a branch name routinely does; nothing else in a branch name needs escaping
/// here. `tests::the_branch_receipt_filename_matches_the_minting_task` is what
/// stops the two halves drifting.
fn branch_receipt_name(check: &str, branch: &str) -> String {
    format!("{check}.{}", branch.replace('/', "-"))
}

/// Whether a receipt exists for `check` against the subject the call named
/// (CLOUD-987).
///
/// **The subject is not a ref, so neither staleness verdict is reachable here.**
/// [`Validity::StaleHead`] and [`Validity::StaleMain`] both compare a recorded
/// ref against the checkout, and the subject of a `named` receipt is a row on
/// somebody's board — a commit moving says nothing about it. So this answers
/// existence, and says so rather than implying more.
///
/// **THIS FUNCTION STILL DOES NOT ESTABLISH RECENCY, AND NO LONGER HAS TO.** The
/// division is the load-bearing part: `adjudicate` reads no clock — pinned by
/// `adjudicate_reads_no_clock_even_now_that_a_waiver_can_lapse` — so a clock
/// belongs where the waiver table's does, supplied by the boundary and never
/// taken inside the decision. CLOUD-988 supplied it: a row declares `max_age`,
/// [`receipt_validity`] is handed a `now`, and a `Valid` answer from here is
/// downgraded to [`Validity::Expired`] when the receipt file is older than the
/// bound. So the answer this variant gives is still *which subject*, and *how
/// fresh* is one layer out.
///
/// Which means CLOUD-312's row 2 IS expressible now, and is configured
/// (`an-update-owes-a-recent-read`) — the sentence that said otherwise outlived
/// the column that closed it. The age read there is the receipt file's **mtime**,
/// not a field of its body: nothing here parses the receipt, so there is no
/// half-read line to mistake for a verdict.
///
/// No `replace('/', "-")` twin to [`branch_receipt_name`]: a branch name
/// legitimately contains separators and is rewritten, where a subject that
/// contains one is refused by `safe_subject` before it reaches here. Rewriting
/// would let two subjects collide onto one receipt.
fn named_validity(git_dir: &str, check: &str, subject: &str) -> Validity {
    let path = Path::new(git_dir)
        .join("batten-receipts")
        .join(format!("{check}.{subject}"));
    if std::fs::read_to_string(&path).is_ok() {
        Validity::Valid
    } else {
        Validity::Missing
    }
}

/// Whether a branch-keyed receipt for `check` on `branch` still describes this
/// branch.
///
/// A new commit cannot invalidate it ([`Validity::StaleHead`] stays unreachable):
/// a branch-keyed receipt attests to a decision about the *work* rather than to a
/// set of bytes, and a SHA-keyed claim would demand a re-claim per commit — the
/// false-positive rate that gets a guard bypassed. That asymmetry is the whole
/// reason the second keying exists.
///
/// **But existence alone is not the verdict, and CLOUD-516 is why.** A branch NAME
/// outlives the branch it described: `git checkout -B <name> origin/main` is the
/// documented remedy once a PR merges, and it repoints the name at a new base and
/// discards the old commits while this file, keyed by the name, survives. Measured
/// 2026-08-13 — a receipt naming CLOUD-230 authorised every edit behind four
/// unrelated stories, and reported nothing. A gate passing on evidence that
/// expired is the silent false green this repository treats as worse than no gate.
///
/// So the receipt records the `origin/main` it was minted against, and is void
/// ([`Validity::StaleMain`]) when **both** halves hold:
///
/// ```text
/// situation                                    base moved   own   ahead   verdict
/// ---------------------------------------------------------------------------------
/// claim, then work                             no           0->n  -       valid
/// a lap rebases onto newer main                yes          >=1   -       VALID
/// main moves, branch untouched                 yes          >=1   -       valid
/// checkout -B <name> origin/main after a merge yes          0     >0      VOID
/// branch cut from an earlier main, unrebased   yes          0     0       VALID
/// ```
///
/// **The last row is CLOUD-1091 and it is the one this comparison got wrong for
/// its whole life.** `recorded != head` is symmetric and the situation is not:
/// it fires just as readily when the receipt's base is NEWER than HEAD, which is
/// an ordinary freshly-cut branch in a repository landing ~40 commits a day. The
/// receipt is then more current than the branch, and the remedy the refusal
/// prescribes — take the evidence again — appends a correct base and changes
/// nothing, because the comparison still runs against HEAD. Measured
/// 2026-08-28: three honest searches, three identical refusals, cleared only by
/// a fast-forward merge the message never mentions.
///
/// So the conjunct is the DIRECTION: void only where HEAD carries commits the
/// recorded base does not, which is the restart and nothing else.
///
/// **The own-commits half is what makes this safe to ship.** The obvious rule —
/// void it whenever the base moves — fires on every `land` lap, because a lap
/// rebases onto the current `origin/main` and that is the loop working, not a
/// fault. A restart is the one state with a moved base and nothing of its own,
/// because the restart discarded the commits that were the branch. No timestamps,
/// no reflog, no heuristics.
///
/// **"Base moved" is read off HEAD, not off a merge base**, and the two are the
/// same commit in the only case that reaches the comparison: with no commits of
/// its own the branch sits at or below `origin/main`, so where it forks *is*
/// HEAD. That equivalence is what keeps CLOUD-36 satisfied — nothing here decides
/// anything by reachability — and it drops a git invocation from the mediated hot
/// path, since HEAD is already resolved for the head-keyed rows.
///
/// A receipt carrying no `base` line is void rather than valid, so receipts
/// predating this change do not grandfather themselves in.
///
/// Read from `--git-dir`, so it resolves per worktree and one worktree's claim
/// cannot vouch for another's.
fn branch_validity(git_dir: &str, check: &str, branch: &str, head: &str, own: usize) -> Validity {
    branch_validity_with(git_dir, check, branch, head, own, moved_forward)
}

/// How many commits `head` carries that `base` does not, or `None` for "could
/// not look".
///
/// A RANGE, exactly as [`own_commit_count`] is one, and legal for its reason:
/// CLOUD-36 forbids concluding that one commit CONTAINS another, and leaves
/// range forms alone because selecting which commits to count is a different act
/// from drawing that conclusion. This counts; it concludes nothing about
/// landing.
fn moved_forward(base: &str, head: &str) -> Option<usize> {
    git::commit_count(Path::new("."), &format!("{base}..{head}")).ok()
}

/// [`branch_validity`] with the range reader injected, so the direction below is
/// testable without a repository per case.
fn branch_validity_with(
    git_dir: &str,
    check: &str,
    branch: &str,
    head: &str,
    own: usize,
    ahead: impl Fn(&str, &str) -> Option<usize>,
) -> Validity {
    let path = Path::new(git_dir)
        .join("batten-receipts")
        .join(branch_receipt_name(check, branch));
    let Ok(body) = std::fs::read_to_string(&path) else {
        return Validity::Missing;
    };
    let recorded = recorded_base(&body);
    // Absent, unreadable, or `-`: the claim cannot say what it was made against,
    // which is exactly as unproven as one made against something that moved.
    let Some(recorded) = recorded else {
        return Validity::StaleMain;
    };
    if own != 0 || recorded == head {
        return Validity::Valid;
    }
    // THE DIRECTION IS THE MISSING CONJUNCT (CLOUD-1091). `recorded != head` is
    // symmetric and the situation is not:
    //
    //   * CLOUD-516's RESTART — `checkout -B <name> origin/main` after a merge —
    //     moves the branch FORWARD off a base the receipt predates. `recorded`
    //     is an older main, so `head` carries commits `recorded` does not, and
    //     the receipt describes work that is gone. Void.
    //   * A branch merely BEHIND `origin/main` — cut from an earlier main and
    //     not yet rebased — has a receipt taken against the CURRENT main, so
    //     `head` carries nothing `recorded` does not. The receipt is MORE
    //     current than the branch, not less. Valid.
    //
    // Measured 2026-08-28 on `claude/stage-2-3-grooming-uqk71k`: an
    // `issue-search` receipt recording the current `origin/main` was voided, and
    // three fresh searches refused identically, because the remedy the refusal
    // prescribes appends a correct base that the comparison then ignores. The
    // loop broke only on a fast-forward merge, which the message never asks for.
    //
    // Could-not-look stays VOID rather than becoming valid: this change widens
    // what passes only where the repository can actually be read, so an
    // unreadable range cannot be the thing that admits a stale claim.
    match ahead(&recorded, head) {
        Some(0) => Validity::Valid,
        Some(_) | None => Validity::StaleMain,
    }
}

/// The `base <sha>` line a claim receipt carries, or `None` when it carries none.
///
/// Matched by KEY rather than by line number: `mise-tasks/claim-check.sh` writes the
/// id list on line 1 and has already grown two more fields under it (CLOUD-431),
/// so a positional reader would break on the next one. `-` is the task's own
/// spelling for "origin/main did not resolve when I minted this" and reads as
/// absent here, never as a base that happens to match nothing.
///
/// **The LAST such line, not the first, because every writer APPENDS**
/// (CLOUD-1057). `issue-search-check.sh` and `claim-check.sh` both open the
/// receipt with `>>`, so a branch that mints twice carries two `base` lines and
/// the newer one describes the evidence just taken.
///
/// Reading the first pinned the verdict to the oldest base a branch ever
/// recorded, and crossed with [`branch_validity`]'s `own == 0` arm that made the
/// refusal **unclearable**: a branch whose PR had merged was told its receipt was
/// stale, and running the step the refusal prescribed appended a correct base
/// that this function then ignored. Measured — three `base` lines on one receipt,
/// the first from a release two tags back, the last equal to HEAD, verdict
/// `stale-main` twice over two honest searches.
///
/// A remedy that cannot reach the state it prescribes is worse than no remedy,
/// because the author reads the gate as broken rather than the receipt as stale;
/// `mise-tasks/suite-bench.sh` records the same lesson for its own report.
///
/// **The reader is the half that was wrong, not the writers.** A receipt is
/// append-only on purpose — see the CLOUD-431 note above — so a truncating writer
/// would have to know which of the other lines to carry forward.
fn recorded_base(body: &str) -> Option<String> {
    body.lines()
        .filter_map(|line| line.strip_prefix("base "))
        .next_back()
        .map(str::trim)
        .filter(|base| !base.is_empty() && *base != "-")
        .map(str::to_owned)
}

/// Resolve `.` and `..` without touching the filesystem.
///
/// The lexical half of what `realpath -m` did for the bash guard this ports: the
/// target need not exist, so nothing here may require it to. A `..` above the
/// root is dropped rather than escaping into a prefix, which keeps the result a
/// path this containment test can compare.
fn lexically_normal(path: &Path) -> std::path::PathBuf {
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
    let Ok(absolute) =
        std::path::absolute(Path::new(path)).map(|absolute| lexically_normal(&absolute))
    else {
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
#[must_use]
pub fn rfc3339_utc(unix_seconds: u64) -> String {
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
///
/// A transcript this verb cannot read is NOT among them (CLOUD-819): see
/// [`record_agent_context`].
pub fn run_record(check: &str, mode: Mode, err: &mut dyn Write) -> Result<ExitCode> {
    validate_check_name(check)?;
    let facts = repo_facts()?;
    let policy = git::show(Path::new("."), "HEAD", config::CONFIG_FILE)
        .map_err(|_| {
            UsageError::raise(
                "batten.toml is not committed at HEAD, so there is no policy to digest",
            )
        })?
        .into_bytes();
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

    record_agent_context(check, &facts, &statement.subject, now, mode, err)?;

    Ok(ExitCode::Success)
}

/// The agent-context path of [`run_record`] (CLOUD-579).
///
/// Silent and side-effect-free when no transcript is configured: a repository
/// that never named one is not missing one, and minting an empty statement would
/// read as "nothing was in effect" rather than "nothing was stated".
///
/// # A transcript this verb cannot read is REPORTED, never a refusal (CLOUD-819)
///
/// It used to raise, and `run_record` calls this last — so the receipt reached
/// disk and `batten receipt record` still exited 1. `mise-tasks/linear-check.sh`
/// ends with that command under `set -e`, so `verify`, and therefore `land`,
/// stopped on a gate that had already measured linearity correctly. The three
/// states `batten.toml`'s `[transcript]` header calls ORDINARY — a fresh
/// checkout, a non-Claude host, a gate run by hand outside a turn — are exactly
/// the three where nothing could land.
///
/// The reasoning it raised for was right about the STATEMENT and wrong about the
/// exit code: "nothing was stated" and "nothing was in effect" are different
/// claims, so no statement is written here either way. What changes is that the
/// verb reports and returns, which is what [`crate::lib`]'s message path already
/// did with the same constant. Nothing in the tree reads the agent-context file,
/// so its absence gates nothing downstream — only the exit code did.
///
/// **Two unreadable states, one verdict, and the second is not silent.** Absent
/// is a missing file; a line that does not decode is [`crate::transcript::parse`]
/// refusing the whole stream. Both are could-not-look about the ENVIRONMENT
/// rather than about this commit, and both write no statement — the second
/// carries a `<label>:<line>` pointer so the seam can be repaired.
///
/// **What this deliberately does not do**: it does not make
/// [`crate::transcript::resolve`] lenient. The policy paths that read the stream
/// — bypass detection and self-write detection — still take a decode failure as
/// a usage error and exit 1, because a rule that silently read a truncated
/// transcript as a clean one is the false green this whole module exists to
/// avoid. The narrowing is to this verb, whose subject is a receipt.
fn record_agent_context(
    check: &str,
    facts: &RepoFacts,
    subject: &[Subject],
    now: u64,
    mode: Mode,
    err: &mut dyn Write,
) -> Result<()> {
    let config = crate::config::load(Path::new(crate::config::CONFIG_FILE))?;
    let declared = config
        .transcript
        .as_ref()
        .and_then(|declared| declared.path.as_deref());
    let agent = match crate::transcript::resolve(Path::new("."), declared) {
        crate::transcript::Capability::Unconfigured => return Ok(()),
        // One arm per state, beside absent rather than catching an error before
        // the match. `resolve` is total (CLOUD-819), so there is no second
        // reading of the same fact hiding in an `Err` branch.
        crate::transcript::Capability::Unreadable(pointer) => {
            output::message(
                mode,
                Verbosity::Normal,
                err,
                &format!("{} ({pointer})", crate::transcript::UNREADABLE_NOTICE),
            )?;
            return Ok(());
        }
        crate::transcript::Capability::Absent => {
            output::message(
                mode,
                Verbosity::Normal,
                err,
                &format!(
                    "{}, so no agent-context statement was written",
                    crate::transcript::ABSENT_NOTICE
                ),
            )?;
            return Ok(());
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

/// The `receipt status -J` document: the pointer line's tokens, named.
///
/// Borrowed rather than owned, so the document is a view over the facts already
/// read and nothing is copied to be serialized.
///
/// **`key` and `subject` rather than a bare `head`** (CLOUD-741). The second
/// token is the git fact the verdict was judged against, and once `--key branch`
/// exists that is a SHA under one keying and a branch name under the other. A
/// field whose meaning silently changes with a flag is exactly what the `json`
/// arm exists to prevent, so the keying is named beside it and the field is not
/// called `head` when it is not one.
#[derive(Debug, serde::Serialize)]
struct StatusReport<'a> {
    check: &'a str,
    key: &'a str,
    subject: &'a str,
    verdict: &'a str,
}

/// Judge the recorded receipt for `check` against the git fact `key` names.
///
/// Prints the pointer line `<check> <subject> <verdict>` — byte-stable, and
/// never the receipt payload; `json` swaps it for the same tokens as a named
/// document. The subject is HEAD under [`ReceiptKey::Head`] and the branch name
/// under [`ReceiptKey::Branch`].
///
/// **This is the whole point of the verb gaining a key** (CLOUD-741). A
/// `receipt` rule is pinned to `RuleScope::MediatedCall`, so `batten check`
/// cannot evaluate one and `verify` cannot reach [`branch_validity`] through the
/// engine — it had re-implemented the question in shell as a presence test,
/// which passed the exact branch restart CLOUD-516 was filed for. Exposing the
/// keying here lets the tree surface call the one implementation instead of
/// growing a second.
///
/// Exits [`ExitCode::Success`] iff the receipt is valid and
/// [`ExitCode::Violation`] otherwise.
///
/// # Errors
///
/// Returns a [`UsageError`] for a bad check name or an unusable checkout (not
/// a repository, unresolvable HEAD or `origin/main` — a checkout problem is
/// never reported as a verification verdict), and an internal error when the
/// output stream cannot be written.
///
/// A **detached HEAD under `--key branch`** is an internal error rather than a
/// verdict, for [`branch_facts`]'s reason: a rebase detaches, and answering
/// "not valid" there would make every rebase look like an unclaimed branch.
pub fn run_status(
    check: &str,
    key: ReceiptKey,
    json: bool,
    out: &mut dyn Write,
) -> Result<ExitCode> {
    validate_check_name(check)?;
    let facts = repo_facts()?;
    let (subject, verdict) = match key {
        // REFUSED FROM THIS VERB, and stated rather than left inert (CLOUD-987).
        //
        // `--key` exists for the operator question CLOUD-741 added: judge a
        // receipt against a fact of the CHECKOUT. A `named` receipt's subject is
        // an argument of a mediated call, which this verb has no way to name and
        // should not invent — a default subject would answer about a row nobody
        // asked about. The two uses of `ReceiptKey` have diverged that far, and a
        // usage error saying so is honest where a silently-wrong verdict is not.
        ReceiptKey::Named => {
            return Err(UsageError::raise(
                "receipt status --key named: a named receipt is keyed on a subject the mediated call supplies, and this verb has none to give. It is read by `batten hook` from the declaring row's `key_from` projection.",
            ));
        }
        ReceiptKey::Head => {
            let statement = load_statement(&receipt_path(&facts.repo_root, check)?);
            (
                facts.head.clone(),
                validity(statement.as_ref(), &facts.head, &facts.main, &facts.git_dir),
            )
        }
        ReceiptKey::Branch => {
            let Some((branch, own)) = branch_facts(&facts.main) else {
                return Err(anyhow::anyhow!(
                    "receipt status --key branch: HEAD is detached, so there is no branch to key a receipt on. This is not a verdict about the receipt — a rebase detaches, and reporting one here would read as an unclaimed branch."
                ));
            };
            let verdict = branch_validity(&facts.git_dir, check, &branch, &facts.head, own);
            (branch, verdict)
        }
    };
    if json {
        // The same tokens the pointer line carries, named — so a caller reading
        // the verdict programmatically stops splitting on whitespace and a
        // further token could never be mistaken for the last. Emitted for a
        // valid receipt too: a document that is sometimes absent is unparseable.
        let report = StatusReport {
            check,
            key: key_token(key),
            subject: &subject,
            verdict: verdict.as_str(),
        };
        writeln!(out, "{}", serde_json::to_string_pretty(&report)?)?;
    } else {
        writeln!(out, "{check} {subject} {}", verdict.as_str())?;
    }
    Ok(match verdict {
        Validity::Valid => ExitCode::Success,
        Validity::StaleHead
        | Validity::StaleMain
        | Validity::Missing
        | Validity::Expired
        | Validity::Refuted => ExitCode::Violation,
    })
}

/// Whether the receipt at `path` records something other than what `bound`
/// requires (CLOUD-1100).
///
/// **Every could-not-look answers `false`**, and the list is deliberate rather
/// than incidental: an unreadable file, an empty one, a first line with fewer
/// fields than the bound names. Each of those is a statement about the receipt's
/// shape, and refusing on one would speak a verdict about the environment in a
/// verdict about the subject — the direction `Read::Status`'s unmapped-status
/// rule refuses one module over, and the direction that lets this column be
/// declared over receipts already on disk.
///
/// The FIRST line only. A `mode = "append"` receipt is a journal and asking which
/// of its lines carries the verdict is a different question with a different
/// answer; a `mode = "replace"` receipt has exactly one line, which is the family
/// this column is for.
fn field_refutes(path: &Path, bound: &crate::rules::FieldBound) -> bool {
    let Ok(text) = std::fs::read_to_string(path) else {
        return false;
    };
    let Some(line) = text.lines().next() else {
        return false;
    };
    // `at` is 1-indexed, as every prose reader of these receipts already counts.
    // `checked_sub` rather than a subtraction the loader has already made
    // impossible: a panic on a reachable path is what the workspace lints forbid,
    // and "the loader refuses it" is a claim about a different file.
    let Some(index) = bound.at.checked_sub(1) else {
        return false;
    };
    let Some(field) = line.split_whitespace().nth(index) else {
        return false;
    };
    // THE ABSENT TOKEN IS COULD-NOT-LOOK, not a value that differs. It is this
    // crate's one spelling for *nothing to say* — [`crate::mint::ABSENT`] and
    // [`crate::recorder::ABSENT`] are the same character for the same reason — so
    // a renderer that could not judge writes it, and reading that as a refusal
    // would turn every payload the authority could not parse into a deny.
    field != crate::recorder::ABSENT && field != bound.is
}

/// The wire spelling of a [`ReceiptKey`], for the `-J` document.
///
/// Matched rather than derived from `Debug`: the token is part of the output
/// contract, and a `Debug` rename would move it without failing anything.
const fn key_token(key: ReceiptKey) -> &'static str {
    match key {
        ReceiptKey::Head => "head",
        ReceiptKey::Branch => "branch",
        ReceiptKey::Named => "named",
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {

    /// The three-valued read, and the two arms that must ALLOW.
    ///
    /// `Refuted` is the only verdict in this module that is a statement about
    /// what a receipt RECORDED rather than about whether one exists, so it is the
    /// only one that can turn a property of the environment into a refusal about
    /// somebody's row. Both could-not-look arms are asserted here rather than
    /// left to the integration tier, because the direction is the whole design.
    #[test]
    fn a_field_bound_refutes_only_a_field_that_says_something_else() {
        let dir = std::env::temp_dir().join(format!("batten-field-bound-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("the scratch directory is creatable");
        let bound = crate::rules::FieldBound {
            at: 6,
            is: "ready".to_owned(),
        };
        let case = |body: &str| {
            let path = dir.join("receipt");
            std::fs::write(&path, body).expect("the receipt is writable");
            field_refutes(&path, &bound)
        };

        assert!(
            !case("CLOUD-1 t 1 - todo ready\n"),
            "the required value satisfies"
        );
        assert!(
            case("CLOUD-1 t 1 - todo unready\n"),
            "and any other value refutes"
        );
        assert!(
            !case("CLOUD-1 t 1 - todo\n"),
            "a receipt with fewer fields than the bound names is could-not-look"
        );
        assert!(
            !case("CLOUD-1 t 1 - todo -\n"),
            "and so is the absent token, which is what a renderer writes when it could not judge"
        );
        assert!(
            !case(""),
            "an empty receipt is could-not-look, never a refusal"
        );
        assert!(
            !field_refutes(&dir.join("nothing-here"), &bound),
            "and so is a receipt that cannot be read at all"
        );

        // The FIRST line only: an appending receipt is a journal, and which of its
        // lines carries the verdict is a different question with a different
        // answer. Reading further would let a later line silently outrank the one
        // the replacing families write.
        assert!(
            !case("CLOUD-1 t 1 - todo ready\nCLOUD-1 t 2 - todo unready\n"),
            "the first line decides, so a later one cannot outrank it"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
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
    fn the_branch_receipt_filename_matches_the_minter() {
        // The reader↔writer contract (CLOUD-444). The writer creates this file and
        // this module reads it; if the two spellings drift, the gate reports a
        // missing receipt for one that exists — a deny on a claim that was
        // actually made, which no test on either side alone could catch.
        //
        // IT ASSERTS OVER THE MINTED PATH NOW, NOT OVER A SHELL SOURCE
        // (CLOUD-1121). This was a grep of `mise-tasks/claim-check.sh` for the
        // bash substitution that built the name, which was the best available
        // while the two halves were in different languages: a text test, blind to
        // a rename that kept the literal and to a literal that stopped being
        // reached. `claim::mint` is the writer since the retirement, so the two
        // spellings can be compared as VALUES.
        let dir = tempdir("name-contract");
        let receipts = dir.join("batten-receipts");
        let issues = [crate::claim::Issue {
            id: "CLOUD-1".to_owned(),
            status: "Todo".to_owned(),
            assigned: false,
            live_pr: None,
            description: None,
        }];
        let minted = crate::claim::mint(
            &receipts,
            "user/cloud-444-slug",
            &issues,
            &crate::claim::Verdict::default(),
            &crate::claim::Request::default(),
            None,
            "2026-01-01T00:00:00Z",
        )
        .expect("mint a receipt");
        assert_eq!(
            minted.file_name().and_then(|name| name.to_str()),
            Some(branch_receipt_name("claim", "user/cloud-444-slug").as_str()),
            "the minter no longer writes the filename this module reads"
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

    /// A receipt body in the shape `mise-tasks/claim-check.sh` mints, so the reader
    /// is exercised against the real format rather than a convenient one.
    fn minted(base: Option<&str>) -> String {
        let mut body = String::from(
            "CLOUD-516\nready-lint pass\nclaimed-at 2026-08-13T14:13:03Z\nupdated-at CLOUD-516 2026-08-13T07:37:37Z\n",
        );
        if let Some(base) = base {
            body.push_str("base ");
            body.push_str(base);
            body.push('\n');
        }
        body
    }

    /// The range reader every case supplies for itself (CLOUD-1091).
    ///
    /// Injected rather than resolved, because the DIRECTION is now the predicate
    /// and a scratch directory is not a repository — a case reading the real
    /// range would get could-not-look and pass for that reason instead of for
    /// the one it is about.
    fn judge_ahead(
        case: &str,
        body: &str,
        head: &str,
        own: usize,
        ahead: Option<usize>,
    ) -> Validity {
        let dir = tempdir(case);
        let receipts = dir.join("batten-receipts");
        std::fs::create_dir_all(&receipts).expect("create the store");
        std::fs::write(receipts.join("claim.branch"), body).expect("mint");
        branch_validity_with(
            dir.to_str().expect("utf-8 scratch path"),
            "claim",
            "branch",
            head,
            own,
            |_, _| ahead,
        )
    }

    fn judge(case: &str, body: &str, head: &str, own: usize) -> Validity {
        let dir = tempdir(case);
        let receipts = dir.join("batten-receipts");
        std::fs::create_dir_all(&receipts).expect("create the store");
        std::fs::write(receipts.join("claim.branch"), body).expect("mint");
        branch_validity(
            dir.to_str().expect("utf-8 scratch path"),
            "claim",
            "branch",
            head,
            own,
        )
    }

    #[test]
    fn a_restarted_branch_carries_no_usable_claim() {
        // CLOUD-516's whole point, and the row that was silently green: the base
        // moved AND the branch carries nothing of its own, which is what
        // `git checkout -B <name> origin/main` after a merge produces and what
        // nothing else produces.
        // AHEAD BY ONE is what a restart looks like: `head` carries a commit
        // the recorded base does not, because the base is the OLDER main the
        // receipt was taken against. That is the conjunct CLOUD-1091 added, and
        // this case is what keeps the widening from swallowing this row.
        assert_eq!(
            judge_ahead("restart", &minted(Some("aaa")), "bbb", 0, Some(1)),
            Validity::StaleMain
        );
    }

    #[test]
    fn a_branch_behind_its_own_receipt_keeps_it() {
        // CLOUD-1091, and RED against the predicate this replaces: `recorded !=
        // head` fired here just as readily as on the restart above, because the
        // comparison is symmetric and the situation is not.
        //
        // AHEAD BY ZERO is what "behind" looks like from the receipt's side:
        // the base is the CURRENT `origin/main`, `head` is an older commit, so
        // `head` carries nothing the base does not. The receipt is more current
        // than the branch.
        assert_eq!(
            judge_ahead("behind", &minted(Some("bbb")), "aaa", 0, Some(0)),
            Validity::Valid
        );
    }

    #[test]
    fn a_base_equal_to_head_needs_no_range_at_all() {
        // The third case, and it is the cheap one: equality short-circuits
        // before the range is read, so an unreadable repository cannot make the
        // ordinary claim-then-work state look stale.
        assert_eq!(
            judge_ahead("equal", &minted(Some("aaa")), "aaa", 0, None),
            Validity::Valid
        );
    }

    #[test]
    fn a_range_nobody_can_read_stays_void() {
        // The direction the widening must NOT take. This change admits more only
        // where the repository can actually be read; could-not-look keeps the
        // verdict it had, so an unreadable range can never be the thing that
        // admits a claim that expired.
        assert_eq!(
            judge_ahead("unreadable", &minted(Some("aaa")), "bbb", 0, None),
            Validity::StaleMain
        );
    }

    #[test]
    fn a_rebase_lap_is_never_asked_to_re_claim() {
        // THE ROW A CARELESS FIX BREAKS. `land` rebases onto the current
        // origin/main every lap, so the base moves every lap — voiding on that
        // alone would demand a re-claim per lap, which is the false-positive rate
        // that gets a guard bypassed and would be reverted within a day.
        assert_eq!(
            judge("lap", &minted(Some("aaa")), "bbb", 1),
            Validity::Valid
        );
        assert_eq!(
            judge("lap2", &minted(Some("aaa")), "ccc", 7),
            Validity::Valid
        );
    }

    #[test]
    fn an_unmoved_base_is_valid_with_or_without_work() {
        // Claim, then work: the ordinary case, before and after the first commit.
        assert_eq!(
            judge("unmoved", &minted(Some("aaa")), "aaa", 0),
            Validity::Valid
        );
        assert_eq!(
            judge("unmoved2", &minted(Some("aaa")), "aaa", 3),
            Validity::Valid
        );
    }

    #[test]
    fn a_receipt_predating_this_change_does_not_grandfather_itself_in() {
        // The fourth acceptance clause. A receipt with no `base` line cannot say
        // what it was made against, and reading that as agreement would leave
        // every receipt minted before this change permanently authoritative —
        // including the six-day-old one this branch was carrying.
        assert_eq!(
            judge("nobase", &minted(None), "bbb", 0),
            Validity::StaleMain
        );
        assert_eq!(
            judge("nobase2", "CLOUD-516\n", "bbb", 0),
            Validity::StaleMain
        );
        // `-` is the task's spelling for "origin/main did not resolve at mint
        // time" and must read as absent, never as a base that matches nothing.
        assert_eq!(
            judge("nobase3", &minted(Some("-")), "bbb", 0),
            Validity::StaleMain
        );
    }

    #[test]
    fn an_absent_receipt_is_missing_not_void() {
        // The two verdicts carry different remedies — mint one, versus mint one
        // again — so collapsing them would cost the reader the distinction.
        let dir = tempdir("absent");
        assert_eq!(
            branch_validity(
                dir.to_str().expect("utf-8 scratch path"),
                "claim",
                "branch",
                "aaa",
                0,
            ),
            Validity::Missing
        );
    }

    #[test]
    fn the_base_line_is_read_by_key_not_by_position() {
        // `claim-check` has already grown two fields under line 1 (CLOUD-431) and
        // will grow more; a positional reader would break on the next one, and it
        // would break toward Valid.
        assert_eq!(recorded_base("base aaa\n").as_deref(), Some("aaa"));
        assert_eq!(recorded_base(&minted(Some("aaa"))).as_deref(), Some("aaa"));
        assert_eq!(recorded_base("CLOUD-1\nbased on nothing\n"), None);
        assert_eq!(recorded_base("base \n"), None);
    }

    #[test]
    fn a_re_minted_receipt_is_read_at_its_newest_base_not_its_oldest() {
        // CLOUD-1057. THE TWO ORDERS ARE THE WHOLE TEST, and a single-`base`-line
        // fixture is why the defect shipped: every case above writes one line, and
        // one line passes under either reader. So the assertions below are the pair
        // that discriminates, not one of them plus a restatement.
        //
        // Every writer appends (`>>`), so the last line is the evidence just taken.
        assert_eq!(
            recorded_base("CLOUD-1\nbase old\nCLOUD-1\nbase new\n").as_deref(),
            Some("new"),
            "an appended receipt is read at the base it most recently recorded"
        );
        // And the mirror, so this cannot be satisfied by a reader that simply
        // prefers whichever line happens to sit later in the file for some other
        // reason: reverse the order and the answer reverses with it.
        assert_eq!(
            recorded_base("CLOUD-1\nbase new\nCLOUD-1\nbase old\n").as_deref(),
            Some("old"),
            "position decides, so the same two values in the other order swap"
        );
        // `-` keeps meaning could-not-look in last position too, rather than
        // falling back to an older line that WOULD have resolved. A mint that could
        // not see `origin/main` is the newest thing this receipt knows, and reading
        // past it to an older base would manufacture evidence the writer declined
        // to claim.
        assert_eq!(recorded_base("base aaa\nbase -\n"), None);
    }

    #[test]
    fn a_re_minted_receipt_clears_the_refusal_that_prescribed_re_minting() {
        // CLOUD-1057's Acceptance, at the verdict rather than at the parse: the loop
        // this closes was a merged branch (`own == 0`) told its receipt was stale,
        // running the step the refusal named, and being told the same thing again
        // because the correct base it appended was never read.
        let dir = tempdir("re-minted");
        let git_dir = dir.to_str().expect("utf-8 scratch path");
        let receipts = dir.join("batten-receipts");
        std::fs::create_dir_all(&receipts).expect("create the store");

        // The state a merged branch is in after one re-mint: a stale base from
        // before the merge, then the base the fresh search recorded.
        std::fs::write(
            receipts.join("issue-search.feature"),
            "CLOUD-1\nbase stale\nCLOUD-1\nbase head\n",
        )
        .expect("mint twice");
        assert_eq!(
            branch_validity(git_dir, "issue-search", "feature", "head", 0),
            Validity::Valid,
            "re-running the prescribed step must clear the refusal that prescribed it"
        );

        // And the case the `own == 0` arm exists for still voids: a branch restarted
        // after a merge carries a receipt whose NEWEST base predates the restart, so
        // there is nothing recent to vouch for it.
        std::fs::write(
            receipts.join("issue-search.restarted"),
            "CLOUD-1\nbase older\nCLOUD-1\nbase stale\n",
        )
        .expect("mint twice, both before the restart");
        assert_eq!(
            branch_validity(git_dir, "issue-search", "restarted", "head", 0),
            Validity::StaleMain,
            "reading the newest base must not grandfather in a pre-restart receipt"
        );
    }

    #[test]
    fn the_base_line_matches_what_the_minter_writes() {
        // The other half of the crate↔writer contract
        // `the_branch_receipt_filename_matches_the_minting_task` pins: this reader
        // and that writer must agree on the key, or the guard reads every receipt
        // as baseless and denies every edit.
        //
        // IT READS THE MINTER'S OUTPUT NOW, NOT ITS SOURCE (CLOUD-1121). The
        // writer was `mise-tasks/claim-check.sh` and this case grepped it for the
        // line it emitted — a text test over a shell program, which was the best
        // available while the two halves were in different languages. The minter
        // is `claim::mint` since the retirement, so the contract can be asserted
        // over the BYTES it actually produces instead of over the source that
        // produces them, which is strictly stronger: a rename of the key inside
        // `mint` would pass a grep for the old literal and fail here.
        let dir = tempdir("base-contract");
        let receipts = dir.join("batten-receipts");
        let issues = [crate::claim::Issue {
            id: "CLOUD-1".to_owned(),
            status: "Todo".to_owned(),
            assigned: false,
            live_pr: None,
            description: None,
        }];
        let minted = crate::claim::mint(
            &receipts,
            "feature",
            &issues,
            &crate::claim::Verdict::default(),
            &crate::claim::Request::default(),
            Some("deadbeef"),
            "2026-01-01T00:00:00Z",
        )
        .expect("mint a receipt");
        let text = std::fs::read_to_string(&minted).expect("read the minted receipt");
        assert_eq!(
            recorded_base(&text),
            Some("deadbeef".to_owned()),
            "the minter no longer records the base this module reads: {text}"
        );
    }

    #[test]
    fn a_traversal_is_resolved_before_the_containment_test() {
        // The defect this closes, found by the end-to-end suite rather than by
        // reading the code: `absolute` only prepends the working directory, so
        // `../sibling.md` began with the repository root and was judged as inside
        // it — a deny on a write OUTSIDE the repository, which is the
        // over-denying direction a claim gate cannot afford.
        assert_eq!(
            lexically_normal(Path::new("/repo/../sibling.md")),
            std::path::PathBuf::from("/sibling.md")
        );
        assert_eq!(
            lexically_normal(Path::new("/repo/./src/../src/x.rs")),
            std::path::PathBuf::from("/repo/src/x.rs")
        );
        // A traversal above the root stays a path rather than escaping upward.
        assert_eq!(
            lexically_normal(Path::new("/../../x")),
            std::path::PathBuf::from("/x")
        );
        // A path needing no resolution is unchanged.
        assert_eq!(
            lexically_normal(Path::new("/repo/src/x.rs")),
            std::path::PathBuf::from("/repo/src/x.rs")
        );
    }

    #[test]
    fn a_branch_keyed_receipt_answers_for_its_own_branch_and_check_only() {
        // WAS `a_branch_keyed_verdict_is_existence_and_nothing_else`, and the old
        // name was the defect stated as a contract: it wrote a receipt with no
        // base and asserted Valid, which is exactly the state CLOUD-516 measured
        // authorising four unrelated stories. The addressing assertions below are
        // the half that was always right and are kept verbatim.
        let dir = tempdir("addressing");
        let git_dir = dir.to_str().expect("utf-8 scratch path");
        assert_eq!(
            branch_validity(git_dir, "claim", "feature", "aaa", 0),
            Validity::Missing
        );
        let receipts = dir.join("batten-receipts");
        std::fs::create_dir_all(&receipts).expect("create the store");
        std::fs::write(receipts.join("claim.feature"), "CLOUD-444\nbase aaa\n").expect("mint");
        assert_eq!(
            branch_validity(git_dir, "claim", "feature", "aaa", 0),
            Validity::Valid
        );
        // A new commit still cannot invalidate it — the asymmetry the second
        // keying exists for, and the one thing CLOUD-516 did not change.
        assert_eq!(
            branch_validity(git_dir, "claim", "feature", "aaa", 12),
            Validity::Valid
        );
        // A receipt for another branch does not vouch for this one.
        assert_eq!(
            branch_validity(git_dir, "claim", "other", "aaa", 0),
            Validity::Missing
        );
        // Nor does another check's receipt on the same branch.
        assert_eq!(
            branch_validity(git_dir, "verify", "feature", "aaa", 0),
            Validity::Missing
        );
        // A directory at the path is not a receipt: reading it fails, which is
        // what makes the store's own parent unable to answer for a check called
        // nothing.
        std::fs::create_dir_all(receipts.join("claim.dir")).expect("create a directory");
        assert_eq!(
            branch_validity(git_dir, "claim", "dir", "aaa", 0),
            Validity::Missing
        );
    }

    /// A per-process, per-CASE scratch directory, in this crate's unit-test idiom
    /// (`drain`, `findings`): `CARGO_TARGET_TMPDIR` is integration-only, and a
    /// pid-suffixed name keeps concurrent test binaries from sharing one.
    ///
    /// **`case` is not decoration.** This wipes the directory on entry, and the
    /// harness runs cases in parallel threads of one process — so a pid alone had
    /// every case in this module sharing one path, and a second case calling it
    /// deleted the first's receipt mid-assertion. That was survivable while
    /// exactly one case used it and became a flake the moment CLOUD-516 added
    /// more: it fails as `Missing`, which is the direction that reads as a real
    /// verdict rather than as a broken fixture.
    fn tempdir(case: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "batten-branch-receipt-{}-{case}",
            std::process::id()
        ));
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
