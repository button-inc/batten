//! That a **vendored** agent prompt was dispatched over a declared subject
//! (CLOUD-472).
//!
//! **The second occupant of [`Cost::Effect`]**, and the third adopter of the
//! delegated-analyser shape: `secrets.rs` (ripsecrets) → `symbols.rs` (clippy) →
//! this. What carries across is the SHAPE — a declared program, flags pinned
//! beside the parser, provenance recorded because a fact whose meaning depends on
//! an unrecorded tool version is not canonical, and one invariant verbatim:
//!
//! > **clean is never inferred from a stream that failed to parse.**
//!
//! # What it answers, and why the narrowness is the whole mechanism
//!
//! **THAT a particular prompt ran over these exact bytes.** Not whether the
//! review was good, not whether its findings are real. Those are judgements and
//! non-negotiable rule 3 forbids a gate deciding one — so a gate over this fact
//! refuses ABSENCE, which is a comparison of two digests, and the agent's
//! findings reach a module as pointers that carry no claim to weigh.
//!
//! That bound is what makes an LLM in a resolution path legal at all. It is also
//! why the cheaper tiers do not substitute: `ready-lint` gates the SHAPE of a
//! refinement block, and shape is what an author optimises against once the gate
//! exists — the measured failure that opened CLOUD-472, where every clause was
//! present and none had been pressure-tested. Confirming a named prompt ran over
//! these bytes is a hash comparison no better-shaped prose can satisfy, because
//! the prose is the input to the hash.
//!
//! # Spawn on miss, read on hit — `step-receipt`'s pattern, not a new one
//!
//! A review costs minutes and tokens, and `check` runs every landing lap, so
//! resolving it unconditionally would be unaffordable and the gate would be
//! switched off. The record is keyed by (prompt digest, subject digest), so the
//! agent runs ONCE per unique subject and every later lap is a cache hit — the
//! same "same inputs, same command, same toolchain ⇒ same verdict" the step
//! receipts already use.
//!
//! **The keying is the anti-staleness property, not an optimisation.** Edit the
//! ticket body or push a commit and the subject digest moves, so the record lives
//! under a name nothing looks up and the review must run again. A `reviewed: true`
//! marker could never provide that.
//!
//! # Why the prompt is vendored
//!
//! The prompt is compiled into this binary, the way `src/policy/presets/**` are,
//! so its digest is a constant of the build. That is what makes *a particular
//! prompt* a checkable claim rather than an intention — a consumer cannot satisfy
//! the gate by pointing it at an easier prompt, because the digest in the key is
//! not theirs to choose.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::facts::Look;

/// The vendored prompts, by id.
///
/// Compiled in for the reason `policy/presets/**` are: a consumer who wrote no
/// rows still gets them, and the text cannot be swapped to something weaker
/// without changing the digest the record is keyed by.
pub const PROMPTS: &[(&str, &str)] = &[(
    "ready-pressure-test",
    include_str!("review/ready-pressure-test.md"),
)];

/// The directory the records live under, beneath the git dir.
const STORE: &str = "batten-review";

/// What joins a record's key components into one name.
///
/// Stated once rather than at both the composing and the validating site, which
/// is the two-authorities shape `rules/policy-modules.md` records for
/// patterns one layer down. Shared with [`crate::facts::KEY_SEPARATOR`]'s reason
/// and spelled the same way.
const KEY_SEPARATOR: char = '@';

/// One pointer a review produced.
///
/// **A pointer and nothing else.** There is no field an agent's prose could
/// occupy, so non-negotiable rule 4 holds structurally here rather than by the
/// parser remembering to strip — the same shaping `symbols::Site` uses to keep a
/// diagnostic's rendered message out of the fact.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
#[non_exhaustive]
pub struct Finding {
    /// Repo-relative and `/`-separated, or the subject's own id where the
    /// subject is not a file.
    pub path: String,
    /// 1-indexed, where the subject has lines.
    pub line: u32,
    /// Which clause of the reviewed object this points at, e.g. `§7`. A closed
    /// token the prompt declares, never a sentence.
    pub clause: String,
}

/// Which agent produced a record, and how.
///
/// [`crate::symbols::Provenance`] plus the prompt's digest, because here the
/// prompt is half of what the answer means: two runs that disagree because the
/// prompt changed must be distinguishable from two that disagree because the
/// subject did.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Provenance {
    /// The program, as invoked.
    pub tool: String,
    /// The version the row pinned it at.
    pub version: String,
    /// The exact flags, so a reader can tell which question was asked.
    pub invocation: Vec<String>,
    /// The digest of the VENDORED prompt text.
    pub prompt: String,
}

/// What the review ran over.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Subject {
    /// The declared kind, e.g. `document` or `delta`.
    pub kind: String,
    /// The digest of the reviewed bytes.
    pub digest: String,
}

/// Why a dispatch produced no record, when it produced none.
///
/// **The three are not interchangeable and the first is the load-bearing one.**
/// A runner that is not installed is a fact about the ENVIRONMENT; an agent that
/// ran and failed is a fact about the RUN. Collapsing them makes a machine with
/// no reviewer indistinguishable from a branch that skipped its review, and a
/// gate over that would refuse every checkout where nobody has installed the
/// agent — which is a verdict about the operator wearing a verdict about the
/// branch. `symbols::resolve` keeps the identical pair apart, in the same words.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Dispatch {
    /// It ran and a record was written.
    Ran,
    /// It ran and did not complete — a non-zero exit. The review was ASKED FOR
    /// and did not answer, which is the branch's problem and must refuse.
    ///
    /// **A stream that is not pointers is NOT this**, and used to be: completion
    /// is the whole contract the gate reads, so demanding the agent speak
    /// Batten's line format made every real reviewer's output a failed dispatch.
    Failed,
    /// There is no runner here to ask, or its own probe says it cannot review —
    /// not installed, or installed and unauthenticated. Could-not-look, never a
    /// finding: this is a fact about the machine rather than about the branch.
    NoRunner,
}

/// Whether the runner's own probe says it can review here.
///
/// **The runner is the authority on its own readiness**, which is why this is a
/// declared subcommand rather than a check Batten invents. A reviewer knows
/// whether its CLI is installed AND whether a session is authenticated; the
/// engine can see neither, and inferring readiness from a file's existence
/// answers a narrower question than the one that matters.
///
/// Conservative in the direction that costs nothing: anything other than an
/// explicit `"ready": true` reads as NOT ready, so a probe that fails to spawn,
/// exits non-zero, or answers in a shape this does not recognise leaves the
/// review unjudged rather than refusing a branch over an environment nobody can
/// see. `serde_json` rather than a substring scan, so a `"ready": false` beside
/// a `"nextSteps"` mentioning the word cannot read as true.
fn ready(root: &Path, row: &crate::facts::ReviewQuery) -> bool {
    let Some((code, stdout)) = crate::exec::piped(root, Path::new(&row.runner), &row.probe, "")
    else {
        return false;
    };
    if code != 0 {
        return false;
    }
    serde_json::from_str::<serde_json::Value>(&stdout)
        .ok()
        .and_then(|value| value.get("ready").and_then(serde_json::Value::as_bool))
        .unwrap_or(false)
}

/// One dispatched review.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Record {
    /// Which agent, which version, which prompt.
    pub provenance: Provenance,
    /// Which bytes, and their digest.
    pub subject: Subject,
    /// Every pointer the run produced, sorted — an agent's output order is not
    /// stable across runs and §6 byte-stability is.
    pub findings: Vec<Finding>,
}

/// The digest of some bytes, as the key composes it.
#[must_use]
pub fn digest(bytes: &[u8]) -> String {
    crate::tools::digest(bytes)
}

/// The record's path for one (id, prompt digest, subject digest) triple.
///
/// **Keyed rather than compared**, for [`crate::facts::ToolQuery`]'s reason: a
/// record from another prompt or over other bytes lives under a different name
/// and is never opened, so staleness cannot be a comparison a caller forgets to
/// make.
#[must_use]
pub fn record_path(git_dir: &Path, id: &str, prompt: &str, subject: &str) -> PathBuf {
    git_dir.join(STORE).join(format!(
        "{id}{KEY_SEPARATOR}{prompt}{KEY_SEPARATOR}{subject}"
    ))
}

/// The vendored prompt text for an id, and its digest.
#[must_use]
pub fn prompt(id: &str) -> Option<(&'static str, String)> {
    PROMPTS
        .iter()
        .find(|(name, _)| *name == id)
        .map(|(_, text)| (*text, digest(text.as_bytes())))
}

/// Read a record back, or say why it could not be read.
///
/// **Absent is not empty**, and the two are the whole point: a missing file means
/// the prompt never ran over these bytes, which is the one thing a gate over this
/// fact may refuse on. A file present with no findings means it ran and pointed
/// at nothing.
#[must_use]
pub fn read(path: &Path) -> Look<Vec<Finding>> {
    let Ok(text) = std::fs::read_to_string(path) else {
        return Look::IsNot;
    };
    let mut findings = Vec::new();
    for line in text.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let mut words = line.split_whitespace();
        let (Some(path), Some(line_no), Some(clause)) = (words.next(), words.next(), words.next())
        else {
            // CLEAN IS NEVER INFERRED FROM A STREAM THAT FAILED TO PARSE
            // (`secrets.rs`' invariant, carried verbatim). A malformed record is
            // could-not-look, never an empty finding set.
            return Look::CouldNotLook;
        };
        let Ok(line_no) = line_no.parse::<u32>() else {
            return Look::CouldNotLook;
        };
        findings.push(Finding {
            path: path.to_owned(),
            line: line_no,
            clause: clause.to_owned(),
        });
    }
    findings.sort();
    Look::Is(findings)
}

/// Every declared review this tree has a record for.
///
/// Returns [`Look::CouldNotLook`] when no store is readable at all, and a map
/// otherwise — with a declared id ABSENT from it when its prompt has not run over
/// its subject. That absence is the refusal, and keeping it distinct from an
/// empty finding list is what stops a gate reporting clean over a review that
/// never happened.
#[must_use]
pub fn resolve(
    root: &Path,
    declared: &[crate::facts::ReviewQuery],
) -> Look<BTreeMap<String, Record>> {
    if declared.is_empty() {
        return Look::IsNot;
    }
    let Ok(git_dir) = crate::git::git_dir(root) else {
        return Look::CouldNotLook;
    };
    let mut found = BTreeMap::new();
    for row in declared {
        let Some((_, prompt_digest)) = prompt(&row.prompt) else {
            continue;
        };
        // A DOCUMENT REVIEW WITHOUT A PATH IS SKIPPED, never guessed at. The
        // column is optional because a `tracker-body` review has an issue key
        // instead, and `for_body` is that subject's entry point — reaching for a
        // default here would take a review over bytes nobody declared.
        let Some(subject_path) = row.path.as_deref() else {
            continue;
        };
        let Ok(bytes) = std::fs::read(root.join(subject_path)) else {
            // COULD NOT READ THE SUBJECT is could-not-look, and it must not
            // dispatch: a review keyed to bytes nobody could read would be a
            // record about a subject that does not exist.
            continue;
        };
        let subject = digest(&bytes);
        let path = record_path(&git_dir, &row.id, &prompt_digest, &subject);
        // SPAWN ON MISS, READ ON HIT. The dispatch is the engine's rather than a
        // call somebody has to remember, which is the whole difference from a
        // producer-writes-outside store — measured dead on `tool-verdict`, where
        // `validator-verdict-clean` reads a record nothing ever writes
        // (CLOUD-1265). A hit costs a file read, so the agent runs once per
        // unique subject and every later landing lap is free.
        if matches!(read(&path), Look::IsNot)
            && dispatch(root, row, &path, &subject) == Dispatch::NoRunner
        {
            // COULD NOT LOOK, FOR THE WHOLE FACT rather than for this row.
            // `input.tree.review` is `null` and every gate over it goes quiet,
            // which is the honest answer on a machine that has no reviewer: the
            // question "was this reviewed" cannot be put where nothing can
            // review. A per-row absence here would read as "this one was
            // skipped", which is a different and false claim.
            return Look::CouldNotLook;
        }
        let Look::Is(findings) = read(&path) else {
            continue;
        };
        found.insert(
            row.id.clone(),
            Record {
                provenance: Provenance {
                    tool: row.runner.clone(),
                    version: row.version.clone(),
                    invocation: row.args.clone(),
                    prompt: prompt_digest,
                },
                subject: Subject {
                    kind: row.subject.clone(),
                    digest: subject,
                },
                findings,
            },
        );
    }
    Look::Is(found)
}

/// Run the vendored prompt over this row's subject and store what it pointed at.
///
/// # Everything that can go wrong leaves NO record, deliberately
///
/// A failed dispatch must be indistinguishable from one that never happened:
/// both mean this prompt has not been shown to run over these bytes, and both
/// must refuse. Writing an empty record on failure would turn a broken runner
/// into a clean review — `secrets.rs`' invariant carried verbatim, **clean is
/// never inferred from a stream that failed to parse**, and here the stakes are
/// the whole gate rather than one finding.
fn dispatch(
    root: &Path,
    row: &crate::facts::ReviewQuery,
    path: &Path,
    subject_digest: &str,
) -> Dispatch {
    let Some((text, _)) = prompt(&row.prompt) else {
        return Dispatch::NoRunner;
    };
    // THE SUBJECT TRAVELS AS A POINTER, NEVER AS BYTES — Batten's law, not an
    // economy.
    //
    // `judge.rs` states the law at its own head: "sensitive or bulky content is
    // reduced to a pointer and never dumped into a model's context", and names
    // the LLM judge "the ONE component that inverts it". A review dispatch must
    // not be a second inversion. So what crosses is the vendored prompt, the
    // subject's PATH, and the subject's DIGEST — and the agent reads the bytes
    // with its own tools, under whatever access its operator gave it.
    //
    // That is not a weaker claim about what was reviewed. The digest in the
    // record is over the bytes on disk, so a record still cannot be keyed to
    // anything but the exact subject; what changes is that Batten never becomes
    // the thing that moved somebody's file into a model.
    //
    // It is also what lets a subject with no repo path work at all. `judge`'s
    // fail-closed rule reads a span with no path provenance as PROTECTED and
    // refuses the whole invocation — correct for a span, and fatal for a tracker
    // body, which legitimately has an issue key instead of a path. A pointer has
    // no such problem.
    // THE POINTER NAMES THE SUBJECT, whatever kind it is: a repository path for
    // a `document` review, and the row's own id for a `tracker-body` one, where
    // the id IS the issue key the agent must look up. `row.id` is the fallback
    // rather than a placeholder — a review with no path has a name, and a name is
    // what a pointer is for.
    let subject_name = row.path.as_deref().unwrap_or(&row.id);
    let pointer = format!("{subject_name} {subject_digest}\n");
    // THROUGH `exec::piped`, WHICH IS THE PLACED CHILD-PROCESS ADAPTER, rather
    // than a `Command::new` of this module's own.
    //
    // That helper exists for exactly this and says so: two callers had each grown
    // their own spawn, "which is two spawns in two unplaced modules and one shape
    // written twice". This was very nearly the third — the first attempt spawned
    // directly and then placed `review` in `policy/spawn-adapters.rego`'s table,
    // which is the move that rule's own remedy tells you not to make. Routing
    // here instead means there is no new spawn site to place at all.
    //
    // It also buys the shebang resolution ladder, which a `#!/usr/bin/env`
    // runner needs on a host where `CreateProcess` refuses an extensionless
    // program — a refusal the caller would otherwise read as could-not-look.
    //
    // `None` is the runner not being here, which is the distinction the whole
    // `Dispatch` enum exists to preserve.
    // THE PROBE FIRST, so "cannot review here" is a READING rather than an
    // inference from a missing file.
    //
    // `is_file()` alone cannot tell a machine that never installed the reviewer
    // from one where it is installed and unauthenticated, and those are different
    // remedies for the operator. A declared probe answers it: the reviewer
    // batten's customers run reports `ready` alongside `node`, `npm`, `codex` and
    // `auth`, with `nextSteps` attached. An undeclared probe skips this entirely,
    // so a row that says nothing is judged exactly as before.
    if !row.probe.is_empty() && !ready(root, row) {
        return Dispatch::NoRunner;
    }
    // THE PROMPT GOES DOWN THE CHANNEL THE RUNNER ACTUALLY READS. A runner that
    // ignores stdin discards it in SILENCE and reviews whatever it chose to look
    // at, so the record would attest to a review that never asked the question.
    let mut args = row.args.clone();
    let stdin = match row.prompt_arg {
        crate::facts::PromptArg::Stdin => format!("{text}\n{pointer}"),
        crate::facts::PromptArg::Positional => {
            args.push(format!("{text}\n{pointer}"));
            String::new()
        }
    };
    let Some((code, stdout)) = crate::exec::piped(root, Path::new(&row.runner), &args, &stdin)
    else {
        return Dispatch::NoRunner;
    };
    // THE CROSS-CHECK. A non-zero status means the agent itself failed, and
    // findings parsed out of a failed run describe a review that did not finish.
    if code != 0 {
        return Dispatch::Failed;
    }
    // COMPLETION IS THE CONTRACT, AND THE FINDINGS ARE A BONUS.
    //
    // The gate over this fact refuses ABSENCE and never reads a finding, so
    // demanding the agent speak Batten's line format couples the record to a
    // schema nothing consumes — and guarantees that a real reviewer's output is
    // rejected as unparseable, leaving no record and a refusal that blames the
    // branch for somebody else's stdout. A run that exited 0 reviewed the
    // subject; that is what is being attested.
    //
    // A runner that DOES emit pointers still gets them stored, so a consumer who
    // wires one loses nothing. What changed is that failing to is no longer a
    // failed dispatch.
    let body = pointers_in(&stdout).unwrap_or_default();
    if let Some(parent) = path.parent()
        && std::fs::create_dir_all(parent).is_err()
    {
        return Dispatch::Failed;
    }
    let _ = std::fs::write(path, body);
    Dispatch::Ran
}

/// Keep only the lines that are pointers, and refuse the stream if any line is
/// not one.
///
/// **Refusing rather than filtering** is what keeps an agent's prose out of the
/// record: a parser that skipped what it did not understand would store whichever
/// subset happened to look like a pointer and call the rest absent, which is a
/// silent partial answer. `None` rejects the whole stream.
fn pointers_in(stdout: &str) -> Option<String> {
    let mut lines = Vec::new();
    for line in stdout.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let mut words = line.split_whitespace();
        let (Some(subject), Some(number), Some(clause), None) =
            (words.next(), words.next(), words.next(), words.next())
        else {
            return None;
        };
        number.parse::<u32>().ok()?;
        lines.push(format!("{subject} {number} {clause}"));
    }
    lines.sort();
    Some(if lines.is_empty() {
        String::new()
    } else {
        format!("{}\n", lines.join("\n"))
    })
}

/// Whether a vendored prompt has run over a BODY the caller holds, dispatching
/// on a miss.
///
/// # Why this exists beside [`resolve`] rather than inside it
///
/// [`resolve`] answers for the whole declared set at `check` time, over subjects
/// it can read off the disk. A refinement body is neither: it arrives on the
/// `ready lint` payload, from the TRACKER, and there is nothing in the tree to
/// read. Folding it into `resolve` would mean handing the tree surface a byte
/// string from a caller — a second way for a subject to enter the engine, and the
/// one a caller could forge.
///
/// **The forgery control is the caller's, and it is the one already earned.**
/// `ready lint`'s payload is what the recorder's `verdict` authority column
/// reads, so the body here is what the tracker returned rather than a payload
/// somebody assembled — the distinction measured when `ready-lint` over a
/// self-assembled payload came back green three times against text in a local
/// file, once under an id no row carried.
#[must_use]
pub fn for_body(root: &Path, row: &crate::facts::ReviewQuery, body: &str) -> Look<Vec<Finding>> {
    let Some((_, prompt_digest)) = prompt(&row.prompt) else {
        return Look::CouldNotLook;
    };
    let Ok(git_dir) = crate::git::git_dir(root) else {
        return Look::CouldNotLook;
    };
    let subject = digest(body.as_bytes());
    let path = record_path(&git_dir, &row.id, &prompt_digest, &subject);
    // SPAWN ON MISS, READ ON HIT, and NoRunner stays could-not-look — the same
    // three answers the tree surface gives, because a machine with no reviewer
    // installed cannot be asked whether it reviewed.
    if matches!(read(&path), Look::IsNot)
        && dispatch(root, row, &path, &subject) == Dispatch::NoRunner
    {
        return Look::CouldNotLook;
    }
    read(&path)
}
