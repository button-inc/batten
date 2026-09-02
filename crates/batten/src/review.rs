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
/// is the two-authorities shape `.claude/rules/policy-modules.md` records for
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
        let Ok(bytes) = std::fs::read(root.join(&row.path)) else {
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
        if matches!(read(&path), Look::IsNot) {
            dispatch(root, row, &path, &subject);
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
fn dispatch(root: &Path, row: &crate::facts::ReviewQuery, path: &Path, subject_digest: &str) {
    let Some((text, _)) = prompt(&row.prompt) else {
        return;
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
    let pointer = format!("{} {}\n", row.path, subject_digest);
    #[expect(
        clippy::disallowed_types,
        reason = "stays: this fact IS Cost::Effect — resolving it dispatches the vendored prompt, which is the classification rather than an accident of it. A verb the caller must remember instead is the producer-writes-outside shape CLOUD-1265 measures dead (CLOUD-472)"
    )]
    let spawned = std::process::Command::new(&row.runner)
        .args(&row.args)
        .current_dir(root)
        .stdin(std::process::Stdio::piped())
        // Both streams captured, NEITHER forwarded: an agent's stderr is prose,
        // and echoing a child's stream would put output Batten never shaped onto
        // Batten's own (rule 4).
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn();
    let Ok(mut child) = spawned else {
        return;
    };
    // THE PROMPT AND THEN THE POINTER. The prompt ALONE was what this function
    // sent before, and that was the defect: the agent was told what to look for
    // and never told what to look at, so its answer was a review of nothing while
    // the record was keyed to bytes it had never seen — a record that reads as a
    // completed review and is not one, which is worse than no record at all.
    if let Some(mut stdin) = child.stdin.take() {
        use std::io::Write as _;
        if stdin.write_all(text.as_bytes()).is_err()
            || stdin.write_all(b"\n").is_err()
            || stdin.write_all(pointer.as_bytes()).is_err()
        {
            return;
        }
    }
    let Ok(output) = child.wait_with_output() else {
        return;
    };
    // THE CROSS-CHECK. A non-zero status means the agent itself failed, and
    // findings parsed out of a failed run describe a review that did not finish.
    if !output.status.success() {
        return;
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let Some(body) = pointers_in(&stdout) else {
        return;
    };
    if let Some(parent) = path.parent()
        && std::fs::create_dir_all(parent).is_err()
    {
        return;
    }
    let _ = std::fs::write(path, body);
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
