//! Mutation coverage over the declared gate set (CLOUD-418, CLOUD-1267).
//!
//! # What this decides, and why nothing else in the tree decides it
//!
//! The obligation this repository already had was *"a rule ships with a runnable
//! gate"* — a gate that EXISTS. Nothing required evidence that it
//! DISCRIMINATES, and a test which passes on both the fixed and the broken code
//! satisfies every other rule here. That is this repo's most-repeated failure:
//! `land`'s refusal branch was dead for months (CLOUD-235), `timeout-check`'s
//! budgets were placeholders that could not fire (CLOUD-352), a shape rule whose
//! `pattern` was a program could never match and read as coverage (CLOUD-401) —
//! and then it happened live while building the landing lease, where a
//! concurrency test written for a real race PASSED ON THE BROKEN CODE.
//!
//! So: a gate is covered when a stated one-line corruption of it makes a NAMED
//! case in its declared suite go RED. **A pass under mutation is the defect.**
//!
//! # Why this is a verb rather than the shell task it replaces
//!
//! Its predecessor was `mise-tasks/mutant.sh`, and the predecessor could not
//! reach a single policy module: it resolved a gate's SOURCE with a Rego
//! fallback and its SUITE as `tests/$gate.bats` unconditionally, so a mutation
//! applied to a `.rego` module had no suite that could turn red. Measured at the
//! time of the port: 32 modules, 32 `#MUTANT-EXEMPT` rows, 29 of them citing
//! that exact hole, 0 with a bats suite, and 141 compiled-binary tiers the
//! runner could not see.
//!
//! That hole was unfixable in place. `shell edit refused` declares one route,
//! `rule read first`, with no override and no `bypass_env`, so the coverage
//! mechanism could only be retired (CLOUD-1111 enumerated the three resolutions
//! and rejected the two that meant editing the program). This module is that
//! retirement.
//!
//! # The effect class
//!
//! `Cost::Effect` on the spawning side: it stages a tracked tree and runs
//! suites, so it cannot be `check`, which is declared `read` and structurally
//! cannot spawn (§5). CLOUD-1171 settled that the engine spawning is legitimate
//! — `batten perf` ships and runs hyperfine — and `perf.rs` is the shape this
//! follows.
//!
//! # The one behavioural change, and everything conserved around it
//!
//! **A gate's suite comes from a DECLARED mapping**: `#MUTANT-SUITE <path>`
//! beside the `#MUTANT` rows, defaulting to `tests/<gate>.bats` when absent. A
//! `.rego` module can therefore name `crates/batten/tests/<x>.rs` — the tier
//! that actually drives the engine — as the suite a mutation must redden.
//!
//! Everything else is conserved from the predecessor, one signal at a time,
//! because each of them is a could-not-look and collapsing one into a pass is
//! the defect this exists to refuse: `no-such-gate`, `no-suite`,
//! `no-mutant-declared` (the anti-vacuity term — a listed gate with no
//! declaration FAILS, it is not skipped), `malformed-row`, `case-already-red`,
//! `names-no-case`, `filter-names-every-case`, `unappliable-mutation`,
//! `inert-mutation`, `self-mutating-row` and `SURVIVED`.
//!
//! Four harness properties travel with them:
//!
//! * **The tracked file is never mutated in place.** Mutating in place staged a
//!   mutant into a pushed commit on 2026-08-12; every run builds a throwaway
//!   copy of the tracked tree and mutates THAT.
//! * **The copy is a repository.** A suite whose gate asks git for its own
//!   enclosing worktree otherwise answered about whatever repository enclosed
//!   `$TMPDIR`, and the case came back red for a reason that had nothing to do
//!   with the mutation.
//! * **The tree is restored between rows.** A gate composing over a sibling was
//!   otherwise judged against the sibling's mutant, so the survivor it reported
//!   changed with the sweep ORDER — worse than a missed one.
//! * **The case must be GREEN before it is mutated.** "Red under mutation" is
//!   only evidence if the row was green without it; a case that can never pass
//!   is red either way and every mutation aimed at it reads as caught.
//!
//! # `#MUTANT-OWNER` is not an exemption
//!
//! A file may declare `#MUTANT-OWNER <KEY>|<one line>`. It is echoed on that
//! file's survivor lines and **changes no exit code** — the sweep is still red.
//! It exists so a predicate already known to be dead is reported with the row
//! that owns it rather than as an anonymous survivor. A declaration that
//! suppressed the finding would be the laundering this whole module refuses.
//!
//! # Output and exit
//!
//! Pointer-only (non-negotiable rule 4): the gate, the mutation id and the case.
//! Never a diff, and never a line of a mutated source. The exit contract is
//! [`crate::ExitCode`]'s: `0` every declared mutation caught, `2` the verdict (a
//! survivor, or any per-row finding), `3` could-not-look — a gate whose declared
//! suite cannot be resolved or run — and `1` usage.

use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail};

/// The declaration markers, bare — the comment opener is [`OPENERS`]'s business.
///
/// Beside the code rather than in a manifest, for the reason `step-receipt`'s
/// spec table lives in `step-receipt`: a declaration in a second file is a
/// second authority that drifts.
///
/// **THE OPENER USED TO BE PART OF THE MARKER, AND THAT EXCLUDED AN ENTIRE
/// IMPLEMENTATION LANGUAGE** (CLOUD-1369). These read `#MUTANT `, matched with
/// `strip_prefix` and no trim, so a declaration could only live in a `#`-comment
/// file — bash or Rego. `#MUTANT` is not valid Rust, so no predicate in
/// `crates/batten/src/**` could carry one, while `obligations-bound` demands the
/// declared obligation file carry exactly that row. The pair was unsatisfiable
/// for every Rust change, and `.bats` is no escape because `V-SHELL-RULE-ADDED`
/// refuses adding one.
///
/// The measured cost was not the gap itself: CLOUD-1349's "shown able to fail"
/// was performed BY HAND — predicate edited to a constant, suite re-run, result
/// read by eye, edit reverted — which is a model verdict standing where
/// non-negotiable rule 3 wants a command and an exit code. The revert then took
/// the uncommitted implementation with it.
///
/// **The trailing space is still load-bearing and is what keeps the four apart**:
/// `MUTANT ` can never match `MUTANT-EXEMPT`, whatever opener precedes it.
const ROW: &str = "MUTANT ";
const SUITE: &str = "MUTANT-SUITE ";
const OWNER: &str = "MUTANT-OWNER ";
const EXEMPT: &str = "MUTANT-EXEMPT ";

/// The comment openers a declaration may follow, longest first.
///
/// **Longest first is correctness, not tidiness.** Neither of these is a prefix
/// of the other today, so the order is inert — but a future opener that shares a
/// lead character with another (`#` and `#!`, say) would resolve to whichever
/// matched first, and a marker read against the shorter one keeps the remainder
/// in its slug. Sorting by length removes the class rather than relying on
/// today's set.
///
/// **An opener is required, and a bare marker is NOT a declaration.** A row must
/// be a comment in its own language or it is source the compiler will reject, and
/// accepting a bare `MUTANT ` would read a line of prose in any file as a
/// declaration.
const OPENERS: &[&str] = &["//", "#"];

/// Where a Rust source lives, relative to the repository root.
///
/// A gate name is kebab and a Rust module is snake, so the name is transliterated
/// rather than matched: `sources_for` is the one place that mapping happens.
const ENGINE: &str = "crates/batten/src";

/// The namespace an engine subject's name carries.
///
/// **A PREFIX RATHER THAN THE BARE MODULE NAME, BECAUSE THE NAMES COLLIDE.**
/// `mise-tasks/doctor.sh` is a gate called `doctor` and `crates/batten/src/
/// doctor.rs` transliterates to `doctor` too — so a bare name would have made
/// `subjects` overwrite the shell gate's row with the module's, and left
/// `sources_for` still resolving the shell task, which means the module's
/// declared mutations would never be applied while reading as declared. A
/// coverage-shaped nothing, from a name clash, in the verb whose whole job is
/// refusing exactly that.
///
/// Caught while landing CLOUD-1369, whose own worked example is `doctor.rs`, so
/// the collision was the first thing the route hit rather than a hypothetical.
const ENGINE_PREFIX: &str = "engine-";

/// Strip a marker from a line, whatever comment opener introduced it.
///
/// Returns the row's body, or `None` where this line is not that declaration.
/// Leading whitespace is deliberately NOT trimmed: a declaration is a top-level
/// statement about the file, and permitting an indented one would let a marker
/// inside a nested block or a doc example read as a declaration of the whole
/// source.
fn strip_marker(line: &str, marker: &str) -> Option<String> {
    OPENERS
        .iter()
        .find_map(|opener| line.strip_prefix(opener)?.strip_prefix(marker))
        .map(str::to_owned)
}

/// The vendored bats runner, relative to the repository root.
const BATS: &str = "tests/bats/bin/bats";

/// Where a preset's modules live, relative to the repository root.
const PRESETS: &str = "crates/batten/src/policy/presets";

/// One declared mutation: `#MUTANT <slug>|<script>|<case>`.
///
/// **Exactly three fields, counted before the split.** That is the root the
/// other evasions grow from: splitting first collapses every extra `|` into the
/// case filter, so a script containing one is silently truncated AND its tail
/// becomes part of the filter — an alternation with an empty leading branch,
/// which selects the whole suite. Both halves then read as coverage. Measured:
/// four rows in this tree carried 5 and 7 fields after a repair that left the
/// old tail in place, and the sweep called every one of them caught.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Row {
    /// The mutation's id, reported with the gate.
    pub slug: String,
    /// The `sed` script applied to the source.
    pub script: String,
    /// The substring naming the case this mutation must redden.
    pub want: String,
    /// The source file this row was read from, repo-relative. A gate may have
    /// several (a preset is a directory), and each row mutates its own file.
    pub source: String,
}

/// How a gate's suite is run.
///
/// Two shapes rather than one, and the declared mapping is what chooses between
/// them: the predecessor hardcoded the first and could not express the second,
/// which is the whole of CLOUD-1267.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Suite {
    /// `tests/<name>.bats`, run through the vendored runner.
    Bats(String),
    /// A Rust suite, run as `cargo test -- <case>`. The path is carried to be
    /// READ — for the existence check and the case census — and never to be
    /// turned into a target name.
    Cargo { path: String },
}

impl Suite {
    /// The suite a declared path names, or `None` for a path this runner has no
    /// runner for — which is reported rather than guessed at.
    #[must_use]
    pub fn declared(path: &str) -> Option<Self> {
        if has_extension(path, "bats") {
            return Some(Suite::Bats(path.to_owned()));
        }
        if !has_extension(path, "rs") {
            return None;
        }
        // THE EXTENSION DECIDES AND NO PART OF THE PATH NAMES A TARGET.
        //
        // This used to derive `--test <stem>` from the file stem, on the reading
        // that "a target's name is its file stem wherever cargo found it". That
        // invoked non-negotiable rule 1 correctly and then broke it one level
        // down: a cargo target NAME is not a property of a source file at all.
        // Cargo compiles `tests/<dir>/main.rs` as one target and every sibling
        // in that directory as a MODULE inside it, so a stem is the target's
        // name only in the flat layout — itself a convention, and one this
        // repository stopped using (CLOUD-1267).
        //
        // Measured: after that move, every declared Rust suite resolved to a
        // `--test` argument naming no target, so all 32 answered `no-suite` —
        // exit 3, could-not-look, with the mapping silently enforcing nothing.
        //
        // So the runner asks for no target. `want` is a libtest substring
        // filter, which selects the case wherever it was compiled to, and that
        // is layout-agnostic in a way no path rule can be.
        Some(Suite::Cargo {
            path: path.to_owned(),
        })
    }

    /// The repo-relative path of the file the suite lives in.
    #[must_use]
    pub fn path(&self) -> &str {
        match self {
            Suite::Bats(path) | Suite::Cargo { path, .. } => path,
        }
    }
}

/// One gate the sweep judges.
#[derive(Debug, Clone)]
pub struct Gate {
    /// The name `$MUTANT_GATES` carries — a task name, a module stem, or a
    /// preset name. Task names carry no extension, so every arm builds the
    /// filename rather than assuming the name is one (CLOUD-865).
    pub name: String,
    /// The sources this gate's rows are read from, repo-relative.
    pub sources: Vec<String>,
    /// The declared suite, or the default.
    pub suite: Suite,
    /// The declared mutations, in file then declaration order.
    pub rows: Vec<Row>,
    /// The owning row a known-dead predicate declares, echoed on a survivor and
    /// deciding nothing.
    pub owner: Option<String>,
}

/// What one row, or one gate, resolved to.
///
/// Every variant except [`Verdict::Caught`] is a finding. They are separate
/// variants rather than one failure because the predecessor's whole design is
/// that a could-not-look is distinguishable from "every mutation caught" —
/// collapsing them is the vacuous pass this module exists to refuse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// The mutation reddened the case it names. The only clean answer.
    Caught,
    /// The mutation ran and the case stayed green.
    Survived { want: String },
    /// The name resolves to no shell task, module or preset.
    NoSuchGate,
    /// The gate's declared suite does not exist.
    NoSuite { suite: String },
    /// The gate is in the enforced set and declares no mutation. The
    /// anti-vacuity term: without it the sweep reports success over a set it
    /// never touched.
    NoMutantDeclared,
    /// The row does not carry exactly three fields.
    MalformedRow { fields: usize },
    /// The filter matched no case, on either the clean or the mutated run.
    NamesNoCase { want: String },
    /// The case was already red before the mutation, so its redness afterwards
    /// is not evidence.
    CaseAlreadyRed { want: String },
    /// The filter selected the whole suite, so redness could come from anywhere
    /// in it and the row stops naming a case.
    FilterNamesEveryCase { want: String },
    /// The script would not apply.
    UnappliableMutation,
    /// The script changed nothing, so it proves nothing.
    InertMutation,
    /// The diff touched only declaration lines: a pattern spelled literally
    /// matches its own row, so the gate's behaviour is untouched and the
    /// mutation survives every run while reading as enforced coverage.
    SelfMutatingRow,
}

impl Verdict {
    /// Whether this verdict is a finding at all.
    #[must_use]
    pub const fn is_finding(&self) -> bool {
        !matches!(self, Verdict::Caught)
    }

    /// Whether this verdict says the runner could not look, rather than saying
    /// something about the gate's coverage.
    ///
    /// The split decides the exit code, and it is the acceptance CLOUD-1267
    /// states in its own words: a gate whose declared suite cannot be resolved
    /// or run is exit `3` and must stay distinguishable from "every mutation
    /// caught".
    #[must_use]
    pub const fn could_not_look(&self) -> bool {
        matches!(
            self,
            Verdict::NoSuchGate
                | Verdict::NoSuite { .. }
                | Verdict::NamesNoCase { .. }
                | Verdict::CaseAlreadyRed { .. }
                | Verdict::UnappliableMutation
        )
    }
}

impl fmt::Display for Verdict {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Verdict::Caught => write!(out, "caught"),
            Verdict::Survived { want } => write!(out, "SURVIVED ({want})"),
            Verdict::NoSuchGate => write!(out, "no-such-gate"),
            Verdict::NoSuite { suite } => write!(out, "no-suite ({suite})"),
            Verdict::NoMutantDeclared => write!(out, "no-mutant-declared"),
            Verdict::MalformedRow { fields } => {
                write!(out, "malformed-row ({fields} fields, want 3)")
            }
            Verdict::NamesNoCase { want } => write!(out, "names-no-case ({want})"),
            Verdict::CaseAlreadyRed { want } => write!(out, "case-already-red ({want})"),
            Verdict::FilterNamesEveryCase { want } => {
                write!(out, "filter-names-every-case ({want})")
            }
            Verdict::UnappliableMutation => write!(out, "unappliable-mutation"),
            Verdict::InertMutation => write!(out, "inert-mutation"),
            Verdict::SelfMutatingRow => write!(out, "self-mutating-row"),
        }
    }
}

/// One reported line: a pointer and a verdict, never a payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    /// The gate's name.
    pub gate: String,
    /// The mutation's id, absent for a gate-level verdict.
    pub slug: Option<String>,
    /// What the runner decided.
    pub verdict: Verdict,
    /// The owning row a known-dead predicate declares. Echoed, never acted on.
    pub owner: Option<String>,
}

impl fmt::Display for Finding {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.slug {
            Some(slug) => write!(out, "{}/{slug} {}", self.gate, self.verdict)?,
            None => write!(out, "{} {}", self.gate, self.verdict)?,
        }
        match &self.owner {
            Some(owner) => write!(out, " [owner {owner}]"),
            None => Ok(()),
        }
    }
}

/// What a whole sweep answered.
#[derive(Debug, Clone)]
pub struct Sweep {
    /// Every finding, in gate then row order.
    pub findings: Vec<Finding>,
    /// How many mutations were declared across the enforced set.
    pub declared: usize,
    /// How many gates the set named.
    pub gates: usize,
}

impl Sweep {
    /// The exit code this sweep answers with.
    #[must_use]
    pub fn code(&self) -> crate::ExitCode {
        if self.findings.iter().any(|f| f.verdict.could_not_look()) {
            return crate::ExitCode::Internal;
        }
        if self.findings.is_empty() {
            crate::ExitCode::Success
        } else {
            crate::ExitCode::Violation
        }
    }

    /// How many findings are could-not-look rather than a verdict about
    /// coverage.
    ///
    /// THE SUMMARY LINE MUST NOT ADD THE TWO TOGETHER, and it did: a set naming
    /// gates a tree does not carry reported `124 of 0 declared mutation(s) …
    /// were not caught`, which states a coverage verdict over a denominator of
    /// zero — the exact conflation the variants above are separate to prevent,
    /// re-introduced one layer up in the rendering. The exit code was right
    /// throughout, which is what made it survive: nothing that reads the code
    /// could see it.
    #[must_use]
    pub fn unlooked(&self) -> usize {
        self.findings
            .iter()
            .filter(|f| f.verdict.could_not_look())
            .count()
    }
}

// ---------------------------------------------------------------------------
// Reading the declarations.
// ---------------------------------------------------------------------------

/// Whether a repo-relative path carries this extension.
///
/// Through `Path` rather than a suffix test, because a suffix test also matches
/// a filename that merely ends in those bytes with no separator before them.
fn has_extension(path: &str, extension: &str) -> bool {
    Path::new(path)
        .extension()
        .is_some_and(|found| found == extension)
}

/// Every line of `path` under `root`, or `None` where it will not read.
fn lines_of(root: &Path, path: &str) -> Option<Vec<String>> {
    let text = std::fs::read_to_string(root.join(path)).ok()?;
    Some(text.lines().map(str::to_owned).collect())
}

/// The value after a marker on the first line that carries it.
///
/// Goes through [`strip_marker`] rather than `strip_prefix`, and that is the half
/// of CLOUD-1369 a compiler cannot catch: dropping the `#` from the marker
/// constants left this function matching a BARE `MUTANT-SUITE ` at column zero,
/// which no file in the tree carries. It compiled clean and would have silently
/// stopped resolving every landed `.rego` declaration — a suite falling back to
/// `tests/<gate>.bats`, an owner and an exemption reading as absent. Compile-clean
/// and gate-dead is the same shape `rules/policy-modules.md` opens with.
fn declared(lines: &[String], marker: &str) -> Option<String> {
    lines.iter().find_map(|line| strip_marker(line, marker))
}

/// The `#MUTANT` rows in one source, refusing a row that is not three fields.
///
/// The count precedes the split because after the split the evidence is gone: a
/// case filter holding a `|` is indistinguishable from one that meant to.
fn rows_in(lines: &[String], source: &str) -> Vec<std::result::Result<Row, (String, usize)>> {
    lines
        .iter()
        .filter_map(|line| strip_marker(line, ROW))
        .map(|body| {
            let fields: Vec<&str> = body.split('|').collect();
            let [slug, script, want] = fields.as_slice() else {
                let head = body.split('|').next().unwrap_or_default().to_owned();
                return Err((head, fields.len()));
            };
            Ok(Row {
                slug: (*slug).to_owned(),
                script: (*script).to_owned(),
                want: (*want).to_owned(),
                source: source.to_owned(),
            })
        })
        .collect()
}

/// The sources a gate name resolves to, in the order the predecessor resolved
/// them: a shell task first, then a module of the same name, then a preset
/// directory.
///
/// The preset arm is CLOUD-1267's addition and it is not decoration: a preset
/// ships to every consumer and its predicates are the ones a `[[pattern]]` row
/// cannot reach, so a runner blind to that directory is blind to the class the
/// sweep exists to find.
#[must_use]
pub fn sources_for(root: &Path, name: &str) -> Vec<String> {
    let task = format!("mise-tasks/{name}.sh");
    if root.join(&task).is_file() {
        return vec![task];
    }
    let module = format!("policy/{name}.rego");
    if root.join(&module).is_file() {
        return vec![module];
    }
    // THE ENGINE ARM (CLOUD-1369), and its POSITION is what keeps it additive: a
    // name that resolved to a shell task or a module before still resolves to
    // exactly that, so no landed gate changes meaning by growing a same-named
    // Rust neighbour.
    //
    // A gate name is kebab and a Rust module is snake, so the name is
    // transliterated here — the one place that mapping lives, because a second
    // spelling of it is the second authority this file already refuses for argv.
    // The `engine-` prefix is what keeps `doctor` (the shell gate) and
    // `engine-doctor` (the module) from being one name; see `ENGINE_PREFIX`.
    if let Some(module) = name.strip_prefix(ENGINE_PREFIX) {
        let engine = format!("{ENGINE}/{}.rs", module.replace('-', "_"));
        if root.join(&engine).is_file() {
            return vec![engine];
        }
    }
    let dir = root.join(PRESETS).join(name);
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return Vec::new();
    };
    let mut found: Vec<String> = entries
        .filter_map(std::result::Result::ok)
        .filter_map(|entry| {
            let file = entry.file_name().to_string_lossy().into_owned();
            has_extension(&file, "rego").then(|| format!("{PRESETS}/{name}/{file}"))
        })
        .collect();
    // Sorted so the sweep is byte-stable: a directory read has no order, and a
    // report whose row order varies per run cannot be diffed.
    found.sort();
    found
}

/// Resolve one gate name against the tree.
///
/// `None` where the name resolves to no source at all — the caller reports
/// `no-such-gate` rather than skipping, because a name in the set that resolves
/// to nothing is exactly the drift the census exists to find.
#[must_use]
pub fn resolve(root: &Path, name: &str) -> Option<Gate> {
    let sources = sources_for(root, name);
    if sources.is_empty() {
        return None;
    }
    let mut rows = Vec::new();
    let mut malformed = Vec::new();
    let mut suite = None;
    let mut owner = None;
    for source in &sources {
        let Some(lines) = lines_of(root, source) else {
            continue;
        };
        suite = suite.or_else(|| declared(&lines, SUITE));
        owner = owner.or_else(|| declared(&lines, OWNER));
        for row in rows_in(&lines, source) {
            match row {
                Ok(row) => rows.push(row),
                Err(bad) => malformed.push(bad),
            }
        }
    }
    // A malformed row is carried as a row whose script cannot apply, so the
    // caller reports it in place rather than losing it: the predecessor
    // reported it and counted it as declared, and a repair that dropped it
    // would make a broken declaration cheaper than an honest one.
    for (head, fields) in malformed {
        rows.push(Row {
            slug: head,
            script: String::new(),
            want: format!("\u{0}malformed:{fields}"),
            source: sources[0].clone(),
        });
    }
    let declared_suite = suite.unwrap_or_else(|| format!("tests/{name}.bats"));
    Some(Gate {
        name: name.to_owned(),
        sources,
        suite: Suite::declared(&declared_suite)
            .unwrap_or_else(|| Suite::Bats(declared_suite.clone())),
        rows,
        owner,
    })
}

/// The gate names `$MUTANT_GATES` declares.
///
/// An unset or empty set is fatal rather than an empty sweep: a task that
/// silently covers nothing is the defect this exists to refuse, one level up.
///
/// # Errors
///
/// Unset or empty is a usage error (→ exit `1`).
pub fn enforced_set() -> Result<Vec<String>> {
    let raw = std::env::var("MUTANT_GATES").unwrap_or_default();
    let names: Vec<String> = raw
        .split(',')
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .map(str::to_owned)
        .collect();
    if names.is_empty() {
        bail!(
            "MUTANT_GATES is unset — run this through `mise run mutant`, which is where the \
             enforced set is declared. An empty set makes this a sweep that silently covers \
             nothing, which is the defect it exists to refuse."
        );
    }
    Ok(names)
}

// ---------------------------------------------------------------------------
// The staged tree.
// ---------------------------------------------------------------------------

/// A throwaway copy of the tracked tree, made a repository, that every mutation
/// is applied to.
#[derive(Debug)]
pub struct Staged {
    dir: PathBuf,
    /// The path most recently corrupted, restored before the next row.
    dirty: Option<String>,
}

impl Staged {
    /// Stage the tracked tree under `dir`.
    ///
    /// **The WORKING copy of each tracked file, never `git archive HEAD`.**
    /// Tracked-only, so an untracked scratch file cannot change a verdict — but
    /// the working bytes, because the moment this matters most is while a gate
    /// and its suite are being written, and a sweep that could only see the last
    /// commit would report `names-no-case` over every case not yet committed.
    ///
    /// # Errors
    ///
    /// Any failure to stage is could-not-look (→ exit `3`).
    pub fn new(root: &Path, dir: PathBuf) -> Result<Self> {
        let tracked = crate::git::tracked_paths(root)
            .context("mutate: could not list the tracked tree to stage it")?;
        reconcile(&dir, &tracked)?;
        for path in &tracked {
            let from = root.join(path);
            // A tracked path can be absent from the working tree (deleted but
            // not committed) and a symlink is copied as what it points at, so
            // both are skipped rather than failing the stage.
            if !from.is_file() {
                continue;
            }
            let to = dir.join(path);
            // COPIED ONLY WHERE THE BYTES DIFFER, and this is an economy with a
            // correctness argument rather than a shortcut. A declared suite can
            // be a compiled tier, and cargo's fingerprint is keyed on mtime — so
            // re-copying an unchanged source would rebuild the whole crate on
            // every sweep, which is what makes a Rust-tier gate affordable at
            // all. The staged bytes are still exactly the tracked bytes; the
            // only thing preserved is the timestamp of a file nothing changed.
            if std::fs::read(&to)
                .is_ok_and(|there| std::fs::read(&from).is_ok_and(|here| here == there))
            {
                continue;
            }
            if let Some(parent) = to.parent() {
                std::fs::create_dir_all(parent)
                    .with_context(|| format!("mutate: could not stage {path}"))?;
            }
            std::fs::copy(&from, &to).with_context(|| format!("mutate: could not stage {path}"))?;
        }
        // The submodule's contents are not tracked here; the runner is the same
        // binary either way, so a symlink is honest rather than a second
        // checkout.
        let bats = dir.join("tests/bats");
        // `symlink_metadata`, never `exists`: the staged tree persists between
        // runs, so what is there is usually the symlink this made last time —
        // and `remove_dir_all` refuses a symlink because it is not a directory,
        // which is a could-not-look on the second sweep and a green first one.
        match std::fs::symlink_metadata(&bats) {
            Ok(meta) if meta.is_symlink() => {
                std::fs::remove_file(&bats).context("mutate: could not provide the bats runner")?;
            }
            Ok(_) => {
                std::fs::remove_dir_all(&bats)
                    .context("mutate: could not provide the bats runner")?;
            }
            Err(_) => {}
        }
        if root.join(BATS).is_file() {
            if let Some(parent) = bats.parent() {
                std::fs::create_dir_all(parent)
                    .context("mutate: could not provide the bats runner")?;
            }
            symlink(&root.join("tests/bats"), &bats)
                .context("mutate: could not provide the bats runner")?;
        }
        let staged = Staged { dir, dirty: None };
        staged.make_a_repository()?;
        Ok(staged)
    }

    /// THE COPY MUST BE A REPOSITORY, and this is a defect rather than a nicety
    /// (CLOUD-480). A staged tree carries tracked bytes and no `.git`, so a
    /// suite whose gate asks git for its own enclosing worktree ran against
    /// whatever repository enclosed the temporary directory — or none — and the
    /// case came back red for a reason that had nothing to do with the
    /// mutation. The runner then reported `case-already-red`, naming the SUITE
    /// for a defect in this harness.
    ///
    /// Identity is passed per command rather than written into a config, so a
    /// contributor with no global `user.email` gets the same throwaway commit as
    /// CI.
    fn make_a_repository(&self) -> Result<()> {
        let steps: [&[&str]; 3] = [
            &["init", "-q"],
            &["add", "-A"],
            &[
                "-c",
                "user.email=mutate@localhost",
                "-c",
                "user.name=mutate",
                "commit",
                "-qm",
                "mutate: the tree under judgement",
            ],
        ];
        for args in steps {
            let owned: Vec<String> = args.iter().map(|arg| (*arg).to_owned()).collect();
            let answer = spawn(&self.dir, "git", &owned, &[])?;
            if !answer.ok {
                bail!(
                    "mutate: could not make the staged tree a repository; a suite that resolves \
                     its own root would answer about the wrong one"
                );
            }
        }
        Ok(())
    }

    /// Restore the previous row's subject.
    ///
    /// **The tree is restored between rows**, and this is a defect the per-row
    /// copy does not cover (CLOUD-480): that copy restores THIS row's subject,
    /// and nothing restored the LAST row's, so the throwaway tree accumulated
    /// corruption and a gate that composes over a sibling was judged against the
    /// sibling's mutant. A survivor that depends on sweep ORDER is worse than a
    /// missed one, because it reports a finding about the suite that changes
    /// with the set.
    ///
    /// # Errors
    ///
    /// A failed restore is could-not-look (→ exit `3`).
    pub fn restore(&mut self, root: &Path) -> Result<()> {
        let Some(path) = self.dirty.take() else {
            return Ok(());
        };
        std::fs::copy(root.join(&path), self.dir.join(&path))
            .with_context(|| format!("mutate: could not restore {path} in the staged tree"))?;
        Ok(())
    }

    /// Put the committed bytes of `path` back and record it as this row's
    /// subject.
    ///
    /// # Errors
    ///
    /// A failed stage is could-not-look (→ exit `3`).
    pub fn stage_subject(&mut self, root: &Path, path: &str) -> Result<()> {
        std::fs::copy(root.join(path), self.dir.join(path))
            .with_context(|| format!("mutate: could not stage {path}"))?;
        self.dirty = Some(path.to_owned());
        Ok(())
    }

    /// The staged tree's root.
    #[must_use]
    pub fn dir(&self) -> &Path {
        &self.dir
    }
}

/// The manifest of what a previous run staged, inside the staged tree.
const MANIFEST: &str = ".mutate-staged";

/// Remove the paths a PREVIOUS run staged that the tracked set no longer names,
/// and record what this one stages.
///
/// The staged tree PERSISTS between runs so an unchanged source keeps its
/// timestamp — which is what makes a compiled tier affordable — and a persisted
/// tree that only ever grew would judge a gate against a file this checkout
/// deleted.
///
/// **A MANIFEST RATHER THAN A WALK, and that is a measured defect rather than a
/// preference.** The first version walked the staged tree and removed every file
/// the tracked set did not name. A suite run inside that tree writes its own
/// artefacts there — a `cargo` build directory reached **1.1 GB** on the first
/// live sweep — so the walk then spent its time recursing through, and deleting,
/// a build nothing asked it to judge. The manifest touches exactly the paths a
/// run put there and never looks at anything else.
fn reconcile(dir: &Path, tracked: &std::collections::BTreeSet<String>) -> Result<()> {
    let previous = std::fs::read_to_string(dir.join(MANIFEST)).unwrap_or_default();
    for path in previous.lines() {
        if path.is_empty() || tracked.contains(path) {
            continue;
        }
        let stale = dir.join(path);
        if stale.is_file() {
            std::fs::remove_file(&stale)
                .with_context(|| format!("mutate: could not clear {path}"))?;
        }
    }
    let manifest: Vec<&str> = tracked.iter().map(String::as_str).collect();
    std::fs::write(dir.join(MANIFEST), manifest.join("\n"))
        .context("mutate: could not record what was staged")?;
    Ok(())
}

#[cfg(unix)]
fn symlink(from: &Path, to: &Path) -> std::io::Result<()> {
    std::os::unix::fs::symlink(from, to)
}

#[cfg(not(unix))]
fn symlink(from: &Path, to: &Path) -> std::io::Result<()> {
    std::os::windows::fs::symlink_dir(from, to)
}

// ---------------------------------------------------------------------------
// Spawning.
// ---------------------------------------------------------------------------

/// What one spawned program answered.
#[derive(Debug)]
pub struct Ran {
    /// Whether it exited zero.
    pub ok: bool,
    /// Its combined output, which is scanned for case lines and never reported.
    pub output: String,
}

/// Run a program to completion in `dir`, capturing what it said.
fn spawn(dir: &Path, program: &str, args: &[String], env: &[(String, String)]) -> Result<Ran> {
    #[expect(
        clippy::disallowed_types,
        reason = "stays: staging a tree and re-running a suite against it IS this module's effect (CLOUD-1267). A mutation cannot be shown to redden a case without running the case, and the spawning side is where §5 puts that — the same disposition `perf.rs` carries for hyperfine"
    )]
    let mut command = std::process::Command::new(program);
    command.args(args).current_dir(dir);
    for (key, value) in env {
        command.env(key, value);
    }
    // A suite reads stdin, and the sweep's own declarations used to be on it —
    // measured on `claimed-keys`, where each invocation SWALLOWED the rows after
    // the one it was running, three declared rows reached two, and the sweep
    // reported "every one caught". Nothing here feeds a suite from stdin, and
    // closing it is what keeps that true if anything ever does.
    command.stdin(std::process::Stdio::null());
    let answer = command
        .output()
        .with_context(|| format!("mutate: could not run {program}"))?;
    let mut output = String::from_utf8_lossy(&answer.stdout).into_owned();
    output.push_str(&String::from_utf8_lossy(&answer.stderr));
    Ok(Ran {
        ok: answer.status.success(),
        output,
    })
}

// ---------------------------------------------------------------------------
// Running a suite.
// ---------------------------------------------------------------------------

/// The staged tree's own cargo target directory, and it is NOT the repository's.
///
/// Kept under `target/` so one `cargo clean` still reaches it and `.gitignore`
/// already covers it, but its own directory so the two builds cannot meet.
const SUITE_TARGET: &str = "target/mutate-cargo";

/// The environment every suite run carries.
///
/// # The target directory is the sweep's own, and sharing it was a defect
///
/// This used to be `root/target` — the repository's own — so the ~400 dependency
/// crates were reused and only this workspace's units recompiled against the
/// staged manifest. The economy was real. What it bought with it was a second
/// source tree writing `batten`'s artifacts into the directory a developer's own
/// `cargo nextest run` reads, and cargo then handed those artifacts back as
/// fresh: measured here, a `mise run test:filter` in the real tree printed
/// `Compiling batten`, linked a library whose debug info named
/// `target/mutate/crates/batten/src/policy.rs`, and evaluated an engine that
/// projected `input.tree.missing` as an array while the source on disk projected
/// a map. Two hours went into a projection defect that did not exist.
///
/// The staged tree carries whatever mutation was applied last, so a sweep killed
/// mid-row leaves DELIBERATELY CORRUPTED engine bytes in that cache — every later
/// local run in this tree then verifies code nobody wrote, at exit 0 and with a
/// reassuring `Compiling` line above it. That is a gate switched off by its own
/// tooling, which is the class this repository exists to refuse.
///
/// **Cleanup cannot fix it and that is why the directory moves.** A sweep is
/// killed by `SIGKILL` and by a reclaimed container, neither of which runs a
/// restore; the only property that holds under both is that the two builds never
/// shared a cache in the first place. The dependency crates are rebuilt once into
/// the sweep's own directory and cached there across every later sweep, so the
/// recurring cost is the same and only the first run pays.
///
/// `BATTEN_TEST_SCRATCH_LANE` is the neighbouring hazard rather than a mitigation
/// of this one, and reading it as one is how the sharing survived review: the
/// suites resolve their fixtures under `CARGO_TARGET_TMPDIR`, so without a lane a
/// sweep and a concurrent local `cargo test` would resolve the same scratch
/// PATHS. That says nothing about the artifact cache above it.
fn suite_env(root: &Path) -> Vec<(String, String)> {
    vec![
        (
            String::from("CARGO_TARGET_DIR"),
            root.join(SUITE_TARGET).to_string_lossy().into_owned(),
        ),
        (
            String::from("BATTEN_TEST_SCRATCH_LANE"),
            String::from("mutate"),
        ),
    ]
}

/// How many cases the run selected, and whether it passed.
struct Selection {
    selected: usize,
    ok: bool,
}

/// Run a gate's suite filtered to `want`, inside the staged tree.
fn run_suite(staged: &Staged, root: &Path, suite: &Suite, want: &str) -> Result<Selection> {
    let env = suite_env(root);
    match suite {
        Suite::Bats(path) => {
            let args = vec![String::from("--filter"), want.to_owned(), path.to_owned()];
            let ran = spawn(
                staged.dir(),
                &root.join(BATS).to_string_lossy(),
                &args,
                &env,
            )?;
            Ok(Selection {
                selected: tap_lines(&ran.output),
                ok: ran.ok,
            })
        }
        Suite::Cargo { .. } => {
            // NO `--test`, for `Suite::declared`'s reason: nothing in the
            // declared path names a cargo target. Every test target is built
            // and each filters `want` for itself, so the case runs wherever it
            // was compiled to and a layout change cannot silently deselect it.
            //
            // The compile is shared across targets, so the cost of the ones
            // that match nothing is their startup. A target selecting no case
            // is not a pass either: `selected` stays 0 and the caller reports
            // `names-no-case`, which is a could-not-look.
            let args = vec![String::from("test"), String::from("--"), want.to_owned()];
            let ran = spawn(staged.dir(), "cargo", &args, &env)?;
            Ok(Selection {
                selected: libtest_lines(&ran.output),
                ok: ran.ok && !ran.output.contains("error: could not compile"),
            })
        }
    }
}

/// TAP result lines in a bats run.
fn tap_lines(output: &str) -> usize {
    output
        .lines()
        .filter(|line| line.starts_with("ok ") || line.starts_with("not ok "))
        .count()
}

/// Case result lines in a libtest run.
///
/// `test <name> ... ok` / `... FAILED`, which is what libtest prints per
/// selected case. Counted rather than read off the summary line, so a run that
/// died before the summary is zero cases rather than an unreadable number.
fn libtest_lines(output: &str) -> usize {
    output
        .lines()
        .filter(|line| line.starts_with("test ") && line.contains(" ... "))
        .count()
}

/// How many cases a suite declares in total.
///
/// **Both bats spellings**, because a suite is not always observed in the form
/// it was written in: bats PREPROCESSES a file it runs, rewriting each `@test`
/// line into a `bats_test_function` call, and counting only `@test` returned 0
/// over such a file — which made the total zero and switched the too-wide-filter
/// term off silently, the shape of false green it exists to catch.
fn total_cases(root: &Path, suite: &Suite) -> usize {
    let Some(lines) = lines_of(root, suite.path()) else {
        return 0;
    };
    match suite {
        Suite::Bats(_) => lines
            .iter()
            .filter(|line| line.starts_with("@test ") || line.starts_with("bats_test_function "))
            .count(),
        Suite::Cargo { .. } => lines
            .iter()
            .filter(|line| line.trim_start().starts_with("#[test]"))
            .count(),
    }
}

// ---------------------------------------------------------------------------
// The sweep.
// ---------------------------------------------------------------------------

/// Apply one row's script to its source inside the staged tree.
///
/// `sed -i.bak` and not the bare in-place flag (CLOUD-282): BSD sed reads the
/// next argument as the suffix, so the no-suffix spelling consumes the script on
/// a Mac. The backup is removed rather than kept — it exists only to satisfy the
/// one form both seds accept.
fn apply(staged: &Staged, row: &Row) -> Result<bool> {
    let args = vec![
        String::from("-i.bak"),
        row.script.clone(),
        row.source.clone(),
    ];
    let ran = spawn(staged.dir(), "sed", &args, &[])?;
    let _ = std::fs::remove_file(staged.dir().join(format!("{}.bak", row.source)));
    Ok(ran.ok)
}

/// Whether the mutation changed anything, and whether it changed anything but a
/// declaration line.
///
/// **A row's pattern is a string that must also appear ON the declaration line**
/// — so a pattern spelled literally matches its own row, the file changes, the
/// gate's behaviour is untouched, and the mutation SURVIVES every run while
/// reading as enforced coverage. Measured: `board-write-record`'s
/// `overlap-frozen-at-write-time` had done exactly that for its whole life.
fn diff_shape(root: &Path, staged: &Staged, source: &str) -> (bool, usize) {
    let before = std::fs::read_to_string(root.join(source)).unwrap_or_default();
    let after = std::fs::read_to_string(staged.dir().join(source)).unwrap_or_default();
    if before == after {
        return (false, 0);
    }
    let head: Vec<&str> = after.lines().collect();
    let base: Vec<&str> = before.lines().collect();
    let changed = base
        .iter()
        .filter(|line| !head.contains(*line))
        .chain(head.iter().filter(|line| !base.contains(*line)))
        .filter(|line| !line.trim_start().starts_with("#MUTANT"))
        .count();
    (true, changed)
}

/// Judge one row.
fn judge_row(root: &Path, staged: &mut Staged, gate: &Gate, row: &Row) -> Result<Verdict> {
    if let Some(fields) = row.want.strip_prefix('\u{0}') {
        let count = fields
            .strip_prefix("malformed:")
            .and_then(|n| n.parse().ok())
            .unwrap_or(0);
        return Ok(Verdict::MalformedRow { fields: count });
    }
    // The previous row's subject first — it may be a DIFFERENT gate's file, and
    // this row's suite may compose over it.
    staged.restore(root)?;
    staged.stage_subject(root, &row.source)?;

    // THE CASE MUST BE GREEN BEFORE IT IS MUTATED. "Red under mutation" is only
    // evidence if the row was green without it: a case that CANNOT pass — an
    // assertion that never holds, a fixture that never builds — is red either
    // way, and every mutation aimed at it reads as caught. Costs one extra
    // filtered run per row, which is what an anti-vacuity term is worth.
    let clean = run_suite(staged, root, &gate.suite, &row.want)?;
    // "Named no case" is read BEFORE the status, because a filter matching
    // nothing is itself a non-zero exit on both runners — and reporting that as
    // "already red" would name the wrong defect to whoever has to fix it.
    if clean.selected == 0 {
        return Ok(Verdict::NamesNoCase {
            want: row.want.clone(),
        });
    }
    if !clean.ok {
        return Ok(Verdict::CaseAlreadyRed {
            want: row.want.clone(),
        });
    }
    // The other side of `names-no-case`: a filter matching EVERY case is the
    // same vacuity, because the row stops naming a case and redness under
    // mutation can then come from anywhere in the suite.
    let total = total_cases(root, &gate.suite);
    if total > 1 && clean.selected >= total {
        return Ok(Verdict::FilterNamesEveryCase {
            want: row.want.clone(),
        });
    }

    if !apply(staged, row)? {
        return Ok(Verdict::UnappliableMutation);
    }
    let (changed, code_lines) = diff_shape(root, staged, &row.source);
    if !changed {
        return Ok(Verdict::InertMutation);
    }
    if code_lines == 0 {
        return Ok(Verdict::SelfMutatingRow);
    }

    let mutated = run_suite(staged, root, &gate.suite, &row.want)?;
    if mutated.selected == 0 {
        return Ok(Verdict::NamesNoCase {
            want: row.want.clone(),
        });
    }
    if mutated.ok {
        return Ok(Verdict::Survived {
            want: row.want.clone(),
        });
    }
    Ok(Verdict::Caught)
}

/// Sweep the enforced set.
///
/// # Errors
///
/// A tree that cannot be staged is could-not-look (→ exit `3`).
pub fn sweep(root: &Path, names: &[String], work: PathBuf) -> Result<Sweep> {
    let mut staged = Staged::new(root, work)?;
    let mut findings = Vec::new();
    let mut declared = 0;
    for name in names {
        let Some(gate) = resolve(root, name) else {
            findings.push(Finding {
                gate: name.clone(),
                slug: None,
                verdict: Verdict::NoSuchGate,
                owner: None,
            });
            continue;
        };
        if !root.join(gate.suite.path()).is_file() {
            findings.push(Finding {
                gate: name.clone(),
                slug: None,
                verdict: Verdict::NoSuite {
                    suite: gate.suite.path().to_owned(),
                },
                owner: gate.owner.clone(),
            });
            continue;
        }
        // THE ANTI-VACUITY TERM, AND IT IS THE WHOLE DESIGN. A listed gate with
        // no declaration is a failure, not a skip. Without this the sweep
        // reports success over a set it never touched.
        if gate.rows.is_empty() {
            findings.push(Finding {
                gate: name.clone(),
                slug: None,
                verdict: Verdict::NoMutantDeclared,
                owner: gate.owner.clone(),
            });
            continue;
        }
        for row in &gate.rows {
            declared += 1;
            let verdict = judge_row(root, &mut staged, &gate, row)?;
            if verdict.is_finding() {
                findings.push(Finding {
                    gate: name.clone(),
                    slug: Some(row.slug.clone()),
                    verdict,
                    owner: gate.owner.clone(),
                });
            }
        }
    }
    staged.restore(root)?;
    Ok(Sweep {
        findings,
        declared,
        gates: names.len(),
    })
}

// ---------------------------------------------------------------------------
// The census.
// ---------------------------------------------------------------------------

/// What the census decided about one subject.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CensusVerdict {
    /// A gate in the tree that is neither declared nor exempt.
    Uncovered,
    /// An exemption with no issue key or no reason.
    ExemptUnfiled,
    /// Declared and exempt at once, so the exemption's reason is a dead letter.
    DeclaredAndExempt,
    /// A name in the enforced set resolving to no gate at all.
    NamesNoSubject,
}

impl fmt::Display for CensusVerdict {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        let word = match self {
            CensusVerdict::Uncovered => "uncovered",
            CensusVerdict::ExemptUnfiled => "exempt-unfiled",
            CensusVerdict::DeclaredAndExempt => "declared-and-exempt",
            CensusVerdict::NamesNoSubject => "names-no-subject",
        };
        out.write_str(word)
    }
}

/// What a census run answered.
///
/// `#[non_exhaustive]` for [`crate::doctor::SessionReport`]'s reason, and adding
/// it is CLOUD-1369's own bill coming due: this struct was constructible, so the
/// `engine_undeclared` field below is `constructible_struct_adds_field` and
/// `semver` refused the branch until a commit declared the break. Its two sibling
/// report types already carry the attribute; this one did not, which is why a
/// report type gaining a field — the most ordinary change such a type has — was a
/// breaking one. Marking it now is what stops the next field costing the same.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Census {
    /// Pointer and verdict, in subject order.
    pub findings: Vec<(String, CensusVerdict)>,
    /// How many subjects were censused.
    pub subjects: usize,
    /// How many engine modules carry no declaration at all (CLOUD-1369).
    ///
    /// The population `subjects` deliberately does not admit, reported so the
    /// retrofit backlog has a size. Never a finding — see [`engine_undeclared`].
    pub engine_undeclared: usize,
}

/// Whether a `mise-tasks/` program describes itself as a gate.
///
/// **Derived from the program's own `#MISE description`, never a second list.**
/// `mise-tasks/` holds programs that refuse and programs that measure, launch,
/// record or report, and only the first kind owes a mutation. That is the same
/// string `mise tasks` shows a human, so a task cannot quietly leave the census
/// by being renamed — it would have to stop describing itself as a gate, which
/// is a visible edit to the line every reader sees.
fn is_gate(lines: &[String]) -> bool {
    let Some(description) = lines.iter().find_map(|line| {
        line.strip_prefix("#MISE description=\"")
            .and_then(|rest| rest.strip_suffix('"'))
    }) else {
        return false;
    };
    description.starts_with("Gate") || description.contains("hook body")
}

/// Every gate the tree carries, by name.
///
/// `policy/*.rego` is in scope unconditionally: a module has no `#MISE` line and
/// every module in this tree is a policy that decides, so there is nothing to
/// discriminate. Presets are in scope for the same reason, and because a runner
/// blind to them is blind to the one predicate class a `[[pattern]]` row cannot
/// reach (CLOUD-934).
#[must_use]
pub fn subjects(root: &Path) -> BTreeMap<String, String> {
    let mut found = BTreeMap::new();
    if let Ok(entries) = std::fs::read_dir(root.join("mise-tasks")) {
        for entry in entries.filter_map(std::result::Result::ok) {
            let file = entry.file_name().to_string_lossy().into_owned();
            let Some(name) = file.strip_suffix(".sh") else {
                continue;
            };
            let path = format!("mise-tasks/{file}");
            if lines_of(root, &path).is_some_and(|lines| is_gate(&lines)) {
                found.insert(name.to_owned(), path);
            }
        }
    }
    if let Ok(entries) = std::fs::read_dir(root.join("policy")) {
        for entry in entries.filter_map(std::result::Result::ok) {
            let file = entry.file_name().to_string_lossy().into_owned();
            if let Some(name) = file.strip_suffix(".rego") {
                found.insert(name.to_owned(), format!("policy/{file}"));
            }
        }
    }
    // THE ENGINE, OPT-IN BY DECLARATION (CLOUD-1369) — and the opt-in is the
    // design rather than a softer version of it.
    //
    // `mise-tasks/` is already opt-in by the same shape: a program is censused
    // only if its own `#MISE description` calls it a gate, because that directory
    // holds programs that refuse and programs that measure, and only the first
    // kind owes a mutation. `crates/batten/src` is the same population problem
    // one language over — most modules are plumbing, and a census that demanded a
    // mutation from every one of them would report ~50 uncovered subjects on the
    // day the route landed. CLOUD-1369 puts that retrofit out of scope in its own
    // words: this row buys the ROUTE.
    //
    // SO A DECLARING MODULE IS A SUBJECT AND IS HELD TO THE SET. That is what
    // stops the opt-in being a way out: a module that declares rows and is not in
    // `$MUTANT_GATES` reads `uncovered`, because rows nobody sweeps are the
    // coverage-shaped nothing this whole verb exists to refuse.
    //
    // What sizes the backlog is `engine_undeclared` below — a COUNT, not a
    // finding, because a number is a sensor and a finding is a gate. Reporting
    // the population without refusing it is how the next author learns the size
    // without this change having to close it.
    if let Ok(entries) = std::fs::read_dir(root.join(ENGINE)) {
        for entry in entries.filter_map(std::result::Result::ok) {
            let file = entry.file_name().to_string_lossy().into_owned();
            let Some(stem) = file.strip_suffix(".rs") else {
                continue;
            };
            let path = format!("{ENGINE}/{file}");
            let declares = lines_of(root, &path).is_some_and(|lines| {
                !rows_in(&lines, &path).is_empty()
                    || [SUITE, OWNER, EXEMPT]
                        .iter()
                        .any(|marker| declared(&lines, marker).is_some())
            });
            if declares {
                found.insert(format!("{ENGINE_PREFIX}{}", stem.replace('_', "-")), path);
            }
        }
    }
    if let Ok(entries) = std::fs::read_dir(root.join(PRESETS)) {
        for entry in entries.filter_map(std::result::Result::ok) {
            if !entry.path().is_dir() {
                continue;
            }
            let name = entry.file_name().to_string_lossy().into_owned();
            if !sources_for(root, &name).is_empty() {
                found.insert(name.clone(), format!("{PRESETS}/{name}"));
            }
        }
    }
    found
}

/// Whether an exemption is filed: an issue key and a reason, separated.
///
/// **An exemption is a filed row, and that is the whole difference between this
/// and a `TODO`.** Three ways to be unfiled: a key that is not a tracker key, a
/// blank reason, and no separator at all.
fn exemption_is_filed(row: &str) -> bool {
    let Some((key, why)) = row.split_once('|') else {
        return false;
    };
    if why.trim().is_empty() {
        return false;
    }
    let Some(number) = key.strip_prefix("CLOUD-") else {
        return false;
    };
    !number.is_empty() && number.chars().all(|ch| ch.is_ascii_digit())
}

/// Census the tree against the enforced set, in both directions.
///
/// The reason an exemption gives is READ but never echoed: the verdict names the
/// row's defect, and the prose is in the file the pointer points at
/// (non-negotiable rule 4).
#[must_use]
pub fn census(root: &Path, names: &[String]) -> Census {
    let subjects = subjects(root);
    let mut findings = Vec::new();
    for (name, path) in &subjects {
        let in_set = names.iter().any(|declared| declared == name);
        let exempt = sources_for(root, name)
            .iter()
            .filter_map(|source| lines_of(root, source))
            .find_map(|lines| declared(&lines, EXEMPT));
        match exempt {
            Some(row) if !exemption_is_filed(&row) => {
                findings.push((path.clone(), CensusVerdict::ExemptUnfiled));
            }
            Some(_) if in_set => {
                findings.push((path.clone(), CensusVerdict::DeclaredAndExempt));
            }
            None if !in_set => findings.push((path.clone(), CensusVerdict::Uncovered)),
            // A filed exemption outside the set is a closed census, and so is a
            // declared gate with no exemption. Both are the answer this gate
            // exists to allow.
            Some(_) | None => {}
        }
    }
    // THE REVERSE DIRECTION. The sweep already answers `no-such-gate` for a name
    // that resolves to nothing, but only when somebody runs it — and it is
    // deliberately off the landing path, so a rename that stranded a name could
    // sit unread. This is the cheap half and it runs wherever this gate does.
    for name in names {
        if sources_for(root, name).is_empty() {
            findings.push((name.clone(), CensusVerdict::NamesNoSubject));
        }
    }
    Census {
        findings,
        subjects: subjects.len(),
        engine_undeclared: engine_undeclared(root, &subjects),
    }
}

/// How many engine modules carry no declaration at all.
///
/// **A COUNT, AND DELIBERATELY NOT A FINDING** (CLOUD-1369). `subjects` admits an
/// engine module only once it declares something, so an un-declared one produces
/// no verdict — which would leave the population invisible and make "the backlog
/// is what the census will then report" untrue. This is that report.
///
/// A number is a sensor and a finding is a gate, and the split is what lets the
/// route land green while still saying how much is uncovered. Whoever retrofits
/// the declarations gets the size from here; nothing here refuses anything.
///
/// Pointer-only by construction (rule 4): a count names no module.
///
/// The censused set is passed in rather than re-derived, because `subjects` walks
/// three directories and reads every candidate: computing it per entry would make
/// this quadratic in the size of the engine for a number nobody decides on.
#[must_use]
fn engine_undeclared(root: &Path, censused: &BTreeMap<String, String>) -> usize {
    let Ok(entries) = std::fs::read_dir(root.join(ENGINE)) else {
        return 0;
    };
    entries
        .filter_map(std::result::Result::ok)
        .filter(|entry| {
            let file = entry.file_name().to_string_lossy().into_owned();
            file.strip_suffix(".rs").is_some_and(|stem| {
                !censused.contains_key(&format!("{ENGINE_PREFIX}{}", stem.replace('_', "-")))
            })
        })
        .count()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The sweep's cargo cache is not the repository's, and this is the gate on
    /// it rather than the doc comment above `suite_env`.
    ///
    /// Fails by: putting `root/target` back. That spelling is not a slower build,
    /// it is a WRONG one — the staged tree writes `batten`'s artifacts into the
    /// directory a developer's own `cargo nextest run` reads, and a sweep killed
    /// mid-row leaves the last mutation's bytes there to be linked and verified
    /// against. Asserted as a prefix relationship rather than a string
    /// inequality, so a sibling that merely differs in spelling (`target/../
    /// target`) cannot satisfy it either.
    #[test]
    fn the_sweeps_cargo_cache_is_never_the_repositorys_own() {
        let root = Path::new("/repo");
        let env = suite_env(root);
        let target = env
            .iter()
            .find(|(key, _)| key == "CARGO_TARGET_DIR")
            .map(|(_, value)| PathBuf::from(value));
        let Some(target) = target else {
            panic!("the sweep declares a cargo target directory");
        };
        assert_ne!(
            target,
            root.join("target"),
            "sharing the repository's own target directory is how a staged \
             mutation gets linked into a developer's next local run"
        );
        assert!(
            target.starts_with(root.join("target")),
            "but it stays under `target/`, so one `cargo clean` reaches it and \
             `.gitignore` already covers it"
        );
    }

    #[test]
    fn a_row_is_exactly_three_fields() {
        let lines = vec![
            String::from("#MUTANT slug|s/a/b/|the case"),
            String::from("#MUTANT bad|s/a|b/|extra|the case"),
        ];
        let rows = rows_in(&lines, "policy/x.rego");
        assert!(rows[0].is_ok());
        assert_eq!(rows[1].as_ref().err().map(|(_, n)| *n), Some(5));
    }

    #[test]
    fn an_exempt_row_is_not_a_mutation_row() {
        // The marker carries a trailing space, so `#MUTANT-EXEMPT` and
        // `#MUTANT-SUITE` can never be read as declarations of a mutation.
        let lines = vec![
            String::from("#MUTANT-EXEMPT CLOUD-1|why"),
            String::from("#MUTANT-SUITE crates/batten/tests/x.rs"),
        ];
        assert!(rows_in(&lines, "policy/x.rego").is_empty());
    }

    #[test]
    fn a_declared_rust_suite_carries_its_path_and_names_no_target() {
        // The path is carried to be READ — the existence check and the case
        // census both open it — and a target name is deliberately not derived
        // from it. A grouped suite lives at `tests/it/<x>.rs` and is a MODULE,
        // not a target called `<x>`, so a stem here would name nothing.
        let suite = Suite::declared("crates/batten/tests/it/shell_retirement.rs");
        assert_eq!(
            suite,
            Some(Suite::Cargo {
                path: String::from("crates/batten/tests/it/shell_retirement.rs"),
            })
        );
    }

    #[test]
    fn a_bats_suite_still_resolves() {
        assert_eq!(
            Suite::declared("tests/land.bats"),
            Some(Suite::Bats(String::from("tests/land.bats")))
        );
    }

    #[test]
    fn a_suite_this_runner_cannot_run_is_refused_rather_than_guessed() {
        assert_eq!(Suite::declared("policy/shell-retirement.rego"), None);
        assert_eq!(Suite::declared("mise-tasks/land.sh"), None);
    }

    #[test]
    fn the_extension_decides_and_the_directory_does_not() {
        // Non-negotiable rule 1 as an assertion, and it survives CLOUD-1267's
        // change with MORE force than before: a `.rs` suite resolves wherever it
        // sits, and now nothing about where it sits is read at all. A flat path
        // and a grouped one resolve to the same shape, which is what stopped the
        // core carrying either layout as a convention.
        assert_eq!(
            Suite::declared("somewhere/else/toy.rs"),
            Some(Suite::Cargo {
                path: String::from("somewhere/else/toy.rs"),
            })
        );
        assert_eq!(
            Suite::declared("deep/nested/group/toy.rs"),
            Some(Suite::Cargo {
                path: String::from("deep/nested/group/toy.rs"),
            })
        );
    }

    #[test]
    fn could_not_look_is_not_the_verdict_class() {
        // The acceptance in one assertion: a gate whose suite cannot be resolved
        // or run must stay distinguishable from a survivor, because one is exit
        // 3 and the other is exit 2.
        assert!(
            Verdict::NoSuite {
                suite: String::new()
            }
            .could_not_look()
        );
        assert!(
            Verdict::NamesNoCase {
                want: String::new()
            }
            .could_not_look()
        );
        assert!(
            !Verdict::Survived {
                want: String::new()
            }
            .could_not_look()
        );
        assert!(!Verdict::NoMutantDeclared.could_not_look());
        assert!(!Verdict::Caught.is_finding());
    }

    #[test]
    fn an_unfiled_exemption_is_refused_three_ways() {
        assert!(exemption_is_filed("CLOUD-931|a stated reason"));
        assert!(!exemption_is_filed("later|a stated reason"));
        assert!(!exemption_is_filed("CLOUD-931|   "));
        assert!(!exemption_is_filed("CLOUD-931"));
    }

    #[test]
    fn a_gate_describes_itself_as_one() {
        let gate = vec![String::from("#MISE description=\"Gate: something\"")];
        let hook = vec![String::from("#MISE description=\"PreToolUse hook body\"")];
        let other = vec![String::from("#MISE description=\"Measure: something\"")];
        assert!(is_gate(&gate));
        assert!(is_gate(&hook));
        assert!(!is_gate(&other));
    }

    #[test]
    fn a_survivor_line_echoes_its_owner_and_decides_nothing() {
        let finding = Finding {
            gate: String::from("validator-verdict-clean"),
            slug: Some(String::from("verdict-unread")),
            verdict: Verdict::Survived {
                want: String::from("a_record_carrying_a_finding"),
            },
            owner: Some(String::from("CLOUD-1265|nothing writes a record")),
        };
        let line = finding.to_string();
        assert!(line.contains("SURVIVED"), "{line}");
        assert!(line.contains("CLOUD-1265"), "{line}");
        // The owner annotates; it does not clear the finding.
        assert!(finding.verdict.is_finding());
    }
}
