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
//! fallback and its SUITE as a bats file named after the gate, unconditionally, so a mutation
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
//! beside the `#MUTANT` rows, and nothing else (CLOUD-2160). A source declaring
//! none, or naming a path no runner here recognizes, reports `no-suite` and runs
//! nothing — a guessed suite is a guessed verdict. A
//! `.rego` module can therefore name a crate's `tests/<x>.rs` — the tier
//! that actually drives the engine — as the suite a mutation must redden. The
//! declaration is read PER SOURCE: a preset gate is a directory of modules, and
//! each module's rows run under its own module's suite (see `Gate::suite_for`).
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
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail};

pub mod cover;
pub mod schema;

/// The declaration markers, bare — the comment opener is [`OPENERS`]'s business.
///
/// Beside the code rather than in a manifest: a declaration in a second file is
/// a second authority that drifts.
///
/// **THE OPENER USED TO BE PART OF THE MARKER, AND THAT EXCLUDED AN ENTIRE
/// IMPLEMENTATION LANGUAGE** (CLOUD-1369). These read `#MUTANT `, matched with
/// `strip_prefix` and no trim, so a declaration could only live in a `#`-comment
/// file — bash or Rego. `#MUTANT` is not valid Rust, so no predicate in
/// a crate's `src/**` could carry one, while `obligations-bound` demands the
/// declared obligation file carry exactly that row. The pair was unsatisfiable
/// for every Rust change, and a shell suite was no escape because
/// `V-SHELL-RULE-ADDED` refuses adding one.
///
/// The measured cost was not the gap itself: CLOUD-1349's "shown able to fail"
/// was performed BY HAND — predicate edited to a constant, suite re-run, result
/// read by eye, edit reverted — which is a gated-model verdict standing where
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

/// The namespace an inline task's name carries (CLOUD-1909).
///
/// **A PREFIX, BECAUSE NAMES COLLIDE ACROSS A RETIREMENT.** The retirement
/// campaign keeps a program's name when it moves the body inline, so
/// `mise-tasks/<name>.sh` and `[tasks."<name>"]` routinely name the same gate
/// across a retirement. A bare name would resolve the shell program and leave the
/// inline block's declared rows unread while they read as declared.
const TASK_PREFIX: &str = "task-";

/// The file inline tasks are declared in, as the consumer names it.
///
/// **NAMED BY THE CONSUMER, NEVER BY THE CRATE** — non-negotiable rule 1, and
/// `document_facts::no_artifact_name_reaches_the_core` refused the first draft of
/// this route for spelling the manifest's filename here. Which file carries a
/// task table is a fact about the repository, so it arrives the way the enforced
/// set already does: `$MUTANT_TASKS`, declared beside `$MUTANT_GATES`.
///
/// **UNSET SWITCHES THE ROUTE OFF, and that is the safe direction.** A `task-`
/// name then resolves to nothing, which the sweep reports `no-such-gate` and the
/// census reports as a name resolving to no subject — a could-not-look, never a
/// quiet pass. Read from the environment for `suite_bound`'s reason: the runner's
/// own knobs arrive there, and this is one.
fn task_manifest() -> Option<String> {
    std::env::var("MUTANT_TASKS")
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

/// The revision `$MUTANT_CHANGED_SINCE` names, against which a sweep narrows the
/// enforced set to the gates a change touched (CLOUD-2072). Unset or blank, the
/// sweep covers the whole set, as it always has. Read from the environment for
/// `task_manifest`'s reason: the sweep's scope is declared there.
#[must_use]
pub fn changed_since() -> Option<String> {
    std::env::var("MUTANT_CHANGED_SINCE")
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

/// The lines of one inline task's table, header included, or `None` where the
/// manifest declares no such task (CLOUD-1909).
///
/// **THE BLOCK, NEVER THE FILE, and that is the whole of the route.** Every inline
/// gate shares one source file, so a reader that took the file would let each
/// `task-` gate claim every `#MUTANT` row in it — and a sweep would then apply one
/// task's mutation against another task's suite and call the result coverage.
///
/// **ANCHORED TO A LINE THAT IS THE HEADER.** `[tasks.verify]` is spelled inside
/// comments hundreds of lines above the table it names; a substring search reads
/// the wrong region, which is the measured failure on CLOUD-1329. Both spellings
/// are accepted because both are valid TOML and the manifest uses both.
///
/// **THE BLOCK ENDS AT THE NEXT TABLE HEADER, NOT AT THE NEXT `[`.** A task body is
/// shell, and shell opens lines with `[` and `[[` at column zero — `ci-wait`'s body
/// does. A header carries no whitespace (`[tasks."build:release"]`, `[prune.cold]`),
/// and a shell test always does (`[ -n "$x" ]`), so that is the discriminator. The
/// opposite error would end the block inside a body and drop every declaration
/// written below it.
///
/// Public because the suites that pin a task's own body read it through this, so
/// there is one definition of where a task's table begins and ends rather than one
/// per suite.
#[must_use]
pub fn task_block(lines: &[String], name: &str) -> Option<Vec<String>> {
    let quoted = format!("[tasks.\"{name}\"]");
    let bare = format!("[tasks.{name}]");
    let start = lines.iter().position(|line| {
        let trimmed = line.trim_end();
        trimmed == quoted || trimmed == bare
    })?;
    let rest = lines[start + 1..]
        .iter()
        .take_while(|line| !is_table_header(line))
        .cloned();
    Some(std::iter::once(lines[start].clone()).chain(rest).collect())
}

/// Whether a manifest line opens a TOML table: `[` at column zero, `]` at the end,
/// and no whitespace between — which no line of shell satisfies.
fn is_table_header(line: &str) -> bool {
    let trimmed = line.trim_end();
    trimmed.starts_with('[') && trimmed.ends_with(']') && !trimmed.chars().any(char::is_whitespace)
}

/// Every task name the manifest declares a table for, in file order.
fn task_names(lines: &[String]) -> Vec<String> {
    lines
        .iter()
        .filter(|line| is_table_header(line))
        .filter_map(|line| {
            let inner = line.trim_end().strip_prefix("[tasks.")?.strip_suffix(']')?;
            let name = inner
                .strip_prefix('"')
                .and_then(|quoted| quoted.strip_suffix('"'))
                .unwrap_or(inner);
            // A nested table (`[tasks.x.env]`) is part of its task, not a task.
            (!name.contains('.') || inner.starts_with('"')).then(|| name.to_owned())
        })
        .collect()
}

/// The lines a gate's declarations are read from, out of one of its sources.
///
/// Every source but the manifest is read whole, exactly as before. The manifest is
/// read as the named task's block alone — for a `task-` gate, so its reads cannot
/// reach another task's rows (CLOUD-1909).
fn declaring_lines(root: &Path, name: &str, source: &str) -> Option<Vec<String>> {
    declaring_in(name, source, lines_of(root, source)?)
}

/// [`declaring_lines`] over a source's lines already read: the task block a
/// `task-` gate owns, else every line.
fn declaring_in(name: &str, source: &str, lines: Vec<String>) -> Option<Vec<String>> {
    match name.strip_prefix(TASK_PREFIX) {
        Some(task) if task_manifest().as_deref() == Some(source) => task_block(&lines, task),
        _ => Some(lines),
    }
}

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

/// What `no-suite` names for a gate none of whose sources declares a suite.
const UNDECLARED: &str = "undeclared";

/// Where the consumer keeps its presets, one directory per preset of `.rego`
/// modules, relative to the repository root: `$MUTANT_PRESETS`, read as
/// `MUTANT_TASKS` is, beside the rest of the sweep's scope. Unset, there is no
/// preset arm: the crate names no directory of a consumer's (rule 1,
/// CLOUD-2711).
fn presets_dir() -> Option<String> {
    std::env::var("MUTANT_PRESETS")
        .ok()
        .map(|value| value.trim().trim_end_matches('/').to_owned())
        .filter(|value| !value.is_empty())
}

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
    /// The `MUTANT-SUITE` this row is judged under, as declared: the nearest
    /// one above it in its source, else that source's first; `None` where the
    /// source declares none (CLOUD-2193). Kept as written so a declaration no
    /// runner recognizes can be named in the row's `no-suite`.
    pub suite: Option<String>,
    /// [`Row::suite`] as a runner resolves it, or `None` where it names no
    /// runner here; [`Gate::suite_for`] hands this back by reference.
    pub resolved: Option<Suite>,
}

/// How a gate's suite is run.
///
/// One variant per harness, and the declared mapping is what chooses between
/// them: the predecessor hardcoded one runner and could not express a second,
/// which is the whole of CLOUD-1267.
///
/// **THE NATIVE HARNESSES ARE CLOUD-2160's**, and they are here because the
/// consumers this verb serves are `tofu`, `kyverno`, `conftest` and Python, and no
/// mutation tool exists for Rego or Kyverno. The `#MUTANT` rows, their `sed`
/// scripts and the file arm already work on `.tf`, YAML, `.rego` and `.py`; only
/// the runner set was missing. Each arm reads the HARNESS'S OWN case verdict,
/// never its exit code alone (`probe_verdict.rs`'s rule): a failing case and a
/// run that could not load both exit non-zero, and only the first is evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Suite {
    /// A Rust suite, run as `cargo test -- <case>`. The path is carried to be
    /// READ — for the existence check and the case census — and never to be
    /// turned into a target name.
    Cargo { path: String },
    /// `*.tftest.hcl`, run as `tofu test -json -filter=<file>`. The case is the
    /// `run` block's name, matched exactly against the `test_run` lines.
    Tofu { path: String },
    /// `kyverno-test.yaml`, run as `kyverno test <dir> -t <selector>`. The case
    /// is the `policy=…,rule=…,resource=…` selector, matched exactly.
    Kyverno { path: String },
    /// `*.rego`, run as `conftest verify -p <dir>`. The case is the `test_`
    /// rule's name, matched exactly. conftest has no case filter.
    Conftest { path: String },
    /// `test_*.py` or `*_test.py`, run as `pytest <file> -k <case>`. The case
    /// is a `-k` substring filter, as libtest's is for `Cargo`.
    Pytest { path: String },
}

impl Suite {
    /// The suite a declared path names, or `None` for a path this runner has no
    /// runner for — which is reported rather than guessed at.
    #[must_use]
    pub fn declared(path: &str) -> Option<Self> {
        let file = Path::new(path)
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default();
        let path = path.to_owned();
        if file.ends_with(".tftest.hcl") {
            return Some(Suite::Tofu { path });
        }
        if file == "kyverno-test.yaml" {
            return Some(Suite::Kyverno { path });
        }
        if has_extension(&path, "rego") {
            return Some(Suite::Conftest { path });
        }
        if has_extension(&path, "py") && (file.starts_with("test_") || file.ends_with("_test.py")) {
            return Some(Suite::Pytest { path });
        }
        if !has_extension(&path, "rs") {
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
        Some(Suite::Cargo { path })
    }

    /// The repo-relative path of the file the suite lives in.
    #[must_use]
    pub fn path(&self) -> &str {
        match self {
            Suite::Cargo { path }
            | Suite::Tofu { path }
            | Suite::Kyverno { path }
            | Suite::Conftest { path }
            | Suite::Pytest { path } => path,
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
    /// The first source's declared suite, which a row whose own source declares
    /// none runs under — or `None` where no source declares one, which the
    /// sweep reports as `no-suite (undeclared)` and runs nothing for.
    ///
    /// **NO DEFAULT, AND THERE USED TO BE ONE** (CLOUD-2160). An undeclared
    /// source fell back to a bats file named after the gate, run through a
    /// runner this repository no longer carries — so the code still read as a
    /// supported route, and a consumer plan built on it before review caught it.
    pub suite: Option<Suite>,
    /// The first declared suite path no runner here recognizes, reported as
    /// `no-suite (<path>)` rather than guessed at.
    pub unrunnable: Option<String>,
    /// Every `#MUTANT-SUITE` each source declares, in order, keyed by that
    /// source.
    ///
    /// **EVERY DECLARATION, NOT ONE PER GATE OR PER SOURCE.** A preset gate is
    /// a directory of modules, and each module declares the suite its own cases
    /// live in; a module may declare several, each over the rows below it
    /// (CLOUD-2193). Keeping only the first found made every later line decide
    /// nothing: the census counted the wrong file, a declaration naming a
    /// missing file was never checked, and a change to it selected no sweep.
    /// [`Gate::suites`] reads this; a row's own is on the row.
    pub own_suites: BTreeMap<String, Vec<Suite>>,
    /// The declared mutations, in file then declaration order.
    pub rows: Vec<Row>,
    /// The owning row a known-dead predicate declares, echoed on a survivor and
    /// deciding nothing.
    pub owner: Option<String>,
}

impl Gate {
    /// The suite a row is judged under: the declaration above it in its own
    /// source (CLOUD-2193), else, where its source declares none, the gate's.
    /// `None` where neither resolves, including a declaration no runner here
    /// recognizes, which costs that row alone ([`Row::suite`] names it).
    #[must_use]
    pub fn suite_for<'a>(&'a self, row: &'a Row) -> Option<&'a Suite> {
        match &row.suite {
            Some(_) => row.resolved.as_ref(),
            None => self.suite.as_ref(),
        }
    }

    /// Every suite this gate's rows run under, the gate's own first, each once.
    #[must_use]
    pub fn suites(&self) -> Vec<&Suite> {
        let mut all: Vec<&Suite> = self.suite.iter().collect();
        for suite in self.own_suites.values().flatten() {
            if !all.contains(&suite) {
                all.push(suite);
            }
        }
        all
    }
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
    /// The row does not carry exactly three fields, or its case field is not
    /// one case (`rows_in`); `why` says which.
    MalformedRow { why: String },
    /// The filter matched no case, on either the clean or the mutated run.
    NamesNoCase { want: String },
    /// The suite was still running at its bound and was killed (CLOUD-1860).
    ///
    /// **ITS OWN VARIANT BECAUSE IT NAMES A DIFFERENT ARTIFACT.** A killed run
    /// selects no case, so this was indistinguishable from [`Verdict::NamesNoCase`]
    /// and reported as one — which points the reader at the DECLARATION, the one
    /// thing that is not wrong. The declaration is correct, the case exists, and
    /// what ran out was the clock.
    SuiteTimedOut { seconds: u64 },
    /// The runner printed no summary, so it never ran the suite — a build that
    /// failed or was contended (CLOUD-1910). Not the row's fault, and reported
    /// apart from [`Verdict::NamesNoCase`] so nobody fixes the wrong thing.
    SuiteDidNotRun { want: String },
    /// The harness ran and reported the named case ERRORED rather than failed —
    /// a run that could not load what it was asked to judge (CLOUD-2160).
    ///
    /// **ITS OWN VARIANT, AND A COULD-NOT-LOOK, because the exit code cannot
    /// tell the two apart.** A parse-broken `.tf`, a policy conftest cannot
    /// load and a pytest collection error all exit non-zero exactly as a failing
    /// case does, so a sweep reading the code would call every mutation that
    /// breaks the parse `caught`. Only the case's own failure kills a mutant.
    CaseErrored { want: String },
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
    /// A registered runner's program does not answer here (CLOUD-1746).
    RunnerAbsent,
    /// Two registered runners claim one source, so which judged it is unknown.
    RunnerOverlap,
    /// A declared row in a source a registered runner owns (CLOUD-2253). That
    /// runner judges the source and never reads the row, so the row is
    /// coverage-shaped nothing: refused, never skipped. 868 such rows
    /// accumulated in Rust while the sweep passed over them in silence.
    RunnerOwned {
        /// The runner that owns the source.
        runner: &'static str,
    },
    /// A `command` runner exited with neither 0 (caught) nor 2 (survived), or
    /// ran out of time, so it said nothing about the mutants (CLOUD-2211).
    ///
    /// NOT 1 FOR A SURVIVOR, because 1 is what an uncaught exception or a
    /// crashed wrapper exits with: reading it as a survivor would report a
    /// broken runner as a coverage gap, and reading it as caught would report it
    /// as coverage.
    RunnerErrored { code: Option<i32> },
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
                | Verdict::SuiteTimedOut { .. }
                | Verdict::SuiteDidNotRun { .. }
                | Verdict::CaseErrored { .. }
                | Verdict::CaseAlreadyRed { .. }
                | Verdict::UnappliableMutation
                | Verdict::RunnerAbsent
                | Verdict::RunnerOverlap
                | Verdict::RunnerErrored { .. }
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
            Verdict::MalformedRow { why } => write!(out, "malformed-row ({why})"),
            Verdict::NamesNoCase { want } => write!(out, "names-no-case ({want})"),
            Verdict::SuiteTimedOut { seconds } => {
                write!(out, "suite-timed-out ({seconds}s)")
            }
            Verdict::SuiteDidNotRun { want } => write!(out, "suite-did-not-run ({want})"),
            Verdict::CaseErrored { want } => write!(out, "case-errored ({want})"),
            Verdict::CaseAlreadyRed { want } => write!(out, "case-already-red ({want})"),
            Verdict::FilterNamesEveryCase { want } => {
                write!(out, "filter-names-every-case ({want})")
            }
            Verdict::UnappliableMutation => write!(out, "unappliable-mutation"),
            Verdict::InertMutation => write!(out, "inert-mutation"),
            Verdict::SelfMutatingRow => write!(out, "self-mutating-row"),
            Verdict::RunnerAbsent => write!(out, "runner-absent"),
            Verdict::RunnerOverlap => write!(out, "runner-overlap"),
            Verdict::RunnerOwned { runner } => write!(out, "runner-owned ({runner})"),
            Verdict::RunnerErrored { code: Some(code) } => {
                write!(out, "runner-errored (exit {code})")
            }
            Verdict::RunnerErrored { code: None } => write!(out, "runner-errored (no exit)"),
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
    /// Every finding: the gate-level ones, then the rows', each in sorted gate
    /// order.
    pub findings: Vec<Finding>,
    /// How many declared mutations this sweep judged.
    pub declared: usize,
    /// How many gates this sweep answered for: a gate-level finding reported,
    /// or a row judged ([`sweep_shard`]).
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
    let text = crate::fsio::read_to_string(root.join(path)).ok()?;
    Some(text.lines().map(str::to_owned).collect())
}

/// The value after a marker on the first line that carries it.
///
/// Goes through [`strip_marker`] rather than `strip_prefix`, and that is the half
/// of CLOUD-1369 a compiler cannot catch: dropping the `#` from the marker
/// constants left this function matching a BARE `MUTANT-SUITE ` at column zero,
/// which no file in the tree carries. It compiled clean and would have silently
/// stopped resolving every landed `.rego` declaration — a suite reading as
/// undeclared, an owner and an exemption reading as absent. Compile-clean
/// and gate-dead is the same shape `rules/policy-modules.md` opens with.
fn declared(lines: &[String], marker: &str) -> Option<String> {
    lines.iter().find_map(|line| strip_marker(line, marker))
}

/// Every well-formed `#MUTANT` row in one source under `root`, for a census that
/// applies them (CLOUD-2255): a malformed row is the sweep's to report.
#[must_use]
pub fn rows_of(root: &Path, source: &str) -> Vec<Row> {
    lines_of(root, source)
        .map(|lines| {
            rows_in(&lines, source)
                .into_iter()
                .filter_map(std::result::Result::ok)
                .collect()
        })
        .unwrap_or_default()
}

/// Why [`rows_in`] refuses a three-field row whose case field is not one case.
const NOT_ONE_CASE: &str = "case field is not one case";

/// The `#MUTANT` rows in one source, refusing a row that is not three fields,
/// as `(slug, why)`.
///
/// The count precedes the split because after the split the evidence is gone: a
/// case filter holding a `|` is indistinguishable from one that meant to.
///
/// A CASE FIELD IS ONE CASE NAME, so whitespace or a marker (an opener then
/// `MUTANT`) in it is refused here (CLOUD-2586). Removing a row together with its line break glued
/// the next line's `//MUTANT-SUITE <path>` onto the row above: three fields
/// still, a case that names nothing, and the suite switch lost. The sweep read
/// it `names-no-case` only when it reached that source; the census reads every
/// row and names this one by `path:line`.
///
/// EACH ROW CARRIES THE SUITE ABOVE IT (CLOUD-2193). A source may declare
/// several (`land.rs` declares four, `lib.rs` fifteen), and every author of a
/// later one wrote its rows under it; reading only the first judged them all
/// under the first, so a change to a later suite selected no sweep and the
/// every-case check counted the wrong file. A row above every declaration
/// keeps the first, which is all a single-declaration source ever had.
fn rows_in(lines: &[String], source: &str) -> Vec<std::result::Result<Row, (String, String)>> {
    let first = declared(lines, SUITE);
    let mut above = first.clone();
    let mut rows = Vec::new();
    for line in lines {
        if let Some(suite) = strip_marker(line, SUITE) {
            above = Some(suite);
            continue;
        }
        let Some(body) = strip_marker(line, ROW) else {
            continue;
        };
        let fields: Vec<&str> = body.split('|').collect();
        let [slug, script, want] = fields.as_slice() else {
            let why = format!("{} fields, want 3", fields.len());
            rows.push(Err((fields[0].to_owned(), why)));
            continue;
        };
        let glued = OPENERS
            .iter()
            .any(|opener| want.contains(&format!("{opener}MUTANT")));
        if glued || want.contains(char::is_whitespace) {
            rows.push(Err(((*slug).to_owned(), String::from(NOT_ONE_CASE))));
            continue;
        }
        rows.push(Ok(Row {
            slug: (*slug).to_owned(),
            script: (*script).to_owned(),
            want: (*want).to_owned(),
            source: source.to_owned(),
            resolved: above.as_deref().and_then(Suite::declared),
            suite: above.clone(),
        }));
    }
    rows
}

/// The sources a gate name resolves to, in the order the predecessor resolved
/// them: a shell task first, then a module of the same name, then a preset
/// directory — and after the engine and inline-task arms, a name that IS a
/// repo-relative file path.
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
    let mut found: Vec<String> = presets_dir()
        .and_then(|presets| {
            std::fs::read_dir(root.join(&presets).join(name))
                .ok()
                .map(|entries| (presets, entries))
        })
        .map(|(presets, entries)| {
            entries
                .filter_map(std::result::Result::ok)
                .filter_map(|entry| {
                    let file = entry.file_name().to_string_lossy().into_owned();
                    has_extension(&file, "rego").then(|| format!("{presets}/{name}/{file}"))
                })
                .collect()
        })
        .unwrap_or_default();
    // Sorted so the sweep is byte-stable: a directory read has no order, and a
    // report whose row order varies per run cannot be diffed.
    found.sort();
    if !found.is_empty() {
        return found;
    }
    // THE INLINE-TASK ARM (CLOUD-1909), LAST OF ALL, so it stays additive:
    // a name that resolved to anything before still resolves to exactly that, so
    // no landed gate changes meaning by growing a same-named task block.
    if let Some(task) = name.strip_prefix(TASK_PREFIX)
        && let Some(manifest) = task_manifest()
        && lines_of(root, &manifest).is_some_and(|lines| task_block(&lines, task).is_some())
    {
        return vec![manifest];
    }
    // THE FILE ARM (CLOUD-1991), after every other for the same additive reason: a
    // predicate evaluated by a tool the engine does not host — a Pkl module beside
    // the hook config it reads, say — lives in a file no arm above can name. The
    // gate name IS that file's repo-relative path, so a row declared in it mutates
    // the predicate itself rather than a caller's spelling of it. A kebab gate name
    // carries no extension, so no landed name can start resolving here.
    if is_source_path(name) && root.join(name).is_file() {
        return vec![name.to_owned()];
    }
    Vec::new()
}

/// Whether a gate name is a repo-relative file path the file arm may resolve: it
/// carries an extension, and every component is a plain name — so it can neither
/// be absolute nor climb out of the root with `..`.
fn is_source_path(name: &str) -> bool {
    let path = Path::new(name);
    path.extension().is_some()
        && path
            .components()
            .all(|component| matches!(component, std::path::Component::Normal(_)))
}

/// Resolve one gate name against the tree.
///
/// `None` where the name resolves to no source at all — the caller reports
/// `no-such-gate` rather than skipping, because a name in the set that resolves
/// to nothing is exactly the drift the census exists to find.
#[must_use]
pub fn resolve(root: &Path, name: &str) -> Option<Gate> {
    gate_of(root, name, &sources_for(root, name))
}

/// The gate `name` is over `sources`, or `None` for no source: [`resolve`]'s
/// reading, apart from where the sources were found.
fn gate_of(root: &Path, name: &str, sources: &[String]) -> Option<Gate> {
    if sources.is_empty() {
        return None;
    }
    let mut rows = Vec::new();
    let mut malformed = Vec::new();
    let mut suite = None;
    let mut unrunnable = None;
    let mut own_suites = BTreeMap::new();
    let mut owner = None;
    for source in sources {
        let Some(lines) = declaring_lines(root, name, source) else {
            continue;
        };
        // EVERY DECLARATION IN THE SOURCE, NOT ITS FIRST (CLOUD-2193): each
        // is a suite some of its rows run under, so each is one a change can
        // weaken. A source's FIRST naming a path no runner here recognizes is
        // reported as `no-suite` under that path for the gate, as before; a
        // later one costs only the rows under it ([`Gate::suite_for`]).
        let mut own = Vec::new();
        for (index, raw) in lines
            .iter()
            .filter_map(|line| strip_marker(line, SUITE))
            .enumerate()
        {
            match Suite::declared(&raw) {
                Some(resolved) => {
                    suite = suite.or(Some(resolved.clone()));
                    own.push(resolved);
                }
                None if index == 0 => unrunnable = unrunnable.or(Some(raw)),
                None => {}
            }
        }
        if !own.is_empty() {
            own_suites.insert(source.clone(), own);
        }
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
    for (head, why) in malformed {
        rows.push(Row {
            slug: head,
            script: String::new(),
            want: format!("\u{0}malformed:{why}"),
            source: sources[0].clone(),
            suite: None,
            resolved: None,
        });
    }
    Some(Gate {
        name: name.to_owned(),
        sources: sources.to_vec(),
        suite,
        unrunnable,
        own_suites,
        rows,
        owner,
    })
}

/// The enforced set: the committed `[mutate].gates`, expanded, then every name
/// `$MUTANT_GATES` adds (CLOUD-2010).
///
/// **ONE COMMITTED AUTHORITY, PLUS A RAISE-ONLY OVERRIDE** (house-style §8). The
/// set used to be the variable alone, which only this repository's own task
/// runner set, so every consumer refused with `MUTANT_GATES is unset`. The
/// variable still adds names and can never remove one the table declares.
///
/// An empty set is fatal rather than an empty sweep: a task that silently
/// covers nothing is the defect this exists to refuse, one level up.
///
/// # Errors
///
/// Both empty, a `[mutate]` glob or scope that does not compile, or a tree
/// whose tracked paths cannot be listed for a glob, is a usage error
/// (→ exit `1`).
pub fn enforced_set(root: &Path, table: Option<&crate::config::Mutate>) -> Result<Vec<String>> {
    let mut names = committed(root, table)?;
    let raw = std::env::var("MUTANT_GATES").unwrap_or_default();
    for name in raw
        .split(',')
        .map(str::trim)
        .filter(|name| !name.is_empty())
    {
        if !names.iter().any(|have| have == name) {
            names.push(name.to_owned());
        }
    }
    if names.is_empty() {
        bail!(
            "the enforced set is empty — `[mutate].gates` in the committed batten.toml declares \
             no gate and $MUTANT_GATES adds none. An empty set makes this a sweep that silently \
             covers nothing, which is the defect it exists to refuse."
        );
    }
    Ok(names)
}

/// The committed table's gates, each glob expanded to the names its matches
/// already have as subjects, in tracked-path order.
fn committed(root: &Path, table: Option<&crate::config::Mutate>) -> Result<Vec<String>> {
    let Some(table) = table else {
        return Ok(Vec::new());
    };
    // Compiled here, where an error can still be a usage error, so the census's
    // declaration arm below never meets a scope it cannot read.
    crate::rules::PathSet::scope(&table.scope)?;
    let declared = &table.gates;
    let tracked = if declared.iter().any(|entry| entry.contains('*')) {
        crate::git::tracked_paths(root)
            .context("mutate: could not list the tracked tree to expand `[mutate].gates`")?
    } else {
        std::collections::BTreeSet::new()
    };
    let mut names: Vec<String> = Vec::new();
    for entry in declared {
        let expanded = if entry.contains('*') {
            let selector = crate::rules::Selector::new(entry)?;
            let matched: Vec<String> = tracked
                .iter()
                .filter(|path| selector.matches(path))
                .map(|path| subject_name(root, path))
                .collect();
            // A glob matching nothing stays as written: it resolves to no
            // source, so the census names it rather than the set shrinking
            // silently around it.
            if matched.is_empty() {
                vec![entry.clone()]
            } else {
                matched
            }
        } else {
            vec![entry.clone()]
        };
        for name in expanded {
            if !names.contains(&name) {
                names.push(name);
            }
        }
    }
    Ok(names)
}

/// The name a tracked file already has as a subject: `X` for `policy/X.rego`,
/// the task name for `mise-tasks/X.sh`, the preset for a preset's module — and its own path, the file arm's name, for a
/// file no other arm names.
///
/// **CHECKED BY RESOLVING IT BACK**, so a name is only offered where
/// [`sources_for`] would take it to this very file: a module whose stem a shell
/// task also carries resolves to the task, and gets its path instead.
fn subject_name(root: &Path, path: &str) -> String {
    let presets = presets_dir().map(|presets| format!("{presets}/"));
    let candidates = [
        path.strip_prefix("mise-tasks/")
            .and_then(|rest| rest.strip_suffix(".sh"))
            .map(str::to_owned),
        path.strip_prefix("policy/")
            .and_then(|rest| rest.strip_suffix(".rego"))
            .map(str::to_owned),
        presets
            .as_deref()
            .and_then(|presets| path.strip_prefix(presets))
            .and_then(|rest| rest.split_once('/'))
            .map(|(name, _)| name.to_owned()),
    ];
    candidates
        .into_iter()
        .flatten()
        .find(|name| {
            !name.contains('/') && sources_for(root, name).iter().any(|source| source == path)
        })
        .unwrap_or_else(|| path.to_owned())
}

// ---------------------------------------------------------------------------
// Narrowing the set to a change (CLOUD-2072).
// ---------------------------------------------------------------------------

/// The enforced gates a change can move, so a sweep can run at admission over
/// the gates a pull request touched rather than on a schedule over all of them.
///
/// A gate is touched when a changed path is one of its sources, or one of
/// [`Gate::suites`] whose CODE changed (`code_changed`, the paths whose
/// non-comment remainder moved): a weaker suite is the commonest way a gate stops
/// discriminating, so a change to the suite alone must re-sweep its rows, and a
/// comment edit to one cannot weaken it. A source is read whole, comments
/// included, because a gate's rows are comment lines in it.
///
/// A changed path inside a PRESET gate's directory touches that gate too, and
/// that is what reaches a DELETED module: `resolve` reads the tree as it is now,
/// so a module the change removed is no longer among the gate's sources, and a
/// match on sources alone let the deletion pass unswept (review of #1099).
///
/// A gate whose rows another registered runner owns is touched like any other,
/// so the sweep reaches its rows and refuses each as `runner-owned`: a row is
/// never judged by two runners, and never passed over by both.
///
/// A name that resolves to nothing is KEPT. Narrowing it away would turn the
/// sweep's `no-such-gate` report into silence; could-not-look widens here as it
/// does in `ci suites`.
#[must_use]
pub fn touched(
    root: &Path,
    names: &[String],
    changed: &std::collections::BTreeSet<String>,
    code_changed: &std::collections::BTreeSet<String>,
) -> Vec<String> {
    names
        .iter()
        .filter(|name| {
            resolve(root, name).is_none_or(|gate| changed_by(&gate, name, changed, code_changed))
        })
        .cloned()
        .collect()
}

/// Whether the change moves `gate`: a changed path is one of its sources, a
/// [`Gate::suites`] entry whose code changed, or inside its preset directory
/// ([`touched`]'s three arms).
fn changed_by(
    gate: &Gate,
    name: &str,
    changed: &std::collections::BTreeSet<String>,
    code_changed: &std::collections::BTreeSet<String>,
) -> bool {
    let by_source = gate.sources.iter().any(|path| changed.contains(path));
    let by_suite = gate
        .suites()
        .iter()
        .any(|s| code_changed.contains(s.path()));
    let by_preset = presets_dir().is_some_and(|presets| {
        let dir = format!("{presets}/{name}/");
        changed.iter().any(|path| path.starts_with(&dir))
    });
    by_source || by_suite || by_preset
}

// ---------------------------------------------------------------------------
// The runner registry (CLOUD-1746).
// ---------------------------------------------------------------------------

/// The registry's declaration: `<runner>=<glob>[,<glob>…]`, entries split by `;`.
///
/// AN ENVIRONMENT VALUE, BESIDE `$MUTANT_GATES`, for `task_manifest`'s reason:
/// the sweep's whole scope is declared there today, and CLOUD-2010 moves the set
/// into config together rather than one key at a time.
pub const RUNNERS: &str = "MUTANT_RUNNERS";

/// Which registered runner this invocation ALSO runs, by its id, after the
/// declared runner's sweep. Unset runs the declared runner alone, which is what
/// `verify` does; a CI job sets it where the runner is installed.
pub const RUNNER: &str = "MUTANT_RUNNER";

/// The shard this invocation takes, as `k/n` with `k` counted from zero: slice
/// `k` of the declared runner's rows ([`shard_owns_row`]), and the registered
/// runner's own shard `k`.
pub const SHARD: &str = "MUTANT_SHARD";

/// The gates whose GATE-LEVEL findings one `$MUTANT_SHARD` of `k/n` reports:
/// every `n`-th of the sorted set, starting at `k`, so each is reported once.
///
/// Rows are sliced finer, by [`shard_owns_row`] (CLOUD-2533): slicing by gate put
/// a 45-row gate on one shard, past the `mutants` job's bound. Sorted first, so
/// every shard of one run slices the same order and the slices partition the set.
///
/// # Errors
///
/// A value that is not `k/n` with `n > 0` and `k < n`.
pub fn shard_of(names: &[String], shard: &str) -> Result<Vec<String>, String> {
    Ok(by_shard(names, Some(shard_parsed(shard)?))
        .into_iter()
        .filter(|(_, owned)| *owned)
        .map(|(name, _)| name.clone())
        .collect())
}

/// Every name once, sorted, with whether `shard` owns it: the one order every
/// shard of a run numbers the gates in, so [`shard_of`] and [`sweep_shard`]
/// agree. Gates are dealt by the same rule as rows, [`shard_owns_row`].
fn by_shard(names: &[String], shard: Option<(usize, usize)>) -> Vec<(&String, bool)> {
    let mut sorted: Vec<&String> = names.iter().collect();
    sorted.sort();
    sorted.dedup();
    sorted
        .into_iter()
        .enumerate()
        .map(|(index, name)| (name, shard_owns_row(index, shard)))
        .collect()
}

/// Whether the declared row numbered `index` (counted across the sorted gates,
/// each gate's rows as declared) is this shard's to judge: every row when
/// unsharded, else every `n`-th starting at `k`.
///
/// BY ROW, NOT BY GATE (CLOUD-2533). A gate's rows share one staged tree and one
/// suite build, so a gate split across shards pays that build on each; that is
/// one warm build against a shard that cannot finish at all.
#[must_use]
pub fn shard_owns_row(index: usize, shard: Option<(usize, usize)>) -> bool {
    shard.is_none_or(|(k, n)| index % n == k)
}

/// A mutation runner the registry can name.
///
/// CLOSED, for [`Program`]'s reason (CLOUD-1924): a runner is a program this
/// module spawns and an outcome format it reads, so a new one is a variant a
/// reviewer reads rather than an argv a consumer types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RunnerKind {
    /// The hand-rolled runner: applies each declared `MUTANT` row's sed script
    /// and requires the case the row names to go red. It owns every source no
    /// other runner is registered for, so no source is ever owned by none.
    Declared,
    /// `cargo mutants --in-diff`: generates its own mutants over the changed
    /// functions of the Rust sources it owns, and runs against each the suites
    /// that source declares beside its own unit tests.
    CargoMutants,
    /// The consumer's own mutation tool (CLOUD-2211), run once over the sources
    /// it owns. Its argv is committed `[mutate] command`, so the CLOSED principle
    /// above still holds: the program is one a reviewer reads in the authority,
    /// and only its exit code is read — 0 caught, 2 survived, anything else
    /// [`Verdict::RunnerErrored`].
    Command,
}

impl RunnerKind {
    /// The id the registry and `$MUTANT_RUNNER` spell.
    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            RunnerKind::Declared => "declared",
            RunnerKind::CargoMutants => "cargo-mutants",
            RunnerKind::Command => "command",
        }
    }

    /// The runner an id names, or `None` for an id no runner carries.
    #[must_use]
    pub fn parse(id: &str) -> Option<Self> {
        [
            RunnerKind::Declared,
            RunnerKind::CargoMutants,
            RunnerKind::Command,
        ]
        .into_iter()
        .find(|kind| kind.id() == id)
    }
}

/// Which registered runner owns which sources.
///
/// Every source has exactly one owner: the first registered runner whose glob
/// matches it, else [`RunnerKind::Declared`]. Two runners matching one source is
/// [`Registry::owner`]'s error, because a source judged twice is a second
/// mutation system and a source judged by the wrong one is a silent gap.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Registry {
    owns: Vec<(RunnerKind, String)>,
    /// The `command` runner's argv, from committed `[mutate] command`.
    command: Vec<String>,
}

impl Registry {
    /// Read a declaration (see [`RUNNERS`]).
    ///
    /// # Errors
    ///
    /// An entry with no `=`, a runner id no variant carries, or a glob given to
    /// the declared runner, which owns by default and takes none.
    pub fn parse(raw: &str) -> Result<Self> {
        let mut owns = Vec::new();
        for entry in raw
            .split(';')
            .map(str::trim)
            .filter(|entry| !entry.is_empty())
        {
            let Some((id, globs)) = entry.split_once('=') else {
                bail!("{RUNNERS} entry `{entry}` is not `<runner>=<glob>[,<glob>]`");
            };
            let Some(kind) = RunnerKind::parse(id.trim()) else {
                bail!(
                    "{RUNNERS} names `{}`, which is no runner: the runners are `declared`, \
                     `cargo-mutants` and `command`",
                    id.trim()
                );
            };
            if kind == RunnerKind::Declared {
                bail!(
                    "{RUNNERS} gives `declared` globs, but it owns every source no other runner \
                     is registered for and takes none"
                );
            }
            for glob in globs
                .split(',')
                .map(str::trim)
                .filter(|glob| !glob.is_empty())
            {
                owns.push((kind, glob.to_owned()));
            }
        }
        Ok(Self {
            owns,
            ..Self::default()
        })
    }

    /// Attach the `command` runner's committed argv (CLOUD-2211).
    ///
    /// # Errors
    ///
    /// The registry registers `command` and `[mutate] command` declares no argv:
    /// a runner with nothing to run would otherwise be found absent only where it
    /// runs, as a could-not-look, rather than here as the usage error it is.
    pub fn with_command(mut self, argv: &[String]) -> Result<Self> {
        if argv.is_empty() && self.registered().contains(&RunnerKind::Command) {
            bail!(
                "{RUNNERS} registers `command`, and `[mutate] command` in batten.toml declares no \
                 argv for it to run"
            );
        }
        self.command = argv.to_vec();
        Ok(self)
    }

    /// The registry `$MUTANT_RUNNERS` declares; unset is the empty registry, in
    /// which the declared runner owns everything.
    ///
    /// # Errors
    ///
    /// [`Registry::parse`]'s.
    pub fn from_env() -> Result<Self> {
        Self::parse(&std::env::var(RUNNERS).unwrap_or_default())
    }

    /// The runner that owns `path`.
    ///
    /// # Errors
    ///
    /// Two different runners register a glob matching it.
    pub fn owner(&self, path: &str) -> Result<RunnerKind> {
        let owners: std::collections::BTreeSet<RunnerKind> = self
            .owns
            .iter()
            .filter(|(_, glob)| crate::rules::glob_match(glob, path))
            .map(|(kind, _)| *kind)
            .collect();
        let mut owners = owners.into_iter();
        match (owners.next(), owners.next()) {
            (None, _) => Ok(RunnerKind::Declared),
            (Some(kind), None) => Ok(kind),
            (Some(first), Some(second)) => bail!(
                "{RUNNERS} registers both `{}` and `{}` for {path}; a source has one owner",
                first.id(),
                second.id()
            ),
        }
    }

    /// Whether the declared runner judges `row`. An overlap answers yes, so
    /// the row is still judged by someone while [`run_registered`] reports it.
    #[must_use]
    pub fn declares(&self, row: &Row) -> bool {
        self.owner(&row.source)
            .map_or(true, |kind| kind == RunnerKind::Declared)
    }

    /// Every runner the registry names besides the declared one, each once.
    #[must_use]
    pub fn registered(&self) -> Vec<RunnerKind> {
        let kinds: std::collections::BTreeSet<RunnerKind> =
            self.owns.iter().map(|(kind, _)| *kind).collect();
        kinds.into_iter().collect()
    }
}

/// What a registered runner decided about a change.
#[derive(Debug, Clone, Default)]
pub struct Registered {
    /// Every finding, a pointer each: the source and line of a missed mutant,
    /// or a source the runner could not judge.
    pub findings: Vec<Finding>,
    /// How many mutants the runner generated and ran.
    pub mutants: usize,
    /// How many changed sources it owned.
    pub sources: usize,
}

/// The changed sources `kind` owns: present in the tree, so a deleted file,
/// which has nothing left to mutate, is not one.
#[must_use]
pub fn owned_changes(
    root: &Path,
    changed: &std::collections::BTreeSet<String>,
    registry: &Registry,
    kind: RunnerKind,
) -> Vec<String> {
    changed
        .iter()
        .filter(|path| root.join(path).is_file())
        .filter(|path| registry.owner(path).is_ok_and(|owner| owner == kind))
        .cloned()
        .collect()
}

/// Whether each registered runner's program answers in `root`, as a finding per
/// runner that does not (`runner-absent`, could-not-look).
///
/// Checked before a registered runner is run (`$MUTANT_RUNNER`), so a runner
/// that is not installed reads as could-not-look rather than as a clean sweep.
///
/// CARGO-MUTANTS RUNS NEXTEST (`--test-tool nextest`), so nextest is probed
/// beside it and reported as its own [`NEXTEST`] finding (CLOUD-2466 item 4).
#[must_use]
pub fn unresolvable(root: &Path, registry: &Registry) -> Vec<Finding> {
    // A LOOKUP, NEVER A PROBE RUN: the consumer's program has no `--version`
    // contract, and running it would be the sweep itself.
    absent_runners(registry, |program| resolves(root, program))
        .into_iter()
        .map(runner_absent)
        .collect()
}

/// The runners `registry` needs whose program does not answer, by id: `command`
/// says whether a `command` runner's program resolves.
fn absent_runners(registry: &Registry, command: impl Fn(&str) -> bool) -> Vec<&'static str> {
    registry
        .registered()
        .into_iter()
        .filter(|kind| match kind {
            // The declared runner is this module; cargo-mutants runs as itself.
            RunnerKind::Declared | RunnerKind::CargoMutants => false,
            RunnerKind::Command => !registry
                .command
                .first()
                .is_some_and(|program| command(program)),
        })
        .map(RunnerKind::id)
        .collect()
}

/// The runner every declared Cargo suite runs under, as its `runner-absent`
/// names it.
pub const NEXTEST: &str = "cargo-nextest";

/// `cargo <subcommand> --version` answers from `root`.
fn cargo_answers(root: &Path, subcommand: &str) -> bool {
    let args = [subcommand, "--version"].map(String::from);
    spawn(root, Program::Cargo, &args, &[], HOUSEKEEPING_BOUND).is_ok_and(|ran| ran.passed())
}

/// The could-not-look finding for a runner whose program does not answer.
fn runner_absent(runner: &str) -> Finding {
    Finding {
        gate: runner.to_owned(),
        slug: None,
        verdict: Verdict::RunnerAbsent,
        owner: None,
    }
}

/// Whether `program` names something runnable from `root`: a path (any name
/// with a separator) that is a file, or a bare name found on `PATH`.
fn resolves(root: &Path, program: &str) -> bool {
    if program.contains('/') {
        return root.join(program).is_file();
    }
    std::env::var_os("PATH")
        .is_some_and(|path| std::env::split_paths(&path).any(|dir| dir.join(program).is_file()))
}

/// What a `command` runner's exit says (CLOUD-2211): 0 caught, 2 survived, and
/// anything else — 1 included, which is a crash's code — could-not-look.
#[must_use]
fn command_verdict(ran: &Ran) -> Verdict {
    match ran.outcome {
        Outcome::Passed => Verdict::Caught,
        Outcome::Failed(Some(2)) => Verdict::Survived {
            want: String::from("exit 2"),
        },
        Outcome::Failed(code) => Verdict::RunnerErrored { code },
        Outcome::TimedOut => Verdict::RunnerErrored { code: None },
    }
}

/// The `command` runner (CLOUD-2211): the committed argv once, over every owned
/// source, in the checkout. The tool owns its own staging, and `$MUTANT_SHARD`
/// reaches it through the inherited environment unchanged.
fn run_command(root: &Path, registry: &Registry, sources: &[String]) -> Result<Option<Finding>> {
    let Some((program, args)) = registry.command.split_first() else {
        bail!("mutate: `command` is registered and `[mutate] command` declares no argv");
    };
    let args: Vec<String> = args.iter().chain(sources).cloned().collect();
    let ran = spawn(root, Program::Command(program), &args, &[], runner_bound())?;
    let verdict = command_verdict(&ran);
    Ok(verdict.is_finding().then(|| Finding {
        gate: RunnerKind::Command.id().to_owned(),
        slug: None,
        verdict,
        owner: None,
    }))
}

/// Judge a change for `kind`: every changed path two runners claim is a
/// `runner-overlap`, and the `command` runner runs once over the sources it
/// owns (cargo-mutants runs as itself; the declared runner is the sweep).
///
/// # Errors
///
/// The `command` runner cannot be spawned; a `shard` that is not `k/n` with
/// `k < n`, which [`shard_parsed`] never yields.
pub fn run_registered(
    root: &Path,
    registry: &Registry,
    changed: &std::collections::BTreeSet<String>,
    kind: RunnerKind,
    shard: Option<(usize, usize)>,
) -> Result<Registered> {
    if let Some((k, n)) = shard
        && shard_bounded(k, n).is_none()
    {
        bail!("mutate: shard {k}/{n} is not `k/n` with 0 <= k < n");
    }
    let mut result = Registered::default();
    for path in changed {
        if let Err(reason) = registry.owner(path) {
            let _ = reason;
            result.findings.push(Finding {
                gate: kind.id().to_owned(),
                slug: Some(path.clone()),
                verdict: Verdict::RunnerOverlap,
                owner: None,
            });
        }
    }
    let sources = owned_changes(root, changed, registry, kind);
    result.sources = sources.len();
    // ONLY THE `command` RUNNER IS RUN HERE. cargo-mutants runs as itself
    // (`cargo mutants --in-diff`), and the declared runner is the sweep.
    if kind == RunnerKind::Command && !sources.is_empty() {
        result
            .findings
            .extend(run_command(root, registry, &sources)?);
    }
    Ok(result)
}

/// The nextest settings that decide a verdict, chosen by the sweep on BOTH of
/// its nextest runners (the declared Cargo arm and cargo-mutants) so no profile
/// or inherited variable does (CLOUD-2466 item 9). `retries` turns a killing
/// case's flaky pass into a survivor; a profile's `default-filter` intersects
/// with `-E` and empties the selection; a `status-level` below `pass` hides the
/// lines the declared arm counts, so its clean run names no case.
///
/// THE TIMEOUT IS NOT HERE, because cargo-nextest 0.9.104 has no flag for it
/// (`cargo nextest run --help`): a profile's `terminate-after` still bounds a
/// case inside the sweep's own bound (CLOUD-2590).
///
/// `--fail-fast`: A MUTANT IS DECIDED BY ITS FIRST FAILING CASE.
/// `.config/nextest.toml` sets `fail-fast = false` so a suite run reports every
/// failure, which a mutant run has no use for: measured on CLOUD-2595,
/// `declared -> None` failed case after case for 53s until the bound cut it off
/// as TIMEOUT, a caught mutant graded as a finding. A clean run is unchanged, so
/// the declared arm still counts every case it names.
const NEXTEST_VERDICT_FLAGS: [&str; 4] = [
    "--retries=0",
    "--ignore-default-filter",
    "--status-level=pass",
    "--fail-fast",
];

/// The shard a `$MUTANT_SHARD` of `value` asks for: none when it is unset or
/// blank, else its raw text for [`parse_shard`] to read or refuse.
#[must_use]
pub fn shard_set(value: Option<String>) -> Option<String> {
    value.filter(|shard| !shard.trim().is_empty())
}

/// `$MUTANT_SHARD`'s `k/n`, or the usage error that refuses it.
///
/// # Errors
///
/// A value that is not `k/n` with `n > 0` and `k < n`.
pub fn shard_parsed(shard: &str) -> Result<(usize, usize), String> {
    parse_shard(shard).ok_or_else(|| format!("{SHARD}={shard} is not `k/n` with 0 <= k < n"))
}

/// `$MUTANT_SHARD`'s `k/n`, or `None` where it is not one (`k < n`, `n > 0`).
#[must_use]
pub fn parse_shard(shard: &str) -> Option<(usize, usize)> {
    let (k, n) = shard.trim().split_once('/')?;
    let (k, n) = (k.trim().parse().ok()?, n.trim().parse().ok()?);
    shard_bounded(k, n)
}

/// `(k, n)` where it names a shard (`k < n`, so `n > 0`), else `None`: the one
/// statement of the bound, for the text [`parse_shard`] reads and the tuple
/// [`run_registered`] is handed.
const fn shard_bounded(k: usize, n: usize) -> Option<(usize, usize)> {
    if k < n { Some((k, n)) } else { None }
}

/// How long one registered run over one source may take: a build per mutant.
fn runner_bound() -> std::time::Duration {
    std::time::Duration::from_secs(
        std::env::var("BATTEN_MUTATE_RUNNER_TIMEOUT")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .filter(|seconds| *seconds > 0)
            .unwrap_or(21_600),
    )
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
            if crate::fsio::read(&to)
                .is_ok_and(|there| crate::fsio::read(&from).is_ok_and(|here| here == there))
            {
                continue;
            }
            if let Some(parent) = to.parent() {
                std::fs::create_dir_all(parent)
                    .with_context(|| format!("mutate: could not stage {path}"))?;
            }
            std::fs::copy(&from, &to).with_context(|| format!("mutate: could not stage {path}"))?;
        }
        let staged = Staged { dir, dirty: None };
        let tracked: Vec<String> = tracked.into_iter().collect();
        staged.make_a_repository(&tracked)?;
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
    /// The identity is the engine's own, so a contributor with no global
    /// `user.email` gets the same throwaway commit as CI.
    ///
    /// **RE-RUNNABLE, AND THAT IS WHAT THE OLD `--allow-empty` WAS FOR.** The
    /// staged tree PERSISTS between runs by design — that is what keeps an
    /// unchanged source's timestamp and a compiled tier affordable — so every run
    /// after the first commits a tree identical to `HEAD`'s. `commit_paths` takes
    /// the current `HEAD` as the parent and commits regardless, where a plain
    /// `git commit` exited 1 and this step bailed naming the wrong thing.
    fn make_a_repository(&self, tracked: &[String]) -> Result<()> {
        // IN-PROCESS (review of #962): `git init`, `git add -A` and `git commit
        // --allow-empty` were three spawns of the one program this crate stopped
        // invoking. `commit_paths` commits the tracked list and writes the index,
        // so a suite asking git what is tracked reads what `add -A` staged.
        crate::gitwrite::commit_paths(&self.dir, tracked, "mutate: the tree under judgement")
            .context(
                "mutate: could not make the staged tree a repository; a suite that resolves \
                 its own root would answer about the wrong one",
            )
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
        copy_if_changed(&root.join(&path), &self.dir.join(&path))
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
        copy_if_changed(&root.join(path), &self.dir.join(path))
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

/// Copy `from` over `to` only where the bytes differ (review of #962).
///
/// A copy always bumps the destination's mtime, so staging the clean subject
/// and restoring it made cargo see a changed source on every row and rebuild
/// inside the timed run. Leaving identical bytes untouched keeps the tree warm.
fn copy_if_changed(from: &Path, to: &Path) -> std::io::Result<()> {
    let wanted = crate::fsio::read(from)?;
    if crate::fsio::read(to).is_ok_and(|have| have == wanted) {
        return Ok(());
    }
    std::fs::copy(from, to).map(|_| ())
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
    let previous = crate::fsio::read_to_string(dir.join(MANIFEST)).unwrap_or_default();
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
    crate::durable::replace(dir.join(MANIFEST), manifest.join("\n"))
        .context("mutate: could not record what was staged")?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Spawning.
// ---------------------------------------------------------------------------

/// How one spawned program ended (CLOUD-2246): one answer, where `ok`, `code`
/// and `timed_out` were three fields whose readers combined them in different
/// orders, and `apply` read a timeout as the row's own refusal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// It exited zero.
    Passed,
    /// It exited non-zero, with its code, `None` for a child ended by a signal.
    /// The `command` runner's whole contract is the code (CLOUD-2211).
    Failed(Option<i32>),
    /// Its bound expired and this process killed the child
    /// (CLOUD-1860).
    ///
    /// **CARRIED RATHER THAN INFERRED, because inferring it is the defect.** A
    /// killed child wrote no case line, so `selected` is 0 and the caller
    /// reported `names-no-case` — *a filter that matches nothing* — for a case
    /// that is present, reachable and green. That sends whoever reads the sweep
    /// to repair a declaration which is already correct, and it is how 109 of 341
    /// declared mutations sat unlooked-at while the verb reported coverage.
    TimedOut,
}

/// What one spawned program answered.
#[derive(Debug)]
pub struct Ran {
    /// How it ended.
    pub outcome: Outcome,
    /// Its combined output, which is scanned for case lines and never reported.
    pub output: String,
    /// Its standard output alone, for a program whose answer is a document
    /// (nextest's binary list, cargo's metadata) that stderr would corrupt.
    pub stdout: String,
}

impl Ran {
    /// Whether it exited zero.
    #[must_use]
    pub fn passed(&self) -> bool {
        self.outcome == Outcome::Passed
    }
}

/// The unified patch `cargo mutants --in-diff` reads: each changed source's
/// bytes at `base` against its working bytes, written in process (CLOUD-2255).
///
/// It was `git diff <base> -- <sources>`, spawned, on the reason that `gix`
/// writes no unified patch; [`crate::git::unified_hunks`] does, in process, and
/// [`crate::git::read_at`] reads the base blob with no argv. A source absent
/// at `base` diffs from empty, a deleted one to empty, as `git diff` shows them.
///
/// # Errors
///
/// When `root` is not a repository this binary can open, or `base` resolves to
/// something that is not a tree.
pub fn in_diff_patch(root: &Path, base: &str, sources: &[String]) -> Result<String> {
    use std::fmt::Write as _;
    let mut patch = String::new();
    for source in sources {
        let before = match crate::git::read_at(root, base, source)? {
            crate::git::BaseBlob::Found { text, .. } => text,
            _ => String::new(),
        };
        let after = crate::fsio::read_to_string(root.join(source)).unwrap_or_default();
        if before == after {
            continue;
        }
        let _ = writeln!(patch, "--- a/{source}\n+++ b/{source}");
        patch.push_str(&crate::git::unified_hunks(&before, &after)?);
    }
    Ok(patch)
}

/// The programs this module runs, CLOSED (CLOUD-1924).
///
/// `spawn` took the program as a free string, so its one `#[expect]` covered
/// whatever a caller named while its reason named none of them — the per-site
/// ban laundered through a parameter. A variant per program means the reason
/// below can say, for each, why no in-process route exists, and a new program is
/// a new variant a reviewer reads rather than a string nobody does.
#[derive(Clone, Copy)]
enum Program<'a> {
    /// Builds the staged tree's test binaries once before any row is timed
    /// (CLOUD-1910). There is no in-process compiler.
    Cargo,
    /// The consumer's declared suite runner, re-run against the mutant: the verb.
    Suite(&'a str),
    /// The consumer's own mutation tool, `[mutate] command`'s first element
    /// (CLOUD-2211): committed in the reviewed authority, like a suite runner.
    Command(&'a str),
    /// One test binary nextest handed the schema's reach recorder
    /// ([`schema`]): the case under measurement, which no in-process route
    /// can run.
    Test(&'a str),
}

impl Program<'_> {
    const fn name(&self) -> &str {
        match self {
            Program::Cargo => "cargo",
            Program::Suite(program) | Program::Command(program) | Program::Test(program) => program,
        }
    }
}

/// Run a program to completion in `dir`, capturing what it said.
fn spawn(
    dir: &Path,
    program: Program<'_>,
    args: &[String],
    env: &[(String, String)],
    // The bound is the CALLER'S, so this function has no opinion about how long
    // its child should take (CLOUD-1860). Passing the duration rather than the
    // `Suite` keeps `spawn` a process primitive: it is also what the two suite
    // arms already differ by, and threading the suite here would put a second
    // reader of that distinction one level below the one that owns it.
    bound: std::time::Duration,
) -> Result<Ran> {
    spawn_as(dir, program, args, env, bound, Said::Captured)
}

/// Where a spawned program's output goes.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Said {
    /// Into [`Ran::output`], read once it has exited.
    Captured,
    /// Straight to this process's stderr, as it is written, for a runner whose
    /// verdict is a file it writes (cargo-mutants' `mutants.out`): measured on
    /// #1132, capturing it left fifteen shards' logs silent for 111 minutes and
    /// lost every mutant they judged when their bound stopped them.
    Streamed,
}

fn spawn_as(
    dir: &Path,
    program: Program<'_>,
    args: &[String],
    env: &[(String, String)],
    bound: std::time::Duration,
    said: Said,
) -> Result<Ran> {
    let program = program.name();
    #[expect(
        clippy::disallowed_types,
        reason = "stays: staging a tree and re-running a suite against it IS this module's effect (CLOUD-1267), and `Program` is the closed set it may run — cargo documents on its variant why no in-process route exists, and a suite or command is the consumer's declared runner (CLOUD-1924, CLOUD-2255)"
    )]
    let mut command = std::process::Command::new(program);
    command.args(args).current_dir(dir);
    for key in scrubbed(
        std::env::vars_os().filter_map(|(key, _)| key.into_string().ok()),
        env,
    ) {
        command.env_remove(key);
    }
    for (key, value) in env {
        command.env(key, value);
    }
    // A suite reads stdin, and the sweep's own declarations used to be on it —
    // measured on `claimed-keys`, where each invocation SWALLOWED the rows after
    // the one it was running, three declared rows reached two, and the sweep
    // reported "every one caught". Nothing here feeds a suite from stdin, and
    // closing it is what keeps that true if anything ever does.
    command.stdin(std::process::Stdio::null());
    // OUR OWN WATCHDOG, BECAUSE THE RUNNER'S CHARGES FOR EVERY RED CASE
    // (CLOUD-1726, and this closes the question that row left open).
    //
    // The earlier reading blamed `.output()` reading two pipes to EOF while
    // bats' watchdog subshell still held them. That is wrong, and the
    // measurement that settles it does not involve this process at all — bats
    // invoked straight from a shell, output to `/dev/null`, stdin closed, the
    // same lent runner and the same `run` helper:
    //
    // | case | bound 3 | bound 6 |
    // | ---- | ------- | ------- |
    // | passing | 0.086s | 0.084s |
    // | FAILING | 3.086s | 6.092s |
    //
    // The discriminator is the case's VERDICT, not the capture. `bats-exec-test`
    // aborts its countdown on a normal finish and does not on a failing one, so
    // the bound is paid in full by exactly the outcome a mutation sweep exists
    // to produce: a caught mutation IS a red case. Every row this sweep gets
    // right was buying the whole watchdog, which is why the cost read as linear
    // in the bound and why unsetting it looked like a fix.
    //
    // So the bound moves here and `BATS_TEST_TIMEOUT` goes. The requirement is
    // unchanged and is the reason a bound has to exist at all — a mutant that
    // hangs is precisely what a sweep must survive — but a watchdog that only
    // fires on a hang costs nothing on the rows that pass.
    //
    // ITS OWN GROUP, ENDED WHOLE — see `wait_bounded`, which records why the
    // direct child alone left every hung suite's test binary alive under init.
    //
    // FILES RATHER THAN PIPES, because nothing reads them until the child is
    // gone. A pipe holds 64 KiB and then blocks its writer, so a chatty failure
    // would deadlock against a reader that is waiting for the exit — the one
    // hazard `.output()` avoided by reading both pipes concurrently. A file has
    // no such bound, and the watchdog above is what makes waiting-then-reading
    // safe rather than merely tidy.
    let capture = std::env::temp_dir().join(format!(
        "batten-mutate-{}-{}",
        std::process::id(),
        CAPTURE.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    fs::create_dir_all(&capture).with_context(|| {
        format!(
            "mutate: could not create the capture directory {}",
            capture.display()
        )
    })?;
    let out_path = capture.join("stdout");
    let err_path = capture.join("stderr");
    if said == Said::Streamed {
        command.stdout(std::process::Stdio::from(std::io::stderr()));
        command.stderr(std::process::Stdio::from(std::io::stderr()));
    } else {
        command.stdout(std::process::Stdio::from(
            fs::File::create(&out_path) // stream: a child's stdout sink
                .with_context(|| format!("mutate: could not open {}", out_path.display()))?,
        ));
        command.stderr(std::process::Stdio::from(
            fs::File::create(&err_path) // stream: a child's stderr sink
                .with_context(|| format!("mutate: could not open {}", err_path.display()))?,
        ));
    }
    // A GROUP OF ITS OWN, AND THE SWEEP FORWARDS WHAT IT IS SENT. Leading a group
    // is what lets the teardown reach the suite's grandchildren; it also takes the
    // suite out of the group an outer runner signals — nextest's terminate, a
    // ^C, mise's cancel — so the forwarder is armed BEFORE the spawn, for
    // `exec::Forwarding::arm`'s stated reason, and hands those signals on.
    crate::exec::lead_group(&mut command);
    let forwarding = crate::exec::Forwarding::arm(crate::exec::GroupDecision::OWNED)?;
    let child = command
        .spawn()
        .with_context(|| format!("mutate: could not run {program}"))?;
    forwarding.adopt(child.id())?;
    let waited = wait_bounded(child, bound);
    // A signal outranks the row: the sweep was asked to stop, so it stops, with
    // the signal's own status rather than a verdict on a suite it interrupted.
    let forwarded = forwarding.finish();
    // Only unix forwards, so only unix has a signal to re-raise; elsewhere
    // `finish` answers `None` and there is nothing to do.
    #[cfg(unix)]
    if let Some(signal) = forwarded {
        reraise(signal)?;
    }
    #[cfg(not(unix))]
    let _ = forwarded;
    let (status, timed_out) =
        waited.with_context(|| format!("mutate: could not wait for {program}"))?;
    // The ONE place a `Ran` may say `TimedOut`: `finish` describes a child that
    // reached its own exit, and only the bound expiring here makes that untrue.
    let ran = finish(status, &out_path, &err_path, &capture);
    Ok(if timed_out {
        Ran {
            outcome: Outcome::TimedOut,
            ..ran
        }
    } else {
        ran
    })
}

/// Wait for `child` until `bound`, end its whole process group, then reap it,
/// answering its status and whether the bound ran out (CLOUD-1860, CLOUD-2059).
///
/// A BLOCKING WAIT WITH A DEADLINE, NOT A POLL. `std::thread::sleep` is a denied
/// method here (`clippy.toml`), and this wait has a terminal state to block on:
/// a worker blocks on the child's exit, the receive carries the bound, and a
/// suite that returns wakes this immediately.
///
/// **KILL THE GROUP, THEN REAP THE LEADER, IN THAT ORDER.** The worker waits with
/// `WNOWAIT`, which reports the exit without reaping, so the leader stays an
/// unreaped zombie and its pid — which IS the group id — cannot be reused while
/// the group is signalled. Then the group is killed whatever happened: on a hang
/// that ends the suite; on a normal exit it ends whatever the suite left running.
/// Only then is the leader reaped.
///
/// The earlier contract killed the direct child alone, reasoning that a group
/// that failed to form would make `kill(-pid)` land on the sweep's own siblings.
/// Neither half held: `std` reports a failed `setpgid` as a failed spawn, and a
/// pid that leads no group answers `ESRCH`. What it cost was measured: every hung
/// cargo suite left its test binary — which a mutant can make loop forever —
/// alive under init, two of them found 35 and 56 minutes after their runs.
#[cfg(unix)]
fn wait_bounded(
    mut child: std::process::Child,
    bound: std::time::Duration,
) -> std::io::Result<(std::process::ExitStatus, bool)> {
    let pid = child.id();
    let (send, exits) = std::sync::mpsc::channel();
    let worker = std::thread::spawn(move || {
        // The receiver is gone only when the bound already ran out and the
        // caller stopped listening; the group kill below is what ends this wait.
        let _ = send.send(await_exit(pid));
    });
    let timed_out = match exits.recv_timeout(bound) {
        Ok(Ok(())) => false,
        Ok(Err(failed)) => {
            // The wait itself failed, so whether the suite exited is unknown.
            // It is ended rather than left running, and the failure is the answer.
            kill_group(pid);
            // No sweep: with these flags and a valid pid `waitid` fails only with
            // `ECHILD`, the leader reaped elsewhere, which frees the id a repeat
            // would signal. The one kill above is CLOUD-2525's.
            let _ = worker.join();
            let _ = child.wait();
            return Err(failed);
        }
        Err(_) => true,
    };
    if timed_out {
        // A RUNNER THAT LEADS ITS OWN GROUPS IS ASKED FIRST. nextest starts each
        // test in a process group of its own, so a `SIGKILL` to the runner's
        // group leaves a hung test binary, and whatever it spawned, alive under
        // init (measured 2026-10-16 once the declared Cargo arm moved onto
        // nextest). `SIGTERM` is what nextest answers by ending every group it
        // started. The grace is bounded, and the `SIGKILL` below still follows.
        terminate_group(pid);
        let _ = exits.recv_timeout(TERMINATE_GRACE);
    }
    kill_group(pid);
    sweep_group(pid);
    let _ = worker.join();
    let status = child.wait()?;
    Ok((status, timed_out))
}

/// How many more `SIGKILL`s [`sweep_group`] sends before it stops asking.
#[cfg(unix)]
const SWEEPS: usize = 1024;

/// [`sweep_group`] where there are no process groups.
#[cfg(all(not(unix), test))]
fn sweep_group(_leader: u32) {}

/// Kill `leader`'s group again, [`SWEEPS`] times with a yield between, after
/// [`kill_group`] and BEFORE the leader is reaped.
///
/// **DARWIN'S FORK DOES NOT RESTART UNDER A GROUP SIGNAL** (CLOUD-2514). Linux
/// restarts a `fork` that races a signal to the parent's group, so the child is
/// either never made or signalled with it; Darwin lets the child join the group
/// unsignalled. Measured on the `macos` runner: the group kill ended a suite's
/// background subshell while it was forking `sleep`, and the `sleep` lived on in
/// the leader's group, reparented to init, holding what the suite held.
///
/// **BEFORE THE REAP, FOR [`wait_bounded`]'S OWN REASON.** The leader is still an
/// unreaped zombie, so its pid — which IS the group id — cannot be reused while
/// the sweep signals it, and every `SIGKILL` reaches this suite's group or
/// nobody. The zombie also keeps the group answering, so the sweep runs its full
/// count rather than stopping at the first `ESRCH`: a bounded cost of microseconds
/// per suite, against a build per mutant.
#[cfg(unix)]
fn sweep_group(leader: u32) {
    let Some(group) = rustix::process::Pid::from_raw(i32::try_from(leader).unwrap_or_default())
    else {
        return;
    };
    for _ in 0..SWEEPS {
        let Ok(()) = rustix::process::kill_process_group(group, rustix::process::Signal::KILL)
        else {
            return;
        };
        std::thread::yield_now();
    }
}

/// How long a timed-out runner has to end what it started before `SIGKILL`.
#[cfg(unix)]
const TERMINATE_GRACE: std::time::Duration = std::time::Duration::from_secs(15);

/// `SIGTERM` the process group `leader` leads, through [`crate::exec::signal_group`].
/// Best effort, as [`kill_group`].
#[cfg(unix)]
fn terminate_group(leader: u32) {
    if let Some(group) = rustix::process::Pid::from_raw(i32::try_from(leader).unwrap_or_default()) {
        crate::exec::signal_group(group, rustix::process::Signal::TERM);
    }
}

/// [`wait_bounded`] off unix, as it was: no `waitid`, no group, and no `kill(2)`
/// to reach for, so a hung suite there is waited out rather than ended.
#[cfg(not(unix))]
fn wait_bounded(
    mut child: std::process::Child,
    bound: std::time::Duration,
) -> std::io::Result<(std::process::ExitStatus, bool)> {
    let (send, statuses) = std::sync::mpsc::channel();
    let worker = std::thread::spawn(move || {
        let _ = send.send(child.wait());
    });
    let (status, timed_out) = match statuses.recv_timeout(bound) {
        Ok(status) => (status?, false),
        Err(_) => (
            statuses
                .recv()
                .map_err(|_| std::io::Error::other("mutate: the wait for the suite was lost"))??,
            true,
        ),
    };
    let _ = worker.join();
    Ok((status, timed_out))
}

/// Block until `pid` has exited, WITHOUT reaping it (`WNOWAIT`), so its pid and
/// its group id stay reserved until [`wait_bounded`] has signalled the group.
#[cfg(unix)]
fn await_exit(pid: u32) -> std::io::Result<()> {
    let pid = rustix::process::Pid::from_raw(i32::try_from(pid).unwrap_or_default())
        .ok_or_else(|| std::io::Error::other("mutate: the suite reported an unusable pid"))?;
    loop {
        match rustix::process::waitid(
            rustix::process::WaitId::Pid(pid),
            rustix::process::WaitIdOptions::EXITED | rustix::process::WaitIdOptions::NOWAIT,
        ) {
            Ok(_) => return Ok(()),
            // A forwarded signal can interrupt the wait; the child is still the
            // child, so the wait resumes.
            Err(rustix::io::Errno::INTR) => {}
            Err(errno) => return Err(errno.into()),
        }
    }
}

/// Re-raise the signal the sweep was sent, after its suite group is gone.
#[cfg(unix)]
fn reraise(signal: i32) -> Result<()> {
    // The one re-raise, so registered terminate work runs here too. It restores
    // the default disposition and raises on self, so this does not return.
    crate::exec::terminate(signal).context("mutate: re-raise the signal the sweep was sent")
}

/// Read back what the child wrote and drop the capture.
///
/// One place, because both the ordinary exit and the hang path answer with the
/// same shape and a second copy is how the two drift apart.
fn finish(
    status: std::process::ExitStatus,
    out_path: &Path,
    err_path: &Path,
    capture: &Path,
) -> Ran {
    let stdout = crate::fsio::read_to_string(out_path).unwrap_or_default();
    let mut output = stdout.clone();
    output.push_str(&crate::fsio::read_to_string(err_path).unwrap_or_default());
    // Best effort: a capture left behind is a few bytes under the system temp
    // directory, and failing a sweep over housekeeping would trade a real
    // verdict for tidiness.
    let _ = fs::remove_dir_all(capture);
    // The ordinary path. The hang path above overrides it, and it is the ONE
    // caller that may: a `Ran` built anywhere else describes a child that
    // reached its own exit.
    let outcome = if status.success() {
        Outcome::Passed
    } else {
        Outcome::Failed(status.code())
    };
    Ran {
        outcome,
        output,
        stdout,
    }
}

/// Distinguishes concurrent captures within one process; the pid separates
/// processes. A counter rather than a random name, so a leftover directory names
/// the call that made it.
static CAPTURE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// How long a suite may run before the sweep stops waiting for it.
///
/// **PER SUITE KIND, AND THE SPLIT IS THE FIX (CLOUD-1860).** One number served
/// both, justified as *"one filtered case over a staged toy tree rather than a
/// repository's whole suite"*. That is true of bats and false of cargo, and it
/// was never revisited when CLOUD-1267 introduced Rust suites — so **every** one
/// of them was killed mid-build and reported as a filter that matched nothing.
/// Measured: 109 of 341 declared mutations, the whole Rust half of CLOUD-418's
/// mechanism, reading as enforced coverage while looking at nothing.
///
/// * **The native harnesses get 120s** (CLOUD-2160): each runs one file's cases
///   and has no build step, so the bound covers interpreter or plugin start-up
///   and the cases, never a compile.
/// * **Cargo gets a bound that admits a build**, because it cannot avoid one. The
///   sweep's `CARGO_TARGET_DIR` is isolated by construction (CLOUD-1315), so the
///   first row pays a cold workspace build — measured at 414s here and at 21
///   minutes on a smaller container (CLOUD-1603) — and every later row pays a
///   recompile of whatever the mutation touched. The case itself then runs in
///   0.00s, so this number is bounding compilation and nothing else.
///
/// Overridable by one env var for both, because a consumer whose suite is
/// genuinely slower needs a way up that is not editing the engine; the name is
/// batten's own so it cannot collide with a namespace any runner owns.
/// An explicit override applies to whichever kind is running — a reader setting
/// it is answering for their own tree, not for this split.
/// The bound for the sweep's own housekeeping (probing a runner, writing the
/// change's patch), which is not a suite and must not borrow one's number
/// (CLOUD-1860).
///
/// Named rather than inlined because the alternative is a bare `30` beside two
/// calls that have nothing to do with a test runner, which is how the suite
/// bound came to cover a case it was never measured against. These are local
/// file operations over an already-staged tree; a minute is generous and a hang
/// here is a real defect rather than a slow build.
const HOUSEKEEPING_BOUND: std::time::Duration = std::time::Duration::from_secs(60);

fn suite_bound(suite: &Suite) -> std::time::Duration {
    let declared = match suite {
        Suite::Cargo { .. } => 900,
        Suite::Tofu { .. }
        | Suite::Kyverno { .. }
        | Suite::Conftest { .. }
        | Suite::Pytest { .. } => 120,
    };
    std::time::Duration::from_secs(
        std::env::var("BATTEN_MUTATE_SUITE_TIMEOUT")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .filter(|seconds| *seconds > 0)
            .unwrap_or(declared),
    )
}

/// How long the one staged BUILD may take, before any row runs (CLOUD-1910).
///
/// **The per-case bound was paying for the compile.** A Cargo suite's first
/// filtered run built the whole staged tree inside [`suite_bound`]'s 30 seconds,
/// so any change touching engine source made row one exceed it: the run was
/// killed before libtest printed a summary, and every later row passed on the
/// warm cache. Measured twice on one branch, first as `names-no-case` on every
/// row, then as `suite-did-not-run` on the first row alone. The build is paid
/// once, here, under a bound sized for a build rather than for one case.
fn build_bound() -> std::time::Duration {
    std::time::Duration::from_secs(
        std::env::var("BATTEN_MUTATE_BUILD_TIMEOUT")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .filter(|seconds| *seconds > 0)
            .unwrap_or(1800),
    )
}

/// `SIGKILL` the process group `leader` leads, and the leader itself.
///
/// No grace of its own. Where the runner TIMED OUT, [`wait_bounded`] first gives
/// it one bounded `SIGTERM` ([`TERMINATE_GRACE`]), for a runner that leads groups
/// of its own; on its other paths this is the only signal. The leader is
/// signalled as well so that a group that somehow did not
/// form still ends its direct child — a leak the descendant case would report,
/// never a hang. Best effort, because `ESRCH` means the process is already gone,
/// which is the outcome being asked for.
#[cfg(unix)]
fn kill_group(leader: u32) {
    if let Some(group) = rustix::process::Pid::from_raw(i32::try_from(leader).unwrap_or_default()) {
        let _ = rustix::process::kill_process_group(group, rustix::process::Signal::KILL);
        let _ = rustix::process::kill_process(group, rustix::process::Signal::KILL);
    }
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
/// the mutated copy's `policy.rs` under `target/mutate/`, and evaluated an engine that
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
        // NO DEBUG INFO FOR THE CRATE UNDER MUTATION (CLOUD-1746). Measured:
        // one mutant's `--lib --test=it` rebuild is 25.5s at `debug = 1` and
        // 22.3s at `0`, and nothing reads a mutant's debug info. Set here, for
        // every runner over this one target directory: on cargo-mutants alone
        // it flipped the profile under the declared sweep's builds, and each
        // flip rebuilt the workspace crates.
        (String::from("CARGO_PROFILE_TEST_DEBUG"), String::from("0")),
        // THE PROFILE EVERY NEXTEST CONFIG HAS, for both runners that run
        // nextest (the declared Cargo arm and cargo-mutants). An inherited
        // `NEXTEST_PROFILE` (this repository's `[env]` set `ci` under CI until
        // CLOUD-2588; a consumer's still may) names a profile the staged tree
        // may not declare, a fixture's or a consumer's, and nextest then exits
        // before selecting a case, which is how every declared Cargo row once
        // read `suite-did-not-run` in CI alone. A profile
        // the staged tree DOES declare is kept by [`nextest_env`], for its
        // setup scripts; its verdict settings are overridden by
        // [`NEXTEST_VERDICT_FLAGS`] (CLOUD-2466 item 9).
        (String::from("NEXTEST_PROFILE"), String::from("default")),
    ]
}

/// Where a consumer's suite reads a mutated source from instead of the staged
/// tree, declared by three variables together (CLOUD-2253):
///
/// - `MUTANT_PRESETS` ([`presets_dir`]): a module under it is mutated in a copy
///   under [`Overlay::dir`], and the staged tree keeps the original;
/// - `MUTANT_OVERLAY_ENV`: the variable that names [`Overlay::dir`] to the suite;
/// - `MUTANT_OVERLAY_FEATURES`: the cargo features a suite is built with so it
///   reads that copy.
///
/// FOR A SOURCE A BUILD EMBEDS. A file the crate `include_str!`s is a build
/// input, so mutating it in the staged tree recompiled the crate twice per row
/// (the mutation, then its restore): measured on #1276, ~41 s a row, nearly all
/// build. The overlay leaves the build's inputs untouched, so the suite built
/// once runs every row, against exactly the mutated bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Overlay {
    root: String,
    env: String,
    features: String,
    dir: PathBuf,
}

impl Overlay {
    /// The overlay the environment declares for the tree at `root`, or `None`
    /// where any of the three variables is unset or blank.
    #[must_use]
    pub fn declared(root: &Path) -> Option<Self> {
        Self::declared_by(root, overlay_var)
    }

    /// [`Overlay::declared`] over the variables `var` answers: each trimmed of
    /// space and a trailing `/`, and a blank one unset.
    fn declared_by(root: &Path, var: impl Fn(&str) -> Option<String>) -> Option<Self> {
        let read = |name: &str| {
            var(name)
                .map(|value| value.trim().trim_end_matches('/').to_owned())
                .filter(|value| !value.is_empty())
        };
        Some(Self {
            root: read("MUTANT_PRESETS")?,
            env: read("MUTANT_OVERLAY_ENV")?,
            features: read("MUTANT_OVERLAY_FEATURES")?,
            dir: target_dir(root).join("mutate-overlay"),
        })
    }

    /// The `--features` a cargo invocation carries for this overlay.
    fn feature_args(&self) -> Vec<String> {
        vec![String::from("--features"), self.features.clone()]
    }

    /// Where the mutated copy of `source` is written, or `None` for a source
    /// outside [`Overlay::root`], which is mutated in place.
    #[must_use]
    pub fn path_of(&self, source: &str) -> Option<PathBuf> {
        source
            .strip_prefix(&self.root)
            .and_then(|rest| rest.strip_prefix('/'))
            .filter(|rest| !rest.is_empty())
            .map(|rest| self.dir.join(rest))
    }
}

#[cfg(test)]
thread_local! {
    /// The variables [`with_overlay_vars`] scoped to this thread.
    static OVERLAY_VARS: std::cell::RefCell<Option<Vec<(&'static str, &'static str)>>> =
        const { std::cell::RefCell::new(None) };
}

/// Run `body` with [`Overlay::declared`] answered from `vars` on this thread,
/// as the environment would answer it: THE ENVIRONMENT'S OWN SEAM, REACHABLE
/// IN PROCESS, because this crate forbids the `unsafe` `set_var` needs (the
/// pattern of `rest::with_fixture`). The previous scope is restored on the way
/// out, unwinding included.
#[cfg(test)]
fn with_overlay_vars<T>(vars: &[(&'static str, &'static str)], body: impl FnOnce() -> T) -> T {
    /// Puts the scope it replaced back when dropped.
    struct Restore(Option<Vec<(&'static str, &'static str)>>);
    impl Drop for Restore {
        fn drop(&mut self) {
            OVERLAY_VARS.with(|scoped| scoped.replace(self.0.take()));
        }
    }
    let _restore = Restore(OVERLAY_VARS.with(|scoped| scoped.replace(Some(vars.to_vec()))));
    body()
}

/// One overlay variable: the thread's scoped set where a test declared one,
/// else the environment.
fn overlay_var(name: &str) -> Option<String> {
    #[cfg(test)]
    if let Some(vars) = OVERLAY_VARS.with(|scoped| scoped.borrow().clone()) {
        return vars
            .iter()
            .find(|(key, _)| *key == name)
            .map(|(_, value)| (*value).to_owned());
    }
    std::env::var(name).ok()
}

/// The `--features` every cargo invocation of a sweep carries, so the build it
/// pays once is the one every row runs.
fn overlay_features(root: &Path) -> Vec<String> {
    Overlay::declared(root)
        .as_ref()
        .map_or_else(Vec::new, Overlay::feature_args)
}

/// The environment a nextest run in `staged` carries: [`suite_env`], with the
/// inherited `NEXTEST_PROFILE` kept where `staged` declares that profile
/// ([`declared_profile`]).
///
/// [`spawn_as`] scrubs every OTHER inherited `NEXTEST_*` variable from a child
/// this env reaches, because it names nextest's profile ([`scrubbed`]).
fn nextest_env(root: &Path, staged: &Path) -> Vec<(String, String)> {
    let mut env = suite_env(root);
    if let Some(overlay) = Overlay::declared(root) {
        env.push((overlay.env, overlay.dir.to_string_lossy().into_owned()));
    }
    if let Some(profile) = declared_profile(staged, std::env::var("NEXTEST_PROFILE").ok())
        && let Some((_, value)) = env.iter_mut().find(|(key, _)| key == "NEXTEST_PROFILE")
    {
        *value = profile;
    }
    env
}

/// `profile` where `staged`'s `.config/nextest.toml` declares `[profile.<it>]`,
/// else `None`: an undeclared profile stops nextest before it selects a case.
///
/// READ FROM THE STAGED COPY, never the live tree, which is what the reverted
/// 035fd4ea variant got wrong: the staged tree is the one nextest runs in.
fn declared_profile(staged: &Path, profile: Option<String>) -> Option<String> {
    let profile = profile.filter(|name| !name.trim().is_empty())?;
    let text = crate::fsio::read_to_string(staged.join(".config/nextest.toml")).ok()?;
    let config: toml::Table = text.parse().ok()?;
    config
        .get("profile")
        .and_then(toml::Value::as_table)
        .is_some_and(|profiles| profiles.contains_key(&profile))
        .then_some(profile)
}

/// The inherited variables to remove from a child whose `env` names nextest's
/// profile: every `NEXTEST_*` the env does not set itself (CLOUD-2466 item 9).
/// `NEXTEST_RETRIES`, `NEXTEST_STATUS_LEVEL` and the rest otherwise reach the
/// run, and a verdict with them. Nothing, for an env that names no profile.
fn scrubbed(inherited: impl IntoIterator<Item = String>, env: &[(String, String)]) -> Vec<String> {
    if !env.iter().any(|(key, _)| key == "NEXTEST_PROFILE") {
        return Vec::new();
    }
    inherited
        .into_iter()
        .filter(|key| key.starts_with("NEXTEST_") && !env.iter().any(|(set, _)| set == key))
        .collect()
}

/// How far a run got, in the order `judge_row` must read it — every state but
/// `Reported` is a could-not-look, and each names a different cause.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
enum Reach {
    /// The runner printed no summary, so it never ran the suite (CLOUD-1910).
    #[default]
    Silent,
    /// The runner reported its cases; `selected` and `ok` are readable.
    Reported,
    /// The harness reported the named case ERRORED, or emitted an error and no
    /// line for any case at all (CLOUD-2160). Above `Silent` and `Reported`: a
    /// run that could not load its subject selects nothing and may print no
    /// summary, so read later it would be blamed on the filter or the runner —
    /// and read as a status, it would be a kill.
    Errored,
    /// Killed at its bound rather than reaching an exit (CLOUD-1860). Above all
    /// of them, because a killed run selects nothing and that is a fact about
    /// the clock, never about the filter.
    TimedOut,
}

impl Reach {
    /// The reach a reader's two observations give: errored outranks ran.
    const fn of(ran: bool, errored: bool) -> Self {
        match (errored, ran) {
            (true, _) => Reach::Errored,
            (false, true) => Reach::Reported,
            (false, false) => Reach::Silent,
        }
    }
}

/// How many cases the run selected, whether it passed, and how far it got.
#[derive(Debug, Default, PartialEq, Eq)]
struct Selection {
    selected: usize,
    ok: bool,
    reach: Reach,
}

/// Run a gate's suite filtered to `want`, inside the staged tree.
/// Run one declared [`crate::arm::Arm`], which is the harness's unit of work
/// (CLOUD-1714).
///
/// The adapter is one line of destructuring because `spawn` already takes
/// exactly what an arm carries: an arm's `argv` is program-then-arguments, and
/// splitting it here is what keeps the declaration a table rather than four
/// positional parameters at every call site. An arm with an EMPTY argv names no
/// program, which is a could-not-look rather than a run of nothing.
/// **THE BOUND IS THE CALLER'S AND TRAVELS BESIDE THE ARM, not inside it.**
///
/// Two changes met here: CLOUD-1714 made this module an INSTANCE of the declared
/// arm harness, and CLOUD-1860 bounded a suite by what it must do so a timeout is
/// never read as a filter fault. Both are kept.
///
/// The duration is a parameter rather than an `Arm` field, which is the same
/// division `spawn`'s own header states one level down: how long a child may take
/// is the CALLER's question, and `arm::Arm` describes what to run — where, what,
/// and under which environment — for every instance of the harness. Putting one
/// instance's clock into the shared type would make the generic harness carry a
/// concern only `mutate` has, which is the drift the extraction removed.
fn spawn_arm(
    arm: &crate::arm::Arm,
    env: &[(String, String)],
    bound: std::time::Duration,
) -> Result<Ran> {
    let (program, args) = arm
        .argv
        .split_first()
        .ok_or_else(|| anyhow::anyhow!("mutate: arm {} names no program.", arm.id))?;
    spawn(&arm.cwd, Program::Suite(program), args, env, bound)
}

/// Run a gate's suite against the staged tree, filtered to `want` where its
/// harness can filter, and read the named case's own verdict back.
///
/// **A RUNNER THAT WILL NOT SPAWN IS THIS ROW'S `suite-did-not-run`, NOT THE
/// SWEEP'S ABORT** (CLOUD-2160). The native harnesses come from the `PATH` the
/// invoking task provides, exactly as `sed` and `cargo` do, so one missing
/// program used to end the whole sweep with an error naming nothing about the
/// gates it never reached.
fn run_suite(
    staged: &Staged,
    root: &Path,
    suite: &Suite,
    row: &Row,
    prebuilt: Option<&Prebuilt>,
) -> Selection {
    let want = row.want.as_str();
    let dir = staged.dir();
    let cargo = matches!(suite, Suite::Cargo { .. });
    // No recorded build means the one build failed: nothing to run against, and
    // a rebuild here is the per-row cost [`Prebuilt`] exists to rule out.
    if cargo && prebuilt.is_none() {
        return Selection::default();
    }
    // The recorded binaries, unless they embed this row's subject outside the
    // overlay — then only a rebuild sees the mutation ([`Prebuilt`]).
    let overlaid = Overlay::declared(root).is_some_and(|o| o.path_of(&row.source).is_some());
    let reuse = prebuilt.filter(|built| cargo && (overlaid || !built.embeds(&row.source)));
    let env = nextest_env(root, dir);
    // Where a `JUnit` report lands for the one arm whose verdict is a file
    // rather than a stream. Beside the captures, never inside the tree under
    // judgement.
    let junit = std::env::temp_dir().join(format!(
        "batten-mutate-junit-{}-{}.xml",
        std::process::id(),
        CAPTURE.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    let _ = fs::remove_file(&junit);
    if cargo && reuse.is_none() {
        // AN EMBEDDED SUBJECT ONLY: BUILT UNDER THE BUILD BOUND FIRST, THEN TIMED
        // (review of #962). A mutated embedded source must be recompiled, and
        // paying that inside the per-case bound is how a slow compile reads as
        // `suite-did-not-run`. A build that fails here is left for the timed run
        // to report.
        let mut build = vec![String::from("test"), String::from("--no-run")];
        build.extend(overlay_features(root));
        let _ = spawn(dir, Program::Cargo, &build, &env, build_bound());
    }
    if let Suite::Tofu { path } = suite {
        // INITIALISED UNDER THE BUILD BOUND FIRST, THEN TIMED (CLOUD-2190). The
        // staged tree carries tracked files only, and `.terraform/` never is, so
        // a module calling a module or needing a provider errored `Module not
        // installed` on every row — could-not-look over a whole consumer.
        // `-backend=false` because `tofu test` never reads the backend, and a
        // remote one would ask for credentials. The staged tree persists, so
        // later inits find `.terraform/` in place. A failed init is left for the
        // timed run to report.
        let module = dir.join(tofu_module(path).0);
        let init = ["init", "-backend=false", "-input=false", "-no-color"].map(String::from);
        let _ = spawn(&module, Program::Suite("tofu"), &init, &env, build_bound());
    }
    let (cwd, mut argv) = invocation(dir, suite, want, &junit);
    if let Some(built) = reuse {
        argv.extend(built.reuse_args());
    } else if cargo {
        argv.extend(overlay_features(root));
    }
    // DECLARED AS AN ARM (CLOUD-1714), which is what makes this module an
    // INSTANCE of the harness rather than a second copy of it. The arm carries
    // what it takes to run the thing once — where, what, and under which
    // environment — and `arm::Outcome` carries the distinction the
    // `selected == 0` reading already draws: a suite that selected no case has
    // not passed, it has not been looked at.
    let arm = crate::arm::Arm {
        id: format!("{}:{want}", argv.first().map_or("", String::as_str)),
        cwd,
        argv,
        stdin: None,
        env: env.iter().cloned().collect(),
    };
    let Ok(ran) = spawn_arm(&arm, &env, suite_bound(suite)) else {
        return Selection::default();
    };
    let selection = match suite {
        Suite::Cargo { .. } => Selection {
            selected: libtest_lines(&ran.output) + nextest_lines(&ran.output),
            ok: ran.passed() && !ran.output.contains("error: could not compile"),
            reach: Reach::of(libtest_ran(&ran.output) || nextest_ran(&ran.output), false),
        },
        Suite::Tofu { .. } => tofu_verdict(&ran.output, want),
        Suite::Kyverno { .. } => kyverno_verdict(&ran.output, want),
        Suite::Conftest { path } => {
            conftest_verdict(&ran.output, want, &lines_of(dir, path).unwrap_or_default())
        }
        Suite::Pytest { .. } => {
            pytest_verdict(&crate::fsio::read_to_string(&junit).unwrap_or_default())
        }
    };
    let _ = fs::remove_file(&junit);
    if ran.outcome == Outcome::TimedOut {
        if let Some(stopped) = stopped_at(&ran.output) {
            use std::io::Write as _;
            let _ = writeln!(
                std::io::stderr(),
                "mutate sweep: {want} timed out at `{stopped}`"
            );
        }
        return Selection {
            reach: Reach::TimedOut,
            ..selection
        };
    }
    selection
}

/// The words cargo and nextest open a status line with.
const STATUS_WORDS: &[&str] = &[
    "Compiling",
    "Blocking",
    "Finished",
    "Running",
    "Starting",
    "SETUP",
    "START",
    "SLOW",
    "PASS",
    "FAIL",
    "TIMEOUT",
    "LEAK",
];

/// Where a suite killed at its bound had got to: the first five words of a
/// status line cargo or nextest printed, so `Compiling <crate>`, `SETUP` or
/// `SLOW [> Ns] <case>` (CLOUD-2206). A POINTER, NEVER THE OUTPUT: a timeout
/// used to say only `suite-timed-out`, measured on #1258 where one CI shard's
/// first row hit 900s while the same case ran in 0.5s locally, and nothing told
/// a cold compile from a hung case.
///
/// A STUCK CASE OUTRANKS A LATER LINE: nextest runs cases in parallel, so the
/// `PASS` of a sibling can follow the `SLOW` of the case that hung. A case is
/// stuck where nextest killed it (`TIMEOUT`), or where it was marked `SLOW`
/// and never finished after. With none, the last status line says where the
/// run was.
fn stopped_at(output: &str) -> Option<String> {
    let lines: Vec<Vec<&str>> = output
        .lines()
        .map(|line| line.split_whitespace().collect())
        .collect();
    let mut finished = std::collections::HashSet::new();
    for words in lines.iter().rev() {
        match words.first().copied() {
            Some("PASS" | "FAIL" | "LEAK") => {
                finished.insert(case_of(words));
            }
            Some("TIMEOUT") => return Some(pointer(words)),
            Some("SLOW") if !finished.contains(&case_of(words)) => return Some(pointer(words)),
            _ => {}
        }
    }
    lines
        .iter()
        .rev()
        .find(|words| {
            words
                .first()
                .is_some_and(|word| STATUS_WORDS.contains(word))
        })
        .map(|words| pointer(words))
}

/// The case a nextest status line names: the two words after its bracketed
/// duration, `<binary> <case>`.
fn case_of<'a>(words: &[&'a str]) -> Vec<&'a str> {
    words
        .iter()
        .skip_while(|word| !word.ends_with(']'))
        .skip(1)
        .take(2)
        .copied()
        .collect()
}

/// A status line's first five words.
fn pointer(words: &[&str]) -> String {
    words.iter().take(5).copied().collect::<Vec<_>>().join(" ")
}

/// Where each harness runs and what it is handed: the working directory and
/// the argv, program first.
fn invocation(dir: &Path, suite: &Suite, want: &str, junit: &Path) -> (PathBuf, Vec<String>) {
    let argv = |words: &[&str]| words.iter().map(|word| (*word).to_owned()).collect();
    match suite {
        // NO `--test`, for `Suite::declared`'s reason: nothing in the declared
        // path names a cargo target. Every test target is built and each
        // filters `want` for itself, so the case runs wherever it was compiled
        // to and a layout change cannot silently deselect it.
        //
        // The compile is shared across targets, so the cost of the ones that
        // match nothing is their startup. A target selecting no case is not a
        // pass either: `selected` stays 0 and the caller reports
        // `names-no-case`, which is a could-not-look.
        //
        // UNDER NEXTEST, AS CARGO-MUTANTS ALREADY RUNS (CLOUD-1746). Plain
        // `cargo test` skips a repository's nextest setup scripts, and a suite
        // whose cases depend on what one exports then reds unmutated: measured
        // 2026-10-16, a `one_pr.rs` case passed under nextest and failed in the
        // staged tree for want of the variable its setup script sets, so the row
        // read `case-already-red`. `test(<want>)` matches by containment, the
        // filter libtest applied; `--no-tests=pass` leaves an empty selection
        // to `names-no-case` rather than to nextest's own error.
        Suite::Cargo { .. } => {
            let filter = format!("test({want})");
            let mut words = vec![
                "cargo",
                "nextest",
                "run",
                "--no-fail-fast",
                "--no-tests=pass",
                "--color=never",
            ];
            words.extend(NEXTEST_VERDICT_FLAGS);
            words.extend(["-E", &filter]);
            (dir.to_path_buf(), argv(&words))
        }
        // `tofu test` runs in the module's root, and a test file lives there or
        // in its `tests/` directory — so the root is read off the path and
        // `-filter` names the file relative to it. `-filter` selects a FILE,
        // never a run, so the run is picked out of the output.
        Suite::Tofu { path } => {
            let (module, file) = tofu_module(path);
            let filter = format!("-filter={file}");
            (dir.join(module), argv(&["tofu", "test", "-json", &filter]))
        }
        Suite::Kyverno { path } => (
            dir.to_path_buf(),
            argv(&[
                "kyverno",
                "test",
                &parent_of(path),
                "-o",
                "json",
                "--detailed-results",
                "-t",
                want,
            ]),
        ),
        Suite::Conftest { path } => (
            dir.to_path_buf(),
            argv(&["conftest", "verify", "-p", &parent_of(path), "-o", "json"]),
        ),
        Suite::Pytest { path } => {
            let report = format!("--junitxml={}", junit.display());
            (
                dir.to_path_buf(),
                argv(&["pytest", path, "-k", want, &report]),
            )
        }
    }
}

/// The directory a suite file sits in, as a repo-relative argument: `.` for a
/// file at the root.
fn parent_of(path: &str) -> String {
    Path::new(path)
        .parent()
        .map(|parent| parent.to_string_lossy().into_owned())
        .filter(|parent| !parent.is_empty())
        .unwrap_or_else(|| String::from("."))
}

/// A `*.tftest.hcl` path split into the module root `tofu test` runs in and the
/// file as `-filter` names it from there. A file under a directory called
/// `tests` belongs to that directory's parent — `tofu test`'s own default test
/// directory — and any other file to the directory it sits in.
fn tofu_module(path: &str) -> (PathBuf, String) {
    let file = Path::new(path);
    let name = file
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    let Some(parent) = file
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    else {
        return (PathBuf::new(), name);
    };
    if parent.file_name().is_some_and(|dir| dir == "tests") {
        let module = parent.parent().map(Path::to_path_buf).unwrap_or_default();
        return (module, format!("tests/{name}"));
    }
    (parent.to_path_buf(), name)
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

/// Whether a libtest run printed a summary. Every test target prints one, even
/// one that filters out every case, so its absence means nothing ran.
fn libtest_ran(output: &str) -> bool {
    output.lines().any(|line| line.contains("test result: "))
}

/// The cases a nextest run selected, one per case whatever its attempts or
/// outcome: every attempt [`crate::replay::attempts`] reads (`SIGTERM` among
/// the results, which [`wait_bounded`] itself sends a timed-out runner),
/// counted by distinct case, so a retried case is one.
fn nextest_lines(output: &str) -> usize {
    crate::replay::attempts(output)
        .map(|(_, case)| case)
        .collect::<std::collections::BTreeSet<_>>()
        .len()
}

/// Whether a nextest run printed its summary, which it does for an empty
/// selection under `--no-tests=pass` too; absent, nothing ran.
fn nextest_ran(output: &str) -> bool {
    output.lines().any(crate::replay::summary)
}

/// The named `run`'s verdict out of `tofu test -json`'s machine-readable lines.
///
/// Measured against `tofu` 1.13.1 (the recorded fixtures): each run reports a
/// `test_run` line carrying `pass`, `fail` or `error`, and a module that does not
/// parse prints an error `diagnostic` and NO `test_run` line at all — so that
/// shape is the errored one, and reading it as a failure would call every
/// parse-breaking mutation caught. The `version` line opens every run, so it is
/// what says the harness started.
fn tofu_verdict(output: &str, want: &str) -> Selection {
    let mut status = None;
    let mut any_run = false;
    let mut diagnosed = false;
    let mut ran = false;
    for line in output.lines() {
        let Ok(value) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        match value.get("type").and_then(serde_json::Value::as_str) {
            Some("version" | "test_summary") => ran = true,
            Some("test_run") => {
                ran = true;
                any_run = true;
                let run = &value["test_run"];
                if run["run"].as_str() == Some(want)
                    && let Some(found) = run["status"].as_str()
                {
                    status = Some(found.to_owned());
                }
            }
            Some("diagnostic") => {
                diagnosed |= value["diagnostic"]["severity"].as_str() == Some("error");
            }
            _ => {}
        }
    }
    let (selected, ok, errored) = match status.as_deref() {
        Some("pass") => (1, true, false),
        Some("fail") => (1, false, false),
        Some("error") => (0, false, true),
        _ => (0, false, diagnosed && !any_run),
    };
    Selection {
        selected,
        ok,
        reach: Reach::of(ran, errored),
    }
}

/// The first JSON array in a harness's output, which both `kyverno test` and
/// `conftest verify` print among lines of prose.
fn json_array(output: &str) -> Option<Vec<serde_json::Value>> {
    let start = output
        .match_indices('\n')
        .map(|(at, _)| at + 1)
        .chain(std::iter::once(0))
        .filter(|at| output[*at..].starts_with('['))
        .min()?;
    serde_json::Deserializer::from_str(&output[start..])
        .into_iter::<Vec<serde_json::Value>>()
        .next()?
        .ok()
}

/// The named test case's verdict out of `kyverno test -o json --detailed-results`.
///
/// `want` is the `-t` selector, `policy=…,rule=…,resource=…`, matched exactly
/// against the result's `POLICY`, `RULE` and resource name. Measured against
/// kyverno 1.19.1: `RESULT` is the TEST's verdict (`Pass` where the policy did
/// what the test wants), and a policy that will not load prints an `ERROR:` line
/// and then reports the case `Fail` with reason `Not found` — so a load error is
/// the errored shape whatever the case line says.
///
/// **A GENERATING CASE IS SELECTED BY ITS TRIGGER AND REPORTED BY WHAT IT
/// GENERATED** (CLOUD-2252). `-t` filters a `GeneratingPolicy` case by the
/// resource that triggers it (a Namespace), while each result's `RESOURCE` is a
/// generated object, so no selector names both. Measured against kyverno
/// 1.19.1, the two are told apart by the RECORDING, never by a failed match
/// (CLOUD-2264): a generated object's `RESOURCE` carries no group, version or
/// kind (`/tenant-quota`), a validated one's does (`v1/Pod/default/labelled`).
/// Generated results are pooled, because `-t` has already narrowed them to the
/// named trigger's case (measured with two Namespace triggers: selecting one
/// never reports the other's objects); validated results must match the
/// selector's resource exactly. A selector that matches neither names no case,
/// so a typo is could-not-look rather than a verdict about other resources.
///
/// **THE CASE'S VERDICT IS A FUNCTION OF THE SET** ([`case_verdict`]): any
/// error, else any fail, else all pass. The previous ladder fell back to the
/// first verdict, so `[pass, fail, skip]` read pass.
fn kyverno_verdict(output: &str, want: &str) -> Selection {
    let field = |key: &str| {
        want.split(',')
            .filter_map(|part| part.split_once('='))
            .find(|(name, _)| name.trim() == key)
            .map(|(_, value)| value.trim().to_owned())
    };
    let (policy, rule, resource) = (field("policy"), field("rule"), field("resource"));
    let load_error = output
        .lines()
        .any(|line| line.trim_start().starts_with("ERROR:"));
    let results = json_array(output);
    let suffix = resource.as_ref().map(|want| format!("/{want}"));
    let status = results.as_ref().and_then(|results| {
        let case = results.iter().filter(|result| {
            result["POLICY"].as_str() == policy.as_deref()
                && result["RULE"].as_str() == rule.as_deref()
        });
        let (generated, validated): (Vec<&serde_json::Value>, Vec<&serde_json::Value>) = case
            .partition(|result| {
                result["RESOURCE"]
                    .as_str()
                    .is_some_and(|got| got.starts_with('/'))
            });
        let chosen = if generated.is_empty() {
            validated
                .into_iter()
                .filter(|result| {
                    let got = result["RESOURCE"].as_str();
                    got.is_some_and(|got| {
                        resource.as_deref() == Some(got)
                            || suffix.as_deref().is_some_and(|tail| got.ends_with(tail))
                    })
                })
                .collect()
        } else {
            generated
        };
        // A selected result with no readable verdict is an error, never dropped:
        // dropping it would let its siblings' passes decide the case.
        case_verdict(chosen.iter().copied().map(result_verdict))
    });
    let errored = load_error || status == Some("error");
    let selected = usize::from(matches!(status, Some("pass" | "fail")));
    Selection {
        selected,
        ok: status == Some("pass"),
        reach: Reach::of(
            results.is_some() || output.contains("Test Summary:"),
            errored,
        ),
    }
}

/// One result's verdict token, `error` when it carries none to read: a dropped
/// result would let its siblings' passes decide the case.
fn result_verdict(result: &serde_json::Value) -> &str {
    result["RESULT"].as_str().unwrap_or("error")
}

/// One case's verdict from its results' verdicts, by precedence and never by
/// order (CLOUD-2264): any `error`, else any `fail`, else `pass` when every one
/// passed. Only `skip` or `warn` verdicts, or none, are no verdict.
fn case_verdict<'a>(verdicts: impl Iterator<Item = &'a str>) -> Option<&'static str> {
    let (mut any, mut error, mut fail, mut every_pass) = (false, false, false, true);
    for v in verdicts {
        any = true;
        if v.eq_ignore_ascii_case("error") {
            error = true;
        } else if v.eq_ignore_ascii_case("fail") {
            fail = true;
        }
        every_pass &= v.eq_ignore_ascii_case("pass");
    }
    if error {
        Some("error")
    } else if fail {
        Some("fail")
    } else if any && every_pass {
        Some("pass")
    } else {
        None
    }
}

/// The named `test_` rule's verdict out of `conftest verify -o json`.
///
/// **A FAIL IS READ FROM THE OUTPUT, AND A PASS CANNOT BE.** Measured against
/// conftest 0.71.1: a failing test is a `failures` entry whose `msg` names it
/// (`data.<package>.<rule>`), and a passing one is an anonymous `"successes": 1`
/// in every output format conftest offers — JSON, TAP, `JUnit` and table alike. So
/// the case's EXISTENCE is read from the declared suite file, a rule defined at
/// column zero under exactly that name, and its verdict from whether the output
/// names it failed. A run that cannot load a policy prints no results at all,
/// only an `Error:` line, and that is the errored shape.
fn conftest_verdict(output: &str, want: &str, suite: &[String]) -> Selection {
    let Some(results) = json_array(output) else {
        return Selection {
            reach: Reach::of(false, output.contains("Error:")),
            ..Selection::default()
        };
    };
    let failed = results.iter().any(|result| {
        result["failures"].as_array().is_some_and(|failures| {
            failures.iter().any(|failure| {
                failure["msg"]
                    .as_str()
                    .is_some_and(|msg| msg.rsplit('.').next() == Some(want))
            })
        })
    });
    let defined = suite.iter().any(|line| {
        line.strip_prefix(want)
            .is_some_and(|rest| rest.is_empty() || rest.starts_with([' ', '{', '(', '[']))
    });
    Selection {
        selected: usize::from(defined || failed),
        ok: defined && !failed,
        reach: Reach::Reported,
    }
}

/// The selected cases' verdict out of pytest's `JUnit` report.
///
/// `-k` already narrowed the run to `want`, so every `<testcase>` is a selected
/// case, except one pytest skipped. Measured against pytest 9.1.1: a failing case
/// carries `<failure>`, and a collection or fixture error carries `<error>` —
/// for a module that will not import, on a `<testcase>` named after the module
/// rather than any test in it — so any `<error>` is the errored shape.
fn pytest_verdict(report: &str) -> Selection {
    let cases: Vec<&str> = report
        .split("<testcase")
        .skip(1)
        .map(|case| case.split("</testcase>").next().unwrap_or(case))
        .collect();
    let errored = cases.iter().any(|case| case.contains("<error"));
    let run: Vec<&&str> = cases
        .iter()
        .filter(|case| !case.contains("<skipped") && !case.contains("<error"))
        .collect();
    Selection {
        selected: run.len(),
        ok: !run.iter().any(|case| case.contains("<failure")),
        reach: Reach::of(report.contains("<testsuite"), errored),
    }
}

/// How many cases a suite declares in total — for the two arms whose `want` is
/// a substring filter. The others match `want` exactly, select at most one case,
/// and so cannot select every case of a suite holding more than one.
fn total_cases(root: &Path, suite: &Suite) -> usize {
    let Some(lines) = lines_of(root, suite.path()) else {
        return 0;
    };
    let marker = match suite {
        Suite::Cargo { .. } => "#[test]",
        Suite::Pytest { .. } => "def test_",
        Suite::Tofu { .. } | Suite::Kyverno { .. } | Suite::Conftest { .. } => return 0,
    };
    lines
        .iter()
        .filter(|line| line.trim_start().starts_with(marker))
        .count()
}

// ---------------------------------------------------------------------------
// The sweep.
// ---------------------------------------------------------------------------

/// Apply one row's script to its source inside the staged tree, in process
/// ([`substitute`], CLOUD-2255): no `sed`, so nothing can hang or differ between
/// a GNU and a BSD host (CLOUD-282, CLOUD-2246).
///
/// `None` when it applied, else `unappliable-mutation`: a source that does not
/// read, or a script outside the one-substitution subset.
fn apply(staged: &Staged, overlay: Option<&Overlay>, row: &Row) -> Result<Option<Verdict>> {
    let path = staged.dir().join(&row.source);
    let Ok(before) = crate::fsio::read_to_string(&path) else {
        return Ok(Some(Verdict::UnappliableMutation));
    };
    let Some(after) = substitute(&before, &row.script) else {
        return Ok(Some(Verdict::UnappliableMutation));
    };
    // Into the overlay for a source a build embeds, so the staged tree, the
    // build's input, never moves ([`Overlay`]).
    let target = overlay
        .and_then(|overlay| overlay.path_of(&row.source))
        .unwrap_or(path);
    if let Some(dir) = target.parent() {
        fs::create_dir_all(dir)
            .with_context(|| format!("mutate: could not create {}", dir.display()))?;
    }
    crate::durable::replace(&target, after)
        .with_context(|| format!("mutate: could not write the mutated {}", row.source))?;
    Ok(None)
}

/// One row's `s<d>re<d>rep<d>` applied to `text` the way `sed` applies it: the
/// first match on each line, with sed's basic-regex escapes and its `&`
/// (CLOUD-2255).
///
/// IN-PROCESS, NO `sed`. The rows' grammar was sed's because `sed` ran them,
/// spawned once per row; the subset every committed row uses is one
/// substitution with no flags and no address, which the `regex` crate states
/// exactly. Anything outside it (an address, a second command, a flag, a
/// backreference in the pattern) is `None`, refused as unappliable rather than
/// approximated.
#[must_use]
pub fn substitute(text: &str, script: &str) -> Option<String> {
    let mut chars = script.chars();
    if chars.next()? != 's' {
        return None;
    }
    let delimiter = chars.next()?;
    let rest: String = chars.collect();
    let fields = split_unescaped(&rest, delimiter);
    let [pattern, replacement, flags] = fields.as_slice() else {
        return None;
    };
    if !flags.is_empty() {
        return None;
    }
    let pattern = regex::Regex::new(&basic_to_rust(pattern, delimiter)?).ok()?;
    let replacement = sed_replacement(replacement);
    let mut out = String::with_capacity(text.len());
    for line in text.split_inclusive('\n') {
        let (body, end) = line
            .strip_suffix('\n')
            .map_or((line, ""), |body| (body, "\n"));
        out.push_str(&pattern.replacen(body, 1, replacement.as_str()));
        out.push_str(end);
    }
    Some(out)
}

/// `text` split on each `delimiter` not preceded by a backslash, the escapes
/// kept for the field's own reader.
fn split_unescaped(text: &str, delimiter: char) -> Vec<String> {
    let mut fields = vec![String::new()];
    let mut escaped = false;
    for c in text.chars() {
        if !escaped && c == delimiter {
            fields.push(String::new());
            continue;
        }
        escaped = !escaped && c == '\\';
        if let Some(field) = fields.last_mut() {
            field.push(c);
        }
    }
    fields
}

/// A sed basic regular expression as the `regex` crate spells it: `\(` `\)`
/// `\{` `\}` `\|` `\+` `\?` are the operators and their bare forms literal, the
/// reverse of the crate's; an escaped delimiter is the literal delimiter.
fn basic_to_rust(pattern: &str, delimiter: char) -> Option<String> {
    let mut out = String::with_capacity(pattern.len());
    let mut chars = pattern.chars().peekable();
    // `^` anchors only first (or first in a group) and `$` only last: anywhere
    // else a basic regex reads them as themselves (`version=$(awk`, `"\[^"`).
    let mut at_start = true;
    while let Some(c) = chars.next() {
        let starting = std::mem::replace(&mut at_start, false);
        match c {
            '^' if !starting => out.push_str("\\^"),
            '$' if chars.peek().is_some() => out.push_str("\\$"),
            '\\' => match chars.next()? {
                '(' => {
                    out.push('(');
                    at_start = true;
                }
                op @ (')' | '{' | '}' | '|' | '+' | '?') => out.push(op),
                'n' => out.push_str("\\n"),
                't' => out.push_str("\\t"),
                'x' => out.push_str("\\x"),
                digit if digit.is_ascii_digit() => return None,
                other if other == delimiter => out.push_str(&regex::escape(&other.to_string())),
                other => {
                    out.push('\\');
                    out.push(other);
                }
            },
            '(' | ')' | '{' | '}' | '|' | '+' | '?' => {
                out.push('\\');
                out.push(c);
            }
            _ => out.push(c),
        }
    }
    Some(out)
}

/// A sed replacement as `regex` spells one: `&` is the whole match and `\&` a
/// literal ampersand, `\1`…`\9` a group, `$` literal. Any other escaped
/// character, the delimiter included, is that character, so the delimiter is
/// not an input here.
fn sed_replacement(replacement: &str) -> String {
    let mut out = String::with_capacity(replacement.len());
    let mut chars = replacement.chars();
    while let Some(c) = chars.next() {
        match c {
            '&' => out.push_str("${0}"),
            '$' => out.push_str("$$"),
            '\\' => match chars.next() {
                Some('n') => out.push('\n'),
                Some('t') => out.push('\t'),
                Some('x') => {
                    let hex: String = chars.by_ref().take(2).collect();
                    match u32::from_str_radix(&hex, 16).ok().and_then(char::from_u32) {
                        Some('$') => out.push_str("$$"),
                        Some(byte) => out.push(byte),
                        None => {
                            out.push('x');
                            out.push_str(&hex);
                        }
                    }
                }
                Some(digit) if digit.is_ascii_digit() => {
                    out.push_str("${");
                    out.push(digit);
                    out.push('}');
                }
                Some('$') => out.push_str("$$"),
                // An escaped delimiter, `&` or `\` is itself, as is any other.
                Some(other) => out.push(other),
                None => out.push('\\'),
            },
            _ => out.push(c),
        }
    }
    out
}

/// Whether the mutation changed anything, and whether it changed anything but a
/// declaration line.
///
/// **A row's pattern is a string that must also appear ON the declaration line**
/// — so a pattern spelled literally matches its own row, the file changes, the
/// gate's behaviour is untouched, and the mutation SURVIVES every run while
/// reading as enforced coverage. Measured: `board-write-record`'s
/// `overlap-frozen-at-write-time` had done exactly that for its whole life.
fn diff_shape(
    root: &Path,
    staged: &Staged,
    overlay: Option<&Overlay>,
    source: &str,
) -> (bool, usize) {
    let before = crate::fsio::read_to_string(root.join(source)).unwrap_or_default();
    let mutated = overlay
        .and_then(|overlay| overlay.path_of(source))
        .unwrap_or_else(|| staged.dir().join(source));
    let after = crate::fsio::read_to_string(mutated).unwrap_or_default();
    if before == after {
        return (false, 0);
    }
    (true, code_lines_changed(&before, &after))
}

/// The lines a mutation changed that are not a declaration line.
///
/// **Every opener in [`OPENERS`], not `#` alone.** The guard once skipped only
/// `#MUTANT…` lines, so a Rust row (`//MUTANT …`) whose unanchored pattern
/// matched nothing but its own declaration counted that rewrite as a code change
/// — exactly the self-match this guard exists to refuse, in the half of the
/// tree it did not look at.
///
/// **COUNTED AS A MULTISET, NOT A SET.** A line is changed by the number of
/// copies it gained or lost, never by whether its text appears somewhere in the
/// other version. Judged by membership, a mutation whose old and new lines both
/// recur elsewhere in the file counted zero code lines and was refused as a
/// self-match: `toolchain-probe-blind` swaps one `return Toolchain::…;` for
/// another and `missing-receipt-route-dropped` blanks a list entry, and every
/// one of those lines occurs elsewhere in its file (CLOUD-2067).
fn code_lines_changed(before: &str, after: &str) -> usize {
    let mut net: BTreeMap<&str, isize> = BTreeMap::new();
    for line in before.lines() {
        *net.entry(line).or_default() += 1;
    }
    for line in after.lines() {
        *net.entry(line).or_default() -= 1;
    }
    net.into_iter()
        .filter(|(line, _)| strip_marker(line.trim_start(), "MUTANT").is_none())
        .map(|(_, copies)| copies.unsigned_abs())
        .sum()
}

/// Judge one row.
fn judge_row(
    root: &Path,
    staged: &mut Staged,
    gate: &Gate,
    row: &Row,
    prebuilt: Option<&Prebuilt>,
) -> Result<Verdict> {
    if let Some(why) = row.want.strip_prefix("\u{0}malformed:") {
        return Ok(Verdict::MalformedRow {
            why: why.to_owned(),
        });
    }
    // The previous row's subject first — it may be a DIFFERENT gate's file, and
    // this row's suite may compose over it.
    staged.restore(root)?;
    staged.stage_subject(root, &row.source)?;
    // The previous row's mutated copy goes with its subject: a clean run must
    // read the embedded module.
    let overlay = Overlay::declared(root);
    if let Some(overlay) = &overlay {
        let _ = fs::remove_dir_all(&overlay.dir);
    }
    if declares_own_case(root, row)
        && let Some(verdict) = judge_by_module(root, staged, row)?
    {
        return Ok(verdict);
    }
    // The suite declared above the row in its OWN source, never merely the
    // gate's first: a preset gate is several modules, and a module may name
    // several suites (CLOUD-2193). A declaration no runner recognizes is named.
    let Some(suite) = gate.suite_for(row) else {
        return Ok(Verdict::NoSuite {
            suite: row
                .suite
                .clone()
                .unwrap_or_else(|| String::from(UNDECLARED)),
        });
    };

    // THE CASE MUST BE GREEN BEFORE IT IS MUTATED. "Red under mutation" is only
    // evidence if the row was green without it: a case that CANNOT pass — an
    // assertion that never holds, a fixture that never builds — is red either
    // way, and every mutation aimed at it reads as caught. Costs one extra
    // filtered run per row, which is what an anti-vacuity term is worth.
    let clean = run_suite(staged, root, suite, row, prebuilt);
    // AND HOW FAR THE RUN GOT IS READ BEFORE EITHER (CLOUD-1860, CLOUD-2160),
    // for the same reason one rung up: a killed or errored run selects no case
    // and exits non-zero, so it satisfies both tests below while meaning
    // neither. Reported as `names-no-case` it sent the reader to repair a
    // declaration that was already correct, and that is how the whole Rust half
    // of this mechanism read as coverage.
    if let Some(unlooked) = unreported(&clean, suite, row) {
        return Ok(unlooked);
    }
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
    let total = total_cases(root, suite);
    if total > 1 && clean.selected >= total {
        return Ok(Verdict::FilterNamesEveryCase {
            want: row.want.clone(),
        });
    }

    if let Some(refused) = apply(staged, overlay.as_ref(), row)? {
        return Ok(refused);
    }
    let (changed, code_lines) = diff_shape(root, staged, overlay.as_ref(), &row.source);
    if !changed {
        return Ok(Verdict::InertMutation);
    }
    if code_lines == 0 {
        return Ok(Verdict::SelfMutatingRow);
    }

    let mutated = run_suite(staged, root, suite, row, prebuilt);
    // THE SAME GUARD, AND HERE IT IS THE DANGEROUS DIRECTION. The clean run's
    // timeout costs a could-not-look reported under the wrong name; this one
    // would be read as evidence. A killed run exits non-zero, so without this
    // test `mutated.ok` is false and the row reports `Caught` — the sweep
    // asserting a mutation was caught by a suite that never ran a case. A
    // mutation that breaks the parse is the same forged pass (CLOUD-2160): only
    // the named case's own failure kills a mutant. Fail-closed is not enough
    // when the failure mode is a forged pass.
    if let Some(unlooked) = unreported(&mutated, suite, row) {
        return Ok(unlooked);
    }
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

/// Whether a `.rego` row's case is a `test_` rule the mutated module itself
/// declares (CLOUD-2255): an exact name in the module's own text, never a guess
/// at which suite a name belongs to.
fn declares_own_case(root: &Path, row: &Row) -> bool {
    has_extension(&row.source, "rego")
        && lines_of(root, &row.source).is_some_and(|lines| {
            let rule = format!("test_{} ", row.want);
            lines.iter().any(|line| line.starts_with(&rule))
        })
}

/// A row judged by its module's own test tier, in process ([`crate::policy_case`]),
/// with the same three-step discipline as a suite: green before the mutation,
/// a change that touches code, red after it. A fault is could-not-look, never a
/// catch: a mutation that breaks the module's parse is not one its case caught.
///
/// `None` when the module is no registered row's (a preset's module is loaded
/// another way), so the row falls to its declared suite rather than reading as
/// naming no case.
fn judge_by_module(root: &Path, staged: &mut Staged, row: &Row) -> Result<Option<Verdict>> {
    let want = row.want.clone();
    match crate::policy_case(staged.dir(), &row.source, &row.want) {
        Ok(Some(true)) => {}
        Ok(Some(false)) => return Ok(Some(Verdict::CaseAlreadyRed { want })),
        Ok(None) => return Ok(None),
        Err(_) => return Ok(Some(Verdict::SuiteDidNotRun { want })),
    }
    // IN PLACE: this tier reads the staged file itself and builds nothing.
    if let Some(refused) = apply(staged, None, row)? {
        return Ok(Some(refused));
    }
    let (changed, code_lines) = diff_shape(root, staged, None, &row.source);
    if !changed {
        return Ok(Some(Verdict::InertMutation));
    }
    if code_lines == 0 {
        return Ok(Some(Verdict::SelfMutatingRow));
    }
    Ok(Some(
        match crate::policy_case(staged.dir(), &row.source, &row.want) {
            Ok(Some(false)) => Verdict::Caught,
            Ok(Some(true)) => Verdict::Survived { want },
            Ok(None) => Verdict::NamesNoCase { want },
            Err(_) => Verdict::SuiteDidNotRun { want },
        },
    ))
}

/// The could-not-look a run's reach names, or `None` where it reported cases.
fn unreported(run: &Selection, suite: &Suite, row: &Row) -> Option<Verdict> {
    let want = row.want.clone();
    match run.reach {
        Reach::TimedOut => Some(Verdict::SuiteTimedOut {
            seconds: suite_bound(suite).as_secs(),
        }),
        Reach::Errored => Some(Verdict::CaseErrored { want }),
        Reach::Silent => Some(Verdict::SuiteDidNotRun { want }),
        Reach::Reported => None,
    }
}

/// Where the sweep records each row it saw caught, under its work directory.
///
/// CARGO-MUTANTS' `--iterate`, FOR THE DECLARED RUNNER (CLOUD-2253). Measured on
/// #1132: 173 changed rows at ~47s each, past the two-hour limit every time, and
/// a killed sweep kept nothing, so every lap paid the whole set again. A row
/// recorded caught under the same key is skipped, so a killed sweep resumes and
/// an unchanged row is never re-run. Like `--iterate` it is a heuristic: the key
/// is the row, its source and its suite, so a change elsewhere in what the case
/// exercises does not invalidate it. CI starts with no record, which keeps the
/// full sweep the confirmation.
const CAUGHT_RECORD: &str = "caught.tsv";

/// A row's key: its script, the bytes it mutates, and its suite's CODE, the
/// non-comment remainder [`crate::git::without_comments`] reads, so a comment
/// edit to the suite keeps the row it already saw caught. The source is keyed
/// whole: its rows are comments in it.
fn row_key(root: &Path, gate: &Gate, row: &Row) -> String {
    let mut material = row.script.clone().into_bytes();
    material.push(0);
    material.extend(crate::fsio::read(root.join(&row.source)).unwrap_or_default());
    material.push(0);
    if let Some(suite) = gate.suite_for(row) {
        let path = suite.path();
        let text = crate::fsio::read_to_string(root.join(path)).unwrap_or_default();
        material.extend(crate::git::without_comments(path, &text).into_bytes());
    }
    crate::provision::digest(&material)
}

/// The keys recorded caught; an unreadable record is an empty one.
fn recorded_caught(record: &Path) -> std::collections::HashSet<String> {
    crate::fsio::read_to_string(record)
        .map(|text| text.lines().map(str::to_owned).collect())
        .unwrap_or_default()
}

/// Append one caught key, whole-line so a torn tail never fuses two keys. Best
/// effort: a key not recorded is a row run again.
fn record_caught(record: &Path, key: &str) {
    let _ = crate::durable::append_whole_lines(record, &format!("{key}\n"));
}

/// Where a sweep records a change it saw pass whole: `target/mutate-passed.tsv`,
/// BESIDE [`work_dir`] AND NOT IN IT, because the work directory is the staged
/// repository itself, and a file there sits in the tree every suite runs in.
///
/// A WHOLE-CHANGE ANSWER, FOR `mutant:changed`'s LAPS (CLOUD-2588). Measured on
/// #1209: every `land` lap re-ran the diff's mutants, about 33 minutes, when
/// only a rebase had moved. A change recorded passing under the same key is
/// answered without running either half. It is [`CAUGHT_RECORD`]'s heuristic
/// widened to the change, and it is NOT cargo-mutants' `--iterate`, which
/// skips by mutant name and was refused on CLOUD-1746: the key here is the
/// change's content, so a mutant whose code moved is a key that moved.
///
/// WHAT IT DOES NOT SEE, AND WHY THAT IS SAFE. Outside the key: code beyond the
/// patch that a source's own test target compiles (a changed `lib.rs` is judged
/// by every unit test in the crate), inherited `NEXTEST_*` settings, the
/// cargo-mutants pin and the engine binary, and a non-UTF-8 path's base side.
/// Each can move a verdict under an unchanged key, as with [`row_key`]. So the
/// record never answers under `$CI` ([`ChangePass::of`]): the required
/// `mutants (k)` shards judge every pull-request head whole, and a local
/// answer only spares a lap's re-run. CLOUD-2591 owns keying those inputs.
const PASSED_RECORD: &str = "mutate-passed.tsv";

/// The directory a sweep stages its copy in, runs its tools under and keeps
/// [`CAUGHT_RECORD`] in.
#[must_use]
pub fn work_dir(root: &Path) -> PathBuf {
    target_dir(root).join("mutate")
}

/// The build root every sweep path sits under: [`work_dir`], and beside it the
/// state that must stay outside the staged tree ([`PASSED_RECORD`]).
fn target_dir(root: &Path) -> PathBuf {
    root.join("target")
}

/// The environment a sweep's scope is read from, beside the tree: which runner
/// judges, which sources it owns, and which shard of them this run is.
const PASS_ENV: [&str; 3] = [RUNNER, RUNNERS, SHARD];

/// One change a sweep is about to judge, keyed so a whole passing result is
/// recorded once and answered after (CLOUD-2588).
#[derive(Debug)]
pub struct ChangePass {
    inputs: ChangeInputs,
    key: String,
}

/// What a [`ChangePass`] key is computed over, kept so the key can be taken
/// again once the sweep ends.
#[derive(Debug)]
struct ChangeInputs {
    root: PathBuf,
    base: String,
    /// The changed paths, sorted and unique, as the change's set holds them.
    paths: Vec<String>,
    names: Vec<String>,
    command: Vec<String>,
}

impl ChangePass {
    /// The pass of `change`, the base and paths a sweep narrowed against, and
    /// of `names`, the gates it narrowed to; `None` where there is no change in
    /// hand, its patch cannot be written, or [`crate::step::bypassed`] holds (a
    /// non-empty `$CI`, or the step cache's own bypass), and the sweep then
    /// runs as it always did.
    ///
    /// NOT UNDER CI, AND IT IS THE STRUCTURAL HALF OF [`PASSED_RECORD`]'s
    /// SAFETY: a runner that keeps its workspace between runs (self-hosted, or a
    /// cached `target/`) would otherwise answer a confirmation from a record.
    #[must_use]
    pub fn of(
        root: &Path,
        change: Option<&(String, std::collections::BTreeSet<String>)>,
        names: &[String],
        command: &[String],
    ) -> Option<Self> {
        if crate::step::bypassed() {
            return None;
        }
        let (base, changed) = change?;
        let inputs = ChangeInputs {
            root: root.to_path_buf(),
            base: base.clone(),
            paths: changed.iter().cloned().collect(),
            names: names.to_vec(),
            command: command.to_vec(),
        };
        let key = inputs.key()?;
        Some(Self { inputs, key })
    }

    /// Whether this change already passed whole under the same key.
    #[must_use]
    pub fn passed(&self) -> bool {
        recorded_caught(&self.inputs.record_path()).contains(&self.key)
    }

    /// Record this change as passing whole, ONLY WHERE THE TREE STILL KEYS AS
    /// IT DID WHEN THE SWEEP BEGAN: an edit made while it ran (a backgrounded
    /// lap is half an hour) was never judged, so its key is not this one. Best
    /// effort, as [`record_caught`] is: a key not recorded is a change run again.
    pub fn record(&self) {
        if self.inputs.key().as_deref() != Some(self.key.as_str()) {
            return;
        }
        let _ = fs::create_dir_all(target_dir(&self.inputs.root));
        record_caught(&self.inputs.record_path(), &self.key);
    }
}

impl ChangeInputs {
    /// Where the pass record lives: [`PASSED_RECORD`] in [`target_dir`].
    fn record_path(&self) -> PathBuf {
        target_dir(&self.root).join(PASSED_RECORD)
    }

    /// The key of the tree as it stands now.
    ///
    /// THE KEY IS CONTENT, NEVER A COMMIT ID, so a rebase that moves nothing in
    /// the change hits. Its material, each part prefixed with its length, so two
    /// different scopes cannot serialise to the same bytes:
    ///
    /// - who judges: [`PASS_ENV`]'s values, trimmed as the verb reads them, and
    ///   `command`, the `[mutate] command` the registry carries;
    /// - the change: for each changed path, whether it is absent (a deleted
    ///   file and one emptied to nothing write the same patch, and are two
    ///   trees), then the hunks [`in_diff_patch`] writes for it WITH THEIR
    ///   `@@` LINE NUMBERS COLLAPSED, so a base that added lines above the
    ///   change, most rebases onto a busy trunk, keys alike while the context
    ///   lines still place the change; or, where no patch can be written
    ///   (non-UTF-8 working bytes), the path and a digest of those bytes;
    /// - what judges it: each narrowed gate's name and its rows' [`row_key`]s,
    ///   which carry the bytes of the sources a declared row mutates and the
    ///   code of the suites it runs against.
    ///
    /// So a base that moved a suite's code under an unchanged patch is a key
    /// that moved.
    fn key(&self) -> Option<String> {
        let Self {
            root,
            base,
            paths,
            names,
            command,
        } = self;
        let mut material = Vec::new();
        let mut put = |part: &[u8]| {
            material.extend_from_slice(&part.len().to_le_bytes());
            material.extend_from_slice(part);
        };
        for name in PASS_ENV {
            put(std::env::var(name).unwrap_or_default().trim().as_bytes());
        }
        for word in command {
            put(word.as_bytes());
        }
        for path in paths {
            // EACH PATH'S OWN HUNKS, OR ITS BYTES. A non-UTF-8 working file,
            // which `in_diff_patch` would read as empty, is keyed by its bytes,
            // so one binary file neither disables the record nor goes unkeyed.
            // Any other patch that cannot be written (a base that will not
            // open) is `None`: no record, a full run. A binary base side
            // reads as empty, so its text successor keys as a whole-file add.
            let read = crate::fsio::read(root.join(path));
            let absent = read
                .as_ref()
                .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound);
            let bytes = read.unwrap_or_default();
            if std::str::from_utf8(&bytes).is_ok() {
                put(&[u8::from(absent)]);
                let patch = in_diff_patch(root, base, std::slice::from_ref(path)).ok()?;
                for line in patch.lines() {
                    put(if line.starts_with("@@") { "@@" } else { line }.as_bytes());
                }
            } else {
                put(path.as_bytes());
                put(crate::provision::digest(&bytes).as_bytes());
            }
        }
        for name in names {
            put(name.as_bytes());
            if let Some(gate) = resolve(root, name) {
                for row in &gate.rows {
                    put(row_key(root, &gate, row).as_bytes());
                }
            }
        }
        Some(crate::provision::digest(&material))
    }
}

/// The one suite build every Cargo row runs against, written by
/// [`build_if_owed`].
///
/// **A ROW NEVER ASKS CARGO TO BUILD.** The rows of this runner are
/// Rego, Pkl and manifests, and a mutation of one changes no Rust, so a row that
/// recompiles is paying for nothing. Leaving that to cargo's freshness check was
/// a convention, and one `rerun-if-changed` naming a missing path broke it
/// silently: every row rebuilt the library, 75s where the row took 1-6s. Each row
/// instead hands nextest the binaries this build recorded, so a rebuild cannot
/// happen whatever the fingerprint says.
///
/// **EXCEPT A SUBJECT THE BUILD EMBEDS**, which reused binaries would judge
/// unmutated. Which subjects those are is READ, from the dep-info and build
/// script output cargo wrote, never listed by hand; the preset overlay covers the
/// ones it can, and the rest rebuild, row by row, because only a rebuild sees the
/// mutation.
struct Prebuilt {
    /// nextest's `binaries-only` list, as `--binaries-metadata` reads it.
    binaries: PathBuf,
    /// `cargo metadata`'s answer, as `--cargo-metadata` reads it.
    metadata: PathBuf,
    /// Staged-tree paths the build read, and directories a build script watches.
    embedded: Vec<String>,
}

impl Prebuilt {
    /// Whether a mutation of `source` is invisible to the recorded binaries.
    fn embeds(&self, source: &str) -> bool {
        self.embedded.iter().any(|path| {
            source == path
                || source
                    .strip_prefix(path.as_str())
                    .is_some_and(|rest| rest.starts_with('/'))
        })
    }

    /// The arguments that make a nextest run use the recorded binaries.
    fn reuse_args(&self) -> [String; 4] {
        [
            String::from("--binaries-metadata"),
            self.binaries.to_string_lossy().into_owned(),
            String::from("--cargo-metadata"),
            self.metadata.to_string_lossy().into_owned(),
        ]
    }
}

/// Where [`Prebuilt`]'s documents live: beside the binaries they describe.
fn prebuilt_dir(root: &Path) -> PathBuf {
    root.join(SUITE_TARGET).join("mutate-reuse")
}

/// Every staged-tree path cargo recorded reading, and every directory a build
/// script asked to be rerun over, under `target`.
///
/// Dep-info lists each input as its own `path:` line; a build script's
/// `rerun-if-changed` is in its `output`. Both are read wholesale: a stale file
/// left by an older build can only name MORE paths, which rebuilds a row that
/// did not need it — never the other way round.
fn embedded_paths(target: &Path, staged: &Path) -> Vec<String> {
    let mut found = std::collections::BTreeSet::new();
    // Cargo writes absolute paths canonically.
    let staged = crate::git::canonical(staged);
    // RELATIVE TO THE WORKSPACE ROOT, AND UNNORMALISED: rustc runs there and
    // writes `include_str!`'s path as it resolved it — measured,
    // `tests/../mise-tasks/toy.sh` — so a path is anchored on the staged tree and
    // its `..` folded before it is compared with a row's subject.
    let relative = |path: &str| {
        let mut resolved = PathBuf::new();
        for part in staged.join(path.trim()).components() {
            match part {
                std::path::Component::ParentDir => {
                    resolved.pop();
                }
                std::path::Component::CurDir => {}
                other => resolved.push(other),
            }
        }
        resolved
            .strip_prefix(&staged)
            .ok()
            .map(|rest| rest.to_string_lossy().into_owned())
            .filter(|rest| !rest.is_empty())
    };
    let deps = target.join("debug").join("deps");
    for entry in fs::read_dir(&deps).into_iter().flatten().flatten() {
        let path = entry.path();
        if path.extension().is_none_or(|ext| ext != "d") {
            continue;
        }
        let text = crate::fsio::read_to_string(&path).unwrap_or_default();
        for line in text.lines() {
            if let Some(input) = line.strip_suffix(':') {
                found.extend(relative(&input.replace("\\ ", " ")));
            }
        }
    }
    let build = target.join("debug").join("build");
    for entry in fs::read_dir(&build).into_iter().flatten().flatten() {
        let text = crate::fsio::read_to_string(entry.path().join("output")).unwrap_or_default();
        for line in text.lines() {
            let watched = line
                .strip_prefix("cargo:rerun-if-changed=")
                .or_else(|| line.strip_prefix("cargo::rerun-if-changed="));
            found.extend(watched.and_then(relative));
        }
    }
    found.into_iter().collect()
}

/// Run `args` in `staged` and keep its standard output at `into`.
fn record_document(
    root: &Path,
    staged: &Staged,
    program: Program<'_>,
    args: &[String],
    into: &Path,
) -> Option<()> {
    let ran = spawn(
        staged.dir(),
        program,
        args,
        &nextest_env(root, staged.dir()),
        build_bound(),
    )
    .ok()?;
    let document = ran.stdout.lines().find(|line| line.starts_with('{'))?;
    (ran.passed() && crate::durable::replace(into, document).is_ok()).then_some(())
}

/// BUILD ONCE, BEFORE ANY ROW IS TIMED (CLOUD-1910), and record the build so no
/// row repeats it ([`Prebuilt`]). Best effort: a build that fails answers `None`,
/// and every Cargo row then reports `suite-did-not-run` without spawning, which
/// is the honest verdict. NOT AT ALL when every Cargo row is already recorded
/// caught (CLOUD-2253): the build is minutes and no row would use it.
///
/// SAID ON `progress` WHEN IT BUILDS: the build is minutes, so a sweep that
/// paid it says so, and a sweep that skipped it is told apart by its silence.
fn build_if_owed(
    root: &Path,
    names: &[String],
    registry: &Registry,
    caught: &std::collections::HashSet<String>,
    staged: &Staged,
    progress: &mut dyn std::io::Write,
) -> Option<Prebuilt> {
    let owed = names
        .iter()
        .filter_map(|name| resolve(root, name))
        .any(|gate| {
            gate.rows.iter().any(|row| {
                registry.declares(row)
                    && !caught.contains(&row_key(root, &gate, row))
                    && matches!(gate.suite_for(row), Some(Suite::Cargo { .. }))
            })
        });
    // A record from an earlier sweep describes binaries this one may not have.
    let dir = prebuilt_dir(root);
    let _ = fs::remove_dir_all(&dir);
    if !owed {
        return None;
    }
    let _ = writeln!(
        progress,
        "mutate sweep: building the cargo suites the rows run under"
    );
    fs::create_dir_all(&dir).ok()?;
    let prebuilt = Prebuilt {
        binaries: dir.join("binaries.json"),
        metadata: dir.join("cargo-metadata.json"),
        embedded: Vec::new(),
    };
    let mut list = [
        "nextest",
        "list",
        "--list-type",
        "binaries-only",
        "--message-format",
        "json",
    ]
    .map(String::from)
    .to_vec();
    list.extend(overlay_features(root));
    record_document(root, staged, Program::Cargo, &list, &prebuilt.binaries)?;
    let metadata = ["metadata", "--format-version", "1", "--no-deps"].map(String::from);
    record_document(root, staged, Program::Cargo, &metadata, &prebuilt.metadata)?;
    Some(Prebuilt {
        embedded: embedded_paths(&root.join(SUITE_TARGET), staged.dir()),
        ..prebuilt
    })
}

/// Sweep the enforced set.
///
/// # Errors
///
/// A tree that cannot be staged is could-not-look (→ exit `3`).
pub fn sweep(root: &Path, names: &[String], work: PathBuf) -> Result<Sweep> {
    sweep_owned(
        root,
        names,
        work,
        &Registry::default(),
        &mut std::io::sink(),
    )
}

/// [`sweep`], judging only the rows the declared runner owns under `registry`;
/// a row another runner owns is that runner's ([`run_registered`]).
///
/// `progress` gets the row count before any row runs, then one line per row
/// with its verdict and wall time (CLOUD-2253): a sweep that printed nothing
/// for two hours could not be told apart from a hung one, nor its cost read.
///
/// # Errors
///
/// [`sweep`]'s.
pub fn sweep_owned(
    root: &Path,
    names: &[String],
    work: PathBuf,
    registry: &Registry,
    progress: &mut dyn std::io::Write,
) -> Result<Sweep> {
    sweep_shard(root, names, work, registry, None, progress)
}

/// The gate-level finding that stops every row of `gate` before any runs, if
/// there is one.
fn gate_stopped(root: &Path, gate: &Gate) -> Option<Verdict> {
    // EVERY suite the gate's rows run under must be declared, runnable and
    // present, not only the first: a later module's declaration naming a
    // missing file is as much a could-not-look as the first one's. Checked
    // before any row, so a gate that fails here invokes no runner at all.
    let unrunnable = gate
        .unrunnable
        .clone()
        .or_else(|| gate.suite.is_none().then(|| String::from(UNDECLARED)))
        .or_else(|| {
            gate.suites()
                .into_iter()
                .find(|suite| !root.join(suite.path()).is_file())
                .map(|missing| missing.path().to_owned())
        });
    if let Some(suite) = unrunnable {
        return Some(Verdict::NoSuite { suite });
    }
    // THE ANTI-VACUITY TERM, AND IT IS THE WHOLE DESIGN. A listed gate with
    // no declaration is a failure, not a skip. Without this the sweep
    // reports success over a set it never touched.
    gate.rows.is_empty().then_some(Verdict::NoMutantDeclared)
}

/// Every row of `runnable` a registered runner owns, as `runner-owned`.
///
/// REFUSED, NEVER PASSED OVER: a row another runner owns is never read by it,
/// and filtering it out in silence is how 868 hand-written Rust rows read as
/// coverage (CLOUD-2253).
fn runner_owned(registry: &Registry, runnable: &[(&String, Gate)]) -> Vec<Finding> {
    runnable
        .iter()
        .flat_map(|(name, gate)| {
            gate.rows
                .iter()
                .filter(|row| !registry.declares(row))
                .filter_map(move |row| {
                    let owner = registry.owner(&row.source).ok()?;
                    Some(Finding {
                        gate: (*name).clone(),
                        slug: Some(row.slug.clone()),
                        verdict: Verdict::RunnerOwned { runner: owner.id() },
                        owner: gate.owner.clone(),
                    })
                })
        })
        .collect()
}

/// One shard's rows of one gate, as [`sweep_shard`] numbers them.
type ShardRow<'a> = (&'a String, &'a Gate, &'a Row);

/// `mine` less the rows that run under nextest where `cargo nextest` does not
/// answer, and the one [`NEXTEST`] `runner-absent` that says so.
///
/// ONE `runner-absent` FOR A CONSUMER WITHOUT NEXTEST (CLOUD-2466 item 4),
/// probed once before anything is staged, where every Cargo row used to read
/// `suite-did-not-run` on its own. Those rows are not judged; the rest are. A
/// row its own module judges in process needs no nextest.
fn without_absent_nextest<'a>(
    root: &Path,
    mine: Vec<ShardRow<'a>>,
) -> (Vec<ShardRow<'a>>, Option<Finding>) {
    let runs_nextest = |(_, gate, row): &ShardRow<'_>| {
        !declares_own_case(root, row) && matches!(gate.suite_for(row), Some(Suite::Cargo { .. }))
    };
    let absent = mine.iter().any(runs_nextest) && !cargo_answers(root, "nextest");
    if !absent {
        return (mine, None);
    }
    (
        mine.into_iter().filter(|row| !runs_nextest(row)).collect(),
        Some(runner_absent(NEXTEST)),
    )
}

/// [`sweep_owned`] over one parsed `$MUTANT_SHARD`'s slice ([`shard_parsed`]):
/// the declared rows [`shard_owns_row`] gives it, and the gate-level findings
/// of the gates `by_shard` gives it. `None` is every row and every gate.
///
/// # Errors
///
/// [`sweep`]'s.
pub fn sweep_shard(
    root: &Path,
    names: &[String],
    work: PathBuf,
    registry: &Registry,
    shard: Option<(usize, usize)>,
    progress: &mut dyn std::io::Write,
) -> Result<Sweep> {
    // SORTED, so every shard numbers the same gates and rows in the same order
    // whatever order its caller listed them in.
    let mut findings = Vec::new();
    let mut runnable = Vec::new();
    for (name, reports) in by_shard(names, shard) {
        let (verdict, owner) = match resolve(root, name) {
            None => (Verdict::NoSuchGate, None),
            Some(gate) => {
                let Some(verdict) = gate_stopped(root, &gate) else {
                    runnable.push((name, gate));
                    continue;
                };
                (verdict, gate.owner.clone())
            }
        };
        // A GATE-LEVEL finding is reported by the one shard `by_shard` gives
        // the gate, so a sharded run reports it once.
        if reports {
            findings.push(Finding {
                gate: name.clone(),
                slug: None,
                verdict,
                owner,
            });
        }
    }
    // THE SHARD'S ROWS, numbered across the runnable gates in sorted order, so
    // one numbering partitions the rows between the shards.
    findings.extend(runner_owned(registry, &runnable));
    let mine: Vec<(&String, &Gate, &Row)> = runnable
        .iter()
        .flat_map(|(name, gate)| {
            gate.rows
                .iter()
                .filter(|row| registry.declares(row))
                .map(move |row| (*name, gate, row))
        })
        .enumerate()
        .filter(|(number, _)| shard_owns_row(*number, shard))
        .map(|(_, row)| row)
        .collect();
    let (mine, nextest_absent) = without_absent_nextest(root, mine);
    // The gates holding a row of this shard's: only they can owe it a build.
    let mut holding: Vec<String> = mine.iter().map(|(name, _, _)| (*name).clone()).collect();
    holding.dedup();
    // Disjoint from the gates reported above, which are never runnable.
    let gates = findings.len() + holding.len();
    findings.extend(nextest_absent);
    let total = mine.len();
    let _ = writeln!(
        progress,
        "mutate sweep: {total} row(s) across {gates} gate(s)"
    );
    if mine.is_empty() {
        // Nothing to judge, so nothing to stage or build.
        return Ok(Sweep {
            findings,
            declared: 0,
            gates,
        });
    }
    let record = work.join(CAUGHT_RECORD);
    let caught = recorded_caught(&record);
    let mut staged = Staged::new(root, work)?;
    let prebuilt = build_if_owed(root, &holding, registry, &caught, &staged, progress);
    let mut declared = 0;
    for (name, gate, row) in mine {
        declared += 1;
        let key = row_key(root, gate, row);
        if caught.contains(&key) {
            let _ = writeln!(
                progress,
                "mutate sweep: row {declared}/{total} {name} {} caught (recorded) 0s",
                row.slug
            );
            continue;
        }
        let started = std::time::Instant::now();
        let verdict = judge_row(root, &mut staged, gate, row, prebuilt.as_ref())?;
        if verdict == Verdict::Caught {
            record_caught(&record, &key);
        }
        let _ = writeln!(
            progress,
            "mutate sweep: row {declared}/{total} {name} {} {verdict} {}s",
            row.slug,
            started.elapsed().as_secs()
        );
        if verdict.is_finding() {
            findings.push(Finding {
                gate: name.clone(),
                slug: Some(row.slug.clone()),
                verdict,
                owner: gate.owner.clone(),
            });
        }
    }
    staged.restore(root)?;
    Ok(Sweep {
        findings,
        declared,
        gates,
    })
}

// ---------------------------------------------------------------------------
// The census.
// ---------------------------------------------------------------------------

/// What the census decided about one subject.
///
/// `#[non_exhaustive]` for [`Census`]'s reason: CLOUD-2250's `InertMutation`
/// was a breaking `enum_variant_added`, and marking it now is what stops the
/// next verdict costing the same.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum CensusVerdict {
    /// A gate in the tree that is neither declared nor exempt.
    Uncovered,
    /// An exemption with no issue key or no reason.
    ExemptUnfiled,
    /// Declared and exempt at once, so the exemption's reason is a dead letter.
    DeclaredAndExempt,
    /// A name in the enforced set resolving to no gate at all.
    NamesNoSubject,
    /// A declared row whose script, applied to its own file, changes nothing:
    /// it proves nothing, and a sweep would only say so once it reached it.
    InertMutation,
    /// A declared row that is not three `|`-separated fields, or whose case
    /// field is not one case (a marker glued into it, CLOUD-2586), so no
    /// script and case can be read from it.
    MalformedRow,
    /// A declared row whose script is outside the one-substitution subset the
    /// runner applies ([`substitute`]), so it can never be applied.
    UnappliableMutation,
    /// A subject declaring rows in a source a registered runner owns, which
    /// that runner judges without reading them ([`Verdict::RunnerOwned`]).
    RunnerOwned,
}

impl fmt::Display for CensusVerdict {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        let word = match self {
            CensusVerdict::Uncovered => "uncovered",
            CensusVerdict::ExemptUnfiled => "exempt-unfiled",
            CensusVerdict::DeclaredAndExempt => "declared-and-exempt",
            CensusVerdict::NamesNoSubject => "names-no-subject",
            CensusVerdict::InertMutation => "inert-mutation",
            CensusVerdict::MalformedRow => "malformed-row",
            CensusVerdict::UnappliableMutation => "unappliable-mutation",
            CensusVerdict::RunnerOwned => "runner-owned",
        };
        out.write_str(word)
    }
}

/// What a census run answered.
///
/// `#[non_exhaustive]` for [`crate::doctor::SessionReport`]'s reason: a report
/// type gaining a field is the most ordinary change it has, and must not be a
/// breaking one.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Census {
    /// Pointer and verdict, in subject order.
    pub findings: Vec<(String, CensusVerdict)>,
    /// How many subjects were censused.
    pub subjects: usize,
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
///
/// With a committed `[mutate]` table, a DECLARATION ARM joins them (CLOUD-2010).
#[must_use]
pub fn subjects(root: &Path, table: Option<&crate::config::Mutate>) -> BTreeMap<String, String> {
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
    if let Some(presets) = presets_dir()
        && let Ok(entries) = std::fs::read_dir(root.join(&presets))
    {
        for entry in entries.filter_map(std::result::Result::ok) {
            if !entry.path().is_dir() {
                continue;
            }
            let name = entry.file_name().to_string_lossy().into_owned();
            if !sources_for(root, &name).is_empty() {
                found.insert(name.clone(), format!("{presets}/{name}"));
            }
        }
    }
    // INLINE TASKS, OPT-IN BY DECLARATION (CLOUD-1909): most of
    // the manifest's tasks run, build or report and owe nothing, so
    // a block is a subject only once it declares something — and then it is held
    // to the set, so a row nobody sweeps reads `uncovered` rather than covered.
    if let Some((manifest, lines)) =
        task_manifest().and_then(|manifest| Some((manifest.clone(), lines_of(root, &manifest)?)))
    {
        for task in task_names(&lines) {
            let declares = task_block(&lines, &task).is_some_and(|block| {
                !rows_in(&block, &manifest).is_empty()
                    || [SUITE, OWNER, EXEMPT]
                        .iter()
                        .any(|marker| declared(&block, marker).is_some())
            });
            if declares {
                found.insert(format!("{TASK_PREFIX}{task}"), manifest.clone());
            }
        }
    }
    if let Some(table) = table {
        declaring_files(root, table, &mut found);
    }
    found
}

/// THE DECLARATION ARM (CLOUD-2010): every tracked file — narrowed by
/// `[mutate].scope` when set — that carries a `MUTANT`, `MUTANT-SUITE` or
/// `MUTANT-EXEMPT` line at column zero and is no other arm's subject, keyed by
/// its path, which is the file arm's name for it.
///
/// **ON THE INLINE-TASK ARM'S TERMS, AND ONLY UNDER A TABLE.** A
/// consumer's gates live wherever its tree keeps them — `.tf`, YAML, `.rego`,
/// `.py` — so no directory list can find them, and a file that declares rows is
/// exactly one that owes a sweep. Held to the set like those arms: a declaring
/// file no gate entry covers reads `uncovered`. Off without a table, so a
/// census that declares none is unchanged.
fn declaring_files(
    root: &Path,
    table: &crate::config::Mutate,
    found: &mut BTreeMap<String, String>,
) {
    let scope = crate::rules::PathSet::scope(&table.scope).ok();
    let claimed: Vec<String> = found.values().cloned().collect();
    for path in crate::git::tracked_paths(root).unwrap_or_default() {
        if !table.scope.is_empty() && !scope.as_ref().is_some_and(|set| set.contains(&path)) {
            continue;
        }
        if claimed
            .iter()
            .any(|subject| *subject == path || path.starts_with(&format!("{subject}/")))
        {
            continue;
        }
        let declaring = lines_of(root, &path).is_some_and(|lines| {
            lines.iter().any(|line| {
                [ROW, SUITE, EXEMPT]
                    .iter()
                    .any(|marker| strip_marker(line, marker).is_some())
            })
        });
        if declaring {
            found.insert(path.clone(), path);
        }
    }
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
pub fn census(
    root: &Path,
    names: &[String],
    table: Option<&crate::config::Mutate>,
    registry: &Registry,
) -> Census {
    let subjects = subjects(root, table);
    let mut findings = Vec::new();
    // A ROW NO RUNNER WILL EVER READ (CLOUD-2253): a subject declaring rows in a
    // source a registered runner owns. Reported whatever the set says, because
    // neither declaring nor exempting it makes the row run.
    // Every gate the census knows, discovered or named in the set: a `.rs` path
    // named as a gate is no discovered subject, and is exactly where a Rust row
    // would be declared.
    let known: std::collections::BTreeSet<&String> = subjects.keys().chain(names.iter()).collect();
    for name in known {
        for source in sources_for(root, name) {
            let owned = registry
                .owner(&source)
                .is_ok_and(|owner| owner != RunnerKind::Declared)
                && lines_of(root, &source)
                    .is_some_and(|lines| !rows_in(&lines, &source).is_empty());
            if owned {
                findings.push((source, CensusVerdict::RunnerOwned));
            }
        }
    }
    for (name, path) in &subjects {
        let in_set = names.iter().any(|declared| declared == name);
        // Through the block for a `task-` gate (CLOUD-1909): an exemption written
        // in one task's table is not a statement about any other task.
        let exempt = sources_for(root, name)
            .iter()
            .filter_map(|source| declaring_lines(root, name, source))
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
    findings.extend(inert_rows(root, &subjects));
    Census {
        findings,
        subjects: subjects.len(),
    }
}

/// Every declared row, in every censused subject, whose script leaves its own
/// file byte-identical, as `path:line slug` (CLOUD-2250).
///
/// REFUSED WHEN THE ROW IS WRITTEN, NOT WHEN A SWEEP REACHES IT. The sweep
/// reports `inert-mutation` only for the gates it runs, and `mutant:changed`
/// runs only the ones a branch touched, so a row that rustfmt re-indented or a
/// refactor removed the line of sat dead on `main` until somebody happened to
/// sweep its module: three were, and #1132 re-anchored ten more by hand. The
/// census runs on every change, and [`substitute`] is the sweep's own
/// application, in process, so this costs a read and a regex per row.
///
/// THE OTHER TWO DEAD SHAPES TOO, which the full declared sweep measured in its
/// first 155 rows: a row split into four fields by a literal `|`, and a script
/// outside the one-substitution subset (a sed address block left from before
/// CLOUD-2255). Neither can ever apply, both are decidable from the text, and
/// the sweep named each only after an hour of building.
fn inert_rows(root: &Path, subjects: &BTreeMap<String, String>) -> Vec<(String, CensusVerdict)> {
    let mut found = Vec::new();
    for name in subjects.keys() {
        for source in sources_for(root, name) {
            let Ok(text) = crate::fsio::read_to_string(root.join(&source)) else {
                continue;
            };
            // ONE READ PER SOURCE: the declaring lines are sliced from the
            // text this already holds rather than read again.
            let Some(lines) =
                declaring_in(name, &source, text.lines().map(str::to_owned).collect())
            else {
                continue;
            };
            for row in rows_in(&lines, &source) {
                let row = match row {
                    Ok(row) => row,
                    Err((head, _)) => {
                        let at = row_line(&text, &head);
                        found.push((format!("{source}:{at} {head}"), CensusVerdict::MalformedRow));
                        continue;
                    }
                };
                let verdict = match substitute(&text, &row.script) {
                    None => CensusVerdict::UnappliableMutation,
                    Some(after) if code_lines_changed(&text, &after) == 0 => {
                        CensusVerdict::InertMutation
                    }
                    Some(_) => continue,
                };
                found.push((
                    format!("{source}:{} {}", row_line(&text, &row.slug), row.slug),
                    verdict,
                ));
            }
        }
    }
    found
}

/// The 1-based line of `slug`'s row in `text`, or `0` where none declares it.
/// A malformed row with no `|` at all is its whole body.
fn row_line(text: &str, slug: &str) -> usize {
    let head = format!("{slug}|");
    text.lines()
        .position(|line| {
            strip_marker(line, ROW).is_some_and(|body| body.starts_with(&head) || body == slug)
        })
        .map_or(0, |index| index + 1)
}

/// What one cargo-mutants job costs, as the repository declares it: the
/// `MUTANT_JOB_DISK_MB` and `MUTANT_JOB_MEMORY_MB` a copy's build was measured
/// to take. A property of THIS tree's build, so it is declared beside the task
/// that runs it; the machine's side is measured at run time by [`Machine::probe`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JobCost {
    /// Megabytes one copy and its target directory reach.
    pub disk_mb: u64,
    /// Megabytes one copy's build peaks at.
    pub memory_mb: u64,
}

impl JobCost {
    /// The declared cost, from the environment.
    ///
    /// # Errors
    ///
    /// Either variable absent or not a whole number of megabytes: a job count
    /// sized against a guessed cost is the hardcoding this replaces.
    pub fn declared() -> Result<Self> {
        let read = |name: &str| -> Result<u64> {
            let raw =
                std::env::var(name).map_err(|_| anyhow::anyhow!("`{name}` is not declared"))?;
            raw.trim()
                .parse()
                .map_err(|_| anyhow::anyhow!("`{name}` is not a whole number of megabytes"))
        };
        Ok(Self {
            disk_mb: read("MUTANT_JOB_DISK_MB")?,
            memory_mb: read("MUTANT_JOB_MEMORY_MB")?,
        })
    }
}

/// What this machine has left for jobs, measured where they will run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Machine {
    /// Cores this process may use (cgroup quota included).
    pub cores: usize,
    /// Free megabytes on the volume the copies are made in, above the
    /// collector's floor.
    pub disk_headroom_mb: u64,
    /// Megabytes available to this process: `MemAvailable`, or the cgroup's
    /// remaining limit where that is smaller.
    pub memory_mb: u64,
}

impl Machine {
    /// Measure the machine. Copies go to the temp directory (cargo-mutants'
    /// own default), so that is the volume whose headroom counts.
    ///
    /// # Errors
    ///
    /// The temp volume's free space cannot be read.
    pub fn probe(floor_mb: u64) -> Result<Self> {
        let cores = std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get);
        let free_mb = crate::prune::sampler(std::env::temp_dir())?()?;
        let meminfo = crate::fsio::read_to_string("/proc/meminfo").unwrap_or_default();
        let available = mem_available_mb(&meminfo);
        let cgroup = cgroup_remaining_mb(Path::new("/sys/fs/cgroup"));
        let memory_mb = match (available, cgroup) {
            (Some(a), Some(c)) => a.min(c),
            (Some(a), None) => a,
            (None, Some(c)) => c,
            (None, None) => u64::MAX,
        };
        Ok(Self {
            cores,
            disk_headroom_mb: free_mb.saturating_sub(floor_mb),
            memory_mb,
        })
    }
}

/// `MemAvailable` from a `/proc/meminfo` body, in megabytes.
fn mem_available_mb(meminfo: &str) -> Option<u64> {
    meminfo.lines().find_map(|line| {
        let kb = line
            .strip_prefix("MemAvailable:")?
            .trim()
            .strip_suffix("kB")?;
        kb.trim().parse::<u64>().ok().map(|kb| kb / 1024)
    })
}

/// The cgroup's limit minus its usage, in megabytes, v2 then v1; `None` where
/// neither is readable or the limit is unbounded.
fn cgroup_remaining_mb(root: &Path) -> Option<u64> {
    let read = |name: &str| -> Option<String> {
        crate::fsio::read_to_string(root.join(name))
            .ok()
            .map(|text| text.trim().to_owned())
    };
    let (limit, usage) = read("memory.max").zip(read("memory.current")).or_else(|| {
        read("memory/memory.limit_in_bytes").zip(read("memory/memory.usage_in_bytes"))
    })?;
    let limit: u64 = limit.parse().ok()?;
    let usage: u64 = usage.parse().ok()?;
    // v1 spells "unbounded" as a page-rounded i64::MAX; anything past a
    // petabyte is that, not a limit.
    (limit < 1 << 50).then(|| limit.saturating_sub(usage) / (1024 * 1024))
}

/// Write the change since `base` that cargo-mutants owns to `diff`, as the
/// patch `--in-diff` reads, and answer how many sources it holds. `None`, and
/// nothing written, when no source the registry gives cargo-mutants changed.
///
/// # Errors
///
/// No `base` to compare against, or a patch that cannot be written.
pub fn write_change(
    root: &Path,
    registry: &Registry,
    base: &str,
    diff: &Path,
) -> Result<Option<usize>> {
    let Some(delta) = crate::git::base_delta(root, base, &[String::from("**")], false)? else {
        bail!("mutate cargo: no {base} to compare against");
    };
    let changed: std::collections::BTreeSet<String> =
        delta.added.into_iter().chain(delta.edited).collect();
    let sources = owned_changes(root, &changed, registry, RunnerKind::CargoMutants);
    if sources.is_empty() {
        return Ok(None);
    }
    let patch = in_diff_patch(root, base, &sources)?;
    if let Some(dir) = diff.parent() {
        fs::create_dir_all(dir)
            .with_context(|| format!("mutate cargo: create {}", dir.display()))?;
    }
    crate::durable::replace(diff, patch)
        .with_context(|| format!("mutate cargo: write {}", diff.display()))?;
    Ok(Some(sources.len()))
}

/// Every mutant cargo-mutants makes of `diff`, as `--list --json` names them:
/// its own generator, so the schema judges exactly the set it would.
///
/// # Errors
///
/// `runner` cannot be spawned, refuses, or prints no listing.
pub fn list_mutants(root: &Path, runner: &Path, diff: &Path) -> Result<Vec<schema::Listed>> {
    let args = cargo_mutants_argv(diff, ["--list", "--json"].map(String::from));
    let runner = runner.to_string_lossy();
    let ran = spawn(root, Program::Command(&runner), &args, &[], runner_bound())?;
    if !ran.passed() {
        bail!(
            "mutate cargo: cargo-mutants could not list the change: {}",
            ran.output
        );
    }
    schema::listing(&ran.stdout)
}

/// cargo-mutants' argv over the change in `diff`, then `rest`: BUILT HERE AND
/// NOWHERE ELSE (`mutation_markers`), so the listing the schema judges and the
/// run that judges what it hands back read one change the one way.
fn cargo_mutants_argv(diff: &Path, rest: impl IntoIterator<Item = String>) -> Vec<String> {
    let mut args = vec![
        String::from("mutants"),
        String::from("--in-diff"),
        diff.to_string_lossy().into_owned(),
    ];
    args.extend(rest);
    args
}

/// The regex cargo-mutants' `--re` matches exactly `name` with: anchored, and
/// every character the `regex` crate gives a meaning escaped (its own
/// `regex::escape` set).
#[must_use]
pub fn exactly(name: &str) -> String {
    let mut pattern = String::from("^");
    for c in name.chars() {
        if "\\.+*?()|[]{}^$#&-~".contains(c) {
            pattern.push('\\');
        }
        pattern.push(c);
    }
    pattern.push('$');
    pattern
}

/// Run cargo-mutants itself over the mutants of `diff` named `names`, the
/// ones the schema handed back: `--in-diff`, `--re` per name, `--jobs` as
/// sized and `--iterate`, its output streamed as it judges.
///
/// AN ARGV, NEVER A HARNESS. Copy mode, timeouts, the baseline and the verdict
/// files are cargo-mutants' own (`.cargo/mutants.toml` carries the rest); this
/// assembles what a task body would otherwise spell in shell, and reads back
/// only the exit. `runner` is the provisioned binary, run as cargo runs a
/// subcommand: its own name's suffix, `mutants`, first.
///
/// # Errors
///
/// A `runner` that cannot be spawned.
pub fn cargo_mutants(
    root: &Path,
    runner: &Path,
    diff: &Path,
    jobs: usize,
    names: &[String],
) -> Result<Outcome> {
    let mut rest = vec![
        String::from("--jobs"),
        jobs.to_string(),
        String::from("--iterate"),
    ];
    for name in names {
        rest.extend([String::from("--re"), exactly(name)]);
    }
    let args = cargo_mutants_argv(diff, rest);
    let runner = runner.to_string_lossy();
    let ran = spawn_as(
        root,
        Program::Command(&runner),
        &args,
        &[],
        runner_bound(),
        Said::Streamed,
    )?;
    Ok(ran.outcome)
}

/// cargo-mutants' exit read onto the house contract (§6): 0 every mutant
/// caught, 1 its usage error, 2 a missed mutant; 3 a timeout, 4 a failed
/// baseline, a signal or the bound decided nothing, so could not look.
#[must_use]
pub const fn cargo_exit(outcome: Outcome) -> crate::exit::ExitCode {
    use crate::exit::ExitCode;
    match outcome {
        Outcome::Passed => ExitCode::Success,
        Outcome::Failed(Some(1)) => ExitCode::Usage,
        Outcome::Failed(Some(2)) => ExitCode::Violation,
        Outcome::Failed(_) | Outcome::TimedOut => ExitCode::Internal,
    }
}

/// How many workers a schema sweep judges on: a core each but one. A worker
/// builds nothing (the schema is one build) and runs its cases under nextest,
/// which spends cores of its own, so the copy-sized [`job_count`] does not
/// apply. Measured on #1276: three workers on four cores judged 2,402 mutants
/// at about three minutes a hundred. Never below one.
#[must_use]
pub const fn judging_jobs(machine: Machine) -> usize {
    if machine.cores > 1 {
        machine.cores - 1
    } else {
        1
    }
}

/// How many cargo-mutants jobs this machine holds (`--jobs`).
///
/// A job per core at most, and as many as disk and memory each have room for.
/// NOT HALF THE CORES: a mutant's build is the incremental rebuild of the one
/// crate it mutates, which is mostly serial (a lap measured 4.1 h of build to
/// 1.0 h of test), so one job leaves cores idle; the memory term is what keeps
/// parallel builds from oversubscribing. Never below one: one job is
/// cargo-mutants' own default, and the disk collector keeps it inside the floor.
#[must_use]
pub fn job_count(machine: Machine, cost: JobCost) -> usize {
    let fit = |have: u64, need: u64| {
        usize::try_from(have.checked_div(need).unwrap_or(u64::MAX)).unwrap_or(usize::MAX)
    };
    machine
        .cores
        .min(fit(machine.disk_headroom_mb, cost.disk_mb))
        .min(fit(machine.memory_mb, cost.memory_mb))
        .max(1)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    const COST: JobCost = JobCost {
        disk_mb: 2_000,
        memory_mb: 3_000,
    };

    fn machine(cores: usize, disk_headroom_mb: u64, memory_mb: u64) -> Machine {
        Machine {
            cores,
            disk_headroom_mb,
            memory_mb,
        }
    }

    /// Fails by: the cores divided, or any term ignored.
    #[test]
    fn the_scarcest_resource_sizes_the_jobs() {
        assert_eq!(job_count(machine(8, 100_000, 100_000), COST), 8);
        assert_eq!(job_count(machine(8, 6_000, 100_000), COST), 3);
        assert_eq!(job_count(machine(8, 100_000, 6_000), COST), 2);
    }

    /// Fails by: zero jobs on a full disk, or a zero cost dividing by zero.
    #[test]
    fn a_starved_machine_still_runs_one_job() {
        assert_eq!(job_count(machine(1, 0, 0), COST), 1);
        let free = JobCost {
            disk_mb: 0,
            memory_mb: 0,
        };
        assert_eq!(job_count(machine(6, 0, 0), free), 6);
    }

    /// Fails by: a source outside the root, or the root itself, given an overlay
    /// path, or the path not mirroring the source under the root.
    #[test]
    fn an_overlay_mirrors_only_the_sources_under_its_root() {
        let overlay = Overlay {
            root: String::from("crates/x/presets"),
            env: String::from("X_OVERLAY"),
            features: String::from("overlay"),
            dir: PathBuf::from("/t/mutate-overlay"),
        };
        assert_eq!(
            overlay.path_of("crates/x/presets/git/a.rego"),
            Some(PathBuf::from("/t/mutate-overlay/git/a.rego"))
        );
        assert_eq!(overlay.path_of("crates/x/presetsy/a.rego"), None);
        assert_eq!(overlay.path_of("crates/x/presets"), None);
        assert_eq!(overlay.path_of("policy/a.rego"), None);
    }

    /// Fails by: a missed mutant read as anything but a violation, or a timeout
    /// or failed baseline read as a verdict.
    #[test]
    fn cargo_mutants_exits_read_onto_the_contract() {
        use crate::exit::ExitCode;
        assert_eq!(cargo_exit(Outcome::Passed), ExitCode::Success);
        assert_eq!(cargo_exit(Outcome::Failed(Some(1))), ExitCode::Usage);
        assert_eq!(cargo_exit(Outcome::Failed(Some(2))), ExitCode::Violation);
        for undecided in [
            Outcome::Failed(Some(3)),
            Outcome::Failed(Some(4)),
            Outcome::Failed(None),
            Outcome::TimedOut,
        ] {
            assert_eq!(cargo_exit(undecided), ExitCode::Internal, "{undecided:?}");
        }
    }

    /// Fails by: a diff written, or a count answered, for a change
    /// cargo-mutants owns no source of; or an owned change left unwritten.
    #[test]
    fn only_a_change_cargo_mutants_owns_is_written() {
        let root = fixture("cargo-run-unowned");
        crate::gitwrite::init_on_main(&root).expect("a repository");
        put(&root, "src/a.rs", "fn a() {}\n");
        put(&root, "notes.txt", "one\n");
        crate::gitwrite::commit_paths(
            &root,
            &[String::from("src/a.rs"), String::from("notes.txt")],
            "base",
        )
        .expect("commit");
        put(&root, "notes.txt", "two\n");
        let registry = Registry::parse("cargo-mutants=src/*.rs").expect("parses");
        let diff = root.join("state").join("change.diff");
        assert_eq!(
            write_change(&root, &registry, "HEAD", &diff).expect("judged"),
            None
        );
        assert!(!diff.exists(), "no diff is written for nothing to run");
        put(&root, "src/a.rs", "fn a() { b() }\n");
        assert_eq!(
            write_change(&root, &registry, "HEAD", &diff).expect("judged"),
            Some(1)
        );
        let written = crate::fsio::read_to_string(&diff).expect("written");
        assert!(
            written.contains("src/a.rs") && written.contains("+fn a() { b() }"),
            "{written}"
        );
    }

    #[test]
    fn a_sweep_judges_on_every_core_but_one() {
        let on = |cores| Machine {
            cores,
            disk_headroom_mb: 0,
            memory_mb: 0,
        };
        assert_eq!(judging_jobs(on(4)), 3);
        assert_eq!(judging_jobs(on(2)), 1);
        assert_eq!(judging_jobs(on(1)), 1);
        assert_eq!(judging_jobs(on(0)), 1);
    }

    /// A handed-back mutant is selected by its whole name and nothing else.
    #[test]
    fn a_name_is_matched_whole_and_literally() {
        assert_eq!(
            exactly("src/a.rs:3:5: replace a -> u8 with 0"),
            "^src/a\\.rs:3:5: replace a \\-> u8 with 0$"
        );
        assert_eq!(exactly("a|b(c)"), "^a\\|b\\(c\\)$");
    }

    /// Fails by: the first field read, kilobytes reported as megabytes.
    #[test]
    fn available_memory_is_read_in_megabytes() {
        let meminfo =
            "MemTotal:       16384000 kB\nMemFree:  100 kB\nMemAvailable:    8192000 kB\n";
        assert_eq!(mem_available_mb(meminfo), Some(8_000));
        assert_eq!(mem_available_mb("MemTotal: 1 kB\n"), None);
    }

    /// Fails by: usage ignored, v1 not read, or v1's unbounded limit taken as one.
    #[test]
    fn the_cgroup_limit_is_what_remains_of_it() {
        let v2 = crate::scratch::scratch("mutate-cgroup-v2");
        std::fs::write(v2.join("memory.max"), format!("{}\n", 10u64 << 30)).unwrap();
        std::fs::write(v2.join("memory.current"), format!("{}\n", 4u64 << 30)).unwrap();
        assert_eq!(cgroup_remaining_mb(&v2), Some(6 * 1024));

        let v1 = crate::scratch::scratch("mutate-cgroup-v1");
        std::fs::create_dir(v1.join("memory")).unwrap();
        std::fs::write(
            v1.join("memory/memory.limit_in_bytes"),
            (2u64 << 30).to_string(),
        )
        .unwrap();
        std::fs::write(
            v1.join("memory/memory.usage_in_bytes"),
            (1u64 << 30).to_string(),
        )
        .unwrap();
        assert_eq!(cgroup_remaining_mb(&v1), Some(1024));

        std::fs::write(
            v1.join("memory/memory.limit_in_bytes"),
            "9223372036854771712",
        )
        .unwrap();
        assert_eq!(cgroup_remaining_mb(&v1), None);

        std::fs::write(v2.join("memory.max"), "max\n").unwrap();
        assert_eq!(cgroup_remaining_mb(&v2), None);
        // A petabyte exactly is already "unbounded".
        std::fs::write(v2.join("memory.max"), (1_u64 << 50).to_string()).unwrap();
        assert_eq!(cgroup_remaining_mb(&v2), None);
    }

    /// Fails by: the first status line reported instead of the last, or a
    /// non-status line (a case's own output) taken for one, or the whole line
    /// reported rather than a pointer to it (CLOUD-2206).
    #[test]
    fn a_timed_out_suite_names_where_it_stopped() {
        let output = "   Compiling batten v0.0.217 (/w)\n    Finished `test` profile\n        \
                      SLOW [> 890.000s] batten::it preapprove::a_case and more words\n\
                      a case's own stderr line\n";
        assert_eq!(
            stopped_at(output).as_deref(),
            Some("SLOW [> 890.000s] batten::it preapprove::a_case")
        );
        assert_eq!(stopped_at("no status here\n"), None);
        // A sibling's later `PASS` does not hide the case that hung.
        let parallel = "        SLOW [> 890.000s] batten::it hung::case\n        \
                        PASS [   0.400s] batten::it quick::case\n";
        assert_eq!(
            stopped_at(parallel).as_deref(),
            Some("SLOW [> 890.000s] batten::it hung::case")
        );
        assert_eq!(
            stopped_at("   Compiling a v1\n        START [ 1/1] x::y\n").as_deref(),
            Some("START [ 1/1] x::y")
        );
        // A case marked slow that then finished is not where the run stopped.
        let finished = "        SLOW [> 60.000s] it a::case\n        \
                        PASS [  70.000s] it a::case\n        \
                        START [ 2/2] it b::case\n";
        assert_eq!(
            stopped_at(finished).as_deref(),
            Some("START [ 2/2] it b::case")
        );
        // A case nextest killed is where the run stopped, whatever follows it.
        let killed = "        TIMEOUT [ 120.000s] it a::case\n        \
                      PASS [   0.100s] it b::case\n";
        assert_eq!(
            stopped_at(killed).as_deref(),
            Some("TIMEOUT [ 120.000s] it a::case")
        );
    }

    /// Fails by: an inherited `NEXTEST_*` variable left on a nextest child, so
    /// `NEXTEST_RETRIES` reads a killing case's flaky pass as a survivor; one the
    /// env sets itself removed; or a child that names no profile (the consumer's
    /// own `command` runner) scrubbed.
    #[test]
    fn an_env_naming_nextest_scrubs_every_inherited_nextest_variable() {
        let inherited = [
            "NEXTEST_RETRIES",
            "NEXTEST_PROFILE",
            "PATH",
            "NEXTEST_STATUS_LEVEL",
        ]
        .map(String::from);
        let env = suite_env(Path::new("/repo"));
        assert_eq!(
            scrubbed(inherited.clone(), &env),
            ["NEXTEST_RETRIES", "NEXTEST_STATUS_LEVEL"]
        );
        assert!(scrubbed(inherited.clone(), &[]).is_empty());
        assert!(
            scrubbed(inherited, &[(String::from("PATH"), String::from("/bin"))]).is_empty(),
            "an env setting only PATH names no profile, so nothing is scrubbed"
        );
    }

    /// Fails by: cargo-mutants, which runs as itself, reported absent, or a
    /// `command` runner whose program does not resolve read as resolvable.
    #[test]
    fn only_a_command_runner_is_probed() {
        let cargo_mutants = Registry::parse("cargo-mutants=**/*.rs").expect("parses");
        assert!(absent_runners(&cargo_mutants, |_| false).is_empty());
        let command = Registry::parse("command=**/*.rs")
            .and_then(|registry| registry.with_command(&[String::from("./mutscore.sh")]))
            .expect("parses");
        assert!(absent_runners(&command, |_| true).is_empty());
        assert_eq!(absent_runners(&command, |_| false), ["command"]);
        let missing = Registry::parse("command=**/*.rs")
            .and_then(|registry| {
                registry.with_command(&[String::from("no-such-mutation-runner-anywhere")])
            })
            .expect("parses");
        assert_eq!(unresolvable(Path::new("/"), &missing).len(), 1);
    }

    /// An overlay needs all three variables, each trimmed, and names its
    /// features to cargo.
    #[test]
    fn an_overlay_is_declared_only_by_all_three_variables() {
        let vars = |presets: &str| {
            let presets = presets.to_owned();
            move |name: &str| match name {
                "MUTANT_PRESETS" => Some(presets.clone()),
                "MUTANT_OVERLAY_ENV" => Some(String::from(" BATTEN_PRESET_OVERLAY ")),
                "MUTANT_OVERLAY_FEATURES" => Some(String::from("preset-overlay")),
                _ => None,
            }
        };
        let root = Path::new("/r");
        let overlay = Overlay::declared_by(root, vars("crates/x/presets/")).expect("declared");
        assert_eq!(overlay.root, "crates/x/presets");
        assert_eq!(overlay.env, "BATTEN_PRESET_OVERLAY");
        assert_eq!(overlay.feature_args(), ["--features", "preset-overlay"]);
        assert!(
            Overlay::declared_by(root, vars("  ")).is_none(),
            "a blank one is unset"
        );
        assert!(Overlay::declared_by(root, |_| None).is_none());
    }

    /// The listing asks cargo-mutants for exactly the change's mutants as
    /// JSON, reads what it prints, and refuses a runner that failed.
    ///
    /// Fails by: an empty listing, a refusal read as a listing, or an argv
    /// other than `mutants --in-diff <diff> --list --json`.
    #[test]
    fn the_listing_asks_for_the_changes_mutants_and_refuses_a_failed_runner() {
        // The stand-in runner is a `#!/bin/sh` script, which only a unix host
        // executes; the case compiles everywhere and asserts there.
        if !cfg!(unix) {
            return;
        }
        let root = fixture("list-mutants");
        let listed = "[{\"name\":\"m\",\"file\":\"src/lib.rs\",\"package\":\"p\",\
                      \"genre\":\"FnValue\",\"replacement\":\"true\",\"span\":{\"start\":\
                      {\"line\":1,\"column\":2},\"end\":{\"line\":3,\"column\":4}},\
                      \"function\":null}]";
        let runner = |name: &str, exit: u8| {
            put(
                &root,
                name,
                &format!(
                    "#!/bin/sh\nprintf '%s\\n' \"$@\" > args\nprintf '%s' '{listed}'\nexit {exit}\n"
                ),
            );
            let path = root.join(name);
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).expect("chmod");
            }
            path
        };
        let diff = root.join("change.diff");
        let got = list_mutants(&root, &runner("lists", 0), &diff).expect("listed");
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].name, "m");
        assert_eq!(
            crate::fsio::read_to_string(root.join("args")).expect("args"),
            format!("mutants\n--in-diff\n{}\n--list\n--json\n", diff.display())
        );
        assert!(list_mutants(&root, &runner("refuses", 1), &diff).is_err());
    }

    /// The overlay the environment declares reaches every sweep's cargo
    /// invocation as its features, and an undeclared one adds none.
    ///
    /// Fails by: `Overlay::declared` answering `None` whatever is set, or
    /// `overlay_features` answering empty or a blank feature.
    #[test]
    fn a_declared_overlay_names_its_features_to_every_invocation() {
        let root = Path::new("/r");
        let declared = [
            ("MUTANT_PRESETS", "crates/x/presets"),
            ("MUTANT_OVERLAY_ENV", "BATTEN_PRESET_OVERLAY"),
            ("MUTANT_OVERLAY_FEATURES", "preset-overlay"),
        ];
        let (overlay, features) = with_overlay_vars(&declared, || {
            (Overlay::declared(root), overlay_features(root))
        });
        assert_eq!(
            overlay.map(|overlay| overlay.root),
            Some(String::from("crates/x/presets"))
        );
        assert_eq!(features, ["--features", "preset-overlay"]);
        assert!(with_overlay_vars(&[], || overlay_features(root)).is_empty());
    }

    /// Fails by: an inherited profile kept that the staged tree does not
    /// declare (nextest then exits before selecting a case), a declared one
    /// dropped (its setup scripts never run), or the live tree read in place of
    /// the staged copy.
    #[test]
    fn a_declared_profile_is_kept_and_an_undeclared_one_is_not() {
        let staged = fixture("declared-profile");
        put(
            &staged,
            ".config/nextest.toml",
            "[profile.ci]\nretries = 3\n\n[profile.ci.junit]\npath = \"j.xml\"\n",
        );
        let kept = |profile: &str| declared_profile(&staged, Some(profile.to_owned()));
        assert_eq!(kept("ci"), Some(String::from("ci")));
        assert_eq!(kept("narrow"), None);
        assert_eq!(kept(" "), None);
        assert_eq!(declared_profile(&staged, None), None);
        assert_eq!(
            declared_profile(Path::new("/no/such/tree"), Some(String::from("ci"))),
            None
        );
    }

    /// Fails by: the pinned profile dropped or changed, so an inherited
    /// `NEXTEST_PROFILE` the staged tree does not declare reaches nextest and
    /// every declared Cargo row reads `suite-did-not-run`.
    #[test]
    fn every_runner_runs_the_default_nextest_profile() {
        let env = suite_env(Path::new("/repo"));
        assert_eq!(
            env.iter()
                .find(|(key, _)| key == "NEXTEST_PROFILE")
                .map(|(_, value)| value.as_str()),
            Some("default"),
            "suite_env must pin NEXTEST_PROFILE=default: {env:?}"
        );
    }

    /// Fails by: a nextest run read as libtest, which counts no case and finds
    /// no summary, so every declared Cargo row reads `suite-did-not-run`.
    #[test]
    fn a_nextest_run_is_read_for_its_cases_and_its_summary() {
        let ran = "    Starting 2 tests across 1 binary\n        \
                   PASS [   0.004s] batten::it one_pr::a\n        \
                   FAIL [   0.010s] batten::it one_pr::b\n────────────\n     \
                   Summary [   0.012s] 2 tests run: 1 passed, 1 failed, 8 skipped\n";
        assert_eq!(nextest_lines(ran), 2);
        assert!(nextest_ran(ran));
        // Every terminal word counts, the one the sweep's own bound sends
        // included; a retried case is one case whatever its attempts; a
        // progress line does not count, nor the failure repeated after the
        // summary.
        let ended = "        LEAK [   0.120s] batten::it a\n  \
                     TRY 1 FAIL [   0.004s] batten::it b\n  \
                     TRY 2 FAIL [   0.004s] batten::it b\n     \
                     SIGTERM [  60.000s] batten::it c\n   \
                     LEAK-FAIL [   0.010s] batten::it d\n        \
                     SLOW [> 60.000s] batten::it e\n     \
                     Summary [  60.100s] 4 tests run: 1 passed, 3 failed\n   \
                     LEAK-FAIL [   0.010s] batten::it d\n";
        assert_eq!(nextest_lines(ended), 4);
        assert_eq!(
            nextest_lines("        PASS [   0.004s]\n"),
            0,
            "a result names a case"
        );
        // Each word judged alone, so one wrong reading cannot cancel another.
        assert_eq!(nextest_lines("        LEAK [   0.120s] batten::it a\n"), 1);
        assert_eq!(nextest_lines("        SLOW [> 60.000s] batten::it e\n"), 0);
        let empty = "    Starting 0 tests across 1 binary\n     \
                     Summary [   0.000s] 0 tests run: 0 passed, 9 skipped\n";
        assert_eq!(nextest_lines(empty), 0);
        assert!(nextest_ran(empty));
        assert!(!nextest_ran("error: could not compile `batten`\n"));
    }

    /// A selected result with no readable verdict outranks its passing
    /// siblings (CLOUD-2264), rather than vanishing from the set.
    #[test]
    fn a_result_with_no_verdict_is_an_error() {
        let results = [
            serde_json::json!({"RESULT": "Pass"}),
            serde_json::json!({"RESULT": null}),
        ];
        assert_eq!(
            case_verdict(results.iter().map(result_verdict)),
            Some("error")
        );
    }

    /// Fails by: a case field holding whitespace or a `MUTANT` marker read as a
    /// case (CLOUD-2586), the glued form a removed line break leaves; or a
    /// field-count refusal no longer saying its count.
    #[test]
    fn a_case_glued_to_the_next_directive_is_refused_at_parse() {
        let lines = vec![
            format!("//{ROW}spaced|s@a@b@|one_case//{SUITE}tests/x.rs"),
            format!("//{ROW}marked|s@a@b@|one_case//MUTANT-OWNER"),
            format!("//{ROW}split|s@a@b@|one|two"),
            format!("//{ROW}kept|s@a@b@|tests::one_case"),
            format!("//{ROW}named|s@a@b@|test_MUTANT_rows"),
        ];
        let read: Vec<std::result::Result<String, (String, String)>> = rows_in(&lines, "src/x.rs")
            .into_iter()
            .map(|row| row.map(|row| row.slug))
            .collect();
        let glued = String::from(NOT_ONE_CASE);
        assert_eq!(
            read,
            [
                Err((String::from("spaced"), glued.clone())),
                Err((String::from("marked"), glued)),
                Err((String::from("split"), String::from("4 fields, want 3"))),
                Ok(String::from("kept")),
                Ok(String::from("named")),
            ],
            "a case may say MUTANT; only a marker glued into it is refused"
        );
    }

    /// Fails by: a row judged under its source's first declaration rather than
    /// the nearest one above it (CLOUD-2193); a row above every declaration
    /// keeps the first, which is what a single-declaration source always had.
    #[test]
    fn a_row_is_judged_under_the_suite_above_it() {
        let lines = vec![
            format!("//{ROW}above|s@a@b@|w"),
            format!("//{SUITE}tests/first.rs"),
            format!("//{ROW}under-first|s@a@b@|w"),
            format!("//{SUITE}tests/second.rs"),
            format!("//{ROW}under-second|s@a@b@|w"),
        ];
        let rows: Vec<Row> = rows_in(&lines, "src/x.rs").into_iter().flatten().collect();
        let suites: Vec<Option<&str>> = rows.iter().map(|row| row.suite.as_deref()).collect();
        assert_eq!(
            suites,
            [
                Some("tests/first.rs"),
                Some("tests/first.rs"),
                Some("tests/second.rs")
            ]
        );
    }

    /// Fails by: a later declaration no runner recognizes costing the whole
    /// gate (`unrunnable`) instead of only the rows under it (CLOUD-2193).
    /// cargo-mutants' in-diff run over this change missed exactly that:
    /// `replace match guard index == 0 with true in resolve`.
    #[test]
    fn a_later_unrecognized_suite_costs_only_the_rows_under_it() {
        let root = std::env::temp_dir().join(format!(
            "batten-mutate-later-suite-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("policy")).unwrap_or_else(|e| panic!("mkdir: {e}"));
        std::fs::write(
            root.join("policy/probe.rego"),
            [
                format!("#{SUITE}tests/it/a.rs"),
                format!("#{ROW}one|s/x/y/|case_a"),
                format!("#{SUITE}tests/it/b.unknown"),
                format!("#{ROW}two|s/x/y/|case_b"),
            ]
            .join("\n"),
        )
        .unwrap_or_else(|e| panic!("write: {e}"));
        let Some(gate) = resolve(&root, "probe") else {
            panic!("the module resolves to a gate");
        };
        let _ = std::fs::remove_dir_all(&root);
        assert_eq!(gate.unrunnable, None, "the gate itself stays runnable");
        let suite_of = |slug: &str| {
            let Some(row) = gate.rows.iter().find(|row| row.slug == slug) else {
                panic!("row {slug} is declared");
            };
            gate.suite_for(row).map(|suite| suite.path().to_owned())
        };
        assert_eq!(suite_of("one").as_deref(), Some("tests/it/a.rs"));
        assert_eq!(suite_of("two"), None, "only the row under it has no suite");
    }

    fn row_from(source: &str) -> Row {
        Row {
            slug: String::from("s"),
            script: String::from("s@a@b@"),
            want: String::from("w"),
            source: source.to_owned(),
            suite: None,
            resolved: None,
        }
    }

    #[test]
    fn shards_partition_the_sorted_gates_and_refuse_a_malformed_value() {
        let names: Vec<String> = ["d", "a", "c", "b", "e"]
            .iter()
            .map(|n| (*n).to_owned())
            .collect();
        let slices: Vec<Vec<String>> = (0..2)
            .map(|k| shard_of(&names, &format!("{k}/2")).expect("a well-formed shard"))
            .collect();
        assert_eq!(slices[0], ["a", "c", "e"]);
        assert_eq!(slices[1], ["b", "d"]);
        for bad in ["2/2", "0/0", "1", "x/2"] {
            assert!(shard_of(&names, bad).is_err(), "{bad} is not a shard");
        }
    }

    /// CLOUD-2533: a gate's rows are spread across the shards, not stacked on
    /// the one its name falls to. Fails by: a filter that hands every shard
    /// every row, or one shard all of them.
    #[test]
    fn a_large_gates_rows_spread_across_every_shard() {
        let slices: Vec<std::collections::BTreeSet<usize>> = (0..4)
            .map(|k| {
                (0..45)
                    .filter(|index| shard_owns_row(*index, Some((k, 4))))
                    .collect()
            })
            .collect();
        let union: std::collections::BTreeSet<usize> = slices.iter().flatten().copied().collect();
        assert_eq!(union, (0..45).collect(), "every row is some shard's");
        assert_eq!(
            slices
                .iter()
                .map(std::collections::BTreeSet::len)
                .sum::<usize>(),
            45,
            "and no row is two shards'"
        );
        assert!(slices.iter().all(|slice| slice.len() <= 12), "{slices:?}");
        assert!((0..45).all(|index| shard_owns_row(index, None)));
    }

    #[test]
    fn a_registered_glob_owns_its_sources_and_the_declared_runner_the_rest() {
        let registry = Registry::parse("cargo-mutants=crates/**/*.rs").expect("parses");
        assert_eq!(
            registry
                .owner("crates/app/src/drain.rs")
                .expect("one owner"),
            RunnerKind::CargoMutants
        );
        assert_eq!(
            registry.owner("policy/filed-here.rego").expect("one owner"),
            RunnerKind::Declared
        );
        assert!(!registry.declares(&row_from("crates/app/src/drain.rs")));
        assert!(registry.declares(&row_from("policy/filed-here.rego")));
        assert!(Registry::default().declares(&row_from("crates/app/src/drain.rs")));
    }

    /// The committed globs own what ships and the cases that test it: a crate's
    /// `src/`, its `build.rs` and its `tests/`, never `examples/` (no test target
    /// compiles it).
    #[test]
    fn the_committed_globs_own_what_ships() {
        let registry = Registry::parse(
            "cargo-mutants=crates/*/src/**/*.rs,crates/*/build.rs,crates/*/tests/**/*.rs",
        )
        .expect("parses");
        for owned in [
            "crates/app/src/lib.rs",
            "crates/app/src/policy/presets/x.rs",
            "crates/app/build.rs",
            "crates/app/tests/it/mutate.rs",
        ] {
            assert_eq!(
                registry.owner(owned).expect("one owner"),
                RunnerKind::CargoMutants,
                "{owned}"
            );
        }
        assert_eq!(
            registry
                .owner("crates/app/examples/hook-read-bench.rs")
                .expect("one owner"),
            RunnerKind::Declared
        );
    }

    /// Fails by: a set `$MUTANT_SHARD` read as unset, which sweeps every row on
    /// every shard, or a blank one read as a shard to refuse.
    #[test]
    fn a_blank_shard_is_no_shard_and_a_set_one_is_kept() {
        assert_eq!(shard_set(None), None);
        assert_eq!(shard_set(Some(String::from("  "))), None);
        assert_eq!(
            shard_set(Some(String::from("1/4"))),
            Some(String::from("1/4"))
        );
    }

    #[test]
    fn a_registry_naming_no_runner_or_giving_the_declared_one_globs_is_refused() {
        assert!(Registry::parse("mutmut=**/*.py").is_err());
        assert!(Registry::parse("declared=**/*.rego").is_err());
        assert!(Registry::parse("cargo-mutants").is_err());
    }

    #[test]
    fn a_source_two_runners_claim_has_no_owner() {
        let registry = Registry {
            owns: vec![
                (RunnerKind::CargoMutants, String::from("**/*.rs")),
                (RunnerKind::Declared, String::from("crates/**")),
            ],
            ..Registry::default()
        };
        assert!(registry.owner("crates/a/src/lib.rs").is_err());
        assert!(registry.declares(&row_from("crates/a/src/lib.rs")));
    }

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

    /// Fails by: the guard reading only the `#` opener again. A Rust row whose
    /// pattern rewrote nothing but its own `//MUTANT` line would then count one
    /// changed code line and read as an applied mutation.
    #[test]
    fn a_rewritten_declaration_is_not_a_changed_code_line_under_any_opener() {
        let before = "//MUTANT a|s@x@y@|case\n    let x = 1;\n#MUTANT b|s@x@y@|case\n";
        let after = "//MUTANT a|s@y@y@|case\n    let x = 1;\n#MUTANT b|s@y@y@|case\n";
        assert_eq!(code_lines_changed(before, after), 0);
        let code = "//MUTANT a|s@x@y@|case\n    let y = 1;\n#MUTANT b|s@x@y@|case\n";
        assert_eq!(
            code_lines_changed(before, code),
            2,
            "the old and new code line"
        );
    }

    /// Fails by: judging a line changed only when its text appears nowhere in the
    /// other version. A swap between two lines that each recur elsewhere, or a
    /// duplicated line blanked where a blank already stands, then counts zero
    /// code lines and the row is refused as `self-mutating-row` — measured on two
    /// real rows (CLOUD-2067).
    #[test]
    fn a_changed_line_repeated_elsewhere_in_the_file_is_still_a_changed_code_line() {
        let before = "    return A;\n    return B;\n\n    return A;\n";
        let swapped = "    return A;\n    return B;\n\n    return B;\n";
        assert_eq!(
            code_lines_changed(before, swapped),
            2,
            "the old and new line, though each recurs elsewhere"
        );
        let blanked = "    return A;\n    return B;\n\n\n";
        assert_eq!(
            code_lines_changed(before, blanked),
            2,
            "a duplicated line blanked beside a blank that already stood"
        );
    }

    /// The file arm resolves a path-shaped name to that file and nothing else.
    ///
    /// Fails by: dropping the component check, which lets a name climb out of the
    /// root; or dropping the extension check, which lets a kebab gate name that
    /// happens to match a root file start resolving somewhere new.
    #[test]
    fn a_path_shaped_gate_name_resolves_to_that_file_and_stays_inside_the_root() {
        assert!(is_source_path("predicate.pkl"));
        assert!(is_source_path("nested/dir/predicate.pkl"));
        assert!(!is_source_path("fix-selection"));
        assert!(!is_source_path("../outside.pkl"));
        assert!(!is_source_path("/abs/predicate.pkl"));
        assert!(!is_source_path("nested/../predicate.pkl"));
        let crate_root = Path::new(env!("CARGO_MANIFEST_DIR"));
        assert_eq!(
            sources_for(crate_root, "Cargo.toml"),
            vec![String::from("Cargo.toml")]
        );
        assert!(sources_for(crate_root, "absent-file.toml").is_empty());
    }

    #[test]
    fn a_row_is_exactly_three_fields() {
        let lines = vec![
            String::from("#MUTANT slug|s/a/b/|the_case"),
            String::from("#MUTANT bad|s/a|b/|extra|the_case"),
        ];
        let rows = rows_in(&lines, "policy/x.rego");
        assert!(rows[0].is_ok());
        assert_eq!(
            rows[1].as_ref().err().map(|(_, why)| why.as_str()),
            Some("5 fields, want 3")
        );
    }

    #[test]
    fn an_exempt_row_is_not_a_mutation_row() {
        // The marker carries a trailing space, so `#MUTANT-EXEMPT` and
        // `#MUTANT-SUITE` can never be read as declarations of a mutation.
        let lines = vec![
            String::from("#MUTANT-EXEMPT CLOUD-1|why"),
            String::from("#MUTANT-SUITE crates/app/tests/x.rs"),
        ];
        assert!(rows_in(&lines, "policy/x.rego").is_empty());
    }

    #[test]
    fn a_declared_rust_suite_carries_its_path_and_names_no_target() {
        // The path is carried to be READ — the existence check and the case
        // census both open it — and a target name is deliberately not derived
        // from it. A grouped suite lives at `tests/it/<x>.rs` and is a MODULE,
        // not a target called `<x>`, so a stem here would name nothing.
        let suite = Suite::declared("crates/app/tests/it/shell_retirement.rs");
        assert_eq!(
            suite,
            Some(Suite::Cargo {
                path: String::from("crates/app/tests/it/shell_retirement.rs"),
            })
        );
    }

    /// A preset gate is several modules, and each row runs under ITS OWN
    /// module's `#MUTANT-SUITE`, falling back to the gate's only where its
    /// module declares none.
    ///
    /// Fails by: `suite_for` returning `&self.suite` (the first declaration
    /// found, which is what `resolve` used to keep alone) — `b.rego`'s row then
    /// resolves to `a.rs`, and a second module's declaration decides nothing.
    #[test]
    fn each_preset_module_row_runs_under_its_own_declared_suite() {
        let root = std::env::temp_dir().join(format!(
            "batten-mutate-own-suite-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let presets = "presets";
        let dir = root.join(presets).join("probe");
        std::fs::create_dir_all(&dir).unwrap_or_else(|e| panic!("mkdir: {e}"));
        for (file, text) in [
            (
                "a.rego",
                "#MUTANT-SUITE tests/it/a.rs\n#MUTANT one|s/x/y/|case_a\n",
            ),
            (
                "b.rego",
                "#MUTANT-SUITE tests/it/b.rs\n#MUTANT two|s/x/y/|case_b\n",
            ),
            ("c.rego", "#MUTANT three|s/x/y/|case_c\n"),
        ] {
            std::fs::write(dir.join(file), text).unwrap_or_else(|e| panic!("write: {e}"));
        }
        let sources: Vec<String> = ["a.rego", "b.rego", "c.rego"]
            .map(|file| format!("{presets}/probe/{file}"))
            .to_vec();
        let Some(gate) = gate_of(&root, "probe", &sources) else {
            panic!("the preset's modules make a gate");
        };
        let _ = std::fs::remove_dir_all(&root);
        let suite_of = |slug: &str| {
            let Some(row) = gate.rows.iter().find(|row| row.slug == slug) else {
                panic!("row {slug} is declared");
            };
            gate.suite_for(row)
                .map(Suite::path)
                .unwrap_or_default()
                .to_owned()
        };
        assert_eq!(suite_of("one"), "tests/it/a.rs");
        assert_eq!(suite_of("two"), "tests/it/b.rs");
        assert_eq!(suite_of("three"), "tests/it/a.rs");
        let every: Vec<&str> = gate.suites().into_iter().map(Suite::path).collect();
        assert_eq!(every, vec!["tests/it/a.rs", "tests/it/b.rs"]);
    }

    /// Each native harness is chosen by the declared path's NAME, and nothing
    /// else resolves to one (CLOUD-2160).
    ///
    /// Fails by: a catch-all arm, which would hand a path no runner understands
    /// to whichever harness it named — and a guessed suite is a guessed verdict.
    #[test]
    fn each_native_harness_is_chosen_by_the_declared_name() {
        let declared = |path: &str| Suite::declared(path);
        let owned = String::from;
        assert_eq!(
            declared("infra/tests/limit.tftest.hcl"),
            Some(Suite::Tofu {
                path: owned("infra/tests/limit.tftest.hcl")
            })
        );
        assert_eq!(
            declared("policies/kyverno-test.yaml"),
            Some(Suite::Kyverno {
                path: owned("policies/kyverno-test.yaml")
            })
        );
        assert_eq!(
            declared("policy/limit_test.rego"),
            Some(Suite::Conftest {
                path: owned("policy/limit_test.rego")
            })
        );
        assert_eq!(
            declared("tests/test_limit.py"),
            Some(Suite::Pytest {
                path: owned("tests/test_limit.py")
            })
        );
        assert_eq!(
            declared("tests/limit_test.py"),
            Some(Suite::Pytest {
                path: owned("tests/limit_test.py")
            })
        );
    }

    #[test]
    fn a_suite_this_runner_cannot_run_is_refused_rather_than_guessed() {
        assert_eq!(Suite::declared("mise-tasks/land.sh"), None);
        assert_eq!(Suite::declared("policies/other.yaml"), None);
        assert_eq!(Suite::declared("scripts/helper.py"), None);
        assert_eq!(Suite::declared("infra/main.tf"), None);
    }

    /// The recorded output of one harness, its version line dropped.
    fn recorded(arm: &str, state: &str) -> String {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/mutate")
            .join(arm)
            .join(state);
        let text = crate::fsio::read_to_string(&path)
            .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        text.split_once('\n')
            .map(|(_, rest)| rest.to_owned())
            .unwrap_or_default()
    }

    /// The three states each reader must tell apart, over the real tools'
    /// recorded output (CLOUD-2160): a pass, a failure of the named case, and a
    /// run that could not load its subject.
    ///
    /// Fails by: any reader taking the errored shape for a failure — the one
    /// confusion that turns every parse-breaking mutation into `caught`.
    #[test]
    fn each_reader_tells_a_pass_a_failure_and_an_errored_run_apart() {
        let conftest_suite: Vec<String> = [
            "package main",
            "test_limit_is_ten if {",
            "\tlimit == 10",
            "}",
        ]
        .map(String::from)
        .to_vec();
        let kyverno = "policy=require-team,rule=check-team,resource=labelled";
        let read = |arm: &str, state: &str| {
            let output = recorded(arm, state);
            match arm {
                "tofu" => tofu_verdict(&output, "limit_is_ten"),
                "kyverno" => kyverno_verdict(&output, kyverno),
                "conftest" => conftest_verdict(&output, "test_limit_is_ten", &conftest_suite),
                _ => pytest_verdict(&output),
            }
        };
        for arm in ["tofu", "kyverno", "conftest", "pytest"] {
            let pass = read(arm, "pass");
            assert!(
                pass.reach == Reach::Reported && pass.ok && pass.selected == 1,
                "{arm} pass: {pass:?}"
            );
            let fail = read(arm, "fail");
            assert!(
                fail.reach == Reach::Reported && !fail.ok && fail.selected == 1,
                "{arm} fail: {fail:?}"
            );
            let error = read(arm, "error");
            assert_eq!(error.reach, Reach::Errored, "{arm} error: {error:?}");
        }
    }

    /// The exactly-matched arms name ONE case, so a sibling's verdict is never
    /// read as the named one's.
    ///
    /// Fails by: a substring match, under which `name_is_set` — which passed in
    /// the recording — would be read for a want it merely contains.
    #[test]
    fn an_exact_arm_reads_only_the_case_it_names() {
        let output = recorded("tofu", "fail");
        assert!(tofu_verdict(&output, "name_is_set").ok);
        assert_eq!(tofu_verdict(&output, "name").selected, 0);
        let none: Vec<String> = Vec::new();
        let conftest = recorded("conftest", "fail");
        assert_eq!(conftest_verdict(&conftest, "test_limit", &none).selected, 0);
    }

    #[test]
    fn a_tofu_suite_runs_in_its_modules_root() {
        assert_eq!(
            tofu_module("infra/tests/limit.tftest.hcl"),
            (
                PathBuf::from("infra"),
                String::from("tests/limit.tftest.hcl")
            )
        );
        assert_eq!(
            tofu_module("infra/limit.tftest.hcl"),
            (PathBuf::from("infra"), String::from("limit.tftest.hcl"))
        );
        assert_eq!(
            tofu_module("limit.tftest.hcl"),
            (PathBuf::new(), String::from("limit.tftest.hcl"))
        );
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
    fn a_run_with_no_summary_did_not_run_rather_than_naming_no_case() {
        // CLOUD-1910: a contended build printed no case lines, the row was blamed
        // as naming no case, and a re-run on the same tree caught every row.
        assert!(!libtest_ran(
            "   Compiling batten v0.1.0\nerror: could not compile\n"
        ));
        assert!(libtest_ran(
            "running 0 tests\n\ntest result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 9 filtered out\n"
        ));
        assert!(
            Verdict::SuiteDidNotRun {
                want: String::new()
            }
            .could_not_look()
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
        assert!(
            Verdict::CaseErrored {
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

    /// Fails by: a header test that admits a line missing either bracket, or a
    /// shell test (`[ -n "$x" ]`) at column zero, because one condition went
    /// unread.
    #[test]
    fn a_table_header_is_both_brackets_and_no_whitespace() {
        assert!(is_table_header("[tasks.verify]"));
        assert!(is_table_header("[tasks.\"build:release\"]  "));
        assert!(!is_table_header("[ -n \"$x\" ]"));
        assert!(!is_table_header("[tasks.verify"));
        assert!(!is_table_header("tasks.verify]"));
    }

    /// Fails by: the could-not-look count read as a constant, or as every
    /// finding.
    #[test]
    fn unlooked_counts_only_the_could_not_look_findings() {
        let finding = |verdict: Verdict| Finding {
            gate: String::from("g"),
            slug: None,
            verdict,
            owner: None,
        };
        let sweep = Sweep {
            findings: vec![
                finding(Verdict::NoSuite {
                    suite: String::new(),
                }),
                finding(Verdict::Survived {
                    want: String::new(),
                }),
                finding(Verdict::CaseErrored {
                    want: String::new(),
                }),
            ],
            declared: 3,
            gates: 1,
        };
        assert_eq!(sweep.unlooked(), 2);
    }

    /// Fails by: a root-level suite's directory read as empty, or any line
    /// that merely starts `test ` (the summary) or holds ` ... ` counted as a
    /// case.
    #[test]
    fn a_suites_directory_and_its_case_lines_are_read_exactly() {
        assert_eq!(parent_of("tests/it/x.bats"), "tests/it");
        assert_eq!(parent_of("x.bats"), ".");
        let run = "running 2 tests\ntest a::one ... ok\ntest a::two ... FAILED\n\
                   not a test ... ok\n\ntest result: FAILED. 1 passed; 1 failed\n";
        assert_eq!(libtest_lines(run), 2);
    }

    /// Fails by: a run that printed only its `version` line read as never
    /// started, or a `test_run` whose status is `error` read as reported.
    #[test]
    fn a_tofu_run_that_started_reports_and_an_errored_case_is_errored() {
        let version = r#"{"type":"version","tofu":"1.13.1"}"#;
        assert_eq!(
            tofu_verdict(version, "limit_is_ten"),
            Selection {
                selected: 0,
                ok: false,
                reach: Reach::Reported
            }
        );
        let errored = format!(
            "{version}\n{}",
            r#"{"type":"test_run","test_run":{"run":"limit_is_ten","status":"error"}}"#
        );
        assert_eq!(
            tofu_verdict(&errored, "limit_is_ten"),
            Selection {
                selected: 0,
                ok: false,
                reach: Reach::Errored
            }
        );
    }

    /// Fails by: the array's start taken anywhere but just after a newline.
    #[test]
    fn the_first_json_array_is_found_after_a_line_of_prose() {
        assert_eq!(
            json_array("Loading policies\n[1, 2]\ntrailing prose\n"),
            Some(vec![serde_json::json!(1), serde_json::json!(2)])
        );
    }

    /// Fails by: a result matched on its policy OR its rule, an exact resource
    /// name refused, a load error that needs an errored status too, or a
    /// printed result set that needs the `Test Summary:` line as well.
    #[test]
    fn a_kyverno_case_is_its_policy_rule_and_resource_and_a_load_error_errors() {
        let want = "policy=p,rule=r,resource=labelled";
        let report = |results: &serde_json::Value| format!("Applying policies\n{results}\n");
        let validated = report(&serde_json::json!([
            {"POLICY": "p", "RULE": "other", "RESOURCE": "v1/Pod/default/labelled", "RESULT": "Fail"},
            {"POLICY": "p", "RULE": "r", "RESOURCE": "v1/Pod/default/labelled", "RESULT": "Pass"}
        ]));
        let passed = Selection {
            selected: 1,
            ok: true,
            reach: Reach::Reported,
        };
        assert_eq!(kyverno_verdict(&validated, want), passed);
        let exact = report(&serde_json::json!([
            {"POLICY": "p", "RULE": "r", "RESOURCE": "labelled", "RESULT": "Pass"}
        ]));
        assert_eq!(kyverno_verdict(&exact, want), passed);
        let load_error = format!("ERROR: the policy will not load\n{exact}");
        assert_eq!(kyverno_verdict(&load_error, want).reach, Reach::Errored);
    }

    /// Fails by: a skipped case counted as selected.
    #[test]
    fn a_skipped_pytest_case_is_not_selected() {
        let report = r#"<testsuite name="pytest"><testcase name="test_a"><skipped message="off"/></testcase><testcase name="test_b"></testcase></testsuite>"#;
        assert_eq!(
            pytest_verdict(report),
            Selection {
                selected: 1,
                ok: true,
                reach: Reach::Reported
            }
        );
    }

    /// Fails by: a backreference passed through, an escaped delimiter kept
    /// escaped, or any other escape read as the literal delimiter.
    #[test]
    fn a_basic_regex_refuses_a_backreference_and_reads_an_escaped_delimiter_literally() {
        assert_eq!(basic_to_rust(r"a\1", '/'), None);
        assert_eq!(basic_to_rust(r"a\/b", '/').as_deref(), Some("a/b"));
        assert_eq!(basic_to_rust(r"a\@b", '@').as_deref(), Some("a@b"));
        assert_eq!(basic_to_rust(r"\w", '/').as_deref(), Some(r"\w"));
    }

    /// Fails by: an empty or non-numeric issue number accepted.
    #[test]
    fn an_exemption_key_is_cloud_and_digits_only() {
        assert!(exemption_is_filed("CLOUD-12|a stated reason"));
        assert!(!exemption_is_filed("CLOUD-|a stated reason"));
        assert!(!exemption_is_filed("CLOUD-12a|a stated reason"));
    }

    /// A fresh directory for one case under the crate's shared scratch root,
    /// which a later run reaps once this process is gone.
    fn fixture(name: &str) -> PathBuf {
        let root = crate::scratch::scratch(&format!("mutate-{name}"));
        assert!(root.is_dir(), "the fixture root");
        root
    }

    /// Write `text` at `path` under `root`, its directories included.
    fn put(root: &Path, path: &str, text: &str) {
        let file = root.join(path);
        fs::create_dir_all(file.parent().expect("a file has a parent")).expect("dirs");
        fs::write(file, text).expect("write the fixture file");
    }

    /// Fails by: a module of another extension, or a rule the module does not
    /// spell exactly, read as the row's own case.
    #[test]
    fn a_rego_row_declares_its_own_case_only_by_an_exact_test_rule() {
        let root = fixture("own-case");
        let module = "package p\n\ntest_limit_is_ten if {\n\ttrue\n}\n";
        put(&root, "policy/p.rego", module);
        put(&root, "policy/p.txt", module);
        let row = |source: &str, want: &str| Row {
            want: want.to_owned(),
            ..row_from(source)
        };
        let owns = |source: &str, want: &str| declares_own_case(&root, &row(source, want));
        assert!(owns("policy/p.rego", "limit_is_ten"));
        assert!(!owns("policy/p.rego", "limit"));
        assert!(!owns("policy/p.txt", "limit_is_ten"));
        assert!(!owns("policy/absent.rego", "limit_is_ten"));
    }

    /// Fails by: an arm's candidate name taken without checking it resolves
    /// back to the path, so an absent task names a gate that is not there.
    #[test]
    fn a_subject_takes_an_arms_name_only_when_that_name_resolves_back_to_it() {
        let root = fixture("subject-name");
        put(&root, "policy/limit.rego", "package limit\n");
        assert_eq!(subject_name(&root, "policy/limit.rego"), "limit");
        assert_eq!(
            subject_name(&root, "mise-tasks/absent.sh"),
            "mise-tasks/absent.sh"
        );
    }

    /// Fails by: a program read as runnable whether or not a file answers.
    #[test]
    fn a_program_resolves_only_where_a_file_answers_to_it() {
        let root = fixture("resolves");
        put(&root, "bin/tool.sh", "#!/bin/sh\n");
        assert!(resolves(&root, "bin/tool.sh"));
        assert!(!resolves(&root, "bin/absent.sh"));
        assert!(!resolves(&root, "batten-no-program-is-called-this"));
    }

    /// Fails by: the declaration arm reading outside its `scope` (or only
    /// outside it), or reading a path another arm's subject already claims,
    /// exactly or as a directory.
    #[test]
    fn the_declaration_arm_reads_only_its_scope_and_no_claimed_path() {
        let root = fixture("declaring-files");
        crate::gitwrite::init_on_main(&root).expect("a repository");
        let declaring = format!("#{ROW}a|s/x/y/|case\n");
        let paths = [
            "in/decl.txt",
            "out/decl.txt",
            "claimed/inner.txt",
            "exact.txt",
        ];
        for path in paths {
            put(&root, path, &declaring);
        }
        crate::gitwrite::commit_paths(&root, &paths.map(String::from), "fixture").expect("commit");
        let table = |scope: &[&str]| crate::config::Mutate {
            gates: Vec::new(),
            scope: scope.iter().map(|glob| (*glob).to_owned()).collect(),
            command: Vec::new(),
        };
        let mut scoped = BTreeMap::new();
        declaring_files(&root, &table(&["in/**"]), &mut scoped);
        assert_eq!(
            scoped.keys().map(String::as_str).collect::<Vec<_>>(),
            ["in/decl.txt"]
        );
        let mut claimed = BTreeMap::from([
            (String::from("dir-gate"), String::from("claimed")),
            (String::from("file-gate"), String::from("exact.txt")),
        ]);
        declaring_files(&root, &table(&[]), &mut claimed);
        assert_eq!(
            claimed.keys().map(String::as_str).collect::<Vec<_>>(),
            ["dir-gate", "file-gate", "in/decl.txt", "out/decl.txt"]
        );
    }

    /// Fails by: the build owed by a row the registered runner owns, or by a
    /// row already recorded caught. The staged directory is outside any cargo
    /// workspace, so the owed build fails at once rather than building one.
    #[test]
    fn the_build_is_owed_only_by_a_declared_uncaught_cargo_row() {
        let root = fixture("build-owed");
        put(
            &root,
            "policy/probe.rego",
            &format!("#{SUITE}crates/k/tests/it/a.rs\n#{ROW}one|s/x/y/|case_a\n"),
        );
        let staged = Staged {
            dir: fixture("build-owed-staged"),
            dirty: None,
        };
        let names = [String::from("probe")];
        let said = |registry: &Registry, caught: &std::collections::HashSet<String>| {
            let mut progress = Vec::new();
            let _ = build_if_owed(&root, &names, registry, caught, &staged, &mut progress);
            String::from_utf8(progress).expect("utf-8")
        };
        let none = std::collections::HashSet::new();
        let elsewhere = Registry::parse("cargo-mutants=policy/*.rego").expect("parses");
        let Some(gate) = resolve(&root, "probe") else {
            panic!("the module resolves to a gate");
        };
        let caught: std::collections::HashSet<String> = gate
            .rows
            .iter()
            .map(|row| row_key(&root, &gate, row))
            .collect();
        assert_eq!(
            said(&elsewhere, &none),
            "",
            "a row the registered runner owns"
        );
        assert_eq!(
            said(&Registry::default(), &caught),
            "",
            "every row recorded caught"
        );
        let owed = said(&Registry::default(), &none);
        assert!(owed.contains("building the cargo suites"), "{owed}");
    }

    /// CLOUD-2533: one gate's rows are judged across the shards, each by one,
    /// and a gate-level finding is reported by one shard. Every row is recorded
    /// caught, so no suite runs. Fails by: a sweep that ignores its shard for
    /// rows or for gate-level findings, numbers the gates unsorted, numbers a
    /// stopped gate's rows, or sweeps a gate named twice twice.
    #[test]
    fn a_sharded_sweep_judges_each_row_and_reports_each_gate_once() {
        let root = fixture("sweep-shard");
        crate::gitwrite::init_on_main(&root).expect("a repository");
        let rows = (0..5)
            .map(|row| format!("#{ROW}r{row}|s/x/y/|case_{row}\n"))
            .collect::<Vec<_>>()
            .concat();
        put(
            &root,
            "policy/probe.rego",
            &format!("#{SUITE}crates/k/tests/it/a.rs\n{rows}"),
        );
        put(&root, "crates/k/tests/it/a.rs", "\n");
        put(
            &root,
            "policy/mm-nosuite.rego",
            &format!("#{SUITE}crates/k/tests/it/absent.rs\n#{ROW}m0|s/x/y/|case_m\n"),
        );
        crate::gitwrite::commit_paths(
            &root,
            &[
                String::from("policy/probe.rego"),
                String::from("policy/mm-nosuite.rego"),
                String::from("crates/k/tests/it/a.rs"),
            ],
            "fixture",
        )
        .expect("commit");
        let Some(gate) = resolve(&root, "probe") else {
            panic!("the module resolves to a gate");
        };
        let work = fixture("sweep-shard-work");
        let keys: Vec<String> = gate
            .rows
            .iter()
            .map(|row| row_key(&root, &gate, row))
            .collect();
        fs::write(work.join(CAUGHT_RECORD), keys.join("\n")).expect("record every row caught");
        let names = [
            "zz-missing",
            "probe",
            "bb-missing",
            "aa-missing",
            "mm-nosuite",
            "probe",
        ]
        .map(String::from);
        let mut judged = Vec::new();
        let mut reported = Vec::new();
        for k in 0..2 {
            let mut progress = Vec::new();
            let sweep = sweep_shard(
                &root,
                &names,
                work.clone(),
                &Registry::default(),
                Some((k, 2)),
                &mut progress,
            )
            .expect("the sweep stages");
            let said = String::from_utf8(progress).expect("utf-8");
            judged.push(
                said.lines()
                    .filter_map(|line| line.split(" probe ").nth(1))
                    .filter_map(|rest| rest.split(' ').next())
                    .map(str::to_owned)
                    .collect::<Vec<_>>(),
            );
            reported.push(
                sweep
                    .findings
                    .iter()
                    .map(|finding| finding.gate.clone())
                    .collect::<Vec<_>>(),
            );
        }
        assert_eq!(
            judged,
            [vec!["r0", "r2", "r4"], vec!["r1", "r3"]],
            "each row once, numbered past the gate a missing suite stopped"
        );
        assert_eq!(
            reported,
            [
                vec![
                    String::from("aa-missing"),
                    String::from("mm-nosuite"),
                    String::from("zz-missing")
                ],
                vec![String::from("bb-missing")]
            ],
            "each gate-level finding once, by its sorted position"
        );
    }

    /// CLOUD-2533: a shard that owns no row stages nothing, so it pays no copy
    /// of the tree and no build. Fails by: the empty shard staged anyway.
    #[test]
    fn a_shard_owning_no_row_stages_nothing() {
        let root = fixture("sweep-empty-shard");
        let work = fixture("sweep-empty-shard-work");
        let sweep = sweep_shard(
            &root,
            &[String::from("aa-missing")],
            work.clone(),
            &Registry::default(),
            Some((1, 2)),
            &mut std::io::sink(),
        )
        .expect("nothing to stage");
        assert!(sweep.findings.is_empty(), "shard 0 reports the gate");
        assert_eq!((sweep.declared, sweep.gates), (0, 0));
        assert!(!work.join(".git").exists(), "the tree was never staged");
    }

    /// Fails by: the staged copy left without a repository, a path the
    /// checkout stopped tracking left staged, or an unchanged tracked file
    /// cleared and copied again (its timestamp, an input set here, then moves).
    #[test]
    fn a_restaged_tree_drops_what_is_untracked_and_keeps_what_is_unchanged() {
        let root = fixture("restage");
        crate::gitwrite::init_on_main(&root).expect("a repository");
        put(&root, "keep.txt", "kept\n");
        put(&root, "drop.txt", "dropped\n");
        crate::gitwrite::commit_paths(
            &root,
            &[String::from("keep.txt"), String::from("drop.txt")],
            "both",
        )
        .expect("commit");
        let work = fixture("restage-work");
        Staged::new(&root, work.clone()).expect("the first stage");
        assert!(
            work.join(".git").is_dir(),
            "the staged copy is a repository"
        );
        let set = std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_000_000_000);
        fs::File::options()
            .write(true)
            .open(work.join("keep.txt"))
            .expect("open the staged copy")
            .set_modified(set)
            .expect("set its timestamp");
        crate::gitwrite::commit_paths(&root, &[String::from("keep.txt")], "one").expect("commit");
        Staged::new(&root, work.clone()).expect("the second stage");
        assert!(
            !work.join("drop.txt").exists(),
            "a path no longer tracked is cleared"
        );
        let kept = fs::metadata(work.join("keep.txt"))
            .and_then(|meta| meta.modified())
            .expect("the kept file's timestamp");
        assert_eq!(kept, set, "an unchanged file is not rewritten");
    }

    /// Fails by: a shard outside `0 <= k < n` accepted, where `n = 0` divides
    /// by zero and `k >= n` judges a shard that does not exist; or a valid one
    /// refused.
    #[test]
    fn a_registered_run_refuses_a_shard_shard_parsed_never_yields() {
        let root = fixture("registered-shard-bounds");
        let changed = std::collections::BTreeSet::new();
        let run = |shard| {
            run_registered(
                &root,
                &Registry::default(),
                &changed,
                RunnerKind::Declared,
                shard,
            )
        };
        assert!(run(Some((0, 1))).is_ok(), "0/1 is a shard");
        for bad in [(0, 0), (2, 2), (3, 2)] {
            assert!(run(Some(bad)).is_err(), "{bad:?} is not a shard");
        }
    }

    /// Fails by: a runner other than `command` spawning anything, or the owned
    /// sources miscounted.
    #[test]
    fn only_the_command_runner_runs_and_every_owned_source_is_counted() {
        let root = fixture("registered");
        put(&root, "elsewhere/x.rs", "fn f() {}\n");
        let changed = std::collections::BTreeSet::from([String::from("elsewhere/x.rs")]);
        let declared = run_registered(
            &root,
            &Registry::default(),
            &changed,
            RunnerKind::Declared,
            None,
        )
        .expect("the declared runner returns at once");
        assert_eq!((declared.sources, declared.findings), (1, Vec::new()));
        let owned = Registry::parse("cargo-mutants=elsewhere/*.rs").expect("parses");
        let cargo_mutants = run_registered(
            &root,
            &owned,
            &changed,
            RunnerKind::CargoMutants,
            Some((0, 1)),
        )
        .expect("cargo-mutants is never spawned here");
        assert_eq!(
            (cargo_mutants.sources, cargo_mutants.findings),
            (1, Vec::new())
        );
    }

    /// Fails by: the wait answering anything but the child's own status and
    /// `false`, or leaving the group the child led alive once it exits — the
    /// background job then holds the fifo this case reads to its end open past
    /// the deadline.
    ///
    /// Through the module's own [`spawn`], so no spawn site exists for the case
    /// alone. That spawn captures to files it reads at the exit, before a stray
    /// job could write, so the job is observed through a fifo instead: the suite
    /// opens its write end and the job inherits it, and the read reaches its end
    /// only once every writer — the job included — is gone.
    #[test]
    fn a_suite_that_exits_is_answered_with_its_status_and_its_group_is_ended() {
        // Only unix has the group to end; elsewhere the wait is waited out.
        if !cfg!(unix) {
            return;
        }
        let dir = crate::scratch::scratch("mutate-suite-exits");
        let bound = std::time::Duration::from_secs(60);
        let made = spawn(
            &dir,
            Program::Suite("mkfifo"),
            &[String::from("held")],
            &[],
            bound,
        )
        .expect("mkfifo runs");
        assert_eq!(made.outcome, Outcome::Passed, "{}", made.output);
        let fifo = dir.join("held");
        let (send, said) = std::sync::mpsc::channel();
        // A thread, because opening a fifo's read end blocks until a writer
        // opens it — which is the suite, below.
        std::thread::spawn(move || {
            let read = crate::fsio::read_to_string(&fifo);
            let _ = send.send(read);
        });
        // The suite names its own pid and its job's, so a job that outlives the
        // group kill can be described rather than only waited out (CLOUD-2514).
        let ran = spawn(
            &dir,
            Program::Suite("sh"),
            &[
                String::from("-c"),
                String::from(
                    "echo $$ >leader; exec 3>held; (sleep 30; echo orphaned >&3) & echo $! >job; exit 3",
                ),
            ],
            &[],
            bound,
        )
        .expect("the wait answers");
        assert_eq!(ran.outcome, Outcome::Failed(Some(3)), "{}", ran.output);
        let Ok(read) = said.recv_timeout(std::time::Duration::from_secs(10)) else {
            panic!(
                "the job the suite left running outlived the group kill: {}",
                survivors(&dir)
            );
        };
        assert_eq!(
            read.expect("read the fifo to its end"),
            "",
            "the job the suite left running is ended with it"
        );
    }

    /// Fails by: the sweep sending nothing. The suite leads a group holding a
    /// `sleep 30` and waits on it, so only a sweep of that group returns it
    /// before the sleep would.
    ///
    /// Driven directly, because the interleaving that leaves a member behind is
    /// Darwin's alone (CLOUD-2514): on Linux the first kill never misses one.
    #[test]
    fn a_sweep_ends_what_is_left_in_a_group() {
        // Only unix has the group to sweep.
        if !cfg!(unix) {
            return;
        }
        let dir = crate::scratch::scratch("mutate-sweep");
        let bound = std::time::Duration::from_secs(60);
        let made = spawn(
            &dir,
            Program::Suite("mkfifo"),
            &[String::from("ready")],
            &[],
            bound,
        )
        .expect("mkfifo runs");
        assert_eq!(made.outcome, Outcome::Passed, "{}", made.output);
        let (send, swept) = std::sync::mpsc::channel();
        let suite = dir.clone();
        std::thread::spawn(move || {
            let _ = send.send(spawn(
                &suite,
                Program::Suite("sh"),
                &[
                    String::from("-c"),
                    String::from("sleep 30 & echo $$ >ready; wait"),
                ],
                &[],
                bound,
            ));
        });
        // The fifo's open blocks until the suite writes, so the read is the wait,
        // and it is taken on its own thread so a suite that never writes fails
        // the case within a bound instead of holding it.
        let (named, said) = std::sync::mpsc::channel();
        let ready = dir.join("ready");
        std::thread::spawn(move || {
            let _ = named.send(crate::fsio::read_to_string(ready));
        });
        let leader: u32 = said
            .recv_timeout(std::time::Duration::from_secs(20))
            .expect("the suite names itself")
            .expect("read the fifo")
            .trim()
            .parse()
            .expect("a pid");
        sweep_group(leader);
        let ran = swept
            .recv_timeout(std::time::Duration::from_secs(20))
            .expect("the swept suite returns before its sleep would")
            .expect("the wait answers");
        assert_ne!(ran.outcome, Outcome::Passed, "{}", ran.output);
    }

    /// What a group kill left behind in `dir`'s suite: the leader's and the job's
    /// pids as the suite wrote them, whether the leader's group still answers a
    /// probe, and each survivor's pid, parent, group, state and name.
    ///
    /// It signals nothing. A failing case's job is `sleep 30` and ends on its own,
    /// while any pid read here may already have been reused by the time `kill`
    /// would run, so a cleanup could only trade a bounded leak for a stranger.
    fn survivors(dir: &std::path::Path) -> String {
        let read = |name: &str| {
            crate::fsio::read_to_string(dir.join(name))
                .unwrap_or_default()
                .trim()
                .to_owned()
        };
        let (leader, job) = (read("leader"), read("job"));
        // Through the module's own `spawn`, as the case's suites are, so the
        // probe and the listing compile on every target the case is built for.
        let kill = |args: &[&str]| {
            spawn(
                dir,
                Program::Suite("kill"),
                &args.iter().map(|arg| (*arg).to_owned()).collect::<Vec<_>>(),
                &[],
                std::time::Duration::from_secs(10),
            )
            .map_or_else(
                |err| format!("kill: {err}"),
                |ran| format!("{:?}", ran.outcome),
            )
        };
        // An empty pid would ask `kill` about nothing, or every row about "".
        let named = |field: &str| !field.is_empty() && (field == leader || field == job);
        let group = if leader.is_empty() {
            String::from("no leader pid written")
        } else {
            kill(&["-0", "--", &format!("-{leader}")])
        };
        let rows = spawn(
            dir,
            Program::Suite("ps"),
            &[
                String::from("-A"),
                String::from("-o"),
                String::from("pid=,ppid=,pgid=,stat=,comm="),
            ],
            &[],
            std::time::Duration::from_secs(10),
        )
        .map(|listed| {
            listed
                .output
                .lines()
                .filter(|line| line.split_whitespace().take(3).any(&named))
                .map(str::to_owned)
                .collect::<Vec<_>>()
        });
        let listing = rows.map_or_else(|err| format!("ps: {err}"), |rows| rows.join(" / "));
        format!("leader {leader}, job {job}, group probe {group}, ps [{listing}]")
    }

    /// Fails by: a module's own case not judged at all, or a mutation that
    /// changed its code read as inert or as rewriting only its own row. Over a
    /// one-rule fixture whose module declares its own row and the case it names.
    #[test]
    fn a_rego_row_is_judged_by_its_modules_own_case() {
        let root = fixture("own-module");
        crate::gitwrite::init_on_main(&root).expect("a repository");
        put(
            &root,
            "batten.toml",
            "version = 1\n\n[[rule]]\nid = \"limit-probe\"\nkind = \"policy\"\n\
             scope = \"tree\"\nmodule = \"policy/limit.rego\"\nseverity = \"warn\"\n\
             no_fix_reason = \"this row exists to carry its module's own case\"\n\n\
             [[verdict]]\nid = \"the limit moved\"\ngloss = \"the limit is not ten\"\n\
             class = \"What this fixture's probe asserts, at the length explain answers with.\"\n\n\
             [[verdict.route]]\nid = \"read the limit\"\nkind = \"document\"\n\
             target = \"policy/limit.rego\"\n",
        );
        put(
            &root,
            "policy/limit.rego",
            &format!(
                "#{ROW}limit-moved|s/^limit := 10$/limit := 11/|limit_is_ten\n\
                 package batten\n\nrules contains \"limit-probe\"\n\nlimit := 10\n\n\
                 violation contains {{\n\t\"rule\": \"limit-probe\",\n\t\"verdict\": \"the limit moved\",\n\
                 }} if {{\n\tlimit != 10\n}}\n\n\
                 test_limit_is_ten if {{\n\tlimit == 10\n}}\n"
            ),
        );
        crate::gitwrite::commit_paths(
            &root,
            &[
                String::from("batten.toml"),
                String::from("policy/limit.rego"),
            ],
            "fixture",
        )
        .expect("commit");
        let Some(gate) = resolve(&root, "limit") else {
            panic!("the module resolves to a gate");
        };
        let [row] = gate.rows.as_slice() else {
            panic!("the module declares exactly one row");
        };
        assert!(declares_own_case(&root, row), "the row names its own case");
        let mut staged = Staged::new(&root, fixture("own-module-work")).expect("stage");
        assert_eq!(
            judge_by_module(&root, &mut staged, row).expect("the module judges"),
            Some(Verdict::Caught)
        );
    }
}
