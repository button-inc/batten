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
//! `.rego` module can therefore name `crates/batten/tests/<x>.rs` — the tier
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

/// The declaration markers, bare — the comment opener is [`OPENERS`]'s business.
///
/// Beside the code rather than in a manifest: a declaration in a second file is
/// a second authority that drifts.
///
/// **THE OPENER USED TO BE PART OF THE MARKER, AND THAT EXCLUDED AN ENTIRE
/// IMPLEMENTATION LANGUAGE** (CLOUD-1369). These read `#MUTANT `, matched with
/// `strip_prefix` and no trim, so a declaration could only live in a `#`-comment
/// file — bash or Rego. `#MUTANT` is not valid Rust, so no predicate in
/// `crates/batten/src/**` could carry one, while `obligations-bound` demands the
/// declared obligation file carry exactly that row. The pair was unsatisfiable
/// for every Rust change, and a shell suite was no escape because
/// `V-SHELL-RULE-ADDED` refuses adding one.
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

/// The namespace an inline task's name carries (CLOUD-1909).
///
/// **A PREFIX FOR `ENGINE_PREFIX`'s REASON, one file over.** The retirement
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
//MUTANT-SUITE crates/batten/tests/it/mutate.rs
//MUTANT task-block-unscoped|s@        Some(task) if task_manifest().as_deref() == Some(source) => task_block(&lines, task),@        Some(_) if task_manifest().as_deref() == Some(source) => Some(lines),@|a_task_gate_sweeps_only_its_own_block
//MUTANT suite-first-only|s@own_suites.get(&row.source)@own_suites.get(\&row.slug)@|each_preset_module_row_runs_under_its_own_declared_suite
//MUTANT registered-rows-swept-by-hand|s@^                if !gate.rows.is_empty() \&\& !gate.rows.iter().any(|row| registry.declares(row)) {$@                if false {@|a_change_to_a_rust_gate_is_judged_by_its_registered_runner
//MUTANT registered-row-judged-twice|s@^        for row in gate.rows.iter().filter(|row| registry.declares(row)) {$@        for row in \&gate.rows {@|a_registered_runners_rows_are_never_swept_by_the_declared_runner
//MUTANT every-gate-touched|s@^        \.filter(\x7cname\x7c {$@        .filter(\x7cname\x7c { true \x7c\x7c@|a_change_touching_no_gate_sweeps_nothing
fn declaring_lines(root: &Path, name: &str, source: &str) -> Option<Vec<String>> {
    let lines = lines_of(root, source)?;
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

//MUTANT unrecognized-suite-guessed|s@^            return None;$@            return Some(Suite::Pytest { path: path.to_owned() });@|an_unrecognized_suite_is_reported_not_run
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
    /// Each source's OWN `#MUTANT-SUITE`, keyed by that source.
    ///
    /// **ONE DECLARATION PER SOURCE, NOT ONE PER GATE.** A preset gate is a
    /// directory of modules, and each module declares the suite its own cases
    /// live in. Keeping only the first declaration found made every later
    /// module's line decide nothing: every row was judged under the first
    /// module's suite, so the census counted the wrong file and a declaration
    /// naming a missing file was never checked. [`Gate::suite_for`] reads this.
    pub own_suites: BTreeMap<String, Suite>,
    /// The declared mutations, in file then declaration order.
    pub rows: Vec<Row>,
    /// The owning row a known-dead predicate declares, echoed on a survivor and
    /// deciding nothing.
    pub owner: Option<String>,
}

impl Gate {
    /// The suite a row is judged under: its own source's declaration, else
    /// the gate's, else none.
    #[must_use]
    pub fn suite_for(&self, row: &Row) -> Option<&Suite> {
        self.own_suites.get(&row.source).or(self.suite.as_ref())
    }

    /// Every suite this gate's rows run under, the gate's own first, each once.
    #[must_use]
    pub fn suites(&self) -> Vec<&Suite> {
        let mut all: Vec<&Suite> = self.suite.iter().collect();
        for suite in self.own_suites.values() {
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
    /// The row does not carry exactly three fields.
    MalformedRow { fields: usize },
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
/// stopped resolving every landed `.rego` declaration — a suite reading as
/// undeclared, an owner and an exemption reading as absent. Compile-clean
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
    let mut found: Vec<String> = std::fs::read_dir(&dir)
        .map(|entries| {
            entries
                .filter_map(std::result::Result::ok)
                .filter_map(|entry| {
                    let file = entry.file_name().to_string_lossy().into_owned();
                    has_extension(&file, "rego").then(|| format!("{PRESETS}/{name}/{file}"))
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
    // THE INLINE-TASK ARM (CLOUD-1909), LAST OF ALL, for the engine arm's reason:
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
    let sources = sources_for(root, name);
    if sources.is_empty() {
        return None;
    }
    let mut rows = Vec::new();
    let mut malformed = Vec::new();
    let mut suite = None;
    let mut unrunnable = None;
    let mut own_suites = BTreeMap::new();
    let mut owner = None;
    for source in &sources {
        let Some(lines) = declaring_lines(root, name, source) else {
            continue;
        };
        if let Some(own) = declared(&lines, SUITE) {
            // A source naming a path no runner here recognizes is reported as
            // `no-suite` under that path, never judged under another source's
            // suite and never handed to a runner chosen by guesswork.
            match Suite::declared(&own) {
                Some(resolved) => {
                    own_suites.insert(source.clone(), resolved.clone());
                    suite = suite.or(Some(resolved));
                }
                None => unrunnable = unrunnable.or(Some(own)),
            }
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
    for (head, fields) in malformed {
        rows.push(Row {
            slug: head,
            script: String::new(),
            want: format!("\u{0}malformed:{fields}"),
            source: sources[0].clone(),
        });
    }
    Some(Gate {
        name: name.to_owned(),
        sources,
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
//MUTANT-SUITE crates/batten/tests/it/mutate.rs
//MUTANT committed-set-unread|s@^    let declared = \&table.gates;$@    let declared = \&table.scope;@|census_runs_on_the_set_batten_toml_declares
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
/// the task name for `mise-tasks/X.sh`, `engine-x` for an engine module, the
/// preset for a preset's module — and its own path, the file arm's name, for a
/// file no other arm names.
///
/// **CHECKED BY RESOLVING IT BACK**, so a name is only offered where
/// [`sources_for`] would take it to this very file: a module whose stem a shell
/// task also carries resolves to the task, and gets its path instead.
fn subject_name(root: &Path, path: &str) -> String {
    let engine = format!("{ENGINE}/");
    let presets = format!("{PRESETS}/");
    let candidates = [
        path.strip_prefix("mise-tasks/")
            .and_then(|rest| rest.strip_suffix(".sh"))
            .map(str::to_owned),
        path.strip_prefix("policy/")
            .and_then(|rest| rest.strip_suffix(".rego"))
            .map(str::to_owned),
        path.strip_prefix(&engine)
            .and_then(|rest| rest.strip_suffix(".rs"))
            .map(|stem| format!("{ENGINE_PREFIX}{}", stem.replace('_', "-"))),
        path.strip_prefix(&presets)
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
/// [`Gate::suites`]: a weaker suite is the commonest way a gate stops
/// discriminating, so a change to the suite alone must re-sweep its rows.
///
/// A changed path inside a PRESET gate's directory touches that gate too, and
/// that is what reaches a DELETED module: `resolve` reads the tree as it is now,
/// so a module the change removed is no longer among the gate's sources, and a
/// match on sources alone let the deletion pass unswept (review of #1099).
///
/// A gate none of whose rows the DECLARED runner owns is not touched: another
/// registered runner owns every source it mutates ([`Registry::owner`]) and
/// judges the change itself ([`run_registered`]). A row is never judged by two
/// runners, and never by none.
///
/// A name that resolves to nothing is KEPT. Narrowing it away would turn the
/// sweep's `no-such-gate` report into silence; could-not-look widens here as it
/// does in `ci suites`.
#[must_use]
pub fn touched(
    root: &Path,
    names: &[String],
    changed: &std::collections::BTreeSet<String>,
    registry: &Registry,
) -> Vec<String> {
    names
        .iter()
        .filter(|name| {
            resolve(root, name).is_none_or(|gate| {
                if !gate.rows.is_empty() && !gate.rows.iter().any(|row| registry.declares(row)) {
                    return false;
                }
                changed_by(&gate, name, changed)
            })
        })
        .cloned()
        .collect()
}

/// Whether `changed` moves `gate`: a changed path is one of its sources, one of
/// [`Gate::suites`], or inside its preset directory ([`touched`]'s three arms).
//MUTANT source-change-ignored|s@^    let by_source = .*;$@    let by_source = false;@|a_change_to_one_gate_sweeps_only_that_gate
//MUTANT suite-change-ignored|s@^    let by_suite = .*;$@    let by_suite = false;@|a_change_to_a_suite_sweeps_its_gate
//MUTANT deleted-module-ignored|s@^    let by_preset = .*;$@    let by_preset = false;@|a_deleted_preset_module_sweeps_its_gate
fn changed_by(gate: &Gate, name: &str, changed: &std::collections::BTreeSet<String>) -> bool {
    let by_source = gate.sources.iter().any(|path| changed.contains(path));
    let by_suite = gate.suites().iter().any(|s| changed.contains(s.path()));
    let dir = format!("{PRESETS}/{name}/");
    let by_preset = changed.iter().any(|path| path.starts_with(&dir));
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

/// Which registered runner this invocation runs, by its id. Unset runs the
/// declared runner, which is what `verify` does; a CI job sets it per shard.
pub const RUNNER: &str = "MUTANT_RUNNER";

/// The shard a registered runner takes, as `k/n` with `k` counted from zero.
pub const SHARD: &str = "MUTANT_SHARD";

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
}

impl RunnerKind {
    /// The id the registry and `$MUTANT_RUNNER` spell.
    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            RunnerKind::Declared => "declared",
            RunnerKind::CargoMutants => "cargo-mutants",
        }
    }

    /// The runner an id names, or `None` for an id no runner carries.
    #[must_use]
    pub fn parse(id: &str) -> Option<Self> {
        [RunnerKind::Declared, RunnerKind::CargoMutants]
            .into_iter()
            .find(|kind| kind.id() == id)
    }
}

//MUTANT-SUITE crates/batten/src/mutate.rs
//MUTANT registry-owns-nothing|s@^            .filter(|(_, glob)| crate::rules::glob_match(glob, path))$@            .filter(|_| false)@|a_registered_glob_owns_its_sources_and_the_declared_runner_the_rest
//MUTANT overlap-picks-one|s@^        let mut owners = owners.into_iter();$@        let mut owners = owners.into_iter().take(1);@|a_source_two_runners_claim_has_no_owner
//MUTANT declared-runner-takes-globs|s@^            if kind == RunnerKind::Declared {$@            if false {@|a_registry_naming_no_runner_or_giving_the_declared_one_globs_is_refused
//MUTANT declared-suites-unscoped|s@^        if has_extension(suite, "rs")$@        if false@|a_sources_scope_is_its_own_tests_and_every_suite_it_declares
//MUTANT missed-unread|s@^    let missed: Vec<String> = lines("missed.txt")@    let missed: Vec<String> = lines("absent.txt")@|a_missed_mutant_is_a_survivor_named_by_pointer_alone
//MUTANT failed-run-reads-caught|s@^        } else if !ran.ok \&\& found.is_empty() {$@        } else if false {@|a_failed_run_with_nothing_missed_is_never_every_mutant_caught
//MUTANT-SUITE crates/batten/tests/it/mutate.rs
/// Which registered runner owns which sources.
///
/// Every source has exactly one owner: the first registered runner whose glob
/// matches it, else [`RunnerKind::Declared`]. Two runners matching one source is
/// [`Registry::owner`]'s error, because a source judged twice is a second
/// mutation system and a source judged by the wrong one is a silent gap.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Registry {
    owns: Vec<(RunnerKind, String)>,
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
                    "{RUNNERS} names `{}`, which is no runner: the runners are `declared` and \
                     `cargo-mutants`",
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
        Ok(Self { owns })
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
/// THE LOCAL HALF OF A RUNNER THAT RUNS ELSEWHERE. `verify` does not run
/// cargo-mutants (a branch's mutants cost about 40s each, measured, and a CI
/// matrix shards them); what it CAN decide is that the runner the registry
/// names is pinned and resolves, so the CI job is not the first to find out.
#[must_use]
pub fn unresolvable(root: &Path, registry: &Registry) -> Vec<Finding> {
    registry
        .registered()
        .into_iter()
        .filter(|kind| {
            let args: Vec<String> = match kind {
                RunnerKind::Declared => return false,
                RunnerKind::CargoMutants => {
                    vec![String::from("mutants"), String::from("--version")]
                }
            };
            !spawn(root, Program::Cargo, &args, &[], HOUSEKEEPING_BOUND).is_ok_and(|ran| ran.ok)
        })
        .map(|kind| Finding {
            gate: kind.id().to_owned(),
            slug: None,
            verdict: Verdict::RunnerAbsent,
            owner: None,
        })
        .collect()
}

/// Run `kind` over the sources it owns that changed since `base`.
///
/// For cargo-mutants, one invocation per source, `--in-diff` over the change
/// and `--in-place` in the staged copy (the book's CI recipe; the copy is a
/// repository, so a suite asking git about its tree is answered). Each run's
/// tests are that source's own unit tests plus every suite it declares with
/// `MUTANT-SUITE` ([`test_scope`]), so the obligation a row already states is
/// what bounds the cost.
///
/// # Errors
///
/// A tree that cannot be staged, or a diff that cannot be written.
pub fn run_registered(
    root: &Path,
    base: &str,
    changed: &std::collections::BTreeSet<String>,
    registry: &Registry,
    kind: RunnerKind,
    shard: Option<&str>,
    work: &Path,
) -> Result<Registered> {
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
    if kind == RunnerKind::Declared || sources.is_empty() {
        return Ok(result);
    }
    let diff = spawn(
        root,
        Program::Git,
        &[
            String::from("diff"),
            String::from("--no-color"),
            String::from("--no-ext-diff"),
            base.to_owned(),
            String::from("--"),
        ]
        .into_iter()
        .chain(sources.iter().cloned())
        .collect::<Vec<_>>(),
        &[],
        HOUSEKEEPING_BOUND,
    )?;
    if !diff.ok {
        bail!("mutate: `git diff {base}` failed, so the change cannot be named to cargo-mutants");
    }
    let staged = Staged::new(root, work.to_path_buf())?;
    let runs = work.join("cargo-mutants");
    fs::create_dir_all(&runs)
        .with_context(|| format!("mutate: could not create {}", runs.display()))?;
    let patch = runs.join("change.diff");
    crate::durable::replace(&patch, diff.output)
        .with_context(|| format!("mutate: could not write {}", patch.display()))?;
    for (index, source) in sources.iter().enumerate() {
        let Some(scope) = test_scope(root, source) else {
            result.findings.push(Finding {
                gate: kind.id().to_owned(),
                slug: Some(source.clone()),
                verdict: Verdict::NoSuite {
                    suite: String::from("no cargo target compiles it"),
                },
                owner: None,
            });
            continue;
        };
        let output = runs.join(index.to_string());
        let _ = fs::remove_dir_all(&output);
        let mut args = vec![
            String::from("mutants"),
            String::from("--in-place"),
            String::from("--no-shuffle"),
            String::from("--in-diff"),
            patch.to_string_lossy().into_owned(),
            String::from("--file"),
            source.clone(),
            String::from("--test-tool"),
            String::from("nextest"),
            String::from("--output"),
            output.to_string_lossy().into_owned(),
        ];
        if let Some(shard) = shard {
            args.extend([String::from("--shard"), shard.to_owned()]);
        }
        args.extend([String::from("--"), String::from("-E"), scope]);
        let ran = spawn(
            staged.dir(),
            Program::Cargo,
            &args,
            &suite_env(root),
            runner_bound(),
        )?;
        let outcome = read_outcomes(&output.join("mutants.out"));
        result.mutants += outcome.ran;
        result.findings.extend(outcome.findings(kind, source, &ran));
    }
    Ok(result)
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

/// What one cargo-mutants run wrote to its `mutants.out`.
#[derive(Debug, Default, PartialEq, Eq)]
struct Outcomes {
    /// Every mutant it ran, whatever became of it.
    ran: usize,
    /// `path:line:col` of each mutant no test caught.
    missed: Vec<String>,
    /// `path:line:col` of each mutant whose tests ran out of time.
    timeout: Vec<String>,
    /// Whether the unmutated baseline failed, so no catch means anything.
    baseline_failed: bool,
}

/// The pointer of one `mutants.out` line, `path:line:col`, never the mutation's
/// text, which quotes the source (rule 4).
fn pointer_of(line: &str) -> Option<String> {
    let mut fields = line.splitn(4, ':');
    let path = fields.next()?;
    let row = fields.next()?;
    let column = fields.next()?;
    (row.parse::<u32>().is_ok() && column.parse::<u32>().is_ok())
        .then(|| format!("{path}:{row}:{column}"))
}

/// Read a run's outcome files. Absent files are empty: a run that never got as
/// far as writing them is told apart by [`Outcomes::findings`] from its exit.
fn read_outcomes(dir: &Path) -> Outcomes {
    let lines = |name: &str| -> Vec<String> {
        fs::read_to_string(dir.join(name))
            .unwrap_or_default()
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(str::to_owned)
            .collect()
    };
    let caught = lines("caught.txt").len();
    let unviable = lines("unviable.txt").len();
    let missed: Vec<String> = lines("missed.txt")
        .iter()
        .filter_map(|l| pointer_of(l))
        .collect();
    let timeout: Vec<String> = lines("timeout.txt")
        .iter()
        .filter_map(|l| pointer_of(l))
        .collect();
    let baseline_failed = fs::read_to_string(dir.join("outcomes.json"))
        .ok()
        .and_then(|text| serde_json::from_str::<serde_json::Value>(&text).ok())
        .and_then(|json| {
            json.get("outcomes")?.as_array().map(|outcomes| {
                outcomes.iter().any(|outcome| {
                    outcome.get("scenario").and_then(serde_json::Value::as_str) == Some("Baseline")
                        && outcome.get("summary").and_then(serde_json::Value::as_str)
                            != Some("Success")
                })
            })
        })
        .unwrap_or(false);
    Outcomes {
        ran: caught + unviable + missed.len() + timeout.len(),
        missed,
        timeout,
        baseline_failed,
    }
}

impl Outcomes {
    /// The findings one run over `source` amounts to.
    ///
    /// A run that failed with nothing missed and nothing timed out decided
    /// nothing: a failed baseline is `case-already-red`, anything else is
    /// `suite-did-not-run`. Neither may read as every mutant caught.
    fn findings(&self, kind: RunnerKind, source: &str, ran: &Ran) -> Vec<Finding> {
        let at = |slug: &str, verdict: Verdict| Finding {
            gate: kind.id().to_owned(),
            slug: Some(slug.to_owned()),
            verdict,
            owner: None,
        };
        let mut found: Vec<Finding> = self
            .missed
            .iter()
            .map(|pointer| {
                at(
                    pointer,
                    Verdict::Survived {
                        want: String::from("in-diff"),
                    },
                )
            })
            .chain(
                self.timeout
                    .iter()
                    .map(|pointer| at(pointer, Verdict::SuiteTimedOut { seconds: 0 })),
            )
            .collect();
        if ran.timed_out {
            found.push(at(
                source,
                Verdict::SuiteTimedOut {
                    seconds: runner_bound().as_secs(),
                },
            ));
        } else if !ran.ok && found.is_empty() {
            found.push(at(
                source,
                if self.baseline_failed {
                    Verdict::CaseAlreadyRed {
                        want: String::from("baseline"),
                    }
                } else {
                    Verdict::SuiteDidNotRun {
                        want: String::from("cargo mutants"),
                    }
                },
            ));
        }
        found
    }
}

/// The nextest filterset of the tests that judge `source`: its own tests, and
/// every Rust suite it declares with `MUTANT-SUITE`, each inside its package.
///
/// `None` when no cargo target compiles the source, so nothing could be named.
#[must_use]
pub fn test_scope(root: &Path, source: &str) -> Option<String> {
    let mut terms = vec![tests_of(root, source)?];
    for line in lines_of(root, source).unwrap_or_default() {
        let Some(suite) = strip_marker(&line, SUITE) else {
            continue;
        };
        let suite = suite.trim();
        if has_extension(suite, "rs")
            && let Some(term) = tests_of(root, suite)
            && !terms.contains(&term)
        {
            terms.push(term);
        }
    }
    Some(terms.join(" | "))
}

/// The filterset term naming the tests compiled from `path`, inside its package.
///
/// Cargo's own layout decides it, never this repository's: `src/lib.rs` is the
/// library's whole unit-test set and `src/a/b.rs` its `a::b::` module;
/// `tests/<t>.rs` and `tests/<t>/main.rs` are the target `<t>`, and
/// `tests/<t>/<m>.rs` its `<m>::` module.
fn tests_of(root: &Path, path: &str) -> Option<String> {
    let (package, dir) = package_of(root, path)?;
    let relative = Path::new(path)
        .strip_prefix(&dir)
        .ok()?
        .to_string_lossy()
        .replace('\\', "/");
    let stem = relative.strip_suffix(".rs")?;
    let term = if let Some(module) = stem.strip_prefix("src/") {
        let module = module.strip_suffix("/mod").unwrap_or(module);
        match module {
            "lib" => String::from("kind(lib)"),
            "main" => String::from("kind(bin)"),
            _ => match module.strip_prefix("bin/") {
                Some(binary) => format!("binary({binary})"),
                None => format!("kind(lib) & test(/^{}::/)", module.replace('/', "::")),
            },
        }
    } else {
        let test = stem.strip_prefix("tests/")?;
        match test.split_once('/') {
            None => format!("binary({test})"),
            Some((target, "main")) => format!("binary({target})"),
            Some((target, module)) => {
                format!(
                    "binary({target}) & test(/^{}::/)",
                    module.replace('/', "::")
                )
            }
        }
    };
    Some(format!("(package({package}) & {term})"))
}

/// The package whose manifest is nearest above `path`, and that manifest's
/// directory, repo-relative.
fn package_of(root: &Path, path: &str) -> Option<(String, PathBuf)> {
    let mut dir = Path::new(path).parent();
    while let Some(candidate) = dir {
        if let Ok(text) = fs::read_to_string(root.join(candidate).join("Cargo.toml"))
            && let Ok(manifest) = text.parse::<toml::Table>()
            && let Some(name) = manifest
                .get("package")
                .and_then(|package| package.get("name"))
                .and_then(toml::Value::as_str)
        {
            return Some((name.to_owned(), candidate.to_path_buf()));
        }
        dir = candidate.parent();
    }
    None
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
    let wanted = std::fs::read(from)?;
    if std::fs::read(to).is_ok_and(|have| have == wanted) {
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
    crate::durable::replace(dir.join(MANIFEST), manifest.join("\n"))
        .context("mutate: could not record what was staged")?;
    Ok(())
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
    /// Whether [`suite_bound`] expired and this process killed the child
    /// (CLOUD-1860).
    ///
    /// **CARRIED RATHER THAN INFERRED, because inferring it is the defect.** A
    /// killed child wrote no case line, so `selected` is 0 and the caller
    /// reported `names-no-case` — *a filter that matches nothing* — for a case
    /// that is present, reachable and green. That sends whoever reads the sweep
    /// to repair a declaration which is already correct, and it is how 109 of 341
    /// declared mutations sat unlooked-at while the verb reported coverage.
    pub timed_out: bool,
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
    /// Applies a `#MUTANT` row, whose script IS a sed program: the declared row
    /// language every module authors against. An in-process interpreter would be
    /// a second implementation of it, drifting from the sed the author tested with.
    Sed,
    /// Builds the staged tree's test binaries once before any row is timed
    /// (CLOUD-1910). There is no in-process compiler.
    Cargo,
    /// The consumer's declared suite runner, re-run against the mutant: the verb.
    Suite(&'a str),
    /// Writes the unified diff `cargo mutants --in-diff` reads (CLOUD-1746).
    /// `gix` computes a tree delta but writes no unified patch, and a second
    /// patch writer would be a second reading of what changed.
    Git,
}

impl Program<'_> {
    const fn name(&self) -> &str {
        match self {
            Program::Sed => "sed",
            Program::Cargo => "cargo",
            Program::Git => "git",
            Program::Suite(program) => program,
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
    let program = program.name();
    #[expect(
        clippy::disallowed_types,
        reason = "stays: staging a tree and re-running a suite against it IS this module's effect (CLOUD-1267), and `Program` is the closed set it may run — sed and cargo each document on their variant why no in-process route exists, and a suite is the consumer's declared runner (CLOUD-1924)"
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
    command.stdout(std::process::Stdio::from(
        fs::File::create(&out_path) // stream: a child's stdout sink
            .with_context(|| format!("mutate: could not open {}", out_path.display()))?,
    ));
    command.stderr(std::process::Stdio::from(
        fs::File::create(&err_path) // stream: a child's stderr sink
            .with_context(|| format!("mutate: could not open {}", err_path.display()))?,
    ));
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
    // The ONE place a `Ran` may say `timed_out`: `finish` describes a child that
    // reached its own exit, and only the bound expiring here makes that untrue.
    Ok(Ran {
        timed_out,
        ..finish(status, &out_path, &err_path, &capture)
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
//MUTANT hung-suite-not-reported|s@^        Err(_) => true,$@        Err(_) => false,@|a_suite_that_hangs_is_ended_by_the_sweeps_own_bound
//MUTANT suite-reap-leader-only|s@^        let _ = rustix::process::kill_process_group(group, @        let _ = rustix::process::kill_process(group, @|a_suite_that_hangs_is_ended_by_the_sweeps_own_bound
//MUTANT suite-ungrouped|s@^    crate::exec::lead_group(&mut command);$@    let _ = \&mut command;@|a_suite_that_hangs_is_ended_by_the_sweeps_own_bound
//MUTANT forwarding-unadopted|s@^    forwarding.adopt(child.id())?;$@@|a_signalled_sweep_takes_its_suite_with_it
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
            let _ = worker.join();
            let _ = child.wait();
            return Err(failed);
        }
        Err(_) => true,
    };
    kill_group(pid);
    let _ = worker.join();
    let status = child.wait()?;
    Ok((status, timed_out))
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
    // Restores the default disposition and raises on self, so this does not
    // return.
    signal_hook::low_level::emulate_default_handler(signal)
        .context("mutate: re-raise the signal the sweep was sent")
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
    let mut output = fs::read_to_string(out_path).unwrap_or_default();
    output.push_str(&fs::read_to_string(err_path).unwrap_or_default());
    // Best effort: a capture left behind is a few bytes under the system temp
    // directory, and failing a sweep over housekeeping would trade a real
    // verdict for tidiness.
    let _ = fs::remove_dir_all(capture);
    Ran {
        ok: status.success(),
        output,
        // The ordinary path. The hang path above overrides it, and it is the ONE
        // caller that may: a `Ran` built anywhere else describes a child that
        // reached its own exit.
        timed_out: false,
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
/// The bound for the sweep's own housekeeping — staging a git repository,
/// applying a `sed` script — which is not a suite and must not borrow one's
/// number (CLOUD-1860).
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
/// No grace, for `exec::escalate_group`'s measured reason: a suite past its bound
/// is hung by definition, and a polite signal it ignores only spends the bound
/// again. The leader is signalled as well so that a group that somehow did not
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

//MUTANT tofu-arm-never-initialises|s@^        let _ = spawn(&module, Program::Suite("tofu"), &init, &env, build_bound());$@        let _ = (module, init);@|a_tofu_suite_is_initialised_before_it_runs
/// Run a gate's suite against the staged tree, filtered to `want` where its
/// harness can filter, and read the named case's own verdict back.
///
/// **A RUNNER THAT WILL NOT SPAWN IS THIS ROW'S `suite-did-not-run`, NOT THE
/// SWEEP'S ABORT** (CLOUD-2160). The native harnesses come from the `PATH` the
/// invoking task provides, exactly as `sed` and `cargo` do, so one missing
/// program used to end the whole sweep with an error naming nothing about the
/// gates it never reached.
fn run_suite(staged: &Staged, root: &Path, suite: &Suite, want: &str) -> Selection {
    let env = suite_env(root);
    let dir = staged.dir();
    // Where a `JUnit` report lands for the one arm whose verdict is a file
    // rather than a stream. Beside the captures, never inside the tree under
    // judgement.
    let junit = std::env::temp_dir().join(format!(
        "batten-mutate-junit-{}-{}.xml",
        std::process::id(),
        CAPTURE.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    let _ = fs::remove_file(&junit);
    if matches!(suite, Suite::Cargo { .. }) {
        // BUILT UNDER THE BUILD BOUND FIRST, THEN TIMED (review of #962). A
        // mutated source must be recompiled, and paying that inside the
        // per-case bound is how a slow compile reads as `suite-did-not-run`.
        // A build that fails here is left for the timed run to report.
        let build = vec![String::from("test"), String::from("--no-run")];
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
    let (cwd, argv) = invocation(dir, suite, want, &junit);
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
            selected: libtest_lines(&ran.output),
            ok: ran.ok && !ran.output.contains("error: could not compile"),
            reach: Reach::of(libtest_ran(&ran.output), false),
        },
        Suite::Tofu { .. } => tofu_verdict(&ran.output, want),
        Suite::Kyverno { .. } => kyverno_verdict(&ran.output, want),
        Suite::Conftest { path } => {
            conftest_verdict(&ran.output, want, &lines_of(dir, path).unwrap_or_default())
        }
        Suite::Pytest { .. } => pytest_verdict(&fs::read_to_string(&junit).unwrap_or_default()),
    };
    let _ = fs::remove_file(&junit);
    if ran.timed_out {
        return Selection {
            reach: Reach::TimedOut,
            ..selection
        };
    }
    selection
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
        Suite::Cargo { .. } => (dir.to_path_buf(), argv(&["cargo", "test", "--", want])),
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

/// The named `run`'s verdict out of `tofu test -json`'s machine-readable lines.
///
/// Measured against `tofu` 1.13.1 (the recorded fixtures): each run reports a
/// `test_run` line carrying `pass`, `fail` or `error`, and a module that does not
/// parse prints an error `diagnostic` and NO `test_run` line at all — so that
/// shape is the errored one, and reading it as a failure would call every
/// parse-breaking mutation caught. The `version` line opens every run, so it is
/// what says the harness started.
//MUTANT errored-case-read-as-killed|s@^        _ => (0, false, diagnosed && !any_run),$@        _ => (usize::from(diagnosed), false, false),@|an_errored_tofu_run_is_could_not_look
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
    let status = results.as_ref().and_then(|results| {
        results
            .iter()
            .find(|result| {
                let named = |key: &str| result[key].as_str().map(str::to_owned);
                named("POLICY") == policy
                    && named("RULE") == rule
                    && resource.as_ref().is_some_and(|want| {
                        named("RESOURCE")
                            .is_some_and(|got| got == *want || got.ends_with(&format!("/{want}")))
                    })
            })
            .and_then(|result| result["RESULT"].as_str().map(str::to_ascii_lowercase))
    });
    let errored = load_error || status.as_deref() == Some("error");
    let selected = usize::from(matches!(status.as_deref(), Some("pass" | "fail")));
    Selection {
        selected,
        ok: status.as_deref() == Some("pass"),
        reach: Reach::of(
            results.is_some() || output.contains("Test Summary:"),
            errored,
        ),
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
    let ran = spawn(staged.dir(), Program::Sed, &args, &[], HOUSEKEEPING_BOUND)?;
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
//MUTANT shared-line-uncounted|s@^        \.filter(\x7c(line, _)\x7c strip_marker(line\.trim_start(), "MUTANT")\.is_none())$@        .filter(\x7c(line, _)\x7c !(before.contains(line) \&\& after.contains(line)) \&\& strip_marker(line.trim_start(), "MUTANT").is_none())@|a_changed_line_repeated_elsewhere_in_the_file_is_still_a_changed_code_line
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
    // The row's OWN source's suite, never merely the gate's first: a preset
    // gate is several modules, each naming where its cases live.
    let Some(suite) = gate.suite_for(row) else {
        return Ok(Verdict::NoSuite {
            suite: String::from(UNDECLARED),
        });
    };

    // THE CASE MUST BE GREEN BEFORE IT IS MUTATED. "Red under mutation" is only
    // evidence if the row was green without it: a case that CANNOT pass — an
    // assertion that never holds, a fixture that never builds — is red either
    // way, and every mutation aimed at it reads as caught. Costs one extra
    // filtered run per row, which is what an anti-vacuity term is worth.
    let clean = run_suite(staged, root, suite, &row.want);
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

    let mutated = run_suite(staged, root, suite, &row.want);
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

/// Sweep the enforced set.
///
/// # Errors
///
/// A tree that cannot be staged is could-not-look (→ exit `3`).
pub fn sweep(root: &Path, names: &[String], work: PathBuf) -> Result<Sweep> {
    sweep_owned(root, names, work, &Registry::default())
}

/// [`sweep`], judging only the rows the declared runner owns under `registry`;
/// a row another runner owns is that runner's ([`run_registered`]).
///
/// # Errors
///
/// [`sweep`]'s.
pub fn sweep_owned(
    root: &Path,
    names: &[String],
    work: PathBuf,
    registry: &Registry,
) -> Result<Sweep> {
    let mut staged = Staged::new(root, work)?;
    // BUILD ONCE, BEFORE ANY ROW IS TIMED (CLOUD-1910). Best effort: a build that
    // fails leaves every Cargo row to report `suite-did-not-run` on its own, which
    // is the honest verdict, so nothing is decided here.
    if names
        .iter()
        .filter_map(|name| resolve(root, name))
        .any(|gate| {
            gate.suites()
                .into_iter()
                .any(|suite| matches!(suite, Suite::Cargo { .. }))
        })
    {
        let args = vec![String::from("test"), String::from("--no-run")];
        let _ = spawn(
            staged.dir(),
            Program::Cargo,
            &args,
            &suite_env(root),
            build_bound(),
        );
    }
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
            findings.push(Finding {
                gate: name.clone(),
                slug: None,
                verdict: Verdict::NoSuite { suite },
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
        for row in gate.rows.iter().filter(|row| registry.declares(row)) {
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
    // INLINE TASKS, OPT-IN BY DECLARATION (CLOUD-1909), on the engine arm's terms
    // above: most of the manifest's tasks run, build or report and owe nothing, so
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
/// **ON THE ENGINE AND INLINE-TASK ARMS' TERMS, AND ONLY UNDER A TABLE.** A
/// consumer's gates live wherever its tree keeps them — `.tf`, YAML, `.rego`,
/// `.py` — so no directory list can find them, and a file that declares rows is
/// exactly one that owes a sweep. Held to the set like those arms: a declaring
/// file no gate entry covers reads `uncovered`. Off without a table, so a
/// census that declares none is unchanged.
//MUTANT declaring-file-not-a-subject|s@^        if declaring {$@        if false \&\& declaring {@|a_declaring_file_outside_the_set_is_uncovered
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
pub fn census(root: &Path, names: &[String], table: Option<&crate::config::Mutate>) -> Census {
    let subjects = subjects(root, table);
    let mut findings = Vec::new();
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
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn row_from(source: &str) -> Row {
        Row {
            slug: String::from("s"),
            script: String::from("s@a@b@"),
            want: String::from("w"),
            source: source.to_owned(),
        }
    }

    #[test]
    fn a_registered_glob_owns_its_sources_and_the_declared_runner_the_rest() {
        let registry = Registry::parse("cargo-mutants=crates/**/*.rs").expect("parses");
        assert_eq!(
            registry
                .owner("crates/batten/src/drain.rs")
                .expect("one owner"),
            RunnerKind::CargoMutants
        );
        assert_eq!(
            registry.owner("policy/filed-here.rego").expect("one owner"),
            RunnerKind::Declared
        );
        assert!(!registry.declares(&row_from("crates/batten/src/drain.rs")));
        assert!(registry.declares(&row_from("policy/filed-here.rego")));
        assert!(Registry::default().declares(&row_from("crates/batten/src/drain.rs")));
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
        };
        assert!(registry.owner("crates/a/src/lib.rs").is_err());
        assert!(registry.declares(&row_from("crates/a/src/lib.rs")));
    }

    #[test]
    fn a_sources_scope_is_its_own_tests_and_every_suite_it_declares() {
        let root = std::env::temp_dir().join(format!("batten-scope-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("crates/k/src/a")).expect("dirs");
        fs::create_dir_all(root.join("crates/k/tests/it")).expect("dirs");
        fs::write(
            root.join("crates/k/Cargo.toml"),
            "[package]\nname = \"k\"\n",
        )
        .expect("manifest");
        fs::write(
            root.join("crates/k/src/a/b.rs"),
            "//MUTANT-SUITE crates/k/tests/it/flows.rs\n//MUTANT-SUITE tests/x.bats\n",
        )
        .expect("source");
        fs::write(root.join("crates/k/src/lib.rs"), "").expect("lib");
        assert_eq!(
            test_scope(&root, "crates/k/src/a/b.rs").as_deref(),
            Some(
                "(package(k) & kind(lib) & test(/^a::b::/)) | (package(k) & binary(it) & \
                 test(/^flows::/))"
            )
        );
        assert_eq!(
            test_scope(&root, "crates/k/src/lib.rs").as_deref(),
            Some("(package(k) & kind(lib))")
        );
        assert_eq!(test_scope(&root, "elsewhere/x.rs"), None);
        let _ = fs::remove_dir_all(&root);
    }

    fn ran(ok: bool) -> Ran {
        Ran {
            ok,
            output: String::new(),
            timed_out: false,
        }
    }

    #[test]
    fn a_missed_mutant_is_a_survivor_named_by_pointer_alone() {
        let dir = std::env::temp_dir().join(format!("batten-outcomes-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("dir");
        fs::write(
            dir.join("caught.txt"),
            "src/a.rs:3:5: replace f -> bool with true\n",
        )
        .expect("caught");
        fs::write(dir.join("missed.txt"), "src/a.rs:9:1: replace g with ()\n").expect("missed");
        let outcomes = read_outcomes(&dir);
        assert_eq!(outcomes.ran, 2);
        let found = outcomes.findings(RunnerKind::CargoMutants, "src/a.rs", &ran(false));
        assert_eq!(found.len(), 1);
        assert_eq!(
            found[0].to_string(),
            "cargo-mutants/src/a.rs:9:1 SURVIVED (in-diff)"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_failed_run_with_nothing_missed_is_never_every_mutant_caught() {
        let dir = std::env::temp_dir().join(format!("batten-baseline-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("dir");
        fs::write(
            dir.join("outcomes.json"),
            r#"{"outcomes":[{"scenario":"Baseline","summary":"Failure"}]}"#,
        )
        .expect("outcomes");
        let found = read_outcomes(&dir).findings(RunnerKind::CargoMutants, "src/a.rs", &ran(false));
        assert_eq!(found.len(), 1);
        assert!(found[0].verdict.could_not_look(), "{}", found[0]);
        assert_eq!(
            found[0].to_string(),
            "cargo-mutants/src/a.rs case-already-red (baseline)"
        );
        let none = std::env::temp_dir().join(format!("batten-nothing-{}", std::process::id()));
        let found =
            read_outcomes(&none).findings(RunnerKind::CargoMutants, "src/a.rs", &ran(false));
        assert_eq!(
            found[0].to_string(),
            "cargo-mutants/src/a.rs suite-did-not-run (cargo mutants)"
        );
        assert!(
            read_outcomes(&none)
                .findings(RunnerKind::CargoMutants, "src/a.rs", &ran(true))
                .is_empty()
        );
        let _ = fs::remove_dir_all(&dir);
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
        let dir = root.join(PRESETS).join("probe");
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
        let Some(gate) = resolve(&root, "probe") else {
            panic!("the preset directory resolves to a gate");
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
        let text = std::fs::read_to_string(&path)
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
}
