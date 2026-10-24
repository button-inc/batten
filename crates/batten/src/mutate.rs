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
//MUTANT registered-rows-swept-by-hand|s@^                if !gate.rows.is_empty() \&\& !gate.rows.iter().any(\x7crow\x7c registry.declares(row)) {$@                if false {@|a_change_to_a_rust_gate_is_judged_by_its_registered_runner
//MUTANT registered-row-judged-twice|s@^        for row in gate.rows.iter().filter(\x7crow\x7c registry.declares(row)) {$@        for row in \&gate.rows {@|a_registered_runners_rows_are_never_swept_by_the_declared_runner
//MUTANT shard-slices-unsorted|s@^    sorted.sort();$@@|shards_partition_the_sorted_gates_and_refuse_a_malformed_value
//MUTANT shard-takes-every-gate|s@^        .filter(\x7c(index, _)\x7c index % n == k)$@        .filter(\x7c_\x7c true)@|shards_partition_the_sorted_gates_and_refuse_a_malformed_value
//MUTANT every-gate-touched|s@^        \.filter(\x7cname\x7c {$@        .filter(\x7cname\x7c { true \x7c\x7c@|a_change_touching_no_gate_sweeps_nothing
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

/// The `#MUTANT` rows in one source, refusing a row that is not three fields.
///
/// The count precedes the split because after the split the evidence is gone: a
/// case filter holding a `|` is indistinguishable from one that meant to.
///
/// EACH ROW CARRIES THE SUITE ABOVE IT (CLOUD-2193). A source may declare
/// several (`land.rs` declares four, `lib.rs` fifteen), and every author of a
/// later one wrote its rows under it; reading only the first judged them all
/// under the first, so a change to a later suite selected no sweep and the
/// every-case check counted the wrong file. A row above every declaration
/// keeps the first, which is all a single-declaration source ever had.
fn rows_in(lines: &[String], source: &str) -> Vec<std::result::Result<Row, (String, usize)>> {
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
            let head = body.split('|').next().unwrap_or_default().to_owned();
            rows.push(Err((head, fields.len())));
            continue;
        };
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
    for (head, fields) in malformed {
        rows.push(Row {
            slug: head,
            script: String::new(),
            want: format!("\u{0}malformed:{fields}"),
            source: sources[0].clone(),
            suite: None,
            resolved: None,
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

/// Which registered runner this invocation ALSO runs, by its id, after the
/// declared runner's sweep. Unset runs the declared runner alone, which is what
/// `verify` does; a CI job sets it where the runner is installed.
pub const RUNNER: &str = "MUTANT_RUNNER";

/// The shard this invocation takes, as `k/n` with `k` counted from zero: slice
/// `k` of the declared runner's gates, and the registered runner's own shard `k`.
pub const SHARD: &str = "MUTANT_SHARD";

/// The gates one `$MUTANT_SHARD` of `k/n` sweeps: every `n`-th of the sorted
/// set, starting at `k`.
///
/// BY GATE, NOT BY ROW, because a gate's rows share one staged tree and one
/// suite build: splitting a gate across shards would pay its build twice. Sorted
/// first, so every shard of one run slices the same order and the slices
/// partition the set.
///
/// # Errors
///
/// A value that is not `k/n` with `n > 0` and `k < n`.
pub fn shard_of(names: &[String], shard: &str) -> Result<Vec<String>, String> {
    let (k, n) = parse_shard(shard)
        .ok_or_else(|| format!("{SHARD}={shard} is not `k/n` with 0 <= k < n"))?;
    let mut sorted = names.to_vec();
    sorted.sort();
    Ok(sorted
        .into_iter()
        .enumerate()
        .filter(|(index, _)| index % n == k)
        .map(|(_, name)| name)
        .collect())
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

//MUTANT-SUITE crates/batten/src/mutate.rs
//MUTANT registry-owns-nothing|s@^            .filter(\x7c(_, glob)\x7c crate::rules::glob_match(glob, path))$@            .filter(\x7c_\x7c false)@|a_registered_glob_owns_its_sources_and_the_declared_runner_the_rest
//MUTANT overlap-picks-one|s@^        let mut owners = owners.into_iter();$@        let mut owners = owners.into_iter().take(1);@|a_source_two_runners_claim_has_no_owner
//MUTANT declared-runner-takes-globs|s@^            if kind == RunnerKind::Declared {$@            if false {@|a_registry_naming_no_runner_or_giving_the_declared_one_globs_is_refused
//MUTANT declared-suites-unscoped|s@^        if has_extension(suite, "rs")$@        if false@|a_sources_scope_is_its_own_tests_and_every_suite_it_declares
//MUTANT missed-unread|s@^    let missed: Vec<String> = lines("missed.txt")@    let missed: Vec<String> = lines("absent.txt")@|a_missed_mutant_is_a_survivor_named_by_pointer_alone
//MUTANT failed-run-reads-caught|s@^        } else if !ran.passed() \&\& found.is_empty() {$@        } else if false {@|a_failed_run_with_nothing_missed_is_never_every_mutant_caught
//MUTANT row-judged-under-first-suite|s@^            above = Some(suite);$@            above = first.clone().or(Some(suite));@|a_row_is_judged_under_the_suite_above_it
//MUTANT later-unrecognized-costs-the-gate|s@^                None if index == 0 => unrunnable@                None if true => unrunnable@|a_later_unrecognized_suite_costs_only_the_rows_under_it
//MUTANT suite-first-only|s@^            Some(_) => row.resolved.as_ref(),$@            Some(_) => self.suite.as_ref(),@|each_preset_module_row_runs_under_its_own_declared_suite
//MUTANT nextest-profile-unpinned|s@^        (String::from("NEXTEST_PROFILE"), String::from("default")),$@        (String::from("NEXTEST_PROFILE"), String::from("ci")),@|every_runner_runs_the_default_nextest_profile
//MUTANT-SUITE crates/batten/tests/it/mutate.rs
//MUTANT later-suites-unread|s@^                    own.push(resolved);$@                    if own.is_empty() { own.push(resolved); }@|a_change_to_a_sources_second_suite_sweeps_its_gate
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
            command: Vec::new(),
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
                // A LOOKUP, NEVER A PROBE RUN: the consumer's program has no
                // `--version` contract, and running it would be the sweep itself.
                RunnerKind::Command => {
                    return !registry
                        .command
                        .first()
                        .is_some_and(|program| resolves(root, program));
                }
            };
            !spawn(
                root,
                Program::Cargo,
                &args,
                &runner_path(),
                HOUSEKEEPING_BOUND,
            )
            .is_ok_and(|ran| ran.passed())
        })
        .map(|kind| Finding {
            gate: kind.id().to_owned(),
            slug: None,
            verdict: Verdict::RunnerAbsent,
            owner: None,
        })
        .collect()
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
//MUTANT command-exit-unread|s@^    match ran.outcome {$@    match Outcome::Passed {@|a_command_runner_exit_two_is_survived
//MUTANT command-error-read-as-caught|s@^        Outcome::Failed(code) => Verdict::RunnerErrored { code },$@        Outcome::Failed(_) => Verdict::Caught,@|a_command_runner_that_errors_cannot_look
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

/// Where a sweep runs: the checkout, the base its change is measured from, the
/// committed registry, and the scratch directory a staged copy lives under.
#[derive(Debug, Clone, Copy)]
pub struct Site<'a> {
    /// The checkout.
    pub root: &'a Path,
    /// The base the change is measured from.
    pub base: &'a str,
    /// The committed runner registry.
    pub registry: &'a Registry,
    /// The scratch directory the staged copy and each run's output live under.
    pub work: &'a Path,
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
    site: &Site<'_>,
    changed: &std::collections::BTreeSet<String>,
    kind: RunnerKind,
    shard: Option<&str>,
    progress: &mut dyn std::io::Write,
) -> Result<Registered> {
    let Site {
        root,
        base,
        registry,
        work,
    } = *site;
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
    if kind == RunnerKind::Command {
        result
            .findings
            .extend(run_command(root, registry, &sources)?);
        return Ok(result);
    }
    let diff = in_diff_patch(root, base, &sources).with_context(|| {
        format!("mutate: the change since {base} cannot be named to cargo-mutants")
    })?;
    let staged = Staged::new(root, work.to_path_buf())?;
    let runs = work.join("cargo-mutants");
    fs::create_dir_all(&runs)
        .with_context(|| format!("mutate: could not create {}", runs.display()))?;
    let patch = runs.join("change.diff");
    crate::durable::replace(&patch, diff)
        .with_context(|| format!("mutate: could not write {}", patch.display()))?;
    let shards = shard_plan(root, staged.dir(), &patch, &sources, shard)?;
    let assigned = shards.iter().filter(|on| **on != Place::Off).count();
    let mut position = 0usize;
    for (index, (source, on)) in sources.iter().zip(shards).enumerate() {
        // A source with no mutant on this shard is not run here at all: no
        // build, no suite, no finding, which another shard carries.
        let local = match on {
            Place::Off => continue,
            Place::On(local) => shard.and_then(parse_shard).map(|(_, n)| (local, n)),
            Place::Unsharded => None,
        };
        position += 1;
        // ONE READ OF THE SCOPE: the filterset and the target selectors are
        // both this list's, so it is built once per source.
        let scope = scope_of(root, source);
        if scope.is_empty() {
            result.findings.push(Finding {
                gate: kind.id().to_owned(),
                slug: Some(source.clone()),
                verdict: Verdict::NoSuite {
                    suite: String::from("no cargo target compiles it"),
                },
                owner: None,
            });
            continue;
        }
        let output = runs.join(index.to_string());
        let _ = fs::remove_dir_all(&output);
        let args = source_args(&patch, source, &output, local, &scope);
        let started = std::time::Instant::now();
        let _ = writeln!(
            progress,
            "mutate sweep: source {position}/{assigned} {source} starting"
        );
        let ran = spawn_as(
            staged.dir(),
            Program::Cargo,
            &args,
            &suite_env(root),
            runner_bound(),
            Said::Streamed,
        )?;
        let outcome = read_outcomes(&output.join("mutants.out"));
        // ONE LINE PER SOURCE (CLOUD-2253's progress, for this runner), AND ITS
        // FINDINGS AS IT ENDS: on #1132 fifteen shards ran 111 minutes each,
        // were stopped at their bound, and their logs held nothing of what they
        // had judged, because every finding waited for the last source.
        let _ = writeln!(
            progress,
            "mutate sweep: source {position}/{assigned} {source} {} mutant(s) {}s",
            outcome.ran,
            started.elapsed().as_secs()
        );
        let found = outcome.findings(kind, source, &ran);
        for finding in &found {
            let _ = writeln!(progress, "mutate sweep: {finding}");
        }
        result.mutants += outcome.ran;
        result.findings.extend(found);
    }
    Ok(result)
}

/// Where one source's run sits on the sweep's shard.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Place {
    /// The sweep is not sharded: the source runs whole.
    Unsharded,
    /// No mutant of the source is on this shard: it is not run here.
    Off,
    /// The source runs its own `--shard <local>/<n>`.
    On(usize),
}

/// Each source's [`Place`] on `shard`: [`Place::Unsharded`] where the sweep is
/// not sharded, else [`source_shards`] over the change's listed mutants.
fn shard_plan(
    root: &Path,
    staged: &Path,
    patch: &Path,
    sources: &[String],
    shard: Option<&str>,
) -> Result<Vec<Place>> {
    let Some(raw) = shard else {
        return Ok(vec![Place::Unsharded; sources.len()]);
    };
    let (k, n) = parse_shard(raw)
        .ok_or_else(|| anyhow::anyhow!("mutate: {SHARD} `{raw}` is not `<k>/<n>`"))?;
    let mut list = vec![
        String::from("mutants"),
        String::from("--list"),
        String::from("--no-shuffle"),
        String::from("--in-diff"),
        patch.to_string_lossy().into_owned(),
    ];
    for source in sources {
        list.extend([String::from("--file"), source.clone()]);
    }
    let listed = spawn(
        staged,
        Program::Cargo,
        &list,
        &suite_env(root),
        build_bound(),
    )?;
    if !listed.passed() {
        bail!("mutate: cargo-mutants could not list the change's mutants");
    }
    Ok(source_shards(&mutant_counts(&listed.output, sources), k, n)
        .into_iter()
        .map(|local| local.map_or(Place::Off, Place::On))
        .collect())
}

/// One source's cargo-mutants argv; `local` is its `--shard` as `(k, n)`, and
/// `scope` its [`scope_of`], which names both the filterset and the targets.
fn source_args(
    patch: &Path,
    source: &str,
    output: &Path,
    local: Option<(usize, usize)>,
    scope: &[(String, Option<String>)],
) -> Vec<String> {
    let mut args = vec![
        String::from("mutants"),
        String::from("--in-place"),
        String::from("--no-shuffle"),
        String::from("--in-diff"),
        patch.to_string_lossy().into_owned(),
        String::from("--file"),
        source.to_owned(),
        String::from("--test-tool"),
        String::from("nextest"),
        String::from("--output"),
        output.to_string_lossy().into_owned(),
    ];
    // ONLY THE TARGETS THE SCOPE RUNS ARE BUILT ([`targets_of`]): `--cargo-arg`
    // reaches both the build and the test invocation, so what is compiled per
    // mutant is what the filterset below can select, and nothing else.
    args.extend(
        targets_of(scope)
            .iter()
            .map(|target| format!("--cargo-arg={target}")),
    );
    // A SHARD SKIPS THE BASELINE, as the book's CI recipe does
    // (mutants.rs/shards.html). One invocation per source meant every shard
    // built and tested 157 unmutated baselines, most for sources with no
    // mutant in that shard: measured on #1132, the shards ran past their
    // 120-minute bound and only one finished. The book's precondition is a
    // suite already green on the unmutated tree; `--timeout` stands in for the
    // per-mutant bound the baseline would have measured.
    if let Some((k, n)) = local {
        args.extend([
            String::from("--shard"),
            format!("{k}/{n}"),
            String::from("--sharding"),
            String::from("round-robin"),
            String::from("--baseline=skip"),
            String::from("--timeout"),
            SHARD_MUTANT_TIMEOUT_SECS.to_string(),
        ]);
    }
    // `-v`: a line per mutant as it is judged, caught ones included, so the
    // log says how far a run got against what it was given.
    args.extend([
        String::from("-v"),
        String::from("--"),
        String::from("-E"),
        terms_of(scope),
    ]);
    args
}

/// One mutant's test bound in a sharded run, which skips the baseline that
/// would otherwise measure it: the book's CI recipe's `--timeout 300`.
const SHARD_MUTANT_TIMEOUT_SECS: u64 = 300;

/// `$MUTANT_SHARD`'s `k/n`, or `None` where it is not one (`k < n`, `n > 0`).
#[must_use]
pub fn parse_shard(shard: &str) -> Option<(usize, usize)> {
    let (k, n) = shard.trim().split_once('/')?;
    let (k, n) = (k.trim().parse().ok()?, n.trim().parse().ok()?);
    (k < n).then_some((k, n))
}

/// The `--shard` each source's own run takes on shard `k` of `n`, so the
/// matrix shares the whole change's mutants evenly: mutant `g` of the change,
/// counted across the sources in order, belongs to shard `g % n`, which is
/// `--sharding round-robin` within one source run offset by the mutants before
/// it. `None` for a source with no mutant on this shard, which is not run.
///
/// ONE RUN PER SOURCE SHARDED ALONE PILED THE WORK ON THE LOW SHARDS: cargo-mutants'
/// default `slice` hands a source of five mutants to shards 0 to 4, so on #1132
/// shard 0 drew a mutant from nearly every one of 158 sources, ran past its
/// 120-minute bound and reported nothing, while shard 15 finished in an hour.
#[must_use]
pub fn source_shards(counts: &[usize], k: usize, n: usize) -> Vec<Option<usize>> {
    let mut before = 0usize;
    counts
        .iter()
        .map(|&count| {
            let local = (k + n - before % n) % n;
            before += count;
            (local < count).then_some(local)
        })
        .collect()
}

/// How many mutants cargo-mutants' `--list` names in each of `sources`, from
/// its `<path>:<line>:<col>: <mutation>` lines.
fn mutant_counts(listing: &str, sources: &[String]) -> Vec<usize> {
    sources
        .iter()
        .map(|source| {
            let prefix = format!("{source}:");
            listing
                .lines()
                .filter(|line| line.starts_with(&prefix))
                .count()
        })
        .collect()
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
        if ran.outcome == Outcome::TimedOut {
            found.push(at(
                source,
                Verdict::SuiteTimedOut {
                    seconds: runner_bound().as_secs(),
                },
            ));
        } else if !ran.passed() && found.is_empty() {
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
/// `None` when no cargo target compiles the source and it declares no suite, so
/// nothing could be named. A source no test target compiles (`build.rs`) is
/// judged by the suites it declares: what it generates is what they read.
#[must_use]
pub fn test_scope(root: &Path, source: &str) -> Option<String> {
    let scope = scope_of(root, source);
    (!scope.is_empty()).then(|| terms_of(&scope))
}

/// A [`scope_of`]'s filterset: its terms, alternated.
fn terms_of(scope: &[(String, Option<String>)]) -> String {
    scope
        .iter()
        .map(|(term, _)| term.as_str())
        .collect::<Vec<_>>()
        .join(" | ")
}

/// The cargo target selectors that build exactly the test binaries a
/// [`scope_of`] names, each once, in order: `--lib`, `--bins`, `--bin=<b>`,
/// `--test=<t>`.
///
/// THE BUILD IS THE WHOLE COST OF A MUTANT, and this is what bounds it
/// (CLOUD-1746). Measured on this tree, a mutant's tests ran in 0s and its
/// build in 27-41s, because `cargo nextest run` with no selector compiles every
/// test target of the package — the library twice (as a dependency and under
/// `cfg(test)`), every integration target and every example — whichever of them
/// the filterset then runs. A scope of one module's unit tests needs only
/// `--lib` (20-27s); a declared `tests/<t>` suite adds `--test=<t>`, and cargo
/// builds the package's binaries for an integration target by itself.
fn targets_of(scope: &[(String, Option<String>)]) -> Vec<String> {
    let mut targets: Vec<String> = Vec::new();
    for target in scope.iter().filter_map(|(_, target)| target.as_ref()) {
        if !targets.contains(target) {
            targets.push(target.clone());
        }
    }
    targets
}

/// Each `(filterset term, cargo target selector)` judging `source`: its own
/// tests, then every Rust suite it declares with `MUTANT-SUITE`, each once. A
/// suite in another package carries no selector.
fn scope_of(root: &Path, source: &str) -> Vec<(String, Option<String>)> {
    let mut scope: Vec<(String, Option<String>)> = tests_of(root, source)
        .into_iter()
        .map(|(term, target)| (term, Some(target)))
        .collect();
    let home = package_of(root, source).map(|(package, _)| package);
    for line in lines_of(root, source).unwrap_or_default() {
        let Some(suite) = strip_marker(&line, SUITE) else {
            continue;
        };
        let suite = suite.trim();
        if has_extension(suite, "rs")
            && let Some((term, target)) = tests_of(root, suite)
            && !scope.iter().any(|(known, _)| *known == term)
        {
            // A SUITE IN ANOTHER PACKAGE NAMES NO TARGET HERE: cargo-mutants
            // builds the mutated package, where `--test=<t>` of a sibling's
            // target is a build error rather than a narrower build.
            let home_package = package_of(root, suite).map(|(package, _)| package) == home;
            scope.push((term, home_package.then_some(target)));
        }
    }
    scope
}

/// The filterset term naming the tests compiled from `path`, inside its
/// package, and the cargo selector of the target that compiles them.
///
/// Cargo's own layout decides it, never this repository's: `src/lib.rs` is the
/// library's whole unit-test set and `src/a/b.rs` its `a::b::` module;
/// `tests/<t>.rs` and `tests/<t>/main.rs` are the target `<t>`, and
/// `tests/<t>/<m>.rs` its `<m>::` module.
fn tests_of(root: &Path, path: &str) -> Option<(String, String)> {
    let (package, dir) = package_of(root, path)?;
    let relative = Path::new(path)
        .strip_prefix(&dir)
        .ok()?
        .to_string_lossy()
        .replace('\\', "/");
    let stem = relative.strip_suffix(".rs")?;
    let (term, target) = if let Some(module) = stem.strip_prefix("src/") {
        let module = module.strip_suffix("/mod").unwrap_or(module);
        match module {
            "lib" => (String::from("kind(lib)"), String::from("--lib")),
            "main" => (String::from("kind(bin)"), String::from("--bins")),
            _ => match module.strip_prefix("bin/") {
                Some(binary) => {
                    // `src/bin/<name>/main.rs` is the binary `<name>`, as
                    // `src/bin/<name>.rs` is: cargo's layout, never this repo's.
                    let binary = binary.strip_suffix("/main").unwrap_or(binary);
                    (format!("binary({binary})"), format!("--bin={binary}"))
                }
                None => (
                    format!("kind(lib) & test(/^{}::/)", module.replace('/', "::")),
                    String::from("--lib"),
                ),
            },
        }
    } else {
        let test = stem.strip_prefix("tests/")?;
        let (target, module) = match test.split_once('/') {
            None => (test, None),
            Some((target, "main")) => (target, None),
            Some((target, module)) => (target, Some(module)),
        };
        let term = match module {
            None => format!("binary({target})"),
            Some(module) => format!(
                "binary({target}) & test(/^{}::/)",
                module.replace('/', "::")
            ),
        };
        (term, format!("--test={target}"))
    };
    Some((format!("(package({package}) & {term})"), target))
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
        let after = fs::read_to_string(root.join(source)).unwrap_or_default();
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
}

impl Program<'_> {
    const fn name(&self) -> &str {
        match self {
            Program::Cargo => "cargo",
            Program::Suite(program) | Program::Command(program) => program,
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
            // The failed wait reaped nothing (`await_exit` never does), so the
            // group id is still reserved and the sweep is as safe here.
            kill_group(pid);
            sweep_group(pid);
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
//MUTANT runner-not-asked-first|s@^        crate::exec::signal_group(group, rustix::process::Signal::TERM);$@        let _ = group;@|a_suite_that_hangs_is_ended_by_the_sweeps_own_bound
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
    let mut output = fs::read_to_string(out_path).unwrap_or_default();
    output.push_str(&fs::read_to_string(err_path).unwrap_or_default());
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
    Ran { outcome, output }
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
    let mut env = runner_path();
    env.extend([
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
        // `NEXTEST_PROFILE` (this repository's `[env]` sets `ci` under CI)
        // names a profile the staged tree may not declare, a fixture's or a
        // consumer's, and nextest then exits before selecting a case: every
        // declared Cargo row read `suite-did-not-run` in CI alone. A declared
        // non-default profile is not kept either, so its settings cannot reach
        // a verdict; `[profile.default]`'s own settings and the other inherited
        // `NEXTEST_*` variables still do (CLOUD-2466 item 9).
        (String::from("NEXTEST_PROFILE"), String::from("default")),
    ]);
    env
}

/// The directory a committed `[[provision]]` row installed a registered
/// runner's program into, set once by the verb before it runs ([`use_provisioned`]).
///
/// PROCESS-WIDE, AND THAT IS A CHOICE AGAINST TWO BREAKS: a field on `Registry`
/// fails the existing struct-literal case that `test-replay` replays, and a new
/// parameter on `run_registered` or `unresolvable` is a semver break of both.
static PROVISIONED: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();

/// Run every registered runner's program from `dir` first: the pinned
/// cargo-mutants a `[[provision]]` row ships, which a CI runner holds nowhere
/// on its `PATH` (CLOUD-2345). Only the first call takes effect.
pub fn use_provisioned(dir: PathBuf) {
    let _ = PROVISIONED.set(dir);
}

/// `PATH` with [`use_provisioned`]'s directory ahead of the inherited one, or
/// nothing where none was set, so the inherited `PATH` passes through unchanged.
fn runner_path() -> Vec<(String, String)> {
    let Some(dir) = PROVISIONED.get() else {
        return Vec::new();
    };
    let inherited = std::env::var_os("PATH").unwrap_or_default();
    let paths = std::iter::once(dir.clone()).chain(std::env::split_paths(&inherited));
    std::env::join_paths(paths).map_or_else(
        |_| Vec::new(),
        |joined| vec![(String::from("PATH"), joined.to_string_lossy().into_owned())],
    )
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
            selected: libtest_lines(&ran.output) + nextest_lines(&ran.output),
            ok: ran.passed() && !ran.output.contains("error: could not compile"),
            reach: Reach::of(libtest_ran(&ran.output) || nextest_ran(&ran.output), false),
        },
        Suite::Tofu { .. } => tofu_verdict(&ran.output, want),
        Suite::Kyverno { .. } => kyverno_verdict(&ran.output, want),
        Suite::Conftest { path } => {
            conftest_verdict(&ran.output, want, &lines_of(dir, path).unwrap_or_default())
        }
        Suite::Pytest { .. } => pytest_verdict(&fs::read_to_string(&junit).unwrap_or_default()),
    };
    let _ = fs::remove_file(&junit);
    if ran.outcome == Outcome::TimedOut {
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
            (
                dir.to_path_buf(),
                argv(&[
                    "cargo",
                    "nextest",
                    "run",
                    "--no-fail-fast",
                    "--no-tests=pass",
                    "--color=never",
                    "-E",
                    &filter,
                ]),
            )
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
/// outcome: a line led by one of nextest's result words
/// ([`crate::replay::TERMINAL`], `SIGTERM` among them, which [`wait_bounded`]
/// itself sends a timed-out runner, plus `LEAK`, a pass that leaked handles),
/// bare or after a `TRY <n>` retry prefix, then the bracketed duration. Counted
/// by distinct case, so a retried case is one, and read up to the `Summary [`
/// line, past which nextest repeats each failure.
fn nextest_lines(output: &str) -> usize {
    output
        .lines()
        .take_while(|line| !line.trim_start().starts_with("Summary ["))
        .filter_map(|line| {
            let mut words = line.split_whitespace();
            let mut word = words.next()?;
            if word == "TRY" {
                words.next()?.parse::<u32>().ok()?;
                word = words.next()?;
            }
            let result = word == "LEAK" || crate::replay::TERMINAL.contains(&word);
            (result && words.next()?.starts_with('[')).then(|| line.split_once(']'))?
        })
        .map(|(_, case)| case.trim())
        .filter(|case| !case.is_empty())
        .collect::<std::collections::BTreeSet<_>>()
        .len()
}

/// Whether a nextest run printed its summary, which it does for an empty
/// selection under `--no-tests=pass` too; absent, nothing ran.
fn nextest_ran(output: &str) -> bool {
    output
        .lines()
        .any(|line| line.trim_start().starts_with("Summary ["))
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
//MUTANT-SUITE crates/batten/tests/it/mutate.rs
//MUTANT generated-case-any-pass|s@^    } else if any \&\& every_pass {$@    } else if any {@|a_case_verdict_is_independent_of_order
//MUTANT generated-pool-ignores-fail-order|s@^        } else if v.eq_ignore_ascii_case("fail") {$@        } else if false {@|a_case_verdict_is_independent_of_order
//MUTANT exact-shadow-restored|s@^        let chosen = if generated.is_empty() {$@        let chosen = if true {@|a_generating_kyverno_case_fails_when_any_object_it_generates_does
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
//MUTANT result-verdict-dropped|s@^    result\["RESULT"\].as_str().unwrap_or("error")$@    result["RESULT"].as_str().unwrap_or("pass")@|a_result_with_no_verdict_is_an_error
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
fn apply(staged: &Staged, row: &Row) -> Result<Option<Verdict>> {
    let path = staged.dir().join(&row.source);
    let Ok(before) = std::fs::read_to_string(&path) else {
        return Ok(Some(Verdict::UnappliableMutation));
    };
    let Some(after) = substitute(&before, &row.script) else {
        return Ok(Some(Verdict::UnappliableMutation));
    };
    crate::durable::replace(&path, after)
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

    if let Some(refused) = apply(staged, row)? {
        return Ok(refused);
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
    if let Some(refused) = apply(staged, row)? {
        return Ok(Some(refused));
    }
    let (changed, code_lines) = diff_shape(root, staged, &row.source);
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

/// A row's key: its script, the bytes it mutates, and the bytes of its suite.
fn row_key(root: &Path, gate: &Gate, row: &Row) -> String {
    let mut material = row.script.clone().into_bytes();
    material.push(0);
    material.extend(std::fs::read(root.join(&row.source)).unwrap_or_default());
    material.push(0);
    if let Some(suite) = gate.suite_for(row) {
        material.extend(std::fs::read(root.join(suite.path())).unwrap_or_default());
    }
    crate::provision::digest(&material)
}

/// The keys recorded caught; an unreadable record is an empty one.
fn recorded_caught(record: &Path) -> std::collections::HashSet<String> {
    std::fs::read_to_string(record)
        .map(|text| text.lines().map(str::to_owned).collect())
        .unwrap_or_default()
}

/// Append one caught key, whole-line so a torn tail never fuses two keys. Best
/// effort: a key not recorded is a row run again.
fn record_caught(record: &Path, key: &str) {
    let _ = crate::durable::append_whole_lines(record, &format!("{key}\n"));
}

/// BUILD ONCE, BEFORE ANY ROW IS TIMED (CLOUD-1910). Best effort: a build that
/// fails leaves every Cargo row to report `suite-did-not-run` on its own, which
/// is the honest verdict, so nothing is decided here. NOT AT ALL when every
/// Cargo row is already recorded caught (CLOUD-2253): the build is minutes and
/// no row would use it.
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
) {
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
    if owed {
        let _ = writeln!(
            progress,
            "mutate sweep: building the cargo suites the rows run under"
        );
        let args = vec![String::from("test"), String::from("--no-run")];
        let _ = spawn(
            staged.dir(),
            Program::Cargo,
            &args,
            &suite_env(root),
            build_bound(),
        );
    }
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
    let total: usize = names
        .iter()
        .filter_map(|name| resolve(root, name))
        .map(|gate| {
            gate.rows
                .iter()
                .filter(|row| registry.declares(row))
                .count()
        })
        .sum();
    let _ = writeln!(
        progress,
        "mutate sweep: {total} row(s) across {} gate(s)",
        names.len()
    );
    let record = work.join(CAUGHT_RECORD);
    let caught = recorded_caught(&record);
    let mut staged = Staged::new(root, work)?;
    build_if_owed(root, names, registry, &caught, &staged, progress);
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
            let key = row_key(root, &gate, row);
            if caught.contains(&key) {
                let _ = writeln!(
                    progress,
                    "mutate sweep: row {declared}/{total} {name} {} caught (recorded) 0s",
                    row.slug
                );
                continue;
            }
            let started = std::time::Instant::now();
            let verdict = judge_row(root, &mut staged, &gate, row)?;
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
    /// A declared row that is not three `|`-separated fields, so no script and
    /// case can be read from it at all.
    MalformedRow,
    /// A declared row whose script is outside the one-substitution subset the
    /// runner applies ([`substitute`]), so it can never be applied.
    UnappliableMutation,
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
    findings.extend(inert_rows(root, &subjects));
    Census {
        findings,
        subjects: subjects.len(),
        engine_undeclared: engine_undeclared(root, &subjects),
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
//MUTANT inert-row-admitted|s@^                    Some(after) if code_lines_changed(\&text, \&after) == 0 => {$@                    Some(after) if false => {@|a_row_whose_script_changes_nothing_is_refused_by_the_census
//MUTANT malformed-row-admitted|s@, CensusVerdict::MalformedRow));$@, CensusVerdict::InertMutation));@|a_row_that_cannot_apply_is_refused_by_the_census
//MUTANT unappliable-row-admitted|s@^                    None => CensusVerdict::UnappliableMutation,$@                    None => continue,@|a_row_that_cannot_apply_is_refused_by_the_census
fn inert_rows(root: &Path, subjects: &BTreeMap<String, String>) -> Vec<(String, CensusVerdict)> {
    let mut found = Vec::new();
    for name in subjects.keys() {
        for source in sources_for(root, name) {
            let Ok(text) = std::fs::read_to_string(root.join(&source)) else {
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

    /// Fails by: the provisioned runner's directory dropped, or put after the
    /// inherited `PATH`, so a CI runner with no cargo-mutants reads
    /// `runner-absent` and a host's own version runs instead of the pin. The
    /// one test that sets the process-wide directory.
    #[test]
    fn a_provisioned_runner_directory_leads_every_runner_path() {
        let dir = PathBuf::from("/provisioned/cargo-mutants");
        use_provisioned(dir.clone());
        let env = suite_env(Path::new("/repo"));
        let path = env
            .iter()
            .find(|(key, _)| key == "PATH")
            .map(|(_, value)| value.clone())
            .expect("a provisioned directory sets PATH");
        assert_eq!(
            std::env::split_paths(&path).next(),
            Some(dir),
            "the provisioned directory must come first: {path}"
        );
        assert_eq!(runner_path().len(), 1, "unresolvable reads the same PATH");
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
            "crates/batten/src/lib.rs",
            "crates/batten/src/policy/presets/x.rs",
            "crates/batten/build.rs",
            "crates/batten/tests/it/mutate.rs",
        ] {
            assert_eq!(
                registry.owner(owned).expect("one owner"),
                RunnerKind::CargoMutants,
                "{owned}"
            );
        }
        assert_eq!(
            registry
                .owner("crates/batten/examples/hook-read-bench.rs")
                .expect("one owner"),
            RunnerKind::Declared
        );
    }

    /// THE MATRIX SHARES THE CHANGE, NOT EACH SOURCE: every mutant of every
    /// source lands on exactly one shard, and no shard carries more than one
    /// more than another.
    #[test]
    fn each_mutant_of_the_change_lands_on_exactly_one_shard_evenly() {
        let counts = [5usize, 0, 40, 1, 1, 17, 3];
        let n = 16;
        let mut per_shard = vec![0usize; n];
        for (source, &count) in counts.iter().enumerate() {
            let mut covered = 0;
            for (k, load) in per_shard.iter_mut().enumerate() {
                if let Some(local) = source_shards(&counts, k, n)[source] {
                    assert!(local < count, "a run is only asked of a source with work");
                    let ran = (count - local).div_ceil(n);
                    covered += ran;
                    *load += ran;
                }
            }
            assert_eq!(covered, count, "source {source}'s mutants, each once");
        }
        let (least, most) = (
            per_shard.iter().min().copied().unwrap_or_default(),
            per_shard.iter().max().copied().unwrap_or_default(),
        );
        assert!(most - least <= 1, "evenly: {per_shard:?}");
        assert_eq!(parse_shard(" 3/16 "), Some((3, 16)));
        for bad in ["16/16", "0/0", "3", "x/16"] {
            assert_eq!(parse_shard(bad), None, "{bad}");
        }
    }

    #[test]
    fn a_listing_counts_each_sources_mutants_by_its_path() {
        let listing = "crates/a/src/x.rs:1:1: replace f -> u8 with 0\n\
                       crates/a/src/x.rs:2:5: replace + with -\n\
                       crates/a/src/xy.rs:3:1: replace g with ()\n";
        let sources = [
            String::from("crates/a/src/x.rs"),
            String::from("crates/a/src/xy.rs"),
            String::from("crates/a/src/z.rs"),
        ];
        assert_eq!(mutant_counts(listing, &sources), vec![2, 1, 0]);
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
            command: Vec::new(),
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

    /// Fails by: a target the scope runs left unbuilt (its cases then select
    /// nothing), or every target built again (the cost this exists to cut).
    #[test]
    fn a_sources_build_is_exactly_the_targets_its_scope_runs() {
        let root = std::env::temp_dir().join(format!("batten-targets-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("crates/k/src/a")).expect("dirs");
        fs::create_dir_all(root.join("crates/k/src/bin")).expect("dirs");
        fs::create_dir_all(root.join("crates/k/tests/it")).expect("dirs");
        fs::write(
            root.join("crates/k/Cargo.toml"),
            "[package]\nname = \"k\"\n",
        )
        .expect("manifest");
        // A sibling package: its suite is filtered for, never a `--test` here.
        fs::create_dir_all(root.join("crates/o/tests")).expect("dirs");
        fs::write(
            root.join("crates/o/Cargo.toml"),
            "[package]\nname = \"o\"\n",
        )
        .expect("manifest");
        fs::write(
            root.join("crates/k/src/a/b.rs"),
            [
                "crates/k/tests/it/flows.rs",
                "crates/k/tests/it/more.rs",
                "crates/k/tests/solo.rs",
                "crates/k/src/lib.rs",
                "crates/o/tests/elsewhere.rs",
            ]
            .map(|suite| format!("//{SUITE}{suite}\n"))
            .concat(),
        )
        .expect("source");
        fs::write(root.join("crates/k/src/main.rs"), "").expect("main");
        fs::write(root.join("crates/k/src/bin/tool.rs"), "").expect("bin");
        fs::create_dir_all(root.join("crates/k/src/bin/dir")).expect("dirs");
        fs::write(root.join("crates/k/src/bin/dir/main.rs"), "").expect("bin");
        let test_targets = |root: &Path, source: &str| targets_of(&scope_of(root, source));
        assert_eq!(
            test_targets(&root, "crates/k/src/a/b.rs"),
            ["--lib", "--test=it", "--test=solo"]
        );
        assert!(
            terms_of(&scope_of(&root, "crates/k/src/a/b.rs")).contains("package(o)"),
            "the sibling's suite is still in the filterset"
        );
        assert_eq!(test_targets(&root, "crates/k/src/main.rs"), ["--bins"]);
        assert_eq!(
            test_targets(&root, "crates/k/src/bin/tool.rs"),
            ["--bin=tool"]
        );
        assert_eq!(
            test_targets(&root, "crates/k/src/bin/dir/main.rs"),
            ["--bin=dir"]
        );
        assert_eq!(
            test_targets(&root, "crates/k/tests/it/main.rs"),
            ["--test=it"]
        );
        assert!(test_targets(&root, "elsewhere/x.rs").is_empty());
        let args = source_args(
            Path::new("change.diff"),
            "crates/k/src/a/b.rs",
            Path::new("out"),
            None,
            &scope_of(&root, "crates/k/src/a/b.rs"),
        );
        for target in [
            "--cargo-arg=--lib",
            "--cargo-arg=--test=it",
            "--cargo-arg=--test=solo",
        ] {
            assert!(args.iter().any(|arg| arg == target), "{target} in {args:?}");
        }
        assert_eq!(
            args.iter()
                .filter(|arg| arg.starts_with("--cargo-arg="))
                .count(),
            3
        );
        assert!(
            suite_env(&root)
                .iter()
                .any(|(key, value)| key == "CARGO_PROFILE_TEST_DEBUG" && value == "0"),
            "every runner over the shared target builds without debug info"
        );
        let _ = fs::remove_dir_all(&root);
    }

    fn ran(ok: bool) -> Ran {
        Ran {
            outcome: if ok {
                Outcome::Passed
            } else {
                Outcome::Failed(Some(1))
            },
            output: String::new(),
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

    /// Fails by: a line whose row or column is not a number read as a pointer.
    #[test]
    fn an_outcome_line_is_a_pointer_only_when_line_and_column_are_numbers() {
        assert_eq!(
            pointer_of("src/a.rs:3:5: replace f with ()").as_deref(),
            Some("src/a.rs:3:5")
        );
        assert_eq!(pointer_of("src/a.rs:x:5: replace f with ()"), None);
        assert_eq!(pointer_of("src/a.rs:3:y: replace f with ()"), None);
    }

    /// Fails by: an outcome file dropped from (or subtracted out of) `ran`, or a
    /// failed MUTANT scenario read as a failed baseline.
    #[test]
    fn every_outcome_file_counts_toward_ran_and_only_a_failed_baseline_is_one() {
        let dir = fixture("outcome-counts");
        let lines = |n: usize| {
            (1..=n)
                .map(|i| format!("src/a.rs:{i}:1: replace f with ()"))
                .collect::<Vec<_>>()
                .join("\n")
        };
        fs::write(dir.join("caught.txt"), lines(3)).expect("caught");
        fs::write(dir.join("unviable.txt"), lines(2)).expect("unviable");
        fs::write(dir.join("missed.txt"), lines(1)).expect("missed");
        fs::write(dir.join("timeout.txt"), "src/a.rs:9:9: replace g with ()\n").expect("timeout");
        fs::write(
            dir.join("outcomes.json"),
            r#"{"outcomes":[{"scenario":"Mutant","summary":"MissedMutant"},{"scenario":"Baseline","summary":"Success"}]}"#,
        )
        .expect("outcomes");
        assert_eq!(
            read_outcomes(&dir),
            Outcomes {
                ran: 7,
                missed: vec![String::from("src/a.rs:1:1")],
                timeout: vec![String::from("src/a.rs:9:9")],
                baseline_failed: false,
            }
        );
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

    /// Fails by: an engine module that declares rows but no suite (or the
    /// reverse) left out of the census, or the undeclared count read as a
    /// constant or as the declared ones.
    #[test]
    fn an_engine_module_is_a_subject_by_any_declaration_and_the_rest_are_counted() {
        let root = fixture("engine-subjects");
        put(
            &root,
            &format!("{ENGINE}/rows_only.rs"),
            &format!("//{ROW}a|s@x@y@|case\n"),
        );
        put(
            &root,
            &format!("{ENGINE}/suite_only.rs"),
            &format!("//{SUITE}crates/batten/tests/it/x.rs\n"),
        );
        for plain in ["plain_a.rs", "plain_b.rs", "plain_c.rs"] {
            put(&root, &format!("{ENGINE}/{plain}"), "fn f() {}\n");
        }
        let found = subjects(&root, None);
        let names: Vec<&str> = found.keys().map(String::as_str).collect();
        assert_eq!(names, ["engine-rows-only", "engine-suite-only"]);
        assert_eq!(engine_undeclared(&root, &found), 3);
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
            build_if_owed(&root, &names, registry, caught, &staged, &mut progress);
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

    /// Fails by: the declared runner carried past its early return, every
    /// source's plan dropped so nothing is judged, or a listing that failed
    /// read as an empty shard.
    #[test]
    fn a_registered_run_returns_early_for_the_declared_runner_and_plans_every_source() {
        let root = fixture("registered");
        crate::gitwrite::init_on_main(&root).expect("a repository");
        put(&root, "elsewhere/x.rs", "fn f() {}\n");
        crate::gitwrite::commit_paths(&root, &[String::from("elsewhere/x.rs")], "base")
            .expect("commit");
        put(&root, "elsewhere/x.rs", "fn f() {\n    let _ = 1;\n}\n");
        let changed = std::collections::BTreeSet::from([String::from("elsewhere/x.rs")]);
        let run = |registry: &Registry, kind: RunnerKind, shard: Option<&str>, name: &str| {
            let work = fixture(name);
            let site = Site {
                root: &root,
                base: "HEAD",
                registry,
                work: &work,
            };
            run_registered(&site, &changed, kind, shard, &mut std::io::sink())
        };
        let declared = run(
            &Registry::default(),
            RunnerKind::Declared,
            None,
            "registered-declared",
        )
        .expect("the declared runner returns at once");
        assert_eq!((declared.sources, declared.findings), (1, Vec::new()));
        let owned = Registry::parse("cargo-mutants=elsewhere/*.rs").expect("parses");
        let unsharded = run(
            &owned,
            RunnerKind::CargoMutants,
            None,
            "registered-unsharded",
        )
        .expect("an unsharded run");
        assert_eq!(
            unsharded.findings,
            vec![Finding {
                gate: String::from("cargo-mutants"),
                slug: Some(String::from("elsewhere/x.rs")),
                verdict: Verdict::NoSuite {
                    suite: String::from("no cargo target compiles it"),
                },
                owner: None,
            }]
        );
        assert!(
            run(
                &owned,
                RunnerKind::CargoMutants,
                Some("0/1"),
                "registered-sharded",
            )
            .is_err(),
            "a listing that fails is an error, never an empty plan"
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
            let read = std::fs::read_to_string(&fifo);
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
            let _ = named.send(std::fs::read_to_string(ready));
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
            std::fs::read_to_string(dir.join(name))
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
