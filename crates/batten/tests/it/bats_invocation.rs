//! `policy/bats-invocation.rego` decides over the compiled engine (CLOUD-386,
//! retired under CLOUD-1059).
//!
//! # Where this came from
//!
//! The successor to `tests/test-bats-parallel.bats`, whose subject is
//! `mise.toml`'s `[tasks."test:bats"]`. The suite was an authored bats file, so
//! `shell-retirement`'s arm B refused maintaining it in place; the predicate
//! moved into the module and the classification of the task body moved into fact
//! acquisition, which is the same split `command-task-defined` already makes.
//!
//! # Why this tier and not the module's own rules
//!
//! The module's `test_` cases hand themselves a `documents` object, so they are
//! green over a shape the engine may never build — the hazard
//! `.claude/rules/policy-modules.md` names, and the reason both of its measured
//! instances were found by adding this tier rather than by reading. Two things
//! here can only be proved against the real boundary: that the manifest's
//! `[tasks."test:bats"].run` reaches a module as a parsed string at all, and that
//! `.github/workflows/ci.yml` parses into `jobs.ci.steps[].with.install_args`
//! rather than into lines the module would have to scan.
//!
//! # The case that carries the most
//!
//! `this_repository_is_clean_today` runs the row over this checkout. Every
//! fixture below is a shape somebody wrote to fail; that one is the shape that
//! has to keep passing, and it is what would have caught the retired suite's own
//! vacuity risk — a gate whose subject moved out from under it reports nothing
//! and looks identical to a gate that passed.

// THE FILE-GRANULARITY RETIREMENT ARM (CLOUD-1059). Its grammar is disjoint from
// CLOUD-908's case arms below by construction: a case arm's first field after the
// marker is a QUOTED case name, and a file arm's is a path.
//
// carried: tests/test-bats-parallel.bats policy/bats-invocation.rego crates/batten/tests/it/bats_invocation.rs

// CLOUD-908's case arms: every `@test` the retired suite declared, and where its
// predicate now lives. Twelve carried and one changed — the change is stated
// rather than smuggled, because a suite that asserted its own subject exists
// cannot port to a module that treats an absent subject as not-applicable.
//
// carried: "the suite runs in parallel — a silent revert to serial is this gate's whole purpose" policy/bats-invocation.rego
// carried: "the job count is derived from the machine, never a hand-typed number that outlives its runner" policy/bats-invocation.rego
// carried: "the job count is not capped below the machine — that was measured, and it is a large regression" policy/bats-invocation.rego
// carried: "the run asserts how many cases it executed, not merely that none failed" policy/bats-invocation.rego
// carried: "the suites are SELECTED, and the count is taken over the same list" policy/bats-invocation.rego
// carried: "a selector that answers nothing runs everything rather than narrowing" policy/bats-invocation.rego
// carried: "the report survives the run, or the cost corpus has no source" policy/bats-invocation.rego
// carried: "a jobs count of 1 is refused — that is serial wearing the flag's costume" policy/bats-invocation.rego
// carried: "tests are parallelised across files only, never within one" policy/bats-invocation.rego
// carried: "the parallel backend is named explicitly rather than left to bats' default probe" policy/bats-invocation.rego
// carried: "the parallel backend is a pinned tool, so the fast path cannot depend on the host" policy/bats-invocation.rego
// carried: "CI installs the parallel backend — an absent rush is a missing TOOL, not a slow suite" policy/bats-invocation.rego
// changed: "the test:bats invocation was found at all — this suite is not passing vacuously" crates/batten/tests/it/bats_invocation.rs the suite asserted its own subject exists, which a module cannot: a tree with no `test:bats` task is not-applicable rather than in violation, or the row fires on every fixture that copies this config (`command-task-defined` measured seven such findings). The property survives as `this_repository_is_clean_today` plus `a_tree_with_no_such_task_is_not_judged`, which together say the same thing about THIS tree without claiming it about every tree

// CLOUD-1268's fifth arm, and the first ledger block in this tree to use it. The
// four above describe a subject that went with its suite; `tests/helpers.bash` is
// loaded by eleven other suites, does not die, and is not touched — so every arm
// names it as the survivor it still accounts for. The file arm and the eight case
// arms are one delta.
//
// ported: tests/helpers.bats crates/batten/tests/it/bats_invocation.rs subject:tests/helpers.bash
// ported: "a command that finishes in time keeps its OWN exit status" crates/batten/tests/it/bats_invocation.rs subject:tests/helpers.bash
// ported: "a timed-out command is 124, GNU's timed-out status" crates/batten/tests/it/bats_invocation.rs subject:tests/helpers.bash
// ported: "-s KILL reports 137, because the child died of SIGKILL" crates/batten/tests/it/bats_invocation.rs subject:tests/helpers.bash
// ported: "-k on a subject that dies to TERM is 124 — the escalation never fires" crates/batten/tests/it/bats_invocation.rs subject:tests/helpers.bash
// ported: "-k that actually escalates is 137, matching GNU" crates/batten/tests/it/bats_invocation.rs subject:tests/helpers.bash
// ported: "a command killed by a signal it raised ITSELF is not a timeout" crates/batten/tests/it/bats_invocation.rs subject:tests/helpers.bash
// ported: "sed_i edits in place and leaves no backup behind" crates/batten/tests/it/bats_invocation.rs subject:tests/helpers.bash
// ported: "sed_i propagates a failing sed rather than reporting success" crates/batten/tests/it/bats_invocation.rs subject:tests/helpers.bash

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::fs;
use std::path::{Path, PathBuf};

use batten::rules::{self, Rule};

/// The row as `batten.toml` declares it, deserialized rather than
/// struct-literalled: `Rule` carries `deny_unknown_fields`, so this goes through
/// the same column census a consumer's config does.
fn row() -> Rule {
    serde_json::from_value(serde_json::json!({
        "id": "bats-invocation",
        "kind": "policy",
        "scope": "tree",
        "sources": ["mise.toml", ".github/workflows/ci.yml"],
        "line_sources": ["mise.toml", ".github/workflows/ci.yml"],
        "module": "policy/bats-invocation.rego",
        "severity": "deny",
    }))
    .expect("the row batten.toml declares")
}

/// A scratch tree carrying a manifest and a workflow, plus the committed module.
fn tree(name: &str, manifest: &str, workflow: &str) -> PathBuf {
    let root = common::scratch(&format!("bats-invocation-{name}"));
    common::write(&root, "mise.toml", manifest);
    common::write(&root, ".github/workflows/ci.yml", workflow);
    install_module(&root);
    root
}

/// The COMMITTED module, copied in rather than restated: an inline copy would
/// drift from the shipped one and pass while the real gate was broken.
fn install_module(root: &Path) {
    let source = common::at_root("policy/bats-invocation.rego")
        .canonicalize()
        .expect("the committed module is where the row says it is");
    fs::create_dir_all(root.join("policy")).expect("scratch policy dir");
    fs::copy(source, root.join("policy/bats-invocation.rego")).expect("install committed module");
}

fn findings(root: &Path) -> Vec<(String, Option<usize>)> {
    // A fixture holds this module and no other, so its own tree is the honest
    // vocabulary. The real checkout is not: `verdicts_in` would collect every
    // module's tokens while only this row is loaded, and registry equality runs
    // in BOTH directions — the load is refused for the tokens nothing here emits.
    // That refusal is correct (a class no gate reaches reads as coverage), so the
    // vocabulary is scoped rather than the assertion loosened.
    findings_declared_by(root, root)
}

fn findings_declared_by(root: &Path, vocabulary_root: &Path) -> Vec<(String, Option<usize>)> {
    let verdicts = common::verdicts_in(vocabulary_root);
    rules::run_static(
        &[row()],
        &[],
        batten::policy::Vocabulary {
            patterns: &[],
            verdicts: &verdicts,
            recorders: &[],
        },
        root,
    )
    .expect("the read surface runs a policy row")
    .findings
    .into_iter()
    .map(|finding| (finding.path, finding.line))
    .collect()
}

/// A manifest whose `test:bats` body carries every conjunct the row wants.
///
/// Assembled from the shipped body's own markers rather than copied wholesale:
/// a fixture that pasted the real 40-line body would be re-asserting the file
/// under test, and every edit to it would be a fixture edit too.
fn sound_manifest() -> String {
    format!(
        r#"
# sweep: measured=2026-08-28 cores=2 (taskset -c 0,1 on a 4-core box)
[tools]
"aqua:shenwei356/rush" = "0.6.0"

[tasks."test:bats"]
run = '''
{}
'''
"#,
        sound_body()
    )
}

fn sound_body() -> String {
    [
        r#"suites=$(./mise-tasks/suite-select.sh) || suites="""#,
        r#"if [ -z "$suites" ]; then suites=$(git ls-files); fi"#,
        r"expected=$(awk '/^@test /{n++} END{print n+0}' $suites)",
        "workers=$(nproc)",
        "report=./target/bats-report",
        "started=$(date +%s)",
        r#"bats --parallel-binary-name rush --jobs "$workers" --no-parallelize-within-files --report-formatter junit --output "$report" $suites"#,
        "elapsed=$(($(date +%s) - started))",
        r#"if [ "$ran" != "$expected" ]; then echo "of $expected cases reported by the runner"; fi"#,
        "recorded=$(awk -f - bench/suites/RESULTS.md)",
        r#"if [ "$recorded" = "-" ]; then :; fi"#,
        r#"if [ "$elapsed" -ge "$recorded" ]; then echo "::error:: slower"; fi"#,
        r#"echo "${elapsed}s wall vs ${recorded}s recorded serial""#,
    ]
    .join("\n")
}

// THE JOB THAT RUNS THE SUITE CARRIES THE INVOCATION AS WELL AS THE INSTALL LIST
// (CLOUD-1140). The install clause used to read `jobs.ci.steps` by name, correct
// exactly while the `ci` job ran the suite; it derives the job from the
// `mise run test:bats` invocation now, so it follows the suite wherever it goes.
// A fixture carrying only the list would leave that derivation empty and the
// clause vacuous — green over every mutation of it, which is a fixture that
// cannot reach the assertion it exists for.
//
// The budget comment stays on the `ci` job because that is where the workflow
// carries it, and the two clauses read different jobs on purpose.
const SOUND_WORKFLOW: &str = r"
jobs:
  ci:
    timeout-minutes: 87 # budget: p95=1730s x3 measured=2026-08-28
    steps:
      - run: mise run ci
  bats:
    steps:
      - run: mise run test:bats
      - uses: jdx/mise-action@v4
        with:
          install_args: rust hk aqua:shenwei356/rush
";

// ---------------------------------------------------------------------------
// The tree this row actually defends.
// ---------------------------------------------------------------------------

#[test]
fn this_repository_is_clean_today() {
    let root = common::at_root(".")
        .canonicalize()
        .expect("this checkout is where the manifest says it is");
    // The vocabulary comes from a directory holding only this module, for the
    // reason `findings` states; the scratch name is this case's own, because
    // nextest runs each case in its own process and a shared name is a wipe under
    // another process's read.
    let only = common::scratch("bats-invocation-vocabulary-real-tree");
    install_module(&only);
    let found = findings_declared_by(&root, &only);
    assert!(
        found.is_empty(),
        "the committed invocation should satisfy its own row: {found:?}"
    );
}

#[test]
fn the_fixture_shape_is_clean_too() {
    // Without this, every refusal below could be produced by a fixture the row
    // simply cannot read — a module that fires on everything looks identical to
    // one that discriminates, until something is supposed to pass.
    let root = tree("sound", &sound_manifest(), SOUND_WORKFLOW);
    assert!(
        findings(&root).is_empty(),
        "the sound fixture should be clean: {:?}",
        findings(&root)
    );
}

// ---------------------------------------------------------------------------
// The speed-up, and the two ways it goes away.
// ---------------------------------------------------------------------------

#[test]
fn a_body_that_lost_the_worker_flag_is_refused() {
    let manifest = sound_manifest().replace(r#"--jobs "$workers""#, "");
    let root = tree("no-jobs", &manifest, SOUND_WORKFLOW);
    let found = findings(&root);
    assert!(
        found.iter().any(|(path, _)| path == "mise.toml"),
        "a dropped --jobs should be refused against the manifest: {found:?}"
    );
}

#[test]
fn a_worker_count_capped_below_the_machine_is_refused() {
    let manifest = sound_manifest().replace("workers=$(nproc)", "workers=$(($(nproc) / 2))");
    let root = tree("capped", &manifest, SOUND_WORKFLOW);
    assert!(
        !findings(&root).is_empty(),
        "capping the count below the machine should be refused"
    );
}

#[test]
fn a_workflow_that_does_not_install_the_backend_is_refused() {
    // The half `ci-tools-check` structurally cannot answer: it holds names in the
    // workflow to being declared in the manifest, never a tool the gate needs to
    // being installed. bats aborts rather than falling back when the named
    // parallel binary is absent, so the omission is a failed gate, not a slow one.
    let workflow = SOUND_WORKFLOW.replace(" aqua:shenwei356/rush", "");
    let root = tree("no-rush", &sound_manifest(), &workflow);
    let found = findings(&root);
    assert!(
        found
            .iter()
            .any(|(path, _)| path == ".github/workflows/ci.yml"),
        "the workflow should be named as the place to fix it: {found:?}"
    );
}

// ---------------------------------------------------------------------------
// The count, and the cost.
// ---------------------------------------------------------------------------

#[test]
fn a_run_that_asserts_no_count_is_refused() {
    let manifest = sound_manifest().replace(r#""$ran" != "$expected""#, "false");
    let root = tree("uncounted", &manifest, SOUND_WORKFLOW);
    assert!(
        !findings(&root).is_empty(),
        "a run that cannot say how many cases it executed should be refused"
    );
}

#[test]
fn a_run_that_compares_no_wall_clock_is_refused() {
    let manifest = sound_manifest().replace(r#"[ "$elapsed" -ge "$recorded" ]"#, "false");
    let root = tree("uncosted", &manifest, SOUND_WORKFLOW);
    assert!(
        !findings(&root).is_empty(),
        "a run that measures nothing against the corpus should be refused"
    );
}

#[test]
fn a_budget_measured_before_the_sweep_is_refused() {
    // CLOUD-386's third predicate, and the one that needs both files at once: the
    // sweep's date lives in a manifest COMMENT and the budget's in a workflow
    // comment, so neither is visible to a parsed document and both come from
    // `line_sources`. This case is what proves the engine fills that key for two
    // paths in one row.
    let workflow = SOUND_WORKFLOW.replace(
        "timeout-minutes: 87 # budget: p95=1730s x3 measured=2026-08-28",
        "timeout-minutes: 36 # budget: p95=701s x3 measured=2026-08-14",
    );
    let root = tree("stale-budget", &sound_manifest(), &workflow);
    let found = findings(&root);
    assert!(
        found
            .iter()
            .any(|(path, line)| path == ".github/workflows/ci.yml" && line.is_some()),
        "the stale budget line should be pointed at: {found:?}"
    );
}

#[test]
fn a_sweep_that_names_no_hardware_is_refused() {
    // The defect that produced the predicate: the recorded optimum was measured on
    // a 4-core box and the runner has 2, so the table read as a live instruction
    // about hardware CI does not have.
    let manifest = sound_manifest().replace(
        "# sweep: measured=2026-08-28 cores=2 (taskset -c 0,1 on a 4-core box)",
        "# the sweep says four is best",
    );
    let root = tree("no-hardware", &manifest, SOUND_WORKFLOW);
    assert!(
        !findings(&root).is_empty(),
        "a sweep table that cannot say what it was taken on should be refused"
    );
}

// ---------------------------------------------------------------------------
// Not-applicable is not a pass, and is not a refusal either.
// ---------------------------------------------------------------------------

#[test]
fn a_tree_with_no_such_task_is_not_judged() {
    // `command-task-defined`'s measured lesson, one row over: an unguarded module
    // reported seven findings against a fixture that copies this config without a
    // task namespace, including against a case named "this repository is clean
    // today".
    let manifest = "[tasks.other]\nrun = \"true\"\n";
    let root = tree("foreign", manifest, SOUND_WORKFLOW);
    assert!(
        findings(&root).is_empty(),
        "a tree with no pole is answering for nothing: {:?}",
        findings(&root)
    );
}

// ---------------------------------------------------------------------------
// `tests/helpers.bash`'s exit contract (CLOUD-282, ported under CLOUD-1268).
//
// PORTED, NOT RETIRED, AND THE SUBJECT IS THE WHOLE REASON. `tests/helpers.bash`
// is loaded by eleven other suites; it does not die and is not touched. What died
// is `tests/helpers.bats`, whose 8 cases are these — a port-without-retirement,
// which is the shape the fifth ledger arm exists to spell.
//
// WHY THE COVERAGE MOVED RATHER THAN GOING. `run_timeout` stands in for a GNU
// `timeout(1)` macOS does not ship, at call sites that assert exact numbers. Nine
// of them across three suites depend on the mapping, so a helper that returned
// merely "non-zero" would make every one pass vacuously. Each branch stays pinned.
//
// WHY IT IS FASTER HERE, which is the point of the port rather than a side effect:
// `test:bats` runs `--no-parallelize-within-files`, so these eight cases were
// serial by construction and several of them WAIT. nextest parallelises per test.
//
// UNIX ONLY, AND THE PORT IS WHAT MADE THAT NEED SAYING. Every number below is
// POSIX's `128 + signal`: 137 is SIGKILL, 143 is SIGTERM, and 124 is what GNU
// `timeout(1)` returns so that a caller can tell a timeout from either. Windows
// has no such mapping, so `kill -TERM $$` under Git Bash exits 1 and the whole
// contract is not merely untestable there but meaningless.
//
// The BATS lane is ubuntu-only, so `tests/helpers.bats` never ran on Windows and
// this gate takes nothing away — measured the hard way, on CI: porting these onto
// `cargo test` silently WIDENED them onto the windows matrix, and
// `a_command_killed_by_a_signal_it_raised_itself_is_not_a_timeout` failed there
// with `left: 1, right: 143` while every POSIX runner stayed green. A port moves
// a case between harnesses, and the harnesses do not run the same platforms; that
// difference is the port's to declare rather than the next author's to discover.
// ---------------------------------------------------------------------------

#[cfg(unix)]
/// Run one expression against the committed helper library and return its status.
///
/// The library is SOURCED from the real checkout rather than copied into a
/// fixture: it is the subject, it survives this change, and a copy would drift
/// and pass while the shipped helper was broken — the same argument
/// `install_module` above makes for a policy module.
fn helper_status(script: &str) -> i32 {
    let root = common::at_root(".")
        .canonicalize()
        .expect("this checkout is where the manifest says it is");
    let tmp = common::scratch("helpers-bash");
    // `run_timeout` writes its flag file under `$BATS_TEST_TMPDIR`, falling back
    // to `/tmp`. Pointing it at a scratch dir keeps concurrent cases from sharing
    // one path — nextest runs each case in its own process, and the fallback is
    // shared where the bats harness's per-test dir was not.
    #[expect(
        clippy::disallowed_types,
        reason = "stays — CLOUD-1268: the subject IS a bash library, so exercising it means running bash. The retired suite made this same spawn; it moved rather than being added, and it goes when `tests/helpers.bash` does"
    )]
    let output = std::process::Command::new("bash")
        .arg("-c")
        .arg(format!(
            "source '{}/tests/helpers.bash'\n{script}",
            root.display()
        ))
        .env("BATS_TEST_TMPDIR", &tmp)
        .current_dir(&root)
        .output()
        .expect("bash runs the committed helper");
    output.status.code().unwrap_or(-1)
}

#[cfg(unix)]
#[test]
fn a_command_that_finishes_in_time_keeps_its_own_exit_status() {
    // The pass-through case, and the one a naive implementation gets wrong by
    // reporting the watchdog's status instead.
    assert_eq!(helper_status("run_timeout 10 bash -c 'exit 7'"), 7);
    assert_eq!(helper_status("run_timeout 10 true"), 0);
}

#[cfg(unix)]
#[test]
fn a_timed_out_command_is_124() {
    // `tests/land.bats` asserts this number directly: 124 is GNU's timed-out
    // status and the result that case is proving, not a failure of it.
    assert_eq!(helper_status("run_timeout 1 sleep 30"), 124);
}

#[cfg(unix)]
#[test]
fn kill_reports_137_because_the_child_died_of_sigkill() {
    // `tests/main-watch.bats` asserts 137. It uses KILL rather than the default
    // TERM because bash defers a trapped signal until the running `sleep` returns,
    // so a TERM would cost every blocking case a full poll interval.
    assert_eq!(helper_status("run_timeout -s KILL 1 sleep 30"), 137);
}

#[cfg(unix)]
#[test]
fn an_escalation_that_never_fires_is_124() {
    // `tests/land.bats`' shape: `land` takes the TERM, so `-k` is insurance and
    // the answer is the plain timed-out status. Measured against GNU coreutils
    // and matched here rather than assumed.
    assert_eq!(helper_status("run_timeout -k 1 1 sleep 30"), 124);
}

#[cfg(unix)]
#[test]
fn an_escalation_that_actually_fires_is_137() {
    // The half worth measuring rather than guessing: GNU reports the SIGNAL that
    // ended the child, not the timeout, once the escalation is what ended it. A
    // helper answering 124 here would disagree with the tool it replaces in the
    // one case the two could differ.
    assert_eq!(
        helper_status("run_timeout -k 1 1 bash -c 'trap \"\" TERM; sleep 30'"),
        137
    );
}

#[cfg(unix)]
#[test]
fn a_command_killed_by_a_signal_it_raised_itself_is_not_a_timeout() {
    // The distinction the flag file exists for: 143 is TERM, the same status a
    // TERM-timeout produces, so an implementation reading only the exit status
    // would report this as 124 and hide a genuine crash.
    assert_eq!(helper_status("run_timeout 10 bash -c 'kill -TERM $$'"), 143);
}

#[cfg(unix)]
#[test]
fn sed_i_edits_in_place_and_leaves_no_backup_behind() {
    // `-i.bak` is the one spelling GNU and BSD both accept; the backup is an
    // artifact of portability, so the helper removes it and no call site has to
    // know it existed. A stray `.bak` would break suites that list a fixture dir.
    let dir = common::scratch("helpers-sed-i");
    let subject = dir.join("subject");
    fs::write(&subject, "alpha\nbeta\n").expect("write the subject");
    let status = helper_status(&format!("sed_i 's/alpha/gamma/' '{}'", subject.display()));
    assert_eq!(status, 0, "a well-formed edit succeeds");
    assert_eq!(
        fs::read_to_string(&subject).expect("read back"),
        "gamma\nbeta\n"
    );
    assert!(
        !dir.join("subject.bak").exists(),
        "the portability backup is removed rather than left in the tree"
    );
}

#[cfg(unix)]
#[test]
fn sed_i_propagates_a_failing_sed_rather_than_reporting_success() {
    // A gate helper that swallowed the status would be the CLOUD-199 shape in
    // miniature: the edit silently not happening, reported green.
    let dir = common::scratch("helpers-sed-i-fail");
    let absent = dir.join("absent");
    assert_ne!(
        helper_status(&format!("sed_i 's/unterminated' '{}'", absent.display())),
        0,
        "a failing sed is a failing helper"
    );
}
