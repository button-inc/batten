//! `batten mutate` over the compiled binary (CLOUD-418, CLOUD-1267).
//!
//! # What this file is the successor to
//!
//! `tests/mutant.bats` and `tests/mutant-census.bats`, whose subjects —
//! `mise-tasks/mutant.sh` and `mise-tasks/mutant-census.sh` — this change
//! deletes. Every case below builds a throwaway repository with one toy gate and
//! one toy suite, because the subject here is the HARNESS, not any real gate's
//! coverage: running it against the live enforced set would make this file's
//! verdict a function of whichever gate someone edited last, which is the
//! opposite of a decision table.
//!
//! # The case the port exists for
//!
//! `a_declared_rust_suite_is_reddened_by_a_mutation_on_the_module` is
//! CLOUD-1267 in one assertion. The predecessor resolved a gate's suite as
//! `tests/<gate>.bats` unconditionally, so a mutation on a `.rego` module had
//! nothing that could turn red and the runner answered `no-suite`. That fixture
//! is a policy module, a `#MUTANT-SUITE` naming a Rust tier, and a mutation the
//! tier catches — the shape 29 exemptions said was unreachable.
//!
//! Its mirror is `a_module_whose_tier_cannot_see_it_reports_a_survivor`, and the
//! pair is what makes either evidence: a runner that reported `caught` for
//! everything would pass the first and fail the second.
//!
//! # Why `git` and `cargo` are real here
//!
//! The repository is local and instant, and stubbing either would test the
//! stub. Every fixture is a single package with no dependencies, so its `cargo
//! test` compiles in seconds against a target directory of its own.
//!
//! # Why the decision table runs over Rust tiers (CLOUD-843, CLOUD-2160)
//!
//! The toy suites were shell suites run through a runner this repository
//! vendored. CLOUD-843 retired that runner with the last shell suite and
//! CLOUD-2160 retired its arm from the engine, so the decision table runs over
//! Rust tiers: it is decided in `judge_row` over a `Selection`, which every arm
//! produces, so every verdict below is carried.
//!
//! # Why the native harnesses are stubs replaying recorded output
//!
//! `tofu`, `kyverno`, `conftest` and `pytest` are a consumer's tools, not this
//! repository's, so pinning them here would add four toolchains to test four
//! readers. Each arm's harness is instead a shebang stub on the case's `PATH`
//! that replays one of three outputs recorded ONCE from the real tool —
//! `crates/batten/tests/fixtures/mutate/<arm>/{pass,fail,error}`, the version on
//! each file's first line. The stub picks by reading the staged subject: a row
//! rewrites its sentinel to `KILL` (replays `fail`) or `BREAK` (replays
//! `error`), or changes an unread line (replays `pass`). So the readers are held
//! to the real tools' bytes, and real-tool conformance is the first consumer's
//! own sweep.

// THE FILE-GRANULARITY RETIREMENT ARMS (CLOUD-1059). Their grammar is disjoint
// from CLOUD-908's case arms below by construction: a case arm's first field
// after the marker is a QUOTED case name, and a file arm's is a path.
//
// carried: mise-tasks/mutant.sh crates/batten/src/mutate.rs kind:verb crates/batten/tests/it/mutate.rs
// carried: tests/mutant.bats crates/batten/src/mutate.rs kind:verb crates/batten/tests/it/mutate.rs
// carried: mise-tasks/mutant-census.sh crates/batten/src/mutate.rs kind:verb crates/batten/tests/it/mutate.rs
// carried: tests/mutant-census.bats crates/batten/src/mutate.rs kind:verb crates/batten/tests/it/mutate.rs

// THE CASE ARMS (CLOUD-908). One per `@test` the two dying suites declared.
//
// carried: "mutant.bats::a mutation its suite catches is a pass" crates/batten/tests/it/mutate.rs
// carried: "mutant.bats::THE DEFECT: a mutation the suite does NOT catch fails" crates/batten/tests/it/mutate.rs
// carried: "mutant.bats::A ROW IS EXACTLY THREE FIELDS, and a fourth is refused before the split" crates/batten/tests/it/mutate.rs
// carried: "mutant.bats::A FILTER THAT SELECTS THE WHOLE SUITE names no case, like one that selects none" crates/batten/tests/it/mutate.rs
// carried: "mutant.bats::a filter selecting one case of a single-case suite is not read as too wide" crates/batten/tests/it/mutate.rs
// carried: "mutant.bats::THE TREE IS RESTORED BETWEEN ROWS, so a gate is judged against a pristine sibling" crates/batten/tests/it/mutate.rs
// carried: "mutant.bats::A ROW THAT MUTATES ITS OWN DECLARATION is refused, not reported as a survivor" crates/batten/tests/it/mutate.rs
// carried: "mutant.bats::THE COPY IS A REPOSITORY, so a suite that resolves its own root answers about it" crates/batten/tests/it/mutate.rs
// carried: "mutant.bats::ANTI-VACUITY: a listed gate with NO declaration fails, rather than being skipped" crates/batten/tests/it/mutate.rs
// carried: "mutant.bats::ANTI-VACUITY: a filter naming no case is not a pass" crates/batten/tests/it/mutate.rs
// carried: "mutant.bats::ANTI-VACUITY: a mutation that changes nothing is not a pass" crates/batten/tests/it/mutate.rs
// carried: "mutant.bats::an unset enforced set is fatal rather than an empty one" crates/batten/tests/it/mutate.rs
// changed: "mutant.bats::a gate named with no suite is reported, not silently passed" crates/batten/tests/it/mutate.rs the verdict is unchanged and its EXIT CODE is not: could-not-look is exit 3 where the predecessor answered 1, which is the acceptance CLOUD-1267 states
// carried: "mutant.bats::POINTER, NEVER PAYLOAD: the report carries no line of the mutated source" crates/batten/tests/it/mutate.rs
// carried: "mutant.bats::the tracked file is never mutated in place" crates/batten/tests/it/mutate.rs
// carried: "mutant.bats::an UNCOMMITTED case is still covered — the working tree is the subject" crates/batten/tests/it/mutate.rs
// carried: "mutant.bats::ANTI-VACUITY: a case that is red BEFORE the mutation is not evidence" crates/batten/tests/it/mutate.rs
// carried: "mutant-census.bats::a gate named in the set is a closed census" crates/batten/tests/it/mutate.rs
// carried: "mutant-census.bats::THE DEFECT: a gate the set omits is uncovered, and named" crates/batten/tests/it/mutate.rs
// carried: "mutant-census.bats::a task that does not describe itself as a gate owes no mutation" crates/batten/tests/it/mutate.rs
// carried: "mutant-census.bats::a hook body is a gate too — it decides by emitting a deny" crates/batten/tests/it/mutate.rs
// carried: "mutant-census.bats::a policy module is censused unconditionally, so a migration cannot shrink the set" crates/batten/tests/it/mutate.rs
// carried: "mutant-census.bats::a filed exemption is a closed census, not a gap" crates/batten/tests/it/mutate.rs
// carried: "mutant-census.bats::an exemption naming no issue is unfiled — the whole difference from a TODO" crates/batten/tests/it/mutate.rs
// carried: "mutant-census.bats::an exemption with no reason is unfiled as well" crates/batten/tests/it/mutate.rs
// carried: "mutant-census.bats::declared AND exempt is refused — the reason would be a dead letter" crates/batten/tests/it/mutate.rs
// carried: "mutant-census.bats::THE REVERSE DIRECTION: a name in the set resolving to no gate is refused" crates/batten/tests/it/mutate.rs
// carried: "mutant-census.bats::an unset set is could-not-look, never a closed census" crates/batten/tests/it/mutate.rs
// changed: "mutant-census.bats::ANTI-VACUITY: a tree resolving no gate at all is exit 2, not perfect coverage" crates/batten/tests/it/mutate.rs an empty subject set is no longer a separate refusal: the census reports the reverse direction instead, so a set naming gates over a tree holding none is `names-no-subject` per name rather than one unreadable verdict about the tree
// carried: "mutant-census.bats::output is pointer-only — the exemption's reason never reaches the log" crates/batten/tests/it/mutate.rs
// carried: "mutant-census.bats::this repository's own census is closed — the gate on the real tree" crates/batten/tests/it/mutate.rs

// THE FIXTURE CASES. The dying suites wrote a toy suite inside a heredoc, so
// these `@test` lines are the SUBJECT a case exercised rather than a case of the
// suite itself — and the counter cannot tell the two apart, which is right: a
// fixture case deleted with nothing carrying it is coverage lost either way.
// They travel into `toy_suite` and `rust_tier_repo` here, exercised by every case
// that builds a toy repository.
//
// carried: "mutant.bats::over the limit is refused" crates/batten/tests/it/mutate.rs
// carried: "mutant.bats::under the limit passes" crates/batten/tests/it/mutate.rs
// carried: "mutant.bats::the sibling answers strict" crates/batten/tests/it/mutate.rs
// carried: "mutant.bats::the composer refuses under a strict sibling" crates/batten/tests/it/mutate.rs
// carried: "mutant.bats::over the limit is refused, from a root the suite resolves itself" crates/batten/tests/it/mutate.rs
// carried: "mutant.bats::an uncommitted case is exercised" crates/batten/tests/it/mutate.rs

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;
// Only the unix cases capture a child, so only they need the adapter's trait.
#[cfg(unix)]
use batten::capture::Streamed as _;

use std::fs;
use std::path::{Path, PathBuf};

use common::{stderr, stdout};

// ---------------------------------------------------------------------------
// The fixtures.
// ---------------------------------------------------------------------------

/// A toy gate with one real decision. `LIMIT` is what a mutation moves.
///
/// **IT DECLARES ITS SUITE, AND THE SUITE IS A RUST TIER (CLOUD-843).** A gate
/// with no `#MUTANT-SUITE` reports `no-suite (undeclared)` and runs nothing
/// (CLOUD-2160). The harness is suite-agnostic above `run_suite`: every verdict
/// this file's decision table asserts is decided by `judge_row` over a
/// `Selection`, which every arm produces.
/// Where the toy repositories keep presets, as this repository's `[env]`
/// declares its own: the crate names no preset directory (CLOUD-2711).
const PRESETS: &str = "crates/batten/src/policy/presets";

const TOY_GATE: &str = r#"#!/usr/bin/env bash
#MISE description="Gate: the toy"
#MUTANT-SUITE tests/toy.rs
set -uo pipefail
LIMIT=10
[ "${1:-0}" -le "$LIMIT" ] || exit 1
exit 0
"#;

/// The helper every toy tier opens with: run the staged gate named `@GATE@`
/// with one argument and answer its exit code.
///
/// `CARGO_MANIFEST_DIR` is the STAGED tree, because the sweep runs `cargo` there
/// — so the tier executes the mutated gate, never the source tree's.
///
/// THROUGH `bash`, NOT THE FILE'S EXEC BIT, so the tier runs on every platform.
/// The gate is a bash program, so bash is the subject's own dependency; what was
/// unix-only was executing the file directly, which needs a mode bit and a
/// shebang Windows has neither of. Every CI leg carries `bash` (Git for Windows
/// on the `windows` runner), and the sweep applies a row in-process
/// (`mutate::substitute`), so nothing else here needs a unix host.
const GATE_HELPER: &str = r#"fn gate(input: &str) -> Option<i32> {
    std::process::Command::new("bash")
        .arg(concat!(env!("CARGO_MANIFEST_DIR"), "/mise-tasks/@GATE@"))
        .arg(input)
        .status()
        .expect("run the toy gate")
        .code()
}
"#;

/// The mutation the toy suite catches: the gate stops refusing anything.
const CAUGHT: &str = "#MUTANT limit-ignored|s/^LIMIT=10$/LIMIT=999/|over_the_limit_is_refused";

/// The package every toy carries, so `cargo test` has something to build.
///
/// `[workspace]` is load-bearing: the scratch root lives under this crate's own
/// `target/`, so without it cargo resolves the enclosing workspace and refuses
/// the package as an unlisted member.
const TOY_MANIFEST: &str = "[package]\nname = \"toy\"\nversion = \"0.0.0\"\nedition = \
                            \"2021\"\n\n[lib]\npath = \"src/lib.rs\"\n\n[workspace]\n";

/// A wiped scratch repository.
fn toy(name: &str) -> PathBuf {
    let root = common::scratch(&format!("mutate-{name}"));
    common::git_in(&root, &["init", "--initial-branch=main"]);
    root
}

fn write(root: &Path, path: &str, body: &str) {
    common::write(root, path, body);
}

/// Make `root` a single package with no dependencies, so its tiers compile in
/// seconds against the sweep's own target directory.
fn cargo_package(root: &Path) {
    write(root, "Cargo.toml", TOY_MANIFEST);
    write(root, "src/lib.rs", "");
}

/// Write an executable program.
fn write_program(root: &Path, path: &str, body: &str) {
    common::write(root, path, body);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(root.join(path), fs::Permissions::from_mode(0o755))
            .expect("make the toy gate executable");
    }
}

/// Track everything written so far. The staged tree is the TRACKED set, so a
/// fixture that skipped this would be staging nothing.
fn track(root: &Path) {
    common::git_in(root, &["add", "-A"]);
}

/// The helper that runs the staged gate `mise-tasks/<gate>`.
fn runs(gate: &str) -> String {
    GATE_HELPER.replace("@GATE@", gate)
}

/// One libtest case. Its NAME is what a row's filter selects: a row names a
/// case by the whole function name (or its trailing `module::` path), never a
/// substring of it.
fn case(name: &str, body: &str) -> String {
    format!("\n#[test]\nfn {name}() {{\n    {body}\n}}\n")
}

/// Two cases, so a filter can name one of them and `total > 1` holds. `prefix`
/// keeps two suites in one package apart: `cargo test -- <filter>` runs every
/// test target, so two suites sharing a case name would both be selected.
fn toy_suite(gate: &str, prefix: &str) -> String {
    format!(
        "{}{}{}",
        runs(gate),
        case(
            &format!("{prefix}over_the_limit_is_refused"),
            "assert_eq!(gate(\"99\"), Some(1));"
        ),
        case(
            &format!("{prefix}under_the_limit_passes"),
            "assert_eq!(gate(\"1\"), Some(0));"
        ),
    )
}

/// A toy repository carrying one gate, one suite and the declared rows.
///
/// Portable: the tier runs the gate through `bash`, not its exec bit (`GATE_HELPER`).
fn toy_repo(name: &str, rows: &[&str]) -> PathBuf {
    let root = toy(name);
    let mut gate = String::from(TOY_GATE);
    for row in rows {
        gate.push_str(row);
        gate.push('\n');
    }
    write_program(&root, "mise-tasks/toy.sh", &gate);
    write(&root, "tests/toy.rs", &toy_suite("toy.sh", ""));
    cargo_package(&root);
    track(&root);
    root
}

/// Run a verb of `mutate` in `root` with the enforced set `gates`.
fn run(root: &Path, verb: &str, gates: &str) -> (i32, String, String) {
    run_with(root, verb, gates, &[])
}

/// [`run`], with `extra` variables for the sweep and every child it starts.
fn run_with(
    root: &Path,
    verb: &str,
    gates: &str,
    extra: &[(&str, &Path)],
) -> (i32, String, String) {
    let answer = common::batten()
        .args(["mutate", verb])
        .current_dir(root)
        // A forge runner's own `$CI`, and the step cache's bypass, either of
        // which turns the row record off (`step::bypassed`): a case that wants
        // one names it in `extra`, so its verdict does not depend on where it ran.
        .env_remove("CI")
        .env_remove("BATTEN_STEP_RECEIPT_BYPASS")
        .envs(extra.iter().copied())
        .env("MUTANT_GATES", gates)
        // Declared explicitly rather than inherited, so a case's verdict does not
        // depend on whether the runner happened to export the repository's own
        // `[env]` (CLOUD-1909). A toy with no manifest resolves no `task-` gate
        // either way.
        .env("MUTANT_TASKS", "mise.toml")
        .env("MUTANT_PRESETS", PRESETS)
        // A PROFILE NO TOY DECLARES, as a consumer's `[env]` may export (this
        // repository's did under CI until CLOUD-2588), so every case whose Cargo
        // row reaches nextest proves an undeclared
        // inherited profile does not reach the sweep's nextest runs.
        .env("NEXTEST_PROFILE", "ci")
        .streamed_output()
        .expect("run batten mutate");
    (
        answer.status.code().unwrap_or(-1),
        stdout(&answer),
        stderr(&answer),
    )
}

fn sweep(root: &Path, gates: &str) -> (i32, String, String) {
    run(root, "sweep", gates)
}

fn census(root: &Path, gates: &str) -> (i32, String, String) {
    run(root, "census", gates)
}

// ---------------------------------------------------------------------------
// The sweep's decision table.
// ---------------------------------------------------------------------------

/// A `$MUTANT_SHARD` that is not `k/n` is a usage error before any row is
/// judged, never a sweep of every row (CLOUD-2533). Fails by: a set shard read as
/// unset, which sweeps the named gate and answers for it instead.
#[test]
fn a_malformed_shard_is_refused_before_the_sweep() {
    let root = toy("shard-malformed");
    let answer = common::batten()
        .args(["mutate", "sweep"])
        .current_dir(&root)
        .env("MUTANT_GATES", "nope")
        .env("MUTANT_TASKS", "mise.toml")
        .env(batten::mutate::SHARD, "two/four")
        .streamed_output()
        .expect("run batten mutate");
    let err = stderr(&answer);
    assert_eq!(answer.status.code(), Some(1), "the usage code: {err}");
    assert!(err.contains("MUTANT_SHARD=two/four"), "{err}");
}

/// The registered runner takes the shard the sweep already parsed (CLOUD-2541),
/// so a malformed `$MUTANT_SHARD` under any `MUTANT_RUNNER` is the one usage
/// error, refused before the runner is resolved. A second refusal downstream
/// once printed `mutate: mutate: ...` at exit 3; the assertion on that text
/// guards against its return. Fails by: the sweep's refusal dropped.
#[test]
fn a_malformed_shard_is_refused_before_the_registered_runner() {
    let root = toy("shard-malformed-registered");
    let answer = common::batten()
        .args(["mutate", "sweep"])
        .current_dir(&root)
        .env("MUTANT_GATES", "nope")
        .env("MUTANT_TASKS", "mise.toml")
        .env("MUTANT_RUNNERS", "cargo-mutants=crates/**/*.rs")
        .env("MUTANT_RUNNER", "cargo-mutants")
        .env("MUTANT_CHANGED_SINCE", "HEAD")
        .env(batten::mutate::SHARD, "two/four")
        .streamed_output()
        .expect("run batten mutate");
    let err = stderr(&answer);
    assert_eq!(answer.status.code(), Some(1), "the usage code: {err}");
    assert_eq!(err.matches("MUTANT_SHARD=two/four").count(), 1, "{err}");
    assert!(!err.contains("mutate: mutate:"), "{err}");
}

/// ANTI-VACUITY FOR THE SWEEP'S OWN WATCHDOG (CLOUD-1726).
///
/// The bound moved out of `BATS_TEST_TIMEOUT` and into the sweep, because the
/// runner implements its bound as a `sleep N` child it does not reap on a
/// FAILING case — and a caught mutation is a failing case, so every row the
/// sweep got right waited the bound out. Unsetting it took this module from
/// 92.6s to 2.4s.
///
/// That is only safe while something still ends a suite that genuinely hangs,
/// which is what a mutation sweep must survive by construction: a mutant can
/// make a gate loop forever. Without this case the removal is indistinguishable
/// from having no bound at all, and the first hanging mutant would block a sweep
/// until somebody noticed.
#[cfg(unix)]
#[test]
fn a_suite_that_hangs_is_ended_by_the_sweeps_own_bound() {
    let (root, hung) = hung_toy("hangs");

    let answer = common::batten()
        .args(["mutate", "sweep"])
        .current_dir(&root)
        .env("MUTANT_GATES", "toy")
        // Ten rather than the two a bats run fitted in: the timed run is a warm
        // `cargo test`, whose freshness check is part of the bound even though
        // the build itself is paid beforehand under the build bound.
        .env("BATTEN_MUTATE_SUITE_TIMEOUT", "10")
        .streamed_output()
        .expect("run batten mutate");

    // THE BOUND FIRED, READ FROM WHAT THE SWEEP RECORDED RATHER THAN FROM A
    // CLOCK (CLOUD-2059). `suite-timed-out` is set in exactly one place, when
    // the bound runs out, and a bound that never fired would not return at all
    // before the hour the case sleeps — so the elapsed-time ceiling this case
    // used to assert added nothing the verdict below does not already decide.
    //
    // AND NOTHING THE SUITE STARTED OUTLIVES IT (CLOUD-2059). Killing the direct
    // child alone left the test binary and its own child alive under init; two
    // were found 35 and 56 minutes after their runs, on the machine running
    // this suite. Both pids the hung case recorded must be gone.
    // WAITED ON AS AN EVENT (CLOUD-2789): the toy and its child each hold the
    // `alive` fifo, so its end of file is both of them gone. One the bound
    // left running holds it open, and this case hangs on it: the bound must
    // end the suite's whole process group, not its direct child.
    hung.ended();
    // AND WHAT IT REPORTS, WHICH THIS CASE USED TO DECLINE TO ASSERT
    // (CLOUD-1860). The declining comment read: *"what a killed suite reports is
    // the sweep's business and is covered by the decision table above."* It was
    // not covered, and the gap was the defect: a killed run selects no case, so
    // the sweep called it `names-no-case` — a filter that matches nothing — for
    // a case that is present and green. Every Rust suite hit that, because a
    // cargo run cannot finish inside a bats-sized bound: 109 of 341 declared
    // mutations reported a filter fault and looked at nothing, while the verb
    // reported coverage.
    //
    // So the bound firing is half the property and NAMING ITS OWN CAUSE is the
    // other half.
    let code = answer.status.code().unwrap_or(-1);
    let out = stdout(&answer);
    assert_eq!(code, 3, "a killed suite is a could-not-look: {out}");
    assert!(
        out.contains("suite-timed-out"),
        "the verdict must name the clock, not the filter: {out}"
    );
    assert!(
        !out.contains("names-no-case"),
        "blaming the filter sends the reader to repair a declaration that is \
         already correct: {out}"
    );
}

/// A SED THAT HANGS SAYS NOTHING ABOUT THE ROW, BECAUSE NO SED RUNS (CLOUD-2246,
/// CLOUD-2255).
///
/// `apply` read a spawned sed's `ok` alone, so a hung sed reported
/// `unappliable-mutation` and blamed a correct row. The row is now applied in
/// process: the `sed` first on `PATH` here hangs forever, and the sweep still
/// applies the row and reports it caught.
#[cfg(unix)]
#[test]
fn a_mutation_whose_sed_times_out_is_not_unappliable() {
    let root = toy_repo("sed-hangs", &[CAUGHT]);
    let bin = common::scratch("mutate-sed-hangs-bin");
    write_program(&bin, "sed", "#!/bin/sh\nexec sleep 3600\n");
    let path = std::env::join_paths(std::iter::once(bin).chain(std::env::split_paths(
        &std::env::var_os("PATH").unwrap_or_default(),
    )))
    .expect("join PATH");
    let answer = common::batten()
        .args(["mutate", "sweep"])
        .current_dir(&root)
        .env("MUTANT_GATES", "toy")
        .env("MUTANT_TASKS", "mise.toml")
        .env("PATH", path)
        .streamed_output()
        .expect("run batten mutate");
    let out = stdout(&answer);
    assert_eq!(answer.status.code(), Some(0), "the row applied: {out}");
    assert!(out.contains("every one caught"), "{out}");
    assert!(!out.contains("unappliable-mutation"), "{out}");
}

/// The tracked sources whose rows the declared runner applies: everything but
/// the Rust sources `MUTANT_RUNNERS` gives cargo-mutants.
fn declared_runner_sources(root: &Path) -> Vec<String> {
    batten::git::tracked_paths(root)
        .expect("list the tracked tree")
        .into_iter()
        .filter(|path| {
            let rust = Path::new(path)
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("rs"));
            !(path.starts_with("crates/") && rust)
        })
        .collect()
}

/// EVERY ROW THE DECLARED RUNNER SWEEPS STILL APPLIES, AND STILL CHANGES ITS FILE
/// (CLOUD-2255). The rows were sed scripts run by `sed`; they are now applied in
/// process, and this is the census that proves the conversion: a row that no
/// longer applies, or applies and changes nothing, is named. Rust sources are
/// cargo-mutants' (`MUTANT_RUNNERS`), so the declared runner never applies theirs.
#[test]
fn every_declared_row_applies_in_process_and_changes_its_file() {
    let root = common::at_root("");
    let mut broken = Vec::new();
    let mut applied = 0;
    for path in &declared_runner_sources(&root) {
        let Ok(text) = std::fs::read_to_string(root.join(path)) else {
            continue;
        };
        for row in batten::mutate::rows_of(&root, path) {
            match batten::mutate::substitute(&text, &row.script) {
                Some(after) if after != text => applied += 1,
                Some(_) => broken.push(format!("{path} {} inert", row.slug)),
                None => broken.push(format!("{path} {} unappliable", row.slug)),
            }
        }
    }
    assert!(applied > 0, "the census found rows to apply");
    assert!(broken.is_empty(), "{applied} applied; broken: {broken:#?}");
}

/// THE IN-PROCESS APPLIER IS SED, BYTE FOR BYTE, ON EVERY DECLARED ROW (CLOUD-2255).
///
/// The differential that proves the conversion did not change what any row
/// mutates: each row's script through the host's `sed` and through
/// [`batten::mutate::substitute`] must produce identical bytes. This is the only
/// place `sed` is still run, and only as the oracle; a host without it fails.
#[cfg(unix)]
#[test]
#[expect(
    clippy::disallowed_types,
    reason = "stays, and test-only: `sed` is the oracle the in-process applier is compared against, never a route the engine takes"
)]
fn the_in_process_applier_matches_sed_on_every_declared_row() {
    use std::process::{Command, Stdio};

    let root = common::at_root("");
    // sed READS A COPY BY PATH: piping the whole file to its stdin before reading
    // its stdout deadlocks once the output pipe fills.
    let copy = common::scratch("mutate-sed-oracle").join("source");
    let mut differ = Vec::new();
    for path in &declared_runner_sources(&root) {
        let Ok(text) = std::fs::read_to_string(root.join(path)) else {
            continue;
        };
        std::fs::write(&copy, &text).expect("copy the source");
        for row in batten::mutate::rows_of(&root, path) {
            // A MISSING ORACLE FAILS, never skips: a unix host without `sed`
            // would otherwise pass this case having compared nothing.
            let out = Command::new("sed")
                .arg("-e")
                .arg(&row.script)
                .arg(&copy)
                .stdin(Stdio::null())
                .stderr(Stdio::null())
                .streamed_output_keeping(batten::capture::Keep {
                    stdin: true,
                    stdout: false,
                    stderr: true,
                })
                .expect("`sed` is the oracle this case compares against");
            let sed = String::from_utf8_lossy(&out.stdout).into_owned();
            if batten::mutate::substitute(&text, &row.script).as_deref() != Some(sed.as_str()) {
                differ.push(format!("{path} {}", row.slug));
            }
        }
    }
    assert!(
        differ.is_empty(),
        "the applier differs from sed: {differ:#?}"
    );
}

/// THE `--in-diff` PATCH IS WRITTEN IN PROCESS (CLOUD-2255): each changed source
/// against its bytes at the base, `---`/`+++` headed and hunked as `git diff`
/// prints it, a new file diffed from empty, and an unchanged one left out.
#[test]
fn the_in_diff_patch_is_written_without_git() {
    let root = common::scratch("mutate-in-diff-patch");
    common::init_repo(&root);
    common::git_in(&root, &["config", "user.email", "t@example.com"]);
    common::git_in(&root, &["config", "user.name", "t"]);
    common::write(&root, "a.rs", "one\ntwo\nthree\n");
    common::write(&root, "same.rs", "kept\n");
    common::git_in(&root, &["add", "-A"]);
    common::git_in(&root, &["commit", "--quiet", "-m", "base"]);
    common::write(&root, "a.rs", "one\nTWO\nthree\n");
    common::write(&root, "new.rs", "fresh\n");

    let sources = ["a.rs", "new.rs", "same.rs"].map(String::from);
    let patch = batten::mutate::in_diff_patch(&root, "HEAD", &sources).expect("write the patch");
    assert!(
        patch.contains("--- a/a.rs\n+++ b/a.rs\n@@ -1,3 +1,3 @@\n one\n-two\n+TWO\n three\n"),
        "{patch}"
    );
    assert!(
        patch.contains("--- a/new.rs\n+++ b/new.rs\n@@ -1,0 +1,1 @@\n+fresh\n"),
        "{patch}"
    );
    assert!(
        !patch.contains("same.rs"),
        "an unchanged source is left out: {patch}"
    );
}

/// A HUNK BELOW THE TOP CARRIES ITS OWN LINE NUMBERS (CLOUD-2507). The case
/// above changes line 2, so its context starts at line 1 and an offset error
/// cannot show. Measured on a doc-comment change at line 7: cargo-mutants
/// refused the patch with "Diff content doesn't match source file … line 4",
/// and the source was reported `suite-did-not-run`.
#[test]
fn a_hunk_below_the_top_names_its_own_lines() {
    let patch = numbered_patch("mutate-in-diff-offset", 12, &[7]);
    assert!(
        patch.contains("@@ -4,7 +4,7 @@\n l4\n l5\n l6\n-l7\n+L7\n l8\n l9\n l10\n"),
        "the hunk must start where its first context line is: {patch}"
    );
}

/// HUNKS WHOSE CONTEXTS TOUCH PRINT AS ONE, AND ONLY THOSE (CLOUD-2507). Lines
/// 5 and 12 sit exactly twice the context apart, so their contexts meet and
/// they share a header; line 22 sits further on and gets its own, as `git diff`
/// prints them.
#[test]
fn hunks_whose_contexts_touch_print_as_one() {
    let patch = numbered_patch("mutate-in-diff-groups", 30, &[5, 12, 22]);
    let joined = "@@ -2,14 +2,14 @@\n l2\n l3\n l4\n-l5\n+L5\n l6\n l7\n l8\n l9\n l10\n l11\n-l12\n+L12\n l13\n l14\n l15\n";
    let apart = "@@ -19,7 +19,7 @@\n l19\n l20\n l21\n-l22\n+L22\n l23\n l24\n l25\n";
    assert!(
        patch.contains(&format!("{joined}{apart}")),
        "two touching hunks share one header, a third gets its own: {patch}"
    );
    assert_eq!(patch.matches("@@ -").count(), 2, "{patch}");
}

/// The in-diff patch of a committed `a.rs` holding `l1`..`l{lines}`, after the
/// lines named in `changed` are rewritten to `L{n}`.
fn numbered_patch(name: &str, lines: u32, changed: &[u32]) -> String {
    let text = |changed: &[u32]| -> String {
        (1..=lines)
            .map(|n| {
                if changed.contains(&n) {
                    format!("L{n}\n")
                } else {
                    format!("l{n}\n")
                }
            })
            .collect()
    };
    let root = common::Fixture::new(name)
        .file("a.rs", &text(&[]))
        .base_commit()
        .build();
    common::write(&root, "a.rs", &text(changed));
    batten::mutate::in_diff_patch(&root, "HEAD", &[String::from("a.rs")]).expect("write the patch")
}

/// A MODULE'S OWN TEST IS RUN IN PROCESS, AS `policy test` RUNS IT (CLOUD-2255):
/// the case a `.rego` row names in its own module is judged by that `test_`
/// rule, under the committed config's registry, with no conftest spawned.
#[test]
fn a_modules_own_test_is_run_in_process() {
    let root = common::at_root("");
    assert_eq!(
        batten::policy_case(
            &root,
            "policy/run-shape.rego",
            "a_backgrounded_bare_sleep_raises_only_the_timer"
        )
        .expect("the committed config resolves"),
        Some(true),
        "a committed module test passes"
    );
    assert_eq!(
        batten::policy_case(&root, "policy/run-shape.rego", "no_such_case")
            .expect("the committed config resolves"),
        None,
        "a name the module does not declare is no case"
    );
}

/// A ROW APPLIES WITHOUT SPAWNING, WITH SED'S MEANING (CLOUD-2255): the first match
/// on each line, `&` the whole match, `\&` a literal ampersand, `\x7c` a pipe, an
/// escaped delimiter literal; anything outside the one-substitution subset is
/// refused rather than approximated.
#[test]
fn a_mutation_row_applies_without_spawning() {
    use batten::mutate::substitute;
    assert_eq!(
        substitute("a b a\nb a\n", "s@a@[&]@").as_deref(),
        Some("[a] b a\nb [a]\n"),
        "the first match per line, `&` is the match"
    );
    assert_eq!(
        substitute("x\n", r"s@x@\&\x7c@").as_deref(),
        Some("&|\n"),
        "`\\&` is literal and `\\x7c` a pipe"
    );
    assert_eq!(
        substitute("a|b (c)\n", r"s@b (c)@d@").as_deref(),
        Some("a|d\n"),
        "a bare paren is literal in a basic regex"
    );
    assert_eq!(
        substitute("ab\n", r"s@\(a\)b@\1\1@").as_deref(),
        Some("aa\n"),
        "an escaped paren is a group, `\\1` its text"
    );
    assert_eq!(
        substitute("a@b\n", r"s@a\@b@c@").as_deref(),
        Some("c\n"),
        "an escaped delimiter is literal"
    );
    assert_eq!(
        substitute("v=$(a ^b)\n", r"s@^v=$(a ^b)$@w@").as_deref(),
        Some("w\n"),
        "`^` and `$` anchor only at the pattern's ends"
    );
    assert_eq!(substitute("a\n", "s@a@b@g"), None, "a flag is refused");
    assert_eq!(
        substitute("a\n", "/a/{n;s@a@b@}"),
        None,
        "an address is refused"
    );
}

/// THE SWEEP'S OWN SIGNAL REACHES ITS SUITE (CLOUD-2059).
///
/// The suite leads a process group of its own so the bound can end it whole —
/// which takes it out of the group an outer runner signals. nextest's terminate,
/// a ^C or mise's cancel then reaches the sweep and not the suite, and a sweep
/// that died of it would orphan the suite for the rest of its hour. So the sweep
/// forwards what it is sent, waits for the group to go, and dies of the same
/// signal: TERM to the sweep alone, and nothing it started may outlive it.
#[cfg(unix)]
#[test]
fn a_signalled_sweep_takes_its_suite_with_it() {
    use std::os::unix::process::ExitStatusExt as _;

    let (root, hung) = hung_toy("signalled");
    let mut sweep = common::batten()
        .args(["mutate", "sweep"])
        .current_dir(&root)
        .env("MUTANT_GATES", "toy")
        .env("MUTANT_TASKS", "mise.toml")
        // Far past any run here, so the bound cannot be what ends the suite.
        .env("BATTEN_MUTATE_SUITE_TIMEOUT", "3000")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn batten mutate");
    hung.started();

    kill(sweep.id(), "TERM");
    // THE SWEEP'S EXIT AND ITS SUITE'S END ARE BOTH EVENTS (CLOUD-2789): a
    // sweep that waits out its suite, or leaves the suite's group running
    // rather than forwarding what it is sent, hangs this case.
    let status = sweep.wait().expect("wait for the sweep");
    hung.ended();
    assert_eq!(
        status.signal(),
        Some(15),
        "a sweep asked to stop stops with the signal's own status, not a verdict: {status:?}"
    );
}

/// AN ORPHANED SWEEP ENDS, AND TAKES ITS SUITE (CLOUD-2854).
///
/// A capped `mutant:changed` lost its mise while `mutant:rust` ran on under
/// init, holding the schema mirror's lock. Here the sweep runs under a shell
/// that outlives the exec (`; :`), the shell is `SIGKILL`ed once the hung suite
/// has started, and then neither the sweep nor anything its suite started may
/// still run. The lock is an `flock`, so it drops with them.
///
/// Fails by: the parent watch never firing, so the sweep and its suite run on
/// under init until the suite bound.
#[cfg(target_os = "linux")]
#[test]
fn an_orphaned_sweep_ends_and_leaves_nothing_running() {
    let (root, hung) = hung_toy("orphaned");
    let body = format!("{} mutate sweep; :", env!("CARGO_BIN_EXE_batten"));
    let mut shell = common::task_bash(&root, &body)
        .env("MUTANT_GATES", "toy")
        .env("MUTANT_TASKS", "mise.toml")
        // Far past any run here, so the bound cannot be what ends the suite.
        .env("BATTEN_MUTATE_SUITE_TIMEOUT", "3000")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn the shell over batten mutate");
    hung.started();
    let children = format!("/proc/{0}/task/{0}/children", shell.id());
    let sweep: u32 = fs::read_to_string(&children)
        .expect("the shell's children")
        .split_whitespace()
        .next()
        .and_then(|pid| pid.parse().ok())
        .expect("the sweep runs under the shell");

    kill(shell.id(), "KILL");
    let _ = shell.wait();
    // BOTH ENDS ARE EVENTS (CLOUD-2789): the sweep, no child of this case, by
    // its pidfd, and the suite by the `alive` fifo's end. A parent watch that
    // never fires leaves the sweep and its suite running, and this case hangs.
    await_gone(sweep);
    hung.ended();
}

/// A toy whose `over_the_limit_is_refused` case never returns, and leaves a
/// process of its own, with a [`Hung`] watching it. The case holds the `alive`
/// fifo and hands it to the `sleep 3600` it spawns, writes its own pid and the
/// sleep's into the `note` fifo, then sleeps an hour. `read` on a closed stdin
/// would return, so the wait has to be one nothing external can satisfy.
#[cfg(unix)]
fn hung_toy(name: &str) -> (PathBuf, Hung) {
    let fifos = common::scratch(&format!("mutate-{name}-fifos"));
    let (note_at, alive_at) = (fifos.join("pids"), fifos.join("alive"));
    let hung = Hung::watch(&note_at, &alive_at);
    let root = toy(name);
    let mut gate = String::from(TOY_GATE);
    gate.push_str(CAUGHT);
    gate.push('\n');
    write_program(&root, "mise-tasks/toy.sh", &gate);
    let (note, alive) = (
        note_at.display().to_string(),
        alive_at.display().to_string(),
    );
    let body = format!(
        "let alive = std::fs::OpenOptions::new().append(true).open({alive:?}).expect(\"hold \
         the alive fifo\");\n    let held = std::process::Command::new(\"sh\").args([\"-c\", \
         \"exec 3>>\\\"$0\\\"; exec sleep 3600\", {alive:?}]).spawn().expect(\"spawn the \
         grandchild\");\n    std::fs::write({note:?}, format!(\"{{}} {{}}\", std::process::id(), \
         held.id())).expect(\"write the note\");\n    let _held = alive;\n    \
         std::thread::sleep(std::time::Duration::from_secs(3600));"
    );
    write(
        &root,
        "tests/toy.rs",
        &format!(
            "{}{}{}",
            runs("toy.sh"),
            case("over_the_limit_is_refused", &body),
            case("under_the_limit_passes", "assert!(gate(\"1\").is_some());"),
        ),
    );
    cargo_package(&root);
    track(&root);
    (root, hung)
}

/// What a hung toy says while it runs, each read off a fifo so a case waits
/// on it as an event and never on a clock (CLOUD-2789): the two pids its case
/// records once it has started, and the end of everything it started, which
/// is the `alive` fifo's end of file once its last holder is gone.
#[cfg(unix)]
struct Hung {
    pids: std::sync::mpsc::Receiver<Vec<u32>>,
    gone: std::sync::mpsc::Receiver<()>,
}

#[cfg(unix)]
impl Hung {
    /// Make both fifos and start reading them, before the toy can run.
    fn watch(note: &Path, alive: &Path) -> Self {
        fifo(note);
        fifo(alive);
        let (named, pids) = std::sync::mpsc::channel();
        let note = note.to_path_buf();
        std::thread::spawn(move || {
            let text = fs::read_to_string(&note).expect("read the note fifo");
            let _ = named.send(
                text.split_whitespace()
                    .map(|pid| pid.parse().expect("a recorded pid"))
                    .collect(),
            );
        });
        let (ended, gone) = std::sync::mpsc::channel();
        let alive = alive.to_path_buf();
        std::thread::spawn(move || {
            let _ = fs::read_to_string(&alive);
            let _ = ended.send(());
        });
        Self { pids, gone }
    }

    /// Block until the hung case has started, answering the two pids it
    /// recorded: its test binary, then the process it spawned.
    fn started(&self) -> Vec<u32> {
        let pids = self.pids.recv().expect("the note's reader answers");
        assert_eq!(pids.len(), 2, "the test binary and its child: {pids:?}");
        pids
    }

    /// Block until everything the hung case started is gone.
    fn ended(&self) {
        self.gone.recv().expect("the alive fifo's reader answers");
    }
}

/// A fifo at `path`.
#[cfg(unix)]
#[expect(
    clippy::disallowed_types,
    reason = "stays, and test-only: `mkfifo` is the POSIX way to make a fifo, and this suite runs on macOS, where rustix makes none"
)]
fn fifo(path: &Path) {
    let made = std::process::Command::new("mkfifo")
        .arg(path)
        .status()
        .expect("run mkfifo");
    assert!(made.success(), "mkfifo {}", path.display());
}

/// Block until `pid`, no child of this case, has exited: its pidfd reads ready
/// then, a zombie included. One already reaped has no pidfd and is gone.
#[cfg(target_os = "linux")]
fn await_gone(pid: u32) {
    let pid = rustix::process::Pid::from_raw(i32::try_from(pid).expect("a pid")).expect("a pid");
    let Ok(pidfd) = rustix::process::pidfd_open(pid, rustix::process::PidfdFlags::empty()) else {
        return;
    };
    let mut fds = [rustix::event::PollFd::new(
        &pidfd,
        rustix::event::PollFlags::IN,
    )];
    while let Err(rustix::io::Errno::INTR) = rustix::event::poll(&mut fds, None) {}
}

/// Send `signal` to `pid`, by name, best effort: the pid may already be gone.
#[cfg(unix)]
#[expect(
    clippy::disallowed_types,
    reason = "stays, and test-only: delivering a real signal to a real pid is what the forwarding and teardown are asserted against"
)]
fn kill(pid: u32, signal: &str) {
    let _ = std::process::Command::new("kill")
        .args([&format!("-{signal}"), &pid.to_string()])
        .status();
}

/// **THE MIRROR, and without it this fix is indistinguishable from deleting the
/// term** (CLOUD-1860, CLOUD-418's own shape).
///
/// The case above asserts a timing-out suite stops being called `names-no-case`.
/// A change that simply removed `names-no-case` would satisfy it. This asserts
/// the verdict still fires where it is the truth: the suite returns promptly and
/// the row names a case that genuinely is not in it.
///
/// The two differ only in whether the suite returns, which is the discrimination
/// the repair turns on.
#[cfg(unix)]
#[test]
fn a_filter_naming_no_case_is_still_a_filter_fault_and_not_a_timeout() {
    let root = toy_repo(
        "no-case-not-timeout",
        &["#MUTANT limit-ignored|s/^LIMIT=10$/LIMIT=999/|no_case_is_named_this"],
    );
    let answer = common::batten()
        .args(["mutate", "sweep"])
        .current_dir(&root)
        .env("MUTANT_GATES", "toy")
        // A bound the suite returns well inside, so a runner that reported every
        // bounded run as a timeout would fail this — the over-correction the
        // mirror exists to catch. Not the timeout case's 10s: that one HAS to be
        // short, because it waits its bound out, while here a short bound only
        // made a warm `cargo test` on a loaded host the thing being measured
        // (CLOUD-2059).
        .env("BATTEN_MUTATE_SUITE_TIMEOUT", "120")
        .streamed_output()
        .expect("run batten mutate");
    let code = answer.status.code().unwrap_or(-1);
    let out = stdout(&answer);
    assert_eq!(code, 3, "still a could-not-look: {out}");
    assert!(out.contains("names-no-case"), "{out}");
    assert!(
        !out.contains("suite-timed-out"),
        "a suite that answered in time did not time out: {out}"
    );
}

/// Two inline tasks in one manifest, each declaring one row over its own body,
/// and a Rust tier for task `a` that reads the staged manifest (CLOUD-1909).
///
/// **The suite reads the manifest rather than running the task**, and that is what
/// keeps this tier a test of the ROUTE: whether the sweep can find, scope, apply
/// and judge a row declared in `mise.toml`. Running a task body is a property of
/// mise, which a toy repository does not have.
///
/// **ONLY `a`'s SUITE IS WRITTEN, AND THAT IS THE DISCRIMINATION.** `cargo test --
/// <filter>` runs every test target in the package, so a `tests/b.rs` beside it
/// would select `b_keeps_its_limit` wherever it was asked for — and an unscoped
/// reader running `b-limit` under `a`'s gate would then report it caught, which
/// is the defect `a_task_gate_sweeps_only_its_own_block` exists to see. With no
/// `b` tier, that reader's `b-limit` row names no case and the sweep exits 3.
///
/// COMPILED ON EVERY TARGET: `a_recorded_row_is_judged_again_under_ci` calls it
/// behind a `cfg!` arm rather than an attribute, so a `#[cfg(unix)]` here left
/// that case unresolvable off unix, and `cross-check`'s Windows pass failed.
fn two_task_repo(name: &str) -> PathBuf {
    let root = toy(name);
    write(
        &root,
        "mise.toml",
        "[tasks.\"a\"]\n\
         #MUTANT-SUITE tests/a.rs\n\
         #MUTANT a-limit|s/^LIMIT_A=10$/LIMIT_A=999/|a_keeps_its_limit\n\
         run = '''\n\
         LIMIT_A=10\n\
         [ -n \"$LIMIT_A\" ]\n\
         '''\n\
         \n\
         [tasks.b]\n\
         #MUTANT-SUITE tests/b.rs\n\
         #MUTANT b-limit|s/^LIMIT_B=10$/LIMIT_B=999/|b_keeps_its_limit\n\
         run = '''\n\
         LIMIT_B=10\n\
         '''\n",
    );
    let manifest = "std::fs::read_to_string(concat!(env!(\"CARGO_MANIFEST_DIR\"), \
                    \"/mise.toml\")).expect(\"read the staged manifest\")";
    write(
        &root,
        "tests/a.rs",
        &format!(
            "{}{}",
            case(
                "a_keeps_its_limit",
                &format!("assert!({manifest}.lines().any(|line| line == \"LIMIT_A=10\"));")
            ),
            case(
                "a_has_a_body",
                &format!("assert!({manifest}.contains(\"LIMIT_A\"));")
            ),
        ),
    );
    cargo_package(&root);
    track(&root);
    root
}

/// **CLOUD-1909's discriminating case: a `task-` gate sweeps its own block and no
/// other.**
///
/// Scoped, `task-a` finds one row, its suite catches it, and the sweep is clean.
/// Unscoped — the file read whole — it also finds `b-limit` and runs it against
/// `a`'s suite, where no case is named `b keeps its limit`, so the sweep reports
/// `names-no-case` and exits 3. The column-zero `[ -n … ]` line inside `a`'s body
/// is deliberate: a reader that ended the block at the next `[` would stop there
/// and still pass, so the fixture makes the header rule do the work.
#[cfg(unix)]
#[test]
fn a_task_gate_sweeps_only_its_own_block() {
    let root = two_task_repo("task-scoped");
    let (code, out, err) = sweep(&root, "task-a");
    assert_eq!(code, 0, "{out}{err}");
    assert!(out.contains("every one caught"), "{out}");
    assert!(
        !out.contains("b-limit"),
        "another task's row is not this gate's: {out}"
    );
}

/// THE SWEEP SAYS HOW FAR IT GOT (CLOUD-2253). On #1132 a sweep ran two hours,
/// printed one line and was killed, so neither its row count nor any row's cost
/// was known. The count comes before any row runs, then one line per row with its
/// verdict and seconds, in declared order, so a killed run still shows where it
/// was. TWO rows, so an order and a per-row line are both observable: one row
/// would pass a runner that printed only the last row, or only `1/1`.
#[test]
fn a_sweep_reports_its_row_count_and_each_rows_time() {
    let root = toy_repo(
        "progress",
        &[
            CAUGHT,
            "#MUTANT limit-lowered|s/^LIMIT=10$/LIMIT=0/|under_the_limit_passes",
        ],
    );
    let (code, out, err) = sweep(&root, "toy");
    assert_eq!(code, 0, "{out}{err}");
    let at = |needle: &str| {
        err.find(needle)
            .unwrap_or_else(|| panic!("{needle:?} in: {err}"))
    };
    let count = at("mutate sweep: 2 row(s) across 1 gate(s)");
    let first = at("mutate sweep: row 1/2 toy limit-ignored ");
    let second = at("mutate sweep: row 2/2 toy limit-lowered ");
    assert!(count < first, "the count precedes the first row: {err}");
    assert!(first < second, "the rows follow in order: {err}");
    for row in [first, second] {
        let line = err
            .get(row..)
            .and_then(|rest| rest.lines().next())
            .unwrap_or_default();
        assert!(
            line.contains(" caught ") && line.ends_with('s'),
            "the row line carries its verdict and seconds: {line}"
        );
    }
}

/// A ROW SEEN CAUGHT IS NOT RUN AGAIN WHILE NOTHING IT READS HAS CHANGED
/// (CLOUD-2253): cargo-mutants' `--iterate`, for the declared runner. The second
/// sweep of an unchanged tree judges nothing; a change to the row's source makes
/// the row run again.
#[cfg(unix)]
#[test]
fn a_caught_row_is_not_run_again_until_its_inputs_change() {
    let root = two_task_repo("task-recorded");
    let (code, out, err) = sweep(&root, "task-a");
    assert_eq!(code, 0, "{out}{err}");
    assert!(!err.contains("(recorded)"), "the first sweep judges: {err}");

    let (code, out, err) = sweep(&root, "task-a");
    assert_eq!(code, 0, "{out}{err}");
    assert!(
        err.contains("caught (recorded)"),
        "the second sweep skips the recorded row: {err}"
    );
    assert!(
        out.contains("every one caught (1 recorded)"),
        "the summary says how much of it was replayed: {out}"
    );

    let manifest = root.join("mise.toml");
    let text = std::fs::read_to_string(&manifest).expect("read the manifest");
    std::fs::write(&manifest, format!("{text}\n# touched\n")).expect("touch the source");
    let (_, _, err) = sweep(&root, "task-a");
    assert!(
        !err.contains("(recorded)"),
        "a changed source runs its row again: {err}"
    );
}

/// UNDER CI A RECORDED ROW IS JUDGED AGAIN (#1276), as `ChangePass::of` already
/// refuses a whole-change pass there: a runner that keeps its workspace would
/// otherwise answer a confirmation from a record. The first sweep runs without
/// `$CI` and records the row; the second, under it, must run the row and say
/// nothing was replayed. Fails by: the row replay reading the record whatever
/// `step::bypassed` says.
#[test]
fn a_recorded_row_is_judged_again_under_ci() {
    if !cfg!(unix) {
        return;
    }
    let root = two_task_repo("task-recorded-ci");
    let (code, out, err) = sweep(&root, "task-a");
    assert_eq!(code, 0, "{out}{err}");

    let (code, out, err) = run_with(&root, "sweep", "task-a", &[("CI", Path::new("true"))]);
    assert_eq!(code, 0, "{out}{err}");
    assert!(
        !err.contains("(recorded)"),
        "under CI the row is judged, not replayed: {err}"
    );
    assert!(out.contains("every one caught"), "{out}");
    assert!(!out.contains("recorded)"), "nothing replayed: {out}");
}

/// The census half: a block that declares rows and is absent from the set is
/// `uncovered`, so an inline task cannot declare a mutation nobody sweeps.
#[cfg(unix)]
#[test]
fn a_declaring_task_block_absent_from_the_set_is_uncovered() {
    let root = two_task_repo("task-uncovered");
    let (code, out, err) = census(&root, "task-a");
    assert_ne!(code, 0, "{out}{err}");
    assert!(out.contains("uncovered"), "{out}");
    assert!(
        out.contains("mise.toml"),
        "the pointer names the manifest: {out}"
    );
}

/// **THE MIRROR.** A `task-` name the manifest declares no table for is still
/// `no-such-gate` — the route resolves real blocks, and does not turn every
/// prefixed name into a gate over the whole manifest.
/// **The route is the consumer's to switch on.** With no manifest named, a `task-`
/// gate resolves to nothing and says so — the crate never guesses which file a
/// repository keeps its tasks in (non-negotiable rule 1), and an unnamed manifest
/// is a could-not-look rather than a quiet pass.
#[cfg(unix)]
#[test]
fn an_unnamed_manifest_resolves_no_task_gate() {
    let root = two_task_repo("task-unnamed");
    let answer = common::batten()
        .args(["mutate", "sweep"])
        .current_dir(&root)
        .env("MUTANT_GATES", "task-a")
        .env_remove("MUTANT_TASKS")
        .streamed_output()
        .expect("run batten mutate");
    let out = stdout(&answer);
    assert_eq!(answer.status.code(), Some(3), "{out}");
    assert!(out.contains("no-such-gate"), "{out}");
}

#[cfg(unix)]
#[test]
fn a_task_name_with_no_block_is_still_no_such_gate() {
    let root = two_task_repo("task-absent");
    let (code, out, err) = sweep(&root, "task-nope");
    assert_eq!(code, 3, "{out}{err}");
    assert!(out.contains("no-such-gate"), "{out}");
}

#[cfg(unix)]
#[test]
fn a_mutation_its_suite_catches_is_a_pass() {
    let root = toy_repo("caught", &[CAUGHT]);
    let (code, out, err) = sweep(&root, "toy");
    assert_eq!(code, 0, "{out}{err}");
    assert!(out.contains("every one caught"), "{out}");
    // A Cargo row not yet recorded caught owes the up-front build, and says so.
    assert!(
        err.contains("mutate sweep: building the cargo suites"),
        "the first sweep builds: {err}"
    );

    // AND AGAIN OVER THE SAME ROOT, which is a second property carried by this
    // case rather than a second case, because `platform-gated-test-added` is a
    // ratchet and every case in this file is `#[cfg(unix)]` — `toy_repo` and
    // its bash gate are themselves gated, so the `cfg!` arm that rule prefers is
    // not reachable here without restructuring the file.
    //
    // THE STAGED TREE PERSISTS BETWEEN RUNS, which is what keeps an unchanged
    // source's timestamp and a compiled tier affordable — so a second sweep is
    // the ordinary case rather than an edge one. It stages nothing new, and a
    // plain `git commit` over a clean tree exits 1: the harness bailed on that
    // with "could not make the staged tree a repository" over a tree that
    // already was one, so every sweep after the first in a checkout was
    // could-not-look at exit 3. Measured on CLOUD-1606, whose own declared
    // mutation could not be run at all until it was repaired.
    let (again, out, err) = sweep(&root, "toy");
    assert_eq!(
        again, 0,
        "a second sweep over the persisted staged tree still runs: {out}{err}"
    );
    assert!(out.contains("every one caught"), "{out}");
    // Every Cargo row is recorded caught now, so no build is owed (CLOUD-2253).
    assert!(
        !err.contains("mutate sweep: building the cargo suites"),
        "the second sweep builds nothing: {err}"
    );
}

/// A build script cargo reruns on EVERY build — it watches a path that does not
/// exist — and that counts its runs into `$TOY_BUILD_COUNTER`.
const ALWAYS_STALE_BUILD: &str = r#"fn main() {
    println!("cargo:rerun-if-changed=no-such-path");
    if let Some(path) = std::env::var_os("TOY_BUILD_COUNTER") {
        use std::io::Write as _;
        let mut counter = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .expect("open the counter");
        writeln!(counter, "built").expect("count the build");
    }
}
"#;

/// ONE BUILD JUDGES EVERY ROW, whatever cargo's fingerprint says. Two rows over a
/// non-Rust gate, in a package whose build script is stale on every build: the
/// sweep builds once up front and each row runs the recorded binaries, so the
/// script runs exactly once. Fails by: any row asking cargo to build, which reran
/// this script per row — and the library with it, 75s a row in this repository's
/// own sweep when a missing `rerun-if-changed` path did the same.
#[test]
fn a_row_runs_the_one_build_and_never_compiles() {
    let root = toy_repo(
        "one-build",
        &[
            CAUGHT,
            "#MUTANT comparison-flipped|s/-le/-ge/|over_the_limit_is_refused",
        ],
    );
    write(&root, "build.rs", ALWAYS_STALE_BUILD);
    track(&root);
    let counter = common::scratch("mutate-one-build-counter").join("builds");
    let (code, out, err) = run_with(&root, "sweep", "toy", &[("TOY_BUILD_COUNTER", &counter)]);
    assert_eq!(code, 0, "{out}{err}");
    assert!(out.contains("every one caught"), "{out}");
    let builds = fs::read_to_string(&counter).unwrap_or_default();
    assert_eq!(
        builds.lines().count(),
        1,
        "the build script ran once per build; two rows must cost one build\n{err}"
    );
}

/// A SUBJECT THE BUILD EMBEDS IS STILL JUDGED MUTATED. The case reads the gate
/// through `include_str!`, so the recorded binaries carry the unmutated text and
/// only a rebuild sees the row's mutation. Fails by: reusing the binaries for a
/// subject cargo's dep-info names, which reads the mutant as surviving.
#[test]
fn a_row_whose_subject_the_build_embeds_is_rebuilt() {
    let root = toy_repo(
        "embedded-subject",
        &["#MUTANT limit-embedded|s/^LIMIT=10$/LIMIT=999/|embedded_limit_is_ten"],
    );
    let suite = format!(
        "{}{}",
        toy_suite("toy.sh", ""),
        case(
            "embedded_limit_is_ten",
            "assert!(include_str!(\"../mise-tasks/toy.sh\").contains(\"\\nLIMIT=10\\n\"));"
        ),
    );
    write(&root, "tests/toy.rs", &suite);
    track(&root);
    let (code, out, err) = sweep(&root, "toy");
    assert_eq!(
        code, 0,
        "an embedded subject's mutation must be caught\n{out}{err}"
    );
    assert!(out.contains("every one caught"), "{out}");
}

/// A REBUILT ROW LEAVES NO MUTANT BEHIND IN THE BINARIES A LATER ROW REUSES.
/// `user`'s case reads `toy`'s gate through `include_str!`, so `toy`'s row
/// rebuilds, and its mutated build overwrites the recorded binaries at the same
/// paths. Gates are judged in name order, so `toy`'s row runs first; `user`'s
/// subject is not embedded, so its row reuses them. Fails by: reusing a binary
/// the previous row rebuilt mutated, which reads `user`'s clean case as
/// `case-already-red`.
#[test]
fn a_row_after_a_rebuilt_row_reuses_clean_binaries() {
    let root = toy_repo("dirty-reuse", &[CAUGHT]);
    let gate = TOY_GATE
        .replace("the toy", "the user")
        .replace("tests/toy.rs", "tests/user.rs");
    write_program(
        &root,
        "mise-tasks/user.sh",
        &format!("{gate}#MUTANT user-limit|s/^LIMIT=10$/LIMIT=999/|user_refuses_ninety_nine\n"),
    );
    let suite = format!(
        "{}{}{}",
        runs("user.sh"),
        case(
            "user_refuses_ninety_nine",
            "assert!(include_str!(\"../mise-tasks/toy.sh\").contains(\"\\nLIMIT=10\\n\"));\n    \
             assert_eq!(gate(\"99\"), Some(1));"
        ),
        case("user_passes_one", "assert_eq!(gate(\"1\"), Some(0));"),
    );
    write(&root, "tests/user.rs", &suite);
    track(&root);
    let (code, out, err) = sweep(&root, "toy,user");
    assert_eq!(code, 0, "a later row must reuse clean binaries\n{out}{err}");
    assert!(out.contains("every one caught"), "{out}");
}

#[cfg(unix)]
#[test]
fn the_defect_a_mutation_the_suite_does_not_catch_fails() {
    // The mutation moves a line no case exercises, so the suite stays green.
    let root = toy_repo(
        "survivor",
        &["#MUTANT unwatched|s/^exit 0$/exit 0 # unwatched/|over_the_limit_is_refused"],
    );
    let (code, out, err) = sweep(&root, "toy");
    assert_eq!(code, 2, "{out}");
    assert!(out.contains("SURVIVED"), "{out}");
    assert!(
        err.contains("1 of 1 declared mutation(s) across 1 gate(s) survived"),
        "a survivor is counted over the rows judged: {err}"
    );
    // A survivor is no row defect: the row applied, and named one case.
    assert!(!err.contains("prove nothing as written"), "{err}");
    // Nor a gate-level finding: the one gate declared the row that was judged.
    assert!(!err.contains("declare no row"), "{err}");
}

#[cfg(unix)]
#[test]
fn a_row_is_exactly_three_fields_and_a_fourth_is_refused_before_the_split() {
    let root = toy_repo("malformed", &["#MUTANT five|s/a|b/|and|the case", CAUGHT]);
    let (code, out, _) = sweep(&root, "toy");
    assert_eq!(code, 2, "{out}");
    assert!(out.contains("malformed-row"), "{out}");
    assert!(out.contains("5 fields, want 3"), "{out}");
    assert!(!out.contains("every one caught"), "{out}");
}

#[cfg(unix)]
#[test]
fn a_filter_that_selects_more_than_one_case_names_no_case_like_one_that_selects_none() {
    // A second module carries a case of the same name, so the exact filter
    // selects two and redness under mutation could come from either.
    let root = toy_repo("wide-filter", &[CAUGHT]);
    let suite = format!(
        "{}\nmod again {{\n    use super::gate;\n{}}}\n",
        toy_suite("toy.sh", ""),
        case(
            "over_the_limit_is_refused",
            "assert_eq!(gate(\"99\"), Some(1));"
        ),
    );
    write(&root, "tests/toy.rs", &suite);
    track(&root);
    let (code, out, _) = sweep(&root, "toy");
    assert_eq!(code, 2, "{out}");
    assert!(out.contains("filter-names-every-case"), "{out}");
    assert!(!out.contains("every one caught"), "{out}");
}

/// A SIBLING WHOSE NAME CONTAINS THE CASE'S IS NEVER CREDITED. `limit_case`
/// does not see the mutation and `limit_case_over` does. Fails by: selecting by
/// containment, which ran both and read the sibling's redness as the row's catch.
#[test]
fn a_case_is_selected_by_its_whole_name_and_a_longer_sibling_is_not_credited() {
    let root = toy_repo(
        "anchored-filter",
        &["#MUTANT limit-ignored|s/^LIMIT=10$/LIMIT=999/|limit_case"],
    );
    let suite = format!(
        "{}{}{}",
        toy_suite("toy.sh", ""),
        case("limit_case", "assert_eq!(gate(\"1\"), Some(0));"),
        case("limit_case_over", "assert_eq!(gate(\"99\"), Some(1));"),
    );
    write(&root, "tests/toy.rs", &suite);
    track(&root);
    let (code, out, err) = sweep(&root, "toy");
    assert_eq!(code, 2, "{out}{err}");
    assert!(out.contains("SURVIVED (limit_case)"), "{out}{err}");
}

#[cfg(unix)]
#[test]
fn a_filter_selecting_one_case_of_a_single_case_suite_is_not_read_as_too_wide() {
    // The guard on the false positive above: with one case, selecting it is the
    // only thing a filter can do.
    let root = toy("single-case");
    let mut gate = String::from(TOY_GATE);
    gate.push_str(CAUGHT);
    gate.push('\n');
    write_program(&root, "mise-tasks/toy.sh", &gate);
    write(
        &root,
        "tests/toy.rs",
        &format!(
            "{}{}",
            runs("toy.sh"),
            case(
                "over_the_limit_is_refused",
                "assert_eq!(gate(\"99\"), Some(1));"
            ),
        ),
    );
    cargo_package(&root);
    track(&root);
    let (code, out, err) = sweep(&root, "toy");
    assert_eq!(code, 0, "{out}{err}");
    assert!(out.contains("every one caught"), "{out}");
}

#[cfg(unix)]
#[test]
fn the_tree_is_restored_between_rows_so_a_gate_is_judged_against_a_pristine_sibling() {
    // A composer whose verdict depends on a sibling's answer. Without the
    // restore the sibling's mutant is still in place when the composer is
    // judged, and the survivor reported changes with the sweep ORDER.
    let root = toy("restore");
    // Each suite's cases carry its gate's name, because `cargo test --
    // <filter>` runs every test target: two suites sharing a case name would
    // both be selected, and the filter would stop naming one gate's case.
    write(
        &root,
        "tests/sibling.rs",
        &toy_suite("sibling.sh", "sibling_"),
    );
    let mut sibling = TOY_GATE.replace("tests/toy.rs", "tests/sibling.rs");
    sibling.push_str(
        "#MUTANT sibling-limit|s/^LIMIT=10$/LIMIT=999/|sibling_over_the_limit_is_refused\n",
    );
    write_program(&root, "mise-tasks/sibling.sh", &sibling);

    // The mutation is `|`-free and anchored on a line carrying no `$`, so the
    // three-field rule and sed's own metacharacters both stay out of the way.
    let composer = r#"#!/usr/bin/env bash
#MISE description="Gate: the composer"
#MUTANT-SUITE tests/composer.rs
set -uo pipefail
DELEGATE=1
if [ "${DELEGATE}" = 1 ]; then
	"$(dirname "$0")/sibling.sh" "${1:-0}" || exit 1
fi
exit 0
#MUTANT composer-delegates|s@^DELEGATE=1$@DELEGATE=0@|composer_over_the_limit_is_refused
"#;
    write_program(&root, "mise-tasks/composer.sh", composer);
    write(
        &root,
        "tests/composer.rs",
        &toy_suite("composer.sh", "composer_"),
    );
    cargo_package(&root);
    track(&root);

    let (code, out, err) = sweep(&root, "sibling,composer");
    assert_eq!(code, 0, "{out}{err}");
    assert!(out.contains("every one caught"), "{out}");
}

#[cfg(unix)]
#[test]
fn a_row_that_mutates_its_own_declaration_is_refused_not_reported_as_a_survivor() {
    // A pattern spelled literally matches its own declaration line, so the file
    // changes, the gate's behaviour does not, and the mutation survives every
    // run while reading as enforced coverage.
    let root = toy_repo(
        "self-mutating",
        &["#MUTANT self|s/MUTANT self/MUTANT other/|over_the_limit_is_refused"],
    );
    let (code, out, err) = sweep(&root, "toy");
    assert_eq!(code, 2, "{out}");
    assert!(out.contains("self-mutating-row"), "{out}");
    assert!(!out.contains("SURVIVED"), "{out}");
    assert!(
        err.contains("1 declared row(s) prove nothing as written") && !err.contains("survived"),
        "a row defect is counted apart from survivors: {err}"
    );
}

#[cfg(unix)]
#[test]
fn the_copy_is_a_repository_so_a_suite_that_resolves_its_own_root_answers_about_it() {
    let root = toy("is-a-repo");
    let mut gate = String::from(TOY_GATE);
    gate.push_str(CAUGHT);
    gate.push('\n');
    write_program(&root, "mise-tasks/toy.sh", &gate);
    write(
        &root,
        "tests/toy.rs",
        &format!(
            "{}{}{}",
            runs("toy.sh"),
            case(
                "over_the_limit_is_refused",
                "assert!(std::process::Command::new(\"git\")\n        \
                 .args([\"rev-parse\", \"--show-toplevel\"])\n        \
                 .current_dir(env!(\"CARGO_MANIFEST_DIR\"))\n        \
                 .status()\n        .expect(\"run git\")\n        .success());\n    \
                 assert_eq!(gate(\"99\"), Some(1));"
            ),
            case(
                "under_the_limit_passes",
                "assert_eq!(gate(\"1\"), Some(0));"
            ),
        ),
    );
    cargo_package(&root);
    track(&root);
    let (code, out, err) = sweep(&root, "toy");
    assert!(!out.contains("case-already-red"), "{out}");
    assert_eq!(code, 0, "{out}{err}");
}

/// The tier [`a_suite_reading_the_index_judges_the_mutant`] runs: the gate's
/// STAGED bytes, `git show :path`, as a gate judging the committed rule reads
/// them, never the checkout's. It reads them in Rust rather than running them
/// through a shell, so the case runs on every target `cross-check` builds.
const INDEX_GATE_HELPER: &str = r#"fn indexed() -> String {
    let shown = std::process::Command::new("git")
        .args(["show", ":mise-tasks/toy.sh"])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("read the toy gate from the index");
    String::from_utf8(shown.stdout).expect("the toy gate is UTF-8")
}
"#;

#[test]
fn a_suite_reading_the_index_judges_the_mutant() {
    // CLOUD-2789: a manifest's `settings-unlocked` row survived because the
    // mutant reached the staged checkout and not its index, which is what
    // `batten check` reads for a committed rule. A suite that reads the index
    // must see the mutant: `limit-ignored` turns the staged `LIMIT=10` into
    // `LIMIT=999`, and a mutant left in the working copy alone survives here.
    // The control case reads the index too, so a restore that left it mutated
    // would read as `case-already-red` on the next row.
    let root = toy("index");
    let mut gate = String::from(TOY_GATE);
    gate.push_str(CAUGHT);
    gate.push('\n');
    write_program(&root, "mise-tasks/toy.sh", &gate);
    write(
        &root,
        "tests/toy.rs",
        &format!(
            "{}{}{}",
            INDEX_GATE_HELPER,
            case(
                "over_the_limit_is_refused",
                "assert!(indexed().contains(\"\\nLIMIT=10\\n\"));"
            ),
            case(
                "under_the_limit_passes",
                "assert!(indexed().contains(\"#MUTANT limit-ignored\"));"
            ),
        ),
    );
    cargo_package(&root);
    track(&root);
    let (code, out, err) = sweep(&root, "toy");
    assert!(!out.contains("SURVIVED"), "{out}{err}");
    assert_eq!(code, 0, "{out}{err}");
    assert!(out.contains("every one caught"), "{out}");
}

#[cfg(unix)]
#[test]
fn anti_vacuity_a_listed_gate_with_no_declaration_fails_rather_than_being_skipped() {
    let root = toy_repo("no-declaration", &[]);
    let (code, out, err) = sweep(&root, "toy");
    assert_eq!(code, 2, "{out}");
    assert!(out.contains("no-mutant-declared"), "{out}");
    // #1276: this read `1 of 0 declared mutation(s) … were not caught`, a
    // coverage verdict over a denominator of zero.
    assert!(
        err.contains("1 gate(s) declare no row this sweep judges") && !err.contains(" of 0 "),
        "a gate-level finding is counted apart from the rows: {err}"
    );
}

#[cfg(unix)]
#[test]
fn anti_vacuity_a_filter_naming_no_case_is_not_a_pass() {
    let root = toy_repo(
        "no-case",
        &["#MUTANT limit-ignored|s/^LIMIT=10$/LIMIT=999/|no_case_is_named_this"],
    );
    let (code, out, _) = sweep(&root, "toy");
    // Could-not-look, and it is exit 3 rather than the verdict class.
    assert_eq!(code, 3, "{out}");
    assert!(out.contains("names-no-case"), "{out}");
}

#[cfg(unix)]
#[test]
fn anti_vacuity_a_mutation_that_changes_nothing_is_not_a_pass() {
    let root = toy_repo(
        "inert",
        &["#MUTANT inert|s/^NOTHING_MATCHES_THIS$/x/|over_the_limit_is_refused"],
    );
    let (code, out, err) = sweep(&root, "toy");
    assert_eq!(code, 2, "{out}");
    assert!(out.contains("inert-mutation"), "{out}");
    assert!(
        err.contains("1 declared row(s) prove nothing as written") && !err.contains("survived"),
        "an inert row is a row defect, not a survivor: {err}"
    );
}

/// A ROW IN NEXTEST'S OWN CONFIG IS JUDGED BY ITS CASE, NOT BY THE HARNESS IT
/// BREAKS (#1276). The row makes `.config/nextest.toml` unreadable to nextest,
/// and its case reads that file as data. Run against the mutated config,
/// nextest stops before it selects a case and the row cannot be looked at;
/// handed the unmutated copy with `--config-file`, the harness runs and the
/// case reddens. Fails by: the suite run under the config it was mutating.
#[test]
fn a_row_in_the_nextest_config_runs_under_an_unmutated_copy() {
    if !cfg!(unix) {
        return;
    }
    let root = toy("nextest-config-row");
    write(
        &root,
        ".config/nextest.toml",
        "#MUTANT-SUITE tests/config.rs\n\
         #MUTANT timeout-unreadable|s/^slow-timeout = \"60s\"$/slow-timeout = \"never\"/|\
         the_config_keeps_its_timeout\n\
         [profile.default]\nslow-timeout = \"60s\"\n",
    );
    write(
        &root,
        "tests/config.rs",
        &format!(
            "{}{}",
            case(
                "the_config_keeps_its_timeout",
                "let text = std::fs::read_to_string(concat!(env!(\"CARGO_MANIFEST_DIR\"), \
                 \"/.config/nextest.toml\")).expect(\"the config\");\n    \
                 assert!(text.lines().any(|line| line == \"slow-timeout = \\\"60s\\\"\"), \
                 \"{text}\");"
            ),
            case("a_second_case_keeps_the_filter_honest", ""),
        ),
    );
    cargo_package(&root);
    track(&root);
    let (code, out, err) = sweep(&root, ".config/nextest.toml");
    assert_eq!(code, 0, "{out}{err}");
    assert!(out.contains("every one caught"), "{out}{err}");
}

/// A ROW THAT PROVES NOTHING COSTS NO SUITE RUN (#1276): the mutation is
/// applied and diffed in memory before the clean run, so an inert or
/// self-mutating row is refused as such even where its case filter names
/// nothing. Fails by: the shape read only after the clean run, so a suite ran
/// for a row that could prove nothing, and these rows answered
/// `names-no-case` from that run instead.
#[test]
fn a_row_that_proves_nothing_is_refused_before_its_suite_runs() {
    if !cfg!(unix) {
        return;
    }
    for (name, row, verdict) in [
        (
            "inert-first",
            "#MUTANT inert|s/^NOTHING_MATCHES_THIS$/x/|no_case_is_named_this",
            "toy/inert inert-mutation",
        ),
        (
            "self-first",
            "#MUTANT self|s/MUTANT self/MUTANT other/|no_case_is_named_this",
            "toy/self self-mutating-row",
        ),
    ] {
        let root = toy_repo(name, &[row]);
        let (code, out, err) = sweep(&root, "toy");
        assert_eq!(code, 2, "{out}{err}");
        assert!(out.contains(verdict), "{out}");
        assert!(!out.contains("names-no-case"), "no suite ran: {out}");
    }
}

#[cfg(unix)]
#[test]
fn an_unset_enforced_set_is_fatal_rather_than_an_empty_one() {
    let root = toy_repo("unset", &[CAUGHT]);
    let (code, _, err) = sweep(&root, "");
    assert_eq!(code, 1, "{err}");
    assert!(err.contains("the enforced set is empty"), "{err}");
    assert!(
        err.contains("[mutate].gates"),
        "the refusal names the table: {err}"
    );
}

#[cfg(unix)]
#[test]
fn a_gate_named_with_no_suite_is_reported_and_is_could_not_look() {
    // CHANGED FROM THE PREDECESSOR, deliberately: the verdict is the same and
    // its exit code is not. `no-suite` says the runner could not look, which
    // CLOUD-1267 requires to stay distinguishable from "every mutation caught"
    // — and from a survivor, which is a verdict about the tree.
    let root = toy("no-suite");
    let mut gate = String::from(TOY_GATE);
    gate.push_str(CAUGHT);
    gate.push('\n');
    // The gate declares `tests/toy.rs` and nothing writes it, so the declared
    // suite is absent — the predecessor's shape was the defaulted
    // `tests/toy.bats` absent, and both are one verdict about the same fact.
    write_program(&root, "mise-tasks/toy.sh", &gate);
    cargo_package(&root);
    track(&root);
    let (code, out, _) = sweep(&root, "toy");
    assert_eq!(code, 3, "{out}");
    assert!(out.contains("no-suite"), "{out}");
}

#[cfg(unix)]
#[test]
fn a_name_resolving_to_nothing_is_no_such_gate() {
    let root = toy_repo("ghost", &[CAUGHT]);
    let (code, out, _) = sweep(&root, "ghost");
    assert_eq!(code, 3, "{out}");
    assert!(out.contains("no-such-gate"), "{out}");
}

#[cfg(unix)]
#[test]
fn pointer_never_payload_the_report_carries_no_line_of_the_mutated_source() {
    let root = toy_repo(
        "pointer",
        &["#MUTANT leak|s/^exit 0$/SECRETMARKER=1/|over_the_limit_is_refused"],
    );
    let (_, out, err) = sweep(&root, "toy");
    assert!(!out.contains("SECRETMARKER"), "{out}");
    assert!(!err.contains("SECRETMARKER"), "{err}");
}

#[cfg(unix)]
#[test]
fn the_tracked_file_is_never_mutated_in_place() {
    let root = toy_repo("in-place", &[CAUGHT]);
    let before = common::git_in(&root, &["hash-object", "mise-tasks/toy.sh"]);
    let (code, out, err) = sweep(&root, "toy");
    assert_eq!(code, 0, "{out}{err}");
    let after = common::git_in(&root, &["hash-object", "mise-tasks/toy.sh"]);
    assert_eq!(before, after, "the tracked gate must not be corrupted");
}

#[cfg(unix)]
#[test]
fn an_uncommitted_case_is_still_covered_because_the_working_tree_is_the_subject() {
    let root = toy_repo("uncommitted", &[CAUGHT]);
    common::git_in(&root, &["commit", "-m", "base"]);
    // A case added and staged but never committed. `git archive HEAD` would not
    // see it, and every mutation naming it would report `names-no-case`.
    write(
        &root,
        "tests/toy.rs",
        &format!(
            "{}{}",
            toy_suite("toy.sh", ""),
            case(
                "a_third_case_uncommitted",
                "assert_eq!(gate(\"0\"), Some(0));"
            ),
        ),
    );
    track(&root);
    let (code, out, err) = sweep(&root, "toy");
    assert_eq!(code, 0, "{out}{err}");
}

// ---------------------------------------------------------------------------
// Narrowed to a change (CLOUD-2072).
// ---------------------------------------------------------------------------

/// A row `other`'s suite cannot catch: dropping `pipefail` changes nothing the
/// suite observes. So the sweep exits non-zero exactly when `other` is swept,
/// which is what lets a case tell "narrowed" from "swept everything and passed".
const OTHER_SURVIVES: &str =
    "#MUTANT pipefail-dropped|s/^set -uo pipefail$/set -u/|other_refuses_ninety_nine";

/// `toy_repo` plus a second gate, `other`, whose one row survives, committed as
/// the base a change is measured against.
fn two_gate_repo(name: &str) -> PathBuf {
    let root = toy_repo(name, &[CAUGHT]);
    let gate = TOY_GATE
        .replace("the toy", "the other")
        .replace("tests/toy.rs", "tests/other.rs");
    write_program(
        &root,
        "mise-tasks/other.sh",
        &format!("{gate}{OTHER_SURVIVES}\n"),
    );
    write(&root, "tests/other.rs", &other_suite(""));
    track(&root);
    common::git_in(&root, &["commit", "-m", "base"]);
    root
}

/// `other`'s suite. Its case names share no substring with `toy`'s, because
/// `cargo test -- <filter>` runs every target: `toy_suite`'s `other_` prefix
/// would leave `toy`'s `over_the_limit` naming a case of each.
fn other_suite(tail: &str) -> String {
    format!(
        "{}{}{}{tail}",
        runs("other.sh"),
        case(
            "other_refuses_ninety_nine",
            "assert_eq!(gate(\"99\"), Some(1));"
        ),
        case("other_passes_one", "assert_eq!(gate(\"1\"), Some(0));"),
    )
}

/// Sweep `gates` narrowed to what changed since `base`.
fn sweep_since(root: &Path, gates: &str, base: &str) -> (i32, String, String) {
    // THE INHERITED ENVIRONMENT, as before CLOUD-2588: these cases run under a
    // CI leg's own `$CI`, which is where #1209's class showed. Only the
    // pass-record cases clear it, through `sweep_since_with`.
    answered(&mut narrowed_sweep(root, gates, base))
}

/// The sweep of `gates` narrowed to what changed since `base`, as a command
/// both narrowed helpers start from.
fn narrowed_sweep(root: &Path, gates: &str, base: &str) -> common::Batten {
    let mut command = common::batten();
    command
        .args(["mutate", "sweep"])
        .current_dir(root)
        .env("MUTANT_GATES", gates)
        .env("MUTANT_CHANGED_SINCE", base)
        .env("MUTANT_TASKS", "mise.toml")
        .env("MUTANT_PRESETS", PRESETS);
    command
}

/// Run `command` to its exit, as `(code, stdout, stderr)`.
fn answered(command: &mut common::Batten) -> (i32, String, String) {
    let answer = command.streamed_output().expect("run batten mutate");
    (
        answer.status.code().unwrap_or(-1),
        stdout(&answer),
        stderr(&answer),
    )
}

/// `two_gate_repo` with the enforced set committed as `before` in `path`, then
/// rewritten to `after` and left uncommitted: a change that enrolls a gate and
/// touches none of its sources or suites.
fn enrolling(name: &str, path: &str, before: &str, after: &str) -> PathBuf {
    let root = two_gate_repo(name);
    write(&root, path, before);
    track(&root);
    common::git_in(&root, &["commit", "-m", "enroll toy"]);
    write(&root, path, after);
    root
}

/// A GATE ENROLLED SINCE THE BASE IS SWEPT (#1276): `other` joins the set the
/// task manifest declares, and nothing of `other`'s changed. Fails by: the
/// narrowing reading sources and suites alone, so the change answered "no
/// enforced gate's source or suite changed" and the new gate's survivor was
/// never reached.
#[test]
fn a_gate_enrolled_in_the_manifest_since_the_base_is_swept() {
    if !cfg!(unix) {
        return;
    }
    let root = enrolling(
        "since-enrolled-env",
        "mise.toml",
        "[env]\nMUTANT_GATES = \"toy\"\n",
        "[env]\nMUTANT_GATES = \"toy,other\"\n",
    );
    let (code, out, err) = sweep_since(&root, "toy,other", "HEAD");
    assert_ne!(code, 0, "{out}{err}");
    assert!(
        out.contains("other/pipefail-dropped SURVIVED"),
        "{out}{err}"
    );
}

/// The committed table's arm of the same: `other` joins `[mutate].gates`.
#[test]
fn a_gate_enrolled_in_the_committed_table_since_the_base_is_swept() {
    if !cfg!(unix) {
        return;
    }
    let root = enrolling(
        "since-enrolled-table",
        "batten.toml",
        "version = 1\n\n[mutate]\ngates = [\"toy\"]\n",
        "version = 1\n\n[mutate]\ngates = [\"toy\", \"other\"]\n",
    );
    let (code, out, err) = sweep_since(&root, "", "HEAD");
    assert_ne!(code, 0, "{out}{err}");
    assert!(
        out.contains("other/pipefail-dropped SURVIVED"),
        "{out}{err}"
    );
}

/// The glob arm of the same: a glob newly written in the manifest enrolls the
/// gate whose source it matches, though no gate's NAME grew. Fails by: a new
/// glob never read, so `other` was not swept and the change looked inert.
#[test]
fn a_gate_enrolled_by_a_new_glob_since_the_base_is_swept() {
    if !cfg!(unix) {
        return;
    }
    let root = enrolling(
        "since-enrolled-glob",
        "mise.toml",
        "[env]\nMUTANT_GATES = \"toy,other\"\n",
        "[env]\nMUTANT_GATES = \"toy,other\"\n# mise-tasks/oth*.sh\n",
    );
    let (code, out, err) = sweep_since(&root, "toy,other", "HEAD");
    assert_ne!(code, 0, "{out}{err}");
    assert!(
        out.contains("other/pipefail-dropped SURVIVED"),
        "{out}{err}"
    );
}

/// `toy`'s cases moved out of its declared suite into a module of the same
/// target, as a `tests/<dir>/main.rs` layout has them: libtest selects a case
/// wherever it compiled, so the case file is not the declared one. Committed.
fn split_suite_repo(name: &str) -> PathBuf {
    let root = toy(name);
    let gate = TOY_GATE.replace("tests/toy.rs", "tests/toy/main.rs");
    write_program(&root, "mise-tasks/toy.sh", &format!("{gate}{CAUGHT}\n"));
    write(
        &root,
        "tests/toy/main.rs",
        &format!("{}mod cases;\n", runs("toy.sh")),
    );
    write(&root, "tests/toy/cases.rs", &split_cases(true));
    cargo_package(&root);
    track(&root);
    common::git_in(&root, &["commit", "-m", "base"]);
    root
}

/// The module holding `toy`'s cases: the over-the-limit case asserts the
/// refusal where `strict`, and only that the gate ran where not, so the row's
/// mutation survives it.
fn split_cases(strict: bool) -> String {
    let over = if strict {
        "assert_eq!(gate(\"99\"), Some(1));"
    } else {
        "assert!(gate(\"99\").is_some());"
    };
    format!(
        "use super::gate;\n{}{}",
        case("over_the_limit_is_refused", over),
        case(
            "under_the_limit_passes",
            "assert_eq!(gate(\"1\"), Some(0));"
        ),
    )
}

/// A CASE OUTSIDE ITS DECLARED SUITE IS PART OF WHAT A CHANGE CAN MOVE
/// (#1276): weakening the case file touches the gate. Fails by: the touch set
/// reading the declared suite's path alone, so the weakened case answered "no
/// enforced gate's source or suite changed".
#[test]
fn a_weakened_case_outside_its_suite_touches_the_gate() {
    if !cfg!(unix) {
        return;
    }
    let root = split_suite_repo("since-case-file");
    write(&root, "tests/toy/cases.rs", &split_cases(false));
    let (code, out, err) = sweep_since(&root, "toy", "HEAD");
    assert_ne!(code, 0, "{out}{err}");
    assert!(out.contains("toy/limit-ignored SURVIVED"), "{out}{err}");
}

/// And it is part of the row's key, so a recorded catch is not replayed over a
/// case weakened since. Fails by: the key reading the declared suite alone.
#[test]
fn a_weakened_case_outside_its_suite_runs_its_row_again() {
    if !cfg!(unix) {
        return;
    }
    let root = split_suite_repo("recorded-case-file");
    let (code, out, err) = sweep(&root, "toy");
    assert_eq!(code, 0, "{out}{err}");
    write(&root, "tests/toy/cases.rs", &split_cases(false));
    let (code, out, err) = sweep(&root, "toy");
    assert_ne!(code, 0, "{out}{err}");
    assert!(!err.contains("(recorded)"), "{err}");
    assert!(out.contains("toy/limit-ignored SURVIVED"), "{out}{err}");
}

/// `toy`'s gate, edited: the one change most cases below judge.
fn edit_toy(root: &Path) {
    write_program(
        root,
        "mise-tasks/toy.sh",
        &format!("{TOY_GATE}{CAUGHT}\n# edited\n"),
    );
}

/// The control: unnarrowed, `other`'s survivor fails the sweep. Without it the
/// narrowed cases below could pass on a fixture that never fails at all.
#[cfg(unix)]
#[test]
fn anti_vacuity_the_whole_set_reaches_the_surviving_row() {
    let root = two_gate_repo("since-control");
    let (code, out, err) = sweep(&root, "toy,other");
    assert_ne!(code, 0, "{out}{err}");
    assert!(out.contains("other/pipefail-dropped SURVIVED"), "{out}");
}

/// **The discriminating case.** Only `toy`'s gate changed since the base, so only
/// `toy` is swept and `other`'s survivor is never reached.
#[cfg(unix)]
#[test]
fn a_change_to_one_gate_sweeps_only_that_gate() {
    let root = two_gate_repo("since-one");
    edit_toy(&root);
    let (code, out, err) = sweep_since(&root, "toy,other", "HEAD");
    assert_eq!(code, 0, "{out}{err}");
    assert!(out.contains("every one caught"), "{out}");
    assert!(!out.contains("SURVIVED"), "{out}");
}

/// A changed SUITE touches its gate: a weakened test is exactly the change a
/// mutation sweep exists to catch.
#[cfg(unix)]
#[test]
fn a_change_to_a_suite_sweeps_its_gate() {
    let root = two_gate_repo("since-suite");
    write(&root, "tests/other.rs", &other_suite("fn helper() {}\n"));
    let (code, out, err) = sweep_since(&root, "toy,other", "HEAD");
    assert_ne!(code, 0, "{out}{err}");
    assert!(out.contains("other/pipefail-dropped SURVIVED"), "{out}");
}

/// A COMMENT CANNOT WEAKEN A SUITE, so a comment-only edit to one touches no
/// gate. Fails by: the suite arm reading raw bytes, which re-swept every gate
/// naming a suite whose comments moved (134 rows on #1276, from deleting
/// markers).
#[test]
fn a_comment_edit_to_a_suite_sweeps_nothing() {
    let root = two_gate_repo("since-suite-comment");
    write(&root, "tests/other.rs", &other_suite("// a comment\n"));
    let (code, out, err) = sweep_since(&root, "toy,other", "HEAD");
    assert_eq!(code, 0, "{out}{err}");
    assert!(
        out.contains("no enforced gate's source or suite changed since HEAD"),
        "{out}{err}"
    );
}

/// Fails by: only a source's FIRST `MUTANT-SUITE` counting as its suite, so a
/// change touching a later one selects no sweep (CLOUD-2193: `land.rs`
/// declares four, and a weakened `tests/it/land.rs` re-proved none of them).
#[cfg(unix)]
#[test]
fn a_change_to_a_sources_second_suite_sweeps_its_gate() {
    let root = two_gate_repo("since-second-suite");
    let other = std::fs::read_to_string(root.join("mise-tasks/other.sh")).expect("other.sh");
    write_program(
        &root,
        "mise-tasks/other.sh",
        &format!("{other}#MUTANT-SUITE tests/extra.rs\n"),
    );
    // Its own case name: `cargo test -- <want>` runs every target, and a
    // second `other_refuses_*` would make the row name every case.
    write(&root, "tests/extra.rs", "#[test]\nfn extra_holds() {}\n");
    track(&root);
    common::git_in(&root, &["commit", "-m", "second suite"]);
    write(
        &root,
        "tests/extra.rs",
        "#[test]\nfn extra_holds() {}\nfn helper() {}\n",
    );
    let (code, out, err) = sweep_since(&root, "toy,other", "HEAD");
    assert_ne!(code, 0, "{out}{err}");
    assert!(out.contains("other/pipefail-dropped SURVIVED"), "{out}");
}

// ---------------------------------------------------------------------------
// The whole-change pass record (CLOUD-2588): a change that passed whole is
// answered without running again, under a key that moves with its content.
// ---------------------------------------------------------------------------

/// The line a sweep answers with when the change already passed whole.
///
/// EVERY CASE BELOW IS COMPILED ON EVERY TARGET AND RUNS ON UNIX ALONE, by
/// `cfg!` rather than `#[cfg]` (`policy/cfg-gated-test.rego`): the toy gate is a
/// bash program, so off unix there is no subject to judge, and `cross-check`
/// still type-checks each case where it does not run.
const NOT_RUN_AGAIN: &str = "so it is not run again";

/// Sweep `gates` narrowed to what changed since `base`, with `env` on top of a
/// scope the runner and shard variables of the outer run cannot reach.
fn sweep_since_with(
    root: &Path,
    gates: &str,
    base: &str,
    env: &[(&str, &str)],
) -> (i32, String, String) {
    let mut command = narrowed_sweep(root, gates, base);
    command
        .env_remove("MUTANT_SHARD")
        .env_remove("MUTANT_RUNNER")
        .env_remove("MUTANT_RUNNERS")
        // A forge runner's own `$CI`, and the step cache's bypass, either of
        // which turns the record off (`step::bypassed`).
        .env_remove("CI")
        .env_remove("BATTEN_STEP_RECEIPT_BYPASS");
    for (key, value) in env {
        command.env(key, value);
    }
    answered(&mut command)
}

/// `two_gate_repo` with `target/` ignored and committed, as a real checkout
/// has it: the sweep writes its staged copy and builds under `target/`, and an
/// unignored one is a change the next run's key would carry.
fn ignoring_target(name: &str) -> PathBuf {
    let root = two_gate_repo(name);
    write(&root, ".gitignore", "/target/\n");
    common::git_in(&root, &["add", ".gitignore"]);
    common::git_in(&root, &["commit", "-m", "ignore target"]);
    root
}

/// Sweep `root`'s change, which must pass, then sweep it unmoved and require it
/// answered: THE CONTROL a case runs before moving something, so the run after
/// is judged because something moved and not because nothing was recorded.
fn sweep_recorded(root: &Path) {
    let (code, out, err) = sweep_since_with(root, "toy,other", "HEAD", &[]);
    assert_eq!(code, 0, "{out}{err}");
    let (_, out, _) = sweep_since_with(root, "toy,other", "HEAD", &[]);
    assert!(
        out.contains(NOT_RUN_AGAIN),
        "the first sweep was recorded: {out}"
    );
}

/// `ignoring_target` with `toy`'s gate edited, and a first sweep of that change
/// that passes whole and so is recorded.
fn passed_change(name: &str) -> PathBuf {
    let root = ignoring_target(name);
    edit_toy(&root);
    let (code, out, err) = sweep_since_with(&root, "toy,other", "HEAD", &[]);
    assert_eq!(code, 0, "{out}{err}");
    assert!(out.contains("every one caught"), "{out}");
    assert!(!out.contains(NOT_RUN_AGAIN), "a first run is run: {out}");
    root
}

/// **The discriminating case.** The same change, swept again, is answered from
/// the record and judges no row.
#[test]
fn a_change_that_passed_whole_is_not_swept_again() {
    if !cfg!(unix) {
        return;
    }
    let root = passed_change("pass-again");
    let (code, out, err) = sweep_since_with(&root, "toy,other", "HEAD", &[]);
    assert_eq!(code, 0, "{out}{err}");
    assert!(out.contains(NOT_RUN_AGAIN), "{out}");
    assert!(
        !out.contains("declared mutation(s)"),
        "a row was judged: {out}"
    );
}

/// A change whose patch moved is a key that moved.
#[test]
fn a_change_whose_patch_moved_is_swept_again() {
    if !cfg!(unix) {
        return;
    }
    let root = passed_change("pass-patch-moved");
    write_program(
        &root,
        "mise-tasks/toy.sh",
        &format!("{TOY_GATE}{CAUGHT}\n# edited twice\n"),
    );
    let (code, out, err) = sweep_since_with(&root, "toy,other", "HEAD", &[]);
    assert_eq!(code, 0, "{out}{err}");
    assert!(!out.contains(NOT_RUN_AGAIN), "{out}");
    assert!(out.contains("every one caught"), "{out}");
}

/// A COMMENT EDIT TO A ROW'S SUITE KEEPS THE ROW'S CATCH: its key carries the
/// suite's code, and a comment cannot weaken it. Fails by: the suite keyed by
/// its raw bytes, so every recorded row re-ran after a comment moved.
#[test]
fn a_comment_edit_to_a_suite_keeps_its_rows_caught() {
    if !cfg!(unix) {
        return;
    }
    let root = passed_change("pass-suite-comment");
    let suite = format!("{}// a comment\n", toy_suite("toy.sh", ""));
    write(&root, "tests/toy.rs", &suite);
    let (code, out, err) = sweep_since_with(&root, "toy,other", "HEAD", &[]);
    assert_eq!(code, 0, "{out}{err}");
    assert!(err.contains("caught (recorded)"), "{out}{err}");
}

/// The base moved a row's SUITE under an unchanged patch, as a rebase does:
/// the rows' keys carry the suite's code, so the change runs again.
#[test]
fn a_change_whose_suite_moved_under_it_is_swept_again() {
    if !cfg!(unix) {
        return;
    }
    let root = passed_change("pass-suite-moved");
    let suite = format!("{}fn moved_on_the_base() {{}}\n", toy_suite("toy.sh", ""));
    write(&root, "tests/toy.rs", &suite);
    common::git_in(&root, &["add", "tests/toy.rs"]);
    common::git_in(&root, &["commit", "-m", "the base moves the suite"]);
    let (code, out, err) = sweep_since_with(&root, "toy,other", "HEAD", &[]);
    assert_eq!(code, 0, "{out}{err}");
    assert!(!out.contains(NOT_RUN_AGAIN), "{out}");
}

/// **What the record is for.** The base moved a changed file AWAY FROM the
/// change, as a rebase onto a busy trunk does: the change's hunks are the same,
/// so the key is, and the lap is answered. A key over the file's whole working
/// bytes would miss here.
#[test]
fn a_rebase_that_moves_only_unchanged_context_is_answered() {
    if !cfg!(unix) {
        return;
    }
    let root = ignoring_target("pass-context");
    let lines: Vec<String> = (1..=20).map(|n| format!("line {n}")).collect();
    write(&root, "notes.txt", &format!("{}\n", lines.join("\n")));
    common::git_in(&root, &["add", "notes.txt"]);
    common::git_in(&root, &["commit", "-m", "notes"]);
    edit_toy(&root);
    write(
        &root,
        "notes.txt",
        &format!("{}\nline 21\n", lines.join("\n")),
    );
    let (code, out, err) = sweep_since_with(&root, "toy,other", "HEAD", &[]);
    assert_eq!(code, 0, "{out}{err}");
    // The base edits line 1 and adds a line above it, far outside the hunk at
    // the end, so every line number under the change moves. The working copy
    // keeps the change on top of it.
    let mut moved = lines.clone();
    moved[0] = String::from("line one");
    moved.insert(0, String::from("line zero"));
    write(&root, "notes.txt", &format!("{}\n", moved.join("\n")));
    common::git_in(&root, &["add", "notes.txt"]);
    common::git_in(&root, &["commit", "-m", "the base moves unchanged context"]);
    write(
        &root,
        "notes.txt",
        &format!("{}\nline 21\n", moved.join("\n")),
    );
    let (code, out, err) = sweep_since_with(&root, "toy,other", "HEAD", &[]);
    assert_eq!(code, 0, "{out}{err}");
    assert!(out.contains(NOT_RUN_AGAIN), "{out}");
}

/// A changed file emptied and the same file deleted write the same patch, and
/// are two trees: a deleted source removes a module. They are two keys.
#[test]
fn a_deleted_file_is_not_the_emptied_one() {
    if !cfg!(unix) {
        return;
    }
    let root = ignoring_target("pass-deleted");
    write(&root, "notes.txt", "notes\n");
    common::git_in(&root, &["add", "notes.txt"]);
    common::git_in(&root, &["commit", "-m", "notes"]);
    edit_toy(&root);
    write(&root, "notes.txt", "");
    sweep_recorded(&root);
    fs::remove_file(root.join("notes.txt")).expect("delete notes.txt");
    let (code, out, err) = sweep_since_with(&root, "toy,other", "HEAD", &[]);
    assert_eq!(code, 0, "{out}{err}");
    assert!(!out.contains(NOT_RUN_AGAIN), "{out}");
}

/// Under `$CI` the record is never read: a confirmation run judges the change
/// whole even where a workspace kept a record from an earlier run.
#[test]
fn a_change_under_ci_is_swept_again() {
    if !cfg!(unix) {
        return;
    }
    let root = passed_change("pass-under-ci");
    let (code, out, err) = sweep_since_with(&root, "toy,other", "HEAD", &[("CI", "true")]);
    assert_eq!(code, 0, "{out}{err}");
    assert!(!out.contains(NOT_RUN_AGAIN), "{out}");
    assert!(out.contains("every one caught"), "{out}");
}

/// Another shard is another scope, so another key.
#[test]
fn a_change_under_another_shard_is_swept_again() {
    if !cfg!(unix) {
        return;
    }
    let root = passed_change("pass-shard");
    let (code, out, err) = sweep_since_with(&root, "toy,other", "HEAD", &[("MUTANT_SHARD", "0/1")]);
    assert_eq!(code, 0, "{out}{err}");
    assert!(!out.contains(NOT_RUN_AGAIN), "{out}");
}

/// A sweep that refused is never recorded: the same change refuses again.
#[test]
fn a_failing_change_is_never_recorded() {
    if !cfg!(unix) {
        return;
    }
    let root = ignoring_target("pass-failing");
    write(&root, "tests/other.rs", &other_suite("fn helper() {}\n"));
    for _ in 0..2 {
        let (code, out, err) = sweep_since_with(&root, "toy,other", "HEAD", &[]);
        assert_ne!(code, 0, "{out}{err}");
        assert!(out.contains("other/pipefail-dropped SURVIVED"), "{out}");
        assert!(!out.contains(NOT_RUN_AGAIN), "{out}");
    }
}

/// A changed file the patch reads as empty, because it is not UTF-8, still
/// moves the key through its digest.
#[test]
fn a_changed_binary_file_moves_the_key() {
    if !cfg!(unix) {
        return;
    }
    let root = ignoring_target("pass-binary");
    fs::write(root.join("data.bin"), [0xff_u8, 0x00]).expect("write data.bin");
    common::git_in(&root, &["add", "data.bin"]);
    common::git_in(&root, &["commit", "-m", "a binary file"]);
    edit_toy(&root);
    fs::write(root.join("data.bin"), [0xff_u8, 0x01]).expect("write data.bin");
    sweep_recorded(&root);
    fs::write(root.join("data.bin"), [0xff_u8, 0x02]).expect("write data.bin");
    let (code, out, err) = sweep_since_with(&root, "toy,other", "HEAD", &[]);
    assert_eq!(code, 0, "{out}{err}");
    assert!(!out.contains(NOT_RUN_AGAIN), "{out}");
}

/// `sweep_since` with a runner registry declared, and optionally the registered
/// runner to run instead of the declared one.
fn sweep_registered(
    root: &Path,
    gates: &str,
    base: &str,
    runners: &str,
    runner: Option<&str>,
) -> (i32, String, String) {
    let mut command = common::batten();
    command
        .args(["mutate", "sweep"])
        .current_dir(root)
        .env("MUTANT_GATES", gates)
        .env("MUTANT_CHANGED_SINCE", base)
        .env("MUTANT_TASKS", "mise.toml")
        .env("MUTANT_RUNNERS", runners);
    match runner {
        Some(runner) => command.env("MUTANT_RUNNER", runner),
        None => command.env_remove("MUTANT_RUNNER"),
    };
    let answer = command.streamed_output().expect("run batten mutate");
    (
        answer.status.code().unwrap_or(-1),
        stdout(&answer),
        stderr(&answer),
    )
}

/// A changed Rust source beside the two toy gates: no gate names it, so only a
/// registered runner's ownership decides who judges it.
fn rust_gate_repo(name: &str) -> PathBuf {
    let root = two_gate_repo(name);
    write(&root, "crates/batten/src/rusty.rs", "fn rusty() {}\n");
    track(&root);
    common::git_in(&root, &["commit", "-m", "rust source"]);
    write(
        &root,
        "crates/batten/src/rusty.rs",
        "fn rusty() {}\n// edited\n",
    );
    root
}

/// A change to a Rust gate whose source a registered runner owns is that
/// runner's, never the declared runner's (CLOUD-1746): the declared sweep does
/// not reach the row, and says which runner judges the change.
#[test]
fn a_change_to_a_rust_gate_is_judged_by_its_registered_runner() {
    // THE TOY GATES ARE `sh` SCRIPTS: off unix there is no gate to sweep, and
    // the case compiles everywhere so the other target type-checks it.
    if !cfg!(unix) {
        return;
    }
    let root = rust_gate_repo("since-rust");
    let (code, out, err) = sweep_registered(
        &root,
        "toy,other",
        "HEAD",
        "cargo-mutants=crates/**/*.rs",
        None,
    );
    assert!(
        out.contains(
            "1 changed source(s) owned by cargo-mutants — judged by `cargo mutants --in-diff`"
        ),
        "{out}{err}"
    );
    assert_eq!(code, 0, "{out}{err}");
    assert!(
        out.contains("no enforced gate's source or suite changed since HEAD"),
        "{out}{err}"
    );
}

/// cargo-mutants runs as itself (`cargo mutants --in-diff`), so naming it as
/// the runner this verb spawns is a usage error, never a sweep that quietly
/// judged nothing or a probe for a program the verb will not run.
#[test]
fn cargo_mutants_is_never_spawned_by_the_sweep() {
    // THE TOY GATES ARE `sh` SCRIPTS: off unix there is no gate to sweep, and
    // the case compiles everywhere so the other target type-checks it.
    if !cfg!(unix) {
        return;
    }
    let root = rust_gate_repo("since-rust-runner");
    let answer = common::batten()
        .args(["mutate", "sweep"])
        .current_dir(&root)
        .env("MUTANT_GATES", "toy,other")
        .env("MUTANT_CHANGED_SINCE", "HEAD")
        .env("MUTANT_TASKS", "mise.toml")
        .env("MUTANT_RUNNERS", "cargo-mutants=crates/**/*.rs")
        .env("MUTANT_RUNNER", "cargo-mutants")
        .streamed_output()
        .expect("run batten mutate");
    let (out, err) = (stdout(&answer), stderr(&answer));
    assert_eq!(answer.status.code(), Some(1), "the usage code: {out}{err}");
    assert!(err.contains("runs as itself"), "{out}{err}");
    assert!(!out.contains("runner-absent"), "{out}{err}");
}

/// `batten mutate cargo` in this repository's toy tree, with `env` set.
fn mutate_cargo(root: &Path, env: &[(&str, &str)]) -> (Option<i32>, String, String) {
    let mut command = common::batten();
    command
        .args(["mutate", "cargo"])
        .current_dir(root)
        .env("MUTANT_RUNNERS", "cargo-mutants=**/*.rs");
    for (name, value) in env {
        command.env(name, value);
    }
    let answer = command.streamed_output().expect("run batten mutate cargo");
    (answer.status.code(), stdout(&answer), stderr(&answer))
}

/// THE WHOLE WORKSPACE NEEDS NO BASE (CLOUD-2849): `MUTANT_WHOLE_TREE` alone
/// passes the base check and writes no change, so the run goes on to fetch
/// the runner that lists `--workspace`. The toy tree provisions none, so that
/// is where it stops. Fails by: the whole-tree run refused for naming no base,
/// which is how the schedule lost its Rust proof, or narrowed to a change.
#[test]
fn a_whole_tree_run_needs_no_base_and_lists_no_change() {
    let root = rust_gate_repo("whole-tree-no-base");
    let (code, out, err) = mutate_cargo(&root, &[("MUTANT_WHOLE_TREE", "1")]);
    assert!(!err.contains("names no base"), "{out}{err}");
    assert!(!out.contains("changed since"), "{out}{err}");
    assert!(
        err.contains("no [[provision]] row ships cargo-mutants"),
        "the run reached the runner: {code:?} {out}{err}"
    );
    assert!(
        out.contains("cargo-mutants runner-absent"),
        "the unfetched runner is named: {out}{err}"
    );
    // nextest answers on this suite's PATH, so the probe names nothing.
    assert!(!out.contains("cargo-nextest runner-absent"), "{out}{err}");
}

/// RUNNER FIRST (CLOUD-2881): a Cargo sweep where `cargo nextest` does not
/// answer is `cargo-nextest runner-absent`, exit 3, before any mutant is
/// listed or the schema is built — the build it used to start first cost 7-20
/// minutes before the first judging run found nextest missing. `PATH` holds
/// only the directory of the `cargo` running this suite, and `CARGO_HOME` is
/// empty, as in `a_declared_cargo_row_without_nextest_reads_one_runner_absent`.
/// Fails by: the probe dropped or moved after the listing, so no
/// `cargo-nextest runner-absent` is said.
#[test]
fn a_cargo_sweep_without_nextest_refuses_before_it_builds() {
    let root = rust_gate_repo("cargo-sweep-no-nextest");
    let cargo = PathBuf::from(env!("CARGO"));
    let only_cargo = cargo.parent().expect("cargo lives in a directory");
    assert!(
        !only_cargo.join("cargo-nextest").exists(),
        "this case needs a cargo directory without nextest"
    );
    let home = common::scratch("cargo-sweep-no-nextest-cargo-home");
    let (code, out, err) = mutate_cargo(
        &root,
        &[
            ("MUTANT_WHOLE_TREE", "1"),
            ("PATH", &only_cargo.to_string_lossy()),
            ("CARGO_HOME", &home.to_string_lossy()),
        ],
    );
    assert_eq!(code, Some(3), "{out}{err}");
    assert_eq!(
        out.matches("cargo-nextest runner-absent").count(),
        1,
        "{out}{err}"
    );
    assert!(
        !out.contains("mutant(s) of"),
        "nothing was listed: {out}{err}"
    );
}

/// [`rust_gate_repo`] with cargo-mutants provisioned, so only nextest can be
/// the missing runner.
fn provisioned_rust_gate_repo(name: &str) -> PathBuf {
    let root = rust_gate_repo(name);
    // The toy repository carries no config of its own; this is its whole one.
    write(
        &root,
        "batten.toml",
        &format!("version = 1\n{}", crate::step_journal::MUTANTS_PROVISION),
    );
    root
}

/// `PATH` holding only the `cargo` running this suite, and an empty
/// `CARGO_HOME`: a host where `cargo nextest` does not answer.
fn without_nextest(name: &str) -> (String, String) {
    let cargo = PathBuf::from(env!("CARGO"));
    let only_cargo = cargo.parent().expect("cargo lives in a directory");
    assert!(
        !only_cargo.join("cargo-nextest").exists(),
        "this case needs a cargo directory without nextest"
    );
    let home = common::scratch(name);
    (
        only_cargo.to_string_lossy().into_owned(),
        home.to_string_lossy().into_owned(),
    )
}

/// RUNNER FIRST WITH THE OTHER RUNNER PRESENT (CLOUD-2881): cargo-mutants
/// provisioned and nextest missing is `cargo-nextest runner-absent`, exit 3,
/// and cargo-mutants is never asked to list. Fails by: the early return
/// deleted or moved below `list_mutants`, so the run lists every mutant and
/// pays the schema build before any judging run finds nextest gone.
#[test]
fn a_provisioned_sweep_without_nextest_refuses_before_it_lists() {
    let root = provisioned_rust_gate_repo("cargo-sweep-provisioned-no-nextest");
    let (path, home) = without_nextest("cargo-sweep-provisioned-no-nextest-home");
    let (code, out, err) = mutate_cargo(
        &root,
        &[
            ("MUTANT_WHOLE_TREE", "1"),
            ("PATH", &path),
            ("CARGO_HOME", &home),
        ],
    );
    assert_eq!(code, Some(3), "{out}{err}");
    assert_eq!(
        out.matches("cargo-nextest runner-absent").count(),
        1,
        "{out}{err}"
    );
    assert!(
        !out.contains("cargo-mutants runner-absent"),
        "provisioned: {out}{err}"
    );
    assert!(
        !out.contains("mutant(s) of"),
        "nothing was listed: {out}{err}"
    );
}

/// THE REACH SEED ASKS TOO (CLOUD-2881): the detached seed lists and builds the
/// schema like the sweep, so nextest missing is could-not-look before it lists.
/// Fails by: the seed fetching cargo-mutants and listing with no probe.
#[test]
fn a_reach_seed_without_nextest_refuses_before_it_lists() {
    let root = provisioned_rust_gate_repo("cargo-seed-no-nextest");
    let (path, home) = without_nextest("cargo-seed-no-nextest-home");
    let (code, out, err) = mutate_cargo(
        &root,
        &[
            (batten::mutate::resume::SEED_ENV, "1"),
            ("MUTANT_PHASE", "reach"),
            ("PATH", &path),
            ("CARGO_HOME", &home),
        ],
    );
    assert_eq!(code, Some(3), "{out}{err}");
    assert_eq!(
        out.matches("cargo-nextest runner-absent").count(),
        1,
        "{out}{err}"
    );
    assert!(
        !out.contains("reach seed over"),
        "nothing was listed: {out}{err}"
    );
}

/// A CHANGE OR THE WHOLE WORKSPACE, NEVER BOTH (CLOUD-2849): a schedule that
/// inherited a base would judge one diff while reporting a whole-tree sweep.
/// Fails by: the base winning in silence, or the refusal not naming both.
#[test]
fn a_base_beside_the_whole_tree_is_a_usage_error() {
    let root = rust_gate_repo("whole-tree-and-base");
    let (code, out, err) = mutate_cargo(
        &root,
        &[("MUTANT_WHOLE_TREE", "1"), ("MUTANT_CHANGED_SINCE", "HEAD")],
    );
    assert_eq!(
        code,
        Some(batten::exit::ExitCode::Usage.code()),
        "{out}{err}"
    );
    assert!(
        err.contains("MUTANT_WHOLE_TREE") && err.contains("MUTANT_CHANGED_SINCE"),
        "{out}{err}"
    );
    assert!(
        !err.contains("[[provision]]"),
        "nothing was fetched: {out}{err}"
    );
    let (code, out, err) = mutate_cargo(&root, &[]);
    assert_eq!(
        code,
        Some(batten::exit::ExitCode::Usage.code()),
        "{out}{err}"
    );
    assert!(
        err.contains("names no base"),
        "neither is today's refusal: {out}{err}"
    );
}

/// A RUST ROW IS REFUSED, NEVER PASSED OVER (CLOUD-2253): a gate named by a
/// `.rs` path whose row cargo-mutants' registry owns is `runner-owned` in both
/// the sweep and the census. Fails by: the row filtered out in silence, which is
/// how 868 hand-written Rust rows read as coverage.
#[test]
fn a_row_in_a_source_cargo_mutants_owns_is_refused() {
    if !cfg!(unix) {
        return;
    }
    let root = two_gate_repo("runner-owned-row");
    let rust = [
        "//MUTANT-SUITE tests/other.rs",
        "//MUTANT ignored|s@^fn a@fn b@|other_keeps_its_limit",
        "fn a() {}",
        "",
    ]
    .join("\n");
    write(&root, "src/owned.rs", &rust);
    track(&root);
    for verb in ["sweep", "census"] {
        let answer = common::batten()
            .args(["mutate", verb])
            .current_dir(&root)
            .env("MUTANT_GATES", "toy,other,src/owned.rs")
            .env("MUTANT_TASKS", "mise.toml")
            .env("MUTANT_RUNNERS", "cargo-mutants=**/*.rs")
            .streamed_output()
            .expect("run batten mutate");
        let (out, err) = (stdout(&answer), stderr(&answer));
        assert_eq!(answer.status.code(), Some(2), "{verb}: {out}{err}");
        assert!(out.contains("runner-owned"), "{verb}: {out}{err}");
    }
}

/// A REGISTERED RUNNER THAT DOES NOT RESOLVE CANNOT LOOK: a `command` runner
/// whose program is not there is `command runner-absent`, exit 3, before
/// anything spawns, and never every source caught. Fails by: the
/// `mutate::unresolvable` probe dropped from the registered path, which leaves
/// a spawn error with no `runner-absent` naming the runner, or its exit read
/// as a verdict.
///
/// Carries `main`'s `a_registered_runner_that_does_not_resolve_cannot_look`,
/// whose runner (cargo-mutants through this verb) is a usage error since
/// CLOUD-2253; `command` is the registered runner the verb still spawns.
#[test]
fn a_command_runner_that_does_not_resolve_cannot_look() {
    // THE TOY GATES ARE `sh` SCRIPTS: off unix there is no gate to sweep, and
    // the case compiles everywhere so the other target type-checks it.
    if !cfg!(unix) {
        return;
    }
    let root = rust_gate_repo("command-unresolved");
    write(
        &root,
        "batten.toml",
        "version = 1\n\n[mutate]\ncommand = [\"./no-such-runner.sh\"]\n",
    );
    let (code, out, err) = sweep_registered(
        &root,
        "toy,other",
        "HEAD",
        "command=crates/**/*.rs",
        Some("command"),
    );
    assert_eq!(code, 3, "{out}{err}");
    assert!(out.contains("command runner-absent"), "{out}{err}");
    assert!(!out.contains("every one caught"), "{out}{err}");
}

/// A `command` runner (CLOUD-2211) over the changed Rust gate: `[mutate]
/// command` names a stub that records its argv and exits `code`.
fn sweep_command(name: &str, code: i32) -> (PathBuf, i32, String, String) {
    let root = rust_gate_repo(name);
    write(
        &root,
        "batten.toml",
        "version = 1\n\n[mutate]\ncommand = [\"./mutscore.sh\", \"--fail-over\", \"0\"]\n",
    );
    write_program(
        &root,
        "mutscore.sh",
        &format!("#!/bin/sh\nprintf '%s\\n' \"$@\" > argv.txt\nexit {code}\n"),
    );
    let (status, out, err) = sweep_registered(
        &root,
        "toy,other",
        "HEAD",
        "command=crates/**/*.rs",
        Some("command"),
    );
    (root, status, out, err)
}

#[test]
fn a_command_runner_exit_zero_is_caught() {
    // THE TOY GATES ARE `sh` SCRIPTS: off unix there is no gate to sweep, and
    // the case compiles everywhere so the other target type-checks it.
    if !cfg!(unix) {
        return;
    }
    let (root, code, out, err) = sweep_command("command-caught", 0);
    assert_eq!(code, 0, "{out}{err}");
    assert!(
        out.contains("1 changed source(s) by command, every one caught"),
        "{out}{err}"
    );
    let argv = fs::read_to_string(root.join("argv.txt")).expect("the stub ran");
    assert_eq!(
        argv, "--fail-over\n0\ncrates/batten/src/rusty.rs\n",
        "the declared argv, then the owned sources"
    );
}

#[test]
fn a_command_runner_exit_two_is_survived() {
    // THE TOY GATES ARE `sh` SCRIPTS: off unix there is no gate to sweep, and
    // the case compiles everywhere so the other target type-checks it.
    if !cfg!(unix) {
        return;
    }
    let (_, code, out, err) = sweep_command("command-survived", 2);
    assert_eq!(code, 2, "{out}{err}");
    assert!(out.contains("command SURVIVED (exit 2)"), "{out}{err}");
}

/// Exit 1 is a crash's code (an uncaught exception), never a survivor and
/// never every mutant caught.
#[test]
fn a_command_runner_that_errors_cannot_look() {
    // THE TOY GATES ARE `sh` SCRIPTS: off unix there is no gate to sweep, and
    // the case compiles everywhere so the other target type-checks it.
    if !cfg!(unix) {
        return;
    }
    let (_, code, out, err) = sweep_command("command-errored", 1);
    assert_eq!(code, 3, "{out}{err}");
    assert!(
        out.contains("command runner-errored (exit 1)"),
        "{out}{err}"
    );
}

#[test]
fn a_command_entry_without_a_declared_argv_is_refused() {
    // THE TOY GATES ARE `sh` SCRIPTS: off unix there is no gate to sweep, and
    // the case compiles everywhere so the other target type-checks it.
    if !cfg!(unix) {
        return;
    }
    let root = rust_gate_repo("command-undeclared");
    let (code, out, err) = sweep_registered(
        &root,
        "toy,other",
        "HEAD",
        "command=crates/**/*.rs",
        Some("command"),
    );
    assert_eq!(code, 1, "{out}{err}");
    assert!(err.contains("[mutate] command"), "{err}");
}

/// An id no runner carries is a usage error, never an empty registry.
#[test]
fn an_unknown_runner_is_refused() {
    // THE TOY GATES ARE `sh` SCRIPTS: off unix there is no gate to sweep, and
    // the case compiles everywhere so the other target type-checks it.
    if !cfg!(unix) {
        return;
    }
    let root = rust_gate_repo("since-rust-unknown");
    let (code, out, err) = sweep_registered(&root, "toy,other", "HEAD", "mutmut=**/*.py", None);
    assert_eq!(code, 1, "{out}{err}");
    assert!(err.contains("`mutmut`, which is no runner"), "{err}");
}

#[cfg(unix)]
#[test]
fn a_change_touching_no_gate_sweeps_nothing_and_says_so() {
    let root = two_gate_repo("since-none");
    write(&root, "README.md", "unrelated\n");
    let (code, out, err) = sweep_since(&root, "toy,other", "HEAD");
    assert_eq!(code, 0, "{out}{err}");
    assert!(
        out.contains("no enforced gate's source or suite changed since HEAD"),
        "{out}"
    );
}

/// Could-not-look WIDENS: a base that does not resolve sweeps the whole set, so
/// `other`'s survivor is reached and the sweep fails.
#[cfg(unix)]
#[test]
fn an_unresolvable_base_sweeps_every_gate() {
    let root = two_gate_repo("since-nobase");
    let (code, out, err) = sweep_since(&root, "toy,other", "no-such-rev");
    assert!(err.contains("sweeping every enforced gate"), "{err}");
    assert_ne!(code, 0, "{out}{err}");
    assert!(out.contains("other/pipefail-dropped SURVIVED"), "{out}");
}

/// **A DELETED PRESET MODULE TOUCHES ITS GATE** (review of #1099). A preset gate
/// is a directory of modules, and `resolve` reads the tree as it is now, so a
/// module the change deleted is no longer among the gate's sources. Matched on
/// sources alone, deleting `b.rego` touched nothing and the sweep passed without
/// running the gate. `a.rego`'s row survives, so reaching the gate is a failure.
#[cfg(unix)]
#[test]
fn a_deleted_preset_module_sweeps_its_gate() {
    let root = toy_repo("since-preset-delete", &[CAUGHT]);
    let dir = format!("{PRESETS}/demo");
    write(
        &root,
        &format!("{dir}/a.rego"),
        "#MUTANT-SUITE tests/preset.rs\n\
         #MUTANT package-renamed|s/^package batten.demo$/package batten.demo2/|preset_passes_always\n\
         package batten.demo\n",
    );
    write(&root, &format!("{dir}/b.rego"), "package batten.demo\n");
    write(
        &root,
        "tests/preset.rs",
        &format!(
            "{}{}",
            case("preset_passes_always", "assert!(true);"),
            case("preset_other_case", "assert!(true);"),
        ),
    );
    track(&root);
    common::git_in(&root, &["commit", "-m", "base"]);
    fs::remove_file(root.join(format!("{dir}/b.rego"))).expect("delete one module");
    let (code, out, err) = sweep_since(&root, "toy,demo", "HEAD");
    assert_ne!(code, 0, "{out}{err}");
    assert!(out.contains("demo/package-renamed SURVIVED"), "{out}");
}

/// A PRESET A TEST TARGET EMBEDS IS NEVER JUDGED THROUGH THE OVERLAY. The
/// overlay reaches only the readers built to consult it; this case
/// `include_str!`s the module itself, so a mutated copy in the overlay is
/// invisible to it. Fails by: writing the mutation to the overlay and reusing
/// the binaries, which reads a mutation the case would catch as SURVIVED.
#[test]
fn a_preset_a_test_embeds_is_mutated_in_place_and_rebuilt() {
    let root = toy("overlay-embedded");
    write(
        &root,
        "Cargo.toml",
        &format!("{TOY_MANIFEST}\n[features]\noverlay = []\n"),
    );
    write(&root, "src/lib.rs", "");
    write(
        &root,
        &format!("{PRESETS}/demo/a.rego"),
        "#MUTANT-SUITE tests/preset.rs\n\
         #MUTANT limit-moved|s/^limit := 10$/limit := 99/|demo_limit_is_ten\n\
         package batten.demo\n\
         \n\
         limit := 10\n",
    );
    write(
        &root,
        "tests/preset.rs",
        &format!(
            "{}{}",
            case(
                "demo_limit_is_ten",
                &format!(
                    "assert!(include_str!(\"../{PRESETS}/demo/a.rego\").contains(\"\\nlimit := 10\\n\"));"
                ),
            ),
            case("demo_other_case", "assert!(true);"),
        ),
    );
    track(&root);
    let (code, out, err) = run_with(
        &root,
        "sweep",
        "demo",
        &[
            ("MUTANT_OVERLAY_ENV", Path::new("TOY_OVERLAY")),
            ("MUTANT_OVERLAY_FEATURES", Path::new("overlay")),
        ],
    );
    assert_eq!(code, 0, "{out}{err}");
    assert!(out.contains("every one caught"), "{out}{err}");
}

/// A toy preset row whose suite reads its module through the overlay, the way
/// `PresetModuleExt::text` does: the mutated copy at `$TOY_OVERLAY/<looked>`
/// where one reads, leaving the receipt the sweep requires beside it, else the
/// staged module. `looked` is the overlay path the reader consults.
fn overlay_reader_toy(name: &str, looked: &str) -> PathBuf {
    let root = toy(name);
    write(
        &root,
        "Cargo.toml",
        &format!("{TOY_MANIFEST}\n[features]\noverlay = []\n"),
    );
    write(&root, "src/lib.rs", "");
    write(
        &root,
        &format!("{PRESETS}/demo/a.rego"),
        "#MUTANT-SUITE tests/preset.rs\n\
         #MUTANT limit-moved|s/^limit := 10$/limit := 99/|demo_limit_is_ten\n\
         package batten.demo\n\
         \n\
         limit := 10\n",
    );
    let reader = format!(
        "fn module() -> String {{\n\
         \x20   if let Ok(dir) = std::env::var(\"TOY_OVERLAY\") {{\n\
         \x20       let copy = std::path::Path::new(&dir).join({looked:?});\n\
         \x20       if let Ok(text) = std::fs::read_to_string(&copy) {{\n\
         \x20           let mut receipt = copy.into_os_string();\n\
         \x20           receipt.push({read:?});\n\
         \x20           std::fs::write(receipt, \"\").expect(\"leave the receipt\");\n\
         \x20           return text;\n\
         \x20       }}\n\
         \x20   }}\n\
         \x20   std::fs::read_to_string(concat!(env!(\"CARGO_MANIFEST_DIR\"), \"/{PRESETS}/demo/a.rego\"))\n\
         \x20       .expect(\"the staged module\")\n\
         }}\n",
        read = batten::preset::OVERLAY_READ,
    );
    write(
        &root,
        "tests/preset.rs",
        &format!(
            "{reader}{}{}",
            case(
                "demo_limit_is_ten",
                "assert!(module().contains(\"\\nlimit := 10\\n\"));"
            ),
            case("demo_other_case", "assert!(true);"),
        ),
    );
    track(&root);
    root
}

/// A toy crate that EMBEDS a library module outside the presets
/// (`lib/r.rego`), read the way `policy::library_text` reads it: under the
/// `overlay` feature the mutated copy at `$TOY_OVERLAY/lib/r.rego`, receipted,
/// else the `include_str!`'d text. `rows` rows all name one case, which counts
/// its runs into `$TOY_RUN_COUNTER`; the build script counts builds into
/// `$TOY_BUILD_COUNTER`.
fn embedded_library_toy(name: &str, rows: usize) -> PathBuf {
    let root = toy(name);
    write(
        &root,
        "Cargo.toml",
        &format!("{TOY_MANIFEST}\n[features]\noverlay = []\n"),
    );
    write(&root, "build.rs", ALWAYS_STALE_BUILD);
    let mut module = String::from("#MUTANT-SUITE tests/library.rs\n");
    for row in 0..rows {
        module.push_str(&format!(
            "#MUTANT limit-moved-{row}|s/^limit := 10$/limit := {}/|library_limit_is_ten\n",
            90 + row
        ));
    }
    module.push_str("package batten.library\n\nlimit := 10\n");
    write(&root, "lib/r.rego", &module);
    write(
        &root,
        "src/lib.rs",
        &format!(
            "pub fn module() -> String {{\n\
             \x20   #[cfg(feature = \"overlay\")]\n\
             \x20   if let Ok(dir) = std::env::var(\"TOY_OVERLAY\") {{\n\
             \x20       let copy = std::path::Path::new(&dir).join(\"lib/r.rego\");\n\
             \x20       if let Ok(text) = std::fs::read_to_string(&copy) {{\n\
             \x20           let mut receipt = copy.into_os_string();\n\
             \x20           receipt.push({read:?});\n\
             \x20           std::fs::write(receipt, \"\").expect(\"leave the receipt\");\n\
             \x20           return text;\n\
             \x20       }}\n\
             \x20   }}\n\
             \x20   include_str!(\"../lib/r.rego\").to_owned()\n\
             }}\n",
            read = batten::preset::OVERLAY_READ,
        ),
    );
    let count = "if let Some(path) = std::env::var_os(\"TOY_RUN_COUNTER\") {\n\
         \x20       use std::io::Write as _;\n\
         \x20       let mut counter = std::fs::OpenOptions::new().create(true).append(true)\n\
         \x20           .open(path).expect(\"open the counter\");\n\
         \x20       writeln!(counter, \"ran\").expect(\"count the run\");\n\
         \x20   }\n\
         \x20   assert!(toy::module().contains(\"\\nlimit := 10\\n\"));";
    write(
        &root,
        "tests/library.rs",
        &format!(
            "{}{}",
            case("library_limit_is_ten", count),
            case("library_other_case", "assert!(true);"),
        ),
    );
    track(&root);
    root
}

/// A SWEEP OF N ROWS OVER AN EMBEDDED LIBRARY BUILDS AT MOST TWICE AND RUNS
/// EACH CASE'S UNMUTATED CONTROL ONCE (CLOUD-2253). The library is a build
/// input, so before the overlay reached it every row rebuilt the crate twice
/// (its mutant, then the clean binaries the next row reuses), and every row
/// re-ran the same unmutated control: on #1276's 54 library rows, 108 rebuilds
/// and 108 suite runs. Declared as an overlay root, the one build reads each
/// row's mutated copy, and the control is keyed by case and unmutated tree.
///
/// Fails by: the library row rebuilt per row, a control re-run per row, or
/// any row judged on the unmutated module (`every one caught` lost).
#[test]
fn an_embedded_library_sweep_builds_once_and_runs_each_control_once() {
    const ROWS: usize = 3;
    let root = embedded_library_toy("library-overlay", ROWS);
    let counters = common::scratch("mutate-library-overlay-counters");
    let (builds, runs) = (counters.join("builds"), counters.join("runs"));
    let (code, out, err) = run_with(
        &root,
        "sweep",
        "lib/r.rego",
        &[
            ("MUTANT_OVERLAY_ENV", Path::new("TOY_OVERLAY")),
            ("MUTANT_OVERLAY_FEATURES", Path::new("overlay")),
            ("MUTANT_OVERLAY_ROOTS", Path::new("lib")),
            ("TOY_BUILD_COUNTER", &builds),
            ("TOY_RUN_COUNTER", &runs),
        ],
    );
    assert_eq!(code, 0, "{out}{err}");
    assert!(out.contains("every one caught"), "{out}{err}");
    let count = |path: &Path| fs::read_to_string(path).unwrap_or_default().lines().count();
    assert!(
        count(&builds) <= 2,
        "{} builds for {ROWS} embedded rows\n{err}",
        count(&builds)
    );
    assert_eq!(
        count(&runs),
        1 + ROWS,
        "one control, then one mutant per row\n{err}"
    );
}

/// The sweep of [`overlay_reader_toy`]'s one row, with the overlay declared.
fn overlay_sweep(root: &Path) -> (i32, String, String) {
    run_with(
        root,
        "sweep",
        "demo",
        &[
            ("MUTANT_OVERLAY_ENV", Path::new("TOY_OVERLAY")),
            ("MUTANT_OVERLAY_FEATURES", Path::new("overlay")),
        ],
    )
}

/// A SUITE THAT READ THE MUTATED COPY IS JUDGED AS IT ALWAYS WAS (CLOUD-2839).
/// The reader found the copy and left its receipt, so the red run is a catch.
/// Fails by: requiring a receipt the protocol does not name, which would read
/// every overlay row as unjudged.
#[test]
fn a_suite_that_read_the_overlay_copy_is_judged() {
    let root = overlay_reader_toy("overlay-read", "demo/a.rego");
    let (code, out, err) = overlay_sweep(&root);
    assert_eq!(code, 0, "{out}{err}");
    assert!(out.contains("every one caught"), "{out}{err}");
}

/// A SUITE THAT NEVER READ THE MUTATED COPY JUDGED UNMUTATED CODE, SO ITS GREEN
/// RUN IS NO SURVIVOR (CLOUD-2839). With the variable set and the copy absent
/// where the reader looks, the reader falls back to the embedded module, as
/// `PresetModuleExt::text` once did in silence. That is could-not-look, exit 3,
/// never a coverage gap. Fails by: reading the green run as `SURVIVED`, the
/// verdict CLOUD-2836's one-off survivor carried.
#[test]
fn a_suite_that_never_read_the_overlay_copy_is_unjudged() {
    let root = overlay_reader_toy("overlay-unread", "demo/absent.rego");
    let (code, out, err) = overlay_sweep(&root);
    assert_eq!(code, 3, "{out}{err}");
    assert!(
        out.contains("demo/limit-moved overlay-unread"),
        "{out}{err}"
    );
    assert!(!out.contains("SURVIVED"), "{out}{err}");
}

#[cfg(unix)]
#[test]
fn anti_vacuity_a_case_that_is_red_before_the_mutation_is_not_evidence() {
    let root = toy("already-red");
    let mut gate = String::from(TOY_GATE);
    gate.push_str(CAUGHT);
    gate.push('\n');
    write_program(&root, "mise-tasks/toy.sh", &gate);
    write(
        &root,
        "tests/toy.rs",
        &format!(
            "{}{}{}",
            runs("toy.sh"),
            case(
                "over_the_limit_is_refused",
                "assert_eq!(gate(\"99\"), Some(99));"
            ),
            case(
                "under_the_limit_passes",
                "assert_eq!(gate(\"1\"), Some(0));"
            ),
        ),
    );
    cargo_package(&root);
    track(&root);
    let (code, out, _) = sweep(&root, "toy");
    assert_eq!(code, 3, "{out}");
    assert!(out.contains("case-already-red"), "{out}");
    assert!(!out.contains("every one caught"), "{out}");
}

// ---------------------------------------------------------------------------
// The declared suite, which is the whole of CLOUD-1267.
// ---------------------------------------------------------------------------

/// A single-package repository whose gate is a policy module and whose suite is
/// a compiled-binary tier that reads it.
///
/// No dependencies, so the compile is seconds and the target directory is its
/// own — which is also what proves the sweep runs `cargo` inside the STAGED
/// tree: a run against the source tree would read the unmutated module.
fn rust_tier_repo(name: &str, limit_in_tier: &str) -> PathBuf {
    let root = toy(name);
    cargo_package(&root);
    write(
        &root,
        "policy/toy.rego",
        "#MUTANT-SUITE tests/tier.rs\n#MUTANT limit-moved|s@^limit := 10$@limit := 999@|the_limit_is_ten\nlimit := 10\n",
    );
    write(
        &root,
        "tests/tier.rs",
        // THE DECLARATION LINES ARE STRIPPED BEFORE THE ASSERT, and that is the
        // fixture's own version of a real tier's behaviour rather than a
        // convenience: a `#MUTANT` row carries its own sed script, so its text
        // contains the very bytes the mutation removes elsewhere — and a tier
        // that read the whole file would stay green over a mutated module for
        // the same reason `self-mutating-row` exists.
        &format!(
            "#[test]\nfn the_limit_is_ten() {{\n    let text = \
             std::fs::read_to_string(std::path::Path::new(env!(\"CARGO_MANIFEST_DIR\"\
             )).join(\"policy/toy.rego\")).unwrap();\n    let live: String = \
             text.lines().filter(|line| \
             !line.starts_with(\"#MUTANT\")).collect::<Vec<_>>().join(\"\\n\");\n    \
             assert!(live.contains(\"{limit_in_tier}\"), \"{{live}}\");\n}}\n\n#[test]\nfn \
             a_second_case_keeps_the_filter_honest() {{\n    assert!(!\"\".is_empty() || \
             true);\n}}\n"
        ),
    );
    track(&root);
    root
}

#[test]
fn a_declared_rust_suite_is_reddened_by_a_mutation_on_the_module() {
    // CLOUD-1267 IN ONE ASSERTION. The predecessor resolved this gate's suite as
    // `tests/toy.bats`, found none, and answered `no-suite` — so the module was
    // exempt and 141 compiled-binary tiers were unreachable. The declared
    // mapping is what makes the mutation reach a case that can turn red.
    let root = rust_tier_repo("rust-tier", "limit := 10");
    let (code, out, err) = sweep(&root, "toy");
    assert_eq!(code, 0, "{out}{err}");
    assert!(out.contains("every one caught"), "{out}");
}

/// NO NEXTEST SETTING THE SWEEP DID NOT CHOOSE DECIDES A VERDICT (CLOUD-2466
/// item 9). The toy declares the profile the caller names, `ci`, with every
/// setting that used to reach a verdict, and a setup script its case needs; the
/// caller also exports `NEXTEST_RETRIES` and `NEXTEST_STATUS_LEVEL`. The case
/// fails under the mutation on its FIRST attempt only, so a retry would pass it:
/// it leaves a marker keyed by `NEXTEST_RUN_ID`, which every attempt of one run
/// shares (cargo-nextest 0.9.104 sets no attempt number).
///
/// Fails by: `--retries=0` dropped (retries pass the flaky catch: SURVIVED),
/// `--ignore-default-filter` dropped (the default filter empties `-E`:
/// `names-no-case`), `--status-level=pass` dropped (no PASS line is printed:
/// `names-no-case`), or the declared profile not kept (its setup script never
/// runs: `case-already-red`). The exported variables are overridden by those
/// flags too, so the scrub itself is `scrubbed`'s unit case, not this one.
#[test]
fn a_declared_profile_keeps_its_setup_scripts_and_none_of_its_verdict_settings() {
    let root = rust_tier_repo("rust-tier-ci-profile", "limit := 10");
    write(
        &root,
        "tests/tier.rs",
        "#[test]\nfn the_limit_is_ten() {\n    assert_eq!(std::env::var(\"TOY_READY\").as_deref(), \
         Ok(\"1\"), \"the ci profile's setup script ran\");\n    let text = \
         std::fs::read_to_string(std::path::Path::new(env!(\"CARGO_MANIFEST_DIR\")).join(\"\
         policy/toy.rego\")).unwrap();\n    let live = text.lines().any(|line| line == \"limit := \
         10\");\n    let run = std::env::var(\"NEXTEST_RUN_ID\").unwrap_or_default();\n    let \
         marker = std::env::temp_dir().join(format!(\"toy-attempt-{run}\"));\n    let retried = \
         !run.is_empty() && marker.exists();\n    let _ = std::fs::write(&marker, \"\");\n    \
         assert!(live || retried, \"{text}\");\n}\n\n#[test]\nfn \
         a_second_case_keeps_the_filter_honest() {}\n",
    );
    write(
        &root,
        ".config/nextest.toml",
        "experimental = [\"setup-scripts\"]\n\n[scripts.setup.ready]\ncommand = \"sh -c 'echo \
         TOY_READY=1 >> \\\"$NEXTEST_ENV\\\"'\"\n\n[profile.ci]\nretries = 3\ndefault-filter = \
         \"not test(the_limit_is_ten)\"\nstatus-level = \"fail\"\n\n[[profile.ci.scripts]]\nfilter \
         = \"all()\"\nsetup = \"ready\"\n",
    );
    track(&root);
    let answer = common::batten()
        .args(["mutate", "sweep"])
        .current_dir(&root)
        .env("MUTANT_GATES", "toy")
        .env("MUTANT_TASKS", "mise.toml")
        .env("NEXTEST_PROFILE", "ci")
        .env("NEXTEST_RETRIES", "3")
        .env("NEXTEST_STATUS_LEVEL", "none")
        .streamed_output()
        .expect("run batten mutate");
    let (out, err) = (stdout(&answer), stderr(&answer));
    assert_eq!(answer.status.code(), Some(0), "{out}{err}");
    assert!(out.contains("every one caught"), "{out}{err}");
}

/// A consumer without cargo-nextest reads ONE `runner-absent` (CLOUD-2466 item
/// 4), never `suite-did-not-run` on every declared Cargo row. `PATH` holds only
/// the directory of the `cargo` running this suite, which carries no nextest,
/// and `CARGO_HOME` is empty, since cargo also finds subcommands in its `bin`.
/// Fails by: the probe dropped, so each row runs and reads `suite-did-not-run`.
#[test]
fn a_declared_cargo_row_without_nextest_reads_one_runner_absent() {
    let root = rust_tier_repo("rust-tier-no-nextest", "limit := 10");
    let cargo = PathBuf::from(env!("CARGO"));
    let only_cargo = cargo.parent().expect("cargo lives in a directory");
    assert!(
        !only_cargo.join("cargo-nextest").exists(),
        "this case needs a cargo directory without nextest"
    );
    let answer = common::batten()
        .args(["mutate", "sweep"])
        .current_dir(&root)
        .env("PATH", only_cargo)
        .env(
            "CARGO_HOME",
            common::scratch("mutate-no-nextest-cargo-home"),
        )
        .env("MUTANT_GATES", "toy")
        .env("MUTANT_TASKS", "mise.toml")
        .streamed_output()
        .expect("run batten mutate");
    let (out, err) = (stdout(&answer), stderr(&answer));
    assert_eq!(answer.status.code(), Some(3), "{out}{err}");
    assert_eq!(
        out.matches("cargo-nextest runner-absent").count(),
        1,
        "{out}{err}"
    );
    assert!(!out.contains("suite-did-not-run"), "{out}{err}");
}

#[test]
fn a_module_whose_tier_cannot_see_it_reports_a_survivor() {
    // THE DISCRIMINATING MIRROR, and without it the case above is satisfied by a
    // runner that answers `caught` unconditionally. This tier asserts something
    // the mutation cannot move, which is exactly the shape of a dead predicate:
    // the mutation runs, the tier stays green, and the row SURVIVES.
    let root = rust_tier_repo("rust-tier-dead", "limit");
    let (code, out, _) = sweep(&root, "toy");
    assert_eq!(code, 2, "{out}");
    assert!(out.contains("SURVIVED"), "{out}");
}

#[test]
fn an_owner_is_echoed_on_a_survivor_and_clears_nothing() {
    // `#MUTANT-OWNER` exists so a predicate already known to be dead is reported
    // with the row that owns it. It must not become an exemption: the finding
    // stands and the exit code is unmoved.
    let root = rust_tier_repo("owner", "limit");
    let module = fs::read_to_string(root.join("policy/toy.rego")).unwrap();
    write(
        &root,
        "policy/toy.rego",
        &format!("#MUTANT-OWNER CLOUD-1265|nothing writes the record this reads\n{module}"),
    );
    track(&root);
    let (code, out, _) = sweep(&root, "toy");
    assert_eq!(code, 2, "{out}");
    assert!(out.contains("SURVIVED"), "{out}");
    assert!(out.contains("CLOUD-1265"), "{out}");
}

// ---------------------------------------------------------------------------
// The native harnesses (CLOUD-2160).
// ---------------------------------------------------------------------------

/// One native harness's fixture: the program the arm runs, the subject a row
/// mutates, the declared suite, and the case the recorded output names.
#[cfg(unix)]
struct Native {
    /// The stub's program name.
    arm: &'static str,
    /// The recorded fixture directory under `tests/fixtures/mutate`.
    fixtures: &'static str,
    /// The subject, repo-relative — also the gate's name (the file arm).
    subject: &'static str,
    /// What the subject holds above its sentinel lines.
    body: &'static str,
    /// The declared suite, repo-relative.
    suite: &'static str,
    /// What the suite holds. Only conftest's and pytest's are read: conftest's
    /// for whether the case is defined, pytest's for how many cases it has.
    suite_body: &'static str,
    /// The case, as the recorded output names it.
    want: &'static str,
}

#[cfg(unix)]
const TOFU: Native = Native {
    arm: "tofu",
    fixtures: "tofu",
    subject: "main.tf",
    body: "locals {\n  limit = 10\n}\n",
    suite: "main.tftest.hcl",
    suite_body: "run \"limit_is_ten\" {\n  command = plan\n}\n",
    want: "limit_is_ten",
};

#[cfg(unix)]
const KYVERNO: Native = Native {
    arm: "kyverno",
    fixtures: "kyverno",
    subject: "policies/policy.yaml",
    body: "apiVersion: kyverno.io/v1\nkind: ClusterPolicy\n",
    suite: "policies/kyverno-test.yaml",
    suite_body: "apiVersion: cli.kyverno.io/v1alpha1\nkind: Test\n",
    want: "policy=require-team,rule=check-team,resource=labelled",
};

#[cfg(unix)]
const CONFTEST: Native = Native {
    arm: "conftest",
    fixtures: "conftest",
    subject: "checks/limit.rego",
    body: "package main\n\nlimit := 10\n",
    suite: "checks/limit_test.rego",
    suite_body: "package main\n\ntest_limit_is_ten if {\n\tlimit == 10\n}\n\ntest_small_input_passes if {\n\tcount(deny) == 0\n}\n",
    want: "test_limit_is_ten",
};

#[cfg(unix)]
const PYTEST: Native = Native {
    arm: "pytest",
    fixtures: "pytest",
    subject: "limit.py",
    body: "LIMIT = 10\n",
    suite: "test_limit.py",
    suite_body: "from limit import LIMIT\n\n\ndef test_limit_is_ten():\n    assert LIMIT == 10\n\n\ndef test_name_is_set():\n    assert True\n",
    want: "test_limit_is_ten",
};

/// What a row does to the subject's sentinel, and so which recording the stub
/// replays.
#[cfg(unix)]
#[derive(Clone, Copy)]
enum Mutant {
    /// The sentinel becomes `KILL`: the stub replays the recorded failure.
    Kill,
    /// An unread line changes: the stub replays the recorded pass.
    Unread,
    /// The sentinel becomes `BREAK`: the stub replays the recorded errored run.
    Break,
}

/// The stub standing in for one harness. It replays the recorded output the
/// staged subject's sentinel selects, minus the version line; for pytest the
/// report is the `--junitxml` file rather than the stream.
#[cfg(unix)]
fn native_stub(native: &Native) -> String {
    let fixtures = common::at_root("crates/batten/tests/fixtures/mutate").join(native.fixtures);
    format!(
        "#!/bin/sh\n\
         state=pass\n\
         if grep -q '^# KILL$' '{subject}'; then state=fail; fi\n\
         if grep -q '^# BREAK$' '{subject}'; then state=error; fi\n\
         report=''\n\
         for arg in \"$@\"; do\n\
         \x20 case $arg in --junitxml=*) report=${{arg#--junitxml=}} ;; esac\n\
         done\n\
         if [ -n \"$report\" ]; then\n\
         \x20 tail -n +2 '{fixtures}'/\"$state\" > \"$report\"\n\
         else\n\
         \x20 tail -n +2 '{fixtures}'/\"$state\"\n\
         fi\n\
         [ \"$state\" = pass ]\n",
        subject = native.subject,
        fixtures = fixtures.display(),
    )
}

/// A repository whose gate is `native`'s subject, declaring one row, with the
/// harness stub in an untracked `bin/` of its own. Returns the root and that
/// directory.
///
/// **THE STUB IS PER CASE, NEVER SHARED.** The cases run in parallel, and
/// rewriting an executable another case is running fails with `ETXTBSY`.
#[cfg(unix)]
fn native_repo(native: &Native, mutant: Mutant, case: &str) -> (PathBuf, PathBuf) {
    let root = toy(&format!("native-{}-{case}", native.arm));
    let row = match mutant {
        Mutant::Kill => format!("#MUTANT kill|s@^# sentinel$@# KILL@|{}", native.want),
        Mutant::Unread => format!("#MUTANT unread|s@^# unread$@# moved@|{}", native.want),
        Mutant::Break => format!("#MUTANT break|s@^# sentinel$@# BREAK@|{}", native.want),
    };
    write(
        &root,
        native.subject,
        &format!(
            "#MUTANT-SUITE {}\n{row}\n{}# sentinel\n# unread\n",
            native.suite, native.body
        ),
    );
    write(&root, native.suite, native.suite_body);
    track(&root);
    let bin = root.join(".stub-bin");
    write_program(&bin, native.arm, &native_stub(native));
    (root, bin)
}

/// Sweep `root` with the stubs in `bin` ahead of the ambient `PATH`.
#[cfg(unix)]
fn sweep_with(root: &Path, gate: &str, bin: &Path) -> (i32, String, String) {
    let mut entries = vec![bin.as_os_str().to_owned()];
    entries.extend(std::env::split_paths(&common::ambient_path()).map(PathBuf::into_os_string));
    let answer = common::batten()
        .args(["mutate", "sweep"])
        .current_dir(root)
        .env("MUTANT_GATES", gate)
        .env("MUTANT_TASKS", "mise.toml")
        .env(
            "PATH",
            std::env::join_paths(entries).expect("join the stub onto PATH"),
        )
        .streamed_output()
        .expect("run batten mutate");
    (
        answer.status.code().unwrap_or(-1),
        stdout(&answer),
        stderr(&answer),
    )
}

/// The verdict one arm's sweep gives one mutant.
#[cfg(unix)]
fn native_sweep(native: &Native, mutant: Mutant, case: &str) -> (i32, String, String) {
    let (root, bin) = native_repo(native, mutant, case);
    sweep_with(&root, native.subject, &bin)
}

#[cfg(unix)]
fn assert_caught(native: &Native) {
    let (code, out, err) = native_sweep(native, Mutant::Kill, "caught");
    assert_eq!(code, 0, "{}: {out}{err}", native.arm);
    assert!(out.contains("every one caught"), "{}: {out}", native.arm);
}

#[cfg(unix)]
fn assert_survives(native: &Native) {
    let (code, out, err) = native_sweep(native, Mutant::Unread, "survives");
    assert_eq!(code, 2, "{}: {out}{err}", native.arm);
    assert!(out.contains("SURVIVED"), "{}: {out}", native.arm);
}

/// The errored run is a could-not-look, and the one reading it must never get
/// is `caught`: the run exits non-zero exactly as a failing case does.
#[cfg(unix)]
fn assert_errored(native: &Native) {
    let (code, out, err) = native_sweep(native, Mutant::Break, "errored");
    assert_eq!(code, 3, "{}: {out}{err}", native.arm);
    assert!(out.contains("case-errored"), "{}: {out}", native.arm);
    assert!(!out.contains("every one caught"), "{}: {out}", native.arm);
}

#[cfg(unix)]
#[test]
fn a_tofu_mutant_its_run_fails_on_is_caught() {
    assert_caught(&TOFU);
}

#[cfg(unix)]
#[test]
fn a_tofu_mutant_its_run_cannot_see_survives() {
    assert_survives(&TOFU);
}

#[cfg(unix)]
#[test]
fn an_errored_tofu_run_is_could_not_look() {
    assert_errored(&TOFU);
}

/// THE STAGED TREE IS INITIALISED BEFORE `tofu test` (CLOUD-2190). It carries
/// tracked files only and `.terraform/` never is, so a module calling a module
/// errored `Module not installed` on every row. The stub models exactly that:
/// `init -backend=false` makes `.terraform/` in its working directory, and
/// `test` replays the recorded error unless one is there — so an init in the
/// wrong directory, or with a backend, still reads as could-not-look.
#[cfg(unix)]
#[test]
fn a_tofu_suite_is_initialised_before_it_runs() {
    const NESTED: Native = Native {
        subject: "infra/main.tf",
        suite: "infra/tests/main.tftest.hcl",
        ..TOFU
    };
    let (root, bin) = native_repo(&NESTED, Mutant::Kill, "initialised");
    let stub = native_stub(&NESTED).replacen(
        "state=pass\n",
        "case \"$1\" in init) [ \"$2\" = -backend=false ] && mkdir -p .terraform; exit 0 ;; esac\n\
         state=pass\n\
         if [ ! -d .terraform ]; then tail -n +2 \"$(dirname \"$0\")/error\"; exit 1; fi\n",
        1,
    )
    // The stub runs in the module's root, where the subject is `main.tf`.
    .replace("'infra/main.tf'", "'main.tf'");
    write_program(&bin, NESTED.arm, &stub);
    let fixtures = common::at_root("crates/batten/tests/fixtures/mutate/tofu");
    fs::copy(fixtures.join("error"), bin.join("error")).expect("stage the recorded error");
    let (code, out, err) = sweep_with(&root, NESTED.subject, &bin);
    assert_eq!(code, 0, "{out}{err}");
    assert!(out.contains("every one caught"), "{out}");
}

#[cfg(unix)]
#[test]
fn a_kyverno_mutant_its_test_case_fails_on_is_caught() {
    assert_caught(&KYVERNO);
}

#[cfg(unix)]
#[test]
fn a_kyverno_mutant_its_test_case_cannot_see_survives() {
    assert_survives(&KYVERNO);
}

#[cfg(unix)]
#[test]
fn an_errored_kyverno_run_is_could_not_look() {
    assert_errored(&KYVERNO);
}

/// A `GeneratingPolicy` case, which `kyverno test -t` selects by its trigger
/// (the Namespace) and reports by each object it generated (CLOUD-2252). The
/// recordings are kyverno 1.19.1 over one policy generating three objects: all
/// three pass, and, under a real mutation, one of the three failing.
#[cfg(unix)]
const KYVERNO_GENERATE: Native = Native {
    fixtures: "kyverno-generate",
    subject: "policies/policy.yaml",
    body: "apiVersion: policies.kyverno.io/v1\nkind: GeneratingPolicy\n",
    want: "policy=add-tenant-quota,rule=add-tenant-quota,resource=tenant-small",
    ..KYVERNO
};

/// A sweep over [`KYVERNO_GENERATE`], under the name the two cases below have
/// always called, so their bodies stay what they were.
#[cfg(unix)]
fn generate_sweep(mutant: Mutant, name: &str) -> (i32, String, String) {
    native_sweep(&KYVERNO_GENERATE, mutant, name)
}

/// ONE GENERATED OBJECT WRONG IS THE CASE FAILING. Before CLOUD-2252 no selector
/// named a generating case at all (`names-no-case`); a reading that took any one
/// passing object as the case's verdict would call this mutant survived, since
/// two of its three objects still pass.
#[cfg(unix)]
#[test]
fn a_generating_kyverno_case_fails_when_any_object_it_generates_does() {
    let (code, out, err) = generate_sweep(Mutant::Kill, "generate-caught");
    assert_eq!(code, 0, "{out}{err}");
    assert!(out.contains("every one caught"), "{out}");
}

/// The generating case is SELECTED: a mutation its objects cannot see survives,
/// rather than reading `names-no-case`.
#[cfg(unix)]
#[test]
fn a_generating_kyverno_case_is_selected_by_its_trigger() {
    let (code, out, err) = generate_sweep(Mutant::Unread, "generate-survives");
    assert_eq!(code, 2, "{out}{err}");
    assert!(out.contains("SURVIVED"), "{out}");
    assert!(!out.contains("names-no-case"), "{out}");
}

/// THE VERDICT IS A FUNCTION OF THE SET, NOT ITS ORDER (CLOUD-2264). The
/// recording is `[pass, fail, skip]`; the ladder this replaced fell back to the
/// first verdict and read it pass, so this mutant was SURVIVED.
#[cfg(unix)]
#[test]
fn a_case_verdict_is_independent_of_order() {
    const MIXED: Native = Native {
        fixtures: "kyverno-mixed",
        ..KYVERNO_GENERATE
    };
    // And a case whose objects only pass or are skipped has no verdict: it is
    // not selected, rather than read as a pass.
    const SKIPPED: Native = Native {
        fixtures: "kyverno-skip",
        ..KYVERNO_GENERATE
    };
    let (code, out, err) = native_sweep(&MIXED, Mutant::Kill, "mixed-order");
    assert_eq!(code, 0, "{out}{err}");
    assert!(out.contains("every one caught"), "{out}");

    let (code, out, err) = native_sweep(&SKIPPED, Mutant::Kill, "skip-only");
    assert_eq!(code, 3, "{out}{err}");
    assert!(out.contains("names-no-case"), "{out}");
}

/// A GENERATED OBJECT SHARING ITS TRIGGER'S NAME DOES NOT SHADOW ITS SIBLINGS
/// (CLOUD-2264). The recording has `/tenant-small` passing and `/tenant-quota`
/// failing, selected by `resource=tenant-small`; the exact-name filter this
/// replaced judged only the first and called the mutant SURVIVED.
#[cfg(unix)]
#[test]
fn a_generated_object_named_like_its_trigger_shadows_nothing() {
    const COLLIDE: Native = Native {
        fixtures: "kyverno-collide",
        ..KYVERNO_GENERATE
    };
    let (code, out, err) = native_sweep(&COLLIDE, Mutant::Kill, "collide");
    assert_eq!(code, 0, "{out}{err}");
    assert!(out.contains("every one caught"), "{out}");
}

/// A VALIDATING SELECTOR THAT NAMES NO RESULT NAMES NO CASE (CLOUD-2264). The
/// recording's only result is `v1/Pod/default/labelled`; a typo'd resource used
/// to fall back to every result for the policy and rule and read caught.
#[cfg(unix)]
#[test]
fn a_typod_kyverno_selector_names_no_case() {
    const TYPO: Native = Native {
        want: "policy=require-team,rule=check-team,resource=labeled",
        ..KYVERNO
    };
    let (code, out, err) = native_sweep(&TYPO, Mutant::Kill, "typo");
    assert_eq!(code, 3, "{out}{err}");
    assert!(out.contains("names-no-case"), "{out}");
}

/// EACH TRIGGER'S CASE IS ITS OWN (CLOUD-2264), recorded from a consumer's
/// add-tenant-quota suite with two Namespace triggers and `tenant-medium`'s
/// expectation broken: selecting `tenant-medium` reports its failure, and
/// selecting `tenant-small` (the `pass` recording) reports only its own three
/// passing objects, so `-t` already narrows a generating case to its trigger.
#[cfg(unix)]
#[test]
fn each_generating_trigger_is_judged_on_its_own_objects() {
    const MEDIUM: Native = Native {
        fixtures: "kyverno-generate-two",
        want: "policy=add-tenant-quota,rule=add-tenant-quota,resource=tenant-medium",
        ..KYVERNO_GENERATE
    };
    const SMALL: Native = Native {
        fixtures: "kyverno-generate-two",
        ..KYVERNO_GENERATE
    };
    let (code, out, err) = native_sweep(&MEDIUM, Mutant::Kill, "two-medium");
    assert_eq!(code, 0, "{out}{err}");
    assert!(out.contains("every one caught"), "{out}");
    let (code, out, err) = native_sweep(&SMALL, Mutant::Unread, "two-small");
    assert_eq!(code, 2, "{out}{err}");
    assert!(out.contains("SURVIVED"), "{out}");
}

#[cfg(unix)]
#[test]
fn a_conftest_mutant_its_rule_fails_on_is_caught() {
    assert_caught(&CONFTEST);
}

#[cfg(unix)]
#[test]
fn a_conftest_mutant_its_rule_cannot_see_survives() {
    assert_survives(&CONFTEST);
}

#[cfg(unix)]
#[test]
fn an_errored_conftest_run_is_could_not_look() {
    assert_errored(&CONFTEST);
}

#[cfg(unix)]
#[test]
fn a_pytest_mutant_its_case_fails_on_is_caught() {
    assert_caught(&PYTEST);
    // A suite of ONE case: its filter selects every case there is, and that
    // is still the case the row names. Fails by: a lone case's filter read as
    // `filter-names-every-case`, which only a suite of two or more can be.
    let alone = Native {
        suite_body: "from limit import LIMIT\n\n\ndef test_limit_is_ten():\n    assert LIMIT == 10\n",
        ..PYTEST
    };
    let (code, out, err) = native_sweep(&alone, Mutant::Kill, "alone");
    assert_eq!(code, 0, "{out}{err}");
    assert!(out.contains("every one caught"), "{out}");
}

#[cfg(unix)]
#[test]
fn a_pytest_mutant_its_case_cannot_see_survives() {
    assert_survives(&PYTEST);
}

#[cfg(unix)]
#[test]
fn an_errored_pytest_run_is_could_not_look() {
    assert_errored(&PYTEST);
}

/// A stub that records it was invoked, for the cases asserting no runner ran.
#[cfg(unix)]
fn tripwire(bin: &Path, program: &str, marker: &Path) {
    write_program(
        bin,
        program,
        &format!("#!/bin/sh\n: > '{}'\nexit 0\n", marker.display()),
    );
}

/// **A declared suite no runner recognizes is reported, and nothing is run for
/// it** (CLOUD-2160). The path exists and is runnable-looking, so the only
/// thing between it and a guessed harness is `Suite::declared`'s refusal.
///
/// Fails by: that refusal answering with any runner arm, which hands the path
/// to a harness that was never declared — here the tripwire `pytest` fires.
#[cfg(unix)]
#[test]
fn an_unrecognized_suite_is_reported_not_run() {
    let root = toy("native-unrecognized");
    write(
        &root,
        "checks/limit.rego",
        "#MUTANT-SUITE checks/limit.sh\n#MUTANT kill|s@^# sentinel$@# KILL@|limit_is_ten\n# sentinel\n",
    );
    write(&root, "checks/limit.sh", "exit 0\n");
    track(&root);
    let bin = root.join(".stub-bin");
    let marker = root.join(".invoked");
    for program in ["pytest", "tofu", "kyverno", "conftest", "cargo"] {
        tripwire(&bin, program, &marker);
    }
    let (code, out, err) = sweep_with(&root, "checks/limit.rego", &bin);
    assert_eq!(code, 3, "{out}{err}");
    assert!(out.contains("no-suite (checks/limit.sh)"), "{out}");
    assert!(
        !marker.exists(),
        "a runner was invoked for an unrecognized suite: {out}"
    );
}

/// The other half: a source declaring no suite at all is `no-suite
/// (undeclared)`, where it used to be handed a default path under a runner this
/// repository no longer carries.
#[cfg(unix)]
#[test]
fn a_source_declaring_no_suite_is_reported_not_run() {
    let root = toy("native-undeclared");
    write(
        &root,
        "checks/limit.rego",
        "#MUTANT kill|s@^# sentinel$@# KILL@|limit_is_ten\n# sentinel\n",
    );
    track(&root);
    let bin = root.join(".stub-bin");
    let marker = root.join(".invoked");
    for program in ["pytest", "tofu", "kyverno", "conftest", "cargo"] {
        tripwire(&bin, program, &marker);
    }
    let (code, out, err) = sweep_with(&root, "checks/limit.rego", &bin);
    assert_eq!(code, 3, "{out}{err}");
    assert!(out.contains("no-suite (undeclared)"), "{out}");
    assert!(
        !marker.exists(),
        "a runner was invoked for an undeclared suite: {out}"
    );
}

/// A harness that is not on `PATH` costs its own row, not the sweep (CLOUD-2160):
/// the row reads `suite-did-not-run` and the sweep still reports.
#[cfg(unix)]
#[test]
fn a_harness_missing_from_path_did_not_run_and_the_sweep_still_reports() {
    let (root, _) = native_repo(&TOFU, Mutant::Kill, "missing");
    let empty = root.join(".empty-bin");
    fs::create_dir_all(&empty).expect("make an empty bin");
    let answer = common::batten()
        .args(["mutate", "sweep"])
        .current_dir(&root)
        .env("MUTANT_GATES", TOFU.subject)
        .env("PATH", &empty)
        .streamed_output()
        .expect("run batten mutate");
    let out = stdout(&answer);
    assert_eq!(answer.status.code(), Some(3), "{out}{}", stderr(&answer));
    assert!(out.contains("suite-did-not-run"), "{out}");
}

// ---------------------------------------------------------------------------
// The census.
// ---------------------------------------------------------------------------

/// A repository carrying named tasks with the descriptions the classifier reads.
fn census_repo(name: &str, tasks: &[(&str, &str)]) -> PathBuf {
    let root = toy(name);
    for (task, description) in tasks {
        write_program(
            &root,
            &format!("mise-tasks/{task}.sh"),
            &format!("#!/usr/bin/env bash\n#MISE description=\"{description}\"\nexit 0\n"),
        );
    }
    track(&root);
    root
}

#[test]
fn a_gate_named_in_the_set_is_a_closed_census() {
    let root = census_repo("census-closed", &[("alpha-check", "Gate: something")]);
    let (code, out, err) = census(&root, "alpha-check");
    assert_eq!(code, 0, "{out}{err}");
    assert!(out.contains("1 gate(s)"), "{out}");
}

#[test]
fn the_defect_a_gate_the_set_omits_is_uncovered_and_named() {
    let root = census_repo(
        "census-uncovered",
        &[
            ("alpha-check", "Gate: something"),
            ("beta-check", "Gate: something else"),
        ],
    );
    let (code, out, _) = census(&root, "alpha-check");
    assert_eq!(code, 2, "{out}");
    assert!(out.contains("mise-tasks/beta-check.sh uncovered"), "{out}");
    assert!(!out.contains("alpha-check.sh uncovered"), "{out}");
}

#[test]
fn a_task_that_does_not_describe_itself_as_a_gate_owes_no_mutation() {
    let root = census_repo(
        "census-not-a-gate",
        &[
            ("alpha-check", "Gate: something"),
            ("measure", "Measure: something"),
            ("effect", "Effect: something"),
        ],
    );
    let (code, out, err) = census(&root, "alpha-check");
    assert_eq!(code, 0, "{out}{err}");
    assert!(out.contains("1 gate(s)"), "{out}");
}

#[test]
fn a_hook_body_is_a_gate_too_because_it_decides_by_emitting_a_deny() {
    let root = census_repo("census-hook", &[("some-guard", "PreToolUse hook body")]);
    let (code, out, _) = census(&root, "");
    // An unset set is could-not-look before anything else is decided.
    assert_eq!(code, 1, "{out}");
    let (code, out, _) = census(&root, "nothing");
    assert_eq!(code, 2, "{out}");
    assert!(out.contains("mise-tasks/some-guard.sh uncovered"), "{out}");
}

#[test]
fn a_policy_module_is_censused_unconditionally_so_a_migration_cannot_shrink_the_set() {
    let root = toy("census-module");
    write(&root, "policy/some-rule.rego", "package batten.some_rule\n");
    track(&root);
    let (code, out, _) = census(&root, "nothing");
    assert_eq!(code, 2, "{out}");
    assert!(out.contains("policy/some-rule.rego uncovered"), "{out}");
}

/// THE PRESET DIRECTORY IS THE CONSUMER'S (CLOUD-2711): a preset outside the one
/// `MUTANT_PRESETS` declares is no subject at all. Fails by: the crate naming its
/// own preset directory again, which censused this repository's layout in
/// every consumer.
#[test]
fn a_preset_outside_the_declared_directory_is_no_subject() {
    let root = toy("census-preset-elsewhere");
    write(
        &root,
        &format!("{PRESETS}/some-preset/rule.rego"),
        "package batten.some_preset\n",
    );
    track(&root);
    let answer = common::batten()
        .args(["mutate", "census"])
        .current_dir(&root)
        .env("MUTANT_GATES", "nothing")
        .env("MUTANT_TASKS", "mise.toml")
        .env("MUTANT_PRESETS", "presets")
        .streamed_output()
        .expect("run batten mutate");
    let out = stdout(&answer);
    assert!(!out.contains("some-preset"), "{out}");
}

#[test]
fn a_preset_is_censused_too_so_the_one_class_a_pattern_row_cannot_reach_is_visible() {
    // CLOUD-1267's widening, and it is the census half of the same hole: a
    // preset ships to every consumer, and a runner blind to that directory is
    // blind to CLOUD-934's dead-predicate class.
    let root = toy("census-preset");
    write(
        &root,
        &format!("{PRESETS}/some-preset/rule.rego"),
        "package batten.some_preset\n",
    );
    track(&root);
    let (code, out, _) = census(&root, "nothing");
    assert_eq!(code, 2, "{out}");
    assert!(out.contains("some-preset uncovered"), "{out}");
}

/// Fails by: a row whose script changes nothing in its file read as coverage
/// until a sweep happens to reach it (CLOUD-2250: three such rows on `main`,
/// ten more re-anchored by hand on #1132, each after rustfmt or a refactor
/// moved the line out from under it). The live row beside it stays silent.
#[test]
fn a_row_whose_script_changes_nothing_is_refused_by_the_census() {
    let root = toy("census-inert");
    write(
        &root,
        "policy/some-rule.rego",
        "package batten.some_rule\n\
         #MUTANT dead|s@^deny if input.gone$@deny if false@|test_x\n\
         #MUTANT live|s@^deny if input.bad$@deny if false@|test_x\n\
         #MUTANT selfie|s@input.vanished@false@|test_x\n\
         deny if input.bad\n",
    );
    track(&root);
    let (code, out, _) = census(&root, "some-rule");
    assert_eq!(code, 2, "{out}");
    assert!(
        out.contains("policy/some-rule.rego:2 dead inert-mutation"),
        "{out}"
    );
    // Unanchored, its pattern matches only its own row: still inert.
    assert!(
        out.contains("policy/some-rule.rego:4 selfie inert-mutation"),
        "{out}"
    );
    assert!(
        !out.contains(" live "),
        "the applying row is not named: {out}"
    );
}

/// Fails by: a row that can never apply read as coverage until a sweep spends a
/// build reaching it. Both shapes were measured by the full declared sweep: a
/// literal `|` splitting a row into four fields, and a sed address block the
/// in-process runner does not apply (CLOUD-2255).
#[test]
fn a_row_that_cannot_apply_is_refused_by_the_census() {
    let root = toy("census-unapplied");
    write(
        &root,
        "policy/some-rule.rego",
        "package batten.some_rule\n\
         #MUTANT split|s@a | b@c@|test_x\n\
         #MUTANT addressed|/^deny/{n;s@x@y@}|test_x\n\
         #MUTANT glued|s@^deny@allow@|test_x#MUTANT-SUITE tests/x.rs\n\
         deny if input.bad\n",
    );
    track(&root);
    let (code, out, _) = census(&root, "some-rule");
    assert_eq!(code, 2, "{out}");
    // CLOUD-2586: a row whose case swallowed the next line's directive is
    // three fields and applies, and is still refused, by its line.
    assert!(
        out.contains("policy/some-rule.rego:4 glued malformed-row"),
        "{out}"
    );
    assert!(
        out.contains("policy/some-rule.rego:2 split malformed-row"),
        "{out}"
    );
    assert!(
        out.contains("policy/some-rule.rego:3 addressed unappliable-mutation"),
        "{out}"
    );
}

#[test]
fn a_filed_exemption_is_a_closed_census_not_a_gap() {
    let root = toy("census-exempt");
    write_program(
        &root,
        "mise-tasks/alpha-check.sh",
        "#!/usr/bin/env bash\n#MISE description=\"Gate: something\"\n#MUTANT-EXEMPT CLOUD-931|its \
         suite runs no arm that can go red\nexit 0\n",
    );
    write_program(
        &root,
        "mise-tasks/beta-check.sh",
        "#!/usr/bin/env bash\n#MISE description=\"Gate: something else\"\nexit 0\n",
    );
    track(&root);
    let (code, out, err) = census(&root, "beta-check");
    assert_eq!(code, 0, "{out}{err}");
    assert!(out.contains("2 gate(s)"), "{out}");
}

#[test]
fn an_exemption_naming_no_issue_is_unfiled_which_is_the_whole_difference_from_a_todo() {
    let root = toy("census-unfiled-key");
    write_program(
        &root,
        "mise-tasks/alpha-check.sh",
        "#!/usr/bin/env bash\n#MISE description=\"Gate: something\"\n#MUTANT-EXEMPT later|a \
         reason\nexit 0\n",
    );
    track(&root);
    let (code, out, _) = census(&root, "nothing");
    assert_eq!(code, 2, "{out}");
    assert!(
        out.contains("mise-tasks/alpha-check.sh exempt-unfiled"),
        "{out}"
    );
}

#[test]
fn an_exemption_with_no_reason_is_unfiled_as_well() {
    let root = toy("census-unfiled-reason");
    write_program(
        &root,
        "mise-tasks/alpha-check.sh",
        "#!/usr/bin/env bash\n#MISE description=\"Gate: something\"\n#MUTANT-EXEMPT \
         CLOUD-931\nexit 0\n",
    );
    track(&root);
    let (code, out, _) = census(&root, "nothing");
    assert_eq!(code, 2, "{out}");
    assert!(out.contains("exempt-unfiled"), "{out}");
}

/// Fails by: an exemption on a file that still declares rows read as a closed
/// census, so those rows were never swept. Measured on this repository:
/// `policy/connector-not-granted.rego` carried a `write-grant-refused` row under
/// a stale `#MUTANT-EXEMPT`, outside the set, and no sweep ever applied it.
#[test]
fn an_exemption_over_declared_rows_is_refused_because_the_rows_never_run() {
    let root = toy("census-exempt-rows");
    write(
        &root,
        "policy/some-rule.rego",
        "package batten.some_rule\n\
         #MUTANT-EXEMPT CLOUD-931|a reason that went stale\n\
         #MUTANT live|s@^deny if input.bad$@deny if false@|test_x\n\
         deny if input.bad\n",
    );
    track(&root);
    let (code, out, _) = census(&root, "nothing");
    assert_eq!(code, 2, "{out}");
    assert!(
        out.contains("policy/some-rule.rego exempt-with-rows"),
        "{out}"
    );
}

#[test]
fn declared_and_exempt_is_refused_because_the_reason_would_be_a_dead_letter() {
    let root = toy("census-both");
    write_program(
        &root,
        "mise-tasks/alpha-check.sh",
        "#!/usr/bin/env bash\n#MISE description=\"Gate: something\"\n#MUTANT-EXEMPT CLOUD-931|a \
         reason\nexit 0\n",
    );
    track(&root);
    let (code, out, _) = census(&root, "alpha-check");
    assert_eq!(code, 2, "{out}");
    assert!(
        out.contains("mise-tasks/alpha-check.sh declared-and-exempt"),
        "{out}"
    );
}

#[test]
fn the_reverse_direction_a_name_in_the_set_resolving_to_no_gate_is_refused() {
    let root = census_repo("census-ghost", &[("alpha-check", "Gate: something")]);
    let (code, out, _) = census(&root, "alpha-check,ghost-check");
    assert_eq!(code, 2, "{out}");
    assert!(out.contains("ghost-check names-no-subject"), "{out}");
}

#[test]
fn an_unset_set_is_could_not_look_never_a_closed_census() {
    let root = census_repo("census-unset", &[("alpha-check", "Gate: something")]);
    let (code, _, err) = census(&root, "");
    assert_eq!(code, 1, "{err}");
    assert!(err.contains("the enforced set is empty"), "{err}");
    assert!(
        err.contains("[mutate].gates"),
        "the refusal names the table: {err}"
    );
}

#[test]
fn output_is_pointer_only_so_the_exemptions_reason_never_reaches_the_log() {
    let root = toy("census-pointer");
    write_program(
        &root,
        "mise-tasks/alpha-check.sh",
        "#!/usr/bin/env bash\n#MISE description=\"Gate: something\"\n#MUTANT-EXEMPT \
         CLOUD-931|SECRETPROSE\nexit 0\n",
    );
    track(&root);
    let (_, out, err) = census(&root, "alpha-check");
    assert!(!out.contains("SECRETPROSE"), "{out}");
    assert!(!err.contains("SECRETPROSE"), "{err}");
}

// ---------------------------------------------------------------------------
// The committed enforced set (CLOUD-2010).
// ---------------------------------------------------------------------------

/// A consumer with no task runner manifest and no `$MUTANT_GATES`: its enforced
/// set is whatever its `batten.toml` declares, and its gates are `.rego` files
/// in a directory no built-in arm reads.
fn consumer(name: &str, mutate_table: &str) -> PathBuf {
    let root = toy(name);
    write(
        &root,
        "batten.toml",
        &format!("version = 1\n\n{mutate_table}"),
    );
    write(
        &root,
        "checks/limit.rego",
        "#MUTANT-SUITE checks/limit_test.rego\n#MUTANT limit-moved|s/10/999/|test_limit\npackage main\n\nlimit := 10\n",
    );
    write(
        &root,
        "checks/limit_test.rego",
        "package main\n\ntest_limit if {\n\tlimit == 10\n}\n",
    );
    track(&root);
    root
}

/// A second declaring file, deliberately outside `checks/`, `policy/`,
/// `mise-tasks/` and the engine directory, so only the declaration arm sees it.
fn add_extra(root: &Path) {
    write(
        root,
        "extra/y.rego",
        "#MUTANT-SUITE checks/limit_test.rego\n#MUTANT y-moved|s/1/2/|test_limit\npackage extra\n\ny := 1\n",
    );
    track(root);
}

/// Run `mutate census` in a consumer, with `$MUTANT_GATES` exactly as given —
/// absent when `None`.
fn consumer_census(root: &Path, gates: Option<&str>) -> (i32, String, String) {
    let mut command = common::batten();
    command.args(["mutate", "census"]).current_dir(root);
    let command = match gates {
        Some(gates) => command.env("MUTANT_GATES", gates),
        None => command.env_remove("MUTANT_GATES"),
    };
    let answer = command
        .env_remove("MUTANT_TASKS")
        .streamed_output()
        .expect("run batten mutate");
    (
        answer.status.code().unwrap_or(-1),
        stdout(&answer),
        stderr(&answer),
    )
}

#[test]
fn census_runs_on_the_set_batten_toml_declares() {
    let root = consumer("set-committed", "[mutate]\ngates = [\"checks/*.rego\"]\n");
    let (code, out, err) = consumer_census(&root, None);
    assert_eq!(code, 0, "{out}{err}");
    assert!(out.contains("every one enforced"), "{out}");
}

#[test]
fn a_declaring_file_outside_the_set_is_uncovered() {
    let root = consumer("set-uncovered", "[mutate]\ngates = [\"checks/*.rego\"]\n");
    add_extra(&root);
    let (code, out, err) = consumer_census(&root, None);
    assert_eq!(code, 2, "{out}{err}");
    assert!(out.contains("extra/y.rego uncovered"), "{out}");
    assert!(!out.contains("checks/limit.rego uncovered"), "{out}");
}

/// The variable ADDS `extra/y.rego`, and the table's `checks/limit.rego` is
/// still enforced beside it — a variable that replaced the table would leave
/// that one `uncovered`, so one clean census shows both halves.
#[test]
fn the_environment_only_raises_the_committed_set() {
    let root = consumer("set-raised", "[mutate]\ngates = [\"checks/*.rego\"]\n");
    add_extra(&root);
    let (code, out, err) = consumer_census(&root, Some("extra/y.rego"));
    assert_eq!(code, 0, "{out}{err}");
    assert!(!out.contains("uncovered"), "{out}");
}

#[test]
fn no_set_anywhere_is_a_usage_error_naming_the_table() {
    let root = consumer("set-none", "[mutate]\ngates = []\n");
    let (code, out, err) = consumer_census(&root, None);
    assert_eq!(code, 1, "{out}{err}");
    assert!(err.contains("[mutate].gates"), "{err}");
}

#[test]
fn a_mutate_table_with_an_unknown_key_is_refused() {
    let root = consumer(
        "set-unknown-key",
        "[mutate]\ngates = [\"checks/*.rego\"]\ngate = [\"typo\"]\n",
    );
    let (code, out, err) = consumer_census(&root, None);
    assert_eq!(code, 1, "{out}{err}");
    assert!(
        err.contains("mutate.gate"),
        "the refusal names the key: {err}"
    );
}

#[test]
fn a_glob_matching_nothing_names_no_subject() {
    let root = consumer(
        "set-empty-glob",
        "[mutate]\ngates = [\"checks/*.rego\", \"nowhere/*.tf\"]\n",
    );
    let (code, out, err) = consumer_census(&root, None);
    assert_eq!(code, 2, "{out}{err}");
    assert!(out.contains("nowhere/*.tf names-no-subject"), "{out}");
}

/// A glob over `policy/` names each module by its stem, the name the policy arm
/// already gives it — so the census's exact comparison holds. Named by path
/// instead, both modules would read `uncovered`.
#[test]
fn a_policy_glob_names_each_module_by_its_stem() {
    let root = consumer("set-policy-glob", "[mutate]\ngates = [\"policy/*.rego\"]\n");
    write(&root, "policy/alpha.rego", "package alpha\n");
    write(&root, "policy/beta.rego", "package beta\n");
    // The `checks/` gate is exempt, so the census is about the glob alone.
    write(
        &root,
        "checks/limit.rego",
        "#MUTANT-EXEMPT CLOUD-1|not under test here\npackage main\n",
    );
    track(&root);
    let (code, out, err) = consumer_census(&root, None);
    assert_eq!(code, 0, "{out}{err}");
    // `alpha`, `beta`, and the exempt `checks/limit.rego` the declaration arm reads.
    assert!(out.contains("3 gate(s)"), "{out}");
}

// ---------------------------------------------------------------------------
// The gate on the real tree.
// ---------------------------------------------------------------------------

#[test]
fn this_repositorys_own_census_is_closed() {
    // What makes every fixture above evidence about THIS repository. A tree
    // whose census is open is a gate covered by nothing stronger than "its suite
    // is green", which CLOUD-418 measured as insufficient four times.
    //
    // THE SET IS THE COMMITTED `[mutate]` TABLE, run with `$MUTANT_GATES`
    // unset (CLOUD-2010). Read from the variable, the census had no table, so
    // its declaration arm never ran and the file-path gates (`action.yml`,
    // `hk.pkl`, the workflows) were swept but never censused: a new file with
    // rows that nobody enrolled read as nothing rather than `uncovered`.
    let root = common::at_root(".")
        .canonicalize()
        .expect("this checkout is where the manifest says it is");
    let config: toml::Table = fs::read_to_string(root.join("batten.toml"))
        .expect("the authority reads")
        .parse()
        .expect("the authority parses");
    let gates = config
        .get("mutate")
        .and_then(|table| table.get("gates"))
        .and_then(toml::Value::as_array)
        .expect("the committed authority declares `[mutate] gates`");
    assert!(
        gates.iter().any(|gate| gate.as_str() == Some("action.yml")),
        "the file-path gates are in the committed set"
    );
    let manifest = fs::read_to_string(root.join("mise.toml")).expect("the manifest reads");
    assert!(
        !manifest
            .lines()
            .any(|line| line.starts_with("MUTANT_GATES =")),
        "one committed authority: the manifest no longer restates the set"
    );
    let answer = common::batten()
        .args(["mutate", "census"])
        .current_dir(&root)
        .env_remove("MUTANT_GATES")
        .env("MUTANT_TASKS", "mise.toml")
        .env("MUTANT_PRESETS", "crates/batten/src/policy/presets")
        .streamed_output()
        .expect("run batten mutate");
    let (code, out, err) = (
        answer.status.code().unwrap_or(-1),
        stdout(&answer),
        stderr(&answer),
    );
    assert_eq!(code, 0, "{out}{err}");
}
