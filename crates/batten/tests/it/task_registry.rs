//! `batten task alive` over the compiled binary (CLOUD-425), ported off
//! `mise-tasks/alive.sh` under CLOUD-843.
//!
//! **THE SECOND TIER, AND IT IS NOT OPTIONAL.** `task.rs`'s own `mod tests` pins
//! the predicates — the corroboration match, the render, the field reader — over
//! values handed to them. What it cannot pin is that the VERB builds the input
//! those predicates read: a module whose `alive` resolved the wrong git dir
//! would pass every unit case and report "nothing registered" forever. That
//! failure and a clean registry are byte-identical on the decision surface,
//! which is why this file exists.
//!
//! **The fixtures write the record bytes directly, and that is the honest shape
//! rather than a shortcut.** The engine ships no writer — CLOUD-1283 — so the
//! format belongs to `mise-tasks/task-registry.sh`, and a test that minted
//! through an engine verb would be asserting against a writer this reader does
//! not have. Seeding the bytes is what a consumer's writer actually leaves
//! behind.
//!
//! **The live-process cases use THIS process.** `rust.md` requires a test be
//! shown able to fail, and a corroboration case needs a process in a known
//! state; spawning one would assert its own premise before its conclusion, and
//! `clippy::disallowed_types` refuses the spawn besides. The test binary is a
//! process this file knows everything about — its pid, and its own `cmdline` —
//! so seeding a record under its real name is the one fixture that cannot be
//! wrong about itself.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::{Path, PathBuf};
use std::process::Output;

use common::{Fixture, batten, scratch, stderr, stdout};

/// A repository with a registry to read, and nothing in it yet.
fn registry_repo(name: &str) -> PathBuf {
    Fixture::at(scratch(name).join("repo"))
        .config("version = 1\n")
        .git()
        .base_commit()
        .build()
}

/// `batten task alive …` in `dir`, fenced so a fixture that forgot `git init`
/// fails loudly instead of reading the real checkout's registry.
fn alive(dir: &Path, args: &[&str]) -> Output {
    let mut command = batten();
    command.args(["task", "alive"]);
    command
        .args(args)
        .current_dir(dir)
        .env("GIT_CEILING_DIRECTORIES", env!("CARGO_TARGET_TMPDIR"))
        .output()
        .expect("run batten task alive")
}

/// The registry directory for a fixture.
fn entries(repo: &Path) -> PathBuf {
    repo.join(".git/batten-tasks")
}

/// Seed one record, in the field order the writer produces.
///
/// The unread fields are written too — `pgid`, `tick`, `tick_at`, `sig`,
/// `sig_at` — because a fixture that omitted them would be a narrower record
/// than any real one, and the reader's job includes stepping past them.
fn seed(repo: &Path, task: &str, pid: &str, phase: &str, started: u64) {
    let dir = entries(repo);
    std::fs::create_dir_all(&dir).expect("a registry");
    std::fs::write(
        dir.join(pid),
        format!(
            "task: {task}\npid: {pid}\npgid: {pid}\nphase: {phase}\n\
             started_at: {started}\nphase_since: {started}\n\
             tick: \ntick_at: \nsig: \nsig_at: \n"
        ),
    )
    .expect("a record");
}

/// This process, as the registry would have to describe it to corroborate.
///
/// Returns `(program_root, task_name)` derived from the running test binary's
/// own path — `…/deps/task_registry-<hash>` gives `("deps", "task_registry-…")`.
/// Derived rather than written down, because a hardcoded name would go stale on
/// the next rebuild and the case would then pass for the wrong reason: an
/// unmatched corroboration reads as ALIVE, so a wrong name is invisible.
fn this_process() -> (String, String) {
    let exe = std::env::current_exe().expect("the running test binary");
    let name = exe
        .file_name()
        .and_then(|name| name.to_str())
        .expect("the binary's file name")
        .to_owned();
    let root = exe
        .parent()
        .and_then(Path::file_name)
        .and_then(|name| name.to_str())
        .expect("the binary's directory name")
        .to_owned();
    (root, name)
}

/// A pid no process can hold.
///
/// `/proc/sys/kernel/pid_max` is exclusive — the kernel never assigns it — so
/// this is a genuine "no such process" rather than a race against whatever
/// happens to be running. A literal high number would eventually collide, and
/// the collision would turn a crashed case green.
fn unassignable_pid() -> String {
    std::fs::read_to_string("/proc/sys/kernel/pid_max")
        .ok()
        .and_then(|raw| raw.trim().parse::<u64>().ok())
        .map_or_else(|| "4194304".to_owned(), |max| max.to_string())
}

#[test]
fn an_empty_registry_and_one_that_was_never_created_both_report_nothing() {
    // Two paths to one answer, and the answer is REAL — "nothing is running" —
    // rather than could-not-look. Conflating those two is the defect CLOUD-425
    // exists to fix, so both are asserted rather than one standing for the pair.
    let repo = registry_repo("task-alive-empty");
    let (root, _) = this_process();

    let never = alive(&repo, &["--program-root", &root]);
    assert_eq!(never.status.code(), Some(0), "{}", stderr(&never));
    assert_eq!(stdout(&never), "alive: nothing registered\n");

    std::fs::create_dir_all(entries(&repo)).expect("an empty registry");
    let empty = alive(&repo, &["--program-root", &root]);
    assert_eq!(empty.status.code(), Some(0), "{}", stderr(&empty));
    assert_eq!(stdout(&empty), "alive: nothing registered\n");
}

#[test]
fn a_running_task_reports_its_task_phase_pid_and_age() {
    // THE LIVE CASE, over this process — see the module header for why that is
    // the honest fixture. `--instant` is what makes the age assertable at all:
    // without it the number is whatever the clock said, and a case that could
    // only assert "some number" would pass over a renderer that printed one.
    let repo = registry_repo("task-alive-running");
    let (root, name) = this_process();
    let pid = std::process::id().to_string();
    seed(&repo, &name, &pid, "verify", 1000);

    let output = alive(&repo, &["--program-root", &root, "--instant", "1060"]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert_eq!(
        stdout(&output),
        format!("{name} verify {pid} 60s in-phase 60s\n"),
        "stderr: {}",
        stderr(&output)
    );
    // Still there: a live task is never reaped.
    assert!(entries(&repo).join(&pid).exists());
}

#[test]
fn a_supplied_instant_decides_the_age_rather_than_the_clock() {
    // The anti-vacuity partner to the case above, and the pair is the point: the
    // first alone passes over a renderer that ignored `--instant` and happened to
    // print a plausible number. A different instant must produce a different age
    // over an identical registry.
    let repo = registry_repo("task-alive-instant");
    let (root, name) = this_process();
    let pid = std::process::id().to_string();
    seed(&repo, &name, &pid, "verify", 1000);

    let early = alive(&repo, &["--program-root", &root, "--instant", "1005"]);
    let late = alive(&repo, &["--program-root", &root, "--instant", "1500"]);
    assert!(stdout(&early).contains(" 5s "), "got: {}", stdout(&early));
    assert!(stdout(&late).contains(" 500s "), "got: {}", stdout(&late));
    assert_ne!(stdout(&early), stdout(&late));
}

#[test]
fn the_same_instant_over_one_registry_state_yields_byte_identical_output() {
    // House-style §6, and the reason `--instant` exists at all: two calls that
    // read a clock cannot promise this, and a reader whose bytes move is one no
    // diff can be taken over.
    let repo = registry_repo("task-alive-stable");
    let (root, name) = this_process();
    let pid = std::process::id().to_string();
    seed(&repo, &name, &pid, "verify", 1000);

    let args = ["--program-root", root.as_str(), "--instant", "9999999999"];
    let first = alive(&repo, &args);
    let second = alive(&repo, &args);
    assert_eq!(stdout(&first), stdout(&second));
}

#[test]
fn a_record_whose_process_is_gone_reports_crashed_and_is_reaped() {
    // THE ACCEPTANCE CASE. `crashed` is a STATE, not an absence: an absent entry
    // means "never registered", and a registered entry whose process is gone
    // means "started and died" — which is the state a human actually needs, and
    // the one that cost seventeen minutes of guessing on 2026-08-12.
    //
    // Reporting it also reaps it, so the registry is self-healing rather than an
    // ever-growing pile of headstones.
    let repo = registry_repo("task-alive-crashed");
    let (root, _) = this_process();
    let pid = unassignable_pid();
    seed(&repo, "land", &pid, "verify", 1000);

    let output = alive(&repo, &["--program-root", &root, "--instant", "1060"]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert_eq!(
        stdout(&output),
        format!("land crashed(verify) {pid} 60s in-phase 60s\n")
    );
    assert!(
        !entries(&repo).join(&pid).exists(),
        "a genuine corpse is reaped"
    );
}

#[test]
fn a_live_pid_that_is_not_this_task_reports_crashed_and_is_never_reaped() {
    // CLOUD-901, and the asymmetry is the whole of it. Pids recycle — this clone
    // measurably wrapped its pid space inside 20 minutes — so a live pid alone is
    // not evidence. But `task_alive` collapses "the process is gone" and "the
    // process is not this task" into one `false`, and reaping on the second made
    // a READ VERB DESTROY THE STATE IT READS: measured, one call reported a live
    // `land` as crashed AND erased its entry, so the follow-up call reported
    // nothing registered — a different lie, caused by the first.
    //
    // So `kill -0` alone licenses deletion. A future corroboration bug then costs
    // a wrong word, never the evidence.
    let repo = registry_repo("task-alive-miscorroborated");
    let (root, _) = this_process();
    let pid = std::process::id().to_string();
    seed(&repo, "somethingelse", &pid, "verify", 1000);

    let output = alive(&repo, &["--program-root", &root, "--instant", "1000"]);
    assert!(
        stdout(&output).contains("crashed(verify)"),
        "got: {}",
        stdout(&output)
    );
    assert!(
        entries(&repo).join(&pid).exists(),
        "an unmatched corroboration is a wrong word, never a reason to delete evidence"
    );
}

#[test]
fn two_consecutive_calls_over_one_live_task_say_the_same_thing() {
    // The reaping half read forwards: a reader that destroyed what it read would
    // answer differently the second time, which is exactly how the measured
    // defect surfaced — `nothing registered` on the follow-up call.
    let repo = registry_repo("task-alive-repeatable");
    let (root, name) = this_process();
    let pid = std::process::id().to_string();
    seed(&repo, &name, &pid, "verify", 1000);

    let args = ["--program-root", root.as_str(), "--instant", "1060"];
    assert_eq!(stdout(&alive(&repo, &args)), stdout(&alive(&repo, &args)));
}

#[test]
fn a_half_written_record_is_skipped_rather_than_rendered_as_blanks() {
    // A partial record is not a task, and inventing one would be a claim. With
    // nothing else registered the reading falls back to "nothing", which is the
    // honest answer for a registry holding no renderable task.
    let repo = registry_repo("task-alive-partial");
    let (root, _) = this_process();
    std::fs::create_dir_all(entries(&repo)).expect("a registry");
    std::fs::write(entries(&repo).join("31337"), "task: land\n").expect("a half-written record");

    let output = alive(&repo, &["--program-root", &root, "--instant", "0"]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert_eq!(stdout(&output), "alive: nothing registered\n");
}

#[test]
fn a_record_predating_the_phase_stamp_still_renders() {
    // Byte-stability for a reader that predates a field: the `in-phase` suffix is
    // appended, never substituted, so an older record renders without it rather
    // than failing to render at all.
    let repo = registry_repo("task-alive-old-record");
    let (root, _) = this_process();
    let pid = unassignable_pid();
    std::fs::create_dir_all(entries(&repo)).expect("a registry");
    std::fs::write(
        entries(&repo).join(&pid),
        format!("task: land\npid: {pid}\nphase: verify\nstarted_at: 1000\n"),
    )
    .expect("a record with no phase stamp");

    let output = alive(&repo, &["--program-root", &root, "--instant", "1060"]);
    assert_eq!(stdout(&output), format!("land crashed(verify) {pid} 60s\n"));
}

#[test]
fn n_records_report_one_line_each_in_a_stable_order() {
    let repo = registry_repo("task-alive-many");
    let (root, name) = this_process();
    let pid = std::process::id().to_string();
    seed(&repo, &name, &pid, "verify", 1000);
    // A second record under a pid nobody holds: two lines, and the crashed one
    // proves the loop renders every entry rather than stopping at the first.
    let corpse = unassignable_pid();
    seed(&repo, "land", &corpse, "push", 1000);

    let output = alive(&repo, &["--program-root", &root, "--instant", "1000"]);
    let rendered = stdout(&output);
    let lines: Vec<&str> = rendered.lines().collect();
    assert_eq!(lines.len(), 2, "got: {rendered}");
    assert!(
        lines.iter().any(|line| line.contains("crashed(push)")),
        "got: {lines:?}"
    );
    assert!(
        lines.iter().any(|line| line.contains(" verify ")),
        "got: {lines:?}"
    );
}

#[test]
fn a_registry_that_cannot_be_read_is_could_not_look_and_never_nothing_runs() {
    // The third answer, and the one the whole exit table turns on: "I could not
    // tell" must not read as "nothing is running". Present-but-not-a-directory is
    // also the only way to drive this branch as root, for whom the permission
    // bits are not a constraint (`rust.md`'s premise rule).
    //
    // Exit 3, where the retiring shell spelled it 2 — the one contract has one
    // meaning per code and no per-verb exception.
    let repo = registry_repo("task-alive-unreadable");
    let (root, _) = this_process();
    std::fs::write(entries(&repo), "not a directory\n").expect("a file");

    let output = alive(&repo, &["--program-root", &root]);
    assert_eq!(output.status.code(), Some(3), "{}", stderr(&output));
    assert!(
        !stdout(&output).contains("nothing registered"),
        "could not look is not an answer about what runs"
    );
}

#[test]
fn outside_a_repository_it_is_could_not_look_rather_than_nothing_runs() {
    let outside = Fixture::at(scratch("task-no-repo").join("plain")).build();
    let (root, _) = this_process();
    let output = alive(&outside, &["--program-root", &root]);
    assert_eq!(output.status.code(), Some(3), "{}", stderr(&output));
}

#[test]
fn the_report_is_a_pointer_and_never_a_line_of_any_log() {
    // Non-negotiable rule 4, and here it is the POINT rather than hygiene: being
    // forced to read logs is the defect CLOUD-425 removes, so emitting log
    // content would reintroduce it through the front door.
    //
    // BOTH DIRECTIONS, because either alone is weak. A shape assertion alone
    // passes over a reader that emitted some other payload in the right number
    // of words; a canary assertion alone passes over a reader that emitted a
    // DIFFERENT byte of the record. So: the rendered line matches the declared
    // shape, AND no byte of a field this reader does not render reaches either
    // channel.
    //
    // The canaries go in fields the reader legitimately does NOT render — the
    // loop tokens, and a line no field name claims. Planting one in `phase`
    // would have been a test about the writer's own value rather than about a
    // leak, which is the first version of this case and why it failed: a phase
    // reading `LOG BODY HERE` is the writer's word, emitted correctly.
    let repo = registry_repo("task-alive-pointer");
    let (root, name) = this_process();
    let pid = std::process::id().to_string();
    std::fs::create_dir_all(entries(&repo)).expect("a registry");
    std::fs::write(
        entries(&repo).join(&pid),
        format!(
            "task: {name}\npid: {pid}\npgid: {pid}\nphase: verify\n\
             started_at: 1000\nphase_since: 1000\n\
             tick: Q7vtickedx9nK\ntick_at: 1000\nsig: Q7vsignedx9nK\nsig_at: 1000\n\
             Q7vstrayx9nK\n"
        ),
    )
    .expect("a record carrying unrendered fields");

    let output = alive(&repo, &["--program-root", &root, "--instant", "1000"]);
    let rendered = stdout(&output);
    for line in rendered.lines() {
        let words: Vec<&str> = line.split(' ').collect();
        assert!(
            words.len() == 4 || words.len() == 6,
            "a line is `<task> <phase> <pid> <age>s[ in-phase <n>s]`, got: {line:?}"
        );
    }
    for canary in ["Q7vtickedx9nK", "Q7vsignedx9nK", "Q7vstrayx9nK"] {
        assert!(
            !rendered.contains(canary) && !stderr(&output).contains(canary),
            "a field this reader does not render reached the output: {canary}"
        );
    }
}

#[test]
fn the_reader_sends_no_signal() {
    // CLOUD-425's safety property, held structurally rather than by review.
    // `SIGUSR1`'s default disposition is Term, so a reader that signalled would
    // KILL what it came to inspect — and the probe this module does use,
    // `test_kill_process`, delivers nothing by construction.
    //
    // A source scan rather than a behavioural assertion, because the failing
    // condition is "a signal was delivered" and a test that produced it would
    // have killed its own process to find out.
    //
    // `test_kill_process(` CONTAINS `kill_process(`, so a plain substring ban
    // refuses the one probe this module is supposed to use — measured, this case
    // failed on its own subject. Each occurrence is judged by what precedes it
    // instead: a `test_` prefix is the probe, anything else delivers.
    let source =
        std::fs::read_to_string(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/task.rs"))
            .expect("the reader module");
    for banned in ["kill_process(", "kill_process_group(", "signal_group("] {
        for (at, _) in source.match_indices(banned) {
            assert!(
                source[..at].ends_with("test_"),
                "`{banned}` at byte {at} delivers a signal; this module must not"
            );
        }
    }
    // And the probe it DOES use is present, so the scan above is not passing
    // over a file that stopped probing at all.
    assert!(source.contains("test_kill_process("));
}

#[test]
fn the_program_root_is_required_rather_than_defaulted() {
    // Non-negotiable rule 1 at the surface. A default would be one consumer's
    // layout promoted to the engine's, and it would fail SILENTLY everywhere
    // else: an unmatched corroboration reads as alive, so a wrong root produces
    // a registry that never reports a crash and looks like one with nothing to
    // report. Refusing the invocation is the only failure mode that is visible.
    //
    // Exit 1: a missing required argument is a statement about the INVOCATION,
    // which the one contract spells `Usage`. `2` is the policy verdict
    // everywhere and would read as an answer about the registry.
    let repo = registry_repo("task-alive-no-root");
    let output = alive(&repo, &[]);
    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
}

#[test]
fn a_malformed_instant_is_refused_rather_than_silently_read_as_the_clock() {
    let repo = registry_repo("task-alive-bad-instant");
    let (root, _) = this_process();
    let output = alive(&repo, &["--program-root", &root, "--instant", "soon"]);
    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
}
// --- `alive`, retired onto `batten task alive` (CLOUD-843 / CLOUD-425) -------
//
// **ONE OF THE PAIR RETIRES, AND THE GATE IS WHY.** `mise-tasks/alive.sh` (the
// reader) and `mise-tasks/task-registry.sh` (the writer) are one mechanism, and
// both were ported here. Only the reader could land, because
// `mise-tasks/land-lock.sh:625` binds the writer to a variable and SPENDS it
// three lines later as `"$reg" read "$pid" <field>` — and `shell-retirement`'s
// `repoints_at_the_declared_invocation` admits a repointing at the BINDING and
// has no admitted addition for the SPEND. `"$reg"` is one shell word, so a
// successor whose invocation is three words cannot be reached without editing
// the spend sites, and every spelling of that edit is refused. CLOUD-1283 owns
// it; the writer verbs are built and tested here against that unblocking, and
// `ci-wait`'s `--progress` consumes `tick` and `sig` today.
//
// **THE PROGRAM ROOT MOVED FROM A LITERAL TO A FLAG, and that is the only
// deliberate behavioural change in the port.** The shell matched
// `/mise-tasks/<task>` inside a live process's cmdline; a literal like that in
// `crates/batten` is non-negotiable rule 1's violation, and
// `document_facts::no_artifact_name_reaches_the_core` is the gate that says so.
// It is `--program-root`, REQUIRED rather than defaulted, because a wrong root
// fails silently: an unmatched corroboration reads as ALIVE, so a registry with
// the wrong root never reports a crash and looks exactly like one with nothing
// to report.
//
// carried: mise-tasks/alive.sh crates/batten/src/task.rs kind:verb crates/batten/tests/it/task_registry.rs
// carried: tests/alive.bats crates/batten/src/task.rs kind:verb crates/batten/tests/it/task_registry.rs
//
// carried: "nothing registered is a real answer, and exit 0" crates/batten/tests/it/task_registry.rs
// carried: "a registry that exists but is empty still reports nothing registered" crates/batten/tests/it/task_registry.rs
// carried: "a running task reports its task, phase, pid and age" crates/batten/tests/it/task_registry.rs
// carried: "a line says how long the task has been in its phase, not only how long it has run" crates/batten/tests/it/task_registry.rs
// carried: "an entry written before the phase stamp existed still renders" crates/batten/src/task.rs kind:mechanism
// carried: "N running tasks report one line each" crates/batten/tests/it/task_registry.rs
// carried: "THE ACCEPTANCE CASE: an entry whose pid is gone reports crashed, and is reaped" crates/batten/tests/it/task_registry.rs
// carried: "a live pid that is no longer the task that registered it reports crashed" crates/batten/tests/it/task_registry.rs
// carried: "a task that never registered is invisible, never assumed dead" crates/batten/tests/it/task_registry.rs
// carried: "a registry that is not a directory is exit 2 — could not look is not 'nothing runs'" crates/batten/tests/it/task_registry.rs
// carried: "outside a git repository it exits 2 rather than claiming nothing runs" crates/batten/tests/it/task_registry.rs
// carried: "a half-written entry is skipped, not rendered as a line of blanks" crates/batten/tests/it/task_registry.rs
// carried: "output is byte-stable across runs for the same registry state" crates/batten/tests/it/task_registry.rs
// carried: "THE PROPERTY: output is a pointer — never a line of any log" crates/batten/tests/it/task_registry.rs
// carried: "THE PROPERTY: the reader never sends a signal" crates/batten/tests/it/task_registry.rs
// carried: "CLOUD-901: a task whose FILE carries .sh and whose NAME does not is running" crates/batten/src/task.rs kind:mechanism
// carried: "CLOUD-901: a sibling task whose name EXTENDS this one does not corroborate" crates/batten/src/task.rs kind:mechanism
// carried: "CLOUD-901: a live pid that fails corroboration is reported, never reaped" crates/batten/tests/it/task_registry.rs
// carried: "CLOUD-901: two consecutive calls over one live task say the same thing" crates/batten/tests/it/task_registry.rs
//
// CHANGED — one exit code, deliberately.
//
// changed: "an unreadable registry directory is exit 2" crates/batten/tests/it/task_registry.rs the exit code is 3, not 2: could-not-look is `Internal` in the one contract and `2` is the policy verdict everywhere, with no per-verb exception. The `mise.toml` wrapper translates it back so the retiring program's callers see what they always saw, which is where a consumer's compatibility with its own history belongs. The PREDICATE is carried unchanged, in `a_registry_that_cannot_be_read_is_could_not_look_and_never_nothing_runs` — and over a registry that is present but not a directory, which is also the only way to drive the branch as root
