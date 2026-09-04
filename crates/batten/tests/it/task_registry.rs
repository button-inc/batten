//! The `task` noun over the compiled binary (CLOUD-425), ported off
//! `mise-tasks/alive.sh` and `mise-tasks/task-registry.sh` under CLOUD-843.
//!
//! **BOTH HALVES, because the registry is one mechanism read from both ends.**
//! An earlier revision of this file landed the reader alone and recorded the
//! writer as blocked; that was wrong, and the retraction is on CLOUD-1283. The
//! claim was that `shell-retirement` admits a repointing at the BINDING
//! (`reg="$(dirname "$0")/task-registry.sh"`) and none at the SPEND
//! (`"$reg" read "$pid" phase_since`). It admits both — the successor declared
//! on the arm below is `batten task`, so the span the module derives over a
//! spend site is exactly `"$reg"`, which `spellings()` strips to `$reg` and
//! `retired_path_vars` resolves. Declaring the longer `batten task read` is what
//! made the span unreachable, and that was the author's choice rather than the
//! gate's verdict.
//!
//! **THE SECOND TIER, AND IT IS NOT OPTIONAL.** `task.rs`'s own `mod tests` pins
//! the predicates — the corroboration match, the render, the field reader — over
//! values handed to them. What it cannot pin is that the VERB builds the input
//! those predicates read: a module whose `alive` resolved the wrong git dir
//! would pass every unit case and report "nothing registered" forever. That
//! failure and a clean registry are byte-identical on the decision surface,
//! which is why this file exists.
//!
//! **The reader's fixtures seed the record bytes directly, and the writer's
//! cases mint through the verbs.** That split is deliberate rather than
//! inconsistent: a reader case seeding bytes states the format it is asserting
//! against, so a writer defect cannot make a reader case pass; a writer case
//! minting through the verb is the only shape that proves the VERB builds the
//! record, which is what a unit test over `Entry::render` cannot say.
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

/// `batten task <args>` in `dir`, fenced the same way `alive` is.
fn task(dir: &Path, args: &[&str]) -> Output {
    let mut command = batten();
    command.arg("task");
    command
        .args(args)
        .current_dir(dir)
        .env("GIT_CEILING_DIRECTORIES", env!("CARGO_TARGET_TMPDIR"))
        .output()
        .expect("run batten task")
}

/// One field of one record, read the way the retiring shell's own helper did —
/// the FIRST matching line, so a record carrying a stray line that happens to
/// start with a field name still answers with the field.
fn field(repo: &Path, pid: &str, name: &str) -> String {
    let body = std::fs::read_to_string(entries(repo).join(pid)).unwrap_or_default();
    body.lines()
        .find_map(|line| line.strip_prefix(&format!("{name}: ")))
        .unwrap_or_default()
        .to_owned()
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

/// Whether a record under [`unassignable_pid`] can read as a corpse on this target.
///
/// `pid_exists` has **no probe off unix** — its `#[cfg(not(unix))]` arm answers
/// `true` for every parseable pid, deliberately, so nothing is ever reported dead
/// and nothing is ever reaped. The helper above compounds it: there is no
/// `/proc/sys/kernel/pid_max` to read there either, so it falls back to a literal
/// that is parseable and therefore "alive". A corpse is unreachable off unix, and
/// every row whose subject is the crashed verdict has to say so.
///
/// STATED ONCE, AND AS A `cfg!` RATHER THAN AN ATTRIBUTE. Three rows below need
/// it and each spelling it inline is how the first two drifted apart. `cfg!`
/// keeps BOTH arms compiled on every target, so `cross-check` type-checks the
/// off-unix branch instead of skipping over it unparsed — which matters here more
/// than usual, since the whole class was discovered by CI compiling what no local
/// gate runs.
const CORPSE_IS_DETECTABLE: bool = cfg!(unix);

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
    if CORPSE_IS_DETECTABLE {
        assert_eq!(
            stdout(&output),
            format!("land crashed(verify) {pid} 60s in-phase 60s\n")
        );
        assert!(
            !entries(&repo).join(&pid).exists(),
            "a genuine corpse is reaped"
        );
    } else {
        // The same registry state, read where nothing can be reported dead: the
        // record renders as the running task it claims to be, and — the half that
        // still matters — it is NOT reaped. A reap off unix would be the read verb
        // destroying evidence on a verdict it could not reach.
        assert_eq!(
            stdout(&output),
            format!("land verify {pid} 60s in-phase 60s\n")
        );
        assert!(
            entries(&repo).join(&pid).exists(),
            "nothing is reaped where nothing can be found dead"
        );
    }
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

    // THE CORROBORATION IS LINUX'S, AND THE ENGINE ALREADY SAYS SO. `task_alive`
    // reads `/proc/<pid>/cmdline`, and its own doc records the direction: "an
    // unevaluable corroboration reads as ALIVE — which also keeps the reader
    // honest off Linux, where /proc/<pid>/cmdline does not exist at all." So the
    // mismatch this row is about is only DETECTABLE where that file is, and
    // asserting the crashed verdict everywhere states the Linux contract as
    // universal — which the `windows` job read as `somethingelse verify …`.
    //
    // Split rather than `cfg`-gated away, for the reason its two siblings in
    // `task.rs` and `singleton.rs` carry: gating the test leaves the off-Linux
    // contract unstated, and an unstated contract is the hole that ships the next
    // one. `target_os` rather than `unix`, because macOS has no `/proc` either —
    // the discriminator is the FILE, not the family.
    #[cfg(target_os = "linux")]
    assert!(
        stdout(&output).contains("crashed(verify)"),
        "got: {}",
        stdout(&output)
    );
    #[cfg(not(target_os = "linux"))]
    // Unevaluable, so the safe direction wins and the entry reads as the task it
    // claims to be. That is the deliberate answer rather than a gap: a live task
    // misreported as dead licenses the duplicate-landing incident the registry
    // exists to prevent, which is the asymmetry the engine's doc argues.
    assert!(
        stdout(&output).contains("somethingelse verify"),
        "got: {}",
        stdout(&output)
    );

    // PLATFORM-INDEPENDENT, and deliberately outside the split: whichever word the
    // corroboration produces, it never licenses deletion. That is CLOUD-901's
    // actual invariant, and it must hold on every target.
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
    // This row's subject is the RENDERING of a record with no phase stamp, not the
    // liveness word in front of it — so only that word moves off unix, and the
    // missing suffix is asserted on both targets.
    let expected = if CORPSE_IS_DETECTABLE {
        format!("land crashed(verify) {pid} 60s\n")
    } else {
        format!("land verify {pid} 60s\n")
    };
    assert_eq!(stdout(&output), expected);
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
    // The COUNT is this row's subject — the loop renders every entry rather than
    // stopping at the first — and it holds on every target. The crashed word is
    // what carries the second line's identity on unix and is unreachable off it,
    // so the assertion moves to the phase, which distinguishes the two lines
    // either way.
    let second = if CORPSE_IS_DETECTABLE {
        "crashed(push)"
    } else {
        " push "
    };
    assert!(
        lines.iter().any(|line| line.contains(second)),
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
// -- The writers -------------------------------------------------------------

#[test]
fn register_writes_one_entry_carrying_task_pid_pgid_and_a_start_time() {
    let repo = registry_repo("task-register");
    let output = task(&repo, &["register", "land", "4242", "starting"]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));

    assert!(entries(&repo).join("4242").exists());
    assert_eq!(field(&repo, "4242", "task"), "land");
    assert_eq!(field(&repo, "4242", "pid"), "4242");
    assert_eq!(field(&repo, "4242", "phase"), "starting");
    // A group of one is the truth for a task started outside job control, so
    // the fallback is a reading rather than a placeholder — never empty.
    assert!(!field(&repo, "4242", "pgid").is_empty());
    // A start time the reader can turn into an age, never a formatted date.
    assert!(
        field(&repo, "4242", "started_at")
            .chars()
            .all(|c| c.is_ascii_digit()),
        "got: {:?}",
        field(&repo, "4242", "started_at")
    );
}

#[test]
fn register_defaults_the_phase_rather_than_writing_an_empty_one() {
    // Defaulted in the verb rather than at the surface: an empty phase renders
    // as `unknown`, which is a claim about the record, and a task that has just
    // registered is `starting`, which is a fact about it.
    let repo = registry_repo("task-register-default");
    let output = task(&repo, &["register", "land", "4242"]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert_eq!(field(&repo, "4242", "phase"), "starting");
}

#[test]
fn a_phase_push_rewrites_only_the_phase_preserving_task_and_start_time() {
    // The entry is rewritten WHOLE on every push, so this is the case that says
    // a writer which dropped a field it does not own would be caught.
    let repo = registry_repo("task-phase");
    task(&repo, &["register", "land", "4242", "starting"]);
    let started = field(&repo, "4242", "started_at");

    let output = task(&repo, &["phase", "4242", "verify(lap 1)"]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert_eq!(field(&repo, "4242", "phase"), "verify(lap 1)");
    assert_eq!(field(&repo, "4242", "task"), "land");
    assert_eq!(field(&repo, "4242", "started_at"), started);
}

#[test]
fn a_push_for_a_pid_that_never_registered_fabricates_nothing() {
    // The registry records what registered. Inventing an entry here would let a
    // half-wired task look fully wired, which is the failure CLOUD-425 is about:
    // a confident answer with nothing behind it.
    //
    // All three signals, because they are three verbs over one rule and a
    // fabricating one would be found only by the case that names it.
    let repo = registry_repo("task-push-unregistered");
    for args in [
        ["phase", "9999", "verify"],
        ["tick", "9999", "1"],
        ["sig", "9999", "abc123"],
    ] {
        let output = task(&repo, &args);
        assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
        assert!(!entries(&repo).join("9999").exists(), "{args:?} fabricated");
    }
}

#[test]
fn unregister_removes_the_entry_and_an_absent_one_is_a_no_op() {
    // It runs from an exit trap, which fires on paths where registration never
    // happened. A trap that can fail is a trap that masks the real exit code.
    let repo = registry_repo("task-unregister");
    task(&repo, &["register", "land", "4242", "starting"]);

    let removed = task(&repo, &["unregister", "4242"]);
    assert_eq!(removed.status.code(), Some(0), "{}", stderr(&removed));
    assert!(!entries(&repo).join("4242").exists());

    let absent = task(&repo, &["unregister", "9999"]);
    assert_eq!(absent.status.code(), Some(0), "{}", stderr(&absent));
}

#[test]
fn an_unwritable_registry_degrades_to_a_no_op_rather_than_failing_the_caller() {
    // A `land` must never die because its own bookkeeping could not be written.
    //
    // Blocked by putting a FILE where the registry directory belongs rather than
    // by clearing permission bits: this suite runs as root, and root is not
    // subject to the bits, so a chmod-based version would pass because the write
    // SUCCEEDED — a green case asserting the opposite of what it claims
    // (`rust.md`'s premise rule).
    let repo = registry_repo("task-unwritable");
    std::fs::write(entries(&repo), "not a directory\n").expect("a file");

    let output = task(&repo, &["register", "land", "4242", "starting"]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert!(!entries(&repo).join("4242").exists());
}

#[test]
fn a_write_leaves_no_temporary_file_beside_the_record() {
    // Rewrite-and-rename, so a reader sees either the old record or the new one
    // and never a half-written line. Asserted over the DIRECTORY the write left
    // behind rather than over the writer's source: the shell suite could only
    // scan its own text for a redirect, and a residue assertion is the same
    // property stated where a consumer can observe it.
    let repo = registry_repo("task-atomic");
    task(&repo, &["register", "land", "4242", "starting"]);
    task(&repo, &["phase", "4242", "verify"]);

    let mut names: Vec<String> = std::fs::read_dir(entries(&repo))
        .expect("a registry")
        .map(|entry| {
            entry
                .expect("an entry")
                .file_name()
                .to_string_lossy()
                .into()
        })
        .collect();
    names.sort();
    assert_eq!(
        names,
        vec!["4242".to_owned()],
        "a temp file survived a write"
    );
}

#[test]
fn register_stamps_the_phase_and_leaves_the_loop_stamps_empty() {
    // A task that has not ticked has not ticked. Seeding the loop stamps at the
    // start time would let a stall detector read REGISTRATION as progress, and
    // an invented epoch would read as "stopped ticking in 1970" to any bound.
    let repo = registry_repo("task-register-stamps");
    let output = task(&repo, &["register", "land", "4242", "starting"]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));

    assert!(
        field(&repo, "4242", "phase_since")
            .chars()
            .all(|c| c.is_ascii_digit())
            && !field(&repo, "4242", "phase_since").is_empty()
    );
    assert_eq!(field(&repo, "4242", "tick"), "");
    assert_eq!(field(&repo, "4242", "tick_at"), "");
    assert_eq!(field(&repo, "4242", "sig"), "");
    assert_eq!(field(&repo, "4242", "sig_at"), "");
}

/// Seed one record whose stamps are all `1`.
///
/// The stamp cases turn on whether a stamp MOVED, and the writers take the
/// boundary's own clock — there is no `--instant` on a write, because a record
/// is not a verdict and §6 binds the reader. The retiring suite bought the
/// distinction with `sleep 1` per case. A stamp of `1` buys it for nothing and
/// buys it exactly: an unmoved stamp is still `1`, and any stamp the clock
/// writes is not.
fn seed_stamped(repo: &Path, pid: &str, phase: &str) {
    let dir = entries(repo);
    std::fs::create_dir_all(&dir).expect("a registry");
    std::fs::write(
        dir.join(pid),
        format!(
            "task: land\npid: {pid}\npgid: {pid}\nphase: {phase}\n\
             started_at: 1\nphase_since: 1\n\
             tick: 7\ntick_at: 1\nsig: abc123\nsig_at: 1\n"
        ),
    )
    .expect("a record");
}

#[test]
fn restating_the_same_phase_does_not_move_its_stamp() {
    // THE RULE (CLOUD-499), and it is not hygiene: `land-lock hold` reads these
    // stamps to decide whether the landing they describe is still going
    // anywhere. A writer that restamped on every write would report progress
    // every beat and the stall bail could never fire — a mechanism that looks
    // correct and detects nothing.
    let repo = registry_repo("task-stamp-held");
    seed_stamped(&repo, "4242", "ci-wait(lap 1)");

    let output = task(&repo, &["phase", "4242", "ci-wait(lap 1)"]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert_eq!(field(&repo, "4242", "phase_since"), "1");
}

#[test]
fn a_phase_that_actually_changes_moves_the_stamp() {
    // The discriminating partner to the case above, and the pair is the point:
    // without it a writer that never stamped anything at all would satisfy the
    // rule and record nothing.
    let repo = registry_repo("task-stamp-moved");
    seed_stamped(&repo, "4242", "ci-wait(lap 1)");

    task(&repo, &["phase", "4242", "verify(lap 2)"]);
    assert_ne!(field(&repo, "4242", "phase_since"), "1");
    assert_eq!(field(&repo, "4242", "phase"), "verify(lap 2)");
}

#[test]
fn tick_and_sig_are_independent_and_neither_erases_the_other_or_the_phase() {
    // They answer different questions — the loop went round, versus the world
    // moved — and a rising tick over an unchanged sig IS the livelock signature,
    // so the two stamps must be able to part.
    let repo = registry_repo("task-tick-sig");
    seed_stamped(&repo, "4242", "ci-wait(lap 1)");

    task(&repo, &["tick", "4242", "8"]);
    task(&repo, &["sig", "4242", "abc123"]);

    assert_eq!(field(&repo, "4242", "tick"), "8");
    assert_eq!(field(&repo, "4242", "sig"), "abc123");
    assert_eq!(field(&repo, "4242", "phase"), "ci-wait(lap 1)");
    // The phase and the unchanged sig held; only the tick moved.
    assert_eq!(field(&repo, "4242", "phase_since"), "1");
    assert_eq!(field(&repo, "4242", "sig_at"), "1");
    assert_ne!(field(&repo, "4242", "tick_at"), "1");
}

#[test]
fn read_prints_one_field_and_a_pid_that_never_registered_is_a_reading() {
    // A field rather than the layout, so a prober composes instead of parsing.
    //
    // A pid that never registered is a READING — invisible, exactly as `alive`
    // reports it — and a caller must be able to tell it from a field that is
    // legitimately empty, which is why it is a code rather than a blank line.
    // The retiring shell spelled it `1`; the one contract spells a record that
    // is not there `2` and reserves `3` for could-not-look.
    let repo = registry_repo("task-read");
    task(&repo, &["register", "land", "4242", "ci-wait(lap 1)"]);

    let found = task(&repo, &["read", "4242", "phase"]);
    assert_eq!(found.status.code(), Some(0), "{}", stderr(&found));
    assert_eq!(stdout(&found), "ci-wait(lap 1)\n");

    let absent = task(&repo, &["read", "9999", "phase"]);
    assert_eq!(absent.status.code(), Some(2), "{}", stderr(&absent));
    assert_eq!(stdout(&absent), "");
}

#[test]
fn a_missing_positional_is_usage_and_leaves_no_partial_record() {
    // Exit 1 everywhere, where the retiring shell spelled all three `2`: a
    // missing argument is a statement about the INVOCATION, which the one
    // contract spells `Usage`. `2` is the policy verdict, and here it already
    // means "no such record".
    let repo = registry_repo("task-usage");
    for args in [
        vec!["register", "land"],
        vec!["phase", "4242"],
        vec!["tick", "4242"],
        vec!["read", "4242"],
        vec!["sniff", "4242"],
    ] {
        let output = task(&repo, &args);
        assert_eq!(
            output.status.code(),
            Some(1),
            "{args:?}: {}",
            stderr(&output)
        );
    }
    assert!(
        !entries(&repo).exists(),
        "a refused invocation wrote a partial record"
    );
}

#[test]
fn outside_a_repository_a_write_is_could_not_look_rather_than_a_silent_success() {
    // There is nowhere to record, and saying so is the point: a write that
    // succeeded loudly into nothing is how a half-wired task looks fully wired.
    // Exit 3 where the shell spelled it 2 — could-not-look is `Internal`.
    let outside = Fixture::at(scratch("task-write-no-repo").join("plain")).build();
    let output = task(&outside, &["register", "land", "4242"]);
    assert_eq!(output.status.code(), Some(3), "{}", stderr(&output));
}

// --- `alive`, retired onto `batten task alive` (CLOUD-843 / CLOUD-425) -------
//
// **BOTH OF THE PAIR RETIRE, in one delta, because they are one mechanism.**
// `mise-tasks/alive.sh` is the reader and `mise-tasks/task-registry.sh` the
// writer, over one record format. Landing one alone would have left the format
// owned by a program the engine could not write, which is the second-authority
// class `.claude/rules/policy-modules.md` records for parsers.
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

// --- `task-registry`, retired onto the six writer verbs (CLOUD-843/CLOUD-425)-
//
// **THE CALL SITES ARE REPOINTED, NOT REWRITTEN.** `mise-tasks/land-lock.sh`
// bound the program to `reg` and spent it three times; the successor declared on
// the arms below is `batten task`, so each spend's derived span is exactly
// `"$reg"` and `shell-retirement`'s `repoints_at_the_declared_invocation` admits
// the substitution. `mise.toml`'s `task-registry` task is the same repointing at
// the other end — one line, translating the engine's `2`/`3` back to the shell's
// `1`/`2` so a caller written against the retiring program's codes still reads
// the same answers.
//
// **THE USAGE CODE MOVED, and it is the one break the wrapper does not hide.**
// The shell spelled every bad invocation `2`; the one contract spells it `1`.
// Nothing calls these verbs with a missing argument — the wrapper's translation
// is for the READ codes, which callers branch on — and hiding a usage error
// behind a policy verdict is the conflation the table exists to prevent.
//
// carried: mise-tasks/task-registry.sh crates/batten/src/task.rs kind:verb crates/batten/tests/it/task_registry.rs runs:batten+task
// carried: tests/task-registry.bats crates/batten/src/task.rs kind:verb crates/batten/tests/it/task_registry.rs
//
// carried: "register writes one entry per pid, carrying task, pid, pgid and a start time" crates/batten/tests/it/task_registry.rs
// carried: "register defaults the phase rather than writing an empty one" crates/batten/tests/it/task_registry.rs
// carried: "phase rewrites only the phase, preserving task and start time" crates/batten/tests/it/task_registry.rs
// carried: "a phase update for a pid that never registered fabricates nothing" crates/batten/tests/it/task_registry.rs
// carried: "a tick for a pid that never registered fabricates nothing" crates/batten/tests/it/task_registry.rs
// carried: "unregister removes the entry" crates/batten/tests/it/task_registry.rs
// carried: "unregister of an absent entry is a no-op, not a failure" crates/batten/tests/it/task_registry.rs
// carried: "an unwritable registry degrades to a no-op rather than failing the caller" crates/batten/tests/it/task_registry.rs
// carried: "register stamps the phase, and leaves the loop stamps empty" crates/batten/tests/it/task_registry.rs
// carried: "THE RULE: re-stating the same phase does not move its stamp" crates/batten/tests/it/task_registry.rs
// carried: "a phase that actually changes moves the stamp" crates/batten/tests/it/task_registry.rs
// carried: "tick and sig are independent, and neither erases the other or the phase" crates/batten/tests/it/task_registry.rs
//
// CHANGED — the atomic-write case, and every exit code the one contract respells.
//
// changed: "an entry is never observed half-written" crates/batten/tests/it/task_registry.rs the shell could only scan its own text for a redirect onto the live path, because a bats suite cannot see inside its subject any other way. `a_write_leaves_no_temporary_file_beside_the_record` asserts the same rewrite-and-rename property where a CONSUMER can observe it — the directory a write left behind holds the record and nothing else — and `write_entry`'s own unit tier pins the failure path
// changed: "read prints one field, and says nothing about a pid that never registered" crates/batten/tests/it/task_registry.rs the no-such-record code is 2, not 1: a record that is not there is the policy verdict, and `1` is `Usage`. The predicate is carried whole in `read_prints_one_field_and_a_pid_that_never_registered_is_a_reading`, including the silence, and the `mise.toml` wrapper maps it back to `1` so `land-lock.sh`'s three spends read "no verdict" exactly as they did
// changed: "task-registry.bats::an unknown verb is exit 2, never a silent success" crates/batten/tests/it/task_registry.rs exit 1: an unknown subcommand is a statement about the invocation. Carried into `a_missing_positional_is_usage_and_leaves_no_partial_record`, which asserts the code over the unknown verb and over all four missing positionals at once, because they are one class and the shell had spelled them as four
// changed: "register without a pid is exit 2, never a partial record" crates/batten/tests/it/task_registry.rs exit 1, same class and same case; the "no partial record" half is carried unchanged as an assertion that the registry directory was never created
// changed: "phase without a phase word is exit 2" crates/batten/tests/it/task_registry.rs exit 1, same class and same case
// changed: "tick and read without their argument are exit 2" crates/batten/tests/it/task_registry.rs exit 1, same class and same case
// changed: "outside a git repository it exits 2 — there is nowhere to record" crates/batten/tests/it/task_registry.rs exit 3: could-not-look is `Internal`, which is the same respelling the reader's own unreadable-registry case took, and for the same reason — there is nowhere to record, which is not a verdict about the record
//
// SUBSUMED — one property, one scan, one file.
//
// subsumed: "this task never sends a signal" crates/batten/tests/it/task_registry.rs the writer and the reader are now one module, so `the_reader_sends_no_signal` scans the file both halves live in. The shell needed two copies because they were two programs; a second case here would scan the same bytes twice
