//! CLOUD-427: `batten exec` owns the process tree it dispatched, or declines.
//!
//! Everything here is `#[cfg(unix)]`, per CLOUD-113: `setpgid`, `killpg` and the
//! four forwarded signals have no Windows analogue, and on that platform
//! `GroupDecision::observe` answers `false` unconditionally — so the shape these
//! cases assert is a shape Windows does not have rather than one it fails.
//!
//! The measurements are made **by pid**, never by reading a log. A supervisor
//! that reports having cleaned up is exactly the thing under test, so its own
//! account of itself is not evidence; `kill -0` against the leaked grandchild is.
//!
//! Two cases are the pair that makes the rest meaningful, and they are
//! deliberately kept adjacent: with the opt-in on the tree dies whole, and with
//! it off the grandchild survives. The second is not a bug being enshrined — it
//! is the acceptance clause "with the opt-in off, the process topology is
//! byte-for-byte what it is today", and it is also this suite's own mutation
//! check: a rig that killed the tree either way would pass the first case while
//! measuring nothing.

#![cfg(unix)]
// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::fs;
use std::os::unix::process::ExitStatusExt as _;
use std::path::{Path, PathBuf};
#[expect(
    clippy::disallowed_types,
    reason = "stays, and test-only: the subject is a negotiated process-group protocol with mise's supervisor (CLOUD-427), which is only observable across real processes"
)]
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use common::{Fixture, StateHome as _, scratch};

/// How long a case waits for a process to reach a state before giving up.
///
/// Generous, because the alternative to waiting is sleeping a fixed interval and
/// hoping — which is how a suite becomes flaky on a loaded machine. Every wait
/// here polls for the condition and fails with what it saw.
const PATIENCE: Duration = Duration::from_secs(20);

/// A repository whose `batten.toml` declares `manage_process_group = <opt_in>`.
fn repo(name: &str, opt_in: bool) -> PathBuf {
    let config = if opt_in {
        "version = 1\n\n[exec]\nmanage_process_group = true\n"
    } else {
        "version = 1\n"
    };
    Fixture::new(name)
        .config(config)
        .git()
        .base_commit()
        .build()
}

/// A `#!/bin/sh` fixture child, executable, that runs `body`.
fn script(dir: &Path, body: &str) -> PathBuf {
    script_named(dir, "child.sh", body)
}

/// The same, under a caller-chosen name.
///
/// Needed the moment one case wants TWO scripts in one fixture directory: with a
/// single hard-coded name the second write silently replaces the first, and a
/// wrapper that ends up invoking itself is the shape that produced 69 iterations
/// of a five-iteration loop here before this existed.
fn script_named(dir: &Path, name: &str, body: &str) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let path = dir.join(name);
    fs::write(&path, format!("#!/bin/sh\n{body}\n")).expect("write child");
    let mut mode = fs::metadata(&path).expect("stat child").permissions();
    mode.set_mode(0o755);
    fs::set_permissions(&path, mode).expect("chmod child");
    path
}

/// Say why a case was skipped.
///
/// Not `eprintln!`: the workspace denies the print macros because Batten's own
/// output is a byte-stable contract, and a test target inherits the lint.
fn skipped(reason: &str) {
    use std::io::Write as _;
    drop(writeln!(std::io::stderr(), "{reason}"));
}

/// Whether `pid` still names a live process.
///
/// `kill -0` rather than `/proc`: the question is POSIX and `/proc` is Linux's
/// answer to it, and this suite already runs on macOS.
#[expect(
    clippy::disallowed_types,
    reason = "stays, and test-only: `kill -0` is the POSIX spelling of the question, and this suite runs on macOS too where `/proc` is not an answer"
)]
fn alive(pid: i32) -> bool {
    Command::new("kill")
        .args(["-0", &pid.to_string()])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("run kill -0")
        .success()
}

/// Send `signal` to `pid`, by name (`TERM`, `INT`, `KILL`).
fn signal(pid: u32, name: &str) {
    #[expect(
        clippy::disallowed_types,
        reason = "stays, and test-only: delivering a real signal to a real pid is the whole of what the forwarding protocol is asserted against"
    )]
    let sent = Command::new("kill")
        .args([&format!("-{name}"), &pid.to_string()])
        .status()
        .expect("run kill");
    assert!(sent.success(), "could not send {name} to {pid}");
}

/// Block until `path` exists and is non-empty, then read it trimmed.
fn await_file(path: &Path) -> String {
    let deadline = Instant::now() + PATIENCE;
    while Instant::now() < deadline {
        if let Ok(text) = fs::read_to_string(path)
            && !text.trim().is_empty()
        {
            return text.trim().to_owned();
        }
        #[expect(
            clippy::disallowed_methods,
            reason = "the interval of a poll whose exit condition is `read_to_string` returning \
                      something non-empty, bounded by `PATIENCE` — past that this panics rather \
                      than waiting longer (CLOUD-1177)"
        )]
        std::thread::sleep(Duration::from_millis(20));
    }
    panic!("{} never appeared", path.display());
}

/// Block until `pid` is gone, reporting whether it got there in time.
fn await_death(pid: i32) -> bool {
    let deadline = Instant::now() + PATIENCE;
    while Instant::now() < deadline {
        if !alive(pid) {
            return true;
        }
        #[expect(
            clippy::disallowed_methods,
            reason = "the interval of a poll whose exit condition is `alive` going false, bounded \
                      by `PATIENCE` — the bound is the ANSWER here, since running out is what this \
                      reports as `false` (CLOUD-1177)"
        )]
        std::thread::sleep(Duration::from_millis(20));
    }
    false
}

/// Spawn `batten exec -- <script>` in `dir`, with state under `home`.
fn spawn_exec(dir: &Path, home: &Path, child: &Path, env: &[(&str, &str)]) -> Child {
    fs::create_dir_all(home).expect("create home");
    let mut command = common::batten();
    command
        .args(["exec", "--", child.to_str().expect("utf-8")])
        .current_dir(dir)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        // SCRUBBED, and this is the hermeticity that matters here: the whole
        // suite runs under `mise run verify`, which sets the very marker the
        // predicate reads. Inheriting it makes Batten decline — correctly — and
        // every "owned" case below then measures how the SUITE was launched
        // rather than what Batten decided. Measured: three cases passed run
        // directly and failed under the gate, for exactly this reason.
        //
        // A case that wants the marker sets it back through `env`, below.
        .env_remove("MISE_TASK_PGID_MANAGED");
    for (key, value) in env {
        command.env(key, value);
    }
    command.state_home(home).spawn().expect("spawn batten exec")
}

/// A child that leaves a grandchild running and then parks.
///
/// The shape that leaks today: a wrapped command whose own children outlive the
/// signal, which is every `mise run` — mise, a subshell, a `cargo`, an `rustc`
/// per crate.
fn leaky_child(dir: &Path) -> (PathBuf, PathBuf) {
    let note = dir.join("grandchild.pid");
    let body = format!(
        "sleep 300 &\nprintf '%s' \"$!\" > {note}\nwait\n",
        note = note.display()
    );
    (script(dir, &body), note)
}

#[test]
fn an_owned_tree_dies_whole_when_batten_is_signalled() {
    // The primary case, and the acceptance clause verbatim: signalled at
    // Batten's pid ALONE, no member of the tree is left alive, asserted by pid.
    let dir = repo("pgroup-owned", true);
    let home = scratch("pgroup-owned-home");
    let (child, note) = leaky_child(&dir);

    let mut batten = spawn_exec(&dir, &home, &child, &[]);
    let grandchild: i32 = await_file(&note).parse().expect("a pid");
    signal(batten.id(), "TERM");

    let status = batten.wait().expect("batten exits");
    // THE ASSERTION CHANGED BECAUSE THE ANSWER CHANGED (CLOUD-746 S2). It read
    // `code() == Some(128 + 15)` until then. Batten no longer reports its own
    // death as an exit code: it dies of the signal, so a parent's `waitpid` sees
    // `WIFSIGNALED` and `code()` is `None`. A shell still sets `$?` to 143.
    assert_eq!(
        status.signal(),
        Some(15),
        "Batten dies OF the signal it was sent, rather than describing itself \
         with a convention meant for describing a child"
    );
    assert_eq!(
        status.code(),
        None,
        "a signalled process has no exit code — that is the whole difference"
    );
    assert!(
        await_death(grandchild),
        "the grandchild at {grandchild} outlived the supervisor that dispatched it"
    );
}

#[test]
fn an_unowned_tree_survives_because_the_opt_in_is_off() {
    // The pair to the case above, and this suite's mutation check. With nothing
    // declared, `exec` behaves exactly as it did before CLOUD-427 — which means
    // the grandchild IS orphaned. A rig that killed the tree here would have
    // passed the case above while measuring nothing at all.
    let dir = repo("pgroup-default", false);
    let home = scratch("pgroup-default-home");
    let (child, note) = leaky_child(&dir);

    let mut batten = spawn_exec(&dir, &home, &child, &[]);
    let grandchild: i32 = await_file(&note).parse().expect("a pid");
    signal(batten.id(), "TERM");
    let _ = batten.wait().expect("batten exits");

    assert!(
        alive(grandchild),
        "with the opt-in off the topology must be unchanged, orphan and all"
    );
    // Left running otherwise, and a `sleep 300` in `target/` outliving the suite
    // is the same untidiness this issue is about.
    signal(u32::try_from(grandchild).expect("a positive pid"), "KILL");
}

#[test]
fn an_interrupt_is_reported_as_the_interrupt_batten_received() {
    // The second of the two signals the acceptance clause names. Separate from
    // TERM because the mapping is `128 + received` rather than a constant, and a
    // single case cannot tell those apart.
    let dir = repo("pgroup-interrupt", true);
    let home = scratch("pgroup-interrupt-home");
    let (child, note) = leaky_child(&dir);

    let mut batten = spawn_exec(&dir, &home, &child, &[]);
    let grandchild: i32 = await_file(&note).parse().expect("a pid");
    signal(batten.id(), "INT");

    // Was `code() == Some(128 + 2)`; see the TERM case for why it moved. Kept as
    // a separate case for its original reason: the mapping is the signal Batten
    // RECEIVED rather than a constant, and one case cannot tell those apart.
    assert_eq!(
        batten.wait().expect("batten exits").signal(),
        Some(2),
        "an INT to Batten kills Batten with INT, whatever the child fell to"
    );
    assert!(await_death(grandchild), "the tree still dies whole");
}

#[test]
fn a_second_signal_escalates_instead_of_being_swallowed() {
    // CLOUD-746 S1, and it is red against the old forwarder. That worker took
    // ONE signal off the stream and then never read it again — but
    // `Signals::new` had already replaced the default disposition, so a second
    // Ctrl-C inside the 5s grace was caught, queued in an iterator nobody read,
    // and did nothing. Worse than missing: before the forwarder existed a second
    // Ctrl-C killed Batten outright, so installing it took that away and put
    // nothing back.
    //
    // The child IGNORES TERM, which is what makes the grace observable at all: a
    // child that dies on the first signal would reach the same end state either
    // way and this case would measure nothing.
    let dir = repo("pgroup-second", true);
    let home = scratch("pgroup-second-home");
    let note = dir.join("grandchild.pid");
    let child = script(
        &dir,
        &format!(
            "trap '' TERM\nsleep 300 &\nprintf '%s' \"$!\" > {note}\nwait\n",
            note = note.display()
        ),
    );

    let mut batten = spawn_exec(&dir, &home, &child, &[]);
    let grandchild: i32 = await_file(&note).parse().expect("a pid");

    let started = Instant::now();
    signal(batten.id(), "TERM");
    // The second signal has to land INSIDE the grace window the first opened,
    // or this measures the ordinary escalation. Wait for the forwarder to have
    // taken the first — the group is still alive because the child traps it.
    std::thread::sleep(Duration::from_millis(250));
    signal(batten.id(), "TERM");

    let _ = batten.wait().expect("batten exits");
    let waited = started.elapsed();
    assert!(
        await_death(grandchild),
        "the tree must still die whole on the escalation"
    );
    // GROUP_GRACE is 5s. A second signal that escalates immediately gets there
    // well inside it; a swallowed one waits the whole grace out. The bound is
    // generous rather than tight, because the claim is "promptly, not after the
    // full grace" and a tight bound would flake on a loaded runner instead of
    // discriminating.
    assert!(
        waited < Duration::from_secs(4),
        "a second signal must escalate rather than queue in a stream nobody \
         reads — the teardown took {waited:?}, which is the full grace"
    );
}

#[test]
fn a_signal_in_the_spawn_window_leaves_no_orphan() {
    // CLOUD-746 S3. The forwarder used to be installed AFTER the spawn, with two
    // `Drain::spawn` and two `Spool::open` calls in between — real file IO, not a
    // couple of instructions. A signal landing there killed Batten by default
    // disposition and orphaned the group.
    //
    // LOOPED, because the window is timing-dependent and a single pass proves
    // nothing: the acceptance says so in as many words. Each iteration signals
    // at a different offset, so the sweep walks across the window rather than
    // sampling one point in it.
    let home = scratch("pgroup-window-home");
    let mut orphans = Vec::new();
    for attempt in 0_u64..12 {
        let dir = repo(&format!("pgroup-window-{attempt}"), true);
        let (child, note) = leaky_child(&dir);
        let mut batten = spawn_exec(&dir, &home, &child, &[]);

        // Walk the offset across the spawn/install window rather than guessing
        // one value for it.
        std::thread::sleep(Duration::from_micros(200 * attempt));
        signal(batten.id(), "TERM");
        let _ = batten.wait().expect("batten exits");

        // The grandchild may not exist at all — the signal can land before the
        // child got that far, which is a clean outcome rather than a miss. What
        // must never happen is one that exists and outlives Batten.
        if let Ok(text) = fs::read_to_string(&note)
            && let Ok(pid) = text.trim().parse::<i32>()
            && !await_death(pid)
        {
            orphans.push(pid);
            signal(u32::try_from(pid).expect("a positive pid"), "KILL");
        }
    }
    assert!(
        orphans.is_empty(),
        "a signal in the spawn/install window orphaned the group: {orphans:?}"
    );
}

#[test]
fn a_signalled_child_is_still_reported_as_a_code_rather_than_re_raised() {
    // THE OTHER SIDE OF S2's BOUNDARY, and the case that makes the pair mean
    // something. Batten dying of a signal it was SENT is one thing; a CHILD that
    // died of a signal is a different one, and that one is still reported as
    // `128 + N` — there Batten is describing the child, which is correct and
    // must not change.
    //
    // Without this, "Batten dies of the signal" is satisfied by a build that
    // re-raises whenever anything anywhere was signalled, which would make every
    // `batten exec` wrapping a killed command kill its own caller too.
    let dir = repo("pgroup-child-signal", true);
    let home = scratch("pgroup-child-signal-home");
    let child = script_named(&dir, "child.sh", "kill -TERM $$\n");

    let mut batten = spawn_exec(&dir, &home, &child, &[]);
    let status = batten.wait().expect("batten exits");

    assert_eq!(
        status.signal(),
        None,
        "Batten was not signalled, so Batten must not die of one"
    );
    assert_eq!(
        status.code(),
        Some(128 + 15),
        "a child that died of a signal is described with the shell's own \
         convention, which is what `128 + N` is for"
    );
}

// THE SHELL-LOOP CASE CLOUD-746's ACCEPTANCE NAMES IS NOT HERE, and this note is
// the finding rather than an omission. The clause asks that
// `for f in …; do batten exec -- …; done` interrupted by SIGINT stops looping,
// on the premise that a shell aborts a loop by checking `WIFSIGNALED`.
//
// Measured on this image, bash 5.2.21, with a child that genuinely dies of INT:
//
//     $ bash -c 'for i in 1 2 3; do bash -c "kill -INT \$\$"; \
//                printf "iter%s rc=%s " "$i" "$?"; done; echo loop-finished'
//     iter1 rc=130 iter2 rc=130 iter3 rc=130 loop-finished
//
// The loop runs to completion. What DOES stop it is the shell receiving the
// signal itself — which is what happens at a terminal, because Ctrl-C goes to
// the whole foreground process group and reaches the shell whatever the child
// reports. So the premise does not hold for a non-interactive shell where only
// the child is signalled, and a case written against it would either fail
// honestly or be contorted until it passed while measuring the shell rather
// than Batten.
//
// S2 is unaffected and still right: a `waitpid` caller gains `WIFSIGNALED`,
// which is strictly more information, and that IS asserted — by
// `an_owned_tree_dies_whole_when_batten_is_signalled` and
// `an_interrupt_is_reported_as_the_interrupt_batten_received` reading
// `status.signal()`, paired with the case above keeping a signalled CHILD on
// `128 + N`. Only the worked example was wrong. Recorded on CLOUD-746.

#[test]
fn the_capture_is_sealed_before_the_re_raise() {
    // THE ORDERING THAT LICENSES RE-RAISING AT ALL. Batten now dies of the signal
    // it was sent, and the whole reason that is safe rather than abrupt is that
    // it happens AFTER the drains are collected and the captures sealed. A
    // re-raise moved earlier would lose the record, and nothing else in this
    // suite would notice.
    //
    // Byte-identical to the same command run to completion is the assertion,
    // because "a capture exists" would pass over a truncated one.
    let dir = repo("pgroup-sealed", true);
    let home = scratch("pgroup-sealed-home");
    let said = "the child speaks before it is stopped";

    // Says its piece, then parks. The signal lands after the bytes are through
    // the pipe, so a correct teardown seals exactly what a clean run would.
    let child = script_named(
        &dir,
        "child.sh",
        &format!("printf '%s\\n' '{said}'\nsleep 300\n"),
    );
    let mut batten = spawn_exec(&dir, &home, &child, &[]);
    // The bytes have to be through the drain before the signal, or this measures
    // a race rather than the ordering.
    std::thread::sleep(Duration::from_millis(700));
    signal(batten.id(), "TERM");
    let _ = batten.wait().expect("batten exits");

    // The same command, run to completion, is the comparand.
    let clean_dir = repo("pgroup-sealed-clean", true);
    let clean_home = scratch("pgroup-sealed-clean-home");
    let clean_child = script_named(
        &clean_dir,
        "child.sh",
        &format!("printf '%s\\n' '{said}'\n"),
    );
    let mut clean = spawn_exec(&clean_dir, &clean_home, &clean_child, &[]);
    let _ = clean.wait().expect("batten exits");

    let signalled = newest_capture(&home);
    let completed = newest_capture(&clean_home);
    assert!(
        !signalled.is_empty(),
        "a signalled run must still have sealed the bytes its child produced"
    );
    assert_eq!(
        signalled, completed,
        "the capture sealed before the re-raise must be byte-identical to the \
         same command run to completion"
    );
}

/// The largest stdout capture under `home`'s store, or empty when there is none.
///
/// By content rather than by handle: the two runs are different processes in
/// different repositories, so their handles differ by construction and only the
/// BYTES are comparable — which is what the acceptance clause is about.
fn newest_capture(home: &Path) -> Vec<u8> {
    fn walk(dir: &Path, found: &mut Vec<Vec<u8>>) {
        let Ok(entries) = fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(&path, found);
            } else if let Ok(bytes) = fs::read(&path)
                && !bytes.is_empty()
            {
                found.push(bytes);
            }
        }
    }
    let mut found = Vec::new();
    walk(home, &mut found);
    found
        .into_iter()
        .filter(|bytes| std::str::from_utf8(bytes).is_ok_and(|text| text.contains("speaks")))
        .max_by_key(Vec::len)
        .unwrap_or_default()
}

/// A child that writes its own pid and process-group id, and the marker it was
/// handed, then exits.
fn reporting_child(dir: &Path) -> (PathBuf, PathBuf) {
    let note = dir.join("topology");
    let body = format!(
        "printf '%s %s %s' \"$$\" \"$(ps -o pgid= -p $$ | tr -d ' ')\" \
         \"${{MISE_TASK_PGID_MANAGED:-absent}}\" > {note}\n",
        note = note.display()
    );
    (script(dir, &body), note)
}

/// `(pid, pgid, marker)` as the wrapped child saw them.
fn topology(dir: &Path, home: &Path, env: &[(&str, &str)]) -> (String, String, String) {
    let (child, note) = reporting_child(dir);
    let mut batten = spawn_exec(dir, home, &child, env);
    let _ = batten.wait().expect("batten exits");
    let seen = await_file(&note);
    let mut fields = seen.split_whitespace();
    (
        fields.next().expect("a pid").to_owned(),
        fields.next().expect("a pgid").to_owned(),
        fields.next().expect("a marker").to_owned(),
    )
}

#[test]
fn an_owned_child_leads_its_own_group_and_carries_the_marker() {
    // The two halves of grouping, asserted together because either alone is a
    // regression: a group with no marker means a nested mise groups again and
    // Batten's killpg reaches mise rather than the leaves.
    let dir = repo("pgroup-topology", true);
    let home = scratch("pgroup-topology-home");
    let (own, group, marker) = topology(&dir, &home, &[]);
    assert_eq!(
        own, group,
        "an owned child leads the group Batten made for it"
    );
    assert_eq!(marker, "1", "and a nested manager is told to stand down");
}

#[test]
fn an_ancestors_marker_makes_batten_decline() {
    // mise's first decline rule, live. The marker in Batten's own environment
    // says an ancestor is already managing, so Batten must NOT make a second
    // group under it — that is the exact arrangement whose killpg reaches the
    // inner manager and leaks the leaves.
    let dir = repo("pgroup-marked", true);
    let home = scratch("pgroup-marked-home");
    let (own, group, _) = topology(&dir, &home, &[("MISE_TASK_PGID_MANAGED", "1")]);
    assert_ne!(
        own, group,
        "with an ancestor managing, the child stays in the group it inherited"
    );
}

#[test]
fn a_session_leader_declines_even_with_the_opt_in_on() {
    // mise's second decline rule. `setsid` is what makes Batten its own session
    // leader, and a session leader manages nothing an ancestor was not already
    // placed to manage.
    //
    // `setsid` is util-linux rather than POSIX, so where it is absent the live
    // reading cannot be taken at all. The rule is still covered by
    // `GroupDecision::decide`'s unit case; what is skipped here is the
    // observation, and the case says so out loud rather than passing quietly.
    #[expect(
        clippy::disallowed_types,
        reason = "stays, and test-only: probing for `setsid` is asking the host a question about itself, and the case says out loud when the live reading is skipped"
    )]
    if !Command::new("sh")
        .args(["-c", "command -v setsid >/dev/null"])
        .status()
        .expect("probe for setsid")
        .success()
    {
        skipped(
            "process_group: `setsid` is not installed, so the session-leader rule's LIVE \
             reading is skipped; the predicate itself is covered in exec.rs's unit tests",
        );
        return;
    }

    let dir = repo("pgroup-session", true);
    let home = scratch("pgroup-session-home");
    fs::create_dir_all(&home).expect("create home");
    let (child, note) = reporting_child(&dir);

    // Built by hand rather than through `common::batten()`, because the program
    // being run is `setsid` and Batten is its argument. `--wait` keeps the status
    // meaningful: without it `setsid` returns the moment it has forked.
    #[expect(
        clippy::disallowed_types,
        reason = "stays, and test-only: `setsid` is what makes Batten a session leader, which is mise's second decline rule and cannot be observed without it"
    )]
    let mut command = Command::new("setsid");
    command
        .arg("--wait")
        .arg(env!("CARGO_BIN_EXE_batten"))
        .args(["exec", "--", child.to_str().expect("utf-8")])
        .current_dir(&dir)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        // For `spawn_exec`'s reason: this case must decline on the SESSION-LEADER
        // rule, and an inherited marker would make it decline on the other one —
        // passing while measuring nothing it claims to.
        .env_remove("MISE_TASK_PGID_MANAGED");
    command.state_home(&home);
    let status = command.status().expect("run batten under setsid");
    assert!(status.success(), "the wrapped child itself succeeds");

    let seen = await_file(&note);
    let mut fields = seen.split_whitespace();
    let own = fields.next().expect("a pid");
    let group = fields.next().expect("a pgid");
    assert_ne!(
        own, group,
        "a session leader declines, so the child keeps the inherited group"
    );
}

#[test]
fn a_clean_run_leaves_no_group_record_and_a_killed_one_does() {
    // `SIGKILL` cannot be caught, so the one case forwarding cannot help with is
    // the one case a record can. The asymmetry IS the design: the note exists
    // only while a group is owned, so its presence after the fact means a Batten
    // died holding one.
    let dir = repo("pgroup-record", true);
    let clean_home = scratch("pgroup-record-clean");
    let (child, _) = reporting_child(&dir);
    let mut batten = spawn_exec(&dir, &clean_home, &child, &[]);
    let _ = batten.wait().expect("batten exits");
    assert!(
        group_records(&clean_home).is_empty(),
        "a clean reap clears the note, so a clean run leaves nothing to read"
    );

    let killed_home = scratch("pgroup-record-killed");
    let (leaky, note) = leaky_child(&dir);
    let mut batten = spawn_exec(&dir, &killed_home, &leaky, &[]);
    let grandchild: i32 = await_file(&note).parse().expect("a pid");
    signal(batten.id(), "KILL");
    let _ = batten.wait().expect("batten exits");

    let records = group_records(&killed_home);
    assert_eq!(
        records.len(),
        1,
        "an uncatchable kill leaves exactly one note naming the orphaned group"
    );
    let recorded: i32 = records[0].trim().parse().expect("the note holds a pgid");
    assert!(
        recorded > 0,
        "the note is a pgid and nothing else — pointer-only, like every record here"
    );
    signal(u32::try_from(grandchild).expect("a positive pid"), "KILL");
}

/// The contents of every `exec/group.*` note under a scratch state home.
fn group_records(home: &Path) -> Vec<String> {
    let mut found = Vec::new();
    let mut stack = vec![home.join("data")];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("group."))
            {
                found.push(fs::read_to_string(&path).expect("read the note"));
            }
        }
    }
    found
}

#[test]
fn a_surviving_grandchild_cannot_hang_exec() {
    // The live hang CLOUD-162 introduced: EOF on the child's stdout arrives when
    // the LAST holder of the write end closes it, and a grandchild that
    // inherited it holds it open indefinitely. Run with the opt-in OFF, which is
    // the configuration a consumer has today, so the grandchild genuinely
    // survives and genuinely holds the pipe. Without the deadline this case does
    // not fail — it never returns.
    let dir = repo("pgroup-drain", false);
    let home = scratch("pgroup-drain-home");
    let note = dir.join("holder.pid");
    let child = script(
        &dir,
        &format!(
            "sleep 300 &\nprintf '%s' \"$!\" > {note}\n",
            note = note.display()
        ),
    );

    fs::create_dir_all(&home).expect("create home");
    let mut batten = common::batten()
        .args(["exec", "--", child.to_str().expect("utf-8")])
        .current_dir(&dir)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .state_home(&home)
        .spawn()
        .expect("spawn batten exec");
    let holder: i32 = await_file(&note).parse().expect("a pid");

    let started = Instant::now();
    let status = batten.wait().expect("batten exits rather than hanging");
    let took = started.elapsed();

    assert!(status.success(), "the wrapped command itself exited 0");
    assert!(
        took < Duration::from_mins(1),
        "exec must be bounded by the drain deadline, not by the grandchild: {took:?}"
    );
    signal(u32::try_from(holder).expect("a positive pid"), "KILL");
}
