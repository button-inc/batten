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

use crate::common;
use batten::capture::StreamedChild as _;

use std::fs;
use std::os::unix::process::ExitStatusExt as _;
use std::path::{Path, PathBuf};
#[expect(
    clippy::disallowed_types,
    reason = "stays, and test-only: the subject is a negotiated process-group protocol with mise's supervisor (CLOUD-427), which is only observable across real processes"
)]
use std::process::{Child, Command, Stdio};

use common::{Fixture, StateHome as _, scratch};

// EVERY WAIT HERE IS ON AN EVENT, NEVER A CLOCK (CLOUD-2789). A process's
// word arrives through a [`Note`], a tree's death is the EOF of the pipe it was
// handed as stdin ([`await_tree_gone`]), and anything a case holds alive blocks
// on the case's [`leash`] rather than sleeping out an interval. A mutant that
// suppresses an event hangs its case, and the mutation judge's per-case cut
// files that as the timeout it is; the leash is what ends every held process
// with the case however the case ends.

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

/// A FIFO a fixture process writes its word to, held open read-write by the
/// case — the `exec.rs` fixture's shape. A writer opens it with `1<>`, which
/// never blocks and never loses the bytes, because this end keeps the pipe
/// alive; [`Note::read`] blocks on the write itself.
struct Note {
    path: PathBuf,
    file: fs::File,
}

impl Note {
    /// Make the FIFO at `path` and hold it.
    #[expect(
        clippy::disallowed_types,
        reason = "stays, test-only: a FIFO is made by `mkfifo`, and no door in `common` makes one"
    )]
    fn at(path: PathBuf) -> Self {
        let made = Command::new("mkfifo")
            .arg(&path)
            .status()
            .expect("run mkfifo");
        assert!(made.success(), "mkfifo {}", path.display());
        let file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .expect("hold the fifo open");
        Self { path, file }
    }

    /// The path a script redirects to.
    fn shown(&self) -> std::path::Display<'_> {
        self.path.display()
    }

    /// Block until a write arrives — THE EVENT — and return it trimmed.
    fn read(&self) -> String {
        use std::io::Read as _;
        let mut said = [0_u8; 256];
        let read = (&self.file).read(&mut said).expect("read the note");
        String::from_utf8_lossy(&said[..read]).trim().to_owned()
    }
}

/// The FIFO every process a case holds alive blocks on, with `read _ < leash`:
/// no clock keeps it alive, and it ends at the case's exit, when the last
/// writer — this case's own end — closes, however the case ends.
fn leash(dir: &Path) -> Note {
    Note::at(dir.join("leash"))
}

/// Block until every process that holds the write end of `life` is gone: its
/// EOF, the event, and the whole of what "the tree died" means here.
fn await_tree_gone(mut life: std::io::PipeReader) {
    use std::io::Read as _;
    let mut rest = Vec::new();
    let _ = life.read_to_end(&mut rest);
}

/// [`spawn_exec`], with the tree holding the write end of a pipe as its stdin;
/// the read end is the case's. A script keeps it past a backgrounded command,
/// which a shell hands `/dev/null`, with `exec 3<&0`.
fn spawn_exec_held(
    dir: &Path,
    home: &Path,
    child: &Path,
    env: &[(&str, &str)],
) -> (Child, std::io::PipeReader) {
    let (life, held) = std::io::pipe().expect("a pipe for the tree to hold");
    let batten = exec_command(dir, home, child, env)
        .stdin(held)
        .spawn()
        .expect("spawn batten exec");
    (batten, life)
}

/// Spawn `batten exec -- <script>` in `dir`, with state under `home`.
fn spawn_exec(dir: &Path, home: &Path, child: &Path, env: &[(&str, &str)]) -> Child {
    exec_command(dir, home, child, env)
        .spawn()
        .expect("spawn batten exec")
}

/// The command [`spawn_exec`] spawns, for a case that configures it further —
/// capturing the stderr a teardown's recorded reason lands on.
fn exec_command(dir: &Path, home: &Path, child: &Path, env: &[(&str, &str)]) -> common::Batten {
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
    command.state_home(home);
    command
}

/// A child that leaves a grandchild running and then parks.
///
/// The shape that leaks today: a wrapped command whose own children outlive the
/// signal, which is every `mise run` — mise, a subshell, a `cargo`, an `rustc`
/// per crate.
fn leaky_child(dir: &Path) -> (PathBuf, Note, Note) {
    let note = Note::at(dir.join("grandchild.pid"));
    let leash = leash(dir);
    let body = format!(
        "exec 3<&0\nread _ < {leash} &\nprintf '%s' \"$!\" 1<>{note}\nwait\n",
        leash = leash.shown(),
        note = note.shown()
    );
    (script(dir, &body), note, leash)
}

#[test]
fn an_owned_tree_dies_whole_when_batten_is_signalled() {
    // The primary case, and the acceptance clause verbatim: signalled at
    // Batten's pid ALONE, no member of the tree is left alive, asserted by pid.
    let dir = repo("pgroup-owned", true);
    let home = scratch("pgroup-owned-home");
    let (child, note, _leash) = leaky_child(&dir);

    let (mut batten, life) = spawn_exec_held(&dir, &home, &child, &[]);
    let grandchild: i32 = note.read().parse().expect("a pid");
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
    // THE TREE DIES WHOLE: the pipe every member holds reaches EOF. A grandchild
    // that outlived its supervisor holds it open and hangs the case, which the
    // judge's cut files as the timeout it is.
    assert!(grandchild > 0, "the grandchild said its pid");
    await_tree_gone(life);
}

#[test]
fn an_unowned_tree_survives_because_the_opt_in_is_off() {
    // The pair to the case above, and this suite's mutation check. With nothing
    // declared, `exec` behaves exactly as it did before CLOUD-427 — which means
    // the grandchild IS orphaned. A rig that killed the tree here would have
    // passed the case above while measuring nothing at all.
    let dir = repo("pgroup-default", false);
    let home = scratch("pgroup-default-home");
    let (child, note, _leash) = leaky_child(&dir);

    let mut batten = spawn_exec(&dir, &home, &child, &[]);
    let grandchild: i32 = note.read().parse().expect("a pid");
    signal(batten.id(), "TERM");
    let _ = batten.wait().expect("batten exits");

    assert!(
        alive(grandchild),
        "with the opt-in off the topology must be unchanged, orphan and all"
    );
    // Left running otherwise until the case's leash lets go, and a held process
    // outliving its case is the same untidiness this issue is about.
    signal(u32::try_from(grandchild).expect("a positive pid"), "KILL");
}

#[test]
fn an_interrupt_is_reported_as_the_interrupt_batten_received() {
    // The second of the two signals the acceptance clause names. Separate from
    // TERM because the mapping is `128 + received` rather than a constant, and a
    // single case cannot tell those apart.
    let dir = repo("pgroup-interrupt", true);
    let home = scratch("pgroup-interrupt-home");
    let (child, note, _leash) = leaky_child(&dir);

    let (mut batten, life) = spawn_exec_held(&dir, &home, &child, &[]);
    let grandchild: i32 = note.read().parse().expect("a pid");
    signal(batten.id(), "INT");

    // Was `code() == Some(128 + 2)`; see the TERM case for why it moved. Kept as
    // a separate case for its original reason: the mapping is the signal Batten
    // RECEIVED rather than a constant, and one case cannot tell those apart.
    assert_eq!(
        batten.wait().expect("batten exits").signal(),
        Some(2),
        "an INT to Batten kills Batten with INT, whatever the child fell to"
    );
    // The tree still dies whole: its pipe reaches EOF.
    assert!(grandchild > 0, "the grandchild said its pid");
    await_tree_gone(life);
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
    //
    // AND SO DOES THE GRANDCHILD, which this case once missed. A trapped TERM
    // ends the child's `wait` early, and a grandchild that dies on the forwarded
    // TERM leaves nothing to wait for: the script ran off its end, the group
    // emptied on its own, and a teardown timed against the grace passed with no
    // escalation at all. Reading the recorded reason is what exposed it
    // (CLOUD-2059). The grandchild is a subshell IGNORING TERM, held on the
    // case's leash, and the child waits until killed, so only an escalation ends
    // the group early.
    let dir = repo("pgroup-second", true);
    let home = scratch("pgroup-second-home");
    let note = Note::at(dir.join("grandchild.pid"));
    let leash = leash(&dir);
    // The trap RECORDS rather than just ignoring, so the first signal's arrival
    // at the group is observable. That is what lets the second signal be timed
    // against a real terminal state instead of a guessed delay.
    let trapped = Note::at(dir.join("trapped"));
    let child = script(
        &dir,
        &format!(
            "exec 3<&0\ntrap 'echo trapped 1<>{trapped}' TERM\n(trap '' TERM; read _ < {leash}) &\nprintf '%s' \"$!\" 1<>{note}\nwhile :; do wait; done\n",
            trapped = trapped.shown(),
            leash = leash.shown(),
            note = note.shown()
        ),
    );

    let (life, held) = std::io::pipe().expect("a pipe for the tree to hold");
    let batten = exec_command(&dir, &home, &child, &[])
        .stdin(held)
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn batten exec");
    let grandchild: i32 = note.read().parse().expect("a pid");

    signal(batten.id(), "TERM");
    // The second signal has to land INSIDE the grace window the first opened, or
    // this measures the ordinary escalation. Waiting for the trap marker is what
    // establishes that: it appears only once the forwarder has taken the first
    // signal and delivered it to the group, so the window is provably open. The
    // read blocks on the trap's write — the event, never a timer.
    assert_eq!(
        trapped.read(),
        "trapped",
        "the first signal reached the group, so the grace window is open"
    );
    signal(batten.id(), "TERM");

    let output = batten.streamed_wait().expect("batten exits");
    // The tree still dies whole on the escalation: its pipe reaches EOF.
    assert!(grandchild > 0, "the grandchild said its pid");
    await_tree_gone(life);
    // THE REASON IS RECORDED, SO THE CASE READS IT (CLOUD-2059). A second signal
    // that escalates does so at once and says `second-signal`; a swallowed one
    // queues in a stream nobody reads until `GROUP_GRACE` runs out, and the
    // teardown then says `grace-expired`. This used to tell the two apart by
    // timing the teardown against the grace, which a loaded runner can blur.
    let said = String::from_utf8_lossy(&output.stderr);
    assert!(
        said.contains("group escalated to SIGKILL (second-signal)"),
        "a second signal must escalate rather than queue in a stream nobody reads: {said}"
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
    //
    // THE OFFSET IS A COUNT, NEVER A CLOCK (CLOUD-2789): the window has no
    // observable state to wait on, so the sweep varies how much work this
    // thread does between the spawn and the signal, in spin hints, and reads
    // no time at all. It is the variable swept, not a wait for anything.
    /// How many offsets the sweep walks.
    const SWEEP: u32 = 12;
    /// The spin hints between offsets.
    const STEP: u32 = 20_000;

    let home = scratch("pgroup-window-home");
    for attempt in 0..SWEEP {
        let dir = repo(&format!("pgroup-window-{attempt}"), true);
        let (child, _note, _leash) = leaky_child(&dir);
        let (mut batten, life) = spawn_exec_held(&dir, &home, &child, &[]);

        // Walk the offset across the spawn/install window rather than guessing
        // one value for it.
        for _ in 0..STEP * attempt {
            std::hint::spin_loop();
        }
        signal(batten.id(), "TERM");
        let _ = batten.wait().expect("batten exits");

        // The grandchild may not exist at all — the signal can land before the
        // child got that far, which is a clean outcome rather than a miss. What
        // must never happen is one that exists and outlives Batten: it holds
        // the tree's pipe open, so this read never reaches EOF and the case
        // hangs, which the judge's cut files as the timeout it is. The leash
        // ends that orphan with the case.
        await_tree_gone(life);
    }

    // AND ONCE PAST THE WINDOW, ON AN EVENT (CLOUD-2936): the grandchild's note
    // is written only once Batten has spawned the tree and installed its
    // forwarder, so this attempt runs the whole path every swept attempt runs a
    // prefix of. Without it, how far the furthest attempt got was the
    // scheduler's draw, and one reach recording ran Batten's config load and
    // the next did not, with no code changed.
    let dir = repo("pgroup-window-past", true);
    let (child, note, _leash) = leaky_child(&dir);
    let (mut batten, life) = spawn_exec_held(&dir, &home, &child, &[]);
    let _grandchild = note.read();
    signal(batten.id(), "TERM");
    let _ = batten.wait().expect("batten exits");
    await_tree_gone(life);
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

    // Says its piece, marks that it has, then parks. The marker is what makes
    // "the bytes are through" observable — without it the signal below would be
    // timed by a guess, and a guess that fired early would measure a race rather
    // than the teardown ordering this case is about.
    let spoken = Note::at(dir.join("spoken"));
    let leash = leash(&dir);
    let child = script_named(
        &dir,
        "child.sh",
        &format!(
            "printf '%s\\n' '{said}'\necho spoken 1<>{spoken}\nread _ < {leash}\n",
            spoken = spoken.shown(),
            leash = leash.shown()
        ),
    );
    let mut batten = spawn_exec(&dir, &home, &child, &[]);
    // The read blocks on the marker's write — the event, never a timer.
    assert_eq!(
        spoken.read(),
        "spoken",
        "the child spoke, so there are bytes for the seal to be about"
    );
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
    // Read once the engine has exited, which is after its child wrote this.
    let seen = fs::read_to_string(&note).expect("the child wrote its topology");
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
    // `setsid` is util-linux rather than POSIX: on every Linux leg and on no
    // macOS one. The rule is still covered by `GroupDecision::decide`'s unit case;
    // the live reading is a `cfg!` arm, and a Linux host without `setsid` FAILS
    // rather than passing over an observation it never took (CLOUD-2059).
    if !cfg!(target_os = "linux") {
        return;
    }
    #[expect(
        clippy::disallowed_types,
        reason = "stays, and test-only: probing for `setsid` is asking the host a question about itself"
    )]
    let installed = Command::new("sh")
        .args(["-c", "command -v setsid >/dev/null"])
        .status()
        .expect("probe for setsid")
        .success();
    assert!(
        installed,
        "`setsid` is util-linux, installed on every Linux leg"
    );

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
        // `common::batten()`'s CLOUD-1951 mask, applied by hand for the reason
        // above: nothing this wraps may resolve an installed `batten` by name.
        .env("PATH", common::ambient_path())
        // For `spawn_exec`'s reason: this case must decline on the SESSION-LEADER
        // rule, and an inherited marker would make it decline on the other one —
        // passing while measuring nothing it claims to.
        .env_remove("MISE_TASK_PGID_MANAGED");
    command.state_home(&home);
    let status = command.status().expect("run batten under setsid");
    assert!(status.success(), "the wrapped child itself succeeds");

    // `--wait` returned, so the child has exited and written this.
    let seen = fs::read_to_string(&note).expect("the child wrote its topology");
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
    // THE NOTE IMPLIES THE PRECONDITION, by construction (CLOUD-2789). The
    // child would otherwise write its note concurrently with Batten's own drain
    // and spool setup, ahead of `GroupRecord::write` — and a `SIGKILL` landing
    // in that window leaves ZERO notes and fails a case that is about what
    // survives a kill, not about who won a race (measured: green in isolation,
    // red under a full `verify`). So the child spins on builtins until the
    // record exists and only then says its grandchild's pid: the wait is on the
    // record's arrival, never on a clock, and what is asserted below — that
    // exactly one note survives an uncatchable kill and holds a pgid — is
    // unchanged.
    let note = Note::at(dir.join("grandchild.pid"));
    let leash = leash(&dir);
    let records = killed_home
        .join("data")
        .join("*")
        .join("*")
        .join("exec")
        .join("group.*");
    let leaky = script_named(
        &dir,
        "leaky-after-record.sh",
        &format!(
            "exec 3<&0\nread _ < {leash} &\ng=$!\nuntil set -- {records}; [ -e \"$1\" ]; do :; done\nprintf '%s' \"$g\" 1<>{note}\nwait\n",
            leash = leash.shown(),
            records = records.display(),
            note = note.shown()
        ),
    );
    let mut batten = spawn_exec(&dir, &killed_home, &leaky, &[]);
    let grandchild: i32 = note.read().parse().expect("a pid");
    assert!(
        !group_records(&killed_home).is_empty(),
        "Batten never recorded the group it owns, so there is nothing for the \
         kill below to leave behind"
    );

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
    // The holder blocks on the case's leash — no clock keeps it alive — and so
    // holds both pipes until the case kills it or ends.
    let note = Note::at(dir.join("holder.pid"));
    let leash = leash(&dir);
    let child = script(
        &dir,
        &format!(
            "read _ < {leash} &\nprintf '%s' \"$!\" 1<>{note}\n",
            leash = leash.shown(),
            note = note.shown()
        ),
    );

    fs::create_dir_all(&home).expect("create home");
    let batten = common::batten()
        .args(["exec", "--", child.to_str().expect("utf-8")])
        .current_dir(&dir)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .state_home(&home)
        .spawn()
        .expect("spawn batten exec");
    let holder: i32 = note.read().parse().expect("a pid");

    // Returning at all is the first half: without the drain deadline this never
    // does, because the grandchild holds both pipes for as long as it lives.
    let output = batten
        .streamed_wait()
        .expect("batten exits rather than hanging");
    signal(u32::try_from(holder).expect("a positive pid"), "KILL");

    assert!(
        output.status.success(),
        "the wrapped command itself exited 0"
    );
    // ONE BUDGET, NOT TWO (CLOUD-1288), read from what the drain REPORTS rather
    // than from a clock (CLOUD-2059). The held grandchild inherits both pipes, so both
    // are leaked: stdout waits out what is left of the one budget, and stderr is
    // then left exactly nothing — it reports `0ns`. Collected with a fresh full
    // `PIPE_DRAIN_TIMEOUT` each, as the defect did, stderr would report the
    // whole budget instead; that cost 20.07s where the constant reads ten.
    let said = String::from_utf8_lossy(&output.stderr);
    assert!(
        said.contains("stdout did not reach EOF"),
        "the leaked stdout is reported, as a count: {said}"
    );
    assert!(
        said.contains("stderr did not reach EOF within 0ns"),
        "the two pipe drains share ONE deadline budget, so the second is left \
         nothing by the first: {said}"
    );
}

/// An owned tree ends WITH its child on the clean path too (CLOUD-2789): a
/// child that exits 0 leaving a grandchild on its stdout is followed by its
/// group, so the drain reaches EOF on the grandchild's death and the
/// grandchild does not outlive the `exec` that dispatched it.
///
/// Fails by: the clean path reaping the direct child only, as the
/// interrupted paths alone used to signal the group — the drain then waits out
/// its budget on the held pipe and reports it, and the grandchild lives on.
#[test]
fn an_owned_tree_ends_with_its_child_on_a_clean_exit() {
    let dir = repo("pgroup-clean-exit", true);
    let home = scratch("pgroup-clean-exit-home");
    // The grandchild blocks on the case's leash, not a clock, and holds the
    // tree's pipe, whose EOF is the event this case waits on (CLOUD-2789).
    let note = Note::at(dir.join("holder.pid"));
    let leash = leash(&dir);
    let child = script(
        &dir,
        &format!(
            "exec 3<&0\nread _ < {leash} &\nprintf '%s' \"$!\" 1<>{note}\n",
            leash = leash.shown(),
            note = note.shown()
        ),
    );

    let (life, held) = std::io::pipe().expect("a pipe for the tree to hold");
    let output = exec_command(&dir, &home, &child, &[])
        .stdin(held)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn batten exec")
        .streamed_wait()
        .expect("batten exits");
    let holder: i32 = note.read().parse().expect("a pid");

    let said = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "the wrapped command exited 0: {said}"
    );
    assert!(
        !said.contains("did not reach EOF"),
        "the grandchild was ended with its group, so both pipes closed: {said}"
    );
    // The grandchild at `holder` ends with its owned group: the tree's pipe
    // reaches EOF. One that outlived the clean exit holds it open and hangs the
    // case, which the judge's cut files as the timeout it is.
    assert!(holder > 0, "the grandchild said its pid");
    await_tree_gone(life);
}

/// A group whose leader and registrant are both gone, with a member that began
/// before the record's last stamp, is the orphan a reap may signal
/// (CLOUD-2366); the same group against a stamp no member predates is not.
///
/// Fails by: the live process table never consulted, so no orphan is ever
/// proven and nothing is reaped; or every group read as one.
#[test]
#[expect(
    clippy::disallowed_types,
    reason = "stays, and test-only: an orphaned group is a property of processes this one is not, so only a real spawn can leave one"
)]
fn a_group_its_leader_and_registrant_left_is_an_orphan() {
    use std::os::unix::process::CommandExt as _;

    let dir = scratch("pgroup-orphaned");
    let note = Note::at(dir.join("member.pid"));
    let leash = leash(&dir);
    // The member blocks on the case's leash, so no clock keeps it alive.
    let mut leader = Command::new("sh")
        .args([
            "-c",
            "read _ < \"$LEASH\" & printf '%s' \"$!\" 1<>\"$MEMBER_PID\"",
        ])
        .env("MEMBER_PID", &note.path)
        .env("LEASH", &leash.path)
        .process_group(0)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("a leader to leave its group");
    let group = leader.id().to_string();
    leader.wait().expect("the leader exits");
    let member: i32 = note.read().parse().expect("the member's pid");
    // A stamp every live member predates, fixed rather than read off the clock:
    // 2100-01-01, so no assertion here is about the time it ran.
    let stamped = 4_102_444_800;
    let orphaned = batten::collect::is_orphaned_group(&group, &group, stamped);
    let predated = batten::collect::is_orphaned_group(&group, &group, 0);
    signal(u32::try_from(member).expect("a pid"), "KILL");
    assert_eq!(
        orphaned,
        cfg!(any(target_os = "linux", target_os = "android")),
        "only a /proc reader proves an orphan"
    );
    assert!(!predated, "no member began before second 0");
}

/// A lap that takes the land singleton ends a running reach seed's whole
/// process group, frees its lock and leaves it owed, so the lap's gates never
/// queue behind a reach run and the seed starts over once the lap ends
/// (CLOUD-2842).
///
/// Fails by: the seed left running, its lock left held, or nothing owed.
#[test]
#[expect(
    clippy::disallowed_types,
    reason = "stays, and test-only: ending a seed's group is a property of a process this one is not, so only a real spawn can stand in for it"
)]
fn a_lap_taking_the_land_singleton_ends_a_running_reach_seed() {
    use std::os::unix::process::CommandExt as _;

    let repo = common::scratch_repo("pgroup-seed-preempt");
    let _ = common::scratch_state_root();
    let mut seed = Command::new("cat")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .process_group(0)
        .spawn()
        .expect("spawn a stand-in seed");
    let lock = repo
        .join(".git")
        .join("batten-singleton")
        .join(batten::mutate::resume::SEED_TASK);
    common::write(&lock, "pid", &format!("{}\n", seed.id()));
    assert!(
        batten::mutate::resume::preempt(&repo),
        "a live seed is ended"
    );
    let status = seed.wait().expect("the seed is reaped");
    assert!(
        status.signal().is_some(),
        "ended by a signal, not by its input: {status}"
    );
    assert!(!lock.exists(), "its lock is freed");
    let owed = batten::state::repo_state_dir(&repo)
        .expect("the state dir")
        .join("test-run")
        .join("seed-pending");
    assert!(owed.is_file(), "it is owed to the lap's end");
}
