//! The installed git hook body (CLOUD-476), driven from Rust — ported from
//! `tests/git-hook.bats` under CLOUD-843.
//!
//! `.claude/hooks/git-hook.sh` stays bash, and nothing else can do its job: it
//! runs where mise's shims are off `PATH`, before any batten is resolvable. It is
//! checked in precisely so it can be asserted here rather than only through an
//! installation, and this tier runs the committed file itself.
//!
//! Two properties carry the whole design, and each has a measured failure behind
//! it: `hk` is resolved through mise (bare `hk` is not on `PATH` in a cloud
//! container, and that is why no hook was installed at all for months), and the
//! gate refuses to re-enter itself (`doctor` runs inside the gate, so a hook run
//! from in there recurses — measured as a hung `git commit`, 2026-08-12).
//!
//! # A stub runner, never the real gate
//!
//! Each case puts a `mise` on `PATH` that records the argv it was called with AND
//! the marker the hook exported, so the re-entrancy assertions observe behaviour
//! rather than grep the source. The marker's liveness is read FROM INSIDE the
//! call the hook made, because it is only meaningful while the gate runs.
//!
//! # Unix only
//!
//! The subject is a bash program dispatched by the name of the symlink it is
//! invoked through, and its re-entrancy guard is `kill -0` over a pid. None of
//! that exists on Windows, where the retired suite never ran either.

#![cfg(unix)]
// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

// CLOUD-1268's fifth arm: the hook body is one of the four files that stay bash,
// so every arm names it as the survivor it still accounts for.
//
// ported: tests/git-hook.bats subject:.claude/hooks/git-hook.sh crates/batten/tests/it/git_hook.rs
// ported: "git-hook.bats::the hook body is executable and checked in" crates/batten/tests/it/git_hook.rs subject:.claude/hooks/git-hook.sh
// ported: "git-hook.bats::hk is resolved through mise, never bare — the failure that blocked installing a hook at all" crates/batten/tests/it/git_hook.rs subject:.claude/hooks/git-hook.sh
// ported: "git-hook.bats::probe mode asks the runner, and does NOT run the gate" crates/batten/tests/it/git_hook.rs subject:.claude/hooks/git-hook.sh
// ported: "git-hook.bats::a live gate marker is refused with exit 9, and spends nothing" crates/batten/tests/it/git_hook.rs subject:.claude/hooks/git-hook.sh
// ported: "git-hook.bats::a DEAD gate marker does not refuse — a stale marker must not disarm a real commit" crates/batten/tests/it/git_hook.rs subject:.claude/hooks/git-hook.sh
// ported: "git-hook.bats::the gate run exports a LIVE pid as the marker" crates/batten/tests/it/git_hook.rs subject:.claude/hooks/git-hook.sh
// ported: "git-hook.bats::the hook dispatches on the name it is invoked as" crates/batten/tests/it/git_hook.rs subject:.claude/hooks/git-hook.sh
// ported: "git-hook.bats::the hook disables the slow profile, which is what makes a commit fast" crates/batten/tests/it/git_hook.rs subject:.claude/hooks/git-hook.sh
// ported: "git-hook.bats::the gate's exit status is the hook's" crates/batten/tests/it/git_hook.rs subject:.claude/hooks/git-hook.sh

use crate::common;

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Output;

/// The committed hook body.
fn hook_body() -> PathBuf {
    common::at_root(".claude/hooks/git-hook.sh")
        .canonicalize()
        .expect("the hook body is checked in where the installation links to")
}

/// A case's scratch: a `bin/` carrying the recording `mise` stub, and the path its
/// calls are logged to.
struct Fixture {
    dir: PathBuf,
    calls: PathBuf,
}

impl Fixture {
    fn new(case: &str) -> Self {
        let dir = common::scratch(&format!("git-hook-{case}"));
        let calls = dir.join("mise-calls");
        let stub = format!(
            "#!/usr/bin/env bash\n\
             if [ -n \"${{BATTEN_GATE_PID:-}}\" ] && kill -0 \"$BATTEN_GATE_PID\" 2>/dev/null; then\n\
             \tmarker=\"$BATTEN_GATE_PID alive\"\n\
             else\n\
             \tmarker=\"${{BATTEN_GATE_PID:-none}} not-alive\"\n\
             fi\n\
             printf '%s | marker=%s\\n' \"$*\" \"$marker\" >>'{}'\n",
            calls.display()
        );
        stub_runner(&dir, &stub);
        Self { dir, calls }
    }

    /// Replace the recording stub with one that only exits `code`.
    fn runner_exits(&self, code: i32) {
        stub_runner(&self.dir, &format!("#!/usr/bin/env bash\nexit {code}\n"));
    }

    /// A link to the hook body named `hook`, which is how git invokes it: the
    /// body dispatches on `${0##*/}`, so every case goes through a link named
    /// like the real installation rather than through the file's own path.
    fn link(&self, hook: &str) -> PathBuf {
        let link = self.dir.join(hook);
        let _ = fs::remove_file(&link);
        std::os::unix::fs::symlink(hook_body(), &link).expect("link the hook body");
        link
    }

    /// Run `hook` through its link with `args`, the stub first on `PATH` and no
    /// inherited marker, plus `env`.
    fn run(&self, hook: &str, args: &[&str], env: &[(&str, &str)]) -> Output {
        let link = self.link(hook);
        let inherited = std::env::var_os("PATH").unwrap_or_default();
        let path = std::env::join_paths(
            std::iter::once(self.dir.join("bin")).chain(std::env::split_paths(&inherited)),
        )
        .expect("a PATH entry carries no separator");
        #[expect(
            clippy::disallowed_types,
            reason = "stays — CLOUD-843: the subject IS the checked-in hook program, so exercising it means running it; the retired suite made this same spawn"
        )]
        let mut command = std::process::Command::new(link);
        command
            .args(args)
            .current_dir(&self.dir)
            .env("PATH", path)
            .env_remove("BATTEN_GATE_PID")
            .env_remove("BATTEN_HOOK_PROBE");
        for (name, value) in env {
            command.env(name, value);
        }
        command.output().expect("the hook runs")
    }

    /// Every call the stub recorded, one per line; empty when it was never run.
    fn calls(&self) -> String {
        fs::read_to_string(&self.calls).unwrap_or_default()
    }
}

/// Write `body` as the executable `mise` in `dir/bin`.
fn stub_runner(dir: &Path, body: &str) {
    let bin = dir.join("bin");
    fs::create_dir_all(&bin).expect("create the stub dir");
    let stub = bin.join("mise");
    fs::write(&stub, body).expect("write the stub runner");
    fs::set_permissions(&stub, fs::Permissions::from_mode(0o755)).expect("make the stub runnable");
}

/// A pid that is certainly not live: the process that owned it has exited and
/// been reaped.
fn dead_pid() -> String {
    #[expect(
        clippy::disallowed_types,
        reason = "stays — CLOUD-843: a pid known to be dead is minted by letting a process exit, which is the retired suite's `bash -c 'echo $$'` without the shell"
    )]
    let mut child = std::process::Command::new("true")
        .spawn()
        .expect("spawn a short-lived process");
    let pid = child.id();
    child.wait().expect("reap it");
    pid.to_string()
}

#[test]
fn the_hook_body_is_executable_and_checked_in() {
    let mode = fs::metadata(hook_body())
        .expect("the hook body exists")
        .permissions()
        .mode();
    assert_ne!(mode & 0o111, 0, "the hook body is not executable");
    let tracked = common::git_in(
        &common::at_root("."),
        &["ls-files", "--", ".claude/hooks/git-hook.sh"],
    );
    assert_eq!(
        tracked, ".claude/hooks/git-hook.sh",
        "the hook body is not checked in"
    );
}

#[test]
fn hk_is_resolved_through_mise_never_bare() {
    let fixture = Fixture::new("through-mise");
    let output = fixture.run("pre-commit", &[], &[]);
    assert_eq!(output.status.code(), Some(0));
    assert!(
        fixture
            .calls()
            .lines()
            .any(|line| line.starts_with("exec -- hk run pre-commit")),
        "the gate was not run through mise: {}",
        fixture.calls()
    );
}

#[test]
fn probe_mode_asks_the_runner_and_does_not_run_the_gate() {
    // The narrow question doctor needs answered from inside the gate. Running the
    // gate to answer it is the recursion this exists to avoid.
    let fixture = Fixture::new("probe");
    let output = fixture.run("pre-commit", &[], &[("BATTEN_HOOK_PROBE", "1")]);
    assert_eq!(output.status.code(), Some(0));
    let calls = fixture.calls();
    assert!(
        calls
            .lines()
            .any(|line| line.starts_with("exec -- hk --version")),
        "probe mode did not ask the runner: {calls}"
    );
    assert!(
        !calls.contains("hk run"),
        "probe mode ran the gate: {calls}"
    );
}

#[test]
fn a_live_gate_marker_is_refused_with_exit_9_and_spends_nothing() {
    let fixture = Fixture::new("live-marker");
    let live = std::process::id().to_string();
    let output = fixture.run("pre-commit", &[], &[("BATTEN_GATE_PID", live.as_str())]);
    assert_eq!(output.status.code(), Some(9));
    let said = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(said.contains("gate is already running"), "{said}");
    assert!(
        said.contains(&live),
        "the refusal does not name the pid: {said}"
    );
    assert!(
        !fixture.calls.exists(),
        "a refused hook still reached the runner"
    );
}

#[test]
fn a_dead_gate_marker_does_not_refuse() {
    // The reason the marker is a pid rather than a boolean: a gate run that died
    // leaves its variable behind in every orphan, and refusing there would block
    // ordinary commits with no way to tell why.
    let fixture = Fixture::new("dead-marker");
    let dead = dead_pid();
    let output = fixture.run("pre-commit", &[], &[("BATTEN_GATE_PID", dead.as_str())]);
    assert_eq!(output.status.code(), Some(0));
    assert!(fixture.calls().contains("hk run pre-commit"));
}

#[test]
fn the_gate_run_exports_a_live_pid_as_the_marker() {
    // Read by the stub AS THE GATE RAN: the marker names a process that is alive
    // for the whole run, which is what makes the refusal above trustworthy.
    let fixture = Fixture::new("exports-marker");
    let output = fixture.run("pre-commit", &[], &[]);
    assert_eq!(output.status.code(), Some(0));
    let live = regex::Regex::new(r"marker=[0-9]+ alive").expect("a valid expression");
    assert!(
        live.is_match(&fixture.calls()),
        "the gate ran without a live marker: {}",
        fixture.calls()
    );
}

#[test]
fn the_hook_dispatches_on_the_name_it_is_invoked_as() {
    // One body, two hooks: hk.pkl defines pre-commit and commit-msg, and the
    // installation links both to this file. The hook's own arguments still reach
    // hk after the profile flag — asserted as two facts rather than one literal
    // argv, so adding a flag does not red a case about dispatch.
    let fixture = Fixture::new("dispatch");
    let output = fixture.run("commit-msg", &[".git/COMMIT_EDITMSG"], &[]);
    assert_eq!(output.status.code(), Some(0));
    let calls = fixture.calls();
    assert!(calls.contains("hk run commit-msg"), "{calls}");
    assert!(calls.contains(".git/COMMIT_EDITMSG"), "{calls}");
}

#[test]
fn the_hook_disables_the_slow_profile_which_is_what_makes_a_commit_fast() {
    // The other half of CLOUD-509's split, at its only switch-off point. If this
    // flag stops being passed, every commit pays the whole slow tier again.
    let fixture = Fixture::new("fast-profile");
    let output = fixture.run("pre-commit", &[], &[]);
    assert_eq!(output.status.code(), Some(0));
    let calls = fixture.calls();
    assert!(calls.contains("--profile"), "{calls}");
    assert!(calls.contains("!slow"), "{calls}");
}

#[test]
fn the_gates_exit_status_is_the_hooks() {
    let fixture = Fixture::new("exit-status");
    fixture.runner_exits(1);
    let output = fixture.run("pre-commit", &[], &[]);
    assert_eq!(output.status.code(), Some(1));
}
