//! Session-start provisioning, driven THROUGH the door, over the compiled binary
//! (CLOUD-312 row 10).
//!
//! # What retired, and what this is the second tier of
//!
//! `.claude/hooks/session-start.sh` was 295 lines of bash registered by path on
//! `SessionStart` — the last by-path registration on any surface this repository
//! owns. It did three separable things, and only one of them was its own:
//!
//! * it ORDERED a list of provisioning steps,
//! * it BOUNDED none of them,
//! * it wrapped each in a `step` helper that logged to a file and tailed five
//!   lines to stderr on failure.
//!
//! The first two are now `batten.toml`'s: ten `[[hook.handler]] on =
//! "session-start"` rows, whose declaration order IS the running order and whose
//! `timeout_ms` is imposed by the parent. The third stayed, as `mise.toml`'s
//! `session:*` tasks, because the door does not provide it.
//!
//! # Why the retired suite could not be this tier
//!
//! `tests/session-start.bats` ran the script directly and read what it printed.
//! That is the bash equivalent of a Rego module's `with input as`, and
//! `.claude/rules/policy-modules.md` names its failure exactly: it fabricates
//! the shape the ENGINE may be unable to consume. Its ordering case is the
//! sharpest instance — it stubbed `mise`, ran the hook, and grepped a call log
//! for line numbers. That observes bash, not dispatch. Here the same property is
//! read off `Dispatched`, which is the thing that will actually run it.
//!
//! # The stubs are the design, not a shortcut
//!
//! Every case below runs against a fixture repository whose handlers are stub
//! programs with a chosen exit status and stdout. Driving the REAL rows would
//! run `mise install`, `mise run doctor` and a release build — 141 seconds
//! measured cold (CLOUD-1085) — inside `test:cargo`, which is the cost
//! CLOUD-1268 exists to stop moving from one lane to another. It would also stop
//! discriminating: a case that provisions a container tests the container.
//!
//! The one case that reads the committed `batten.toml` reads it as a DOCUMENT,
//! asserting what is declared rather than running it. That split is deliberate —
//! the engine's behaviour is proved against stubs, and the declaration is proved
//! against the file that ships.
//!
//! # RETIREMENT LEDGER, PER PATH — what `shell-retirement` reads
//!
//! `.claude/hooks/session-start.sh` is not in `governed_when_deleted` (that set
//! is `mise-tasks/` paths and `.bats` suites), so it owes no arm. The suite does.
//!
//! The policy surface is `crates/batten/src/handler.rs`: the properties the
//! retired suite pinned about the SCRIPT — that it is synchronous, that it fails
//! loudly, that it does not tell the host to start early — are now properties of
//! the door, held for every dispatched program rather than re-derived in each.
//! `kind:mechanism` and not `kind:verb`: no command surface widened, and the
//! module is read by `batten hook`, which already existed.
//!
// carried: tests/session-start.bats crates/batten/src/handler.rs kind:mechanism crates/batten/tests/it/session_provisioning.rs
//!
//! # RETIREMENT LEDGER — `tests/session-start.bats`, 10 cases
//!
//! CARRIED — the property survives, proved here against the engine or against
//! the committed declaration.
//!
// carried: "doctor runs inside the synchronous window — after install, before the preflight" crates/batten/tests/it/session_provisioning.rs
// carried: "mise install runs — the step whose absence was the defect" crates/batten/tests/it/session_provisioning.rs
// carried: "the install is lockfile-free — provisioning must not dirty the tracked lock" crates/batten/tests/it/session_provisioning.rs
// carried: "a failed step exits non-zero — absence must never be silent" crates/batten/tests/it/session_provisioning.rs
// carried: "the hook is registered as a SessionStart hook" crates/batten/tests/it/session_provisioning.rs
//!
//! SUBSUMED — the property became the door's, held for every handler rather than
//! for this one program. Each names where it now lives.
//!
// subsumed: "the hook is executable" crates/batten/src/handler.rs kind:mechanism
// subsumed: "the hook is synchronous — async would restore the race it closes" crates/batten/src/handler.rs kind:mechanism
//!
//! CHANGED — the property is narrower than it was, and each of these is a real
//! fidelity loss rather than a relabelling. Stated at the granularity CLOUD-908
//! demands: what the case asserted, and what now holds instead.
//!
//! * `"the hook runs green on this checkout"` ran the WHOLE provisioning
//!   end to end and asserted exit 0 with empty stdout. The exit-0-and-silent half
//!   is carried below against stubs; the end-to-end half is gone, because
//!   dispatching the real rows means provisioning a container inside the test
//!   suite. What covers it instead is the session itself: a failed step now
//!   reports on the advisory channel at the moment it fails.
//! * `"running the hook leaves the tracked lockfile untouched"` was the
//!   end-to-end half of the CLOUD-223 residue check. `[settings] lockfile = false`
//!   in `mise.toml` is the authority and `mise run lock-complete` is the standing
//!   gate; what is lost is the observation that THIS provisioning path honours it,
//!   and `session:install` carrying `MISE_LOCKFILE=false` is asserted below as the
//!   declaration rather than as the effect.
//! * `"the git hooks are installed — the per-clone step that was absent"` ran the
//!   hook and then stat-ed two symlinks. `doctor` decides that same state on every
//!   later run — which the retired case's own comment already named as its
//!   backstop — and `tests/git-hook.bats` owns what the installed body does. What
//!   is lost is the end-to-end pairing of the step with its effect in one case.
//!
// changed: "the hook runs green on this checkout" crates/batten/tests/it/session_provisioning.rs the exit-0-and-silent half survives as `a_step_that_passes_says_nothing`, against stubs; the END-TO-END half is withdrawn, because dispatching the real rows provisions a container inside `test:cargo` — 141s measured cold — which is the cost CLOUD-1268 exists to stop moving between lanes. What covers it instead is the session itself: a failed step reports on the advisory channel at the moment it fails
// changed: "running the hook leaves the tracked lockfile untouched" crates/batten/tests/it/session_provisioning.rs narrowed from the EFFECT to the DECLARATION: `the_install_step_is_declared_lockfile_free` asserts `session:install` carries MISE_LOCKFILE=false, where the retired case ran the hook and diffed `git status -- mise.lock`. `[settings] lockfile = false` in mise.toml is the standing authority and `lock-complete` the standing gate; what is lost is the observation that this particular path honours it
// changed: "the session-start hook calls it — the whole point is WHEN it runs" crates/batten/tests/it/session_provisioning.rs from `tests/container-preflight.bats`, whose own subject survives. The case grepped the retired script for `container-preflight`; the property — that a preflight nothing runs at startup is worthless — is now the `session-container-preflight` row, and its POSITION is asserted too, which the grep could not say
// changed: "the hook passes --degraded when provisioning failed" batten.toml the capability is gone rather than moved, and this is the one real loss in this retirement. `--degraded` told the preflight not to trust toolchain-dependent probes when an earlier step had failed, and it worked because the script carried a `fail` variable across its steps. Handlers share no state — each is its own process with its own outcome — so nothing can compute the flag. The consequence is bounded: a container whose install failed now gets the full probe set, so it may report a second symptom of one cause, and both refusals arrive in the same reply. Recovering it needs a fact the door does not carry; filed rather than papered over
// changed: "the fixer is wired: session-start runs it, so a clone is compliant before it commits" crates/batten/tests/it/session_provisioning.rs from `tests/commit-attribution.bats`, whose own subject (hk.pkl, mise.toml) survives. The case grepped the retired script for its `step attribution-identity` line; the property — that the identity fixer runs before a clone commits — is now the `session-attribution-identity` row, asserted by `the_committed_provisioning_declares_every_step_in_order`. It is CHANGED rather than CARRIED because the retired case pinned the invocation's exact spelling inside a program and this pins a row's presence and position in a list
// changed: "the git hooks are installed — the per-clone step that was absent" mise-tasks/doctor.sh narrowed from perform-and-assert in one case to assert-only: `doctor` decides that same state on every later run, which the retired case's own comment already named as its backstop, and `tests/git-hook.bats` owns what the installed body does. What is lost is the pairing of the step with its effect inside one case
//!
//! # UNIX ONLY, and the gate is load-bearing rather than tidy
//!
//! Every dispatch case below runs a `#!/bin/sh` stub as a `[[hook.handler]]` row.
//! On a Windows runner the spawn ladder cannot start the interpreter the shebang
//! names, so the door reports a could-not-run and forwards nothing — and the
//! cases that assert an ABSENCE would then pass for the wrong reason, which is
//! the vacuous-pass class this file exists to close. `connector_allow_door.rs`
//! gates its whole suite on the same rung, and the retired `.bats` suite never
//! ran on Windows either, so nothing is narrowed that was covered.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![cfg(unix)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::{Path, PathBuf};

use common::{at_root, git_in, scratch, stderr, stdout, write};

/// The committed rows, in declaration order, as this suite expects to find them.
///
/// A LIST RATHER THAN A COUNT, because a count cannot tell an added row from a
/// renamed one, and the ordering claim below needs the names anyway.
const DECLARED: [&str; 10] = [
    "session-stamp",
    "session-install",
    "session-submodules",
    "session-doctor",
    "session-batten",
    "session-git-hooks",
    "session-attribution-identity",
    "session-signing-posture",
    "session-container-preflight",
    "session-census",
];

/// A fixture repository carrying only what a case declares.
///
/// NO `[[rule]]` AT ALL, for `connector_allow_door.rs`'s reason: an engine row
/// producing a verdict of its own could stand in for the handler's, which is
/// exactly the substitution that hid CLOUD-312 row 5's dropped verdict for the
/// life of that migration.
struct Bench {
    repo: PathBuf,
}

/// What the door said to the host, and what it said about the handlers.
struct Door {
    out: String,
    err: String,
    code: Option<i32>,
}

impl Bench {
    /// Hand one `SessionStart` envelope to the engine.
    ///
    /// The two streams are kept apart deliberately: a handler's advisory reaches
    /// the host through Batten's own reply, and a contract violation is reported
    /// on stderr. Merging them is how a dropped verdict reads as a delivered one.
    fn session_start(&self) -> Door {
        use std::io::Write as _;

        let payload = serde_json::json!({
            "hook_event_name": "SessionStart",
            "session_id": "session-provisioning-fixture",
            "source": "startup",
        })
        .to_string();

        let mut child = common::batten()
            .current_dir(&self.repo)
            .args(["hook", "--harness", "claude-code"])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("the binary runs");
        child
            .stdin
            .take()
            .expect("stdin is piped")
            .write_all(payload.as_bytes())
            .expect("write stdin");
        let outcome = child.wait_with_output().expect("wait for batten");
        Door {
            out: stdout(&outcome),
            err: stderr(&outcome),
            code: outcome.status.code(),
        }
    }

    /// Write one stub step and declare it as a `session-start` handler body.
    fn step(&self, id: &str, body: &str) {
        let path = format!("steps/{id}");
        write(&self.repo, &path, &format!("#!/bin/sh\n{body}\n"));
        make_executable(&self.repo.join(&path));
    }
}

/// Build a fixture whose `batten.toml` declares `rows`, in order.
fn bench(name: &str, rows: &[(&str, u64)]) -> Bench {
    let dir = scratch(name);
    let repo = dir.join("repo");
    std::fs::create_dir_all(repo.join("steps")).expect("the fixture repo");

    let mut config = String::from("version = 1\n");
    for (id, timeout_ms) in rows {
        config.push_str(&format!(
            "\n[[hook.handler]]\nid = \"{id}\"\non = \"session-start\"\nrun = [\"steps/{id}\"]\ntimeout_ms = {timeout_ms}\nowner = \"CLOUD-312\"\nexpires = \"2027-02-28\"\n"
        ));
    }
    write(&repo, "batten.toml", &config);
    git_in(&repo, &["init", "-q", "-b", "main", "."]);

    Bench { repo }
}

// No `#[cfg(unix)]` pair here: the module gate above already decides the target,
// so a `#[cfg(not(unix))]` twin would be a definition nothing can reach.
fn make_executable(path: &Path) {
    use std::os::unix::fs::PermissionsExt as _;
    let mut mode = std::fs::metadata(path)
        .expect("the stub exists")
        .permissions();
    mode.set_mode(0o755);
    std::fs::set_permissions(path, mode).expect("the stub is runnable");
}

/// One `[[hook.handler]]` row, reduced to the three fields this suite asks
/// about.
struct Row {
    id: String,
    on: String,
    bounded: bool,
}

/// The committed `[[hook.handler]]` rows, in declaration order, read as TEXT.
///
/// **NOT `toml::from_str`, and the reason is measured rather than stylistic.**
/// The committed `batten.toml` does not round-trip through the `toml` crate this
/// workspace has in scope — it fails with `unexpected content, expected nothing`
/// — while the engine reads it every run. Making this suite depend on a second
/// parser agreeing with the engine's would be a second authority over what the
/// config says, and it would fail for a reason having nothing to do with the
/// property under test.
///
/// The scan is deliberately shallow and deliberately strict about its own
/// premise: it takes each `[[hook.handler]]` header and reads the `key = value`
/// lines up to the next table header. `every_handler_row_is_read` asserts the
/// scan actually found rows, so a header this repository re-spells cannot turn
/// every case below vacuous.
fn handler_rows() -> Vec<Row> {
    let text = std::fs::read_to_string(at_root("batten.toml"))
        .expect("the committed authority is readable");

    let mut rows = Vec::new();
    for block in text.split("\n[[hook.handler]]\n").skip(1) {
        let body = block.split("\n[").next().unwrap_or(block);
        let field = |key: &str| -> Option<String> {
            body.lines()
                .find_map(|line| line.strip_prefix(&format!("{key} = ")))
                .map(|value| value.trim().trim_matches('"').to_owned())
        };
        rows.push(Row {
            id: field("id").unwrap_or_default(),
            on: field("on").unwrap_or_default(),
            bounded: field("timeout_ms").is_some(),
        });
    }
    rows
}

/// The `session-start` rows, in declaration order.
fn session_rows() -> Vec<Row> {
    handler_rows()
        .into_iter()
        .filter(|row| row.on == "session-start")
        .collect()
}

// ---------------------------------------------------------------------------
// The engine's half: what the door does with what the declaration says.
// ---------------------------------------------------------------------------

#[test]
fn the_steps_run_in_declaration_order() {
    // CARRIES `"doctor runs inside the synchronous window — after install, before
    // the preflight"`, and it is a strictly better instrument than what it
    // replaces. The retired case stubbed `mise`, ran the script, and grepped the
    // stub's call log for line numbers — an observation about bash. Order is now
    // a property of `dispatch`, which iterates the handler table as the config
    // lists it, so this reads the thing that will actually run in a session.
    //
    // Three steps rather than two: with two, a dispatcher that reversed the list
    // and one that preserved it are distinguishable, but a dispatcher that sorted
    // by id is not — `first` and `second` happen to sort into the order they are
    // declared in. The ids below are declared in an order that no sort produces.
    let bench = bench(
        "session-order",
        &[("zulu", 5000), ("alpha", 5000), ("mike", 5000)],
    );
    let log = bench.repo.join("order.log");
    for id in ["zulu", "alpha", "mike"] {
        bench.step(
            id,
            &format!("printf '{id}\\n' >> \"$(dirname \"$0\")/../order.log\""),
        );
    }

    let door = bench.session_start();
    assert_eq!(door.code, Some(0), "session start allows: {}", door.err);

    let ran = std::fs::read_to_string(&log).expect("every step ran");
    assert_eq!(
        ran.lines().collect::<Vec<_>>(),
        ["zulu", "alpha", "mike"],
        "the declaration order is the running order"
    );
}

#[test]
fn a_failed_step_is_reported_rather_than_silent() {
    // CARRIES `"a failed step exits non-zero — absence must never be silent"`.
    //
    // The retired case asserted this by grepping the script for the string
    // `exit 1`, which is a claim about its source rather than about what a
    // session sees. Here a step actually fails and the reason has to arrive.
    //
    // `VIOLATION_EXIT` rather than `DENY_EXIT`: a provisioning failure is
    // "the thing you asked about is wrong", not a refusal of the call. At
    // `session-start` a deny would be demoted to advice anyway
    // (`Event::carries_a_verdict`), so exiting 2 would prove nothing this does
    // not — and it would misstate the step's own meaning in the exit table.
    let bench = bench("session-loud", &[("failing", 5000)]);
    bench.step(
        "failing",
        "echo '::error:: session-start: failing failed — see /tmp/x.log' >&2\nexit 1",
    );

    let door = bench.session_start();
    assert_eq!(
        door.code,
        Some(0),
        "a failed provisioning step never blocks the session"
    );
    let said = format!("{}{}", door.out, door.err);
    assert!(
        said.contains("session-start: failing failed"),
        "the step's own reason reaches the session, not just its exit code: {said}"
    );
}

#[test]
fn a_step_that_passes_says_nothing() {
    // CARRIES the silent half of `"the hook runs green on this checkout"`
    // (CLOUD-891: silence is the pass). The end-to-end half is `changed:` above.
    //
    // Asserted over BOTH streams, because a success line on stderr is the same
    // defect as one on stdout — the retired hook's `container-preflight` line
    // was on stdout and the argument against it was about the reader, not the
    // file descriptor.
    let bench = bench("session-silent", &[("quiet", 5000)]);
    bench.step("quiet", "exit 0");

    let door = bench.session_start();
    assert_eq!(door.code, Some(0));
    assert!(
        door.out.is_empty(),
        "a passing step announces nothing on stdout: {}",
        door.out
    );
    assert!(
        !door.err.contains("quiet"),
        "a passing step is not named on stderr either: {}",
        door.err
    );
}

#[test]
fn a_step_that_hangs_is_killed_at_its_declared_bound() {
    // SUBSUMES `"the hook is synchronous — async would restore the race it
    // closes"`, and it is the half that was never testable before.
    //
    // The retired case asserted that the script does not print `{"async": true}`.
    // That was the only spelling of the property available to it, and it is
    // weaker in both directions: the script could have been synchronous and
    // hung forever, which is what the absence of any bound made possible.
    //
    // Behind the door synchrony is structural — `run_one` waits for the child
    // before `dispatch` returns and `batten hook` replies — so what is worth
    // asserting is the thing that makes synchrony affordable: the bound. A step
    // declaring 300ms and sleeping 30s must not hold the session for 30s.
    //
    // THE ASSERTION IS ON THE WALL CLOCK AND THAT IS DELIBERATE, against
    // `.claude/rules/rust.md`'s standing preference for counters over timing:
    // the property here IS elapsed time, and a counter cannot express "was
    // killed early". The margin is two orders wide — 10s against a 30s sleep and
    // a 300ms bound — so it discriminates a working bound from an absent one
    // without discriminating a slow runner from a fast one.
    let bench = bench("session-bound", &[("hanging", 300)]);
    bench.step("hanging", "sleep 30");

    let started = std::time::Instant::now();
    let door = bench.session_start();
    let took = started.elapsed();

    assert_eq!(door.code, Some(0), "a timed-out step allows: {}", door.err);
    assert!(
        took < std::time::Duration::from_secs(10),
        "the declared bound is imposed by the parent, not hoped for: took {took:?}"
    );
}

#[test]
fn a_steps_stdout_is_interpreted_never_forwarded() {
    // SUBSUMES the other half of the async case, and it is why no handler can
    // reintroduce the race whatever it writes.
    //
    // The retired script was registered directly, so anything it put on stdout
    // went to the host verbatim — `{"async": true}` included, which is exactly
    // the window the MCP handshake lost. Behind the door stdout is read into
    // Batten's own types and re-rendered per harness, so a handler speaks to
    // BATTEN and never to the host.
    //
    // Asserted as "the bytes do not appear verbatim", not as "nothing is said":
    // the text is legitimately allowed to become advisory content, and a case
    // demanding silence would be asserting the wrong property and would break
    // the moment the advisory channel renders it.
    let bench = bench("session-passthrough", &[("talkative", 5000)]);
    bench.step("talkative", "printf '{\"async\": true}\\n'");

    let door = bench.session_start();
    assert_eq!(door.code, Some(0));
    assert!(
        !door.out.contains("{\"async\": true}"),
        "a handler's stdout is never forwarded to the host verbatim: {}",
        door.out
    );
}

// ---------------------------------------------------------------------------
// The declaration's half: what the committed authority actually says.
// ---------------------------------------------------------------------------

#[test]
fn the_committed_provisioning_declares_every_step_in_order() {
    // CARRIES `"the hook is registered as a SessionStart hook"`. That case read
    // `.claude/settings.json` and asserted a by-path command was present; the
    // registration this change removes. The property it was protecting — that
    // provisioning is actually wired to session start rather than merely written
    // down — is now the handler roster, so this is where it is asserted.
    let ids: Vec<String> = session_rows().into_iter().map(|row| row.id).collect();

    assert_eq!(
        ids, DECLARED,
        "the provisioning steps are declared, in the order they must run"
    );
}

#[test]
fn every_handler_row_is_read() {
    // THE ANTI-VACUITY CASE FOR THE SCAN ABOVE, and it is the reason the scan is
    // allowed to be shallow. `handler_rows` matches a literal table header; if
    // this repository ever spells one differently — an inline array, a rename —
    // the scan returns nothing, every `session_rows()` case below passes over an
    // empty list, and the suite reports green over a declaration it never read.
    // That is the silent-empty-answer class `.claude/rules/scanning.md` records
    // for a matcher pointed at an extensionless tree, one file over.
    let rows = handler_rows();
    assert!(
        rows.len() > DECLARED.len(),
        "the scan reads the handler table: the provisioning rows plus the \
         user-prompt-submit and pre-tool rows that predate them, found {}",
        rows.len()
    );
    assert!(
        rows.iter().any(|row| row.on == "user-prompt-submit"),
        "a row on another event is read too, so `session_rows` is filtering \
         rather than being all there is"
    );
}

#[test]
fn every_provisioning_step_declares_its_own_bound() {
    // NOT A CARRIED CASE — the retired suite had nothing like it, because the
    // script it tested had no bound to assert. It is here because the bound is
    // the one thing the door adds that the script could not have, and an
    // undeclared `timeout_ms` silently falls back to `DEFAULT_TIMEOUT` — five
    // seconds, chosen for handlers that read two `jq` documents. A cold
    // `mise install` under a five-second bound is the fail-open absence this
    // whole surface exists to close, arriving as a default nobody wrote.
    for row in session_rows() {
        assert!(
            row.bounded,
            "{} declares its own bound rather than inheriting the five-second default",
            row.id
        );
    }
}

#[test]
fn the_install_step_is_declared_lockfile_free() {
    // CARRIES `"the install is lockfile-free — provisioning must not dirty the
    // tracked lock"` (CLOUD-223), and `"mise install runs — the step whose
    // absence was the defect"` with it: both were greps over the retired
    // script's source, and the same fact now lives in the task the handler runs.
    //
    // READ FROM `mise.toml` RATHER THAN FROM THE HANDLER ROW, because that is
    // where it is: the row names `mise run session:install`, and the environment
    // assignment is inside that task's body. Asserting it on the row would be
    // asserting a spelling this change did not choose.
    let text = std::fs::read_to_string(at_root("mise.toml")).expect("mise.toml is readable");
    let body = text
        .split("[tasks.\"session:install\"]")
        .nth(1)
        .expect("the install step is a declared task")
        .split("\n[tasks")
        .next()
        .expect("the task body ends at the next table");

    assert!(
        body.contains("MISE_LOCKFILE=false"),
        "provisioning installs purely, so it cannot append a platform key `mise lock` \
         cannot produce and `lock-complete` rejects"
    );
    assert!(
        body.contains("mise install"),
        "the step whose absence was CLOUD-196 is the one this task performs"
    );
}

#[test]
fn no_by_path_registration_survives_on_the_session_start_surface() {
    // THE OTHER HALF OF THE RETIRED REGISTRATION CASE, in the direction that
    // matters now. That case asserted a by-path command was PRESENT; the point
    // of this change is that none is, so the assertion inverts rather than
    // disappearing — and inverting it is what stops the registration coming back
    // by hand while the handler rows sit unread beside it.
    //
    // `[hook] exclusive` is the capability that would decide this globally
    // (CLOUD-893) and it stays undeclared while `run-shape-guard` is registered
    // on `pre-tool` (CLOUD-856). This is that predicate for the one event this
    // change clears, which is what makes the clearing durable.
    let text = std::fs::read_to_string(at_root(".claude/settings.json"))
        .expect("the wiring file is readable");
    let settings: serde_json::Value = serde_json::from_str(&text).expect("the wiring file is JSON");

    let commands: Vec<&str> = settings["hooks"]["SessionStart"]
        .as_array()
        .expect("SessionStart is registered")
        .iter()
        .flat_map(|group| {
            group["hooks"]
                .as_array()
                .expect("a group carries hooks")
                .iter()
        })
        .filter_map(|hook| hook["command"].as_str())
        .collect();

    assert_eq!(
        commands,
        ["batten hook --harness claude-code"],
        "the engine is the only thing registered on session start; everything else \
         is a `[[hook.handler]]` row it dispatches"
    );
}
