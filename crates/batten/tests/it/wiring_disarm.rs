//! `batten wiring reclaim`'s script pass, over the compiled binary and a real
//! `$HOME` on disk.
//!
//! **The tier the unit cases structurally cannot reach (CLOUD-1704).** `disarm`
//! is a function over a path, so a unit case can pin its arms perfectly and say
//! nothing about the four things that actually decide whether the repair
//! happens: that the verb reads the config's rows at all, that it resolves the
//! caller's home rather than the repository, that it runs AFTER the registration
//! pass rather than instead of it, and that the exit code a `[[startup]]` row
//! consumes moves with a `foreign` script. Each of those is a wiring question
//! between the module and the binary, and each is exactly what a fabricated
//! document hides.
//!
//! **WHY A FIXTURE `$HOME` AND NOT THIS CONTAINER'S**, which here is sharper
//! than it is for the registration half. This container's real home carries the
//! two launcher scripts the row was filed about, and a suite pointed at it would
//! rewrite the box it is measuring — once, after which every later run asserts
//! over a state the first run destroyed. Worse than for `wiring_reclaim.rs`: a
//! settings file is regenerated next spawn, and so is a script, but a suite that
//! blanked the real Stop hook would also be silently disarming the very hook the
//! case (a) fixture exists to simulate.
//!
//! `common::at_home` sets `HOME` **and** `USERPROFILE` for the reason
//! `wiring_reclaim.rs`'s header records at length: `etcetera` reads the second
//! on Windows, and a POSIX-only override left half that suite passing over a
//! fixture never in play.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::PathBuf;

use common::{StateHome as _, scratch, stderr, stdout, write};

/// A stand-in for what a launcher writes: a script that exits non-zero and says
/// something, so "it no longer runs" is observable rather than assumed.
///
/// Deliberately NOT a copy of any real launcher's script. What the fixture needs
/// is a body that is not the shim and an exit code that is not `0`; copying a
/// vendor's program would put its artifact in this tree for no test value.
const ARMED: &str = "#!/bin/sh\necho 'the launcher hook ran' >&2\nexit 2\n";

/// The marker the fixture config declares.
const MARKER: &str = "neutralized-by-session-start";

struct Bench {
    repo: PathBuf,
    home: PathBuf,
}

impl Bench {
    fn script(&self, name: &str) -> PathBuf {
        self.home.join(".launcher").join(name)
    }

    fn body(&self, name: &str) -> String {
        std::fs::read_to_string(self.script(name)).expect("the script is readable")
    }

    fn reclaim(&self, args: &[&str]) -> (i32, String) {
        let outcome = self.run_in("disposable", &[&["wiring", "reclaim"], args].concat());
        (outcome.status.code().unwrap_or(-1), stderr(&outcome))
    }

    fn run_in(&self, environment: &str, args: &[&str]) -> std::process::Output {
        common::batten()
            .current_dir(&self.repo)
            .args(args)
            .at_home(&self.home)
            .env("BATTEN_ENVIRONMENT", environment)
            .output()
            .expect("the binary runs")
    }
}

/// A fixture repo whose config declares `rows`, and a fixture home.
///
/// The declared paths sit under `.launcher/` rather than any real harness's
/// directory: this suite is about the mechanism, and borrowing a vendor's layout
/// would make the case look like it depends on one.
fn bench(name: &str, rows: &str, scripts: &[(&str, &str)]) -> Bench {
    let dir = scratch(name);
    let repo = dir.join("repo");
    std::fs::create_dir_all(&repo).expect("the fixture repo");
    write(&repo, "batten.toml", &format!("version = 1\n{rows}"));
    // The published template rather than a fork: `git init` is 1,819 of the
    // suite's 9,476 git processes, and `fixture-forks` is the ratchet that stops
    // a new fixture putting one back.
    common::init_repo(&repo);

    let home = dir.join("home");
    std::fs::create_dir_all(home.join(".launcher")).expect("the fixture home");
    for (name, body) in scripts {
        let path = home.join(".launcher").join(name);
        std::fs::write(&path, body).expect("the fixture script");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
                .expect("the fixture script is executable");
        }
    }
    Bench { repo, home }
}

/// The one-row config every case but the multi-row ones uses.
fn one_row(path: &str) -> String {
    format!("[[wiring.disarm]]\npath = '.launcher/{path}'\nmarker = \"{MARKER}\"\n")
}

/// Case (a): a launcher body is replaced, and the result actually exits 0.
///
/// **Asserted by RUNNING the script**, not by reading its bytes. The whole claim
/// of the row is that the hook stops doing anything when the harness executes
/// it, and a shim that carried the marker but exited non-zero — a missing
/// shebang, a stray character — would satisfy every string assertion and fail
/// the only thing that matters.
///
/// **The platform split is `cfg!` INSIDE the case, never `#[cfg]` over it**
/// (`rules/rust.md`). The rewrite is the subject and it is the same on every
/// target, so the assertions about the bytes must compile and run everywhere;
/// only EXECUTING a `#!/bin/sh` file is POSIX-shaped, and that is the one part
/// the arm guards. An attribute here would delete the whole case on Windows and
/// leave the next edit to it discovered by CI.
#[test]
fn an_armed_script_is_replaced_by_a_shim_that_exits_zero() {
    let bench = bench("disarm-armed", &one_row("stop.sh"), &[("stop.sh", ARMED)]);

    let (status, err) = bench.reclaim(&["-y"]);
    assert_eq!(status, 0, "{err}");
    assert!(err.contains("disarmed 1 of 1 declared script(s)"), "{err}");
    assert!(err.contains("stop.sh shimmed"), "{err}");

    let body = bench.body("stop.sh");
    assert!(body.contains(MARKER), "{body}");
    assert!(!body.contains("the launcher hook ran"), "{body}");

    // The hook's own contract: a Stop hook is handed JSON on stdin. The shim
    // must answer 0 with nothing on either stream. POSIX-only: executing a file
    // by its shebang is what Windows does not do.
    if !cfg!(unix) {
        return;
    }
    // A SPAWN IS AN INVENTORY ROW (CLOUD-320), and this one earns its place: the
    // claim of the whole change is that the harness EXECUTES the shimmed file and
    // gets nothing, and only running it can say so. Reading the bytes would
    // assert the shim's text and leave every way a two-line script still fails to
    // run — a lost shebang, a lost mode bit — untested.
    #[expect(
        clippy::disallowed_types,
        reason = "stays: the hook contract IS an execution — the shim must exit 0 on the hook's own stdin, and no read of its bytes can establish that. A byte comparison passes over a shim that lost its shebang or its mode bit (CLOUD-320)"
    )]
    let run = std::process::Command::new(bench.script("stop.sh"))
        .stdin(std::process::Stdio::null())
        .output()
        .expect("the shim runs");
    assert_eq!(run.status.code(), Some(0));
    assert!(run.stdout.is_empty() && run.stderr.is_empty());
}

/// Case (a), the half a string assertion cannot make: the shim is still
/// executable.
///
/// **Cross-platform by construction, which is why this needs no `#[cfg]` and no
/// waiver.** The obvious spelling asserts `PermissionsExt::mode() & 0o111`, and
/// `mode` is a `std::os::unix` symbol — so the case would compile on one target,
/// carry an attribute deleting it on the others, and owe a `[[waiver]]` for the
/// privilege. `Permissions` is `PartialEq` and portable, so asking whether the
/// permissions CHANGED answers the same question everywhere: the shim must land
/// with the bits the launcher set, whatever those bits are on this host.
///
/// That is also the stronger assertion. `mode & 0o111` passes over a rewrite
/// that silently widened the file to `0o777`; equality does not.
///
/// Fails by: staging the new body in a temporary and renaming it over the
/// original, which is what the registration pass does and is wrong here — the
/// staged file carries the creating process's mode, so the shim lands with the
/// umask's bits, the harness cannot execute it, and the hook fails to run
/// instead of exiting 0.
#[test]
fn the_shim_keeps_the_mode_the_launcher_set() {
    let bench = bench("disarm-mode", &one_row("stop.sh"), &[("stop.sh", ARMED)]);
    let before = std::fs::metadata(bench.script("stop.sh"))
        .expect("the fixture script is there")
        .permissions();

    let (status, err) = bench.reclaim(&["-y"]);
    assert_eq!(status, 0, "{err}");

    let after = std::fs::metadata(bench.script("stop.sh"))
        .expect("the script survives the disarm")
        .permissions();
    assert_eq!(
        before, after,
        "the shim did not land with the permissions the launcher set"
    );
}

/// Case (b): an already-shimmed script is left BYTE for byte.
///
/// **The declared mutation's target** (`disarm-ignores-marker`). A disarm that
/// rewrote unconditionally reports `shimmed` here too and passes every other
/// case in this file; the only thing that separates it from the correct one is
/// that it churns the file on every session start — so this case has to assert
/// the bytes and the write COUNT, not the state token.
#[test]
fn an_already_shimmed_script_is_not_rewritten() {
    let shim = format!("#!/bin/sh\nexit 0 # {MARKER}\n");
    let bench = bench(
        "disarm-idempotent",
        &one_row("stop.sh"),
        &[("stop.sh", &shim)],
    );
    let before = std::fs::metadata(bench.script("stop.sh")).expect("the script is there");

    let (status, err) = bench.reclaim(&["-y"]);
    assert_eq!(status, 0, "{err}");
    // Zero written is the assertion. `shimmed` alone would be satisfied by a
    // verb that rewrote the file to identical bytes.
    assert!(err.contains("disarmed 0 of 1 declared script(s)"), "{err}");
    assert!(err.contains("stop.sh shimmed"), "{err}");
    assert_eq!(bench.body("stop.sh"), shim);

    // mtime is the observable that separates "left alone" from "rewritten with
    // the same bytes" — the exact thing a content comparison cannot see.
    let after = std::fs::metadata(bench.script("stop.sh")).expect("the script is there");
    assert_eq!(
        before.modified().expect("mtime"),
        after.modified().expect("mtime"),
        "the script was rewritten despite already carrying the marker"
    );
}

/// Case (c): a declared path that does not exist is reported and never created.
///
/// A consumer declares the scripts its launcher MAY write, and a host that has
/// none is the ordinary case. Creating one would be this verb installing a hook
/// script on a machine that had none — the inverse of its whole purpose.
#[test]
fn an_absent_script_is_reported_and_never_created() {
    let bench = bench("disarm-absent", &one_row("stop.sh"), &[]);
    let (status, err) = bench.reclaim(&["-y"]);
    assert_eq!(status, 0, "{err}");
    assert!(err.contains("stop.sh absent"), "{err}");
    assert!(err.contains("disarmed 0 of 1 declared script(s)"), "{err}");
    assert!(
        !bench.script("stop.sh").exists(),
        "the verb created a script"
    );
}

/// Case (d): a path that escapes the home directory is refused at LOAD.
///
/// Refused where `config lint` names the key, rather than at the write — a shim
/// over a tracked file is a mutation of the tree, and a verb that declined it
/// quietly at write time would leave the row looking enforced. Both spellings of
/// the escape are asserted, because refusing only the absolute one leaves `..`
/// as an open route to the same place.
#[test]
fn a_declared_path_outside_the_home_directory_is_refused_at_load() {
    for path in ["/etc/profile", "../outside.sh"] {
        // A LITERAL STRING, because the value under test IS a path (CLOUD-113):
        // a basic string processes escapes, so a Windows path reads `\a` as a
        // control character and `\U` is rejected outright — the fixture then
        // fails to PARSE and this case dies on its own setup rather than on the
        // refusal it exists to assert.
        let rows = format!("[[wiring.disarm]]\npath = '{path}'\nmarker = \"{MARKER}\"\n");
        let bench = bench("disarm-escapes", &rows, &[]);
        let (status, err) = bench.reclaim(&["-y"]);
        assert_eq!(status, 1, "{path} was accepted: {err}");
        assert!(err.contains("wiring.disarm"), "{err}");
    }
}

/// A blank marker is refused too, and for the reason that makes it a hole rather
/// than a typo: every body contains the empty string, so a blank marker reports
/// every declared script `shimmed` while writing nothing at all.
#[test]
fn a_blank_marker_is_refused_at_load() {
    let rows = "[[wiring.disarm]]\npath = \".launcher/stop.sh\"\nmarker = \"\"\n";
    let bench = bench("disarm-blank-marker", rows, &[("stop.sh", ARMED)]);
    let (status, err) = bench.reclaim(&["-y"]);
    assert_eq!(status, 1, "{err}");
    assert!(err.contains("marker"), "{err}");
    assert_eq!(bench.body("stop.sh"), ARMED, "a refused config still wrote");
}

/// `--check` DECIDES, and the pair is what makes it a decider.
///
/// Red while a declared script is still armed, green once it is not — over the
/// same fixture, so a build that always exits 1 fails the second half. This is
/// the arm `[[startup]] hook-surfaces-are-battens` consumes, which is why a
/// `foreign` script has to move it at all.
#[test]
fn check_is_red_while_a_script_is_armed_and_green_once_it_is_shimmed() {
    let bench = bench("disarm-check", &one_row("stop.sh"), &[("stop.sh", ARMED)]);

    let (status, err) = bench.reclaim(&["--check"]);
    assert_eq!(status, 1, "a repair is owed: {err}");
    assert!(err.contains("stop.sh foreign"), "{err}");
    // `--check` implies `--dry-run`, so the script it just judged is untouched.
    assert_eq!(bench.body("stop.sh"), ARMED);

    let (status, err) = bench.reclaim(&["-y"]);
    assert_eq!(status, 0, "{err}");

    let (status, err) = bench.reclaim(&["--check"]);
    assert_eq!(status, 0, "the repair landed: {err}");
    assert!(err.contains("stop.sh shimmed"), "{err}");
}

/// An environment that declared nothing reports and never writes.
///
/// The posture gate is the registration pass's, shared rather than re-derived:
/// on a developer's own machine somebody else's script is theirs, and a tool
/// they installed to check their commits must not blank it.
#[test]
fn an_undeclared_environment_reports_and_writes_nothing() {
    let bench = bench(
        "disarm-conservative",
        &one_row("stop.sh"),
        &[("stop.sh", ARMED)],
    );
    let outcome = bench.run_in("", &["wiring", "reclaim", "-y"]);
    assert_eq!(outcome.status.code(), Some(0));
    let err = stderr(&outcome);
    assert!(err.contains("would disarm 0 of 1"), "{err}");
    assert_eq!(bench.body("stop.sh"), ARMED, "a conservative run wrote");
}

/// Every declared row is judged, not just the first.
///
/// Fails by: returning after the first row, which passes every single-row case
/// in this file and leaves the second declared script armed forever.
#[test]
fn every_declared_row_is_judged() {
    let rows = format!("{}{}", one_row("stop.sh"), one_row("session.sh"));
    let bench = bench(
        "disarm-many",
        &rows,
        &[("stop.sh", ARMED), ("session.sh", ARMED)],
    );
    let (status, err) = bench.reclaim(&["-y"]);
    assert_eq!(status, 0, "{err}");
    assert!(err.contains("disarmed 2 of 2 declared script(s)"), "{err}");
    for name in ["stop.sh", "session.sh"] {
        assert!(bench.body(name).contains(MARKER), "{name} was left armed");
    }
}

/// The registration pass still runs, and the disarm reports after it.
///
/// The row asks for the script pass to be added to this verb, not to replace
/// what it did — and a change that dropped the registration half would leave
/// every case above green.
#[test]
fn the_registration_pass_still_runs_beside_the_script_pass() {
    let bench = bench(
        "disarm-both-passes",
        &one_row("stop.sh"),
        &[("stop.sh", ARMED)],
    );
    let (status, err) = bench.reclaim(&["-y"]);
    assert_eq!(status, 0, "{err}");
    let registrations = err
        .find("sibling registration(s)")
        .expect("the registration pass reported");
    let scripts = err
        .find("declared script(s)")
        .expect("the script pass reported");
    assert!(
        registrations < scripts,
        "the script pass reported before the registration pass: {err}"
    );
}

/// `doctor hooks -J` carries the same reading, as basenames and state tokens.
///
/// Pointer-only (non-negotiable rule 4): the declared path is a filename off
/// somebody's home directory and the body is somebody's program, so neither may
/// leave the engine. What a consumer's gate needs is which script, and whether
/// it is still armed.
#[test]
fn doctor_hooks_reports_each_declared_script_without_naming_a_path() {
    let bench = bench("disarm-doctor", &one_row("stop.sh"), &[("stop.sh", ARMED)]);
    let report = bench.run_in("disposable", &["doctor", "hooks", "-J"]);
    let document: serde_json::Value =
        serde_json::from_str(&stdout(&report)).expect("the report is JSON");
    let rows = document["disarmed"].as_array().expect("disarmed is a list");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["basename"], "stop.sh");
    assert_eq!(rows[0]["state"], "foreign");

    // The declared path and the body stay inside the engine.
    let whole = stdout(&report);
    assert!(!whole.contains(".launcher/"), "{whole}");
    assert!(!whole.contains("the launcher hook ran"), "{whole}");
}

/// A `foreign` script is REPORTED by `doctor hooks` and never JUDGED by it.
///
/// The same split `at_load_siblings` takes: the engine supplies the arithmetic
/// and the consumer's gate supplies the verdict, which for this repository is
/// `wiring reclaim --check`. A `doctor` that reddened here would be a second
/// authority over one question.
#[test]
fn a_foreign_script_does_not_move_doctors_own_verdict() {
    let armed = bench(
        "disarm-doctor-verdict",
        &one_row("stop.sh"),
        &[("stop.sh", ARMED)],
    );
    let with_script = armed.run_in("disposable", &["doctor", "hooks", "-J"]);
    let with_script: serde_json::Value =
        serde_json::from_str(&stdout(&with_script)).expect("the report is JSON");

    let none = bench("disarm-doctor-verdict-clean", &one_row("stop.sh"), &[]);
    let without: serde_json::Value = serde_json::from_str(&stdout(
        &none.run_in("disposable", &["doctor", "hooks", "-J"]),
    ))
    .expect("the report is JSON");

    assert_eq!(with_script["disarmed"][0]["state"], "foreign");
    assert_eq!(without["disarmed"][0]["state"], "absent");
    assert_eq!(
        with_script["ok"], without["ok"],
        "an armed script moved doctor's verdict"
    );
}
