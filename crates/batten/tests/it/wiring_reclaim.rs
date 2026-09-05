//! `batten wiring reclaim`, over the compiled binary against a real `$HOME`.
//!
//! **The second tier for the verb (CLOUD-893).** `wiring.rs`'s own unit cases
//! pin `prune_siblings` against documents they build themselves, which is the
//! `with input as` shape `.claude/rules/policy-modules.md` names: it fabricates
//! the document the ENGINE may be unable to locate, so every one of them could
//! pass over a verb that reads the wrong home directory, refuses without `-y` in
//! the wrong direction, or writes the record after the repair instead of before.
//!
//! Those four are what this file asserts.
//!
//! **WHY A FIXTURE `$HOME` AND NOT THIS CONTAINER'S.** The verb's whole subject
//! is a file under the caller's home directory, and this container HAS one —
//! with the two launcher-provisioned registrations CLOUD-605 owns still in it. A
//! suite driving the real one would repair the box it is measuring, exactly
//! once, and every later run would assert over a state the first run destroyed.
//! `etcetera` resolves the home directory, so overriding it is the whole
//! isolation.
//!
//! **AND `$HOME` IS ONLY HALF OF THAT OVERRIDE**, which is the same shape
//! `common::state_home`'s header already records one axis over: a redirect
//! spelled for POSIX and silently inert on Windows. `etcetera::home_dir()`
//! wraps `std::env::home_dir()`, which reads `USERPROFILE` there and has never
//! heard of `HOME` — so on the Windows runner this fixture was not in play at
//! all and the verb read the RUNNER's home.
//!
//! It did not fail the suite, it split it: the two cases asserting an ABSENCE —
//! a refusal without `-y`, a record not written — passed over a home carrying
//! no surface, while the two asserting the counts failed with `0 sibling
//! registration(s) across 0 surface(s) read`. Half a suite green over a fixture
//! that was never in play is the vacuous pass this header is about, one layer
//! up. `common::at_home` sets both spellings, so the isolation is one call
//! rather than a variable per platform remembered per spawn.
//!
//! **Rust rather than a `.bats` suite** (CLOUD-843): `shell-retirement` refuses
//! a new one, correctly — the campaign's corpus has to shrink rather than stay
//! level while the census reports movement. Nothing here needed bash.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::{Path, PathBuf};

use common::{StateHome as _, git_in, scratch, stderr, stdout, write};

/// One merged surface carrying one batten registration and two siblings.
///
/// `.claude/launcher-settings.json` is a path `Harness::merge_surfaces`
/// declares, so this is the real selection rather than a name invented here.
const SURFACE: &str = r#"{
  "hooks": {
    "SessionStart": [
      {
        "hooks": [
          {"type": "command", "command": "batten adjudicate --harness claude-code"},
          {"type": "command", "command": "/opt/launcher/session-start-git-identity.sh"}
        ]
      }
    ],
    "Stop": [
      {"hooks": [{"type": "command", "command": "/opt/launcher/stop-hook-git-check.sh"}]}
    ]
  }
}
"#;

struct Bench {
    repo: PathBuf,
    home: PathBuf,
}

impl Bench {
    fn surface(&self) -> PathBuf {
        self.home.join(".claude/launcher-settings.json")
    }

    fn record(&self) -> PathBuf {
        self.repo.join(".git/batten-wiring/at-load.json")
    }

    fn surface_text(&self) -> String {
        std::fs::read_to_string(self.surface()).expect("the surface is readable")
    }

    fn record_text(&self) -> String {
        std::fs::read_to_string(self.record()).expect("the record is readable")
    }

    /// Drive the verb with the fixture home, keeping the two streams apart: the
    /// arithmetic is on stderr (rule 4 — it is a count whose subject is a
    /// filename off somebody's disk) and there is no stdout contract at all.
    fn reclaim(&self, args: &[&str]) -> (i32, String) {
        let outcome = self.run(&[&["wiring", "reclaim"], args].concat());
        (outcome.status.code().unwrap_or(-1), stderr(&outcome))
    }

    fn run(&self, args: &[&str]) -> std::process::Output {
        self.run_in("disposable", args)
    }

    /// Drive the verb with this environment's declared kind (CLOUD-1383).
    ///
    /// **The fixture declares itself disposable exactly as a container does**, and
    /// that is the honest shape rather than a convenience: the destructive arm is
    /// licensed by a fact about the machine, so a bench asserting removal has to
    /// state it. Before this the cases were asserting a repair no environment had
    /// authorised — which is the behaviour a developer's laptop must NOT get.
    fn run_in(&self, environment: &str, args: &[&str]) -> std::process::Output {
        common::batten()
            .current_dir(&self.repo)
            .args(args)
            .at_home(&self.home)
            .env("BATTEN_ENVIRONMENT", environment)
            .output()
            .expect("the binary runs")
    }

    /// `wiring reclaim` under an environment that declared nothing.
    fn reclaim_undeclared(&self, args: &[&str]) -> (i32, String) {
        let outcome = self.run_in("", &[&["wiring", "reclaim"], args].concat());
        (outcome.status.code().unwrap_or(-1), stderr(&outcome))
    }
}

fn bench(name: &str) -> Bench {
    let dir = scratch(name);
    let repo = dir.join("repo");
    std::fs::create_dir_all(&repo).expect("the fixture repo");
    write(&repo, "batten.toml", "version = 1\n");
    git_in(&repo, &["init", "-q", "-b", "main", "."]);

    let home = dir.join("home");
    std::fs::create_dir_all(home.join(".claude")).expect("the fixture home");
    std::fs::write(home.join(".claude/launcher-settings.json"), SURFACE)
        .expect("the merged surface");
    Bench { repo, home }
}

#[test]
fn a_destructive_verb_refuses_without_y_rather_than_prompting() {
    // §4's refusal, asserted over the FILE rather than over the exit status: a
    // verb that refused and had already written is the failure that matters, and
    // an exit code alone cannot tell that apart.
    let bench = bench("reclaim-refuses");
    let (status, err) = bench.reclaim(&[]);
    assert_eq!(status, 1, "{err}");
    assert!(err.contains("pass -y"), "{err}");
    assert!(!bench.record().exists());
    assert!(bench.surface_text().contains("session-start-git-identity"));
}

#[test]
fn dry_run_reports_what_would_go_and_writes_nothing() {
    let bench = bench("reclaim-dry-run");
    let (status, err) = bench.reclaim(&["-n"]);
    assert_eq!(status, 0, "{err}");
    assert!(
        err.contains("would remove 2 sibling registration(s)"),
        "{err}"
    );
    // The per-event rows, which are what make the count actionable without
    // naming a path.
    assert!(
        err.contains("claude-code:SessionStart would remove 1"),
        "{err}"
    );
    assert!(err.contains("claude-code:Stop would remove 1"), "{err}");
    assert!(!bench.record().exists());
    let surface = bench.surface_text();
    assert!(surface.contains("session-start-git-identity"));
    assert!(surface.contains("stop-hook-git-check"));
}

/// `--check` DECIDES where the bare verb and `--dry-run` only report.
///
/// The pair is what makes it a decider rather than a third rendering: the same
/// surfaces, red while a sibling is there and green once it is gone. Without the
/// second half a build that always exits 1 satisfies the first.
#[test]
fn check_is_red_while_a_sibling_stands_and_green_once_it_is_gone() {
    let bench = bench("reclaim-check");
    let (status, err) = bench.reclaim(&["--check"]);
    assert_eq!(status, 1, "a repair is owed: {err}");
    // Decides without repairing — `--check` implies `--dry-run`, so the surface
    // it just judged is untouched.
    assert!(bench.surface_text().contains("session-start-git-identity"));

    let (status, err) = bench.reclaim(&["-y"]);
    assert_eq!(status, 0, "{err}");
    let (status, err) = bench.reclaim(&["--check"]);
    assert_eq!(status, 0, "nothing is owed once the repair ran: {err}");
}

#[test]
fn the_repair_takes_the_siblings_and_leaves_battens_own_registration() {
    let bench = bench("reclaim-repair");
    let (status, err) = bench.reclaim(&["-y"]);
    assert_eq!(status, 0, "{err}");
    assert!(err.contains("removed 2 sibling registration(s)"), "{err}");

    let surface = bench.surface_text();
    // THE LOAD-BEARING POSITIVE. A `retain` at the wrong level takes batten's
    // registration out with the sibling sharing its entry, and every negative
    // assertion in this file is satisfied by that bug.
    assert!(
        surface.contains("batten adjudicate --harness claude-code"),
        "{surface}"
    );
    assert!(!surface.contains("session-start-git-identity"), "{surface}");
    assert!(!surface.contains("stop-hook-git-check"), "{surface}");

    let doc: serde_json::Value = serde_json::from_str(&surface).expect("still a hook map");
    // `Stop` held nothing else, so the event goes with its last entry rather
    // than surviving as an empty array no generator emits.
    assert!(doc["hooks"].get("Stop").is_none(), "{surface}");
    assert_eq!(
        doc["hooks"]["SessionStart"][0]["hooks"]
            .as_array()
            .map(Vec::len),
        Some(1),
        "{surface}"
    );
}

#[test]
fn record_before_repair_so_it_carries_the_pre_repair_count() {
    let bench = bench("reclaim-record");
    bench.reclaim(&["-y"]);
    assert!(bench.record().exists());

    let record = bench.record_text();
    let doc: serde_json::Value = serde_json::from_str(&record).expect("the record parses");
    let total: i64 = doc["rows"]
        .as_array()
        .expect("rows")
        .iter()
        .map(|row| row["siblings"].as_i64().unwrap_or(0))
        .sum();
    assert_eq!(total, 2, "{record}");

    // Rule 4 on the record itself. It lives under `$GIT_DIR` and is never
    // committed, and it still carries no path and no filename: the harness and
    // the event are where to look, and a basename would be a name off somebody's
    // disk bought for a nicer message.
    assert!(
        !record.contains(&bench.home.display().to_string()),
        "{record}"
    );
    assert!(!record.contains("launcher"), "{record}");
    assert!(!record.contains("git-identity"), "{record}");
    assert!(!record.contains('/'), "{record}");
}

#[test]
fn the_record_is_written_once_so_a_second_run_cannot_report_the_repair() {
    let bench = bench("reclaim-once");
    let (_, first) = bench.reclaim(&["-y"]);
    assert!(first.contains("removed 2 sibling"), "{first}");

    // THE WHOLE ORDERING PROPERTY. A second reclaim finds nothing — and must not
    // overwrite a record saying 2 with one saying 0, because the record
    // describes what the RUNNING session loaded and that has not changed.
    let (_, second) = bench.reclaim(&["-y"]);
    assert!(second.contains("removed 0 sibling"), "{second}");

    let doc: serde_json::Value =
        serde_json::from_str(&bench.record_text()).expect("the record parses");
    let total: i64 = doc["rows"]
        .as_array()
        .expect("rows")
        .iter()
        .map(|row| row["siblings"].as_i64().unwrap_or(0))
        .sum();
    assert_eq!(total, 2);
}

#[test]
fn doctor_hooks_reports_the_record_beside_the_live_count() {
    // The two numbers that must be able to disagree. Before the repair there is
    // no record — `null`, which is read-the-disk — and after it the disk says
    // zero while the record says two.
    let bench = bench("reclaim-doctor");
    let before = stdout(&bench.run(&["doctor", "hooks", "-J"]));
    let before_doc: serde_json::Value = serde_json::from_str(&before).expect("a diagnosis");
    assert!(before_doc["at_load_siblings"].is_null(), "{before}");

    bench.reclaim(&["-y"]);
    let after = stdout(&bench.run(&["doctor", "hooks", "-J"]));
    let after_doc: serde_json::Value = serde_json::from_str(&after).expect("a diagnosis");
    assert_eq!(after_doc["at_load_siblings"].as_i64(), Some(2), "{after}");

    // And the live half genuinely fell, or the two numbers would agree for the
    // wrong reason.
    let live: i64 = after_doc["harnesses"]
        .as_array()
        .expect("harnesses")
        .iter()
        .map(|harness| harness["merged_siblings"].as_i64().unwrap_or(0))
        .sum();
    assert_eq!(live, 0, "{after}");
}

#[test]
fn a_session_start_expires_the_record_which_is_the_restart_this_reports() {
    let bench = bench("reclaim-expiry");
    bench.reclaim(&["-y"]);
    assert!(bench.record().exists());

    // The one moment the disk and what a harness has loaded are the same thing,
    // and therefore the only honest place to drop the record. Driven through the
    // real hook entry point rather than by deleting the file, because what is
    // asserted is that the ENGINE does it.
    let outcome = {
        use std::io::Write as _;
        let mut child = common::batten()
            .current_dir(&bench.repo)
            .args(["adjudicate", "--harness", "claude-code"])
            .at_home(&bench.home)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("the binary runs");
        child
            .stdin
            .take()
            .expect("stdin is piped")
            .write_all(br#"{"hook_event_name":"SessionStart"}"#)
            .expect("write stdin");
        child.wait_with_output().expect("wait for batten")
    };
    assert!(outcome.status.success(), "{}", stderr(&outcome));
    assert!(!bench.record().exists());
}

/// Drive one `SessionStart` through the real hook entry point.
///
/// Shared by the two cases below so the only difference between them is the
/// config they were built with, which is what makes the pair discriminate.
fn session_start(bench: &Bench) -> std::process::Output {
    session_start_in(bench, "disposable")
}

/// A session start under a named environment kind (CLOUD-1383).
///
/// **The variable has to reach the CHILD, which is the whole path under test.**
/// The hook spawns the declared repair as its own process, so the fact travels by
/// inheritance — and a container that sets it in the platform's one Environment
/// variables field is doing exactly this. A fixture that set it only on the verb
/// would prove nothing about the route a session actually takes.
fn session_start_in(bench: &Bench, environment: &str) -> std::process::Output {
    use std::io::Write as _;
    let mut child = common::batten()
        .current_dir(&bench.repo)
        .args(["adjudicate", "--harness", "claude-code"])
        .at_home(&bench.home)
        .env("BATTEN_ENVIRONMENT", environment)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("the binary runs");
    child
        .stdin
        .take()
        .expect("stdin is piped")
        .write_all(br#"{"hook_event_name":"SessionStart"}"#)
        .expect("write stdin");
    child.wait_with_output().expect("wait for batten")
}

/// A consumer that DECLARED the repair as a `[[startup]]` row gets it at session
/// start, without invoking the verb (CLOUD-1324).
///
/// The measured reason for a repair rather than `exclusive`'s refusal: this
/// repository's launcher rewrites both surfaces mid-session — observed at 03:49
/// over a surface emptied at 01:08 — so a gate on the count is red at moments
/// nobody chose and blocks every commit made after the rewrite. A repair runs at
/// the one moment the host is about to read its hooks and refuses nothing.
///
/// Asserted over the SURFACE rather than over stdout, because the repair is
/// deliberately silent: it says nothing an agent has to read, which is the whole
/// point of solving the problem instead of reporting it.
#[test]
fn a_declared_repair_takes_the_siblings_at_session_start() {
    let bench = bench("reclaim-declared");
    // THE BUILT BINARY BY PATH, not `batten` by bare name. The committed config
    // spells the bare name because a container has the engine on PATH — that is
    // `engine-on-path`'s own row — but a fixture must not depend on whether this
    // suite's host does, or the case would pass or fail on the developer's
    // installation rather than on the code under test.
    write(
        &bench.repo,
        "batten.toml",
        &format!(
            "version = 1\n\n\
             [[startup]]\n\
             id = \"hook-surfaces-are-battens\"\n\
             gloss = \"no non-batten registration survives\"\n\
             check = [{bin}, \"wiring\", \"reclaim\", \"--check\"]\n\
             repair = [{bin}, \"wiring\", \"reclaim\", \"-y\"]\n",
            bin = serde_json::to_string(env!("CARGO_BIN_EXE_batten")).unwrap()
        ),
    );
    let outcome = session_start(&bench);
    assert!(outcome.status.success(), "{}", stderr(&outcome));

    let surface = bench.surface_text();
    // The same load-bearing positive the verb's own case carries: a `retain` at
    // the wrong level takes batten's registration out with the siblings, and
    // every negative below is satisfied by that bug.
    assert!(
        surface.contains("batten adjudicate --harness claude-code"),
        "{surface}"
    );
    assert!(!surface.contains("session-start-git-identity"), "{surface}");
    assert!(!surface.contains("stop-hook-git-check"), "{surface}");
}

/// AND THE SAME SESSION START ON AN UNDECLARED MACHINE TAKES NOTHING.
///
/// The mirror for the case above, over the route that actually runs in a session
/// rather than over the verb. It is the one that matters most: the repair is
/// deliberately silent, so on a developer's laptop a declared `[[startup]]` row
/// would otherwise delete registrations out of their real `~/.claude` with
/// nothing printed and nothing asked. The fact travels to the spawned child by
/// inheritance, which is exactly how a container sets it.
#[test]
fn a_declared_repair_takes_nothing_on_an_undeclared_machine() {
    let bench = bench("reclaim-declared-undeclared-env");
    write(
        &bench.repo,
        "batten.toml",
        &format!(
            "version = 1\n\n\
             [[startup]]\n\
             id = \"hook-surfaces-are-battens\"\n\
             gloss = \"no non-batten registration survives\"\n\
             check = [{bin}, \"wiring\", \"reclaim\", \"--check\"]\n\
             repair = [{bin}, \"wiring\", \"reclaim\", \"-y\"]\n",
            bin = serde_json::to_string(env!("CARGO_BIN_EXE_batten")).unwrap()
        ),
    );
    let outcome = session_start_in(&bench, "");
    assert!(outcome.status.success(), "{}", stderr(&outcome));

    let surface = bench.surface_text();
    assert!(
        surface.contains("session-start-git-identity"),
        "somebody else's registration survives an undeclared machine: {surface}"
    );
    assert!(surface.contains("stop-hook-git-check"), "{surface}");
    assert!(
        surface.contains("batten adjudicate --harness claude-code"),
        "and batten's own is still there: {surface}"
    );
}

/// THE ANTI-VACUITY MIRROR, and the flag is the only difference.
///
/// Rewriting files under somebody's `$HOME` is not the engine's to decide for a
/// project. Without this case the one above is satisfied by a build that
/// reclaims unconditionally — which would repair every adopter's home directory
/// on upgrade, the opposite of house-style §8's raise-only promise.
#[test]
fn an_undeclared_repair_leaves_the_merged_surface_exactly_as_it_found_it() {
    // A NAME OF ITS OWN, because `bench` is not a read: `scratch` clears and
    // recreates the directory it is handed, so two cases sharing one name are two
    // processes racing over one fixture under a parallel runner. This case and
    // `an_undeclared_environment_reports_and_removes_nothing` both spelled it
    // `reclaim-undeclared`, and the race produced both of its symptoms — a
    // `git init` that could not lock a config file another process had just
    // created, and a verb reading a home whose `.claude` had been swept out from
    // under it, reporting `0 sibling registration(s) across 0 surface(s) read`
    // where the fixture had written two.
    //
    // It flaked rather than failing, which is what let it land: run alone, or
    // scheduled apart, either case passes. CI is where the two met.
    let bench = bench("reclaim-undeclared-repair");
    let before = bench.surface_text();
    let outcome = session_start(&bench);
    assert!(outcome.status.success(), "{}", stderr(&outcome));
    assert_eq!(
        bench.surface_text(),
        before,
        "an undeclared repair is not a quiet one — it is no repair at all"
    );
}

#[test]
fn a_merged_surface_that_is_not_a_wiring_file_is_left_alone() {
    // Could-not-look, and the direction matters: a document this verb cannot
    // read as a hook map is one it must not write back, or a repair would
    // silently reformat a file whose shape it never understood.
    let bench = bench("reclaim-unreadable");
    std::fs::write(bench.surface(), "[]\n").expect("an unreadable surface");
    let (status, err) = bench.reclaim(&["-y"]);
    assert_eq!(status, 0, "{err}");
    assert_eq!(bench.surface_text(), "[]\n");
    assert!(err.contains("0 surface(s) read"), "{err}");
}

#[test]
fn a_checkout_sitting_at_the_home_directory_is_never_its_own_merged_surface() {
    // The `same_file` arm, driven by the collision its comment describes: every
    // path `merge_surfaces` declares is resolved against BOTH the home directory
    // and the repository, so a checkout sitting at `$HOME` resolves each of them
    // to one file. Without the arm this verb would rewrite a version-controlled
    // file and fight `tree-clean` on every run.
    //
    // The collision is TOTAL here, not partial: the launcher surface deduplicates
    // for exactly the reason the settings one does, so the honest expectation is
    // ZERO surfaces read rather than one. The first draft of this case asserted
    // the launcher file was still reclaimed, which was a wrong premise rather
    // than a bug.
    let bench = bench("reclaim-home-checkout");
    std::fs::copy(bench.surface(), bench.home.join(".claude/settings.json"))
        .expect("the colliding surface");
    git_in(&bench.home, &["init", "-q", "-b", "main", "."]);
    std::fs::copy(
        bench.repo.join("batten.toml"),
        bench.home.join("batten.toml"),
    )
    .expect("the authority");

    let outcome = common::batten()
        .current_dir(&bench.home)
        .args(["wiring", "reclaim", "-y"])
        .at_home(&bench.home)
        .output()
        .expect("the binary runs");
    assert!(outcome.status.success(), "{}", stderr(&outcome));
    let said = format!("{}{}", stdout(&outcome), stderr(&outcome));
    assert!(said.contains("0 surface(s) read"), "{said}");

    // Untouched, both of them — which is the whole claim. That this is not
    // simply "the verb never works" is what the cases above establish, over the
    // same binary and a home directory the repository does not sit in.
    let settings =
        std::fs::read_to_string(bench.home.join(".claude/settings.json")).expect("still readable");
    assert!(
        settings.contains("session-start-git-identity"),
        "{settings}"
    );
    let surface = bench.surface_text();
    assert!(surface.contains("session-start-git-identity"), "{surface}");
    assert!(surface.contains("stop-hook-git-check"), "{surface}");
}

/// Kept honest: the fixture home is never this container's.
///
/// **THE REAL HOME IS READ IN BOTH SPELLINGS**, for the reason the header gives:
/// `HOME` alone is empty on Windows, so this guard — the one case whose whole job
/// is proving the isolation — was the last one still asking a POSIX-only
/// question, and it failed there on `!real.is_empty()` while every case it
/// guards had already been repaired. `at_home` sets both, so this reads both.
#[test]
fn the_fixture_home_is_never_the_real_one() {
    let bench = bench("reclaim-isolation");
    let real = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .unwrap_or_default();
    assert!(!real.is_empty());
    assert_ne!(bench.home.display().to_string(), real);
    assert!(Path::new(&real).exists());
}

// ---------------------------------------------------------------------------
// Whose `$HOME` is this (CLOUD-1383).
// ---------------------------------------------------------------------------

/// AN UNDECLARED ENVIRONMENT IS SOMEBODY'S OWN MACHINE, so the repair reports and
/// removes nothing.
///
/// This is the direction that has to be safe. A developer installs batten to
/// check their commits; a tool that then deletes a hook registration out of their
/// real `~/.claude` because a repository asked it to is doing something they never
/// agreed to. The census is identical on both machines — what differs is the
/// authority to act on it.
#[test]
fn an_undeclared_environment_reports_and_removes_nothing() {
    let bench = bench("reclaim-undeclared");
    let (status, err) = bench.reclaim_undeclared(&["-y"]);
    assert_eq!(status, 0, "{err}");

    // IT STILL FOUND THEM, which is the half that keeps this a posture rather
    // than a blindfold: same walk, same count, same per-event rows.
    assert!(
        err.contains("would remove 2 sibling registration(s)"),
        "the finding survives the posture: {err}"
    );

    // AND IT SAID WHY, because a repair that reports siblings, changes nothing,
    // and explains nothing is the could-not-look-as-clean shape one layer over.
    assert!(
        err.contains("not declared disposable"),
        "the reason is named: {err}"
    );
    assert!(
        err.contains("BATTEN_ENVIRONMENT=disposable"),
        "and so is the remedy: {err}"
    );

    let surface = bench.surface_text();
    assert!(surface.contains("session-start-git-identity"), "{surface}");
    assert!(surface.contains("stop-hook-git-check"), "{surface}");
}

/// THE TWO ARMS AGREE ABOUT SCOPE AND DIFFER ONLY IN WHETHER THEY ACT.
///
/// Without this, "disposable" is free to become a licence to touch more than the
/// conservative arm ever reported — the widening the row refuses by name. Asserted
/// as the SAME counted subjects from the same fixture, one run each.
#[test]
fn declaring_the_environment_changes_the_authority_and_not_the_subjects() {
    let conservative = bench("reclaim-scope-conservative");
    let (_, reported) = conservative.reclaim_undeclared(&["-y"]);

    let authoritative = bench("reclaim-scope-authoritative");
    let (_, acted) = authoritative.reclaim(&["-y"]);

    for event in ["claude-code:SessionStart", "claude-code:Stop"] {
        assert!(
            reported.contains(&format!("{event} would remove 1")),
            "the conservative arm names {event}: {reported}"
        );
        assert!(
            acted.contains(&format!("{event} removed 1")),
            "and the authoritative arm acts on the same one: {acted}"
        );
    }
    assert!(reported.contains("would remove 2 sibling registration(s)"));
    assert!(acted.contains("removed 2 sibling registration(s)"));

    // Only the second one wrote.
    assert!(authoritative.record().exists(), "the repair recorded");
    assert!(
        !conservative.record().exists(),
        "and the report did not, because it changed nothing"
    );
}

/// A MISSPELLING IS NOT A LICENCE, which is the whole reason the read is an exact
/// match rather than a truthiness test.
///
/// The anti-vacuity mirror for the authoritative case: a predicate accepting
/// "anything non-empty" passes every removal case above while turning a typo in a
/// platform text field into a deletion from somebody's home directory.
#[test]
fn a_misspelled_environment_is_conservative() {
    for wrong in ["disposible", "Disposable", "1", "true"] {
        let bench = bench(&format!("reclaim-typo-{wrong}"));
        let outcome = bench.run_in(wrong, &["wiring", "reclaim", "-y"]);
        let err = stderr(&outcome);
        assert!(
            err.contains("would remove"),
            "{wrong:?} must not license a removal: {err}"
        );
        assert!(
            bench.surface_text().contains("stop-hook-git-check"),
            "{wrong:?} left the surface untouched"
        );
    }
}
