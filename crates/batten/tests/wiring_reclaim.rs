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
//! `etcetera` resolves from `$HOME`, so overriding it is the whole isolation.
//!
//! **Rust rather than a `.bats` suite** (CLOUD-843): `shell-retirement` refuses
//! a new one, correctly — the campaign's corpus has to shrink rather than stay
//! level while the census reports movement. Nothing here needed bash.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::path::{Path, PathBuf};

use common::{git_in, scratch, stderr, stdout, write};

/// One merged surface carrying one batten registration and two siblings.
///
/// `.claude/launcher-settings.json` is a path `Harness::merge_surfaces`
/// declares, so this is the real selection rather than a name invented here.
const SURFACE: &str = r#"{
  "hooks": {
    "SessionStart": [
      {
        "hooks": [
          {"type": "command", "command": "batten hook --harness claude-code"},
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
        common::batten()
            .current_dir(&self.repo)
            .args(args)
            .env("HOME", &self.home)
            .output()
            .expect("the binary runs")
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
        surface.contains("batten hook --harness claude-code"),
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
            .args(["hook", "--harness", "claude-code"])
            .env("HOME", &bench.home)
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
        .env("HOME", &bench.home)
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
#[test]
fn the_fixture_home_is_never_the_real_one() {
    let bench = bench("reclaim-isolation");
    let real = std::env::var("HOME").unwrap_or_default();
    assert!(!real.is_empty());
    assert_ne!(bench.home.display().to_string(), real);
    assert!(Path::new(&real).exists());
}
