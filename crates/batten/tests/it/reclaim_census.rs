//! `[tasks.reclaim-census]` — was a landing in flight when this container
//! replaced the last one (CLOUD-451), over the task's own body (CLOUD-1752).
//!
//! THE ROWS ARE ABOUT TRANSITIONS, not files (CLOUD-696): every verdict case
//! fixtures a boots file as well as a log, because a verdict without a boundary
//! is not one. `BATTEN_BOOT_TIME` is injected throughout, or `/proc/stat` is the
//! only boot source and no row could discriminate (CLOUD-418).
//!
//! # RETIREMENT LEDGER, PER PATH — what `shell retire partial` reads
//!
// carried: mise-tasks/reclaim-census.sh mise.toml kind:mechanism crates/batten/tests/it/reclaim_census.rs
// carried: tests/reclaim-census.bats mise.toml kind:mechanism crates/batten/tests/it/reclaim_census.rs
// carried: "a landing in flight when the container was replaced" mise.toml kind:mechanism
// carried: "a landing that stopped on purpose means none was in flight" mise.toml kind:mechanism
// carried: "ABSENCE IS UNOBSERVED, NEVER IDLE — the row the whole correction turns on" mise.toml kind:mechanism
// carried: "REGRESSION: a record under an OLDER boot does not answer for this boundary" mise.toml kind:mechanism
// carried: "records under THIS boot do not answer for the boundary either" mise.toml kind:mechanism
// carried: "no boot predates this one: a fresh disk cannot look" mise.toml kind:mechanism
// carried: "a malformed BATTEN_BOOT_TIME is cannot-look, not a silent /proc fallback" mise.toml kind:mechanism
// carried: "an unknown verb exits 2 and names the ones that exist" mise.toml kind:mechanism
// carried: "tally classifies every boundary, not just the newest" mise.toml kind:mechanism
// carried: "COUNTING IS IDEMPOTENT: repeated reads of one history give one answer" mise.toml kind:mechanism
// carried: "a disk with no replacement has nothing to tally" mise.toml kind:mechanism
// carried: "note h appends a beat carrying the epoch and the boot, and no reason field" mise.toml kind:mechanism
// carried: "note x carries its reason, which is what makes the census readable later" mise.toml kind:mechanism
// carried: "note refuses a kind that is neither h nor x rather than inventing one" mise.toml kind:mechanism
// carried: "A SENSOR NEVER KILLS WHAT IT OBSERVES: an unwritable log is still exit 0" mise.toml kind:mechanism
// carried: "record-boot is idempotent by the last line, so a resumed session adds nothing" mise.toml kind:mechanism
// carried: "record-boot appends when the boot genuinely changed" mise.toml kind:mechanism
// carried: "A KILLED LOOP LEAVES AN h, even though its trap runs" mise.toml kind:mechanism
// carried: "a loop that stops on purpose leaves the matching x" mise.toml kind:mechanism

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::PathBuf;
use std::time::Duration;

const OLD_BOOT: &str = "1000";
const PRIOR_BOOT: &str = "1500";
const THIS_BOOT: &str = "2000";

/// A clone, and the committed body written beside it as a program a loop can
/// call the way `land-lock hold` calls the census.
struct Clone {
    root: PathBuf,
    repo: PathBuf,
}

impl Clone {
    fn new(name: &str) -> Self {
        let root = common::scratch(&format!("reclaim-census-{name}"));
        let repo = root.join("clone");
        std::fs::create_dir_all(&repo).expect("the clone");
        common::init_repo(&repo);
        std::fs::write(root.join("census.sh"), common::task_body("reclaim-census"))
            .expect("the census body");
        Self { root, repo }
    }

    fn census(&self) -> PathBuf {
        self.root.join("census.sh")
    }

    fn log(&self) -> PathBuf {
        self.repo.join(".git/batten-reclaim-log")
    }

    fn boots(&self) -> PathBuf {
        self.repo.join(".git/batten-boots")
    }

    fn with_boots(self, boots: &[&str]) -> Self {
        std::fs::write(self.boots(), format!("{}\n", boots.join("\n"))).expect("boots");
        self
    }

    fn with_log(self, log: &str) -> Self {
        std::fs::write(self.log(), log).expect("log");
        self
    }

    /// The boundary under judgement: PRIOR_BOOT replaced by THIS_BOOT.
    fn boundary(self) -> Self {
        self.with_boots(&[PRIOR_BOOT, THIS_BOOT])
    }

    fn at(&self, boot: &str, args: &[&str]) -> (Option<i32>, String) {
        let out = common::program("bash")
            .arg(self.census())
            .args(args)
            .current_dir(&self.repo)
            .env("BATTEN_BOOT_TIME", boot)
            .env_remove("usage_args")
            .output()
            .expect("run the census");
        (
            out.status.code(),
            format!(
                "{}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            ),
        )
    }

    fn run(&self, args: &[&str]) -> (Option<i32>, String) {
        self.at(THIS_BOOT, args)
    }

    fn read(&self, path: &PathBuf) -> String {
        std::fs::read_to_string(path).unwrap_or_default()
    }
}

#[test]
fn a_landing_in_flight_when_the_container_was_replaced() {
    let c = Clone::new("active")
        .boundary()
        .with_log(&format!("h 1400 {PRIOR_BOOT}\n"));
    let (code, text) = c.run(&["report"]);
    assert_eq!(code, Some(0), "{text}");
    assert!(text.contains("A LANDING WAS IN FLIGHT"), "{text}");
}

#[test]
fn a_landing_that_stopped_on_purpose_means_none_was_in_flight() {
    let c = Clone::new("stopped").boundary().with_log(&format!(
        "h 1300 {PRIOR_BOOT}\nx 1400 {PRIOR_BOOT} land-stopped\n"
    ));
    let (code, text) = c.run(&["report"]);
    assert_eq!(code, Some(1), "{text}");
    assert!(text.contains("stopped on purpose"), "{text}");
    assert!(text.contains("no landing was in flight"), "{text}");
}

#[test]
fn absence_is_unobserved_never_idle() {
    let c = Clone::new("unobserved").boundary().with_log("");
    let (code, text) = c.run(&["report"]);
    assert_eq!(code, Some(2), "{text}");
    assert!(text.contains("UNOBSERVED, not idle"), "{text}");
    // Records under THIS boot do not answer for the boundary either.
    let c = Clone::new("this-boot")
        .boundary()
        .with_log(&format!("h 2100 {THIS_BOOT}\n"));
    let (code, text) = c.run(&["report"]);
    assert_eq!(code, Some(2), "{text}");
    assert!(text.contains("UNOBSERVED"), "{text}");
}

/// The defect itself: the log's newest line is real but two replacements old.
#[test]
fn a_record_under_an_older_boot_does_not_answer_for_this_boundary() {
    let c = Clone::new("older")
        .with_boots(&[OLD_BOOT, PRIOR_BOOT, THIS_BOOT])
        .with_log(&format!("x 900 {OLD_BOOT} land-stopped\n"));
    let (code, text) = c.run(&["report"]);
    assert_eq!(code, Some(2), "{text}");
    assert!(text.contains("UNOBSERVED"), "{text}");
}

#[test]
fn a_fresh_disk_or_a_malformed_boot_time_cannot_look() {
    let c = Clone::new("fresh").with_boots(&[THIS_BOOT]);
    let (code, text) = c.run(&["report"]);
    assert_eq!(code, Some(2), "{text}");
    assert!(text.contains("no evidence either way"), "{text}");
    let c = Clone::new("malformed")
        .boundary()
        .with_log(&format!("h 1400 {PRIOR_BOOT}\n"));
    assert_eq!(c.at("nonsense", &["report"]).0, Some(2));
}

#[test]
fn an_unknown_verb_exits_2_and_names_the_ones_that_exist() {
    let (code, text) = Clone::new("verb").run(&["bogus"]);
    assert_eq!(code, Some(2), "{text}");
    assert!(
        text.contains("unknown mode") && text.contains("tally"),
        "{text}"
    );
}

#[test]
fn tally_classifies_every_boundary_and_is_idempotent() {
    let c = Clone::new("tally")
        .with_boots(&[OLD_BOOT, PRIOR_BOOT, THIS_BOOT])
        .with_log(&format!("h 900 {OLD_BOOT}\n"));
    let (code, text) = c.run(&["tally"]);
    assert_eq!(code, Some(0), "{text}");
    assert!(text.contains("2 replacement(s)"), "{text}");
    assert!(text.contains("1 with a landing in flight"), "{text}");
    assert!(text.contains("1 unobserved"), "{text}");
    let c = Clone::new("tally-twice")
        .with_boots(&[OLD_BOOT, PRIOR_BOOT, THIS_BOOT])
        .with_log(&format!("x 900 {OLD_BOOT} land-stopped\n"));
    let first = c.run(&["tally"]);
    assert_eq!(first, c.run(&["tally"]));
    assert!(first.1.contains("1 idle of landings"), "{}", first.1);
    let (code, text) = Clone::new("no-tally")
        .with_boots(&[THIS_BOOT])
        .run(&["tally"]);
    assert_eq!(code, Some(2), "{text}");
    assert!(text.contains("no container replacement"), "{text}");
}

#[test]
fn the_notes_carry_epoch_boot_and_only_a_given_reason() {
    let c = Clone::new("notes");
    assert_eq!(c.run(&["note", "h"]).0, Some(0));
    let beat = c.read(&c.log());
    let fields: Vec<&str> = beat.trim_end().split(' ').collect();
    assert_eq!(fields.len(), 3, "{beat:?}");
    assert_eq!(fields[0], "h");
    assert!(fields[1].chars().all(|ch| ch.is_ascii_digit()), "{beat:?}");
    assert_eq!(fields[2], THIS_BOOT);
    let c = Clone::new("note-x");
    assert_eq!(c.run(&["note", "x", "land-stopped"]).0, Some(0));
    let stop = c.read(&c.log());
    assert!(
        stop.starts_with("x ") && stop.trim_end().ends_with(" 2000 land-stopped"),
        "{stop:?}"
    );
    assert_eq!(c.run(&["note", "q"]).0, Some(2));
}

/// Called from inside the lease's renewal loop: a census that could abort a
/// landing is worse than the evidence it fails to collect.
#[test]
fn a_sensor_never_kills_what_it_observes() {
    use std::os::unix::fs::PermissionsExt as _;
    let c = Clone::new("unwritable");
    let git = c.repo.join(".git");
    std::fs::set_permissions(&git, std::fs::Permissions::from_mode(0o555)).expect("chmod");
    let code = c.run(&["note", "h"]).0;
    std::fs::set_permissions(&git, std::fs::Permissions::from_mode(0o755)).expect("chmod");
    assert_eq!(code, Some(0));
}

#[test]
fn record_boot_is_idempotent_by_the_last_line_and_appends_a_change() {
    let c = Clone::new("record-boot");
    assert_eq!(c.run(&["record-boot"]).0, Some(0));
    assert_eq!(c.run(&["record-boot"]).0, Some(0));
    assert_eq!(c.read(&c.boots()), format!("{THIS_BOOT}\n"));
    let c = Clone::new("record-change").with_boots(&[PRIOR_BOOT]);
    assert_eq!(c.run(&["record-boot"]).0, Some(0));
    assert_eq!(c.read(&c.boots()), format!("{PRIOR_BOOT}\n{THIS_BOOT}\n"));
}

/// CLOUD-491: a trap fires on the kill too, so an `x` written from one would
/// report every reclaimed container as an intentional stop. A real SIGKILL.
#[test]
fn a_killed_loop_leaves_an_h_even_though_its_trap_runs() {
    let c = Clone::new("killed").boundary();
    let mut loop_child = common::program("bash")
        .args([
            "-c",
            r#"trap 'exit 0' EXIT TERM; while :; do bash "$1" note h; sleep 0.2; done"#,
            "_",
        ])
        .arg(c.census())
        .current_dir(&c.repo)
        .env("BATTEN_BOOT_TIME", PRIOR_BOOT)
        .env_remove("usage_args")
        // The SIGKILL orphans the loop's `sleep`; it must hold none of our pipes.
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("the loop");
    std::thread::sleep(Duration::from_secs(1));
    loop_child.kill().expect("SIGKILL the loop");
    let _ = loop_child.wait();
    let log = c.read(&c.log());
    assert!(
        log.lines()
            .last()
            .is_some_and(|line| line.starts_with("h ")),
        "{log:?}"
    );
    let (code, text) = c.run(&["report"]);
    assert_eq!(code, Some(0), "{text}");
    assert!(text.contains("A LANDING WAS IN FLIGHT"), "{text}");
}

#[test]
fn a_loop_that_stops_on_purpose_leaves_the_matching_x() {
    let c = Clone::new("purpose").boundary();
    for args in [
        &["note", "h"][..],
        &["note", "h"],
        &["note", "x", "land-stopped"],
    ] {
        assert_eq!(c.at(PRIOR_BOOT, args).0, Some(0));
    }
    let log = c.read(&c.log());
    assert!(
        log.lines()
            .last()
            .is_some_and(|line| line.starts_with("x ") && line.ends_with("land-stopped")),
        "{log:?}"
    );
    assert_eq!(c.run(&["report"]).0, Some(1));
}

/// The lease spawns what the consumer declares; after the retirement it must
/// name the inline task, not the deleted file.
#[test]
fn the_declared_stop_note_reaches_the_inline_task() {
    let note = common::task_env("LEASE_STOP_NOTE");
    assert!(note.contains("reclaim-census"), "{note}");
    assert!(!note.contains("mise-tasks/"), "{note}");
    assert!(note.ends_with("note x land-stopped"), "{note}");
}
