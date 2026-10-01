//! `batten record census` — was a landing in flight when this container
//! replaced the last one (CLOUD-451), over the compiled binary (CLOUD-843).
//!
//! THE ROWS ARE ABOUT TRANSITIONS, not files (CLOUD-696): every verdict case
//! records the boots as well as the beats, because a verdict without a boundary
//! is not one. `BATTEN_BOOT_TIME` is injected throughout, or `/proc/stat` is the
//! only boot source and no row could discriminate (CLOUD-418).
//!
//! THE FIXTURES ARE WRITTEN THROUGH THE VERBS THEMSELVES, never by hand: the
//! stores are journal families, and a case that planted a shard would assert
//! over a layout rather than over what `note` and `record-boot` write. The one
//! exception is the torn tail, which no verb can produce by construction.
//!
//! # RETIREMENT LEDGER, PER PATH — what `shell retire partial` reads
//!
// carried: mise-tasks/reclaim-census.sh crates/batten/src/reclaim.rs kind:verb crates/batten/tests/it/reclaim_census.rs
// carried: tests/reclaim-census.bats crates/batten/src/reclaim.rs kind:verb crates/batten/tests/it/reclaim_census.rs
// changed: "a landing in flight when the container was replaced" crates/batten/src/reclaim.rs kind:verb same reading on stdout, folded onto §7 through `ExitCode::combine` (rule 5): the one finding is exit 2 where the task answered 0
// changed: "a landing that stopped on purpose means none was in flight" crates/batten/src/reclaim.rs kind:verb same reading on stdout, folded onto §7: nothing to report is exit 0 where the task answered 1, which is §7's usage code and no statement about a past container can be
// changed: "ABSENCE IS UNOBSERVED, NEVER IDLE — the row the whole correction turns on" crates/batten/src/reclaim.rs kind:verb same reading on stderr, folded onto §7: a blind spot is could-not-look, exit 3 where the task answered 2 — the code `record-boot` and `tally` give the same causes
// changed: "REGRESSION: a record under an OLDER boot does not answer for this boundary" crates/batten/src/reclaim.rs kind:verb same UNOBSERVED reading, at exit 3 where the task answered 2 (folded onto §7)
// changed: "records under THIS boot do not answer for the boundary either" crates/batten/src/reclaim.rs kind:verb same UNOBSERVED reading, at exit 3 where the task answered 2 (folded onto §7)
// changed: "no boot predates this one: a fresh disk cannot look" crates/batten/src/reclaim.rs kind:verb same could-not-look on stderr, at §7's exit 3 where the task answered 2
// changed: "a malformed BATTEN_BOOT_TIME is cannot-look, not a silent /proc fallback" crates/batten/src/reclaim.rs kind:verb still could-not-look and still never a `/proc/stat` fallback, at §7's exit 3 where the task's `report` answered 2
// changed: "an unknown verb exits 2 and names the ones that exist" crates/batten/src/cli.rs kind:verb the modes are clap subcommands now, so an unknown one is refused by the parser before the verb runs, at §7's usage code 1 rather than the task's 2, and the parser's own error names what it did not recognise
// carried: "tally classifies every boundary, not just the newest" crates/batten/src/reclaim.rs kind:verb
// carried: "COUNTING IS IDEMPOTENT: repeated reads of one history give one answer" crates/batten/src/reclaim.rs kind:verb
// changed: "a disk with no replacement has nothing to tally" crates/batten/src/reclaim.rs kind:verb zero replacements is a COUNT, printed as one at exit 0: `tally` is declared with §7's standard exits, where 2 is a verdict about the repository and a tally renders none. Could-not-look — no git directory, an unreadable store — is exit 3
// carried: "note h appends a beat carrying the epoch and the boot, and no reason field" crates/batten/src/reclaim.rs kind:verb
// carried: "note x carries its reason, which is what makes the census readable later" crates/batten/src/reclaim.rs kind:verb
// changed: "note refuses a kind that is neither h nor x rather than inventing one" crates/batten/src/reclaim.rs kind:verb still refused, at §7's usage code 1 rather than the task's 2; the kind is also REQUIRED now where the task defaulted an absent one to h, and a reason carrying whitespace is refused because it would fold back as extra fields
// carried: "A SENSOR NEVER KILLS WHAT IT OBSERVES: an unwritable log is still exit 0" crates/batten/src/reclaim.rs kind:verb
// carried: "record-boot is idempotent by the last line, so a resumed session adds nothing" crates/batten/src/reclaim.rs kind:verb
// carried: "record-boot appends when the boot genuinely changed" crates/batten/src/reclaim.rs kind:verb
// changed: "A KILLED LOOP LEAVES AN h, even though its trap runs" crates/batten/src/lib.rs kind:mechanism there is no shell loop and no trap any more. The holder that runs is `land lap`, which writes `$LEASE_BEAT_NOTE` once when it starts, before any lap or lease, and `$LEASE_STOP_NOTE` only where it RETURNS, never where a lap hands its lease back and laps (`land_census_window`, `a_landing_notes_its_start_and_every_chosen_end`). Its `Heartbeat` writes no census note: the census reads only the kind of the last record under the boot, so no beat between those two can change a verdict, and one there also fired under the hand-stepping `land wait`, which no window closes. A kill never returns, so the last record stays a beat by construction. What is observable here is the census half, `beats_that_end_without_a_stop_read_as_in_flight`
// changed: "a loop that stops on purpose leaves the matching x" crates/batten/src/reclaim.rs kind:verb the matching x is still the last record and still reads as a deliberate stop, now at §7's exit 0 where the task's `report` answered 1
// changed: "log-path and boot print the store and the boot time" crates/batten/src/reclaim.rs kind:verb withdrawn as accessors: they existed only so `session:census` could rebuild the mark path in shell, and `report --once` writes the mark itself, so no caller re-derives either
// changed: "the stores are $GIT_DIR/batten-reclaim-log and $GIT_DIR/batten-boots" crates/batten/src/reclaim.rs kind:verb the two stores are journal families (`reclaim-beats`, `reclaim-boots`) written through `journal::append_line_healing`, which truncates a torn tail before it appends so a new record cannot glue onto one, and read through `fold_lines`, which drops a torn tail — `a_torn_stop_does_not_answer_for_its_boot` — where the hand-rolled log would have read one as the last record. A disk's pre-retirement history is not migrated: the first boot after the change is UNOBSERVED, which is the verdict the census already gives a boundary it has no record of

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::fmt::Write as _;

use std::path::PathBuf;

const OLD_BOOT: &str = "1000";
const PRIOR_BOOT: &str = "1500";
const THIS_BOOT: &str = "2000";

/// A clone whose git directory holds the census's two stores.
struct Clone {
    repo: PathBuf,
}

impl Clone {
    fn new(name: &str) -> Self {
        let root = common::scratch(&format!("reclaim-census-{name}"));
        let repo = root.join("clone");
        std::fs::create_dir_all(&repo).expect("the clone");
        common::init_repo(&repo);
        Self { repo }
    }

    /// `batten record census <args>` under the boot `boot`.
    fn at(&self, boot: &str, args: &[&str]) -> (Option<i32>, String) {
        let out = common::batten()
            .args(["record", "census"])
            .args(args)
            .current_dir(&self.repo)
            .env("BATTEN_BOOT_TIME", boot)
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

    /// Record each boot in order, the way successive containers would.
    fn with_boots(self, boots: &[&str]) -> Self {
        for boot in boots {
            assert_eq!(self.at(boot, &["record-boot"]).0, Some(0), "record {boot}");
        }
        self
    }

    /// Write one note under `boot`.
    fn noted(self, boot: &str, args: &[&str]) -> Self {
        let mut command = vec!["note"];
        command.extend_from_slice(args);
        assert_eq!(
            self.at(boot, &command).0,
            Some(0),
            "note {args:?} under {boot}"
        );
        self
    }

    /// The boundary under judgement: `PRIOR_BOOT` replaced by `THIS_BOOT`.
    fn boundary(self) -> Self {
        self.with_boots(&[PRIOR_BOOT, THIS_BOOT])
    }

    /// One family's whole records, as `record fold` reads them back.
    fn fold(&self, family: &str) -> String {
        let out = common::run(&self.repo, &["record", "fold", family]);
        assert_eq!(out.status.code(), Some(0), "fold {family}");
        common::stdout(&out)
    }

    fn beats(&self) -> String {
        self.fold("reclaim-beats")
    }

    fn boots(&self) -> String {
        self.fold("reclaim-boots")
    }
}

#[test]
fn a_landing_in_flight_when_the_container_was_replaced() {
    let c = Clone::new("active")
        .with_boots(&[PRIOR_BOOT])
        .noted(PRIOR_BOOT, &["h"])
        .with_boots(&[THIS_BOOT]);
    let (code, text) = c.run(&["report"]);
    assert_eq!(
        code,
        Some(2),
        "the one finding is §7's verdict code: {text}"
    );
    assert!(text.contains("A LANDING WAS IN FLIGHT"), "{text}");
    assert!(
        text.contains(&format!("under boot {PRIOR_BOOT}, now {THIS_BOOT}")),
        "{text}"
    );
}

#[test]
fn a_landing_that_stopped_on_purpose_means_none_was_in_flight() {
    let c = Clone::new("stopped")
        .with_boots(&[PRIOR_BOOT])
        .noted(PRIOR_BOOT, &["h"])
        .noted(PRIOR_BOOT, &["x", "land-stopped"])
        .with_boots(&[THIS_BOOT]);
    let (code, text) = c.run(&["report"]);
    assert_eq!(code, Some(0), "nothing to report is clean: {text}");
    assert!(text.contains("stopped on purpose"), "{text}");
    assert!(text.contains("no landing was in flight"), "{text}");
}

#[test]
fn absence_is_unobserved_never_idle() {
    let c = Clone::new("unobserved").boundary();
    let (code, text) = c.run(&["report"]);
    assert_eq!(code, Some(3), "a blind spot is could-not-look: {text}");
    assert!(text.contains("UNOBSERVED, not idle"), "{text}");
    // Records under THIS boot do not answer for the boundary either.
    let c = Clone::new("this-boot").boundary().noted(THIS_BOOT, &["h"]);
    let (code, text) = c.run(&["report"]);
    assert_eq!(code, Some(3), "{text}");
    assert!(text.contains("UNOBSERVED"), "{text}");
}

/// The defect itself: the store's newest record is real but two replacements old.
#[test]
fn a_record_under_an_older_boot_does_not_answer_for_this_boundary() {
    let c = Clone::new("older")
        .with_boots(&[OLD_BOOT])
        .noted(OLD_BOOT, &["x", "land-stopped"])
        .with_boots(&[PRIOR_BOOT, THIS_BOOT]);
    let (code, text) = c.run(&["report"]);
    assert_eq!(code, Some(3), "{text}");
    assert!(text.contains("UNOBSERVED"), "{text}");
}

#[test]
fn a_fresh_disk_or_a_malformed_boot_time_cannot_look() {
    let c = Clone::new("fresh").with_boots(&[THIS_BOOT]);
    let (code, text) = c.run(&["report"]);
    assert_eq!(code, Some(3), "{text}");
    assert!(text.contains("no evidence either way"), "{text}");
    let c = Clone::new("malformed")
        .with_boots(&[PRIOR_BOOT])
        .noted(PRIOR_BOOT, &["h"])
        .with_boots(&[THIS_BOOT]);
    assert_eq!(c.at("nonsense", &["report"]).0, Some(3));
    // AUTHORITATIVE WHEN SET: a malformed override never falls through to
    // `/proc/stat`, so it records no boot (could-not-look, exit 3) and a note
    // under it writes nothing while still exiting 0.
    assert_eq!(c.at("nonsense", &["record-boot"]).0, Some(3));
    assert_eq!(c.boots(), format!("{PRIOR_BOOT}\n{THIS_BOOT}\n"));
    let before = c.beats();
    assert_eq!(c.at("12x", &["note", "h"]).0, Some(0));
    assert_eq!(c.beats(), before);
}

#[test]
fn an_unknown_mode_is_a_usage_error() {
    let (code, text) = Clone::new("verb").run(&["bogus"]);
    assert_eq!(code, Some(1), "{text}");
    assert!(text.contains("bogus"), "{text}");
}

#[test]
fn tally_classifies_every_boundary_and_is_idempotent() {
    let c = Clone::new("tally")
        .with_boots(&[OLD_BOOT])
        .noted(OLD_BOOT, &["h"])
        .with_boots(&[PRIOR_BOOT, THIS_BOOT]);
    let (code, text) = c.run(&["tally"]);
    assert_eq!(code, Some(0), "{text}");
    assert!(text.contains("2 replacement(s)"), "{text}");
    assert!(text.contains("1 with a landing in flight"), "{text}");
    assert!(text.contains("1 unobserved"), "{text}");
    let c = Clone::new("tally-twice")
        .with_boots(&[OLD_BOOT])
        .noted(OLD_BOOT, &["x", "land-stopped"])
        .with_boots(&[PRIOR_BOOT, THIS_BOOT]);
    let first = c.run(&["tally"]);
    assert_eq!(first, c.run(&["tally"]));
    assert!(first.1.contains("1 idle of landings"), "{}", first.1);
    // Zero is a count, and a count is an answer.
    let (code, text) = Clone::new("no-tally")
        .with_boots(&[THIS_BOOT])
        .run(&["tally"]);
    assert_eq!(code, Some(0), "{text}");
    assert!(text.contains("0 replacement(s)"), "{text}");
}

#[test]
fn the_notes_carry_epoch_boot_and_only_a_given_reason() {
    let c = Clone::new("notes").noted(THIS_BOOT, &["h"]);
    let beat = c.beats();
    let fields: Vec<&str> = beat.trim_end().split(' ').collect();
    assert_eq!(fields.len(), 3, "{beat:?}");
    assert_eq!(fields[0], "h");
    assert!(fields[1].chars().all(|ch| ch.is_ascii_digit()), "{beat:?}");
    assert_eq!(fields[2], THIS_BOOT);
    let c = Clone::new("note-x").noted(THIS_BOOT, &["x", "land-stopped"]);
    let stop = c.beats();
    assert!(
        stop.starts_with("x ") && stop.trim_end().ends_with(" 2000 land-stopped"),
        "{stop:?}"
    );
    assert_eq!(c.run(&["note", "q"]).0, Some(1));
    assert_eq!(c.run(&["note", "x", "two words"]).0, Some(1));
    assert_eq!(c.beats(), stop, "a refused note writes nothing");
}

/// Called from inside the lease's renewal loop: a census that could abort a
/// landing is worse than the evidence it fails to collect.
#[test]
fn a_sensor_never_kills_what_it_observes() {
    let c = Clone::new("unwritable");
    let git = c.repo.join(".git");
    // The store is made unwritable where the platform can say so. Elsewhere the
    // case still runs, and still asserts the sensor exits 0 over a live clone.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&git, std::fs::Permissions::from_mode(0o555)).expect("chmod");
    }
    let code = c.run(&["note", "h"]).0;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&git, std::fs::Permissions::from_mode(0o755)).expect("chmod");
    }
    #[cfg(not(unix))]
    let _ = &git;
    assert_eq!(code, Some(0));
    // And outside a repository entirely, the sensor still exits 0.
    // OUTSIDE THIS TREE, because `scratch` lives under `target/` and discovery
    // from there would find this repository and write to its real store.
    let outside = common::scratch_outside_tree("batten-reclaim-census", "outside");
    let out = common::batten()
        .args(["record", "census", "note", "h"])
        .current_dir(&outside)
        .env("BATTEN_BOOT_TIME", THIS_BOOT)
        .output()
        .expect("run the census");
    assert_eq!(out.status.code(), Some(0));
}

#[test]
fn record_boot_is_idempotent_by_the_last_line_and_appends_a_change() {
    let c = Clone::new("record-boot").with_boots(&[THIS_BOOT, THIS_BOOT]);
    assert_eq!(c.boots(), format!("{THIS_BOOT}\n"));
    let c = Clone::new("record-change").with_boots(&[PRIOR_BOOT, THIS_BOOT]);
    assert_eq!(c.boots(), format!("{PRIOR_BOOT}\n{THIS_BOOT}\n"));
    // A boot that RECURS after a different one is a genuine new boundary.
    let c = Clone::new("record-recur").with_boots(&[PRIOR_BOOT, THIS_BOOT, PRIOR_BOOT]);
    assert_eq!(
        c.boots(),
        format!("{PRIOR_BOOT}\n{THIS_BOOT}\n{PRIOR_BOOT}\n")
    );
}

/// What a holder killed mid-landing leaves: beats, and no stop after them.
#[test]
fn beats_that_end_without_a_stop_read_as_in_flight() {
    let c = Clone::new("killed")
        .with_boots(&[PRIOR_BOOT])
        .noted(PRIOR_BOOT, &["h"])
        .noted(PRIOR_BOOT, &["x", "land-stopped"])
        .noted(PRIOR_BOOT, &["h"])
        .noted(PRIOR_BOOT, &["h"])
        .with_boots(&[THIS_BOOT]);
    assert!(
        c.beats()
            .lines()
            .last()
            .is_some_and(|line| line.starts_with("h ")),
        "{}",
        c.beats()
    );
    let (code, text) = c.run(&["report"]);
    assert_eq!(code, Some(2), "{text}");
    assert!(text.contains("A LANDING WAS IN FLIGHT"), "{text}");
}

#[test]
fn a_loop_that_stops_on_purpose_leaves_the_matching_x() {
    let c = Clone::new("purpose")
        .with_boots(&[PRIOR_BOOT])
        .noted(PRIOR_BOOT, &["h"])
        .noted(PRIOR_BOOT, &["h"])
        .noted(PRIOR_BOOT, &["x", "land-stopped"])
        .with_boots(&[THIS_BOOT]);
    let beats = c.beats();
    assert!(
        beats
            .lines()
            .last()
            .is_some_and(|line| line.starts_with("x ") && line.ends_with("land-stopped")),
        "{beats:?}"
    );
    assert_eq!(c.run(&["report"]).0, Some(0));
}

/// THE DISCRIMINATING CASE FOR THE STORE (CLOUD-1032): a process killed
/// mid-append leaves a line with no terminator. The census classifies a boot by
/// the KIND of its last record, so a torn stop read as a record would turn an
/// in-flight landing into an intentional one. No verb can write a torn line, so
/// this one is appended by hand to the shard the notes went to.
#[test]
fn a_torn_stop_does_not_answer_for_its_boot() {
    let c = Clone::new("torn")
        .with_boots(&[PRIOR_BOOT])
        .noted(PRIOR_BOOT, &["h"])
        .with_boots(&[THIS_BOOT]);
    let shards = c
        .repo
        .join(".git/batten-journals/reclaim-beats/journal/shards");
    let shard = std::fs::read_dir(&shards)
        .expect("the beat went to a shard")
        .flatten()
        .map(|entry| entry.path())
        .find(|path| path.extension().is_some_and(|ext| ext == "jsonl"))
        .expect("one shard");
    let mut text = std::fs::read_to_string(&shard).expect("readable shard");
    write!(text, "x 1600 {PRIOR_BOOT} land-stopped").expect("a String takes a write");
    std::fs::write(&shard, &text).expect("writable shard");
    let (code, out) = c.run(&["report"]);
    assert_eq!(code, Some(2), "{out}");
    assert!(out.contains("A LANDING WAS IN FLIGHT"), "{out}");
    // AND AFTER THE NEXT APPEND (round-2 review). `O_APPEND` would write the new
    // record straight after the fragment, and the pair would fold back as ONE
    // whole `x` under the prior boot — idle, with this container's own record
    // swallowed. The write drops the fragment first.
    assert_eq!(c.run(&["note", "h"]).0, Some(0));
    let (code, out) = c.run(&["report"]);
    assert_eq!(code, Some(2), "a torn stop glued to the next record: {out}");
    let beats = c.beats();
    assert!(
        beats
            .lines()
            .any(|line| line.starts_with("h ") && line.ends_with(THIS_BOOT)),
        "the next record stands alone: {beats:?}"
    );
    assert!(!beats.contains("land-stopped"), "{beats:?}");
}

/// The lease spawns what the consumer declares, and both notes are now ARGV for
/// the engine's own verb — never a task runner and never a shell.
#[test]
fn the_declared_notes_are_argv_for_the_census_verb() {
    assert_eq!(
        common::task_env("LEASE_STOP_NOTE"),
        "batten record census note x land-stopped"
    );
    assert_eq!(
        common::task_env("LEASE_BEAT_NOTE"),
        "batten record census note h"
    );
}

/// The two retired tasks are gone, and the session-start row names the verb.
#[test]
fn the_census_tasks_are_retired_onto_the_verb() {
    let manifest = std::fs::read_to_string(common::at_root("mise.toml")).expect("mise.toml");
    let manifest: toml::Value = toml::from_str(&manifest).expect("mise.toml parses");
    for task in ["reclaim-census", "session:census"] {
        assert!(manifest["tasks"].get(task).is_none(), "[tasks.{task:?}]");
    }
    let config = std::fs::read_to_string(common::at_root("batten.toml")).expect("batten.toml");
    let parsed: toml::Value = toml::from_str(&config).expect("batten.toml parses");
    let handlers = parsed["hook"]["handler"].as_array().expect("handler rows");
    let row = handlers
        .iter()
        .find(|row| row["id"].as_str() == Some("session-census"))
        .expect("the session-census row");
    let run: Vec<&str> = row["run"]
        .as_array()
        .expect("argv")
        .iter()
        .map(|word| word.as_str().expect("a word"))
        .collect();
    assert_eq!(run, ["batten", "record", "census", "report", "--once"]);
}
