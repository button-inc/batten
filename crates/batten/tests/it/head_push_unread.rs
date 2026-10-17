//! A push over a red head owes each failed check's log a read (CLOUD-2270).
//!
//! Over the compiled binary: the hook resolves the `red-head` fact from the
//! branch's record, the `red-head` preset refuses the push naming each unread
//! failure and each check still running, and a log read — minted by the REAL
//! post-tool path, never a receipt this suite types — admits the same push.
//!
//! A FIXTURE config rather than the committed table, for `forced_push.rs`'s
//! `linear_decision` reason: a consumer row naming a preset the pinned engine
//! does not ship is a config that engine cannot load.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::{Path, PathBuf};

use crate::common;

/// The preset at the mediated surface, and the receipt a log read mints.
const CONFIG: &str = "version = 1\n\n\
[[rule]]\nid = \"job read unread\"\nkind = \"policy\"\n\
scope = \"mediated_call\"\npreset = \"red-head\"\nseverity = \"deny\"\n\n\
[[mint]]\nname = \"check-log-read\"\ntool = \"get_job_logs\"\nkey = \"named\"\n\
key_from = \"job_id\"\nrequires = [\"job_id\", \"logs_content\"]\nmode = \"replace\"\n\
body = \"{job_id} {now}\"\n\n\
[[mint]]\nname = \"check-run-read\"\ntool = \"get_check_run\"\nkey = \"named\"\n\
key_from = \"id\"\nrequires = [\"id\", \"conclusion\"]\nmode = \"replace\"\n\
body = \"{id} {now}\"\n";

/// A repository on a branch whose head stopped red: `windows` failed as run
/// `101`, and `macos` was still running when the stop was taken.
fn red_repo(name: &str) -> PathBuf {
    let dir = common::Fixture::new(name)
        .config(CONFIG)
        .base_commit()
        .build();
    common::git_in(&dir, &["checkout", "-q", "-b", "work/red"]);
    let store = dir.join(".git/batten-receipts");
    std::fs::create_dir_all(&store).expect("the receipt store is creatable");
    std::fs::write(
        store.join(format!(
            "{}.{}",
            batten::land::RED_HEAD,
            batten::land::red_head_slug("work/red")
        )),
        "head abc123\nfailed 101 windows\nrunning macos\n",
    )
    .expect("record the red head");
    dir
}

/// Replace `work/red`'s record with `text`.
fn rewrite_record(dir: &Path, text: &str) {
    std::fs::write(
        dir.join(".git/batten-receipts").join(format!(
            "{}.{}",
            batten::land::RED_HEAD,
            batten::land::red_head_slug("work/red")
        )),
        text,
    )
    .expect("rewrite the red head");
}

/// A required check's completed run, as a reading carries it.
fn run(conclusion: &str, name: &str, id: u64) -> batten::checks_green::Run {
    batten::checks_green::Run {
        status: "completed".to_owned(),
        conclusion: conclusion.to_owned(),
        name: name.to_owned(),
        started_at: "2026-01-01T00:00:00Z".to_owned(),
        completed_at: String::new(),
        id,
    }
}

fn roster(required: &[&str], fanin: Option<&str>) -> batten::checks_green::Roster {
    batten::checks_green::Roster {
        required: required.iter().map(|name| (*name).to_owned()).collect(),
        absent_ok: Vec::new(),
        answered: vec!["success".to_owned(), "failure".to_owned()],
        fanin: fanin.map(str::to_owned),
    }
}

fn failed(check: &str) -> batten::checks_green::Finding {
    batten::checks_green::Finding {
        check: check.to_owned(),
        conclusion: "failure".to_owned(),
    }
}

/// A RECORD FOR A SUPERSEDED HEAD OWES NOTHING (CLOUD-2443): once the branch's
/// remote head is another commit, the runs the record names decide nothing, and
/// before this the debt stood until a green landing cleared it.
#[test]
fn a_record_for_a_superseded_head_owes_nothing() {
    let dir = red_repo("head-push-superseded");
    let tip = common::git_in(&dir, &["rev-parse", "HEAD"]);
    let tip = tip.trim();

    // The remote head IS the recorded head: owed.
    common::git_in(&dir, &["update-ref", "refs/remotes/origin/work/red", tip]);
    rewrite_record(&dir, &format!("head {tip}\nfailed 101 windows\n"));
    assert!(
        decision(&dir, "git push origin HEAD").contains("job read unread"),
        "a record for the remote head is owed"
    );

    // Another route moved the branch: the record is about a head nobody pushes over.
    rewrite_record(&dir, "head abc123\nfailed 101 windows\n");
    let out = decision(&dir, "git push origin HEAD");
    assert!(
        !out.contains("job read unread"),
        "a superseded head owes nothing\n{out}"
    );
    assert_eq!(batten::land::red_head_owed(&dir, "work/red"), None);
}

/// A FAILED FAN-IN OWES ITS FAILED MEMBERS (CLOUD-2443), so reading the
/// aggregator's "a dependency failed" pays nothing: #1132's incident.
#[test]
fn a_failed_fan_in_owes_its_failed_members() {
    let dir = red_repo("head-push-fan-in");
    let runs = [
        run("failure", "final", 1),
        run("failure", "windows", 2),
        run("cancelled", "linux", 3),
    ];
    let reading = batten::land::red_runs(
        &runs,
        &roster(&["final"], Some("final")),
        &[failed("final")],
    );
    batten::land::record_red_head(&dir, "work/red", "abc123", &reading).expect("record");

    read_the_log(&dir, 1);
    let out = decision(&dir, "git push origin HEAD");
    assert!(
        out.contains("job read unread") && out.contains("windows job 2"),
        "the aggregator's log pays nothing; the failed member is owed\n{out}"
    );
    read_the_log(&dir, 2);
    assert!(!decision(&dir, "git push origin HEAD").contains("job read unread"));
}

/// A CHECK RUNNING AT THE STOP IS OWED UNTIL READ (CLOUD-2443): reading the
/// named failure no longer admits a push over a check whose verdict it buries.
#[test]
fn a_check_running_at_the_stop_is_owed_until_read() {
    let dir = red_repo("head-push-running");
    rewrite_record(&dir, "head abc123\nfailed 101 windows\nrunning 102 macos\n");
    read_the_log(&dir, 101);
    let out = decision(&dir, "git push origin HEAD");
    assert!(
        out.contains("job read unread") && out.contains("macos job 102"),
        "the run the stop abandoned is still owed\n{out}"
    );
    read_the_log(&dir, 102);
    assert!(!decision(&dir, "git push origin HEAD").contains("job read unread"));
}

/// ONE RECORD AND EVERY STORE ACROSS WORKTREES (CLOUD-2443): `land` in a
/// linked worktree writes where the main checkout reads, and a read minted in
/// the worktree pays a debt judged from the main checkout.
#[test]
fn a_linked_worktrees_record_and_reads_are_the_repositorys() {
    let dir = red_repo("head-push-worktree");
    let linked = common::scratch("head-push-worktree-linked");
    let _ = std::fs::remove_dir_all(&linked);
    common::git_in(
        &dir,
        &[
            "worktree",
            "add",
            "-q",
            "-b",
            "work/linked",
            linked.to_str().expect("utf-8"),
        ],
    );
    std::fs::write(linked.join("batten.toml"), CONFIG).expect("the worktree's config");

    let reading = batten::land::red_runs(
        &[run("failure", "lint", 7)],
        &roster(&["lint"], None),
        &[failed("lint")],
    );
    batten::land::record_red_head(&linked, "work/linked", "abc123", &reading).expect("record");
    assert!(
        batten::land::red_head_owed(&dir, "work/linked").is_some(),
        "the main checkout reads the linked worktree's record"
    );

    // The main checkout's own debt, read from inside the linked worktree.
    read_the_log(&linked, 101);
    let out = decision(&dir, "git push origin HEAD");
    assert!(
        !out.contains("job read unread"),
        "a read minted in a linked worktree pays\n{out}"
    );
}

/// A RUN WITH NO ID IS NEVER RECORDED (CLOUD-2443): `failed 0 <name>` is a debt
/// no receipt can name, so it would refuse every push for good.
#[test]
fn a_run_with_no_id_owes_nothing() {
    let dir = red_repo("head-push-no-id");
    let runs = [run("failure", "lint", 0), run("failure", "fmt", 9)];
    let reading = batten::land::red_runs(
        &runs,
        &roster(&["lint", "fmt"], None),
        &[failed("lint"), failed("fmt")],
    );
    assert_eq!(reading.failed, vec![(9, "fmt".to_owned())]);
    batten::land::record_red_head(&dir, "work/red", "abc123", &reading).expect("record");
    read_the_log(&dir, 9);
    assert_eq!(batten::land::red_head_owed(&dir, "work/red"), None);
}

/// THE READS GO WITH THE RECORD (CLOUD-2443): a cleared record sweeps the
/// receipts it named, and a replacing one keeps only those it still names.
#[test]
fn a_cleared_record_sweeps_its_reads() {
    let dir = red_repo("head-push-sweep");
    let receipt = |id: u64| {
        dir.join(".git/batten-receipts")
            .join(format!("{}.{id}", batten::land::CHECK_LOG_READ))
    };
    rewrite_record(&dir, "head abc123\nfailed 101 windows\nfailed 102 linux\n");
    read_the_log(&dir, 101);
    read_the_log(&dir, 102);
    assert!(receipt(101).is_file() && receipt(102).is_file());

    let reading = batten::land::RedReading {
        failed: vec![(101, "windows".to_owned())],
        running: Vec::new(),
    };
    batten::land::record_red_head(&dir, "work/red", "def456", &reading).expect("record");
    assert!(
        receipt(101).is_file(),
        "a run the new record still names keeps its read"
    );
    assert!(!receipt(102).is_file(), "a run it no longer names is swept");

    assert!(batten::land::clear_red_head(&dir, "work/red").expect("clear"));
    assert!(
        !receipt(101).is_file(),
        "clearing the record sweeps its reads"
    );
}

/// THE KEY IS INJECTIVE (review of #1180): `work/red` and `work-red` are two
/// branches and two records, so neither's debt is read, or cleared, as the
/// other's. Under the shared `/` → `-` slug both named one file.
#[test]
fn a_sibling_branchs_red_head_is_not_this_branchs() {
    assert_ne!(
        batten::land::red_head_slug("work/red"),
        batten::land::red_head_slug("work-red")
    );
    assert_ne!(
        batten::land::red_head_slug("a%2Fb"),
        batten::land::red_head_slug("a/b")
    );
}

/// A Claude Code `PreToolUse` envelope carrying a shell command.
fn bash_payload(command: &str) -> String {
    let escaped = serde_json::to_string(command).expect("a command is encodable");
    format!(
        "{{\"hook_event_name\":\"PreToolUse\",\"tool_name\":\"Bash\",\
         \"tool_input\":{{\"command\":{escaped}}}}}"
    )
}

fn decision(dir: &Path, command: &str) -> String {
    common::stdout(&common::run_with_stdin(
        dir,
        &["adjudicate", "--harness", "claude-code"],
        &bash_payload(command),
    ))
}

/// A completed `get_job_logs` call, handed to the engine as the host would.
fn read_the_log(dir: &Path, job_id: u64) {
    let payload = format!(
        "{{\"hook_event_name\":\"PostToolUse\",\"tool_name\":\"mcp__github__get_job_logs\",\
         \"tool_input\":{{\"job_id\":{job_id}}},\
         \"tool_response\":{{\"job_id\":{job_id},\"logs_content\":\"error: the build failed\"}}}}"
    );
    // The status is discarded: a post-tool event carries no verdict. What the
    // case reads is the push decided after it.
    let _ = common::run_with_stdin(dir, &["adjudicate", "--harness", "exit-code"], &payload);
}

#[test]
fn a_push_over_an_unread_red_check_is_refused() {
    let dir = red_repo("head-push-unread-refused");
    let out = decision(&dir, "git push origin HEAD");
    assert!(
        out.contains("\"deny\"") && out.contains("job read unread"),
        "a push over an unread failure is refused by this class\n{out}"
    );
    assert!(
        out.contains("windows") && out.contains("macos"),
        "naming the unread failure AND the check still running\n{out}"
    );

    // ANTI-VACUITY: the same tree admits a call that is not a push, so the
    // refusal above is about the push and not about the record's existence.
    let fetch = decision(&dir, "git fetch origin");
    assert!(
        !fetch.contains("job read unread"),
        "a fetch owes the red head nothing\n{fetch}"
    );
}

#[test]
fn reading_the_failed_check_admits_the_push() {
    let dir = red_repo("head-push-unread-read");
    // The premise first: unread, the push is refused.
    assert!(
        decision(&dir, "git push origin HEAD").contains("job read unread"),
        "the push is refused before the log is read"
    );

    read_the_log(&dir, 101);
    assert!(
        dir.join(".git/batten-receipts")
            .join(format!("{}.101", batten::land::CHECK_LOG_READ))
            .is_file(),
        "the read minted its own receipt"
    );

    let out = decision(&dir, "git push origin HEAD");
    assert!(
        !out.contains("job read unread"),
        "reading the failed check's log admits the push, though macos still runs\n{out}"
    );
}

/// A FAILED CHECK NO ACTIONS JOB RUNS has no log to read, so its check run is
/// the read (review of #1180): without this route a third-party failure would
/// refuse every push for good.
#[test]
fn reading_a_failed_check_run_admits_the_push() {
    let dir = red_repo("head-push-unread-check-run");
    let payload = "{\"hook_event_name\":\"PostToolUse\",\
         \"tool_name\":\"mcp__github__get_check_run\",\
         \"tool_input\":{\"check_run_id\":101},\
         \"tool_response\":{\"id\":101,\"conclusion\":\"failure\"}}";
    let _ = common::run_with_stdin(&dir, &["adjudicate", "--harness", "exit-code"], payload);
    let out = decision(&dir, "git push origin HEAD");
    assert!(
        !out.contains("job read unread"),
        "a read check run pays the debt as a job log does\n{out}"
    );
}

/// `land` IS THE PRESCRIBED PUSH, and the hook sees `mise run land`, never the
/// lap's own push (review of #1180). The landing's entry asks the same record,
/// and only where a row enables the preset.
#[test]
fn the_landing_owes_the_same_read_as_a_hand_push() {
    let dir = red_repo("head-push-unread-landing");
    let owed = batten::land::red_head_owed(&dir, "work/red").expect("unread debt is owed");
    assert!(
        owed.iter().any(|subject| subject.contains("windows"))
            && owed
                .iter()
                .any(|subject| subject.contains("macos still running")),
        "{owed:?}"
    );

    read_the_log(&dir, 101);
    assert_eq!(
        batten::land::red_head_owed(&dir, "work/red"),
        None,
        "a read failure owes the landing nothing"
    );

    // WITHOUT THE PRESET nothing is owed, whatever the record says: a consumer
    // that never opted in has no mint to pay with.
    let bare = red_repo("head-push-unread-landing-bare");
    std::fs::write(bare.join("batten.toml"), "version = 1\n").expect("write a bare config");
    assert_eq!(batten::land::red_head_owed(&bare, "work/red"), None);
}
