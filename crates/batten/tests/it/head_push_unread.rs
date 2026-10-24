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
            batten::receipt::branch_slug("work/red")
        )),
        "head abc123\nfailed 101 windows\nrunning macos\n",
    )
    .expect("record the red head");
    dir
}

/// THE KEY IS INJECTIVE (review of #1180): `work/red` and `work-red` are two
/// branches and two records, so neither's debt is read, or cleared, as the
/// other's. Under the old `/` → `-` slug both named one file; every receipt now
/// takes the injective one (CLOUD-2353).
#[test]
fn a_sibling_branchs_red_head_is_not_this_branchs() {
    assert_ne!(
        batten::receipt::branch_slug("work/red"),
        batten::receipt::branch_slug("work-red")
    );
    assert_ne!(
        batten::receipt::branch_slug("a%2Fb"),
        batten::receipt::branch_slug("a/b")
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
