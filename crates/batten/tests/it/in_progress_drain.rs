//! `[tasks.in-progress-drain]` — which In Progress issues have landed, and which
//! are abandoned claims (CLOUD-469), over the task's own body (CLOUD-1752).
//!
//! `landed-unswept` is DELEGATED to `landed-check`, so these cases assert the
//! delegation carries rather than re-testing that predicate. `claimed-abandoned`
//! is a conjunction, and most cases prove it is one: a claim failing any single
//! conjunct is live work. Every world-reading is injected; nothing touches the
//! network.
//!
//! # RETIREMENT LEDGER, PER PATH — what `shell retire partial` reads
//!
// carried: mise-tasks/in-progress-drain.sh mise.toml kind:mechanism crates/batten/tests/it/in_progress_drain.rs
// carried: tests/in-progress-drain.bats mise.toml kind:mechanism crates/batten/tests/it/in_progress_drain.rs
// carried: "an In Progress issue whose commits are on main is landed-unswept" mise.toml kind:mechanism
// carried: "a landed row is not ALSO reported as abandoned — the verdicts are exclusive" mise.toml kind:mechanism
// carried: "the landed report says it is candidates, and names what decides a move" mise.toml kind:mechanism
// carried: "a citation on main is not landed-unswept, through the delegation" mise.toml kind:mechanism
// carried: "a merged PR in the evidence lands a row with no closing key on main" mise.toml kind:mechanism
// carried: "a clean board is exit 0 and says so" mise.toml kind:mechanism
// carried: "a row in another column is judged by neither verdict" mise.toml kind:mechanism
// carried: "all five conjuncts satisfied is claimed-abandoned" mise.toml kind:mechanism
// carried: "a claim carrying a PR attachment is not abandoned" mise.toml kind:mechanism
// carried: "a non-PR attachment does not rescue a claim — only a pull request does" mise.toml kind:mechanism
// carried: "a claim with a live remote branch is not abandoned" mise.toml kind:mechanism
// carried: "a claim touched today is not abandoned" mise.toml kind:mechanism
// carried: "the idle bound is exclusive at exactly the threshold" mise.toml kind:mechanism
// carried: "the idle bound is configurable and the report names the value it used" mise.toml kind:mechanism
// carried: "an In Progress row with no attachments key is exit 2 and named" mise.toml kind:mechanism
// carried: "an In Progress row with no gitBranchName key is exit 2 and named" mise.toml kind:mechanism
// carried: "an In Progress row with no updatedAt key is exit 2 and named" mise.toml kind:mechanism
// carried: "a FRESH row is not demanded of attachments — the idle bound already resolved it" mise.toml kind:mechanism
// carried: "a stale row IS demanded of attachments — the narrowing is not a hole" mise.toml kind:mechanism
// carried: "a LANDED row is not demanded of those keys — it is already answered" mise.toml kind:mechanism
// carried: "an UNRESOLVED row missing a key is still exit 2, alongside a landed one" mise.toml kind:mechanism
// carried: "a row in another column is not demanded of those keys" mise.toml kind:mechanism
// carried: "presence is what is checked, not truthiness" mise.toml kind:mechanism
// carried: "an unreadable updatedAt is reported, never silently treated as fresh" mise.toml kind:mechanism
// carried: "empty stdin is exit 2, not a clean board" mise.toml kind:mechanism
// carried: "a payload missing id or status is exit 2" mise.toml kind:mechanism
// carried: "an unreadable WIP_DRAIN_REFS is exit 2, not an empty branch list" mise.toml kind:mechanism
// carried: "an unreadable WIP_DRAIN_TODAY is exit 2" mise.toml kind:mechanism
// carried: "the report carries keys and counts, never a body" mise.toml kind:mechanism
// carried: "both verdicts report together, each under its own label" mise.toml kind:mechanism
// carried: "the id list is byte-stable regardless of input order" mise.toml kind:mechanism

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::io::Write as _;
use std::path::PathBuf;
use std::process::Stdio;

struct Board {
    root: PathBuf,
    repo: PathBuf,
}

impl Board {
    fn new(name: &str) -> Self {
        let root = common::scratch(&format!("in-progress-drain-{name}"));
        let repo = root.join("repo");
        std::fs::create_dir_all(&repo).expect("repo");
        let board = Self { root, repo };
        board.git(&["init", "-q", "-b", "work"]);
        // THE COMMITTED CONFIG: the claim derivation is an engine leaf that
        // resolves its key grammar from the `[[pattern]]` registry.
        std::fs::copy(
            common::at_root("batten.toml"),
            board.repo.join("batten.toml"),
        )
        .expect("config");
        board.git(&["config", "user.email", "t@t"]);
        board.git(&["config", "user.name", "t"]);
        board.git(&["config", "commit.gpgsign", "false"]);
        board.git(&["commit", "-q", "--allow-empty", "-m", "chore: init"]);
        board.git(&["branch", "main"]);
        board.git(&["update-ref", "refs/remotes/origin/main", "main"]);
        std::fs::write(board.root.join("refs"), "").expect("refs");
        std::fs::write(board.root.join("merged.tsv"), "").expect("evidence");
        board
    }

    fn git(&self, args: &[&str]) {
        let out = common::program("git")
            .args(args)
            .current_dir(&self.repo)
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_SYSTEM", "/dev/null")
            .output()
            .expect("git");
        assert!(out.status.success(), "git {args:?}");
    }

    fn land(&self, message: &str) {
        self.git(&["checkout", "-q", "main"]);
        self.git(&["commit", "-q", "--allow-empty", "-m", message]);
        self.git(&["update-ref", "refs/remotes/origin/main", "main"]);
        self.git(&["checkout", "-q", "work"]);
    }

    fn drain_with(&self, stdin: &str, env: &[(&str, String)]) -> (Option<i32>, String) {
        let mut command = common::task_command(&self.repo, "in-progress-drain");
        command
            .env("MISE_CONFIG_FILE", common::at_root("mise.toml"))
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_SYSTEM", "/dev/null")
            .env("WIP_DRAIN_REFS", self.root.join("refs"))
            .env("WIP_DRAIN_TODAY", "2026-08-20")
            .env("DRAIN_MERGED_PRS", self.root.join("merged.tsv"))
            .env_remove("WIP_MAX_IDLE_DAYS")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        for (name, value) in env {
            command.env(name, value);
        }
        let mut child = command.spawn().expect("spawn the drain");
        let _ = child
            .stdin
            .take()
            .expect("stdin")
            .write_all(stdin.as_bytes());
        let out = child.wait_with_output().expect("run the drain");
        (
            out.status.code(),
            format!(
                "{}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            ),
        )
    }

    fn drain(&self, stdin: &str) -> (Option<i32>, String) {
        self.drain_with(stdin, &[])
    }
}

/// One In Progress row: `row(id, updatedAt, gitBranchName, attachment-url)`.
fn row(id: &str, updated: &str, branch: &str, url: &str) -> String {
    let attachments = if url.is_empty() {
        "[]".to_owned()
    } else {
        format!(r#"[{{"url":"{url}"}}]"#)
    };
    format!(
        r#"{{"id":"{id}","status":"In Progress","updatedAt":"{updated}","gitBranchName":"{branch}","attachments":{attachments}}}"#
    )
}

fn set(rows: &[String]) -> String {
    format!("[{}]", rows.join(","))
}

const OLD: &str = "2026-01-01T10:00:00.000Z";
const TODAY: &str = "2026-08-20T10:00:00.000Z";
const CLOSES: &str = "feat: work\n\nCloses CLOUD-179";

#[test]
fn an_in_progress_issue_whose_commits_are_on_main_is_landed_unswept() {
    let b = Board::new("landed");
    b.land(CLOSES);
    let (code, text) = b.drain(&set(&[row("CLOUD-179", TODAY, "feat/x", "")]));
    assert_eq!(code, Some(1), "{text}");
    assert!(
        text.contains("landed-unswept") && text.contains("CLOUD-179"),
        "{text}"
    );
    // Candidates, pointing at what decides a move and away from completeness.
    assert!(
        text.contains("board-move-guard") && text.contains("released"),
        "{text}"
    );
}

#[test]
fn a_landed_row_is_not_also_reported_as_abandoned() {
    let b = Board::new("exclusive");
    b.land(CLOSES);
    let (code, text) = b.drain(&set(&[row("CLOUD-179", OLD, "feat/x", "")]));
    assert_eq!(code, Some(1), "{text}");
    assert!(!text.contains("::error:: claimed-abandoned"), "{text}");
    assert!(
        text.contains("1 landed-unswept, 0 claimed-abandoned"),
        "{text}"
    );
}

#[test]
fn the_delegation_carries_landed_checks_precision() {
    let b = Board::new("citation");
    b.land("feat(ci): verify the declared MSRV against the compiler it names\n\non the newer compiler while the published claim quietly goes false. That is\nCLOUD-271's shape.");
    let (code, text) = b.drain(&set(&[row(
        "CLOUD-271",
        TODAY,
        "feat/x",
        "https://github.com/o/r/pull/579",
    )]));
    assert_eq!(code, Some(0), "{text}");
    assert!(text.contains("0 landed-unswept"), "{text}");
    // And a merged PR in the evidence lands a row no commit names.
    let b = Board::new("merged");
    b.land("fix(doctor): serialize the two repairs doctor's own graph races");
    std::fs::write(b.root.join("merged.tsv"), "CLOUD-201\t339\n").expect("evidence");
    let (code, text) = b.drain(&set(&[row("CLOUD-201", TODAY, "feat/x", "")]));
    assert_eq!(code, Some(1), "{text}");
    assert!(text.contains("CLOUD-201"), "{text}");
}

#[test]
fn a_clean_board_or_another_column_is_exit_0() {
    let b = Board::new("clean");
    let (code, text) = b.drain("[]");
    assert_eq!(code, Some(0), "{text}");
    assert!(
        text.contains("0 In Progress — 0 landed-unswept, 0 claimed-abandoned"),
        "{text}"
    );
    b.land(CLOSES);
    assert_eq!(
        b.drain(r#"[{"id":"CLOUD-179","status":"In Review"}]"#).0,
        Some(0)
    );
    assert_eq!(
        b.drain(r#"[{"id":"CLOUD-124","status":"Done"}]"#).0,
        Some(0)
    );
}

#[test]
fn all_conjuncts_satisfied_is_claimed_abandoned() {
    let b = Board::new("abandoned");
    let (code, text) = b.drain(&set(&[row("CLOUD-124", OLD, "feat/gone", "")]));
    assert_eq!(code, Some(1), "{text}");
    assert!(
        text.contains("claimed-abandoned") && text.contains("CLOUD-124"),
        "{text}"
    );
    assert!(
        text.contains("0 landed-unswept, 1 claimed-abandoned"),
        "{text}"
    );
    // Only a pull request rescues a claim, not any attachment.
    let (code, text) = b.drain(&set(&[row(
        "CLOUD-124",
        OLD,
        "feat/gone",
        "https://linear.app/x/document/y",
    )]));
    assert_eq!(code, Some(1), "{text}");
    // Presence, not truthiness: empty branch and attachments are data.
    let (code, text) = b.drain(&set(&[row("CLOUD-124", OLD, "", "")]));
    assert_eq!(code, Some(1), "{text}");
    assert!(text.contains("claimed-abandoned"), "{text}");
}

#[test]
fn a_claim_carrying_a_pr_attachment_is_not_abandoned() {
    let b = Board::new("pr");
    let (code, text) = b.drain(&set(&[row(
        "CLOUD-124",
        OLD,
        "feat/gone",
        "https://github.com/o/r/pull/12",
    )]));
    assert_eq!(code, Some(0), "{text}");
    assert!(!text.contains("::error:: claimed-abandoned"), "{text}");
}

#[test]
fn a_claim_with_a_live_remote_branch_is_not_abandoned() {
    let b = Board::new("branch");
    std::fs::write(b.root.join("refs"), "feat/live\n").expect("refs");
    let (code, text) = b.drain(&set(&[row("CLOUD-124", OLD, "feat/live", "")]));
    assert_eq!(code, Some(0), "{text}");
}

#[test]
fn a_claim_touched_today_is_not_abandoned() {
    let b = Board::new("fresh");
    let (code, text) = b.drain(&set(&[row(
        "CLOUD-124",
        "2026-08-20T09:00:00.000Z",
        "feat/gone",
        "",
    )]));
    assert_eq!(code, Some(0), "{text}");
    // The idle bound is exclusive at exactly the threshold.
    assert_eq!(
        b.drain(&set(&[row(
            "CLOUD-124",
            "2026-08-18T09:00:00.000Z",
            "feat/gone",
            ""
        )]))
        .0,
        Some(0)
    );
    assert_eq!(
        b.drain(&set(&[row(
            "CLOUD-124",
            "2026-08-17T09:00:00.000Z",
            "feat/gone",
            ""
        )]))
        .0,
        Some(1)
    );
}

#[test]
fn the_idle_bound_is_configurable_and_named() {
    let b = Board::new("bound");
    let rows = set(&[row(
        "CLOUD-124",
        "2026-08-01T09:00:00.000Z",
        "feat/gone",
        "",
    )]);
    assert_eq!(
        b.drain_with(&rows, &[("WIP_MAX_IDLE_DAYS", "30".to_owned())])
            .0,
        Some(0)
    );
    let (code, text) = b.drain_with(&rows, &[("WIP_MAX_IDLE_DAYS", "5".to_owned())]);
    assert_eq!(code, Some(1), "{text}");
    assert!(text.contains("idle > 5d"), "{text}");
}

#[test]
fn a_missing_key_on_a_row_that_needs_it_is_exit_2_and_named() {
    let b = Board::new("keys");
    for (payload, key) in [
        (
            r#"[{"id":"CLOUD-124","status":"In Progress","updatedAt":"2026-01-01T00:00:00.000Z","gitBranchName":"x"}]"#,
            "attachments",
        ),
        (
            r#"[{"id":"CLOUD-124","status":"In Progress","updatedAt":"2026-01-01T00:00:00.000Z","attachments":[]}]"#,
            "gitBranchName",
        ),
        (
            r#"[{"id":"CLOUD-124","status":"In Progress","gitBranchName":"x","attachments":[]}]"#,
            "updatedAt",
        ),
        (
            r#"[{"id":"CLOUD-124","status":"In Progress","updatedAt":"2026-01-01T09:00:00.000Z"}]"#,
            "attachments",
        ),
    ] {
        let (code, text) = b.drain(payload);
        assert_eq!(code, Some(2), "{key}: {text}");
        assert!(
            text.contains(key) && text.contains("CLOUD-124"),
            "{key}: {text}"
        );
    }
    // A fresh row is not demanded of attachments: the bound resolved it.
    let (code, text) = b.drain(
        r#"[{"id":"CLOUD-124","status":"In Progress","updatedAt":"2026-08-20T09:00:00.000Z"}]"#,
    );
    assert_eq!(code, Some(0), "{text}");
    assert!(!text.contains("::error::"), "{text}");
}

#[test]
fn a_landed_row_is_not_demanded_of_keys_but_an_unresolved_one_is() {
    let b = Board::new("landed-keys");
    b.land(CLOSES);
    let (code, text) = b.drain(r#"[{"id":"CLOUD-179","status":"In Progress"}]"#);
    assert_eq!(code, Some(1), "{text}");
    assert!(!text.contains("::error:: in-progress-drain"), "{text}");
    let (code, text) = b.drain(
        r#"[{"id":"CLOUD-179","status":"In Progress"},{"id":"CLOUD-124","status":"In Progress"}]"#,
    );
    assert_eq!(code, Some(2), "{text}");
    assert!(
        text.contains("CLOUD-124") && !text.contains("CLOUD-179"),
        "{text}"
    );
}

#[test]
fn an_unreadable_updated_at_is_reported() {
    let b = Board::new("date");
    let (code, text) = b.drain(
        r#"[{"id":"CLOUD-124","status":"In Progress","updatedAt":"not-a-date","gitBranchName":"x","attachments":[]}]"#,
    );
    assert_eq!(code, Some(1), "{text}");
    assert!(
        text.contains("unreadable-updatedat") && text.contains("CLOUD-124"),
        "{text}"
    );
}

#[test]
fn unreadable_input_or_readings_are_exit_2() {
    let b = Board::new("unreadable");
    let (code, text) = b.drain("");
    assert_eq!(code, Some(2), "{text}");
    assert!(text.contains("stdin is empty"), "{text}");
    assert_eq!(b.drain(r#"[{"status":"In Progress"}]"#).0, Some(2));
    let rows = set(&[row("CLOUD-124", OLD, "feat/gone", "")]);
    let absent = b.root.join("nope").display().to_string();
    assert_eq!(
        b.drain_with(&rows, &[("WIP_DRAIN_REFS", absent)]).0,
        Some(2)
    );
    assert_eq!(
        b.drain_with(&rows, &[("WIP_DRAIN_TODAY", "nonsense".to_owned())])
            .0,
        Some(2)
    );
}

#[test]
fn the_report_is_a_pointer_and_byte_stable() {
    let b = Board::new("pointer");
    let secret = "SENSITIVE-BODY-TEXT-DO-NOT-EMIT";
    let (code, text) = b.drain(&format!(
        r#"[{{"id":"CLOUD-124","status":"In Progress","updatedAt":"2026-01-01T00:00:00.000Z","gitBranchName":"feat/gone","attachments":[],"description":"{secret}"}}]"#
    ));
    assert_eq!(code, Some(1), "{text}");
    assert!(!text.contains(secret), "{text}");
    let first = b.drain(&set(&[
        row("CLOUD-9", OLD, "a", ""),
        row("CLOUD-124", OLD, "b", ""),
    ]));
    let second = b.drain(&set(&[
        row("CLOUD-124", OLD, "b", ""),
        row("CLOUD-9", OLD, "a", ""),
    ]));
    assert_eq!(first, second);
}

#[test]
fn both_verdicts_report_together() {
    let b = Board::new("both");
    b.land(CLOSES);
    let (code, text) = b.drain(&set(&[
        row("CLOUD-179", TODAY, "feat/x", ""),
        row("CLOUD-124", OLD, "feat/gone", ""),
    ]));
    assert_eq!(code, Some(1), "{text}");
    assert!(
        text.contains("2 In Progress — 1 landed-unswept, 1 claimed-abandoned"),
        "{text}"
    );
}
