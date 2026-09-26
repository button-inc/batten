//! `[tasks.board-sweep]` — every board gate over one payload set (CLOUD-825),
//! over the task's own body (CLOUD-1752).
//!
//! About the CALLER and nothing else: each case asserts a gate was REACHED and
//! its verdict carried, never that the gate's own predicate is right — that is
//! each gate's own tier. Every fixture differs from a passing one in exactly one
//! way, so a refusal can be attributed to the clause it came from. The body runs
//! in a fixture repository with `MISE_CONFIG_FILE` naming this manifest, which is
//! how it resolves a gate that has moved inline.
//!
//! # RETIREMENT LEDGER, PER PATH — what `shell retire partial` reads
//!
// carried: mise-tasks/board-sweep.sh mise.toml kind:mechanism crates/batten/tests/it/board_sweep.rs
// carried: tests/board-sweep.bats mise.toml kind:mechanism crates/batten/tests/it/board_sweep.rs
// carried: "a set with no dissonance exits 0 and says every gate ran" mise.toml kind:mechanism
// carried: "every gate is reached, and the report names each one" mise.toml kind:mechanism
// carried: "a landed-but-In-Progress row is named by in-progress-drain" mise.toml kind:mechanism
// carried: "a payload set reaches graph-check behind released" mise.toml kind:mechanism
// carried: "an empty payload set is COULD NOT LOOK, not a clean board" mise.toml kind:mechanism
// carried: "a gate exiting 2 is not laundered into the refusal lane" mise.toml kind:mechanism
// carried: "a board-scoped could-not-look outranks a refusal, so a half-run sweep is never exit 1" mise.toml kind:mechanism
// carried: "a duplicate close sharing its target's operation is named by the sweep" mise.toml kind:mechanism
// carried: "a tag-less clone still gets a graph-check verdict, and the sweep says so" mise.toml kind:mechanism
// carried: "an abstention and a not-judged sweep are different exit codes" mise.toml kind:mechanism
// carried: "a refusal outranks a clone-scoped abstention, so reachability buys no weaker verdict" mise.toml kind:mechanism
// carried: "a tag-less clone reaches ready-lint, which is graph-check's own leaf" mise.toml kind:mechanism
// carried: "the report carries no issue body" mise.toml kind:mechanism

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Output, Stdio};

const GATES: [&str; 6] = [
    "graph-check",
    "duplicate-close-check",
    "released",
    "in-progress-drain",
    "done-pr-check",
    "spec-ref-check",
];

/// A fixture clone: the committed config, `main` and `origin/main` at one empty
/// commit, a `v0.0.1` tag, and every world-reading injected so no case touches
/// the network.
struct Board {
    root: PathBuf,
    repo: PathBuf,
}

impl Board {
    fn new(name: &str) -> Self {
        let root = common::scratch(&format!("board-sweep-{name}"));
        let repo = root.join("repo");
        std::fs::create_dir_all(&repo).expect("repo dir");
        let board = Self { root, repo };
        board.git(&["init", "-q", "-b", "work"]);
        std::fs::copy(
            common::at_root("batten.toml"),
            board.repo.join("batten.toml"),
        )
        .expect("the committed config");
        // AND THE COMMITTED MODULES: a gate that moved onto a policy row decides
        // nothing in a tree that carries the row and not the module it names.
        let policy = board.repo.join("policy");
        std::fs::create_dir_all(&policy).expect("policy dir");
        for entry in std::fs::read_dir(common::at_root("policy")).expect("read policy") {
            let path = entry.expect("a policy entry").path();
            if path
                .extension()
                .is_some_and(|extension| extension == "rego")
            {
                std::fs::copy(&path, policy.join(path.file_name().expect("a name")))
                    .expect("copy a module");
            }
        }
        board.git(&["config", "user.email", "t@t"]);
        board.git(&["config", "user.name", "t"]);
        board.git(&["config", "commit.gpgsign", "false"]);
        board.git(&["commit", "-q", "--allow-empty", "-m", "chore: init"]);
        board.git(&["branch", "main"]);
        board.git(&["update-ref", "refs/remotes/origin/main", "main"]);
        board.git(&["tag", "v0.0.1", "main"]);
        std::fs::write(board.root.join("merged.tsv"), "").expect("evidence");
        std::fs::write(board.root.join("refs"), "").expect("refs");
        std::fs::create_dir_all(board.root.join("payloads")).expect("payloads");
        board.pulls(r#"[{"number":1,"state":"merged","draft":false}]"#);
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
        assert!(out.status.success(), "git {args:?}: {}", said(&out));
    }

    fn pulls(&self, json: &str) {
        std::fs::write(self.root.join("pulls.json"), json).expect("pulls");
    }

    fn evidence(&self, tsv: &str) {
        std::fs::write(self.root.join("merged.tsv"), tsv).expect("evidence");
    }

    /// A commit on `main` naming `message`.
    fn land(&self, message: &str) {
        self.git(&["checkout", "-q", "main"]);
        self.git(&["commit", "-q", "--allow-empty", "-m", message]);
        self.git(&["update-ref", "refs/remotes/origin/main", "main"]);
        self.git(&["checkout", "-q", "work"]);
    }

    fn sweep(&self, payloads: &str, spec_root: Option<&Path>) -> Output {
        let mut command = common::task_command(&self.repo, "board-sweep");
        command
            .env("MISE_CONFIG_FILE", common::at_root("mise.toml"))
            .env("usage_payloads", "-")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_SYSTEM", "/dev/null")
            .env("DRAIN_MERGED_PRS", self.root.join("merged.tsv"))
            .env("WIP_DRAIN_REFS", self.root.join("refs"))
            .env("WIP_DRAIN_TODAY", "2026-08-20")
            .env("SPEC_REF_ROOT", spec_root.unwrap_or(&self.repo))
            .env("BOARD_PAYLOADS_DIR", self.root.join("payloads"))
            .env("SWEEP_PULLS", self.root.join("pulls.json"))
            .env_remove("usage_tag")
            .env_remove("usage_pulls")
            .env_remove("SWEEP_TAG")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = command.spawn().expect("spawn the sweep");
        let _ = child
            .stdin
            .take()
            .expect("stdin")
            .write_all(payloads.as_bytes());
        child.wait_with_output().expect("run the sweep")
    }
}

/// A row that satisfies every gate; each argument overrides one field.
fn row(id: &str, status: &str, assignee: &str, attachments: &str) -> String {
    format!(
        r#"{{"id":"{id}","status":"{status}","updatedAt":"2026-08-20T00:00:00.000Z","gitBranchName":"x/{id}","projectMilestone":{{"name":"m"}},"assignee":{assignee},"assigneeId":{assignee},"description":"a body","relations":{{"blockedBy":[],"blocks":[],"relatedTo":[],"duplicateOf":null}},"attachments":{attachments}}}"#
    )
}

const PR: &str = r#"[{"url":"https://github.com/o/r/pull/1"}]"#;

fn clean(id: &str) -> String {
    row(id, "In Progress", "\"t@t\"", PR)
}

fn set_of(rows: &[String]) -> String {
    format!("[{}]", rows.join(","))
}

fn said(out: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

const CLOSES_ONE: &str = "feat: work\n\nCloses CLOUD-1";

#[test]
fn a_clean_board_exits_0_and_every_gate_is_reached_and_named() {
    let board = Board::new("clean");
    let out = board.sweep(&set_of(&[clean("CLOUD-1")]), None);
    let text = said(&out);
    assert_eq!(out.status.code(), Some(0), "{text}");
    assert!(text.contains("every gate ran"), "{text}");
    for gate in GATES {
        assert!(text.contains(gate), "{gate} unreached: {text}");
    }
}

#[test]
fn a_landed_but_in_progress_row_is_named_by_in_progress_drain() {
    let board = Board::new("drain");
    board.land(CLOSES_ONE);
    board.evidence("CLOUD-1\t1\n");
    let out = board.sweep(&set_of(&[clean("CLOUD-1")]), None);
    assert_ne!(out.status.code(), Some(0), "{}", said(&out));
    assert!(said(&out).contains("in-progress-drain"), "{}", said(&out));
}

/// `REFUSED (in-review-no-pr)` is `graph-check`'s verdict as printed by
/// `released`, reachable only if `released` was handed the payload set.
#[test]
fn a_payload_set_reaches_graph_check_behind_released() {
    let board = Board::new("released");
    board.land(CLOSES_ONE);
    board.git(&["tag", "v0.0.2", "main"]);
    let out = board.sweep(
        &set_of(&[row("CLOUD-1", "In Review", "\"t@t\"", "[]")]),
        None,
    );
    assert_ne!(out.status.code(), Some(0), "{}", said(&out));
    assert!(
        said(&out).contains("REFUSED (in-review-no-pr)"),
        "{}",
        said(&out)
    );
}

#[test]
fn an_empty_payload_set_is_could_not_look() {
    let board = Board::new("empty");
    let out = board.sweep("", None);
    let text = said(&out);
    assert_eq!(out.status.code(), Some(2), "{text}");
    assert!(!text.contains("every gate ran"), "{text}");
    // The verdict must be this task's own, not a gate choking on the set.
    assert!(text.contains("the payload set is empty"), "{text}");
}

#[test]
fn a_gate_exiting_2_is_not_laundered_into_the_refusal_lane() {
    let board = Board::new("laundered");
    board.pulls("[]");
    let out = board.sweep(&set_of(&[clean("CLOUD-1")]), None);
    let text = said(&out);
    assert_eq!(out.status.code(), Some(2), "{text}");
    assert!(text.contains("done-pr-check COULD NOT LOOK"), "{text}");
    assert!(!text.contains("done-pr-check REFUSED"), "{text}");
}

#[test]
fn a_board_scoped_could_not_look_outranks_a_refusal() {
    let board = Board::new("outranks");
    board.land(CLOSES_ONE);
    board.evidence("CLOUD-1\t1\n");
    let gone = board.root.join("gone");
    let out = board.sweep(&set_of(&[clean("CLOUD-1")]), Some(&gone));
    assert_eq!(out.status.code(), Some(2), "{}", said(&out));
}

#[test]
fn a_duplicate_close_sharing_its_targets_operation_is_named_by_the_sweep() {
    let board = Board::new("duplicate");
    let op = "2026-08-21T02:37:51.492Z";
    let target = format!(
        r#"{{"id":"CLOUD-1","status":"Done","updatedAt":"{op}","gitBranchName":"x/1","projectMilestone":{{"name":"m"}},"assignee":"t@t","assigneeId":"t@t","description":"a body","completedAt":"{op}","canceledAt":null,"relations":{{"blockedBy":[],"blocks":[],"relatedTo":[],"duplicateOf":null}},"attachments":{PR}}}"#
    );
    let duplicate = format!(
        r#"{{"id":"CLOUD-2","status":"Canceled","updatedAt":"{op}","gitBranchName":"x/2","projectMilestone":{{"name":"m"}},"assignee":"t@t","assigneeId":"t@t","description":"a body","completedAt":null,"canceledAt":"{op}","relations":{{"blockedBy":[],"blocks":[],"relatedTo":[],"duplicateOf":{{"id":"CLOUD-1"}}}},"attachments":[]}}"#
    );
    let out = board.sweep(&set_of(&[target, duplicate]), None);
    assert_ne!(out.status.code(), Some(0), "{}", said(&out));
    assert!(
        said(&out).contains("duplicate-close-check REFUSED"),
        "{}",
        said(&out)
    );
}

#[test]
fn a_tag_less_clone_still_gets_a_graph_check_verdict() {
    let board = Board::new("tagless");
    board.git(&["tag", "-d", "v0.0.1"]);
    let out = board.sweep(&set_of(&[clean("CLOUD-1")]), None);
    let text = said(&out);
    assert!(text.contains("graph-check ok"), "{text}");
    assert!(text.contains("released ABSTAINED"), "{text}");
    assert_eq!(out.status.code(), Some(3), "{text}");
}

#[test]
fn an_abstention_and_a_not_judged_sweep_are_different_exit_codes() {
    let board = Board::new("lanes");
    board.git(&["tag", "-d", "v0.0.1"]);
    let abstained = board.sweep(&set_of(&[clean("CLOUD-1")]), None);
    assert_eq!(abstained.status.code(), Some(3), "{}", said(&abstained));
    board.pulls("[]");
    let unjudged = board.sweep(&set_of(&[clean("CLOUD-1")]), None);
    assert_eq!(unjudged.status.code(), Some(2), "{}", said(&unjudged));
}

#[test]
fn a_refusal_outranks_a_clone_scoped_abstention() {
    let board = Board::new("refusal-wins");
    board.git(&["tag", "-d", "v0.0.1"]);
    board.land(CLOSES_ONE);
    board.evidence("CLOUD-1\t1\n");
    let out = board.sweep(&set_of(&[clean("CLOUD-1")]), None);
    assert_eq!(out.status.code(), Some(1), "{}", said(&out));
    assert!(said(&out).contains("in-progress-drain"), "{}", said(&out));
}

#[test]
fn a_tag_less_clone_reaches_ready_lint() {
    let board = Board::new("ready-lint");
    board.git(&["tag", "-d", "v0.0.1"]);
    let out = board.sweep(&set_of(&[row("CLOUD-1", "Todo", "null", "[]")]), None);
    assert_eq!(out.status.code(), Some(1), "{}", said(&out));
    assert!(said(&out).contains("todo-not-ready"), "{}", said(&out));
}

#[test]
fn the_report_carries_no_issue_body() {
    let board = Board::new("pointer");
    board.land(CLOSES_ONE);
    board.git(&["tag", "v0.0.2", "main"]);
    let out = board.sweep(
        &set_of(&[row("CLOUD-1", "In Review", "\"t@t\"", "[]")]),
        None,
    );
    assert!(!said(&out).contains("a body"), "{}", said(&out));
}
