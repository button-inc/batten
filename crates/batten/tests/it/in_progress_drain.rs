//! `[tasks.in-progress-drain]`'s successor — which In Progress issues have
//! landed, and which are abandoned claims (CLOUD-469) — over the compiled
//! `batten landed abandoned --gather` (CLOUD-843).
//!
//! The task was GLUE around two engine verbs: it gathered three evidence arms in
//! shell (the trunk's closing keys through `git log | batten claim keys`, merged
//! pull requests through `batten claim merged`, the remote's branches through
//! `git ls-remote`), then asked `landed check` and re-derived the abandonment
//! conjunction in `jq`. The conjunction had already landed as `landed::drain`
//! (CLOUD-1513), so the port moves the GATHER into the verb and deletes the
//! second copy of the predicate. These cases drive the same fixtures the task's
//! tier drove, through the binary, with every world-reading injected: the merged
//! set and the branches as files or through `rest`'s `BATTEN_REST_FIXTURE` seam,
//! the trunk's history from the fixture's own `origin/main`.
//!
//! # RETIREMENT LEDGER, PER PATH — what `shell retire partial` reads
//!
// ported: mise-tasks/in-progress-drain.sh subject:mise.toml crates/batten/tests/it/in_progress_drain.rs
// ported: tests/in-progress-drain.bats subject:mise.toml crates/batten/tests/it/in_progress_drain.rs
// carried: [tasks.in-progress-drain] crates/batten/src/lib.rs kind:mechanism crates/batten/tests/it/in_progress_drain.rs runs:batten+landed+abandoned
// carried: "an In Progress issue whose commits are on main is landed-unswept" crates/batten/tests/it/in_progress_drain.rs
// carried: "a landed row is not ALSO reported as abandoned — the verdicts are exclusive" crates/batten/tests/it/in_progress_drain.rs
// changed: "the landed report says it is candidates, and names what decides a move" crates/batten/src/lib.rs the verb labels the block `landed-unswept — In Progress while their work is on main`; which gate authorises a move is `[[rule]]` remedy text, not the drain's report
// carried: "a citation on main is not landed-unswept, through the delegation" crates/batten/tests/it/in_progress_drain.rs
// carried: "a merged PR in the evidence lands a row with no closing key on main" crates/batten/tests/it/in_progress_drain.rs
// carried: "a clean board is exit 0 and says so" crates/batten/tests/it/in_progress_drain.rs
// carried: "a row in another column is judged by neither verdict" crates/batten/tests/it/in_progress_drain.rs
// changed: "all five conjuncts satisfied is claimed-abandoned" crates/batten/src/lib.rs exit 2 (Violation) on the engine's table where the corpus answered 1
// carried: "a claim carrying a PR attachment is not abandoned" crates/batten/tests/it/in_progress_drain.rs
// carried: "a non-PR attachment does not rescue a claim — only a pull request does" crates/batten/tests/it/in_progress_drain.rs
// carried: "a claim with a live remote branch is not abandoned" crates/batten/tests/it/in_progress_drain.rs
// carried: "a claim touched today is not abandoned" crates/batten/tests/it/in_progress_drain.rs
// carried: "the idle bound is exclusive at exactly the threshold" crates/batten/tests/it/in_progress_drain.rs
// changed: "the idle bound is configurable and the report names the value it used" crates/batten/src/lib.rs `WIP_MAX_IDLE_DAYS` is the `--max-idle-days` flag; the report names the bound as before
// changed: "an In Progress row with no attachments key is exit 2 and named" crates/batten/src/lib.rs could-not-look about the INPUT is `Usage` (1) on the engine's table, where the corpus answered 2
// changed: "an In Progress row with no gitBranchName key is exit 2 and named" crates/batten/src/lib.rs could-not-look about the INPUT is `Usage` (1) on the engine's table, where the corpus answered 2
// changed: "an In Progress row with no updatedAt key is exit 2 and named" crates/batten/src/lib.rs could-not-look about the INPUT is `Usage` (1) on the engine's table, where the corpus answered 2
// carried: "a FRESH row is not demanded of attachments — the idle bound already resolved it" crates/batten/tests/it/in_progress_drain.rs
// carried: "a stale row IS demanded of attachments — the narrowing is not a hole" crates/batten/tests/it/in_progress_drain.rs
// carried: "a LANDED row is not demanded of those keys — it is already answered" crates/batten/tests/it/in_progress_drain.rs
// changed: "an UNRESOLVED row missing a key is still exit 2, alongside a landed one" crates/batten/src/lib.rs could-not-look about the INPUT is `Usage` (1) on the engine's table, where the corpus answered 2
// carried: "a row in another column is not demanded of those keys" crates/batten/tests/it/in_progress_drain.rs
// carried: "presence is what is checked, not truthiness" crates/batten/tests/it/in_progress_drain.rs
// changed: "an unreadable updatedAt is reported, never silently treated as fresh" crates/batten/src/lib.rs reported under `unreadable-updatedat` at exit 2 (Violation) where the corpus answered 1
// changed: "empty stdin is exit 2, not a clean board" crates/batten/src/lib.rs `Usage` (1) on the engine's table
// changed: "a payload missing id or status is exit 2" crates/batten/src/lib.rs `Usage` (1) on the engine's table
// changed: "an unreadable WIP_DRAIN_REFS is exit 2, not an empty branch list" crates/batten/src/lib.rs the refs are the `--refs` file, and an unreadable one is `Usage` (1)
// changed: "an unreadable WIP_DRAIN_TODAY is exit 2" crates/batten/src/lib.rs the instant is `--instant`, and an unreadable one is `Usage` (1)
// carried: "the report carries keys and counts, never a body" crates/batten/tests/it/in_progress_drain.rs
// carried: "both verdicts report together, each under its own label" crates/batten/tests/it/in_progress_drain.rs
// carried: "the id list is byte-stable regardless of input order" crates/batten/tests/it/in_progress_drain.rs
// carried: "no DRAIN_MERGED_PRS gathers the merged set itself rather than refusing" crates/batten/tests/it/in_progress_drain.rs
// carried: "a trunk whose history cannot be read is could-not-look, not a clean column" crates/batten/tests/it/in_progress_drain.rs
// carried: "the remote's branch list is gathered, and an empty one is could-not-look" crates/batten/tests/it/in_progress_drain.rs

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::io::Write as _;
use std::path::PathBuf;
use std::process::Stdio;

/// A fixture clone: the committed config (its `[[pattern]]` key grammar and its
/// `[board]` columns are what the verb decides with), `main` and `origin/main` at
/// one commit, and an `origin` remote the forge seam can derive a slug from.
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
        common::init_repo(&board.repo);
        board.git(&["checkout", "-q", "-b", "work"]);
        std::fs::copy(
            common::at_root("batten.toml"),
            board.repo.join("batten.toml"),
        )
        .expect("config");
        board.git(&["commit", "-q", "--allow-empty", "-m", "chore: init"]);
        board.git(&["branch", "main"]);
        board.git(&["update-ref", "refs/remotes/origin/main", "main"]);
        board.git(&[
            "remote",
            "add",
            "origin",
            "https://github.com/acme/widgets.git",
        ]);
        std::fs::write(board.repo.join("refs.txt"), "").expect("refs");
        std::fs::write(board.repo.join("merged.tsv"), "").expect("evidence");
        std::fs::create_dir_all(board.root.join("forge")).expect("forge");
        board
    }

    fn git(&self, args: &[&str]) {
        common::git_in(&self.repo, args);
    }

    fn land(&self, message: &str) {
        self.git(&["checkout", "-q", "main"]);
        self.git(&["commit", "-q", "--allow-empty", "-m", message]);
        self.git(&["update-ref", "refs/remotes/origin/main", "main"]);
        self.git(&["checkout", "-q", "work"]);
    }

    /// Answer one forge endpoint with a JSON body, through `rest`'s seam.
    fn forge(&self, needle: &str, file: &str, body: &str) {
        let forge = self.root.join("forge");
        let routes = std::fs::read_to_string(forge.join("routes")).unwrap_or_default();
        std::fs::write(forge.join("routes"), format!("{routes}{needle}\t{file}\n"))
            .expect("routes");
        std::fs::write(forge.join(file), format!("HTTP/2 200\n\n{body}")).expect("a response");
    }

    /// `landed abandoned --gather`, at `--instant 2026-08-20` unless `extra` names
    /// one, plus `extra`, with the
    /// merged set and the refs as files unless a case drops them.
    fn drain_with(&self, stdin: &str, extra: &[&str], files: bool) -> (Option<i32>, String) {
        let mut args = vec!["landed", "abandoned", "--gather"];
        if !extra.contains(&"--instant") {
            args.extend_from_slice(&["--instant", "2026-08-20"]);
        }
        if files {
            args.extend_from_slice(&["--merged-prs", "merged.tsv", "--refs", "refs.txt"]);
        }
        args.extend_from_slice(extra);
        let mut command = common::batten();
        command
            .args(&args)
            .current_dir(&self.repo)
            .env("BATTEN_REST_FIXTURE", self.root.join("forge"))
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_SYSTEM", "/dev/null")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
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
        self.drain_with(stdin, &[], true)
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

/// The engine's codes, named so a case reads as the lane it asserts.
const CLEAN: Option<i32> = Some(0);
const USAGE: Option<i32> = Some(1);
const VIOLATION: Option<i32> = Some(2);
const COULD_NOT_LOOK: Option<i32> = Some(3);

/// THE GATHERED TRUNK ARM. No `--claimed` is passed, so the only way the key can
/// land is the verb reading `origin/main`'s history itself — which is what the
/// task did with `git log | claim keys`.
#[test]
fn an_in_progress_issue_whose_commits_are_on_main_is_landed_unswept() {
    let b = Board::new("landed");
    b.land(CLOSES);
    let (code, text) = b.drain(&set(&[row("CLOUD-179", TODAY, "feat/x", "")]));
    assert_eq!(code, VIOLATION, "{text}");
    assert!(
        text.contains("landed-unswept") && text.contains("CLOUD-179"),
        "{text}"
    );
    // Gathered, so the absent-arm notice has nothing to say.
    assert!(!text.contains("no --claimed evidence"), "{text}");
}

#[test]
fn a_landed_row_is_not_also_reported_as_abandoned() {
    let b = Board::new("exclusive");
    b.land(CLOSES);
    let (code, text) = b.drain(&set(&[row("CLOUD-179", OLD, "feat/x", "")]));
    assert_eq!(code, VIOLATION, "{text}");
    assert!(!text.contains("claimed-abandoned —"), "{text}");
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
    assert_eq!(code, CLEAN, "{text}");
    assert!(text.contains("0 landed-unswept"), "{text}");
    // And a merged PR in the evidence lands a row no commit names.
    let b = Board::new("merged");
    b.land("fix(doctor): serialize the two repairs doctor's own graph races");
    std::fs::write(b.repo.join("merged.tsv"), "CLOUD-201\t339\n").expect("evidence");
    let (code, text) = b.drain(&set(&[row("CLOUD-201", TODAY, "feat/x", "")]));
    assert_eq!(code, VIOLATION, "{text}");
    assert!(text.contains("CLOUD-201"), "{text}");
}

#[test]
fn a_clean_board_or_another_column_is_exit_0() {
    let b = Board::new("clean");
    let (code, text) = b.drain("[]");
    assert_eq!(code, CLEAN, "{text}");
    assert!(
        text.contains("0 In Progress — 0 landed-unswept, 0 claimed-abandoned"),
        "{text}"
    );
    b.land(CLOSES);
    assert_eq!(
        b.drain(r#"[{"id":"CLOUD-179","status":"In Review"}]"#).0,
        CLEAN
    );
    assert_eq!(b.drain(r#"[{"id":"CLOUD-124","status":"Done"}]"#).0, CLEAN);
}

#[test]
fn all_conjuncts_satisfied_is_claimed_abandoned() {
    let b = Board::new("abandoned");
    let (code, text) = b.drain(&set(&[row("CLOUD-124", OLD, "feat/gone", "")]));
    assert_eq!(code, VIOLATION, "{text}");
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
    assert_eq!(code, VIOLATION, "{text}");
    // Presence, not truthiness: empty branch and attachments are data.
    let (code, text) = b.drain(&set(&[row("CLOUD-124", OLD, "", "")]));
    assert_eq!(code, VIOLATION, "{text}");
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
    assert_eq!(code, CLEAN, "{text}");
    assert!(!text.contains("claimed-abandoned —"), "{text}");
}

#[test]
fn a_claim_with_a_live_remote_branch_is_not_abandoned() {
    let b = Board::new("branch");
    std::fs::write(b.repo.join("refs.txt"), "feat/live\n").expect("refs");
    let (code, text) = b.drain(&set(&[row("CLOUD-124", OLD, "feat/live", "")]));
    assert_eq!(code, CLEAN, "{text}");
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
    assert_eq!(code, CLEAN, "{text}");
    // The idle bound is exclusive at exactly the threshold.
    assert_eq!(
        b.drain(&set(&[row(
            "CLOUD-124",
            "2026-08-18T09:00:00.000Z",
            "feat/gone",
            ""
        )]))
        .0,
        CLEAN
    );
    assert_eq!(
        b.drain(&set(&[row(
            "CLOUD-124",
            "2026-08-17T09:00:00.000Z",
            "feat/gone",
            ""
        )]))
        .0,
        VIOLATION
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
        b.drain_with(&rows, &["--max-idle-days", "30"], true).0,
        CLEAN
    );
    let (code, text) = b.drain_with(&rows, &["--max-idle-days", "5"], true);
    assert_eq!(code, VIOLATION, "{text}");
    assert!(text.contains("idle > 5d"), "{text}");
}

#[test]
fn a_missing_key_on_a_row_that_needs_it_is_refused_and_named() {
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
        assert_eq!(code, USAGE, "{key}: {text}");
        assert!(
            text.contains(key) && text.contains("CLOUD-124"),
            "{key}: {text}"
        );
    }
    // A fresh row is not demanded of attachments: the bound resolved it.
    let (code, text) = b.drain(
        r#"[{"id":"CLOUD-124","status":"In Progress","updatedAt":"2026-08-20T09:00:00.000Z"}]"#,
    );
    assert_eq!(code, CLEAN, "{text}");
}

#[test]
fn a_landed_row_is_not_demanded_of_keys_but_an_unresolved_one_is() {
    let b = Board::new("landed-keys");
    b.land(CLOSES);
    let (code, text) = b.drain(r#"[{"id":"CLOUD-179","status":"In Progress"}]"#);
    assert_eq!(code, VIOLATION, "{text}");
    let (code, text) = b.drain(
        r#"[{"id":"CLOUD-179","status":"In Progress"},{"id":"CLOUD-124","status":"In Progress"}]"#,
    );
    assert_eq!(code, USAGE, "{text}");
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
    assert_eq!(code, VIOLATION, "{text}");
    assert!(
        text.contains("unreadable-updatedat") && text.contains("CLOUD-124"),
        "{text}"
    );
}

#[test]
fn unreadable_input_or_readings_are_refused() {
    let b = Board::new("unreadable");
    let (code, text) = b.drain("");
    assert_eq!(code, USAGE, "{text}");
    assert!(text.contains("stdin is empty"), "{text}");
    assert_eq!(b.drain(r#"[{"status":"In Progress"}]"#).0, USAGE);
    let rows = set(&[row("CLOUD-124", OLD, "feat/gone", "")]);
    assert_eq!(
        b.drain_with(
            &rows,
            &["--merged-prs", "merged.tsv", "--refs", "nope.txt"],
            false
        )
        .0,
        USAGE
    );
    assert_eq!(
        b.drain_with(&rows, &["--instant", "nonsense"], true).0,
        USAGE
    );
}

#[test]
fn the_report_is_a_pointer_and_byte_stable() {
    let b = Board::new("pointer");
    let secret = "SENSITIVE-BODY-TEXT-DO-NOT-EMIT";
    let (code, text) = b.drain(&format!(
        r#"[{{"id":"CLOUD-124","status":"In Progress","updatedAt":"2026-01-01T00:00:00.000Z","gitBranchName":"feat/gone","attachments":[],"description":"{secret}"}}]"#
    ));
    assert_eq!(code, VIOLATION, "{text}");
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
    assert_eq!(code, VIOLATION, "{text}");
    assert!(
        text.contains("2 In Progress — 1 landed-unswept, 1 claimed-abandoned"),
        "{text}"
    );
}

/// THE MERGED ARM, GATHERED. No `--merged-prs`: the verb asks the forge for
/// closed pull requests and reads the closing keys out of the MERGED ones'
/// bodies, `claim merged`'s own body. A closed-unmerged one closes nothing.
#[test]
fn the_merged_set_is_gathered_when_no_file_names_it() {
    let b = Board::new("gather-merged");
    b.forge(
        "/pulls",
        "pulls",
        r#"[{"number":7,"merged_at":"2026-01-02T00:00:00Z","body":"Closes CLOUD-124"},{"number":8,"merged_at":null,"body":"Closes CLOUD-9"}]"#,
    );
    let (code, text) = b.drain_with(
        &set(&[
            row("CLOUD-124", OLD, "feat/gone", ""),
            row("CLOUD-9", OLD, "feat/gone", ""),
        ]),
        &["--refs", "refs.txt"],
        false,
    );
    assert_eq!(code, VIOLATION, "{text}");
    assert!(
        text.contains("2 In Progress — 1 landed-unswept, 1 claimed-abandoned"),
        "{text}"
    );
}

/// THE BRANCH ARM, GATHERED — and its empty answer is could-not-look, which is
/// what the task's `git ls-remote` reading refused: a repository with a trunk
/// has at least one branch, and an empty list would make every claim's branch
/// read as gone.
#[test]
fn the_remote_branch_list_is_gathered_and_an_empty_one_could_not_look() {
    let b = Board::new("gather-refs");
    b.forge(
        "/branches",
        "branches",
        r#"[{"name":"main"},{"name":"feat/live"}]"#,
    );
    let (code, text) = b.drain_with(
        &set(&[row("CLOUD-124", OLD, "feat/live", "")]),
        &["--merged-prs", "merged.tsv"],
        false,
    );
    assert_eq!(code, CLEAN, "a live branch the forge lists rescues: {text}");

    let empty = Board::new("gather-refs-empty");
    empty.forge("/branches", "branches", "[]");
    let (code, text) = empty.drain_with(
        &set(&[row("CLOUD-124", OLD, "feat/live", "")]),
        &["--merged-prs", "merged.tsv"],
        false,
    );
    assert_eq!(code, COULD_NOT_LOOK, "{text}");
    assert!(text.contains("could not look"), "{text}");
}

/// A TRUNK THAT WILL NOT RESOLVE IS COULD-NOT-LOOK, never an empty claimed set:
/// read as empty, every row whose only landing is a closing keyword would read
/// as live, and idle, as abandoned.
#[test]
fn a_gather_that_cannot_read_the_trunk_is_could_not_look() {
    let b = Board::new("no-trunk");
    b.git(&["update-ref", "-d", "refs/remotes/origin/main"]);
    let (code, text) = b.drain(&set(&[row("CLOUD-124", OLD, "feat/gone", "")]));
    assert_eq!(code, COULD_NOT_LOOK, "{text}");
    assert!(text.contains("origin/main"), "{text}");
}

/// A MERGED-PR GATHER THAT FAILS IS THE DRAIN'S COULD-NOT-LOOK — the translation
/// `claimed_keys.rs` records as belonging to this port. The forge answers, and
/// its answer holds no merged pull request at all, which `claim merged`'s own
/// body refuses as impossible of a repository with a trunk. Read as an empty
/// arm instead, every row a merged pull request closed would be live and, idle,
/// abandoned; here the row is fresh, so a laundered failure reads as CLEAN.
#[test]
fn a_gather_whose_merged_pull_requests_cannot_be_read_is_could_not_look() {
    let b = Board::new("gather-merged-empty");
    b.forge("/pulls", "pulls", "[]");
    let (code, text) = b.drain_with(
        &set(&[row("CLOUD-124", TODAY, "feat/gone", "")]),
        &["--refs", "refs.txt"],
        false,
    );
    assert_eq!(code, COULD_NOT_LOOK, "{text}");
    assert!(text.contains("could not look"), "{text}");
    assert!(text.contains("merged pull requests:"), "{text}");
}

/// THE TRUNK IS THE CONSUMER'S DECLARATION, never a literal `origin/main`. This
/// fixture's trunk is `origin/trunk` and no `origin/main` exists at all, so a
/// gather reading the literal is could-not-look forever; reading `must_land_on`
/// it finds the closing key and the row is landed-unswept.
#[test]
fn the_gather_reads_the_declared_trunk_not_origin_main() {
    let b = Board::new("declared-trunk");
    let config = std::fs::read_to_string(b.repo.join("batten.toml")).expect("config");
    let declared = "must_land_on = \"origin/main\"";
    assert!(config.contains(declared), "the fixture's trunk line moved");
    std::fs::write(
        b.repo.join("batten.toml"),
        config.replace(declared, "must_land_on = \"origin/trunk\""),
    )
    .expect("config");
    b.git(&["checkout", "-q", "main"]);
    b.git(&["commit", "-q", "--allow-empty", "-m", CLOSES]);
    b.git(&["update-ref", "refs/remotes/origin/trunk", "main"]);
    b.git(&["update-ref", "-d", "refs/remotes/origin/main"]);
    b.git(&["checkout", "-q", "work"]);
    let (code, text) = b.drain(&set(&[row("CLOUD-179", TODAY, "feat/x", "")]));
    assert_eq!(code, VIOLATION, "{text}");
    assert!(
        text.contains("landed-unswept") && text.contains("CLOUD-179"),
        "{text}"
    );
}
