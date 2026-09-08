//! `batten startup` over the compiled binary (CLOUD-1324).
//!
//! # What this tier reaches that the unit cases cannot
//!
//! `src/startup.rs`'s own cases pin the decision — what a passing check, a
//! failing one, an unspawnable one and a repair that does not satisfy its own
//! check each produce. What they structurally cannot reach is everything
//! between the config file and that decision: that `[[startup]]` parses at all,
//! that `resolve` carries the rows to the verb, that the verb renders them in
//! §6's pointer shape, that its exit code stays inside the `0`/`1` pair, and
//! that a malformed row is refused at LOAD rather than at the first run.
//!
//! Each of those is a place the feature can be completely dead while every unit
//! case passes — the class `rules/policy-modules.md` records for a Rego
//! predicate reading a key the engine never builds.
//!
//! # Why the fixtures use `true`, `false` and `test -f`
//!
//! A row's check is a command, so a fixture that ran a REAL precondition would
//! be testing the container. These are the smallest commands whose exit code is
//! known, which leaves exactly the plumbing above under test.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::Path;
use std::process::Output;

use common::{batten, git_in, scratch, stdout, write};

/// A repository whose `batten.toml` carries `rows`.
fn fixture(name: &str, rows: &str) -> std::path::PathBuf {
    let dir = scratch(name);
    write(&dir, "batten.toml", &format!("version = 1\n\n{rows}"));
    write(&dir, "a.txt", "x\n");
    git_in(&dir, &["init", "-q", "-b", "main", "."]);
    dir
}

fn startup(dir: &Path, args: &[&str]) -> Output {
    batten()
        .current_dir(dir)
        .arg("startup")
        .args(args)
        .output()
        .expect("the binary runs")
}

/// A row spelling `check` and optionally `repair`, as TOML.
fn row(id: &str, check: &str, repair: Option<&str>) -> String {
    let repair = repair.map_or_else(String::new, |argv| format!("repair = {argv}\n"));
    format!("[[startup]]\nid = \"{id}\"\ngloss = \"a fixture row\"\ncheck = {check}\n{repair}\n")
}

#[test]
fn a_provisioned_container_reports_every_row_and_exits_zero() {
    let dir = fixture("startup-clean", &row("clean", "[\"true\"]", None));
    let out = startup(&dir, &[]);
    assert_eq!(out.status.code(), Some(0));
    // EVERY row, not only the failing ones, and deliberately unlike `provision
    // status`: a reader running this is asking whether the container is right,
    // and silence cannot distinguish a row that passed from one never declared.
    assert_eq!(stdout(&out), "clean ok\nstartup: 1 row(s), 0 failed\n");
}

#[test]
fn a_row_with_no_repair_reports_the_class_a_reader_can_act_on() {
    let dir = fixture("startup-bare", &row("bare", "[\"false\"]", None));
    let out = startup(&dir, &[]);
    // `1`, never `2`: a container that does not match what the repository
    // declares is the config-or-usage class, and a mediating harness reads `2`
    // as a policy denial (§7). `doctor`'s reasoning, inherited.
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(
        stdout(&out),
        "bare failed not-provisioned\nstartup: 1 row(s), 1 failed\n"
    );
}

/// THE VERB'S WHOLE POINT, in one pair: the same tree, the same row, and the
/// flag is the only difference.
///
/// The check is a file test and the repair creates the file, so the two runs
/// genuinely differ rather than rendering one answer twice.
#[test]
fn repair_fixes_and_says_so_while_the_bare_verb_changes_nothing() {
    let dir = scratch("startup-repair");
    let target = dir.join("marker");
    let path = target.to_str().unwrap().to_owned();
    let rows = row(
        "makes-it",
        &format!("[\"test\", \"-f\", {}]", json(&path)),
        Some(&format!("[\"touch\", {}]", json(&path))),
    );
    write(&dir, "batten.toml", &format!("version = 1\n\n{rows}"));
    git_in(&dir, &["init", "-q", "-b", "main", "."]);

    let bare = startup(&dir, &[]);
    assert_eq!(out_code(&bare), 1);
    assert!(
        !target.exists(),
        "the read path must not mutate — that is the whole of --repair"
    );

    let repaired = startup(&dir, &["--repair"]);
    assert_eq!(out_code(&repaired), 0);
    assert_eq!(
        stdout(&repaired),
        "makes-it ok repaired\nstartup: 1 row(s), 0 failed\n",
        "a reader who ran --repair should see which rows it moved"
    );
    assert!(target.exists());

    // Idempotent, and reported as ordinary rather than as repaired again: a
    // repair that runs every time is a repair whose check is wrong, and the two
    // renderings are what let a reader tell those apart.
    let again = startup(&dir, &["--repair"]);
    assert_eq!(stdout(&again), "makes-it ok\nstartup: 1 row(s), 0 failed\n");
}

/// The commit gate as a declared precondition, end to end (CLOUD-1398).
///
/// **The one case in this file whose check is a REAL precondition**, which the
/// module header says the others deliberately avoid — and the exception is the
/// point rather than a lapse. Every other fixture uses `true`/`false`/`test -f`
/// because a real check would be testing the container; this row exists because
/// nothing was testing the container, and a fixture that stubbed the predicate
/// out would reproduce exactly the defect it is here to catch. `doctor
/// commit-gate` is batten's own verb over a scratch repository, so what is under
/// test is still this tree and not the host.
///
/// The repair sets `core.hooksPath`, which is argv-only — no shell between the
/// declaration and what runs (`batten.toml`'s own bound on `check`/`repair`) —
/// and it exercises the branch of [`doctor::hooks_dir`] that a repository
/// redirecting its hooks takes. A `git init` leaves `.git/hooks` carrying only
/// `*.sample` files, so the fixture starts genuinely bypassed rather than being
/// made so.
///
/// The third run is what the row's §7 asks for and is not decoration: `ok`
/// WITHOUT `repaired` is the only thing separating a repair that worked from one
/// that exits zero having fixed nothing.
#[test]
fn a_clone_with_no_commit_hooks_fails_the_row_and_repair_installs_them() {
    let dir = scratch("startup-commit-gate");
    write(&dir, "batten.toml", "version = 1\n\n");
    common::init_repo(&dir);

    // The hooks the repair will point git at. Written before the row, so the
    // repair is a redirection and never a creation — it is `session:git-hooks`'s
    // shape (an existing body, linked into place) rather than a second author of
    // the hook.
    let hooks = dir.join("committed-hooks");
    std::fs::create_dir_all(&hooks).unwrap();
    for name in ["pre-commit", "commit-msg"] {
        let at = hooks.join(name);
        std::fs::write(&at, "#!/bin/sh\nexit 0\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&at, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
    }
    // THE BUILT BINARY BY ABSOLUTE PATH, never bare `batten` — and this is the
    // one thing this case got wrong first. `startup` spawns a row's `check` by
    // resolving it the way any spawn does, so a bare name reaches whatever
    // `batten` is INSTALLED on PATH. That made this case grade the container's
    // install currency rather than this tree: it passed while the installed copy
    // happened to carry the verb, and went red the moment the verb was renamed
    // here. Which is CLOUD-1650's own subject, arriving inside CLOUD-1398's suite.
    let bin = json(env!("CARGO_BIN_EXE_batten"));
    let rows = row(
        "commit-gate-installed",
        &format!("[{bin}, \"doctor\", \"gate\"]"),
        Some(&format!(
            "[\"git\", \"config\", \"core.hooksPath\", {}]",
            json(hooks.to_str().unwrap())
        )),
    );
    write(&dir, "batten.toml", &format!("version = 1\n\n{rows}"));

    // A fresh clone: `.git/hooks` holds samples and nothing git will run, so a
    // commit here bypasses the gate. This is the state the row was filed over.
    let bare = startup(&dir, &[]);
    assert_eq!(out_code(&bare), 1);
    assert_eq!(
        stdout(&bare),
        "commit-gate-installed failed not-provisioned\nstartup: 1 row(s), 1 failed\n",
        "a clone whose commit path does not run the gate must say so"
    );

    let repaired = startup(&dir, &["--repair"]);
    assert_eq!(out_code(&repaired), 0);
    assert_eq!(
        stdout(&repaired),
        "commit-gate-installed ok repaired\nstartup: 1 row(s), 0 failed\n"
    );

    let again = startup(&dir, &["--repair"]);
    assert_eq!(
        stdout(&again),
        "commit-gate-installed ok\nstartup: 1 row(s), 0 failed\n",
        "a repair that runs every time is a repair whose check is wrong"
    );
}

/// The sub-verb answers alone, and answers the same thing the row does.
///
/// **This is the property the `[[startup]]` row depends on and nothing else
/// asserts.** A row decides on an exit status, so `doctor commit-gate` has to
/// carry the commit-gate verdict and NO other check's — if it ever started
/// folding in a sibling row, the committed row would fail for an unrelated
/// unreachable program and fire a git-hook repair that cannot fix it.
#[test]
fn the_commit_gate_sub_verb_answers_only_its_own_question() {
    let dir = scratch("startup-commit-gate-verb");
    write(&dir, "batten.toml", "version = 1\n\n");
    common::init_repo(&dir);

    let bare = batten()
        .current_dir(&dir)
        .args(["doctor", "gate"])
        .output()
        .expect("the binary runs");
    assert_eq!(out_code(&bare), 1, "doctor never renders a policy verdict");
    assert_eq!(
        stdout(&bare),
        "commit-gate failed commit-hook-missing commit-msg pre-commit\n",
        "the hook NAMES are the actionable subjects; the directory is a path and never emitted"
    );

    let hooks = dir.join(".git").join("hooks");
    std::fs::create_dir_all(&hooks).unwrap();
    for name in ["pre-commit", "commit-msg"] {
        let at = hooks.join(name);
        std::fs::write(&at, "#!/bin/sh\nexit 0\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&at, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
    }
    let healthy = batten()
        .current_dir(&dir)
        .args(["doctor", "gate"])
        .output()
        .expect("the binary runs");
    assert_eq!(out_code(&healthy), 0);
    assert_eq!(stdout(&healthy), "commit-gate ok\n");
}

/// A non-executable hook is not a hook, which is git's own reading.
///
/// The arm that separates this check from a file-existence one — and the
/// distinction `mise-tasks/doctor.sh` already draws for the same subject, since
/// "present but git will not run it" is indistinguishable from healthy to a
/// probe that only stats for existence.
#[test]
fn a_present_but_unrunnable_hook_reads_as_missing() {
    let dir = scratch("startup-commit-gate-mode");
    write(&dir, "batten.toml", "version = 1\n\n");
    common::init_repo(&dir);
    let hooks = dir.join(".git").join("hooks");
    std::fs::create_dir_all(&hooks).unwrap();
    std::fs::write(hooks.join("commit-msg"), "#!/bin/sh\nexit 0\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(
            hooks.join("commit-msg"),
            std::fs::Permissions::from_mode(0o755),
        )
        .unwrap();
    }
    // Present, and mode 0644: git skips it silently.
    std::fs::write(hooks.join("pre-commit"), "#!/bin/sh\nexit 0\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(
            hooks.join("pre-commit"),
            std::fs::Permissions::from_mode(0o644),
        )
        .unwrap();
    }

    let out = batten()
        .current_dir(&dir)
        .args(["doctor", "gate"])
        .output()
        .expect("the binary runs");
    assert_eq!(
        stdout(&out),
        "commit-gate failed commit-hook-missing pre-commit\n",
        "only the unrunnable one is named — a subject list is what a reader acts on"
    );
}

/// The row's own remedy names a path that exists.
///
/// **The assertion that stops CLOUD-1398 recurring, and it is the whole reason
/// the row exists at all.** `doctor.sh` told an agent to run
/// `.claude/hooks/session-start.sh` for its entire life after `7d188580` deleted
/// that program: the refusal was correct and its instruction could not be
/// followed. Prose cannot hold that; a case over the tracked file can.
///
/// It asserts the SUCCESSOR resolves rather than that the old name is absent,
/// because those are different claims — a remedy could name a second dead path
/// and pass the weaker one.
#[test]
fn every_remedy_the_hook_check_prints_names_something_that_resolves() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("the workspace root is two levels above the crate");
    // THE COMMITTED AUTHORITY IS THE SUBJECT, not `mise-tasks/doctor.sh`, and
    // that narrowing is measured rather than chosen. The shell task's two
    // `::error::` remedies still name `.claude/hooks/session-start.sh`, which
    // `7d188580` deleted — the defect this row was filed on. It is NOT repaired
    // here because `policy/shell-retirement.rego` refuses the edit: its one
    // admitted arm, `only_drops_a_retired_reference`, requires every removed line
    // to name a path THIS SAME DELTA deleted, and this delta deletes nothing. So
    // the task has two landable shapes — retire it whole, or leave it alone — and
    // this change leaves it alone.
    //
    // What the row CAN hold is its own remedy, and that is what this asserts: the
    // `[[startup]]` row's `repair` argv must name a task the manifest declares and
    // a hook body present in the tree. A remedy naming a retired file is what
    // CLOUD-1398 is about; this makes the successor's remedy unable to become one.
    let config =
        std::fs::read_to_string(root.join("batten.toml")).expect("the authority is tracked");
    assert!(
        config.contains(r#"repair = ["mise", "run", "session:git-hooks"]"#),
        "the commit-gate row must repair through the installer that exists"
    );
    let manifest =
        std::fs::read_to_string(root.join("mise.toml")).expect("the manifest is tracked");
    assert!(
        manifest.contains("[tasks.\"session:git-hooks\"]"),
        "the remedy names a task the manifest must declare"
    );
    assert!(
        root.join(".claude")
            .join("hooks")
            .join("git-hook.sh")
            .is_file(),
        "the hook body the row's repair links must be present in the tree"
    );
}

/// A repository declaring nothing says so, rather than saying nothing.
///
/// The count line is what makes silence legible: without it, "no rows" and
/// "every row passed" are the same empty output.
#[test]
fn a_repository_with_no_rows_reports_the_count_rather_than_nothing() {
    let dir = fixture("startup-none", "");
    let out = startup(&dir, &[]);
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(stdout(&out), "startup: 0 row(s), 0 failed\n");
}

#[test]
fn the_data_channel_carries_every_row_with_its_verdict() {
    let dir = fixture(
        "startup-json",
        &(row("good", "[\"true\"]", None) + &row("bad", "[\"false\"]", None)),
    );
    let out = startup(&dir, &["-J"]);
    let rows: serde_json::Value = serde_json::from_str(&stdout(&out)).expect("one JSON document");
    let rows = rows.as_array().expect("an array of outcomes");
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0]["id"], "good");
    assert_eq!(rows[0]["ok"], true);
    // Omitted rather than nulled on a pass — a key whose only value is null is
    // a field every reader has to learn to ignore.
    assert!(rows[0].get("reason").is_none(), "{:?}", rows[0]);
    assert_eq!(rows[1]["reason"], "not-provisioned");
}

/// A ROW THAT COULD NEVER DECIDE IS REFUSED AT LOAD, not once per session.
///
/// The direction is what matters: an empty check answers could-not-look
/// forever, so the row would report a failure nobody can fix and its repair
/// would never run — a dead gate that reads as a broken container.
#[test]
fn a_malformed_row_is_refused_when_the_config_loads() {
    let dir = fixture("startup-malformed", &row("empty", "[]", None));
    let out = startup(&dir, &[]);
    assert_eq!(out.status.code(), Some(1));
    let text = common::stderr(&out);
    assert!(text.contains("startup"), "{text}");

    // The same refusal reaches every verb, because it is the CONFIG that is
    // refused rather than this one command — which is what makes it a load-time
    // rule instead of a check inside `startup`.
    let elsewhere = batten()
        .current_dir(&dir)
        .arg("check")
        .output()
        .expect("the binary runs");
    assert_eq!(elsewhere.status.code(), Some(1));
}

#[test]
fn two_rows_may_not_share_an_id() {
    let dir = fixture(
        "startup-duplicate",
        &(row("same", "[\"true\"]", None) + &row("same", "[\"false\"]", None)),
    );
    assert_eq!(startup(&dir, &[]).status.code(), Some(1));
}

fn json(value: &str) -> String {
    serde_json::to_string(value).expect("a path is encodable")
}

fn out_code(output: &Output) -> i32 {
    output.status.code().unwrap_or(-1)
}
