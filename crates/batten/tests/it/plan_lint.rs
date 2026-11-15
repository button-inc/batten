//! `batten plan lint` and `batten plan path`, over the compiled binary
//! (CLOUD-2766).
//!
//! Each case is a scratch repository on branch `work` with its own `[plan]`
//! table, a local `origin/main` at the base commit — without a resolvable trunk
//! the branch-validity reader cannot look and allows, so no case could show a
//! denial — and a plan record written by the real `batten record plan`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Output;

/// The `[plan]` table every case declares unless it says otherwise.
const TABLE: &str = "[plan]\n\
sections = [\"Acceptance\", \"Steps\", \"Notes\", \"Validation\"]\n\
verdict = \"verdict: executable\"\n";

/// A write-triggered receipt rule reading the lint's receipt.
const HOLD: &str = "\n[[rule]]\nid = \"plan hold\"\nkind = \"receipt\"\n\
scope = \"mediated_call\"\nseverity = \"deny\"\ntrigger = \"write\"\n\
checks = [\"plan-check\"]\nkey = \"branch\"\nreason = \"lint the plan first\"\n";

/// A plan that passes [`TABLE`] with the record `S1 pending`, `S2 pending`.
const GOOD: &str = "# Plan\n\
## Acceptance\n\
- A1 the first outcome\n\
- A2 the second outcome\n\
## Steps\n\
- S1 build the first, see `seed.txt:1` (A1)\n\
- S2 build the second\n\
  which serves A2\n\
## Notes\n\
Nothing surprising.\n\
## Validation\n\
verdict: executable\n";

const RECORD: &[&str] = &["S1 pending", "S2 pending"];

/// A repository on `work` with `config` committed, `origin/main` at the base.
fn repo(name: &str, config: &str) -> PathBuf {
    let root = common::scratch(name);
    common::git_in(&root, &["init", "--quiet", "--initial-branch", "work"]);
    common::git_in(&root, &["config", "user.email", "t@example.com"]);
    common::git_in(&root, &["config", "user.name", "t"]);
    fs::write(root.join("seed.txt"), "seed\n").unwrap();
    // The trunk is DECLARED, not merely pinned: with no `must_land_on` the
    // branch-validity reader cannot look and allows, as `Fixture::base_commit`
    // records (CLOUD-2188).
    fs::write(
        root.join("batten.toml"),
        format!("must_land_on = \"origin/main\"\nversion = 1\n{config}"),
    )
    .unwrap();
    common::git_in(&root, &["add", "-A"]);
    common::git_in(&root, &["commit", "--quiet", "-m", "base"]);
    let base = common::git_in(&root, &["rev-parse", "HEAD"]);
    common::git_in(
        &root,
        &["update-ref", "refs/remotes/origin/main", base.trim()],
    );
    common::git_in(&root, &["update-ref", "refs/heads/main", base.trim()]);
    root
}

fn git_dir(root: &Path) -> PathBuf {
    PathBuf::from(common::git_in(root, &["rev-parse", "--absolute-git-dir"]).trim())
}

fn receipts(root: &Path) -> PathBuf {
    git_dir(root).join("batten-receipts")
}

/// Write the plan file where `plan path` says it is.
fn write_plan(root: &Path, text: &str) -> PathBuf {
    let path = PathBuf::from(common::stdout(&common::run(root, &["plan", "path"])).trim());
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(&path, text).unwrap();
    path
}

/// Record the plan through the real writer.
fn record(root: &Path, lines: &[&str]) {
    let body = if lines.is_empty() {
        String::new()
    } else {
        format!("{}\n", lines.join("\n"))
    };
    let output = common::run_with_stdin(root, &["record", "plan"], &body);
    assert_eq!(output.status.code(), Some(0), "{}", common::stderr(&output));
}

fn lint(root: &Path) -> Output {
    common::run(root, &["plan", "lint"])
}

/// The clauses the lint refused with, in order.
fn clauses(output: &Output) -> Vec<String> {
    common::stderr(output)
        .lines()
        .filter_map(|line| line.split_once("plan grade refused at "))
        .filter_map(|(_, subject)| subject.split(';').next())
        .filter_map(|subject| subject.split_once(' ').map(|(_, clause)| clause.to_owned()))
        .collect()
}

/// The lines carrying a finding.
fn finding_lines(output: &Output) -> Vec<String> {
    common::stderr(output)
        .lines()
        .filter(|line| line.contains("plan grade refused"))
        .map(str::to_owned)
        .collect()
}

fn plan_receipt(root: &Path) -> PathBuf {
    receipts(root).join("plan-check.work")
}

/// Whether an `Edit` of the tracked seed file is refused.
fn edit_denied(root: &Path) -> bool {
    let payload = serde_json::json!({
        "session_id": "plan-lint",
        "hook_event_name": "PreToolUse",
        "tool_name": "Edit",
        "tool_input": {
            "file_path": root.join("seed.txt").to_string_lossy(),
            "old_string": "seed",
            "new_string": "seeded"
        }
    })
    .to_string();
    let output =
        common::run_with_stdin(root, &["adjudicate", "--harness", "claude-code"], &payload);
    output.status.code() == Some(2) || common::stdout(&output).contains("\"deny\"")
}

fn passing(name: &str, config: &str) -> PathBuf {
    let root = repo(name, config);
    record(&root, RECORD);
    write_plan(&root, GOOD);
    root
}

#[test]
fn a_complete_plan_passes_and_leaves_the_receipt() {
    let root = passing("plan-lint-pass", &format!("{TABLE}{HOLD}"));
    assert!(edit_denied(&root), "the hold applies before the lint");
    let output = lint(&root);
    assert_eq!(output.status.code(), Some(0), "{}", common::stderr(&output));
    let body = fs::read_to_string(plan_receipt(&root)).unwrap();
    let head = common::git_in(&root, &["rev-parse", "HEAD"]);
    let lines: Vec<&str> = body.lines().collect();
    assert_eq!(lines.len(), 2, "{body}");
    assert_eq!(lines[0], format!("base {}", head.trim()));
    let plan = fs::read(git_dir(&root).join("batten-plans/work.md")).unwrap();
    assert_eq!(
        lines[1],
        format!("plan {}", batten::receipt::hex_sha256(&plan))
    );
    assert!(!edit_denied(&root), "the receipt lifts the hold");
}

#[test]
fn a_missing_section_is_refused_and_nothing_is_written() {
    let root = repo("plan-lint-missing", TABLE);
    record(&root, RECORD);
    write_plan(
        &root,
        &GOOD.replace("## Validation\nverdict: executable\n", ""),
    );
    let output = lint(&root);
    assert_eq!(output.status.code(), Some(2), "{}", common::stderr(&output));
    assert_eq!(
        clauses(&output),
        ["section-missing 4"],
        "{}",
        common::stderr(&output)
    );
    assert!(
        !plan_receipt(&root).exists(),
        "a refused plan writes nothing"
    );
    let swapped = GOOD.replace("## Notes\nNothing surprising.\n", "").replace(
        "## Validation\n",
        "## Validation\n## Notes\nNothing surprising.\n",
    );
    write_plan(&root, &swapped);
    let output = lint(&root);
    assert!(
        finding_lines(&output)
            .iter()
            .any(|line| line.contains("section-missing")),
        "{}",
        common::stderr(&output)
    );
}

#[test]
fn an_empty_section_is_a_missing_section() {
    let root = repo("plan-lint-empty", TABLE);
    record(&root, RECORD);
    write_plan(&root, &GOOD.replace("Nothing surprising.\n", ""));
    let output = lint(&root);
    assert_eq!(output.status.code(), Some(2));
    assert!(common::stderr(&output).contains("section-missing 3"));
}

#[test]
fn a_pointer_past_the_end_of_its_file_is_dead() {
    let root = repo("plan-lint-past-end", TABLE);
    record(&root, RECORD);
    write_plan(&root, &GOOD.replace("`seed.txt:1`", "`seed.txt:9`"));
    let output = lint(&root);
    assert_eq!(
        clauses(&output),
        ["pointer-dead"],
        "{}",
        common::stderr(&output)
    );
}

#[test]
fn a_pointer_to_a_file_not_in_the_tree_is_dead() {
    let root = repo("plan-lint-absent-file", TABLE);
    record(&root, RECORD);
    write_plan(&root, &GOOD.replace("`seed.txt:1`", "`nowhere.rs:1`"));
    assert_eq!(clauses(&lint(&root)), ["pointer-dead"]);
}

#[test]
fn a_path_without_a_line_is_not_judged() {
    let root = repo("plan-lint-bare-path", TABLE);
    record(&root, RECORD);
    write_plan(&root, &GOOD.replace("`seed.txt:1`", "`new/file.rs`"));
    let output = lint(&root);
    assert_eq!(output.status.code(), Some(0), "{}", common::stderr(&output));
}

#[test]
fn an_item_no_step_reaches_is_refused() {
    let root = repo("plan-lint-unreached", TABLE);
    record(&root, RECORD);
    write_plan(&root, &GOOD.replace("which serves A2", "which serves A1"));
    let output = lint(&root);
    assert_eq!(
        clauses(&output),
        ["item-unreached"],
        "{}",
        common::stderr(&output)
    );
    assert!(
        finding_lines(&output)[0].contains(":4 "),
        "at the item's line"
    );
}

#[test]
fn a_step_serving_no_item_is_refused() {
    let root = repo("plan-lint-unasked", TABLE);
    record(&root, &["S1 pending", "S2 pending", "S3 pending"]);
    write_plan(
        &root,
        &GOOD.replace("## Notes\n", "- S3 tidy up\n## Notes\n"),
    );
    let output = lint(&root);
    assert_eq!(
        clauses(&output),
        ["step-unasked"],
        "{}",
        common::stderr(&output)
    );
    assert!(
        finding_lines(&output)[0].contains(":9 "),
        "at the step's line"
    );
}

#[test]
fn a_step_naming_an_unlisted_id_is_refused() {
    let root = repo("plan-lint-unlisted", TABLE);
    record(&root, RECORD);
    write_plan(
        &root,
        &GOOD.replace("which serves A2", "which serves A2 and A7"),
    );
    assert_eq!(clauses(&lint(&root)), ["step-unasked"]);
}

#[test]
fn a_trivial_change_lints_with_an_empty_record() {
    let trivial = "## Acceptance\nnone\n## Steps\nnone\n## Notes\nA one-line fix.\n\
## Validation\nverdict: executable\n";
    let root = repo("plan-lint-trivial", TABLE);
    record(&root, &[]);
    write_plan(&root, trivial);
    let output = lint(&root);
    assert_eq!(output.status.code(), Some(0), "{}", common::stderr(&output));
    let root = repo("plan-lint-trivial-held", TABLE);
    record(&root, &["S1 pending"]);
    write_plan(&root, trivial);
    assert!(clauses(&lint(&root)).contains(&"entry-unplanned".to_owned()));
}

#[test]
fn a_recorded_entry_of_another_shape_is_named_as_such() {
    let root = repo("plan-lint-misnamed", TABLE);
    record(&root, &["S1 pending", "S2 pending", "fix-tests pending"]);
    write_plan(&root, GOOD);
    assert_eq!(clauses(&lint(&root)), ["entry-misnamed"]);
}

#[test]
fn a_fenced_block_is_not_read() {
    let root = repo("plan-lint-fenced", TABLE);
    record(&root, RECORD);
    write_plan(
        &root,
        &GOOD.replace(
            "Nothing surprising.\n",
            "Nothing surprising.\n```\n## Validation\n- A9 not an item\n`gone.rs:1`\n```\n",
        ),
    );
    let output = lint(&root);
    assert_eq!(output.status.code(), Some(0), "{}", common::stderr(&output));
}

#[test]
fn a_malformed_plan_table_does_not_load() {
    for (name, table) in [
        (
            "plan-lint-two",
            "[plan]\nsections = [\"Acceptance\", \"Steps\"]\nverdict = \"v\"\n",
        ),
        (
            "plan-lint-first",
            "[plan]\nsections = [\"Validation\", \"Steps\", \"Validation\"]\nverdict = \"v\"\n",
        ),
    ] {
        let root = repo(name, table);
        let output = lint(&root);
        assert_eq!(
            output.status.code(),
            Some(1),
            "{name}: {}",
            common::stderr(&output)
        );
        assert!(
            common::stderr(&output).contains("plan declare partial"),
            "{name}: {}",
            common::stderr(&output)
        );
    }
}

#[test]
fn an_id_is_matched_whole() {
    let root = repo("plan-lint-whole-id", TABLE);
    record(&root, RECORD);
    write_plan(
        &root,
        &GOOD
            .replace(
                "- A2 the second outcome\n",
                "- A2 the second outcome\n- A10 a tenth\n",
            )
            .replace("(A1)", "(A10)"),
    );
    let output = lint(&root);
    assert_eq!(
        clauses(&output),
        ["item-unreached"],
        "{}",
        common::stderr(&output)
    );
    assert!(
        finding_lines(&output)[0].contains(":3 "),
        "A1 is the unreached item"
    );
}

#[test]
fn the_steps_must_be_the_recorded_entries() {
    let root = repo("plan-lint-record", TABLE);
    write_plan(&root, GOOD);
    assert_eq!(clauses(&lint(&root)), ["record-missing"]);
    record(&root, &["S1 pending"]);
    assert_eq!(clauses(&lint(&root)), ["step-unrecorded"]);
    record(&root, &["S1 pending", "S2 pending", "S3 pending"]);
    assert_eq!(clauses(&lint(&root)), ["entry-unplanned"]);
    record(&root, RECORD);
    assert_eq!(lint(&root).status.code(), Some(0));
}

#[test]
fn the_hold_returns_after_a_new_claim() {
    let root = passing("plan-lint-void", &format!("{TABLE}{HOLD}"));
    assert_eq!(lint(&root).status.code(), Some(0));
    assert!(!edit_denied(&root));
    batten::durable::append(&plan_receipt(&root), "base -").unwrap();
    assert!(edit_denied(&root), "a voided receipt holds again");
}

#[test]
fn the_validation_section_is_read_for_the_verdict_only() {
    let root = repo("plan-lint-validation", TABLE);
    record(&root, RECORD);
    write_plan(
        &root,
        &GOOD.replace(
            "## Validation\nverdict: executable\n",
            "## Validation\nThe reader quoted `gone.rs:4`.\n## Reply\nverdict: executable\n",
        ),
    );
    let output = lint(&root);
    assert_eq!(output.status.code(), Some(0), "{}", common::stderr(&output));
}

#[test]
fn the_verdict_line_must_be_there() {
    let root = repo("plan-lint-verdict", TABLE);
    record(&root, RECORD);
    write_plan(&root, &GOOD.replace("verdict: executable", "looks fine"));
    assert_eq!(clauses(&lint(&root)), ["verdict-absent"]);
}

#[test]
fn the_required_receipt_must_exist_first() {
    let table = format!("{TABLE}requires = \"plan-skill\"\n");
    let root = passing("plan-lint-requires", &table);
    assert_eq!(clauses(&lint(&root)), ["check-unasked"]);
    fs::create_dir_all(receipts(&root)).unwrap();
    fs::write(receipts(&root).join("plan-skill.work"), "loaded\n").unwrap();
    assert_eq!(lint(&root).status.code(), Some(0));
}

#[test]
fn no_plan_table_is_a_usage_error() {
    let root = repo("plan-lint-no-table", "");
    write_plan(&root, GOOD);
    let output = lint(&root);
    assert_eq!(output.status.code(), Some(1), "{}", common::stderr(&output));
    assert!(!plan_receipt(&root).exists());
}

#[test]
fn a_detached_head_is_a_usage_error() {
    let root = passing("plan-lint-detached", TABLE);
    common::git_in(&root, &["checkout", "--quiet", "--detach"]);
    let output = lint(&root);
    assert_eq!(output.status.code(), Some(1), "{}", common::stderr(&output));
    assert!(!plan_receipt(&root).exists());
}

#[test]
fn the_findings_carry_no_plan_text() {
    let marker = "ZEBRA-MARKER";
    let root = repo("plan-lint-no-text", TABLE);
    record(&root, RECORD);
    write_plan(
        &root,
        &GOOD.replace("Nothing surprising.", &format!("{marker} `{marker}.rs:3`")),
    );
    let output = lint(&root);
    assert_eq!(clauses(&output), ["pointer-dead"]);
    assert!(!common::stdout(&output).contains(marker));
    assert!(!common::stderr(&output).contains(marker));
}

#[test]
fn plan_path_names_the_branch_file_and_creates_nothing() {
    let root = repo("plan-lint-path", TABLE);
    common::git_in(&root, &["checkout", "--quiet", "-b", "a/b"]);
    let output = common::run(&root, &["plan", "path"]);
    assert_eq!(output.status.code(), Some(0), "{}", common::stderr(&output));
    assert!(
        common::stdout(&output)
            .trim()
            .ends_with("batten-plans/a-b.md"),
        "{}",
        common::stdout(&output)
    );
    assert!(!git_dir(&root).join("batten-plans").exists());
}

#[test]
fn a_passing_lint_consumes_the_prerequisite() {
    let table = format!("{TABLE}requires = \"plan-skill\"\n");
    let root = passing("plan-lint-consume", &table);
    fs::create_dir_all(receipts(&root)).unwrap();
    let prerequisite = receipts(&root).join("plan-skill.work");
    write_plan(&root, &GOOD.replace("verdict: executable", "not yet"));
    fs::write(&prerequisite, "loaded\n").unwrap();
    assert_eq!(lint(&root).status.code(), Some(2));
    assert!(
        prerequisite.exists(),
        "a failing lint leaves the prerequisite"
    );
    write_plan(&root, GOOD);
    assert_eq!(lint(&root).status.code(), Some(0));
    assert!(!prerequisite.exists(), "a pass consumes it");
    assert_eq!(clauses(&lint(&root)), ["check-unasked"]);
}

#[test]
fn an_earlier_tickets_steps_stay_in_the_plan() {
    let root = repo("plan-lint-earlier", TABLE);
    record(&root, &["S2 pending"]);
    write_plan(&root, GOOD);
    assert_eq!(clauses(&lint(&root)), ["step-unrecorded"]);
}

#[test]
fn a_second_lint_appends_and_the_newest_base_is_read() {
    let table = format!("{TABLE}requires = \"plan-skill\"\n{HOLD}");
    let root = passing("plan-lint-second", &table);
    fs::create_dir_all(receipts(&root)).unwrap();
    let prerequisite = receipts(&root).join("plan-skill.work");
    fs::write(&prerequisite, "loaded\n").unwrap();
    assert_eq!(lint(&root).status.code(), Some(0));
    fs::write(root.join("seed.txt"), "seed\nmore\n").unwrap();
    common::git_in(&root, &["commit", "--quiet", "-am", "more"]);
    fs::write(&prerequisite, "loaded\n").unwrap();
    assert_eq!(lint(&root).status.code(), Some(0));
    let body = fs::read_to_string(plan_receipt(&root)).unwrap();
    assert_eq!(
        body.lines()
            .filter(|line| line.starts_with("base "))
            .count(),
        2,
        "{body}"
    );
    assert!(!edit_denied(&root), "the newest base is read: {body}");
}
