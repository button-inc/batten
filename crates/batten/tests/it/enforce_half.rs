//! End-to-end: `enforce --half tree|live` splits the rows by what their verdict
//! is a function of (step 13a).
//!
//! # Why the compiled binary
//!
//! The classifier and the backstop are unit-tested where they live
//! (`rules::half_tests`, `policy::tests`). What only the binary can pin is the
//! WIRING a consumer depends on: that a row reading live state is judged by the
//! live half and never by the receipted one, that `--rule` cannot launder a row
//! into the wrong half, that the tree half under a `[[step]]` receipt skips its
//! work on a hit and re-runs on every input the key covers — the store baseline
//! and admissions through `--inputs-digest` included — that the receipted half
//! refuses an override, that each half applies only its own rows' baseline
//! entries, and that the engine-side ledger answers only in the live half.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::{Path, PathBuf};
use std::process::Output;

use common::{Fixture, StateHome, git_in, init_repo, scratch, stderr, stdout, write};

/// One tree row (a `forbid`) and nothing else.
const FORBID: &str = "version = 1\n\
                      scope = [\"**\"]\n\
                      \n[[rule]]\n\
                      id = \"no-banned\"\n\
                      kind = \"forbid\"\n\
                      glob = \"**/*.txt\"\n\
                      pattern = \"BANNED\"\n\
                      severity = \"deny\"\n\
                      scope = \"tree\"\n";

/// A committed repository carrying `config` and `files`.
fn repo(name: &str, config: &str, files: &[(&str, &str)]) -> PathBuf {
    let dir = scratch(&format!("enforce-half-{name}"));
    init_repo(&dir);
    write(&dir, "batten.toml", config);
    for (path, body) in files {
        write(&dir, path, body);
    }
    git_in(&dir, &["add", "-A"]);
    git_in(&dir, &["commit", "-qm", "base"]);
    dir
}

/// `batten <args>` in `dir`, with the step cache on.
fn batten(dir: &Path, args: &[&str]) -> Output {
    common::batten()
        .args(args)
        .current_dir(dir)
        .env_remove("CI")
        .env_remove("BATTEN_STEP_RECEIPT_BYPASS")
        .env_remove("BATTEN_FAIL_ON_WARNING")
        .streamed_output()
        .expect("run batten")
}

fn code(output: &Output) -> Option<i32> {
    output.status.code()
}

#[test]
fn a_tree_row_is_judged_by_the_tree_half_alone() {
    let dir = repo("forbid", FORBID, &[("a.txt", "BANNED\n")]);

    let tree = batten(&dir, &["enforce", "--half", "tree"]);
    assert_eq!(
        code(&tree),
        Some(2),
        "the tree half judges it: {}",
        stderr(&tree)
    );
    assert!(stdout(&tree).contains("no-banned"), "{}", stdout(&tree));

    let live = batten(&dir, &["enforce", "--half", "live"]);
    assert_eq!(
        code(&live),
        Some(0),
        "the live half does not: {}",
        stdout(&live)
    );
    assert!(!stdout(&live).contains("no-banned"), "{}", stdout(&live));

    // UNSET, NOTHING MOVES: every row, exactly as before the split.
    let whole = batten(&dir, &["enforce"]);
    assert_eq!(code(&whole), Some(2), "{}", stderr(&whole));
}

#[test]
fn a_rule_selected_into_the_wrong_half_is_refused() {
    let dir = repo("wrong-half", FORBID, &[("a.txt", "BANNED\n")]);

    let refused = batten(&dir, &["enforce", "--half", "live", "--rule", "no-banned"]);
    assert_eq!(
        code(&refused),
        Some(1),
        "a narrowed run that judged nothing would read as a pass: {}",
        stderr(&refused)
    );
    assert!(
        stderr(&refused).contains("no-banned"),
        "{}",
        stderr(&refused)
    );

    let right = batten(&dir, &["enforce", "--half", "tree", "--rule", "no-banned"]);
    assert_eq!(code(&right), Some(2), "{}", stderr(&right));
}

/// One `ratchet` over tree facts, against `HEAD`.
const RATCHET: &str = "version = 1\n\
                       scope = [\"**\"]\n\
                       \n[[rule]]\n\
                       id = \"todo-grew\"\n\
                       kind = \"ratchet\"\n\
                       glob = \"*.txt\"\n\
                       pattern = \"TODO\"\n\
                       direction = \"non_increasing\"\n\
                       base = \"HEAD\"\n\
                       severity = \"deny\"\n\
                       scope = \"tree\"\n";

/// A ratchet is a tree row only when its `base` is one the caller keys the
/// receipt on (`--keyed-base`): unkeyed, its base can move under a receipt, so
/// `--rule` into the tree half is refused (CLOUD-2789).
///
/// Fails by: the keyed bases dropped on the way into the run, which leaves a
/// keyed ratchet in the live half and refuses it here.
#[test]
fn a_ratchet_on_a_keyed_base_is_judged_by_the_tree_half() {
    let dir = repo("keyed-ratchet", RATCHET, &[("a.txt", "TODO\n")]);

    let keyed = batten(
        &dir,
        &[
            "enforce",
            "--half",
            "tree",
            "--keyed-base",
            "HEAD",
            "--rule",
            "todo-grew",
        ],
    );
    assert_eq!(code(&keyed), Some(0), "{}", stderr(&keyed));

    let unkeyed = batten(&dir, &["enforce", "--half", "tree", "--rule", "todo-grew"]);
    assert_eq!(
        code(&unkeyed),
        Some(1),
        "an unkeyed ratchet is the live half's: {}",
        stderr(&unkeyed)
    );
    assert!(
        stderr(&unkeyed).contains("todo-grew"),
        "{}",
        stderr(&unkeyed)
    );
}

/// A module deciding over the family `runs`, which no tree key covers.
const READS_THE_RUNS: &str = r#"# METADATA
# description: reads a record family.
# schemas:
#   - input: schema["policy-input.schema"]
package batten.reads_the_runs

import rego.v1

rules contains "record read other"

violation contains {
	"rule": "record read other",
	"verdict": "record read other",
	"subjects": [{"artifact": "runs"}],
} if {
	some line in input.tree.records.runs
	contains(line, "failure")
}
"#;

const RECORDS: &str = r#"version = 1
scope = ["**"]

[[verdict]]
id = "record read other"
gloss = "the record this rule reads says so"
class = "A test fixture's class."

[[verdict.route]]
id = "record read first"
kind = "document"
target = "the record this rule reads"

[[rule]]
id = "record read other"
kind = "policy"
scope = "tree"
module = "policy/reads-the-runs.rego"
severity = "deny"

[[record]]
record = "runs"
writer = "batten record query runs --input workflow=land.yml"

[[forge.query]]
id = "runs"
endpoint = "repos/{owner}/{repo}/actions/workflows/{workflow}/runs"
rows = "workflow_runs"
per_page = 2
max_pages = 3
select = ["id", "conclusion"]
"#;

#[test]
fn a_record_flip_reaches_the_tree_half_that_reads_it() {
    // A RECORD FLIPPING TO A DENY VALUE WITH NO TRACKED CHANGE. Since a1397f5ab
    // (CLOUD-2329) the tree half reads the recorder stores and folds them into
    // its key, so a record row is the tree half's and its receipt is a hit only
    // on identical records. The flip must therefore move the tree half's own
    // verdict: before that commit the tree half never saw the record and passed.
    let dir = repo(
        "records",
        RECORDS,
        &[("policy/reads-the-runs.rego", READS_THE_RUNS)],
    );
    let clean = batten(&dir, &["enforce", "--half", "tree"]);
    assert_eq!(
        code(&clean),
        Some(0),
        "no record, no finding: {}",
        stdout(&clean)
    );

    let branch = git_in(&dir, &["rev-parse", "--abbrev-ref", "HEAD"]);
    let record = batten::recorder::record_path(&dir.join(".git"), "runs", &branch, None);
    std::fs::create_dir_all(record.parent().expect("a record has a directory")).unwrap();
    std::fs::write(&record, "row\t{\"conclusion\":\"failure\",\"id\":1}\n").unwrap();

    let tree = batten(&dir, &["enforce", "--half", "tree"]);
    assert_eq!(code(&tree), Some(2), "the tree half: {}", stdout(&tree));
    assert!(
        stdout(&tree).contains("record read other"),
        "{}",
        stdout(&tree)
    );
}

/// A warning row (a finding on stdout, exit 0) under the tree half's step row,
/// keyed on the index and one repository config value.
const STEPPED: &str = "version = 1\n\
                       scope = [\"**\"]\n\
                       \n[[rule]]\n\
                       id = \"warn-me\"\n\
                       kind = \"forbid\"\n\
                       glob = \"**/*.txt\"\n\
                       pattern = \"WARNME\"\n\
                       severity = \"warn\"\n\
                       scope = \"tree\"\n\
                       \n[[step]]\n\
                       id = \"enforce-tree\"\n\
                       inputs = [\".\"]\n\
                       tools = [[\"git\", \"config\", \"--get\", \"batten.knob\"], [\"batten\", \"step\", \"config\"]]\n";

/// `step run enforce-tree -- batten enforce --half tree`, and whether the tree
/// half's work ran — its warning on stdout is the sentinel.
fn stepped(dir: &Path) -> bool {
    let out = batten(
        dir,
        &[
            "step",
            "run",
            "enforce-tree",
            "--",
            env!("CARGO_BIN_EXE_batten"),
            "enforce",
            "--half",
            "tree",
        ],
    );
    assert_eq!(code(&out), Some(0), "{}{}", stdout(&out), stderr(&out));
    stdout(&out).contains("warn-me")
}

#[test]
fn a_hit_skips_the_tree_half_and_each_keyed_input_is_a_miss() {
    let dir = repo("stepped", STEPPED, &[("a.txt", "WARNME\n")]);
    git_in(&dir, &["config", "batten.knob", "1"]);

    assert!(stepped(&dir), "the first run is a miss and does the work");
    assert!(!stepped(&dir), "an unchanged tree is a hit and skips it");

    // A CHANGED TOOL ANSWER.
    git_in(&dir, &["config", "batten.knob", "2"]);
    assert!(stepped(&dir), "a moved tool answer is a miss");
    assert!(!stepped(&dir), "and is receipted again");

    // A STAGED CHANGE.
    write(&dir, "b.txt", "fine\n");
    git_in(&dir, &["add", "b.txt"]);
    assert!(stepped(&dir), "a staged change is a miss");
    assert!(!stepped(&dir));

    // AN UNTRACKED FILE: no key at all, so never a hit.
    write(&dir, "c.txt", "untracked\n");
    assert!(stepped(&dir), "an untracked file is a miss");
    assert!(stepped(&dir), "and stays one while it is there");
}

#[test]
fn the_tree_half_refuses_a_global_override() {
    let dir = repo("override", FORBID, &[("a.txt", "fine\n")]);
    let refused = batten(&dir, &["--fail-on-warning", "enforce", "--half", "tree"]);
    assert_eq!(code(&refused), Some(1), "{}", stderr(&refused));
    assert!(
        stderr(&refused).contains("--half tree"),
        "{}",
        stderr(&refused)
    );

    let live = batten(&dir, &["--fail-on-warning", "enforce", "--half", "live"]);
    assert_eq!(
        code(&live),
        Some(0),
        "the live half takes it: {}",
        stderr(&live)
    );
}

/// A tree row over `.rs` files, with the landing ref a baseline is minted at,
/// under the tree half's step row keyed on the engine's own inputs digest.
fn baselined() -> String {
    format!(
        "version = 1\n\
         must_land_on = \"refs/remotes/origin/main\"\n\
         \n[[rule]]\n\
         id = \"no-todo\"\n\
         kind = \"forbid\"\n\
         glob = \"**/*.rs\"\n\
         pattern = \"TODO\"\n\
         severity = \"deny\"\n\
         \n[[step]]\n\
         id = \"enforce-tree\"\n\
         inputs = [\".\"]\n\
         tools = [[{exe:?}, \"enforce\", \"--half\", \"tree\", \"--inputs-digest\"], [\"batten\", \"step\", \"config\"]]\n",
        exe = env!("CARGO_BIN_EXE_batten")
    )
}

/// `step run enforce-tree -- batten enforce --half tree` under `home`'s state:
/// whether it was a hit, and the code it exited with.
fn stepped_in(dir: &Path, home: &Path) -> (bool, Option<i32>) {
    let out = common::batten()
        .state_home(home)
        .args([
            "step",
            "run",
            "enforce-tree",
            "--",
            env!("CARGO_BIN_EXE_batten"),
            "enforce",
            "--half",
            "tree",
        ])
        .current_dir(dir)
        .env("GIT_CEILING_DIRECTORIES", common::target_tmp())
        .env_remove("CI")
        .env_remove("BATTEN_STEP_RECEIPT_BYPASS")
        .env_remove("BATTEN_FAIL_ON_WARNING")
        .streamed_output()
        .expect("run batten");
    let said = format!("{}{}", stdout(&out), stderr(&out));
    (
        said.lines().any(|line| line.starts_with("hit ")),
        code(&out),
    )
}

/// Every file under `dir`, recursively.
fn walk(dir: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    for entry in std::fs::read_dir(dir).into_iter().flatten().flatten() {
        let path = entry.path();
        if path.is_dir() {
            found.extend(walk(&path));
        } else {
            found.push(path);
        }
    }
    found
}

#[test]
fn a_baseline_added_or_removed_with_no_tracked_change_is_a_miss() {
    // THE TRANSITION A SKIPPED BASELINE LEFT UNSOUND: the store moves, the index
    // does not. The tree half applies its own rows' entries, and the digest tool
    // puts the baseline's bytes in the key, so each move is a miss.
    let root = scratch("enforce-half-baseline");
    let dir = Fixture::at(root.join("repo"))
        .config(&baselined())
        .files(&[("lib.rs", "fine\nTODO fix this\n")])
        .git()
        .base_commit()
        .build();
    let home = Fixture::at(root.join("home")).build();
    let run = |args: &[&str]| {
        common::batten()
            .state_home(&home)
            .args(args)
            .current_dir(&dir)
            .env("GIT_CEILING_DIRECTORIES", common::target_tmp())
            .env_remove("BATTEN_FAIL_ON_WARNING")
            .streamed_output()
            .expect("run batten")
    };
    assert_eq!(code(&run(&["state", "adopt"])), Some(0));
    git_in(&dir, &["update-ref", "refs/remotes/origin/main", "HEAD"]);

    assert_eq!(
        stepped_in(&dir, &home),
        (false, Some(2)),
        "un-baselined, the row refuses"
    );

    let minted = run(&["baseline"]);
    assert_eq!(code(&minted), Some(0), "{}", stderr(&minted));
    assert_eq!(
        stepped_in(&dir, &home),
        (false, Some(0)),
        "an added baseline is a miss, and the tree half applies it"
    );
    assert_eq!(stepped_in(&dir, &home), (true, Some(0)), "then a hit");

    let baseline = walk(&home.join("data"))
        .into_iter()
        .find(|path| path.file_name().is_some_and(|name| name == "baseline.json"))
        .expect("the minted baseline is on disk");
    std::fs::remove_file(&baseline).unwrap();
    assert_eq!(
        stepped_in(&dir, &home),
        (false, Some(2)),
        "a removed baseline is a miss, and the finding is back"
    );
}

#[test]
fn a_baseline_entry_of_the_other_half_is_neither_applied_nor_stale() {
    // A BASELINE OVER BOTH HALVES. The tree half must not report the live row's
    // entry stale (it judged nothing about it), and the live half must not
    // report the tree row's.
    let root = scratch("enforce-half-baseline-split");
    let config = RECORDS.replacen(
        "scope = [\"**\"]\n",
        "scope = [\"**\"]\nmust_land_on = \"refs/remotes/origin/main\"\n",
        1,
    ) + "\n[[rule]]\nid = \"no-todo\"\nkind = \"forbid\"\nglob = \"**/*.rs\"\n\
         pattern = \"TODO\"\nseverity = \"deny\"\n";
    let dir = Fixture::at(root.join("repo"))
        .config(&config)
        .files(&[
            ("lib.rs", "TODO fix this\n"),
            ("policy/reads-the-runs.rego", READS_THE_RUNS),
        ])
        .git()
        .base_commit()
        .build();
    let home = Fixture::at(root.join("home")).build();
    let run = |args: &[&str]| {
        common::batten()
            .state_home(&home)
            .args(args)
            .current_dir(&dir)
            .env("GIT_CEILING_DIRECTORIES", common::target_tmp())
            .env_remove("BATTEN_FAIL_ON_WARNING")
            .streamed_output()
            .expect("run batten")
    };
    assert_eq!(code(&run(&["state", "adopt"])), Some(0));
    git_in(&dir, &["update-ref", "refs/remotes/origin/main", "HEAD"]);
    let branch = git_in(&dir, &["rev-parse", "--abbrev-ref", "HEAD"]);
    let record = batten::recorder::record_path(&dir.join(".git"), "runs", &branch, None);
    std::fs::create_dir_all(record.parent().expect("a record has a directory")).unwrap();
    std::fs::write(&record, "row\t{\"conclusion\":\"failure\",\"id\":1}\n").unwrap();
    let minted = run(&["baseline"]);
    assert_eq!(code(&minted), Some(0), "{}", stderr(&minted));
    let whole = run(&["enforce"]);
    assert_eq!(
        code(&whole),
        Some(0),
        "the premise: both are held: {}",
        stdout(&whole)
    );

    for half in ["tree", "live"] {
        let out = run(&["enforce", "--half", half]);
        assert_eq!(
            code(&out),
            Some(0),
            "--half {half}: {}{}",
            stdout(&out),
            stderr(&out)
        );
        assert!(
            !stdout(&out).contains("stale") && !stderr(&out).contains("stale"),
            "--half {half} reports nothing stale: {}{}",
            stdout(&out),
            stderr(&out)
        );
    }
}

/// One tree policy row that always refuses with an admissible class, under the
/// tree half's step row keyed on the inputs digest — `admission.rs`'s fixture.
fn admits() -> String {
    format!(
        r#"version = 1

[[rule]]
id = "always-refuses"
kind = "policy"
scope = "tree"
bundle = "policy-admits/"
severity = "deny"

[[verdict]]
id = "always probe probe"
gloss = "the fixture's row refuses unconditionally"
class = "A fixture predicate that always fires, so a case has a finding to admit."

[[verdict.route]]
id = "admits fix probe"
kind = "command"
target = "change the thing the fixture refuses"

[[verdict.route]]
id = "override admits probe"
kind = "override"
precondition = "the refusal is the fixture's point and there is nothing to fix"

[[step]]
id = "enforce-tree"
inputs = ["."]
tools = [[{exe:?}, "enforce", "--half", "tree", "--inputs-digest"], ["batten", "step", "config"]]
"#,
        exe = env!("CARGO_BIN_EXE_batten")
    )
}

const ALWAYS: &str = r#"
package batten.admits

import rego.v1

rules contains "always-refuses"

violation contains {
	"rule": "always-refuses",
	"verdict": "always probe probe",
	"subjects": [{"path": "a.rs"}],
}
"#;

#[test]
fn an_admission_covers_a_tree_half_finding_and_its_removal_is_a_miss() {
    let dir = scratch("enforce-half-admits");
    write(&dir, "batten.toml", &admits());
    write(&dir, "policy-admits/gate.rego", ALWAYS);
    write(&dir, "a.rs", "fn main() {}\n");
    init_repo(&dir);
    git_in(&dir, &["add", "-A"]);
    git_in(&dir, &["commit", "-qm", "seed"]);
    let store = batten::admission::store_dir(&dir).expect("the store resolves");
    let _ = std::fs::remove_dir_all(&store);
    let step = |dir: &Path| {
        let out = batten(
            dir,
            &[
                "step",
                "run",
                "enforce-tree",
                "--",
                env!("CARGO_BIN_EXE_batten"),
                "enforce",
                "--half",
                "tree",
            ],
        );
        let said = format!("{}{}", stdout(&out), stderr(&out));
        (
            said.lines().any(|line| line.starts_with("hit ")),
            code(&out),
        )
    };

    assert_eq!(
        step(&dir),
        (false, Some(2)),
        "the tree row refuses before any admission"
    );

    let issued = common::run_with_stdin(
        &dir,
        &[
            "override",
            "request",
            "--rule",
            "always-refuses",
            "--verdict",
            "always probe probe",
            "--subject",
            "a.rs",
        ],
        "precondition=the refusal is the fixture's point\nlost=nothing to show\n\
         rejected-route=admits fix probe has nothing to change\n",
    );
    let address = stdout(&issued).trim().to_owned();
    assert_eq!(
        address.len(),
        64,
        "an address was issued: {}",
        stderr(&issued)
    );
    let spent = common::run(
        &dir,
        &[
            "override",
            "spend",
            "--admission",
            &address,
            "--rule",
            "always-refuses",
            "--verdict",
            "always probe probe",
            "--subject",
            "a.rs",
        ],
    );
    assert_eq!(code(&spent), Some(0), "{}", stderr(&spent));

    assert_eq!(
        step(&dir),
        (false, Some(0)),
        "the spent admission is a miss, and the tree half admits the finding"
    );
    assert_eq!(step(&dir), (true, Some(0)), "then a hit");

    std::fs::remove_dir_all(&store).unwrap();
    assert_eq!(
        step(&dir),
        (false, Some(2)),
        "the admission removed with no tracked change is a miss, and the finding is back"
    );
}

#[test]
fn the_inputs_digest_takes_the_tree_half() {
    let dir = repo("digest", FORBID, &[("a.txt", "fine\n")]);
    for args in [
        &["enforce", "--inputs-digest"][..],
        &["enforce", "--half", "live", "--inputs-digest"][..],
    ] {
        let out = batten(&dir, args);
        assert_eq!(code(&out), Some(1), "{args:?}: {}", stderr(&out));
        assert!(out.stdout.is_empty(), "{args:?} printed no digest");
    }
    let first = batten(&dir, &["enforce", "--half", "tree", "--inputs-digest"]);
    assert_eq!(code(&first), Some(0), "{}", stderr(&first));
    let digest = stdout(&first);
    assert_eq!(digest.trim().len(), 64, "one blake3 line: {digest:?}");
    assert_eq!(digest.lines().count(), 1);
    let again = batten(&dir, &["enforce", "--half", "tree", "--inputs-digest"]);
    assert_eq!(stdout(&again), digest, "stable over unchanged state");
    write(&dir, "batten.local.toml", "fail_on_warning = true\n");
    let moved = batten(&dir, &["enforce", "--half", "tree", "--inputs-digest"]);
    assert_ne!(stdout(&moved), digest, "a local override moves the digest");
}

#[test]
fn the_defect_ledger_answers_in_the_live_half_only() {
    let row = |id: &str, class: &str| {
        format!(
            "{{\"id\":\"{id}\",\"class\":\"{class}\",\"observed\":\"2026-08-11\",\"evidence\":\"a.rs:1\"}}"
        )
    };
    let config =
        "version = 1\n\n[defects]\npath = \"defects.jsonl\"\nclasses = [\"false-green\"]\n";
    let ledger = format!(
        "{}\n{}\n",
        row("d-1", "false-green"),
        row("d-2", "invented-locally")
    );
    let dir = repo("ledger", config, &[("defects.jsonl", &ledger)]);

    let tree = batten(&dir, &["enforce", "--half", "tree"]);
    assert_eq!(code(&tree), Some(0), "{}", stdout(&tree));
    assert!(!stdout(&tree).contains("defect-"), "{}", stdout(&tree));

    let live = batten(&dir, &["enforce", "--half", "live"]);
    assert_eq!(code(&live), Some(2), "{}", stderr(&live));
    assert!(
        stdout(&live).contains("defect-unknown-class"),
        "{}",
        stdout(&live)
    );
}

#[test]
fn a_narrowed_half_holds_only_its_selected_rows_entries() {
    // A HALF NARROWED BY `--rule` JUDGES THAT ROW ALONE, so another tree row's
    // baseline entry is neither applied nor reported held (step 13a).
    let root = scratch("enforce-half-baseline-narrowed");
    let config = FORBID.replacen(
        "scope = [\"**\"]\n",
        "scope = [\"**\"]\nmust_land_on = \"refs/remotes/origin/main\"\n",
        1,
    ) + "\n[[rule]]\nid = \"no-fixme\"\nkind = \"forbid\"\nglob = \"**/*.txt\"\n\
         pattern = \"FIXME\"\nseverity = \"deny\"\nscope = \"tree\"\n";
    let dir = Fixture::at(root.join("repo"))
        .config(&config)
        .files(&[("a.txt", "BANNED\n"), ("b.txt", "FIXME\n")])
        .git()
        .base_commit()
        .build();
    let home = Fixture::at(root.join("home")).build();
    let run = |args: &[&str]| {
        common::batten()
            .state_home(&home)
            .args(args)
            .current_dir(&dir)
            .env("GIT_CEILING_DIRECTORIES", common::target_tmp())
            .env_remove("BATTEN_FAIL_ON_WARNING")
            .streamed_output()
            .expect("run batten")
    };
    assert_eq!(code(&run(&["state", "adopt"])), Some(0));
    git_in(&dir, &["update-ref", "refs/remotes/origin/main", "HEAD"]);
    let minted = run(&["baseline"]);
    assert_eq!(code(&minted), Some(0), "{}", stderr(&minted));
    let narrowed = run(&["enforce", "--half", "tree", "--rule", "no-banned"]);
    assert_eq!(
        code(&narrowed),
        Some(0),
        "the selected row is held, and no other row's entry is judged: {}",
        stderr(&narrowed)
    );
    assert!(
        !stderr(&narrowed).contains("no-fixme"),
        "the unselected row's entry is not this run's: {}",
        stderr(&narrowed)
    );
}
