//! `workflow run unknown` over the compiled binary (CLOUD-1833).
//!
//! # Why this tier exists and the module's own `test_` rules do not suffice
//!
//! `policy/task-callable.rego` carries eleven load-time cases and every one of
//! them fabricates its input with `with input as`. That is the shape
//! `rules/policy-modules.md` warns about: such a case asserts over a fact the
//! engine may be unable to produce, so the module stays green while the row
//! decides nothing on any real checkout. Two live instances of exactly that
//! class have already landed in this repository, and both were found by adding
//! this tier rather than by reading.
//!
//! The risk is concrete here rather than theoretical. This module reads three
//! keys the engine must actually build over a `sources`/`line_sources` pair:
//! `input.tree.documents[<workflow>].jobs`, `input.tree.lines[<workflow>]` for
//! the pointer, and `input.tree.tracked` for the file-task arm. A glob that
//! acquired the manifest but not the workflows — or the reverse — would leave
//! the predicate undefined and the gate byte-identical to a clean tree.
//!
//! # No retirement ledger, because nothing is retired
//!
//! `shell retire partial` reads `// carried:` arms in a tier that inherits a
//! dying program's cases. This module has no predecessor: it is a new clause
//! over a population nothing was judging, so there are no arms to account for
//! and inventing some would claim a fidelity this change never owed.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use common::{git_in, init_repo, run, scratch, write};

/// The authority every case registers, verbatim in the shape `batten.toml`
/// carries it — the same `sources`/`line_sources` pair, because the pair is
/// precisely what this tier exists to prove the engine acquires.
const CONFIG: &str = r#"version = 1
scope = ["**"]

[[pattern]]
id = "mise-run-task"
regex = 'mise run [a-z][a-z0-9:_-]*'

[[verdict]]
id = "task run unknown"
gloss = "a workflow step runs a mise task that nothing in this tree defines"
class = "The step dies the moment it runs, on a trigger that reaches no reviewer."

[[verdict.route]]
id = "task list first"
kind = "command"
target = "mise tasks ls --all"

[[verdict]]
id = "workflow read unread"
gloss = "the workflow this rule judges would not parse, so nothing was decided"
class = "A declared source that will not parse is not an absent one."

[[verdict.route]]
id = "module read first"
kind = "document"
target = "policy/task-callable.rego"

[[verdict]]
id = "task resolve missing"
gloss = "the task graph this rule walks could not be resolved"
class = "With no task namespace there is nothing to judge a caller against."

[[verdict.route]]
id = "module read first"
kind = "document"
target = "policy/task-callable.rego"

[[rule]]
id = "workflow run unknown"
kind = "policy"
scope = "tree"
sources = [".github/workflows/*.yml", "mise.toml"]
line_sources = [".github/workflows/*.yml"]
module = "policy/task-callable.rego"
severity = "deny"
"#;

/// A repository registering the real module against the manifest, the file
/// programs and the workflow BODY a case wants judged.
///
/// The REAL module and the REAL row, never a fixture copy: the whole point of
/// this tier is that the module decides over the engine's own projection, and a
/// stand-in would be one more `with input as` wearing a different costume.
fn repo_with(name: &str, tasks: &[&str], programs: &[&str], workflow: &str) -> std::path::PathBuf {
    let dir = scratch(&format!("task-callable-{name}"));
    let module = std::fs::read_to_string("../../policy/task-callable.rego")
        .expect("the module this tier exists for");
    write(&dir, "policy/task-callable.rego", &module);

    let mut manifest = String::from("[tools]\n\n");
    for task in tasks {
        manifest.push_str("[tasks.");
        manifest.push_str(task);
        manifest.push_str("]\nrun = \"true\"\n\n");
    }
    write(&dir, "mise.toml", &manifest);

    for program in programs {
        write(
            &dir,
            &format!("mise-tasks/{program}"),
            "#!/usr/bin/env bash\n",
        );
    }

    write(&dir, ".github/workflows/probe.yml", workflow);
    write(&dir, "batten.toml", CONFIG);

    init_repo(&dir);
    git_in(&dir, &["add", "-A"]);
    git_in(&dir, &["commit", "-qm", "register the module"]);
    dir
}

/// The ordinary case: one scheduled job whose steps are the given `run:` lines.
///
/// `schedule` rather than `pull_request` deliberately — it is the trigger every
/// one of the five dead callers sat behind, and the reason none of them was ever
/// reported.
fn repo(name: &str, tasks: &[&str], programs: &[&str], steps: &[&str]) -> std::path::PathBuf {
    let mut workflow = String::from(
        "on:\n  schedule:\n    - cron: \"0 0 * * 1\"\njobs:\n  probe:\n    runs-on: ubuntu-latest\n    steps:\n",
    );
    for step in steps {
        workflow.push_str("      - run: ");
        workflow.push_str(step);
        workflow.push('\n');
    }
    repo_with(name, tasks, programs, &workflow)
}

/// Both streams, because which one a finding lands on is the output contract's
/// business rather than this tier's: what is asserted is that the pointer
/// reaches the reader at all.
fn said(decided: &std::process::Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&decided.stdout),
        String::from_utf8_lossy(&decided.stderr)
    )
}

#[test]
fn a_workflow_step_naming_an_undefined_task_is_refused() {
    // THE CASE NO `with input as` CAN REACH. Measured on this branch before the
    // module landed: five steps across four workflows called tasks that do not
    // exist, every one of them on a trigger that reaches no pull request, and
    // nothing in the tree could say so.
    let dir = repo(
        "dangling",
        &["present"],
        &[],
        &["mise run absent-task", "mise run present"],
    );

    let decided = run(&dir, &["check"]);
    assert_eq!(
        decided.status.code(),
        Some(2),
        "a caller naming no task decides\n{}",
        String::from_utf8_lossy(&decided.stderr)
    );
    let reported = said(&decided);
    assert!(
        reported.contains(".github/workflows/probe.yml"),
        "the finding points at the workflow to repair\n{reported}"
    );
}

#[test]
fn a_task_backed_by_a_nested_program_resolves() {
    // `mise-tasks/render/cli.sh` is `mise run render:cli`, which
    // `release-artifacts.yml` calls. A reading that took the last path component
    // alone would resolve it as `cli`, leave `render:cli` undefined, and refuse a
    // caller that works — a false positive on the gate's very first run, which is
    // the failure mode that gets an exception written and then rots.
    let dir = repo("nested", &[], &["render/cli.sh"], &["mise run render:cli"]);

    let quiet = run(&dir, &["check"]);
    assert_eq!(
        quiet.status.code(),
        Some(0),
        "a task backed by a nested program resolves\n{}",
        String::from_utf8_lossy(&quiet.stderr)
    );
}

#[test]
fn a_task_backed_by_a_flat_program_resolves_by_stem_and_by_filename() {
    // Both spellings, because mise accepts either and this repository's callers
    // use the bare stem. A reading that covered only one would refuse half the
    // corpus.
    let dir = repo(
        "programs",
        &[],
        &["checksums.sh"],
        &["mise run checksums", "mise run checksums.sh"],
    );

    let quiet = run(&dir, &["check"]);
    assert_eq!(
        quiet.status.code(),
        Some(0),
        "a file task resolves under either spelling\n{}",
        String::from_utf8_lossy(&quiet.stderr)
    );
}

#[test]
fn an_interpolated_task_name_abstains_rather_than_being_refused() {
    // NOT DECIDABLE FROM A COMMITTED DOCUMENT — the name is not in the string. A
    // gate that refused here would make the one spelling a matrix job needs
    // unwritable, and the abstention is structural: the shared pattern requires a
    // lowercase letter where the name begins, so the fragment never matches.
    let dir = repo(
        "interpolated",
        &["present"],
        &[],
        &["mise run ${{ matrix.task }}", "mise run present"],
    );

    let quiet = run(&dir, &["check"]);
    assert_eq!(
        quiet.status.code(),
        Some(0),
        "an interpolated name is not judged\n{}",
        String::from_utf8_lossy(&quiet.stderr)
    );
}

#[test]
fn a_tree_whose_callers_all_resolve_is_silent() {
    // THE ANTI-VACUITY ARM, and on this tier it carries more than usual: a module
    // whose keys the engine never built would pass every negative case above for
    // the wrong reason. Paired with the refusal case at the top, the two together
    // are what distinguish a live gate from an absent one.
    let dir = repo(
        "clean",
        &["present"],
        &["checksums.sh"],
        &["mise run present && mise run checksums"],
    );

    let quiet = run(&dir, &["check"]);
    assert_eq!(
        quiet.status.code(),
        Some(0),
        "a tree whose every caller resolves is clean\n{}",
        String::from_utf8_lossy(&quiet.stderr)
    );
}

#[test]
fn the_finding_carries_the_line_the_caller_is_written_on() {
    // `line_sources` IS A SEPARATE ACQUISITION FROM `sources`, so the pointer is
    // the half most likely to be silently absent: a module whose line index never
    // filled still refuses, just without saying where. Rule 4's shape is a
    // `path:line`, and this is what holds the glob to it.
    let dir = repo(
        "pointer",
        &["present"],
        &[],
        &["mise run present", "mise run absent-task"],
    );

    let decided = run(&dir, &["check"]);
    let reported = said(&decided);
    assert!(
        reported.contains(".github/workflows/probe.yml:9"),
        "the finding places the caller on its own line\n{reported}"
    );
}

#[test]
fn a_comment_naming_an_absent_task_is_not_judged() {
    // THE PROSE ARM, and it is why the decision reads the parsed `run:` scalar
    // rather than the lines. These files carry long comments naming tasks in
    // order to explain that they are ABSENT — `timeout-drift.yml:7` is one — and
    // a gate that fires on its own documentation is a gate people delete.
    let dir = repo_with(
        "prose",
        &["present"],
        &[],
        "on:\n  schedule:\n    - cron: \"0 0 * * 1\"\n# The commit half is `mise run absent-task`, in the hk gate.\njobs:\n  probe:\n    runs-on: ubuntu-latest\n    steps:\n      - run: mise run present\n",
    );

    let quiet = run(&dir, &["check"]);
    assert_eq!(
        quiet.status.code(),
        Some(0),
        "a comment explaining an absent task does not fire the gate\n{}",
        String::from_utf8_lossy(&quiet.stderr)
    );
}
