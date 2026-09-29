//! `gate table wrong` over the compiled binary (CLOUD-843, p6-board review
//! round 3).
//!
//! # Why this tier exists and the module's own `test_` rules do not suffice
//!
//! `policy/sweep-exit-table.rego` decides over two keys the engine must build
//! from a `sources`/`line_sources` pair: `input.tree.documents["batten.toml"]
//! .board.sweep` and `input.tree.documents["mise.toml"].tasks`, with the pointer
//! from `input.tree.lines["batten.toml"]`. Every module case fabricates those
//! with `with input as`; a glob that acquired one file and not the other would
//! leave the predicate undefined and the gate byte-identical to a clean tree.
//! This tier registers the REAL module against a scratch repository that is not
//! this one.
//!
//! # No retirement ledger, because nothing is retired
//!
//! The module is a new clause over a population nothing judged: the obligation
//! it holds was a comment above the `duplicate-close-check` row. There are no
//! `// carried:` arms to account for.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use common::{git_in, init_repo, run, scratch, write};

/// The registrations every case carries, in the shape `batten.toml` declares
/// them — the same `sources`/`line_sources` pair, because the pair is what this
/// tier exists to prove the engine acquires.
const REGISTRY: &str = r#"version = 1
scope = ["**"]

[[pattern]]
id = "engine-invocation"
regex = '^(batten|\{\{ *vars\.batten *\}\})( |$)'

[[verdict]]
id = "gate table wrong"
gloss = "a board sweep row reads its gate's exits on the other table"
class = "A refusal and a could-not-look trade places."

[[verdict.route]]
id = "module read first"
kind = "document"
target = "policy/sweep-exit-table.rego"

[[rule]]
id = "gate table wrong"
kind = "policy"
scope = "tree"
sources = ["batten.toml", "mise.toml"]
line_sources = ["batten.toml"]
module = "policy/sweep-exit-table.rego"
severity = "deny"
"#;

/// A shell body mapping its own exits — the corpus table.
const SHELL_TASK: &str = "[tasks.gate]\nrun = '''\nset -uo pipefail\nrc=0\nbatten check --rule 'a b c' || rc=$?\ncase \"$rc\" in 2) exit 1 ;; 0) exit 0 ;; *) exit 2 ;; esac\n'''\n";

/// An engine chain — every line invokes the engine, so its exits are the engine's.
const ENGINE_TASK: &str = "[tasks.gate]\nrun = [\n  \"{{vars.batten}} record derive duplicate-close\",\n  \"{{vars.batten}} check --rule 'issue state other'\",\n]\n";

/// A repository registering the real module, one `[[board.sweep]]` row, and the
/// manifest the row's task lives in.
fn repo(name: &str, row: &str, manifest: &str) -> std::path::PathBuf {
    let dir = scratch(&format!("sweep-exit-table-{name}"));
    let module = std::fs::read_to_string("../../policy/sweep-exit-table.rego")
        .expect("the module this tier exists for");
    write(&dir, "policy/sweep-exit-table.rego", &module);
    write(&dir, "mise.toml", manifest);
    write(
        &dir,
        "batten.toml",
        &format!("{REGISTRY}\n[[board.sweep]]\nname = \"gate\"\n{row}"),
    );
    init_repo(&dir);
    git_in(&dir, &["add", "-A"]);
    git_in(&dir, &["commit", "-qm", "register the module"]);
    dir
}

/// Both streams: which one a finding lands on is the output contract's
/// business; what is asserted is that the pointer reaches the reader at all.
fn said(decided: &std::process::Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&decided.stdout),
        String::from_utf8_lossy(&decided.stderr)
    )
}

fn assert_refused(dir: &std::path::Path, why: &str) {
    let decided = run(dir, &["check"]);
    assert_eq!(decided.status.code(), Some(2), "{why}\n{}", said(&decided));
    let reported = said(&decided);
    assert!(
        reported.contains("gate table wrong"),
        "the refusal names its class\n{reported}"
    );
}

fn assert_clean(dir: &std::path::Path, why: &str) {
    let decided = run(dir, &["check"]);
    assert_eq!(decided.status.code(), Some(0), "{why}\n{}", said(&decided));
}

#[test]
fn an_engine_task_read_through_the_corpus_table_is_refused() {
    // THE P7 MERGE AS THE REVIEW NAMED IT: `duplicate-close-check` retires its
    // shell body into an engine chain and the row keeps the corpus `[1]`, so a
    // could-not-look reads as a refused board. `config lint` cannot see it.
    let dir = repo(
        "engine-corpus",
        "run = [\"mise\", \"run\", \"-q\", \"gate\"]\nrefuses = [1]\n",
        ENGINE_TASK,
    );
    assert_refused(&dir, "an engine chain read through [1] is laundering");

    let reported = said(&run(&dir, &["check"]));
    assert!(
        reported.contains("batten.toml:"),
        "the finding places the row on its own line\n{reported}"
    );
}

#[test]
fn an_engine_task_on_the_default_is_clean() {
    // The same move with the key deleted in the same change is exactly right.
    let dir = repo(
        "engine-default",
        "run = [\"mise\", \"run\", \"-q\", \"gate\"]\n",
        ENGINE_TASK,
    );
    assert_clean(&dir, "an engine chain on the engine default is correct");
}

#[test]
fn an_engine_task_naming_both_exits_is_refused() {
    // 2 is classified, so only the named 1 is the laundering — the arm the two
    // `not` clauses cannot reach.
    let dir = repo(
        "engine-both",
        "run = [\"mise\", \"run\", \"-q\", \"gate\"]\nrefuses = [1, 2]\n",
        ENGINE_TASK,
    );
    assert_refused(&dir, "naming 1 over an engine chain is laundering");
}

#[test]
fn an_engine_verb_whose_refusal_is_unclassified_is_refused() {
    let dir = repo(
        "engine-unclassified",
        "run = [\"batten\", \"board\", \"check\"]\nrefuses = [3]\n",
        "[tools]\n",
    );
    assert_refused(
        &dir,
        "an engine verb whose 2 is unclassified loses refusals",
    );
}

#[test]
fn a_shell_task_read_on_the_engine_default_is_refused() {
    // The reverse: the key deleted while the task is still a shell body.
    let dir = repo(
        "shell-default",
        "run = [\"mise\", \"run\", \"-q\", \"gate\"]\n",
        SHELL_TASK,
    );
    assert_refused(&dir, "a shell body on the engine default is laundering");
}

#[test]
fn a_shell_task_read_through_the_corpus_table_is_clean() {
    // This repository's own row today.
    let dir = repo(
        "shell-corpus",
        "run = [\"mise\", \"run\", \"-q\", \"gate\"]\nrefuses = [1]\n",
        SHELL_TASK,
    );
    assert_clean(&dir, "a shell body read through [1] is correct");
}

#[test]
fn a_shell_task_naming_both_exits_is_refused() {
    let dir = repo(
        "shell-both",
        "run = [\"mise\", \"run\", \"-q\", \"gate\"]\nrefuses = [1, 2]\n",
        SHELL_TASK,
    );
    assert_refused(&dir, "naming 2 over a shell body is laundering");
}

#[test]
fn a_shell_task_whose_refusal_is_unclassified_is_refused() {
    let dir = repo(
        "shell-unclassified",
        "run = [\"mise\", \"run\", \"-q\", \"gate\"]\nrefuses = [3]\n",
        SHELL_TASK,
    );
    assert_refused(&dir, "a shell body whose 1 is unclassified loses refusals");
}

#[test]
fn a_task_mixing_shell_and_engine_lines_is_the_corpus_table() {
    // ONE shell line makes the body the corpus's: its exits are whatever that
    // shell maps them to.
    let dir = repo(
        "mixed",
        "run = [\"mise\", \"run\", \"-q\", \"gate\"]\n",
        "[tasks.gate]\nrun = [\n  \"{{vars.batten}} record derive x\",\n  \"test -s out || exit 2\",\n]\n",
    );
    assert_refused(
        &dir,
        "a mixed body read on the engine default is laundering",
    );
}

#[test]
fn a_row_over_a_task_the_manifest_does_not_define_abstains() {
    // A file task's table is not decidable from a committed document.
    let dir = repo(
        "file-task",
        "run = [\"mise\", \"run\", \"-q\", \"file-task\"]\nrefuses = [1]\n",
        ENGINE_TASK,
    );
    assert_clean(&dir, "a task the manifest does not define abstains");
}
