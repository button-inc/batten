//! A report task stays off the landing path, over the compiled binary
//! (CLOUD-582, ported from `mise-tasks/report-only-check.sh` under CLOUD-843).
//!
//! **What is decidable only here.** `policy/report-only.rego` carries load-time
//! cases pinning the predicate, and each fabricates `input.tree.documents` — so
//! it is green whether or not the engine PARSES `mise.toml` and the workflows at
//! all. The whole port turns on reading parsed structure where the predecessor
//! carved a span out of text, and a fabricated document asserts that structure
//! into existence.
//
// carried: mise-tasks/report-only-check.sh policy/report-only.rego crates/batten/tests/it/report_only.rs
// carried: tests/report-only-check.bats policy/report-only.rego crates/batten/tests/it/report_only.rs
//
// carried: "the repo's real manifest and workflows are clean today" policy/report-only.rego
// carried: "a report named in [tasks.verify] is refused" policy/report-only.rego
// carried: "a report run by a pull_request workflow is refused" policy/report-only.rego
// carried: "a report run by a SCHEDULED workflow is the point, not a violation" policy/report-only.rego
// carried: "a longer identifier merely containing the name does not fire" policy/report-only.rego
// carried: "both routes are reported together, not one at a time" policy/report-only.rego
// carried: "a manifest with no [tasks.verify] cannot be judged, and says so" policy/report-only.rego
//
// changed: "the report's output path in verify's body does fire" policy/report-only.rego the shell matched the bare NAME anywhere in verify's span, so `COVERAGE_OUT_DIR` in the body was a hit it had to word-bound away while a genuine mention still fired. The successor asks the invocation question instead — `mise run <task>` — because running it is what makes a report a gate, and an output path that merely names it does not. Strictly narrower and strictly more accurate; `a_longer_identifier_merely_containing_the_name_does_not_fire` is the half that survives
// changed: "a missing manifest is exit 2, never a pass" policy/report-only.rego the shell took the manifest as `$REPORT_ONLY_MANIFEST` and could be pointed at a path that does not exist. The successor's subject is a declared `sources` entry: a glob matching nothing means the rule is not evaluated, and `input.tree.missing` is never populated on the tree surface (CLOUD-1049). The neighbouring could-not-look — a manifest that parses with no `[tasks.verify]` — IS reachable and is carried above

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::{Path, PathBuf};
use std::process::Output;

use common::{Fixture, git_in, run, stdout};

fn report_repo(name: &str, manifest: &str, workflow: Option<&str>) -> PathBuf {
    let mut fixture = Fixture::new(name)
        .config(
            "version = 1\n\n\
             [[verdict]]\n\
             id = \"task judge silent\"\n\
             gloss = \"a task runs somewhere its verdict is not wanted\"\n\
             class = \"A report emits a number for a human; binding it to landing makes a gate of a tool's opinion.\"\n\n\
             [[verdict.route]]\n\
             id = \"prose read first\"\n\
             kind = \"document\"\n\
             target = \"AGENTS.md\"\n\n\
             [[verdict]]\n\
             id = \"task guard missing\"\n\
             gloss = \"the task a rule judges against is not declared\"\n\
             class = \"With no verify task there is nothing to judge a report against, and clean would be a false green.\"\n\n\
             [[verdict.route]]\n\
             id = \"prose read first\"\n\
             kind = \"document\"\n\
             target = \"AGENTS.md\"\n\n\
             [[rule]]\n\
             id = \"report-only\"\n\
             kind = \"policy\"\n\
             scope = \"tree\"\n\
             sources = [\"mise.toml\", \".github/workflows/*.yml\"]\n\
             module = \"policy/report-only.rego\"\n\
             severity = \"deny\"\n",
        )
        .file("AGENTS.md", "the consumer's own authority\n")
        .file("mise.toml", manifest);
    if let Some(body) = workflow {
        fixture = fixture.file(".github/workflows/report.yml", body);
    }
    let dir = fixture.git().build();
    common::write(
        &dir,
        "policy/report-only.rego",
        &std::fs::read_to_string(common::at_root("policy/report-only.rego")).unwrap(),
    );
    git_in(&dir, &["add", "-A"]);
    git_in(&dir, &["commit", "-q", "-m", "base"]);
    dir
}

fn check(dir: &Path) -> Output {
    run(dir, &["check", "--rule", "report-only"])
}

const CLEAN: &str = "[tasks.verify]\ndepends = [\"ci\"]\nrun = \"echo ok\"\n";

#[test]
fn a_clean_manifest_and_workflow_pass() {
    let dir = report_repo(
        "report-clean",
        CLEAN,
        Some("on:\n  pull_request:\njobs:\n  j:\n    steps:\n      - run: mise run ci\n"),
    );
    let output = check(&dir);
    assert_eq!(output.status.code(), Some(0), "{}", stdout(&output));
}

#[test]
fn a_report_in_verifys_depends_is_refused_over_the_binary() {
    let dir = report_repo(
        "report-in-depends",
        "[tasks.verify]\ndepends = [\"ci\", \"coverage\"]\nrun = \"echo ok\"\n",
        None,
    );
    let output = check(&dir);
    assert_eq!(output.status.code(), Some(2), "{}", stdout(&output));
    assert!(
        stdout(&output).contains("mise.toml"),
        "the finding points at the manifest: {}",
        stdout(&output)
    );
}

#[test]
fn a_report_run_by_a_pull_request_workflow_is_refused() {
    let dir = report_repo(
        "report-on-pr",
        CLEAN,
        Some("on:\n  pull_request:\njobs:\n  j:\n    steps:\n      - run: mise run scorecard\n"),
    );
    let output = check(&dir);
    assert_eq!(output.status.code(), Some(2), "{}", stdout(&output));
    assert!(
        stdout(&output).contains(".github/workflows/report.yml"),
        "and at the workflow, not the manifest: {}",
        stdout(&output)
    );
}

#[test]
fn a_report_run_by_a_scheduled_workflow_is_the_point_not_a_violation() {
    // DISCRIMINATING. A gate that judged every trigger would refuse the reason
    // the report exists at all.
    let dir = report_repo(
        "report-on-schedule",
        CLEAN,
        Some(
            "on:\n  schedule:\n    - cron: \"0 0 * * 0\"\njobs:\n  j:\n    steps:\n      - run: mise run scorecard\n",
        ),
    );
    let output = check(&dir);
    assert_eq!(
        output.status.code(),
        Some(0),
        "a scheduled report was refused: {}",
        stdout(&output)
    );
}

#[test]
fn a_longer_identifier_merely_containing_the_name_does_not_fire() {
    // The boundary the predecessor word-bounded a grep for. A parsed `depends`
    // is a list of names, so this is a different entry rather than a near miss.
    let dir = report_repo(
        "report-longer-identifier",
        "[tasks.verify]\ndepends = [\"coverage-report-check\"]\nrun = \"echo $COVERAGE_OUT_DIR\"\n",
        None,
    );
    let output = check(&dir);
    assert_eq!(output.status.code(), Some(0), "{}", stdout(&output));
}

#[test]
fn both_routes_are_reported_together_not_one_at_a_time() {
    let dir = report_repo(
        "report-both-routes",
        "[tasks.verify]\ndepends = [\"ci\", \"coverage\"]\nrun = \"echo ok\"\n",
        Some("on:\n  pull_request:\njobs:\n  j:\n    steps:\n      - run: mise run scorecard\n"),
    );
    let output = check(&dir);
    assert_eq!(output.status.code(), Some(2));
    let text = stdout(&output);
    assert!(
        text.contains("mise.toml") && text.contains(".github/workflows/report.yml"),
        "a reader fixing one must see the other in the same run: {text:?}"
    );
}

#[test]
fn a_manifest_with_no_verify_task_cannot_be_judged_and_says_so() {
    let dir = report_repo("report-no-verify", "[tasks.ci]\nrun = \"echo ok\"\n", None);
    let output = check(&dir);
    assert_eq!(
        output.status.code(),
        Some(2),
        "no verify task is could-not-look, never a clean board: {}",
        stdout(&output)
    );
}

#[test]
fn the_repos_real_manifest_and_workflows_are_clean_today() {
    let output =
        common::run_at_real_root(&common::at_root(""), &["check", "--rule", "report-only"]);
    assert_eq!(
        output.status.code(),
        Some(0),
        "a report reached the landing path in this tree: {}",
        stdout(&output)
    );
}
