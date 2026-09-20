//! `bound guard missing` over the compiled binary — CLOUD-668/CLOUD-700, ported
//! off `mise-tasks/mcp-timeout-budget.sh` under CLOUD-1716.
//!
//! **The question a `with input as` case cannot answer.** The module's own
//! `test_` rules pin the predicate and nothing else: they hand it a fabricated
//! `input.tree.documents[".claude/settings.json"]` and ask what it decides. What
//! they cannot establish is whether the ENGINE builds that key at all for a path
//! inside a dotfile directory — a walker that skipped `.claude/` would leave
//! every clause undefined, Rego reads undefined as *does not hold*, and the
//! whole module would pass over a tree it never opened.
//!
//! **And one of them cannot be fabricated at all.** `to_number` FAULTS on a
//! string it cannot read rather than resolving to undefined, so a declaration of
//! `"soon"` takes the evaluation down and the module decides nothing while
//! exiting as though it had. That failure is invisible to a suite that only ever
//! counts findings; `a_non_numeric_budget_refuses_rather_than_faulting` is the
//! case that sees it, because a fault and a clean tree differ here only in the
//! exit code the engine returns.
//!
//! The module under test is `include_str!`d from `policy/` rather than copied,
//! so this suite cannot drift from the predicate that ships.
//
// carried: mise-tasks/mcp-timeout-budget.sh policy/mcp-timeout-budget.rego kind:module crates/batten/tests/it/mcp_timeout_budget.rs runs:mise+run+batten-check
// carried: tests/mcp-timeout-budget.bats policy/mcp-timeout-budget.rego kind:module crates/batten/tests/it/mcp_timeout_budget.rs
//
// carried: "no env.MCP_TIMEOUT is the host default, which is not a measured budget" policy/mcp-timeout-budget.rego
// carried: "a value below the floor is refused, and both numbers are named" policy/mcp-timeout-budget.rego
// carried: "env.MCP_TIMEOUT that is not a whole number of milliseconds is refused" policy/mcp-timeout-budget.rego
// carried: "the floor disagrees with the basis it declares" policy/mcp-timeout-budget.rego
// carried: "a gate that cannot look must not report a budget it did not check" policy/mcp-timeout-budget.rego
// changed: "the effect half reads the MCP client's connection log" policy/mcp-timeout-budget.rego NOT PORTED and stated in the module's METADATA rather than dropped silently — the log lives at `$HOME/.cache/claude-cli-nodejs/<mangled-cwd>/mcp-logs-<server>/<instant>.jsonl` and `[[rule.external]]` takes a fixed `root` plus `path` with no glob, so neither the working-directory-derived directory nor the timestamped filename can be named; CLOUD-730's question stays open and this is not an answer to it
// changed: "exit 0 pass / 1 fail / 2 could not look" policy/mcp-timeout-budget.rego the shell corpus INVERTS the engine's table, so the port lands on `0` Success and `2` Violation; carrying the inversion across is the hazard CLOUD-1716 names explicitly

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::{Path, PathBuf};
use std::process::Output;

use common::{batten, git_in, scratch, stderr, stdout, write};

// `batten check` renders a finding as `<pointer> <rule-id>`, so these cases
// assert the RULE and the exit code. WHICH verdict fired is the unit tier's
// question and is pinned there — asserting a token this channel does not carry
// would be a case that passes for the wrong reason, or fails for one.

/// The shipped predicate, never a copy of it.
const MODULE: &str = include_str!("../../../../policy/mcp-timeout-budget.rego");

/// The floor the shipped module declares. Asserted against the module's own text
/// rather than restated, so this suite cannot go on testing a number the
/// predicate has moved off.
const FLOOR: u64 = 105_494;

/// Registers the shipped module over a fixture tree. The verdict rows are
/// fixture copies of the shipped classes; the registry's own rows are in
/// `batten.toml`.
const CONFIG: &str = r#"version = 1

[[rule]]
id = "bound guard missing"
kind = "policy"
scope = "tree"
documents = [".claude/settings.json"]
module = "mcp-timeout-budget.rego"
severity = "deny"

[[verdict]]
id = "bound state missing"
gloss = "the MCP startup budget is not declared, so it is the host default"
class = "A fixture copy of the shipped class; the registry's own row is in batten.toml."

[[verdict.route]]
id = "task run first"
kind = "document"
target = "mcp-timeout-budget.rego"

[[verdict]]
id = "bound read wrong"
gloss = "the declared MCP startup budget is not a whole number of milliseconds"
class = "A fixture copy of the shipped class; the registry's own row is in batten.toml."

[[verdict.route]]
id = "task run first"
kind = "document"
target = "mcp-timeout-budget.rego"

[[verdict]]
id = "bound guard early"
gloss = "the declared MCP startup budget is below its measured floor"
class = "A fixture copy of the shipped class; the registry's own row is in batten.toml."

[[verdict.route]]
id = "task run first"
kind = "document"
target = "mcp-timeout-budget.rego"

[[verdict]]
id = "bound measure stale"
gloss = "a declared floor disagrees with the measurement it names as its basis"
class = "A fixture copy of the shipped class; the registry's own row is in batten.toml."

[[verdict.route]]
id = "task run first"
kind = "document"
target = "mcp-timeout-budget.rego"

[[verdict]]
id = "source parse dead"
gloss = "a declared engine source would not parse, so it was never judged"
class = "A fixture copy of the shipped class; the registry's own row is in batten.toml."

[[verdict.route]]
id = "task run first"
kind = "document"
target = "mcp-timeout-budget.rego"
"#;

/// A repository fixture, optionally carrying a settings file with an `env`
/// block.
///
/// One per case: these run in parallel and `git init` races on a shared
/// directory, which is a fact about the harness rather than about the predicate.
fn fixture(name: &str, env: Option<&str>) -> PathBuf {
    let repo = scratch(&format!("mcp-timeout-budget-{name}"));
    write(&repo, "batten.toml", CONFIG);
    write(&repo, "mcp-timeout-budget.rego", MODULE);
    if let Some(block) = env {
        write(
            &repo,
            ".claude/settings.json",
            &format!("{{\n  \"env\": {block}\n}}\n"),
        );
    }
    git_in(&repo, &["init", "-q", "-b", "main", "."]);
    // Tracked, because a consumer's settings file is committed and a suite that
    // only ever judged an untracked one would not be asking this repository's
    // question.
    git_in(&repo, &["add", "-A"]);
    repo
}

fn check(repo: &Path) -> Output {
    let mut command = batten();
    command.current_dir(repo).arg("check");
    command.output().expect("run batten check")
}

/// THE POSITIVE, and it is the shape this repository actually ships: the budget
/// is written as a STRING, because `.claude/settings.json`'s `env` block is
/// string-valued and `"120000"` is what a person types.
#[test]
fn the_declared_budget_is_clean() {
    let repo = fixture("clean", Some(r#"{ "MCP_TIMEOUT": "120000" }"#));
    let outcome = check(&repo);
    let (answer, cause) = (stdout(&outcome), stderr(&outcome));
    assert_eq!(
        outcome.status.code(),
        Some(0),
        "the landed budget must pass\n{answer}{cause}"
    );
}

/// THE CLASS THIS ROW EXISTS FOR, and the reachability proof: this refusal is
/// only raisable if the engine parsed a path under `.claude/`. A walker that
/// skipped dotfile directories would leave `declared_raw` undefined, Rego would
/// read that as *does not hold*, and this case would exit 0.
#[test]
fn an_absent_budget_is_refused() {
    let repo = fixture("absent", Some(r#"{ "OTHER": "1" }"#));
    let outcome = check(&repo);
    let (answer, cause) = (stdout(&outcome), stderr(&outcome));
    assert_eq!(
        outcome.status.code(),
        Some(2),
        "a settings file declaring no budget must refuse\n{answer}{cause}"
    );
    assert!(answer.contains("bound guard missing"), "{answer}{cause}");
}

/// THE ANTI-VACUITY MIRROR. A predicate that only ever asked whether the key was
/// PRESENT satisfies the case above and is silent here — and the host default of
/// 30000 is a declared value, so presence-only is precisely the state CLOUD-668
/// was filed about.
#[test]
fn the_host_default_is_refused_although_it_is_declared() {
    let repo = fixture("host-default", Some(r#"{ "MCP_TIMEOUT": "30000" }"#));
    let outcome = check(&repo);
    let (answer, cause) = (stdout(&outcome), stderr(&outcome));
    assert_eq!(
        outcome.status.code(),
        Some(2),
        "a budget below the floor must refuse\n{answer}{cause}"
    );
    assert!(answer.contains("bound guard missing"), "{answer}{cause}");
}

/// A BUDGET AT THE FLOOR EXACTLY PASSES. The boundary is `<`, not `<=`, and a
/// suite that only ever tested numbers far from the floor would not see it move.
#[test]
fn a_budget_at_the_floor_exactly_is_clean() {
    let repo = fixture(
        "at-floor",
        Some(&format!(r#"{{ "MCP_TIMEOUT": "{FLOOR}" }}"#)),
    );
    let outcome = check(&repo);
    let (answer, cause) = (stdout(&outcome), stderr(&outcome));
    assert_eq!(
        outcome.status.code(),
        Some(0),
        "the floor itself is admissible\n{answer}{cause}"
    );
}

/// ONE BELOW THE FLOOR REFUSES, which is the other side of the same boundary.
#[test]
fn one_millisecond_below_the_floor_is_refused() {
    let repo = fixture(
        "below-floor",
        Some(&format!(r#"{{ "MCP_TIMEOUT": "{}" }}"#, FLOOR - 1)),
    );
    let outcome = check(&repo);
    let (answer, cause) = (stdout(&outcome), stderr(&outcome));
    assert_eq!(
        outcome.status.code(),
        Some(2),
        "the boundary is `<`, so one below refuses\n{answer}{cause}"
    );
}

/// THE FAULT CASE, and it is the one no `with input as` case can reach.
///
/// `to_number` faults on a string it cannot read rather than resolving to
/// undefined. A module that lets it see `"soon"` takes the whole evaluation down
/// and decides NOTHING — which is a dead gate arriving through the one door this
/// module exists to keep shut. What distinguishes the two here is the exit code:
/// a refusal is `2` and an engine fault is `3`.
#[test]
fn a_non_numeric_budget_refuses_rather_than_faulting() {
    let repo = fixture("non-numeric", Some(r#"{ "MCP_TIMEOUT": "soon" }"#));
    let outcome = check(&repo);
    let (answer, cause) = (stdout(&outcome), stderr(&outcome));
    assert_eq!(
        outcome.status.code(),
        Some(2),
        "an unreadable budget is a VIOLATION, never an engine fault\n{answer}{cause}"
    );
    assert!(answer.contains("bound guard missing"), "{answer}{cause}");
}

/// A NUMBER RATHER THAN A STRING IS STILL A BUDGET. JSON permits both and a
/// consumer may write either; refusing the numeric form would refuse a tree that
/// is correct in every way a reader can see.
#[test]
fn a_json_number_is_a_budget_too() {
    let repo = fixture("json-number", Some(r#"{ "MCP_TIMEOUT": 120000 }"#));
    let outcome = check(&repo);
    let (answer, cause) = (stdout(&outcome), stderr(&outcome));
    assert_eq!(
        outcome.status.code(),
        Some(0),
        "the numeric form is admissible\n{answer}{cause}"
    );
}

/// A TREE THAT SHIPS NO SETTINGS FILE REPORTS NOTHING. This gate answers about a
/// repository that ships one; a consumer that ships none is not in breach of a
/// bound it never declared, and refusing there would make the module unusable
/// outside this repository — which is the whole point of the core staying
/// repo-agnostic.
#[test]
fn a_tree_without_the_file_reports_nothing() {
    let repo = fixture("no-file", None);
    let outcome = check(&repo);
    let (answer, cause) = (stdout(&outcome), stderr(&outcome));
    assert_eq!(
        outcome.status.code(),
        Some(0),
        "no settings file is not a missing budget\n{answer}{cause}"
    );
}

/// THE FLOOR CARRIES ITS OWN BASIS, asserted over the shipped module's TEXT.
///
/// A floor moved without the measurement that justifies it is what let a
/// superseded "16.65s" go on justifying a number derived from 52747 ms. The
/// module refuses the disagreement at evaluation; this refuses it at the source,
/// so a reader editing one number is sent to the other.
#[test]
fn the_shipped_floor_agrees_with_its_declared_basis() {
    let number = |name: &str| -> u64 {
        MODULE
            .lines()
            .find_map(|line| line.strip_prefix(&format!("{name} := ")))
            .unwrap_or_else(|| panic!("the module declares `{name}`"))
            .trim()
            .parse()
            .expect("a whole number")
    };
    let (worst, multiplier, floor) = (number("worst_ms"), number("multiplier"), number("floor_ms"));
    assert_eq!(
        floor,
        worst * multiplier,
        "the floor is the measurement times the multiplier, and both move together"
    );
    assert_eq!(floor, FLOOR, "this suite tests the floor the module ships");
}

/// The retired program is gone and no caller resolves it by path.
#[test]
fn the_retired_program_is_not_tracked_and_no_caller_names_it() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("repository root");
    for path in [
        "mise-tasks/mcp-timeout-budget.sh",
        "tests/mcp-timeout-budget.bats",
    ] {
        assert!(
            !root.join(path).exists(),
            "{path} is retired and must not be back"
        );
    }
    let tasks = std::fs::read_to_string(root.join("mise.toml")).expect("mise.toml");
    assert!(
        !tasks.contains("mcp-timeout-budget.sh"),
        "no caller resolves the retired program by path"
    );
}
