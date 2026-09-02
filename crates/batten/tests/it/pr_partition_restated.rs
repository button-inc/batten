//! `pr-partition-restated` over the compiled binary.
//!
//! **What the module's own `test_` rules cannot answer.** They substitute their
//! own vocabulary for `data.batten.patterns` and hand the predicate a fabricated
//! `input.tree.lines`, so they establish that a matching line is refused and
//! nothing about whether the ENGINE builds `input.tree.lines` for the declared
//! globs — nor anything at all about the shipped row's WORDING. A module that
//! reads a key the engine never fills is silent on every tree, and a dead gate
//! and a clean tree are byte-identical on the decision surface.
//!
//! They also cannot be written to carry the real strings. `line_sources` globs
//! `policy/*.rego`, so an in-module case containing text the shipped row matches
//! would refuse the module's own file, and the only repairs are an exemption or a
//! weaker row. This suite is not globbed — the rule names `crates/batten/src/*.rs`
//! and never the test tree — which is what makes it the one place the real
//! wording can be exercised. That is a property of the rule's declaration, stated
//! here so it is checked rather than assumed.
//!
//! Five observations, each here because dropping it lets another pass over a
//! predicate that decides nothing:
//!
//! * `the_shipped_row_is_the_one_under_test` — the fixture copies a regex; this
//!   is what stops the copy drifting from the row that ships.
//! * `a_unit_landing_separately_is_refused` — the measured class, and the
//!   reachability proof: this refusal is only raisable if the engine filled
//!   `input.tree.lines` for the glob.
//! * `a_per_unit_rate_is_refused` — the anti-vacuity mirror. Without it the
//!   case above is satisfied by a row matching one sentence.
//! * `the_ordinary_possessive_uses_stay_clean` — the four sentences this tree
//!   already carries that mean the ordinary thing. A row keyed on the
//!   possessive alone refuses all four, which is the version of this gate that
//!   gets switched off in a day.
//! * `a_tree_with_no_such_prose_is_clean` — without it a predicate that refused
//!   unconditionally passes every case above.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::{Path, PathBuf};
use std::process::Output;

use common::{batten, git_in, scratch, stderr, stdout, write};

/// The shipped predicate, never a copy of it.
const MODULE: &str = include_str!("../../../../policy/pr-partition-restated.rego");

/// The shipped configuration, read so the fixture's copy can be held to it.
const SHIPPED: &str = include_str!("../../../../batten.toml");

/// The pattern the shipped registry declares, copied here because a fixture
/// carries its own `batten.toml` and cannot read the repository's.
///
/// `the_shipped_row_is_the_one_under_test` is what makes the copy safe.
const PATTERN: &str = r"(lands? as (its|their) own (PR|pull request)|(PR|pull request) with its own ledger|one (PR|pull request) per unit|an? (PR|pull request) per unit|each .{0,60} own (PR|pull request))";

fn config() -> String {
    format!(
        r#"version = 1

[[pattern]]
id = "pr-partition-prose"
regex = '{PATTERN}'

[[rule]]
id = "pr-partition-restated"
kind = "policy"
scope = "tree"
line_sources = ["prose/*.md"]
module = "pr-partition-restated.rego"
severity = "deny"
reason = "A fixture copy; the shipped reason is in batten.toml."

[[verdict]]
id = "prose state other"
gloss = "prose outside AGENTS.md states a landing arrangement that file already decides"
class = "A fixture copy of the shipped class; the registry's own row is in batten.toml."

[[verdict.route]]
id = "rule read first"
kind = "document"
target = "pr-partition-restated.rego"

[[verdict]]
id = "source parse refused"
gloss = "a declared prose source exists and could not be read, so its lines were never judged"
class = "A fixture copy of the shipped class; the registry's own row is in batten.toml."

[[verdict.route]]
id = "rule read first"
kind = "document"
target = "pr-partition-restated.rego"
"#
    )
}

/// A repository fixture carrying one prose file.
///
/// One per case: these run in parallel and `git init` races on a shared
/// directory, which is a fact about the harness rather than about the predicate.
fn fixture(name: &str, prose: &str) -> PathBuf {
    let repo = scratch(&format!("pr-partition-{name}"));
    write(&repo, "batten.toml", &config());
    write(&repo, "pr-partition-restated.rego", MODULE);
    write(&repo, "prose/notes.md", prose);
    git_in(&repo, &["init", "-q", "-b", "main", "."]);
    // Tracked, because `line_sources` reads the tracked set and a suite over an
    // untracked file would not be asking this repository's question.
    git_in(&repo, &["add", "-A"]);
    repo
}

fn check(repo: &Path) -> Output {
    let mut command = batten();
    command.current_dir(repo).arg("check");
    command.output().expect("run batten check")
}

fn refuses(name: &str, prose: &str) {
    let repo = fixture(name, prose);
    let outcome = check(&repo);
    let (answer, cause) = (stdout(&outcome), stderr(&outcome));
    assert_eq!(
        outcome.status.code(),
        Some(2),
        "{name}: this prose must refuse\n{answer}{cause}"
    );
    assert!(answer.contains("pr-partition-restated"), "{answer}{cause}");
}

#[test]
fn the_shipped_row_is_the_one_under_test() {
    // THE DRIFT CLAUSE. Every case below exercises the constant above; without
    // this one they would keep passing over a registry row somebody had since
    // narrowed, and the suite would report coverage of a pattern that no longer
    // ships.
    assert!(
        SHIPPED.contains(PATTERN),
        "the fixture's pattern is no longer the shipped `pr-partition-prose` row"
    );
}

#[test]
fn a_unit_landing_separately_is_refused() {
    // THE MEASURED CLASS, and the reachability proof: this refusal is only
    // raisable if the engine filled `input.tree.lines` for the declared glob. A
    // walker that skipped it would leave the comprehension empty, Rego would read
    // that as *does not hold*, and this case would exit 0.
    refuses(
        "unit",
        "each of its eight units \"lands as its own PR with its own ledger arms\"\n",
    );
}

#[test]
fn a_per_unit_rate_is_refused() {
    // THE ANTI-VACUITY MIRROR. The rate spelling asserts the same decision and is
    // strictly easier to write; a row matching only the sentence above ships it
    // as coverage that was never walked.
    refuses("rate", "one PR per unit, so each reviews alone\n");
}

#[test]
fn the_ordinary_possessive_uses_stay_clean() {
    // THE FOUR THIS TREE ALREADY CARRIES, verbatim in substance. Each says a
    // change landed through a request of its own and means the ordinary thing.
    // A predicate keyed on the possessive refuses all four, and a gate that
    // fires four times on correct prose is one somebody switches off.
    let repo = fixture(
        "ordinary",
        "release-plz bumps the version in its own PR, so a\n\
         newly-required key makes its own PR unlandable: the base ref has no such\n\
         its own PR, so that is a `derived-check` failure on every release.\n\
         The guard blocked its own PR, and the deny was not reproducible afterwards.\n",
    );
    let outcome = check(&repo);
    let (answer, cause) = (stdout(&outcome), stderr(&outcome));
    assert_eq!(
        outcome.status.code(),
        Some(0),
        "the ordinary possessive uses must pass\n{answer}{cause}"
    );
}

#[test]
fn an_unreadable_source_is_reported_rather_than_passed() {
    // COULD NOT LOOK IS NOT CLEAN, over the compiled binary rather than over a
    // fabricated `missing` map. `.claude/rules/policy-modules.md` is explicit that
    // a `with input as` case cannot establish this: it manufactures the very
    // channel the engine may never populate, so the module's own tier passes
    // whether or not `input.tree.missing` is ever filled for a `line_sources`
    // glob. Invalid UTF-8 is the cheapest declared source that exists and will
    // not read. `NotAcquired` files it under `unreadable` rather than `unparsed`,
    // because nothing was ever handed to a parser -- and a `line_sources` glob has
    // no parser at all, so `unreadable` is the only could-not-look cause this
    // module can reach. The first version of this case asserted `unparsed` and it
    // is what caught the module asking for a cause that cannot occur.
    let repo = scratch("pr-partition-unreadable");
    write(&repo, "batten.toml", &config());
    write(&repo, "pr-partition-restated.rego", MODULE);
    std::fs::create_dir_all(repo.join("prose")).expect("create prose dir");
    std::fs::write(repo.join("prose/notes.md"), [0xff, 0xfe, 0x00, 0x80])
        .expect("write invalid utf-8");
    git_in(&repo, &["init", "-q", "-b", "main", "."]);
    git_in(&repo, &["add", "-A"]);

    let outcome = check(&repo);
    let (answer, cause) = (stdout(&outcome), stderr(&outcome));
    assert_eq!(
        outcome.status.code(),
        Some(2),
        "a declared source that will not read must refuse, never pass\n{answer}{cause}"
    );
    assert!(answer.contains("pr-partition-restated"), "{answer}{cause}");
}

#[test]
fn a_tree_with_no_such_prose_is_clean() {
    // Without this, a predicate that refused unconditionally passes every case
    // above and the gate reports the whole tree.
    let repo = fixture("clean", "the branch lands by fast-forward\n");
    let outcome = check(&repo);
    let (answer, cause) = (stdout(&outcome), stderr(&outcome));
    assert_eq!(
        outcome.status.code(),
        Some(0),
        "prose saying nothing about partition must pass\n{answer}{cause}"
    );
}
