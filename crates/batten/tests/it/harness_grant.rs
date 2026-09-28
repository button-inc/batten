//! `grant carry missing` over the compiled binary (CLOUD-1247, inverted by
//! CLOUD-1379).
//!
//! **The question a `with input as` case cannot answer.** The module's own
//! `test_` rules pin the predicate and nothing else: they hand it a fabricated
//! `input.tree.documents[".claude/settings.json"]` and ask what it decides. What
//! they cannot establish is whether the ENGINE builds that key at all for a path
//! inside a DOTFILE DIRECTORY — and if it does not, the module is silent on every
//! tree, a dead gate and a clean repository being byte-identical on the decision
//! surface. That is the class `rules/policy-modules.md` records two live
//! instances of, both found by adding this tier rather than by reading.
//!
//! **The proof is structural rather than an extra assertion.** A refusal can only
//! be raised if `settings` is defined, and `settings` is defined only if the
//! engine parsed the dotfile. So `a_committed_grant_is_refused` firing IS the
//! evidence that the document was read.
//!
//! Five observations, each here because dropping it lets another pass over a
//! predicate that decides nothing:
//!
//! * `a_committed_grant_is_refused` — the class the row exists for, and the
//!   reachability proof above.
//! * `an_empty_committed_block_is_refused` — the key is the predicate, not its
//!   contents.
//! * `a_block_beside_permissions_is_refused` — the shape this repository
//!   shipped, where a readable table sat beside the unreadable one.
//! * `settings_without_the_block_are_clean` — the anti-vacuity mirror, and the
//!   engine-walk case: its fixture carries a `permissions.deny` list, which a
//!   module binding the document as a rule leaks as bare deny tokens because
//!   the engine collects `deny` at any depth. A `with input as` case cannot see
//!   that; only this tier can.
//! * `an_absent_settings_file_answers_nothing` — could-not-look is not a
//!   refusal.
//!
//! The module under test is `include_str!`d from `policy/` rather than copied,
//! so this suite cannot drift from the predicate that ships.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::{Path, PathBuf};
use std::process::Output;

use common::{batten, git_in, scratch, stderr, stdout, write};

/// The shipped predicate, never a copy of it.
const MODULE: &str = include_str!("../../../../policy/harness-grant.rego");

/// Registers the shipped module over the dotfile, with the one class it raises.
///
/// The `documents` row is the whole subject of this suite: it is what asks the
/// engine to parse a path under `.claude/`, and every case below is an
/// observation of whether that happened.
const CONFIG: &str = r#"version = 1

[[rule]]
id = "grant carry missing"
kind = "policy"
scope = "tree"
documents = [".claude/settings.json"]
module = "harness-grant.rego"
severity = "deny"

[[verdict]]
id = "grant carry missing"
gloss = "the committed settings carry an autoMode block, which the classifier never reads"
class = "A fixture copy of the shipped class; the registry's own row is in batten.toml."

[[verdict.route]]
id = "task run first"
kind = "document"
target = "harness-grant.rego"
"#;

/// A repository fixture, optionally carrying a settings file with `body`.
///
/// One per case: these run in parallel and `git init` races on a shared
/// directory, which is a fact about the harness rather than about the predicate.
fn fixture(name: &str, body: Option<&str>) -> PathBuf {
    let repo = scratch(&format!("harness-grant-{name}"));
    write(&repo, "batten.toml", CONFIG);
    write(&repo, "harness-grant.rego", MODULE);
    if let Some(body) = body {
        write(&repo, ".claude/settings.json", body);
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

#[test]
fn a_committed_grant_is_refused() {
    // THE CLASS THIS ROW EXISTS FOR, and the reachability proof: this refusal is
    // only raisable if the engine parsed a path under `.claude/`. A walker that
    // skipped dotfile directories would leave `settings` undefined, Rego would
    // read that as *does not hold*, and this case would exit 0.
    let repo = fixture(
        "committed",
        Some(r#"{"autoMode": {"allow": ["$defaults", "Allow every `batten` subcommand."]}}"#),
    );
    let outcome = check(&repo);
    let (answer, cause) = (stdout(&outcome), stderr(&outcome));
    assert_eq!(
        outcome.status.code(),
        Some(2),
        "a committed autoMode block must refuse\n{answer}{cause}"
    );
    assert!(answer.contains("grant carry missing"), "{answer}{cause}");
}

#[test]
fn an_empty_committed_block_is_refused() {
    // AN EMPTY BLOCK IS STILL THE WRONG PLACE. It grants nothing either way, and
    // it reads to the next author as the slot a grant goes in — which is how the
    // measured block grew.
    let repo = fixture("empty", Some(r#"{"autoMode": {}}"#));
    let outcome = check(&repo);
    let (answer, cause) = (stdout(&outcome), stderr(&outcome));
    assert_eq!(
        outcome.status.code(),
        Some(2),
        "an empty committed autoMode block must refuse\n{answer}{cause}"
    );
    assert!(answer.contains("grant carry missing"), "{answer}{cause}");
}

#[test]
fn a_block_beside_permissions_is_refused() {
    // THE SHAPE THIS REPOSITORY ACTUALLY SHIPPED: a real `permissions` table the
    // host does read, with the inert block beside it.
    let repo = fixture(
        "beside",
        Some(
            r#"{"permissions": {"allow": ["Bash(batten:*)"]}, "autoMode": {"allow": ["$defaults"]}}"#,
        ),
    );
    let outcome = check(&repo);
    let (answer, cause) = (stdout(&outcome), stderr(&outcome));
    assert_eq!(
        outcome.status.code(),
        Some(2),
        "a committed block beside permissions must refuse\n{answer}{cause}"
    );
    assert!(answer.contains("grant carry missing"), "{answer}{cause}");
}

#[test]
fn settings_without_the_block_are_clean() {
    // THE ANTI-VACUITY MIRROR, and the engine-walk case. A predicate that refused
    // any settings file fails here; so does a module that binds the document as
    // a rule, because the engine reads `permissions.deny` as deny tokens.
    let repo = fixture(
        "clean",
        Some(r#"{"permissions": {"allow": ["Bash(batten:*)"], "deny": ["mcp__x__y"]}}"#),
    );
    let outcome = check(&repo);
    let (answer, cause) = (stdout(&outcome), stderr(&outcome));
    assert_eq!(
        outcome.status.code(),
        Some(0),
        "settings with no autoMode block must pass\n{answer}{cause}"
    );
}

#[test]
fn an_absent_settings_file_answers_nothing() {
    // COULD NOT LOOK IS NOT A REFUSAL. A consumer with no settings file at all
    // has nothing committed in the wrong scope.
    let repo = fixture("absent", None);
    let outcome = check(&repo);
    let (answer, cause) = (stdout(&outcome), stderr(&outcome));
    assert_eq!(
        outcome.status.code(),
        Some(0),
        "a tree with no settings file must not refuse\n{answer}{cause}"
    );
}
