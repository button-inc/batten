//! `harness-grant` over the compiled binary (CLOUD-1247).
//!
//! **The question a `with input as` case cannot answer.** The module's own
//! `test_` rules pin the predicate and nothing else: they hand it a fabricated
//! `input.tree.documents[".claude/settings.json"]` and ask what it decides. What
//! they cannot establish is whether the ENGINE builds that key at all for a path
//! inside a DOTFILE DIRECTORY — and if it does not, the module is silent on every
//! tree, a dead gate and a correctly-granted repository being byte-identical on
//! the decision surface. That is the class `.claude/rules/policy-modules.md`
//! records two live instances of, both found by adding this tier rather than by
//! reading.
//!
//! **The proof is structural rather than an extra assertion.** A refusal can only
//! be raised if `grants` is defined, and `grants` is defined only if the engine
//! parsed the dotfile. So `a_dropped_grant_is_refused` firing IS the evidence
//! that the document was read; were the walker skipping `.claude/`, that case
//! would exit `0` and fail. No separate reachability case is needed, and adding
//! one would assert the same fact twice.
//!
//! Four observations, per CLOUD-418, each here because dropping it lets another
//! pass over a predicate that decides nothing:
//!
//! * `the_landed_shape_is_clean` — the positive.
//! * `a_dropped_grant_is_refused` — the class the row exists for, and the
//!   reachability proof above.
//! * `a_dropped_sentinel_is_refused` — the anti-vacuity mirror. Without it the
//!   positive is satisfied by a predicate that only ever looks for `batten`, and
//!   the sentinel guarantee ships as coverage having never been walked.
//! * `an_absent_settings_file_answers_nothing` — could-not-look is not a
//!   refusal. Without it, a predicate that refused unconditionally passes the
//!   two negative cases.
//!
//! The module under test is `include_str!`d from `policy/` rather than copied,
//! so this suite cannot drift from the predicate that ships.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::path::{Path, PathBuf};
use std::process::Output;

use common::{batten, git_in, scratch, stderr, stdout, write};

/// The shipped predicate, never a copy of it.
const MODULE: &str = include_str!("../../../policy/harness-grant.rego");

/// Registers the shipped module over the dotfile, with the two classes it raises.
///
/// The `documents` row is the whole subject of this suite: it is what asks the
/// engine to parse a path under `.claude/`, and every case below is an
/// observation of whether that happened.
const CONFIG: &str = r#"version = 1

[[rule]]
id = "harness-grant"
kind = "policy"
scope = "tree"
documents = [".claude/settings.json"]
module = "harness-grant.rego"
severity = "deny"

[[verdict]]
id = "V-HARNESS-GRANT-ABSENT"
gloss = "the committed settings no longer grant this repository's own binary"
class = "A fixture copy of the shipped class; the registry's own row is in batten.toml."

[[verdict.route]]
id = "R-RESTORE-THE-GRANT"
kind = "document"
target = "harness-grant.rego"

[[verdict]]
id = "V-HARNESS-GRANT-DEFAULTS-DROPPED"
gloss = "the grant is there and the built-in classifier rules were discarded with it"
class = "A fixture copy of the shipped class; the registry's own row is in batten.toml."

[[verdict.route]]
id = "R-RESTORE-THE-DEFAULTS"
kind = "document"
target = "harness-grant.rego"
"#;

/// A repository fixture, optionally carrying a settings file with `allow`.
///
/// One per case: these run in parallel and `git init` races on a shared
/// directory, which is a fact about the harness rather than about the predicate.
fn fixture(name: &str, allow: Option<&str>) -> PathBuf {
    let repo = scratch(&format!("harness-grant-{name}"));
    write(&repo, "batten.toml", CONFIG);
    write(&repo, "harness-grant.rego", MODULE);
    if let Some(entries) = allow {
        write(
            &repo,
            ".claude/settings.json",
            &format!("{{\n  \"autoMode\": {{\n    \"allow\": {entries}\n  }}\n}}\n"),
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

#[test]
fn the_landed_shape_is_clean() {
    // THE POSITIVE. The shape CLOUD-1247 landed: the mediator named, the
    // sentinel kept.
    let repo = fixture(
        "clean",
        Some(r#"["$defaults", "Allow every `batten` subcommand."]"#),
    );
    let outcome = check(&repo);
    let (answer, cause) = (stdout(&outcome), stderr(&outcome));
    assert_eq!(
        outcome.status.code(),
        Some(0),
        "the landed grant must pass\n{answer}{cause}"
    );
}

#[test]
fn a_dropped_grant_is_refused() {
    // THE CLASS THIS ROW EXISTS FOR, and the reachability proof: this refusal is
    // only raisable if the engine parsed a path under `.claude/`. A walker that
    // skipped dotfile directories would leave `grants` undefined, Rego would read
    // that as *does not hold*, and this case would exit 0.
    let repo = fixture("dropped-grant", Some(r#"["$defaults"]"#));
    let outcome = check(&repo);
    let (answer, cause) = (stdout(&outcome), stderr(&outcome));
    assert_eq!(
        outcome.status.code(),
        Some(2),
        "a settings file naming no mediator must refuse\n{answer}{cause}"
    );
    assert!(answer.contains("harness-grant"), "{answer}{cause}");
}

#[test]
fn a_dropped_sentinel_is_refused() {
    // THE ANTI-VACUITY MIRROR. A predicate that only ever looked for `batten`
    // satisfies both cases above and is silent here, shipping the sentinel
    // guarantee as coverage that was never walked.
    let repo = fixture(
        "dropped-sentinel",
        Some(r#"["Allow every `batten` subcommand."]"#),
    );
    let outcome = check(&repo);
    let (answer, cause) = (stdout(&outcome), stderr(&outcome));
    assert_eq!(
        outcome.status.code(),
        Some(2),
        "dropping $defaults must refuse in its own right\n{answer}{cause}"
    );
    assert!(answer.contains("harness-grant"), "{answer}{cause}");
}

#[test]
fn an_absent_settings_file_answers_nothing() {
    // COULD NOT LOOK IS NOT A REFUSAL. Without this case, a predicate that
    // refused unconditionally passes both negatives above — and a consumer with
    // no settings file at all would be told its grant was deleted.
    let repo = fixture("absent", None);
    let outcome = check(&repo);
    let (answer, cause) = (stdout(&outcome), stderr(&outcome));
    assert_eq!(
        outcome.status.code(),
        Some(0),
        "a tree with no settings file must not read as a deleted grant\n{answer}{cause}"
    );
}
