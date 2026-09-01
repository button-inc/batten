//! `connector-not-granted` over the compiled binary (CLOUD-1260).
//!
//! **The question a `with input as` case cannot answer.** The module's own `test_`
//! rules pin the predicate and nothing else: they hand it a fabricated
//! `input.tree.documents[".claude/settings.json"]` and ask what it decides. What
//! they cannot establish is whether the ENGINE builds that key at all for a path
//! inside a DOTFILE DIRECTORY — and if it does not, the module is silent on every
//! tree, a dead gate and a repository that dropped the raw grants being
//! byte-identical on the decision surface. That is the class
//! `.claude/rules/policy-modules.md` records two live instances of, both found by
//! adding this tier rather than by reading.
//!
//! **The proof is structural rather than an extra assertion.** A refusal can only
//! be raised if `allows` is defined, and `allows` is defined only if the engine
//! parsed the dotfile. So `a_named_raw_grant_is_refused` firing IS the evidence
//! that the document was read; were the walker skipping `.claude/`, that case
//! would exit `0` and fail. No separate reachability case is needed.
//!
//! Four observations, per CLOUD-418, each here because dropping it lets another
//! pass over a predicate that decides nothing:
//!
//! * `a_tree_granting_nothing_raw_is_clean` — the positive.
//! * `a_named_raw_grant_is_refused` — the class the row exists for, and the
//!   reachability proof above.
//! * `a_globbed_server_grant_is_refused` — the anti-vacuity mirror. Without it the
//!   positive is satisfied by a predicate matching one exact string, and the
//!   strictly WIDER grant ships past the gate built to refuse it.
//! * `an_absent_settings_file_answers_nothing` — could-not-look is not a refusal.
//!   Without it, a predicate that refused unconditionally passes both negatives.
//!
//! The module under test is `include_str!`d from `policy/` rather than copied, so
//! this suite cannot drift from the predicate that ships.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::path::{Path, PathBuf};
use std::process::Output;

use common::{batten, git_in, scratch, stderr, stdout, write};

/// The shipped predicate, never a copy of it.
const MODULE: &str = include_str!("../../../policy/connector-not-granted.rego");

/// Registers the shipped module over the dotfile, with the class it raises.
///
/// The `documents` row is the whole subject of this suite: it is what asks the
/// engine to parse a path under `.claude/`, and every case below is an
/// observation of whether that happened.
const CONFIG: &str = r#"version = 1

[[rule]]
id = "connector-not-granted"
kind = "policy"
scope = "tree"
documents = [".claude/settings.json"]
module = "connector-not-granted.rego"
severity = "deny"

[[verdict]]
id = "V-RAW-CONNECTOR-GRANTED"
gloss = "a reduced tool is also granted raw, so the reduction decides nothing"
class = "A fixture copy of the shipped class; the registry's own row is in batten.toml."

[[verdict.route]]
id = "R-DROP-THE-RAW-GRANT"
kind = "document"
target = "connector-not-granted.rego"
"#;

/// A repository fixture, optionally carrying a settings file with `permissions.allow`.
///
/// One per case: these run in parallel and `git init` races on a shared
/// directory, which is a fact about the harness rather than about the predicate.
fn fixture(name: &str, allow: Option<&str>) -> PathBuf {
    let repo = scratch(&format!("connector-not-granted-{name}"));
    write(&repo, "batten.toml", CONFIG);
    write(&repo, "connector-not-granted.rego", MODULE);
    if let Some(entries) = allow {
        write(
            &repo,
            ".claude/settings.json",
            &format!("{{\n  \"permissions\": {{\n    \"allow\": {entries}\n  }}\n}}\n"),
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
fn a_tree_granting_nothing_raw_is_clean() {
    // THE POSITIVE. A settings file that grants other things freely and hands
    // back no reduced tool.
    let repo = fixture(
        "clean",
        Some(r#"["Bash(git:*)", "Bash(batten:*)", "mcp__serena__*"]"#),
    );
    let outcome = check(&repo);
    let (answer, cause) = (stdout(&outcome), stderr(&outcome));
    assert_eq!(
        outcome.status.code(),
        Some(0),
        "a tree granting no raw connector tool must pass\n{answer}{cause}"
    );
}

#[test]
fn a_named_raw_grant_is_refused() {
    // THE CLASS THIS ROW EXISTS FOR, and the reachability proof: this refusal is
    // only raisable if the engine parsed a path under `.claude/`. A walker that
    // skipped dotfile directories would leave `allows` undefined, Rego would read
    // that as *does not hold*, and this case would exit 0.
    let repo = fixture("named", Some(r#"["mcp__Linear__get_issue"]"#));
    let outcome = check(&repo);
    let (answer, cause) = (stdout(&outcome), stderr(&outcome));
    assert_eq!(
        outcome.status.code(),
        Some(2),
        "a granted raw tool must refuse: the reduction beside it decides nothing\n{answer}{cause}"
    );
    assert!(answer.contains("connector-not-granted"), "{answer}{cause}");
}

#[test]
fn a_globbed_server_grant_is_refused() {
    // THE ANTI-VACUITY MIRROR. A predicate matching only that one exact string
    // satisfies both cases above and is silent here — and a wildcard grant is
    // STRICTLY WIDER than the named one, so it would ship past the gate built to
    // refuse it.
    let repo = fixture("globbed", Some(r#"["mcp__Linear__*"]"#));
    let outcome = check(&repo);
    let (answer, cause) = (stdout(&outcome), stderr(&outcome));
    assert_eq!(
        outcome.status.code(),
        Some(2),
        "a wildcard grant is wider than a named one and must refuse too\n{answer}{cause}"
    );
    assert!(answer.contains("connector-not-granted"), "{answer}{cause}");
}

#[test]
fn the_finding_is_a_pointer_and_never_the_grant_it_refuses() {
    // Non-negotiable rule 4 on the one gate whose subject is a list of strings a
    // reader could be tempted to echo. The finding carries the path and a count;
    // restating the entries would be the payload-in-the-finding shape.
    let repo = fixture(
        "pointer-only",
        Some(r#"["mcp__Linear", "mcp__Linear__*", "mcp__Linear__get_issue"]"#),
    );
    let outcome = check(&repo);
    let (answer, cause) = (stdout(&outcome), stderr(&outcome));
    let rendered = format!("{answer}{cause}");
    assert_eq!(outcome.status.code(), Some(2), "{rendered}");
    assert!(
        !rendered.contains("mcp__Linear__get_issue"),
        "the offending entries must not be restated in the finding:\n{rendered}"
    );
}

#[test]
fn an_absent_settings_file_answers_nothing() {
    // COULD NOT LOOK IS NOT A REFUSAL. Without this case, a predicate that
    // refused unconditionally passes both negatives above — and a consumer with
    // no settings file at all would be told it had granted something.
    let repo = fixture("absent", None);
    let outcome = check(&repo);
    let (answer, cause) = (stdout(&outcome), stderr(&outcome));
    assert_eq!(
        outcome.status.code(),
        Some(0),
        "a tree with no settings file must not read as a raw grant\n{answer}{cause}"
    );
}
