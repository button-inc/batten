//! Every crate source module has a `mem:core` row, over the compiled binary
//! (CLOUD-194, ported from `mise-tasks/module-map-check.sh` under CLOUD-843).
//!
//! **What is decidable only here.** `policy/module-map.rego` carries load-time
//! cases pinning the predicate, and every one of them supplies
//! `input.tree.tracked` with `with input as`. That fabricates the very shape the
//! engine may be unable to produce — and here it fabricates the exact
//! distinction the gate turns on, TRACKED versus merely present, which is what
//! separates "a module landed without its row" from "somebody has a draft open".
//! A module whose suite only fabricated the set would stay green over an engine
//! that resolved the working tree instead of the index.
//!
//! The self-consumption case runs over this repository, which is what the
//! retiring suite's last case did and what makes the gate's own claim about
//! `mem:core` checkable rather than asserted.
//
// carried: mise-tasks/module-map-check.sh policy/module-map.rego crates/batten/tests/it/module_map.rs
// carried: tests/module-map-check.bats policy/module-map.rego crates/batten/tests/it/module_map.rs
//
// carried: "a module with a map row exits 0" policy/module-map.rego
// carried: "a module with no map row is reported with a pointer" policy/module-map.rego
// carried: "output is pointer-only — no map or source prose echoed" policy/module-map.rego
// changed: "an untracked module is not yet the map's problem" policy/module-map.rego the shell asked the INDEX via `git ls-files`; `input.tree.tracked` is a working-tree walk that explicitly is not the index, and nothing available to a module expresses index membership for a glob — `input.tree.staged` parses each declared path by format and no format owns `.rs`, and `git-status.changed` conflates untracked with modified. The successor is stricter in the fail-closed direction and `an_uncommitted_module_is_judged_too_where_the_shell_left_it_alone` pins the difference rather than leaving it to be discovered
// carried: "a bare filename mention does not satisfy the row" policy/module-map.rego
// changed: "a missing map is reported once, not once per module" policy/module-map.rego the clause is carried and is correct, and it cannot fire: a rule whose declared `line_sources` match nothing is not evaluated, and `input.tree.missing` is never populated on the tree surface (CLOUD-1049, measured identically for `policy/mise-pin-agreement.rego`'s own could-not-look clause). A case asserting it would assert the engine gap rather than the predicate, so the arm ships without one until the fact does
// carried: "every module of this repo has a row — the gate on the real tree" policy/module-map.rego

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::{Path, PathBuf};
use std::process::Output;

use common::{Fixture, git_in, run, stderr, stdout};

/// A repository declaring only this rule, so any finding is the one under test.
fn map_repo(name: &str, map: Option<&str>, modules: &[(&str, &str)]) -> PathBuf {
    // The two `[[verdict]]` rows are carried into the fixture rather than
    // assumed: a verdict is emittable only where a row declares it, and the
    // built-in registry is not this consumer's vocabulary. Without them the
    // module loads and the run is a USAGE error, which is exit 1 and not the
    // exit 2 these cases are about — so a fixture that omitted them would test
    // the declaration rather than the predicate.
    let mut fixture = Fixture::new(name).config(
        "version = 1\n\n\
         [[verdict]]\n\
         id = \"memory resolve missing\"\n\
         gloss = \"the memory graph has no root\"\n\
         class = \"The map is the discovery entry point; absent, it is reachable only by listing the directory.\"\n\n\
         [[verdict.route]]\n\
         id = \"prose read first\"\n\
         kind = \"document\"\n\
         target = \"AGENTS.md\"\n\n\
         [[verdict]]\n\
         id = \"module place missing\"\n\
         gloss = \"a module is absent from its table\"\n\
         class = \"An unmapped module is not one with no constraints, it is one whose constraints nobody wrote down.\"\n\n\
         [[verdict.route]]\n\
         id = \"prose read first\"\n\
         kind = \"document\"\n\
         target = \"AGENTS.md\"\n\n\
         [[rule]]\n\
         id = \"module-map\"\n\
         kind = \"policy\"\n\
         scope = \"tree\"\n\
         line_sources = [\".serena/memories/core.md\"]\n\
         module = \"policy/module-map.rego\"\n\
         severity = \"deny\"\n",
    );
    fixture = fixture.file("AGENTS.md", "the consumer's own authority\n");
    if let Some(text) = map {
        fixture = fixture.file(".serena/memories/core.md", text);
    }
    for (path, body) in modules {
        fixture = fixture.file(path, body);
    }
    let dir = fixture.git().build();
    // The module is copied in rather than referenced: the fixture is its own
    // repository, and a rule row naming a path outside it would not resolve.
    common::write(
        &dir,
        "policy/module-map.rego",
        &std::fs::read_to_string(common::at_root("policy/module-map.rego")).unwrap(),
    );
    git_in(&dir, &["add", "-A"]);
    git_in(&dir, &["commit", "-q", "-m", "base"]);
    dir
}

fn check(dir: &Path) -> Output {
    run(dir, &["check", "--rule", "module-map"])
}

const ROW: &str = "- `main.rs` — the binary boundary.\n";

#[test]
fn a_module_with_a_map_row_is_clean() {
    let dir = map_repo(
        "module-map-clean",
        Some(ROW),
        &[("crates/demo/src/main.rs", "fn main() {}\n")],
    );
    let output = check(&dir);
    assert_eq!(
        output.status.code(),
        Some(0),
        "out={} err={}",
        stdout(&output),
        stderr(&output)
    );
}

#[test]
fn a_module_with_no_map_row_is_refused_with_a_pointer() {
    let dir = map_repo(
        "module-map-absent-row",
        Some(ROW),
        &[
            ("crates/demo/src/main.rs", "fn main() {}\n"),
            ("crates/demo/src/severity.rs", "pub fn f() {}\n"),
        ],
    );
    let output = check(&dir);
    assert_eq!(output.status.code(), Some(2), "{}", stdout(&output));
    let text = stdout(&output);
    assert!(
        text.contains("crates/demo/src/severity.rs"),
        "the finding points at the unmapped module: {text:?}"
    );
}

#[test]
fn an_uncommitted_module_is_judged_too_where_the_shell_left_it_alone() {
    // THE ONE BEHAVIOUR THIS PORT CHANGES, asserted rather than left to be
    // discovered. `git ls-files` asked the INDEX; `input.tree.tracked` is a
    // working-tree walk and explicitly is not the index, and nothing available
    // to a module expresses index membership for a glob. So a module written
    // but not yet committed is judged here, where the retiring suite pinned
    // "an untracked module is not yet the map's problem".
    //
    // The direction is fail-closed and the cost is real: a contributor drafting
    // a module is asked for its row before they commit it. This case exists so
    // that the change is a decision CLOUD-1716 can keep or reverse, rather than
    // a silent difference nobody measured.
    let dir = map_repo(
        "module-map-uncommitted",
        Some(ROW),
        &[("crates/demo/src/main.rs", "fn main() {}\n")],
    );
    common::write(&dir, "crates/demo/src/draft.rs", "pub fn f() {}\n");

    let output = check(&dir);
    assert_eq!(
        output.status.code(),
        Some(2),
        "the successor judges the checkout: {}",
        stdout(&output)
    );
}

#[test]
fn a_bare_mention_does_not_satisfy_the_row() {
    // The map names modules in backticks. A sentence ABOUT a module must not
    // read as a row, or the gate passes on the very drift it exists to catch.
    let dir = map_repo(
        "module-map-bare-mention",
        Some("Note: severity.rs is described in another memory.\n"),
        &[("crates/demo/src/severity.rs", "pub fn f() {}\n")],
    );
    let output = check(&dir);
    assert_eq!(output.status.code(), Some(2), "{}", stdout(&output));
}

#[test]
fn output_is_pointer_only() {
    let dir = map_repo(
        "module-map-pointer-only",
        Some("- `main.rs` — the binary boundary, a distinctive phrase.\n"),
        &[("crates/demo/src/hidden.rs", "pub fn secret_helper() {}\n")],
    );
    let output = check(&dir);
    assert_eq!(output.status.code(), Some(2));
    let text = stdout(&output);
    assert!(
        !text.contains("secret_helper"),
        "the module's source is payload: {text:?}"
    );
    assert!(
        !text.contains("distinctive phrase"),
        "and so is the map's prose: {text:?}"
    );
}

#[test]
fn the_repositorys_own_map_is_complete() {
    // The self-consumption case the retiring suite ended on: the claim
    // `rules/rust.md` makes about `mem:core` is checkable rather than asserted.
    let output = common::run_at_real_root(&common::at_root(""), &["check", "--rule", "module-map"]);
    assert_eq!(
        output.status.code(),
        Some(0),
        "this repository's own module map is incomplete: {}",
        stdout(&output)
    );
}
