//! The hook step's trigger covers every path the config makes an input, over the
//! compiled binary (CLOUD-224, ported from `mise-tasks/batten-glob-check.sh`
//! under CLOUD-843).
//!
//! **What is decidable only here.** `policy/glob-containment.rego` carries
//! load-time cases pinning the predicate, and every one of them supplies
//! `input.tree.lines` with `with input as`. That fabricates the very shape the
//! engine may be unable to produce (CLOUD-845): whether a declared `line_sources`
//! path resolves to the COMMITTED bytes at all, and whether two separate paths
//! both resolve in one evaluation, is the engine's half and no `with input as`
//! block can test it. The retiring suite took its two files as positional
//! arguments so it could be pointed at fixtures; the successor's fixtures are
//! whole repositories, which is a stronger tier and not a weaker one.
//!
//! The self-consumption case is the one the retiring suite opened on: this
//! repository's own committed pair covers itself, so the containment claim is
//! checkable rather than asserted.
//
// carried: mise-tasks/batten-glob-check.sh policy/glob-containment.rego crates/batten/tests/it/glob_containment.rs
// carried: tests/batten-glob-check.bats policy/glob-containment.rego crates/batten/tests/it/glob_containment.rs
//
// carried: "the committed pair covers itself today" policy/glob-containment.rego
// carried: "a rule glob absent from the list is caught, and named" policy/glob-containment.rego
// carried: "a verbatim entry covers a rule glob" policy/glob-containment.rego
// carried: "a P/** entry subsumes anything under P — the reason the list stays short" policy/glob-containment.rego
// carried: "subsumption is a prefix test, so a sibling prefix does not count" policy/glob-containment.rego
// carried: "a budget file is an input, and an uncovered one is caught" policy/glob-containment.rego
// carried: "an embedded budget path is an input too" policy/glob-containment.rego
// carried: "a shape rule declares no glob and demands nothing" policy/glob-containment.rego
// carried: "a comment inside the list is not list syntax, parenthesis and all" policy/glob-containment.rego
// carried: "another step's glob list is not read as batten-check's" policy/glob-containment.rego
// carried: "output is a pointer — no file contents echoed" policy/glob-containment.rego
// changed: "a config the gate parses nothing out of is exit 2, not a pass" policy/glob-containment.rego the refusal is carried whole and its EXIT CODE is the engine's rather than the shell's: the shell reserved 2 for could-not-look and used 1 for a violation, and the engine's one contract makes every deny finding exit 2 with no per-verb exception (AGENTS.md rule 5). So the case still separates a failed parse from a pass, which is what it was for, and no longer separates it from a violation by exit code — it separates it by verdict, which is the pointer a reader acts on
// changed: "a batten-check step with no glob at all is a regression, not a default" policy/glob-containment.rego same exit-code change as the row above: the shell exited 1 here and the successor emits a `step declare missing` finding, which is exit 2 on the engine's contract
// changed: "a missing input file is exit 2, distinct from a violation" policy/glob-containment.rego the clause has no successor to carry because the ENGINE decides it earlier: a rule whose declared `line_sources` match nothing is not evaluated at all, and `input.tree.missing` is never populated on the tree surface (CLOUD-1049, measured identically for `policy/mise-pin-agreement.rego`'s own could-not-look clause). A case asserting it would assert the engine gap rather than the predicate, so it ships without one until that fact does

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::{Path, PathBuf};
use std::process::Output;

use common::{Fixture, git_in, run, stderr, stdout};

/// A repository declaring only this rule, so any finding is the one under test.
///
/// The three `[[verdict]]` rows are carried into the fixture rather than
/// assumed: a verdict is emittable only where a row declares it, and the
/// built-in registry is not this consumer's vocabulary. Without them the module
/// loads and the run is a USAGE error, which is exit 1 and not the exit 2 these
/// cases are about — so a fixture that omitted them would test the declaration
/// rather than the predicate.
fn glob_repo(name: &str, config_body: &str, hooks_body: &str) -> PathBuf {
    let config = format!(
        "version = 1\n\n\
         [[verdict]]\n\
         id = \"manifest cover missing\"\n\
         gloss = \"the manifest does not select a path it must judge\"\n\
         class = \"A trigger narrower than its rule set deletes feedback while preserving the verdict.\"\n\n\
         [[verdict.route]]\n\
         id = \"prose read first\"\n\
         kind = \"document\"\n\
         target = \"AGENTS.md\"\n\n\
         [[verdict]]\n\
         id = \"step declare missing\"\n\
         gloss = \"a step declares no trigger\"\n\
         class = \"A step with no glob runs on every commit, which is what the trigger removed.\"\n\n\
         [[verdict.route]]\n\
         id = \"prose read first\"\n\
         kind = \"document\"\n\
         target = \"AGENTS.md\"\n\n\
         [[verdict]]\n\
         id = \"gate parse unread\"\n\
         gloss = \"the gate parsed nothing out of its own input\"\n\
         class = \"A containment check that parses zero requirements passes vacuously.\"\n\n\
         [[verdict.route]]\n\
         id = \"prose read first\"\n\
         kind = \"document\"\n\
         target = \"AGENTS.md\"\n\n\
         [[pattern]]\n\
         id = \"md-quoted-span\"\n\
         regex = '\"[^\"]*\"'\n\n\
         [[rule]]\n\
         id = \"glob-containment\"\n\
         kind = \"policy\"\n\
         scope = \"tree\"\n\
         line_sources = [\"batten.toml\", \"hk.pkl\"]\n\
         module = \"policy/glob-containment.rego\"\n\
         severity = \"deny\"\n\n\
         {config_body}"
    );
    let dir = Fixture::new(name)
        .config(&config)
        .file("AGENTS.md", "the consumer's own authority\n")
        .file("hk.pkl", hooks_body)
        .git()
        .build();
    // The module is copied in rather than referenced: the fixture is its own
    // repository, and a rule row naming a path outside it would not resolve.
    common::write(
        &dir,
        "policy/glob-containment.rego",
        &std::fs::read_to_string(common::at_root("policy/glob-containment.rego")).unwrap(),
    );
    git_in(&dir, &["add", "-A"]);
    git_in(&dir, &["commit", "-q", "-m", "base"]);
    dir
}

fn check(dir: &Path) -> Output {
    run(dir, &["check", "--rule", "glob-containment"])
}

/// A `["batten-check"]` step selecting `entries`, followed by another step so
/// the reader's upper bound is a real one.
fn hooks(entries: &[&str]) -> String {
    let listed = entries
        .iter()
        .map(|e| format!("        \"{e}\",\n"))
        .collect::<String>();
    format!(
        "hooks {{\n  [\"batten-check\"] {{\n    glob =\n      List(\n{listed}      )\n    check = \"mise run batten-check\"\n  }}\n  [\"other-step\"] {{\n    glob = List(\"unrelated\")\n  }}\n}}\n"
    )
}

fn rule_glob(glob: &str) -> String {
    format!(
        "[[rule]]\nid = \"r\"\nkind = \"forbid\"\nscope = \"tree\"\nglob = \"{glob}\"\npattern = \"x\"\nseverity = \"deny\"\n"
    )
}

#[test]
fn a_verbatim_entry_covers_a_rule_glob() {
    let dir = glob_repo(
        "glob-verbatim",
        &rule_glob("mise.toml"),
        &hooks(&["batten.toml", "hk.pkl", "policy/**", "mise.toml"]),
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
fn a_prefix_entry_subsumes_anything_under_it() {
    // The reason the list can stay short: one `crates/**` stands for every glob
    // beneath it.
    let dir = glob_repo(
        "glob-prefix",
        &rule_glob("crates/batten/tests/**/*.rs"),
        &hooks(&["batten.toml", "hk.pkl", "policy/**", "crates/**"]),
    );
    let output = check(&dir);
    assert_eq!(output.status.code(), Some(0), "{}", stdout(&output));
}

#[test]
fn an_unlisted_glob_is_refused_and_named() {
    let dir = glob_repo(
        "glob-unlisted",
        &rule_glob("mise.toml"),
        &hooks(&["batten.toml", "hk.pkl", "policy/**"]),
    );
    let output = check(&dir);
    assert_eq!(output.status.code(), Some(2), "{}", stdout(&output));
    assert!(
        stdout(&output).contains("batten.toml:"),
        "the finding points at the config line that demands it: {:?}",
        stdout(&output)
    );
}

#[test]
fn a_sibling_prefix_does_not_count() {
    // `crates-extra/` is not under `crates/`. A looser string match would call
    // this covered, which is the direction a containment check must never fail
    // in.
    let dir = glob_repo(
        "glob-sibling-prefix",
        &rule_glob("crates-extra/**/*.rs"),
        &hooks(&["batten.toml", "hk.pkl", "policy/**", "crates/**"]),
    );
    let output = check(&dir);
    assert_eq!(output.status.code(), Some(2), "{}", stdout(&output));
}

#[test]
fn a_slashless_entry_does_not_subsume_by_prefix() {
    // The `/**` is what makes an entry a prefix at all. An entry without it
    // subsumes nothing, however much of it a required glob happens to start
    // with — otherwise a bare `crates` would silently stand for
    // `crates-extra/**`, which is a different tree.
    let dir = glob_repo(
        "glob-slashless",
        &rule_glob("crates-extra/**/*.rs"),
        &hooks(&["batten.toml", "hk.pkl", "policy/**", "crates"]),
    );
    let output = check(&dir);
    assert_eq!(output.status.code(), Some(2), "{}", stdout(&output));
}

#[test]
fn a_budget_file_is_an_input() {
    // The case the issue's own wording missed: a declared budget is a gate under
    // `check`, not only under its own verb, so a budgeted document is as much an
    // input as any rule glob.
    let dir = glob_repo(
        "glob-budget-files",
        &format!(
            "{}\n[budget.instructions]\nfiles = [\"AGENTS.md\", \"CONTRIBUTING.md\"]\nmax_tokens = 10\n",
            rule_glob("mise.toml")
        ),
        &hooks(&[
            "batten.toml",
            "hk.pkl",
            "policy/**",
            "mise.toml",
            "AGENTS.md",
        ]),
    );
    let output = check(&dir);
    assert_eq!(output.status.code(), Some(2), "{}", stdout(&output));
}

#[test]
fn an_embedded_budget_path_is_an_input_too() {
    let dir = glob_repo(
        "glob-budget-embedded",
        &format!(
            "{}\n[budget.instructions]\nfiles = [\"AGENTS.md\"]\nmax_tokens = 10\n\n[[budget.instructions.embedded]]\npath = \".serena/project.yml\"\nkey = \"initial_prompt\"\n",
            rule_glob("mise.toml")
        ),
        &hooks(&[
            "batten.toml",
            "hk.pkl",
            "policy/**",
            "mise.toml",
            "AGENTS.md",
        ]),
    );
    let output = check(&dir);
    assert_eq!(output.status.code(), Some(2), "{}", stdout(&output));
    assert!(
        stdout(&output).contains("batten.toml:"),
        "the finding points at the config line that demands it: {:?}",
        stdout(&output)
    );
}

#[test]
fn a_rule_with_no_glob_demands_nothing() {
    let dir = glob_repo(
        "glob-no-glob-rule",
        &format!(
            "[[rule]]\nid = \"s\"\nkind = \"shape\"\nscope = \"mediated_call\"\nseverity = \"deny\"\npattern = \"gh pr merge\"\nreason = \"no\"\n\n{}",
            rule_glob("mise.toml")
        ),
        &hooks(&["batten.toml", "hk.pkl", "policy/**", "mise.toml"]),
    );
    let output = check(&dir);
    assert_eq!(output.status.code(), Some(0), "{}", stdout(&output));
}

#[test]
fn a_comment_inside_the_list_is_not_list_syntax() {
    // The failure the retired gate actually shipped: an entry's comment
    // contained a parenthesised tracker key whose `)` ended the list early, so
    // every entry below it read as uncovered and the gate reported four paths
    // that were listed all along.
    let dir = glob_repo(
        "glob-comment-in-list",
        &rule_glob("mise.toml"),
        &"hooks {\n  [\"batten-check\"] {\n    glob =\n      List(\n        \"batten.toml\",\n        \"hk.pkl\",\n        // the rule that made this an input (CLOUD-614)\n        \"policy/**\",\n        \"mise.toml\",\n      )\n  }\n  [\"other-step\"] {\n    glob = List(\"unrelated\")\n  }\n}\n".to_owned(),
    );
    let output = check(&dir);
    assert_eq!(
        output.status.code(),
        Some(0),
        "a comment closed the list: {}",
        stdout(&output)
    );
}

#[test]
fn another_steps_list_is_not_read_as_this_ones() {
    let dir = glob_repo(
        "glob-other-step",
        &rule_glob("mise.toml"),
        &"hooks {\n  [\"batten-check\"] {\n    glob = List(\"batten.toml\", \"hk.pkl\", \"policy/**\")\n  }\n  [\"other-step\"] {\n    glob = List(\"mise.toml\")\n  }\n}\n".to_owned(),
    );
    let output = check(&dir);
    assert_eq!(output.status.code(), Some(2), "{}", stdout(&output));
}

#[test]
fn a_step_with_no_glob_at_all_is_a_regression_not_a_default() {
    let dir = glob_repo(
        "glob-step-without-list",
        &rule_glob("mise.toml"),
        &"hooks {\n  [\"batten-check\"] {\n    check = \"mise run batten-check\"\n  }\n  [\"other-step\"] {\n    glob = List(\"unrelated\")\n  }\n}\n".to_owned(),
    );
    let output = check(&dir);
    assert_eq!(output.status.code(), Some(2), "{}", stdout(&output));
    assert!(
        stdout(&output).contains("hk.pkl"),
        "the finding points at the manifest: {:?}",
        stdout(&output)
    );
}

#[test]
fn a_config_yielding_no_inputs_is_refused_rather_than_passed() {
    // The vacuous green a containment check produces most easily: parse zero
    // requirements and every list covers them.
    let dir = glob_repo(
        "glob-unparseable-config",
        "# this config declares no rule glob and no budget path\n",
        &hooks(&["batten.toml", "hk.pkl", "policy/**"]),
    );
    let output = check(&dir);
    assert_eq!(output.status.code(), Some(2), "{}", stdout(&output));
}

#[test]
fn output_is_pointer_only() {
    let dir = glob_repo(
        "glob-pointer-only",
        &format!(
            "{}\n# a distinctive phrase nobody should see in a finding\n",
            rule_glob("mise.toml")
        ),
        &hooks(&["batten.toml", "hk.pkl", "policy/**"]),
    );
    let output = check(&dir);
    assert_eq!(output.status.code(), Some(2));
    assert!(
        !stdout(&output).contains("distinctive phrase"),
        "the config's prose is payload: {:?}",
        stdout(&output)
    );
}

#[test]
fn the_committed_pair_covers_itself_today() {
    // The self-consumption case the retiring suite opened on, and the reason
    // this gate is worth having: the two committed files agree, checked rather
    // than asserted.
    let output = common::run_at_real_root(
        &common::at_root(""),
        &["check", "--rule", "glob-containment"],
    );
    assert_eq!(
        output.status.code(),
        Some(0),
        "this repository's own batten-check glob does not cover every input: {}",
        stdout(&output)
    );
}
