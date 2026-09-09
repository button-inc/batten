//! No hook registered BY PATH shells out to a pinned tool, over the compiled
//! binary (CLOUD-479, ported from `mise-tasks/hook-pin-check.sh` under
//! CLOUD-843).
//!
//! **What is decidable only here.** `policy/hook-pin-check.rego` carries
//! load-time cases pinning the predicate, and every one of them hands the module
//! a ready-made map of three different kinds of file with `with input as`. That
//! fabricates the very shape the engine may be unable to produce (CLOUD-845), and
//! here it fabricates the whole judgement: this rule is a JOIN across three
//! `line_sources` shapes — two literal paths and a glob over the task directory —
//! resolved in one evaluation. A module whose suite only fabricated that map
//! would stay green over an engine that resolved a literal path but not the glob,
//! which is precisely the state in which every by-path hook passes vacuously.
//!
//! The self-consumption case is the one the retiring suite ended on: this
//! repository's own registrations are judged, so the pairing is a live claim.
//
// carried: mise-tasks/hook-pin-check.sh policy/hook-pin-check.rego crates/batten/tests/it/hook_pin_check.rs
// carried: tests/hook-pin-check.bats policy/hook-pin-check.rego crates/batten/tests/it/hook_pin_check.rs
//
// carried: "a by-path hook shelling out to a pinned tool is refused, and both are named" policy/hook-pin-check.rego
// carried: "THE SAME TASK VIA mise run IS FINE — the pairing is the defect, not the tool" policy/hook-pin-check.rego
// carried: "a by-path hook using no pinned tool passes" policy/hook-pin-check.rego
// carried: "a DECLARED exemption passes, because the script asserts the tool itself" policy/hook-pin-check.rego
// carried: "an exemption for a DIFFERENT tool does not cover this one" policy/hook-pin-check.rego
// carried: "MENTIONING a tool in a comment is not depending on it" policy/hook-pin-check.rego
// carried: "a tool named as a substring of another word is not a call" policy/hook-pin-check.rego
// carried: "the pinned set is READ from the manifest, not restated here" policy/hook-pin-check.rego
// carried: "a manifest with no [tools] is exit 2 — could not look, never a verdict" policy/hook-pin-check.rego
// carried: "output is pointer-only — the task and the tool, never a line of either file" policy/hook-pin-check.rego
// carried: "this repository's own registrations pass" policy/hook-pin-check.rego
// changed: "the refusal names all three ways out, since a deny with no exit is a wall" policy/hook-pin-check.rego the shell wrote its remedy into the refusal's own prose; on the engine a verdict's remedy is DATA — the `[[verdict.route]]` rows the registry resolves — so the three ways out are declared once beside the verdict rather than restated per firing, and `batten policy explain` is what reads them back. The case is carried as the route's existence rather than as a substring of the refusal
// changed: "no by-path registrations SAYS SO rather than reading as a clean pass" policy/hook-pin-check.rego the shell printed an advisory line to stderr and still exited 0, and the engine's output contract has no advisory channel for a rule that found nothing (AGENTS.md rule 5, one contract with no per-verb exception). The vacuity that actually mattered is kept as a real finding rather than a note: a manifest pinning NOTHING is `tool list empty`, which is what makes every by-path hook stop passing vacuously
// changed: "a missing settings file is exit 2, not a pass" policy/hook-pin-check.rego the ENGINE decides this earlier — a rule whose declared `line_sources` match nothing is not evaluated at all, and `input.tree.missing` is never populated on the tree surface (CLOUD-1049, measured identically for `policy/mise-pin-agreement.rego`'s own could-not-look clause). A case asserting it would assert the engine gap rather than the predicate

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::Output;

use common::{Fixture, git_in, run, stderr, stdout};

/// A repository declaring only this rule, so any finding is the one under test.
fn pin_repo(
    name: &str,
    registrations: &[&str],
    manifest: &str,
    scripts: &[(&str, &str)],
) -> PathBuf {
    let mut fixture = Fixture::new(name).config(
        "version = 1\n\n\
         [[pattern]]\n\
         id = \"md-quoted-span\"\n\
         regex = '\"[^\"]*\"'\n\n\
         [[verdict]]\n\
         id = \"tool reach absent\"\n\
         gloss = \"a by-path invocation depends on a tool it will not get\"\n\
         class = \"Every hook here fails open, so an absent tool allows silently instead of erroring.\"\n\n\
         [[verdict.route]]\n\
         id = \"prose read first\"\n\
         kind = \"document\"\n\
         target = \"AGENTS.md\"\n\n\
         [[verdict]]\n\
         id = \"tool list empty\"\n\
         gloss = \"the manifest pins nothing, so the question cannot be asked\"\n\
         class = \"With the pinned set empty every by-path hook passes vacuously.\"\n\n\
         [[verdict.route]]\n\
         id = \"prose read first\"\n\
         kind = \"document\"\n\
         target = \"AGENTS.md\"\n\n\
         [[rule]]\n\
         id = \"hook-pin-check\"\n\
         kind = \"policy\"\n\
         scope = \"tree\"\n\
         line_sources = [\".claude/settings.json\", \"mise.toml\", \"mise-tasks/*.sh\"]\n\
         module = \"policy/hook-pin-check.rego\"\n\
         severity = \"deny\"\n",
    );
    let mut hooks = String::new();
    for command in registrations {
        writeln!(
            hooks,
            "      {{ \"type\": \"command\", \"command\": \"{command}\" }},"
        )
        .unwrap();
    }
    let settings = format!("{{\n  \"hooks\": {{\n    \"PreToolUse\": [\n{hooks}    ]\n  }}\n}}\n");
    fixture = fixture
        .file("AGENTS.md", "the consumer's own authority\n")
        .file(".claude/settings.json", &settings)
        .file("mise.toml", manifest);
    for (path, body) in scripts {
        fixture = fixture.file(path, body);
    }
    let dir = fixture.git().build();
    common::write(
        &dir,
        "policy/hook-pin-check.rego",
        &std::fs::read_to_string(common::at_root("policy/hook-pin-check.rego")).unwrap(),
    );
    git_in(&dir, &["add", "-A"]);
    git_in(&dir, &["commit", "-q", "-m", "base"]);
    dir
}

fn check(dir: &Path) -> Output {
    run(dir, &["check", "--rule", "hook-pin-check"])
}

const MANIFEST: &str =
    "[tools]\nzizmor = \"1.0\"\n\"aqua:jqlang/jq\" = \"1.7\"\n\n[env]\nX = \"1\"\n";

#[test]
fn a_by_path_hook_shelling_out_to_a_pinned_tool_is_refused() {
    let dir = pin_repo(
        "pin-by-path-pinned",
        &["mise-tasks/guard.sh"],
        MANIFEST,
        &[(
            "mise-tasks/guard.sh",
            "#!/usr/bin/env bash\njq -r '.x' <<<\"$payload\"\n",
        )],
    );
    let output = check(&dir);
    assert_eq!(output.status.code(), Some(2), "{}", stdout(&output));
    let text = stdout(&output);
    assert!(
        text.contains("guard.sh") && text.contains("jq"),
        "the finding names the task and the tool: {text:?}"
    );
}

#[test]
fn a_runner_registration_is_not_judged() {
    // THE PAIRING IS THE DEFECT, not the tool: the same script through the task
    // runner gets its env by construction.
    let dir = pin_repo(
        "pin-via-runner",
        &["mise run -q mise-tasks/guard.sh"],
        MANIFEST,
        &[(
            "mise-tasks/guard.sh",
            "#!/usr/bin/env bash\njq -r '.x' <<<\"$payload\"\n",
        )],
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
fn a_by_path_hook_using_no_pinned_tool_passes() {
    let dir = pin_repo(
        "pin-clean",
        &["mise-tasks/guard.sh"],
        MANIFEST,
        &[(
            "mise-tasks/guard.sh",
            "#!/usr/bin/env bash\nbatten hook claude-code\n",
        )],
    );
    let output = check(&dir);
    assert_eq!(output.status.code(), Some(0), "{}", stdout(&output));
}

#[test]
fn a_declared_exemption_passes() {
    let dir = pin_repo(
        "pin-exempt",
        &["mise-tasks/guard.sh"],
        MANIFEST,
        &[(
            "mise-tasks/guard.sh",
            "#!/usr/bin/env bash\n#PIN-OK: jq\ncommand -v jq >/dev/null || exit 2\njq -r '.x'\n",
        )],
    );
    let output = check(&dir);
    assert_eq!(output.status.code(), Some(0), "{}", stdout(&output));
}

#[test]
fn an_exemption_for_another_tool_does_not_cover_this_one() {
    let dir = pin_repo(
        "pin-exempt-other",
        &["mise-tasks/guard.sh"],
        MANIFEST,
        &[(
            "mise-tasks/guard.sh",
            "#!/usr/bin/env bash\n#PIN-OK: zizmor\njq -r '.x'\n",
        )],
    );
    let output = check(&dir);
    assert_eq!(output.status.code(), Some(2), "{}", stdout(&output));
}

#[test]
fn mentioning_a_tool_in_a_comment_is_not_depending_on_it() {
    let dir = pin_repo(
        "pin-comment",
        &["mise-tasks/guard.sh"],
        MANIFEST,
        &[(
            "mise-tasks/guard.sh",
            "#!/usr/bin/env bash\n# this used to call jq and no longer does\nbatten hook claude-code\n",
        )],
    );
    let output = check(&dir);
    assert_eq!(output.status.code(), Some(0), "{}", stdout(&output));
}

#[test]
fn a_substring_of_another_word_is_not_a_call() {
    let dir = pin_repo(
        "pin-substring",
        &["mise-tasks/guard.sh"],
        MANIFEST,
        &[(
            "mise-tasks/guard.sh",
            "#!/usr/bin/env bash\njqx --render file\ncat file | myjq -r '.x'\n",
        )],
    );
    let output = check(&dir);
    assert_eq!(output.status.code(), Some(0), "{}", stdout(&output));
}

#[test]
fn the_pinned_set_is_read_from_the_manifest() {
    // Pinning a tool enrols it here with no second edit — the case that keeps
    // this from becoming a restated list.
    let dir = pin_repo(
        "pin-read-from-manifest",
        &["mise-tasks/guard.sh"],
        "[tools]\nshellcheck = \"0.10\"\n",
        &[(
            "mise-tasks/guard.sh",
            "#!/usr/bin/env bash\nshellcheck -x \"$0\"\n",
        )],
    );
    let output = check(&dir);
    assert_eq!(output.status.code(), Some(2), "{}", stdout(&output));
}

#[test]
fn a_manifest_pinning_nothing_is_not_clean() {
    // COULD NOT LOOK, never a verdict: with the pinned set empty every by-path
    // hook passes vacuously.
    let dir = pin_repo(
        "pin-empty-tools",
        &["mise-tasks/guard.sh"],
        "[env]\nX = \"1\"\n",
        &[("mise-tasks/guard.sh", "#!/usr/bin/env bash\njq -r '.x'\n")],
    );
    let output = check(&dir);
    assert_eq!(output.status.code(), Some(2), "{}", stdout(&output));
}

#[test]
fn output_is_pointer_only() {
    let dir = pin_repo(
        "pin-pointer-only",
        &["mise-tasks/guard.sh"],
        MANIFEST,
        &[(
            "mise-tasks/guard.sh",
            "#!/usr/bin/env bash\njq -r '.distinctive_selector' <<<\"$payload\"\n",
        )],
    );
    let output = check(&dir);
    assert_eq!(output.status.code(), Some(2));
    assert!(
        !stdout(&output).contains("distinctive_selector"),
        "the script's content is payload: {:?}",
        stdout(&output)
    );
}

#[test]
fn this_repositorys_own_registrations_pass() {
    // The self-consumption case the retiring suite ended on.
    let output =
        common::run_at_real_root(&common::at_root(""), &["check", "--rule", "hook-pin-check"]);
    assert_eq!(
        output.status.code(),
        Some(0),
        "a by-path hook here depends on a pinned tool: {}",
        stdout(&output)
    );
}
