//! No shell program hands awk a regex through `-v`, over the compiled binary
//! (ported from `mise-tasks/awk-regex-check.sh` under CLOUD-843).
//!
//! **What is decidable only here.** `policy/awk-regex.rego` carries load-time
//! cases pinning the predicate, and each supplies `input.tree.lines` with `with
//! input as` — fabricating the corpus the gate is about. Only a real repository
//! shows the engine handing this module the shell it is meant to scan, which is
//! the anti-vacuity half: a scan that matched no file reports "no regex reaches
//! awk through -v" over nothing and reads as coverage (CLOUD-418).
//
// carried: mise-tasks/awk-regex-check.sh policy/awk-regex.rego crates/batten/tests/it/awk_regex.rs
// carried: tests/awk-regex-check.bats policy/awk-regex.rego crates/batten/tests/it/awk_regex.rs
//
// carried: "this repo's own tasks pass today" policy/awk-regex.rego
// carried: "the real bug: a -v name used with ~ is reported" policy/awk-regex.rego
// carried: "the report names file and line, not the whole command" policy/awk-regex.rego
// carried: "match() is regex position too" policy/awk-regex.rego
// carried: "a -v value compared with == is fine — that is most of its use" policy/awk-regex.rego
// carried: "a -v value printed or counted is fine" policy/awk-regex.rego
// carried: "an inline regex in the awk program is the recommended form, not a finding" policy/awk-regex.rego
// carried: "a name that merely PREFIXES another is not confused for it" policy/awk-regex.rego
// carried: "several -v assignments on one line are each judged" policy/awk-regex.rego
// carried: "a tree with no awk at all passes rather than erroring" policy/awk-regex.rego
//
// changed: "an untracked file is not judged — the gate reads what is committed" policy/awk-regex.rego the shell fed itself `git ls-files`, so the index was the subject and the case pinned it. `input.tree.lines` is resolved from a declared glob over the working-tree walk, which honours `.gitignore` and explicitly is not the index (`facts.rs`), and nothing available to a module expresses index membership. The successor judges an uncommitted program too — stricter, fail-closed, and the same difference `policy/module-map.rego` records for its own port

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::{Path, PathBuf};
use std::process::Output;

use common::{Fixture, git_in, run, stdout};

fn awk_repo(name: &str, program: &str) -> PathBuf {
    let dir = Fixture::new(name)
        .config(
            "version = 1\n\n\
             [[pattern]]\n\
             id = \"awk-v-assignment\"\n\
             regex = '-v[[:space:]]*([A-Za-z_][A-Za-z0-9_]*)='\n\n\
             [[pattern]]\n\
             id = \"leading-identifier\"\n\
             regex = '^[A-Za-z_][A-Za-z0-9_]*'\n\n\
             [[verdict]]\n\
             id = \"pattern carry unsafe\"\n\
             gloss = \"a command is spelled in a way whose behaviour is not defined across implementations\"\n\
             class = \"Escape processing on a -v assignment differs between awk implementations, so the same pattern is two different regexes.\"\n\n\
             [[verdict.route]]\n\
             id = \"prose read first\"\n\
             kind = \"document\"\n\
             target = \"AGENTS.md\"\n\n\
             [[rule]]\n\
             id = \"awk-regex\"\n\
             kind = \"policy\"\n\
             scope = \"tree\"\n\
             line_sources = [\"mise-tasks/**\"]\n\
             module = \"policy/awk-regex.rego\"\n\
             severity = \"deny\"\n",
        )
        .file("AGENTS.md", "the consumer's own authority\n")
        .file("mise-tasks/demo.sh", program)
        .git()
        .build();
    common::write(
        &dir,
        "policy/awk-regex.rego",
        &std::fs::read_to_string(common::at_root("policy/awk-regex.rego")).unwrap(),
    );
    git_in(&dir, &["add", "-A"]);
    git_in(&dir, &["commit", "-q", "-m", "base"]);
    dir
}

fn check(dir: &Path) -> Output {
    run(dir, &["check", "--rule", "awk-regex"])
}

#[test]
fn the_real_bug_a_v_name_used_with_tilde_is_reported() {
    let dir = awk_repo(
        "awk-regex-tilde",
        "#!/usr/bin/env bash\nawk -v re=\"$p\" '$0 ~ re' file\n",
    );
    let output = check(&dir);
    assert_eq!(output.status.code(), Some(2), "{}", stdout(&output));
    let text = stdout(&output);
    assert!(
        text.contains("mise-tasks/demo.sh"),
        "the report names the file: {text:?}"
    );
    assert!(
        !text.contains("$0 ~ re"),
        "and not the whole command, which is payload: {text:?}"
    );
}

#[test]
fn match_is_regex_position_too() {
    let dir = awk_repo(
        "awk-regex-match",
        "#!/usr/bin/env bash\nawk -v re=\"$p\" '{ if (match($0, re)) print }' file\n",
    );
    assert_eq!(check(&dir).status.code(), Some(2));
}

#[test]
fn a_value_compared_with_equals_is_fine_over_the_binary() {
    // Most of `-v`'s use, and the half the gate must not refuse.
    let dir = awk_repo(
        "awk-regex-equals",
        "#!/usr/bin/env bash\nawk -v want=\"$p\" '$1 == want' file\n",
    );
    let output = check(&dir);
    assert_eq!(output.status.code(), Some(0), "{}", stdout(&output));
}

#[test]
fn a_name_that_prefixes_another_is_not_confused_for_it() {
    // DISCRIMINATING. The shell guarded this boundary with a trailing character
    // class on a per-name regex; a module may not build one at all, so the port
    // reads the identifier after `~` and compares it WHOLE. A successor that
    // used `startswith` instead passes every other case here and fails this one.
    let dir = awk_repo(
        "awk-regex-prefix",
        "#!/usr/bin/env bash\nawk -v re=\"$p\" '$0 ~ rex' file\n",
    );
    let output = check(&dir);
    assert_eq!(
        output.status.code(),
        Some(0),
        "`re` was confused for `rex`: {}",
        stdout(&output)
    );
}

#[test]
fn an_inline_regex_is_the_recommended_form_not_a_finding() {
    let dir = awk_repo(
        "awk-regex-inline",
        "#!/usr/bin/env bash\nawk '$0 ~ /^ISSUE-[0-9]+$/' file\n",
    );
    assert_eq!(check(&dir).status.code(), Some(0));
}

#[test]
fn a_tree_with_no_awk_at_all_passes_rather_than_erroring() {
    let dir = awk_repo(
        "awk-regex-no-awk",
        "#!/usr/bin/env bash\ngrep -v thing file\n",
    );
    assert_eq!(check(&dir).status.code(), Some(0));
}

#[test]
fn this_repos_own_programs_pass_today() {
    let output = common::run_at_real_root(&common::at_root(""), &["check", "--rule", "awk-regex"]);
    assert_eq!(
        output.status.code(),
        Some(0),
        "a regex reaches awk through -v in this tree: {}",
        stdout(&output)
    );
}
