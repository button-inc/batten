//! `policy/shell-banned.rego` over the compiled binary (CLOUD-1925).
//!
//! The module's own `test_` rules pin the predicate over a fabricated input. What
//! only this tier can show is that the ENGINE builds that input — `lines` for the
//! head, `base-lines` for the base, `added` over the whole tree — for exactly the
//! paths the row declares, so the refusals below come from a real diff against a
//! real `origin/main` (CLOUD-845's class: a module can pass every `with input as`
//! case and decide nothing on a real tree).
//!
//! The module was also replayed against this repository's history before it
//! landed: #962's squash `4f61a1c` is refused (`task write refused` on
//! `mise.toml` and 41 `task add refused` pointers, exit 2), as is `f8b18c5`;
//! `771651d` and `c7ba001`, which added no shell, pass. That replay needs the
//! real history, which a shallow runner does not carry, so its shapes are
//! restated here as synthetic fixtures rather than read from git.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::Output;

use common::{Fixture, git_in, run, stdout};

const RULE: &str = "shell write other";

/// The four verdicts and the rule row, as this repository declares them — the
/// module refuses to load against a registry that lacks any token it raises.
fn config() -> String {
    let mut text = String::from("version = 1\n");
    for (id, gloss) in [
        ("task write refused", "shell lines rose"),
        ("task add refused", "a task gained shell"),
        ("step write refused", "workflow shell rose"),
        ("shell place refused", "a shell file was added"),
    ] {
        let _ = write!(
            text,
            "\n[[verdict]]\nid = \"{id}\"\ngloss = \"{gloss}\"\nclass = \"{gloss}.\"\n\n\
             [[verdict.route]]\nid = \"rule read first\"\nkind = \"document\"\n\
             target = \"policy/shell-banned.rego\"\n"
        );
    }
    let _ = write!(
        text,
        "\n[[rule]]\nid = \"{RULE}\"\nkind = \"policy\"\nscope = \"tree\"\n\
         base = \"origin/main\"\ndelta_sources = [\"**\"]\n\
         line_sources = [\"mise.toml\", \".github/workflows/*.yml\", \"mise-tasks/**\", \".claude/hooks/**\"]\n\
         module = \"policy/shell-banned.rego\"\nseverity = \"deny\"\n"
    );
    text
}

/// A repository whose `origin/main` holds `files`, with the real module.
fn repo(name: &str, files: &[(&str, &str)]) -> PathBuf {
    let mut fixture = Fixture::new(name).config(&config());
    for (path, text) in files {
        fixture = fixture.file(path, text);
    }
    let dir = fixture.git().build();
    common::write(
        &dir,
        "policy/shell-banned.rego",
        &std::fs::read_to_string(common::at_root("policy/shell-banned.rego")).unwrap(),
    );
    git_in(&dir, &["add", "-A"]);
    git_in(&dir, &["commit", "-q", "-m", "base"]);
    git_in(&dir, &["update-ref", "refs/remotes/origin/main", "HEAD"]);
    dir
}

/// Write `text` at `path` and commit it as the branch's change.
fn change(dir: &Path, path: &str, text: &str) {
    common::write(dir, path, text);
    git_in(dir, &["add", "-A"]);
    git_in(dir, &["commit", "-q", "-m", "the change"]);
}

fn check(dir: &Path) -> Output {
    run(dir, &["check", "--rule", RULE])
}

/// A `mise.toml` of `(name, body lines)` tasks, each a `'''` body.
fn manifest(tasks: &[(&str, &[&str])]) -> String {
    let mut text = String::new();
    for (name, body) in tasks {
        let _ = write!(text, "[tasks.{name}]\nrun = '''\n");
        for line in *body {
            text.push_str(line);
            text.push('\n');
        }
        text.push_str("'''\n\n");
    }
    text
}

/// The refusals as `(path, line)` pointers, read off `-J`.
///
/// The four arms are told apart by their pointer rather than by a verdict
/// token, which `check` does not emit: `task write refused` points at
/// `mise.toml` with no line, `task add refused` at the new task's header line,
/// and the other two at their own paths.
fn findings(dir: &Path) -> (Option<i32>, Vec<(String, Option<u64>)>) {
    let output = run(dir, &["check", "-J", "--rule", RULE]);
    let report: serde_json::Value = serde_json::from_str(&stdout(&output)).unwrap();
    let found = report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|finding| finding["rule"] == RULE)
        .map(|finding| {
            (
                finding["path"].as_str().unwrap_or_default().to_owned(),
                finding["line"].as_u64(),
            )
        })
        .collect();
    (output.status.code(), found)
}

/// `task write refused`'s pointer: the manifest, no line.
fn grew(found: &[(String, Option<u64>)]) -> bool {
    found.contains(&("mise.toml".to_owned(), None))
}

/// `task add refused`'s pointer: the manifest at the task header's line.
fn gained_at(found: &[(String, Option<u64>)], line: u64) -> bool {
    found.contains(&("mise.toml".to_owned(), Some(line)))
}

#[test]
fn a_program_moved_inline_is_refused() {
    // #962's shape: a file deleted, its body re-housed in a task string.
    let dir = repo(
        "shell-ban-moved-inline",
        &[
            ("mise.toml", &manifest(&[("a", &["echo a"])])),
            ("mise-tasks/b.sh", "#!/usr/bin/env bash\nset -e\necho b\n"),
        ],
    );
    std::fs::remove_file(dir.join("mise-tasks/b.sh")).unwrap();
    change(
        &dir,
        "mise.toml",
        &manifest(&[("a", &["echo a"]), ("b", &["set -e", "echo b"])]),
    );
    // `a` spans lines 1-4 and a blank, so task `b`'s header is line 6.
    let (code, found) = findings(&dir);
    assert_eq!(code, Some(2), "{found:?}");
    assert!(grew(&found), "the line count rose: {found:?}");
    assert!(gained_at(&found, 6), "task b gained shell: {found:?}");
}

#[test]
fn a_task_body_grown_by_one_line_is_refused() {
    let dir = repo(
        "shell-ban-grown",
        &[("mise.toml", &manifest(&[("a", &["echo one"])]))],
    );
    change(
        &dir,
        "mise.toml",
        &manifest(&[("a", &["echo one", "echo two"])]),
    );
    let (code, found) = findings(&dir);
    assert_eq!(code, Some(2), "{found:?}");
    assert!(grew(&found), "{found:?}");
    assert!(
        !found.iter().any(|(_, line)| line.is_some()),
        "no task gained shell it did not have: {found:?}"
    );
}

#[test]
fn a_body_moved_into_a_new_task_is_refused_even_when_the_total_falls() {
    let dir = repo(
        "shell-ban-relocated",
        &[(
            "mise.toml",
            &manifest(&[("a", &["echo 1", "echo 2", "echo 3"])]),
        )],
    );
    change(&dir, "mise.toml", &manifest(&[("b", &["echo 1"])]));
    let (code, found) = findings(&dir);
    assert_eq!(code, Some(2), "{found:?}");
    assert!(
        !grew(&found),
        "the total fell, so growth is not the arm: {found:?}"
    );
    assert!(
        gained_at(&found, 1),
        "the new task's header is the pointer: {found:?}"
    );
}

#[test]
fn an_in_place_fix_that_does_not_grow_a_body_is_admitted() {
    let dir = repo(
        "shell-ban-fix",
        &[("mise.toml", &manifest(&[("a", &["echo one", "echo two"])]))],
    );
    change(
        &dir,
        "mise.toml",
        &manifest(&[("a", &["echo one", "echo 2"])]),
    );
    let output = check(&dir);
    assert_eq!(output.status.code(), Some(0), "{}", stdout(&output));
}

#[test]
fn a_deleted_body_is_admitted() {
    let dir = repo(
        "shell-ban-deleted",
        &[(
            "mise.toml",
            &manifest(&[("a", &["echo a"]), ("b", &["echo b"])]),
        )],
    );
    change(&dir, "mise.toml", &manifest(&[("a", &["echo a"])]));
    assert_eq!(check(&dir).status.code(), Some(0));
}

#[test]
fn a_plain_argv_one_liner_is_admitted() {
    let base = "[tasks.a]\nrun = \"cargo build\"\n";
    let dir = repo("shell-ban-argv", &[("mise.toml", base)]);
    change(
        &dir,
        "mise.toml",
        &format!("{base}\n[tasks.b]\nrun = \"cargo nextest run\"\n"),
    );
    let output = check(&dir);
    assert_eq!(output.status.code(), Some(0), "{}", stdout(&output));
}

#[test]
fn a_shell_one_liner_added_to_a_task_is_refused() {
    let base = "[tasks.a]\nrun = \"cargo build\"\n";
    let dir = repo("shell-ban-one-liner", &[("mise.toml", base)]);
    change(
        &dir,
        "mise.toml",
        &format!("{base}\n[tasks.b]\nrun = \"cargo build && cargo test\"\n"),
    );
    let (code, found) = findings(&dir);
    assert_eq!(code, Some(2), "{found:?}");
    assert!(gained_at(&found, 4), "task b's header: {found:?}");
}

#[test]
fn a_workflow_run_block_grown_is_refused() {
    let base = "jobs:\n  a:\n    steps:\n      - run: |\n          echo one\n      - uses: x\n";
    let dir = repo("shell-ban-workflow", &[(".github/workflows/ci.yml", base)]);
    change(
        &dir,
        ".github/workflows/ci.yml",
        "jobs:\n  a:\n    steps:\n      - run: |\n          echo one\n          echo two\n      - uses: x\n",
    );
    let output = check(&dir);
    assert_eq!(output.status.code(), Some(2), "{}", stdout(&output));
    assert!(
        stdout(&output).contains(".github/workflows/ci.yml"),
        "{}",
        stdout(&output)
    );
}

#[test]
fn a_single_command_workflow_step_is_admitted() {
    let base = "jobs:\n  a:\n    steps:\n      - run: mise run verify\n";
    let dir = repo("shell-ban-step", &[(".github/workflows/ci.yml", base)]);
    change(
        &dir,
        ".github/workflows/ci.yml",
        &format!("{base}      - run: mise run lint\n"),
    );
    assert_eq!(check(&dir).status.code(), Some(0));
}

#[test]
fn an_added_shell_script_is_refused() {
    let dir = repo("shell-ban-script", &[("README.md", "x\n")]);
    change(&dir, "scripts/deploy.sh", "echo deploy\n");
    let output = check(&dir);
    assert_eq!(output.status.code(), Some(2), "{}", stdout(&output));
    assert!(
        stdout(&output).contains("scripts/deploy.sh"),
        "{}",
        stdout(&output)
    );
}

#[test]
fn an_added_shebang_program_under_a_declared_directory_is_refused() {
    let dir = repo("shell-ban-shebang", &[("README.md", "x\n")]);
    change(
        &dir,
        "mise-tasks/run-thing",
        "#!/usr/bin/env bash\necho thing\n",
    );
    let output = check(&dir);
    assert_eq!(output.status.code(), Some(2), "{}", stdout(&output));
}

#[test]
fn an_exempt_file_is_admitted() {
    let dir = repo("shell-ban-exempt", &[("README.md", "x\n")]);
    change(&dir, "install.sh", "#!/bin/sh\necho install\n");
    assert_eq!(check(&dir).status.code(), Some(0));
}

/// THE EXEMPTION SET, ASSERTED EXACTLY. Growing it is how a ban becomes a
/// hatch, so the set is pinned here and a change to it is a failing test a
/// reviewer must read — never a quiet widening inside the module.
#[test]
fn the_exemption_set_is_exactly_the_files_that_must_be_shell() {
    let module = std::fs::read_to_string(common::at_root("policy/shell-banned.rego")).unwrap();
    let start = module.find("stays_bash := {").unwrap();
    let end = start + module[start..].find('}').unwrap();
    let mut declared: Vec<&str> = module[start..end]
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            line.strip_prefix('"')?.strip_suffix("\",")
        })
        .collect();
    declared.sort_unstable();
    assert_eq!(
        declared,
        [
            ".claude/hooks/git-hook.sh",
            "completions/batten.bash",
            "install.sh",
            "setup.sh",
        ]
    );
}

/// The real tree, against its own base: this repository is clean today, so a
/// module that refused its own checkout would be switched off on the first run.
#[test]
fn this_repositorys_own_tree_passes() {
    let output = run(&common::at_root("."), &["check", "--rule", RULE]);
    assert_eq!(output.status.code(), Some(0), "{}", stdout(&output));
}
