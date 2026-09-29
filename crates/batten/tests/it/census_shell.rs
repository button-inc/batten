//! `batten census shell` over the compiled binary (CLOUD-843).
//!
//! # The case the verb exists for: the census and the ban agree
//!
//! The retirement's rule is that every wave moves the census down, and the ban
//! (`policy/shell-banned.rego`) is what refuses a wave that moves it up. Two
//! readings of "a shell line" would make those claims able to disagree — a wave
//! could read as progress to one and as growth to the other. So the census does
//! not choose its own detection; it carries the ban's, and this tier proves the
//! two count the same over one fixture carrying every shape either can see.
//!
//! **How a count is read out of a gate that only reports growth.** The ban fires
//! `task write refused` exactly when the head's count exceeds the base's. So for a
//! head the census counts at `c`, a base of `c` plain lines must NOT fire and a
//! base of `c - 1` MUST. Together those pin the ban's count of the head to exactly
//! `c` — equality through the gate's own predicate, with nothing parsed out of a
//! fingerprint. The workflow arm is the same argument over `step write refused`,
//! and the file arm compares the `shell place refused` pointers as a set.
//!
//! The exit assertion is **2** for a refusal throughout. The retiring shell corpus
//! spells a violation `1`; carrying that inversion in is the defect CLOUD-1718
//! names.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use common::{Fixture, git_in, run, stdout};

const RULE: &str = "shell write other";

/// The ban's row and vocabulary as this repository declares them, plus the
/// census table over the same files.
///
/// `exempt` is `install.sh` alone — a member of the ban's own `stays_bash` — so
/// the one exemption the fixture exercises is one BOTH readings exempt.
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
         module = \"policy/shell-banned.rego\"\nseverity = \"deny\"\n\
         \n[census.shell]\n\
         workflows = [\".github/workflows/*.yml\"]\n\
         exempt = [\"install.sh\"]\n\
         \n[[census.shell.manifest]]\n\
         path = \"mise.toml\"\n\
         keys = [\"run\"]\n\
         unit = \"[tasks.\"\n"
    );
    text
}

/// A manifest whose one task carries `lines` plain body lines — the shape both
/// readings trivially count one per line.
fn plain_manifest(lines: usize) -> String {
    let mut text = String::from("[tasks.plain]\nrun = '''\n");
    for i in 0..lines {
        let _ = writeln!(text, "echo {i}");
    }
    text.push_str("'''\n");
    text
}

/// A workflow whose one step carries `lines` plain block lines.
fn plain_workflow(lines: usize) -> String {
    let mut text = String::from("name: ci\njobs:\n  a:\n    steps:\n      - run: |\n");
    for i in 0..lines {
        let _ = writeln!(text, "          echo {i}");
    }
    text.push_str("      - uses: x\n");
    text
}

/// Every shape either reading can see, and several it must not.
///
/// Counted: a `'''` body with a comment and a blank inside it; a `"""` body; a
/// one-liner with a pipe, one with a `VAR=` prefix and one with a `;`; an array's
/// shell entry; a one-liner BEFORE any task header (a lone line, which the ban
/// counts and attributes to no task).
///
/// Not counted: a plain argv one-liner; a quoted keyword (the first word keeps
/// its quote, so `"set -e"` is not a keyword to either reading); an array's plain
/// entry; a body that closes on its own opening line; a task with no shell.
const TRICKY_MANIFEST: &str = "\
run = \"a | b\"

[tasks.body]
run = '''
# why this exists
set -e

echo one
'''

[tasks.dquote]
run = \"\"\"
echo two
echo three
\"\"\"

[tasks.pipe]
run = \"cargo build | tee log\"

[tasks.env]
run = \"FOO=1 cargo test\"

[tasks.semi]
run = \"cargo build; cargo test\"

[tasks.array]
run = [
  \"cargo build\",
  \"a && b\",
]

[tasks.argv]
run = \"cargo nextest run\"

[tasks.quoted-keyword]
run = \"set -e\"

[tasks.inline]
run = '''echo closed'''
";

/// Blocks by indentation with a comment and a blank inside, a folded block, a
/// one-liner with shell syntax, a single-command step, and a trigger that is not
/// a step.
const TRICKY_WORKFLOW: &str = "\
name: ci
on:
  workflow_run:
    workflows: [other]
jobs:
  a:
    steps:
      - run: |
          echo one

          # a comment
          echo two
      - name: folded
        run: >
          echo three
          echo four
      - run: mise run verify
      - run: a && b
      - uses: x
";

/// A repository whose `origin/main` carries `manifest` and `workflow`, with the
/// real module.
fn repo(name: &str, manifest: &str, workflow: &str) -> PathBuf {
    let dir = Fixture::new(name)
        .config(&config())
        .file("mise.toml", manifest)
        .file(".github/workflows/ci.yml", workflow)
        .file("README.md", "x\n")
        .git()
        .build();
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

/// Commit the tricky head over whatever the base carried: the manifest, the
/// workflow, and one shell file of each kind the ban can see.
fn tricky_head(dir: &Path) {
    common::write(dir, "mise.toml", TRICKY_MANIFEST);
    common::write(dir, ".github/workflows/ci.yml", TRICKY_WORKFLOW);
    common::write(
        dir,
        "scripts/deploy.sh",
        "#!/bin/sh\n# comment\n\necho deploy\n",
    );
    common::write(dir, "tests/a.bats", "@test \"x\" {\n  true\n}\n");
    common::write(
        dir,
        "mise-tasks/run-thing",
        "#!/usr/bin/env bash\nset -e\necho thing\n",
    );
    common::write(
        dir,
        "mise-tasks/helper.py",
        "#!/usr/bin/env python3\nprint(1)\n",
    );
    common::write(dir, "install.sh", "#!/bin/sh\necho install\n");
    git_in(dir, &["add", "-A"]);
    git_in(dir, &["commit", "-q", "-m", "the change"]);
}

/// The ban's refusals as `(path, line)` pointers, read off `-J`.
fn ban(dir: &Path) -> (Option<i32>, Vec<(String, Option<u64>)>) {
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

/// The census's `-J` document.
fn census(dir: &Path) -> serde_json::Value {
    let output = run(dir, &["census", "shell", "-J"]);
    assert_eq!(output.status.code(), Some(0), "{}", stdout(&output));
    serde_json::from_str(&stdout(&output)).unwrap()
}

fn total(document: &serde_json::Value, key: &str) -> usize {
    usize::try_from(document["totals"][key].as_u64().unwrap()).unwrap()
}

#[test]
fn the_census_counts_the_fixture_as_the_shapes_say() {
    // The census's own reading, pinned first so the agreement cases below compare
    // against a number a reader can check by hand: the manifest carries
    // 1 lone + 2 (body) + 2 (dquote) + 1 + 1 + 1 + 1 (array) = 9 shell lines, the
    // workflow 2 + 2 + 1 = 5, and the shell files 1 + 3 + 2 = 6 code lines (a
    // shebang is a comment), with `install.sh` apart.
    let dir = repo("census-counted", &plain_manifest(1), &plain_workflow(1));
    tricky_head(&dir);
    let document = census(&dir);
    assert_eq!(total(&document, "manifests"), 9, "{document}");
    assert_eq!(total(&document, "steps"), 5, "{document}");
    assert_eq!(total(&document, "files"), 6, "{document}");
    assert_eq!(total(&document, "exempt"), 1, "{document}");
    assert_eq!(total(&document, "total"), 20, "{document}");
    let exempt: Vec<&str> = document["exempt"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| entry["path"].as_str().unwrap())
        .collect();
    assert_eq!(exempt, ["install.sh"]);
}

#[test]
fn a_linked_worktree_is_measured_and_not_the_main_checkout_beside_it() {
    // The files a census counts are the ones this BRANCH changes, so a linked
    // worktree must read its own. Rooted on the repository's common dir instead,
    // a retirement package's worktree reported its base's census unchanged
    // while every unit it retired was gone from its tree — the measurement a
    // wave's "moved down" claim rests on, silently taken from the wrong tree.
    let dir = repo("census-worktree", &plain_manifest(1), &plain_workflow(1));
    let base = census(&dir);
    let linked = dir.with_file_name(format!(
        "{}-linked",
        dir.file_name().unwrap().to_string_lossy()
    ));
    let _ = std::fs::remove_dir_all(&linked);
    git_in(
        &dir,
        &[
            "worktree",
            "add",
            "-q",
            "-b",
            "change",
            linked.to_str().unwrap(),
        ],
    );
    tricky_head(&linked);
    let measured = census(&linked);
    assert_eq!(total(&measured, "manifests"), 9, "{measured}");
    assert_ne!(
        total(&base, "manifests"),
        9,
        "the main checkout still carries the base manifest, so the two must differ: {base}"
    );
    assert_eq!(
        census(&dir)["totals"],
        base["totals"],
        "and the main checkout's own census is unmoved by its sibling"
    );
}

#[test]
fn the_ban_counts_the_manifest_exactly_as_the_census_does() {
    // Equality through the gate's own predicate — see the module header. Nine is
    // the census's count, pinned by the case above.
    let at = repo(
        "census-agree-manifest-at",
        &plain_manifest(9),
        &plain_workflow(5),
    );
    tricky_head(&at);
    let (_, found) = ban(&at);
    assert!(
        !found.contains(&("mise.toml".to_owned(), None)),
        "a base of 9 plain lines is not exceeded, so the ban counts the head at 9 or fewer: \
         {found:?}"
    );

    let under = repo(
        "census-agree-manifest-under",
        &plain_manifest(8),
        &plain_workflow(5),
    );
    tricky_head(&under);
    let (code, found) = ban(&under);
    assert_eq!(code, Some(2), "{found:?}");
    assert!(
        found.contains(&("mise.toml".to_owned(), None)),
        "a base of 8 is exceeded, so the ban counts the head at 9 or more: {found:?}"
    );
}

#[test]
fn the_ban_counts_the_workflow_exactly_as_the_census_does() {
    let at = repo(
        "census-agree-workflow-at",
        &plain_manifest(9),
        &plain_workflow(5),
    );
    tricky_head(&at);
    let (_, found) = ban(&at);
    assert!(
        !found.contains(&(".github/workflows/ci.yml".to_owned(), None)),
        "a base of 5 block lines is not exceeded: {found:?}"
    );

    let under = repo(
        "census-agree-workflow-under",
        &plain_manifest(9),
        &plain_workflow(4),
    );
    tricky_head(&under);
    let (code, found) = ban(&under);
    assert_eq!(code, Some(2), "{found:?}");
    assert!(
        found.contains(&(".github/workflows/ci.yml".to_owned(), None)),
        "a base of 4 is exceeded: {found:?}"
    );
}

#[test]
fn the_tasks_the_ban_says_gained_shell_are_the_units_the_census_names() {
    // The per-task half: every unit the census names is a task the ban says
    // gained shell (the base's only task is `plain`), and the lone line before
    // any header is counted by both and attributed to no task by either.
    let dir = repo("census-agree-tasks", &plain_manifest(9), &plain_workflow(5));
    tricky_head(&dir);
    let (_, found) = ban(&dir);
    let gained: BTreeSet<u64> = found
        .iter()
        .filter(|(path, line)| path == "mise.toml" && line.is_some())
        .filter_map(|(_, line)| *line)
        .collect();
    let document = census(&dir);
    let units: BTreeSet<u64> = document["manifests"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|entry| entry.get("unit").is_some())
        .map(|entry| entry["line"].as_u64().unwrap())
        .collect();
    assert_eq!(gained, units, "{found:?} / {document}");
    let names: BTreeSet<&str> = document["manifests"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|entry| entry["unit"].as_str())
        .collect();
    assert_eq!(
        names,
        BTreeSet::from(["array", "body", "dquote", "env", "pipe", "semi"])
    );
    assert!(
        document["manifests"]
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| entry.get("unit").is_none() && entry["line"] == 1),
        "the lone line before any header stands alone: {document}"
    );
}

#[test]
fn the_files_the_ban_refuses_are_the_files_the_census_counts() {
    let dir = repo("census-agree-files", &plain_manifest(9), &plain_workflow(5));
    tricky_head(&dir);
    let (_, found) = ban(&dir);
    let refused: BTreeSet<String> = found
        .iter()
        .filter(|(path, line)| {
            line.is_none() && path != "mise.toml" && !path.starts_with(".github/")
        })
        .map(|(path, _)| path.clone())
        .collect();
    let document = census(&dir);
    let counted: BTreeSet<String> = document["files"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| entry["path"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(refused, counted, "{found:?} / {document}");
    assert!(
        !counted.contains("mise-tasks/helper.py"),
        "a shebang naming another language is not shell"
    );
}

#[test]
fn the_pointer_lines_carry_no_body() {
    // Pointer-only (rule 4): a path, a line, a unit's declared name and a count.
    let dir = repo("census-pointer", &plain_manifest(1), &plain_workflow(1));
    tricky_head(&dir);
    let output = run(&dir, &["census", "shell"]);
    assert_eq!(output.status.code(), Some(0));
    let text = stdout(&output);
    for body in ["echo", "cargo", "tee log", "FOO=1", "set -e", "@test"] {
        assert!(!text.contains(body), "{body} leaked: {text}");
    }
    assert!(text.contains("mise.toml:3 unit body 2\n"), "{text}");
    assert!(
        text.contains(".github/workflows/ci.yml:8 step 2\n"),
        "{text}"
    );
    assert!(text.contains("scripts/deploy.sh file 1\n"), "{text}");
    assert!(text.contains("install.sh exempt 1\n"), "{text}");
    assert!(
        text.ends_with("total 20 manifests=9 steps=5 files=6 exempt=1\n"),
        "{text}"
    );
}

#[test]
fn an_undeclared_census_is_a_usage_error_never_a_zero() {
    let dir = Fixture::new("census-undeclared")
        .config("version = 1\n")
        .file("run.sh", "echo x\n")
        .git()
        .base_commit()
        .build();
    let output = run(&dir, &["census", "shell", "-J"]);
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty(), "no document for nothing declared");
}

#[test]
fn an_inert_manifest_row_is_refused_at_load() {
    let dir = Fixture::new("census-inert")
        .config("version = 1\n\n[[census.shell.manifest]]\npath = \"m.toml\"\nkeys = []\n")
        .git()
        .base_commit()
        .build();
    assert_eq!(run(&dir, &["census", "shell"]).status.code(), Some(1));
}

#[test]
fn the_census_is_byte_stable() {
    let dir = repo("census-stable", &plain_manifest(1), &plain_workflow(1));
    tricky_head(&dir);
    let first = run(&dir, &["census", "shell", "-J"]).stdout;
    let second = run(&dir, &["census", "shell", "-J"]).stdout;
    assert_eq!(first, second);
}

/// THIS REPOSITORY'S EXEMPTIONS ARE THE BAN'S, EXACTLY. The census reads its
/// exempt list from `[census.shell]` and the ban from `stays_bash`; two lists that
/// could drift apart would let a file be exempt from the count and refused by the
/// gate, or the reverse.
#[test]
fn this_repositorys_exempt_list_is_the_bans_stays_bash() {
    let module = std::fs::read_to_string(common::at_root("policy/shell-banned.rego")).unwrap();
    let start = module.find("stays_bash := {").unwrap();
    let end = start + module[start..].find('}').unwrap();
    let banned: BTreeSet<String> = module[start..end]
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            Some(line.strip_prefix('"')?.strip_suffix("\",")?.to_owned())
        })
        .collect();
    let authority: toml::Value =
        toml::from_str(&std::fs::read_to_string(common::at_root("batten.toml")).unwrap()).unwrap();
    let exempt: BTreeSet<String> = authority["census"]["shell"]["exempt"]
        .as_array()
        .unwrap()
        .iter()
        .map(|glob| glob.as_str().unwrap().to_owned())
        .collect();
    assert_eq!(exempt, banned);
}

/// The real tree, under its own declaration: the census answers, and every
/// exempt file it names is one the ban exempts.
#[test]
fn this_repositorys_own_census_answers() {
    let output = common::run_at_real_root(&common::at_root("."), &["census", "shell", "-J"]);
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let document: serde_json::Value = serde_json::from_str(&stdout(&output)).unwrap();
    assert!(
        document["exempt"]
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| entry["path"] == "install.sh"),
        "{document}"
    );
}
