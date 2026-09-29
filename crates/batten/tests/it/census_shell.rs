//! `batten census shell` over the compiled binary (CLOUD-843).
//!
//! # The case the verb exists for: the census and the ban agree
//!
//! The retirement's rule is that every wave moves the census down, and the ban
//! (`shell-hygiene`'s `no-new-shell` preset module) is what refuses a wave that
//! moves it up. Since CLOUD-1994 both read one `[census.shell]` table, held at
//! load to the glob operators both matchers read alike, so they agree about WHERE
//! (bar `exempt` over a manifest or workflow, which only the census sets apart);
//! this tier proves they agree about WHAT. Two
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

/// The row enabling the ban's preset.
const RULE: &str = "shell hygiene on";

/// The predicate the ban publishes, which its findings name.
const PREDICATE: &str = "shell write other";

/// The row enabling the preset, plus the census table both readings share.
///
/// No `[[verdict]]` row: the ban's classes are vendored by the preset, and a
/// consumer declaring them again is refused at load.
fn config() -> String {
    let mut text = String::from("version = 1\n");
    let _ = write!(
        text,
        "\n[[rule]]\nid = \"{RULE}\"\nkind = \"policy\"\nscope = \"tree\"\n\
         preset = \"shell-hygiene\"\n\
         base = \"origin/main\"\ndelta_sources = [\"**\"]\n\
         documents = [\"batten.toml\"]\n\
         line_sources = [\"mise.toml\", \".github/workflows/*.yml\", \"mise-tasks/**\", \".claude/hooks/**\"]\n\
         severity = \"deny\"\n\
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

/// A repository whose `origin/main` carries `manifest` and `workflow`. The ban
/// ships inside the binary, so nothing else is installed.
fn repo(name: &str, manifest: &str, workflow: &str) -> PathBuf {
    Fixture::new(name)
        .config(&config())
        .file("mise.toml", manifest)
        .file(".github/workflows/ci.yml", workflow)
        .file("README.md", "x\n")
        .git()
        .base_commit()
        .build()
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
        .filter(|finding| finding["rule"] == PREDICATE)
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

/// THIS REPOSITORY'S BAN READS THE CENSUS'S OWN DECLARATION. There used to be a
/// second exempt list inside the ban's module, pinned equal to this table's;
/// since CLOUD-1994 the ban reads this table, so the property to hold is that
/// the enabling row hands it over at all. `shell_banned.rs` pins the exempt set
/// itself, and that every declared home is a line source.
#[test]
fn this_repositorys_ban_reads_the_census_declaration() {
    let authority: toml::Value =
        toml::from_str(&std::fs::read_to_string(common::at_root("batten.toml")).unwrap()).unwrap();
    let row = authority["rule"]
        .as_array()
        .unwrap()
        .iter()
        .find(|rule| rule.get("preset").and_then(toml::Value::as_str) == Some("shell-hygiene"))
        .expect("this repository enables the shell-hygiene preset");
    let documents: BTreeSet<&str> = row["documents"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(toml::Value::as_str)
        .collect();
    assert!(documents.contains("batten.toml"), "{documents:?}");
    assert!(
        authority["census"]["shell"]["exempt"].as_array().is_some(),
        "the census declares the exempt set the ban reads"
    );
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
