//! The `shell-hygiene` preset's shell ban over the compiled binary, for a
//! consumer that is not this repository (CLOUD-1994, lifting CLOUD-1925).
//!
//! # What only this tier can show
//!
//! The module's own `test_` rules pin the predicate over a fabricated input.
//! This tier shows the ENGINE builds that input — the consumer's `[census.shell]`
//! table through `documents`, `lines` for the head, `base-lines` for the base,
//! `added` over the whole tree — so the refusals below come from a real diff
//! against a real `origin/main` (CLOUD-845's class: a module can pass every
//! `with input as` case and decide nothing on a real tree).
//!
//! # The consumer is a stranger on purpose
//!
//! Every scratch repository here carries a `batten.toml` holding ONE policy row
//! that enables the preset, and a `[census.shell]` table. No module is copied in,
//! no `[[verdict]]` row is declared and no `[vocabulary]` exists: that is what a
//! consumer who never saw this repository writes, and a preset that only decided
//! with this repository's own vocabulary beside it would be a consumer module
//! wearing a preset's name. Its exempt file is `bootstrap.sh`, which this
//! repository does not exempt, and one case uses a manifest shape this
//! repository does not have.
//!
//! # The replay the module carried before the lift
//!
//! The consumer module this preset replaced was replayed against this
//! repository's history: #962's squash `4f61a1c` is refused (`task write refused`
//! on `mise.toml` and 41 `task add refused` pointers, exit 2), as is `f8b18c5`;
//! `771651d` and `c7ba001`, which added no shell, pass. That replay needs the
//! real history, which a shallow runner does not carry, so its shapes are
//! restated here as synthetic fixtures rather than read from git.
//!
//! # What the lift changed, stated rather than absorbed
//!
//! The consumer module's `stays_bash` literal and its hard-wired manifest and
//! workflow paths became the consumer's `[census.shell]` table. Four behaviours
//! follow: the ban reads EVERY declared manifest's command keys (in this
//! repository that adds `hk.pkl`'s `check`/`fix` strings, which the census
//! already counted), exempt entries are globs, a consumer declaring no census is
//! not banned at all, and the table's globs are held to `*`, `?` and `**` — the
//! operators both the census and the ban read alike — so a brace, a class or an
//! escape is refused at load rather than read two ways.
//!
//! One behaviour is the old module's, restored after review: an edited manifest
//! whose base side is missing from `base-lines` refuses every shell unit it
//! carries, as the consumer module did, rather than reading the unread base as
//! holding them all.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::Output;

use common::{Fixture, git_in, run, stdout};

/// The enabling row's id, which is the consumer's to choose.
const ROW: &str = "shell hygiene on";

/// The predicate the preset publishes, which every finding here names.
const PREDICATE: &str = "shell write other";

/// A stranger's whole configuration: one row enabling the preset, and the
/// census table saying where its shell lives.
fn config() -> String {
    format!(
        "version = 1\n\
         \n[[rule]]\nid = \"{ROW}\"\nkind = \"policy\"\nscope = \"tree\"\n\
         preset = \"shell-hygiene\"\nseverity = \"deny\"\n\
         base = \"origin/main\"\ndelta_sources = [\"**\"]\n\
         documents = [\"batten.toml\"]\n\
         line_sources = [\"mise.toml\", \"tasks.toml\", \".github/workflows/*.yml\", \"tools/**\"]\n\
         \n[census.shell]\n\
         workflows = [\".github/workflows/*.yml\"]\n\
         exempt = [\"bootstrap.sh\"]\n\
         \n[[census.shell.manifest]]\n\
         path = \"mise.toml\"\n\
         keys = [\"run\"]\n\
         unit = \"[tasks.\"\n\
         \n[[census.shell.manifest]]\n\
         path = \"tasks.toml\"\n\
         keys = [\"cmd\"]\n\
         unit = \"[task.\"\n"
    )
}

/// A repository whose `origin/main` holds `files` and the stranger's config.
fn repo(name: &str, files: &[(&str, &str)]) -> PathBuf {
    Fixture::new(name)
        .config(&config())
        .files(files)
        .git()
        .base_commit()
        .build()
}

/// Write `text` at `path` and commit it as the branch's change.
fn change(dir: &Path, path: &str, text: &str) {
    common::write(dir, path, text);
    git_in(dir, &["add", "-A"]);
    git_in(dir, &["commit", "-q", "-m", "the change"]);
}

fn check(dir: &Path) -> Output {
    run(dir, &["check", "--rule", ROW])
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

/// The ban's refusals as `(path, line)` pointers, read off `-J`.
///
/// Filtered to the ban's own predicate: the same row enables the preset's two
/// naming rules, and a finding of theirs is not this tier's subject. The four
/// arms are told apart by their pointer: `task write refused` points at the
/// manifest with no line, `task add refused` at the new unit's header line, and
/// the other two at their own paths.
fn findings(dir: &Path) -> (Option<i32>, Vec<(String, Option<u64>)>) {
    let output = run(dir, &["check", "-J", "--rule", ROW]);
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

/// `task write refused`'s pointer: the manifest, no line.
fn grew(found: &[(String, Option<u64>)], path: &str) -> bool {
    found.contains(&(path.to_owned(), None))
}

/// `task add refused`'s pointer: the manifest at the unit header's line.
fn gained_at(found: &[(String, Option<u64>)], path: &str, line: u64) -> bool {
    found.contains(&(path.to_owned(), Some(line)))
}

#[test]
fn a_program_moved_inline_is_refused() {
    // #962's shape: a file deleted, its body re-housed in a task string.
    let dir = repo(
        "shell-ban-moved-inline",
        &[
            ("mise.toml", &manifest(&[("a", &["echo a"])])),
            ("tools/b.sh", "#!/usr/bin/env bash\nset -e\necho b\n"),
        ],
    );
    std::fs::remove_file(dir.join("tools/b.sh")).unwrap();
    change(
        &dir,
        "mise.toml",
        &manifest(&[("a", &["echo a"]), ("b", &["set -e", "echo b"])]),
    );
    // `a` spans lines 1-4 and a blank, so task `b`'s header is line 6.
    let (code, found) = findings(&dir);
    assert_eq!(code, Some(2), "{found:?}");
    assert!(grew(&found, "mise.toml"), "the line count rose: {found:?}");
    assert!(
        gained_at(&found, "mise.toml", 6),
        "task b gained shell: {found:?}"
    );
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
    assert!(grew(&found, "mise.toml"), "{found:?}");
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
        !grew(&found, "mise.toml"),
        "the total fell, so growth is not the arm: {found:?}"
    );
    assert!(
        gained_at(&found, "mise.toml", 1),
        "the new task's header is the pointer: {found:?}"
    );
}

/// The manifest is the CONSUMER's: another file, another command key, another
/// unit header, all read off `[census.shell]` rather than off anything the
/// preset spells.
#[test]
fn a_manifest_of_the_consumers_own_shape_is_read_by_its_declaration() {
    let base = "[task.build]\ncmd = \"cargo build\"\n";
    let dir = repo("shell-ban-own-shape", &[("tasks.toml", base)]);
    change(
        &dir,
        "tasks.toml",
        &format!("{base}\n[task.ship]\ncmd = \"cargo build && ./ship\"\n"),
    );
    let (code, found) = findings(&dir);
    assert_eq!(code, Some(2), "{found:?}");
    assert!(grew(&found, "tasks.toml"), "{found:?}");
    assert!(gained_at(&found, "tasks.toml", 4), "{found:?}");
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
    assert!(
        gained_at(&found, "mise.toml", 4),
        "task b's header: {found:?}"
    );
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
    let (code, found) = findings(&dir);
    assert_eq!(code, Some(2), "{found:?}");
    assert!(grew(&found, ".github/workflows/ci.yml"), "{found:?}");
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
    let (code, found) = findings(&dir);
    assert_eq!(code, Some(2), "{found:?}");
    assert!(grew(&found, "scripts/deploy.sh"), "{found:?}");
}

#[test]
fn an_added_shebang_program_under_a_declared_directory_is_refused() {
    let dir = repo("shell-ban-shebang", &[("README.md", "x\n")]);
    change(&dir, "tools/run-thing", "#!/usr/bin/env bash\necho thing\n");
    let (code, found) = findings(&dir);
    assert_eq!(code, Some(2), "{found:?}");
    assert!(grew(&found, "tools/run-thing"), "{found:?}");
}

#[test]
fn an_exempt_file_is_admitted() {
    let dir = repo("shell-ban-exempt", &[("README.md", "x\n")]);
    change(&dir, "bootstrap.sh", "#!/bin/sh\necho bootstrap\n");
    let output = check(&dir);
    assert_eq!(output.status.code(), Some(0), "{}", stdout(&output));
}

/// A BASE THE ENGINE COULD NOT READ AS TEXT IS NOT A BASE HOLDING THE HEAD'S
/// SHELL. A non-UTF-8 base blob reaches the module as an empty base, so the
/// unit the head carries is new and refused; the module's own `test_` rules pin
/// the other could-not-look shape, a path missing from `base-lines`.
#[test]
fn a_manifest_whose_base_is_not_text_is_judged_against_nothing() {
    let fixture = Fixture::new("shell-ban-unreadable-base")
        .config(&config())
        .git();
    let mut base = manifest(&[("a", &["echo a"])]).into_bytes();
    base.extend_from_slice(b"# \xff\xfe\n");
    std::fs::write(fixture.path().join("mise.toml"), base).unwrap();
    let dir = fixture.base_commit().build();
    change(&dir, "mise.toml", &manifest(&[("a", &["echo a"])]));
    let (code, found) = findings(&dir);
    assert_eq!(code, Some(2), "{found:?}");
    assert!(
        gained_at(&found, "mise.toml", 1),
        "the head's unit is judged new: {found:?}"
    );
}

/// ONE LIST, ONE GLOB LANGUAGE. The census reads `[census.shell]` through
/// `globset` and the ban through its own matcher, which implements `*`, `?` and
/// `**` only; a brace would be every workflow to the first and none to the
/// second. So the declaration is refused before either reads it.
#[test]
fn a_census_glob_the_ban_cannot_read_is_refused_at_load() {
    let dir = Fixture::new("shell-ban-brace-glob")
        .config(&config().replace(
            "workflows = [\".github/workflows/*.yml\"]",
            "workflows = [\".github/workflows/*.{yml,yaml}\"]",
        ))
        .file("README.md", "x\n")
        .git()
        .base_commit()
        .build();
    let output = check(&dir);
    assert_eq!(output.status.code(), Some(1), "{}", stdout(&output));
}

/// NO DECLARATION, NO BAN. A consumer enabling `shell-hygiene` for its naming
/// rules alone has not said where its shell lives, and must not be refused a
/// shell file it never agreed to stop writing.
#[test]
fn a_consumer_declaring_no_census_is_not_banned() {
    let dir = Fixture::new("shell-ban-undeclared")
        .config(&format!(
            "version = 1\n\n[[rule]]\nid = \"{ROW}\"\nkind = \"policy\"\nscope = \"tree\"\n\
             preset = \"shell-hygiene\"\nseverity = \"deny\"\n\
             base = \"origin/main\"\ndelta_sources = [\"**\"]\n\
             documents = [\"batten.toml\"]\nline_sources = [\"tools/**\"]\n"
        ))
        .file("README.md", "x\n")
        .git()
        .base_commit()
        .build();
    change(&dir, "scripts/deploy.sh", "echo deploy\n");
    let (code, found) = findings(&dir);
    assert!(found.is_empty(), "{found:?}");
    assert_eq!(code, Some(0));
}

/// THE EXEMPTION SET, ASSERTED EXACTLY. It is this repository's
/// `[census.shell] exempt`, the one list both the census and the ban read, and
/// growing it is how a ban becomes a hatch — so it is pinned here, and a change
/// to it is a failing test a reviewer must read.
#[test]
fn the_exemption_set_is_exactly_the_files_that_must_be_shell() {
    let authority: toml::Value =
        toml::from_str(&std::fs::read_to_string(common::at_root("batten.toml")).unwrap()).unwrap();
    let exempt: BTreeSet<&str> = authority["census"]["shell"]["exempt"]
        .as_array()
        .unwrap()
        .iter()
        .map(|glob| glob.as_str().unwrap())
        .collect();
    assert_eq!(
        exempt,
        BTreeSet::from([
            ".claude/hooks/git-hook.sh",
            "completions/batten.bash",
            "install.sh",
            "setup.sh",
        ])
    );
}

/// THIS REPOSITORY'S ROW READS EVERY HOME ITS CENSUS DECLARES. A manifest or a
/// workflow glob the enabling row does not hand over as lines is a home the ban
/// cannot see, and it would pass silently over every change to it — the census
/// would count a home the gate never judged.
#[test]
fn this_repositorys_ban_reads_every_declared_home() {
    let authority: toml::Value =
        toml::from_str(&std::fs::read_to_string(common::at_root("batten.toml")).unwrap()).unwrap();
    let row = authority["rule"]
        .as_array()
        .unwrap()
        .iter()
        .find(|rule| rule.get("preset").and_then(toml::Value::as_str) == Some("shell-hygiene"))
        .expect("this repository enables the shell-hygiene preset");
    let strings = |key: &str| -> BTreeSet<String> {
        row.get(key)
            .and_then(toml::Value::as_array)
            .map(|values| {
                values
                    .iter()
                    .filter_map(|value| value.as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default()
    };
    assert!(
        strings("documents").contains("batten.toml"),
        "the row hands the ban no census declaration"
    );
    assert!(
        row.get("base").is_some() && strings("delta_sources").contains("**"),
        "the row gives the ban no diff to judge"
    );
    let lines = strings("line_sources");
    let census = &authority["census"]["shell"];
    for manifest in census["manifest"].as_array().unwrap() {
        let path = manifest["path"].as_str().unwrap();
        assert!(lines.contains(path), "the ban cannot read `{path}`");
    }
    for glob in census["workflows"].as_array().unwrap() {
        let glob = glob.as_str().unwrap();
        assert!(lines.contains(glob), "the ban cannot read `{glob}`");
    }
}

/// The real tree, against its own base: this repository is clean today, so a
/// ban that refused its own checkout would be switched off on the first run.
#[test]
fn this_repositorys_own_tree_passes() {
    let root = common::at_root(".");
    let authority: toml::Value =
        toml::from_str(&std::fs::read_to_string(root.join("batten.toml")).unwrap()).unwrap();
    let row = authority["rule"]
        .as_array()
        .unwrap()
        .iter()
        .find(|rule| rule.get("preset").and_then(toml::Value::as_str) == Some("shell-hygiene"))
        .and_then(|rule| rule["id"].as_str())
        .expect("this repository enables the shell-hygiene preset")
        .to_owned();
    let output = run(&root, &["check", "--rule", row.as_str()]);
    assert_eq!(output.status.code(), Some(0), "{}", stdout(&output));
}
