//! `kind = "reference"` over `[[register]]` key sets, through the compiled binary
//! (CLOUD-2005).
//!
//! Every case is a fixture tree with NO `.rego`: the predicate under test is the
//! engine's own join, never a module. Each asserts the exit code and the pointer
//! (`path:line rule reason`), never a row's content, which is the pointer-only
//! contract the kind owes (non-negotiable rule 4).

use crate::common;

use common::{Fixture, run, stdout};

/// A table register over `REGISTER.md`'s first column, width 2, unique.
const KEYS: &str = r#"[[register]]
id = "keyset"
paths = ["REGISTER.md"]
source = "table"
key = 1
width = 2
unique = true
"#;

/// A rule citing `key-*` tokens in `notes/*.md` against `keyset`.
const DANGLING: &str = r#"[[rule]]
id = "dangling"
kind = "reference"
scope = "tree"
glob = "notes/*.md"
regex = '\b(key-[a-z0-9-]+)\b'
severity = "deny"

[rule.cites]
register = "keyset"
"#;

const SOURCES: &str = "| id | file |\n| --- | --- |\n| key-a | a.md |\n";

fn config(rows: &[&str]) -> String {
    format!("version = 1\n\n{}", rows.join("\n"))
}

/// Build, commit and `check` a fixture; return the exit code and stdout.
fn check(name: &str, rows: &[&str], files: &[(&str, &str)]) -> (Option<i32>, String) {
    let dir = Fixture::new(name)
        .config(&config(rows))
        .files(files)
        .base_commit()
        .build();
    let out = run(&dir, &["check"]);
    (out.status.code(), stdout(&out))
}

#[test]
fn a_closing_corpus_exits_zero_and_the_rule_ran() {
    // The anti-vacuity half: the same rule refuses the moment a token goes
    // missing (the next case), so this zero is the rule deciding, not skipping.
    let (code, out) = check(
        "reference-closes",
        &[KEYS, DANGLING],
        &[("REGISTER.md", SOURCES), ("notes/n.md", "cites key-a\n")],
    );
    assert_eq!(code, Some(0), "{out}");
}

#[test]
fn an_absent_key_is_refused_at_its_line() {
    let (code, out) = check(
        "reference-absent",
        &[KEYS, DANGLING],
        &[
            ("REGISTER.md", SOURCES),
            ("notes/n.md", "fine\ncites key-a and key-missing\n"),
        ],
    );
    assert_eq!(code, Some(2), "{out}");
    assert!(
        out.contains("notes/n.md:2 rule 'dangling' unresolved"),
        "{out}"
    );
    assert!(
        !out.contains("key-missing"),
        "pointer-only, never the token: {out}"
    );
}

#[test]
fn a_key_in_two_register_paths_is_refused() {
    // The union across `paths` is what makes this a duplicate at all.
    let keys = KEYS.replace(
        r#"paths = ["REGISTER.md"]"#,
        r#"paths = ["REGISTER.md", "ws/REGISTER.md"]"#,
    );
    let (code, out) = check(
        "reference-duplicate",
        &[&keys, DANGLING],
        &[
            ("REGISTER.md", SOURCES),
            ("ws/REGISTER.md", "| key-a | b.md |\n"),
            ("notes/n.md", "cites key-a\n"),
        ],
    );
    assert_eq!(code, Some(2), "{out}");
    assert!(out.contains("register-key-duplicated"), "{out}");
}

#[test]
fn an_unescaped_pipe_widens_the_row_and_an_escaped_one_is_quiet() {
    let (code, out) = check(
        "reference-pipe-wide",
        &[KEYS, DANGLING],
        &[
            (
                "REGISTER.md",
                "| id | file |\n| - | - |\n| key-a | a|b.md |\n",
            ),
            ("notes/n.md", "cites key-a\n"),
        ],
    );
    assert_eq!(code, Some(2), "{out}");
    assert!(
        out.contains("REGISTER.md:3 rule 'dangling' register-row-width"),
        "{out}"
    );

    let (code, out) = check(
        "reference-pipe-escaped",
        &[KEYS, DANGLING],
        &[
            (
                "REGISTER.md",
                "| id | file |\n| - | - |\n| key-a | a\\|b.md |\n",
            ),
            ("notes/n.md", "cites key-a\n"),
        ],
    );
    assert_eq!(code, Some(0), "{out}");
}

#[test]
fn a_frontmatter_list_item_outside_the_set_is_refused() {
    let rule = r#"[[rule]]
id = "group-unknown"
kind = "reference"
scope = "tree"
glob = "entries/*.md"
format = "markdown"
node = "groups"
severity = "deny"

[rule.cites]
register = "keyset"
"#;
    let (code, out) = check(
        "reference-frontmatter",
        &[KEYS, rule],
        &[
            ("REGISTER.md", SOURCES),
            (
                "entries/e.md",
                "---\ngroups: [key-a, key-nope]\n---\nbody\n",
            ),
        ],
    );
    assert_eq!(code, Some(2), "{out}");
    assert!(
        out.contains("entries/e.md:1 rule 'group-unknown' unresolved"),
        "{out}"
    );
}

#[test]
fn a_split_cell_resolves_each_member() {
    let groups = r#"[[register]]
id = "groups"
paths = ["groups.md"]
source = "table"
key = 1
width = 2
"#;
    let rule = r#"[[rule]]
id = "member-unknown"
kind = "reference"
scope = "tree"
severity = "deny"

[rule.cites]
register = "keyset"
from_register = "groups"
column = 2
split = ";"
"#;
    let (code, out) = check(
        "reference-split",
        &[KEYS, groups, rule],
        &[
            ("REGISTER.md", SOURCES),
            (
                "groups.md",
                "| g | members |\n| - | - |\n| g1 | key-a; key-b |\n",
            ),
        ],
    );
    assert_eq!(code, Some(2), "{out}");
    assert!(
        out.contains("groups.md:3 rule 'member-unknown' unresolved"),
        "{out}"
    );
}

#[test]
fn a_file_cell_naming_an_untracked_path_is_refused_and_an_empty_one_is_not() {
    let tracked = r#"[[pattern]]
id = "any-path"
regex = '^(.*)$'

[[register]]
id = "tracked"
paths = ["**"]
source = "tree"
pattern = "any-path"
"#;
    let rule = r#"[[rule]]
id = "file-missing"
kind = "reference"
scope = "tree"
severity = "deny"

[rule.cites]
register = "tracked"
from_register = "keyset"
column = 2
relative_to = "citer"
"#;
    // The register lives in `out/`, so its file cells resolve against `out/`.
    let keys = KEYS.replace(
        r#"paths = ["REGISTER.md"]"#,
        r#"paths = ["out/REGISTER.md"]"#,
    );
    let (code, out) = check(
        "reference-file-out",
        &[&keys, tracked, rule],
        &[
            (
                "out/REGISTER.md",
                "| id | file |\n| - | - |\n| key-a | a.md |\n| key-b |  |\n| key-c | gone.md |\n",
            ),
            ("out/a.md", "captured\n"),
        ],
    );
    assert_eq!(code, Some(2), "{out}");
    assert!(
        out.contains("out/REGISTER.md:5 rule 'file-missing' unresolved"),
        "{out}"
    );
    assert!(
        !out.contains("out/REGISTER.md:4"),
        "an empty cell is not a citation: {out}"
    );
    assert!(
        !out.contains("out/REGISTER.md:3"),
        "a tracked file resolves: {out}"
    );
}

#[test]
fn an_index_key_no_document_names_is_refused_under_inverse() {
    let rule = r#"[[rule]]
id = "roster-phantom"
kind = "reference"
scope = "tree"
glob = "notes/*.md"
regex = '\b(key-[a-z0-9-]+)\b'
severity = "deny"

[rule.cites]
register = "keyset"
inverse = true
"#;
    let (code, out) = check(
        "reference-inverse",
        &[KEYS, rule],
        &[
            (
                "REGISTER.md",
                "| id | file |\n| - | - |\n| key-a | a.md |\n| key-b | b.md |\n",
            ),
            ("notes/n.md", "cites key-a\n"),
        ],
    );
    assert_eq!(code, Some(2), "{out}");
    assert!(
        out.contains("REGISTER.md:4 rule 'roster-phantom' uncited"),
        "{out}"
    );
}

const ATTESTED: &str = r#"[[register]]
id = "witness"
paths = ["witness/*.md"]
source = "documents"
key_node = "names"

[register.refused_values]
stability = ["unstable"]
"#;

const UNATTESTED: &str = r#"[[rule]]
id = "unwitness"
kind = "reference"
scope = "tree"
glob = "**/middle/*.md"
regex = '\b(key-[a-z0-9-]+)\b'
severity = "deny"

[rule.cites]
register = "witness"
"#;

#[test]
fn a_document_witness_admits_unless_its_only_witness_is_refused() {
    let (code, out) = check(
        "reference-refused-one-of-two",
        &[ATTESTED, UNATTESTED],
        &[
            (
                "witness/1.md",
                "---\nnames: key-a\nstability: unstable\n---\n",
            ),
            (
                "witness/2.md",
                "---\nnames: key-a\nstability: stable\n---\n",
            ),
            ("middle/r.md", "cites key-a\n"),
        ],
    );
    assert_eq!(code, Some(0), "one admissible witness admits: {out}");

    let (code, out) = check(
        "reference-refused-only",
        &[ATTESTED, UNATTESTED],
        &[
            (
                "witness/1.md",
                "---\nnames: key-a\nstability: unstable\n---\n",
            ),
            ("middle/r.md", "cites key-a\n"),
        ],
    );
    assert_eq!(code, Some(2), "{out}");
    assert!(
        out.contains("middle/r.md:1 rule 'unwitness' unresolved"),
        "{out}"
    );
}

#[test]
fn a_witness_in_one_partition_does_not_admit_a_citer_in_another() {
    let partition = r#"[[pattern]]
id = "workspace"
regex = '^workspaces/([^/]+)/'
"#;
    let rule = UNATTESTED.replace(
        "register = \"witness\"\n",
        "register = \"witness\"\npartition = \"workspace\"\n",
    );
    let witness = ATTESTED.replace(
        r#"paths = ["witness/*.md"]"#,
        r#"paths = ["**/witness/*.md"]"#,
    );
    let (code, out) = check(
        "reference-partition",
        &[partition, &witness, &rule],
        &[
            ("workspaces/b/witness/1.md", "---\nnames: key-a\n---\n"),
            ("workspaces/a/middle/r.md", "cites key-a\n"),
        ],
    );
    assert_eq!(code, Some(2), "{out}");
    assert!(
        out.contains("workspaces/a/middle/r.md:1 rule 'unwitness' unresolved"),
        "{out}"
    );
}

#[test]
fn an_undeclared_partition_is_refused_rather_than_read_as_none() {
    let rule = UNATTESTED.replace(
        "register = \"witness\"\n",
        "register = \"witness\"\npartition = \"workspace\"\n",
    );
    let witness = ATTESTED.replace(
        r#"paths = ["witness/*.md"]"#,
        r#"paths = ["**/witness/*.md"]"#,
    );
    let (code, out) = check(
        "reference-partition-undeclared",
        &[&witness, &rule],
        &[
            ("workspaces/b/witness/1.md", "---\nnames: key-a\n---\n"),
            ("workspaces/a/middle/r.md", "cites key-a\n"),
        ],
    );
    assert_eq!(code, Some(1), "{out}");
}

#[test]
fn config_show_attributes_a_declared_register() {
    let dir = Fixture::new("reference-config-show")
        .config(&config(&[KEYS, DANGLING]))
        .files(&[("REGISTER.md", SOURCES)])
        .base_commit()
        .build();
    let out = run(&dir, &["config", "show"]);
    assert_eq!(out.status.code(), Some(0), "{}", stdout(&out));
}

#[test]
fn an_unparseable_witness_is_could_not_look() {
    let (code, out) = check(
        "reference-unparseable",
        &[ATTESTED, UNATTESTED],
        &[
            ("witness/1.md", "---\nnames: [unclosed\n---\n"),
            ("middle/r.md", "cites key-a\n"),
        ],
    );
    assert_eq!(code, Some(2), "{out}");
    assert!(
        out.contains("witness/1.md:1 rule 'unwitness' could-not-look"),
        "{out}"
    );
}

#[test]
fn a_register_path_matching_nothing_is_could_not_look_never_empty() {
    let (code, out) = check(
        "reference-no-register",
        &[KEYS, DANGLING],
        &[("notes/n.md", "cites key-a\n")],
    );
    assert_eq!(code, Some(2), "{out}");
    assert!(out.contains("could-not-look"), "{out}");
    assert!(
        !out.contains("unresolved"),
        "an absent register is not an empty one: {out}"
    );
}

#[test]
fn a_tracked_citer_deleted_from_the_worktree_is_neither_a_finding_nor_could_not_look() {
    let rule = r#"[[rule]]
id = "group-unknown"
kind = "reference"
scope = "tree"
glob = "entries/*.md"
format = "markdown"
node = "groups"
severity = "deny"

[rule.cites]
register = "keyset"
"#;
    let dir = Fixture::new("reference-citer-deleted")
        .config(&config(&[KEYS, rule]))
        .files(&[
            ("REGISTER.md", SOURCES),
            ("entries/e.md", "---\ngroups: [key-nope]\n---\n"),
        ])
        .base_commit()
        .build();
    // Tracked, then gone: the walk lists it and the read finds nothing.
    std::fs::remove_file(dir.join("entries/e.md")).expect("delete the citer");
    let out = run(&dir, &["check"]);
    assert_eq!(out.status.code(), Some(0), "{}", stdout(&out));
}
