//! `kind = "reference"` over `[[register]]` key sets, through the compiled binary
//! (CLOUD-2005).
//!
//! Every case is a fixture tree with NO `.rego`: the predicate under test is the
//! engine's own join, never a module. Each asserts the exit code and the pointer
//! (`path:line rule reason`), never a row's content, which is the pointer-only
//! contract the kind owes (non-negotiable rule 4).

use crate::common;

use common::{Fixture, run, stdout};

/// A table register over `SOURCES.md`'s first column, width 2, unique.
const CAPS: &str = r#"[[register]]
id = "caps"
paths = ["SOURCES.md"]
source = "table"
key = 1
width = 2
unique = true
"#;

/// A rule citing `cap-*` tokens in `notes/*.md` against `caps`.
const DANGLING: &str = r#"[[rule]]
id = "dangling"
kind = "reference"
scope = "tree"
glob = "notes/*.md"
regex = '\b(cap-[a-z0-9-]+)\b'
severity = "deny"

[rule.cites]
register = "caps"
"#;

const SOURCES: &str = "| id | file |\n| --- | --- |\n| cap-a | a.md |\n";

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
        &[CAPS, DANGLING],
        &[("SOURCES.md", SOURCES), ("notes/n.md", "cites cap-a\n")],
    );
    assert_eq!(code, Some(0), "{out}");
}

#[test]
fn an_absent_key_is_refused_at_its_line() {
    let (code, out) = check(
        "reference-absent",
        &[CAPS, DANGLING],
        &[
            ("SOURCES.md", SOURCES),
            ("notes/n.md", "fine\ncites cap-a and cap-missing\n"),
        ],
    );
    assert_eq!(code, Some(2), "{out}");
    assert!(out.contains("notes/n.md:2 dangling unresolved"), "{out}");
    assert!(
        !out.contains("cap-missing"),
        "pointer-only, never the token: {out}"
    );
}

#[test]
fn a_key_in_two_register_paths_is_refused() {
    // The union across `paths` is what makes this a duplicate at all.
    let caps = CAPS.replace(
        r#"paths = ["SOURCES.md"]"#,
        r#"paths = ["SOURCES.md", "ws/SOURCES.md"]"#,
    );
    let (code, out) = check(
        "reference-duplicate",
        &[&caps, DANGLING],
        &[
            ("SOURCES.md", SOURCES),
            ("ws/SOURCES.md", "| cap-a | b.md |\n"),
            ("notes/n.md", "cites cap-a\n"),
        ],
    );
    assert_eq!(code, Some(2), "{out}");
    assert!(out.contains("register-key-duplicated"), "{out}");
}

#[test]
fn an_unescaped_pipe_widens_the_row_and_an_escaped_one_is_quiet() {
    let (code, out) = check(
        "reference-pipe-wide",
        &[CAPS, DANGLING],
        &[
            (
                "SOURCES.md",
                "| id | file |\n| - | - |\n| cap-a | a|b.md |\n",
            ),
            ("notes/n.md", "cites cap-a\n"),
        ],
    );
    assert_eq!(code, Some(2), "{out}");
    assert!(
        out.contains("SOURCES.md:3 dangling register-row-width"),
        "{out}"
    );

    let (code, out) = check(
        "reference-pipe-escaped",
        &[CAPS, DANGLING],
        &[
            (
                "SOURCES.md",
                "| id | file |\n| - | - |\n| cap-a | a\\|b.md |\n",
            ),
            ("notes/n.md", "cites cap-a\n"),
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
register = "caps"
"#;
    let (code, out) = check(
        "reference-frontmatter",
        &[CAPS, rule],
        &[
            ("SOURCES.md", SOURCES),
            (
                "entries/e.md",
                "---\ngroups: [cap-a, cap-nope]\n---\nbody\n",
            ),
        ],
    );
    assert_eq!(code, Some(2), "{out}");
    assert!(
        out.contains("entries/e.md:1 group-unknown unresolved"),
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
register = "caps"
from_register = "groups"
column = 2
split = ";"
"#;
    let (code, out) = check(
        "reference-split",
        &[CAPS, groups, rule],
        &[
            ("SOURCES.md", SOURCES),
            (
                "groups.md",
                "| g | members |\n| - | - |\n| g1 | cap-a; cap-b |\n",
            ),
        ],
    );
    assert_eq!(code, Some(2), "{out}");
    assert!(
        out.contains("groups.md:3 member-unknown unresolved"),
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
from_register = "caps"
column = 2
relative_to = "citer"
"#;
    // The register lives in `out/`, so its file cells resolve against `out/`.
    let caps = CAPS.replace(r#"paths = ["SOURCES.md"]"#, r#"paths = ["out/SOURCES.md"]"#);
    let (code, out) = check(
        "reference-file-out",
        &[&caps, tracked, rule],
        &[
            (
                "out/SOURCES.md",
                "| id | file |\n| - | - |\n| cap-a | a.md |\n| cap-b |  |\n| cap-c | gone.md |\n",
            ),
            ("out/a.md", "captured\n"),
        ],
    );
    assert_eq!(code, Some(2), "{out}");
    assert!(
        out.contains("out/SOURCES.md:5 file-missing unresolved"),
        "{out}"
    );
    assert!(
        !out.contains("out/SOURCES.md:4"),
        "an empty cell is not a citation: {out}"
    );
    assert!(
        !out.contains("out/SOURCES.md:3"),
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
regex = '\b(cap-[a-z0-9-]+)\b'
severity = "deny"

[rule.cites]
register = "caps"
inverse = true
"#;
    let (code, out) = check(
        "reference-inverse",
        &[CAPS, rule],
        &[
            (
                "SOURCES.md",
                "| id | file |\n| - | - |\n| cap-a | a.md |\n| cap-b | b.md |\n",
            ),
            ("notes/n.md", "cites cap-a\n"),
        ],
    );
    assert_eq!(code, Some(2), "{out}");
    assert!(out.contains("SOURCES.md:4 roster-phantom uncited"), "{out}");
}

const ATTESTED: &str = r#"[[register]]
id = "attested"
paths = ["attested/*.md"]
source = "documents"
key_node = "attests"

[register.refused_values]
stability = ["unstable"]
"#;

const UNATTESTED: &str = r#"[[rule]]
id = "unattested"
kind = "reference"
scope = "tree"
glob = "**/extract/*.md"
regex = '\b(cap-[a-z0-9-]+)\b'
severity = "deny"

[rule.cites]
register = "attested"
"#;

#[test]
fn a_document_witness_admits_unless_its_only_witness_is_refused() {
    let (code, out) = check(
        "reference-refused-one-of-two",
        &[ATTESTED, UNATTESTED],
        &[
            (
                "attested/1.md",
                "---\nattests: cap-a\nstability: unstable\n---\n",
            ),
            (
                "attested/2.md",
                "---\nattests: cap-a\nstability: stable\n---\n",
            ),
            ("extract/r.md", "cites cap-a\n"),
        ],
    );
    assert_eq!(code, Some(0), "one admissible witness admits: {out}");

    let (code, out) = check(
        "reference-refused-only",
        &[ATTESTED, UNATTESTED],
        &[
            (
                "attested/1.md",
                "---\nattests: cap-a\nstability: unstable\n---\n",
            ),
            ("extract/r.md", "cites cap-a\n"),
        ],
    );
    assert_eq!(code, Some(2), "{out}");
    assert!(
        out.contains("extract/r.md:1 unattested unresolved"),
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
        "register = \"attested\"\n",
        "register = \"attested\"\npartition = \"workspace\"\n",
    );
    let attested = ATTESTED.replace(
        r#"paths = ["attested/*.md"]"#,
        r#"paths = ["**/attested/*.md"]"#,
    );
    let (code, out) = check(
        "reference-partition",
        &[partition, &attested, &rule],
        &[
            ("workspaces/b/attested/1.md", "---\nattests: cap-a\n---\n"),
            ("workspaces/a/extract/r.md", "cites cap-a\n"),
        ],
    );
    assert_eq!(code, Some(2), "{out}");
    assert!(
        out.contains("workspaces/a/extract/r.md:1 unattested unresolved"),
        "{out}"
    );
}

#[test]
fn an_unparseable_witness_is_could_not_look() {
    let (code, out) = check(
        "reference-unparseable",
        &[ATTESTED, UNATTESTED],
        &[
            ("attested/1.md", "---\nattests: [unclosed\n---\n"),
            ("extract/r.md", "cites cap-a\n"),
        ],
    );
    assert_eq!(code, Some(2), "{out}");
    assert!(
        out.contains("attested/1.md:1 unattested could-not-look"),
        "{out}"
    );
}

#[test]
fn a_register_path_matching_nothing_is_could_not_look_never_empty() {
    let (code, out) = check(
        "reference-no-register",
        &[CAPS, DANGLING],
        &[("notes/n.md", "cites cap-a\n")],
    );
    assert_eq!(code, Some(2), "{out}");
    assert!(out.contains("could-not-look"), "{out}");
    assert!(
        !out.contains("unresolved"),
        "an absent register is not an empty one: {out}"
    );
}
