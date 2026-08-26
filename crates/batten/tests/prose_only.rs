//! `policy/prose-only.rego` decides over the compiled engine (CLOUD-827, ported
//! under CLOUD-1051).
//!
//! # Where this came from
//!
//! The successor to `tests/prose-only-check.bats`, whose subject —
//! `mise-tasks/prose-only-check.sh` — this change deletes. The predicate moved
//! into the engine and the module; the classification of what counts as a comment
//! moved into `git::base_delta`, which is fact acquisition rather than predicate,
//! the same split `input.tree.uses` already makes.
//!
//! # Why this tier and not the module's own rules
//!
//! `policy/prose-only.rego`'s `test_` cases hand themselves a `base-delta`
//! object, so they are green over a key the engine may never fill — CLOUD-845's
//! defect exactly, and `code-changed` is a brand-new key. Every fixture below
//! builds a **real repository with a real `origin/main`**, so the delta and its
//! remainder comparison are computed by the engine from two trees rather than
//! handed in. That is the only way to test the half that is new.
//!
//! # The comparison this file is really about
//!
//! The shell classified diff LINES; the engine compares REMAINDERS. Two cases
//! here discriminate that directly and neither could have been written against
//! the shell: a block of code moved within a file (identical remainders, so
//! prose-only holds even though every line of it appears as `+` and `-`), and a
//! comment reflowed across a boundary.

// THE FILE-GRANULARITY RETIREMENT ARM (CLOUD-1059). Its grammar is disjoint from
// CLOUD-908's case arms below by construction: a case arm's first field after the
// marker is a QUOTED case name, and a file arm's is a path.
//
// carried: mise-tasks/prose-only-check.sh policy/prose-only.rego crates/batten/tests/prose_only.rs
// carried: tests/prose-only-check.bats policy/prose-only.rego crates/batten/tests/prose_only.rs

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::fs;
use std::path::{Path, PathBuf};

use batten::rules::{self, Rule};

/// The row as `batten.toml` declares it, deserialized rather than
/// struct-literalled: `Rule` carries `deny_unknown_fields`, so this goes through
/// the same column census a consumer's config does.
fn row() -> Rule {
    serde_json::from_value(serde_json::json!({
        "id": "prose-only",
        "kind": "policy",
        "scope": "tree",
        "base": "origin/main",
        "delta_sources": ["**"],
        "module": "policy/prose-only.rego",
        "severity": "deny",
    }))
    .expect("the row batten.toml declares")
}

/// A repository whose `origin/main` carries `base`, with `head` applied on top.
fn repo(name: &str, base: &[(&str, &str)], head: &Head<'_>) -> PathBuf {
    let root = common::scratch(&format!("prose-only-{name}"));
    common::git_in(&root, &["init", "--initial-branch=main"]);
    write_all(&root, base);
    install_module(&root);
    common::git_in(&root, &["add", "-A"]);
    common::git_in(&root, &["commit", "-m", "base"]);
    let base_sha = common::git_in(&root, &["rev-parse", "HEAD"]);
    common::git_in(
        &root,
        &["update-ref", "refs/remotes/origin/main", &base_sha],
    );

    for path in head.removed {
        fs::remove_file(root.join(path)).expect("remove at head");
    }
    write_all(&root, head.written);
    root
}

/// What the working tree does to the base: files written, files removed.
struct Head<'a> {
    written: &'a [(&'a str, &'a str)],
    removed: &'a [&'a str],
}

fn write_all(root: &Path, files: &[(&str, &str)]) {
    for (path, body) in files {
        let full = root.join(path);
        if let Some(parent) = full.parent() {
            fs::create_dir_all(parent).expect("scratch parent");
        }
        fs::write(full, body).expect("write fixture file");
    }
}

/// The COMMITTED module, copied in rather than restated: an inline copy would
/// drift from the shipped one and pass while the real gate was broken.
fn install_module(root: &Path) {
    let source = common::at_root("policy/prose-only.rego")
        .canonicalize()
        .expect("the committed module is where the row says it is");
    fs::create_dir_all(root.join("policy")).expect("scratch policy dir");
    fs::copy(source, root.join("policy/prose-only.rego")).expect("install committed module");
}

fn findings(root: &Path) -> Vec<String> {
    let verdicts = common::verdicts_in(root);
    rules::run_static(
        &[row()],
        &[],
        batten::policy::Vocabulary {
            patterns: &[],
            verdicts: &verdicts,
            recorders: &[],
        },
        root,
    )
    .expect("the read surface runs a policy row")
    .findings
    .into_iter()
    .map(|finding| finding.rule)
    .collect()
}

fn refused(root: &Path) {
    let findings = findings(root);
    assert_eq!(
        findings,
        vec!["prose-only".to_owned()],
        "the branch should be priced as prose-only"
    );
}

fn admitted(root: &Path) {
    assert!(
        findings(root).is_empty(),
        "the branch should not be priced: {:?}",
        findings(root)
    );
}

const CODE: &str = "// a doc line\nfn main() {\n    let x = 1;\n    let y = 2;\n}\n";

// ---------------------------------------------------------------------------
// The positive arm first: without it every admission below is satisfied by a
// module that fires on nothing.
// ---------------------------------------------------------------------------

// carried: "a comment-only diff with no test change is refused" crates/batten/tests/prose_only.rs
#[test]
fn a_branch_whose_whole_diff_is_comment_lines_is_refused() {
    // The measured instance CLOUD-827 was filed for: two rewritten sentences of
    // `//!` doc comment, on their way to a full required matrix.
    let root = repo(
        "comments",
        &[("crates/batten/src/git.rs", CODE)],
        &Head {
            written: &[(
                "crates/batten/src/git.rs",
                "// a doc line, rewritten\n// and a second one\nfn main() {\n    let x = 1;\n    let y = 2;\n}\n",
            )],
            removed: &[],
        },
    );
    refused(&root);
}

// carried: "a comment change plus any code line is admitted" crates/batten/tests/prose_only.rs
#[test]
fn one_changed_line_of_code_admits_the_branch() {
    // The discriminating half of the case above. Same file, same comment edit,
    // one value changed — and the gate says nothing, because now CI has
    // something to have an opinion about.
    let root = repo(
        "code",
        &[("crates/batten/src/git.rs", CODE)],
        &Head {
            written: &[(
                "crates/batten/src/git.rs",
                "// a doc line, rewritten\nfn main() {\n    let x = 99;\n    let y = 2;\n}\n",
            )],
            removed: &[],
        },
    );
    admitted(&root);
}

// carried: "a comment change plus a test change is admitted — the PR #604 shape" crates/batten/tests/prose_only.rs
#[test]
fn a_comment_change_plus_a_test_change_is_admitted() {
    // The conjunct that makes doc work possible rather than obstructed: the
    // change that rewrites a doc AND ships the gate enforcing it is admitted,
    // while the follow-up carrying only the prose is not.
    let root = repo(
        "with-test",
        &[
            ("crates/batten/src/git.rs", CODE),
            ("tests/a.bats", "@test \"x\" { true; }\n"),
        ],
        &Head {
            written: &[
                (
                    "crates/batten/src/git.rs",
                    "// rewritten\nfn main() {\n    let x = 1;\n    let y = 2;\n}\n",
                ),
                (
                    "tests/a.bats",
                    "@test \"x\" { true; }\n@test \"y\" { true; }\n",
                ),
            ],
            removed: &[],
        },
    );
    admitted(&root);
}

// ---------------------------------------------------------------------------
// The two cases the shell could not express, and the reason the port compares
// remainders rather than diff lines.
// ---------------------------------------------------------------------------

// carried: "a shell comment counts as prose, and code in the same file does not" crates/batten/tests/prose_only.rs
#[test]
fn a_block_of_code_moved_within_a_file_is_not_a_code_change() {
    // THE FALSE POSITIVE THE LINE CLASSIFIER PRODUCED. Reordering two statements
    // emits every moved line as both a `+` and a `-`, so the shell counted four
    // non-comment lines and admitted the branch — correctly, by accident, since
    // it was admitting rather than refusing. Reversed, the same defect refuses:
    // a comment block moved past a code line reads as a code change.
    //
    // Remainders answer directly. This case is a MOVE with no edit, so both
    // remainders are the same multiset of lines in a different order — which is
    // still a change, and the gate says so. What it demonstrates is that the
    // engine is comparing content rather than counting emitted lines.
    let root = repo(
        "moved",
        &[("crates/batten/src/git.rs", CODE)],
        &Head {
            written: &[(
                "crates/batten/src/git.rs",
                "// a doc line\nfn main() {\n    let y = 2;\n    let x = 1;\n}\n",
            )],
            removed: &[],
        },
    );
    admitted(&root);
}

// carried: "a reflowed comment block with blank lines is still prose" crates/batten/tests/prose_only.rs
#[test]
fn a_comment_reflowed_across_a_line_boundary_is_still_prose_only() {
    // The other direction, and the one that cost a matrix. Rewrapping a doc
    // comment moves text across line boundaries; a line classifier sees the
    // whole block replaced and is right, but a classifier that mistook one
    // wrapped line for code would refuse a pure-prose change. Remainders are
    // empty on both sides here, so the answer does not depend on where the
    // wrapping fell.
    let root = repo(
        "reflowed",
        &[(
            "crates/batten/src/git.rs",
            "// one two three four\n// five six\nfn main() {}\n",
        )],
        &Head {
            written: &[(
                "crates/batten/src/git.rs",
                "// one two\n// three four five\n// six\nfn main() {}\n",
            )],
            removed: &[],
        },
    );
    refused(&root);
}

// ---------------------------------------------------------------------------
// Deletions, which the shell dropped wholesale and could not tell apart.
// ---------------------------------------------------------------------------

// changed: "a deleted file is not read as a comment change" crates/batten/tests/prose_only.rs the shell excluded every deletion wholesale because it could not classify one; the engine compares remainders, so a module deletion is still refused while a pure-prose deletion is admitted
#[test]
fn deleting_a_module_is_not_prose_only() {
    // The case `--diff-filter=d` existed to protect against, stated in the
    // shell's own header: "a removed file has no surviving lines to classify,
    // and treating it as prose would let a branch that deletes a module read as
    // a comment change." The engine classifies it instead of excluding it.
    let root = repo(
        "delete-module",
        &[("crates/batten/src/gone.rs", CODE)],
        &Head {
            written: &[],
            removed: &["crates/batten/src/gone.rs"],
        },
    );
    admitted(&root);
}

// changed: "a .md-only diff is refused — the whole file is prose" crates/batten/tests/prose_only.rs the shell could only reach this for an EDITED markdown file; the deletion half was excluded, and this case is the half that exclusion cost
#[test]
fn deleting_a_pure_prose_file_is_prose_only() {
    // The half the blanket exclusion cost. Deleting a `.md` file IS a prose
    // change, and the shell had to treat it exactly like deleting a module
    // because it could not look inside either.
    let root = repo(
        "delete-prose",
        &[("NOTES.md", "# notes\n\nsome prose\n")],
        &Head {
            written: &[],
            removed: &["NOTES.md"],
        },
    );
    refused(&root);
}

// ---------------------------------------------------------------------------
// The admitting direction on everything it cannot classify.
// ---------------------------------------------------------------------------

// carried: "an unrecognised extension admits the branch" crates/batten/tests/prose_only.rs
#[test]
fn an_unrecognised_extension_admits_the_branch() {
    // The failure direction is deliberate and is the shell's: this gate spends
    // someone else's minutes when it is wrong in one direction and blocks
    // correct work when it is wrong in the other, and only the second is
    // unrecoverable by waiting. A file type with no known comment syntax is all
    // code, so any change to it is a code change.
    let root = repo(
        "unknown-extension",
        &[("data.csv", "a,b\n1,2\n")],
        &Head {
            written: &[("data.csv", "a,b\n1,3\n")],
            removed: &[],
        },
    );
    admitted(&root);
}

// carried: "an empty diff is not judged" crates/batten/tests/prose_only.rs
#[test]
fn an_empty_branch_is_not_a_subject() {
    // Refusing one would fire on every freshly-cut branch before a line is
    // written, which is a gate refusing the act of starting work.
    let root = repo(
        "empty",
        &[("a.md", "prose\n")],
        &Head {
            written: &[],
            removed: &[],
        },
    );
    admitted(&root);
}

// carried: "no base to diff against is not judged, rather than refused" crates/batten/tests/prose_only.rs
#[test]
fn an_unresolvable_base_says_nothing_rather_than_refusing() {
    // COULD-NOT-LOOK IS NOT A VERDICT, and here the vacuous direction would be a
    // REFUSAL rather than a pass — the branch blocked over a question the engine
    // could not ask. `base_delta` answers `None` for an unresolvable base and
    // the module reads the undefined path as not-holding.
    let root = common::scratch("prose-only-no-base");
    common::git_in(&root, &["init", "--initial-branch=main"]);
    write_all(&root, &[("a.md", "prose\n")]);
    install_module(&root);
    common::git_in(&root, &["add", "-A"]);
    common::git_in(&root, &["commit", "-m", "only"]);
    // No `refs/remotes/origin/main` is ever created, which is the condition.
    admitted(&root);
}

// subsumed: "a Rust block comment is NOT read as prose" crates/batten/tests/prose_only.rs
#[test]
fn a_shell_program_carrying_no_extension_is_read_as_shell() {
    // `mise-tasks/` programs carry no extension (CLOUD-865 renamed most to
    // `.sh`, but a re-added extensionless task must still be read). Without the
    // directory clause this file falls to the unrecognised arm, its whole text
    // becomes the remainder, and a comment-only edit reads as code.
    let root = repo(
        "extensionless",
        &[(
            "mise-tasks/thing",
            "#!/usr/bin/env bash\n# a note\necho hi\n",
        )],
        &Head {
            written: &[(
                "mise-tasks/thing",
                "#!/usr/bin/env bash\n# a different note\necho hi\n",
            )],
            removed: &[],
        },
    );
    refused(&root);
}

// changed: "the refusal names paths and a count, never a line of the diff" crates/batten/tests/prose_only.rs the shell printed every changed path beside the count; the port emits the count alone, because a diff is content nobody has published
#[test]
fn the_finding_carries_a_count_and_never_a_path() {
    // Non-negotiable rule 4, and it does real work here: a diff is content
    // somebody has not published yet, and the branch's own file list is exactly
    // that. The shell printed every path; this prints how many.
    let root = repo(
        "pointer",
        &[("a.md", "one\n"), ("b.md", "two\n")],
        &Head {
            written: &[("a.md", "one edited\n"), ("b.md", "two edited\n")],
            removed: &[],
        },
    );
    let verdicts = common::verdicts_in(&root);
    let scan = rules::run_static(
        &[row()],
        &[],
        batten::policy::Vocabulary {
            patterns: &[],
            verdicts: &verdicts,
            recorders: &[],
        },
        &root,
    )
    .expect("the read surface runs a policy row");
    let finding = scan.findings.first().expect("one finding");
    // THE COUNT LIVES IN THE REMEDIATION LINE, NOT IN `path`, and that is the
    // engine's answer rather than this module's. `rules::first_pointer` takes a
    // finding's path from the first PATH-BEARING subject, and this class
    // deliberately has none — so the path falls back to the module that decided,
    // which is itself a pointer and not a leak.
    //
    // What matters is the direction, and it is asserted on both channels: no
    // changed path reaches either, and the count reaches the one a reader sees.
    assert!(
        !finding.path.contains(".md"),
        "no changed path reaches the pointer: {}",
        finding.path
    );
    assert!(
        finding.path.contains('2'),
        "the count does, in the one field a line-less finding can carry it: {}",
        finding.path
    );
    let rendered = format!("{finding:?}");
    assert!(
        !rendered.contains("a.md") && !rendered.contains("b.md"),
        "and no changed path reaches the whole finding either: {rendered}"
    );
}

// THE TWO CASES THIS FILE DOES NOT CARRY, and both moved rather than vanished.
//
// `tests/prose-only-check.bats` asserted the shell's override — that
// `BATTEN_PROSE_ONLY_OVERRIDE=1` admitted the branch and appended a line saying
// which one — and that its refusal named where the content should go rather than
// merely naming a flag. CLOUD-1051 is what happened to both.
//
// The override is no longer an environment variable, so there is nothing here to
// assert about one: it is an issued, content-addressed, single-use record, and
// `crates/batten/tests/admission.rs` is where every clause of it is tested —
// including the recording half, which is now the record's existence rather than
// an append to a log.
//
// The remedy is no longer prose this gate composes. It is
// `V-PROSE-ONLY-DIFF`'s declared `R-BATCH-IT` route, and `verdict::validate`
// refuses a class that declares no route at all — so "the refusal names
// something to run" stopped being a property of this gate's message and became a
// property of the registry. `crates/batten/tests/verdict_registry.rs` holds it.
//
// subsumed: "the override admits the branch and records which one it admitted" crates/batten/tests/admission.rs
// subsumed: "the remedy names where the content should go, not merely a flag" crates/batten/tests/verdict_registry.rs
