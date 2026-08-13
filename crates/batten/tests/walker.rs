//! What the tree walk selects, and from where (CLOUD-214).
//!
//! Two defects blocked adoption, and both were properties of the walk rather
//! than of any rule:
//!
//! * It skipped only `.git`, so a rule's file set was the whole working tree.
//!   Measured on this repository after one `cargo build`: **9221** paths, of
//!   which **8891 (96%)** were ignored build output under `target/` and 330 were
//!   the repository's own. A `forbid` glob was one broad pattern away from
//!   reporting findings against compiler artifacts.
//! * It anchored at `.`, so `batten check` from a subdirectory failed to find
//!   the config it was standing inside. A pre-commit hook survived that because
//!   git runs it at the root; an agent part-way through a trajectory did not.
//!
//! The predicate is behavioural — the walk is what evaluates every rule, so
//! there is nothing here a `[[rule]]` row could assert about itself. These cases
//! assert what a run *reads* and what it *reports*, over the compiled binary.
//!
//! The ignored-tree case is deliberately not "the finding did not appear": that
//! passes for a walk that read the file and matched nothing. The fixture makes
//! the ignored file **carry the banned shape**, so a walk that opened it would
//! have to report it.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::path::PathBuf;

use common::{Fixture, batten, git_in, run, stdout};

/// A `forbid` row reaching every `.rs` file at any depth — the recursive shape
/// that used to drag in `target/`.
///
/// `**/*.rs` rather than a bare `**`, for a reason worth stating: a rule's own
/// `pattern` is a literal that appears in the config file that declares it, so a
/// glob selecting `batten.toml` makes every such rule match itself. Consumer #1
/// solves that by scoping its globs; these fixtures do the same.
fn rust_config(pattern: &str) -> String {
    format!(
        "version = 1\n\n[[rule]]\nid = \"no-banned\"\nkind = \"forbid\"\nglob = \"**/*.rs\"\npattern = \"{pattern}\"\nseverity = \"deny\"\n"
    )
}

/// The shape these fixtures ban. Named through a constant so it never has to be
/// spelled inside a config string that the same rule would then select.
const BANNED: &str = "BANNED";

/// A repo whose `.gitignore` excludes two trees, with the banned shape planted
/// inside both of them and nowhere the repository owns.
fn ignored_tree(name: &str) -> PathBuf {
    Fixture::new(name)
        .config(&rust_config(BANNED))
        .file(".gitignore", "/target\n/vendored\n")
        // Ignored, and carrying the banned shape: a walk that reads either must
        // report it, so silence here is evidence the file was never opened.
        .file("target/debug/build.rs", "BANNED\n")
        .file("vendored/third_party/lib.rs", "BANNED\n")
        // Tracked, and clean — the walk must still reach it.
        .file("src/lib.rs", "fine\n")
        .git()
        .build()
}

#[test]
fn an_ignored_tree_is_never_read() {
    let dir = ignored_tree("walker-gitignore");
    let output = run(&dir, &["check"]);
    let text = stdout(&output);
    assert_eq!(
        output.status.code(),
        Some(0),
        "nothing the repository owns carries the shape: {text}"
    );
    assert!(
        !text.contains("target/"),
        "an ignored build tree is not policy input: {text}"
    );
    assert!(
        !text.contains("vendored/"),
        "an ignored vendored tree is not policy input either: {text}"
    );
}

#[test]
fn a_file_the_repository_owns_is_still_read() {
    // The other half, and the one that makes the case above mean something: a
    // walk that selected nothing would pass it vacuously.
    let dir = ignored_tree("walker-owned");
    common::write(&dir, "src/lib.rs", "BANNED\n");

    let output = run(&dir, &["check"]);
    assert_eq!(output.status.code(), Some(2), "a tracked hit is a verdict");
    assert!(
        stdout(&output).contains("src/lib.rs"),
        "the tracked file is still selected: {}",
        stdout(&output)
    );
}

#[test]
fn hidden_directories_are_policy_input() {
    // `ignore` skips dotfiles by default, and this repository's committed rules
    // select `.github/`, `.serena/` and `.claude/` outright — so the default
    // would turn live gates into dead ones with no diagnostic at all. Pinned
    // here rather than left to the crate's default.
    let dir = Fixture::new("walker-hidden")
        .config(
            "version = 1\n\n[[rule]]\nid = \"no-banned\"\nkind = \"forbid\"\nglob = \".github/**/*.yml\"\npattern = \"BANNED\"\nseverity = \"deny\"\n",
        )
        .file(".github/workflows/ci.yml", "BANNED\n")
        .git()
        .build();

    let output = run(&dir, &["check"]);
    assert_eq!(output.status.code(), Some(2));
    assert!(
        stdout(&output).contains(".github/workflows/ci.yml"),
        "a dot-directory is ordinary policy input: {}",
        stdout(&output)
    );
}

#[test]
fn a_run_from_a_subdirectory_matches_a_run_from_the_root() {
    // The adoption blocker: this used to exit 1 with "no config found at
    // ./batten.toml" while standing inside the repository that carries it.
    //
    // Byte equality is the assertion, not merely "it worked": the pointers are
    // root-relative, so the same finding has to read identically from anywhere,
    // or a consumer parsing output would get a different answer per cwd.
    let dir = Fixture::new("walker-subdir")
        .config(&rust_config(BANNED))
        .file("crates/deep/src/lib.rs", "BANNED\n")
        .git()
        .build();

    let root = run(&dir, &["check"]);
    let nested = batten()
        .args(["check"])
        .current_dir(dir.join("crates/deep/src"))
        .output()
        .expect("run batten from a subdirectory");

    assert_eq!(root.status.code(), Some(2), "the root run finds it");
    assert_eq!(
        nested.status.code(),
        Some(2),
        "and so does the nested one: {}",
        String::from_utf8_lossy(&nested.stderr)
    );
    assert_eq!(
        root.stdout, nested.stdout,
        "root-relative pointers read identically from any directory"
    );
    assert!(
        stdout(&root).contains("crates/deep/src/lib.rs"),
        "and they are relative to the ROOT, not the cwd: {}",
        stdout(&root)
    );
}

#[test]
fn a_directory_that_is_not_a_repository_still_checks() {
    // The fallback the anchor keeps: a directory carrying a `batten.toml` and no
    // git history is a legitimate thing to check, and making git a precondition
    // would refuse a case that worked before this change.
    let dir = Fixture::new("walker-no-git")
        .config(&rust_config(BANNED))
        .file("src/lib.rs", "BANNED\n")
        .build();

    let output = run(&dir, &["check"]);
    assert_eq!(
        output.status.code(),
        Some(2),
        "no repository is not a reason to refuse: {}",
        common::stderr(&output)
    );
    assert!(stdout(&output).contains("src/lib.rs"));
}

#[test]
fn a_malformed_glob_is_refused_naming_the_row() {
    // `globset` rejects patterns the hand-rolled matcher silently accepted. The
    // failure has to be exit 1 naming the row — never a rule that compiles to
    // nothing and reads as a gate that found nothing wrong.
    let dir = Fixture::new("walker-bad-glob")
        .config("version = 1\n\n[[rule]]\nid = \"unclosed-class\"\nkind = \"forbid\"\nglob = \"crates/[unclosed\"\npattern = \"BANNED\"\nseverity = \"deny\"\n")
        .file("crates/lib.rs", "BANNED\n")
        .git()
        .build();

    let output = run(&dir, &["check"]);
    assert_eq!(
        output.status.code(),
        Some(1),
        "a malformed glob is a config error, not a verdict"
    );
    assert!(
        common::stderr(&output).contains("unclosed-class"),
        "and it names the row: {}",
        common::stderr(&output)
    );
}

#[test]
fn the_walk_is_byte_stable_across_runs() {
    // `ignore` yields in directory order, which is filesystem-defined; §6 says
    // identical state produces identical bytes, and the sort is what delivers it.
    let dir = Fixture::new("walker-stable")
        .config(&rust_config(BANNED))
        .files(&[
            ("a/one.rs", "BANNED\n"),
            ("b/two.rs", "BANNED\n"),
            ("c/three.rs", "BANNED\n"),
        ])
        .git()
        .build();
    git_in(&dir, &["add", "-A"]);

    let first = run(&dir, &["check"]);
    let second = run(&dir, &["check"]);
    assert_eq!(first.stdout, second.stdout);
    assert_eq!(first.status.code(), Some(2));
}
