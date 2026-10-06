//! The base-test replay (CLOUD-2090): each modified `#[test]`'s BASE body is run
//! against HEAD's code, and a base expectation HEAD no longer meets is refused by
//! name unless a recorded answer admits it.
//!
//! The subject is a tiny cargo crate in a scratch repository, so each case
//! compiles a handful of lines. Its `Cargo.toml` declares its own `[workspace]`
//! because the materialised tree lands under a state directory inside this
//! repository's `target/`, where cargo would otherwise adopt the enclosing
//! workspace.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common::{self, StateHome as _};

use std::path::{Path, PathBuf};
use std::process::Output;

const MANIFEST: &str = "\
[package]
name = \"replayed\"
version = \"0.1.0\"
edition = \"2021\"

[workspace]
";

const BASE: &str = "\
pub fn add(a: u32, b: u32) -> u32 {
    a + b
}

#[cfg(test)]
mod tests {
    #[test]
    fn sums() {
        assert_eq!(super::add(2, 2), 4);
    }
}
";

/// A repository whose first commit carries the crate at `BASE`, and the sha.
fn repo(name: &str) -> (PathBuf, String) {
    let dir = common::scratch(name);
    common::write(&dir, "Cargo.toml", MANIFEST);
    common::write(&dir, "src/lib.rs", BASE);
    common::write(&dir, ".gitignore", "target/\nCargo.lock\n");
    common::init_repo(&dir);
    common::git_in(&dir, &["add", "-A"]);
    common::git_in(&dir, &["commit", "-qm", "base"]);
    let base = common::git_in(&dir, &["rev-parse", "HEAD"]);
    (dir, base)
}

/// Commit `lib` as HEAD.
fn head(dir: &Path, lib: &str) {
    common::write(dir, "src/lib.rs", lib);
    common::git_in(dir, &["add", "-A"]);
    common::git_in(dir, &["commit", "-qm", "head"]);
}

fn data_dir(dir: &Path) -> PathBuf {
    let mut name = dir.file_name().unwrap().to_os_string();
    name.push(".data");
    dir.with_file_name(name)
}

fn replay(dir: &Path, base: &str) -> Output {
    common::batten()
        .state_dir(&data_dir(dir))
        .args(["test", "replay", "--base", base])
        .current_dir(dir)
        .output()
        .expect("run batten")
}

fn text(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

#[test]
fn no_modified_test_builds_nothing() {
    let (dir, base) = repo("replay-none");
    head(
        &dir,
        &BASE.replace(
            "mod tests {\n",
            "mod tests {\n    #[test]\n    fn added() {\n        assert!(true);\n    }\n",
        ),
    );
    let output = replay(&dir, &base);
    assert!(output.status.success(), "{}", text(&output));
    assert!(output.stdout.is_empty(), "an added test is never replayed");
    assert!(
        !data_dir(&dir).join("batten").exists(),
        "nothing modified, so no tree is materialised and nothing is built"
    );
}

#[test]
fn a_rewritten_body_whose_base_still_passes_is_clean() {
    let (dir, base) = repo("replay-clean");
    head(
        &dir,
        &BASE.replace(
            "assert_eq!(super::add(2, 2), 4);",
            "let four = super::add(2, 2);\n        assert_eq!(four, 4);",
        ),
    );
    let output = replay(&dir, &base);
    assert!(output.status.success(), "{}", text(&output));
    assert!(output.stdout.is_empty(), "{}", text(&output));
}

/// HEAD breaks `add` for this input and loosens the test to match: the base
/// expectation no longer holds, and the replay names it.
fn narrowed(dir: &Path) {
    head(
        dir,
        &BASE
            .replace("    a + b\n", "    if a == 2 { 5 } else { a + b }\n")
            .replace(
                "assert_eq!(super::add(2, 2), 4);",
                "assert!(super::add(2, 2) > 3);",
            ),
    );
}

#[test]
fn a_narrowed_expectation_is_refused_by_name() {
    let (dir, base) = repo("replay-narrowed");
    narrowed(&dir);
    let output = replay(&dir, &base);
    assert_eq!(output.status.code(), Some(2), "{}", text(&output));
    assert!(
        String::from_utf8_lossy(&output.stdout)
            .contains("test-expectation-changed src/lib.rs::tests::sums (refused)"),
        "{}",
        text(&output)
    );
}

#[test]
fn an_asked_admission_lets_it_land() {
    let (dir, base) = repo("replay-admitted");
    narrowed(&dir);
    let pair = "test-expectation-changed src/lib.rs::tests::sums";
    let entry = serde_json::json!({
        "question": format!("Admit `{pair}`? add(2, 2) is 5 now, by design."),
        "options": [
            {"label": "Admit", "description": "the expectation changes"},
            {"label": "Refuse", "description": "keep it"}
        ],
        "answer": "Admit",
        "at": 1
    });
    common::write(&dir, ".batten/asked.jsonl", &format!("{entry}\n"));
    let output = replay(&dir, &base);
    assert!(output.status.success(), "{}", text(&output));
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("(asked)"),
        "{}",
        text(&output)
    );
}

#[test]
fn a_removed_test_is_refused_by_name() {
    let (dir, base) = repo("replay-removed");
    head(
        &dir,
        &BASE.replace(
            "    #[test]\n    fn sums() {\n        assert_eq!(super::add(2, 2), 4);\n    }\n",
            "",
        ),
    );
    let output = replay(&dir, &base);
    assert_eq!(output.status.code(), Some(2), "{}", text(&output));
    assert!(
        String::from_utf8_lossy(&output.stdout)
            .contains("test-removed src/lib.rs::tests::sums (refused)"),
        "{}",
        text(&output)
    );
}
