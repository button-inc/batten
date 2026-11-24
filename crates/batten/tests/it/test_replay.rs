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

/// Run the replay. The outer run's `NEXTEST_PROFILE` is removed: a caller's
/// may name a profile this scratch crate does not declare (this repository's
/// CI named `ci` until CLOUD-2588), and nextest would refuse the replay before
/// running it. In a real repository the tree carries its own
/// profiles, which is why the verb passes the variable through and this does not.
fn replay(dir: &Path, base: &str) -> Output {
    common::batten()
        .state_dir(&data_dir(dir))
        .env_remove("NEXTEST_PROFILE")
        .args(["test", "replay", "--base", base])
        .current_dir(dir)
        .streamed_output()
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
            .contains("test-expectation-changed src/lib.rs::tests::sums (refused not-asked)"),
        "{}",
        text(&output)
    );
}

/// A REFUSAL NAMES ITS CAUSE (CLOUD-2505). The pair was asked, and the answer
/// chosen does not say `Admit`, so the line says that rather than reading as
/// never asked.
#[test]
fn an_answer_that_does_not_admit_names_its_cause() {
    let (dir, base) = repo("replay-not-admitted");
    narrowed(&dir);
    let pair = "test-expectation-changed src/lib.rs::tests::sums";
    let entry = serde_json::json!({
        "question": format!("Override `{pair}`?"),
        "options": [
            {"label": "Yes, override", "description": "the expectation changes"},
            {"label": "No", "description": "keep it"}
        ],
        "answer": "Yes, override",
        "at": 1
    });
    common::write(&dir, ".batten/asked.jsonl", &format!("{entry}\n"));
    let output = replay(&dir, &base);
    assert_eq!(output.status.code(), Some(2), "{}", text(&output));
    assert!(
        String::from_utf8_lossy(&output.stdout)
            .contains(&format!("{pair} (refused answered-without-admit)")),
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
            .contains("test-removed src/lib.rs::tests::sums (refused not-asked)"),
        "{}",
        text(&output)
    );
}

/// Whether `root` holds a directory named `name` at any depth.
fn holds_directory_named(root: &Path, name: &str) -> bool {
    std::fs::read_dir(root)
        .into_iter()
        .flatten()
        .flatten()
        .any(|entry| {
            let path = entry.path();
            path.is_dir() && (entry.file_name() == name || holds_directory_named(&path, name))
        })
}

/// The replay's build lives under the checkout's `target/`, where the prune
/// derives it as a nested build tree, and never in the state directory, where
/// no reclaim reaches it (CLOUD-2196: 5308 MB there on #1132).
#[test]
fn a_replay_builds_where_the_prune_can_reach_it() {
    let (dir, base) = repo("replay-placed");
    head(
        &dir,
        &BASE.replace(
            "assert_eq!(super::add(2, 2), 4);",
            "let four = super::add(2, 2);\n        assert_eq!(four, 4);",
        ),
    );
    let output = replay(&dir, &base);
    assert!(output.status.success(), "{}", text(&output));
    assert!(
        dir.join("target").join("replay").join("debug").is_dir(),
        "the replay builds under the checkout's target/"
    );
    assert!(
        // `debug`, not `target`: the throwaway tree carries nextest's own run
        // store at `tree/target/nextest`, which is no build and goes with it.
        !holds_directory_named(&data_dir(&dir), "debug"),
        "no build tree is left under the state directory"
    );
}

/// CRASH-ONLY: each verdict is journaled the moment it is read, so a rerun over
/// the same HEAD and base reads every one back and builds nothing. The build
/// tree is removed between the runs; a rerun that judged anything would
/// rebuild it, and one that read nothing back would not name the test again.
#[test]
fn a_rerun_over_the_same_head_and_base_reads_every_verdict_back() {
    let (dir, base) = repo("replay-journaled");
    narrowed(&dir);
    let first = replay(&dir, &base);
    assert_eq!(first.status.code(), Some(2), "{}", text(&first));
    let built = dir.join("target").join("replay");
    assert!(built.is_dir(), "the first run builds: {}", text(&first));
    std::fs::remove_dir_all(&built).unwrap();
    let second = replay(&dir, &base);
    assert_eq!(second.status.code(), Some(2), "{}", text(&second));
    assert_eq!(
        String::from_utf8_lossy(&second.stdout),
        String::from_utf8_lossy(&first.stdout),
        "the journaled verdict reads as the judged one"
    );
    assert!(
        !built.exists(),
        "every verdict was journaled, so nothing was built"
    );
}

/// The kept tree is HEAD's: a HEAD that moves rematerialises it, and the test
/// whose base body is unchanged but whose HEAD moved is judged again, here to
/// a different verdict.
#[test]
fn a_moved_head_judges_again() {
    let (dir, base) = repo("replay-moved-head");
    narrowed(&dir);
    let first = replay(&dir, &base);
    assert_eq!(first.status.code(), Some(2), "{}", text(&first));
    head(
        &dir,
        &BASE.replace(
            "assert_eq!(super::add(2, 2), 4);",
            "assert!(super::add(2, 2) > 3);",
        ),
    );
    let second = replay(&dir, &base);
    assert!(second.status.success(), "{}", text(&second));
    assert!(second.stdout.is_empty(), "{}", text(&second));
}

/// A FAILED UNION BUILD NAMES WHERE ITS COMPILER OUTPUT IS KEPT (#1276), in
/// the plain report: HEAD drops the function the base body calls.
#[test]
fn a_union_build_that_failed_names_its_kept_output() {
    let (dir, base) = repo("replay-kept-log");
    head(
        &dir,
        &BASE.replace("pub fn add(", "pub fn plus(").replace(
            "super::add(2, 2), 4);",
            "super::plus(2, 2), 4);\n        let _ = 0;",
        ),
    );
    let output = replay(&dir, &base);
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("test replay: a union build failed"),
        "{}",
        text(&output)
    );
}

/// A `--structural` run builds nothing, so it names no log an earlier run kept.
///
/// Fails by: a kept log's pointer printed on a structural run.
#[test]
fn a_structural_run_names_no_kept_log() {
    let structural = |dir: &Path, base: &str| {
        common::batten()
            .state_dir(&data_dir(dir))
            .env_remove("NEXTEST_PROFILE")
            .args(["test", "replay", "--structural", "--base", base])
            .current_dir(dir)
            .streamed_output()
            .expect("run batten")
    };
    let (built, base) = repo("replay-structural-build-log");
    head(
        &built,
        &BASE.replace("pub fn add(", "pub fn plus(").replace(
            "super::add(2, 2), 4);",
            "super::plus(2, 2), 4);\n        let _ = 0;",
        ),
    );
    let (ran, ran_base) = repo("replay-structural-run-log");
    narrowed(&ran);
    for (dir, base, log) in [
        (&built, &base, "a union build failed"),
        (&ran, &ran_base, "a union test run failed"),
    ] {
        let full = replay(dir, base);
        assert!(
            String::from_utf8_lossy(&full.stdout).contains(log),
            "premise: {}",
            text(&full)
        );
        let after = structural(dir, base);
        assert!(
            !String::from_utf8_lossy(&after.stdout).contains(log),
            "{}",
            text(&after)
        );
    }
}

/// A crate whose test names an item through a path, for the item-move cases
/// (CLOUD-2790): `value` lives in `a`, the test spells `crate::a::value`.
const ITEMS_LIB: &str = "\
pub mod a;
pub mod b;

#[cfg(test)]
mod tests {
    #[test]
    fn named() {
        assert_eq!(crate::a::value(), 1);
    }
}
";

fn items_repo(name: &str) -> (PathBuf, String) {
    let dir = common::scratch(name);
    common::write(&dir, "Cargo.toml", MANIFEST);
    common::write(&dir, "src/lib.rs", ITEMS_LIB);
    common::write(&dir, "src/a.rs", "pub fn value() -> u8 {\n    1\n}\n");
    common::write(&dir, "src/b.rs", "");
    common::write(&dir, ".gitignore", "target/\nCargo.lock\n");
    common::init_repo(&dir);
    common::git_in(&dir, &["add", "-A"]);
    common::git_in(&dir, &["commit", "-qm", "base"]);
    let base = common::git_in(&dir, &["rev-parse", "HEAD"]);
    (dir, base)
}

/// `value` moves to `b`, returning `returns`, and the test's assertion becomes
/// `body`.
fn moved_to_b(dir: &Path, body: &str, returns: &str) {
    common::write(dir, "src/a.rs", "");
    common::write(
        dir,
        "src/b.rs",
        &format!("pub fn value() -> u8 {{\n    {returns}\n}}\n"),
    );
    common::write(
        dir,
        "src/lib.rs",
        &ITEMS_LIB.replace("assert_eq!(crate::a::value(), 1);", body),
    );
    common::git_in(dir, &["add", "-A"]);
    common::git_in(dir, &["commit", "-qm", "head"]);
}

/// Fails by: a path respelled at a moved item's new home read as a modified
/// assertion — the admission every respelled test used to cost. The crate sits
/// at the repository's root, so this also shows the index reads the tree's own
/// manifest rather than this repository's `crates/` layout.
#[test]
fn a_test_respelled_at_a_moved_items_home_is_clean() {
    let (dir, base) = items_repo("replay-item-moved");
    moved_to_b(&dir, "assert_eq!(crate::b::value(), 1);", "1");
    let output = replay(&dir, &base);
    assert!(output.status.success(), "{}", text(&output));
    assert!(output.stdout.is_empty(), "{}", text(&output));
}

/// Fails by: an unrelated item that merely shares the deleted one's name read
/// as its move, so a test switched to it passed unjudged.
#[test]
fn a_test_switched_to_another_item_of_its_name_is_reported() {
    let (dir, base) = items_repo("replay-item-switched");
    moved_to_b(&dir, "assert_eq!(crate::b::value(), 2);", "2");
    let output = replay(&dir, &base);
    assert_eq!(output.status.code(), Some(2), "{}", text(&output));
    assert!(
        String::from_utf8_lossy(&output.stdout)
            .contains("test-expectation-changed src/lib.rs::tests::named"),
        "{}",
        text(&output)
    );
}

/// A two-crate workspace for the cross-crate move (CLOUD-2804): `one` and `two`,
/// each with a `testing` module, and `one`'s holding a test over its helper.
fn two_crates(name: &str) -> (PathBuf, String) {
    let dir = common::scratch(name);
    common::write(
        &dir,
        "Cargo.toml",
        "[workspace]\nmembers = [\"one\", \"two\"]\nresolver = \"2\"\n",
    );
    for krate in ["one", "two"] {
        common::write(
            &dir,
            &format!("{krate}/Cargo.toml"),
            &format!("[package]\nname = \"{krate}\"\nversion = \"0.1.0\"\nedition = \"2021\"\n"),
        );
        common::write(&dir, &format!("{krate}/src/lib.rs"), "pub mod testing;\n");
    }
    common::write(
        &dir,
        "one/src/testing.rs",
        &format!("pub fn kept() {{}}\n{MOVED}"),
    );
    common::write(&dir, "two/src/testing.rs", "pub fn other() {}\n");
    common::write(&dir, ".gitignore", "target/\nCargo.lock\n");
    common::init_repo(&dir);
    common::git_in(&dir, &["add", "-A"]);
    common::git_in(&dir, &["commit", "-qm", "base"]);
    let base = common::git_in(&dir, &["rev-parse", "HEAD"]);
    (dir, base)
}

/// The helper and its test, moved together between the crates.
const MOVED: &str = "\
pub fn helper() -> u8 {
    1
}

#[cfg(test)]
mod tests {
    #[test]
    fn moved_across() {
        assert_eq!(crate::testing::helper(), 1);
    }
}
";

/// Fails by: a test whose name and body reappear in another crate read as
/// removed, because its old file still exists (no file-level move pairs it) and
/// the item index never saw a `cfg(test)` item. Measured on #1276: the
/// `batten-core` cut moved `testing.rs`' test and the structural replay refused it.
#[test]
fn a_test_moved_to_another_crate_is_not_removed() {
    let (dir, base) = two_crates("replay-cross-crate");
    common::write(&dir, "one/src/testing.rs", "pub fn kept() {}\n");
    common::write(
        &dir,
        "two/src/testing.rs",
        &format!("pub fn other() {{}}\n{MOVED}"),
    );
    common::git_in(&dir, &["add", "-A"]);
    common::git_in(&dir, &["commit", "-qm", "head"]);
    let output = common::batten()
        .state_dir(&data_dir(&dir))
        .args(["test", "replay", "--structural", "--base", base.trim()])
        .current_dir(&dir)
        .streamed_output()
        .expect("run batten");
    assert!(output.status.success(), "{}", text(&output));
    assert!(output.stdout.is_empty(), "{}", text(&output));
    // Anti-vacuity: the same test deleted outright is still refused.
    common::write(&dir, "two/src/testing.rs", "pub fn other() {}\n");
    common::git_in(&dir, &["add", "-A"]);
    common::git_in(&dir, &["commit", "-qm", "gone"]);
    let output = common::batten()
        .state_dir(&data_dir(&dir))
        .args(["test", "replay", "--structural", "--base", base.trim()])
        .current_dir(&dir)
        .streamed_output()
        .expect("run batten");
    assert_eq!(output.status.code(), Some(2), "{}", text(&output));
    assert!(
        String::from_utf8_lossy(&output.stdout)
            .contains("test-removed one/src/testing.rs::tests::moved_across"),
        "{}",
        text(&output)
    );
}

/// A file `git.rs` with a helper whose name another file shares (so no
/// tree-wide unique name pairs it), its own test, and a test left behind in
/// `other.rs` naming it through `crate::`.
fn git_rs(returns: &str, moved_expects: &str) -> String {
    format!(
        "pub fn run() -> u8 {{\n    {returns}\n}}\n\n#[cfg(test)]\nmod tests {{\n    #[test]\n    fn moved() {{\n        assert_eq!(crate::git::run(), {moved_expects});\n    }}\n}}\n"
    )
}

fn other_rs(call: &str, expects: &str) -> String {
    format!(
        "pub fn run() -> u8 {{\n    9\n}}\n\n#[cfg(test)]\nmod tests {{\n    #[test]\n    fn uses() {{\n        let got = {call};\n        assert_eq!(got, {expects});\n    }}\n}}\n"
    )
}

/// `one` holding `git` and `other`, committed as base.
fn uncut(name: &str) -> (PathBuf, String) {
    let dir = common::scratch(name);
    common::write(
        &dir,
        "Cargo.toml",
        "[workspace]\nmembers = [\"one\"]\nresolver = \"2\"\n",
    );
    common::write(
        &dir,
        "one/Cargo.toml",
        "[package]\nname = \"one\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    );
    common::write(&dir, "one/src/lib.rs", "pub mod git;\npub mod other;\n");
    common::write(&dir, "one/src/git.rs", &git_rs("1", "1"));
    common::write(
        &dir,
        "one/src/other.rs",
        &other_rs("crate::git::run()", "1"),
    );
    common::write(&dir, ".gitignore", "target/\nCargo.lock\n");
    common::init_repo(&dir);
    common::git_in(&dir, &["add", "-A"]);
    common::git_in(&dir, &["commit", "-qm", "base"]);
    let base = common::git_in(&dir, &["rev-parse", "HEAD"]);
    (dir, base)
}

/// `git` cut out of `one` into `two` as `cut-crate` cuts it: the file moved
/// verbatim, and `other.rs`' path to it respelled `two::git`.
fn cut(dir: &Path, git: &str, other: &str) {
    common::write(
        dir,
        "Cargo.toml",
        "[workspace]\nmembers = [\"one\", \"two\"]\nresolver = \"2\"\n",
    );
    common::write(
        dir,
        "one/Cargo.toml",
        "[package]\nname = \"one\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\ntwo = { path = \"../two\" }\n",
    );
    common::write(
        dir,
        "two/Cargo.toml",
        "[package]\nname = \"two\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    );
    common::write(dir, "one/src/lib.rs", "pub mod other;\n");
    std::fs::remove_file(dir.join("one/src/git.rs")).unwrap();
    common::write(dir, "two/src/lib.rs", "pub mod git;\n");
    common::write(dir, "two/src/git.rs", git);
    common::write(dir, "one/src/other.rs", other);
    common::git_in(dir, &["add", "-A"]);
    common::git_in(dir, &["commit", "-qm", "cut"]);
}

/// Fails by: a test the cut moved reads as modified, since `run` is declared
/// in two files and no tree-wide pairing follows it, and a left-behind test
/// whose base body says `crate::git` is spliced unrespelled, so it does not
/// compile at HEAD and is refused as an expectation change. Measured on #1276:
/// 750 such refusals at c4426587.
#[test]
fn a_test_moved_by_a_crate_cut_replays_clean() {
    let (dir, base) = uncut("replay-cut-clean");
    // `uses` is rewritten beyond the respelling, so its base body is spliced
    // and run: it must be spliced in the cut's spelling to compile.
    cut(
        &dir,
        &git_rs("1", "1"),
        &other_rs("two::git::run() + 0", "1"),
    );
    let output = replay(&dir, base.trim());
    assert!(output.status.success(), "{}", text(&output));
    assert!(output.stdout.is_empty(), "{}", text(&output));
}

/// Anti-vacuity for the test above: the same cut with each assertion changed
/// is still refused, by name, for both the moved test and the left-behind one.
#[test]
fn a_test_moved_by_a_crate_cut_with_a_changed_assertion_is_refused() {
    let (dir, base) = uncut("replay-cut-changed");
    cut(&dir, &git_rs("2", "2"), &other_rs("two::git::run()", "2"));
    let output = replay(&dir, base.trim());
    assert_eq!(output.status.code(), Some(2), "{}", text(&output));
    let stdout = String::from_utf8_lossy(&output.stdout);
    for test in [
        "two/src/git.rs::tests::moved",
        "one/src/other.rs::tests::uses",
    ] {
        assert!(
            stdout.contains(&format!("test-expectation-changed {test}")),
            "{}",
            text(&output)
        );
    }
}
