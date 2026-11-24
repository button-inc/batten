//! `batten startup` where `.` holds no `batten.toml` and is inside no repository:
//! the directory a cloud container's Setup script runs in (CLOUD-2752).
//!
//! **THE ONLY DETERMINISTIC RECOVERY IS A FILE WRITTEN AT BUILD.** A restart is a
//! reboot with the disk kept, the Setup script does not run again, and the harness
//! loads hooks only from files — so after the unchanged Setup line has run, the
//! directory it ran in must carry batten's registration, and the authorities around
//! it must be recorded for the hook to pin from its first call.
//!
//! Every root here is OUTSIDE this repository's tree: one under `target/` is inside
//! the checkout holding this build, and would be judged by the anchored arm.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::{Path, PathBuf};
use std::process::Output;

use common::{StateHome as _, scratch_outside_tree, stderr};

/// A checkout carrying its own authority under `root`.
fn checkout(root: &Path, name: &str, config: &str) -> PathBuf {
    let repo = root.join(name);
    std::fs::create_dir_all(&repo).expect("the fixture checkout");
    common::init_repo(&repo);
    common::write(&repo, "batten.toml", config);
    repo
}

/// `<case>/root`, with a home directory that is NOT an ancestor of it.
fn layout(name: &str) -> (PathBuf, PathBuf) {
    let base = scratch_outside_tree("startup-unanchored", name);
    let root = base.join("root");
    let home = base.join("home");
    std::fs::create_dir_all(&root).expect("the session root");
    std::fs::create_dir_all(&home).expect("the home directory");
    (root, home)
}

fn startup(root: &Path, home: &Path, args: &[&str]) -> Output {
    common::batten()
        .current_dir(root)
        .args([&["startup"], args].concat())
        .state_home(home)
        .env_remove("BATTEN_ENVIRONMENT")
        .output()
        .expect("the binary runs")
}

fn registers_batten(dir: &Path) -> bool {
    std::fs::read_to_string(dir.join(".claude/settings.json"))
        .is_ok_and(|text| text.contains("batten adjudicate"))
}

fn registered_events(dir: &Path) -> usize {
    let text = std::fs::read_to_string(dir.join(".claude/settings.json")).unwrap_or_default();
    let document: serde_json::Value = serde_json::from_str(&text).unwrap_or_default();
    document
        .get("hooks")
        .and_then(serde_json::Value::as_object)
        .map_or(0, serde_json::Map::len)
}

/// How many events Batten derives for Claude Code: the whole hook surface, so
/// the assertion follows it rather than a count typed when it was smaller.
fn derived_events(dir: &Path) -> usize {
    let derived = common::batten()
        .current_dir(dir)
        .args(["generate", "hooks", "--harness", "claude-code"])
        .output()
        .expect("the binary runs");
    let document: serde_json::Value =
        serde_json::from_slice(&derived.stdout).expect("generate hooks parses");
    document
        .get("hooks")
        .unwrap_or(&document)
        .as_object()
        .map_or(0, serde_json::Map::len)
}

/// The authorities `startup` recorded for `root`, read back off the store the
/// child wrote.
fn recorded(home: &Path, root: &Path) -> Option<Vec<PathBuf>> {
    batten::state::recorded_root_authorities_in(
        &home.join("data").join("batten"),
        &batten::git::canonical(root),
        "batten.toml",
    )
}

fn canonical(path: &Path) -> PathBuf {
    batten::git::canonical(path)
}

#[test]
fn repair_above_one_checkout_registers_the_root_and_records_its_authority() {
    // THE REGRESSION. Red before CLOUD-2752: `startup: 0 row(s), 0 failed` and
    // no file — the Setup line ran and the session it built ran unmediated.
    let (root, home) = layout("one-checkout");
    let repo = checkout(&root, "repo", "version = 1\n");
    let output = startup(&root, &home, &["--repair"]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert!(registers_batten(&root), "{}", stderr(&output));
    assert_eq!(
        registered_events(&root),
        derived_events(&repo),
        "every derived event is registered"
    );
    assert_eq!(recorded(&home, &root), Some(vec![canonical(&repo)]));
    assert!(
        !root.parent().unwrap().join(".claude").exists(),
        "nothing is written above the root"
    );
}

#[test]
fn repair_at_home_writes_nothing() {
    // The bound: the surface at the home directory is the user-level one, loaded
    // by a session rooted at a repository too, where batten would fire twice.
    let (root, _home) = layout("at-home");
    checkout(&root, "repo", "version = 1\n");
    for home in [root.clone(), root.join("below")] {
        let output = startup(&root, &home, &["--repair"]);
        assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
        assert!(
            !registers_batten(&root),
            "nothing may be written at or above {}",
            home.display()
        );
    }
}

#[test]
fn two_checkouts_are_both_recorded() {
    let (root, home) = layout("two-checkouts");
    let a = checkout(&root, "a", "version = 1\n");
    let b = checkout(&root, "b", "version = 1\n");
    let output = startup(&root, &home, &["--repair"]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert_eq!(
        recorded(&home, &root),
        Some(vec![canonical(&a), canonical(&b)])
    );
}

#[test]
fn a_config_above_the_root_is_recorded() {
    // A config can sit at any level above the root, and it comes after the
    // children: nearer authorities first.
    let (root, home) = layout("config-above");
    let parent = root.parent().unwrap().to_path_buf();
    common::write(&parent, "batten.toml", "version = 1\n");
    let repo = checkout(&root, "repo", "version = 1\n");
    let output = startup(&root, &home, &["--repair"]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert_eq!(
        recorded(&home, &root),
        Some(vec![canonical(&repo), canonical(&parent)])
    );
}

#[test]
fn bare_startup_above_a_checkout_writes_nothing() {
    let (root, home) = layout("bare");
    checkout(&root, "repo", "version = 1\n");
    let output = startup(&root, &home, &[]);
    assert_eq!(
        output.status.code(),
        Some(1),
        "a registration is owed, and bare startup reports it as `Usage`, never \
         the `2` a harness reads as a denial: {}",
        stderr(&output)
    );
    assert!(!registers_batten(&root), "bare startup writes nothing");
    assert_eq!(recorded(&home, &root), None, "and records nothing");
}

#[test]
fn startup_inside_a_repository_without_a_config_is_unchanged() {
    let (root, home) = layout("inside-a-repository");
    common::init_repo(&root);
    let nested = root.join("sub");
    std::fs::create_dir_all(&nested).expect("a subdirectory");
    let output = startup(&nested, &home, &["--repair"]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        "startup: 0 row(s), 0 failed"
    );
    assert!(!registers_batten(&nested) && !registers_batten(&root));
}

#[test]
fn json_keeps_the_outcomes_on_standard_output() {
    let (root, home) = layout("json");
    checkout(&root, "repo", "version = 1\n");
    let output = startup(&root, &home, &["--repair", "--json"]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let outcomes: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("standard output is the outcomes array");
    assert!(outcomes.is_array(), "{outcomes}");
    assert!(
        stderr(&output).contains("registered at") && stderr(&output).contains("authority"),
        "the registration and authority lines are on standard error: {}",
        stderr(&output)
    );
}

/// A row whose check records the directory it ran in, and passes.
fn recording_row(mark: &Path) -> String {
    format!(
        "version = 1\n\n[[startup]]\nid = \"where\"\ngloss = \"records its working directory\"\n\
         check = [\"sh\", \"-c\", \"pwd -P > '{}'\"]\n",
        mark.display()
    )
}

#[test]
fn each_members_rows_run_in_that_member() {
    let (root, home) = layout("rows-in-member");
    let mark = root.parent().unwrap().join("where");
    let repo = checkout(&root, "repo", &recording_row(&mark));
    let output = startup(&root, &home, &["--repair"]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let ran_in = std::fs::read_to_string(&mark).expect("the member's row ran");
    assert_eq!(Path::new(ran_in.trim()), canonical(&repo));
}

#[test]
fn a_failing_row_leaves_the_registration_and_the_record() {
    // ORDER IS THE GUARANTEE: registration, record, then rows, so a row that
    // fails cannot undo either.
    let (root, home) = layout("failing-row");
    let repo = checkout(
        &root,
        "repo",
        "version = 1\n\n[[startup]]\nid = \"never\"\ngloss = \"always fails\"\n\
         check = [\"false\"]\nrepair = [\"false\"]\n",
    );
    let output = startup(&root, &home, &["--repair"]);
    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    assert!(registers_batten(&root));
    assert_eq!(recorded(&home, &root), Some(vec![canonical(&repo)]));
}

#[cfg(unix)]
#[test]
fn a_linked_root_surface_is_replaced_by_a_regular_file() {
    // Measured 2026-11-24: a regular file written at the root took effect
    // mid-session, while a link into the checkout is a registration that moves
    // or vanishes with it. Red before: a link already resolving to a complete
    // registration owed no event, so it was left a link.
    let (root, home) = layout("linked-surface");
    let repo = checkout(&root, "repo", "version = 1\n");
    let first = startup(&root, &home, &["--repair"]);
    assert_eq!(first.status.code(), Some(0), "{}", stderr(&first));
    let surface = root.join(".claude/settings.json");
    let target = repo.join(".claude/settings.json");
    std::fs::create_dir_all(target.parent().unwrap()).expect("the checkout's .claude");
    std::fs::rename(&surface, &target).expect("move the registration into the checkout");
    std::os::unix::fs::symlink(&target, &surface).expect("link the root surface");
    let held = std::fs::read_to_string(&target).expect("the linked file");
    let output = startup(&root, &home, &["--repair"]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let meta = std::fs::symlink_metadata(&surface).expect("the root surface");
    assert!(
        meta.file_type().is_file(),
        "the root surface is a regular file"
    );
    assert!(registers_batten(&root), "{}", stderr(&output));
    assert_eq!(
        registered_events(&root),
        derived_events(&repo),
        "every derived event is registered"
    );
    assert_eq!(
        std::fs::read_to_string(&target).expect("the linked file"),
        held,
        "the file the link pointed at is untouched"
    );
}

/// A FRESH registration where the surface is a DANGLING link — nothing to read,
/// so every event is owed. Fails by: a write through the link, which leaves the
/// link and creates the file it points at; only the write-then-rename replaces
/// the link itself with a regular file.
#[cfg(unix)]
#[test]
fn a_fresh_registration_is_a_regular_file() {
    let (root, home) = layout("regular-file");
    checkout(&root, "repo", "version = 1\n");
    let surface = root.join(".claude/settings.json");
    let target = root.parent().unwrap().join("elsewhere.json");
    std::fs::create_dir_all(surface.parent().unwrap()).expect("the root's .claude");
    std::os::unix::fs::symlink(&target, &surface).expect("a dangling link");
    let output = startup(&root, &home, &["--repair"]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let meta = std::fs::symlink_metadata(&surface).expect("the root surface exists");
    assert!(meta.file_type().is_file(), "never a link");
    assert!(registers_batten(&root), "{}", stderr(&output));
    assert!(!target.exists(), "nothing is written through the link");
}

/// A link that already resolves to a complete registration is OWED its rewrite,
/// and bare `startup` says so: exit 1 and a line, the link left as it is. Fails
/// by: the rewrite owed but unreported, which exits 0 over a surface `--repair`
/// would then change.
#[cfg(unix)]
#[test]
fn bare_startup_reports_a_linked_surface_as_owed() {
    let (root, home) = layout("linked-bare");
    let repo = checkout(&root, "repo", "version = 1\n");
    let first = startup(&root, &home, &["--repair"]);
    assert_eq!(first.status.code(), Some(0), "{}", stderr(&first));
    let surface = root.join(".claude/settings.json");
    let target = repo.join(".claude/settings.json");
    std::fs::create_dir_all(target.parent().unwrap()).expect("the checkout's .claude");
    std::fs::rename(&surface, &target).expect("move the registration into the checkout");
    std::os::unix::fs::symlink(&target, &surface).expect("link the root surface");
    let output = startup(&root, &home, &[]);
    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    assert!(
        stderr(&output).contains("is a link; its rewrite as a regular file owed"),
        "{}",
        stderr(&output)
    );
    let meta = std::fs::symlink_metadata(&surface).expect("the root surface");
    assert!(meta.file_type().is_symlink(), "bare startup writes nothing");
}

/// A root surface this verb cannot read is a REFUSAL: exit 1 and a line naming
/// the file, nothing written. Fails by: an unreadable surface read as nothing
/// owed, which exits 0 with no line while the session rooted there runs
/// unmediated.
#[test]
fn an_unreadable_root_surface_is_refused_with_a_line() {
    for (name, raw) in [("not-an-object", "[]\n"), ("not-json", "{ not json\n")] {
        let (root, home) = layout(&format!("unreadable-{name}"));
        checkout(&root, "repo", "version = 1\n");
        common::write(&root, ".claude/settings.json", raw);
        let output = startup(&root, &home, &["--repair"]);
        assert_eq!(output.status.code(), Some(1), "{name}: {}", stderr(&output));
        assert!(
            stderr(&output).contains("so nothing is registered at"),
            "{name}: {}",
            stderr(&output)
        );
        assert_eq!(
            std::fs::read_to_string(root.join(".claude/settings.json")).unwrap(),
            raw,
            "{name}: the surface is left as it was"
        );
    }
}
