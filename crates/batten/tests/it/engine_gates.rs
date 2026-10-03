//! The engine pin's landing gates (CLOUD-2063): a source pin never lands, a
//! source pin is kept current by its fixer, and a release pin must load the
//! config and carry every verb a released lane invokes.
//!
//! The pinned release is a STUB seeded into the cache `engine gate` reads
//! (`<repository state dir>/engine/<tag>/batten`), so the cases measure the
//! gate's decisions and never reach the network. Each case runs under its own
//! state directory, outside its checkout, which is where the cache belongs.

#![cfg(unix)]
// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common::{self, StateHome as _};

use std::path::{Path, PathBuf};
use std::process::Output;

fn repo(name: &str, config: &str) -> PathBuf {
    let dir = common::scratch(name);
    common::write(&dir, "batten.toml", config);
    common::write(&dir, "crates/x/src/lib.rs", "fn a() {}\n");
    common::init_repo(&dir);
    common::git_in(&dir, &["add", "batten.toml", "crates/x/src/lib.rs"]);
    dir
}

/// The case's own data directory, a sibling of its checkout.
fn data_dir(dir: &Path) -> PathBuf {
    let mut name = dir.file_name().unwrap().to_os_string();
    name.push(".data");
    dir.with_file_name(name)
}

fn run(dir: &Path, args: &[&str]) -> Output {
    common::batten()
        .state_dir(&data_dir(dir))
        .args(args)
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

/// A stand-in for the pinned release: `config show` answers `config_exit`, and
/// `--help` succeeds only for the verbs it is told it has.
fn seed_release(dir: &Path, tag: &str, config_exit: u8, verbs: &[&str]) {
    let root = dir.canonicalize().unwrap();
    let cache = data_dir(dir)
        .join("batten")
        .join(batten::state::derive_repo_name(&root).unwrap())
        .join("engine")
        .join(tag);
    std::fs::create_dir_all(&cache).unwrap();
    let mut script =
        format!("#!/bin/sh\nif [ \"$1 $2\" = \"config show\" ]; then exit {config_exit}; fi\n");
    for verb in verbs {
        script.push_str("if [ \"$*\" = \"");
        script.push_str(verb);
        script.push_str(" --help\" ]; then exit 0; fi\n");
    }
    script.push_str("exit 2\n");
    common::write(&cache, "batten", &script);
    make_executable(&cache.join("batten"));
}

fn make_executable(path: &Path) {
    use std::os::unix::fs::PermissionsExt as _;
    let mut mode = std::fs::metadata(path)
        .expect("stat the stub")
        .permissions();
    mode.set_mode(0o755);
    std::fs::set_permissions(path, mode).expect("chmod the stub");
}

const LANE: &str = "\
jobs:
  land:
    steps:
      # `batten retired verb` is prose, never an invocation
      - run: |
          batten pr ensure \"$PR_NUM\"
      - run: batten gone verb --x
";

#[test]
fn a_source_pin_is_refused_on_the_landing_path() {
    let dir = repo(
        "engine-gate-source",
        &format!(
            "version = 1\nengine = {{ source = \"{}\" }}\n",
            "0".repeat(64)
        ),
    );
    let output = run(&dir, &["engine", "gate"]);
    assert!(!output.status.success(), "{}", text(&output));
    assert!(
        text(&output).contains("engine pin source never lands"),
        "{}",
        text(&output)
    );
}

#[test]
fn no_pin_is_nothing_to_judge() {
    let dir = repo("engine-gate-unpinned", "version = 1\n");
    let output = run(&dir, &["engine", "gate"]);
    assert!(output.status.success(), "{}", text(&output));
}

#[test]
fn the_fixer_rewrites_a_stale_source_pin_to_the_digest() {
    let stale = format!(
        "version = 1\nengine = {{ source = \"{}\" }}\n",
        "0".repeat(64)
    );
    let dir = repo("engine-pin-fixer", &stale);
    let checked = run(&dir, &["engine", "pin", "--check"]);
    assert!(!checked.status.success(), "--check names a stale pin");
    assert_eq!(
        std::fs::read_to_string(dir.join("batten.toml")).unwrap(),
        stale,
        "--check writes nothing"
    );
    let fixed = run(&dir, &["engine", "pin"]);
    assert!(fixed.status.success(), "{}", text(&fixed));
    let digest = text(&run(&dir, &["engine", "digest"])).trim().to_owned();
    assert_eq!(
        std::fs::read_to_string(dir.join("batten.toml")).unwrap(),
        format!("version = 1\nengine = {{ source = \"{digest}\" }}\n")
    );
    let again = run(&dir, &["engine", "pin", "--check"]);
    assert!(again.status.success(), "a current pin is left alone");
}

#[test]
fn the_fixer_leaves_a_release_pin_alone() {
    let pinned = "version = 1\nengine = { release = \"v0.0.1\" }\n";
    let dir = repo("engine-pin-release-kept", pinned);
    let output = run(&dir, &["engine", "pin"]);
    assert!(output.status.success(), "{}", text(&output));
    assert_eq!(
        std::fs::read_to_string(dir.join("batten.toml")).unwrap(),
        pinned
    );
}

#[test]
fn a_verb_the_pinned_release_lacks_is_drift() {
    let dir = repo(
        "engine-gate-verb",
        "version = 1\nengine = { release = \"v9.9.9\" }\n",
    );
    common::write(&dir, "lane.yml", LANE);
    seed_release(&dir, "v9.9.9", 0, &["pr ensure"]);
    let output = run(&dir, &["engine", "gate", "--lane", "lane.yml"]);
    assert!(!output.status.success(), "{}", text(&output));
    let said = text(&output);
    assert!(
        said.contains("batten gone verb not in engine pin v9.9.9"),
        "{said}"
    );
    assert!(
        !said.contains("pr ensure"),
        "a verb the release has is fine: {said}"
    );
    assert!(
        !said.contains("retired"),
        "prose is not an invocation: {said}"
    );
}

#[test]
fn a_config_the_pinned_release_cannot_load_is_drift() {
    let dir = repo(
        "engine-gate-config",
        "version = 1\nengine = { release = \"v9.9.9\" }\n",
    );
    seed_release(&dir, "v9.9.9", 1, &[]);
    let output = run(&dir, &["engine", "gate"]);
    assert!(!output.status.success(), "{}", text(&output));
    assert!(
        text(&output).contains("engine pin v9.9.9 cannot load this config"),
        "{}",
        text(&output)
    );
}

#[test]
fn a_release_pin_that_loads_and_carries_every_verb_passes() {
    let dir = repo(
        "engine-gate-green",
        "version = 1\nengine = { release = \"v9.9.9\" }\n",
    );
    common::write(&dir, "lane.yml", LANE);
    seed_release(&dir, "v9.9.9", 0, &["pr ensure", "gone verb"]);
    let output = run(&dir, &["engine", "gate", "--lane", "lane.yml"]);
    assert!(output.status.success(), "{}", text(&output));
}
