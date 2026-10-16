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

/// A stand-in for the pinned release. `config show` always exits 0, as a real
/// older engine's does even when it drops a row it cannot read (CLOUD-2096);
/// `config lint` answers `lint_exit`, and `--help` succeeds only for the verbs
/// it is told it has.
fn seed_release(dir: &Path, tag: &str, lint_exit: u8, verbs: &[&str]) {
    let root = dir.canonicalize().unwrap();
    let cache = data_dir(dir)
        .join("batten")
        .join(batten::state::derive_repo_name(&root).unwrap())
        .join("engine")
        .join(tag);
    std::fs::create_dir_all(&cache).unwrap();
    let mut script = format!(
        "#!/bin/sh\nif [ \"$1 $2\" = \"config show\" ]; then exit 0; fi\nif [ \"$1 $2\" = \"config lint\" ]; then exit {lint_exit}; fi\n"
    );
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

/// A fixture forge whose tag read answers 404 and whose release list carries
/// `tag` as a draft.
fn draft_forge(dir: &Path, tag: &str) -> PathBuf {
    let mut name = dir.file_name().unwrap().to_os_string();
    name.push(".forge");
    let forge = dir.with_file_name(name);
    std::fs::create_dir_all(&forge).unwrap();
    common::write(&forge, "tag", "HTTP/2 404\n\n{\"message\": \"Not Found\"}");
    common::write(
        &forge,
        "list",
        &format!(
            "HTTP/2 200\ncontent-type: application/json\n\n[{{\"tag_name\": \"{tag}\", \"draft\": true, \"assets\": []}}]\n"
        ),
    );
    common::write(&forge, "routes", "/releases?\tlist\n/releases/tags/\ttag\n");
    forge
}

/// A PIN NAMING A DRAFT IS NEVER WAITED ON (CLOUD-2033, retiring CLOUD-2138's
/// wait). `main` pins a release only after `land` published and verified it, so
/// a draft pin is a defect the gate reports at once rather than a build it sits
/// out.
#[test]
fn a_pin_naming_a_draft_is_never_waited_on() {
    let dir = repo(
        "engine-gate-draft",
        "version = 1\nengine = { release = \"v9.9.9\" }\n",
    );
    let forge = draft_forge(&dir, "v9.9.9");
    let output = common::batten()
        .state_dir(&data_dir(&dir))
        .args(["engine", "gate"])
        .env("BATTEN_REST_FIXTURE", &forge)
        .current_dir(&dir)
        .output()
        .expect("run batten");
    assert!(!output.status.success(), "{}", text(&output));
    assert!(!text(&output).contains("waited"), "{}", text(&output));
}

/// ANTI-VACUITY: a pin already fetched is a published release, so the gate
/// judges it as before.
#[test]
fn a_cached_pin_is_judged_without_asking_about_drafts() {
    let dir = repo(
        "engine-gate-cached-draft",
        "version = 1\nengine = { release = \"v9.9.9\" }\n",
    );
    seed_release(&dir, "v9.9.9", 0, &[]);
    let forge = draft_forge(&dir, "v9.9.9");
    let output = common::batten()
        .state_dir(&data_dir(&dir))
        .args(["engine", "gate"])
        .env("BATTEN_REST_FIXTURE", &forge)
        .current_dir(&dir)
        .output()
        .expect("run batten");
    assert!(output.status.success(), "{}", text(&output));
    assert!(!text(&output).contains("draft"), "{}", text(&output));
}

/// EVERY COPY AGREES WITH THE PIN (CLOUD-2279): a batten provision row on
/// another release, and a floor above the pin, are each refused by `path:line`
/// before the pinned release is judged. The release is seeded so that, were
/// the check skipped, the gate would pass rather than reach the network.
#[test]
fn a_provision_row_disagreeing_with_the_pin_is_refused() {
    let dir = repo(
        "engine-gate-disagreeing-provision",
        "version = 1\nmin_batten_version = \"9.9.10\"\nengine = { release = \"v9.9.9\" }\n\n\
         [[provision]]\nname = \"batten\"\nversion = \"9.9.8\"\n\n\
         [[provision]]\nname = \"other\"\nversion = \"1.0.0\"\n",
    );
    seed_release(&dir, "v9.9.9", 0, &[]);
    let output = run(&dir, &["engine", "gate"]);
    assert_eq!(output.status.code(), Some(2), "{}", text(&output));
    let said = text(&output);
    assert!(
        said.contains("batten.toml:2 min_batten_version 9.9.10 disagrees with engine pin v9.9.9"),
        "{said}"
    );
    assert!(
        said.contains("batten.toml:7 provision batten 9.9.8 disagrees with engine pin v9.9.9"),
        "{said}"
    );
    assert!(
        !said.contains("other"),
        "another tool's row is not a copy: {said}"
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

/// `config show` exits 0 and `config lint` refuses: the pinned engine LOADED
/// this config by dropping a row it cannot read (CLOUD-2096). Measured on
/// `v0.0.201` over a branch adding `[forge] nothing_graded`: a gate reading
/// `config show` passed it, and the key the config relies on enforced nothing.
#[test]
fn a_config_the_pinned_release_drops_a_row_of_is_drift() {
    let dir = repo(
        "engine-gate-config",
        "version = 1\nengine = { release = \"v9.9.9\" }\n",
    );
    seed_release(&dir, "v9.9.9", 2, &[]);
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
