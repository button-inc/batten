//! The engine pin, read before the parse (CLOUD-2061).
//!
//! Driven through the compiled binary over scratch configs. The source-pin cases
//! run a COPY of the binary in their own scratch directory, so the stamp each
//! writes sits beside that copy alone — a stamp beside the shared test binary
//! would be read by every case running in parallel.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::{Path, PathBuf};
use std::process::Output;

const RELEASE: &str = concat!("v", env!("CARGO_PKG_VERSION"));

fn repo(name: &str, config: &str) -> PathBuf {
    let dir = common::scratch(name);
    common::write(&dir, "batten.toml", config);
    common::init_repo(&dir);
    // An INDEX, which a fresh `git init` lacks and `engine digest` reads.
    common::git_in(&dir, &["add", "batten.toml"]);
    dir
}

fn run(binary: &Path, dir: &Path, args: &[&str]) -> Output {
    run_engine(binary, dir, args, false)
}

#[expect(
    clippy::disallowed_types,
    reason = "stays, and test-only: the source-pin cases run a private COPY of the compiled binary so its stamp is its own, which `common::batten` cannot target because it names the shared binary"
)]
fn run_engine(binary: &Path, dir: &Path, args: &[&str], local: bool) -> Output {
    let mut command = std::process::Command::new(binary);
    command
        .args(args)
        .current_dir(dir)
        // These cases measure the pre-parse refusal, which is what a stale engine
        // answers once its one update has run; without this the startup update
        // (CLOUD-2062) would download or build before the refusal is reached.
        .env("BATTEN_ENGINE_UPDATED", "1")
        // ENFORCEMENT IS THE SUBJECT, so the suite's `BATTEN_ENGINE=local`
        // (CLOUD-2232) is not inherited; a case that wants it asks for it.
        .env_remove(batten::engine::LOCAL_ENV);
    if local {
        command.env(batten::engine::LOCAL_ENV, "local");
    }
    // A just-copied binary can be briefly unexecutable (ETXTBSY) while a sibling
    // case's fork holds its write handle; see `common::spawn_copy`.
    command
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    common::spawn_copy(&mut command)
        .wait_with_output()
        .expect("run batten")
}

fn text(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

/// A private copy of the binary, so its stamp is its own.
fn private_binary(dir: &Path) -> PathBuf {
    let copy = dir.join("bin").join("batten");
    std::fs::create_dir_all(copy.parent().unwrap()).unwrap();
    std::fs::copy(env!("CARGO_BIN_EXE_batten"), &copy).unwrap();
    copy
}

fn shared() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_batten"))
}

#[test]
fn a_release_pin_naming_this_build_loads() {
    let dir = repo(
        "engine-pin-release-same",
        &format!("version = 1\nengine = {{ release = \"{RELEASE}\" }}\n"),
    );
    let output = run(&shared(), &dir, &["config", "show"]);
    assert!(output.status.success(), "{}", text(&output));
}

#[test]
fn a_release_pin_naming_another_build_is_refused_with_its_install() {
    let dir = repo(
        "engine-pin-release-other",
        "version = 1\nengine = { release = \"v0.0.1\" }\n",
    );
    let output = run(&shared(), &dir, &["config", "show"]);
    let said = text(&output);
    assert!(
        !output.status.success(),
        "a stale engine must not load: {said}"
    );
    // THE ENGINE'S OWN VERB, never a consumer installer (CLOUD-2116): it is the one
    // command the hook's floor admits over this same skew, so it is the only
    // remedy a refused session can actually run.
    assert!(
        said.contains("v0.0.1") && said.contains("`batten engine install`"),
        "the refusal names the pin and the install: {said}"
    );
    assert!(
        !said.contains("install.sh"),
        "an installer the floor refuses is not a remedy: {said}"
    );
}

#[test]
fn a_source_pin_matching_the_stamp_loads() {
    let dir = repo("engine-pin-source-same", "version = 1\n");
    // An engine input, so the digest names a source rather than nothing
    // (CLOUD-2230).
    common::write(&dir, "crates/engine/src/lib.rs", "// the engine\n");
    common::git_in(&dir, &["add", "crates"]);
    let binary = private_binary(&dir);
    let stamped = run(&binary, &dir, &["engine", "stamp"]);
    assert!(stamped.status.success(), "{}", text(&stamped));
    let digest = text(&run(&binary, &dir, &["engine", "digest"]))
        .trim()
        .to_owned();
    assert_eq!(digest.len(), 64, "a digest is 64 hex: {digest}");
    common::write(
        &dir,
        "batten.toml",
        &format!("version = 1\nengine = {{ source = \"{digest}\" }}\n"),
    );
    let output = run(&binary, &dir, &["config", "show"]);
    assert!(output.status.success(), "{}", text(&output));
}

#[test]
fn a_stamp_over_no_inputs_is_refused() {
    // CLOUD-2230. A tree tracking no engine input hashes to SHA-256's empty
    // value, which names no source; measured on #1132 a debug binary carried
    // that stamp and every `cargo run -p batten` task refused under a source pin.
    let dir = repo("engine-pin-stamp-empty", "version = 1\n");
    let binary = private_binary(&dir);
    let stamped = run(&binary, &dir, &["engine", "stamp"]);
    assert!(!stamped.status.success(), "{}", text(&stamped));
    assert!(
        text(&stamped).contains("no engine input"),
        "{}",
        text(&stamped)
    );
    assert!(
        !batten::engine::stamp_path(&binary).exists(),
        "nothing is written over no inputs"
    );
}

/// `BATTEN_ENGINE=local` RUNS THIS BINARY AS IT IS (CLOUD-2232), Go's
/// `GOTOOLCHAIN=local`: the same unstamped installed engine the case below
/// refuses loads under it. A release pin it does not name is still refused,
/// so the variable is no general bypass.
#[test]
fn the_local_engine_runs_under_a_source_pin() {
    let dir = repo(
        "engine-pin-source-local",
        &format!(
            "version = 1\nengine = {{ source = \"{}\" }}\n",
            "0".repeat(64)
        ),
    );
    let installed = common::scratch("engine-pin-source-local-installed");
    let binary = private_binary(&installed);
    let output = run_engine(&binary, &dir, &["config", "show"], true);
    assert!(output.status.success(), "{}", text(&output));

    common::write(
        &dir,
        "batten.toml",
        "version = 1\nengine = { release = \"v9.9.9\" }\n",
    );
    let output = run_engine(&binary, &dir, &["config", "show"], true);
    assert!(
        !output.status.success(),
        "a release pin is enforced under `local` too: {}",
        text(&output)
    );
}

#[test]
fn a_source_pin_without_a_stamp_is_refused() {
    let digest = "0".repeat(64);
    let dir = repo(
        "engine-pin-source-unstamped",
        &format!("version = 1\nengine = {{ source = \"{digest}\" }}\n"),
    );
    // AN INSTALLED ENGINE, OUTSIDE THE CHECKOUT: one built inside it is that
    // tree's own build and satisfies its source pin (CLOUD-2232).
    let installed = common::scratch("engine-pin-source-unstamped-installed");
    let binary = private_binary(&installed);
    let output = run(&binary, &dir, &["config", "show"]);
    let said = text(&output);
    assert!(
        !output.status.success(),
        "an unstamped engine must not load: {said}"
    );
    assert!(
        said.contains("`batten engine install`"),
        "the refusal names the build: {said}"
    );
}

#[test]
fn a_config_without_a_pin_loads() {
    let dir = repo("engine-pin-none", "version = 1\n");
    let output = run(&shared(), &dir, &["config", "show"]);
    assert!(output.status.success(), "{}", text(&output));
}

#[test]
fn a_pin_naming_both_or_neither_is_refused() {
    for (name, pin) in [
        (
            "engine-pin-both",
            "{ release = \"v0.0.1\", source = \"00\" }",
        ),
        ("engine-pin-neither", "{}"),
    ] {
        let dir = repo(name, &format!("version = 1\nengine = {pin}\n"));
        let output = run(&shared(), &dir, &["config", "show"]);
        assert!(!output.status.success(), "{pin}: {}", text(&output));
    }
}

#[test]
fn the_digest_moves_when_a_tracked_engine_file_changes_and_not_for_an_untracked_one() {
    let dir = repo("engine-pin-digest", "version = 1\n");
    common::write(&dir, "crates/x/src/lib.rs", "fn a() {}\n");
    common::git_in(&dir, &["add", "crates/x/src/lib.rs"]);
    let digest = |dir: &Path| text(&run(&shared(), dir, &["engine", "digest"]));
    let before = digest(&dir);
    common::write(&dir, "crates/x/src/scratch.rs", "untracked\n");
    assert_eq!(
        digest(&dir),
        before,
        "an untracked file is not an engine input"
    );
    common::write(&dir, "crates/x/src/lib.rs", "fn b() {}\n");
    assert_ne!(digest(&dir), before, "a tracked engine input changed");
}

#[test]
fn a_local_override_cannot_set_the_pin() {
    let dir = repo("engine-pin-local", "version = 1\n");
    common::write(
        &dir,
        "batten.local.toml",
        &format!("version = 1\nengine = {{ release = \"{RELEASE}\" }}\n"),
    );
    let output = run(&shared(), &dir, &["config", "show"]);
    let said = text(&output);
    assert!(!output.status.success(), "{said}");
    assert!(
        said.contains("`engine`"),
        "the refusal names the key: {said}"
    );
}

// ---------------------------------------------------------------------------
// CLOUD-2595: the `[[provision]] batten` row is the pin.
//
// The follow and write cases need a served release, so they reuse the install
// suite's loopback TLS host rather than a fourth copy of it (CLOUD-2431). Its
// release ships a shell script, so a followed engine is observed by its output.
// They are Linux-only, as the install suite's are: the fixture archive is a tar
// of a `#!/bin/sh` script.
// ---------------------------------------------------------------------------

use crate::engine_install::{WANTED, published, release_host, served_env};

/// What the fixture release's binary prints when a follow runs it.
const FIXTURE_SAYS: &str = "the fixture release";

/// A batten provision row pinning `tag` for this platform, at `digest`.
fn row(tag: &str, digest: &str) -> String {
    let asset = batten::engine::release_asset(tag, &batten::engine::running_target());
    format!(
        "\n[[provision]]\nname = \"batten\"\nversion = \"{}\"\nunpack = \"tar_gz\"\nbinary = \"batten\"\n\n\
         [provision.platforms.{}]\nurl = \"https://example.invalid/releases/download/{tag}/{asset}\"\n\
         sha256 = \"{digest}\"\n",
        tag.trim_start_matches('v'),
        batten::provision::platform_key()
    )
}

/// `batten <args>` in `dir` with the follow armed: no `BATTEN_ENGINE_UPDATED`,
/// state inside the case, neither `CI` nor the local-engine override ambient,
/// `stdin` on a pipe when given.
fn following(dir: &Path, args: &[&str], env: &[(&str, &str)], stdin: Option<&str>) -> Output {
    use common::StateHome as _;
    use std::io::Write as _;
    let mut command = common::batten();
    command
        .state_dir(&dir.join("data"))
        .args(args)
        .current_dir(dir)
        .env("HOME", dir)
        .env_remove("CI")
        .env_remove("CLAUDE_PROJECT_DIR")
        .env_remove("BATTEN_ENGINE_UPDATED")
        .env_remove(batten::engine::LOCAL_ENV)
        .env_remove("BATTEN_RELEASES")
        .env_remove("BATTEN_VERSION_FROM_REF")
        .env_remove("BATTEN_VERSION")
        .env_remove("BATTEN_INSTALL_DIR")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    for (name, value) in env {
        command.env(name, value);
    }
    let mut child = command.spawn().expect("spawn batten");
    let mut pipe = child.stdin.take().expect("piped stdin");
    if let Some(input) = stdin {
        pipe.write_all(input.as_bytes()).expect("write stdin");
    }
    drop(pipe);
    child.wait_with_output().expect("run batten")
}

/// `engine install` into a directory of the case's own, as the bootstrap's last
/// step runs it.
fn installing(dir: &Path, env: &[(&str, &str)]) -> Output {
    let named = dir.join("bin");
    let named = named.display().to_string();
    let mut env = env.to_vec();
    env.push(("BATTEN_INSTALL_DIR", named.as_str()));
    env.push(("BATTEN_ALLOW_OFF_PATH", "1"));
    following(dir, &["engine", "install"], &env, None)
}

/// A config this build refuses at load, whatever else it says.
const REFUSED_HERE: &str = "version = 1\nnot_a_key = true\n";

#[test]
fn a_provision_row_alone_pins_and_is_followed_before_the_parse() {
    if !cfg!(target_os = "linux") {
        return;
    }
    let dir = common::scratch_repo("engine-pin-row-followed");
    let (_host, served) = release_host(&dir, WANTED, WANTED);
    let digest = published(&dir, WANTED, &batten::engine::running_target());
    // THE INCIDENT'S SHAPE: no `engine` key, one row, and a file THIS build
    // refuses — so only a pin read before the parse can get the call judged.
    common::write(
        &dir,
        "batten.toml",
        &format!("{REFUSED_HERE}{}", row(WANTED, &digest)),
    );
    let output = following(&dir, &["config", "show"], &served_env(&served), None);
    assert!(
        String::from_utf8_lossy(&output.stdout).contains(FIXTURE_SAYS),
        "the row's release ran instead of this build: {}",
        text(&output)
    );
    assert!(output.status.success(), "{}", text(&output));
}

#[test]
fn a_followed_release_is_verified_against_the_rows_digest() {
    if !cfg!(target_os = "linux") {
        return;
    }
    let dir = common::scratch_repo("engine-pin-row-digest");
    let (_host, served) = release_host(&dir, WANTED, WANTED);
    // The release's own SHA256SUMS is right; the ROW pins other bytes.
    common::write(
        &dir,
        "batten.toml",
        &format!("version = 1\n{}", row(WANTED, &"0".repeat(64))),
    );
    let output = following(&dir, &["config", "show"], &served_env(&served), None);
    assert!(!output.status.success(), "{}", text(&output));
    assert!(
        text(&output).contains("the batten provision row pins"),
        "a digest the row does not pin is refused by the row's word: {}",
        text(&output)
    );
    assert!(!String::from_utf8_lossy(&output.stdout).contains(FIXTURE_SAYS));
}

#[test]
fn a_config_without_a_row_gains_one_after_a_clean_load() {
    if !cfg!(target_os = "linux") {
        return;
    }
    let dir = common::scratch_repo("engine-pin-row-written");
    let (_host, served) = release_host(&dir, RELEASE, RELEASE);
    common::write(&dir, "batten.toml", "version = 1\n");
    let output = installing(&dir, &served_env(&served));
    assert!(output.status.success(), "{}", text(&output));
    let config = std::fs::read_to_string(dir.join("batten.toml")).unwrap();
    assert_eq!(
        batten::engine::row_release(&config).as_deref(),
        Some(RELEASE),
        "{config}"
    );
    assert!(
        text(&output).contains(&format!(
            "batten note call fix silent at batten.toml provision.batten (pinned {RELEASE})"
        )),
        "the write is reported: {}",
        text(&output)
    );
}

#[test]
fn the_session_start_writes_the_row() {
    if !cfg!(target_os = "linux") {
        return;
    }
    let dir = common::scratch_repo("engine-pin-row-session");
    let (_host, served) = release_host(&dir, RELEASE, RELEASE);
    common::write(&dir, "batten.toml", "version = 1\n");
    let payload = serde_json::json!({
        "session_id": "cloud-2595-start",
        "transcript_path": "/dev/null",
        "cwd": dir.display().to_string(),
        "hook_event_name": "SessionStart",
        "source": "startup",
    })
    .to_string();
    let output = following(
        &dir,
        &["adjudicate", "--harness", "claude-code"],
        &served_env(&served),
        Some(&payload),
    );
    let config = std::fs::read_to_string(dir.join("batten.toml")).unwrap();
    assert_eq!(
        batten::engine::row_release(&config).as_deref(),
        Some(RELEASE),
        "{config} {}",
        text(&output)
    );
}

/// Under `--config-in` another directory's file is the authority, so a clean
/// load there says nothing about this file: it is never written.
#[test]
fn a_session_under_config_in_never_writes_the_row() {
    if !cfg!(target_os = "linux") {
        return;
    }
    let dir = common::scratch_repo("engine-pin-row-config-in");
    let (_host, served) = release_host(&dir, RELEASE, RELEASE);
    common::write(&dir, "batten.toml", "version = 1\n");
    let elsewhere = dir.join("elsewhere");
    common::write(&elsewhere, "batten.toml", "version = 1\n");
    let payload = serde_json::json!({
        "session_id": "cloud-2595-config-in",
        "transcript_path": "/dev/null",
        "cwd": dir.display().to_string(),
        "hook_event_name": "SessionStart",
        "source": "startup",
    })
    .to_string();
    let elsewhere = elsewhere.display().to_string();
    let mut env = served_env(&served);
    env.push(("BATTEN_CONFIG_IN", elsewhere.as_str()));
    let output = following(
        &dir,
        &["adjudicate", "--harness", "claude-code"],
        &env,
        Some(&payload),
    );
    assert_eq!(
        std::fs::read_to_string(dir.join("batten.toml")).unwrap(),
        "version = 1\n",
        "{}",
        text(&output)
    );
}

#[test]
fn a_config_that_fails_to_load_is_never_written() {
    if !cfg!(target_os = "linux") {
        return;
    }
    let dir = common::scratch_repo("engine-pin-row-unloaded");
    let (_host, served) = release_host(&dir, RELEASE, RELEASE);
    common::write(&dir, "batten.toml", REFUSED_HERE);
    let _ = installing(&dir, &served_env(&served));
    assert_eq!(
        std::fs::read_to_string(dir.join("batten.toml")).unwrap(),
        REFUSED_HERE,
        "a file this engine refuses is not one it pins"
    );
}

#[test]
fn the_written_row_preserves_every_other_byte() {
    if !cfg!(target_os = "linux") {
        return;
    }
    let dir = common::scratch_repo("engine-pin-row-bytes");
    let (_host, served) = release_host(&dir, RELEASE, RELEASE);
    let original = "# the consumer's own words\nversion   =   1\n\n# trailing comment, no newline";
    common::write(&dir, "batten.toml", original);
    let output = installing(&dir, &served_env(&served));
    assert!(output.status.success(), "{}", text(&output));
    let config = std::fs::read_to_string(dir.join("batten.toml")).unwrap();
    assert!(
        config.starts_with(original),
        "every byte before the row is the file's own: {config}"
    );
    assert_eq!(
        batten::engine::row_release(&config).as_deref(),
        Some(RELEASE)
    );
}

#[test]
fn init_writes_the_row() {
    if !cfg!(target_os = "linux") {
        return;
    }
    let dir = common::scratch_repo("engine-pin-row-init");
    let (_host, served) = release_host(&dir, RELEASE, RELEASE);
    let _ = std::fs::remove_file(dir.join("batten.toml"));
    let output = following(&dir, &["init"], &served_env(&served), None);
    assert!(output.status.success(), "{}", text(&output));
    let config = std::fs::read_to_string(dir.join("batten.toml")).unwrap();
    assert_eq!(
        batten::engine::row_release(&config).as_deref(),
        Some(RELEASE),
        "{config}"
    );
    assert!(
        text(&output).contains(&format!("(pinned {RELEASE})")),
        "init reports the pin it wrote: {}",
        text(&output)
    );
}

/// An install that placed ANOTHER release never writes the running engine's:
/// the row would pin bytes nobody installed.
#[test]
fn an_install_of_a_named_version_writes_no_row() {
    if !cfg!(target_os = "linux") {
        return;
    }
    // THE RUNNING ENGINE'S OWN RELEASE IS SERVED, sums and all, so the only
    // thing keeping its row out of the file is that a NAMED version installed.
    let dir = common::scratch_repo("engine-pin-row-named");
    let (_host, served) = release_host(&dir, RELEASE, RELEASE);
    common::write(&dir, "batten.toml", "version = 1\n");
    let mut env = served_env(&served);
    env.push(("BATTEN_VERSION", RELEASE));
    let output = installing(&dir, &env);
    assert!(output.status.success(), "{}", text(&output));
    assert_eq!(
        std::fs::read_to_string(dir.join("batten.toml")).unwrap(),
        "version = 1\n",
        "{}",
        text(&output)
    );
}

/// A checkout CI builds is never dirtied by the write.
#[test]
fn ci_never_writes_the_row() {
    if !cfg!(target_os = "linux") {
        return;
    }
    let dir = common::scratch_repo("engine-pin-row-ci");
    let (_host, served) = release_host(&dir, RELEASE, RELEASE);
    common::write(&dir, "batten.toml", "version = 1\n");
    let mut env = served_env(&served);
    env.push(("CI", "true"));
    let output = installing(&dir, &env);
    assert!(output.status.success(), "{}", text(&output));
    assert_eq!(
        std::fs::read_to_string(dir.join("batten.toml")).unwrap(),
        "version = 1\n",
        "{}",
        text(&output)
    );
}

#[test]
fn engine_pin_rewrites_the_row() {
    if !cfg!(target_os = "linux") {
        return;
    }
    let dir = common::scratch_repo("engine-pin-row-rewritten");
    let (_host, served) = release_host(&dir, WANTED, WANTED);
    common::write(
        &dir,
        "batten.toml",
        &format!("version = 1\n{}", row("v8.8.8", &"0".repeat(64))),
    );
    common::git_in(&dir, &["add", "batten.toml"]);
    let output = following(&dir, &["engine", "pin", WANTED], &served_env(&served), None);
    assert!(output.status.success(), "{}", text(&output));
    let config = std::fs::read_to_string(dir.join("batten.toml")).unwrap();
    assert_eq!(
        batten::engine::row_release(&config).as_deref(),
        Some(WANTED),
        "{config}"
    );
    assert_eq!(
        batten::engine::followed_digest(&config),
        Some(published(&dir, WANTED, &batten::engine::running_target())),
        "the row's digest is the release's own: {config}"
    );
    assert!(
        !config.contains("engine ="),
        "a config that pins by its row is never given a key back: {config}"
    );
}

#[test]
fn an_engine_release_key_disagreeing_with_the_row_is_refused() {
    let dir = repo(
        "engine-pin-row-disagrees",
        &format!(
            "version = 1\nengine = {{ release = \"v9.9.8\" }}\n{}",
            row(RELEASE, &"0".repeat(64))
        ),
    );
    let output = run(&shared(), &dir, &["config", "show"]);
    assert!(!output.status.success(), "{}", text(&output));
    assert!(
        text(&output).contains(&format!(
            "`engine` pins v9.9.8 and the `[[provision]] batten` row pins {RELEASE}"
        )),
        "{}",
        text(&output)
    );
}

#[test]
fn a_followed_pin_names_itself_once() {
    if !cfg!(target_os = "linux") {
        return;
    }
    let dir = common::scratch_repo("engine-pin-row-says-once");
    let (_host, served) = release_host(&dir, WANTED, WANTED);
    let digest = published(&dir, WANTED, &batten::engine::running_target());
    common::write(
        &dir,
        "batten.toml",
        &format!("version = 1\n{}", row(WANTED, &digest)),
    );
    let payload = serde_json::json!({
        "session_id": "cloud-2595-named",
        "transcript_path": "/dev/null",
        "cwd": dir.display().to_string(),
        "permission_mode": "default",
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": { "command": "ls" },
    })
    .to_string();
    let line = format!("batten: this binary is {RELEASE}; following the pinned {WANTED}");
    let args = ["adjudicate", "--harness", "claude-code"];
    let first = following(&dir, &args, &served_env(&served), Some(&payload));
    assert!(
        String::from_utf8_lossy(&first.stderr).contains(&line),
        "the first follow of a session names both engines: {}",
        text(&first)
    );
    let second = following(&dir, &args, &served_env(&served), Some(&payload));
    assert!(
        !String::from_utf8_lossy(&second.stderr).contains(&line),
        "and the session hears it once: {}",
        text(&second)
    );
}
