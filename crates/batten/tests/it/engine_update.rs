//! The engine follows its pin (CLOUD-2062): a release from the per-tag cache on
//! every path, a source pin built only off the hook path.
//!
//! Driven through a private COPY of the compiled binary, because the update
//! replaces the running binary and stamps it — doing that to the shared test
//! binary would change what every other case runs. The source build is a stub
//! `cargo` on `PATH` that writes the "built" engine where the real one would, so
//! the case measures the update's wiring and not a compile.

#![cfg(unix)]
// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::{Path, PathBuf};
use std::process::Output;

/// A repository with one tracked engine input, so a source digest exists.
fn repo(name: &str) -> PathBuf {
    let dir = common::scratch(name);
    common::write(&dir, "batten.toml", "version = 1\n");
    common::write(&dir, "crates/x/src/lib.rs", "fn a() {}\n");
    common::init_repo(&dir);
    common::git_in(&dir, &["add", "batten.toml", "crates/x/src/lib.rs"]);
    dir
}

/// A private copy of the binary, so its replacement and stamp are its own.
fn private_binary(dir: &Path) -> PathBuf {
    let copy = dir.join("engine").join("batten");
    std::fs::create_dir_all(copy.parent().unwrap()).unwrap();
    std::fs::copy(env!("CARGO_BIN_EXE_batten"), &copy).unwrap();
    copy
}

/// A `cargo` stub that records it ran and writes the "built" engine.
fn stub_cargo(dir: &Path) {
    let stub = dir.join("bin").join("cargo");
    std::fs::create_dir_all(stub.parent().unwrap()).unwrap();
    common::write(
        &dir.join("bin"),
        "cargo",
        "#!/bin/sh\n: > \"$STUB_RAN\"\nmkdir -p \"$CARGO_TARGET_DIR/release\"\nprintf 'the built engine\\n' > \"$CARGO_TARGET_DIR/release/batten\"\n",
    );
    make_executable(&stub);
}

fn make_executable(path: &Path) {
    use std::os::unix::fs::PermissionsExt as _;
    let mut mode = std::fs::metadata(path)
        .expect("stat the stub")
        .permissions();
    mode.set_mode(0o755);
    std::fs::set_permissions(path, mode).expect("chmod the stub");
}

#[expect(
    clippy::disallowed_types,
    reason = "stays, and test-only: the update replaces the binary it runs, so each case runs a private COPY of the compiled binary, which `common::batten` cannot target"
)]
fn run(binary: &Path, dir: &Path, args: &[&str], stdin: &str) -> Output {
    use std::io::Write as _;
    // THE CASE'S OWN `bin` AND THE SYSTEM'S, NEVER THE CALLER'S `PATH`. An update
    // installs over the `batten` it resolves there (CLOUD-2226), and with the
    // caller's `PATH` appended that was the session's own engine: measured, a run
    // of this suite replaced `~/.local/bin/batten` with the stub's output.
    let path = std::env::join_paths([
        dir.join("bin"),
        hook_bin(dir),
        PathBuf::from("/usr/bin"),
        PathBuf::from("/bin"),
    ])
    .unwrap();
    let mut command = std::process::Command::new(binary);
    common::state_dir(&mut command, &dir.join("state"));
    command
        .args(args)
        .current_dir(dir)
        .env("PATH", path)
        .env("CARGO_TARGET_DIR", dir.join("target"))
        .env("STUB_RAN", dir.join("cargo-ran"))
        .env_remove("BATTEN_ENGINE_UPDATED")
        .env_remove(batten::engine::LOCAL_ENV)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    let mut child = spawn_copy(&mut command);
    child
        .stdin
        .take()
        .unwrap()
        .write_all(stdin.as_bytes())
        .unwrap();
    child.wait_with_output().expect("wait for batten")
}

/// Spawn a just-copied binary, retrying while exec reports `ETXTBSY`.
///
/// A sibling case forking while this copy's write handle was still open hands
/// that handle to its child, and the kernel refuses to exec a file open for
/// writing until the child execs and closes it. Measured on #1132 as
/// `the_hook_path_never_builds_a_source_pin` failing with "Text file busy". The
/// window is the sibling's fork-to-exec, so a short retry outlasts it.
#[expect(
    clippy::disallowed_types,
    reason = "stays, and test-only: it spawns the private COPY `run` built, which `common::batten` cannot target"
)]
fn spawn_copy(command: &mut std::process::Command) -> std::process::Child {
    for _ in 0..100 {
        match command.spawn() {
            Err(err) if err.kind() == std::io::ErrorKind::ExecutableFileBusy => {
                #[expect(
                    clippy::disallowed_methods,
                    reason = "bounded by a real terminal state: `ETXTBSY` clears when the sibling child holding the copy's write handle execs, so the poll ends at that exec, capped at `100` tries"
                )]
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            spawned => return spawned.expect("run batten"),
        }
    }
    command.spawn().expect("run batten")
}

fn text(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn pin_source(dir: &Path, digest: &str) {
    common::write(
        dir,
        "batten.toml",
        &format!("version = 1\nengine = {{ source = \"{digest}\" }}\n"),
    );
}

#[test]
fn an_unpinned_repo_updates_nothing() {
    let dir = repo("engine-update-unpinned");
    stub_cargo(&dir);
    let binary = private_binary(&dir);
    let before = std::fs::read(&binary).unwrap();
    let output = run(&binary, &dir, &["engine", "update"], "");
    assert!(output.status.success(), "{}", text(&output));
    assert_eq!(std::fs::read(&binary).unwrap(), before, "nothing replaced");
    assert!(!dir.join("cargo-ran").exists(), "nothing built");
}

#[test]
fn a_source_pin_update_installs_where_the_hook_resolves() {
    // CLOUD-2226. Under `mise exec` the running binary is the build output, so
    // installing over it alone left the `batten` the hook resolves on `PATH`
    // unstamped and the refusal standing. A `batten` on `PATH` here is that one.
    let dir = repo("engine-update-path-install");
    stub_cargo(&dir);
    let binary = private_binary(&dir);
    // OUTSIDE THE CHECKOUT, where an installed engine lives (`~/.local/bin`): a
    // `batten` under the repository is cargo's output and is never replaced.
    let on_path = hook_bin(&dir).join("batten");
    std::fs::create_dir_all(hook_bin(&dir)).unwrap();
    std::fs::copy(&binary, &on_path).unwrap();
    let digest = text(&run(&binary, &dir, &["engine", "digest"], ""))
        .trim()
        .to_owned();
    pin_source(&dir, &digest);
    let output = run(&binary, &dir, &["engine", "update"], "");
    assert!(output.status.success(), "{}", text(&output));
    assert_eq!(
        std::fs::read(&on_path).unwrap(),
        b"the built engine\n",
        "the PATH copy was replaced"
    );
    let stamp = std::fs::read_to_string(engine_stamp(&on_path)).unwrap_or_default();
    assert_eq!(stamp.trim(), digest, "and stamped with the pin");
}

/// The case's stand-in for `~/.local/bin`: a sibling of the repository, on `PATH`
/// after the stub `bin`.
fn hook_bin(dir: &Path) -> PathBuf {
    let mut name = dir.file_name().unwrap().to_os_string();
    name.push(".hook-bin");
    dir.with_file_name(name)
}

fn engine_stamp(binary: &Path) -> PathBuf {
    batten::engine::stamp_path(binary)
}

#[test]
fn a_source_pin_builds_installs_and_stamps() {
    let dir = repo("engine-update-source");
    stub_cargo(&dir);
    let binary = private_binary(&dir);
    let digest = text(&run(&binary, &dir, &["engine", "digest"], ""))
        .trim()
        .to_owned();
    pin_source(&dir, &digest);
    let output = run(&binary, &dir, &["engine", "update"], "");
    assert!(output.status.success(), "{}", text(&output));
    assert!(dir.join("cargo-ran").exists(), "the source pin was built");
    assert_eq!(
        std::fs::read(&binary).unwrap(),
        b"the built engine\n",
        "the built engine replaced the running one"
    );
    let stamp = std::fs::read_to_string(dir.join("engine").join("batten.source")).unwrap();
    assert_eq!(
        stamp.trim(),
        digest,
        "and it is stamped with the tree it came from"
    );
}

/// A binary inside the checkout is `cargo`'s output, never an installed engine:
/// the startup update leaves it alone and the pre-parse refusal names the update
/// instead (CLOUD-2063). Measured before the guard: `verify`'s own `cargo run`
/// overwrote `target/debug/batten` with the pinned release.
#[test]
fn a_build_inside_the_checkout_is_never_replaced() {
    let dir = repo("engine-update-checkout-build");
    stub_cargo(&dir);
    let binary = private_binary(&dir);
    let before = std::fs::read(&binary).unwrap();
    pin_source(&dir, &"0".repeat(64));
    let output = run(&binary, &dir, &["config", "show"], "");
    assert!(
        !dir.join("cargo-ran").exists(),
        "a build of this checkout must not rebuild itself: {}",
        text(&output)
    );
    assert_eq!(std::fs::read(&binary).unwrap(), before, "nothing replaced");
    // AND IT LOADS (CLOUD-2232): the checkout's own build answers for the
    // checkout's source pin whatever digest it names — a pin the tree moved
    // off is `engine-pin:check`'s to refuse, never this binary's.
    assert!(output.status.success(), "{}", text(&output));
}

/// THE CHECKOUT'S OWN BUILD SATISFIES ITS OWN SOURCE PIN (CLOUD-2232), rustup's
/// `path` toolchain: a branch pinning the tree it stands on loads under the
/// binary cargo built inside it, with no stamp and no update. The mirror is
/// `a_build_inside_the_checkout_is_never_replaced`: a pin naming some OTHER
/// digest is still refused.
#[test]
fn the_checkouts_own_build_satisfies_its_source_pin() {
    let dir = repo("engine-update-own-source");
    stub_cargo(&dir);
    let binary = private_binary(&dir);
    let digest = text(&run(&binary, &dir, &["engine", "digest"], ""))
        .trim()
        .to_owned();
    pin_source(&dir, &digest);
    let output = run(&binary, &dir, &["config", "show"], "");
    assert!(output.status.success(), "{}", text(&output));
    assert!(
        !text(&output).contains("engine update"),
        "no update is asked of the tree's own build: {}",
        text(&output)
    );
    assert!(!dir.join("cargo-ran").exists(), "nothing built");
    assert!(
        !engine_stamp(&binary).exists(),
        "and no stamp was needed: {}",
        text(&output)
    );
}

/// A stand-in for the checkout's stamped release build: it names itself and its
/// arguments, so a case can see which engine decided.
fn checkout_build(dir: &Path, stamp: &str) {
    let release = dir.join("target").join("release");
    std::fs::create_dir_all(&release).unwrap();
    common::write(
        &release,
        "batten",
        "#!/bin/sh\necho \"checkout build ran $*\"\n",
    );
    make_executable(&release.join("batten"));
    common::write(&release, "batten.source", &format!("{stamp}\n"));
}

/// ONE `batten` ON PATH DISPATCHES TO THE BRANCH'S BUILD (CLOUD-2232), the
/// source-pin half of `a_release_pin_is_followed_from_the_cache_on_the_hook_path`.
/// The installed binary, outside the checkout, finds `target/release/batten`
/// and execs it — on the hook path, nothing built — even under a pin its stamp
/// is behind, since a refreshed pin must never strand the hook. The mirror: a
/// checkout with no release build is not followed, and the refusal names the
/// update.
#[test]
fn a_source_pin_is_followed_to_the_checkouts_build() {
    let digest = "1".repeat(64);
    let dir = repo("engine-update-follow-source");
    stub_cargo(&dir);
    let installed = common::scratch("engine-update-follow-source-installed");
    let binary = private_binary(&installed);
    pin_source(&dir, &digest);
    checkout_build(&dir, &"2".repeat(64));
    let envelope = r#"{"hook_event_name":"PreToolUse","permission_mode":"default","tool_name":"Bash","tool_input":{"command":"ls"}}"#;
    let output = run(
        &binary,
        &dir,
        &["adjudicate", "--harness", "claude-code"],
        envelope,
    );
    assert!(
        text(&output).contains("checkout build ran adjudicate --harness claude-code"),
        "the installed binary runs the branch's stamped build: {}",
        text(&output)
    );
    assert!(!dir.join("cargo-ran").exists(), "nothing built");

    std::fs::remove_dir_all(dir.join("target")).unwrap();
    let output = run(
        &binary,
        &dir,
        &["adjudicate", "--harness", "claude-code"],
        envelope,
    );
    assert!(
        !text(&output).contains("checkout build ran"),
        "with no release build there is nothing to follow: {}",
        text(&output)
    );
    assert!(
        text(&output).contains("batten engine update"),
        "and the refusal names the update: {}",
        text(&output)
    );
}

/// CLOUD-2220: a stale build of the checkout was told to `batten engine update`,
/// which leaves an in-tree binary alone, so `mise exec -- batten` (resolving
/// `target/release`) stayed refused. It is told to rebuild instead.
#[test]
fn a_stale_build_of_the_checkout_names_the_rebuild() {
    let dir = repo("engine-update-stale-checkout-build");
    let binary = private_binary(&dir);
    common::write(
        &dir,
        "batten.toml",
        "version = 1\nengine = { release = \"v9.9.9\" }\n",
    );
    let output = run(&binary, &dir, &["config", "show"], "");
    assert!(
        text(&output).contains("mise exec -- cargo build --release -p batten"),
        "the checkout's own build is rebuilt, not updated: {}",
        text(&output)
    );
}

/// The pinned release, as its per-tag cache holds it: a stand-in that names
/// itself and its arguments, so a case can see which engine decided.
fn seed_release(dir: &Path, tag: &str) {
    let root = dir.canonicalize().unwrap();
    let cache = dir
        .join("state")
        .join("batten")
        .join(batten::state::derive_repo_name(&root).unwrap())
        .join("engine")
        .join(tag);
    std::fs::create_dir_all(&cache).unwrap();
    common::write(
        &cache,
        "batten",
        &format!("#!/bin/sh\necho \"pinned {tag} ran $*\"\n"),
    );
    make_executable(&cache.join("batten"));
}

/// A RELEASE PIN IS FOLLOWED, ON THE HOOK PATH TOO (CLOUD-2059). The hook used
/// to refuse here, which locked every tool call out of the session each time a
/// release moved under the installed binary, while the pinned engine sat in the
/// cache. It is exec'd from the cache, and the installed binary is left alone:
/// a lockfile's runner execs the pinned version, it does not reinstall itself.
#[test]
fn a_release_pin_is_followed_from_the_cache_on_the_hook_path() {
    let dir = repo("engine-update-follow-release");
    stub_cargo(&dir);
    // OUTSIDE the checkout: a binary inside it is that tree's own build, which
    // `a_build_inside_the_checkout_is_never_replaced` keeps out of reach.
    let installed = common::scratch("engine-update-follow-release-installed");
    let binary = private_binary(&installed);
    let before = std::fs::read(&binary).unwrap();
    common::write(
        &dir,
        "batten.toml",
        "version = 1\nengine = { release = \"v9.9.9\" }\n",
    );
    seed_release(&dir, "v9.9.9");
    let envelope = r#"{"hook_event_name":"PreToolUse","permission_mode":"default","tool_name":"Bash","tool_input":{"command":"ls"}}"#;
    let output = run(
        &binary,
        &dir,
        &["adjudicate", "--harness", "claude-code"],
        envelope,
    );
    assert!(
        text(&output).contains("pinned v9.9.9 ran adjudicate --harness claude-code"),
        "the hook must run the pinned release, not refuse: {}",
        text(&output)
    );
    assert_eq!(
        std::fs::read(&binary).unwrap(),
        before,
        "following a pin never rewrites the installed binary"
    );
    assert!(!dir.join("cargo-ran").exists(), "nothing built");
}

#[test]
fn the_hook_path_never_builds_a_source_pin() {
    let dir = repo("engine-update-hook");
    stub_cargo(&dir);
    // OUTSIDE the checkout, so the binary is an installed engine that proves
    // itself by its stamp: the checkout's own build would satisfy the pin.
    let installed = common::scratch("engine-update-hook-installed");
    let binary = private_binary(&installed);
    pin_source(&dir, &"0".repeat(64));
    let envelope = r#"{"hook_event_name":"PreToolUse","permission_mode":"default","tool_name":"Bash","tool_input":{"command":"ls"}}"#;
    let output = run(
        &binary,
        &dir,
        &["adjudicate", "--harness", "claude-code"],
        envelope,
    );
    assert!(
        !dir.join("cargo-ran").exists(),
        "a hook must never build inline: {}",
        text(&output)
    );
    assert!(
        text(&output).contains("batten engine update"),
        "the stale engine refuses and names the update: {}",
        text(&output)
    );
}
