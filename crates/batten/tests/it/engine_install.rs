//! `batten engine install` (CLOUD-2203): the generated bootstrap's last step,
//! run as the compiled binary over scratch directories.
//!
//! Everything after the bootstrap's verified download lives here, in Rust, so
//! this is where the install path's behaviour is pinned: the binary lands in a
//! directory `PATH` finds, a destination off `PATH` is refused unless that is
//! declared deliberate, and a caller-named directory wins.
//!
//! **It always installs the pin (CLOUD-2287)**: a ref's, else the worktree's,
//! else the running binary. The installed engine's repair, once `engine update`,
//! is this verb too, and its cases are the `repair` module below; `engine
//! update` itself is now "move the pin to `main`'s, then install", whose cases
//! close the first half of this file.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::{Path, PathBuf};

/// Run `engine install` with `PATH` set to exactly `path` plus the ambient one
/// (so `cargo`-built binaries still resolve their own tools), `HOME` in the
/// case's scratch tree, and `env` on top.
fn install(home: &Path, path: &[PathBuf], env: &[(&str, &str)]) -> std::process::Output {
    install_as(Path::new(env!("CARGO_BIN_EXE_batten")), home, path, env)
}

/// [`install`], running `program`: a private copy, stamped or not as the case
/// needs (CLOUD-2398).
fn install_as(
    program: &Path,
    home: &Path,
    path: &[PathBuf],
    env: &[(&str, &str)],
) -> std::process::Output {
    // EXACTLY these directories: a root host's ambient PATH carries a writable
    // `/usr/local/bin`, which `engine install` would rightly choose.
    let joined = std::env::join_paths(path).expect("a PATH entry carries no separator");
    let mut command = common::batten_at(program);
    command
        .args(["engine", "install"])
        .current_dir(home)
        .env("HOME", home)
        .env_remove("XDG_BIN_HOME")
        .env_remove("BATTEN_INSTALL_DIR")
        .env_remove("BATTEN_ALLOW_OFF_PATH")
        .env_remove("BATTEN_VERSION_FROM_REF")
        .env_remove("BATTEN_VERSION")
        .env_remove("BATTEN_RELEASES")
        .env_remove("BATTEN_REQUIRE")
        .env("PATH", joined);
    for (name, value) in env {
        command.env(name, value);
    }
    command
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    common::spawn_copy(&mut command)
        .wait_with_output()
        .expect("run batten engine install")
}

/// A private copy of the binary in `dir`, stamped as release `tag` the way
/// `install.sh` stamps its verified download before running it.
fn stamped_copy(dir: &Path, tag: &str) -> PathBuf {
    let copy = dir.join("download").join(binary());
    std::fs::create_dir_all(copy.parent().unwrap()).unwrap();
    std::fs::copy(env!("CARGO_BIN_EXE_batten"), &copy).unwrap();
    batten::engine::stamp_release(&copy, tag).unwrap();
    copy
}

/// The file `engine install` places: `batten.exe` on Windows.
fn binary() -> String {
    format!("batten{}", std::env::consts::EXE_SUFFIX)
}

fn stdout(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

#[test]
fn the_binary_lands_in_the_per_user_directory_when_path_finds_it() {
    let home = common::scratch_repo("engine-install-user");
    let user = home.join(".local").join("bin");
    std::fs::create_dir_all(&user).unwrap();
    let output = install(&home, std::slice::from_ref(&user), &[]);
    assert!(
        output.status.success(),
        "{}{}",
        stdout(&output),
        common::stderr(&output)
    );
    assert!(
        stdout(&output).contains(&format!("installed={}", user.join(binary()).display())),
        "{}",
        stdout(&output)
    );
    assert!(user.join(binary()).is_file());
}

#[test]
fn a_named_directory_wins() {
    let home = common::scratch_repo("engine-install-named");
    let named = home.join("named");
    let named_str = named.display().to_string();
    let output = install(
        &home,
        std::slice::from_ref(&named),
        &[("BATTEN_INSTALL_DIR", &named_str)],
    );
    assert!(
        output.status.success(),
        "{}{}",
        stdout(&output),
        common::stderr(&output)
    );
    assert!(named.join(binary()).is_file());
}

#[test]
fn a_destination_off_path_is_refused() {
    // Every hook registration names `batten` bare, so a binary the shell cannot
    // resolve is not installed: exit 1, naming the directory.
    let home = common::scratch_repo("engine-install-off-path");
    let output = install(&home, &[], &[]);
    assert_eq!(output.status.code(), Some(1), "{}", stdout(&output));
    assert!(
        common::stderr(&output).contains("not on PATH"),
        "{}",
        common::stderr(&output)
    );
}

#[test]
fn an_off_path_destination_declared_deliberate_is_admitted() {
    let home = common::scratch_repo("engine-install-off-path-allowed");
    let output = install(&home, &[], &[("BATTEN_ALLOW_OFF_PATH", "1")]);
    assert!(
        output.status.success(),
        "{}{}",
        stdout(&output),
        common::stderr(&output)
    );
    assert!(stdout(&output).contains("off-path="), "{}", stdout(&output));
    assert!(home.join(".local").join("bin").join(binary()).is_file());
}

/// The repository path the TLS fixture serves the release from.
const REPO: &str = "example/pkg";

/// The release a ref's `batten.toml` pins in the fixture, never this binary's own.
const WANTED: &str = "v9.9.9";

/// The bytes the fixture release ships as its binary.
const SHIPPED: &[u8] = b"#!/bin/sh\necho the fixture release\n";

/// Serve, over loopback TLS, a ref `main` whose `batten.toml` pins [`WANTED`], and
/// [`WANTED`]'s release for this build's target. Returns the host and the
/// environment `engine install` needs to reach and trust it.
fn ref_release_host(home: &Path) -> (common::TlsWww, Vec<(String, String)>) {
    release_host(home, WANTED, WANTED)
}

/// [`ref_release_host`] with `main` pinning `main_pin` and the one published
/// release `served`, so a case can stand a worktree's pin on either side of
/// `main`'s.
fn release_host(
    home: &Path,
    main_pin: &str,
    served: &str,
) -> (common::TlsWww, Vec<(String, String)>) {
    #[expect(
        clippy::disallowed_types,
        reason = "stays, and test-only: `engine install` untars what it fetches, so the fixture release has to be a real gzipped tar and `tar` is what writes one"
    )]
    use std::process::Command;

    let root = home.join("www");
    let repo = root.join(REPO);
    std::fs::create_dir_all(repo.join("main")).unwrap();
    std::fs::write(
        repo.join("main").join("batten.toml"),
        format!("version = 1\nengine = {{ release = \"{main_pin}\" }}\n"),
    )
    .unwrap();

    let stage = home.join("stage");
    std::fs::create_dir_all(&stage).unwrap();
    let bin = stage.join(binary());
    std::fs::write(&bin, SHIPPED).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    let archive = home.join("release.tar.gz");
    #[expect(
        clippy::disallowed_types,
        reason = "stays, and test-only: the spawn the import above names"
    )]
    let packed = Command::new("tar")
        .arg("-czf")
        .arg(&archive)
        .arg("-C")
        .arg(&stage)
        .arg(binary())
        .status()
        .expect("run tar");
    assert!(packed.success(), "the fixture archive must build");
    let bytes = std::fs::read(&archive).unwrap();

    let asset = batten::engine::release_asset(served, &batten::engine::running_target());
    let download = repo.join("releases").join("download").join(served);
    std::fs::create_dir_all(&download).unwrap();
    std::fs::write(download.join(&asset), &bytes).unwrap();
    std::fs::write(
        download.join("SHA256SUMS"),
        format!("{}  {asset}\n", batten::provision::digest(&bytes)),
    )
    .unwrap();

    let tls = home.join("tls");
    std::fs::create_dir_all(&tls).unwrap();
    let host = common::tls_www(&tls, &root);
    let env = vec![
        (
            "BATTEN_RELEASES".to_owned(),
            format!("https://localhost:{}/{REPO}", host.port),
        ),
        (
            "SSL_CERT_FILE".to_owned(),
            tls.join("ca.pem").display().to_string(),
        ),
    ];
    (host, env)
}

/// `BATTEN_VERSION_FROM_REF` installs the release the ref's `batten.toml` pins,
/// fetched and verified, rather than the binary that is running.
#[test]
fn the_version_comes_from_the_refs_manifest() {
    // Linux only, said here so the case compiles everywhere (CLOUD-1148): the
    // TLS fixture's key material comes from `openssl`.
    if !cfg!(target_os = "linux") {
        return;
    }
    let home = common::scratch_repo("engine-install-ref");
    let named = home.join("bin");
    let (_host, served) = ref_release_host(&home);
    let named_str = named.display().to_string();
    let mut env: Vec<(&str, &str)> = served
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    env.push(("BATTEN_INSTALL_DIR", &named_str));
    env.push(("BATTEN_VERSION_FROM_REF", "main"));

    let output = install(&home, std::slice::from_ref(&named), &env);
    assert!(
        output.status.success(),
        "{}{}",
        stdout(&output),
        common::stderr(&output)
    );
    assert!(
        stdout(&output).contains(&format!("version={WANTED}")),
        "{}",
        stdout(&output)
    );
    assert_eq!(
        std::fs::read(named.join(binary())).unwrap(),
        SHIPPED,
        "the installed bytes are the ref's release, not the running binary"
    );
}

/// A named `BATTEN_VERSION` is an escape hatch, never a selector (CLOUD-2287):
/// disagreeing with the ref's pin, it is refused by name and nothing lands.
#[test]
fn a_named_version_disagreeing_with_the_ref_is_refused() {
    // Linux only, said here so the case compiles everywhere (CLOUD-1148): the
    // TLS fixture's key material comes from `openssl`.
    if !cfg!(target_os = "linux") {
        return;
    }
    let home = common::scratch_repo("engine-install-named-wins");
    let named = home.join("bin");
    let (_host, served) = ref_release_host(&home);
    let named_str = named.display().to_string();
    let running = format!("v{}", env!("CARGO_PKG_VERSION"));
    let mut env: Vec<(&str, &str)> = served
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    env.push(("BATTEN_INSTALL_DIR", &named_str));
    env.push(("BATTEN_VERSION_FROM_REF", "main"));
    env.push(("BATTEN_VERSION", &running));

    let output = install(&home, std::slice::from_ref(&named), &env);
    assert_eq!(output.status.code(), Some(1), "{}", stdout(&output));
    assert!(
        common::stderr(&output).contains("BATTEN_VERSION names"),
        "{}",
        common::stderr(&output)
    );
    assert!(!named.join(binary()).exists(), "nothing was installed");
}

/// A ref whose `batten.toml` pins no release is a refusal, never a quiet install of
/// whatever binary is running.
#[test]
fn a_ref_naming_no_version_installs_nothing() {
    // Linux only, said here so the case compiles everywhere (CLOUD-1148): the
    // TLS fixture's key material comes from `openssl`.
    if !cfg!(target_os = "linux") {
        return;
    }
    let home = common::scratch_repo("engine-install-ref-unreadable");
    let named = home.join("bin");
    let (_host, served) = ref_release_host(&home);
    let named_str = named.display().to_string();
    let mut env: Vec<(&str, &str)> = served
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    env.push(("BATTEN_INSTALL_DIR", &named_str));
    // `s_server -WWW` answers 200 with an error body for a path it cannot
    // open, so this ref reads as a `batten.toml` that pins no release.
    env.push(("BATTEN_VERSION_FROM_REF", "absent"));

    let output = install(&home, std::slice::from_ref(&named), &env);
    assert_eq!(output.status.code(), Some(1), "{}", stdout(&output));
    assert!(
        common::stderr(&output).contains("pins no release"),
        "{}",
        common::stderr(&output)
    );
    assert!(!named.join(binary()).exists(), "nothing was installed");
}

/// The worktree's own `batten.toml` pinning `tag`.
fn pin_worktree(home: &Path, tag: &str) {
    common::write(
        home,
        "batten.toml",
        &format!("version = 1\nengine = {{ release = \"{tag}\" }}\n"),
    );
}

/// `served`'s environment as `install` takes it, plus `BATTEN_INSTALL_DIR`.
fn with_named<'a>(served: &'a [(String, String)], named: &'a str) -> Vec<(&'a str, &'a str)> {
    let mut env: Vec<(&str, &str)> = served
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    env.push(("BATTEN_INSTALL_DIR", named));
    env
}

/// Run `batten engine <verb>` in `home` exactly as [`install`] runs `install`.
fn engine_verb(
    verb: &str,
    home: &Path,
    path: &[PathBuf],
    env: &[(&str, &str)],
) -> std::process::Output {
    let joined = std::env::join_paths(path).expect("a PATH entry carries no separator");
    let mut command = common::batten();
    command
        .args(["engine", verb])
        .current_dir(home)
        .env("HOME", home)
        .env_remove("XDG_BIN_HOME")
        .env_remove("BATTEN_INSTALL_DIR")
        .env_remove("BATTEN_ALLOW_OFF_PATH")
        .env_remove("BATTEN_VERSION_FROM_REF")
        .env_remove("BATTEN_VERSION")
        .env_remove("BATTEN_RELEASES")
        .env_remove("BATTEN_REQUIRE")
        .env("PATH", joined);
    for (name, value) in env {
        command.env(name, value);
    }
    command.output().expect("run batten engine")
}

/// THE BINARY FOLLOWS THE WORKTREE'S PIN (CLOUD-2287). With neither environment
/// variable set, the release the worktree pins is fetched, verified and placed,
/// never the binary that happens to be running.
#[test]
fn a_pinned_worktree_installs_its_pin() {
    if !cfg!(target_os = "linux") {
        return;
    }
    let home = common::scratch_repo("engine-install-worktree-pin");
    pin_worktree(&home, WANTED);
    let named = home.join("bin");
    let named_str = named.display().to_string();
    let (_host, served) = ref_release_host(&home);
    let output = install(
        &home,
        std::slice::from_ref(&named),
        &with_named(&served, &named_str),
    );
    assert!(
        output.status.success(),
        "{}{}",
        stdout(&output),
        common::stderr(&output)
    );
    assert!(
        stdout(&output).contains(&format!("version={WANTED}")),
        "{}",
        stdout(&output)
    );
    assert_eq!(std::fs::read(named.join(binary())).unwrap(), SHIPPED);
}

/// A named version that disagrees with the worktree's pin is refused, and
/// nothing is placed: the pin is the one authority.
#[test]
fn a_named_version_never_overrides_the_worktree_pin() {
    if !cfg!(target_os = "linux") {
        return;
    }
    let home = common::scratch_repo("engine-install-named-vs-pin");
    pin_worktree(&home, WANTED);
    let named = home.join("bin");
    let named_str = named.display().to_string();
    let running = format!("v{}", env!("CARGO_PKG_VERSION"));
    let (_host, served) = ref_release_host(&home);
    let mut env = with_named(&served, &named_str);
    env.push(("BATTEN_VERSION", &running));
    let output = install(&home, std::slice::from_ref(&named), &env);
    assert_eq!(output.status.code(), Some(1), "{}", stdout(&output));
    assert!(
        common::stderr(&output).contains("BATTEN_VERSION names"),
        "{}",
        common::stderr(&output)
    );
    assert!(!named.join(binary()).exists(), "nothing was installed");
}

/// The ref CI names outranks the worktree's pin: a lane installs the judge
/// `main` pins even from a branch whose own pin is not published.
#[test]
fn the_ref_outranks_the_worktree_pin() {
    if !cfg!(target_os = "linux") {
        return;
    }
    let home = common::scratch_repo("engine-install-ref-vs-pin");
    pin_worktree(&home, "v8.8.8");
    let named = home.join("bin");
    let named_str = named.display().to_string();
    let (_host, served) = ref_release_host(&home);
    let mut env = with_named(&served, &named_str);
    env.push(("BATTEN_VERSION_FROM_REF", "main"));
    let output = install(&home, std::slice::from_ref(&named), &env);
    assert!(
        output.status.success(),
        "{}{}",
        stdout(&output),
        common::stderr(&output)
    );
    assert!(
        stdout(&output).contains(&format!("version={WANTED}")),
        "{}",
        stdout(&output)
    );
    assert_eq!(std::fs::read(named.join(binary())).unwrap(), SHIPPED);
}

/// The bootstrap's download is placed even when the worktree pins exactly the
/// running release: a download is never "already installed" just because it is
/// current, and it runs off `PATH`. The download is the one `install.sh`
/// stamped as the release (CLOUD-2398), and the placed copy carries the stamp.
#[test]
fn the_bootstrap_places_a_running_pin() {
    let home = common::scratch_repo("engine-install-running-pin");
    let running = format!("v{}", env!("CARGO_PKG_VERSION"));
    pin_worktree(&home, &running);
    let download = stamped_copy(&home, &running);
    let named = home.join("bin");
    let named_str = named.display().to_string();
    let output = install_as(
        &download,
        &home,
        std::slice::from_ref(&named),
        &[("BATTEN_INSTALL_DIR", &named_str)],
    );
    assert!(
        output.status.success(),
        "{}{}",
        stdout(&output),
        common::stderr(&output)
    );
    assert!(
        stdout(&output).contains(&format!("version={running}")),
        "{}",
        stdout(&output)
    );
    assert_eq!(
        std::fs::read(named.join(binary())).unwrap(),
        std::fs::read(env!("CARGO_BIN_EXE_batten")).unwrap(),
        "the running binary, which is the pin, was placed"
    );
    assert_eq!(
        batten::engine::release_of(&named.join(binary())).as_deref(),
        Some(running.as_str()),
        "and it is stamped as the release it is"
    );
}

/// A RUNNING BUILD THAT REPORTS THE PIN'S VERSION IS NOT THE RELEASE
/// (CLOUD-2398), `#MUTANT release-bytes-copies-unstamped`. Unstamped, its bytes
/// are never placed under the release's name: the release is fetched and
/// verified, and the copy placed carries the release stamp.
#[test]
fn an_install_from_an_unstamped_build_fetches_the_release() {
    if !cfg!(target_os = "linux") {
        return;
    }
    let home = common::scratch_repo("engine-install-unstamped-running");
    let running = format!("v{}", env!("CARGO_PKG_VERSION"));
    pin_worktree(&home, &running);
    let named = home.join("bin");
    let named_str = named.display().to_string();
    let (_host, served) = release_host(&home, &running, &running);
    let output = install(
        &home,
        std::slice::from_ref(&named),
        &with_named(&served, &named_str),
    );
    assert!(
        output.status.success(),
        "{}{}",
        stdout(&output),
        common::stderr(&output)
    );
    let placed = named.join(binary());
    assert_eq!(
        std::fs::read(&placed).unwrap(),
        SHIPPED,
        "the published release was placed, not the running build"
    );
    assert_eq!(
        batten::engine::release_of(&placed).as_deref(),
        Some(running.as_str()),
        "stamped as the release it is"
    );
}

/// `engine update` MOVES THE PIN FORWARD, THEN INSTALLS IT (CLOUD-2287): the
/// worktree pins an older release than `main`, so the pin becomes `main`'s and
/// that release lands.
#[test]
fn an_update_moves_an_older_pin_forward_and_installs_it() {
    if !cfg!(target_os = "linux") {
        return;
    }
    let home = common::scratch_repo("engine-update-forward");
    pin_worktree(&home, "v8.8.8");
    let named = home.join("bin");
    let named_str = named.display().to_string();
    let (_host, served) = release_host(&home, WANTED, WANTED);
    let output = engine_verb(
        "update",
        &home,
        std::slice::from_ref(&named),
        &with_named(&served, &named_str),
    );
    assert!(
        output.status.success(),
        "{}{}",
        stdout(&output),
        common::stderr(&output)
    );
    assert!(
        std::fs::read_to_string(home.join("batten.toml"))
            .unwrap()
            .contains(&format!("engine = {{ release = \"{WANTED}\" }}")),
        "the pin moved to main's"
    );
    assert!(
        stdout(&output).contains(&format!("version={WANTED}")),
        "{}",
        stdout(&output)
    );
    assert_eq!(std::fs::read(named.join(binary())).unwrap(), SHIPPED);
}

/// `engine update` NEVER MOVES A PIN BACKWARD: the name says newer, so a pin
/// already past `main`'s is left as it is and only installed. The downgrade
/// gke-platform measured was this verb's old body.
#[test]
fn an_update_never_moves_a_pin_backward() {
    if !cfg!(target_os = "linux") {
        return;
    }
    let home = common::scratch_repo("engine-update-backward");
    pin_worktree(&home, WANTED);
    let named = home.join("bin");
    let named_str = named.display().to_string();
    let (_host, served) = release_host(&home, "v8.8.8", WANTED);
    let output = engine_verb(
        "update",
        &home,
        std::slice::from_ref(&named),
        &with_named(&served, &named_str),
    );
    assert!(
        output.status.success(),
        "{}{}",
        stdout(&output),
        common::stderr(&output)
    );
    assert!(
        std::fs::read_to_string(home.join("batten.toml"))
            .unwrap()
            .contains(&format!("engine = {{ release = \"{WANTED}\" }}")),
        "the newer pin stands"
    );
    assert_eq!(std::fs::read(named.join(binary())).unwrap(), SHIPPED);
}

/// A source pin is not `engine update`'s to move, and it says so.
#[test]
fn an_update_refuses_a_source_pin() {
    let home = common::scratch_repo("engine-update-source");
    common::write(
        &home,
        "batten.toml",
        &format!(
            "version = 1\nengine = {{ source = \"{}\" }}\n",
            "0".repeat(64)
        ),
    );
    let output = engine_verb("update", &home, &[], &[]);
    assert_eq!(output.status.code(), Some(1), "{}", stdout(&output));
    assert!(
        common::stderr(&output).contains("engine pin source"),
        "{}",
        common::stderr(&output)
    );
}

/// The installed engine's repair (CLOUD-2062, CLOUD-2226, CLOUD-2232), which was
/// `engine update` until CLOUD-2287 made it this verb's.
#[cfg(unix)]
mod repair {
    // The engine follows its pin (CLOUD-2062): a release from the per-tag cache on
    // every path, a source pin built only off the hook path. Moved here from
    // `engine_update.rs` when that verb's body became `engine install`'s
    // (CLOUD-2287).
    //
    // Driven through a private COPY of the compiled binary, because the update
    // replaces the running binary and stamps it — doing that to the shared test
    // binary would change what every other case runs. The source build is a stub
    // `cargo` on `PATH` that writes the "built" engine where the real one would, so
    // the case measures the update's wiring and not a compile.

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

    fn run(binary: &Path, dir: &Path, args: &[&str], stdin: &str) -> Output {
        run_from(binary, dir, dir, args, stdin)
    }

    /// [`run`], standing in `cwd` rather than in the repository.
    #[expect(
        clippy::disallowed_types,
        reason = "stays, and test-only: the update replaces the binary it runs, so each case runs a private COPY of the compiled binary, which `common::batten` cannot target"
    )]
    fn run_from(binary: &Path, dir: &Path, cwd: &Path, args: &[&str], stdin: &str) -> Output {
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
            .current_dir(cwd)
            .env("PATH", path)
            .env("CARGO_TARGET_DIR", dir.join("target"))
            .env("STUB_RAN", dir.join("cargo-ran"))
            .env("HOME", dir)
            .env("BATTEN_INSTALL_DIR", dir.join("install-dir"))
            .env_remove("BATTEN_VERSION_FROM_REF")
            .env_remove("BATTEN_VERSION")
            .env_remove("BATTEN_RELEASES")
            .env_remove("BATTEN_ENGINE_UPDATED")
            .env_remove(batten::engine::LOCAL_ENV)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        let mut child = common::spawn_copy(&mut command);
        child
            .stdin
            .take()
            .unwrap()
            .write_all(stdin.as_bytes())
            .unwrap();
        child.wait_with_output().expect("wait for batten")
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
    fn an_unpinned_worktree_writes_nothing() {
        let dir = repo("engine-update-unpinned");
        stub_cargo(&dir);
        let binary = private_binary(&dir);
        let before = std::fs::read(&binary).unwrap();
        let output = run(&binary, &dir, &["engine", "install"], "");
        assert!(output.status.success(), "{}", text(&output));
        assert!(
            output.stdout.is_empty(),
            "nothing written, nothing said: {}",
            text(&output)
        );
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
        let output = run(&binary, &dir, &["engine", "install"], "");
        assert!(output.status.success(), "{}", text(&output));
        assert_eq!(
            std::fs::read(&on_path).unwrap(),
            b"the built engine\n",
            "the PATH copy was replaced"
        );
        let stamp = std::fs::read_to_string(engine_stamp(&on_path)).unwrap_or_default();
        assert_eq!(stamp.trim(), digest, "and stamped with the pin");
    }

    /// CLOUD-2226 THROUGH CLOUD-2232'S HANDOFF. The installed engine hands
    /// the repair to the checkout's build, which already carries the pin's
    /// stamp; judging only itself, it returned success and left the copy the hook
    /// runs behind, so the refusal's one repair changed nothing. Measured on #1132.
    /// A current running engine installs ITSELF over the stale copy, with no build.
    #[test]
    fn a_current_engine_replaces_a_stale_installed_copy() {
        let dir = repo("engine-update-current-runner");
        stub_cargo(&dir);
        let binary = private_binary(&dir);
        let digest = text(&run(&binary, &dir, &["engine", "digest"], ""))
            .trim()
            .to_owned();
        pin_source(&dir, &digest);
        common::write(
            binary.parent().unwrap(),
            "batten.source",
            &format!("{digest}\n"),
        );
        let on_path = hook_bin(&dir).join("batten");
        std::fs::create_dir_all(hook_bin(&dir)).unwrap();
        common::write(&hook_bin(&dir), "batten", "an older engine\n");
        common::write(
            &hook_bin(&dir),
            "batten.source",
            &format!("{}\n", "0".repeat(64)),
        );
        let output = run(&binary, &dir, &["engine", "install"], "");
        assert!(output.status.success(), "{}", text(&output));
        assert!(
            !dir.join("cargo-ran").exists(),
            "a current engine is copied, not rebuilt"
        );
        assert_eq!(
            std::fs::read(&on_path).unwrap(),
            std::fs::read(&binary).unwrap(),
            "the stale installed copy became the running engine"
        );
        let stamp = std::fs::read_to_string(engine_stamp(&on_path)).unwrap_or_default();
        assert_eq!(stamp.trim(), digest, "and carries the pin's stamp");
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
        let output = run(&binary, &dir, &["engine", "install"], "");
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
            !text(&output).contains("engine install"),
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
        let envelope = r#"{"hook_event_name":"PreToolUse","permission_mode":"default","tool_name":"Bash","tool_input":{"command":"touch x"}}"#;
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
            text(&output).contains("batten engine install"),
            "and the refusal names the update: {}",
            text(&output)
        );
    }

    /// A VERB IS FOLLOWED TOO, NOT ONLY THE HOOK (CLOUD-2232): `follow_pin`'s own
    /// source arm, which the hook's hand-off cannot stand in for. An installed
    /// engine whose stamp is behind the checkout's pin runs `config show` by the
    /// checkout's build, from inside the checkout.
    #[test]
    fn a_verb_is_followed_to_the_checkouts_build() {
        let dir = repo("engine-update-follow-verb");
        stub_cargo(&dir);
        let installed = common::scratch_outside_tree("engine-update", "follow-verb-installed");
        let binary = private_binary(&installed);
        pin_source(&dir, &"1".repeat(64));
        checkout_build(&dir, &"2".repeat(64));
        let output = run(&binary, &dir, &["config", "show"], "");
        assert!(
            text(&output).contains("checkout build ran config show"),
            "the installed binary runs the verb by the checkout's build: {}",
            text(&output)
        );
        assert!(!dir.join("cargo-ran").exists(), "nothing built");
    }

    /// THE HOOK HANDS OFF FROM WHERE THE SESSION STANDS, NOT WHERE THE SHELL DOES.
    /// A worker restart put the shell above the checkout; `follow_pin`, reading the
    /// working directory, found no repository, and the stale installed engine
    /// refused every call, its own repair included. Measured on #1132. The hook
    /// knows the session's authority from the envelope (CLOUD-2204) and hands the
    /// call to that checkout's build.
    #[test]
    fn a_hook_outside_the_checkout_hands_off_to_the_authoritys_build() {
        let dir = repo("engine-update-handoff-outside");
        stub_cargo(&dir);
        // OUTSIDE ANY REPOSITORY, both the installed copy and where the shell
        // stands: `common::scratch` is under this checkout's `target/`, from which
        // the working directory resolves THIS repository and its real build.
        let installed = common::scratch_outside_tree("engine-update", "handoff-installed");
        let binary = private_binary(&installed);
        let envelope = r#"{"hook_event_name":"PreToolUse","session_id":"cloud-2232-handoff","permission_mode":"default","tool_name":"Bash","tool_input":{"command":"touch x"}}"#;
        let args = ["adjudicate", "--harness", "claude-code"];
        // The session first stands in the repository, unpinned, and records it.
        let first = run(&binary, &dir, &args, envelope);
        assert!(
            !text(&first).contains("checkout build ran"),
            "{}",
            text(&first)
        );
        pin_source(&dir, &"1".repeat(64));
        checkout_build(&dir, &"2".repeat(64));
        let output = run_from(&binary, &dir, &installed, &args, envelope);
        assert!(
            text(&output).contains("checkout build ran adjudicate --harness claude-code"),
            "from outside the repository, the call reaches the authority's build: {}",
            text(&output)
        );
        assert!(!dir.join("cargo-ran").exists(), "nothing built");
    }

    /// A stale build of the checkout under a RELEASE pin is told to install the
    /// release, never to rebuild: a `cargo build` reports the tag's version without
    /// being the release, so the advice CLOUD-2220 first gave satisfied the pin with
    /// a binary it does not name. The pinned spelling, so it runs as the binary
    /// `_.path` resolves.
    #[test]
    fn a_stale_build_of_the_checkout_names_the_release_update() {
        let dir = repo("engine-update-stale-checkout-build");
        let binary = private_binary(&dir);
        common::write(
            &dir,
            "batten.toml",
            "version = 1\nengine = { release = \"v9.9.9\" }\n",
        );
        let output = run(&binary, &dir, &["config", "show"], "");
        assert!(
            text(&output).contains("`mise exec -- batten engine install`")
                && !text(&output).contains("cargo build"),
            "a release pin is repaired by the release, never by a build: {}",
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
        let envelope = r#"{"hook_event_name":"PreToolUse","permission_mode":"default","tool_name":"Bash","tool_input":{"command":"touch x"}}"#;
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

    /// TREE MODE OUTRANKS THE PIN (CLOUD-2398), `#MUTANT tree-mode-ignored`.
    /// `batten engine use tree` hands an installed engine's invocations — the
    /// hook's included — to the checkout's own build whatever the pin names, and
    /// `engine use release` hands them back to the pinned release.
    #[test]
    fn tree_mode_hands_an_installed_engine_to_the_checkouts_build() {
        let dir = repo("engine-use-tree");
        let installed = common::scratch("engine-use-tree-installed");
        let binary = private_binary(&installed);
        common::write(
            &dir,
            "batten.toml",
            "version = 1\nengine = { release = \"v9.9.9\" }\n",
        );
        seed_release(&dir, "v9.9.9");
        checkout_build(&dir, &"2".repeat(64));
        let envelope = r#"{"hook_event_name":"PreToolUse","permission_mode":"default","tool_name":"Bash","tool_input":{"command":"touch x"}}"#;
        let args = ["adjudicate", "--harness", "claude-code"];

        let chose = run(&binary, &dir, &["engine", "use", "tree"], "");
        assert!(chose.status.success(), "{}", text(&chose));
        let tree = run(&binary, &dir, &args, envelope);
        assert!(
            text(&tree).contains("checkout build ran adjudicate --harness claude-code"),
            "tree mode hands the hook to the checkout's build: {}",
            text(&tree)
        );

        let back = run(&binary, &dir, &["engine", "use", "release"], "");
        assert!(back.status.success(), "{}", text(&back));
        let release = run(&binary, &dir, &args, envelope);
        assert!(
            text(&release).contains("pinned v9.9.9 ran adjudicate --harness claude-code"),
            "and `engine use release` hands it back to the pin: {}",
            text(&release)
        );
    }

    /// SESSION START SAYS SO (CLOUD-2398), `#MUTANT engine-use-unannounced`: the
    /// choice lives outside the tree, so the start of each session it governs is
    /// the one place it can be seen.
    #[test]
    fn session_start_announces_tree_mode() {
        let dir = repo("engine-use-announced");
        // INSIDE the checkout, so no hand-off applies and this binary answers.
        let binary = private_binary(&dir);
        let envelope = r#"{"hook_event_name":"SessionStart","session_id":"cloud-2398-tree","source":"startup"}"#;
        let args = ["adjudicate", "--harness", "claude-code"];

        let before = run(&binary, &dir, &args, envelope);
        assert!(
            !text(&before).contains("engine use tree"),
            "the release is the silent default: {}",
            text(&before)
        );
        let chose = run(&binary, &dir, &["engine", "use", "tree"], "");
        assert!(chose.status.success(), "{}", text(&chose));
        let after = run(&binary, &dir, &args, envelope);
        assert!(
            text(&after).contains("engine use tree"),
            "session start names tree mode: {}",
            text(&after)
        );
        assert!(
            text(&after).contains("mise run build:release"),
            "and, with no build yet, the build: {}",
            text(&after)
        );
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
        let envelope = r#"{"hook_event_name":"PreToolUse","permission_mode":"default","tool_name":"Bash","tool_input":{"command":"touch x"}}"#;
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
            text(&output).contains("batten engine install"),
            "the stale engine refuses and names the update: {}",
            text(&output)
        );
    }
}
