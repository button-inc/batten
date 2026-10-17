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
    // EXACTLY these directories: a root host's ambient PATH carries a writable
    // `/usr/local/bin`, which `engine install` would rightly choose.
    let joined = std::env::join_paths(path).expect("a PATH entry carries no separator");
    let mut command = common::batten();
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
    command.output().expect("run batten engine install")
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

/// The date `main`'s changelog gives `main`'s own release.
const MAIN_DATE: &str = "2020-02-01";

/// Every platform a fixture provision row names. One of them may be this
/// build's own, whose archive [`release_host`] publishes under its real digest;
/// [`published`] reads any of them back.
const PROVISION_TARGETS: &[&str] = &[
    "x86_64-unknown-linux-musl",
    "aarch64-apple-darwin",
    "x86_64-pc-windows-msvc",
];

/// The stand-in digest the fixture release publishes for another platform's
/// archive, which no case downloads.
fn platform_digest(target: &str) -> String {
    batten::provision::digest(target.as_bytes())
}

/// The digest the fixture release `tag` served from `home` publishes for
/// `target`'s archive, read off its `SHA256SUMS`: this build's own is the real
/// archive's, which a case cannot spell ahead of the build.
fn published(home: &Path, tag: &str, target: &str) -> String {
    let sums = std::fs::read_to_string(
        home.join("www")
            .join(REPO)
            .join("releases")
            .join("download")
            .join(tag)
            .join("SHA256SUMS"),
    )
    .unwrap();
    batten::engine::published_digest(&sums, &batten::engine::release_asset(tag, target)).unwrap()
}

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
    // `main`'s changelog (CLOUD-2279): `engine outdated` counts the releases
    // between a pin and `main`'s from its headings.
    let changelog = repo.join("main").join("crates").join("batten");
    std::fs::create_dir_all(&changelog).unwrap();
    std::fs::write(
        changelog.join("CHANGELOG.md"),
        format!(
            "# Changelog\n\n## [Unreleased]\n\n## [{}](https://example.invalid) - {MAIN_DATE}\n\n### Added\n\n- a thing\n\n## [8.8.8](https://example.invalid) - 2020-01-01\n",
            main_pin.trim_start_matches('v')
        ),
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
    // EVERY PROVISION PLATFORM'S ASSET, not only this build's (CLOUD-2279): a
    // provision row names an archive per platform, and `engine update` pins each
    // one's digest from this manifest.
    // THIS BUILD'S OWN PLATFORM IS SERVED ONCE, as the real archive: a second
    // line under a stand-in digest is a manifest naming one asset two ways.
    let mut sums = format!("{}  {asset}\n", batten::provision::digest(&bytes));
    let running = batten::engine::running_target();
    for &target in PROVISION_TARGETS
        .iter()
        .filter(|target| **target != running)
    {
        use std::fmt::Write as _;
        writeln!(
            sums,
            "{}  {}",
            platform_digest(target),
            batten::engine::release_asset(served, target)
        )
        .unwrap();
    }
    let names: Vec<&str> = sums
        .lines()
        .filter_map(|line| line.split_whitespace().nth(1))
        .collect();
    let once: std::collections::BTreeSet<&&str> = names.iter().collect();
    assert_eq!(
        once.len(),
        names.len(),
        "each asset is published once: {sums}"
    );
    std::fs::write(download.join("SHA256SUMS"), sums).unwrap();

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
    let mut env = served_env(&served);
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
    let mut env = served_env(&served);
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
    let mut env = served_env(&served);
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

/// `served`'s environment as a case passes it.
fn served_env(served: &[(String, String)]) -> Vec<(&str, &str)> {
    served
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect()
}

/// `served`'s environment as `install` takes it, plus `BATTEN_INSTALL_DIR`.
fn with_named<'a>(served: &'a [(String, String)], named: &'a str) -> Vec<(&'a str, &'a str)> {
    let mut env = served_env(served);
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
/// current, and it runs off `PATH`.
#[test]
fn the_bootstrap_places_a_running_pin() {
    let home = common::scratch_repo("engine-install-running-pin");
    let running = format!("v{}", env!("CARGO_PKG_VERSION"));
    pin_worktree(&home, &running);
    let named = home.join("bin");
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

/// THE UPDATE INSTALLS ITS OWN TARGET (CLOUD-2418), whatever
/// `BATTEN_VERSION_FROM_REF` would pick: `engine install` re-derives its
/// release from the ref, so handing off to it installed `main`'s v8.8.8 under a
/// config naming v9.9.9. Only v9.9.9 is served, so the ref's choice fails.
#[test]
fn an_update_installs_its_target_whatever_the_ref_pins() {
    if !cfg!(target_os = "linux") {
        return;
    }
    let home = common::scratch_repo("engine-update-ref");
    pin_worktree(&home, WANTED);
    let named = home.join("bin");
    let named_str = named.display().to_string();
    let (_host, served) = release_host(&home, "v8.8.8", WANTED);
    let mut env = with_named(&served, &named_str);
    env.push(("BATTEN_VERSION_FROM_REF", "main"));
    let output = engine_verb("update", &home, std::slice::from_ref(&named), &env);
    assert!(
        output.status.success(),
        "{}{}",
        stdout(&output),
        common::stderr(&output)
    );
    assert_eq!(std::fs::read(named.join(binary())).unwrap(), SHIPPED);
}

/// A FAILED INSTALL LEAVES THE MOVED PIN (CLOUD-2418): the write stands, so a
/// re-run `engine install` finishes the update. Here `main` pins v9.9.9 and the
/// host publishes only v7.7.7, so the install after the write fails.
#[test]
fn a_failed_install_leaves_the_moved_pin() {
    if !cfg!(target_os = "linux") {
        return;
    }
    let home = common::scratch_repo("engine-update-failed-install");
    pin_worktree(&home, "v8.8.8");
    let named = home.join("bin");
    let named_str = named.display().to_string();
    let (_host, served) = release_host(&home, WANTED, "v7.7.7");
    let output = engine_verb(
        "update",
        &home,
        std::slice::from_ref(&named),
        &with_named(&served, &named_str),
    );
    assert!(!output.status.success(), "{}", stdout(&output));
    assert!(
        std::fs::read_to_string(home.join("batten.toml"))
            .unwrap()
            .contains(&format!("engine = {{ release = \"{WANTED}\" }}")),
        "the moved pin stands"
    );
    assert!(!named.join(binary()).exists(), "nothing was installed");
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

/// A worktree pinned at v8.8.8 with every other batten declaration on v8.8.8
/// too: a provision row across [`PROVISION_TARGETS`] and the floor, plus
/// `extra` appended.
fn pin_every_copy(home: &Path, floor: &str, extra: &str) {
    use std::fmt::Write as _;
    let mut config = format!(
        "version = 1\nmin_batten_version = \"{floor}\"\nengine = {{ release = \"v8.8.8\" }}\n\n[[provision]]\nname = \"batten\"\nversion = \"8.8.8\"\nbinary = \"batten\"\n"
    );
    for &target in PROVISION_TARGETS {
        writeln!(
            config,
            "\n[provision.platforms.{target}]\n# the platform's archive\nurl = \"https://example.invalid/releases/download/v8.8.8/{}\"\nsha256 = \"{}\"",
            batten::engine::release_asset("v8.8.8", target),
            "0".repeat(64)
        )
        .unwrap();
    }
    config.push_str(extra);
    common::write(home, "batten.toml", &config);
}

/// Run `batten <args>` in `home` as [`engine_verb`] runs a verb, with the
/// state directory inside the case and neither `CI` nor the opt-out ambient.
fn batten_in(home: &Path, args: &[&str], env: &[(&str, &str)]) -> std::process::Output {
    use common::StateHome as _;
    let mut command = common::batten();
    command
        .state_dir(&home.join("data"))
        .args(args)
        .current_dir(home)
        .env("HOME", home)
        .env_remove("CI")
        .env_remove("BATTEN_NO_UPDATE_NOTICE")
        .env_remove("BATTEN_RELEASES")
        .env_remove("BATTEN_VERSION_FROM_REF")
        .env_remove("BATTEN_VERSION");
    for (name, value) in env {
        command.env(name, value);
    }
    command.output().expect("run batten")
}

/// `engine update` BRINGS EVERY COPY TO THE RELEASE (CLOUD-2279): the pin, the
/// batten provision row's version, URLs and digests, and the floor, in one call.
#[test]
fn an_update_brings_every_batten_declaration_to_the_release() {
    if !cfg!(target_os = "linux") {
        return;
    }
    let home = common::scratch_repo("engine-update-every-copy");
    pin_every_copy(&home, "8.8.8", "");
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
    let config = std::fs::read_to_string(home.join("batten.toml")).unwrap();
    assert!(
        config.contains(&format!("engine = {{ release = \"{WANTED}\" }}")),
        "{config}"
    );
    assert!(
        config.contains("min_batten_version = \"9.9.9\""),
        "{config}"
    );
    assert!(config.contains("version = \"9.9.9\"\nbinary"), "{config}");
    for &target in PROVISION_TARGETS {
        assert!(
            config.contains(&format!(
                "url = \"https://example.invalid/releases/download/v9.9.9/{}\"",
                batten::engine::release_asset("v9.9.9", target)
            )),
            "{config}"
        );
        assert!(
            config.contains(&format!(
                "sha256 = \"{}\"",
                published(&home, "v9.9.9", target)
            )),
            "{config}"
        );
    }
    assert!(
        !config.contains("8.8.8"),
        "no copy is left behind: {config}"
    );
    assert!(
        config.contains("# the platform's archive"),
        "every other byte is kept"
    );
    assert_eq!(std::fs::read(named.join(binary())).unwrap(), SHIPPED);
}

/// A ROW AT THE TARGET VERSION IS STILL REPAIRED (CLOUD-2418): its `version`
/// already names v9.9.9, but one platform carries a zero digest and another a
/// v8.8.8 url, and both are brought to the release.
#[test]
fn an_update_repairs_a_stale_digest_at_the_current_version() {
    use std::fmt::Write as _;
    if !cfg!(target_os = "linux") {
        return;
    }
    let home = common::scratch_repo("engine-update-stale-digest");
    let mut config = String::from(
        "version = 1\nengine = { release = \"v9.9.9\" }\n\n[[provision]]\nname = \"batten\"\nversion = \"9.9.9\"\nbinary = \"batten\"\n",
    );
    for (n, &target) in PROVISION_TARGETS.iter().enumerate() {
        let tag = if n == 0 { "v9.9.9" } else { "v8.8.8" };
        writeln!(
            config,
            "\n[provision.platforms.{target}]\nurl = \"https://example.invalid/releases/download/{tag}/{}\"",
            batten::engine::release_asset(tag, target),
        )
        .unwrap();
        // The last platform carries no digest at all, which the update writes.
        if n + 1 < PROVISION_TARGETS.len() {
            writeln!(config, "sha256 = \"{}\"", "0".repeat(64)).unwrap();
        }
    }
    common::write(&home, "batten.toml", &config);
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
    let config = std::fs::read_to_string(home.join("batten.toml")).unwrap();
    for &target in PROVISION_TARGETS {
        assert!(
            config.contains(&format!(
                "url = \"https://example.invalid/releases/download/v9.9.9/{}\"",
                batten::engine::release_asset("v9.9.9", target)
            )),
            "{config}"
        );
        assert!(
            config.contains(&format!(
                "sha256 = \"{}\"",
                published(&home, "v9.9.9", target)
            )),
            "{config}"
        );
    }
    assert!(
        !config.contains("8.8.8"),
        "no copy is left behind: {config}"
    );
}

/// A DIGEST IN ANOTHER CASE IS NO DISAGREEMENT (CLOUD-2418): `engine gate`
/// accepts it, so `engine update` leaves the config it already accepts as it is.
#[test]
fn an_update_leaves_a_digest_in_another_case() {
    use std::fmt::Write as _;
    if !cfg!(target_os = "linux") {
        return;
    }
    let home = common::scratch_repo("engine-update-digest-case");
    let named = home.join("bin");
    let named_str = named.display().to_string();
    let (_host, served) = release_host(&home, WANTED, WANTED);
    let mut config = String::from(
        "version = 1\nengine = { release = \"v9.9.9\" }\n\n[[provision]]\nname = \"batten\"\nversion = \"9.9.9\"\nbinary = \"batten\"\n",
    );
    for &target in PROVISION_TARGETS {
        writeln!(
            config,
            "\n[provision.platforms.{target}]\nurl = \"https://example.invalid/releases/download/v9.9.9/{}\"\nsha256 = \"{}\"",
            batten::engine::release_asset("v9.9.9", target),
            published(&home, "v9.9.9", target).to_ascii_uppercase()
        )
        .unwrap();
    }
    common::write(&home, "batten.toml", &config);
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
    assert_eq!(
        std::fs::read_to_string(home.join("batten.toml")).unwrap(),
        config,
        "the update wrote a config the gate already accepts"
    );
}

/// The floor is RAISED, never lowered: a `min_batten_version` already past the
/// release is the consumer's own word and stays.
#[test]
fn an_update_never_lowers_min_batten_version() {
    if !cfg!(target_os = "linux") {
        return;
    }
    let home = common::scratch_repo("engine-update-floor");
    pin_every_copy(&home, "10.0.0", "");
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
    let config = std::fs::read_to_string(home.join("batten.toml")).unwrap();
    assert!(
        config.contains("min_batten_version = \"10.0.0\""),
        "{config}"
    );
    assert!(
        config.contains(&format!("engine = {{ release = \"{WANTED}\" }}")),
        "{config}"
    );
}

/// A WORKFLOW LITERAL THE UPDATE CANNOT REWRITE REFUSES IT, AND NOTHING IS
/// WRITTEN: the config editor has no YAML backend, so the stale copy is named by
/// `path:line` rather than left behind. An expression and a longer key are not
/// copies.
#[test]
fn a_workflow_literal_the_update_cannot_rewrite_refuses_and_writes_nothing() {
    if !cfg!(target_os = "linux") {
        return;
    }
    let home = common::scratch_repo("engine-update-workflow-literal");
    pin_every_copy(&home, "8.8.8", "");
    common::write(
        &home,
        ".github/workflows/ci.yml",
        "jobs:\n  a:\n    env:\n      BATTEN_VERSION_FROM_REF: main\n      BATTEN_VERSION: ${{ steps.dist.outputs.version }}\n      BATTEN_VERSION: v8.8.8\n",
    );
    common::git_in(&home, &["add", ".github/workflows/ci.yml"]);
    let before = std::fs::read(home.join("batten.toml")).unwrap();
    let named = home.join("bin");
    let named_str = named.display().to_string();
    let (_host, served) = release_host(&home, WANTED, WANTED);
    let output = engine_verb(
        "update",
        &home,
        std::slice::from_ref(&named),
        &with_named(&served, &named_str),
    );
    assert_eq!(output.status.code(), Some(2), "{}", common::stderr(&output));
    assert_eq!(
        stdout(&output).lines().collect::<Vec<_>>(),
        [
            ".github/workflows/ci.yml:6 BATTEN_VERSION disagrees with v9.9.9, and the update cannot rewrite it"
        ],
    );
    assert_eq!(
        std::fs::read(home.join("batten.toml")).unwrap(),
        before,
        "batten.toml is byte-for-byte unchanged"
    );
    assert!(!named.join(binary()).exists(), "nothing was installed");
}

/// `engine outdated` EXITS BY THE PIN'S DISTANCE FROM `main`: 0 current, 2
/// behind (naming each release between), 2 with no pin, 0 for a source pin,
/// and 3 when it could not look.
#[test]
fn outdated_exits_by_the_pins_distance_from_main() {
    if !cfg!(target_os = "linux") {
        return;
    }
    let home = common::scratch_repo("engine-outdated");
    let (_host, served) = release_host(&home, WANTED, WANTED);
    let env = served_env(&served);

    pin_worktree(&home, WANTED);
    let current = batten_in(&home, &["engine", "outdated"], &env);
    assert_eq!(
        current.status.code(),
        Some(0),
        "{}",
        common::stderr(&current)
    );
    assert_eq!(stdout(&current), "");

    pin_worktree(&home, "v8.8.8");
    let behind = batten_in(&home, &["engine", "outdated"], &env);
    assert_eq!(behind.status.code(), Some(2), "{}", common::stderr(&behind));
    assert_eq!(
        stdout(&behind),
        format!("v8.8.8 → {WANTED}\nv9.9.9 {MAIN_DATE}\n")
    );

    common::write(&home, "batten.toml", "version = 1\n");
    let unpinned = batten_in(&home, &["engine", "outdated"], &env);
    assert_eq!(
        unpinned.status.code(),
        Some(2),
        "{}",
        common::stderr(&unpinned)
    );
    assert!(stdout(&unpinned).ends_with("batten.toml no engine pin\n"));

    common::write(
        &home,
        "batten.toml",
        &format!(
            "version = 1\nengine = {{ source = \"{}\" }}\n",
            "a".repeat(64)
        ),
    );
    let source = batten_in(&home, &["engine", "outdated"], &env);
    assert_eq!(source.status.code(), Some(0), "{}", common::stderr(&source));
    assert_eq!(stdout(&source), "", "a source pin is nothing to be behind");

    pin_worktree(&home, "v8.8.8");
    let mut unreachable = env.clone();
    unreachable.retain(|(name, _)| *name != "BATTEN_RELEASES");
    unreachable.push(("BATTEN_RELEASES", "https://localhost:1/example/pkg"));
    let blind = batten_in(&home, &["engine", "outdated"], &unreachable);
    assert_eq!(blind.status.code(), Some(3), "{}", common::stderr(&blind));
}

/// How many `engine-fresh` records `home`'s store holds, whatever their branch.
fn fresh_records(home: &Path) -> usize {
    std::fs::read_dir(home.join(".git").join("batten-receipts")).map_or(0, |entries| {
        entries
            .flatten()
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with("engine-fresh.")
            })
            .count()
    })
}

/// `--record` CLEARS ITS READING ON EVERY RUN THAT HAS NO DISTANCE TO GIVE
/// (CLOUD-2418), read off the store rather than inferred from `check`: a stale
/// line is written, then cleared by a run with no pin, then written again and
/// cleared by a run that could not look.
#[test]
fn outdated_clears_its_record_without_a_pin_and_when_blind() {
    if !cfg!(target_os = "linux") {
        return;
    }
    let home = common::scratch("engine-outdated-clears");
    common::init_repo(&home);
    pin_worktree(&home, "v8.8.8");
    common::git_in(&home, &["add", "batten.toml"]);
    common::git_in(&home, &["commit", "-qm", "pin"]);
    let (_host, served) = release_host(&home, WANTED, WANTED);
    let env = served_env(&served);
    let mut blind = env.clone();
    blind.retain(|(name, _)| *name != "BATTEN_RELEASES");
    blind.push(("BATTEN_RELEASES", "https://localhost:1/example/pkg"));

    let stale = batten_in(&home, &recorded_args(), &env);
    assert_eq!(stale.status.code(), Some(2), "{}", common::stderr(&stale));
    assert_eq!(fresh_records(&home), 1, "the stale reading is recorded");
    common::write(&home, "batten.toml", "version = 1\n");
    let unpinned = batten_in(&home, &recorded_args(), &env);
    assert_eq!(
        unpinned.status.code(),
        Some(2),
        "{}",
        common::stderr(&unpinned)
    );
    assert_eq!(fresh_records(&home), 0, "no pin clears it");

    pin_worktree(&home, "v8.8.8");
    let again = batten_in(&home, &recorded_args(), &env);
    assert_eq!(again.status.code(), Some(2), "{}", common::stderr(&again));
    assert_eq!(
        fresh_records(&home),
        1,
        "the stale reading is recorded again"
    );
    let unanswered = batten_in(&home, &recorded_args(), &blind);
    assert_eq!(
        unanswered.status.code(),
        Some(3),
        "{}",
        common::stderr(&unanswered)
    );
    assert_eq!(
        fresh_records(&home),
        0,
        "a run that could not look clears it"
    );
}

/// A CHANGELOG THAT LAGS ITS OWN PIN STILL DATES IT (CLOUD-2418): `main`'s
/// changelog lacks v9.9.9's heading, so the release is read off its own tag's
/// changelog, and its date is printed rather than `-`.
#[test]
fn a_lagging_changelog_dates_main_from_its_own_tag() {
    if !cfg!(target_os = "linux") {
        return;
    }
    let home = common::scratch_repo("engine-outdated-lagging");
    let (_host, served) = release_host(&home, WANTED, WANTED);
    let repo = home.join("www").join(REPO);
    let changelog = |reference: &str, body: &str| {
        let dir = repo.join(reference).join("crates").join("batten");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("CHANGELOG.md"), body).unwrap();
    };
    changelog(
        "main",
        "# Changelog\n\n## [8.8.8](https://example.invalid) - 2020-01-01\n",
    );
    changelog(
        WANTED,
        &format!("# Changelog\n\n## [9.9.9](https://example.invalid) - {MAIN_DATE}\n"),
    );
    let env = served_env(&served);
    pin_worktree(&home, "v8.8.8");
    let behind = batten_in(&home, &["engine", "outdated"], &env);
    assert_eq!(behind.status.code(), Some(2), "{}", common::stderr(&behind));
    assert_eq!(
        stdout(&behind),
        format!("v8.8.8 → {WANTED}\nv9.9.9 {MAIN_DATE}\n")
    );
}

/// A MALFORMED PIN IS NAMED AS ONE (CLOUD-2418), with the words every other
/// verb uses, never as an absent pin.
#[test]
fn outdated_names_a_malformed_pin() {
    let home = common::scratch_repo("engine-outdated-malformed");
    common::write(
        &home,
        "batten.toml",
        &format!(
            "version = 1\nengine = {{ release = \"{WANTED}\", source = \"{}\" }}\n",
            "a".repeat(64)
        ),
    );
    let output = batten_in(&home, &["engine", "outdated"], &[]);
    assert_eq!(output.status.code(), Some(2), "{}", common::stderr(&output));
    assert!(
        stdout(&output).ends_with(&format!("batten.toml {}\n", batten::engine::MALFORMED_PIN)),
        "{}",
        stdout(&output)
    );
}

/// THE NOTICE SPEAKS ONCE PER TTL AND NEVER IN CI: silent under `CI`, one line
/// naming `batten engine update` the first time outside it, silent the second
/// time inside the day. Every run exits 0.
#[test]
fn the_notice_speaks_once_per_ttl_and_never_in_ci() {
    if !cfg!(target_os = "linux") {
        return;
    }
    let home = common::scratch_repo("engine-outdated-notice");
    pin_worktree(&home, "v8.8.8");
    let (_host, served) = release_host(&home, WANTED, WANTED);
    let env = served_env(&served);
    let notice = ["engine", "outdated", "--notice"];

    let mut in_ci = env.clone();
    in_ci.push(("CI", "true"));
    let ci = batten_in(&home, &notice, &in_ci);
    assert_eq!(ci.status.code(), Some(0), "{}", common::stderr(&ci));
    assert_eq!(stdout(&ci), "", "never in CI");

    let first = batten_in(&home, &notice, &env);
    assert_eq!(first.status.code(), Some(0), "{}", common::stderr(&first));
    assert!(
        stdout(&first).contains("run `batten engine update`"),
        "{}",
        stdout(&first)
    );
    assert_eq!(stdout(&first).lines().count(), 1);

    let second = batten_in(&home, &notice, &env);
    assert_eq!(second.status.code(), Some(0), "{}", common::stderr(&second));
    assert_eq!(stdout(&second), "", "once per TTL");
}

/// THE `engine-hygiene` PRESET REFUSES A STALE RECORD AND IS SILENT WITH NONE:
/// a consumer pinned at this build's release, `main` two releases on, the
/// record written by `engine outdated` itself with thresholds of zero — and
/// cleared by it once the pin is a source build.
#[test]
fn a_stale_engine_fresh_record_fails_check() {
    if !cfg!(target_os = "linux") {
        return;
    }
    let home = common::scratch("engine-fresh-consumer");
    common::init_repo(&home);
    let running = format!("v{}", env!("CARGO_PKG_VERSION"));
    common::write(
        &home,
        "batten.toml",
        &format!(
            "version = 1\nengine = {{ release = \"{running}\" }}\n\n[[rule]]\nid = \"release pin stale\"\n\
             kind = \"policy\"\nscope = \"tree\"\npreset = \"engine-hygiene\"\nseverity = \"deny\"\n\n\
             [[record]]\nrecord = \"engine-fresh\"\n\
             writer = \"batten engine outdated --record engine-fresh --max-releases 0 --max-days 0\"\n"
        ),
    );
    common::git_in(&home, &["add", "batten.toml"]);
    common::git_in(&home, &["commit", "-qm", "enable the preset"]);
    let (_host, served) = release_host(&home, WANTED, WANTED);
    let env = served_env(&served);
    let check = ["check", "--rule", "release pin stale"];

    let silent = batten_in(&home, &check, &[]);
    assert_eq!(silent.status.code(), Some(0), "{}", common::stderr(&silent));

    let recorded = batten_in(&home, &recorded_args(), &env);
    assert_eq!(
        recorded.status.code(),
        Some(2),
        "{}",
        common::stderr(&recorded)
    );

    let refused = batten_in(&home, &check, &[]);
    assert_eq!(
        refused.status.code(),
        Some(2),
        "{}",
        common::stderr(&refused)
    );

    // A SOURCE PIN CLEARS THE READING: there is no release distance to measure,
    // so the stale line written under the release pin must not outlive it.
    let config = std::fs::read_to_string(home.join("batten.toml")).unwrap();
    let sourced = config.replace(
        &format!("engine = {{ release = \"{running}\" }}"),
        &format!("engine = {{ source = \"{}\" }}", "a".repeat(64)),
    );
    assert_ne!(sourced, config, "the fixture's release pin was swapped");
    common::write(&home, "batten.toml", &sourced);
    let cleared = batten_in(&home, &recorded_args(), &env);
    assert_eq!(
        cleared.status.code(),
        Some(0),
        "{}",
        common::stderr(&cleared)
    );
    let silent_again = batten_in(&home, &check, &[]);
    assert_eq!(
        silent_again.status.code(),
        Some(0),
        "{}",
        common::stderr(&silent_again)
    );
}

/// AN UPDATE CLEARS THE READING IT MADE FALSE (CLOUD-2418): a stale
/// `engine-fresh` line judged the running release's pin, and once `engine
/// update` moves the pin the line no longer describes it, so it is removed —
/// read off the store, since `check` cannot load a pin this build is not.
#[test]
fn an_update_clears_the_engine_fresh_record() {
    if !cfg!(target_os = "linux") {
        return;
    }
    let home = common::scratch("engine-fresh-update");
    common::init_repo(&home);
    common::write(
        &home,
        "batten.toml",
        &format!(
            "version = 1\nengine = {{ release = \"v{}\" }}\n\n[[record]]\nrecord = \"engine-fresh\"\n\
             writer = \"batten engine outdated --record engine-fresh --max-releases 0 --max-days 0\"\n",
            env!("CARGO_PKG_VERSION")
        ),
    );
    common::git_in(&home, &["add", "batten.toml"]);
    common::git_in(&home, &["commit", "-qm", "pin"]);
    let (_host, served) = release_host(&home, WANTED, WANTED);
    let env = served_env(&served);
    let recorded = batten_in(&home, &recorded_args(), &env);
    assert_eq!(
        recorded.status.code(),
        Some(2),
        "{}",
        common::stderr(&recorded)
    );
    assert_eq!(fresh_records(&home), 1, "the stale reading is recorded");

    let named = home.join("bin");
    let named_str = named.display().to_string();
    let updated = engine_verb(
        "update",
        &home,
        std::slice::from_ref(&named),
        &with_named(&served, &named_str),
    );
    assert!(
        updated.status.success(),
        "{}{}",
        stdout(&updated),
        common::stderr(&updated)
    );
    assert_eq!(
        fresh_records(&home),
        0,
        "the update cleared the reading it moved past"
    );
}

/// `engine outdated --record engine-fresh` with thresholds of zero.
fn recorded_args() -> [&'static str; 8] {
    [
        "engine",
        "outdated",
        "--record",
        "engine-fresh",
        "--max-releases",
        "0",
        "--max-days",
        "0",
    ]
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
        let envelope = r#"{"hook_event_name":"PreToolUse","session_id":"cloud-2232-handoff","permission_mode":"default","tool_name":"Bash","tool_input":{"command":"ls"}}"#;
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
            text(&output).contains("batten engine install"),
            "the stale engine refuses and names the update: {}",
            text(&output)
        );
    }
}
