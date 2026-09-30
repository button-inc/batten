//! The single-binary install path (CLOUD-65), driven from Rust — ported from
//! `tests/install.bats` under CLOUD-843.
//!
//! `install.sh` stays bash, and nothing else can do its job: it runs on a machine
//! that has nothing installed yet, so it may assume only what `curl … | sh`
//! already proves is present. Its coverage does not have to stay bash with it —
//! this tier runs the committed script end to end, as the retired suite did.
//!
//! # The clause worth testing is the REFUSAL
//!
//! An installer that verifies a digest when one is present and installs anyway
//! when it is not has never verified anything, and that failure is invisible in
//! the happy path. So every case below that ends in exit 1 also asserts that
//! nothing reached the destination.
//!
//! # A `file://` API tree rather than a stubbed transport
//!
//! The script's whole job is talking to an HTTP API, and stubbing the transport
//! would leave its request shape, its redirect handling and its config-on-stdin
//! token path untested. curl reads `file://` with the same `--config` machinery,
//! so what runs here is the real code path minus the network. The cases that
//! assert what the script DECIDED TO SEND — a CA bundle, a proxy bypass, a
//! credential — stub curl instead and read the config it was handed, because a
//! `file://` transfer involves no TLS and no proxy and would pass whether or not
//! the value was ever passed. `install_web.rs` owns the web route over a loopback
//! host; this file owns the API route.
//!
//! The payload is PRETTY-PRINTED, matching what the release API actually answers
//! with. An earlier version of the script parsed the compact form and failed on
//! the first real request, which is why the fixture commits to the awkward shape
//! and a case below proves the compact one too.
//!
//! # The fixture names its own repository
//!
//! `BATTEN_REPO` is set to a placeholder rather than left at the script's
//! default: `forge name other` refuses this deployment's origin anywhere under
//! `crates/batten/tests/**`, and rightly — the subject is the installer, not
//! where this repository happens to be hosted.
//!
//! # Unix only
//!
//! The subject is a POSIX shell program run through `sh`, needing `curl`, `tar`
//! and `mktemp`, against a Linux target; the retired suite ran in the one Linux
//! lane. `install_web.rs` is scoped the same way for the same reason.

#![cfg(unix)]
// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

// CLOUD-1268's fifth arm: `install.sh` is one of the four files that stay bash,
// so every arm names it as the survivor it still accounts for.
//
// ported: tests/install.bats subject:install.sh crates/batten/tests/it/install_script.rs
// ported: "install.bats::--targets lists the targets a POSIX installer can serve" crates/batten/tests/it/install_script.rs subject:install.sh
// ported: "install.bats::--asset-name is name-vversion-target with a per-target extension" crates/batten/tests/it/install_script.rs subject:install.sh
// ported: "install.bats::the query flags install nothing" crates/batten/tests/it/install_script.rs subject:install.sh
// ported: "install.bats::a release whose digest matches installs the binary" crates/batten/tests/it/install_script.rs subject:install.sh
// ported: "install.bats::BATTEN_VERSION selects a tag rather than the latest release" crates/batten/tests/it/install_script.rs subject:install.sh
// ported: "install.bats::THE DEFECT: a digest that does not match the bytes installs nothing" crates/batten/tests/it/install_script.rs subject:install.sh
// ported: "install.bats::THE DEFECT: an asset the API reports no digest for is refused, not installed unverified" crates/batten/tests/it/install_script.rs subject:install.sh
// ported: "install.bats::a release carrying no asset for this target is exit 1, naming the asset" crates/batten/tests/it/install_script.rs subject:install.sh
// ported: "install.bats::a target no release leg builds is refused before any request" crates/batten/tests/it/install_script.rs subject:install.sh
// ported: "install.bats::an unreadable release is exit 2 — could not look, not a broken release" crates/batten/tests/it/install_script.rs subject:install.sh
// ported: "install.bats::a payload with no tag_name is exit 2, never a guessed version" crates/batten/tests/it/install_script.rs subject:install.sh
// ported: "install.bats::the compact payload shape parses too — neither wire form is assumed" crates/batten/tests/it/install_script.rs subject:install.sh
// ported: "install.bats::--help explains the surface and exits 0" crates/batten/tests/it/install_script.rs subject:install.sh
// ported: "install.bats::THE DEFECT: installing off PATH is a refusal, not a warning over exit 0" crates/batten/tests/it/install_script.rs subject:install.sh
// ported: "install.bats::the off-PATH refusal has an opt-out, for a deliberate destination" crates/batten/tests/it/install_script.rs subject:install.sh
// ported: "install.bats::a declared CA bundle reaches curl, for a proxy that re-terminates TLS" crates/batten/tests/it/install_script.rs subject:install.sh
// ported: "install.bats::CURL_CA_BUNDLE outranks SSL_CERT_FILE when both are declared" crates/batten/tests/it/install_script.rs subject:install.sh
// ported: "install.bats::no CA declaration means no cacert line — an unproxied host is untouched" crates/batten/tests/it/install_script.rs subject:install.sh
// ported: "install.bats::the retry is bounded and reports rather than looping forever" crates/batten/tests/it/install_script.rs subject:install.sh
// ported: "install.bats::a proxy refusal is retried around the proxy with the operator's own credential" crates/batten/tests/it/install_script.rs subject:install.sh
// ported: "install.bats::an ordinary failure never leaves the proxy" crates/batten/tests/it/install_script.rs subject:install.sh
// ported: "install.bats::a refusal from an authority the operator chose is honoured, not bypassed" crates/batten/tests/it/install_script.rs subject:install.sh
// ported: "install.bats::the fallback can be switched off entirely" crates/batten/tests/it/install_script.rs subject:install.sh
// ported: "install.bats::the ordinary token order still wins on the first attempt" crates/batten/tests/it/install_script.rs subject:install.sh
// ported: "install.bats::the version comes from the ref's manifest when one is named" crates/batten/tests/it/install_script.rs subject:install.sh
// ported: "install.bats::a ref naming an unreleased version falls back to the latest release" crates/batten/tests/it/install_script.rs subject:install.sh
// ported: "install.bats::an explicitly named version never falls back" crates/batten/tests/it/install_script.rs subject:install.sh

use crate::common;

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

/// The target every case installs unless it names another.
const TARGET: &str = "x86_64-unknown-linux-musl";

/// The repository the fixture API serves. See the module doc for why it is not
/// the script's default.
const REPO: &str = "example/pkg";

/// The digest the second, never-downloaded asset advertises.
const ZEROS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// One case's fixture API, destination and archive.
struct Fixture {
    /// The case's scratch root.
    dir: PathBuf,
    /// The `file://` API tree.
    api: PathBuf,
    /// The destination, on `PATH` as a real install is.
    dest: PathBuf,
    /// The sha256 of the one archive the release carries.
    digest: String,
}

/// What one run of the installer did.
struct Run {
    code: Option<i32>,
    /// stdout and stderr together, as the retired suite's `run` read them.
    output: String,
}

impl Fixture {
    fn new(case: &str) -> Self {
        let dir = common::scratch(&format!("install-script-{case}"));
        let api = dir.join("api");
        fs::create_dir_all(api.join(format!("repos/{REPO}/releases/tags"))).unwrap();
        fs::create_dir_all(api.join("releases/assets")).unwrap();
        // The payload a release carries: one archive holding `batten` at its root,
        // which is what the release workflow produces.
        let stage = dir.join("stage");
        fs::create_dir_all(&stage).unwrap();
        fs::write(stage.join("batten"), "#!/bin/sh\necho fixture-batten\n").unwrap();
        let archive = api.join("releases/assets/1");
        #[expect(
            clippy::disallowed_types,
            reason = "stays — CLOUD-843: the installer untars what it downloads, so the fixture payload has to be a real gzipped tar and `tar` is what writes one; the retired suite made this same spawn"
        )]
        let status = std::process::Command::new("tar")
            .arg("-czf")
            .arg(&archive)
            .arg("-C")
            .arg(&stage)
            .arg("batten")
            .status()
            .expect("run tar");
        assert!(status.success(), "the fixture archive must build");
        let digest = batten::provision::digest(&fs::read(&archive).unwrap());
        let dest = dir.join("bin");
        fs::create_dir_all(&dest).unwrap();
        Self {
            dir,
            api,
            dest,
            digest,
        }
    }

    /// The release payload, advertising `digest` for the asset — `None` omits the
    /// field entirely, which is the "no digest" case. Written as `latest` and as
    /// the tag both, as the API serves it.
    fn release_json(&self, digest: Option<&str>) {
        let api = self.api.display();
        let digest_line = digest.map_or_else(String::new, |hex| {
            format!("    \"digest\": \"sha256:{hex}\",\n")
        });
        let payload = format!(
            "{{\n  \"url\": \"file://{api}/releases/89\",\n  \"tag_name\": \"v9.9.9\",\n  \
             \"author\": {{\n    \"login\": \"someone\"\n  }},\n  \"assets\": [\n    {{\n      \
             \"url\": \"file://{api}/releases/assets/1\",\n      \"id\": 1,\n      \
             \"name\": \"batten-v9.9.9-{TARGET}.tar.gz\",\n      \"uploader\": {{\n        \
             \"login\": \"someone\"\n      }},\n      \"content_type\": \"application/gzip\",\n\
             {digest_line}      \"browser_download_url\": \"file://{api}/releases/download/v9.9.9/batten-v9.9.9-{TARGET}.tar.gz\"\n    \
             }},\n    {{\n      \"url\": \"file://{api}/releases/assets/2\",\n      \"id\": 2,\n      \
             \"name\": \"batten-v9.9.9-aarch64-apple-darwin.tar.gz\",\n      \
             \"digest\": \"sha256:{ZEROS}\"\n    }}\n  ]\n}}\n"
        );
        fs::write(self.latest(), &payload).unwrap();
        fs::write(
            self.api.join(format!("repos/{REPO}/releases/tags/v9.9.9")),
            &payload,
        )
        .unwrap();
    }

    /// Where the API answers `releases/latest`.
    fn latest(&self) -> PathBuf {
        self.api.join(format!("repos/{REPO}/releases/latest"))
    }

    /// The manifest `BATTEN_VERSION_FROM_REF` reads, at `version`.
    fn manifest_at(&self, version: &str) {
        let contents = self.api.join(format!("repos/{REPO}/contents"));
        fs::create_dir_all(&contents).unwrap();
        fs::write(
            contents.join("Cargo.toml"),
            format!("version = \"{version}\"\n"),
        )
        .unwrap();
    }

    /// A `curl` stub that appends the config it is handed to a file and runs
    /// `answer` — returning the stub's directory and the file it records into.
    fn stub_curl(&self, answer: &str) -> (PathBuf, PathBuf) {
        let stub = self.dir.join("stub");
        fs::create_dir_all(&stub).unwrap();
        let seen = self.dir.join("curl-config");
        let body = format!("#!/bin/sh\ncat >>'{}'\n{answer}\n", seen.display());
        let curl = stub.join("curl");
        fs::write(&curl, body).unwrap();
        fs::set_permissions(&curl, fs::Permissions::from_mode(0o755)).unwrap();
        (stub, seen)
    }

    /// Run the committed installer with `args`, under the fixture environment plus
    /// `env`, with `first` (if any) ahead of the destination on `PATH`.
    ///
    /// The environment is CLEARED, then rebuilt: every credential and CA name is
    /// set empty so a leaked ambient one cannot change a verdict — this container
    /// sets both CA names, and a case declaring one of them used to read the
    /// ambient other and assert about the environment rather than the fixture.
    fn install(&self, args: &[&str], first: Option<&Path>, env: &[(&str, &str)]) -> Run {
        let inherited = std::env::var_os("PATH").unwrap_or_default();
        let path = std::env::join_paths(
            first
                .map(Path::to_path_buf)
                .into_iter()
                .chain(std::iter::once(self.dest.clone()))
                .chain(std::env::split_paths(&inherited)),
        )
        .expect("a PATH entry carries no separator");
        #[expect(
            clippy::disallowed_types,
            reason = "stays — CLOUD-843: the subject IS the committed install script, a program that must stay POSIX shell, so exercising it means running it; the retired suite made this same spawn"
        )]
        let mut command = std::process::Command::new("sh");
        command
            .arg(common::at_root("install.sh"))
            .args(args)
            .current_dir(&self.dir)
            .env_clear()
            .env("PATH", path)
            .env("HOME", &self.dir)
            .env("BATTEN_API", format!("file://{}", self.api.display()))
            .env("BATTEN_REPO", REPO)
            .env("BATTEN_TARGET", TARGET)
            .env("BATTEN_INSTALL_DIR", &self.dest)
            // One attempt: a case asserting a refusal must not pay the backoff.
            .env("BATTEN_RETRIES", "1")
            .env("BATTEN_GITHUB_TOKEN", "")
            .env("GH_TOKEN", "")
            .env("GITHUB_TOKEN", "")
            .env("GITHUB_PERSONAL_ACCESS_TOKEN", "")
            .env("CURL_CA_BUNDLE", "")
            .env("SSL_CERT_FILE", "");
        for (name, value) in env {
            command.env(name, value);
        }
        let output = command.output().expect("run install.sh");
        Run {
            code: output.status.code(),
            output: format!(
                "{}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            ),
        }
    }

    /// The installed binary's path in the default destination.
    fn installed(&self) -> PathBuf {
        self.dest.join("batten")
    }
}

/// Whether `path` is an executable file.
fn executable(path: &Path) -> bool {
    fs::metadata(path).is_ok_and(|meta| meta.is_file() && meta.permissions().mode() & 0o111 != 0)
}

/// What the installed fixture binary prints when run.
fn runs_as_fixture(path: &Path) -> String {
    #[expect(
        clippy::disallowed_types,
        reason = "stays — CLOUD-843: the proof an install landed the right bytes is running what it installed, as the retired suite did"
    )]
    let output = std::process::Command::new(path)
        .output()
        .expect("run the installed binary");
    String::from_utf8_lossy(&output.stdout)
        .trim_end()
        .to_owned()
}

/// The recorded curl config, or empty where curl was never reached.
fn seen(path: &Path) -> String {
    fs::read_to_string(path).unwrap_or_default()
}

// --- the pure query surface, which is what install-check compares -------------

#[test]
fn targets_lists_the_targets_a_posix_installer_can_serve() {
    let fixture = Fixture::new("targets");
    let run = fixture.install(&["--targets"], None, &[]);
    assert_eq!(run.code, Some(0), "{}", run.output);
    assert!(run.output.contains("x86_64-unknown-linux-musl"));
    assert!(run.output.contains("aarch64-apple-darwin"));
    // Windows ships a .zip for a platform with no POSIX shell.
    assert!(!run.output.contains("windows"));
}

#[test]
fn asset_name_is_name_v_version_target_with_a_per_target_extension() {
    let fixture = Fixture::new("asset-name");
    let run = fixture.install(
        &["--asset-name", "1.2.3", "x86_64-unknown-linux-musl"],
        None,
        &[],
    );
    assert_eq!(run.code, Some(0), "{}", run.output);
    assert_eq!(
        run.output.trim_end(),
        "batten-v1.2.3-x86_64-unknown-linux-musl.tar.gz"
    );
    let run = fixture.install(
        &["--asset-name", "1.2.3", "x86_64-pc-windows-gnu"],
        None,
        &[],
    );
    assert_eq!(run.code, Some(0), "{}", run.output);
    assert_eq!(
        run.output.trim_end(),
        "batten-v1.2.3-x86_64-pc-windows-gnu.zip"
    );
}

#[test]
fn the_query_flags_install_nothing() {
    let fixture = Fixture::new("query-installs-nothing");
    fixture.release_json(Some(fixture.digest.as_str()));
    let run = fixture.install(&["--targets"], None, &[]);
    assert_eq!(run.code, Some(0), "{}", run.output);
    assert!(!fixture.installed().exists());
}

// --- the install path ---------------------------------------------------------

#[test]
fn a_release_whose_digest_matches_installs_the_binary() {
    let fixture = Fixture::new("digest-matches");
    fixture.release_json(Some(fixture.digest.as_str()));
    let run = fixture.install(&[], None, &[]);
    assert_eq!(run.code, Some(0), "{}", run.output);
    let dest = fixture.installed();
    assert!(
        run.output
            .contains(&format!("installed={}", dest.display())),
        "{}",
        run.output
    );
    assert!(run.output.contains("version=v9.9.9"), "{}", run.output);
    assert!(run.output.contains("verified=sha256"), "{}", run.output);
    assert!(executable(&dest));
    assert_eq!(runs_as_fixture(&dest), "fixture-batten");
}

#[test]
fn batten_version_selects_a_tag_rather_than_the_latest_release() {
    let fixture = Fixture::new("version-tag");
    fixture.release_json(Some(fixture.digest.as_str()));
    fs::remove_file(fixture.latest()).unwrap();
    let run = fixture.install(&[], None, &[("BATTEN_VERSION", "v9.9.9")]);
    assert_eq!(run.code, Some(0), "{}", run.output);
    assert!(executable(&fixture.installed()));
}

#[test]
fn the_defect_a_digest_that_does_not_match_the_bytes_installs_nothing() {
    let fixture = Fixture::new("digest-mismatch");
    fixture.release_json(Some(ZEROS));
    let run = fixture.install(&[], None, &[]);
    assert_eq!(run.code, Some(1), "{}", run.output);
    assert!(run.output.contains("sha256 mismatch"), "{}", run.output);
    assert!(!fixture.installed().exists());
}

#[test]
fn the_defect_an_asset_reported_with_no_digest_is_refused_not_installed() {
    let fixture = Fixture::new("no-digest");
    fixture.release_json(None);
    let run = fixture.install(&[], None, &[]);
    assert_eq!(run.code, Some(1), "{}", run.output);
    assert!(run.output.contains("no sha256 digest"), "{}", run.output);
    assert!(!fixture.installed().exists());
}

#[test]
fn a_release_carrying_no_asset_for_this_target_is_exit_1_naming_the_asset() {
    let fixture = Fixture::new("no-asset");
    fixture.release_json(Some(fixture.digest.as_str()));
    let run = fixture.install(
        &[],
        None,
        &[("BATTEN_TARGET", "aarch64-unknown-linux-musl")],
    );
    assert_eq!(run.code, Some(1), "{}", run.output);
    assert!(
        run.output
            .contains("batten-v9.9.9-aarch64-unknown-linux-musl.tar.gz"),
        "{}",
        run.output
    );
    assert!(!fixture.installed().exists());
}

#[test]
fn a_target_no_release_leg_builds_is_refused_before_any_request() {
    let fixture = Fixture::new("unknown-target");
    fixture.release_json(Some(fixture.digest.as_str()));
    let run = fixture.install(&[], None, &[("BATTEN_TARGET", "sparc-unknown-none")]);
    assert_eq!(run.code, Some(1), "{}", run.output);
    assert!(
        run.output.contains("not one this script installs"),
        "{}",
        run.output
    );
}

#[test]
fn an_unreadable_release_is_exit_2_could_not_look() {
    let fixture = Fixture::new("unreadable");
    let run = fixture.install(&[], None, &[]);
    assert_eq!(run.code, Some(2), "{}", run.output);
    assert!(
        run.output.contains("cannot read the release list"),
        "{}",
        run.output
    );
    assert!(!fixture.installed().exists());
}

#[test]
fn a_payload_with_no_tag_name_is_exit_2_never_a_guessed_version() {
    let fixture = Fixture::new("no-tag-name");
    fs::write(fixture.latest(), "{ \"message\": \"Not Found\" }\n").unwrap();
    let run = fixture.install(&[], None, &[]);
    assert_eq!(run.code, Some(2), "{}", run.output);
    assert!(run.output.contains("no tag_name"), "{}", run.output);
}

#[test]
fn the_compact_payload_shape_parses_too() {
    let fixture = Fixture::new("compact");
    fixture.release_json(Some(fixture.digest.as_str()));
    let pretty = fs::read_to_string(fixture.latest()).unwrap();
    let mut compact = String::new();
    for ch in pretty.chars().filter(|ch| *ch != '\n') {
        if !(ch == ' ' && compact.ends_with(' ')) {
            compact.push(ch);
        }
    }
    fs::write(fixture.latest(), format!("{compact}\n")).unwrap();
    let run = fixture.install(&[], None, &[]);
    assert_eq!(run.code, Some(0), "{}", run.output);
    assert!(executable(&fixture.installed()));
}

#[test]
fn help_explains_the_surface_and_exits_0() {
    let fixture = Fixture::new("help");
    let run = fixture.install(&["--help"], None, &[]);
    assert_eq!(run.code, Some(0), "{}", run.output);
    assert!(run.output.contains("BATTEN_INSTALL_DIR"), "{}", run.output);
}

#[test]
fn the_defect_installing_off_path_is_a_refusal_not_a_warning() {
    // This printed to stderr and exited 0, which is the silent-absence case: a
    // hook registration naming `batten` bare resolves to nothing, and an
    // unreachable binary and an absent one produce identical, quiet results.
    let fixture = Fixture::new("off-path");
    fixture.release_json(Some(fixture.digest.as_str()));
    let off = fixture.dir.join("nowhere");
    let off_str = off.display().to_string();
    let run = fixture.install(&[], None, &[("BATTEN_INSTALL_DIR", off_str.as_str())]);
    assert_eq!(run.code, Some(1), "{}", run.output);
    assert!(run.output.contains("not on PATH"), "{}", run.output);
    assert!(run.output.contains(&off_str), "{}", run.output);
}

#[test]
fn the_off_path_refusal_has_an_opt_out_for_a_deliberate_destination() {
    let fixture = Fixture::new("off-path-allowed");
    fixture.release_json(Some(fixture.digest.as_str()));
    let off = fixture.dir.join("deliberate");
    let off_str = off.display().to_string();
    let run = fixture.install(
        &[],
        None,
        &[
            ("BATTEN_INSTALL_DIR", off_str.as_str()),
            ("BATTEN_ALLOW_OFF_PATH", "1"),
        ],
    );
    assert_eq!(run.code, Some(0), "{}", run.output);
    assert!(
        run.output.contains(&format!("installed={off_str}/batten")),
        "{}",
        run.output
    );
    assert!(executable(&off.join("batten")));
}

#[test]
fn a_declared_ca_bundle_reaches_curl() {
    // Asserted over the CONFIG curl receives, not over a transfer outcome: a
    // `file://` URL involves no TLS, so a bogus bundle would change nothing.
    let fixture = Fixture::new("ca-bundle");
    fixture.release_json(Some(fixture.digest.as_str()));
    let (stub, seen_at) = fixture.stub_curl("exit 1");
    let ca = fixture.dir.join("proxy-ca.pem");
    fs::write(&ca, "ca bytes\n").unwrap();
    let ca_str = ca.display().to_string();
    let run = fixture.install(&[], Some(&stub), &[("SSL_CERT_FILE", ca_str.as_str())]);
    assert_ne!(run.code, Some(0), "{}", run.output);
    assert!(
        seen(&seen_at).contains(&format!("cacert = \"{ca_str}\"")),
        "{}",
        seen(&seen_at)
    );
}

#[test]
fn curl_ca_bundle_outranks_ssl_cert_file_when_both_are_declared() {
    let fixture = Fixture::new("ca-precedence");
    fixture.release_json(Some(fixture.digest.as_str()));
    let (stub, seen_at) = fixture.stub_curl("exit 1");
    let first = fixture.dir.join("a.pem");
    let second = fixture.dir.join("b.pem");
    fs::write(&first, "a\n").unwrap();
    fs::write(&second, "b\n").unwrap();
    let first_str = first.display().to_string();
    let second_str = second.display().to_string();
    fixture.install(
        &[],
        Some(&stub),
        &[
            ("CURL_CA_BUNDLE", first_str.as_str()),
            ("SSL_CERT_FILE", second_str.as_str()),
        ],
    );
    let config = seen(&seen_at);
    assert!(config.contains("a.pem"), "{config}");
    assert!(!config.contains("b.pem"), "{config}");
}

#[test]
fn no_ca_declaration_means_no_cacert_line() {
    // The negative control. Emitting a cacert unconditionally would point curl at
    // a path that may not exist, breaking the ordinary case to serve the proxied
    // one.
    let fixture = Fixture::new("no-ca");
    fixture.release_json(Some(fixture.digest.as_str()));
    let (stub, seen_at) = fixture.stub_curl("exit 1");
    fixture.install(&[], Some(&stub), &[]);
    let config = seen(&seen_at);
    assert!(!config.is_empty(), "curl was never reached");
    assert!(!config.contains("cacert"), "{config}");
}

#[test]
fn the_retry_is_bounded_and_reports_rather_than_looping_forever() {
    let fixture = Fixture::new("bounded-retry");
    let absent = format!("file://{}", fixture.dir.join("absent").display());
    let run = fixture.install(
        &[],
        None,
        &[("BATTEN_API", absent.as_str()), ("BATTEN_RETRIES", "2")],
    );
    assert_eq!(run.code, Some(2), "{}", run.output);
    assert!(
        run.output.contains("cannot read the release"),
        "{}",
        run.output
    );
}

/// A stub curl that answers `403` from a certificate issued under `org`.
fn refused_by(org: &str) -> String {
    format!("printf '403\\nIssuer:CN = Refusing Proxy CA, O = {org}\\n'\nexit 22")
}

#[test]
fn a_proxy_refusal_is_retried_around_the_proxy_with_the_operators_own_credential() {
    // THE ARM THE OUTAGE NEEDED (CLOUD-1457). A container-BUILD host has no
    // session for the intercepting proxy to scope a credential to, so the proxy
    // answers with one of its own and returns 403. The second attempt has to
    // leave the proxy, and only an authority under the interceptor's declared
    // organisation earns that — the script's own default.
    let fixture = Fixture::new("proxy-bypass");
    let (stub, seen_at) = fixture.stub_curl(&refused_by("Anthropic"));
    let run = fixture.install(
        &[],
        Some(&stub),
        &[
            ("GH_TOKEN", "proxy-placeholder"),
            ("GITHUB_PERSONAL_ACCESS_TOKEN", "operator-pat"),
        ],
    );
    assert_ne!(run.code, Some(0), "{}", run.output);
    let config = seen(&seen_at);
    assert!(config.contains("noproxy = "), "{config}");
    assert!(config.contains("operator-pat"), "{config}");
}

#[test]
fn an_ordinary_failure_never_leaves_the_proxy() {
    // THE ANTI-VACUITY HALF. Without it the script could satisfy the case above
    // by bypassing on every failure. A connect failure reports no status.
    let fixture = Fixture::new("ordinary-failure");
    let (stub, seen_at) = fixture.stub_curl("printf 000\nexit 7");
    fixture.install(
        &[],
        Some(&stub),
        &[
            ("GH_TOKEN", "proxy-placeholder"),
            ("GITHUB_PERSONAL_ACCESS_TOKEN", "operator-pat"),
        ],
    );
    let config = seen(&seen_at);
    assert!(!config.is_empty(), "curl was never reached");
    assert!(!config.contains("noproxy = "), "{config}");
}

#[test]
fn a_refusal_from_an_authority_the_operator_chose_is_honoured_not_bypassed() {
    // THE DISCRIMINATING ARM. Same status, same credentials, same everything
    // except who signed the certificate: a CA the operator chose, so the script
    // must stay on the proxy.
    let fixture = Fixture::new("operator-proxy");
    let (stub, seen_at) = fixture.stub_curl(&refused_by("Acme"));
    let run = fixture.install(
        &[],
        Some(&stub),
        &[
            ("GH_TOKEN", "proxy-placeholder"),
            ("GITHUB_PERSONAL_ACCESS_TOKEN", "operator-pat"),
        ],
    );
    assert_ne!(run.code, Some(0), "{}", run.output);
    let config = seen(&seen_at);
    assert!(!config.is_empty(), "curl was never reached");
    assert!(!config.contains("noproxy = "), "{config}");
    assert!(!config.contains("operator-pat"), "{config}");
}

#[test]
fn the_fallback_can_be_switched_off_entirely() {
    // An empty `BATTEN_INTERCEPT_ORG` means never leave the proxy, whoever signed
    // the refusal. Same input as the bypass case above.
    let fixture = Fixture::new("fallback-off");
    let (stub, seen_at) = fixture.stub_curl(&refused_by("Anthropic"));
    fixture.install(
        &[],
        Some(&stub),
        &[
            ("BATTEN_INTERCEPT_ORG", ""),
            ("GH_TOKEN", "proxy-placeholder"),
            ("GITHUB_PERSONAL_ACCESS_TOKEN", "operator-pat"),
        ],
    );
    let config = seen(&seen_at);
    assert!(!config.is_empty(), "curl was never reached");
    assert!(!config.contains("noproxy = "), "{config}");
}

#[test]
fn the_ordinary_token_order_still_wins_on_the_first_attempt() {
    // On a machine with no intercepting proxy, GH_TOKEN IS the operator's
    // credential and must win. The PAT is a fallback tried once the first has
    // been REFUSED, never a replacement.
    let fixture = Fixture::new("token-order");
    let (stub, seen_at) = fixture.stub_curl("printf 403\nexit 22");
    fixture.install(
        &[],
        Some(&stub),
        &[
            ("GH_TOKEN", "proxy-placeholder"),
            ("GITHUB_PERSONAL_ACCESS_TOKEN", "operator-pat"),
        ],
    );
    let first: Vec<String> = seen(&seen_at).lines().take(20).map(str::to_owned).collect();
    assert!(
        first.iter().any(|line| line.contains("proxy-placeholder")),
        "{first:?}"
    );
}

// --- BATTEN_VERSION_FROM_REF: the pin trunk decides (CLOUD-420) ----------------

#[test]
fn the_version_comes_from_the_refs_manifest_when_one_is_named() {
    let fixture = Fixture::new("from-ref");
    fixture.release_json(Some(fixture.digest.as_str()));
    fixture.manifest_at("9.9.9");
    let run = fixture.install(&[], None, &[("BATTEN_VERSION_FROM_REF", "main")]);
    assert_eq!(run.code, Some(0), "{}", run.output);
    assert_eq!(runs_as_fixture(&fixture.installed()), "fixture-batten");
    assert!(
        !run.output.contains("has no published release yet"),
        "{}",
        run.output
    );
}

#[test]
fn a_ref_naming_an_unreleased_version_falls_back_to_the_latest_release() {
    // THE ARM THE CI GUARD LIVES ON. release-plz bumps the manifest BEFORE
    // publishing the tag, and the step-0 guard swallows a failure by design, so a
    // hard stop here would be silent.
    let fixture = Fixture::new("from-ref-unreleased");
    fixture.release_json(Some(fixture.digest.as_str()));
    fixture.manifest_at("7.7.7");
    let run = fixture.install(&[], None, &[("BATTEN_VERSION_FROM_REF", "main")]);
    assert_eq!(run.code, Some(0), "{}", run.output);
    assert!(
        run.output.contains("v7.7.7 has no published release yet"),
        "{}",
        run.output
    );
    assert_eq!(runs_as_fixture(&fixture.installed()), "fixture-batten");
}

#[test]
fn an_explicitly_named_version_never_falls_back() {
    // THE ANTI-VACUITY MIRROR: a caller who named a version wants that version or
    // an error, so only a ref-derived pin may retry.
    let fixture = Fixture::new("explicit-version");
    fixture.release_json(Some(fixture.digest.as_str()));
    fixture.manifest_at("9.9.9");
    let run = fixture.install(
        &[],
        None,
        &[
            ("BATTEN_VERSION", "v7.7.7"),
            ("BATTEN_VERSION_FROM_REF", "main"),
        ],
    );
    assert_ne!(run.code, Some(0), "{}", run.output);
    assert!(
        !run.output.contains("has no published release yet"),
        "{}",
        run.output
    );
    assert!(!fixture.installed().exists());
}
