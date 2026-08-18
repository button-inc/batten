//! End-to-end tests over the compiled binary for `[[provision]]` (CLOUD-90).
//!
//! Its own suite by the per-surface convention: `tests/cli.rs` is the exit-code
//! and output-contract suite, and other work appends to it.
//!
//! Every fixture is hermetic. The `file://` scheme exists in the fetcher
//! precisely so the apply mechanics can be exercised without a network, and the
//! one test that must prove a *TLS* property stands up its own listener on
//! loopback with its own CA.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Output;

use common::{Fixture, StateHome, batten, git_in, scratch};

/// The SHA-256 of `bytes` as lowercase hex, computed the way the manifest pins
/// it — through the binary's own helper, so a fixture cannot pin a digest the
/// engine would never produce.
fn digest(bytes: &[u8]) -> String {
    batten::provision::digest(bytes)
}

/// A repository plus an isolated `HOME`/`XDG_DATA_HOME`, so the out-of-tree
/// cache lands somewhere this test owns rather than in the developer's real
/// state directory.
struct Env {
    repo: PathBuf,
    home: PathBuf,
    artifacts: PathBuf,
}

impl Env {
    fn new(name: &str) -> Self {
        let root = scratch(name);
        let repo = Fixture::at(root.join("repo"))
            .file("README.md", "base\n")
            .build();
        git_in(&repo, &["init", "-q"]);
        git_in(&repo, &["add", "-A"]);
        git_in(&repo, &["commit", "-q", "-m", "base"]);
        let artifacts = root.join("artifacts");
        fs::create_dir_all(&artifacts).unwrap();
        Env {
            repo,
            home: root.join("home"),
            artifacts,
        }
    }

    /// Write an artifact and return its `file://` URL and digest.
    fn artifact(&self, name: &str, bytes: &[u8]) -> (String, String) {
        let path = self.artifacts.join(name);
        fs::write(&path, bytes).unwrap();
        (format!("file://{}", path.display()), digest(bytes))
    }

    fn config(&self, contents: &str) {
        fs::write(self.repo.join("batten.toml"), contents).unwrap();
    }

    fn run(&self, args: &[&str]) -> Output {
        batten()
            .state_home(&self.home)
            .args(args)
            .current_dir(&self.repo)
            .output()
            .expect("run batten")
    }

    /// The out-of-tree cache directory, which must never be inside the repo.
    fn cache(&self) -> PathBuf {
        self.home.join("data").join("batten")
    }

    /// This repository's own directory under the cache.
    ///
    /// The segment comes from [`batten::state::derive_repo_name`] rather than
    /// being spelled `repo` here: CLOUD-296 gave it a per-checkout digest, so a
    /// fixture holding its own copy of the old rule points at a directory
    /// nothing writes. Canonicalized because the binary's root comes from
    /// `git rev-parse --path-format=absolute`, which resolves symlinks.
    fn state_dir(&self) -> PathBuf {
        let canonical = self
            .repo
            .canonicalize()
            .unwrap_or_else(|_| self.repo.clone());
        let segment =
            batten::state::derive_repo_name(&canonical).expect("derive the state segment");
        self.cache().join(segment)
    }

    /// Every file under the cache, sorted — the comparand for "cache unchanged".
    fn cache_contents(&self) -> Vec<(String, Vec<u8>)> {
        let mut out = Vec::new();
        collect(&self.cache(), &self.cache(), &mut out);
        out.sort();
        out
    }
}

fn collect(root: &Path, dir: &Path, out: &mut Vec<(String, Vec<u8>)>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect(root, &path, out);
        } else if let Ok(rel) = path.strip_prefix(root) {
            out.push((
                rel.display().to_string(),
                fs::read(&path).unwrap_or_default(),
            ));
        }
    }
}

/// A one-entry manifest over `url`/`sha`.
fn manifest(url: &str, sha: &str) -> String {
    // A TOML *literal* string for the url, because it carries a filesystem path:
    // `file://D:\a\batten\...` in a basic string reads `\a` as a control
    // character and rejects `\U`, so nine of this suite's ten cases died on
    // their own fixture rather than on provisioning. Literal strings process no
    // escapes, which is what a path wants — the rule
    // `every_path_valued_toml_key_uses_a_literal_string` now holds every site.
    format!(
        "version = 1\n\n[[provision]]\nname = \"demo\"\nversion = \"1.2.3\"\nurl = '{url}'\n\
         sha256 = \"{sha}\"\nbinary = \"demo\"\n"
    )
}

const BINARY: &[u8] = b"#!/bin/sh\necho demo\n";

// --- (a) an empty cache is stale ----------------------------------------------

#[test]
fn a_manifest_over_an_empty_cache_is_stale_and_names_the_entry() {
    let env = Env::new("provision-stale");
    let (url, sha) = env.artifact("demo", BINARY);
    env.config(&manifest(&url, &sha));

    let output = env.run(&["provision", "status"]);
    assert_eq!(output.status.code(), Some(2), "stale is a policy verdict");
    let text = String::from_utf8_lossy(&output.stdout).into_owned();
    assert!(
        text.contains("demo 1.2.3 missing"),
        "the report names the entry, its pinned version, and the verdict: {text:?}"
    );
    // Pointer-only: a name and a version, never the URL's response and never a
    // byte of the artifact.
    assert!(
        !text.contains("echo demo"),
        "never artifact bytes: {text:?}"
    );
}

// --- (b) apply populates the cache, out of tree --------------------------------

#[test]
fn apply_installs_out_of_tree_and_leaves_the_repository_untouched() {
    let env = Env::new("provision-apply");
    let (url, sha) = env.artifact("demo", BINARY);
    env.config(&manifest(&url, &sha));

    let before = git_in(&env.repo, &["status", "--porcelain"]);
    let output = env.run(&["provision", "apply"]);
    assert_eq!(
        output.status.code(),
        Some(0),
        "{:?}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Installed where `state.rs` resolves, which is outside the repository by
    // construction — the acceptance's "never committed" as a property rather
    // than a promise.
    let installed = env.state_dir().join("provision/demo/1.2.3/bin/demo");
    assert!(
        installed.is_file(),
        "the binary is cached at the version-encoded path"
    );
    assert_eq!(fs::read(&installed).unwrap(), BINARY);
    assert_eq!(
        git_in(&env.repo, &["status", "--porcelain"]),
        before,
        "provisioning must not touch the repository tree"
    );

    // And the pair closes: what apply wrote, status now reads as fresh.
    let status = env.run(&["provision", "status"]);
    assert_eq!(status.status.code(), Some(0));
    assert_eq!(
        String::from_utf8_lossy(&status.stdout),
        "",
        "all fresh prints nothing"
    );
}

// --- (c) a wrong checksum installs nothing -------------------------------------

#[test]
fn a_checksum_mismatch_exits_2_with_nothing_installed() {
    let env = Env::new("provision-mismatch");
    let (url, _) = env.artifact("demo", BINARY);
    // A pin for different bytes entirely: the artifact is not what was promised.
    env.config(&manifest(&url, &digest(b"some other artifact")));
    let before = env.cache_contents();

    let output = env.run(&["provision", "apply"]);
    assert_eq!(
        output.status.code(),
        Some(2),
        "a bad artifact is a verdict about the pin, not a failure of Batten's"
    );
    assert_eq!(env.cache_contents(), before, "nothing may be installed");

    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    assert!(stderr.contains("nothing was installed"), "{stderr:?}");
    assert!(
        !stderr.contains("echo demo"),
        "the mismatched artifact is the last thing to echo: {stderr:?}"
    );
}

// --- (d) a preview writes nothing ----------------------------------------------

#[test]
fn dry_run_previews_and_writes_nothing() {
    let env = Env::new("provision-dry-run");
    let (url, sha) = env.artifact("demo", BINARY);
    env.config(&manifest(&url, &sha));
    let before = env.cache_contents();

    let output = env.run(&["provision", "apply", "--dry-run"]);
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(env.cache_contents(), before, "a preview writes nothing");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("would install"),
        "a preview says what it would do"
    );
    // And it really was a preview: the entry is still stale afterwards.
    assert_eq!(env.run(&["provision", "status"]).status.code(), Some(2));
}

// --- (e) an unknown manifest key is a hard error --------------------------------

#[test]
fn an_unknown_manifest_key_is_exit_1() {
    let env = Env::new("provision-unknown-key");
    let (url, sha) = env.artifact("demo", BINARY);
    env.config(&format!("{}bogus = true\n", manifest(&url, &sha)));

    let output = env.run(&["provision", "status"]);
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("bogus"));
}

#[test]
fn a_pin_that_could_never_match_is_refused_at_load() {
    // Refused here rather than at fetch time, where the mismatch would blame the
    // artifact for a typo in the config.
    let env = Env::new("provision-bad-pin");
    let (url, _) = env.artifact("demo", BINARY);
    env.config(&manifest(&url, "not-a-sha"));

    let output = env.run(&["provision", "status"]);
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("64 hex"));
}

// --- (g) an unreachable URL is exit 3, not a verdict ----------------------------

#[test]
fn an_unreachable_url_is_exit_3_and_leaves_the_cache_alone() {
    // Distinct from a mismatch on purpose: exit 2 says "I fetched it and it is
    // not what you pinned"; this says "I could not complete", which is a claim
    // Batten never made. A harness reads 3 as fail-loud-do-not-block.
    let env = Env::new("provision-unreachable");
    let missing = env.artifacts.join("absent");
    env.config(&manifest(
        &format!("file://{}", missing.display()),
        &digest(BINARY),
    ));
    let before = env.cache_contents();

    let output = env.run(&["provision", "apply"]);
    assert_eq!(output.status.code(), Some(3));
    assert_eq!(env.cache_contents(), before, "the cache is unchanged");
}

// --- unpacking ------------------------------------------------------------------

#[test]
fn a_tar_gz_artifact_yields_the_named_binary_from_a_nested_path() {
    // Matching on the archive path's *file name* is what lets a release tarball
    // nest its binary under a versioned directory without the manifest restating
    // that directory — which would pin the version in two places.
    let env = Env::new("provision-targz");
    let tarball = tar_gz(&[
        ("demo-1.2.3/bin/demo", BINARY),
        ("demo-1.2.3/README", b"docs"),
    ]);
    let (url, sha) = env.artifact("demo.tar.gz", &tarball);
    env.config(&format!("{}unpack = \"tar_gz\"\n", manifest(&url, &sha)));

    let output = env.run(&["provision", "apply"]);
    assert_eq!(
        output.status.code(),
        Some(0),
        "{:?}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        fs::read(env.state_dir().join("provision/demo/1.2.3/bin/demo")).unwrap(),
        BINARY
    );
}

/// Build a gzipped tarball in memory from `(path, bytes)` pairs.
fn tar_gz(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut builder = tar::Builder::new(Vec::new());
    for (path, bytes) in entries {
        let mut header = tar::Header::new_gnu();
        header.set_size(bytes.len() as u64);
        header.set_mode(0o755);
        header.set_cksum();
        builder.append_data(&mut header, path, *bytes).unwrap();
    }
    let tar = builder.into_inner().unwrap();
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    std::io::Write::write_all(&mut encoder, &tar).unwrap();
    encoder.finish().unwrap()
}

// --- byte-stability -------------------------------------------------------------

#[test]
fn the_status_document_is_byte_stable_across_runs() {
    let env = Env::new("provision-stable");
    let (url, sha) = env.artifact("demo", BINARY);
    env.config(&manifest(&url, &sha));

    let first = env.run(&["provision", "status", "--json"]);
    let second = env.run(&["provision", "status", "--json"]);
    assert_eq!(first.stdout, second.stdout);
    // The data channel emits unconditionally, including when nothing is stale.
    env.run(&["provision", "apply"]);
    let fresh = env.run(&["provision", "status", "--json"]);
    assert_eq!(fresh.status.code(), Some(0));
    assert!(
        !fresh.stdout.is_empty(),
        "a clean run still emits its document"
    );
}

#[test]
fn a_repository_that_provisions_nothing_is_not_an_error() {
    // Unlike `policy budget`'s absent budget: zero entries is a complete and
    // honest answer — this repository provisions nothing — where a budget verb
    // with no budget would be claiming to have measured something it did not.
    let env = Env::new("provision-empty");
    env.config("version = 1\n");
    let output = env.run(&["provision", "status"]);
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(String::from_utf8_lossy(&output.stdout), "");
}

// --- (f) the host's TLS stack and CA configuration are honoured -----------------

/// A local HTTPS listener with its own CA, and the fetch that must trust it.
///
/// This is the acceptance's proxy-CA clause, proved rather than asserted: a
/// re-terminating proxy presents a certificate signed by a CA only the host
/// knows about, so the property under test is that **host CA configuration
/// reaches the fetch**. The fixture reproduces exactly that shape — a
/// certificate no public root signs, trusted only because the host was told to
/// trust it.
///
/// Linux-only, and stated rather than hidden: `CURL_CA_BUNDLE` is the trust
/// surface of a curl linked against OpenSSL. A curl built on Secure Transport or
/// Schannel takes its trust from the OS store instead, so the same assertion
/// there would be testing a different mechanism under the same name. The other
/// targets are covered by `cross-check` and `darwin-link`, which compile and
/// link this same call.
///
/// Hermetic: loopback only, its own key material, and a listener it starts and
/// stops. Nothing leaves the machine.
#[cfg(target_os = "linux")]
#[test]
fn an_https_fetch_honours_the_hosts_ca_configuration() {
    use std::net::TcpListener;
    use std::process::{Command, Stdio};

    let env = Env::new("provision-https");
    let tls = env.artifacts.join("tls");
    fs::create_dir_all(&tls).unwrap();

    // A self-signed certificate stands in for the proxy's CA: nothing public
    // signs it, so the fetch can only succeed by reading the host's own trust
    // configuration.
    let openssl = Command::new("openssl")
        .args([
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            tls.join("key.pem").to_str().unwrap(),
            "-out",
            tls.join("cert.pem").to_str().unwrap(),
            "-days",
            "1",
            "-subj",
            "/CN=localhost",
            "-addext",
            "subjectAltName=DNS:localhost,IP:127.0.0.1",
        ])
        .output()
        .expect("openssl is required for the TLS fixture; it is what curl links against");
    assert!(openssl.status.success(), "generate the fixture certificate");

    fs::write(tls.join("payload.bin"), BINARY).unwrap();

    // Bind to find a free port, then release it for the listener. A fixed port
    // would collide with a parallel test run.
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let mut server = Command::new("openssl")
        .args([
            "s_server",
            "-accept",
            &port.to_string(),
            "-cert",
            "cert.pem",
            "-key",
            "key.pem",
            "-WWW",
            "-quiet",
        ])
        .current_dir(&tls)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("start the local TLS listener");

    // Wait for the listener rather than sleeping a guessed interval.
    let mut ready = false;
    for _ in 0..100 {
        if TcpListener::bind(("127.0.0.1", port)).is_err() {
            ready = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    assert!(ready, "the TLS listener never came up");

    env.config(&manifest(
        &format!("https://localhost:{port}/payload.bin"),
        &digest(BINARY),
    ));

    // Without the CA the fetch must fail — otherwise the success below would
    // prove nothing about trust, only that something answered.
    let untrusted = env.run(&["provision", "apply"]);
    let trusted = batten()
        .state_home(&env.home)
        .args(["provision", "apply"])
        .current_dir(&env.repo)
        .env("CURL_CA_BUNDLE", tls.join("cert.pem"))
        .output()
        .expect("run batten");

    let _ = server.kill();
    let _ = server.wait();

    assert_eq!(
        untrusted.status.code(),
        Some(3),
        "an untrusted certificate must fail the fetch, not be waved through"
    );
    assert_eq!(
        trusted.status.code(),
        Some(0),
        "host CA configuration must reach the fetch: {:?}",
        String::from_utf8_lossy(&trusted.stderr)
    );
    assert_eq!(
        fs::read(env.state_dir().join("provision/demo/1.2.3/bin/demo")).unwrap(),
        BINARY,
        "the artifact fetched over https is what was installed"
    );
}
