//! End-to-end tests over the compiled binary for `[[provision]]` (CLOUD-90).
//!
//! Its own suite by the per-surface convention: `tests/cli.rs` is the exit-code
//! and output-contract suite, and other work appends to it.
//!
//! Every fixture is hermetic. The `file://` scheme exists in the fetcher
//! precisely so the apply mechanics can be exercised without a network, and the
//! cases that must reach the HTTPS path stand up their own loopback listener —
//! one that accepts and never answers, for the timeout bound, and one serving a
//! certificate signed by a CA the case generates, for the host-trust clause.
//! Nothing leaves the machine, and section (f) says why each shape is the one
//! its property needs.

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

// --- (f) the https fetch is in process, and it is bounded (CLOUD-745) -----------

// THE `openssl s_server` FIXTURE KEEPS ITS CLAUSE AND CHANGES ITS VARIABLE, and
// the reason is worth reading, because this file briefly said the opposite.
//
// It asserted that `CURL_CA_BUNDLE` reached the fetch — the proxy-CA clause,
// proved rather than described. Retiring it with `curl` looked right for about
// an hour, on the argument that vendored roots make a loopback CA correctly
// untrustable so the case could only ever produce its failing arm.
//
// That argument was wrong, and `batten check` is what said so: it could not
// provision at all, because this container reaches GitHub through a proxy that
// re-terminates TLS with its own CA — the exact shape this fixture reproduces.
// The clause was never `curl`'s; it is the acceptance's, and `fetch.rs` honours
// `SSL_CERT_FILE` because of it. So the variable is generic now and the property
// under test is unchanged.

/// A server that accepts the connection and then says nothing.
///
/// This is the shape CLOUD-745's §7 names, and it is reachable without a
/// certificate: the TCP connect SUCCEEDS, so the connect bound does not fire,
/// and the TLS handshake then blocks forever waiting for a `ServerHello`. Only
/// the **total** bound can end it — which is the bound the `curl` invocation
/// this replaced did not have at all (`--max-time` and `--connect-timeout` were
/// both absent, so `provision apply` hung indefinitely).
///
/// The listener is moved into a detached thread that accepts and holds. It never
/// writes, and it dies with the process.
#[test]
fn a_server_that_accepts_and_never_answers_times_out_rather_than_hanging() {
    use std::net::TcpListener;

    let env = Env::new("provision-hung");
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        // Hold every accepted connection open, writing nothing. Dropping the
        // stream would send a FIN and the client would fail fast on a closed
        // connection — which is a different answer, and not the one under test.
        let mut held = Vec::new();
        while let Ok((stream, _)) = listener.accept() {
            held.push(stream);
        }
    });

    env.config(&manifest(
        &format!("https://127.0.0.1:{port}/payload.bin"),
        &digest(BINARY),
    ));
    let before = env.cache_contents();

    // The bound is shrunk for the fixture rather than the case waiting out the
    // shipped minute. `BATTEN_FETCH_TIMEOUT_MS` moves how long a wait waits and
    // nothing else — the shortest value is the strictest, so it cannot admit
    // anything, which is what separates it from a bypass.
    let output = batten()
        .state_home(&env.home)
        .args(["provision", "apply"])
        .current_dir(&env.repo)
        .env("BATTEN_FETCH_TIMEOUT_MS", "750")
        .output()
        .expect("run batten");

    assert_eq!(
        output.status.code(),
        Some(3),
        "a fetch that could not complete is exit 3, never a verdict about the pin: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        env.cache_contents(),
        before,
        "a timed-out fetch writes nothing — buffer, verify, then write"
    );
}

/// The same listener, judged the other way round.
///
/// Without this, the case above is satisfied by a build that cannot fetch at
/// all: a `provision apply` that errored instantly for any reason would produce
/// the identical exit code and the identical untouched cache. What discriminates
/// is that the process *waited*, and then stopped.
#[test]
fn the_timeout_is_what_ends_it_rather_than_an_instant_failure() {
    use std::net::TcpListener;
    use std::time::Instant;

    let env = Env::new("provision-hung-clock");
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        let mut held = Vec::new();
        while let Ok((stream, _)) = listener.accept() {
            held.push(stream);
        }
    });

    env.config(&manifest(
        &format!("https://127.0.0.1:{port}/payload.bin"),
        &digest(BINARY),
    ));

    let bound = std::time::Duration::from_millis(1_500);
    let started = Instant::now();
    let output = batten()
        .state_home(&env.home)
        .args(["provision", "apply"])
        .current_dir(&env.repo)
        .env("BATTEN_FETCH_TIMEOUT_MS", "1500")
        .output()
        .expect("run batten");
    let waited = started.elapsed();

    assert_eq!(output.status.code(), Some(3));
    // A LOWER bound only, and deliberately no upper one. The process start is
    // included here and a loaded runner makes the upper half a flake, so an
    // assertion on it would discriminate nothing and fail sometimes; the claim
    // is that the wait HAPPENED, which is the half a fail-fast build breaks.
    assert!(
        waited >= bound,
        "the fetch must have waited out its bound, not failed instantly ({waited:?})"
    );
}

/// A local HTTPS listener with its own CA, and the fetch that must trust it.
///
/// **The acceptance's proxy-CA clause, and the case that would have caught the
/// defect this row shipped and then fixed.** A re-terminating proxy presents a
/// certificate signed by a CA only the host knows about, so the property is that
/// **host CA configuration reaches the fetch**. The fixture reproduces exactly
/// that shape: a certificate no public root signs, trusted only because the host
/// was told to trust it.
///
/// The CA is a real one rather than the self-signed certificate the `curl` era
/// used. A verifier that must chain to a root will not accept an end-entity
/// certificate as its own issuer, so the old fixture's shape would fail the
/// trusted arm for a reason that has nothing to do with the property.
///
/// Linux-only, because it spawns `openssl` for the key material. The other
/// targets are covered by `cross-check` and `darwin-link`, which compile and
/// link this same call.
///
/// Hermetic: loopback only — which [`batten::fetch`] reaches directly whatever
/// the ambient proxy variables say — its own key material, and a listener it
/// starts and stops. Nothing leaves the machine.
/// ## Why the 404 half is NOT here, measured rather than assumed
///
/// The obvious next case — a missing path over this same listener must exit `3`
/// where a tampered artifact exits `2` — cannot be written against this fixture,
/// and finding that out cost a run. `openssl s_server -WWW` answers
/// **`HTTP/1.0 200 ok`** for a file it cannot open, with the `fopen` error as
/// the body:
///
/// ```text
/// HTTP/1.0 200 ok
/// Content-type: text/plain
///
/// Error opening 'absent.bin' mode='r'
/// ```
///
/// So the arm reports a checksum MISMATCH — exit 2, correctly, because a 200
/// carrying the wrong bytes is exactly that. The fixture cannot express the
/// distinction, and the `curl`-era one could not either.
///
/// That pair lives in `provision.rs`'s own `body_of` cases, where the response
/// is a VALUE and a status can therefore be chosen. Do not re-add it here.
/// Write `ca.pem`/`ca.key` and a `cert.pem`/`key.pem` the CA signed, into `tls`.
///
/// A real CA rather than a self-signed leaf, which is the difference from the
/// `curl`-era fixture: a verifier that must chain to a root will not accept an
/// end-entity certificate as its own issuer, so the old shape would fail the
/// trusted arm for a reason that has nothing to do with the property under test.
#[cfg(target_os = "linux")]
fn mint_ca_and_server_certificate(tls: &Path) {
    #[expect(
        clippy::disallowed_types,
        reason = "stays, and test-only: the import the spawn below needs, annotated at both sites the way every other openssl row in this file is"
    )]
    use std::process::Command;

    let at = |name: &str| tls.join(name).to_str().unwrap().to_owned();
    let openssl = |args: &[&str]| {
        #[expect(
            clippy::disallowed_types,
            reason = "stays, and test-only: the fixture's key material has to be one nothing public signs, and `openssl` is what generates it"
        )]
        let run = Command::new("openssl")
            .args(args)
            .current_dir(tls)
            .output()
            .expect("openssl is required for the TLS fixture");
        assert!(
            run.status.success(),
            "openssl {:?}: {}",
            args.first(),
            String::from_utf8_lossy(&run.stderr)
        );
    };

    openssl(&[
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-keyout",
        &at("ca.key"),
        "-out",
        &at("ca.pem"),
        "-days",
        "1",
        "-subj",
        "/CN=Batten Fixture CA",
        "-addext",
        "basicConstraints=critical,CA:TRUE",
        "-addext",
        "keyUsage=critical,keyCertSign,cRLSign",
    ]);
    openssl(&[
        "req",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-keyout",
        &at("key.pem"),
        "-out",
        &at("csr.pem"),
        "-subj",
        "/CN=localhost",
    ]);
    // The SAN is what the verifier matches the URL's host against, so a
    // certificate without it fails the trusted arm however well it chains.
    fs::write(
        tls.join("ext.cnf"),
        "subjectAltName=DNS:localhost,IP:127.0.0.1\nbasicConstraints=critical,CA:FALSE\n\
         extendedKeyUsage=serverAuth\n",
    )
    .unwrap();
    openssl(&[
        "x509",
        "-req",
        "-in",
        &at("csr.pem"),
        "-CA",
        &at("ca.pem"),
        "-CAkey",
        &at("ca.key"),
        "-CAcreateserial",
        "-out",
        &at("cert.pem"),
        "-days",
        "1",
        "-extfile",
        &at("ext.cnf"),
    ]);
}

#[cfg(target_os = "linux")]
#[test]
fn host_ca_configuration_reaches_the_fetch() {
    use std::net::TcpListener;
    #[expect(
        clippy::disallowed_types,
        reason = "stays, and test-only: a re-terminating proxy's CA is only reproducible against a real TLS listener, and `openssl s_server` is what serves one on loopback"
    )]
    use std::process::{Command, Stdio};

    let env = Env::new("provision-https");
    let tls = env.artifacts.join("tls");
    fs::create_dir_all(&tls).unwrap();
    let at = |name: &str| tls.join(name).to_str().unwrap().to_owned();

    mint_ca_and_server_certificate(&tls);
    fs::write(tls.join("payload.bin"), BINARY).unwrap();

    // Bind to find a free port, then release it for the listener. A fixed port
    // would collide with a parallel test run.
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    #[expect(
        clippy::disallowed_types,
        reason = "stays, and test-only: a loopback TLS listener the case starts and stops, so nothing leaves the machine"
    )]
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

    // The CA is passed as an environment value rather than a flag, because that
    // is the surface under test: `fetch.rs` reads `SSL_CERT_FILE`, and a case
    // that reached it any other way would not be exercising what an operator
    // behind a proxy actually sets. An absent value is spelled as the empty
    // string, which `fetch.rs` treats as unset — so both arms take one path.
    // Takes its own `Env`, because `apply` short-circuits on a FRESH entry: a
    // second arm reusing the first's cache never reaches the network at all and
    // reports exit 0 without fetching. That is the engine working, and it is
    // also how a case can assert a network property while making no request —
    // measured here, on the 404 arm, before this took a parameter.
    let apply = |env: &Env, url: &str, ca: &str| {
        env.config(&manifest(url, &digest(BINARY)));
        batten()
            .state_home(&env.home)
            .env("SSL_CERT_FILE", ca)
            .args(["provision", "apply"])
            .current_dir(&env.repo)
            .output()
            .expect("run batten")
    };

    let url = format!("https://localhost:{port}/payload.bin");
    // Without the CA the fetch must fail — otherwise the success below would
    // prove nothing about trust, only that something answered.
    let untrusted = apply(&env, &url, "");
    let trusted = apply(&env, &url, &at("ca.pem"));

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
