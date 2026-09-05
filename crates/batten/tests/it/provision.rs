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

use crate::common;

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

/// CLOUD-970's no-regression case, and the one that fails if the indirection
/// changes what already works.
///
/// Every committed row omits `backend`, so `Backend::Native` is what `#[serde(
/// default)]` supplies — and this asserts the row still resolves through the same
/// fetch-verify-unpack-place path with byte-identical behaviour. An `expand →
/// migrate → contract` change needs no migrate step exactly when the default IS
/// the old meaning, and this is the assertion that says so rather than the
/// comment claiming it.
#[test]
fn a_row_naming_the_native_backend_behaves_exactly_as_one_naming_none() {
    let implicit = Env::new("provision-backend-implicit");
    let (url, sha) = implicit.artifact("demo", BINARY);
    implicit.config(&manifest(&url, &sha));
    let without = implicit.run(&["provision", "status"]);

    let explicit = Env::new("provision-backend-explicit");
    let (url, sha) = explicit.artifact("demo", BINARY);
    explicit.config(
        &manifest(&url, &sha).replace("name = \"demo\"", "name = \"demo\"\nbackend = \"native\""),
    );
    let with = explicit.run(&["provision", "status"]);

    assert_eq!(
        without.status.code(),
        with.status.code(),
        "naming the default backend cannot change the verdict"
    );
    assert_eq!(
        String::from_utf8_lossy(&without.stdout),
        String::from_utf8_lossy(&with.stdout),
        "nor a byte of the report (§6)"
    );
}

/// An unknown backend is a named config error, never a silent skip.
///
/// The direction matters more here than the exit code: a row that resolved to
/// nothing would provision nothing and say nothing, which is the shape
/// `.claude/rules/policy-modules.md` calls a dead gate — byte-identical to a
/// clean run on the decision surface.
#[test]
fn an_unknown_backend_is_refused_at_load_and_named() {
    let env = Env::new("provision-backend-unknown");
    let (url, sha) = env.artifact("demo", BINARY);
    env.config(
        &manifest(&url, &sha).replace("name = \"demo\"", "name = \"demo\"\nbackend = \"nix\""),
    );

    let output = env.run(&["provision", "status"]);
    assert_eq!(
        output.status.code(),
        Some(1),
        "a config fault, not a verdict"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("nix"),
        "the refusal names the backend it could not resolve: {stderr:?}"
    );
    assert!(
        stderr.contains("native"),
        "and what it could have been: {stderr:?}"
    );
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
        #[expect(
            clippy::disallowed_methods,
            reason = "the interval of the poll the comment above names: the exit condition is \
                      `TcpListener::bind` failing because the listener took the `port`, and the \
                      100-iteration bound is what turns a listener that never came up into a \
                      failed assertion rather than a hang (CLOUD-1177)"
        )]
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

// ---------------------------------------------------------------------------
// (g) `[[provision.env]]` and the launcher (CLOUD-1455).
//
// The measurement behind this section: a task runner's own `[env]` is applied to
// what it SPAWNS, never to its own resolver, so a pinned tool the runner fetches
// through a proxy 403s no matter what the manifest says. The environment has to
// be supplied by whatever LAUNCHES the runner, which is what a launcher is.
//
// The installed "binary" here is a copy of `env(1)`, which prints the
// environment it was given and nothing else. That is the whole reason it is the
// fixture: asserting on what the CHILD saw is the only way to catch a launcher
// that writes a plausible file and passes nothing on, and it needs no shell.

/// Where this host keeps `env(1)`, or `None` if the fixture cannot run here.
#[cfg(unix)]
fn env_binary() -> Option<PathBuf> {
    ["/usr/bin/env", "/bin/env"]
        .into_iter()
        .map(PathBuf::from)
        .find(|path| path.is_file())
}

/// A manifest whose one entry links, and optionally declares an environment.
#[cfg(unix)]
fn linking_manifest(url: &str, sha: &str, dest: &Path, env_rows: &str) -> String {
    format!(
        "version = 1\n\n[[provision]]\nname = \"demo\"\nversion = \"1.2.3\"\nurl = '{url}'\n\
         sha256 = \"{sha}\"\nbinary = \"demo\"\nlink = '{}'\n{env_rows}",
        dest.display()
    )
}

/// The three rows the shipped manifest declares, in miniature.
#[cfg(unix)]
const ENV_ROWS: &str = "\n[[provision.env]]\nname = \"NO_PROXY\"\n\
     prepend_list = [\"api.example.invalid\", \"assets.example.invalid\"]\n\
     \n[[provision.env]]\nname = \"DEMO_TOKEN\"\n\
     from_first_set = [\"DEMO_PRIMARY\", \"DEMO_FALLBACK\"]\n";

/// AN ENTRY DECLARING NO ENVIRONMENT IS UNCHANGED, which is what keeps the
/// launcher from being a tax every provisioned tool pays. `ripsecrets` declares
/// none and must still be a plain copy a shell can run with no interpreter.
#[cfg(unix)]
#[test]
fn an_entry_declaring_no_environment_is_still_a_plain_copy() {
    let env = Env::new("provision-plain-copy");
    let dest = env.repo.parent().unwrap().join("bin-plain");
    let (url, sha) = env.artifact("demo.bin", b"#not-a-launcher\n");
    env.config(&linking_manifest(&url, &sha, &dest, ""));

    let out = env.run(&["provision", "apply"]);
    assert_eq!(out.status.code(), Some(0), "{out:?}");
    assert_eq!(
        fs::read(dest.join("demo")).unwrap(),
        b"#not-a-launcher\n",
        "an entry with no `env` rows must be linked byte-for-byte, as it always was"
    );
}

/// THE CASE THE WHOLE SEAM EXISTS FOR: what the tool's own process sees.
///
/// Asserting on the launcher's TEXT would pass over a build that writes a
/// correct-looking file and execs with the environment untouched — which is the
/// same defect one layer down as the `[env]` one this replaces.
#[cfg(unix)]
#[test]
fn a_launcher_hands_the_tool_an_environment_a_manifest_could_not() {
    let Some(system_env) = env_binary() else {
        return;
    };
    let env = Env::new("provision-launcher-env");
    let dest = env.repo.parent().unwrap().join("bin-launcher");
    let bytes = fs::read(&system_env).unwrap();
    let (url, sha) = env.artifact("demo.bin", &bytes);
    env.config(&linking_manifest(&url, &sha, &dest, ENV_ROWS));

    let out = env.run(&["provision", "apply"]);
    assert_eq!(out.status.code(), Some(0), "{out:?}");

    let linked = dest.join("demo");
    let text = fs::read_to_string(&linked).unwrap();
    assert!(
        text.starts_with("#!") && text.lines().next().unwrap().ends_with(" provision-exec"),
        "a row declaring an environment is linked as a launcher"
    );

    // Run what is on `PATH`, exactly as a shell, a git hook or a session handler
    // would — no batten in the argv, because none of those know about one.
    #[expect(
        clippy::disallowed_types,
        reason = "stays: the fixture IS a spawn of the linked launcher, and asserting on anything else would not exercise the kernel's `#!` handling (CLOUD-320)"
    )]
    let ran = std::process::Command::new(&linked)
        .env("NO_PROXY", "localhost,pypi.example.invalid")
        .env("DEMO_FALLBACK", "from-the-fallback")
        .env_remove("DEMO_PRIMARY")
        .env_remove("DEMO_TOKEN")
        .output()
        .expect("run the launcher");
    assert_eq!(ran.status.code(), Some(0), "{ran:?}");
    let seen = String::from_utf8_lossy(&ran.stdout);

    assert!(
        seen.lines().any(|line| line
            == "NO_PROXY=api.example.invalid,assets.example.invalid,localhost,pypi.example.invalid"),
        "the declared hosts are prepended and what the host already exempted is kept: {seen}"
    );
    assert!(
        seen.lines()
            .any(|line| line == "DEMO_TOKEN=from-the-fallback"),
        "the credential is taken from the first source that carries one: {seen}"
    );
}

/// Idempotent, which the launcher needs rather than merely benefits from: a tool
/// that re-enters through the same `PATH` entry must not grow the value once per
/// generation, and a host that already exempts one of the declared hosts must
/// not get it twice.
#[cfg(unix)]
#[test]
fn the_prepend_adds_nothing_it_already_carries() {
    let Some(system_env) = env_binary() else {
        return;
    };
    let env = Env::new("provision-launcher-idempotent");
    let dest = env.repo.parent().unwrap().join("bin-idem");
    let bytes = fs::read(&system_env).unwrap();
    let (url, sha) = env.artifact("demo.bin", &bytes);
    env.config(&linking_manifest(&url, &sha, &dest, ENV_ROWS));
    assert_eq!(env.run(&["provision", "apply"]).status.code(), Some(0));

    #[expect(
        clippy::disallowed_types,
        reason = "stays: as above, the launcher must be spawned to be exercised (CLOUD-320)"
    )]
    let ran = std::process::Command::new(dest.join("demo"))
        .env("NO_PROXY", "api.example.invalid,localhost")
        .output()
        .expect("run the launcher");
    let seen = String::from_utf8_lossy(&ran.stdout);
    assert!(
        seen.lines()
            .any(|line| line == "NO_PROXY=assets.example.invalid,api.example.invalid,localhost"),
        "an entry already present is not added again: {seen}"
    );
}

/// AN ABSENT CREDENTIAL STAYS ABSENT. Setting the variable to an empty string
/// would be a different claim about the caller — some tools refuse an empty
/// token where they would have proceeded anonymously — and the container-build
/// case, where no session credential exists yet, is exactly this arm.
#[cfg(unix)]
#[test]
fn a_credential_no_source_carries_is_left_unset() {
    let Some(system_env) = env_binary() else {
        return;
    };
    let env = Env::new("provision-launcher-no-token");
    let dest = env.repo.parent().unwrap().join("bin-no-token");
    let bytes = fs::read(&system_env).unwrap();
    let (url, sha) = env.artifact("demo.bin", &bytes);
    env.config(&linking_manifest(&url, &sha, &dest, ENV_ROWS));
    assert_eq!(env.run(&["provision", "apply"]).status.code(), Some(0));

    #[expect(
        clippy::disallowed_types,
        reason = "stays: as above, the launcher must be spawned to be exercised (CLOUD-320)"
    )]
    let ran = std::process::Command::new(dest.join("demo"))
        .env_remove("DEMO_PRIMARY")
        .env_remove("DEMO_FALLBACK")
        .env_remove("DEMO_TOKEN")
        .output()
        .expect("run the launcher");
    let seen = String::from_utf8_lossy(&ran.stdout);
    assert!(
        !seen.lines().any(|line| line.starts_with("DEMO_TOKEN=")),
        "no source set means the variable is not set at all: {seen}"
    );
}

/// A LAUNCHER WHOSE INTERPRETER HAS GONE IS STALE, NOT FRESH. This is the one
/// way the seam degrades that a plain copy never could, so `status` must see it
/// — otherwise `provision apply` reports `AlreadyFresh` and never rewrites the
/// file, and every invocation of the tool fails with the kernel naming a missing
/// batten rather than anything about the tool.
#[cfg(unix)]
#[test]
fn a_launcher_naming_a_missing_interpreter_is_reported_as_missing() {
    let env = Env::new("provision-launcher-stale");
    let dest = env.repo.parent().unwrap().join("bin-stale");
    let (url, sha) = env.artifact("demo.bin", b"payload\n");
    env.config(&linking_manifest(&url, &sha, &dest, ENV_ROWS));
    assert_eq!(env.run(&["provision", "apply"]).status.code(), Some(0));
    assert_eq!(
        env.run(&["provision", "status"]).status.code(),
        Some(0),
        "a freshly applied entry is fresh"
    );

    fs::write(
        dest.join("demo"),
        "#!/nowhere/at/all/batten provision-exec\n{}\n",
    )
    .unwrap();
    assert_eq!(
        env.run(&["provision", "status"]).status.code(),
        Some(2),
        "a launcher naming an interpreter that is not there must not read as fresh"
    );
}

/// THE LAUNCHER ENTRY POINT IS INTERCEPTED BEFORE THE PARSER, and this is what
/// says so over the shipped binary.
///
/// It is deliberately absent from `surface.rs`, so the only thing that can prove
/// it exists — and that clap is not the one answering — is running it. A build
/// where the interception was removed or reordered answers clap's "unrecognized
/// subcommand" here, which is a different exit code and a different message.
#[test]
fn the_launcher_entry_point_is_read_before_the_parser() {
    let env = Env::new("provision-launcher-intercept");
    let out = env.run(&["provision-exec", "/nowhere/at/all/launcher"]);
    let said = String::from_utf8_lossy(&out.stderr);
    assert!(
        said.contains("launcher"),
        "the launcher's own reader must answer, not clap: {said}"
    );
    assert!(
        !said.contains("unrecognized") && !said.contains("Usage: batten"),
        "clap must never see this argv — it would claim the tool's own flags: {said}"
    );
}

/// AND IT MUST NOT CLAIM THE TOOL'S OWN FLAGS. `--help` after the launcher path
/// belongs to the tool; a build that let clap have it prints batten's help and
/// the caller never learns what the tool does.
#[test]
fn the_tool_s_own_help_flag_is_not_battens() {
    let env = Env::new("provision-launcher-help");
    let out = env.run(&["provision-exec", "/nowhere/at/all/launcher", "--help"]);
    let said = String::from_utf8_lossy(&out.stdout);
    assert!(
        !said.contains("Agent-era completion gate"),
        "`--help` after the launcher path is the tool's, never batten's: {said}"
    );
}

/// The xor is refused at LOAD, in both directions, because a row that sets
/// nothing produces a launcher indistinguishable from one never written — the
/// same silent-failure shape the field exists to end.
#[test]
fn an_env_row_declaring_neither_rule_is_refused_at_load() {
    let env = Env::new("provision-env-neither");
    let (url, sha) = env.artifact("demo.bin", b"x\n");
    env.config(&format!(
        "version = 1\n\n[[provision]]\nname = \"demo\"\nversion = \"1.2.3\"\nurl = '{url}'\n\
         sha256 = \"{sha}\"\nbinary = \"demo\"\n\n[[provision.env]]\nname = \"DEMO\"\n"
    ));
    let out = env.run(&["provision", "status"]);
    assert_eq!(out.status.code(), Some(1), "{out:?}");
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("neither"),
        "the refusal names which half is missing"
    );
}

#[test]
fn an_env_row_declaring_both_rules_is_refused_at_load() {
    let env = Env::new("provision-env-both");
    let (url, sha) = env.artifact("demo.bin", b"x\n");
    env.config(&format!(
        "version = 1\n\n[[provision]]\nname = \"demo\"\nversion = \"1.2.3\"\nurl = '{url}'\n\
         sha256 = \"{sha}\"\nbinary = \"demo\"\n\n[[provision.env]]\nname = \"DEMO\"\n\
         prepend_list = [\"a\"]\nfrom_first_set = [\"B\"]\n"
    ));
    let out = env.run(&["provision", "status"]);
    assert_eq!(out.status.code(), Some(1), "{out:?}");
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("both"),
        "the refusal says two rules cannot decide one variable"
    );
}

/// An organisation no certificate authority carries, so the negative arm cannot
/// pass by accident.
#[cfg(unix)]
const ABSENT_ORG: &str = "No Such Certificate Authority Organisation";

/// An `[[provision.env]]` row conditioned on that, otherwise identical to the
/// shipped shape.
#[cfg(unix)]
fn conditioned_rows(org: &str) -> String {
    format!(
        "\n[[provision.env]]\nname = \"NO_PROXY\"\nwhen_trust_names = \"{org}\"\n\
         prepend_list = [\"api.example.invalid\"]\n"
    )
}

/// A bundle holding exactly one certificate, taken from the host's own, plus the
/// organisation that certificate names.
///
/// Built from a real bundle rather than a literal because the predicate is about
/// PARSING: a hand-written fixture would assert that the fixture is shaped the
/// way its author imagined, which is the tautology the second tier exists to
/// avoid. `None` where the host has no readable bundle or none of its
/// authorities names an organisation — the case is skipped rather than passing
/// vacuously.
#[cfg(unix)]
fn one_certificate_bundle(into: &Path) -> Option<String> {
    const FOOTER: &str = "-----END CERTIFICATE-----";

    let source = ["SSL_CERT_FILE", "CURL_CA_BUNDLE"]
        .into_iter()
        .filter_map(std::env::var_os)
        .map(PathBuf::from)
        .find(|path| path.is_file())
        .or_else(|| {
            let system = PathBuf::from("/etc/ssl/certs/ca-certificates.crt");
            system.is_file().then_some(system)
        })?;
    let text = fs::read_to_string(&source).ok()?;
    for block in text.split_inclusive(FOOTER).filter(|b| b.contains(FOOTER)) {
        let pem = block.trim_start();
        let Some(org) = batten::provision::organisation_of(pem) else {
            continue;
        };
        fs::write(into, pem).ok()?;
        return Some(org);
    }
    None
}

/// THE ROW APPLIES ONLY WHERE THE NAMED AUTHORITY IS TRUSTED, and the negative
/// arm is what makes the positive one mean anything: without it this passes over
/// a build that ignores the condition entirely and applies every row.
#[cfg(unix)]
#[test]
fn a_conditioned_row_applies_only_where_the_trust_bundle_names_that_authority() {
    let Some(system_env) = env_binary() else {
        return;
    };
    let env = Env::new("provision-trust-condition");
    let bundle = env.repo.parent().unwrap().join("one-ca.pem");
    let Some(present_org) = one_certificate_bundle(&bundle) else {
        return;
    };
    let bytes = fs::read(&system_env).unwrap();

    let run = |org: &str, dest: &Path| -> String {
        let (url, sha) = env.artifact("demo.bin", &bytes);
        env.config(&linking_manifest(&url, &sha, dest, &conditioned_rows(org)));
        assert_eq!(env.run(&["provision", "apply"]).status.code(), Some(0));
        #[expect(
            clippy::disallowed_types,
            reason = "stays: the launcher must be spawned for the condition to be exercised (CLOUD-320)"
        )]
        let ran = std::process::Command::new(dest.join("demo"))
            .env("SSL_CERT_FILE", &bundle)
            .env_remove("CURL_CA_BUNDLE")
            .env_remove("REQUESTS_CA_BUNDLE")
            .env("NO_PROXY", "localhost")
            .output()
            .expect("run the launcher");
        String::from_utf8_lossy(&ran.stdout).into_owned()
    };

    let matched = run(&present_org, &env.repo.parent().unwrap().join("bin-yes"));
    assert!(
        matched
            .lines()
            .any(|line| line == "NO_PROXY=api.example.invalid,localhost"),
        "the row must apply where the bundle names {present_org}: {matched}"
    );

    let unmatched = run(ABSENT_ORG, &env.repo.parent().unwrap().join("bin-no"));
    assert!(
        unmatched.lines().any(|line| line == "NO_PROXY=localhost"),
        "the row must NOT apply where no authority names {ABSENT_ORG} — an \
         operator's own proxy stays honoured: {unmatched}"
    );
}

/// COULD-NOT-LOOK IS `false`, so an unreadable bundle leaves the host's proxy
/// alone. The other direction would move traffic off a path the operator chose
/// on the strength of a file this process failed to open.
#[cfg(unix)]
#[test]
fn an_unreadable_trust_bundle_does_not_apply_the_bypass() {
    let Some(system_env) = env_binary() else {
        return;
    };
    let env = Env::new("provision-trust-unreadable");
    let dest = env.repo.parent().unwrap().join("bin-unreadable");
    let bytes = fs::read(&system_env).unwrap();
    let (url, sha) = env.artifact("demo.bin", &bytes);
    env.config(&linking_manifest(
        &url,
        &sha,
        &dest,
        &conditioned_rows("Anthropic"),
    ));
    assert_eq!(env.run(&["provision", "apply"]).status.code(), Some(0));

    #[expect(
        clippy::disallowed_types,
        reason = "stays: as above, the launcher must be spawned (CLOUD-320)"
    )]
    let ran = std::process::Command::new(dest.join("demo"))
        .env(
            "SSL_CERT_FILE",
            env.repo.parent().unwrap().join("nowhere.pem"),
        )
        .env_remove("CURL_CA_BUNDLE")
        .env_remove("REQUESTS_CA_BUNDLE")
        .env("NO_PROXY", "localhost")
        .output()
        .expect("run the launcher");
    let seen = String::from_utf8_lossy(&ran.stdout);
    assert!(
        seen.lines().any(|line| line == "NO_PROXY=localhost"),
        "a bundle that cannot be read is not evidence of an interceptor: {seen}"
    );
}
