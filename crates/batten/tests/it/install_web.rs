//! The generated `install.sh` (CLOUD-2203, CLOUD-2287), run end to end over a
//! loopback release host.
//!
//! The script is `install::render_bootstrap`'s output from an `install.lock` and
//! nothing else: detect the target, download the BAKED tag's archive, compare it
//! with the baked sha256, and run `batten engine install`, which follows the
//! pin from there. It makes no version choice — no `batten.toml` is read, no
//! ref, never the latest release — and `BATTEN_VERSION` is the one escape hatch,
//! checked against that release's own `SHA256SUMS`. Everything after the
//! hand-over is Rust and is tested where it lives (`install.rs`,
//! `engine_install.rs`). This tier proves what only the script can: that the
//! baked tag is what is fetched, that the digest gate refuses bytes the lock or
//! the release did not name, and that a refused download names what answered.
//!
//! # Rendered per case, from a fixture lock
//!
//! The committed `install.sh` carries a real release's digests, which a fixture
//! archive can never match; `install_script.rs` pins those bytes. Each case here
//! renders the same template from a lock naming the fixture's own archive, so a
//! change to the template is exercised here before it is committed.
//!
//! # A loopback HTTP host rather than a `file://` tree
//!
//! A logged host is what lets a case show a pin, a ref or the latest release
//! was never asked for. Nothing leaves the machine.
//!
//! # The archive's `batten` is a stub
//!
//! It prints the arguments it was run with, which is how a case sees the
//! hand-over: `ran engine install` on stdout means the verified bytes were run.

// UNIX ONLY: the subject is a POSIX shell program, driven through `sh` with
// `.env_clear()` (which drops `SystemRoot` and `ComSpec`), needing `uname`,
// `mktemp`, `curl`, `tar` and `sha256sum`/`shasum`.
#![cfg(unix)]
// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::fmt::Write as _;
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::fs::PermissionsExt;
#[expect(
    clippy::disallowed_types,
    reason = "stays, and test-only: the import both spawns below need, annotated at every site the way the other suites in this directory are"
)]
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::thread;

use common::scratch;

/// The tag the fixture host publishes.
const TAG: &str = "v9.9.9";

/// The repository path the fixture host serves.
///
/// Named by the fixture rather than defaulted, so this suite does not spell out
/// where this repository is hosted — `forge name other` refuses that literal
/// anywhere under `crates/batten/tests/**`. The script reads `BATTEN_RELEASES`,
/// so pointing it here is the supported route and not a workaround.
const REPO: &str = "example/pkg";

/// The archive payload: a `batten` stub at the archive root, which is where
/// `batten dist` puts the binary and where the bootstrap extracts it from.
fn tarball(dir: &std::path::Path) -> Vec<u8> {
    let stage = dir.join("stage");
    std::fs::create_dir_all(&stage).unwrap();
    let stub = stage.join("batten");
    std::fs::write(&stub, "#!/bin/sh\necho \"ran $*\"\n").unwrap();
    // Executable, as the binary in a real release archive is.
    std::fs::set_permissions(&stub, std::fs::Permissions::from_mode(0o755)).unwrap();
    let archive = dir.join("payload.tar.gz");
    #[expect(
        clippy::disallowed_types,
        reason = "stays, and test-only: the bootstrap untars what it downloads, so the fixture payload has to be a real gzipped tar and `tar` is what writes one"
    )]
    let status = Command::new("tar")
        .args([
            "-czf",
            archive.to_str().unwrap(),
            "-C",
            stage.to_str().unwrap(),
            "batten",
        ])
        .status()
        .expect("run tar");
    assert!(status.success(), "the fixture archive must build");
    std::fs::read(&archive).unwrap()
}

/// sha256 of `bytes` as lowercase hex, through the same helper the engine uses,
/// so a fixture cannot pin a digest the script would never compute.
fn digest(bytes: &[u8]) -> String {
    batten::provision::digest(bytes)
}

/// The asset name the bootstrap asks for on `target`.
fn asset(target: &str) -> String {
    format!("batten-{TAG}-{target}.tar.gz")
}

/// One route the fixture host serves.
struct Route {
    /// The request path this answers.
    path: String,
    /// The status line's code.
    status: u16,
    /// `Location`, for a redirect.
    location: Option<String>,
    /// The body, for a `200`.
    body: Vec<u8>,
}

/// A loopback HTTP host serving `routes`, returning its base URL.
///
/// Single-threaded and serial by design: the script makes its requests in
/// order, and a concurrent server would let a missing request pass unnoticed as
/// a timing artefact. Unknown paths answer `404`. `build` is handed the host's
/// own base URL, because a release host names itself in the `Location` it
/// redirects to.
fn host(build: impl FnOnce(&str) -> Vec<Route>) -> String {
    logged_host(build).0
}

/// [`host`], also returning the path of every request it answered, in order —
/// so a case can count a retry, or show no request was made at all.
fn logged_host(build: impl FnOnce(&str) -> Vec<Route>) -> (String, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let base = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
    let routes = build(&base);
    let log = Arc::new(Mutex::new(Vec::new()));
    let seen = Arc::clone(&log);
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { continue };
            serve(stream, &routes, &seen);
        }
    });
    (base, log)
}

/// How many requests `log` holds for `path`.
fn requests(log: &Mutex<Vec<String>>, path: &str) -> usize {
    log.lock()
        .unwrap()
        .iter()
        .filter(|seen| seen.as_str() == path)
        .count()
}

fn serve(mut stream: TcpStream, routes: &[Route], log: &Mutex<Vec<String>>) {
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let mut request = String::new();
    if reader.read_line(&mut request).is_err() {
        return;
    }
    // Drain the headers so the client sees a complete exchange.
    loop {
        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(0) | Err(_) => break,
            Ok(_) if line.trim().is_empty() => break,
            Ok(_) => {}
        }
    }
    let path = request.split_whitespace().nth(1).unwrap_or("/").to_owned();
    log.lock().unwrap().push(path.clone());
    let answer = routes.iter().find(|route| route.path == path);
    let response = match answer {
        Some(route) if route.status == 302 => format!(
            "HTTP/1.1 302 Found\r\nLocation: {}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            route.location.clone().unwrap_or_default()
        ),
        Some(route) if route.status == 200 => format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            route.body.len()
        ),
        Some(route) => format!(
            "HTTP/1.1 {} Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            route.status
        ),
        None => {
            "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_owned()
        }
    };
    let _ = stream.write_all(response.as_bytes());
    if let Some(route) = answer
        && route.status == 200
    {
        let _ = stream.write_all(&route.body);
    }
    let _ = stream.flush();
}

/// The routes a complete release serves: `SHA256SUMS`, and the archive under
/// every bootstrap target's name, so a case passes on whichever host runs it.
fn release_routes(_base: &str, archive: &[u8]) -> Vec<Route> {
    let sums = sums_for(&digest(archive));
    let mut routes = vec![Route {
        path: format!("/{REPO}/releases/download/{TAG}/SHA256SUMS"),
        status: 200,
        location: None,
        body: sums.into_bytes(),
    }];
    for target in batten::install::TARGETS {
        routes.push(Route {
            path: format!("/{REPO}/releases/download/{TAG}/{}", asset(target)),
            status: 200,
            location: None,
            body: archive.to_vec(),
        });
    }
    routes
}

/// A `SHA256SUMS` body naming `digest` for the archive of every bootstrap target.
fn sums_for(digest: &str) -> String {
    batten::install::TARGETS
        .iter()
        .fold(String::new(), |mut sums, target| {
            let _ = writeln!(sums, "{digest}  {}", asset(target));
            sums
        })
}

/// The index of the `SHA256SUMS` route in [`release_routes`].
const SUMS: usize = 0;

/// The lock a bake of the fixture release writes, naming `digest` for every
/// target archive.
fn lock_for(digest: &str) -> batten::install::Lock {
    batten::install::Lock::from_sums("batten", TAG, &sums_for(digest))
        .expect("the fixture names every target")
}

/// A lock baked for some OTHER release, so a case can show `BATTEN_VERSION`
/// fetches its own tag and its own `SHA256SUMS` rather than the baked ones.
fn other_lock() -> batten::install::Lock {
    batten::install::Lock {
        tag: String::from("v1.0.0"),
        sums: Vec::new(),
    }
}

/// How many requests `log` holds whose path ends with `suffix`.
fn requests_ending(log: &Mutex<Vec<String>>, suffix: &str) -> usize {
    log.lock()
        .unwrap()
        .iter()
        .filter(|seen| seen.ends_with(suffix))
        .count()
}

/// Run the bootstrap rendered from `lock` against `web`, with every credential
/// unset, from a scratch directory whose `batten.toml` pins nothing.
fn install(
    name: &str,
    web: &str,
    lock: &batten::install::Lock,
    env: &[(&str, &str)],
) -> (Option<i32>, String, String) {
    install_in(name, "version = 1\n", web, lock, env)
}

/// [`install`], from a scratch directory whose `batten.toml` is `config`.
fn install_in(
    name: &str,
    config: &str,
    web: &str,
    lock: &batten::install::Lock,
    env: &[(&str, &str)],
) -> (Option<i32>, String, String) {
    let dir = scratch(name);
    std::fs::write(dir.join("batten.toml"), config).unwrap();
    let script = dir.join("install.sh");
    std::fs::write(
        &script,
        batten::install::render_bootstrap("batten", "https://example.invalid/unused", lock),
    )
    .unwrap();
    #[expect(
        clippy::disallowed_types,
        reason = "stays, and test-only: the subject of this suite IS a shell program, so there is nothing to assert without running it"
    )]
    let mut command = Command::new("sh");
    command
        .arg(&script)
        .current_dir(&dir)
        .env_clear()
        // No `batten` resolvable by name (CLOUD-1951): CI's runner has none, so
        // a script that found one here would be reading a different box.
        .env("PATH", common::ambient_path())
        .env("HOME", dir.to_str().unwrap())
        // The loopback host must not be reached through this container's proxy.
        .env("NO_PROXY", "127.0.0.1,localhost")
        .env("no_proxy", "127.0.0.1,localhost")
        .env("BATTEN_RELEASES", [web, REPO].join("/"));
    for (key, value) in env {
        command.env(key, value);
    }
    let out = command.output().expect("run install.sh");
    (
        out.status.code(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// No token, no API, no pin: the baked tag's archive is fetched, checked against
/// the baked sha256 — no `SHA256SUMS` request — and handed `engine install`.
#[test]
fn install_installs_its_baked_tag() {
    let dir = scratch("install-web-happy");
    let archive = tarball(&dir);
    let (web, log) = logged_host(|base| release_routes(base, &archive));

    let (code, stdout, stderr) = install("install-web-ok", &web, &lock_for(&digest(&archive)), &[]);
    assert_eq!(code, Some(0), "install failed: {stdout}{stderr}");
    assert!(
        stdout.contains("ran engine install"),
        "the verified binary must be run with `engine install`: {stdout}"
    );
    assert_eq!(
        requests_ending(&log, "/SHA256SUMS"),
        0,
        "the baked sha256 needs no manifest"
    );
}

/// `BATTEN_VERSION` is the escape hatch: that tag is fetched and checked against
/// its own release's `SHA256SUMS`, whatever the lock baked.
#[test]
fn a_named_version_reads_its_own_sha256sums() {
    let dir = scratch("install-web-named");
    let archive = tarball(&dir);
    let (web, log) = logged_host(|base| release_routes(base, &archive));

    let (code, stdout, stderr) = install(
        "install-web-named-run",
        &web,
        &other_lock(),
        &[("BATTEN_VERSION", TAG)],
    );
    assert_eq!(code, Some(0), "install failed: {stdout}{stderr}");
    assert!(stdout.contains("ran engine install"), "{stdout}");
    assert_eq!(
        requests(&log, &format!("/{REPO}/releases/download/{TAG}/SHA256SUMS")),
        1
    );
}

/// A served archive whose sha256 is not the one the lock baked is a REFUSAL,
/// and the bytes are never run (CLOUD-2287).
#[test]
fn a_served_archive_disagreeing_with_the_lock_installs_nothing() {
    let dir = scratch("install-web-badlock");
    let archive = tarball(&dir);
    let web = host(|base| release_routes(base, &archive));

    let (code, stdout, stderr) = install(
        "install-web-badlock-run",
        &web,
        &lock_for(&"1".repeat(64)),
        &[],
    );
    assert_eq!(
        code,
        Some(1),
        "a digest mismatch is a refusal: {stdout}{stderr}"
    );
    assert!(stderr.contains("does not match"), "{stderr}");
    assert!(
        !stdout.contains("ran engine install"),
        "unverified bytes must never be run: {stdout}"
    );
}

/// Under `BATTEN_VERSION`, a `SHA256SUMS` disagreeing with the bytes is a
/// REFUSAL, and the bytes are never run.
#[test]
fn a_sha256sums_that_disagrees_with_the_bytes_installs_nothing() {
    let dir = scratch("install-web-badsum");
    let archive = tarball(&dir);
    let web = host(|base| {
        let mut routes = release_routes(base, &archive);
        // Publish a digest for a payload that is not the one served.
        routes[SUMS].body = sums_for(&"1".repeat(64)).into_bytes();
        routes
    });

    let (code, stdout, stderr) = install(
        "install-web-bad",
        &web,
        &other_lock(),
        &[("BATTEN_VERSION", TAG)],
    );
    assert_eq!(
        code,
        Some(1),
        "a digest mismatch is a refusal: {stdout}{stderr}"
    );
    assert!(stderr.contains("does not match"), "{stderr}");
    assert!(
        !stdout.contains("ran engine install"),
        "unverified bytes must never be run: {stdout}"
    );
}

/// An asset `SHA256SUMS` does not name is a refusal, never an unverified run.
/// The manifest is matched by exact field equality, so a release that omits
/// this target's line does not fall through to another's.
#[test]
fn an_asset_absent_from_sha256sums_installs_nothing() {
    let dir = scratch("install-web-nosum");
    let archive = tarball(&dir);
    let web = host(|base| {
        let mut routes = release_routes(base, &archive);
        routes[SUMS].body = format!("{}  some-other-asset.tar.gz\n", digest(&archive)).into_bytes();
        routes
    });

    let (code, stdout, stderr) = install(
        "install-web-nosum-run",
        &web,
        &other_lock(),
        &[("BATTEN_VERSION", TAG)],
    );
    assert_eq!(
        code,
        Some(1),
        "a release that publishes no digest for this asset is a refusal: {stdout}{stderr}"
    );
    assert!(stderr.contains("publishes no sha256"), "{stderr}");
    assert!(!stdout.contains("ran engine install"), "{stdout}");
}

/// A named release with no `SHA256SUMS` is the RELEASE's fault: exit 1, naming
/// the status and the URL that answered, and nothing is run.
#[test]
fn a_release_publishing_no_sha256sums_names_the_status_and_url() {
    let dir = scratch("install-web-nomanifest");
    let archive = tarball(&dir);
    let web = host(|base| {
        let mut routes = release_routes(base, &archive);
        routes.remove(SUMS);
        routes
    });

    let (code, stdout, stderr) = install(
        "install-web-nomanifest-run",
        &web,
        &other_lock(),
        &[("BATTEN_VERSION", TAG)],
    );
    assert_eq!(code, Some(1), "{stdout}{stderr}");
    assert!(
        stderr.contains("SHA256SUMS: 404 http://127.0.0.1:"),
        "a refused download names the status and what answered: {stderr}"
    );
    assert!(!stdout.contains("ran engine install"), "{stdout}");
}

/// A named release carrying no archive for this target is exit 1, naming the
/// asset.
#[test]
fn a_release_carrying_no_asset_for_this_target_is_exit_1_naming_it() {
    let dir = scratch("install-web-noasset");
    let archive = tarball(&dir);
    let web = host(|base| {
        let mut routes = release_routes(base, &archive);
        routes.truncate(SUMS + 1);
        routes
    });

    let (code, stdout, stderr) = install(
        "install-web-noasset-run",
        &web,
        &other_lock(),
        &[("BATTEN_VERSION", TAG)],
    );
    assert_eq!(code, Some(1), "{stdout}{stderr}");
    assert!(
        stderr.contains(&format!("batten-{TAG}-")) && stderr.contains(".tar.gz: 404"),
        "the refusal names the asset and the status: {stderr}"
    );
    assert!(!stdout.contains("ran engine install"), "{stdout}");
}

/// The script makes no version choice (CLOUD-2287): no `batten.toml` is read,
/// on the host or off it, and the latest release is never asked for.
#[test]
fn the_script_never_asks_for_a_pin_or_the_latest_release() {
    let dir = scratch("install-web-nochoice");
    let archive = tarball(&dir);
    let (web, log) = logged_host(|base| release_routes(base, &archive));

    let (code, stdout, stderr) = install(
        "install-web-nochoice-run",
        &web,
        &lock_for(&digest(&archive)),
        &[],
    );
    assert_eq!(code, Some(0), "{stdout}{stderr}");
    assert_eq!(requests_ending(&log, "/batten.toml"), 0, "no pin is read");
    assert_eq!(
        requests(&log, &format!("/{REPO}/releases/latest")),
        0,
        "the latest release is never asked for"
    );
}

/// Run from a directory whose `batten.toml` pins another release, with neither
/// environment variable set, the script still fetches its baked tag: following
/// the pin is the binary's job, which the hand-over gives it.
#[test]
fn a_consumers_pin_never_changes_the_baked_tag() {
    let dir = scratch("install-web-consumer");
    let archive = tarball(&dir);
    let (web, log) = logged_host(|base| release_routes(base, &archive));

    let pinned = "version = 1\nengine = { release = \"v0.0.1\" }\n";
    let (code, stdout, stderr) = install_in(
        "install-web-consumer-run",
        pinned,
        &web,
        &lock_for(&digest(&archive)),
        &[],
    );
    assert_eq!(code, Some(0), "{stdout}{stderr}");
    assert!(stdout.contains("ran engine install"), "{stdout}");
    assert!(
        !log.lock()
            .unwrap()
            .iter()
            .any(|seen| seen.contains("v0.0.1")),
        "nothing of the consumer's pin is fetched"
    );
}

/// `BATTEN_VERSION_FROM_REF` is the binary's to honour, not the script's: the
/// ref's `batten.toml` is never read here, and the baked bytes are run.
#[test]
fn a_ref_is_left_to_the_binary() {
    let dir = scratch("install-web-ref");
    let archive = tarball(&dir);
    let (web, log) = logged_host(|base| release_routes(base, &archive));

    let (code, stdout, stderr) = install(
        "install-web-ref-run",
        &web,
        &lock_for(&digest(&archive)),
        &[("BATTEN_VERSION_FROM_REF", "trunk")],
    );
    assert_eq!(code, Some(0), "{stdout}{stderr}");
    assert!(stdout.contains("ran engine install"), "{stdout}");
    assert_eq!(
        requests_ending(&log, "/batten.toml"),
        0,
        "the ref is never read"
    );
}

/// A transient answer is retried, a bounded number of times, and then reported
/// as could-not-look rather than looping or hanging.
#[test]
fn the_retry_is_bounded_and_reports_rather_than_looping() {
    let dir = scratch("install-web-retry");
    let archive = tarball(&dir);
    let (web, log) = logged_host(|base| {
        let mut routes = release_routes(base, &archive);
        for route in &mut routes {
            route.status = 503;
        }
        routes
    });

    let (code, stdout, stderr) = install(
        "install-web-retry-run",
        &web,
        &lock_for(&digest(&archive)),
        &[],
    );
    assert_eq!(code, Some(2), "{stdout}{stderr}");
    assert!(stderr.contains(".tar.gz: 503"), "{stderr}");
    assert_eq!(
        requests_ending(&log, ".tar.gz"),
        4,
        "one attempt and three retries, then stop"
    );
}
/// A platform no release builds is refused before any request is made.
#[test]
fn a_platform_no_release_builds_is_refused_before_any_request() {
    let dir = scratch("install-web-platform");
    let stub = dir.join("stub");
    std::fs::create_dir_all(&stub).unwrap();
    let uname = stub.join("uname");
    std::fs::write(
        &uname,
        "#!/bin/sh\ncase \"$1\" in -s) echo Linux ;; -m) echo riscv64 ;; esac\n",
    )
    .unwrap();
    std::fs::set_permissions(&uname, std::fs::Permissions::from_mode(0o755)).unwrap();
    let (web, log) = logged_host(|_| Vec::new());
    let ambient = common::ambient_path();
    let path =
        std::env::join_paths(std::iter::once(stub.clone()).chain(std::env::split_paths(&ambient)))
            .expect("a PATH entry carries no separator");
    let path = path.to_string_lossy();

    let (code, stdout, stderr) = install(
        "install-web-platform-run",
        &web,
        &lock_for(&"0".repeat(64)),
        &[("PATH", &path)],
    );
    assert_eq!(code, Some(1), "{stdout}{stderr}");
    assert!(stderr.contains("no release for Linux/riscv64"), "{stderr}");
    assert!(log.lock().unwrap().is_empty(), "no request is made");
}

/// A web host that serves nothing is "could not look" (2), never a broken
/// release (1): the baked tag was published, so its `404` is the
/// private-repository shape.
#[test]
fn a_web_host_that_serves_nothing_is_could_not_look() {
    let web = host(|_| Vec::new());
    let (code, stdout, stderr) = install("install-web-404", &web, &lock_for(&"0".repeat(64)), &[]);
    assert_eq!(
        code,
        Some(2),
        "an unreadable release is environment, not a bad release: {stdout}{stderr}"
    );
    assert!(stderr.contains(".tar.gz: 404"), "{stderr}");
    assert!(!stdout.contains("ran engine install"), "{stdout}");
}

/// A release tree for `s_server -WWW`: `SHA256SUMS` and every target's archive
/// under `releases/download/<tag>/`. No redirect is possible there, so the cases
/// served from it name the tag with `BATTEN_VERSION`.
fn release_tree(root: &std::path::Path, archive: &[u8]) {
    let download = root.join(REPO).join("releases").join("download").join(TAG);
    std::fs::create_dir_all(&download).unwrap();
    std::fs::write(download.join("SHA256SUMS"), sums_for(&digest(archive))).unwrap();
    for target in batten::install::TARGETS {
        std::fs::write(download.join(asset(target)), archive).unwrap();
    }
}

/// One arm of the CA case: its name, the variables it declares, the exit wanted.
type CaArm<'a> = (&'a str, &'a [(&'a str, &'a str)], i32);

/// The CA a host declares reaches the bootstrap's downloads, in curl's own
/// precedence — `CURL_CA_BUNDLE`, then `SSL_CERT_FILE` — so the one-liner
/// installs through a proxy that re-terminates TLS. Without a declaration the
/// same host is refused as could-not-look, which is what makes the trusted arms
/// evidence about trust rather than about something answering.
///
/// Linux only, said inside the case so it compiles everywhere (CLOUD-1148): the
/// fixture's key material comes from `openssl`, as `provision.rs`'s does.
#[test]
fn a_declared_ca_bundle_reaches_the_download_in_curls_precedence() {
    if !cfg!(target_os = "linux") {
        return;
    }
    let dir = scratch("install-web-ca");
    let archive = tarball(&dir);
    let root = dir.join("www");
    release_tree(&root, &archive);
    let tls = dir.join("tls");
    std::fs::create_dir_all(&tls).unwrap();
    let host = common::tls_www(&tls, &root);
    let web = format!("https://localhost:{}", host.port);
    let ca = tls.join("ca.pem").display().to_string();
    let absent = dir.join("absent.pem").display().to_string();

    let arms: [CaArm<'_>; 4] = [
        ("curl-ca-bundle", &[("CURL_CA_BUNDLE", &ca)], 0),
        ("ssl-cert-file", &[("SSL_CERT_FILE", &ca)], 0),
        (
            "curl-ca-bundle-outranks",
            &[("CURL_CA_BUNDLE", &ca), ("SSL_CERT_FILE", &absent)],
            0,
        ),
        ("undeclared", &[], 2),
    ];
    for (name, declared, want) in arms {
        let mut env = vec![("BATTEN_VERSION", TAG)];
        env.extend_from_slice(declared);
        let (code, stdout, stderr) =
            install(&format!("install-web-ca-{name}"), &web, &other_lock(), &env);
        assert_eq!(code, Some(want), "{name}: {stdout}{stderr}");
        assert_eq!(
            stdout.contains("ran engine install"),
            want == 0,
            "{name}: {stdout}{stderr}"
        );
    }
}

// ---------------------------------------------------------------------------
// cargo-dist's installer (CLOUD-2297).
// ---------------------------------------------------------------------------

/// Generate dist's shell installer for `target` with `archive`'s sha256 baked
/// in, exactly as the release's `installers` job does: one manifest fragment in
/// the workspace's `target/distrib/`, then `dist build --artifacts=global`.
///
/// IN A SCRATCH WORKSPACE, because dist stages under the workspace whatever
/// `CARGO_TARGET_DIR` says (`batten::dist::cargo_dist_staging`), so running it
/// here would merge whatever fragments a local build left. The
/// workspace is a stub `batten` package at this crate's version and repository,
/// configured by the committed `dist-workspace.toml`, so the generator under
/// test reads the release's own config.
fn dist_installer(dir: &std::path::Path, target: &str, archive: &[u8]) -> std::path::PathBuf {
    let version = env!("CARGO_PKG_VERSION");
    let name = batten::dist::cargo_dist_archive("batten", target);
    let ws = dir.join("ws");
    // Fresh each run: dist refuses a stale `wix/main.wxs` a prior run generated.
    let _ = std::fs::remove_dir_all(&ws);
    std::fs::create_dir_all(ws.join("src")).unwrap();
    // `dist generate --mode msi` writes `wix/main.wxs` from the package's WiX
    // GUIDs and authors, so the stub carries the crate's own
    // `[package.metadata.wix]` table and the metadata the release generates from.
    let manifest: toml::Table = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml"),
    )
    .unwrap()
    .parse()
    .unwrap();
    let mut metadata = toml::Table::new();
    metadata.insert(
        "wix".to_owned(),
        manifest["package"]["metadata"]["wix"].clone(),
    );
    let mut package = toml::Table::new();
    package.insert("name".to_owned(), "batten".into());
    package.insert("version".to_owned(), version.into());
    package.insert("edition".to_owned(), "2021".into());
    package.insert("repository".to_owned(), env!("CARGO_PKG_REPOSITORY").into());
    package.insert("homepage".to_owned(), env!("CARGO_PKG_HOMEPAGE").into());
    package.insert(
        "description".to_owned(),
        env!("CARGO_PKG_DESCRIPTION").into(),
    );
    package.insert(
        "authors".to_owned(),
        env!("CARGO_PKG_AUTHORS")
            .split(':')
            .collect::<Vec<_>>()
            .into(),
    );
    package.insert("metadata".to_owned(), metadata.into());
    let mut stub = toml::Table::new();
    stub.insert("package".to_owned(), package.into());
    stub.insert("workspace".to_owned(), toml::Table::new().into());
    std::fs::write(ws.join("Cargo.toml"), stub.to_string()).unwrap();
    std::fs::write(ws.join("src/main.rs"), "fn main() {}\n").unwrap();
    let dist_config = common::dist_config();
    std::fs::write(ws.join("dist-workspace.toml"), dist_config.to_string()).unwrap();
    // The fragment claims the dist version the committed config pins.
    let dist_version = dist_config["dist"]["cargo-dist-version"].clone();
    let staged = batten::dist::cargo_dist_staging(&ws);
    std::fs::create_dir_all(&staged).unwrap();
    let checksum = batten::dist::cargo_dist_checksum(&name);
    let fragment = serde_json::json!({
        "dist_version": dist_version.as_str(),
        "announcement_tag": format!("v{version}"),
        "releases": [{
            "app_name": "batten",
            "app_version": version,
            "artifacts": [name, checksum],
        }],
        "artifacts": {
            name.clone(): {
                "name": name,
                "kind": "executable-zip",
                "target_triples": [target],
                "assets": [{"id": format!("batten-{target}-exe-batten"), "name": "batten", "path": "batten", "kind": "executable"}],
                "checksum": checksum,
                "checksums": {"sha256": digest(archive)},
            },
            checksum.clone(): {
                "name": checksum,
                "kind": "checksum",
                "target_triples": [target],
            },
        },
    });
    std::fs::write(
        staged.join(batten::dist::cargo_dist_manifest(target)),
        fragment.to_string(),
    )
    .unwrap();
    // The release's own order: the MSI template, then the global step.
    run_dist(&ws, &batten::dist::CARGO_DIST_MSI_TEMPLATE[1..]);
    run_dist(
        &ws,
        &[
            "build",
            "--artifacts=global",
            "--tag",
            &format!("v{version}"),
        ],
    );
    staged.join("batten-installer.sh")
}

/// Run cargo-dist in `ws` and require it to succeed.
fn run_dist(ws: &std::path::Path, args: &[&str]) {
    #[expect(
        clippy::disallowed_types,
        reason = "stays, and test-only: the subject is cargo-dist's own generator, so the case runs it rather than a restatement of it"
    )]
    let ran = Command::new("dist")
        .args(args)
        .current_dir(ws)
        .output()
        .expect("cargo-dist must be installed: it is a pinned [tools] entry");
    assert!(
        ran.status.success(),
        "dist {}: {}",
        args.join(" "),
        String::from_utf8_lossy(&ran.stderr)
    );
}

/// dist's archive layout: the binary under `batten-<target>/`, which the
/// installer strips with `--strip-components 1`.
fn dist_tarball(dir: &std::path::Path, target: &str) -> Vec<u8> {
    let stage = dir.join("dist-stage");
    let inner = stage.join(format!("batten-{target}"));
    std::fs::create_dir_all(&inner).unwrap();
    let stub = inner.join("batten");
    std::fs::write(&stub, "#!/bin/sh\necho \"ran $*\"\n").unwrap();
    std::fs::set_permissions(&stub, std::fs::Permissions::from_mode(0o755)).unwrap();
    let archive = dir.join("dist-payload.tar.gz");
    #[expect(
        clippy::disallowed_types,
        reason = "stays, and test-only: the installer untars what it downloads, so the fixture payload has to be a real gzipped tar"
    )]
    let status = Command::new("tar")
        .args([
            "-czf",
            archive.to_str().unwrap(),
            "-C",
            stage.to_str().unwrap(),
            &format!("batten-{target}"),
        ])
        .status()
        .expect("run tar");
    assert!(status.success(), "the fixture archive must build");
    std::fs::read(&archive).unwrap()
}

/// Run dist's `installer` against the archive bytes `served`, from a
/// `file://` release directory, into a fresh unmanaged install directory.
fn run_dist_installer(
    dir: &std::path::Path,
    installer: &std::path::Path,
    target: &str,
    served: &[u8],
) -> (bool, std::path::PathBuf, String) {
    let www = dir.join("www");
    std::fs::create_dir_all(&www).unwrap();
    std::fs::write(
        www.join(batten::dist::cargo_dist_archive("batten", target)),
        served,
    )
    .unwrap();
    let into = dir.join("installed");
    std::fs::create_dir_all(&into).unwrap();
    #[expect(
        clippy::disallowed_types,
        reason = "stays, and test-only: the subject is the generated POSIX installer, which only `sh` runs"
    )]
    let ran = Command::new("sh")
        .arg(installer)
        .env("BATTEN_DOWNLOAD_URL", format!("file://{}", www.display()))
        .env("BATTEN_UNMANAGED_INSTALL", &into)
        .env("BATTEN_NO_MODIFY_PATH", "1")
        .output()
        .expect("run sh");
    let said = format!(
        "{}{}",
        String::from_utf8_lossy(&ran.stdout),
        String::from_utf8_lossy(&ran.stderr)
    );
    (ran.status.success(), into.join("batten"), said)
}

/// The installer cargo-dist generates installs only the bytes the release
/// published: a tampered archive is refused and nothing is placed, and the
/// archive whose sha256 the release recorded installs. Both halves, so a
/// generator that dropped the digest (which installs either) fails here.
///
/// Linux only, said inside the case so it compiles everywhere (CLOUD-1148): the
/// installer verifies through `sha256sum`, and where that is absent it skips
/// the check (CLOUD-2307), so only a host carrying it can show the refusal.
#[test]
fn the_dist_installer_refuses_a_digest_mismatch() {
    if !cfg!(target_os = "linux") {
        return;
    }
    let target = batten::engine::running_target();
    let dir = scratch("install-web-dist");
    let archive = dist_tarball(&dir, &target);
    let installer = dist_installer(&dir, &target, &archive);

    let tampered_dir = dir.join("tampered");
    let mut tampered = archive.clone();
    tampered.push(0);
    let (ok, placed, said) = run_dist_installer(&tampered_dir, &installer, &target, &tampered);
    assert!(!ok, "a tampered archive must be refused: {said}");
    assert!(said.contains("checksum mismatch"), "{said}");
    assert!(
        !placed.exists(),
        "nothing is installed from a refused archive"
    );

    let good_dir = dir.join("good");
    let (ok, placed, said) = run_dist_installer(&good_dir, &installer, &target, &archive);
    assert!(ok, "the published archive installs: {said}");
    assert!(placed.is_file(), "the binary is placed: {said}");
}
