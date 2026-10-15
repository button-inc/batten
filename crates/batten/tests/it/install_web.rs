//! The generated `install.sh` (CLOUD-2203), run end to end over a loopback
//! release host.
//!
//! The script is `install::render_bootstrap`'s output and nothing else: detect
//! the target, take the tag a `batten.toml` pins (or `BATTEN_VERSION`) and
//! never the latest release (CLOUD-2033), fetch `SHA256SUMS` and the archive
//! from `releases/download`, check the digest, and run `batten engine install`.
//! Everything after the hand-over is Rust and is tested where it lives
//! (`install.rs`, `engine_install.rs`). This tier proves what only the script can:
//! that the tag resolves, that the digest gate refuses bytes the release did not
//! publish, and that a refused download names what answered.
//!
//! # A loopback HTTP host rather than a `file://` tree
//!
//! The pin comes off the same host the script downloads from — `main`'s
//! `batten.toml` on the raw-file host, which a fixture base serves at
//! `<base>/main/batten.toml` — and a logged host is what lets a case show the
//! latest release was never asked for. Nothing leaves the machine.
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
#[expect(
    clippy::disallowed_methods,
    reason = "bounded: `tarball` reads a test input: a fixture the case wrote or a file this repository tracks"
)]
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

/// `main`'s `batten.toml`, pinning `tag`.
fn pin_route(reference: &str, tag: &str) -> Route {
    Route {
        path: format!("/{REPO}/{reference}/batten.toml"),
        status: 200,
        location: None,
        body: format!("version = 1\nengine = {{ release = \"{tag}\" }}\n").into_bytes(),
    }
}

/// The routes a complete release serves: `main`'s pin naming it,
/// `SHA256SUMS`, and the archive under every bootstrap target's name, so a case
/// passes on whichever host runs it.
fn release_routes(_base: &str, archive: &[u8]) -> Vec<Route> {
    let sums = sums_for(&digest(archive));
    let mut routes = vec![
        pin_route("main", TAG),
        Route {
            path: format!("/{REPO}/releases/download/{TAG}/SHA256SUMS"),
            status: 200,
            location: None,
            body: sums.into_bytes(),
        },
    ];
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
const SUMS: usize = 1;

/// Run the committed `install.sh` against `web`, with every credential unset.
///
/// The scratch directory carries a `batten.toml` pinning nothing, so the
/// script's walk up from its working directory stops there — the scratch root
/// lives inside this repository, whose own pin it would otherwise read — and
/// falls through to `main`'s pin on the fixture host.
fn install(name: &str, web: &str, env: &[(&str, &str)]) -> (Option<i32>, String, String) {
    install_in(name, "version = 1\n", web, env)
}

/// [`install`], from a scratch directory whose `batten.toml` is `config`.
fn install_in(
    name: &str,
    config: &str,
    web: &str,
    env: &[(&str, &str)],
) -> (Option<i32>, String, String) {
    let dir = scratch(name);
    std::fs::write(dir.join("batten.toml"), config).unwrap();
    #[expect(
        clippy::disallowed_types,
        reason = "stays, and test-only: the subject of this suite IS a shell program, so there is nothing to assert without running it"
    )]
    let mut command = Command::new("sh");
    command
        .arg(concat!(env!("CARGO_MANIFEST_DIR"), "/../../install.sh"))
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

/// No token, no API: the tag is `main`'s pin, the digest gate runs, and the
/// verified binary is handed `engine install`.
#[test]
fn install_installs_mains_pin() {
    let dir = scratch("install-web-happy");
    let archive = tarball(&dir);
    let web = host(|base| release_routes(base, &archive));

    let (code, stdout, stderr) = install("install-web-ok", &web, &[]);
    assert_eq!(code, Some(0), "install failed: {stdout}{stderr}");
    assert!(
        stdout.contains("ran engine install"),
        "the verified binary must be run with `engine install`: {stdout}"
    );
}

/// `BATTEN_VERSION` names the tag, so no pin is read.
#[test]
fn a_named_version_reads_no_pin() {
    let dir = scratch("install-web-named");
    let archive = tarball(&dir);
    let web = host(|base| {
        let mut routes = release_routes(base, &archive);
        // Drop main's pin: a script that still read it would fail on the 404.
        routes.remove(0);
        routes
    });

    let (code, stdout, stderr) = install("install-web-named-run", &web, &[("BATTEN_VERSION", TAG)]);
    assert_eq!(code, Some(0), "install failed: {stdout}{stderr}");
    assert!(stdout.contains("ran engine install"), "{stdout}");
}

/// A `SHA256SUMS` disagreeing with the bytes is a REFUSAL, and the bytes are
/// never run.
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

    let (code, stdout, stderr) = install("install-web-bad", &web, &[]);
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

    let (code, stdout, stderr) = install("install-web-nosum-run", &web, &[]);
    assert_eq!(
        code,
        Some(1),
        "a release that publishes no digest for this asset is a refusal: {stdout}{stderr}"
    );
    assert!(stderr.contains("publishes no sha256"), "{stderr}");
    assert!(!stdout.contains("ran engine install"), "{stdout}");
}

/// A release with no `SHA256SUMS` is the RELEASE's fault once its tag resolved:
/// exit 1, naming the status and the URL that answered, and nothing is run.
#[test]
fn a_release_publishing_no_sha256sums_names_the_status_and_url() {
    let dir = scratch("install-web-nomanifest");
    let archive = tarball(&dir);
    let web = host(|base| {
        let mut routes = release_routes(base, &archive);
        routes.remove(SUMS);
        routes
    });

    let (code, stdout, stderr) = install("install-web-nomanifest-run", &web, &[]);
    assert_eq!(code, Some(1), "{stdout}{stderr}");
    assert!(
        stderr.contains("SHA256SUMS: 404 http://127.0.0.1:"),
        "a refused download names the status and what answered: {stderr}"
    );
    assert!(!stdout.contains("ran engine install"), "{stdout}");
}

/// A release carrying no archive for this target is exit 1, naming the asset.
#[test]
fn a_release_carrying_no_asset_for_this_target_is_exit_1_naming_it() {
    let dir = scratch("install-web-noasset");
    let archive = tarball(&dir);
    let web = host(|base| {
        let mut routes = release_routes(base, &archive);
        routes.truncate(SUMS + 1);
        routes
    });

    let (code, stdout, stderr) = install("install-web-noasset-run", &web, &[]);
    assert_eq!(code, Some(1), "{stdout}{stderr}");
    assert!(
        stderr.contains(&format!("batten-{TAG}-")) && stderr.contains(".tar.gz: 404"),
        "the refusal names the asset and the status: {stderr}"
    );
    assert!(!stdout.contains("ran engine install"), "{stdout}");
}

/// A `main` that pins no release is refused, and the latest release is never
/// asked for in its place (CLOUD-2033).
#[test]
fn a_main_pinning_no_release_is_refused_never_latest() {
    let dir = scratch("install-web-nopin");
    let archive = tarball(&dir);
    let (web, log) = logged_host(|base| {
        let mut routes = release_routes(base, &archive);
        routes[0].body = b"version = 1\n".to_vec();
        routes
    });

    let (code, stdout, stderr) = install("install-web-nopin-run", &web, &[]);
    assert_eq!(code, Some(1), "{stdout}{stderr}");
    assert!(stderr.contains("pins no release"), "{stderr}");
    assert_eq!(
        requests(&log, &format!("/{REPO}/releases/latest")),
        0,
        "the latest release is never asked for"
    );
    assert!(!stdout.contains("ran engine install"), "{stdout}");
}

/// The pin of the `batten.toml` above the working directory wins over
/// `main`'s: a consumer gets the release their repository pins (CLOUD-2033).
#[test]
fn install_installs_the_consumers_pin() {
    let dir = scratch("install-web-consumer");
    let archive = tarball(&dir);
    let (web, log) = logged_host(|base| {
        let mut routes = release_routes(base, &archive);
        // main pins something else, which must not be read.
        routes[0] = pin_route("main", "v0.0.1");
        routes
    });

    let pinned = format!("version = 1\nengine = {{ release = \"{TAG}\" }}\n");
    let (code, stdout, stderr) = install_in("install-web-consumer-run", &pinned, &web, &[]);
    assert_eq!(code, Some(0), "{stdout}{stderr}");
    assert!(stdout.contains("ran engine install"), "{stdout}");
    assert_eq!(
        requests(&log, &format!("/{REPO}/main/batten.toml")),
        0,
        "a consumer's pin is read before main's"
    );
}

/// `BATTEN_VERSION_FROM_REF` installs the release that ref's `batten.toml`
/// pins — the CI guard's property (CLOUD-420) — over the working directory's.
#[test]
fn a_ref_installs_the_release_its_batten_toml_pins() {
    let dir = scratch("install-web-ref");
    let archive = tarball(&dir);
    let web = host(|base| {
        let mut routes = release_routes(base, &archive);
        routes[0] = pin_route("trunk", TAG);
        routes
    });

    let (code, stdout, stderr) = install_in(
        "install-web-ref-run",
        "version = 1\nengine = { release = \"v0.0.1\" }\n",
        &web,
        &[("BATTEN_VERSION_FROM_REF", "trunk")],
    );
    assert_eq!(code, Some(0), "{stdout}{stderr}");
    assert!(stdout.contains("ran engine install"), "{stdout}");
}

/// A transient answer is retried, a bounded number of times, and then reported
/// as could-not-look rather than looping or hanging.
#[test]
fn the_retry_is_bounded_and_reports_rather_than_looping() {
    let dir = scratch("install-web-retry");
    let archive = tarball(&dir);
    let (web, log) = logged_host(|base| {
        let mut routes = release_routes(base, &archive);
        routes[SUMS].status = 503;
        routes
    });

    let (code, stdout, stderr) = install("install-web-retry-run", &web, &[]);
    assert_eq!(code, Some(2), "{stdout}{stderr}");
    assert!(stderr.contains("SHA256SUMS: 503"), "{stderr}");
    assert_eq!(
        requests(&log, &format!("/{REPO}/releases/download/{TAG}/SHA256SUMS")),
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

    let (code, stdout, stderr) = install("install-web-platform-run", &web, &[("PATH", &path)]);
    assert_eq!(code, Some(1), "{stdout}{stderr}");
    assert!(stderr.contains("no release for Linux/riscv64"), "{stderr}");
    assert!(log.lock().unwrap().is_empty(), "no request is made");
}

/// A web host that serves nothing is "could not look" (2), never a broken
/// release (1). This is the private-repository shape.
#[test]
fn a_web_host_that_serves_nothing_is_could_not_look() {
    let web = host(|_| Vec::new());
    let (code, stdout, stderr) = install("install-web-404", &web, &[]);
    assert_eq!(
        code,
        Some(2),
        "an unreadable release is environment, not a bad release: {stdout}{stderr}"
    );
    assert!(stderr.contains("main/batten.toml: 404"), "{stderr}");
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
        let (code, stdout, stderr) = install(&format!("install-web-ca-{name}"), &web, &env);
        assert_eq!(code, Some(want), "{name}: {stdout}{stderr}");
        assert_eq!(
            stdout.contains("ran engine install"),
            want == 0,
            "{name}: {stdout}{stderr}"
        );
    }
}
