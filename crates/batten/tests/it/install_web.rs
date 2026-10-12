//! The generated `install.sh` (CLOUD-2203), run end to end over a loopback
//! release host.
//!
//! The script is `install::render_bootstrap`'s output and nothing else: detect
//! the target, read the tag off the web host's `latest` redirect (or take
//! `BATTEN_VERSION`), fetch `SHA256SUMS` and the archive from
//! `releases/download`, check the digest, and run `batten engine install`.
//! Everything after the hand-over is Rust and is tested where it lives
//! (`install.rs`, `engine_install.rs`). This tier proves what only the script can:
//! that the tag resolves, that the digest gate refuses bytes the release did not
//! publish, and that a refused download names what answered.
//!
//! # A loopback HTTP host rather than a `file://` tree
//!
//! The tag comes off the URL curl ENDED on — the web host answers
//! `…/releases/latest` with a `302` to `…/releases/tag/<tag>`. A `file://`
//! fixture cannot redirect, so it could exercise the download leg and never the
//! resolution leg, which is the half that decides WHICH release gets installed.
//! Nothing leaves the machine.
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

use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
#[expect(
    clippy::disallowed_types,
    reason = "stays, and test-only: the import both spawns below need, annotated at every site the way the other suites in this directory are"
)]
use std::process::Command;
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
    std::fs::write(stage.join("batten"), "#!/bin/sh\necho \"ran $*\"\n").unwrap();
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
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let base = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
    let routes = build(&base);
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { continue };
            serve(stream, &routes);
        }
    });
    base
}

fn serve(mut stream: TcpStream, routes: &[Route]) {
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
    let answer = routes.iter().find(|route| route.path == path);
    let response = match answer {
        Some(route) if route.status == 302 => format!(
            "HTTP/1.1 302 Found\r\nLocation: {}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            route.location.clone().unwrap_or_default()
        ),
        Some(route) => format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            route.body.len()
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

/// The routes a complete release serves: the `latest` redirect, the tag page,
/// `SHA256SUMS`, and the archive under every bootstrap target's name, so a case
/// passes on whichever host runs it.
fn release_routes(base: &str, archive: &[u8]) -> Vec<Route> {
    let sums: String = batten::install::TARGETS
        .iter()
        .map(|target| format!("{}  {}\n", digest(archive), asset(target)))
        .collect();
    let mut routes = vec![
        Route {
            path: format!("/{REPO}/releases/latest"),
            status: 302,
            location: Some(format!("{base}/{REPO}/releases/tag/{TAG}")),
            body: Vec::new(),
        },
        Route {
            path: format!("/{REPO}/releases/tag/{TAG}"),
            status: 200,
            location: None,
            body: b"<html>the tag page</html>".to_vec(),
        },
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

/// The index of the `SHA256SUMS` route in [`release_routes`].
const SUMS: usize = 2;

/// Run the committed `install.sh` against `web`, with every credential unset.
fn install(name: &str, web: &str, env: &[(&str, &str)]) -> (Option<i32>, String, String) {
    let dir = scratch(name);
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
        .env("BATTEN_RELEASES", format!("{web}/{REPO}"));
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

/// No token, no API: the tag comes off the redirect, the digest gate runs, and
/// the verified binary is handed `engine install`.
#[test]
fn the_web_route_installs_with_no_token_and_no_api() {
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

/// `BATTEN_VERSION` names the tag, so the `latest` redirect is never asked.
#[test]
fn a_named_version_never_asks_for_latest() {
    let dir = scratch("install-web-named");
    let archive = tarball(&dir);
    let web = host(|base| {
        let mut routes = release_routes(base, &archive);
        // Drop the redirect: a script that still asked would fail on the 404.
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
        routes[SUMS].body = batten::install::TARGETS
            .iter()
            .map(|target| format!("{}  {}\n", "1".repeat(64), asset(target)))
            .collect::<String>()
            .into_bytes();
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

/// A release with no `SHA256SUMS` is a download the host refused: exit 2,
/// naming the status and the URL that answered, and nothing is run.
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
    assert_eq!(code, Some(2), "{stdout}{stderr}");
    assert!(
        stderr.contains("SHA256SUMS: 404 http://127.0.0.1:"),
        "a refused download names the status and what answered: {stderr}"
    );
    assert!(!stdout.contains("ran engine install"), "{stdout}");
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
    assert!(stderr.contains("releases/latest: 404"), "{stderr}");
    assert!(!stdout.contains("ran engine install"), "{stdout}");
}
