//! `install.sh`'s token-free web route, over a loopback release host (CLOUD-205).
//!
//! # Why this tier exists at all
//!
//! `install.sh`'s header has claimed "NO TOKEN IS REQUIRED BY CONSTRUCTION"
//! since it was written and did not hold it: every route ran through
//! `api.github.com`, whose ANONYMOUS budget is 60 an hour per source ADDRESS.
//! On a shared agent-container egress that is exhausted by other tenants, so a
//! container's Setup script died with `cannot read the release list` and named
//! a token the header says is unnecessary. The repair is a second route over
//! the release WEB host, which shares no budget and needs no credential.
//!
//! # Why it is not in `tests/install.bats`
//!
//! That suite is a `.bats` under `tests/`, so `policy/shell-retirement.rego`
//! governs it and an EDIT is refused — the two landable shapes are retire it
//! whole or leave it alone, and neither is what adding a case to it would be.
//! A Rust tier is the shape a new suite takes here anyway
//! (`.claude/rules/toolchain.md`), and it costs that file nothing.
//!
//! **The existing bats suite is still the sensor that caught the design error.**
//! Two of its cases make the fixture API unreadable and require exit 2; the
//! first draft of the fallback reached the real github.com and installed a real
//! binary instead, so the suite's own hermeticity failed it. That is why
//! `BATTEN_API` set without `BATTEN_WEB` switches the fallback OFF, and why the
//! bats file needed no edit: it was right.
//!
//! # A loopback HTTP host rather than a `file://` tree
//!
//! `resolve_via_web` reads the tag off the URL curl ENDED on — the web host
//! answers `…/releases/latest` with a `302` to `…/releases/tag/<tag>`. A
//! `file://` fixture cannot redirect, so it could exercise the download leg and
//! never the resolution leg, which is the half that decides WHICH release gets
//! installed. `provision.rs` stands up loopback listeners for the same reason.
//! Nothing leaves the machine.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
#[expect(
    clippy::disallowed_types,
    reason = "stays, and test-only: the import both spawns below need, annotated at every site the way the other suites in this directory are"
)]
use std::process::Command;
use std::thread;

use common::scratch;

/// The tag the fixture host publishes.
const TAG: &str = "v9.9.9";

/// The archive payload: a `batten` executable at the archive root, which is what
/// `mise-tasks/dist.sh` produces and what the installer requires.
fn tarball(dir: &std::path::Path) -> Vec<u8> {
    let stage = dir.join("stage");
    std::fs::create_dir_all(&stage).unwrap();
    std::fs::write(stage.join("batten"), "#!/bin/sh\necho fixture-batten\n").unwrap();
    let archive = dir.join("payload.tar.gz");
    #[expect(
        clippy::disallowed_types,
        reason = "stays, and test-only: the installer untars what it downloads, so the fixture payload has to be a real gzipped tar and `tar` is what writes one"
    )]
    let status = Command::new("tar")
        .args(["-czf", archive.to_str().unwrap(), "-C", stage.to_str().unwrap(), "batten"])
        .status()
        .expect("run tar");
    assert!(status.success(), "the fixture archive must build");
    std::fs::read(&archive).unwrap()
}

/// sha256 of `bytes` as lowercase hex, through the same helper the engine uses,
/// so a fixture cannot pin a digest the installer would never compute.
fn digest(bytes: &[u8]) -> String {
    batten::provision::digest(bytes)
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
/// Single-threaded and serial by design: the installer makes its requests in
/// order, and a concurrent server would let a missing request pass unnoticed as
/// a timing artefact. Unknown paths answer `404`, which is what a private
/// repository looks like from the web host and is the arm one case below drives.
/// `build` is handed the host's own base URL, because a release host has to name
/// itself in the `Location` it redirects to — binding first and building the
/// routes from the real address is what keeps that from being a guessed port.
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
        None => "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_owned(),
    };
    let _ = stream.write_all(response.as_bytes());
    if let Some(route) = answer
        && route.status == 200
    {
        let _ = stream.write_all(&route.body);
    }
    let _ = stream.flush();
}

/// The four routes a complete release serves.
fn release_routes(base: &str, asset: &str, archive: &[u8]) -> Vec<Route> {
    let sums = format!(
        "{}  {asset}\n{}  batten-{TAG}-aarch64-apple-darwin.tar.gz\n",
        digest(archive),
        "0".repeat(64)
    );
    vec![
        Route {
            path: "/button-inc/batten/releases/latest".to_owned(),
            status: 302,
            location: Some(format!("{base}/button-inc/batten/releases/tag/{TAG}")),
            body: Vec::new(),
        },
        Route {
            path: format!("/button-inc/batten/releases/tag/{TAG}"),
            status: 200,
            location: None,
            body: b"<html>the tag page</html>".to_vec(),
        },
        Route {
            path: format!("/button-inc/batten/releases/download/{TAG}/SHA256SUMS"),
            status: 200,
            location: None,
            body: sums.into_bytes(),
        },
        Route {
            path: format!("/button-inc/batten/releases/download/{TAG}/{asset}"),
            status: 200,
            location: None,
            body: archive.to_vec(),
        },
    ]
}

/// Run `install.sh` against `web`, with the API pointed at a host that answers
/// nothing and EVERY credential unset.
///
/// `BATTEN_API` names an unroutable host rather than being left at its default:
/// the point of each case is that the WEB route did the work, and a default API
/// that happened to answer would let a case pass without the route under test
/// running at all.
fn install(name: &str, web: &str, target: &str) -> (Option<i32>, String, String, PathBuf) {
    let dir = scratch(name);
    let dest = dir.join("bin");
    std::fs::create_dir_all(&dest).unwrap();
    #[expect(
        clippy::disallowed_types,
        reason = "stays, and test-only: the subject of this suite IS a shell program, so there is nothing to assert without running it — the same reason `install.bats` drives it end to end"
    )]
    let out = Command::new("sh")
        .arg(concat!(env!("CARGO_MANIFEST_DIR"), "/../../install.sh"))
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("HOME", dir.to_str().unwrap())
        // The loopback host must not be reached through this container's proxy.
        .env("NO_PROXY", "127.0.0.1,localhost")
        .env("no_proxy", "127.0.0.1,localhost")
        .env("BATTEN_API", "http://127.0.0.1:1")
        .env("BATTEN_WEB", web)
        .env("BATTEN_TARGET", target)
        .env("BATTEN_INSTALL_DIR", &dest)
        .env("BATTEN_ALLOW_OFF_PATH", "1")
        .env("BATTEN_RETRIES", "1")
        .output()
        .expect("run install.sh");
    (
        out.status.code(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
        dest.join("batten"),
    )
}

const TARGET: &str = "x86_64-unknown-linux-musl";

fn asset_name() -> String {
    format!("batten-{TAG}-{TARGET}.tar.gz")
}

/// THE CASE THE DEFECT FAILS. No token, no reachable API — the install still
/// completes, which is the header's claim delivered rather than asserted.
#[test]
fn the_web_route_installs_with_no_token_and_no_api() {
    let dir = scratch("install-web-happy");
    let archive = tarball(&dir);
    let asset = asset_name();
    let web = host(|base| release_routes(base, &asset, &archive));

    let (code, stdout, stderr, installed) = install("install-web-ok", &web, TARGET);
    assert_eq!(code, Some(0), "install failed: {stdout}{stderr}");
    assert!(
        stdout.contains(&format!("version={TAG}")),
        "the tag comes off the redirect, not a payload: {stdout}"
    );
    assert!(
        stdout.contains("verified=sha256"),
        "the digest gate still ran: {stdout}"
    );
    assert!(installed.is_file(), "the binary reached the destination");
}

/// THE DIGEST GATE IS UNCHANGED, and this is the half that proves the web route
/// is a second route rather than a weaker one. A `SHA256SUMS` disagreeing with
/// the bytes is a REFUSAL, and nothing reaches the destination.
#[test]
fn a_sha256sums_that_disagrees_with_the_bytes_installs_nothing() {
    let dir = scratch("install-web-badsum");
    let archive = tarball(&dir);
    let asset = asset_name();
    let web = host(|base| {
        let mut routes = release_routes(base, &asset, &archive);
        // Publish a digest for a payload that is not the one served.
        routes[2].body = format!("{}  {asset}\n", "1".repeat(64)).into_bytes();
        routes
    });

    let (code, stdout, stderr, installed) = install("install-web-bad", &web, TARGET);
    assert_eq!(code, Some(1), "a digest mismatch is a refusal: {stdout}{stderr}");
    assert!(
        !installed.exists(),
        "a refused install must leave the destination empty"
    );
}

/// AN ASSET THE MANIFEST DOES NOT NAME IS A REFUSAL, never an unverified
/// install. `SHA256SUMS` is matched by exact field equality, so a release that
/// simply omits this target's line does not fall through to the next one.
#[test]
fn an_asset_absent_from_sha256sums_installs_nothing() {
    let dir = scratch("install-web-nosum");
    let archive = tarball(&dir);
    let asset = asset_name();
    let web = host(|base| {
        let mut routes = release_routes(base, &asset, &archive);
        routes[2].body = format!("{}  some-other-asset.tar.gz\n", digest(&archive)).into_bytes();
        routes
    });

    let (code, _, _, installed) = install("install-web-nosum-run", &web, TARGET);
    assert_ne!(code, Some(0), "no published digest means no install");
    assert!(!installed.exists(), "nothing may reach the destination");
}

/// A WEB HOST THAT SERVES NOTHING IS "COULD NOT LOOK" (2), never a broken
/// release (1). This is the private-repository shape: the web route 404s and
/// has nothing to say, so the exit class must stay environmental.
#[test]
fn a_web_host_that_serves_nothing_is_could_not_look() {
    let web = host(|_| Vec::new());
    let (code, stdout, stderr, installed) = install("install-web-404", &web, TARGET);
    assert_eq!(
        code,
        Some(2),
        "an unreadable release is environment, not a bad release: {stdout}{stderr}"
    );
    assert!(!installed.exists());
}
