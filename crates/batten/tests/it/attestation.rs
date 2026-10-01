//! A release's attestation over the compiled binary: the `supply-chain` preset's
//! `attestation-is-verified.rego` and the engine's own producer, `batten record
//! attestation` (CLOUD-583, CLOUD-1717, CLOUD-843).
//!
//! # Why this tier and not the module's own `test_` rules
//!
//! Every case in the module fabricates its input with `with input as`, which
//! cannot see a fact the engine never projects. These cases run the vendored
//! module over a record the real verb wrote, in a consumer that is NOT this
//! repository and declares no `[[verdict]]` row: a preset ships its own classes,
//! and a harness supplying them would pass for the wrong reason.
//!
//! # The producer, against a fixture forge and a stub verifier
//!
//! The probe and the latest-release read go through `rest`'s
//! `BATTEN_REST_FIXTURE` seam, so the URL that went out is an assertion. The
//! download and the verification are the VERIFIER's, reached by name on `PATH`;
//! the stub planted there copies real `.tar.gz` archives this tier builds and
//! "verifies" a binary whose bytes carry a marker — the property under test is
//! which verdict the engine records for which archive, never sigstore.
//!
//! # RETIREMENT LEDGER, PER PATH — what `shell retire partial` reads
//!
//! `[tasks.attestation-record]` retired under CLOUD-843 onto `batten record
//! attestation`; its `--precondition` mode is `release check unread`'s own argv
//! now (`mise exec -- gh --version`), the one fact that mode ever asserted.
//!
// carried: mise-tasks/attestation-check.sh crates/batten/src/policy/presets/supply-chain/attestation-is-verified.rego crates/batten/tests/it/attestation.rs
// carried: tests/attestation-check.bats crates/batten/src/policy/presets/supply-chain/attestation-is-verified.rego crates/batten/tests/it/attestation.rs
// carried: "THE GAP IS NOT A VERDICT: a 404 endpoint reports the platform gap and exits 0" crates/batten/src/policy/presets/supply-chain/attestation-is-verified.rego
// carried: "with the platform available and provenance present, the run passes" crates/batten/src/policy/presets/supply-chain/attestation-is-verified.rego
// carried: "with the platform available and provenance absent, the run fails" crates/batten/src/policy/presets/supply-chain/attestation-is-verified.rego
// carried: "THE SUBJECT IS THE BINARY, NOT THE ARCHIVE" crates/batten/src/attestation.rs kind:verb crates/batten/tests/it/attestation.rs
// carried: "a release carrying no archive is exit 2, not a green verdict about nothing" crates/batten/src/policy/presets/supply-chain/attestation-is-verified.rego
// carried: "output is pointer-only — no attestation body reaches the log" crates/batten/src/policy/presets/supply-chain/attestation-is-verified.rego
// changed: "the gap names the repository it asked about, derived from the remote" crates/batten/src/attestation.rs kind:verb the slug is the producer's to derive (`GH_REPO`, then the remote) and the request that went out names it — asserted on the fixture's request log rather than on prose, because a module naming a repository would be a consumer identifier inside a decision surface
// changed: "a download that fails is exit 2 — could not look is not a verdict" crates/batten/src/attestation.rs kind:verb the engine's could-not-look is exit 3 at `record attestation`, which also removes any stale record, and the preset then says nothing
// changed: "a status that is neither 200 nor 404 is exit 2, naming the code" crates/batten/src/attestation.rs kind:verb exit 3, naming the code on stderr, and the stale record removed
// changed: "a missing credential IS exit 2 in the world half — a 404 could not be told from a denial" crates/batten/src/attestation.rs kind:verb exit 3 before anything is asked; the credential is the one `[forge] credential_names` declares, because the probe is a REST read now
// changed: "no github.com remote is exit 2 in the world half, and irrelevant to the precondition" crates/batten/src/attestation.rs kind:verb exit 3 when no remote names a repository; the precondition is a separate row and reads no remote at all
// changed: "the precondition holds when the verifier resolves" batten.toml `release check unread` checks `mise exec -- gh --version`: the verifier resolving through the pin is the one fact the precondition mode asserted, and it is that fact's own argv now
// changed: "THE SEVERITY SPLIT: the precondition holds while the platform gap is open" batten.toml the split is two rows still — the precondition at `deny` on every gate invocation, offline; the platform gap a `posture 404` record the preset reads as no verdict
// changed: "the precondition makes no network call" batten.toml `gh --version` reads nothing but the binary, which is the property that keeps a `deny` row safe on every gate invocation
// changed: "an absent verifier is exit 2 in precondition mode" batten.toml a `command` row whose check cannot run refuses, which is the same deny the mode spelled as exit 2
// changed: "a missing credential does NOT fail the precondition — cannot-look is not a deny" batten.toml `gh --version` reads no credential at all, so its absence cannot fail the row

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::{Path, PathBuf};
use std::process::Output;

use common::{Fixture, run, run_with_stdin, stderr, stdout};

/// The repository every case names — deliberately not this one.
///
/// `unix` like its every reader: the cases that name it drive the stub verifier,
/// which is unix-only (the `test cover unseen` waiver on this file says why), so
/// on Windows it would be dead code and `-D warnings` refuses it.
#[cfg(unix)]
const REPO: &str = "acme/widgets";

/// The variable the consumer declares its forge credential under.
const TOKEN: &str = "ATTESTATION_CASE_TOKEN";

/// A consumer enabling the preset, with the attestation family declared and a
/// credential name of its own. No `[[verdict]]` row: the classes are vendored.
fn config() -> String {
    format!(
        r#"version = 1
scope = ["**"]

[[rule]]
id = "release grade unsafe"
kind = "policy"
scope = "tree"
preset = "supply-chain"
severity = "deny"

[[record]]
record = "attestation"
writer = "batten record attestation --binary tool"

[forge]
credential_names = ["{TOKEN}"]
"#
    )
}

fn repo(name: &str) -> PathBuf {
    Fixture::new(&format!("attestation-{name}"))
        .config(&config())
        .file("src/lib.rs", "fn main() {}\n")
        .git()
        .base_commit()
        .build()
}

/// Write the producer's record directly, for the cases about the DECISION.
fn record(dir: &Path, lines: &str) {
    let written = run_with_stdin(dir, &["record", "named", "attestation"], lines);
    assert!(
        written.status.success(),
        "the setup write lands: {}",
        stderr(&written)
    );
}

/// Both streams: which one carries a finding is the output contract's business,
/// and what these cases assert is that the pointer reaches the reader.
fn said(out: &Output) -> String {
    format!("{}{}", stdout(out), stderr(out))
}

fn check(dir: &Path) -> Output {
    run(dir, &["check", "--rule", "release grade unsafe"])
}

// --- the decision, over the engine's projection -------------------------------

#[test]
fn an_unverified_archive_is_reported_over_the_engines_projection() {
    let dir = repo("unverified");
    record(
        &dir,
        "posture\t200\narchive\ttool-x86_64.tar.gz\tunverified\n",
    );

    let decided = check(&dir);
    assert_eq!(decided.status.code(), Some(2), "{}", said(&decided));
    assert!(
        said(&decided).contains("tool-x86_64.tar.gz"),
        "and the finding names the archive\n{}",
        said(&decided)
    );
}

#[test]
fn a_verified_archive_is_clean() {
    let dir = repo("verified");
    record(
        &dir,
        "posture\t200\narchive\ttool-x86_64.tar.gz\tverified\n",
    );

    let quiet = check(&dir);
    assert_eq!(quiet.status.code(), Some(0), "{}", said(&quiet));
}

#[test]
fn a_platform_gap_judges_nothing_even_with_archives_recorded() {
    // THE GAP IS NOT A VERDICT (CLOUD-585): with the endpoint answering 404 the
    // verifier refuses everything, so judging here would red every release for a
    // reason no branch causes.
    let dir = repo("gap");
    record(
        &dir,
        "posture\t404\narchive\ttool-x86_64.tar.gz\tunverified\n",
    );

    let quiet = check(&dir);
    assert_eq!(quiet.status.code(), Some(0), "{}", said(&quiet));
}

#[test]
fn an_absent_record_says_nothing_rather_than_passing() {
    let dir = repo("absent");
    let quiet = check(&dir);
    assert_eq!(quiet.status.code(), Some(0), "{}", said(&quiet));
}

#[test]
fn a_tag_carrying_no_archive_is_refused_rather_than_read_as_clean() {
    // "A green verdict would be about nothing." Present-and-empty and absent are
    // different readings.
    let dir = repo("empty");
    record(&dir, "posture\t200\n");

    let refused = check(&dir);
    assert_eq!(refused.status.code(), Some(2), "{}", said(&refused));
}

#[test]
fn the_report_names_the_archive_and_carries_no_attestation_body() {
    let dir = repo("pointer");
    record(
        &dir,
        "posture\t200\narchive\ttool-aarch64.tar.gz\tno-binary\n",
    );

    let refused = check(&dir);
    let text = said(&refused);
    assert!(text.contains("tool-aarch64.tar.gz"), "{text}");
    assert!(!text.contains("sha256:"), "{text}");
}

// --- the producer, over a fixture forge and a stub verifier -------------------

/// One canned response in the fixture's `-i` shape.
#[cfg(unix)]
fn respond(forge: &Path, n: u32, status: u16, body: &str) {
    std::fs::write(
        forge.join(format!("resp.{n}")),
        format!("HTTP/2 {status}\ncontent-type: application/json\n\n{body}\n"),
    )
    .expect("write the canned answer");
}

/// What the fixture forge recorded about the requests that went out.
#[cfg(unix)]
fn requests(forge: &Path) -> String {
    std::fs::read_to_string(forge.join("args")).unwrap_or_default()
}

/// A gzipped tarball at `path` carrying `entries` as `(path, bytes)`.
#[cfg(unix)]
fn tarball(path: &Path, entries: &[(&str, &[u8])]) {
    let file = std::fs::File::create(path).expect("create the archive");
    let encoder = flate2::write::GzEncoder::new(file, flate2::Compression::default());
    let mut builder = tar::Builder::new(encoder);
    for (name, bytes) in entries {
        let mut header = tar::Header::new_gnu();
        header.set_size(bytes.len() as u64);
        header.set_mode(0o755);
        header.set_cksum();
        builder
            .append_data(&mut header, name, *bytes)
            .expect("append an entry");
    }
    builder
        .into_inner()
        .expect("finish the tar stream")
        .finish()
        .expect("finish the gzip stream");
}

/// The stub verifier: `release download` copies the case's assets into
/// `--dir` — and fails, as a real download does, when there is nothing to copy —
/// and `attestation verify` passes a binary whose bytes say so. Every call is
/// logged, so a case can assert which were made.
#[cfg(unix)]
const STUB: &str = r#"#!/bin/sh
echo "$*" >> "$STUB_LOG"
case "$1 $2" in
"release download")
  dir=""
  while [ $# -gt 0 ]; do
    [ "$1" = "--dir" ] && dir="$2"
    shift
  done
  mkdir -p "$dir" && cp "$STUB_ASSETS"/* "$dir"/
  ;;
"attestation verify")
  grep -q ATTESTED "$3"
  ;;
*)
  exit 64
  ;;
esac
"#;

/// One producer run's world: the consumer, the fixture forge, the stub's `bin`
/// and the assets the stub will "download".
#[cfg(unix)]
struct World {
    dir: PathBuf,
    forge: PathBuf,
    bin: PathBuf,
    assets: PathBuf,
}

#[cfg(unix)]
fn world(name: &str) -> World {
    use std::os::unix::fs::PermissionsExt as _;

    let dir = repo(name);
    let forge = common::scratch(&format!("attestation-{name}-forge"));
    let bin = common::scratch(&format!("attestation-{name}-bin"));
    let assets = common::scratch(&format!("attestation-{name}-assets"));
    let stub = bin.join("gh");
    std::fs::write(&stub, STUB).expect("plant the stub verifier");
    std::fs::set_permissions(&stub, std::fs::Permissions::from_mode(0o755))
        .expect("make the stub executable");
    World {
        dir,
        forge,
        bin,
        assets,
    }
}

#[cfg(unix)]
impl World {
    fn log(&self) -> PathBuf {
        self.forge.join("stub.log")
    }

    /// `batten record attestation <args>` against the fixture forge and stub.
    fn produce(&self, args: &[&str], credential: bool) -> Output {
        let inherited = std::env::var_os("PATH").unwrap_or_default();
        let path = std::env::join_paths(
            std::iter::once(self.bin.clone()).chain(std::env::split_paths(&inherited)),
        )
        .expect("a PATH entry carries no separator");
        let mut command = common::batten();
        command
            .args(["record", "attestation"])
            .args(args)
            .current_dir(&self.dir)
            .env("PATH", path)
            .env("GH_REPO", REPO)
            .env("BATTEN_REST_FIXTURE", &self.forge)
            .env("STUB_LOG", self.log())
            .env("STUB_ASSETS", &self.assets)
            .env_remove(TOKEN);
        if credential {
            command.env(TOKEN, "a-token-the-fixture-never-checks");
        }
        command.output().expect("the compiled binary runs")
    }

    fn stub_calls(&self) -> String {
        std::fs::read_to_string(self.log()).unwrap_or_default()
    }
}

#[cfg(unix)]
#[test]
fn the_producer_records_an_archive_the_verifier_refuses() {
    // THE SUBJECT IS THE BINARY, NOT THE ARCHIVE, nested however deep, and each
    // archive gets the verdict ITS binary earned.
    let world = world("produce-refused");
    respond(&world.forge, 1, 200, "[]");
    tarball(
        &world.assets.join("tool-x86_64.tar.gz"),
        &[("tool-1.0/tool", &b"ELF ATTESTED"[..])],
    );
    tarball(
        &world.assets.join("tool-aarch64.tar.gz"),
        &[("tool-1.0/tool", &b"ELF forged"[..])],
    );

    let produced = world.produce(&["v1.2.3", "--binary", "tool"], true);
    assert_eq!(produced.status.code(), Some(0), "{}", said(&produced));
    assert!(produced.stdout.is_empty(), "silent on success");
    assert!(
        requests(&world.forge).contains(&format!(
            "repos/{REPO}/attestations/sha256:{}",
            "0".repeat(64)
        )),
        "the probe asks about the repository with the zero digest\n{}",
        requests(&world.forge)
    );
    assert!(
        world
            .stub_calls()
            .contains(&format!("release download v1.2.3 --repo {REPO}")),
        "{}",
        world.stub_calls()
    );

    let decided = check(&world.dir);
    assert_eq!(decided.status.code(), Some(2), "{}", said(&decided));
    assert!(
        said(&decided).contains("tool-aarch64.tar.gz"),
        "{}",
        said(&decided)
    );
    assert!(
        !said(&decided).contains("tool-x86_64.tar.gz"),
        "the verified archive is not named\n{}",
        said(&decided)
    );
}

#[cfg(unix)]
#[test]
fn an_archive_carrying_no_binary_is_recorded_as_such() {
    let world = world("produce-no-binary");
    respond(&world.forge, 1, 200, "[]");
    tarball(
        &world.assets.join("tool-x86_64.tar.gz"),
        &[("README", &b"read me"[..])],
    );

    let produced = world.produce(&["v1.2.3", "--binary", "tool"], true);
    assert_eq!(produced.status.code(), Some(0), "{}", said(&produced));
    assert!(
        !world.stub_calls().contains("attestation verify"),
        "nothing to verify, so the verifier is never asked\n{}",
        world.stub_calls()
    );
    let decided = check(&world.dir);
    assert_eq!(decided.status.code(), Some(2), "{}", said(&decided));
    assert!(
        said(&decided).contains("tool-x86_64.tar.gz"),
        "{}",
        said(&decided)
    );
}

#[cfg(unix)]
#[test]
fn a_platform_gap_is_recorded_as_a_gap_and_judges_nothing() {
    let world = world("produce-gap");
    respond(&world.forge, 1, 404, r#"{"message": "Not Found"}"#);

    let produced = world.produce(&["v1.2.3", "--binary", "tool"], true);
    assert_eq!(produced.status.code(), Some(0), "{}", said(&produced));
    assert_eq!(
        world.stub_calls(),
        "",
        "a gap downloads and verifies nothing"
    );
    // A recorded gap is PRESENT and judges nothing; the next case's stale-record
    // arm is what tells it apart from no record.
    let quiet = check(&world.dir);
    assert_eq!(quiet.status.code(), Some(0), "{}", said(&quiet));
}

#[cfg(unix)]
#[test]
fn no_credential_is_could_not_look_and_removes_a_stale_record() {
    let world = world("produce-no-credential");
    record(
        &world.dir,
        "posture\t200\narchive\ttool-x86_64.tar.gz\tunverified\n",
    );
    respond(&world.forge, 1, 404, "{}");

    let refused = world.produce(&["v1.2.3", "--binary", "tool"], false);
    assert_eq!(refused.status.code(), Some(3), "{}", said(&refused));
    assert!(
        stderr(&refused).contains("could not look"),
        "{}",
        said(&refused)
    );
    assert_eq!(
        requests(&world.forge),
        "",
        "nothing is asked without a credential: a 404 could not be told from a denial"
    );
    let quiet = check(&world.dir);
    assert_eq!(
        quiet.status.code(),
        Some(0),
        "the stale refusal went with the record\n{}",
        said(&quiet)
    );
}

#[cfg(unix)]
#[test]
fn a_status_neither_200_nor_404_is_could_not_look_naming_the_code() {
    let world = world("produce-500");
    respond(&world.forge, 1, 500, "{}");

    let refused = world.produce(&["v1.2.3", "--binary", "tool"], true);
    assert_eq!(refused.status.code(), Some(3), "{}", said(&refused));
    assert!(stderr(&refused).contains("500"), "{}", said(&refused));
    assert_eq!(world.stub_calls(), "", "nothing downloaded");
}

#[cfg(unix)]
#[test]
fn no_tag_falls_back_to_the_latest_release() {
    let world = world("produce-latest");
    respond(&world.forge, 1, 200, "[]");
    respond(&world.forge, 2, 200, r#"{"tag_name": "v7.7.7"}"#);
    tarball(
        &world.assets.join("tool-x86_64.tar.gz"),
        &[("tool", &b"ELF ATTESTED"[..])],
    );

    let produced = world.produce(&["--binary", "tool"], true);
    assert_eq!(produced.status.code(), Some(0), "{}", said(&produced));
    assert!(
        requests(&world.forge).contains(&format!("repos/{REPO}/releases/latest")),
        "{}",
        requests(&world.forge)
    );
    assert!(
        world.stub_calls().contains("release download v7.7.7"),
        "{}",
        world.stub_calls()
    );
    let quiet = check(&world.dir);
    assert_eq!(quiet.status.code(), Some(0), "{}", said(&quiet));
}

#[cfg(unix)]
#[test]
fn a_download_that_fails_is_could_not_look() {
    // No assets to copy, so the stub's download fails the way a real one does,
    // and a stale refusal must not outlive it.
    let world = world("produce-download-fails");
    record(
        &world.dir,
        "posture\t200\narchive\ttool-x86_64.tar.gz\tunverified\n",
    );
    respond(&world.forge, 1, 200, "[]");

    let refused = world.produce(&["v1.2.3", "--binary", "tool"], true);
    assert_eq!(refused.status.code(), Some(3), "{}", said(&refused));
    assert!(
        stderr(&refused).contains("could not look"),
        "{}",
        said(&refused)
    );
    let quiet = check(&world.dir);
    assert_eq!(quiet.status.code(), Some(0), "{}", said(&quiet));
}

#[cfg(unix)]
#[test]
fn an_archive_that_will_not_unpack_is_could_not_look_never_no_binary() {
    // The retired body once discarded the unpack's status and wrote `no-binary`
    // over a corrupt archive — a RELEASE verdict where the honest reading is
    // could-not-look.
    let world = world("produce-corrupt");
    respond(&world.forge, 1, 200, "[]");
    std::fs::write(
        world.assets.join("tool-x86_64.tar.gz"),
        b"not a gzip stream",
    )
    .expect("write the corrupt archive");

    let refused = world.produce(&["v1.2.3", "--binary", "tool"], true);
    assert_eq!(refused.status.code(), Some(3), "{}", said(&refused));
    let quiet = check(&world.dir);
    assert_eq!(quiet.status.code(), Some(0), "{}", said(&quiet));
}

#[test]
fn a_binary_name_that_is_not_one_path_component_is_a_usage_error() {
    let dir = repo("produce-bad-binary");
    let refused = run(&dir, &["record", "attestation", "--binary", "../tool"]);
    assert_eq!(refused.status.code(), Some(1), "{}", said(&refused));
}
