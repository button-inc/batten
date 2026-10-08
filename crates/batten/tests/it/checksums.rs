//! `batten release sums` — CLOUD-278's release manifest, over the compiled binary
//! and a fixture forge (CLOUD-1717, CLOUD-843).
//!
//! The body moved whole into `mise.toml` under CLOUD-1717 and off it onto the
//! engine under CLOUD-843: an effect with no decision in it, so there is still
//! nothing for a module to take. This tier runs the verb the task declares
//! against `BATTEN_REST_FIXTURE`, which serves a release's metadata and each
//! asset's bytes by endpoint. The properties are the ones a packager depends on:
//! `sha256sum -c` reads the manifest with no flags, two runs are identical bytes,
//! it never hashes itself, and it is never written empty.
//!
//! # RETIREMENT LEDGER, PER PATH — what `shell retire partial` reads
//!
// carried: mise-tasks/checksums.sh crates/batten/src/release.rs kind:verb crates/batten/tests/it/checksums.rs
// carried: tests/checksums.bats crates/batten/src/release.rs kind:verb crates/batten/tests/it/checksums.rs
// carried: "--names answers with no tag, no network and no download" crates/batten/src/release.rs kind:verb
// carried: "the manifest covers every asset the release carries" crates/batten/src/release.rs kind:verb
// carried: "the manifest never lists itself" crates/batten/src/release.rs kind:verb
// carried: "two runs over one release produce identical bytes" crates/batten/src/release.rs kind:verb
// carried: "sha256sum -c accepts the manifest with no flags, in a directory of assets" crates/batten/src/release.rs kind:verb
// carried: "corrupting one byte of one asset makes that check fail" crates/batten/src/release.rs kind:verb
// changed: "a release carrying no assets writes no manifest" crates/batten/src/release.rs kind:verb nothing is written, as before, and the exit is 3 rather than 1: under the engine's table 1 is a malformed invocation, and a release with nothing to hash is the world not answering, which is could-not-look
// changed: "an unreadable release exits 2, not 1" crates/batten/src/release.rs kind:verb could-not-look is the engine's 3; the distinction the case protects — lookup failure is not a refusal — is carried exactly
// carried: "checksums.bats::no tag given falls back to the latest release" crates/batten/src/release.rs kind:verb
// carried: "an EMPTY tag argument falls back too, which is what the workflow passes" crates/batten/src/release.rs kind:verb
// changed: "no tag resolvable exits 2 rather than hashing nothing" crates/batten/src/release.rs kind:verb the same move to the engine's could-not-look code, 3, with nothing written

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::fmt::Write as _;

use std::path::{Path, PathBuf};
use std::process::Output;

use common::{scratch, stderr, stdout, write};

/// The repository a case names — deliberately not this one.
const REPO: &str = "acme/widgets";

/// The manifest's name, as `[env]` declares it for the task.
fn manifest_name() -> String {
    common::task_env("BATTEN_CHECKSUM_MANIFEST")
}

/// A fixture forge serving one release: its metadata by tag or as the latest,
/// and each asset's bytes by id. Ids start at 10 so no route's needle is a
/// prefix of another's.
fn serve(forge: &Path, tag: &str, assets: &[(String, String)]) {
    let listing: Vec<serde_json::Value> = assets
        .iter()
        .enumerate()
        .map(|(index, (name, _))| serde_json::json!({"id": 10 + index, "name": name}))
        .collect();
    let body = serde_json::json!({"tag_name": tag, "assets": listing}).to_string();
    write(
        forge,
        "release",
        &format!("HTTP/2 200\ncontent-type: application/json\n\n{body}\n"),
    );
    let mut routes = String::from("/releases/tags/\trelease\n/releases/latest\trelease\n");
    for (index, (_, bytes)) in assets.iter().enumerate() {
        let file = format!("asset.{}", 10 + index);
        write(
            forge,
            &file,
            &format!("HTTP/2 200\ncontent-type: application/octet-stream\n\n{bytes}"),
        );
        writeln!(routes, "/releases/assets/{}\t{file}", 10 + index)
            .expect("a String takes a write");
    }
    write(forge, "routes", &routes);
}

/// A working directory and a fixture forge serving `assets` on `v9.9.9`.
fn bench(name: &str, assets: &[&str]) -> (PathBuf, PathBuf) {
    let dir = common::scratch_repo(&format!("checksums-{name}"));
    let forge = scratch(&format!("checksums-{name}-forge"));
    let served: Vec<(String, String)> = assets
        .iter()
        .map(|asset| ((*asset).to_owned(), format!("bytes of {asset}\n")))
        .collect();
    serve(&forge, "v9.9.9", &served);
    (dir, forge)
}

/// `batten release sums [tag] --manifest <name> --out-dir out` in `dir`.
fn run_sums(dir: &Path, forge: &Path, extra: &[&str]) -> Output {
    let manifest = manifest_name();
    let out = dir.join("out");
    let mut args = vec!["release", "sums"];
    args.extend_from_slice(extra);
    args.extend(["--manifest", manifest.as_str(), "--out-dir"]);
    common::batten()
        .args(&args)
        .arg(&out)
        .env("GH_REPO", REPO)
        .env("BATTEN_REST_FIXTURE", forge)
        .current_dir(dir)
        .output()
        .expect("the compiled binary runs")
}

fn sums(dir: &Path) -> String {
    std::fs::read_to_string(dir.join("out").join(manifest_name())).unwrap_or_default()
}

fn requests(forge: &Path) -> String {
    std::fs::read_to_string(forge.join("args")).unwrap_or_default()
}

const RELEASE: &[&str] = &[
    "batten-9.9.9-x86_64-unknown-linux-gnu.tar.gz",
    "batten-9.9.9-aarch64-apple-darwin.tar.gz",
    "batten.schema.json",
];

#[test]
fn the_committed_task_is_the_verb_and_carries_no_shell() {
    let block = common::task_block("checksums").expect("[tasks.checksums]");
    let run = common::task_value(&block, "run");
    assert!(run.contains("release sums"), "{run}");
    assert!(
        run.contains("{{env.BATTEN_CHECKSUM_MANIFEST}}"),
        "one declaration of the name: {run}"
    );
    assert!(!block.contains("'''"), "no body: {block}");
}

#[test]
fn names_answers_with_no_tag_no_network_and_no_download() {
    let (dir, forge) = bench("names", RELEASE);
    let out = run_sums(&dir, &forge, &["--names"]);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert!(stdout(&out).starts_with("sums="), "{}", stdout(&out));
    assert!(!dir.join("out").exists(), "nothing written");
    assert!(requests(&forge).is_empty(), "nothing asked of the forge");
}

#[test]
fn the_manifest_covers_every_asset_never_itself_and_is_byte_stable() {
    // A manifest already on the release must not be hashed into the next one.
    let manifest = manifest_name();
    let mut assets: Vec<&str> = RELEASE.to_vec();
    assets.push(manifest.as_str());
    let (dir, forge) = bench("covers", &assets);
    let first_run = run_sums(&dir, &forge, &["v9.9.9"]);
    assert_eq!(first_run.status.code(), Some(0), "{}", stderr(&first_run));
    assert_eq!(
        stdout(&first_run).lines().count(),
        1,
        "stdout is the one output line: {}",
        stdout(&first_run)
    );
    let first = sums(&dir);
    for asset in RELEASE {
        assert!(first.contains(asset), "{asset} in {first}");
    }
    assert!(!first.contains(&manifest), "never lists itself: {first}");
    assert_eq!(run_sums(&dir, &forge, &["v9.9.9"]).status.code(), Some(0));
    assert_eq!(first, sums(&dir), "two runs, identical bytes");
}

#[test]
fn sha256sum_accepts_the_manifest_and_a_corrupted_asset_fails_it() {
    let (dir, forge) = bench("verify", RELEASE);
    assert_eq!(run_sums(&dir, &forge, &["v9.9.9"]).status.code(), Some(0));
    let release = dir.join("release");
    for asset in RELEASE {
        write(&release, asset, &format!("bytes of {asset}\n"));
    }
    std::fs::copy(
        dir.join("out").join(manifest_name()),
        release.join(manifest_name()),
    )
    .expect("copy");
    assert!(sums_hold(&release), "every line verifies as written");
    write(&release, RELEASE[0], "tampered\n");
    assert!(!sums_hold(&release), "one corrupt byte fails the check");
}

/// What `sha256sum -c` decides, in-process: every line is `<64 hex>  <name>`
/// and the hex is the named file's digest.
fn sums_hold(release: &Path) -> bool {
    use sha2::Digest as _;
    let manifest = std::fs::read_to_string(release.join(manifest_name())).expect("the manifest");
    manifest.lines().all(|line| {
        let Some((hex, name)) = line.split_once("  ") else {
            return false;
        };
        let Ok(bytes) = std::fs::read(release.join(name)) else {
            return false;
        };
        let digest: String =
            sha2::Sha256::digest(&bytes)
                .iter()
                .fold(String::new(), |mut hex, b| {
                    use std::fmt::Write as _;
                    let _ = write!(hex, "{b:02x}");
                    hex
                });
        hex.len() == 64 && digest == hex
    }) && !manifest.is_empty()
}

#[test]
fn a_release_with_no_assets_writes_no_manifest() {
    // Nothing but a previous manifest is nothing to hash.
    let manifest = manifest_name();
    let (dir, forge) = bench("empty", &[manifest.as_str()]);
    let out = run_sums(&dir, &forge, &["v9.9.9"]);
    assert_eq!(out.status.code(), Some(3), "{}", stderr(&out));
    assert!(!dir.join("out").join(&manifest).exists());
}

#[test]
fn an_unreadable_asset_is_could_not_look_and_writes_nothing() {
    let (dir, forge) = bench("unreadable", RELEASE);
    write(&forge, "asset.10", "HTTP/2 404\n\n{}");
    let out = run_sums(&dir, &forge, &["v9.9.9"]);
    assert_eq!(out.status.code(), Some(3), "{}", stderr(&out));
    assert!(!dir.join("out").join(manifest_name()).exists());
    assert!(
        !stderr(&out).contains("{}"),
        "rule 4: no body reaches the report: {}",
        stderr(&out)
    );
}

#[test]
fn no_tag_or_an_empty_tag_falls_back_to_the_latest_release() {
    for (name, tag) in [("absent", None), ("empty", Some(""))] {
        let (dir, forge) = bench(&format!("latest-{name}"), RELEASE);
        let extra: Vec<&str> = tag.into_iter().collect();
        let out = run_sums(&dir, &forge, &extra);
        assert_eq!(out.status.code(), Some(0), "{name}: {}", stderr(&out));
        assert!(sums(&dir).contains(RELEASE[0]), "{name}");
        assert!(
            requests(&forge).contains("/releases/latest"),
            "{name}: {}",
            requests(&forge)
        );
    }
}

/// A DRAFT IS READ FROM THE RELEASE LIST (CLOUD-2121). The forge answers 404 for
/// a draft's tag, so the checksums job of a draft-first release died before it
/// could write the manifest, and the publish step after it never ran: v0.0.206
/// stayed a draft while `main` pinned it.
#[test]
fn a_draft_release_is_read_from_the_release_list() {
    let (dir, forge) = bench("draft", RELEASE);
    let listing: Vec<serde_json::Value> = RELEASE
        .iter()
        .enumerate()
        .map(|(index, name)| serde_json::json!({"id": 10 + index, "name": name}))
        .collect();
    let list = serde_json::json!([
        {"tag_name": "v9.9.8", "draft": false, "assets": []},
        {"tag_name": "v9.9.9", "draft": true, "assets": listing},
    ]);
    write(
        &forge,
        "release",
        "HTTP/2 404\n\n{\"message\": \"Not Found\"}",
    );
    write(
        &forge,
        "list",
        &format!("HTTP/2 200\ncontent-type: application/json\n\n{list}\n"),
    );
    let routes = std::fs::read_to_string(forge.join("routes")).expect("the routes exist");
    write(&forge, "routes", &format!("/releases?\tlist\n{routes}"));
    let out = run_sums(&dir, &forge, &["v9.9.9"]);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    for asset in RELEASE {
        assert!(sums(&dir).contains(asset), "{asset} is in the manifest");
    }
}

/// ANTI-VACUITY for the case above: a list that carries no entry for the tag is
/// still could-not-look, so the fallback never invents a release.
#[test]
fn a_tag_neither_read_nor_listed_is_could_not_look() {
    let (dir, forge) = bench("unlisted", RELEASE);
    write(
        &forge,
        "release",
        "HTTP/2 404\n\n{\"message\": \"Not Found\"}",
    );
    write(
        &forge,
        "list",
        "HTTP/2 200\ncontent-type: application/json\n\n[{\"tag_name\": \"v9.9.8\", \"assets\": []}]\n",
    );
    let routes = std::fs::read_to_string(forge.join("routes")).expect("the routes exist");
    write(&forge, "routes", &format!("/releases?\tlist\n{routes}"));
    let out = run_sums(&dir, &forge, &["v9.9.9"]);
    assert_eq!(out.status.code(), Some(3), "{}", stderr(&out));
    assert!(!dir.join("out").join(manifest_name()).exists());
}

/// A DRAFT FIRES NOTHING, SO THE ARTIFACTS ARE DISPATCHED (CLOUD-2121). GitHub
/// triggers no workflow on `created` for a draft release, so a `release:` trigger
/// here never ran for v0.0.206 and the draft was never built or published.
#[test]
fn the_release_artifacts_run_only_by_dispatch() {
    use yaml_rust2::YamlLoader;
    let text = std::fs::read_to_string(common::at_root(".github/workflows/release-artifacts.yml"))
        .expect("the release artifacts workflow");
    let docs = YamlLoader::load_from_str(&text).expect("the workflow parses as YAML");
    let on = docs[0]["on"].as_hash().expect("an `on:` map");
    let triggers: Vec<&str> = on.keys().filter_map(|key| key.as_str()).collect();
    assert_eq!(triggers, ["workflow_dispatch"], "{triggers:?}");
    assert!(
        !text.contains("github.event.release"),
        "no expression reads a release event that never arrives"
    );
}

/// The other half: the job that tags the release dispatches the artifacts for
/// the tag it shipped, after resolving it, and only when it shipped one.
#[test]
fn the_release_job_dispatches_the_artifacts_for_the_tag_it_shipped() {
    use yaml_rust2::{Yaml, YamlLoader};
    let text = std::fs::read_to_string(common::at_root(".github/workflows/release-plz.yml"))
        .expect("the release workflow");
    let docs = YamlLoader::load_from_str(&text).expect("the workflow parses as YAML");
    let job = &docs[0]["jobs"]["release-plz"];
    let steps = job["steps"].as_vec().expect("release-plz has steps");
    let field = |step: &Yaml, key: &str| step[key].as_str().unwrap_or_default().to_owned();
    let resolved = steps
        .iter()
        .position(|step| field(step, "id") == "release-tag")
        .expect("a step resolves the shipped tag");
    let dispatch = steps
        .iter()
        .position(|step| field(step, "run").contains("gh workflow run release-artifacts.yml"))
        .expect("a step dispatches release-artifacts");
    assert!(
        dispatch > resolved,
        "the dispatch follows the tag's resolution"
    );
    let step = &steps[dispatch];
    assert_eq!(field(step, "if"), "steps.release-tag.outputs.tag != ''");
    assert!(
        step["env"]["FIELD"]
            .as_str()
            .is_some_and(|value| value == "tag=${{ steps.release-tag.outputs.tag }}"),
        "the dispatch names the shipped tag"
    );
    assert_eq!(
        job["permissions"]["actions"].as_str(),
        Some("write"),
        "the job token may dispatch a workflow"
    );
}

#[test]
fn no_release_resolvable_is_could_not_look_rather_than_hashing_nothing() {
    let (dir, forge) = bench("unresolvable", RELEASE);
    write(
        &forge,
        "release",
        "HTTP/2 404\n\n{\"message\": \"Not Found\"}",
    );
    let out = run_sums(&dir, &forge, &[]);
    assert_eq!(out.status.code(), Some(3), "{}", stderr(&out));
    assert!(!dir.join("out").join(manifest_name()).exists());
}
