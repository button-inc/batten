//! `release grade other` and `release pin other` over the compiled binary, the
//! REAL producer and a fixture forge (CLOUD-258, CLOUD-262, CLOUD-278, CLOUD-1717,
//! CLOUD-843).
//!
//! `[tasks.release-assets-record]`'s body retired onto `batten record release`,
//! which reads the release's assets and its manifest's bytes through
//! `BATTEN_REST_FIXTURE` — a directory of REAL bytes routed by endpoint, because
//! the manifest rules hash, and a stub answering names alone would leave half the
//! gate untested. The expected list is derived by `policy/release-assets.rego`
//! from a fixture build workflow the rule row declares as a document, and the
//! manifest's truth by the `release-hygiene` preset. Every case records, then
//! runs both rules the way `mise run release-assets-check` does.
//!
//! The last cases are properties of the COMMITTED workflow rather than of the
//! gate: they pin that the module is pointed at a shape production actually has.
//!
//! # RETIREMENT LEDGER, PER PATH — what `shell retire partial` reads
//!
// carried: mise-tasks/release-assets-check.sh policy/release-assets.rego kind:mechanism crates/batten/tests/it/release_assets.rs
// carried: tests/release-assets-check.bats policy/release-assets.rego kind:mechanism crates/batten/tests/it/release_assets.rs
// carried: "a release carrying every target's archive passes" policy/release-assets.rego kind:mechanism
// changed: "THE DEFECT: a release with only the schema fails, naming every missing target" policy/release-assets.rego the refusal and both named targets are asserted; the `2 of 2 targets` sentence was the program's own prose, and the engine's output is pointer-only, one line per finding, so the count is the number of lines rather than a sentence about them
// changed: "a partial release fails on the missing target and not the present one" policy/release-assets.rego same as the case above: the present target is asserted absent from the findings and the missing one present; the `1 of 2` sentence is not carried because pointer-only output does not print one
// changed: "THE CLOUD-262 GAP: every archive present but no SBOM still fails" policy/release-assets.rego both missing SBOM documents are asserted, and that no archive is reported; the `3 of 7` sentence is the program's prose and is not carried
// changed: "the non-target list comes from BOTH sources, not just one" policy/release-assets.rego every literal and every derived name is asserted missing by name; the `7 of 7` sentence is not carried
// carried: "a .sh operand is demanded like a .json one — install.sh is an asset now" policy/release-assets.rego kind:mechanism
// carried: "a release carrying the .sh asset satisfies the demand" policy/release-assets.rego kind:mechanism
// changed: "an upload line the parser cannot read exits 2 rather than covering nothing" policy/release-assets.rego no upload line is `release read partial` through `check` now, never a complete release; the producer records the forge's facts alone, so the refusal moved to the one place that reads the list
// carried: "an asset name that contains another's does not satisfy it" policy/release-assets.rego kind:mechanism
// changed: "the authority schema does not stand in for the override schema" policy/release-assets.rego the missing override schema is asserted by name; the `1 of 7` sentence is not carried
// carried: "the real workflow publishes the non-target assets this gate derives" policy/release-assets.rego kind:mechanism
// changed: "the failure names the recovery, not merely that it refused" policy/release-assets.rego the recovery — a `workflow_dispatch` re-run, uploads being `--clobber` idempotent — is the `release ship missing` class's own text now, which `batten policy explain` prints; a refusal line names the class and its route rather than restating it per firing (CLOUD-1286)
// carried: "release-assets-check.bats::no tag given falls back to the latest release" crates/batten/src/release.rs kind:verb
// carried: "an EMPTY tag argument falls back too, which is what the schedule passes" crates/batten/src/release.rs kind:verb
// changed: "an unreadable release exits 2 — could not look is not a verdict" crates/batten/src/release.rs kind:verb could-not-look is the engine's exit 3 at `record release`, which also removes any stale record, and a later `check` has nothing to judge
// changed: "a complete release with a valid manifest reports the verified count" policy/release-assets.rego a clean release is silent at exit 0 — the success sentence with its count was the program's prose, and silence is the engine's pass
// carried: "THE CLOUD-278 GAP: every asset present but no manifest fails" crates/batten/src/policy/presets/release-hygiene/checksums-cover-the-release.rego
// changed: "a manifest that omits an asset the release carries fails, naming only it" crates/batten/src/policy/presets/release-hygiene/checksums-cover-the-release.rego the omitted asset is named and a covered one is not; the `1 checksum-manifest violation(s)` sentence is not carried
// carried: "a manifest entry naming no asset on the release fails" crates/batten/src/policy/presets/release-hygiene/checksums-cover-the-release.rego
// changed: "a manifest whose only entry is itself is the vacuous case, not a pass" crates/batten/src/policy/presets/release-hygiene/checksums-cover-the-release.rego `checksums-self` and `checksums-empty` are both asserted; `covers nothing` was the program's sentence for the second
// changed: "corrupting one byte of one asset fails, naming only that asset" crates/batten/src/policy/presets/release-hygiene/checksums-cover-the-release.rego the tampered asset is named and an untouched one is not; the violation-count sentence is not carried
// changed: "a download that fails exits 2 — could not look is not a verdict" crates/batten/src/release.rs kind:verb the engine's could-not-look, exit 3, and the stale record removed
// changed: "the manifest name comes from checksums --names, not from this gate" mise.toml one authority still: `BATTEN_CHECKSUM_MANIFEST` in `[env]`, rendered into both tasks' argv as `--manifest`
// carried: "the real workflow publishes the manifest this gate demands" policy/release-assets.rego kind:mechanism
// carried: "the manifest job runs after everything that uploads an asset" policy/release-assets.rego kind:mechanism
// changed: "a matrix with no targets exits 2 rather than passing vacuously" policy/release-assets.rego `release read partial` through `check`, never a pass
// changed: "an unreadable workflow exits 2, not 1" policy/release-assets.rego an absent or unparsed workflow document is `release read partial` through `check`
// carried: "the real workflow's matrix is readable by this parser" policy/release-assets.rego kind:mechanism
// carried: "upload precedes attestation in the committed workflow" policy/release-assets.rego kind:mechanism
// carried: "no install-action step names a tool mise.toml already pins" policy/release-assets.rego kind:mechanism
// carried: "the attestation cannot fail the leg while the repo is private" policy/release-assets.rego kind:mechanism

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::{Path, PathBuf};
use std::process::{Output, Stdio};

use common::{at_root, git_in, init_repo, scratch, write};

/// The repository a case names — deliberately not this one.
const REPO: &str = "acme/widgets";

/// The tag every fixture release is cut from.
const TAG: &str = "v9.9.9";

/// Where the rule row reads the expected list from.
const WORKFLOW_PATH: &str = ".github/workflows/release-artifacts.yml";

const WORKFLOW: &str = r#"name: release-artifacts
on: workflow_dispatch
jobs:
  dist:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        include:
          - target: x86_64-unknown-linux-gnu
            build-tool: cargo
          - target: aarch64-apple-darwin
            build-tool: zigbuild
    steps:
      - run: echo build
  schema:
    runs-on: ubuntu-latest
    steps:
      - run: gh release upload "$TAG" schema/batten.schema.json schema/batten.local.schema.json "$SPDX" "$CDX" --clobber
"#;

fn manifest_name() -> String {
    common::task_env("BATTEN_CHECKSUM_MANIFEST")
}

fn reference_name() -> String {
    common::task_env("BATTEN_CLI_REFERENCE")
}

/// A fixture repository registering the real module and the preset, with a
/// fixture build workflow and the reference's `[env]` declaration.
fn repo(name: &str, workflow: Option<&str>) -> PathBuf {
    let dir = scratch(&format!("release-assets-{name}"));
    let module =
        std::fs::read_to_string(at_root("policy/release-assets.rego")).expect("the module");
    write(&dir, "policy/release-assets.rego", &module);
    let verdict = |id: &str| {
        format!(
            "[[verdict]]\nid = \"{id}\"\ngloss = \"fixture\"\nclass = \"fixture\"\n\n\
             [[verdict.route]]\nid = \"task run first\"\nkind = \"command\"\n\
             target = \"mise run release-assets-record\"\n\n"
        )
    };
    write(
        &dir,
        "batten.toml",
        &format!(
            "version = 1\nscope = [\"**\"]\n\n[[pattern]]\nid = \"release-archive\"\n\
             regex = '[.](tar[.]gz|zip)$'\n\n[[pattern]]\nid = \"release-upload-operand\"\n\
             regex = '^\"?[A-Za-z0-9_./-]+[.](json|sh)\"?$'\n\n{}{}\
             [[rule]]\nid = \"release grade other\"\nkind = \"policy\"\nscope = \"tree\"\n\
             module = \"policy/release-assets.rego\"\n\
             documents = [\"{WORKFLOW_PATH}\", \"mise.toml\"]\n\
             line_sources = [\"{WORKFLOW_PATH}\"]\nseverity = \"deny\"\n\n\
             [[rule]]\nid = \"release pin other\"\nkind = \"policy\"\nscope = \"tree\"\n\
             preset = \"release-hygiene\"\nseverity = \"deny\"\n\n\
             [[record]]\nrecord = \"release-assets\"\nwriter = \"batten record release\"\n",
            verdict("release ship missing"),
            verdict("release read partial"),
        ),
    );
    write(
        &dir,
        "mise.toml",
        &format!("[env]\nBATTEN_CLI_REFERENCE = \"{}\"\n", reference_name()),
    );
    if let Some(workflow) = workflow {
        write(&dir, WORKFLOW_PATH, workflow);
    }
    init_repo(&dir);
    git_in(&dir, &["add", "-A"]);
    git_in(&dir, &["commit", "-qm", "register the module"]);
    dir
}

/// Every asset a complete `v9.9.9` of the fixture workflow carries, manifest
/// excluded, plus `extra`.
fn complete(extra: &[&str]) -> Vec<String> {
    let mut assets: Vec<String> = [
        "batten-9.9.9-x86_64-unknown-linux-gnu.tar.gz",
        "batten-9.9.9-aarch64-apple-darwin.tar.gz",
        "batten-v9.9.9-x86_64-unknown-linux-gnu.spdx.json",
        "batten-v9.9.9-aarch64-apple-darwin.spdx.json",
        "batten.schema.json",
        "batten.local.schema.json",
        "batten.spdx.json",
        "batten.cdx.json",
    ]
    .iter()
    .map(|s| (*s).to_owned())
    .collect();
    assets.push(reference_name());
    assets.extend(extra.iter().map(|s| (*s).to_owned()));
    assets
}

/// The bytes a fixture asset carries.
fn bytes_of(name: &str) -> String {
    format!("bytes of {name}\n")
}

/// `sha256sum`'s text format over `names`, each hashed from [`bytes_of`] unless
/// `tampered` names it.
fn manifest_over(names: &[String], tampered: Option<&str>) -> String {
    use sha2::Digest as _;
    use std::fmt::Write as _;
    let mut sorted = names.to_vec();
    sorted.sort();
    sorted.iter().fold(String::new(), |mut lines, name| {
        let bytes = if tampered == Some(name.as_str()) {
            String::from("the bytes before the re-upload\n")
        } else {
            bytes_of(name)
        };
        for b in sha2::Sha256::digest(bytes.as_bytes()) {
            let _ = write!(lines, "{b:02x}");
        }
        let _ = writeln!(lines, "  {name}");
        lines
    })
}

/// A fixture forge serving one release of `assets`, each asset's bytes by id,
/// plus the manifest as one more asset when `manifest` carries text.
fn forge(name: &str, assets: &[String], manifest: Option<&str>) -> PathBuf {
    let forge = scratch(&format!("release-assets-{name}-forge"));
    let mut served: Vec<(String, String)> = assets
        .iter()
        .map(|asset| (asset.clone(), bytes_of(asset)))
        .collect();
    if let Some(text) = manifest {
        served.push((manifest_name(), text.to_owned()));
    }
    let listing: Vec<serde_json::Value> = served
        .iter()
        .enumerate()
        .map(|(index, (asset, _))| serde_json::json!({"id": 10 + index, "name": asset}))
        .collect();
    let body = serde_json::json!({"tag_name": TAG, "assets": listing}).to_string();
    write(
        &forge,
        "release",
        &format!("HTTP/2 200\ncontent-type: application/json\n\n{body}\n"),
    );
    let mut routes = String::from("/releases/tags/\trelease\n/releases/latest\trelease\n");
    for (index, (_, bytes)) in served.iter().enumerate() {
        let file = format!("asset.{}", 10 + index);
        write(
            &forge,
            &file,
            &format!("HTTP/2 200\ncontent-type: application/octet-stream\n\n{bytes}"),
        );
        routes.push_str(&format!("/releases/assets/{}\t{file}\n", 10 + index));
    }
    write(&forge, "routes", &routes);
    forge
}

/// `batten <args>` in `dir` against the fixture forge, naming the repository.
fn against(dir: &Path, forge: &Path, args: &[&str]) -> Output {
    common::batten()
        .args(args)
        .env("GH_REPO", REPO)
        .env("BATTEN_REST_FIXTURE", forge)
        .current_dir(dir)
        .output()
        .expect("the compiled binary runs")
}

/// `record release [tag] --manifest <name>`.
fn produce(dir: &Path, forge: &Path, tag: Option<&str>) -> Output {
    let manifest = manifest_name();
    let mut args = vec!["record", "release"];
    args.extend(tag);
    args.extend(["--manifest", manifest.as_str()]);
    against(dir, forge, &args)
}

/// Both rules, as `mise run release-assets-check` runs them.
fn check(dir: &Path, forge: &Path) -> Output {
    against(
        dir,
        forge,
        &[
            "check",
            "--rule",
            "release grade other",
            "--rule",
            "release pin other",
        ],
    )
}

fn said(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

/// Record (asserting it recorded), then decide.
fn decide(dir: &Path, forge: &Path) -> (Option<i32>, String) {
    let produced = produce(dir, forge, Some(TAG));
    assert_eq!(
        produced.status.code(),
        Some(0),
        "the producer records: {}",
        said(&produced)
    );
    let decided = check(dir, forge);
    (decided.status.code(), said(&decided))
}

/// A repository and a forge for a release of `assets` with a manifest over
/// every one of them.
fn pinned(name: &str, assets: &[String]) -> (PathBuf, PathBuf) {
    let dir = repo(name, Some(WORKFLOW));
    let forge = forge(name, assets, Some(&manifest_over(assets, None)));
    (dir, forge)
}

#[test]
fn a_complete_release_with_a_valid_manifest_is_clean() {
    let (dir, forge) = pinned("complete", &complete(&[]));
    let (code, text) = decide(&dir, &forge);
    assert_eq!(code, Some(0), "{text}");
}

#[test]
fn a_release_with_only_the_schema_is_refused() {
    // v0.0.36 exactly: the schema shipped and every dist leg died.
    let dir = repo("schema-only", Some(WORKFLOW));
    let forge = forge("schema-only", &["batten.schema.json".to_owned()], None);
    let (code, text) = decide(&dir, &forge);
    assert_eq!(code, Some(2), "{text}");
    // THE TARGET ITSELF, as a finding's subject: the binary SBOMs are missing too
    // and their names carry the same triple, so a bare substring would pass with
    // the archive arm dead.
    for target in ["x86_64-unknown-linux-gnu", "aarch64-apple-darwin"] {
        assert!(
            text.lines()
                .any(|line| line.starts_with(&format!("{target} "))),
            "{target}: {text}"
        );
    }
    assert!(text.contains("release grade other"), "the one rule: {text}");
}

#[test]
fn a_partial_release_names_the_missing_target_and_not_the_present_one() {
    let dir = repo("partial", Some(WORKFLOW));
    let forge = forge(
        "partial",
        &["batten-9.9.9-x86_64-unknown-linux-gnu.tar.gz".to_owned()],
        None,
    );
    let (code, text) = decide(&dir, &forge);
    assert_eq!(code, Some(2), "{text}");
    assert!(text.contains("aarch64-apple-darwin"), "{text}");
    assert!(!text.contains("x86_64-unknown-linux-gnu release"), "{text}");
}

#[test]
fn every_non_target_asset_is_demanded_from_both_sources() {
    let archives = vec![
        "batten-9.9.9-x86_64-unknown-linux-gnu.tar.gz".to_owned(),
        "batten-9.9.9-aarch64-apple-darwin.tar.gz".to_owned(),
    ];
    let (dir, forge) = pinned("non-target", &archives);
    let (code, text) = decide(&dir, &forge);
    assert_eq!(code, Some(2), "{text}");
    for name in [
        "batten.schema.json",
        "batten.local.schema.json",
        "batten.spdx.json",
        "batten.cdx.json",
        "batten-v9.9.9-x86_64-unknown-linux-gnu.spdx.json",
        "batten-v9.9.9-aarch64-apple-darwin.spdx.json",
    ] {
        assert!(text.contains(name), "{name}: {text}");
    }
    assert!(text.contains(&reference_name()), "the reference: {text}");
    // CLOUD-262: every archive present and the SBOMs still demanded.
    let mut assets = complete(&[]);
    assets.retain(|a| a != "batten.spdx.json" && a != "batten.cdx.json");
    let (dir, forge) = pinned("no-sbom", &assets);
    let (code, text) = decide(&dir, &forge);
    assert_eq!(code, Some(2), "{text}");
    assert!(
        text.contains("batten.spdx.json") && text.contains("batten.cdx.json"),
        "{text}"
    );
    assert!(!text.contains(".tar.gz"), "no archive reported: {text}");
}

#[test]
fn a_sh_operand_is_demanded_and_satisfied_like_a_json_one() {
    let workflow = WORKFLOW.replace(
        "schema/batten.local.schema.json",
        "schema/batten.local.schema.json install.sh",
    );
    let demanded = repo("sh-demanded", Some(&workflow));
    let assets = complete(&[]);
    let forge_demanded = forge("sh-demanded", &assets, Some(&manifest_over(&assets, None)));
    let (code, text) = decide(&demanded, &forge_demanded);
    assert_eq!(code, Some(2), "{text}");
    assert!(text.contains("install.sh"), "{text}");
    let satisfied = repo("sh-satisfied", Some(&workflow));
    let assets = complete(&["install.sh"]);
    let forge_satisfied = forge("sh-satisfied", &assets, Some(&manifest_over(&assets, None)));
    let (code, text) = decide(&satisfied, &forge_satisfied);
    assert_eq!(code, Some(0), "{text}");
}

#[test]
fn a_name_containing_another_does_not_satisfy_it() {
    // `.spdx.json.sig` must not stand in for `.spdx.json`, nor the authority
    // schema for the override one.
    let mut assets = complete(&["batten.spdx.json.sig"]);
    assets.retain(|a| a != "batten.spdx.json" && a != "batten.local.schema.json");
    let (dir, forge) = pinned("containing", &assets);
    let (code, text) = decide(&dir, &forge);
    assert_eq!(code, Some(2), "{text}");
    assert!(text.contains("batten.spdx.json "), "{text}");
    assert!(text.contains("batten.local.schema.json"), "{text}");
}

#[test]
fn no_tag_or_an_empty_tag_falls_back_to_the_latest_release() {
    for (name, tag) in [("absent", None), ("empty", Some(""))] {
        let (dir, forge) = pinned(&format!("latest-{name}"), &complete(&[]));
        let produced = produce(&dir, &forge, tag);
        assert_eq!(
            produced.status.code(),
            Some(0),
            "{name}: {}",
            said(&produced)
        );
        let asked = std::fs::read_to_string(forge.join("args")).unwrap_or_default();
        assert!(asked.contains("/releases/latest"), "{name}: {asked}");
        assert_eq!(check(&dir, &forge).status.code(), Some(0), "{name}");
    }
}

#[test]
fn an_unreadable_release_is_could_not_look_and_leaves_no_record() {
    // THE STALENESS CASE: a first run records an incomplete release; the second
    // cannot read the release at all. Leaving the first record would let the
    // gate repeat an answer about a release nobody could read.
    let dir = repo("unreadable", Some(WORKFLOW));
    let forge = forge("unreadable", &["batten.schema.json".to_owned()], None);
    let (code, _) = decide(&dir, &forge);
    assert_eq!(code, Some(2), "the first record decides");
    write(&forge, "release", "HTTP/2 500\n\n{\"message\": \"boom\"}");
    let refused = produce(&dir, &forge, Some(TAG));
    assert_eq!(refused.status.code(), Some(3), "{}", said(&refused));
    assert!(
        !said(&refused).contains("boom"),
        "rule 4: {}",
        said(&refused)
    );
    assert_eq!(
        check(&dir, &forge).status.code(),
        Some(0),
        "the stale record is gone, so nothing is judged"
    );

    // AND A DOWNLOAD THAT FAILS is could-not-look the same way.
    let assets = complete(&[]);
    let (dir, forge) = pinned("download-fails", &assets);
    write(&forge, "asset.10", "HTTP/2 404\n\n{}");
    assert_eq!(produce(&dir, &forge, Some(TAG)).status.code(), Some(3));
}

#[test]
fn a_list_that_cannot_be_derived_is_partial_never_complete() {
    let assets = complete(&[]);
    let no_upload = WORKFLOW.replace("gh release upload", "echo");
    let no_targets = "name: x\non: push\njobs:\n  dist:\n    runs-on: x\n    steps:\n      \
                      - run: gh release upload \"$TAG\" a.json\n";
    for (name, workflow) in [
        ("absent-workflow", None),
        ("no-targets", Some(no_targets)),
        ("no-upload", Some(no_upload.as_str())),
    ] {
        let dir = repo(name, workflow);
        let forge = forge(name, &assets, Some(&manifest_over(&assets, None)));
        let (code, text) = decide(&dir, &forge);
        assert_eq!(code, Some(2), "{name}: {text}");
        // THE TEXT CHANNEL IS POINTER-ONLY, `<path> <rule>`, so the verdict token
        // is not on it and the two classes are told apart by their POINTERS:
        // `release read partial` points at the workflow it could not derive the
        // list from, while `release ship missing` carries only an artifact and
        // falls back to the module's own path.
        assert!(
            text.contains(".github/workflows/release-artifacts.yml release grade other"),
            "{name}: {text}"
        );
        assert!(
            !text.contains("policy/release-assets.rego"),
            "{name}: an unknown list demands nothing: {text}"
        );
    }
}

#[test]
fn a_release_with_no_manifest_is_refused_and_nothing_else_is() {
    let dir = repo("no-manifest", Some(WORKFLOW));
    let forge = forge("no-manifest", &complete(&[]), None);
    let (code, text) = decide(&dir, &forge);
    assert_eq!(code, Some(2), "{text}");
    assert!(text.contains("checksums-missing"), "{text}");
    assert!(
        !text.contains("release ship missing"),
        "complete but unpinned: {text}"
    );
}

#[test]
fn a_manifest_omitting_an_asset_or_naming_an_orphan_is_refused() {
    let assets = complete(&[]);
    let without: Vec<String> = assets
        .iter()
        .filter(|a| a.as_str() != "batten.schema.json")
        .cloned()
        .collect();
    let dir = repo("omits", Some(WORKFLOW));
    let forge_omits = forge("omits", &assets, Some(&manifest_over(&without, None)));
    let (code, text) = decide(&dir, &forge_omits);
    assert_eq!(code, Some(2), "{text}");
    assert!(text.contains("batten.schema.json"), "{text}");
    assert!(text.contains("checksums-omits"), "{text}");

    let dir = repo("orphan", Some(WORKFLOW));
    let mut text = manifest_over(&assets, None);
    text.push_str(&"0".repeat(64));
    text.push_str("  batten-9.9.9-x86_64-pc-windows-gnu.zip\n");
    let forge_orphan = forge("orphan", &assets, Some(&text));
    let (code, text) = decide(&dir, &forge_orphan);
    assert_eq!(code, Some(2), "{text}");
    assert!(text.contains("x86_64-pc-windows-gnu.zip"), "{text}");
    assert!(text.contains("checksums-orphan"), "{text}");
}

#[test]
fn a_manifest_whose_only_entry_is_itself_is_self_and_empty() {
    let dir = repo("vacuous", Some(WORKFLOW));
    let only_itself = format!("{:064}  {}\n", 0, manifest_name());
    let forge = forge("vacuous", &complete(&[]), Some(&only_itself));
    let (code, text) = decide(&dir, &forge);
    assert_eq!(code, Some(2), "{text}");
    assert!(text.contains("checksums-self"), "{text}");
    assert!(text.contains("checksums-empty"), "{text}");
}

#[test]
fn a_byte_mismatch_is_refused_once_the_names_agree() {
    // The asset was re-uploaded after the manifest was cut.
    let assets = complete(&[]);
    let dir = repo("mismatch", Some(WORKFLOW));
    let stale = manifest_over(&assets, Some("batten-9.9.9-aarch64-apple-darwin.tar.gz"));
    let forge = forge("mismatch", &assets, Some(&stale));
    let (code, text) = decide(&dir, &forge);
    assert_eq!(code, Some(2), "{text}");
    assert!(text.contains("aarch64-apple-darwin.tar.gz"), "{text}");
    assert!(text.contains("checksums-mismatch"), "{text}");
    assert!(!text.contains("x86_64-unknown-linux-gnu.tar.gz"), "{text}");
}

#[test]
fn a_release_record_without_its_census_is_torn_rather_than_clean() {
    let dir = repo("torn", Some(WORKFLOW));
    let written = common::run_with_stdin(
        &dir,
        &["record", "named", "release-assets"],
        // CLEAN BUT FOR THE CENSUS, so the torn arm is the only thing that can
        // refuse the manifest half.
        "release-tag\tv9.9.9\nrelease-asset\ta.tar.gz\nrelease-asset\tSUMS\n\
         release-manifest\tSUMS\nrelease-covered\ta.tar.gz\n",
    );
    assert!(written.status.success(), "{}", said(&written));
    let decided = common::run(&dir, &["check", "--rule", "release pin other"]);
    assert_eq!(decided.status.code(), Some(2), "{}", said(&decided));
    assert!(
        said(&decided).contains("release record torn"),
        "{}",
        said(&decided)
    );
}

// --- the committed tasks and workflow -------------------------------------------

fn committed(path: &str) -> String {
    std::fs::read_to_string(at_root(path)).expect("committed file")
}

#[test]
fn the_committed_tasks_are_argv_and_the_committed_row_reads_the_real_workflow() {
    for task in ["release-assets-record", "release-assets-check"] {
        let block = common::task_block(task).expect("the task");
        assert!(!block.contains("'''"), "{task} carries no body: {block}");
    }
    let record = common::task_value(
        &common::task_block("release-assets-record").expect("the task"),
        "run",
    );
    assert!(record.contains("record release"), "{record}");
    let authority = committed("batten.toml");
    assert!(
        authority.contains(&format!("documents = [\"{WORKFLOW_PATH}\", \"mise.toml\"]")),
        "the row declares the workflow this tier writes"
    );
    // EVERY RULE THE CHECK TASK NAMES IS A COMMITTED ROW, and the manifest half is
    // the preset's. This tier's fixture writes its own `batten.toml`, so without
    // this a check task naming an undeclared rule would stay green here while the
    // committed gate enforced nothing.
    let rows: toml::Value = toml::from_str(&authority).expect("batten.toml parses");
    let declared: Vec<&toml::Value> = rows["rule"].as_array().expect("[[rule]]").iter().collect();
    let row = |id: &str| {
        declared
            .iter()
            .find(|entry| entry.get("id").and_then(toml::Value::as_str) == Some(id))
            .copied()
    };
    let check = common::task_value(
        &common::task_block("release-assets-check").expect("the task"),
        "run",
    );
    for id in ["release grade other", "release pin other"] {
        assert!(
            check.contains(&format!("'{id}'")),
            "the task checks {id}: {check}"
        );
        assert!(row(id).is_some(), "batten.toml declares {id}");
    }
    assert_eq!(
        row("release pin other")
            .and_then(|entry| entry.get("preset"))
            .and_then(toml::Value::as_str),
        Some("release-hygiene"),
        "the manifest half is the vendored preset's"
    );
}

#[test]
fn the_real_workflow_publishes_both_schemas_and_the_manifest() {
    // Each upload STEP, `env:` included: the files reach `gh release upload`
    // through `ci step --arg-env` since the step became one argv (CLOUD-843,
    // Phase 4), so a line-at-a-time read would see the command and none of them.
    let workflow = committed(WORKFLOW_PATH);
    let steps: Vec<&str> = workflow.split("\n      - ").collect();
    let uploads: String = steps
        .iter()
        .filter(|step| step.contains("gh release upload"))
        .copied()
        .collect::<Vec<_>>()
        .join("\n");
    assert!(uploads.contains("batten.schema.json"), "{uploads}");
    assert!(uploads.contains("batten.local.schema.json"), "{uploads}");
    assert!(workflow.contains("mise run checksums"));
    assert!(
        steps.iter().any(|step| step.contains("gh release upload")
            && step.contains("--arg-env TAG --arg-env SUMS")),
        "{uploads}"
    );
}

#[test]
fn the_manifest_job_runs_after_everything_that_uploads_an_asset() {
    let workflow = committed(WORKFLOW_PATH);
    let needs: String = workflow
        .lines()
        .filter_map(|l| l.trim_start().strip_prefix("needs:"))
        .collect::<Vec<_>>()
        .join(" ");
    assert!(
        needs.contains("dist") && needs.contains("schema"),
        "{needs}"
    );
}

/// Every matrix leg of the committed workflow as `(target, build-tool)`, read as
/// TEXT — an oracle independent of the module's parsed-document path, so a tier
/// comparing the two catches the module misreading the real shape.
fn committed_legs() -> Vec<(String, String)> {
    let mut legs: Vec<(String, String)> = Vec::new();
    for line in committed(WORKFLOW_PATH).lines().map(str::trim_start) {
        if let Some(target) = line.strip_prefix("- target:") {
            legs.push((target.trim().to_owned(), String::new()));
        } else if let Some(tool) = line.strip_prefix("build-tool:")
            && let Some(leg) = legs.last_mut()
            && leg.1.is_empty()
        {
            tool.trim().clone_into(&mut leg.1);
        }
    }
    assert!(legs.len() >= 7, "{} legs: {legs:?}", legs.len());
    assert!(
        legs.iter().all(|(_, tool)| !tool.is_empty()),
        "every leg names its build tool: {legs:?}"
    );
    legs
}

/// A fixture repository carrying the COMMITTED build workflow, not the fixture.
fn real_repo(name: &str) -> PathBuf {
    let workflow = committed(WORKFLOW_PATH);
    repo(name, Some(workflow.as_str()))
}

/// Record `assets` as release `TAG`, then run `release grade other` alone.
fn graded(dir: &Path, name: &str, assets: &[String]) -> (Option<i32>, String) {
    let forge = forge(name, assets, None);
    let produced = produce(dir, &forge, Some(TAG));
    assert_eq!(
        produced.status.code(),
        Some(0),
        "the producer records: {}",
        said(&produced)
    );
    let decided = against(dir, &forge, &["check", "--rule", "release grade other"]);
    (decided.status.code(), said(&decided))
}

#[test]
fn the_real_matrix_is_readable_by_the_module() {
    // THE COMMITTED WORKFLOW THROUGH THE MODULE'S OWN PARSE PATH
    // (`jobs.*.strategy.matrix.include`, `build-tool`): on a release carrying
    // nothing the workflow builds, every target the matrix declares is named
    // missing, and each leg's binary SBOM is demanded exactly when its build tool
    // is not `cross`. A module that could not read the real shape says
    // `release read partial` instead, or names fewer targets.
    let legs = committed_legs();
    let dir = real_repo("real-matrix");
    let (code, text) = graded(&dir, "real-matrix", &["unrelated.txt".to_owned()]);
    assert_eq!(code, Some(2), "{text}");
    assert!(!text.contains("release read partial"), "{text}");
    for (target, tool) in &legs {
        assert!(
            text.lines()
                .any(|line| line.starts_with(&format!("{target} "))),
            "{target}: {text}"
        );
        let sbom = format!("-{TAG}-{target}.spdx.json ");
        assert_eq!(
            text.lines().any(|line| line.contains(&sbom)),
            tool != "cross",
            "{target} ({tool}): {text}"
        );
    }
}

/// The basenames of the committed workflow's literal `.json`/`.sh` upload
/// operands — no `$` expansion — read as text.
fn committed_upload_literals() -> Vec<String> {
    committed(WORKFLOW_PATH)
        .lines()
        .filter(|line| line.contains("gh release upload"))
        .flat_map(|line| line.split(' ').map(str::to_owned).collect::<Vec<_>>())
        .map(|token| token.trim_matches('"').to_owned())
        .filter(|token| {
            !token.contains('$') && (token.ends_with(".json") || token.ends_with(".sh"))
        })
        .map(|token| basename(&token))
        .collect()
}

/// The last `/`-separated segment of `path`.
fn basename(path: &str) -> String {
    path.rsplit('/').next().unwrap_or(path).to_owned()
}

#[test]
fn the_names_the_module_demands_are_the_names_the_producers_write() {
    // THE MODULE'S NAME CONSTANTS AGAINST THEIR PRODUCERS. `release-assets.rego`
    // spells the repository SBOM's two documents and each composed leg's binary
    // SBOM name, stem and suffix both; the producers that write them are `batten
    // sbom --names`, `batten sbom --names --target <triple>` and `batten dist
    // <triple> --stem` for the archive (CLOUD-843 retired the three shell
    // producers onto those verbs). A release carrying EXACTLY the names those
    // producers print, plus the workflow's literal uploads and the reference, is
    // clean — so a constant that drifts from its producer, or a producer that
    // drifts from the constant, turns this red as a `release ship missing` for a
    // name the other side does not spell.
    //
    // ONE SCRATCH CRATE AT THE FIXTURE TAG'S VERSION, because `dist` names its
    // stem from `cargo metadata` and the binary SBOM's name carries the same
    // version: a crate named for this project's binary, and the `[sbom]` table
    // the producers read their names from, copied from this repository's own.
    let legs = committed_legs();
    let crate_dir = scratch("release-assets-stem");
    write(
        &crate_dir,
        "Cargo.toml",
        &format!(
            "[package]\nname = \"batten\"\nversion = \"{}\"\nedition = \"2021\"\n\n[[bin]]\nname = \"batten\"\npath = \"src/main.rs\"\n\n[workspace]\n",
            TAG.trim_start_matches('v')
        ),
    );
    write(&crate_dir, "src/main.rs", "fn main() {}\n");
    // ITS OWN REPOSITORY, because the producers resolve the repository root
    // before they read a manifest: under this checkout's `target/` the walk up
    // finds THIS repository and names its version instead of the fixture's.
    git_in(&crate_dir, &["init", "-q"]);
    write(
        &crate_dir,
        "batten.toml",
        "version = 1\n\n[sbom]\nsubject = \"batten\"\nout_dir = \"sbom\"\nbinary_out_dir = \"dist\"\n",
    );
    let names = |args: &[&str]| -> String {
        let out = common::batten()
            .args(args)
            .current_dir(&crate_dir)
            .stdin(Stdio::null())
            .output()
            .expect("the producer runs");
        assert!(out.status.success(), "{args:?}: {}", said(&out));
        String::from_utf8_lossy(&out.stdout).into_owned()
    };
    let mut assets: Vec<String> = names(&["sbom", "--names"])
        .lines()
        .filter_map(|line| line.split_once('=').map(|(_, path)| basename(path)))
        .collect();
    assert_eq!(assets.len(), 2, "{assets:?}");
    for (target, tool) in &legs {
        let stem = names(&["dist", target, "--stem"]).trim().to_owned();
        assert!(stem.contains(target.as_str()), "{stem}");
        assets.push(format!("{stem}.tar.gz"));
        if tool != "cross" {
            // THE UPLOADED DOCUMENT'S NAME FROM THE VERB THAT WRITES IT, never a
            // suffix spelled here: a suffix restated in this tier would agree with
            // the module while both drifted from the producer.
            let sbom: Vec<String> = names(&["sbom", "--names", "--target", target])
                .lines()
                .filter_map(|line| line.strip_prefix("sbom=").map(basename))
                .collect();
            assert_eq!(sbom.len(), 1, "{target}: {sbom:?}");
            assert!(
                sbom.iter().all(|name| name.starts_with(stem.as_str())),
                "{stem}: {sbom:?}"
            );
            assets.extend(sbom);
        }
    }
    assets.extend(committed_upload_literals());
    assets.push(reference_name());
    let dir = real_repo("producer-names");
    let (code, text) = graded(&dir, "producer-names", &assets);
    assert_eq!(code, Some(0), "{assets:?}: {text}");
}

#[test]
fn upload_precedes_attestation_and_attestation_cannot_fail_the_leg() {
    let workflow = committed(WORKFLOW_PATH);
    let upload = workflow
        .find("name: Upload to the release")
        .expect("upload step");
    let attest = workflow
        .find("attest-build-provenance")
        .expect("attest step");
    assert!(upload < attest, "upload must come first (CLOUD-258)");
    let after: String = workflow[attest..]
        .lines()
        .take(3)
        .collect::<Vec<_>>()
        .join("\n");
    assert!(after.contains("continue-on-error: true"), "{after}");
}

#[test]
fn no_install_action_step_names_a_tool_mise_pins() {
    // CLOUD-259: a second provisioning path for a pinned tool can only fail.
    let workflow = committed(WORKFLOW_PATH);
    let requested: Vec<String> = workflow
        .lines()
        .filter_map(|l| l.trim_start().strip_prefix("tool:"))
        .flat_map(|v| v.split(','))
        .map(|t| t.trim().to_owned())
        .filter(|t| !t.is_empty())
        .collect();
    let manifest: toml::Value = toml::from_str(&committed("mise.toml")).expect("mise.toml");
    let pinned: Vec<String> = manifest["tools"]
        .as_table()
        .expect("[tools]")
        .keys()
        .map(|k| {
            k.rsplit('/')
                .next()
                .unwrap_or(k)
                .rsplit(':')
                .next()
                .unwrap_or(k)
                .to_owned()
        })
        .collect();
    for tool in &requested {
        assert!(
            !pinned.contains(tool),
            "install-action is asked for `{tool}`, which mise.toml pins"
        );
    }
}
