//! `release grade other` over the compiled binary and the REAL producer
//! (CLOUD-258, CLOUD-262, CLOUD-278, CLOUD-1717).
//!
//! `[tasks.release-assets-record]` is read out of `mise.toml` and run against a
//! fixture workflow and a stub `gh` serving a directory of REAL files — the
//! manifest rules hash bytes, so a stub answering names alone would leave half
//! the gate untested. The engine then decides over what was recorded. The
//! per-target SBOM names are derived by the live `mise run sbom-binary -- --names`, the
//! way the producer derives them, so a literal here cannot rot at a version bump.
//!
//! The last cases are properties of the COMMITTED workflow rather than of the
//! gate: they pin that the parser is pointed at a shape production actually has.
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
// carried: "an upload line the parser cannot read exits 2 rather than covering nothing" policy/release-assets.rego kind:mechanism
// carried: "an asset name that contains another's does not satisfy it" policy/release-assets.rego kind:mechanism
// changed: "the authority schema does not stand in for the override schema" policy/release-assets.rego the missing override schema is asserted by name; the `1 of 7` sentence is not carried
// carried: "the real workflow publishes the non-target assets this gate derives" policy/release-assets.rego kind:mechanism
// changed: "the failure names the recovery, not merely that it refused" policy/release-assets.rego the recovery — a `workflow_dispatch` re-run, uploads being `--clobber` idempotent — is the `release ship missing` class's own text now, which `batten policy explain` prints; a refusal line names the class and its route rather than restating it per firing (CLOUD-1286)
// carried: "release-assets-check.bats::no tag given falls back to the latest release" policy/release-assets.rego kind:mechanism
// carried: "an EMPTY tag argument falls back too, which is what the schedule passes" policy/release-assets.rego kind:mechanism
// carried: "an unreadable release exits 2 — could not look is not a verdict" policy/release-assets.rego kind:mechanism
// changed: "a complete release with a valid manifest reports the verified count" policy/release-assets.rego a clean release is silent at exit 0 — the success sentence with its count was the program's prose, and silence is the engine's pass
// carried: "THE CLOUD-278 GAP: every asset present but no manifest fails" policy/release-assets.rego kind:mechanism
// changed: "a manifest that omits an asset the release carries fails, naming only it" policy/release-assets.rego the omitted asset is named and a covered one is not; the `1 checksum-manifest violation(s)` sentence is not carried
// carried: "a manifest entry naming no asset on the release fails" policy/release-assets.rego kind:mechanism
// changed: "a manifest whose only entry is itself is the vacuous case, not a pass" policy/release-assets.rego `checksums-self` and `checksums-empty` are both asserted; `covers nothing` was the program's sentence for the second
// changed: "corrupting one byte of one asset fails, naming only that asset" policy/release-assets.rego the tampered asset is named and an untouched one is not; the violation-count sentence is not carried
// changed: "a download that fails exits 2 — could not look is not a verdict" policy/release-assets.rego the exit 2 is carried; `unverified` was the program's wording and the producer's refusal now says it cannot download the assets
// changed: "the manifest name comes from checksums --names, not from this gate" mise.toml one authority still: `BATTEN_CHECKSUM_MANIFEST` in `[env]`, read by `[tasks.checksums]` and `[tasks.release-assets-record]` alike — the `--names` round trip existed to share a name between two programs, and there is now one declaration and no program to ask
// carried: "the real workflow publishes the manifest this gate demands" policy/release-assets.rego kind:mechanism
// carried: "the manifest job runs after everything that uploads an asset" policy/release-assets.rego kind:mechanism
// carried: "a matrix with no targets exits 2 rather than passing vacuously" policy/release-assets.rego kind:mechanism
// carried: "an unreadable workflow exits 2, not 1" policy/release-assets.rego kind:mechanism
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

const WORKFLOW: &str = r#"        include:
          - target: x86_64-unknown-linux-gnu
            build-tool: cargo
          - target: aarch64-apple-darwin
            build-tool: zigbuild
        run: gh release upload "$TAG" schema/batten.schema.json schema/batten.local.schema.json "$SPDX" "$CDX" --clobber
"#;

/// A fixture repository registering the real module, with a fixture workflow, a
/// version for the SBOM stem, and a stub `gh` over `release/`.
fn repo(name: &str) -> PathBuf {
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
            "version = 1\nscope = [\"**\"]\n\n[[pattern]]\nid = \"whole-number\"\n\
             regex = '^[0-9]+$'\n\n[[pattern]]\nid = \"release-archive\"\n\
             regex = '[.](tar[.]gz|zip)$'\n\n{}{}{}\
             [[rule]]\nid = \"release grade other\"\nkind = \"policy\"\nscope = \"tree\"\n\
             module = \"policy/release-assets.rego\"\nseverity = \"deny\"\n\n\
             [[record]]\nrecord = \"release-assets\"\nwriter = \"mise run release-assets-record\"\n",
            verdict("release ship missing"),
            verdict("release pin broken"),
            verdict("release read partial"),
        ),
    );
    write(
        &dir,
        "Cargo.toml",
        "[package]\nname = \"batten\"\nversion = \"9.9.9\"\n",
    );
    write(&dir, "workflow.yml", WORKFLOW);
    init_repo(&dir);
    git_in(&dir, &["add", "-A"]);
    git_in(&dir, &["commit", "-qm", "register the module"]);
    dir
}

/// Put `assets` on the fixture release as real files, and answer them.
fn release(dir: &Path, assets: &[String]) {
    let root = dir.join("release");
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).expect("release dir");
    for asset in assets {
        std::fs::write(root.join(asset), format!("bytes of {asset}\n")).expect("asset");
    }
    let listing: String = assets.iter().flat_map(|a| [a.as_str(), "\n"]).collect();
    write(dir, "assets", &listing);
    let base = dir.display();
    write(
        dir,
        "bin/gh",
        &format!(
            r#"#!/usr/bin/env bash
[ ! -f "{base}/gh.fails" ] || exit 1
case "$*" in
  *"release download"*)
    [ ! -f "{base}/download.fails" ] || exit 1
    d=""; while [ $# -gt 0 ]; do [ "$1" != --dir ] || d="$2"; shift; done
    mkdir -p "$d"; cp "{base}/release"/* "$d/" ;;
  *tagName*) printf 'v9.9.9\n' ;;
  *assets*) cat "{base}/assets" ;;
esac
"#
        ),
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let gh = dir.join("bin/gh");
        let mut permissions = std::fs::metadata(&gh).expect("stat").permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&gh, permissions).expect("chmod");
    }
}

/// The manifest over `names` (or every asset), attached as one more asset.
fn manifest(dir: &Path, names: Option<&[String]>) {
    let root = dir.join("release");
    let listing = std::fs::read_to_string(dir.join("assets")).expect("assets");
    let mut all: Vec<String> = listing
        .lines()
        .filter(|l| !l.is_empty() && *l != "SHA256SUMS")
        .map(str::to_owned)
        .collect();
    all.sort();
    let over = names.map_or(all, <[String]>::to_vec);
    let out = common::program("sha256sum")
        .args(&over)
        .current_dir(&root)
        .env("LC_ALL", "C")
        .output()
        .expect("sha256sum");
    std::fs::write(root.join("SHA256SUMS"), out.stdout).expect("manifest");
    if !listing.lines().any(|l| l == "SHA256SUMS") {
        write(dir, "assets", &format!("{listing}SHA256SUMS\n"));
    }
}

/// The binary SBOM a composed leg publishes, derived as the producer derives it.
fn binary_sbom(dir: &Path, target: &str) -> String {
    let out = common::program("mise")
        .arg("-C")
        .arg(at_root("."))
        .args(["run", "sbom-binary", "--", "--names", target])
        .env("SBOM_BINARY_ROOT", dir)
        .output()
        .expect("mise run sbom-binary -- --names");
    assert!(
        out.status.success(),
        "sbom-binary --names: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let line = String::from_utf8_lossy(&out.stdout).into_owned();
    line.trim()
        .trim_start_matches("sbom=")
        .rsplit('/')
        .next()
        .expect("a name")
        .to_owned()
}

fn complete(dir: &Path, extra: &[&str]) -> Vec<String> {
    let mut assets: Vec<String> = [
        "batten-9.9.9-x86_64-unknown-linux-gnu.tar.gz",
        "batten-9.9.9-aarch64-apple-darwin.tar.gz",
        "batten.schema.json",
        "batten.local.schema.json",
        "batten.spdx.json",
        "batten.cdx.json",
        "batten-cli-reference.md",
    ]
    .iter()
    .map(|s| (*s).to_owned())
    .collect();
    assets.push(binary_sbom(dir, "x86_64-unknown-linux-gnu"));
    assets.push(binary_sbom(dir, "aarch64-apple-darwin"));
    assets.extend(extra.iter().map(|s| (*s).to_owned()));
    assets
}

fn produce(dir: &Path, tag: Option<&str>) -> Output {
    let mut command = common::task_command(dir, "release-assets-record");
    command
        .env("BATTEN_RELEASE_WORKFLOW", dir.join("workflow.yml"))
        .env("BATTEN_TASKS_DIR", at_root("mise-tasks"))
        .env(
            "BATTEN_CHECKSUM_MANIFEST",
            common::task_env("BATTEN_CHECKSUM_MANIFEST"),
        )
        .env(
            "BATTEN_CLI_REFERENCE",
            common::task_env("BATTEN_CLI_REFERENCE"),
        )
        .stdin(Stdio::null());
    match tag {
        Some(tag) => command.env("usage_tag", tag),
        None => command.env_remove("usage_tag"),
    };
    command.output().expect("run the producer")
}

fn said(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

/// Produce (asserting it recorded), then decide.
fn decide(dir: &Path) -> (Option<i32>, String) {
    let produced = produce(dir, Some("v9.9.9"));
    assert!(
        produced.status.success(),
        "the producer records: {}",
        said(&produced)
    );
    let decided = common::run(dir, &["check", "--rule", "release grade other"]);
    (decided.status.code(), said(&decided))
}

#[test]
fn a_complete_release_with_a_valid_manifest_is_clean() {
    let dir = repo("complete");
    let assets = complete(&dir, &[]);
    release(&dir, &assets);
    manifest(&dir, None);
    let (code, text) = decide(&dir);
    assert_eq!(code, Some(0), "{text}");
}

#[test]
fn a_release_with_only_the_schema_is_refused() {
    // v0.0.36 exactly: the schema shipped and every dist leg died.
    let dir = repo("schema-only");
    release(&dir, &["batten.schema.json".to_owned()]);
    let (code, text) = decide(&dir);
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
}

#[test]
fn a_partial_release_names_the_missing_target_and_not_the_present_one() {
    let dir = repo("partial");
    release(
        &dir,
        &["batten-9.9.9-x86_64-unknown-linux-gnu.tar.gz".to_owned()],
    );
    let (code, text) = decide(&dir);
    assert_eq!(code, Some(2), "{text}");
    assert!(text.contains("aarch64-apple-darwin"), "{text}");
    assert!(!text.contains("x86_64-unknown-linux-gnu release"), "{text}");
}

#[test]
fn every_non_target_asset_is_demanded_from_both_sources() {
    let dir = repo("non-target");
    let archives = vec![
        "batten-9.9.9-x86_64-unknown-linux-gnu.tar.gz".to_owned(),
        "batten-9.9.9-aarch64-apple-darwin.tar.gz".to_owned(),
    ];
    release(&dir, &archives);
    let (code, text) = decide(&dir);
    assert_eq!(code, Some(2), "{text}");
    for name in [
        "batten.schema.json",
        "batten.local.schema.json",
        "batten.spdx.json",
        "batten.cdx.json",
        "batten-cli-reference.md",
    ] {
        assert!(text.contains(name), "{name}: {text}");
    }
    // CLOUD-262: every archive present and the SBOMs still demanded.
    let sboms = repo("no-sbom");
    let mut assets = complete(&sboms, &[]);
    assets.retain(|a| a != "batten.spdx.json" && a != "batten.cdx.json");
    release(&sboms, &assets);
    manifest(&sboms, None);
    let (code, text) = decide(&sboms);
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
    let demanded = repo("sh-demanded");
    write(&demanded, "workflow.yml", &workflow);
    let assets = complete(&demanded, &[]);
    release(&demanded, &assets);
    manifest(&demanded, None);
    let (code, text) = decide(&demanded);
    assert_eq!(code, Some(2), "{text}");
    assert!(text.contains("install.sh"), "{text}");
    let satisfied = repo("sh-satisfied");
    write(&satisfied, "workflow.yml", &workflow);
    let assets = complete(&satisfied, &["install.sh"]);
    release(&satisfied, &assets);
    manifest(&satisfied, None);
    let (code, text) = decide(&satisfied);
    assert_eq!(code, Some(0), "{text}");
}

#[test]
fn a_name_containing_another_does_not_satisfy_it() {
    // `.spdx.json.sig` must not stand in for `.spdx.json`, nor the authority
    // schema for the override one.
    let dir = repo("containing");
    let mut assets = complete(&dir, &["batten.spdx.json.sig"]);
    assets.retain(|a| a != "batten.spdx.json" && a != "batten.local.schema.json");
    release(&dir, &assets);
    manifest(&dir, None);
    let (code, text) = decide(&dir);
    assert_eq!(code, Some(2), "{text}");
    assert!(text.contains("batten.spdx.json"), "{text}");
    assert!(text.contains("batten.local.schema.json"), "{text}");
}

#[test]
fn no_tag_or_an_empty_tag_falls_back_to_the_latest_release() {
    for (name, tag) in [("absent", None), ("empty", Some(""))] {
        let dir = repo(&format!("latest-{name}"));
        let assets = complete(&dir, &[]);
        release(&dir, &assets);
        manifest(&dir, None);
        let produced = produce(&dir, tag);
        assert!(produced.status.success(), "{name}: {}", said(&produced));
        let decided = common::run(&dir, &["check", "--rule", "release grade other"]);
        assert_eq!(decided.status.code(), Some(0), "{name}");
    }
}

#[test]
fn every_input_the_producer_cannot_read_is_exit_2_and_records_nothing() {
    let unreadable = repo("gh-fails");
    let assets = complete(&unreadable, &[]);
    release(&unreadable, &assets);
    manifest(&unreadable, None);
    write(&unreadable, "gh.fails", "");
    assert_eq!(produce(&unreadable, Some("v9.9.9")).status.code(), Some(2));

    let download = repo("download-fails");
    let assets = complete(&download, &[]);
    release(&download, &assets);
    manifest(&download, None);
    write(&download, "download.fails", "");
    assert_eq!(produce(&download, Some("v9.9.9")).status.code(), Some(2));

    let no_upload = repo("no-upload");
    write(
        &no_upload,
        "workflow.yml",
        &WORKFLOW.replace("gh release upload", "echo"),
    );
    release(&no_upload, &[]);
    assert_eq!(produce(&no_upload, Some("v9.9.9")).status.code(), Some(2));

    let no_targets = repo("no-targets");
    write(&no_targets, "workflow.yml", "jobs:\n  dist:\n");
    release(&no_targets, &[]);
    assert_eq!(produce(&no_targets, Some("v9.9.9")).status.code(), Some(2));

    let absent = repo("absent-workflow");
    std::fs::remove_file(absent.join("workflow.yml")).expect("rm");
    release(&absent, &[]);
    assert_eq!(produce(&absent, Some("v9.9.9")).status.code(), Some(2));
    let after = common::run(&absent, &["check", "--rule", "release grade other"]);
    assert_eq!(after.status.code(), Some(0), "nothing recorded to judge");
}

#[test]
fn a_release_with_no_manifest_is_refused_and_nothing_else_is() {
    let dir = repo("no-manifest");
    let assets = complete(&dir, &[]);
    release(&dir, &assets);
    let (code, text) = decide(&dir);
    assert_eq!(code, Some(2), "{text}");
    assert!(text.contains("checksums-missing"), "{text}");
    assert!(
        !text.contains("release ship missing"),
        "complete but unpinned: {text}"
    );
}

#[test]
fn a_manifest_omitting_an_asset_or_naming_an_orphan_is_refused() {
    let omits = repo("omits");
    let assets = complete(&omits, &[]);
    release(&omits, &assets);
    let without: Vec<String> = assets
        .iter()
        .filter(|a| a.as_str() != "batten.schema.json")
        .cloned()
        .collect();
    manifest(&omits, Some(&without));
    let (code, text) = decide(&omits);
    assert_eq!(code, Some(2), "{text}");
    assert!(text.contains("batten.schema.json"), "{text}");
    assert!(text.contains("checksums-omits"), "{text}");

    let orphan = repo("orphan");
    let assets = complete(&orphan, &[]);
    release(&orphan, &assets);
    manifest(&orphan, None);
    let path = orphan.join("release/SHA256SUMS");
    let mut text = std::fs::read_to_string(&path).expect("manifest");
    text.push_str(&"0".repeat(64));
    text.push_str("  batten-9.9.9-x86_64-pc-windows-gnu.zip\n");
    std::fs::write(&path, text).expect("orphan entry");
    let (code, text) = decide(&orphan);
    assert_eq!(code, Some(2), "{text}");
    assert!(text.contains("x86_64-pc-windows-gnu.zip"), "{text}");
    assert!(text.contains("checksums-orphan"), "{text}");
}

#[test]
fn a_manifest_whose_only_entry_is_itself_is_self_and_empty() {
    let dir = repo("vacuous");
    let assets = complete(&dir, &[]);
    release(&dir, &assets);
    manifest(&dir, None);
    std::fs::write(
        dir.join("release/SHA256SUMS"),
        format!("{:064}  SHA256SUMS\n", 0),
    )
    .expect("vacuous manifest");
    let (code, text) = decide(&dir);
    assert_eq!(code, Some(2), "{text}");
    assert!(text.contains("checksums-self"), "{text}");
    assert!(text.contains("checksums-empty"), "{text}");
}

#[test]
fn a_byte_mismatch_is_refused_once_the_names_agree() {
    let dir = repo("mismatch");
    let assets = complete(&dir, &[]);
    release(&dir, &assets);
    manifest(&dir, None);
    std::fs::write(
        dir.join("release/batten-9.9.9-aarch64-apple-darwin.tar.gz"),
        "tampered\n",
    )
    .expect("tamper");
    let (code, text) = decide(&dir);
    assert_eq!(code, Some(2), "{text}");
    assert!(text.contains("aarch64-apple-darwin.tar.gz"), "{text}");
    assert!(text.contains("checksums-mismatch"), "{text}");
    assert!(!text.contains("x86_64-unknown-linux-gnu.tar.gz"), "{text}");
}

#[test]
fn a_release_with_only_the_schema_is_refused_by_the_one_rule() {
    // The rule id is the one the release workflow's wrapper checks.
    let dir = repo("one-rule");
    release(&dir, &["batten.schema.json".to_owned()]);
    let (_, text) = decide(&dir);
    assert!(text.contains("release grade other"), "{text}");
}

// --- the committed workflow ----------------------------------------------------

fn committed(path: &str) -> String {
    std::fs::read_to_string(at_root(path)).expect("committed file")
}

#[test]
fn the_real_workflow_publishes_both_schemas_and_the_manifest() {
    let workflow = committed(".github/workflows/release-artifacts.yml");
    let uploads: String = workflow
        .lines()
        .filter(|l| l.contains("gh release upload"))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(uploads.contains("batten.schema.json"), "{uploads}");
    assert!(uploads.contains("batten.local.schema.json"), "{uploads}");
    assert!(workflow.contains("mise run checksums"));
    assert!(workflow.contains(r#"gh release upload "$TAG" "$SUMS" --clobber"#));
}

#[test]
fn the_manifest_job_runs_after_everything_that_uploads_an_asset() {
    let workflow = committed(".github/workflows/release-artifacts.yml");
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

#[test]
fn the_real_matrix_is_readable_by_the_producers_parser() {
    let workflow = committed(".github/workflows/release-artifacts.yml");
    let targets = workflow
        .lines()
        .filter(|l| {
            let t = l.trim_start();
            t.starts_with("- target:") || t.starts_with("-  target:")
        })
        .count();
    assert!(targets >= 7, "{targets} targets");
}

#[test]
fn upload_precedes_attestation_and_attestation_cannot_fail_the_leg() {
    let workflow = committed(".github/workflows/release-artifacts.yml");
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
    let workflow = committed(".github/workflows/release-artifacts.yml");
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

#[test]
fn a_release_assets_record_without_its_census_is_torn_rather_than_clean() {
    let dir = repo("torn");
    let written = common::run_with_stdin(
        &dir,
        &["record", "named", "release-assets"],
        // CLEAN BUT FOR THE CENSUS, so the torn arm is the only thing that can
        // refuse it: one asset, the manifest on the release, and a manifest
        // covering that asset.
        "asset\ta.tar.gz\nasset\tSHA256SUMS\nmanifest\tSHA256SUMS\ncovered\ta.tar.gz\n",
    );
    assert!(written.status.success(), "{}", said(&written));
    let decided = common::run(&dir, &["check", "--rule", "release grade other"]);
    assert_eq!(decided.status.code(), Some(2), "{}", said(&decided));
}
