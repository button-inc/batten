//! `cargo list other` over the compiled binary and the REAL producer (CLOUD-263,
//! CLOUD-1717, CLOUD-843).
//!
//! `batten sbom --binary` is run against a stubbed `syft` that recovers a chosen
//! count — the real tool cannot be made to, so nothing else would prove the bar
//! is `>= 2` rather than `>= 0`. The engine then decides over what was recorded,
//! through the vendored `supply-chain` preset the fixture enables by name — the
//! decision moved out of this repository's `policy/sbom-binary.rego` under CLOUD-843,
//! so this is also the scratch-repo tier proving the bundle decides for a consumer
//! that is not this one.
//! The producer was `[tasks.sbom-binary-record]`'s inline body until CLOUD-843
//! retired it onto the verb; `[tasks.sbom-binary]` is argv glue now that
//! produces, `[tasks.sbom-binary-check]` the one rule, and their shape is
//! asserted at the foot of this file.
//!
//! # RETIREMENT LEDGER, PER PATH — what `shell retire partial` reads
//!
// carried: mise-tasks/sbom-binary.sh crates/batten/src/policy/presets/supply-chain/binary-inventory-is-lockfile-bound.rego kind:mechanism crates/batten/tests/it/sbom_binary.rs
// carried: tests/sbom-binary.bats crates/batten/src/policy/presets/supply-chain/binary-inventory-is-lockfile-bound.rego kind:mechanism crates/batten/tests/it/sbom_binary.rs
// carried: "a binary whose crates are all in the lockfile passes, and writes the asset" crates/batten/src/policy/presets/supply-chain/binary-inventory-is-lockfile-bound.rego kind:mechanism
// changed: "THE NEGATIVE SELF-TEST: an empty inventory must not report green" crates/batten/src/policy/presets/supply-chain/binary-inventory-is-lockfile-bound.rego refused as `cargo list empty` through `check`, exit 2 rather than 1; the `(0 rust-crate` sentence was the program's prose, and the count is the finding's second subject
// carried: "ONE package is the other vacuous shape, and also fails" crates/batten/src/policy/presets/supply-chain/binary-inventory-is-lockfile-bound.rego kind:mechanism
// carried: "the count is filtered to rust-crate, so a self-artifact cannot pad it" crates/batten/src/sbom.rs kind:verb
// changed: "a refused inventory leaves no asset behind" mise.toml `[tasks.sbom-binary]` is one argv that produces and `[tasks.sbom-binary-check]` one that decides, two tasks because the producer's stdout is `$GITHUB_OUTPUT`'s and the finding's is the log's — so a refusal fails its own step with the asset still on the runner's disk; that step is the workflow's last before the upload, and a failed step publishes nothing. `the_binary_task_produces_and_its_check_task_decides` asserts the split and `the_release_workflow_uploads_the_binary_sbom_only_after_the_task_passes` the workflow's order and channel, the two halves the property now rests on
// changed: "a crate absent from Cargo.lock fails, naming counts and not the crate" crates/batten/src/policy/presets/supply-chain/binary-inventory-is-lockfile-bound.rego refused as `cargo list wrong` through `check`; the count of foreign crates is the finding's subject where the program printed `1 of 2`, and the crate's name is still never printed
// carried: "SUBSET, NOT EQUALITY: a lockfile larger than the recovery passes" crates/batten/src/policy/presets/supply-chain/binary-inventory-is-lockfile-bound.rego kind:mechanism
// changed: "the asset name comes from dist's stem rule, so seven legs cannot race" crates/batten/src/dist.rs the stem is `dist::archive_stem` — `<subject>-v<version>-<target>`, the one naming contract `batten dist --stem` and `release install` also read — computed in-process rather than by spawning a program
// "output is pointer-only — no document body reaches the log" shares its title with a case already ledgered in `sbom_inventory.rs`; a title owes exactly one arm, so that row answers for both suites.
// changed: "a syft that cannot run is exit 2 — could not look is not a verdict" crates/batten/src/sbom.rs could-not-look is exit 3 under the engine's one exit table, and the half-written asset is removed
// changed: "a missing binary is exit 2, not a refusal of the release" crates/batten/src/sbom.rs the same move, to exit 3
// changed: "a missing Cargo.lock is exit 2 — there is nothing to hold the crates against" crates/batten/src/sbom.rs the same move, to exit 3
// changed: "no target is a usage error, never a pass" crates/batten/src/sbom.rs a usage error is exit 1 under the engine's one exit table, where the body exited 2

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Output, Stdio};

use common::{at_root, git_in, init_repo, scratch, write};

const TARGET: &str = "x86_64-unknown-linux-gnu";
const ASSET: &str = "dist/batten-v9.9.9-x86_64-unknown-linux-gnu.spdx.json";

/// A `syft` that writes both outputs and recovers `$FIXTURE/count` rust-crate
/// artifacts. Sentinels: `syft.fails`, `syft.foreign` (the second crate is not
/// in the lockfile) and `syft.file` (also an artifact for the binary itself).
const SYFT: &str = r#"#!/usr/bin/env bash
set -euo pipefail
[ ! -f "$FIXTURE/syft.fails" ] || exit 1
spdx=""
scan=""
want=0
for arg in "$@"; do
	if [ "$want" = 1 ]; then
		case "$arg" in
		spdx-json=*) spdx="${arg#spdx-json=}" ;;
		syft-json=*) scan="${arg#syft-json=}" ;;
		esac
		want=0
		continue
	fi
	[ "$arg" = "--output" ] && want=1
done
n=$(cat "$FIXTURE/count")
names=(alpha beta)
versions=(1.0.0 2.0.0)
[ ! -f "$FIXTURE/syft.foreign" ] || names=(alpha not-in-the-lockfile)
artifacts=""
i=0
while [ "$i" -lt "$n" ]; do
	[ -z "$artifacts" ] || artifacts="$artifacts,"
	artifacts="$artifacts{\"name\":\"${names[$i]}\",\"version\":\"${versions[$i]}\",\"type\":\"rust-crate\"}"
	i=$((i + 1))
done
if [ -f "$FIXTURE/syft.file" ]; then
	[ -z "$artifacts" ] || artifacts="$artifacts,"
	artifacts="$artifacts{\"name\":\"batten\",\"version\":\"9.9.9\",\"type\":\"binary\"}"
fi
mkdir -p "$(dirname "$spdx")" "$(dirname "$scan")"
echo "{\"SPDXID\":\"SPDXRef-DOCUMENT\",\"name\":\"batten\",\"packages\":[]}" >"$spdx"
echo "{\"artifacts\":[$artifacts]}" >"$scan"
"#;

fn executable(path: &Path, text: &str) {
    fs::write(path, text).expect("write stub");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mut permissions = fs::metadata(path).expect("stat").permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(path, permissions).expect("chmod");
    }
}

fn repo(name: &str) -> PathBuf {
    let dir = scratch(&format!("sbom-binary-{name}"));
    // A CONSUMER THAT IS NOT THIS REPOSITORY: no module of its own and no
    // `[[verdict]]` row, only the vendored `supply-chain` preset enabled by name.
    write(
        &dir,
        "batten.toml",
        "version = 1\nscope = [\"**\"]\n\n\
         [[rule]]\nid = \"cargo list other\"\nkind = \"policy\"\nscope = \"tree\"\n\
         preset = \"supply-chain\"\nline_sources = [\"Cargo.lock\"]\n\
         severity = \"deny\"\n\n\
         [[record]]\nrecord = \"sbom-binary\"\nwriter = \"batten sbom --binary <binary> --target <triple>\"\n\n\
         [sbom]\nsubject = \"batten\"\nout_dir = \"sbom\"\nbinary_out_dir = \"dist\"\n",
    );
    // A REAL, if tiny, workspace: the asset name is `batten dist --stem`'s now
    // (CLOUD-843), which reads the package through `cargo metadata` rather than
    // scraping a `version =` line, so the manifest has to be one cargo accepts.
    // `[workspace]` keeps cargo from walking up into the tree the scratch sits in.
    write(
        &dir,
        "Cargo.toml",
        "[workspace]\n\n[package]\nname = \"batten\"\nversion = \"9.9.9\"\nedition = \"2021\"\n\n\
         [[bin]]\nname = \"batten\"\npath = \"main.rs\"\n",
    );
    write(&dir, "main.rs", "fn main() {}\n");
    // The lockfile declares the crates the stub recovers plus one it does not.
    write(
        &dir,
        "Cargo.lock",
        "[[package]]\nname = \"alpha\"\nversion = \"1.0.0\"\n\n\
         [[package]]\nname = \"beta\"\nversion = \"2.0.0\"\n\n\
         [[package]]\nname = \"only-a-dev-dependency\"\nversion = \"3.0.0\"\n",
    );
    write(&dir, "batten", "binary bytes\n");
    write(&dir, "count", "2\n");
    write(&dir, ".gitignore", "bin/\ndist/\ncount\nsyft.*\n");
    fs::create_dir_all(dir.join("bin")).expect("bin");
    executable(&dir.join("bin/syft"), SYFT);
    init_repo(&dir);
    git_in(&dir, &["add", "-A"]);
    git_in(&dir, &["commit", "-qm", "register the module"]);
    dir
}

/// The compiled binary in `dir`, with the stubbed `syft` first on `PATH`.
fn batten(dir: &Path, args: &[&str]) -> Output {
    let inherited = std::env::var_os("PATH").unwrap_or_default();
    let path = std::env::join_paths(
        std::iter::once(dir.join("bin")).chain(std::env::split_paths(&inherited)),
    )
    .expect("a PATH entry carries no separator");
    common::batten()
        .args(args)
        .current_dir(dir)
        .env("PATH", path)
        .env("FIXTURE", dir)
        .stdin(Stdio::null())
        .output()
        .expect("run batten")
}

/// The producer over `binary`, for `target` when given.
fn produce(dir: &Path, binary: &str, target: Option<&str>) -> Output {
    let mut args = vec!["sbom", "--binary", binary];
    if let Some(target) = target {
        args.extend(["--target", target]);
    }
    batten(dir, &args)
}

fn said(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

/// Produce (asserting it recorded), then decide.
fn verdict(dir: &Path) -> (Option<i32>, String) {
    let binary = dir.join("batten").display().to_string();
    let produced = produce(dir, &binary, Some(TARGET));
    assert!(
        produced.status.success(),
        "the producer records: {}",
        said(&produced)
    );
    // JSON, because the pointer line names the row and the verdict is its class.
    let decided = common::run(dir, &["check", "-J", "--rule", "cargo list other"]);
    (decided.status.code(), said(&decided))
}

#[test]
fn a_binary_whose_crates_are_all_in_the_lockfile_passes_and_writes_the_asset() {
    let dir = repo("clean");
    let binary = dir.join("batten").display().to_string();
    let out = produce(&dir, &binary, Some(TARGET));
    assert!(out.status.success(), "{}", said(&out));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(stdout, format!("sbom={ASSET}\npackages=2\n"));
    assert!(dir.join(ASSET).is_file());
    let decided = common::run(&dir, &["check", "--rule", "cargo list other"]);
    assert_eq!(decided.status.code(), Some(0), "{}", said(&decided));
}

#[test]
fn the_negative_self_test_an_empty_inventory_must_not_report_green() {
    let dir = repo("empty");
    write(&dir, "count", "0\n");
    let (code, text) = verdict(&dir);
    assert_eq!(code, Some(2), "{text}");
    assert!(
        text.contains("batten-v9.9.9-x86_64-unknown-linux-gnu.spdx.json"),
        "{text}"
    );
}

#[test]
fn one_package_is_the_other_vacuous_shape() {
    let dir = repo("one");
    write(&dir, "count", "1\n");
    let (code, text) = verdict(&dir);
    assert_eq!(code, Some(2), "{text}");
    assert!(
        text.contains("batten-v9.9.9-x86_64-unknown-linux-gnu.spdx.json"),
        "{text}"
    );
}

#[test]
fn the_count_is_filtered_to_rust_crate_so_a_self_artifact_cannot_pad_it() {
    let dir = repo("self-artifact");
    write(&dir, "count", "1\n");
    write(&dir, "syft.file", "");
    // The count itself, before any decision: a padded count of 2 would turn the
    // vacuous refusal into a `cargo list wrong` one and still exit 2.
    let binary = dir.join("batten").display().to_string();
    let produced = produce(&dir, &binary, Some(TARGET));
    assert!(
        String::from_utf8_lossy(&produced.stdout).contains("packages=1\n"),
        "{}",
        said(&produced)
    );
    let (code, text) = verdict(&dir);
    assert_eq!(code, Some(2), "{text}");
    assert!(
        text.contains("batten-v9.9.9-x86_64-unknown-linux-gnu.spdx.json"),
        "{text}"
    );
}

#[test]
fn a_crate_absent_from_the_lockfile_fails_naming_counts_not_the_crate() {
    let dir = repo("foreign");
    write(&dir, "syft.foreign", "");
    let (code, text) = verdict(&dir);
    assert_eq!(code, Some(2), "{text}");
    assert!(
        text.contains("batten-v9.9.9-x86_64-unknown-linux-gnu.spdx.json"),
        "{text}"
    );
    assert!(!text.contains("not-in-the-lockfile"), "rule 4: {text}");
}

#[test]
fn subset_not_equality_a_larger_lockfile_passes() {
    let dir = repo("subset");
    let (code, text) = verdict(&dir);
    assert_eq!(code, Some(0), "{text}");
}

#[test]
fn the_asset_name_comes_from_dists_stem_rule() {
    let dir = repo("names");
    let out = batten(
        &dir,
        &["sbom", "--names", "--target", "aarch64-apple-darwin"],
    );
    assert!(out.status.success(), "{}", said(&out));
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        "sbom=dist/batten-v9.9.9-aarch64-apple-darwin.spdx.json\n"
    );
}

#[test]
fn output_is_pointer_only() {
    let dir = repo("pointer");
    write(&dir, "syft.foreign", "");
    let binary = dir.join("batten").display().to_string();
    let produced = produce(&dir, &binary, Some(TARGET));
    let decided = common::run(&dir, &["check", "--rule", "cargo list other"]);
    for text in [said(&produced), said(&decided)] {
        assert!(!text.contains("SPDXRef"), "{text}");
        assert!(!text.contains("rust-crate"), "{text}");
        assert!(!text.contains("not-in-the-lockfile"), "{text}");
    }
}

#[test]
fn every_reading_the_producer_cannot_take_is_exit_3_and_records_nothing() {
    for (name, setup, binary, needle) in [
        ("no-syft", "syft.fails", "batten", "unverified"),
        ("no-binary", "", "no-such-binary", "nothing to inventory"),
        (
            "no-lock",
            "rm:Cargo.lock",
            "batten",
            "must not report green",
        ),
    ] {
        let dir = repo(name);
        if let Some(path) = setup.strip_prefix("rm:") {
            fs::remove_file(dir.join(path)).expect("remove");
        } else if !setup.is_empty() {
            write(&dir, setup, "");
        }
        let produced = produce(&dir, &dir.join(binary).display().to_string(), Some(TARGET));
        assert_eq!(
            produced.status.code(),
            Some(3),
            "{name}: {}",
            said(&produced)
        );
        assert!(
            said(&produced).contains(needle),
            "{name}: {}",
            said(&produced)
        );
        assert!(
            !dir.join(ASSET).exists(),
            "{name}: no asset from a scan that failed"
        );
        if dir.join("Cargo.lock").exists() {
            let after = common::run(&dir, &["check", "--rule", "cargo list other"]);
            assert_eq!(
                after.status.code(),
                Some(0),
                "{name}: nothing recorded to judge"
            );
        }
    }
}

#[test]
fn a_scan_that_cannot_look_removes_the_previous_record() {
    // A stale record answering as the current reading is the one failure a
    // could-not-look producer must not leave behind.
    let dir = repo("stale");
    write(&dir, "count", "0\n");
    let binary = dir.join("batten").display().to_string();
    assert!(produce(&dir, &binary, Some(TARGET)).status.success());
    let refused = common::run(&dir, &["check", "--rule", "cargo list other"]);
    assert_eq!(refused.status.code(), Some(2), "{}", said(&refused));
    write(&dir, "syft.fails", "");
    let produced = produce(&dir, &binary, Some(TARGET));
    assert_eq!(produced.status.code(), Some(3), "{}", said(&produced));
    let after = common::run(&dir, &["check", "--rule", "cargo list other"]);
    assert_eq!(after.status.code(), Some(0), "{}", said(&after));
}

#[test]
fn no_target_is_a_usage_error_never_a_pass() {
    let dir = repo("usage");
    let out = produce(&dir, &dir.join("batten").display().to_string(), None);
    assert_eq!(out.status.code(), Some(1), "{}", said(&out));
    assert!(said(&out).contains("usage:"), "{}", said(&out));
    assert!(!dir.join("dist").exists());
}

#[test]
fn the_binary_task_produces_and_its_check_task_decides() {
    // Two tasks because two channels: `sbom-binary`'s stdout is appended to
    // `$GITHUB_OUTPUT`, so it may carry the producer's KEY=VALUE pointers and
    // nothing else — a refusal printed there would reach the output file rather
    // than the job log. The decision is therefore its own task, and the producer
    // must not run it.
    let manifest = fs::read_to_string(at_root("mise.toml")).expect("the manifest");
    let parsed: toml::Value = toml::from_str(&manifest).expect("mise.toml parses as TOML");
    let run = |task: &str| -> String {
        parsed["tasks"][task]["run"]
            .as_str()
            .unwrap_or_else(|| panic!("[tasks.{task}] is one argv"))
            .to_owned()
    };
    let produce = run("sbom-binary");
    assert!(
        produce.ends_with("sbom --binary {{usage.binary}} --target {{usage.target}}"),
        "{produce}"
    );
    assert!(!produce.contains(" check "), "{produce}");
    // The committed row enabling `supply-chain` is `commit grade unsafe`: one row
    // per preset and scope (`policy::load`), so the SBOM half is decided there and
    // `cargo list other` is the module's own rule, not a config row.
    let decide = run("sbom-binary-check");
    assert!(
        decide.ends_with("check --rule 'commit grade unsafe'"),
        "{decide}"
    );
}

#[test]
fn the_release_workflow_uploads_the_binary_sbom_only_after_the_task_passes() {
    // The other half of "a refused inventory is never published": the asset
    // stays on the runner's disk after a refusal, so what keeps it off the
    // release is the WORKFLOW — the upload is a later step of the same job, it
    // reads the task's own output, and neither step lets a failure through.
    use yaml_rust2::{Yaml, YamlLoader};
    let text = fs::read_to_string(at_root(".github/workflows/release-artifacts.yml"))
        .expect("the release workflow");
    let docs = YamlLoader::load_from_str(&text).expect("the workflow parses as YAML");
    let field = |step: &Yaml, key: &str| step[key].as_str().unwrap_or_default().to_owned();
    let mut judged = 0;
    for (_, job) in docs[0]["jobs"].as_hash().expect("jobs") {
        let Some(steps) = job["steps"].as_vec() else {
            continue;
        };
        let Some(at) = steps
            .iter()
            .position(|step| field(step, "run").contains("mise run sbom-binary "))
        else {
            continue;
        };
        let produce = &steps[at];
        let id = field(produce, "id");
        assert!(!id.is_empty(), "the inventory step carries an id");
        assert!(
            produce["continue-on-error"].is_badvalue(),
            "a refused inventory must fail its step"
        );
        // The decision is its own step, whose stdout is the job log: never the
        // step that appends to `$GITHUB_OUTPUT`, and never redirected itself.
        assert!(
            !field(produce, "run").contains("sbom-binary-check"),
            "the check does not share the output-file step"
        );
        let decide = steps
            .iter()
            .position(|step| field(step, "run").contains("mise run sbom-binary-check"))
            .expect("a step runs `mise run sbom-binary-check`");
        assert!(decide > at, "the check follows the inventory step");
        assert!(
            !field(&steps[decide], "run").contains('>'),
            "the check's finding reaches the log, not a file"
        );
        assert!(
            steps[decide]["continue-on-error"].is_badvalue(),
            "a refused inventory must fail its step"
        );
        assert_eq!(
            field(&steps[decide], "if"),
            field(produce, "if"),
            "the check runs on every leg that inventories"
        );
        let reads = format!("steps.{id}.outputs.sbom");
        // The output reaches the upload through its `env:` since the step became
        // one `ci step` argv (CLOUD-843, Phase 4); `run:` is still read, so the
        // older spelling cannot slip past either.
        let hands_on = |step: &Yaml| {
            field(step, "run").contains(&reads)
                || step["env"].as_hash().is_some_and(|env| {
                    env.values()
                        .any(|value| value.as_str().is_some_and(|v| v.contains(&reads)))
                })
        };
        let uploads: Vec<usize> = steps
            .iter()
            .enumerate()
            .filter(|(_, step)| hands_on(step))
            .map(|(index, _)| index)
            .collect();
        assert!(!uploads.is_empty(), "something uploads {reads}");
        for index in uploads {
            assert!(index > decide, "the upload follows the check step");
            let condition = field(&steps[index], "if");
            assert!(
                !condition.contains("always()") && !condition.contains("failure()"),
                "the upload runs only on success: {condition}"
            );
        }
        judged += 1;
    }
    assert!(judged > 0, "a job runs `mise run sbom-binary`");
}
