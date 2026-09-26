//! `cargo list other` over the compiled binary and the REAL producer (CLOUD-263,
//! CLOUD-1717).
//!
//! `[tasks.sbom-binary-record]` is read out of `mise.toml` and run against a
//! stubbed `syft` that recovers a chosen count — the real tool cannot be made to,
//! so nothing else would prove the bar is `>= 2` rather than `>= 0`. The engine
//! then decides over what was recorded, and `[tasks.sbom-binary]`'s own body is
//! run too, with `mise` stubbed to the producer, for the half only the wrapper
//! owns: a refused inventory leaves no asset, and a clean one prints its pointers.
//!
//! # RETIREMENT LEDGER, PER PATH — what `shell retire partial` reads
//!
// carried: mise-tasks/sbom-binary.sh policy/sbom-binary.rego kind:mechanism crates/batten/tests/it/sbom_binary.rs
// carried: tests/sbom-binary.bats policy/sbom-binary.rego kind:mechanism crates/batten/tests/it/sbom_binary.rs
// carried: "a binary whose crates are all in the lockfile passes, and writes the asset" policy/sbom-binary.rego kind:mechanism
// changed: "THE NEGATIVE SELF-TEST: an empty inventory must not report green" policy/sbom-binary.rego refused as `cargo list empty` through `check`, exit 2 rather than 1; the `(0 rust-crate` sentence was the program's prose, and the count is the finding's second subject
// carried: "ONE package is the other vacuous shape, and also fails" policy/sbom-binary.rego kind:mechanism
// carried: "the count is filtered to rust-crate, so a self-artifact cannot pad it" mise.toml kind:mechanism
// carried: "a refused inventory leaves no asset behind" mise.toml kind:mechanism
// changed: "a crate absent from Cargo.lock fails, naming counts and not the crate" policy/sbom-binary.rego refused as `cargo list wrong` through `check`; the count of foreign crates is the finding's subject where the program printed `1 of 2`, and the crate's name is still never printed
// carried: "SUBSET, NOT EQUALITY: a lockfile larger than the recovery passes" policy/sbom-binary.rego kind:mechanism
// carried: "the asset name comes from dist's stem rule, so seven legs cannot race" mise.toml kind:mechanism
// carried: "output is pointer-only — no document body reaches the log" policy/sbom-binary.rego kind:mechanism
// carried: "a syft that cannot run is exit 2 — could not look is not a verdict" mise.toml kind:mechanism
// carried: "a missing binary is exit 2, not a refusal of the release" mise.toml kind:mechanism
// carried: "a missing Cargo.lock is exit 2 — there is nothing to hold the crates against" mise.toml kind:mechanism
// carried: "no target is a usage error, never a pass" mise.toml kind:mechanism

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

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

/// A `mise` answering only `run sbom-binary-record -- <binary> <target>`, by
/// running the producer's committed body.
const MISE: &str = r#"#!/usr/bin/env bash
set -euo pipefail
[ "$1 $2" = "run sbom-binary-record" ] || exit 97
shift 2
[ "${1:-}" != "--" ] || shift
export usage_binary="${1:-}" usage_target="${2:-}"
cd "$PRODUCER_CWD"
exec bash "$FIXTURE/record.sh"
"#;

fn body(task: &str) -> String {
    let manifest = fs::read_to_string(at_root("mise.toml")).expect("the manifest");
    let parsed: toml::Value = toml::from_str(&manifest).expect("mise.toml parses as TOML");
    parsed["tasks"][task]["run"]
        .as_str()
        .unwrap_or_else(|| panic!("[tasks.{task}] declares a run body"))
        .lines()
        .filter(|line| !line.contains("{% raw %}") && !line.contains("{% endraw %}"))
        .collect::<Vec<_>>()
        .join("\n")
}

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
    let module = fs::read_to_string(at_root("policy/sbom-binary.rego")).expect("the module");
    write(&dir, "policy/sbom-binary.rego", &module);
    let verdict = |id: &str| {
        format!(
            "[[verdict]]\nid = \"{id}\"\ngloss = \"fixture\"\nclass = \"fixture\"\n\n\
             [[verdict.route]]\nid = \"task run first\"\nkind = \"command\"\n\
             target = \"mise run sbom-binary-record\"\n\n"
        )
    };
    write(
        &dir,
        "batten.toml",
        &format!(
            "version = 1\nscope = [\"**\"]\n\n{}{}\
             [[rule]]\nid = \"cargo list other\"\nkind = \"policy\"\nscope = \"tree\"\n\
             module = \"policy/sbom-binary.rego\"\nline_sources = [\"Cargo.lock\"]\n\
             severity = \"deny\"\n\n\
             [[record]]\nrecord = \"sbom-binary\"\nwriter = \"mise run sbom-binary-record\"\n",
            verdict("cargo list empty"),
            verdict("cargo list wrong"),
        ),
    );
    write(&dir, "Cargo.toml", "version = \"9.9.9\"\n");
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
    executable(&dir.join("syft"), SYFT);
    fs::create_dir_all(dir.join("bin")).expect("bin");
    executable(&dir.join("bin/mise"), MISE);
    write(&dir, "record.sh", &body("sbom-binary-record"));
    init_repo(&dir);
    git_in(&dir, &["add", "-A"]);
    git_in(&dir, &["commit", "-qm", "register the module"]);
    dir
}

fn command(dir: &Path, task: &str, binary: &str, target: Option<&str>) -> Command {
    let template = common::batten();
    let mut command = Command::new("bash");
    for (name, value) in template.get_envs() {
        match value {
            Some(value) => command.env(name, value),
            None => command.env_remove(name),
        };
    }
    let mut paths = vec![dir.join("bin")];
    paths.extend(std::env::split_paths(
        &std::env::var_os("PATH").unwrap_or_default(),
    ));
    command
        .args(["-c", &body(task)])
        .env("PATH", std::env::join_paths(paths).expect("PATH"))
        .env("FIXTURE", dir)
        .env("PRODUCER_CWD", at_root("."))
        .env("SBOM_BINARY_ROOT", dir)
        .env("SBOM_BINARY_SYFT", dir.join("syft"))
        .env_remove("SBOM_BINARY_OUT_DIR")
        .env("usage_binary", binary)
        .stdin(Stdio::null());
    match target {
        Some(target) => command.env("usage_target", target),
        None => command.env_remove("usage_target"),
    };
    command
}

/// The producer alone, run from the repository root as mise runs it.
fn produce(dir: &Path, binary: &str, target: Option<&str>) -> Output {
    command(dir, "sbom-binary-record", binary, target)
        .current_dir(at_root("."))
        .output()
        .expect("run the producer")
}

/// The wrapper, run from the fixture so its `check` reads the fixture's config.
fn wrapper(dir: &Path) -> Output {
    command(
        dir,
        "sbom-binary",
        &dir.join("batten").display().to_string(),
        Some(TARGET),
    )
    .current_dir(dir)
    .output()
    .expect("run the wrapper")
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
    let out = wrapper(&dir);
    assert!(out.status.success(), "{}", said(&out));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("packages=2"), "{stdout}");
    assert!(stdout.contains(&format!("sbom={ASSET}")), "{stdout}");
    assert!(dir.join(ASSET).is_file());
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
    let (code, text) = verdict(&dir);
    assert_eq!(code, Some(2), "{text}");
    assert!(
        text.contains("batten-v9.9.9-x86_64-unknown-linux-gnu.spdx.json"),
        "{text}"
    );
}

#[test]
fn a_refused_inventory_leaves_no_asset_behind() {
    let dir = repo("refused");
    write(&dir, "count", "0\n");
    let out = wrapper(&dir);
    assert_eq!(out.status.code(), Some(2), "{}", said(&out));
    assert!(!dir.join(ASSET).exists(), "the refused asset was removed");
    assert!(
        !String::from_utf8_lossy(&out.stdout).contains("sbom="),
        "no pointer to a refused asset reaches $GITHUB_OUTPUT"
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
    let out = produce(&dir, "--names", Some("aarch64-apple-darwin"));
    assert!(out.status.success(), "{}", said(&out));
    assert!(
        String::from_utf8_lossy(&out.stdout)
            .contains("batten-v9.9.9-aarch64-apple-darwin.spdx.json"),
        "{}",
        said(&out)
    );
}

#[test]
fn output_is_pointer_only() {
    let dir = repo("pointer");
    write(&dir, "syft.foreign", "");
    let out = wrapper(&dir);
    let text = said(&out);
    assert!(!text.contains("SPDXRef"), "{text}");
    assert!(!text.contains("rust-crate\""), "{text}");
}

#[test]
fn every_reading_the_producer_cannot_take_is_exit_2_and_records_nothing() {
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
            Some(2),
            "{name}: {}",
            said(&produced)
        );
        assert!(
            said(&produced).contains(needle),
            "{name}: {}",
            said(&produced)
        );
        assert!(
            !dir.join(ASSET).exists() || name == "no-lock" || name == "no-binary",
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
fn no_target_is_a_usage_error_never_a_pass() {
    let dir = repo("usage");
    let out = produce(&dir, &dir.join("batten").display().to_string(), None);
    assert_eq!(out.status.code(), Some(2), "{}", said(&out));
    assert!(said(&out).contains("usage:"), "{}", said(&out));
}
