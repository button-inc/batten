//! `batten artifacts write` over the compiled binary (CLOUD-1991).
//!
//! The writer the `completions`, `man`, `schema` and `render:cli` task bodies
//! retired onto. Each of those bodies was a `generate` call and a shell redirect
//! into a committed path; the verb writes the same bytes into the path the
//! caller names. So the property this tier pins is BYTE IDENTITY with `generate`,
//! which is what keeps the drift gates that diff a committed artifact against
//! `generate` (`surface.rs`, `schema-check`) meaningful after the move.
//!
//! # RETIREMENT LEDGER — the four `mise.toml` bodies
//!
// carried: "completions: every shell's script is regenerated from the surface" crates/batten/src/lib.rs kind:verb crates/batten/tests/it/artifacts_write.rs
// carried: "schema: all four surfaces are regenerated together, so none drifts alone" crates/batten/src/lib.rs kind:verb crates/batten/tests/it/artifacts_write.rs
// carried: "man: the page list is derived from the spec, one page per command plus the root" crates/batten/src/lib.rs kind:verb crates/batten/tests/it/artifacts_write.rs
// carried: "man: the directory is cleared first, so a removed verb's page does not survive" crates/batten/src/lib.rs kind:verb crates/batten/tests/it/artifacts_write.rs
// carried: "render:cli: the render writes the reference and names it on stdout, one KEY=VALUE line" crates/batten/src/lib.rs kind:verb crates/batten/tests/it/artifacts_write.rs
// changed: "man: the clear removes every `man/*.1`" crates/batten/src/lib.rs the verb clears only `*.1` in the directory it is handed, which is the same set the body's `rm -f man/*.1` reached; a file of any other kind in the caller's directory is the caller's and survives, which `a_stale_page_is_removed_and_nothing_else_is` pins

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Output;

fn run(dir: &Path, args: &[&str]) -> Output {
    common::batten()
        .args(args)
        .current_dir(dir)
        .output()
        .expect("run batten")
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

/// What `generate` emits for `args`, which is the authority the writer's bytes
/// must equal.
fn generated(dir: &Path, args: &[&str]) -> Vec<u8> {
    let output = run(dir, args);
    assert!(output.status.success(), "generate {args:?} ran");
    output.stdout
}

fn scratch(name: &str) -> PathBuf {
    common::scratch(&format!("artifacts-write-{name}"))
}

#[test]
fn completions_are_the_bytes_generate_emits() {
    let dir = scratch("completions");
    let output = run(&dir, &["artifacts", "write", "--completions", "out"]);
    assert!(output.status.success(), "{}", stdout(&output));
    assert_eq!(
        stdout(&output),
        "completions=out\n",
        "one pointer, never the payload"
    );
    for shell in ["bash", "zsh", "fish"] {
        assert_eq!(
            fs::read(dir.join(format!("out/batten.{shell}"))).expect("the script was written"),
            generated(&dir, &["generate", "completions", "--shell", shell]),
            "the {shell} script is byte-identical to `generate completions`"
        );
    }
}

#[test]
fn every_schema_surface_is_the_bytes_generate_emits() {
    let dir = scratch("schema");
    let output = run(&dir, &["artifacts", "write", "--schema", "out"]);
    assert!(output.status.success(), "{}", stdout(&output));
    assert_eq!(stdout(&output), "schema=out\n");
    for (file, surface) in [
        ("batten.schema.json", "authority"),
        ("batten.local.schema.json", "override"),
        ("policy-input.schema.json", "policy-input"),
        ("policy-call.schema.json", "policy-call"),
    ] {
        assert_eq!(
            fs::read(dir.join("out").join(file)).expect("the schema was written"),
            generated(&dir, &["generate", "schema", "--surface", surface]),
            "{file} is byte-identical to `generate schema --surface {surface}`"
        );
    }
}

/// Every root-relative command path the spec declares, depth first.
fn spec_paths(node: &serde_json::Value, into: &mut Vec<String>) {
    for sub in node["subcommands"].as_array().into_iter().flatten() {
        into.push(sub["path"].as_str().expect("a path").to_owned());
        spec_paths(sub, into);
    }
}

#[test]
fn one_page_per_command_plus_the_root_and_each_is_generates_bytes() {
    let dir = scratch("man");
    let output = run(&dir, &["artifacts", "write", "--man", "out"]);
    assert!(output.status.success(), "{}", stdout(&output));

    let spec: serde_json::Value =
        serde_json::from_slice(&generated(&dir, &["spec", "--format", "json"])).expect("spec");
    let mut paths = Vec::new();
    spec_paths(&spec, &mut paths);
    let mut expected: Vec<String> = std::iter::once(String::from("batten.1"))
        .chain(
            paths
                .iter()
                .map(|path| format!("batten-{}.1", path.replace(' ', "-"))),
        )
        .collect();
    expected.sort();
    let mut written: Vec<String> = fs::read_dir(dir.join("out"))
        .expect("the directory was written")
        .map(|entry| {
            entry
                .expect("entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    written.sort();
    assert_eq!(written, expected, "exactly the pages the spec declares");
    assert_eq!(
        stdout(&output),
        format!("man=out pages={}\n", expected.len())
    );

    // Byte identity, sampled at the root and at a nested command.
    assert_eq!(
        fs::read(dir.join("out/batten.1")).expect("root page"),
        generated(&dir, &["generate", "man"]),
    );
    assert_eq!(
        fs::read(dir.join("out/batten-config-show.1")).expect("a nested page"),
        generated(&dir, &["generate", "man", "config show"]),
    );
}

#[test]
fn a_stale_page_is_removed_and_nothing_else_is() {
    let dir = scratch("man-stale");
    common::write(&dir, "out/batten-a-verb-that-was-removed.1", "stale\n");
    common::write(&dir, "out/README", "the caller's own file\n");
    let output = run(&dir, &["artifacts", "write", "--man", "out"]);
    assert!(output.status.success(), "{}", stdout(&output));
    assert!(
        !dir.join("out/batten-a-verb-that-was-removed.1").exists(),
        "a page the surface no longer declares does not survive the refresh"
    );
    assert!(
        dir.join("out/README").exists(),
        "a file that is not a page is the caller's and is left alone"
    );
}

#[test]
fn the_reference_is_written_and_named_on_one_line() {
    let dir = scratch("reference");
    let output = run(
        &dir,
        &["artifacts", "write", "--reference", "reference/cli.md"],
    );
    assert!(output.status.success(), "{}", stdout(&output));
    assert_eq!(
        stdout(&output),
        "reference=reference/cli.md\n",
        "the KEY=VALUE line is the only thing on stdout"
    );
    let written = fs::read(dir.join("reference/cli.md")).expect("the reference");
    assert!(!written.is_empty(), "the reference is not empty");
    assert_eq!(written, generated(&dir, &["generate", "markdown"]));
}

#[test]
fn naming_nothing_is_a_usage_error_and_writes_nothing() {
    let dir = scratch("nothing");
    let output = run(&dir, &["artifacts", "write"]);
    assert_eq!(
        output.status.code(),
        Some(batten::exit::ExitCode::Usage.code()),
        "a request for no derivation is a statement about the invocation"
    );
    assert_eq!(
        fs::read_dir(&dir).expect("scratch").count(),
        0,
        "and nothing was written"
    );
}
