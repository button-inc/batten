//! End-to-end tests over the compiled binary for the derived `batten.toml`
//! JSON Schema and the `min_batten_version` gate (CLOUD-33).
//!
//! Two properties, both of which a consumer depends on:
//!
//! * the schema Batten **publishes** accepts exactly the configs Batten
//!   **accepts** — a published schema that disagrees with the binary is worse
//!   than none, because it tells a consumer their valid config is invalid;
//! * a binary too old for a config refuses it rather than reporting green over
//!   rules it did not understand.
//!
//! Kept out of `tests/cli.rs` deliberately — that file is the exit-code and
//! output-contract suite, and other work appends to it.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::fs;
use std::path::PathBuf;
use std::process::Output;

use common::{Fixture, at_root, batten, scratch};

/// The schema as the binary derives it, parsed.
fn derived_schema() -> serde_json::Value {
    let output = batten()
        .args(["generate", "schema"])
        .output()
        .expect("run batten generate schema");
    assert_eq!(output.status.code(), Some(0));
    serde_json::from_slice(&output.stdout).expect("the schema is JSON")
}

/// A `batten.toml` body, converted to the JSON the schema validates against.
fn as_json(toml_text: &str) -> serde_json::Value {
    toml::from_str::<serde_json::Value>(toml_text).expect("config is valid TOML")
}

/// Create a temp repo containing a `batten.toml` with `contents`.
fn repo_with_config(name: &str, contents: &str) -> PathBuf {
    Fixture::new(name).config(contents).build()
}

fn check_in(dir: &std::path::Path) -> Output {
    common::run(dir, &["check"])
}

/// The build's own version, which the gate compares against.
const VERSION: &str = env!("CARGO_PKG_VERSION");

// --- the schema is derived, published, and agrees with the binary ------------

#[test]
fn the_committed_schema_is_the_one_the_binary_derives() {
    // DoR §4's byte-for-byte drift assertion, over the compiled binary rather
    // than only through the shell gate — so a stale committed schema fails the
    // Rust suite too and cannot land while `hk` alone is skipped.
    let committed = fs::read_to_string(at_root("schema/batten.schema.json"))
        .expect("read the committed schema");
    let output = batten()
        .args(["generate", "schema"])
        .output()
        .expect("run batten generate schema");
    assert_eq!(
        committed.as_bytes(),
        output.stdout.as_slice(),
        "schema/batten.schema.json differs from the config types; run `mise run schema`"
    );
}

#[test]
fn the_schema_is_byte_stable_across_runs() {
    // §6: identical input, identical bytes. Without this the drift gate would
    // fail at random and teach everyone to re-run it until it passed.
    let first = batten()
        .args(["generate", "schema"])
        .output()
        .unwrap()
        .stdout;
    let second = batten()
        .args(["generate", "schema"])
        .output()
        .unwrap()
        .stdout;
    assert_eq!(first, second, "the derived schema was not byte-stable");
}

#[test]
fn the_schema_validates_the_committed_example_config() {
    // CLOUD-33's headline acceptance. `batten.example.toml` is what a consumer
    // copies, so a schema that rejects it would fail every new adopter in their
    // editor on day one.
    let schema = derived_schema();
    let validator = jsonschema::validator_for(&schema).expect("the schema compiles");
    let example = fs::read_to_string(at_root("batten.example.toml")).expect("read the example");
    let instance = as_json(&example);
    let errors: Vec<String> = validator
        .iter_errors(&instance)
        .map(|err| format!("{}: {err}", err.instance_path()))
        .collect();
    assert!(
        errors.is_empty(),
        "the example config failed the schema: {errors:?}"
    );
}

#[test]
fn the_schema_validates_this_repositorys_own_config() {
    // Consumer #1 in practice, not just in principle: the schema Batten ships
    // is asserted against the config Batten itself is gated by.
    let schema = derived_schema();
    let validator = jsonschema::validator_for(&schema).expect("the schema compiles");
    let own = fs::read_to_string(at_root("batten.toml")).expect("read batten.toml");
    assert!(
        validator.is_valid(&as_json(&own)),
        "this repository's own batten.toml failed the schema it ships"
    );
}

#[test]
fn the_schema_refuses_what_the_binary_refuses() {
    // The property that makes publishing safe: schema and binary must agree.
    // An unknown key is a hard error at parse time (`deny_unknown_fields`), so
    // the schema must reject it too — otherwise an editor waves through a config
    // `batten check` will refuse, which is the worst of both.
    let schema = derived_schema();
    let validator = jsonschema::validator_for(&schema).expect("the schema compiles");
    let bad = "version = 1\nnot_a_real_key = \"oops\"\n";
    assert!(
        !validator.is_valid(&as_json(bad)),
        "the schema accepted an unknown key the binary rejects"
    );

    let dir = repo_with_config("schema-unknown-key", bad);
    assert_eq!(
        check_in(&dir).status.code(),
        Some(1),
        "an unknown key is a usage error"
    );
}

#[test]
fn the_schema_requires_the_keys_the_binary_requires() {
    // `version` is required and every rule pins `severity` explicitly — both
    // are parse-time usage errors, so both must be `required` in the schema.
    let schema = derived_schema();
    let validator = jsonschema::validator_for(&schema).expect("the schema compiles");
    assert!(
        !validator.is_valid(&as_json("strictness = \"strict\"\n")),
        "the schema accepted a config with no version"
    );
    let no_severity = "version = 1\n\n[[rule]]\nid = \"r\"\nkind = \"forbid\"\nglob = \"**/*.rs\"\npattern = \"x\"\n";
    assert!(
        !validator.is_valid(&as_json(no_severity)),
        "the schema accepted a rule with no severity"
    );
}

#[test]
fn generate_schema_writes_no_file() {
    // What keeps `generate schema`'s `read` effect structurally honest (§5):
    // the verb emits on stdout and touches nothing. The redirect that refreshes
    // the committed artifact is `mise run schema`, in the caller.
    let dir = scratch("schema-writes-no-file");
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("create scratch dir");
    let output = batten()
        .args(["generate", "schema"])
        .current_dir(&dir)
        .output()
        .expect("run batten generate schema");
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(
        fs::read_dir(&dir).expect("read scratch dir").count(),
        0,
        "a read-effect verb wrote to the working directory"
    );
}

// --- the min_batten_version gate ---------------------------------------------

#[test]
fn a_config_requiring_a_newer_binary_is_refused() {
    // The gate. Exit 1, not 2: this is a statement about the *invocation*
    // ("this binary is too old"), never a verdict about the repository. A
    // harness reading 2 would report a policy denial that never happened (§7).
    let dir = repo_with_config(
        "min-version-too-new",
        "version = 1\nmin_batten_version = \"99.0.0\"\n",
    );
    let output = check_in(&dir);
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("99.0.0") && stderr.contains(VERSION),
        "the refusal must name both versions, got: {stderr}"
    );
    assert!(
        output.stdout.is_empty(),
        "stdout stays the answer channel; a refusal is not an answer"
    );
}

#[test]
fn a_config_requiring_this_exact_version_runs() {
    // Equal is compatible — the boundary case a `>` / `>=` slip would invert.
    let dir = repo_with_config(
        "min-version-equal",
        &format!("version = 1\nmin_batten_version = \"{VERSION}\"\n"),
    );
    assert_eq!(check_in(&dir).status.code(), Some(0));
}

#[test]
fn a_config_requiring_an_older_binary_runs() {
    let dir = repo_with_config(
        "min-version-older",
        "version = 1\nmin_batten_version = \"0.0.0\"\n",
    );
    assert_eq!(check_in(&dir).status.code(), Some(0));
}

#[test]
fn a_config_with_no_minimum_runs() {
    // Absent means "this file does not speak to a minimum" — not "0.0.0", and
    // certainly not a refusal.
    let dir = repo_with_config("min-version-absent", "version = 1\n");
    assert_eq!(check_in(&dir).status.code(), Some(0));
}

#[test]
fn an_unparseable_minimum_is_refused_rather_than_ignored() {
    // "Cannot compare" is not "compatible". Skipping the gate on a malformed
    // value would let a typo silently disable it — the failure mode the whole
    // narrow-config discipline exists to prevent (§8).
    let dir = repo_with_config(
        "min-version-garbage",
        "version = 1\nmin_batten_version = \"not-a-version\"\n",
    );
    let output = check_in(&dir);
    assert_eq!(output.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("min_batten_version"),
        "the refusal must name the offending key"
    );
}

#[test]
fn the_gate_applies_to_every_verb_that_reads_config() {
    // Enforced at parse time rather than in one verb, so a too-old binary
    // cannot be routed around by picking a different command.
    let dir = repo_with_config(
        "min-version-all-verbs",
        "version = 1\nmin_batten_version = \"99.0.0\"\n",
    );
    for args in [["check"], ["enforce"]] {
        let output = batten()
            .args(args)
            .current_dir(&dir)
            .output()
            .expect("run batten");
        assert_eq!(output.status.code(), Some(1), "{args:?} skipped the gate");
    }
    let output = batten()
        .args(["config", "show"])
        .current_dir(&dir)
        .output()
        .expect("run batten config show");
    assert_eq!(
        output.status.code(),
        Some(1),
        "config show skipped the gate"
    );
}

#[test]
fn the_schema_accepts_a_mediated_call_rule() {
    // The shape kind and its scope are part of the published vocabulary, so an
    // editor validating against the schema must accept a row the binary accepts.
    let schema = derived_schema();
    let validator = jsonschema::validator_for(&schema).expect("the schema compiles");
    let good = "version = 1\n\n[[rule]]\nid = \"s\"\nkind = \"shape\"\n\
                scope = \"mediated_call\"\nseverity = \"deny\"\n\
                pattern = \"gh pr merge\"\nreason = \"use the landing path\"\n";
    assert!(
        validator.is_valid(&as_json(good)),
        "the schema rejected a shape rule the binary accepts"
    );
}

#[test]
fn the_schema_cannot_express_per_kind_requirements() {
    // An honest negative, recorded rather than papered over (CLOUD-48).
    //
    // `Rule` is a flat `deny_unknown_fields` struct — deliberately, because a
    // `#[serde(flatten)]` enum silently defeats that guarantee — so schemars
    // emits ONE `required` list for every kind. "required iff kind == shape"
    // therefore has nowhere to live, and two columns are looser in the schema
    // than in the binary: `glob`, which a file kind cannot load without, and
    // `reason`, which a shape kind cannot.
    //
    // The consequence is the mirror of `the_schema_refuses_what_the_binary_refuses`:
    // an editor waves a config through that `batten check` then refuses. That is
    // the safer direction of the two — the binary is the authority and it still
    // refuses — but it is a real gap, so it is asserted here rather than left for
    // someone to discover as a surprise.
    let schema = derived_schema();
    let validator = jsonschema::validator_for(&schema).expect("the schema compiles");

    for (label, config) in [
        // A forbid rule with no glob.
        (
            "forbid without glob",
            "version = 1\n\n[[rule]]\nid = \"f\"\nkind = \"forbid\"\n\
             severity = \"deny\"\npattern = \"x\"\n",
        ),
        // A shape rule with no reason.
        (
            "shape without reason",
            "version = 1\n\n[[rule]]\nid = \"s\"\nkind = \"shape\"\n\
             scope = \"mediated_call\"\nseverity = \"deny\"\npattern = \"gh pr merge\"\n",
        ),
    ] {
        assert!(
            validator.is_valid(&as_json(config)),
            "{label}: the schema is expected to be looser here; if it now \
             refuses, per-kind requirements became expressible and this test \
             should be replaced by the positive one"
        );
        // The binary is the authority, and it refuses.
        let dir = repo_with_config(&format!("per-kind-{}", label.replace(' ', "-")), config);
        assert_eq!(
            check_in(&dir).status.code(),
            Some(1),
            "{label}: the binary must refuse what the schema let through"
        );
    }
}
