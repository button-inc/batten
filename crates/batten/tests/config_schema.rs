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

// THE FILE-GRANULARITY RETIREMENT ARMS (CLOUD-1059) for `schema-check`, whose
// predicate this file already held over the compiled binary before the program
// retired onto it. Two paths die, so two arms: a program and its suite are
// separate subjects, and one arm covering both would claim a conservation nobody
// checked. The suite's arm names its declared `# subject:` too (CLOUD-1130),
// which this same delta retires.
//
// carried: mise-tasks/schema-check.sh crates/batten/src/config.rs kind:mechanism crates/batten/tests/config_schema.rs
// carried: tests/schema-check.bats mise-tasks/schema-check.sh crates/batten/src/config.rs kind:mechanism crates/batten/tests/config_schema.rs
//
// CLOUD-908's case arms: every `@test` the retired suite declared, all nine
// carried. Arms are suite-qualified because a case TITLE is not unique across
// suites — `tests/config-deprecations.bats`, retired in this same delta, declares
// two of these titles verbatim, and a bare arm would be borrowed by whichever
// suite looked it up first (the resolution order `rules.rs` records at
// `unconserved_cases`).
//
// carried: "schema-check.bats::a committed schema matching the config types exits 0" crates/batten/tests/config_schema.rs
// carried: "schema-check.bats::a drifted override schema is reported with its own pointer" crates/batten/tests/config_schema.rs
// carried: "schema-check.bats::a missing override schema is reported rather than silently skipped" crates/batten/tests/config_schema.rs
// carried: "schema-check.bats::both surfaces are judged in one run, not just the first to fail" crates/batten/tests/config_schema.rs
// carried: "schema-check.bats::a drifted schema is reported with a pointer" crates/batten/tests/config_schema.rs
// carried: "schema-check.bats::a missing schema is reported rather than silently skipped" crates/batten/tests/config_schema.rs
// carried: "schema-check.bats::output is pointer-only — no schema body echoed" crates/batten/tests/config_schema.rs
// carried: "schema-check.bats::the gate leaves the tree it judges unmodified" crates/batten/tests/config_schema.rs
// carried: "schema-check.bats::this repo's committed schema matches its config types — the gate on the real tree" crates/batten/tests/config_schema.rs

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
fn the_schema_validates_the_shipped_starter_config() {
    // The same acceptance over the artifact `batten init` actually writes
    // (CLOUD-206). Held separately from the example above rather than instead of
    // it: one is a document a reader copies, the other is a file Batten authored,
    // and a schema that rejected the second would break `init` itself.
    let schema = derived_schema();
    let validator = jsonschema::validator_for(&schema).expect("the schema compiles");
    let instance = as_json(batten::init::STARTER);
    let errors: Vec<String> = validator
        .iter_errors(&instance)
        .map(|err| format!("{}: {err}", err.instance_path()))
        .collect();
    assert!(
        errors.is_empty(),
        "the starter config failed the schema: {errors:?}"
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

// --- the override surface is its own schema, and the loader agrees (CLOUD-239)
//
// One authority describing two surfaces is what let a validator green-light
// keys the loader refuses and say nothing about keys it silently dropped. These
// assert the two halves separately, because they mislead in opposite directions:
// `min_batten_version` was vouched for and then refused (loud), while a local
// `protected` was accepted everywhere and applied nowhere (silent, and worse —
// the operator's tightening vanished without a word).

/// The override schema as the binary derives it, parsed.
fn derived_override_schema() -> serde_json::Value {
    let output = batten()
        .args(["generate", "schema", "--surface", "override"])
        .output()
        .expect("run batten generate schema --surface override");
    assert_eq!(output.status.code(), Some(0));
    serde_json::from_slice(&output.stdout).expect("the override schema is JSON")
}

/// A repo with both an authority and a local override.
fn repo_with_local(name: &str, authority: &str, local: &str) -> PathBuf {
    let dir = Fixture::new(name).config(authority).build();
    fs::write(dir.join("batten.local.toml"), local).expect("write batten.local.toml");
    dir
}

/// `batten config show -J` in `dir`.
fn show_in(dir: &std::path::Path) -> Output {
    common::run(dir, &["config", "show", "--json"])
}

#[test]
fn the_committed_override_schema_is_the_one_the_binary_derives() {
    let committed = fs::read_to_string(at_root("schema/batten.local.schema.json"))
        .expect("read the committed override schema");
    let output = batten()
        .args(["generate", "schema", "--surface", "override"])
        .output()
        .expect("run batten generate schema --surface override");
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        committed.trim(),
        "the committed override schema drifted; run `mise run schema`"
    );
}

#[test]
fn the_two_surfaces_are_different_schemas() {
    // The defect in one assertion: if these were equal, one document would be
    // describing two surfaces again and every case below would be vacuous.
    assert_ne!(derived_schema(), derived_override_schema());
}

#[test]
fn the_override_schema_describes_only_keys_the_loader_honours() {
    let schema = derived_override_schema();
    let properties = schema
        .get("properties")
        .and_then(serde_json::Value::as_object)
        .expect("the override schema has properties");
    let mut keys: Vec<&str> = properties.keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        [
            "exec_pattern",
            "fail_on_warning",
            "min_batten_version",
            "protected",
            "redirect",
            "rule",
            "scope",
            "strictness",
            "unlanded",
            "version",
            "waiver",
        ],
        "the override surface changed; every key here must be one `resolve` reads"
    );
    // Every authority-only key is absent, so a validator cannot vouch for one.
    for authority_only in [
        "epoch",
        "marker",
        "verb",
        "budget",
        "must_land_on",
        "judge",
        "ci",
        "defects",
        "provision",
        "transcript",
        // CLOUD-720. Sharper than its neighbours, for `hook`'s reason: turning
        // `[trust] offline_fallback` on LOWERS the bar, so there is no reading
        // of §8's raise-only rule under which an uncommitted file may set it.
        "trust",
    ] {
        assert!(
            !properties.contains_key(authority_only),
            "the override schema vouches for `{authority_only}`, which the loader refuses"
        );
    }
    assert_eq!(
        schema.get("additionalProperties"),
        Some(&serde_json::json!(false)),
        "without this an unknown key would validate and then fail to load"
    );
}

#[test]
fn a_local_protected_is_applied_rather_than_dropped() {
    // THE silent-drop case, which no test covered — which is why it shipped. A
    // developer adding a protected path got no complaint from the editor, none
    // from `taplo lint`, none from `batten check`, and no effect.
    let dir = repo_with_local(
        "override-protected",
        "version = 1\nprotected = [\"a/**\"]\n",
        "version = 1\nprotected = [\"migrations/**\"]\n",
    );
    let output = show_in(&dir);
    assert_eq!(output.status.code(), Some(0));
    let doc: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("config show emits JSON");
    assert_eq!(
        doc["protected"]["value"],
        serde_json::json!(["a/**", "migrations/**"]),
        "the local tightening was dropped"
    );
    assert_eq!(
        doc["protected"]["source"],
        serde_json::json!("local-file"),
        "an applied override must be attributed to the layer that applied it"
    );
}

#[test]
fn a_local_unlanded_is_applied_too() {
    let dir = repo_with_local(
        "override-unlanded",
        "version = 1\n",
        "version = 1\nunlanded = [\"wip/**\"]\n",
    );
    let output = show_in(&dir);
    assert_eq!(output.status.code(), Some(0));
    let doc: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("config show emits JSON");
    assert_eq!(doc["unlanded"]["value"], serde_json::json!(["wip/**"]));
    assert_eq!(doc["unlanded"]["source"], serde_json::json!("local-file"));
}

#[test]
fn a_local_scope_narrows_by_excluding() {
    let dir = repo_with_local(
        "override-scope-narrows",
        "version = 1\nscope = [\"src/**\"]\n",
        "version = 1\nscope = [\"!src/vendor/**\"]\n",
    );
    let output = show_in(&dir);
    assert_eq!(output.status.code(), Some(0));
    let doc: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("config show emits JSON");
    assert_eq!(
        doc["scope"]["value"],
        serde_json::json!(["src/**", "!src/vendor/**"]),
        "the exclude must be appended to the authority's ordered list"
    );
    assert_eq!(doc["scope"]["source"], serde_json::json!("local-file"));
}

#[test]
fn a_local_scope_may_not_widen() {
    // Includes union, so a local include could only ever ADD paths — which is
    // the widening §8's raise-only clause exists to make impossible. Refused
    // rather than accepted-and-ignored, so the author learns the file cannot do
    // what they asked.
    let dir = repo_with_local(
        "override-scope-widens",
        "version = 1\nscope = [\"src/**\"]\n",
        "version = 1\nscope = [\"extra/**\"]\n",
    );
    let output = show_in(&dir);
    assert_eq!(
        output.status.code(),
        Some(1),
        "a widening scope must refuse"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("extra/**"),
        "the refusal must name the entry"
    );
    assert!(
        stderr.contains("NARROW"),
        "and say which direction is allowed"
    );
    assert!(output.stdout.is_empty(), "a refusal printed a document");
}

#[test]
fn an_authority_only_key_in_the_local_file_is_refused_by_name() {
    // `deny_unknown_fields` on the override type, doing the work a hand-written
    // refusal list would drift away from.
    let dir = repo_with_local(
        "override-epoch",
        "version = 1\n",
        "version = 1\n[epoch]\ntracked = [\"batten.toml\"]\n",
    );
    let output = show_in(&dir);
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("epoch"), "the refusal must name the key");
}

#[test]
fn the_offline_fallback_cannot_be_turned_on_by_an_uncommitted_file() {
    // The escape hatch has to be a COMMITTED decision (CLOUD-720). Enabling it
    // lets an unreachable base ref be answered from a pin rather than refusing,
    // which is a lower bar — and §8 admits no raise-only reading of a key whose
    // only direction is downward. `deny_unknown_fields` on the override type is
    // what makes the refusal total, so nothing here is a maintained list.
    let dir = repo_with_local(
        "override-trust",
        "version = 1\n",
        "version = 1\n[trust]\noffline_fallback = true\n",
    );
    let output = show_in(&dir);
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("trust"), "the refusal must name the key");
    assert!(output.stdout.is_empty(), "a refusal printed a document");
}

#[test]
fn min_batten_version_keeps_its_specific_refusal() {
    // The loud half of the original defect: the validator called it valid and
    // the loader refused the file. Both now refuse — and the message stays the
    // specific one, because "unknown field" would read as a typo when the real
    // mistake is that the key belongs to the committed authority alone.
    let dir = repo_with_local(
        "override-min-version",
        "version = 1\n",
        &format!("version = 1\nmin_batten_version = \"{VERSION}\"\n"),
    );
    let output = show_in(&dir);
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("authority"),
        "the refusal must say the key is authority-only, not merely unknown: {stderr}"
    );

    // And the schema now agrees with the loader about it: the key is present in
    // the override schema only so the message can name it, so a validator must
    // not treat the file as clean either.
    let schema = derived_override_schema();
    assert!(
        schema["properties"].get("min_batten_version").is_some(),
        "carried deliberately, so the refusal can be specific"
    );
}

#[test]
fn the_honoured_keys_still_load_together() {
    // The positive case: a local file carrying only honoured keys validates and
    // applies, so this change refuses nothing it should accept.
    let dir = repo_with_local(
        "override-honoured",
        "version = 1\nscope = [\"src/**\"]\nprotected = [\"a/**\"]\nstrictness = \"permissive\"\n",
        "version = 1\nstrictness = \"strict\"\nfail_on_warning = true\nscope = [\"!src/gen/**\"]\n\
         protected = [\"b/**\"]\nunlanded = [\"wip/**\"]\n",
    );
    let output = show_in(&dir);
    assert_eq!(
        output.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let doc: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("config show emits JSON");
    assert_eq!(doc["strictness"]["value"], serde_json::json!("strict"));
    assert_eq!(doc["fail_on_warning"]["value"], serde_json::json!(true));
    assert_eq!(
        doc["scope"]["value"],
        serde_json::json!(["src/**", "!src/gen/**"])
    );
    assert_eq!(
        doc["protected"]["value"],
        serde_json::json!(["a/**", "b/**"])
    );
}

// --- the drift gate fires on every module the schemas derive from (CLOUD-33) -
//
// `schema-check` diffs the committed artifacts against their generator, and
// `hk.pkl` scopes it with a literal glob. A module reachable from `Config` but
// absent from that glob is a gate that does not fire on the commit that moved
// the artifact — CLOUD-59 measured exactly that and patched the list by hand,
// adding the two modules its own change touched and leaving fourteen others
// that were already reachable. The repair was incomplete the day it landed,
// which is the argument for a gate rather than for a longer list.
//
// So the list stops being the authority. Set EQUALITY, in both directions:
// a module deriving `JsonSchema` and absent from the glob is the CLOUD-59
// failure; a glob entry naming a module that no longer derives one is a dead
// entry claiming coverage it does not need. Equality rather than an exemption
// list on purpose — an entry that turns out unreachable costs one extra
// pre-commit run of a cheap gate, and a list of stated exceptions is a second
// authority that goes stale the same way the first one did.

/// The `crates/batten/src/*.rs` entries of `hk.pkl`'s `schema-check` glob.
fn schema_check_globbed_modules() -> Vec<String> {
    let hk = fs::read_to_string(at_root("hk.pkl")).expect("read hk.pkl");
    let start = hk
        .find("[\"schema-check\"]")
        .expect("hk.pkl declares a schema-check step");
    let rest = &hk[start..];
    let step = &rest[..rest.find("\n  }").expect("the step closes")];

    let mut modules: Vec<String> = step
        .lines()
        .filter_map(|line| {
            let entry = line.trim().trim_end_matches(',').trim_matches('"');
            entry
                .strip_prefix("crates/batten/src/")?
                .strip_suffix(".rs")
                .map(str::to_owned)
        })
        .collect();
    modules.sort();
    modules
}

/// Every module under `crates/batten/src` that derives `JsonSchema`, which is
/// exactly the set either schema can be reachable from.
fn modules_deriving_json_schema() -> Vec<String> {
    let mut modules: Vec<String> = fs::read_dir(at_root("crates/batten/src"))
        .expect("read the crate source directory")
        .map(|entry| entry.expect("read a directory entry").path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "rs"))
        .filter(|path| {
            fs::read_to_string(path)
                .expect("read a source file")
                .contains("JsonSchema")
        })
        .map(|path| {
            path.file_stem()
                .expect("a .rs file has a stem")
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    modules.sort();
    modules
}

#[test]
fn the_schema_check_glob_names_every_module_the_schemas_derive_from() {
    let globbed = schema_check_globbed_modules();
    let deriving = modules_deriving_json_schema();

    assert!(
        !globbed.is_empty() && !deriving.is_empty(),
        "one side of this comparison came back empty, so the test would pass \
         vacuously. Neither the glob nor the deriving set can legitimately be \
         empty in this crate."
    );

    let missing: Vec<&String> = deriving.iter().filter(|m| !globbed.contains(m)).collect();
    assert!(
        missing.is_empty(),
        "these modules derive `JsonSchema` and are absent from hk.pkl's \
         `schema-check` glob, so a commit touching only one of them moves a \
         published schema without firing the drift gate (CLOUD-59, CLOUD-33): \
         {missing:?}"
    );

    let dead: Vec<&String> = globbed.iter().filter(|m| !deriving.contains(m)).collect();
    assert!(
        dead.is_empty(),
        "hk.pkl's `schema-check` glob names these modules, which no longer \
         derive `JsonSchema`. Drop them rather than leaving the list claiming \
         a reach it does not have: {dead:?}"
    );
}

// --- the drift reading, as the retired `schema-check` decided it (CLOUD-33) ---
//
// The two cases above assert the committed artifacts equal what the binary
// derives, which is the predicate at its happy end. What they cannot show is that
// the reading DISCRIMINATES: an equality assertion over the real tree passes just
// as well for a comparator that answers "equal" unconditionally. These cases run
// the same comparison over a fixture whose copies are doctored, so each verdict
// is shown able to fail — and they carry the two answers the real tree can never
// produce, a missing artifact and a run that must not rewrite what it judges.
//
// Both surfaces, judged the same way (CLOUD-239). `batten.toml` is the committed
// authority and `batten.local.toml` is the raise-only override, which accepts a
// strict subset — two types, so two derivations. Checking only the first is how
// the published schema came to vouch for override keys the loader drops.

/// The two committed artifacts and the surface each is derived from.
const SURFACES: [(&str, &str); 2] = [
    ("authority", "schema/batten.schema.json"),
    ("override", "schema/batten.local.schema.json"),
];

/// The schema the binary derives for `surface`.
fn derived_for(surface: &str) -> Vec<u8> {
    let output = batten()
        .args(["generate", "schema", "--surface", surface])
        .output()
        .expect("run batten generate schema --surface");
    assert_eq!(output.status.code(), Some(0));
    output.stdout
}

/// Pointer-only findings (non-negotiable rule 4): the file that drifted and the
/// predicate id, never the diff body — the remedy is always the same one command,
/// and a schema diff would put the config surface itself into the log.
///
/// Both surfaces are judged before returning, so one run names every drifted
/// artifact rather than only the first.
fn drift_findings(root: &std::path::Path) -> Vec<String> {
    let mut findings = Vec::new();
    for (surface, committed) in SURFACES {
        let path = root.join(committed);
        let Ok(bytes) = fs::read(&path) else {
            findings.push(format!("{committed}:0 schema-missing"));
            continue;
        };
        if bytes != derived_for(surface) {
            findings.push(format!("{committed}:0 schema-drift"));
        }
    }
    findings
}

/// A scratch root holding its own copy of `schema/`, which is the only thing a
/// case mutates.
fn schema_fixture(name: &str) -> PathBuf {
    let root = scratch(name);
    fs::create_dir_all(root.join("schema")).expect("create the schema directory");
    for (surface, committed) in SURFACES {
        fs::write(root.join(committed), derived_for(surface)).expect("seed the committed schema");
    }
    root
}

#[test]
fn a_fixture_matching_the_config_types_raises_nothing() {
    // The anti-vacuity mirror for every case below: without it a comparator that
    // reported drift unconditionally would satisfy all of them.
    let root = schema_fixture("schema-drift-clean");
    assert!(drift_findings(&root).is_empty());
}

#[test]
fn a_drifted_schema_is_reported_with_a_pointer() {
    // The shape of real drift: a key the committed schema still describes after
    // the type behind it changed.
    let root = schema_fixture("schema-drift-authority");
    fs::write(
        root.join("schema/batten.schema.json"),
        b"{\"$schema\":\"https://json-schema.org/draft/2020-12/schema\",\"title\":\"Config\",\"type\":\"object\"}\n",
    )
    .expect("doctor the committed schema");
    assert_eq!(
        drift_findings(&root),
        vec!["schema/batten.schema.json:0 schema-drift".to_owned()]
    );
}

#[test]
fn a_drifted_override_schema_is_reported_with_its_own_pointer() {
    // The override surface is a SECOND artifact with its own derivation
    // (CLOUD-239), and it owes every property the first one does.
    let root = schema_fixture("schema-drift-override");
    fs::write(
        root.join("schema/batten.local.schema.json"),
        b"{\"$schema\":\"https://json-schema.org/draft/2020-12/schema\",\"title\":\"OverrideConfig\",\"type\":\"object\"}\n",
    )
    .expect("doctor the committed override schema");
    assert_eq!(
        drift_findings(&root),
        vec!["schema/batten.local.schema.json:0 schema-drift".to_owned()]
    );
}

#[test]
fn both_surfaces_are_judged_in_one_run_not_just_the_first_to_fail() {
    // Fixing the authority's copy and re-running must not be how you discover the
    // override's is stale too.
    let root = schema_fixture("schema-drift-both");
    fs::write(
        root.join("schema/batten.schema.json"),
        b"{\"title\":\"Drifted\"}\n",
    )
    .expect("doctor the authority schema");
    fs::write(
        root.join("schema/batten.local.schema.json"),
        b"{\"title\":\"AlsoDrifted\"}\n",
    )
    .expect("doctor the override schema");
    assert_eq!(
        drift_findings(&root),
        vec![
            "schema/batten.schema.json:0 schema-drift".to_owned(),
            "schema/batten.local.schema.json:0 schema-drift".to_owned(),
        ]
    );
}

#[test]
fn a_missing_schema_is_reported_rather_than_silently_skipped() {
    let root = schema_fixture("schema-drift-absent-authority");
    fs::remove_file(root.join("schema/batten.schema.json")).expect("drop the committed schema");
    assert_eq!(
        drift_findings(&root),
        vec!["schema/batten.schema.json:0 schema-missing".to_owned()]
    );
}

#[test]
fn a_missing_override_schema_is_reported_rather_than_silently_skipped() {
    let root = schema_fixture("schema-drift-absent-override");
    fs::remove_file(root.join("schema/batten.local.schema.json"))
        .expect("drop the committed override schema");
    assert_eq!(
        drift_findings(&root),
        vec!["schema/batten.local.schema.json:0 schema-missing".to_owned()]
    );
}

#[test]
fn the_drift_report_is_pointer_only_and_echoes_no_schema_body() {
    // rule 4: the remedy is one command, so the diff body adds nothing and would
    // put the config surface itself into the log.
    const DISTINCTIVE: &str = "AVeryDistinctiveInventedTitle";
    let root = schema_fixture("schema-drift-pointer");
    fs::write(
        root.join("schema/batten.schema.json"),
        format!("{{\"title\":\"{DISTINCTIVE}\"}}\n").as_bytes(),
    )
    .expect("doctor the committed schema");
    let findings = drift_findings(&root);
    let report = findings.join(" ");
    assert!(report.contains("schema-drift"), "{report}");
    assert!(
        !report.contains(DISTINCTIVE),
        "the report carried the schema body: {report}"
    );
}

#[test]
fn the_reading_leaves_the_tree_it_judges_unmodified() {
    // A check that rewrites what it judges cannot fail twice: the second run would
    // pass, laundering the drift into a clean result.
    let root = schema_fixture("schema-drift-readonly");
    let doctored = b"{\"title\":\"Drifted\"}\n";
    fs::write(root.join("schema/batten.schema.json"), doctored)
        .expect("doctor the committed schema");
    assert_eq!(drift_findings(&root).len(), 1);
    assert_eq!(
        fs::read(root.join("schema/batten.schema.json")).expect("read it back"),
        doctored,
        "the reading rewrote the artifact it was judging"
    );
    assert_eq!(
        drift_findings(&root).len(),
        1,
        "the same tree must fail twice"
    );
}
