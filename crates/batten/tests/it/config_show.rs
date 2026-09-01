//! End-to-end tests for `batten config show` and its total attribution
//! (CLOUD-30).
//!
//! The property under test is the one that makes the verb worth having: **every
//! emitted key carries a source**. The shape it replaces was flat values plus a
//! parallel `sources` map keyed by `SETTINGS`, which made the printed
//! "effective config" partial *structurally* rather than in a list of keys — a
//! `config::Config` field the resolver did not carry never appeared at all, and
//! an emitted key outside `SETTINGS` appeared with no source. Both holes widened
//! with every `batten.toml` key that landed.
//!
//! That is why the assertions below run over the **parsed document** rather than
//! a hand-written key list: a suite that enumerated the keys it expected would
//! have to be edited by the same change that introduced an unsurfaced one, which
//! is exactly the edit an author who forgot the key will also forget.
//!
//! Kept out of `tests/cli.rs` deliberately — that file is the exit-code and
//! output-contract suite, and the convention here is one file per bundle.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::collections::BTreeMap;
use std::path::Path;
use std::process::Output;

use serde_json::Value;

use common::Fixture;

/// The source classes `resolve::Origin` declares (CLOUD-332).
///
/// Stated as tokens rather than read off the type, because these assertions run
/// over the compiled binary's output: a class the engine renamed must fail here
/// even though the library still compiles.
const PROVENANCE_TOKENS: &[&str] = &[
    "builtin",
    "committed",
    "base-ref",
    "uncommitted",
    "ambient",
    "ingested",
];

/// A `batten.toml` setting **every** `config::Config` key, so obligation (b)
/// can assert the document surfaces all of them.
///
/// Deliberately exhaustive rather than representative: the point is that a
/// config key which the resolver forgets to carry shows up here as an absent
/// document key.
const EVERY_KEY: &str = r#"version = 1
min_batten_version = "0.0.1"
strictness = "strict"
must_land_on = "origin/main"
fail_on_warning = true
scope = ["src/**"]
protected = ["policy/**"]
unlanded = ["draft/**"]

[epoch]
tracked = ["batten.toml"]

[[rule]]
id = "no-todo"
kind = "forbid"
glob = "**/*.rs"
pattern = "TODO"
severity = "deny"
scope = "tree"

[[verb]]
verb = "push"
effect = "write"

[[marker]]
id = "allow-once"
token = "batten: allow-once"

[budget.instructions]
files = ["AGENTS.md"]
max_tokens = 3500
max_lines = 200

[judge]
raw = ["span_text"]
run = "judge-stub --strict"
model = "some-model"

[design]
max_capture_bytes = 8192

[drain]
interval_ms = 500
empty_poll_giveup = 2

"#;

fn show(dir: &Path, extra: &[&str]) -> Output {
    let mut args = vec!["config", "show"];
    args.extend_from_slice(extra);
    common::run(dir, &args)
}

/// The `--json` document, parsed.
fn document(dir: &Path) -> BTreeMap<String, Value> {
    let output = show(dir, &["--json"]);
    assert_eq!(
        output.status.code(),
        Some(0),
        "config show failed: {}",
        common::stderr(&output)
    );
    serde_json::from_slice(&output.stdout).expect("the document is one JSON object")
}

// --- (a) every emitted key carries both halves -------------------------------

#[test]
fn every_key_in_the_document_carries_a_value_and_a_source() {
    // Over the parsed document, never a key list: a key the resolver starts
    // emitting without attribution fails here without this file being touched.
    let dir = Fixture::new("config-show-total").config(EVERY_KEY).build();
    let document = document(&dir);
    assert!(
        !document.is_empty(),
        "an empty document would pass vacuously"
    );

    for (key, entry) in &document {
        let object = entry
            .as_object()
            .unwrap_or_else(|| panic!("{key} is not a {{value, source}} object"));
        assert!(object.contains_key("value"), "{key} carries no value");
        let source = object
            .get("source")
            .and_then(Value::as_str)
            .unwrap_or_else(|| panic!("{key} carries no source"));
        // A source is a layer token — never a filesystem path or a raw env
        // value, either of which would break byte-stability across machines and
        // leak a home directory.
        assert!(
            ["flag", "env", "local-file", "repo-config", "default"].contains(&source),
            "{key}: {source} is not one of the five layer tokens"
        );
    }
}

// --- (b) a config key cannot land unsurfaced ---------------------------------

#[test]
fn a_config_that_sets_every_key_surfaces_every_key() {
    // The fixture sets every `config::Config` key. Each must appear in the
    // document with the value it was given — so a resolver that silently
    // dropped a key fails here rather than printing a confident partial answer.
    let dir = Fixture::new("config-show-every-key")
        .config(EVERY_KEY)
        .build();
    let document = document(&dir);

    for key in [
        "version",
        "min_batten_version",
        "strictness",
        "fail_on_warning",
        "rule",
        "scope",
        "protected",
        "unlanded",
        "epoch",
        "verb",
        "marker",
        "budget",
        "must_land_on",
        "judge",
        "design",
        "drain",
    ] {
        let entry = document
            .get(key)
            .unwrap_or_else(|| panic!("the document does not surface {key}"));
        assert_eq!(
            entry["source"], "repo-config",
            "{key} was set by the authority and must be attributed to it"
        );
    }
}

// --- (c) each of the five layers wins in turn ---------------------------------

#[test]
fn each_layer_is_named_by_its_token_when_it_wins() {
    // `default` — a key no layer speaks to.
    let bare = Fixture::new("config-show-default")
        .config("version = 1\n")
        .build();
    assert_eq!(document(&bare)["strictness"]["source"], "default");

    // `repo-config` — the committed authority.
    let committed = Fixture::new("config-show-repo")
        .config("version = 1\nstrictness = \"strict\"\n")
        .build();
    assert_eq!(document(&committed)["strictness"]["source"], "repo-config");

    // `local-file` — the git-ignored override, raising.
    let local = Fixture::new("config-show-local")
        .config("version = 1\n")
        .file(
            "batten.local.toml",
            "version = 1\nstrictness = \"strict\"\n",
        )
        .build();
    assert_eq!(document(&local)["strictness"]["source"], "local-file");

    // `env` — above the local file.
    let env_output = common::batten()
        .args(["config", "show", "--json"])
        .current_dir(&bare)
        .env("BATTEN_STRICTNESS", "strict")
        .output()
        .expect("run batten config show");
    let parsed: BTreeMap<String, Value> =
        serde_json::from_slice(&env_output.stdout).expect("one JSON object");
    assert_eq!(parsed["strictness"]["source"], "env");

    // `flag` — the highest layer.
    let flagged = show(&bare, &["--json", "--strictness", "strict"]);
    let parsed: BTreeMap<String, Value> =
        serde_json::from_slice(&flagged.stdout).expect("one JSON object");
    assert_eq!(parsed["strictness"]["source"], "flag");
}

// --- (c2) every layer that spoke, not only the one that won (CLOUD-373) ------

/// The `--json` document from a run with `BATTEN_STRICTNESS` exported, as raw
/// bytes and parsed — the byte-stability half needs the bytes themselves.
fn document_with_strictness_env(dir: &Path, value: &str) -> (Vec<u8>, BTreeMap<String, Value>) {
    let output = common::batten()
        .args(["config", "show", "--json"])
        .current_dir(dir)
        .env("BATTEN_STRICTNESS", value)
        .output()
        .expect("run batten config show");
    assert_eq!(
        output.status.code(),
        Some(0),
        "config show failed: {}",
        common::stderr(&output)
    );
    let parsed = serde_json::from_slice(&output.stdout).expect("the document is one JSON object");
    (output.stdout, parsed)
}

#[test]
fn every_key_carries_its_contributors_ending_in_the_layer_that_won() {
    // Over the parsed document rather than a key list, for section (a)'s reason:
    // a key that starts being emitted without contributors fails here without
    // this file being touched.
    let dir = Fixture::new("config-show-contributors")
        .config(EVERY_KEY)
        .build();
    let document = document(&dir);
    assert!(
        !document.is_empty(),
        "an empty document would pass vacuously"
    );

    for (key, entry) in &document {
        let contributors = entry
            .get("contributors")
            .and_then(Value::as_array)
            .unwrap_or_else(|| panic!("{key} carries no contributors list"));
        assert!(
            !contributors.is_empty(),
            "{key}: an empty list would name no layer at all"
        );
        for contributor in contributors {
            // A contributor is a `{layer, provenance}` PAIR since CLOUD-332 —
            // which layer set the key, and what class of thing that layer read.
            let object = contributor
                .as_object()
                .unwrap_or_else(|| panic!("{key}: a contributor is not a pair object"));
            let layer = object
                .get("layer")
                .and_then(Value::as_str)
                .unwrap_or_else(|| panic!("{key}: a contributor names no layer"));
            assert!(
                ["flag", "env", "local-file", "repo-config", "default"].contains(&layer),
                "{key}: {layer} is not one of the five layer tokens"
            );
            let provenance = object
                .get("provenance")
                .and_then(Value::as_str)
                .unwrap_or_else(|| panic!("{key}: a contributor names no provenance"));
            assert!(
                PROVENANCE_TOKENS.contains(&provenance),
                "{key}: {provenance} is not one of the declared source classes"
            );
        }
        assert_eq!(
            contributors.last().and_then(|c| c.get("layer")),
            Some(&entry["source"]),
            "{key}: the winner must be the last, greatest contributor"
        );
        assert_eq!(
            contributors.last().and_then(|c| c.get("provenance")),
            Some(&entry["provenance"]),
            "{key}: the reported class must be the winning contributor's"
        );
        // `default` names "no layer spoke", so it is the whole list or absent
        // from it — never one entry of a contest.
        assert!(
            contributors.len() == 1
                || !contributors
                    .iter()
                    .any(|c| c.get("layer") == Some(&Value::from("default"))),
            "{key}: `default` appears beside another layer"
        );
    }
}

#[test]
fn a_contested_key_names_the_committed_layer_beside_the_override() {
    // The §7 obligation, over the compiled binary: a repository whose committed
    // `strictness` is being raised in a shell. `source` alone reads `env` here
    // and reads `env` for a repository that never set the key at all, which is
    // the diagnostic gap this closes.
    let committed = Fixture::new("config-show-contested")
        .config("version = 1\nstrictness = \"standard\"\n")
        .build();
    let (bytes, document) = document_with_strictness_env(&committed, "strict");
    assert_eq!(document["strictness"]["value"], "strict");
    assert_eq!(document["strictness"]["source"], "env");
    assert_eq!(
        document["strictness"]["contributors"],
        serde_json::json!([
            {"layer": "repo-config", "provenance": "committed"},
            {"layer": "env", "provenance": "ambient"},
        ]),
        "both layers set the key, in declared weakest-first order, each naming what it read"
    );

    // Byte-identical across two runs: the contributor list is a set ordered by
    // the declared precedence, so nothing about the resolver's own traversal
    // can reach the bytes (§6).
    let (again, _) = document_with_strictness_env(&committed, "strict");
    assert_eq!(bytes, again, "identical input must produce identical bytes");

    // The same winner with nothing underneath it — one contributor, not two.
    let bare = Fixture::new("config-show-uncontested")
        .config("version = 1\n")
        .build();
    let (_, document) = document_with_strictness_env(&bare, "strict");
    assert_eq!(document["strictness"]["source"], "env");
    assert_eq!(
        document["strictness"]["contributors"],
        serde_json::json!([{"layer": "env", "provenance": "ambient"}]),
        "a key exactly one layer set reports exactly one contributor"
    );

    // And an authority key no override can reach reports its one layer.
    assert_eq!(
        document_with_strictness_env(&committed, "strict").1["version"]["contributors"],
        serde_json::json!([{"layer": "repo-config", "provenance": "committed"}])
    );
}

// --- (d) byte-stability, in both forms ---------------------------------------

#[test]
fn both_forms_are_byte_stable_across_runs() {
    let dir = Fixture::new("config-show-stable").config(EVERY_KEY).build();
    for extra in [&[][..], &["--json"][..]] {
        let first = show(&dir, extra);
        let second = show(&dir, extra);
        assert_eq!(
            first.stdout, second.stdout,
            "identical input must produce identical bytes"
        );
    }
}

// --- (e) the default channel is pointer lines with a rule COUNT ---------------

#[test]
fn the_unflagged_form_is_pointer_lines_and_never_a_rule_body() {
    // Non-negotiable rule 4: the default channel points at policy, it does not
    // carry it. The fixture's rule bans the literal `TODO`, so that literal
    // appearing on stdout would be a rule body reaching the pointer channel.
    let dir = Fixture::new("config-show-pointers")
        .config(EVERY_KEY)
        .build();
    let output = show(&dir, &[]);
    assert_eq!(output.status.code(), Some(0));
    assert!(common::stderr(&output).is_empty(), "stdout is the answer");

    let stdout = common::stdout(&output);
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(
        lines.len(),
        document(&dir).len(),
        "one pointer line per emitted key"
    );

    let mut sorted = lines.clone();
    sorted.sort_unstable();
    assert_eq!(lines, sorted, "pointer lines are sorted");

    for line in &lines {
        let fields: Vec<&str> = line.split(' ').collect();
        assert_eq!(
            fields.len(),
            4,
            "each line is `<key> <value> <source> <provenance>`: {line}"
        );
        assert!(
            PROVENANCE_TOKENS.contains(&fields[3]),
            "the fourth field is a source class: {line}"
        );
    }

    assert!(
        stdout.contains("rule 1 repo-config committed"),
        "the rule set is reported as a count: {stdout}"
    );
    assert!(
        !stdout.contains("TODO"),
        "a rule body reached the pointer channel: {stdout}"
    );
}

// --- (f) the exit rows, and the one thing that can reach 2 -------------------

#[test]
fn config_show_reaches_a_policy_verdict_only_for_an_authority_violation() {
    // **This assertion used to be unconditional, and CLOUD-332 narrowed it.**
    // Printing config is not itself a policy verdict, and none of the rows below
    // is one: a rule that WOULD fire against the tree still exits `0`, because
    // `config show` reports the config rather than judging the repository.
    //
    // What changed is that the resolver now has exactly one verdict of its own —
    // an ingested reading that is the effective authority for a key a committed
    // source also sets — and it is raised in `resolve`, so every verb that
    // resolves config can return `2`, this one included. No adapter produces an
    // ingested reading in this tree, so no configuration reachable here can take
    // that route; `config_authority_boundary.rs` is where the predicate itself is
    // pinned. The rows below assert the OTHER codes are unmoved, which is the
    // half a reader of the old name was relying on.
    struct Case {
        name: &'static str,
        config: Option<&'static str>,
        expected: i32,
    }

    let cases = [
        Case {
            name: "a resolvable config",
            config: Some("version = 1\n"),
            expected: 0,
        },
        Case {
            // CLOUD-70: absence resolves to the compiled-in default layer, so
            // there is a config to print — every key of it attributed to
            // `default`. The three rows below are what keep that from reading as
            // "an unreadable config is tolerated": a file that is *present* and
            // cannot be honoured is still refused.
            name: "no authority at all",
            config: None,
            expected: 0,
        },
        Case {
            name: "an unknown key",
            config: Some("version = 1\nnot_a_key = true\n"),
            expected: 1,
        },
        Case {
            name: "an unsupported version",
            config: Some("version = 99\n"),
            expected: 1,
        },
        Case {
            name: "a minimum above this build",
            config: Some("version = 1\nmin_batten_version = \"99.0.0\"\n"),
            expected: 1,
        },
        Case {
            name: "a config whose rule would fire",
            config: Some(
                "version = 1\n\n[[rule]]\nid = \"no-todo\"\nkind = \"forbid\"\nglob = \"**/*.rs\"\npattern = \"TODO\"\nseverity = \"deny\"\n",
            ),
            expected: 0,
        },
    ];

    for case in cases {
        let mut fixture = Fixture::new(&format!("config-show-exit-{}", case.expected));
        if let Some(text) = case.config {
            fixture = fixture.config(text);
        }
        // A file the rule above would match, so the "no policy verdict" row is
        // exercised against a tree that a `check` run WOULD fail on.
        let dir = fixture.file("lib.rs", "TODO fix this\n").build();
        for extra in [&[][..], &["--json"][..]] {
            let output = show(&dir, extra);
            assert_eq!(
                output.status.code(),
                Some(case.expected),
                "{}: {}",
                case.name,
                common::stderr(&output)
            );
            assert_ne!(
                output.status.code(),
                Some(2),
                "{}: no ingested reading, so no authority verdict",
                case.name
            );
        }
    }
}
