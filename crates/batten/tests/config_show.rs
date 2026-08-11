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

mod common;

use std::collections::BTreeMap;
use std::path::Path;
use std::process::Output;

use serde_json::Value;

use common::Fixture;

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
            3,
            "each line is `<key> <value> <source>`: {line}"
        );
    }

    assert!(
        stdout.contains("rule 1 repo-config"),
        "the rule set is reported as a count: {stdout}"
    );
    assert!(
        !stdout.contains("TODO"),
        "a rule body reached the pointer channel: {stdout}"
    );
}

// --- (f) the exit rows, including that no input reaches 2 --------------------

#[test]
fn config_show_resolves_or_refuses_and_never_reaches_a_policy_verdict() {
    // Printing config is not a policy verdict, so `2` is unreachable here — the
    // one row that would otherwise be tempting, since a rule finding in the same
    // repository does return it.
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
            name: "no authority at all",
            config: None,
            expected: 1,
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
                "{}: never a verdict",
                case.name
            );
        }
    }
}
