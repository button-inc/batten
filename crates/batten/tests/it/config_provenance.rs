//! Every resolved value carries the CLASS its winning layer read from
//! (CLOUD-332), over the compiled binary.
//!
//! `config_show.rs` owns the layer half — which of §8's five layers won a key.
//! This file owns the half that layer cannot answer: **what kind of thing was
//! read**. The two are separate because the ladder's `Ord` is the precedence
//! specification, so a class folded into it would acquire a rank nobody chose.
//!
//! Assertions run over the parsed document rather than a key list, for
//! `config_show.rs`'s reason: a key that starts being emitted without a class
//! fails here without this file being touched.
//!
//! The predicate the classes exist for is `config_authority_boundary.rs`'s, and
//! it is a library-tier suite for the reason stated in its own header.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::collections::BTreeMap;
use std::path::Path;

use serde_json::Value;

use common::Fixture;

/// The source classes `resolve::Origin` declares.
///
/// Spelled as tokens rather than read off the type, because this suite runs over
/// the binary's output: a class the engine renamed must fail here even though the
/// library still compiles.
const CLASSES: &[&str] = &[
    "builtin",
    "committed",
    "base-ref",
    "uncommitted",
    "ambient",
    "ingested",
];

/// The `--json` document, parsed, and the bytes it was parsed from.
///
/// Named for the verb rather than for the noun, so a caller may bind the result
/// as `document` without shadowing the helper that produced it.
fn shown(dir: &Path, env: &[(&str, &str)]) -> (Vec<u8>, BTreeMap<String, Value>) {
    let mut command = common::batten();
    command.current_dir(dir).args(["config", "show", "--json"]);
    for (name, value) in env {
        command.env(name, value);
    }
    let output = command.output().expect("batten runs");
    assert_eq!(
        output.status.code(),
        Some(0),
        "config show failed: {}",
        common::stderr(&output)
    );
    let parsed = serde_json::from_slice(&output.stdout).expect("the document is one JSON object");
    (output.stdout, parsed)
}

/// The class the winning layer read, for one key.
fn class<'a>(document: &'a BTreeMap<String, Value>, key: &str) -> &'a str {
    document[key]["provenance"]
        .as_str()
        .unwrap_or_else(|| panic!("{key} carries no provenance token"))
}

#[test]
fn every_emitted_key_carries_a_class_from_the_declared_set() {
    // Total over the document. Red against a build with no provenance field at
    // all, and red again if a key is emitted whose class the resolver forgot to
    // attribute — which `Resolved::attributed` refuses rather than defaults.
    let dir = Fixture::new("config-provenance-total")
        .config("version = 1\nstrictness = \"standard\"\nprotected = [\"a/**\"]\n")
        .build();
    let (_, document) = shown(&dir, &[]);
    assert!(
        !document.is_empty(),
        "an empty document would pass vacuously"
    );
    for (key, entry) in &document {
        let token = entry
            .get("provenance")
            .and_then(Value::as_str)
            .unwrap_or_else(|| panic!("{key} carries no provenance"));
        assert!(
            CLASSES.contains(&token),
            "{key}: {token} is not one of the declared source classes"
        );
    }
}

#[test]
fn each_layer_reports_the_class_it_reads_from() {
    // The mapping itself, one key at a time, so a resolver that stamped one class
    // run-wide fails rather than passing on a fixture with a single layer.
    let dir = Fixture::new("config-provenance-layers")
        .config("version = 1\nstrictness = \"standard\"\n")
        .file("batten.local.toml", "version = 1\nfail_on_warning = true\n")
        .build();
    let (_, document) = shown(&dir, &[]);

    assert_eq!(class(&document, "version"), "committed", "the authority");
    assert_eq!(
        class(&document, "fail_on_warning"),
        "uncommitted",
        "the git-ignored local file"
    );
    assert_eq!(
        class(&document, "unlanded"),
        "builtin",
        "nobody spoke, so nothing was read"
    );

    let (_, document) = shown(&dir, &[("BATTEN_STRICTNESS", "strict")]);
    assert_eq!(
        class(&document, "strictness"),
        "ambient",
        "the process environment"
    );
}

#[test]
fn a_class_never_names_a_path_or_a_machine() {
    // §5: a class is portable. A path is both payload and non-portable, so it
    // would fail non-negotiable rule 4 and byte-stability at once — and the
    // second half is asserted rather than argued: the same config bytes under two
    // different directories produce byte-identical documents.
    let config = "version = 1\nstrictness = \"strict\"\nprotected = [\"a/**\"]\n";
    let here = Fixture::new("config-provenance-path-a")
        .config(config)
        .build();
    let there = Fixture::new("config-provenance-path-b")
        .config(config)
        .build();
    let (here_bytes, document) = shown(&here, &[]);
    let (there_bytes, _) = shown(&there, &[]);
    assert_eq!(
        here_bytes, there_bytes,
        "the document names where it was run from"
    );

    for (key, entry) in &document {
        let token = class(&document, key);
        for fragment in ['/', '\\'] {
            assert!(
                !token.contains(fragment),
                "{key}: {token} looks like a path"
            );
        }
        assert!(
            !token.contains("config-provenance"),
            "{key}: {token} names the fixture directory"
        );
        assert!(
            entry["provenance"].is_string(),
            "{key}: a class is one token, not a structure"
        );
    }
}

#[test]
fn a_committed_contributor_is_named_beside_the_ambient_one_that_won() {
    // The contributor-versus-effective-authority reading, and the shape an
    // ingested contest will have once CLOUD-128 lands, minus the class. `source`
    // and `provenance` both read the winner here; only the contributor list can
    // say a committed file also spoke.
    let dir = Fixture::new("config-provenance-contested")
        .config("version = 1\nstrictness = \"standard\"\n")
        .build();
    let (_, document) = shown(&dir, &[("BATTEN_STRICTNESS", "strict")]);
    assert_eq!(document["strictness"]["source"], "env");
    assert_eq!(class(&document, "strictness"), "ambient");
    assert_eq!(
        document["strictness"]["contributors"],
        serde_json::json!([
            {"layer": "repo-config", "provenance": "committed"},
            {"layer": "env", "provenance": "ambient"},
        ]),
        "the committed contributor keeps its own class, not the winner's"
    );
}

#[test]
fn an_accepted_tightening_and_a_refused_loosening_differ_by_more_than_the_winning_value() {
    // §7's discriminating pair. An implementation that simply always preferred
    // the committed value passes committed-wins and the token assertions while
    // getting the ordering wrong; only this pair separates them — and it is
    // compared on the CONTRIBUTOR LIST and the exit code rather than on the
    // winner's value, so it stays red if the class is never emitted.
    let committed = "version = 1\nstrictness = \"standard\"\n";

    let raising = Fixture::new("config-provenance-tighten")
        .config(committed)
        .file(
            "batten.local.toml",
            "version = 1\nstrictness = \"strict\"\n",
        )
        .build();
    let (_, document) = shown(&raising, &[]);
    assert_eq!(
        document["strictness"]["value"], "strict",
        "a tightening override is honoured"
    );
    assert_eq!(class(&document, "strictness"), "uncommitted");
    assert_eq!(
        document["strictness"]["contributors"],
        serde_json::json!([
            {"layer": "repo-config", "provenance": "committed"},
            {"layer": "local-file", "provenance": "uncommitted"},
        ]),
        "the committed layer is still named under the override that raised it"
    );

    let lowering = Fixture::new("config-provenance-loosen")
        .config(committed)
        .file(
            "batten.local.toml",
            "version = 1\nstrictness = \"permissive\"\n",
        )
        .build();
    let output = common::run(&lowering, &["config", "show", "--json"]);
    assert_eq!(
        output.status.code(),
        Some(1),
        "a loosening override is an invalid invocation, not a policy verdict"
    );
    assert!(
        common::stderr(&output).contains("may only tighten"),
        "the refusal names the direction: {}",
        common::stderr(&output)
    );
}

#[test]
fn both_forms_stay_byte_stable_with_the_class_emitted() {
    // §6, re-asserted over the widened document: the class is read off one
    // ordered set, so nothing about the resolver's own traversal can reach the
    // bytes.
    let dir = Fixture::new("config-provenance-stable")
        .config("version = 1\nstrictness = \"strict\"\nprotected = [\"a/**\"]\n")
        .file("batten.local.toml", "version = 1\nfail_on_warning = true\n")
        .build();
    for extra in [&[][..], &["--json"][..]] {
        let mut args = vec!["config", "show"];
        args.extend_from_slice(extra);
        let first = common::run(&dir, &args);
        let second = common::run(&dir, &args);
        assert_eq!(
            first.stdout, second.stdout,
            "identical input must produce identical bytes"
        );
    }
}
