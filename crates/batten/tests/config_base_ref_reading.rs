//! A base-ref reading is structurally distinct from a working-tree one
//! (CLOUD-722), over the compiled binary.
//!
//! Before this, `--config-from <ref>` and a plain working-tree load produced
//! byte-identical output: the ref-loaded authority attributed to `repo-config`
//! exactly as the working-tree one did, and `config::Authority` reported
//! `Present` either way — which is correct, because "a `batten.toml` was found"
//! is a different question from "where it was read from". Nothing answered the
//! second, so a consumer wanting the trusted reading could only inspect whether a
//! flag had been passed, which is plumbing rather than a property of the load.
//!
//! **The discriminator is the same-bytes pair.** Every test below reads ONE set
//! of config bytes two ways. A fixture whose base and working configs differed
//! would pass with the class never emitted at all, since the values alone would
//! already differ — which is the shape this file exists not to be.
//!
//! `--config-from` is not widened here and loads exactly what it loaded before;
//! this makes the reading legible, not different.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde_json::Value;

use batten::resolve::{self, Origin, Overrides};

use common::Fixture;

/// A repository whose base ref and working tree carry the **same** config bytes.
///
/// That identity is the point: it leaves the reading's origin as the only
/// variable between the two runs below.
fn same_bytes(name: &str, config: &str) -> PathBuf {
    Fixture::new(name)
        .config(config)
        .git()
        .base_commit()
        .work_commit()
        .build()
}

fn document(dir: &Path, args: &[&str]) -> (Vec<u8>, BTreeMap<String, Value>) {
    let mut all = vec!["config", "show", "--json"];
    all.extend_from_slice(args);
    let output = common::run(dir, &all);
    assert_eq!(
        output.status.code(),
        Some(0),
        "config show failed: {}",
        common::stderr(&output)
    );
    let parsed = serde_json::from_slice(&output.stdout).expect("the document is one JSON object");
    (output.stdout, parsed)
}

const CONFIG: &str = "version = 1\nstrictness = \"strict\"\nprotected = [\"a/**\"]\n";

#[test]
fn the_same_bytes_read_two_ways_differ_only_in_the_class() {
    // The acceptance. Values and layers are identical — the two readings ARE the
    // same authority — and every key the authority set reports a different class.
    let repo = same_bytes("base-ref-same-bytes", CONFIG);
    let (working_bytes, working) = document(&repo, &[]);
    let (ref_bytes, from_ref) = document(&repo, &["--config-from", "origin/main"]);

    assert_ne!(
        working_bytes, ref_bytes,
        "the two readings are indistinguishable, which is the defect this closes"
    );
    assert_eq!(
        working.keys().collect::<Vec<_>>(),
        from_ref.keys().collect::<Vec<_>>(),
        "the same authority emits the same key set either way"
    );

    let mut authority_keys = 0;
    for (key, entry) in &working {
        let other = &from_ref[key];
        assert_eq!(entry["value"], other["value"], "{key}: the value moved");
        assert_eq!(entry["source"], other["source"], "{key}: the layer moved");
        if entry["source"] == "repo-config" {
            authority_keys += 1;
            assert_eq!(entry["provenance"], "committed", "{key}");
            assert_eq!(other["provenance"], "base-ref", "{key}");
        } else {
            assert_eq!(
                entry["provenance"], other["provenance"],
                "{key}: only the authority's own class moves"
            );
        }
    }
    assert!(
        authority_keys > 0,
        "a fixture whose authority set nothing would pass vacuously"
    );
}

#[test]
fn the_class_is_a_stable_token_and_never_the_ref_that_was_named() {
    // §5: a class, not a revspec. The same commit reached through two different
    // ref names must report the same token — otherwise the token is the ref
    // spelled differently, which is neither portable nor byte-stable.
    let repo = same_bytes("base-ref-token-stable", CONFIG);
    common::git_in(&repo, &["update-ref", "refs/heads/trusted", "HEAD"]);

    let (from_origin, by_origin) = document(&repo, &["--config-from", "origin/main"]);
    let (from_branch, by_branch) = document(&repo, &["--config-from", "trusted"]);
    assert_eq!(
        from_origin, from_branch,
        "the ref that was named reached the bytes"
    );

    for (key, entry) in &by_origin {
        let token = entry["provenance"].as_str().expect("a class is one token");
        assert_eq!(token, by_branch[key]["provenance"], "{key}");
        for leaked in ["origin", "trusted", "refs/", "/"] {
            assert!(
                !token.contains(leaked),
                "{key}: {token} carries {leaked}, which is a ref or a path"
            );
        }
    }
}

#[test]
fn the_pointer_channel_names_the_class_too() {
    // The default channel, not only `-J`: a reader who never passes `--json` is
    // the one most likely to be looking at the wrong authority.
    let repo = same_bytes("base-ref-pointer", CONFIG);
    let working = common::stdout(&common::run(&repo, &["config", "show"]));
    let from_ref = common::stdout(&common::run(
        &repo,
        &["config", "show", "--config-from", "origin/main"],
    ));
    assert!(
        working.contains("version 1 repo-config committed"),
        "the working-tree reading: {working}"
    );
    assert!(
        from_ref.contains("version 1 repo-config base-ref"),
        "the base-ref reading: {from_ref}"
    );
}

#[test]
fn a_consumer_requires_the_trusted_reading_from_the_type() {
    // The library half, and the one assertion that pins the design rather than
    // the output: `authority_origin` reads the LOAD's outcome, never
    // `Overrides::config_from`. Derived from the flag this still passes, which is
    // why the negative direction below is asserted from the same call — a
    // consumer must be unable to fake the trusted reading by passing a flag that
    // did not produce one.
    let repo = same_bytes("base-ref-from-the-type", CONFIG);
    let no_env = |_: &str| None;

    let plain = resolve::resolve_with_env(&repo, &Overrides::default(), &no_env)
        .expect("the working tree resolves");
    assert_eq!(plain.authority_origin(), Origin::Committed);
    assert!(
        plain.base.is_none(),
        "a working-tree reading loaded no base authority"
    );

    let trusted = resolve::resolve_with_env(
        &repo,
        &Overrides {
            config_from: Some("origin/main".to_owned()),
            ..Overrides::default()
        },
        &no_env,
    )
    .expect("the base ref resolves");
    assert_eq!(trusted.authority_origin(), Origin::BaseRef);
    assert!(
        trusted.base.is_some(),
        "the class must follow the load, so a base-ref class needs a loaded base"
    );
}

#[test]
fn the_layers_above_the_authority_keep_their_own_class_under_a_base_ref_reading() {
    // The origin is stamped on the AUTHORITY, not on the run. A resolver that
    // applied it run-wide would report the shell that invoked it as `base-ref`,
    // which is the trusted token attached to the least trusted layer there is.
    let repo = same_bytes("base-ref-other-layers", "version = 1\n");
    let mut command = common::batten();
    command
        .current_dir(&repo)
        .args(["config", "show", "--json", "--config-from", "origin/main"])
        .env("BATTEN_STRICTNESS", "strict");
    let output = command.output().expect("batten runs");
    assert_eq!(output.status.code(), Some(0), "{}", common::stderr(&output));
    let document: BTreeMap<String, Value> =
        serde_json::from_slice(&output.stdout).expect("one JSON object");

    assert_eq!(document["strictness"]["source"], "env");
    assert_eq!(document["strictness"]["provenance"], "ambient");
    assert_eq!(document["version"]["provenance"], "base-ref");
}

#[test]
fn an_unreachable_ref_is_a_usage_error_and_never_a_missing_class() {
    // §5's correction, pinned: an unreachable ref is a statement about the
    // INVOCATION, so it is exit `1`. It is not a "class unavailable" state — no
    // such state exists, because every contributor carries a class by
    // construction — and exit `3` here would be that class invented.
    let repo = same_bytes("base-ref-unreachable", CONFIG);
    let output = common::run(
        &repo,
        &["config", "show", "--config-from", "origin/nonexistent"],
    );
    assert_eq!(
        output.status.code(),
        Some(1),
        "an unreachable ref is a usage error: {}",
        common::stderr(&output)
    );
}
