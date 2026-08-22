//! The checked-in policy-input schema tracks what the engine actually emits
//! (CLOUD-876).
//!
//! WHY THIS TEST IS THE WHOLE POINT OF THE SCHEMA BEING SAFE. `opa check -s`
//! types a Rego module against `schema/policy-input.schema.json` at build time,
//! and that is only worth anything if the schema describes the document the
//! engine really builds. A schema checked in by hand is a SECOND AUTHORITY
//! beside `tree_document`'s projection, and a second authority with nothing
//! holding it in agreement drifts — `mise-tasks/rules-drift.sh`'s lesson, and
//! the reason this file exists rather than a comment promising to keep them
//! aligned.
//!
//! The drift it would cause is the worst kind: a schema naming a key the engine
//! stopped emitting types a module green over a path that is always undefined,
//! which is CLOUD-845's defect arriving through the gate built to prevent it.
//!
//! CLOUD-879 REPLACES THE CHECKED-IN FILE WITH A DERIVED ONE, at which point
//! this test becomes the derivation's own round-trip rather than a drift guard.
//! Until then it is what makes the hand-written file honest.

use std::collections::BTreeSet;

use batten::facts::{Fact, Surface};

/// The one key in the tree document that is not a `Fact`. `tree_document` adds
/// it beside the projected facts, so the schema must carry it and this test has
/// to know it is expected rather than reporting it as drift.
const NOT_A_FACT: &str = "missing";

fn schema() -> serde_json::Value {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../schema/policy-input.schema.json"
    );
    let text =
        std::fs::read_to_string(path).unwrap_or_else(|why| panic!("cannot read {path}: {why}"));
    serde_json::from_str(&text).unwrap_or_else(|why| panic!("{path} is not JSON: {why}"))
}

fn schema_tree_keys() -> BTreeSet<String> {
    let doc = schema();
    let properties = doc
        .pointer("/properties/tree/properties")
        .and_then(serde_json::Value::as_object)
        .expect("the schema declares /properties/tree/properties");
    properties.keys().cloned().collect()
}

/// The emitted set, taken from the same place `tree_document` takes it: every
/// `Fact` whose surface is `Check` and which names a tree key. Derived rather
/// than typed out, so a fact added to `Fact::ALL` moves this side of the
/// comparison by itself and the schema is what has to catch up.
fn emitted_tree_keys() -> BTreeSet<String> {
    let mut keys: BTreeSet<String> = Fact::ALL
        .iter()
        .filter(|fact| fact.class().surface == Surface::Check)
        .filter_map(|fact| fact.tree_key())
        .map(str::to_owned)
        .collect();
    keys.insert(NOT_A_FACT.to_owned());
    keys
}

#[test]
fn the_schema_declares_exactly_the_keys_the_tree_surface_emits() {
    let declared = schema_tree_keys();
    let emitted = emitted_tree_keys();

    // BOTH DIRECTIONS, and the second is the one that matters. A key the schema
    // declares but the engine never emits is CLOUD-845 exactly: a module reads
    // it, `opa check -s` types it green, and it is undefined at runtime forever.
    let undeclared: Vec<_> = emitted.difference(&declared).collect();
    let unemitted: Vec<_> = declared.difference(&emitted).collect();

    assert!(
        undeclared.is_empty(),
        "the tree surface emits keys the schema does not declare, so a module reading them \
         fails `opa check -s` against a document that really carries them: {undeclared:?}"
    );
    assert!(
        unemitted.is_empty(),
        "the schema declares keys the tree surface never emits, so `opa check -s` types a \
         module green over a path that is always undefined — CLOUD-845's defect, arriving \
         through the gate built to prevent it: {unemitted:?}"
    );
}

/// `additionalProperties: false` on `tree` is what makes an unemitted key a
/// build-time ERROR rather than an unconstrained `Any`. Without it the schema
/// above is decoration: every typo types green.
#[test]
fn the_tree_object_is_closed_so_an_unknown_key_is_an_error() {
    let doc = schema();
    let closed = doc
        .pointer("/properties/tree/additionalProperties")
        .and_then(serde_json::Value::as_bool);
    assert_eq!(
        closed,
        Some(false),
        "`/properties/tree/additionalProperties` must be false; with it open, \
         `opa check -s` types every unknown `input.tree.<key>` as Any and the gate checks nothing"
    );
}

/// The root is closed for the same reason, one level up: a module reaching for
/// `input.facts` on the tree surface is asking a question this surface does not
/// answer, and it should fail to build rather than evaluate to undefined.
#[test]
fn the_root_is_closed_so_a_hook_surface_path_is_an_error_on_the_tree_surface() {
    let doc = schema();
    let closed = doc
        .get("additionalProperties")
        .and_then(serde_json::Value::as_bool);
    assert_eq!(
        closed,
        Some(false),
        "the schema root must be closed; a tree module reaching for a hook-surface key \
         is a question with no answer, not an answer of none"
    );
}
