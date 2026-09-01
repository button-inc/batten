//! The two policy-input schemas are DERIVED from the fact model, and the
//! committed files are what the derivation produced (CLOUD-876, CLOUD-879).
//!
//! WHY THIS IS THE WHOLE POINT OF THE SCHEMA BEING SAFE. `opa check -s` types a
//! Rego module against `schema/policy-*.schema.json` at build time, and that is
//! only worth anything if the schema describes the document the engine really
//! builds. The drift it would otherwise cause is the worst kind: a schema naming
//! a key the engine stopped emitting types a module green over a path that is
//! always undefined, which is CLOUD-845's defect arriving through the gate built
//! to prevent it.
//!
//! WHAT CHANGED, AND WHY THE OLD SHAPE WAS NOT ENOUGH. Both files were written by
//! hand, and this suite asserted their key sets matched `Fact::tree_key()` and
//! `Fact::ALL`. That is a drift gate over a second authority: it can report a
//! disagreement, never prevent one, and the repair is always somebody editing the
//! copy. The schemas are generated from the fact model now, so the two cannot
//! disagree — and what is left to assert is different in kind:
//!
//! * a ROUND TRIP, that the committed bytes are the ones the generator produces,
//!   which is what makes `mise run schema` the only thing anyone must remember;
//! * the properties the GENERATOR states rather than derives — closedness at each
//!   object, and that the two surfaces share no key. Neither falls out of the
//!   derivation, and both are load-bearing: an open object types every unknown
//!   key as `Any`, and a shared key would let a module bound to the wrong surface
//!   type check anyway.

use std::collections::BTreeSet;

use batten::facts::{Fact, Surface};

/// The one key in the tree document that is not a `Fact`. `tree_document` adds
/// it beside the projected facts, so the schema must carry it and this test has
/// to know it is expected rather than reporting it as drift.
const NOT_A_FACT: &str = "missing";

/// The committed bytes for one surface.
fn committed(name: &str) -> String {
    let path = format!("{}/../../schema/{name}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read_to_string(&path).unwrap_or_else(|why| panic!("cannot read {path}: {why}"))
}

/// The schema directory, so both surfaces are read the same way.
fn read_schema(name: &str) -> serde_json::Value {
    let path = format!("{}/../../schema/{name}", env!("CARGO_MANIFEST_DIR"));
    let text = committed(name);
    serde_json::from_str(&text).unwrap_or_else(|why| panic!("{path} is not JSON: {why}"))
}

/// What `generate schema` writes for a surface: the derivation plus the trailing
/// newline the emitter adds, so the comparison is against the bytes that reach
/// the file rather than a shape the caller has to remember to adjust.
fn generated(schema: &str) -> String {
    format!("{schema}\n")
}

// --- the round trip ----------------------------------------------------------

#[test]
fn the_committed_tree_schema_is_the_one_the_fact_model_derives() {
    let derived = batten::policy::tree_input_schema()
        .unwrap_or_else(|why| panic!("cannot derive the tree-surface schema: {why}"));
    assert_eq!(
        committed("policy-input.schema.json"),
        generated(&derived),
        "schema/policy-input.schema.json differs from the fact model; run `mise run schema`"
    );
}

#[test]
fn the_committed_call_schema_is_the_one_the_fact_model_derives() {
    let derived = batten::policy::call_input_schema()
        .unwrap_or_else(|why| panic!("cannot derive the call-surface schema: {why}"));
    assert_eq!(
        committed("policy-call.schema.json"),
        generated(&derived),
        "schema/policy-call.schema.json differs from the fact model; run `mise run schema`"
    );
}

/// §6: identical input, identical bytes. Without this the round trip above could
/// fail at random and teach everyone to re-run it until it passed.
#[test]
fn both_derivations_are_byte_stable_across_runs() {
    let derive_tree = || {
        batten::policy::tree_input_schema()
            .unwrap_or_else(|why| panic!("cannot derive the tree-surface schema: {why}"))
    };
    let derive_call = || {
        batten::policy::call_input_schema()
            .unwrap_or_else(|why| panic!("cannot derive the call-surface schema: {why}"))
    };
    assert_eq!(
        derive_tree(),
        derive_tree(),
        "the tree-surface derivation is not byte-stable"
    );
    assert_eq!(
        derive_call(),
        derive_call(),
        "the call-surface derivation is not byte-stable"
    );
}

fn schema() -> serde_json::Value {
    read_schema("policy-input.schema.json")
}

fn call_schema() -> serde_json::Value {
    read_schema("policy-call.schema.json")
}

fn schema_tree_keys() -> BTreeSet<String> {
    let doc = schema();
    let properties = doc
        .pointer("/properties/tree/properties")
        .and_then(serde_json::Value::as_object)
        .unwrap_or_else(|| panic!("the schema declares /properties/tree/properties"));
    properties.keys().cloned().collect()
}

/// The emitted set, taken from the same place `tree_document` takes it: every
/// `Fact` that names a tree key. Derived rather than typed out, so a fact added
/// to `Fact::ALL` moves this side of the comparison by itself and the schema is
/// what has to catch up.
///
/// THE PREDICATE IS `tree_key`, AND IT USED TO BE THE SURFACE (CLOUD-907). While
/// every tree-emitted fact happened to be `Surface::Check` the two read the same;
/// the git family broke the coincidence, because three of its members are
/// `Surface::Hook` — the NARROWEST surface they may be resolved on, which admits
/// the wider tree — and all five are emitted, since the consumers the census
/// found are gate tasks. Under the old filter the schema and the engine disagreed
/// about three keys the engine really carries.
fn emitted_tree_keys() -> BTreeSet<String> {
    let mut keys: BTreeSet<String> = Fact::ALL
        .iter()
        .filter_map(|fact| fact.tree_key())
        .map(str::to_owned)
        .collect();
    keys.insert(NOT_A_FACT.to_owned());
    keys
}

/// Still asserted after the derivation, and deliberately: a fact that names a
/// tree key it cannot be RESOLVED on would be generated into the schema and
/// never emitted — the derivation cannot catch that, and
/// `no_tree_key_names_a_surface_the_fact_cannot_reach` below does.
/// A tree key must name a fact the tree can actually resolve.
///
/// The direction the derivation above cannot see, and `input.tree.tracked`'s
/// defect exactly: a key the document promises and the engine can never fill.
/// `Surface::VerifyOnly` is what this refuses — forge state is `Cost::Read` and
/// cheap, and naming a tree key for it would type a module green over a path
/// `batten check` has no way to answer.
///
/// Fails by: giving a `VerifyOnly` fact a `tree_key`.
#[test]
fn no_tree_key_names_a_surface_the_fact_cannot_reach() {
    let named: Vec<&str> = Fact::ALL
        .iter()
        .filter(|fact| fact.tree_key().is_some())
        .map(|fact| fact.as_str())
        .collect();
    assert!(
        named.len() >= 4,
        "a vacuous pass: with nothing naming a tree key the loop below asserts \
         nothing: {named:?}"
    );
    for fact in Fact::ALL {
        assert!(
            fact.tree_key().is_none() || fact.class().resolvable_on(Surface::Check),
            "{}: names a tree key on a surface it cannot be resolved on",
            fact.as_str()
        );
    }
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

// --- the mediated-call surface ----------------------------------------------
//
// THE CORPUS SPANS TWO SURFACES AND THEY SHARE NO KEYS. `policy/run-shape.rego`
// is `scope = "mediated_call"`, so it reads the call document; the two
// tree-scoped modules read the tree document. A `# METADATA schemas:` block
// binding a module to the wrong one type checks it against a shape the engine
// cannot produce for it, which is CLOUD-845's defect introduced on purpose. Both
// schemas therefore exist, and both are gated the same way.

/// The `facts` key set, taken from where `call_document` takes it: every `Fact`
/// whose surface is `Hook`, keyed by its stable token. Derived, so a fact added
/// to `Fact::ALL` moves this side by itself.
fn emitted_call_fact_keys() -> BTreeSet<String> {
    Fact::ALL
        .iter()
        .filter(|fact| fact.class().surface == Surface::Hook)
        .map(|fact| fact.as_str().to_owned())
        .collect()
}

fn schema_call_fact_keys() -> BTreeSet<String> {
    let doc = call_schema();
    let properties = doc
        .pointer("/properties/facts/properties")
        .and_then(serde_json::Value::as_object)
        .unwrap_or_else(|| panic!("the call schema declares /properties/facts/properties"));
    properties.keys().cloned().collect()
}

#[test]
fn the_call_schema_declares_exactly_the_facts_the_hook_surface_emits() {
    let declared = schema_call_fact_keys();
    let emitted = emitted_call_fact_keys();

    let undeclared: Vec<_> = emitted.difference(&declared).collect();
    let unemitted: Vec<_> = declared.difference(&emitted).collect();

    assert!(
        undeclared.is_empty(),
        "the hook surface projects facts the call schema does not declare, so a module \
         reading them fails `opa check -s` against a document that really carries them: \
         {undeclared:?}"
    );
    assert!(
        unemitted.is_empty(),
        "the call schema declares facts the hook surface never projects, so `opa check -s` \
         types a module green over a path that is always undefined: {unemitted:?}"
    );
}

/// The two surfaces must not drift into each other. A key on both would mean a
/// module could bind to either schema and still type check, which is exactly the
/// mistake having two schemas exists to prevent.
#[test]
fn the_two_surfaces_share_no_keys() {
    let tree = schema_tree_keys();
    let call = schema_call_fact_keys();
    let shared: Vec<_> = tree.intersection(&call).collect();
    assert!(
        shared.is_empty(),
        "the tree and call schemas share keys, so a module bound to the wrong surface \
         would still type check: {shared:?}"
    );
}

#[test]
fn the_call_schema_is_closed_at_the_root_and_at_both_objects() {
    let doc = call_schema();
    for pointer in [
        "/additionalProperties",
        "/properties/call/additionalProperties",
        "/properties/facts/additionalProperties",
    ] {
        let closed = doc.pointer(pointer).and_then(serde_json::Value::as_bool);
        assert_eq!(
            closed,
            Some(false),
            "`{pointer}` must be false; with it open, `opa check -s` types every unknown \
             key as Any and the gate checks nothing"
        );
    }
}
