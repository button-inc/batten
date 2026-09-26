//! `workspace carry unsafe` over the compiled binary and the real walk
//! (CLOUD-224, CLOUD-718, CLOUD-1717).
//!
//! # Why this tier exists and the module's own `test_` rules do not suffice
//!
//! `policy/macos-link.rego` carries five load-time cases and every one fabricates
//! its input with `with input as`, which is the shape `rules/policy-modules.md`
//! warns about: the case asserts over a record the engine may be unable to
//! project, and the module stays green while the row decides nothing on any real
//! checkout.
//!
//! # And why the WALK is driven here rather than described
//!
//! Most of the dying suite is about the walk, not the verdict — the activation
//! filter in both directions, the weak-dependency rule, the dev-edge rule, and
//! which roots the walk starts from. Those are the cases that cost real time to
//! get right: `defmt`, an unactivated optional dependency of `jiff` reaching no
//! Apple framework and never compiled, made this gate refuse a link
//! `darwin-link` then completed on the same tree (CLOUD-718).
//!
//! The walk is `crates/batten/src/cargo_graph.rs`, shared with
//! `evaluator-closure`; this gate's own half is the roots it starts from and the
//! two `[[pattern]]` rows it reads once there. Both
//! programs used to carry their own copy and both headers said "if one is
//! corrected, correct both" — a rule with no mechanism. There is one walk now,
//! and these cases drive it.
//!
//! # RETIREMENT LEDGER, PER PATH — what `shell retire partial` reads
//!
//! Two cases are NOT carried and each says why in its own row rather than being
//! dropped quietly.
//!
// carried: mise-tasks/macos-link-check.sh policy/macos-link.rego kind:mechanism crates/batten/tests/it/macos_link.rs
// carried: tests/macos-link-check.bats policy/macos-link.rego kind:mechanism crates/batten/tests/it/macos_link.rs
// carried: "the repo as it stands has no SDK-requiring dependency" policy/macos-link.rego kind:mechanism
// carried: "a package declaring a native links key is caught without being listed" policy/macos-link.rego kind:mechanism
// carried: "an optional dependency nobody enabled is not reported" crates/batten/src/cargo_graph.rs kind:mechanism crates/batten/tests/it/macos_link.rs
// carried: "the same optional dependency, once enabled, is reported" crates/batten/src/cargo_graph.rs kind:mechanism crates/batten/tests/it/macos_link.rs
// carried: "A WEAK REFERENCE IS NOT AN ACTIVATION: dep-question-mark leaves the dep dormant" crates/batten/src/cargo_graph.rs kind:mechanism crates/batten/tests/it/macos_link.rs
// carried: "rule 2 still fires through the reachability walk" policy/macos-link.rego kind:mechanism
// carried: "a vendored-C links crate is exempt from rule 1" policy/macos-link.rego kind:mechanism
// carried: "an unvetted links crate is still reported, so the exemption is a list not a switch" policy/macos-link.rego kind:mechanism
// carried: "the walk starts at the workspace members" policy/macos-link.rego kind:mechanism
// changed: "the graph is resolved for macOS, not for the host" mise.toml the `--filter-platform aarch64-apple-darwin` flag is a property of the SPAWN, so it moved to `[tasks.macos-link-record]` with the `cargo metadata` call it qualifies. The module reads whatever graph the producer recorded and cannot observe which platform it was resolved for; a case here would assert over input this surface cannot vary
// withdrawn: "the framework crate list covers the ones that actually bit us" the case grepped the shell program's FRAMEWORK_CRATES literal for four names. The list is `crates/batten/src/cargo_graph.rs`'s now and the assertion was over a spelling rather than a behaviour — `rule_2_still_fires_through_the_reachability_walk` pins what the list is FOR, and a second case re-reading its text would re-break on every legitimate addition
// withdrawn: "every vendored-links entry names a crate, so the pattern cannot be widened to a wildcard" the same shape one list over: it asserted that the VENDORED_LINKS regex contains no `.*`. `an_unvetted_links_crate_is_still_reported` is the behavioural statement of the same property — the exemption is a list rather than a switch — and it survives a rewrite of the pattern that the text assertion would not

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use common::{git_in, init_repo, run, run_with_stdin, scratch, write};

/// A repository registering the real module against the declared family.
fn repo(name: &str) -> std::path::PathBuf {
    let dir = scratch(&format!("macos-link-{name}"));
    let module = std::fs::read_to_string("../../policy/macos-link.rego")
        .expect("the module this tier exists for");
    write(&dir, "policy/macos-link.rego", &module);
    write(
        &dir,
        "batten.toml",
        r#"version = 1
scope = ["**"]

[[verdict]]
id = "manifest carry unsafe"
gloss = "a package in the built macOS graph declares a `links` key"
class = "The manifest's own statement that it links a native library."

[[verdict.route]]
id = "module read first"
kind = "document"
target = "policy/macos-link.rego"

[[verdict]]
id = "workspace reach unsafe"
gloss = "a crate linking an Apple system framework is reachable"
class = "Rule 2, and it is a list, so it is incomplete by construction."

[[verdict.route]]
id = "module read first"
kind = "document"
target = "policy/macos-link.rego"

[[verdict]]
id = "workspace read absent"
gloss = "the platform graph resolved and the walk reached no built package, so nothing was inspected"
class = "Could-not-look spelled as a record, which must not read as a clean graph."

[[verdict.route]]
id = "task run first"
kind = "command"
target = "mise run macos-link-record"

[[rule]]
id = "workspace carry unsafe"
kind = "policy"
scope = "tree"
module = "policy/macos-link.rego"
severity = "deny"

[[record]]
record = "macos-link"
writer = "mise run macos-link-record"

# THE TWO CONSUMER FACTS THE VERB RESOLVES, declared here rather than compiled
# into the engine (non-negotiable rule 1). `cargo_graph.rs` names no crate at
# all; which ones need an SDK and which vendor what they link are this
# consumer's to say.
[[pattern]]
id = "sdk-framework-crate"
regex = '^(security-framework|security-framework-sys|core-foundation|core-foundation-sys|native-tls|openssl-sys|cocoa|objc|objc2|system-configuration|system-configuration-sys)$'

# The `scanned` count's guard, by id, exactly as this consumer declares it —
# without it every record reads as a walk that reached nothing.
[[pattern]]
id = "whole-number"
regex = '^[0-9]+$'

[[pattern]]
id = "vendored-links-crate"
regex = '^(tree-sitter|tree-sitter-language)$'
"#,
    );
    init_repo(&dir);
    git_in(&dir, &["add", "-A"]);
    git_in(&dir, &["commit", "-qm", "register the module"]);
    dir
}

fn record(dir: &std::path::Path, lines: &str) {
    let written = run_with_stdin(dir, &["record", "named", "macos-link"], lines);
    assert!(
        written.status.success(),
        "the setup write lands: {}",
        String::from_utf8_lossy(&written.stderr)
    );
}

/// Drive the REAL walk over a `cargo metadata` document, through the REAL verb.
///
/// The activated-edge reachability lives in `crates/batten/src/cargo_graph.rs`
/// and is asserted by that module's own `#[cfg(test)] mod tests` — ONE walk,
/// shared with `evaluator-closure`. Both programs used to carry their own copy
/// and both headers said so in prose: *"if one is corrected, correct both."*
/// That was a rule with no mechanism; this is the mechanism.
///
/// What THIS tier drives is the COMPOSITION: the members it starts from, the
/// `links` key it reads, and the two `[[pattern]]` rows that decide which names
/// mean an SDK and which vendor what they link.
fn walk(dir: &std::path::Path, metadata: &str) -> String {
    let written = run_with_stdin(
        dir,
        &[
            "record",
            "derive",
            "macos-link",
            "--input",
            "framework=sdk-framework-crate",
            "--input",
            "vendored=vendored-links-crate",
        ],
        metadata,
    );
    assert!(
        written.status.success(),
        "the walk reads its graph: {}",
        String::from_utf8_lossy(&written.stderr)
    );
    String::from_utf8_lossy(&written.stdout).into_owned()
}

/// A graph where the member depends on `edge`, optionally behind a feature.
///
/// `extra` goes inside `edge`'s own package object, which is how a `links` key
/// or a framework name is attached to it.
fn member_chain(edge: &str, extra: &str, optional: bool, member_features: &str) -> String {
    let optional_decl = if optional {
        r#", "optional": true"#
    } else {
        ""
    };
    format!(
        r#"{{
  "packages": [
    {{"id": "batten", "name": "batten", "features": {{"tls": ["dep:{edge}"]}},
     "dependencies": [{{"name": "{edge}"{optional_decl}}}]}},
    {{"id": "{edge}", "name": "{edge}", "features": {{}}, "dependencies": []{extra}}}
  ],
  "workspace_members": ["batten"],
  "resolve": {{"nodes": [
    {{"id": "batten", "features": [{member_features}], "deps": [{{"pkg": "{edge}", "dep_kinds": [{{"kind": null}}]}}]}},
    {{"id": "{edge}", "features": [], "deps": []}}
  ]}}
}}"#
    )
}

// --- the decision, over the engine's own projection --------------------------

#[test]
fn a_package_declaring_a_native_links_key_is_caught_without_being_listed() {
    let dir = repo("links");
    let reached = walk(
        &dir,
        &member_chain("openssl-sys", r#", "links": "openssl""#, false, ""),
    );
    assert!(
        reached.contains("links openssl-sys openssl"),
        "the walk names the library\n{reached}"
    );
    record(&dir, &reached);

    let decided = run(&dir, &["check"]);
    assert_eq!(
        decided.status.code(),
        Some(2),
        "a links key decides\n{}",
        String::from_utf8_lossy(&decided.stderr)
    );
    let said = format!(
        "{}{}",
        String::from_utf8_lossy(&decided.stdout),
        String::from_utf8_lossy(&decided.stderr)
    );
    assert!(said.contains("openssl-sys"), "and names it\n{said}");
}

#[test]
fn rule_2_still_fires_through_the_reachability_walk() {
    // The named set rule 1 cannot see: a crate that links an Apple framework from
    // a build script and declares no `links` key.
    let dir = repo("framework");
    let reached = walk(&dir, &member_chain("core-foundation", "", false, ""));
    assert!(
        reached.contains("framework core-foundation"),
        "the walk names it\n{reached}"
    );
    record(&dir, &reached);

    let decided = run(&dir, &["check"]);
    assert_eq!(
        decided.status.code(),
        Some(2),
        "a framework crate decides\n{}",
        String::from_utf8_lossy(&decided.stderr)
    );
}

#[test]
fn a_vendored_c_links_crate_is_exempt_from_rule_1() {
    // `links` reads as "declares it links a native library", and this gate treats
    // that as "needs SDKROOT pointing at a genuine macOS SDK". For a crate that
    // ships C sources and builds them with `cc`, the second does not follow.
    // Measured 2026-08-21: this gate refused `tree-sitter`, and `darwin-link`
    // then linked the same tree with no SDK present.
    let dir = repo("a-vendored-c-links-crate-is-exempt-from-");
    let reached = walk(
        &dir,
        &member_chain("tree-sitter", r#", "links": "tree-sitter""#, false, ""),
    );
    assert!(
        !reached.contains("links "),
        "a vendored-C links crate is exempt\n{reached}"
    );
}

#[test]
fn an_unvetted_links_crate_is_still_reported_so_the_exemption_is_a_list_not_a_switch() {
    // The other direction of the same narrowing. Without this the case above
    // passes on a walk that stopped reading `links` at all.
    let dir = repo("an-unvetted-links-crate-is-still-reporte");
    let reached = walk(
        &dir,
        &member_chain("some-sys", r#", "links": "some""#, false, ""),
    );
    assert!(
        reached.contains("links some-sys some"),
        "an unknown links crate is still a finding\n{reached}"
    );
}

#[test]
fn an_absent_record_says_nothing_rather_than_passing() {
    let dir = repo("unrecorded");

    let quiet = run(&dir, &["check"]);
    assert_eq!(
        quiet.status.code(),
        Some(0),
        "an absent record is silence\n{}",
        String::from_utf8_lossy(&quiet.stderr)
    );
}

#[test]
fn a_walk_that_reached_nothing_is_could_not_look() {
    // `scanned 0` is the producer saying it looked and resolved nothing. Before
    // the module read `scanned`, this record was byte-identical to a clean graph
    // and exited 0 — the vacuous pass the sibling family already refuses with
    // `absent`. A non-zero count with no finding stays the clean answer.
    let dir = repo("reached-nothing");
    record(&dir, "scanned 0\n");
    let decided = run(&dir, &["check"]);
    assert_eq!(
        decided.status.code(),
        Some(2),
        "a walk over nothing is not a clean graph\n{}",
        String::from_utf8_lossy(&decided.stderr)
    );
    // The class is pinned by the module's own case; this tier proves the ENGINE
    // builds the `scanned` line the arm reads, which the exit code shows.

    let clean = repo("reached-some");
    record(&clean, "scanned 200\n");
    assert_eq!(
        run(&clean, &["check"]).status.code(),
        Some(0),
        "a real walk with no finding is clean"
    );
}

// --- the walk itself ---------------------------------------------------------

#[test]
fn an_optional_dependency_nobody_enabled_is_not_reported() {
    // CLOUD-718's `defmt`: an unactivated optional dependency is in the resolve
    // and is not in the build, and a gate that fails on a crate the compiler
    // never sees is not measuring the thing it names.
    let dir = repo("an-optional-dependency-nobody-enabled-is");
    let reached = walk(
        &dir,
        &member_chain("core-foundation", "", true, r#""default""#),
    );
    assert!(
        !reached.contains("framework "),
        "an unactivated optional dep is dormant\n{reached}"
    );
}

#[test]
fn the_same_optional_dependency_once_enabled_is_reported() {
    let dir = repo("the-same-optional-dependency-once-enable");
    let reached = walk(
        &dir,
        &member_chain("core-foundation", "", true, r#""default", "tls""#),
    );
    assert!(
        reached.contains("framework core-foundation"),
        "enabling the feature reaches it\n{reached}"
    );
}

#[test]
fn a_weak_reference_is_not_an_activation() {
    // `foo?/bar` applies only if something ELSE already activated `foo`, so
    // reading it as an activation walks back to the whole-resolve over-scan.
    let dir = repo("a-weak-reference-is-not-an-activation");
    let reached = walk(
        &dir,
        r#"{
  "packages": [
    {"id": "batten", "name": "batten", "features": {"tls": ["core-foundation?/std"]},
     "dependencies": [{"name": "core-foundation", "optional": true}]},
    {"id": "core-foundation", "name": "core-foundation", "features": {}, "dependencies": []}
  ],
  "workspace_members": ["batten"],
  "resolve": {"nodes": [
    {"id": "batten", "features": ["tls"], "deps": [{"pkg": "core-foundation", "dep_kinds": [{"kind": null}]}]},
    {"id": "core-foundation", "features": [], "deps": []}
  ]}
}"#,
    );
    assert!(
        !reached.contains("framework "),
        "a weak reference leaves the dep dormant\n{reached}"
    );
}

#[test]
fn the_walk_starts_at_the_workspace_members() {
    // Unlike `evaluator-closure`, whose roots are one package's nodes. A package
    // in the resolve that no member reaches is not in the built graph.
    let dir = repo("the-walk-starts-at-the-workspace-members");
    let reached = walk(
        &dir,
        r#"{
  "packages": [
    {"id": "batten", "name": "batten", "features": {}, "dependencies": []},
    {"id": "orphan", "name": "core-foundation", "features": {}, "dependencies": []}
  ],
  "workspace_members": ["batten"],
  "resolve": {"nodes": [
    {"id": "batten", "features": [], "deps": []},
    {"id": "orphan", "features": [], "deps": []}
  ]}
}"#,
    );
    assert!(
        !reached.contains("framework "),
        "an unreached package is not in the built graph\n{reached}"
    );
    assert!(
        reached.contains("scanned 1"),
        "and the count is the members' closure\n{reached}"
    );
}

#[test]
#[expect(
    clippy::disallowed_types,
    reason = "stays: resolving the REAL macOS graph is the whole of this case, and it is the only evidence that the fixtures above agree with the tree the release actually links"
)]
fn the_repo_as_it_stands_has_no_sdk_requiring_dependency() {
    // The anti-vacuity arm, against the graph as it actually resolves FOR macOS.
    // Every case above drives a fixture; this one is the only evidence that the
    // pair agrees with the tree `darwin-link` links.
    let metadata = std::process::Command::new("cargo")
        .args([
            "metadata",
            "--format-version",
            "1",
            "--filter-platform",
            "aarch64-apple-darwin",
        ])
        .current_dir("../..")
        .output()
        .expect("cargo metadata runs");
    assert!(metadata.status.success(), "the macOS graph resolves");

    let dir = repo("the-repo-as-it-stands-has-no-sdk-requiri");
    let reached = walk(&dir, &String::from_utf8_lossy(&metadata.stdout));
    assert!(reached.contains("scanned "), "the walk ran\n{reached}");
    assert!(
        !reached.contains("links ") && !reached.contains("framework "),
        "and nothing in the macOS graph needs an SDK to link\n{reached}"
    );
}
