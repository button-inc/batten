//! Vendored preset bundles (CLOUD-836): compiled into the binary, enabled by
//! name, and indistinguishable from an in-repo predicate once they deny.
//!
//! Batten shipped no default policy at all, which is the anomaly rather than the
//! discipline — Conftest ships OCI bundles, Semgrep `p/default`, `ESLint`'s
//! `recommended`, Clippy its lint groups. The non-negotiable that looks
//! like it forbids this argues *for* it: a preset is prior art shipped as data,
//! which is the opposite of expanding the core.
//!
//! This is not the OCI distribution CLOUD-129 rejected. That verdict was about
//! remote policy fetch being a supply-chain surface and it is intact: no
//! network, no registry, no trust-on-first-use, just `include_str!` at build
//! time.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::fs;
use std::path::PathBuf;

use batten::facts::Look;
use batten::policy;
use batten::rules::Rule;

/// A mediated-call row enabling a vendored preset by name.
fn preset_row(id: &str, preset: &str) -> Rule {
    serde_json::from_value(serde_json::json!({
        "id": id,
        "kind": "policy",
        "scope": "mediated_call",
        "preset": preset,
        "severity": "deny",
    }))
    .expect("a preset row the loader accepts")
}

fn call(command: &str) -> String {
    serde_json::json!({"call": {"command": command, "operation": "run", "event": "pre_tool"}})
        .to_string()
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("batten-preset-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("scratch");
    dir
}

/// (a) A preset predicate denies on a violating call and is green on a clean
/// one.
///
/// Both halves, because the first alone passes on a preset that denies
/// unconditionally — which is not a gate.
#[test]
fn a_preset_predicate_denies_and_is_green_by_turns() {
    let root = scratch("denies");
    let bundles = policy::load(&root, &[preset_row("trunk", "trunk-based")], None)
        .expect("a vendored preset loads");

    let Look::Is(violations) = policy::deny(&bundles[0], &call("git push --force origin topic"))
    else {
        panic!("the preset answered");
    };
    assert_eq!(violations.len(), 1, "the practice-level predicate fired");
    assert_eq!(
        bundles[0].attribute(&violations[0]),
        "no-force-push",
        "a preset finding names ITS OWN predicate id — never `preset` as a \
         category, and never the enabling row"
    );

    // `--force-with-lease` is the sanctioned form and is deliberately not
    // matched: a preset that banned both would push its consumers toward the
    // bypass rather than toward the safer flag.
    assert_eq!(
        policy::deny(
            &bundles[0],
            &call("git push --force-with-lease origin topic")
        ),
        Look::Is(Vec::new()),
        "the safer flag is not the thing being refused"
    );
    assert_eq!(
        policy::deny(&bundles[0], &call("git push origin topic")),
        Look::Is(Vec::new()),
        "and an ordinary push is silent"
    );
}

/// The second shipped preset, so the table is exercised rather than one row of
/// it.
#[test]
fn the_commit_hygiene_preset_decides_both_ways() {
    let root = scratch("hygiene");
    let bundles = policy::load(&root, &[preset_row("hygiene", "commit-hygiene")], None)
        .expect("the preset loads");

    let Look::Is(violations) = policy::deny(&bundles[0], &call("git commit --allow-empty -m x"))
    else {
        panic!("the preset answered");
    };
    assert_eq!(bundles[0].attribute(&violations[0]), "no-empty-commit");
    assert_eq!(
        policy::deny(&bundles[0], &call("git commit -m x")),
        Look::Is(Vec::new())
    );
}

/// (b) An unknown preset name is refused at load, not ignored.
///
/// A consumer who typed `trunk-basd` should be told, not quietly gated by
/// nothing — which is the failure a silent no-op produces and the reason this is
/// exit `1` rather than a skip.
#[test]
fn an_unknown_preset_name_is_refused_at_load() {
    let root = scratch("unknown");
    let err = policy::load(&root, &[preset_row("typo", "trunk-basd")], None)
        .expect_err("a name this binary does not ship");
    let text = format!("{err}");
    assert!(
        text.contains("trunk-basd"),
        "names what was asked for: {text}"
    );
    assert!(
        text.contains("trunk-based"),
        "and what IS available, so the fix is in the message: {text}"
    );
}

/// (e) Presets are opt-in, asserted — so this cannot quietly become default-on.
#[test]
fn enabling_no_preset_yields_no_preset_predicates() {
    let root = scratch("opt-in");
    let bundles = policy::load(&root, &[], None).expect("no rows, no bundles");
    assert!(
        bundles.is_empty(),
        "a consumer who enables nothing gets nothing, which is what keeps this \
         clear of §8 entirely"
    );
}

/// (d) A preset id colliding with an in-repo id is refused at load.
///
/// Exercised across the vendored/in-repo boundary specifically: bundles are
/// isolated as ENGINES and still visible to each other for id claims, and that
/// difference is the design — a preset cannot supply a helper to a consumer's
/// module, and cannot silently shadow one of its predicate ids either.
#[test]
fn a_preset_id_colliding_with_an_in_repo_id_is_refused_at_load() {
    let root = scratch("collision");
    // An in-repo module claiming the preset's own id.
    fs::write(
        root.join("mine.rego"),
        "package batten\nimport rego.v1\nrules contains \"no-force-push\"\n",
    )
    .expect("write module");
    let mine: Rule = serde_json::from_value(serde_json::json!({
        "id": "mine",
        "kind": "policy",
        "scope": "mediated_call",
        "module": "mine.rego",
        "severity": "deny",
    }))
    .expect("an in-repo row");

    let err = policy::load(&root, &[preset_row("trunk", "trunk-based"), mine], None)
        .expect_err("one id, two publishers across the boundary");
    let text = format!("{err}");
    assert!(text.contains("no-force-push"), "names the id: {text}");
    assert!(
        text.contains("mine.rego") && text.contains("trunk-based"),
        "and BOTH sides, one of which is vendored: {text}"
    );
}

/// The valid name set is derived from the embedded set, never hand-maintained.
///
/// `surface::SURFACE`'s discipline, and the reason a preset cannot be enabled
/// that does not exist: the loader, the schema enum and this assertion all read
/// one list.
#[test]
fn every_advertised_preset_name_actually_loads() {
    let root = scratch("names");
    let names = policy::preset_names();
    assert!(!names.is_empty(), "the binary ships at least one preset");
    for name in names {
        policy::load(&root, &[preset_row("row", name)], None)
            .unwrap_or_else(|err| panic!("the advertised preset `{name}` does not load: {err}"));
    }
}

/// **Non-negotiable rule 1 over presets — the load-bearing case.**
///
/// A preset is the most inviting place in the crate to vendor a consumer's
/// gates, because a preset genuinely *is* policy-as-data and the boundary
/// between "generic" and "ours" is a judgement the compiler cannot make.
///
/// The mechanism is not a new gate, and that is the finding rather than a
/// shortcut: `batten.toml`'s rule-1 `forbid` rows glob `crates/**`, so every
/// embedded preset source is ALREADY scanned on every gate invocation. Adding a
/// second scanner over the same paths with the same patterns would be the
/// two-authorities-that-drift shape `mise-tasks/rules-drift` exists to warn
/// about — and the patterns themselves cannot be restated in this crate anyway,
/// since naming them here is the violation.
///
/// So this asserts the COVERAGE — that the preset sources are inside the glob
/// those rows use — which turns "rule 1 reaches presets" from an assumption into
/// a fact. Fails by: moving the presets outside `crates/`, which is the only way
/// the existing rows could stop seeing them.
#[test]
fn presets_are_inside_the_rule_one_glob() {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let presets = manifest.join("src/policy/presets");
    assert!(
        presets.is_dir(),
        "the embedded preset sources live where the rule-1 rows can see them"
    );

    let repo_root = manifest
        .parent()
        .and_then(std::path::Path::parent)
        .expect("the workspace root");
    let relative = presets
        .strip_prefix(repo_root)
        .expect("presets sit under the workspace root");
    let relative = relative.to_str().expect("a utf-8 path");
    assert!(
        relative.starts_with("crates/"),
        "the rule-1 rows glob `crates/**`; presets at `{relative}` would be \
         outside it, and rule 1 over presets would be prose again"
    );

    // And that the rows are still there globbing it. A test asserting only the
    // path would pass on a config that had dropped the rows entirely.
    let authority = fs::read_to_string(repo_root.join("batten.toml")).expect("read the authority");
    assert!(
        authority.contains("glob = \"crates/**\""),
        "the authority no longer carries a `crates/**` rule-1 row, so nothing \
         scans the preset sources"
    );
}

/// Every shipped preset publishes at least one id, and declares every id it
/// raises.
///
/// The load-time checks already refuse an undeclared id, so this asserts the
/// other direction: a preset that published nothing would load clean and be
/// unwaivable and unattributable — a vendored gate nobody could name.
#[test]
fn every_shipped_preset_publishes_its_ids() {
    let root = scratch("published");
    for name in policy::preset_names() {
        let bundles = policy::load(&root, &[preset_row("row", name)], None).expect("loads");
        assert!(
            !bundles[0].declared().is_empty(),
            "the preset `{name}` publishes no rule id, so nothing it denies could \
             be waived or attributed"
        );
    }
}
