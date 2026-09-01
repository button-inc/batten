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

/// The mediated-call document, for a fixture command that carries no shell list.
///
/// **`segments` is present because the ENGINE always emits it** (CLOUD-857).
/// `hook::call_document` projects `hook::segments` on every mediated call, so a
/// fixture omitting the key would hand the predicate a shape the boundary never
/// produces — CLOUD-845's defect, in the direction that makes a real deny look
/// like a clean call.
///
/// The whitespace split here is NOT a second tokenizer and must not grow into
/// one: every command below is a single unquoted element, where splitting on
/// spaces and `hook::segments` agree by inspection. Anything with a quote or a
/// list operator belongs in `crates/batten/tests/it/preset_segments.rs`, which
/// drives the real projection through the compiled binary over a real envelope
/// — the tier `.claude/rules/policy-modules.md` says a `with input as` case
/// cannot stand in for.
fn call(command: &str) -> String {
    let words: Vec<&str> = command.split_whitespace().collect();
    assert!(
        !command.contains('"') && !command.contains('\''),
        "a quoted fixture needs the real projection: use tests/preset_segments.rs"
    );
    serde_json::json!({"call": {
        "command": command,
        "segments": [{"words": words, "raw": command, "terminator": null}],
        "operation": "run",
        "event": "pre_tool",
    }})
    .to_string()
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("batten-preset-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("scratch");
    dir
}

/// The surface each shipped preset's modules actually decide over.
///
/// **A table rather than a derivation, because nothing derives it** (CLOUD-1279).
/// A preset ships modules and a `[[rule]]` row picks the scope, so the pairing
/// lives in whichever consumer enables the bundle — and a preset absent from this
/// table is one nobody stated a surface for, which is precisely the state that
/// lets a wrong-surface key hide.
const PRESET_SCOPES: &[(&str, bool)] = &[
    ("commit-hygiene", false),
    ("trunk-based", false),
    ("shell-hygiene", true),
    ("pinned-toolchain", false),
    ("ci-hygiene", true),
    ("landing-loop", true),
];

/// A row enabling `name` at the scope it is really enabled with.
///
/// Every table-wide loop below goes through this rather than through
/// [`preset_row`], and that is the whole of CLOUD-1279's test half. Fabricating
/// `mediated_call` for all of them — which is what those loops used to do, so one
/// loop could cover the table — early-returned the tree arm of
/// `check_tree_paths_are_emittable`, so a tree module reading a key the engine
/// never emits passed every tier it had. The loops still cover the table; they
/// just stop inventing the surface while doing it.
fn row_at_real_scope(id: &str, name: &str) -> Rule {
    let (_, is_tree) = PRESET_SCOPES
        .iter()
        .find(|(preset, _)| *preset == name)
        .unwrap_or_else(|| {
            panic!("the preset `{name}` ships and PRESET_SCOPES does not say which surface it decides over")
        });
    if *is_tree {
        tree_preset_row(id, name)
    } else {
        preset_row(id, name)
    }
}

/// (a) A preset predicate denies on a violating call and is green on a clean
/// one.
///
/// Both halves, because the first alone passes on a preset that denies
/// unconditionally — which is not a gate.
#[test]
fn a_preset_predicate_denies_and_is_green_by_turns() {
    let root = scratch("denies");
    let bundles = policy::load(
        &root,
        &[preset_row("trunk", "trunk-based")],
        policy::Vocabulary::EMPTY,
        policy::ModuleChecks::Run,
        None,
    )
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
    let bundles = policy::load(
        &root,
        &[preset_row("hygiene", "commit-hygiene")],
        policy::Vocabulary::EMPTY,
        policy::ModuleChecks::Run,
        None,
    )
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
    let err = policy::load(
        &root,
        &[preset_row("typo", "trunk-basd")],
        policy::Vocabulary::EMPTY,
        policy::ModuleChecks::Run,
        None,
    )
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
    let bundles = policy::load(
        &root,
        &[],
        policy::Vocabulary::EMPTY,
        policy::ModuleChecks::Run,
        None,
    )
    .expect("no rows, no bundles");
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

    let err = policy::load(
        &root,
        &[preset_row("trunk", "trunk-based"), mine],
        policy::Vocabulary::EMPTY,
        policy::ModuleChecks::Run,
        None,
    )
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
        policy::load(
            &root,
            &[row_at_real_scope("row", name)],
            policy::Vocabulary::EMPTY,
            policy::ModuleChecks::Run,
            None,
        )
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
/// two-authorities-that-drift shape `mise-tasks/rules-drift.sh` exists to warn
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

    // BY PATH COMPONENT, never by string prefix. `Path::join` keeps the
    // separator it was handed, so on Windows this reads
    // `crates\batten\src/policy/presets` — mixed — and `starts_with("crates/")`
    // is false for a directory that is plainly under `crates`. Measured: this
    // assertion was written as a string test and went red on the `windows` job
    // while passing everywhere else, which is a test asserting a property of the
    // host's separator rather than of the tree.
    let first = relative
        .components()
        .next()
        .and_then(|component| component.as_os_str().to_str());
    // Rendered with `/` for the message, so the pointer reads the same on every
    // host — §6's byte-stability applied to a failure message.
    let shown = relative
        .components()
        .filter_map(|component| component.as_os_str().to_str())
        .collect::<Vec<_>>()
        .join("/");
    assert_eq!(
        first,
        Some("crates"),
        "the rule-1 rows glob `crates/**`; presets at `{shown}` would be \
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
        let bundles = policy::load(
            &root,
            &[row_at_real_scope("row", name)],
            policy::Vocabulary::EMPTY,
            policy::ModuleChecks::Run,
            None,
        )
        .expect("loads");
        assert!(
            !bundles[0].declared().is_empty(),
            "the preset `{name}` publishes no rule id, so nothing it denies could \
             be waived or attributed"
        );
    }
}

/// Every vendored preset's own suite is green (CLOUD-835).
///
/// **The mechanism half of the preset tests, and without it they are prose.** A
/// `test_` rule in a shipped module that nothing runs is a comment that happens
/// to parse: it can rot to red, or to vacuous, and the first reader to find out
/// is a consumer who enabled the preset. This is what runs them, in the suite
/// that already owns "the shipped presets are correct".
///
/// It asserts all four terms rather than only the failures, and the last two are
/// the ones that would rot silently: a preset whose predicate nothing exercises
/// still passes every test it has, and a preset that lost its tests entirely
/// still loads and denies. Both are green to a failure count and neither is
/// green here.
#[test]
fn every_shipped_preset_passes_its_own_suite() {
    let root = scratch("suites");
    for name in policy::preset_names() {
        let bundles = policy::load(
            &root,
            &[row_at_real_scope("row", name)],
            policy::Vocabulary::EMPTY,
            policy::ModuleChecks::Run,
            None,
        )
        .expect("loads");
        // NOT MEDIATED HERE, and the reason is this loop's own bound rather
        // than a gap (CLOUD-857). `preset_row` fabricates a `mediated_call`
        // scope for EVERY preset so one loop can load them all — but
        // `shell-hygiene` is enabled `scope = "tree"` in this repository and its
        // two modules decide over files, not commands. Asking them whether a
        // test ever passed a compound COMMAND would be judging a surface this
        // helper invented, which is the fabricated-shape defect one level up.
        //
        // The term is asserted where the scope is real: `policy_test_suite.rs`
        // states it per scope directly, and `mise run policy-test` over the
        // committed `batten.toml` decides it for the rows this repository
        // actually enables.
        let Look::Is(suite) = policy::test(&bundles[0], "{}", false).expect("the suite runs")
        else {
            panic!("the preset `{name}` has a suite that could not run at all");
        };
        assert!(
            !suite.passed.is_empty(),
            "the preset `{name}` passes no test, so nothing about it is established"
        );
        assert!(
            suite.failed.is_empty(),
            "the preset `{name}` fails {:?}",
            suite.failed
        );
        assert!(
            suite.unexercised.is_empty(),
            "the preset `{name}` publishes {:?}, which no test makes fire",
            suite.unexercised
        );
        assert!(
            suite.untested_modules.is_empty(),
            "the preset `{name}` ships {:?} with no test at all",
            suite.untested_modules
        );
    }
}

/// A tree-scoped row enabling a vendored preset by name.
///
/// The sibling of [`preset_row`], and separate rather than parameterised because
/// the two surfaces are different shapes: a tree row's bundle reads
/// `input.tree.*` and a mediated row's reads `input.call.*` / `input.facts.*`,
/// and a helper that took the scope as an argument would invite one fixture to
/// be pointed at both.
fn tree_preset_row(id: &str, preset: &str) -> Rule {
    serde_json::from_value(serde_json::json!({
        "id": id,
        "kind": "policy",
        "scope": "tree",
        "preset": preset,
        "severity": "deny",
    }))
    .expect("a tree preset row the loader accepts")
}

/// The one bundle a preset row compiles, loaded with the EMPTY vocabulary.
///
/// `Vocabulary::EMPTY` is how `patterns: &[]` is spelled here, and it is the
/// whole point of this tier rather than a convenience: it proves the bundle
/// loads and decides for a consumer who wrote no `[[pattern]]` and no
/// `[[verdict]]` row at all. A harness that declared the ids would supply input
/// no consumer supplies, and the deny cases would then pass for the wrong reason
/// — which is how CLOUD-1161's `ci-hygiene` shipped two dead predicates under a
/// green `batten policy test` reporting 330 passed.
fn loaded(name: &str, row: Rule) -> policy::Bundle {
    let root = scratch(name);
    let mut bundles = policy::load(
        &root,
        &[row],
        policy::Vocabulary::EMPTY,
        policy::ModuleChecks::Run,
        None,
    )
    .expect("a vendored preset loads for a consumer with no vocabulary of its own");
    bundles.remove(0)
}

/// The findings a bundle reports over one document, or a panic if it could not
/// answer at all.
fn decided(bundle: &policy::Bundle, document: &str) -> Vec<policy::Violation> {
    let Look::Is(violations) = policy::deny(bundle, document) else {
        panic!("the preset answered");
    };
    violations
}

/// (CLOUD-1269) `graded-head-is-not-regraded` refuses a judged commit and is
/// silent on one nothing has looked at.
///
/// Both halves, because the first alone passes on a preset that refuses
/// unconditionally — which is not a gate (CLOUD-418).
#[test]
fn the_landing_loop_preset_refuses_a_regrade_and_is_green_by_turns() {
    let bundle = loaded("landing-loop", tree_preset_row("landing", "landing-loop"));

    let judged = decided(
        &bundle,
        r#"{"tree":{"forge":{"1111111":{"final":"success"}}}}"#,
    );
    assert_eq!(judged.len(), 1, "a commit the forge already judged");
    assert_eq!(
        bundle.attribute(&judged[0]),
        "graded-head-is-not-regraded",
        "a preset finding names ITS OWN predicate id — never `preset` as a \
         category, and never the enabling row"
    );

    // THE ANTI-VACUITY MIRROR, and then the two states that are not verdicts.
    assert!(
        decided(&bundle, r#"{"tree":{"forge":{}}}"#).is_empty(),
        "a commit with no record has not been judged, so there is nothing to refuse"
    );
    assert!(
        decided(&bundle, r#"{"tree":{"forge":{"1111111":{}}}}"#).is_empty(),
        "judged and silent is not judged: the forge looked and recorded nothing"
    );
    assert!(
        decided(&bundle, r#"{"tree":{"forge":null}}"#).is_empty(),
        "could-not-look allows, and without the module's own guard this FAULTS"
    );
}

/// (CLOUD-1269, CLOUD-1279) Every preset loads at the scope it is enabled with,
/// and the tree-scoped ones therefore reach the guard at all.
///
/// The loops above now go through [`row_at_real_scope`] too, so this is the arm
/// that states the property directly rather than relying on them: a preset whose
/// modules read a key its own surface does not emit fails to load, on either
/// surface. Before CLOUD-1279 the mediated arm did not exist and every loop
/// fabricated `mediated_call`, so neither half could fire.
#[test]
fn every_preset_loads_at_the_scope_it_is_enabled_with() {
    for name in policy::preset_names() {
        let root = scratch(&format!("real-scope-{name}"));
        policy::load(
            &root,
            &[row_at_real_scope("row", name)],
            policy::Vocabulary::EMPTY,
            policy::ModuleChecks::Run,
            None,
        )
        .unwrap_or_else(|err| panic!("the preset `{name}` does not load at its own scope: {err}"));
    }
}

/// (CLOUD-1279) A `mediated_call` module reading `input.tree.*` is refused at
/// load, and its anti-vacuity mirror still loads.
///
/// The class is CLOUD-845's — a module reads a key its document does not carry,
/// Rego takes undefined as *does not hold*, and a dead gate is byte-identical to
/// a clean tree. The guard closed it on the tree surface and early-returned on
/// every other, so the same defect survived intact one scope over. The mirror is
/// what makes this a gate rather than a refusal of everything (CLOUD-418).
#[test]
fn a_mediated_module_reading_a_tree_key_is_refused_at_load() {
    let root = scratch("cross-surface");
    // RAISES NOTHING, deliberately. A fixture that emitted a verdict would be
    // refused by `check_verdicts_are_declared` first — under `Vocabulary::EMPTY`
    // no consumer token is declared — and the test would then pass on the wrong
    // refusal, which is the shape it exists to catch one level down.
    fs::write(
        root.join("crossed.rego"),
        "package batten\nimport rego.v1\nrules contains \"crossed\"\n\
         reaches if { input.tree.tracked[_] }\n",
    )
    .expect("write module");
    let crossed: Rule = serde_json::from_value(serde_json::json!({
        "id": "crossed",
        "kind": "policy",
        "scope": "mediated_call",
        "module": "crossed.rego",
        "severity": "deny",
    }))
    .expect("a mediated row");

    let err = policy::load(
        &root,
        &[crossed],
        policy::Vocabulary::EMPTY,
        policy::ModuleChecks::Run,
        None,
    )
    .expect_err("a mediated module cannot read the tree document");
    let text = format!("{err}");
    assert!(
        text.contains("tracked"),
        "names the key it reached for: {text}"
    );
    assert!(
        text.contains("crossed.rego"),
        "and the module, pointer-only: {text}"
    );

    // THE ANTI-VACUITY MIRROR. `input.tree.tracked` is a key the engine emits
    // perfectly well — on the OTHER surface — so a guard comparing against a key
    // set would have waved it through. The same module, tree-scoped, loads.
    let fine: Rule = serde_json::from_value(serde_json::json!({
        "id": "crossed",
        "kind": "policy",
        "scope": "tree",
        "module": "crossed.rego",
        "severity": "deny",
    }))
    .expect("a tree row");
    policy::load(
        &root,
        &[fine],
        policy::Vocabulary::EMPTY,
        policy::ModuleChecks::Run,
        None,
    )
    .expect("the same module on the surface that emits the key");
}

/// (CLOUD-1279) The mirror direction: a `tree` module reading `input.facts.*` is
/// refused, and a mediated module reading it still loads.
///
/// This half fell through for a different reason than the mediated half — the
/// loop only inspected paths it could `strip_prefix("tree.")`, so a tree module
/// reaching for the call surface was never looked at at all. `input.facts` is
/// `Surface::Hook` and `tree_document` never emits it, so such a module is dead
/// in exactly the way CLOUD-845 records.
#[test]
fn a_tree_module_reading_a_call_fact_is_refused_at_load() {
    let root = scratch("cross-surface-mirror");
    fs::write(
        root.join("reversed.rego"),
        "package batten\nimport rego.v1\nrules contains \"reversed\"\n\
         reaches if { input.facts.receipts[_] }\n",
    )
    .expect("write module");
    let row = |scope: &str| -> Rule {
        serde_json::from_value(serde_json::json!({
            "id": "reversed",
            "kind": "policy",
            "scope": scope,
            "module": "reversed.rego",
            "severity": "deny",
        }))
        .expect("a row the loader accepts")
    };

    let err = policy::load(
        &root,
        &[row("tree")],
        policy::Vocabulary::EMPTY,
        policy::ModuleChecks::Run,
        None,
    )
    .expect_err("a tree module cannot read the call's facts");
    let text = format!("{err}");
    assert!(
        text.contains("facts"),
        "names the surface it reached for: {text}"
    );
    assert!(
        text.contains("reversed.rego"),
        "and the module, pointer-only: {text}"
    );

    // THE ANTI-VACUITY MIRROR. The same module, on the surface that emits
    // `facts`, loads — so this refuses a wrong surface rather than a fact.
    policy::load(
        &root,
        &[row("mediated_call")],
        policy::Vocabulary::EMPTY,
        policy::ModuleChecks::Run,
        None,
    )
    .expect("the same module on the surface that emits the fact");
}

/// (CLOUD-1280) `already-landed-work-is-not-relanded` refuses a target that
/// already carries this work, and is silent on one that does not.
///
/// The deny and its anti-vacuity mirror, plus the two answers that are NOT
/// verdicts — a target nothing could scan, and could-not-look. Without the
/// mirror the deny is satisfied by a module that refuses everything (CLOUD-418).
#[test]
fn the_landing_loop_preset_refuses_a_reland_and_is_green_by_turns() {
    let bundle = loaded("landing-reland", tree_preset_row("landing", "landing-loop"));

    let answered = |answer: &str| format!(r#"{{"tree":{{"landing":{{"origin/main":{answer}}}}}}}"#);

    let landed = decided(
        &bundle,
        &answered(r#"{"verdict":"landed","landed":true,"unlanded":[]}"#),
    );
    assert_eq!(landed.len(), 1, "the target already carries this work");
    assert_eq!(
        bundle.attribute(&landed[0]),
        "already-landed-work-is-not-relanded",
        "a preset finding names its own predicate id"
    );

    // THE SQUASH SHAPE. `landed` is true through the cumulative diff while
    // `unlanded` is non-empty, so a module written over the array would call
    // this branch outstanding — the false negative patch identity exists to
    // prevent, and the case that discriminates this predicate from that one.
    assert_eq!(
        decided(
            &bundle,
            &answered(r#"{"verdict":"landed","landed":true,"unlanded":["1111111"]}"#)
        )
        .len(),
        1,
        "a squash-landed branch is landed even though unlanded is not empty"
    );

    // NOTHING TO LAND IS NOT A DUPLICATE, and this is the case that keeps the
    // predicate about an ATTEMPT rather than about a STATE. `landed` is true
    // here, so a module reading the boolean refuses every clean checkout sitting
    // on the trunk — which is what this one did until the four `cli::` fixtures
    // built from the committed config reported it.
    assert!(
        decided(
            &bundle,
            &answered(r#"{"verdict":"nothing_to_land","landed":true,"unlanded":[]}"#)
        )
        .is_empty(),
        "a branch with no distinct work has no duplicate to warn about"
    );

    // THE ANTI-VACUITY MIRROR.
    assert!(
        decided(
            &bundle,
            &answered(r#"{"verdict":"partially_landed","landed":false,"unlanded":["1111111"]}"#)
        )
        .is_empty(),
        "outstanding work may be landed, or this refuses everything"
    );

    // An UNPROVEN absence is not a negative: the scan is windowed and whether it
    // was truncated is not projected, so this must not read as landed.
    assert!(
        decided(
            &bundle,
            &answered(
                r#"{"verdict":"not_landed_within_window","landed":false,"unlanded":["1111111"]}"#
            )
        )
        .is_empty(),
        "an unproven absence is not a landing verdict"
    );

    // The two could-not-look channels, which the family keeps apart.
    assert!(
        decided(&bundle, r#"{"tree":{"landing":{}}}"#).is_empty(),
        "a declared target that could not be scanned is absent, not a negative"
    );
    assert!(
        decided(&bundle, r#"{"tree":{"landing":null}}"#).is_empty(),
        "could-not-look allows, and without the module's own guard this FAULTS"
    );
}
