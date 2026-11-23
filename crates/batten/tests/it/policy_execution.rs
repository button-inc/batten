//! Every policy module decides on bytecode, on every surface, and says so (#1276).
//!
//! **THE REGRESSION THIS EXISTS FOR WAS SILENT.** `check` and `enforce` loaded
//! every bundle with `ModuleChecks::Run`, and `compile_for` only offered the
//! bytecode cache to `ModuleChecks::SkipOnHotPath`, so every bundle the lap
//! evaluated ran on regorus's tree-walking interpreter. Nothing recorded it:
//! the lap's live half was measured at 824 s with 84% of its samples in the
//! interpreter before anyone asked which evaluator ran.
//!
//! So the evaluator is now a value ([`policy::Execution`]), an interpreted
//! bundle always carries its [`policy::Fallback`], and these cases hold it:
//!
//! - every `[[rule]] kind = "policy"` row this repository declares, loaded at
//!   each of the three [`policy::ModuleChecks`] — `Run` is `check`/`enforce`
//!   (both halves), `RunOverSelection` is `check --rule`, `SkipOnHotPath` is
//!   the hook's adjudication and `state record` — decides on bytecode;
//! - every module every shipped preset carries, at every scope and provider it
//!   selects on, decides on bytecode;
//! - the binary's own `check` and `enforce` halves report, on `-vv`, that no
//!   verdict ran on the interpreter.
//!
//! A module the bytecode compiler genuinely cannot express is listed in
//! [`ALLOWED`] with its reason, and the list only shrinks: an entry that now
//! compiles, or names nothing loaded, fails the case.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use batten::config_model::Rule;
use batten::policy::{self, Execution, Fallback, ModuleChecks};
use batten::preset_catalog::RuleScope;

/// The bundles allowed to decide on the interpreter: `(bundle id, reason)`.
/// It only shrinks (see the module doc). Each is a construct regorus 0.15's
/// bytecode answers WRONGLY rather than refusing, which batten refuses for it:
/// - `KeyedPartialSet`: `f[k] contains v` answered as a flat set
///   (`module-layering.rego:974`, `forbidden[from] contains to`);
/// - `RuleElse`: an `else` after a body that iterates nothing is dropped
///   (`release-tracking.rego:91`, `filed-here.rego:101`,
///   `obligations-bound.rego:133`).
///
/// The policy unit cases pin both defects, so an entry leaves when regorus is
/// fixed or the module stops using the construct.
const ALLOWED: &[(&str, Fallback)] = &[
    ("layer place wrong", Fallback::KeyedPartialSet),
    ("release wire other", Fallback::RuleElse),
    ("issue file other", Fallback::RuleElse),
    ("test name undefined", Fallback::RuleElse),
];

/// Every bundle in `bundles` that did not land on bytecode, as one line each.
fn interpreted(label: &str, bundles: &[policy::Bundle]) -> Vec<(String, Fallback, String)> {
    bundles
        .iter()
        .filter_map(|bundle| match bundle.execution() {
            Execution::Bytecode { .. } => None,
            Execution::Interpreted(why) => Some((
                bundle.id().to_owned(),
                why,
                format!(
                    "{label}: {} on the interpreter ({}): {}",
                    bundle.id(),
                    why.as_str(),
                    bundle.fallback_detail().unwrap_or("no detail")
                ),
            )),
        })
        .collect()
}

/// Fail on any interpreted bundle not in [`ALLOWED`] with that reason, and on
/// any [`ALLOWED`] entry that `seen` contains but did not fall back.
fn hold(found: &[(String, Fallback, String)], seen: &[String]) {
    let unexpected: Vec<&str> = found
        .iter()
        .filter(|(id, why, _)| !ALLOWED.contains(&(id.as_str(), *why)))
        .map(|(_, _, line)| line.as_str())
        .collect();
    assert!(
        unexpected.is_empty(),
        "these policy bundles decide on the tree-walking interpreter; make them \
         compile to bytecode, or list them in ALLOWED with the reason:\n{}",
        unexpected.join("\n")
    );
    for (id, why) in ALLOWED {
        if seen.iter().any(|loaded| loaded == id) {
            assert!(
                found.iter().any(|(at, was, _)| at == id && was == why),
                "`{id}` is allowed the interpreter for {} but now decides on bytecode: \
                 delete its ALLOWED entry",
                why.as_str()
            );
        }
    }
}

/// This repository's resolved config.
fn resolved() -> (std::path::PathBuf, batten::resolve::Resolved) {
    common::scratch_state_root();
    let repo = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let resolved = batten::resolve::resolve(&repo, &batten::resolve::Overrides::default())
        .expect("this repository's config resolves");
    (repo, resolved)
}

#[test]
fn every_repository_policy_row_decides_on_bytecode_at_every_load() {
    let (repo, resolved) = resolved();
    let vocabulary = policy::Vocabulary {
        patterns: &resolved.patterns,
        verdicts: &resolved.verdicts,
        words: (!resolved.vocabulary.is_empty()).then_some(&resolved.vocabulary),
        recorders: &resolved.recorders,
        registers: &resolved.registers,
        traversals: &resolved.traversals,
        records: &resolved.records,
    };
    let mut found = Vec::new();
    let mut seen = Vec::new();
    // Twice per mode: the first load may compile, the second must read the
    // entry the first wrote; neither may fall back.
    for checks in [
        ModuleChecks::Run,
        ModuleChecks::RunOverSelection,
        ModuleChecks::SkipOnHotPath,
        ModuleChecks::Run,
    ] {
        let bundles = policy::load(&repo, &resolved.rules, vocabulary, checks, None)
            .unwrap_or_else(|err| panic!("{checks:?}: this repository's policy loads: {err}"));
        assert!(
            bundles.len() >= 50,
            "{checks:?}: the repository's policy rows reach the load: {}",
            bundles.len()
        );
        seen.extend(bundles.iter().map(|bundle| bundle.id().to_owned()));
        found.extend(interpreted(&format!("{checks:?}"), &bundles));
    }
    hold(&found, &seen);
}

/// The case inputs a module's own cases rarely write: every path it reads set
/// to `null`, and removed, in each of its first three cases (#1276). A builtin
/// over a null or absent fact is where the two evaluators part — `concat("",
/// [input.facts["land-live"], "/"])` over `null` faulted the bytecode's whole
/// bundle where the interpreter read the call as undefined.
fn hollowed(cases: &[String], paths: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    for case in cases.iter().take(3) {
        let Ok(document) = serde_json::from_str::<serde_json::Value>(case) else {
            continue;
        };
        for path in paths {
            let segments: Vec<&str> = path.split('.').collect();
            // NULL ONLY WHERE THE ENGINE CAN HAND ONE OVER: a fact is `null`
            // when its producer reported none (`land-live`), while the call and
            // tree documents never carry a null where a module reads a value.
            // Absent is possible everywhere. Measured: nulling every read path
            // split 84 bundles on shapes no engine input takes.
            let nullable = path.starts_with("facts.");
            for absent in [false, true] {
                if !absent && !nullable {
                    continue;
                }
                let mut changed = document.clone();
                let mut at = &mut changed;
                for segment in &segments[..segments.len() - 1] {
                    if !at.is_object() {
                        *at = serde_json::json!({});
                    }
                    at = at
                        .as_object_mut()
                        .expect("an object")
                        .entry((*segment).to_owned())
                        .or_insert_with(|| serde_json::json!({}));
                }
                let Some(map) = at.as_object_mut() else {
                    continue;
                };
                let last = segments[segments.len() - 1].to_owned();
                if absent {
                    map.remove(&last);
                } else {
                    map.insert(last, serde_json::Value::Null);
                }
                out.push(changed.to_string());
            }
        }
    }
    out
}

/// What a gate reads off a bundle for `input`: its violations.
fn verdicts(bundle: &policy::Bundle, input: &str) -> String {
    format!("{:?}", policy::deny(bundle, input))
}

/// Every repository policy row answers alike on bytecode and on its own
/// interpreter, over the inputs its own cases prove decisions over (#1276).
///
/// `policy_cache` holds this for the mediated rows, which were the only ones
/// on bytecode; every tree row moved onto it here, so every row is compared.
/// Fails by: a construct the bytecode compiler reads differently from the
/// interpreter, which would change a verdict `check` or `enforce` reports.
#[test]
fn every_repository_policy_row_answers_alike_on_bytecode_and_the_interpreter() {
    let (repo, resolved) = resolved();
    let vocabulary = policy::Vocabulary {
        patterns: &resolved.patterns,
        verdicts: &resolved.verdicts,
        words: (!resolved.vocabulary.is_empty()).then_some(&resolved.vocabulary),
        recorders: &resolved.recorders,
        registers: &resolved.registers,
        traversals: &resolved.traversals,
        records: &resolved.records,
    };
    let bundles = policy::load(&repo, &resolved.rules, vocabulary, ModuleChecks::Run, None)
        .expect("this repository's policy loads");
    let mut split = Vec::new();
    let mut corpus = 0;
    for bundle in &bundles {
        if !bundle.is_bytecode() {
            continue;
        }
        let interpreted = bundle
            .as_interpreted()
            .expect("a checked load keeps its interpreter");
        let cases = policy::case_inputs(&interpreted)
            .unwrap_or_else(|| panic!("{}: its case inputs are readable", bundle.id()));
        let hollowed = hollowed(&cases, &policy::input_paths(&interpreted));
        corpus += cases.len() + hollowed.len();
        for input in std::iter::once("{}".to_owned())
            .chain(cases)
            .chain(hollowed)
        {
            let (left, right) = (verdicts(bundle, &input), verdicts(&interpreted, &input));
            if left != right {
                let shown: String = input.chars().take(300).collect();
                split.push(format!(
                    "{}: bytecode {left}\n  interpreter {right}\n  over {shown}",
                    bundle.id()
                ));
                break;
            }
        }
    }
    assert!(
        split.is_empty(),
        "bytecode and the interpreter decide differently:\n{}",
        split.join("\n")
    );
    assert!(
        corpus >= 1000,
        "the cases' inputs reach the comparison: {corpus}"
    );
}

/// Localise each parity split to the rules that introduce it. A diagnostic,
/// run with `--run-ignored only`: it fails naming, per split bundle, every
/// rule whose value differs between the engines (`policy::rule_splits`).
#[test]
#[ignore = "a diagnostic for a parity split, run by hand"]
fn localise_parity_splits() {
    let (repo, resolved) = resolved();
    let vocabulary = policy::Vocabulary {
        patterns: &resolved.patterns,
        verdicts: &resolved.verdicts,
        words: (!resolved.vocabulary.is_empty()).then_some(&resolved.vocabulary),
        recorders: &resolved.recorders,
        registers: &resolved.registers,
        traversals: &resolved.traversals,
        records: &resolved.records,
    };
    let data = batten::pattern::data_document(&resolved.patterns);
    let bundles = policy::load(&repo, &resolved.rules, vocabulary, ModuleChecks::Run, None)
        .expect("this repository's policy loads");
    let mut localised = Vec::new();
    for bundle in bundles.iter().filter(|b| b.is_bytecode()) {
        let interpreted = bundle.as_interpreted().expect("kept");
        let cases = policy::case_inputs(&interpreted).unwrap_or_default();
        for input in std::iter::once("{}".to_owned()).chain(cases) {
            if verdicts(bundle, &input) != verdicts(&interpreted, &input) {
                localised.push(format!("== {}", bundle.id()));
                localised.extend(
                    policy::rule_splits(&interpreted, &data, &input)
                        .into_iter()
                        .map(|split| format!("  {split}")),
                );
                break;
            }
        }
    }
    assert!(localised.is_empty(), "{}", localised.join("\n"));
}

/// Every `(scope, provider)` selection `preset` answers to: no provider, and
/// each provider one of its modules reads.
fn selections(preset: &batten::preset_catalog::Manifest) -> Vec<(RuleScope, Option<&str>)> {
    let mut out = Vec::new();
    for scope in RuleScope::ALL {
        let at: Vec<_> = preset
            .modules
            .iter()
            .filter(|module| module.scope == *scope)
            .collect();
        if at.is_empty() {
            continue;
        }
        let mut providers: Vec<Option<&str>> = vec![None];
        for module in &at {
            if let Some(reads) = module.provider
                && !providers.contains(&Some(reads))
            {
                providers.push(Some(reads));
            }
        }
        out.extend(providers.into_iter().map(|provider| (*scope, provider)));
    }
    out
}

#[test]
fn every_shipped_preset_module_decides_on_bytecode() {
    common::scratch_state_root();
    let root = common::scratch("policy-execution-presets");
    let mut found = Vec::new();
    let mut seen = Vec::new();
    let mut modules = 0;
    for preset in batten::preset_catalog::MANIFESTS {
        for (scope, provider) in selections(preset) {
            let id = format!(
                "preset {} {} {}",
                preset.name,
                scope.as_str(),
                provider.unwrap_or("none")
            );
            let row: Rule = serde_json::from_value(serde_json::json!({
                "id": id,
                "kind": "policy",
                "scope": scope.as_str(),
                "preset": preset.name,
                "provider": provider,
                "severity": "deny",
            }))
            .expect("a preset row the loader accepts");
            // A selection with nothing in it is the loader's refusal to make,
            // not this case's: no module, nothing to evaluate.
            let Ok(bundles) = policy::load(
                &root,
                &[row],
                policy::Vocabulary::EMPTY,
                ModuleChecks::SkipOnHotPath,
                None,
            ) else {
                continue;
            };
            modules += bundles.iter().map(|b| b.modules().len()).sum::<usize>();
            seen.extend(bundles.iter().map(|bundle| bundle.id().to_owned()));
            found.extend(interpreted(&id, &bundles));
        }
    }
    // 56 measured on #1276; the floor sits just under it, so a selection that
    // silently stopped loading fails here rather than passing on nothing.
    assert!(
        modules >= 50,
        "the shipped presets' modules reach the load: {modules}"
    );
    hold(&found, &seen);
}

/// A tree-scope module, in a repository the binary runs in. It decides nothing
/// on any tree; the case is about which evaluator ran it, not what it found.
const PROBE: &str = r#"package batten.probe

import rego.v1

rules contains "probe run never"

violation contains {"rule": "probe run never", "verdict": "probe run never"} if {
	input.tree["git-head"] == "a head no repository has"
}
"#;

const PROBE_ROWS: &str = r#"
[[rule]]
id = "probe tree"
kind = "policy"
scope = "tree"
module = "probe.rego"
severity = "deny"

[[verdict]]
id = "probe run never"
gloss = "the fixture's row, which no tree satisfies"
class = "A fixture predicate that never fires, so the case reads only its evaluator."

[[verdict.route]]
id = "probe fix never"
kind = "command"
target = "nothing: the fixture never refuses"
"#;

#[test]
fn check_and_both_enforce_halves_report_no_interpreted_verdict() {
    let dir = common::Fixture::new("policy-execution-cli")
        .config(&format!("version = 1\n{PROBE_ROWS}"))
        .file("probe.rego", PROBE)
        .git()
        .base_commit()
        .build();
    // The probe reads `git-head`, so it is a live row: the tree half evaluates
    // no verdict, and says so with a zero census rather than none.
    for (args, evaluates) in [
        (&["check", "-vv"][..], true),
        (&["enforce", "--half", "tree", "-vv"], false),
        (&["enforce", "--half", "live", "-vv"], true),
        (&["enforce", "-vv"], true),
    ] {
        let output = common::run(&dir, args);
        let said = common::stderr(&output);
        let total = said
            .lines()
            .find(|line| line.contains("policy evaluator:") && line.contains("bytecode"))
            .unwrap_or_else(|| panic!("{args:?} prints the evaluator census on -vv: {said}"));
        assert!(
            total.contains(" 0 interpreted evaluation(s)"),
            "{args:?}: a verdict ran on the interpreter: {said}"
        );
        assert_eq!(
            !total.contains(" 0 bytecode evaluation(s)"),
            evaluates,
            "{args:?}: the probe's verdict was evaluated on bytecode where the half runs it: \
             {said}"
        );
    }
}

/// The census counts each verdict evaluation against the evaluator that ran it,
/// and an interpreter-only bundle names why.
#[test]
fn a_verdict_evaluation_is_counted_against_its_evaluator() {
    let sources = vec![(String::from("probe.rego"), String::from(PROBE))];
    let bundle = policy::compile("census probe", &sources, &serde_json::json!({}))
        .expect("the probe compiles");
    assert_eq!(
        bundle.execution(),
        Execution::Interpreted(Fallback::NotOffered)
    );
    let _ = policy::deny(&bundle, "{}");
    let count = policy::execution_census()
        .into_iter()
        .find(|(id, how, _)| {
            id == "census probe" && *how == Execution::Interpreted(Fallback::NotOffered)
        })
        .map(|(_, _, count)| count);
    assert_eq!(
        count,
        Some(1),
        "one interpreted evaluation, with its reason"
    );
}
