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
//! THERE IS NO EXEMPTION LIST. Four bundles once decided on the interpreter
//! because regorus 0.15's bytecode answers two constructs wrongly — a keyed
//! partial set (`f[k] contains v`) and an `else` after a body that iterates —
//! and each module was rewritten into a form that compiles alike instead. A
//! module using either construct is still refused bytecode by batten
//! ([`Fallback::KeyedPartialSet`], [`Fallback::RuleElse`]), so it fails here: the
//! fix is the module's spelling, never a list entry.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use batten::config_model::Rule;
use batten::policy::{self, Execution, Fallback, ModuleChecks};
use batten::preset_catalog::RuleScope;

/// Every bundle in `bundles` that did not land on bytecode, as one line each.
fn interpreted(label: &str, bundles: &[policy::Bundle]) -> Vec<String> {
    bundles
        .iter()
        .filter_map(|bundle| match bundle.execution() {
            Execution::Bytecode { .. } => None,
            Execution::Interpreted(why) => Some(format!(
                "{label}: {} on the interpreter ({}): {}",
                bundle.id(),
                why.as_str(),
                bundle.fallback_detail().unwrap_or("no detail")
            )),
        })
        .collect()
}

/// Fail on any interpreted bundle: none is exempt.
fn hold(found: &[String]) {
    assert!(
        found.is_empty(),
        "these policy bundles decide on the tree-walking interpreter; rewrite each \
         module into a form the bytecode compiles alike:\n{}",
        found.join("\n")
    );
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
    let mut compiled = Vec::new();
    // Twice per mode: the first load may compile, every later one must read
    // the entry the first wrote; none may fall back.
    for (load, checks) in [
        ModuleChecks::Run,
        ModuleChecks::RunOverSelection,
        ModuleChecks::SkipOnHotPath,
        ModuleChecks::Run,
    ]
    .into_iter()
    .enumerate()
    {
        let bundles = policy::load(&repo, &resolved.rules, vocabulary, checks, None)
            .unwrap_or_else(|err| panic!("{checks:?}: this repository's policy loads: {err}"));
        assert!(
            bundles.len() >= 50,
            "{checks:?}: the repository's policy rows reach the load: {}",
            bundles.len()
        );
        found.extend(interpreted(&format!("{checks:?}"), &bundles));
        if load > 0 {
            compiled.extend(
                bundles
                    .iter()
                    .filter(|bundle| bundle.execution() == Execution::Bytecode { cached: false })
                    .map(|bundle| format!("{checks:?} (load {load}): {}", bundle.id())),
            );
        }
    }
    hold(&found);
    assert!(
        compiled.is_empty(),
        "a load after the first compiled its program rather than reading the cached \
         entry:\n{}",
        compiled.join("\n")
    );
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
            found.extend(interpreted(&id, &bundles));
        }
    }
    // 56 measured on #1276; the floor sits just under it, so a selection that
    // silently stopped loading fails here rather than passing on nothing.
    assert!(
        modules >= 50,
        "the shipped presets' modules reach the load: {modules}"
    );
    hold(&found);
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

/// The probe, carrying its own cases: each writes a `with`, the construct the
/// bytecode compiler refuses and `policy test` desugars (#1276).
const SUITE_PROBE: &str = r#"package batten.probe

import rego.v1

rules contains "probe run never"

violation contains {"rule": "probe run never", "verdict": "probe run never"} if {
	input.tree["git-head"] == "a head no repository has"
}

test_the_probe_fires_on_the_head_it_names if {
	some v in violation with input as {"tree": {"git-head": "a head no repository has"}}
	v.verdict == "probe run never"
}

test_the_probe_is_silent_on_any_other_head if {
	count(violation) == 0 with input as {"tree": {"git-head": "a head"}}
}
"#;

/// `policy test` decides every case on bytecode, and its `-vv` census says so:
/// zero interpreted evaluations, the cases' own counted on bytecode (#1276).
///
/// Fails by: a case run on the tree-walking interpreter, which every case was
/// until the suite program existed — `policy test` evaluated each `test_` rule
/// on the coverage interpreter and printed no census at all.
#[test]
fn policy_test_reports_no_interpreted_case() {
    let dir = common::Fixture::new("policy-execution-suite")
        .config(&format!("version = 1\n{PROBE_ROWS}"))
        .file("probe.rego", SUITE_PROBE)
        .git()
        .base_commit()
        .build();
    // Twice: the first run compiles the suite program, the second reads it.
    for _ in 0..2 {
        let output = common::run(&dir, &["policy", "test", "-vv"]);
        let said = common::stderr(&output);
        assert!(
            output.status.success(),
            "the probe's two cases pass: {}{said}",
            common::stdout(&output)
        );
        let total = said
            .lines()
            .find(|line| line.contains("policy evaluator:") && line.contains("bytecode"))
            .unwrap_or_else(|| panic!("`policy test -vv` prints the evaluator census: {said}"));
        assert!(
            total.contains(" 0 interpreted evaluation(s)"),
            "a case ran on the interpreter: {said}"
        );
        assert!(
            total.contains(" 2 bytecode evaluation(s)"),
            "both cases decided on bytecode: {said}"
        );
    }
}

/// Every case of every repository policy row and shipped preset decides alike
/// on the suite program and on the interpreter, and none is left off bytecode
/// (#1276).
///
/// Fails by: a desugared `with` that reads a rule under the wrong context, or
/// a case the desugaring cannot express, which would decide on the
/// interpreter.
#[test]
fn every_policy_case_decides_alike_on_bytecode_and_the_interpreter() {
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
    let mut bundles = policy::load(&repo, &resolved.rules, vocabulary, ModuleChecks::Run, None)
        .expect("this repository's policy loads");
    let root = common::scratch("policy-execution-preset-cases");
    for preset in batten::preset_catalog::MANIFESTS {
        for (scope, provider) in selections(preset) {
            let row: Rule = serde_json::from_value(serde_json::json!({
                "id": format!("preset {} {} {}", preset.name, scope.as_str(), provider.unwrap_or("none")),
                "kind": "policy",
                "scope": scope.as_str(),
                "preset": preset.name,
                "provider": provider,
                "severity": "deny",
            }))
            .expect("a preset row the loader accepts");
            if let Ok(loaded) = policy::load(
                &root,
                &[row],
                policy::Vocabulary::EMPTY,
                ModuleChecks::Run,
                None,
            ) {
                bundles.extend(loaded);
            }
        }
    }
    let (off, splits): (Vec<String>, Vec<String>) = bundles
        .iter()
        .flat_map(|bundle| policy::suite_splits(bundle, "{}"))
        .partition(|line| !line.contains(": bytecode "));
    assert!(
        splits.is_empty(),
        "these cases decide differently on bytecode and on the interpreter:\n{}",
        splits.join("\n")
    );
    // THE RESIDUE STILL ON THE INTERPRETER, AND IT ONLY SHRINKS (#1276). 216
    // measured when the suite program landed: a helper writing its own `with`
    // (109), a `with` in a nested query (37), a case defined twice (26), a
    // `with` term reading a variable bound under `with` (24), a function reading
    // the input under `with` (15), three bundles with no expressible case. Each
    // is a desugaring still to write, or a case to respell; lower the ceiling
    // with the count.
    assert!(
        off.len() <= 216,
        "a case left bytecode for the interpreter ({} > 216):\n{}",
        off.len(),
        off.join("\n")
    );
}
