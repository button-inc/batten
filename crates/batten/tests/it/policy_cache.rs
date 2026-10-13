//! The hot path's bytecode cache (CLOUD-2236): a warm load compiles nothing, a
//! changed module is never answered from stale bytecode, and bytecode answers
//! exactly as the interpreter does — over a fixture and over this repository's
//! own mediated bundles.
//!
//! Counters, never clocks, for `policy_engine_count`'s reason: a warm load is
//! the absence of `Engine::new()`, and nextest's process-per-case keeps the
//! process-global count this case's alone.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use batten::facts::Look;
use batten::policy;
use batten::rules::Rule;

/// A mediated row registering `module`.
fn row(module: &str) -> Rule {
    serde_json::from_value(serde_json::json!({
        "id": "policy-cached",
        "kind": "policy",
        "scope": "mediated_call",
        "module": module,
        "severity": "deny",
    }))
    .expect("a policy row the loader accepts")
}

/// Every rule a caller reads: both refusal shapes, a pre-approval and a rewrite.
const ANSWERS_EVERY_RULE: &str = r#"
package batten.cached

import rego.v1

rules contains "write refused probe"

rules contains "read approved probe"

deny contains "bare refused probe" if input.call.operation == "delete"

violation contains {"rule": "write refused probe", "verdict": "write refused probe", "subjects": [{"path": input.call.path}]} if {
    input.call.operation == "write"
}

preapprove contains "read approved probe" if input.call.operation == "read"

rewrite contains {"rule": "read approved probe", "key": "timeout", "value": 600000} if {
    input.call.operation == "read"
}

test_never_compiled_on_the_hot_path if true
"#;

/// The same row, now refusing reads too: what an edit between two calls makes.
const EDITED: &str = r#"
package batten.cached

import rego.v1

rules contains "write refused probe"

violation contains {"rule": "write refused probe", "verdict": "write refused probe"} if {
    input.call.operation in {"write", "read"}
}
"#;

/// A scratch root holding `source` as its one module, with state contained.
fn root_with(name: &str, source: &str) -> std::path::PathBuf {
    common::scratch_state_root();
    let root = common::scratch(&format!("policy-cache-{name}"));
    std::fs::write(root.join("cached.rego"), source).expect("write module");
    root
}

/// One load of the fixture row at `checks`.
fn load(root: &std::path::Path, checks: policy::ModuleChecks) -> policy::Bundle {
    // The module's own tokens, declared, so the checked load accepts them.
    let verdicts: &'static [batten::verdict::DeclaredVerdict] =
        Box::leak(common::verdicts_in(root).into_boxed_slice());
    let vocabulary = policy::Vocabulary {
        verdicts,
        ..policy::Vocabulary::EMPTY
    };
    policy::load(root, &[row("cached.rego")], vocabulary, checks, None)
        .expect("the fixture loads")
        .remove(0)
}

/// Everything a hook call reads off a bundle for `input`, in one comparable value.
fn decided(
    bundle: &policy::Bundle,
    input: &str,
) -> (
    Look<Vec<policy::Violation>>,
    Look<Vec<String>>,
    Look<Vec<policy::Rewrite>>,
) {
    (
        policy::deny(bundle, input),
        policy::preapprove(bundle, input),
        policy::rewrite(bundle, input),
    )
}

const CALLS: [&str; 5] = [
    "{}",
    r#"{"call":{"operation":"write","path":"src/lib.rs"}}"#,
    r#"{"call":{"operation":"read"}}"#,
    r#"{"call":{"operation":"delete"}}"#,
    r#"{"call":{"operation":"exec","command":"git status"}}"#,
];

#[test]
fn a_warm_load_compiles_no_engine() {
    let root = root_with("warm", ANSWERS_EVERY_RULE);
    let cold = load(&root, policy::ModuleChecks::SkipOnHotPath);
    let before = policy::engines_constructed();
    let warm = load(&root, policy::ModuleChecks::SkipOnHotPath);
    assert_eq!(
        policy::engines_constructed() - before,
        0,
        "the second hot-path load of unchanged sources must read the cached \
         bytecode, not parse and compile the module again"
    );
    assert_eq!(warm.declared(), cold.declared());
    for input in CALLS {
        assert_eq!(decided(&warm, input), decided(&cold, input), "{input}");
    }
}

#[test]
fn an_edited_module_is_not_answered_from_stale_bytecode() {
    let root = root_with("edited", ANSWERS_EVERY_RULE);
    let first = load(&root, policy::ModuleChecks::SkipOnHotPath);
    let read = r#"{"call":{"operation":"read"}}"#;
    let Look::Is(before) = policy::deny(&first, read) else {
        panic!("the fixture answers");
    };
    assert!(before.is_empty(), "the first module refuses no read");

    std::fs::write(root.join("cached.rego"), EDITED).expect("edit module");
    let second = load(&root, policy::ModuleChecks::SkipOnHotPath);
    let Look::Is(after) = policy::deny(&second, read) else {
        panic!("the edited fixture answers");
    };
    assert_eq!(
        after.len(),
        1,
        "the edited module refuses a read; answering from the first module's \
         bytecode would let it through"
    );
}

#[test]
fn bytecode_answers_as_the_interpreter_does() {
    let root = root_with("agree", ANSWERS_EVERY_RULE);
    let interpreted = load(&root, policy::ModuleChecks::Run);
    let compiled = load(&root, policy::ModuleChecks::SkipOnHotPath);
    let mut refused = 0;
    for input in CALLS {
        let (denied, approved, rewritten) = decided(&compiled, input);
        assert_eq!(
            (denied.clone(), approved, rewritten),
            decided(&interpreted, input),
            "{input}"
        );
        if let Look::Is(found) = denied {
            refused += found.len();
        }
    }
    assert_eq!(refused, 2, "the corpus reaches both refusal shapes");
}

/// The same agreement over every bundle this repository enables on the
/// mediated surface, so a construct the bytecode compiler reads differently is
/// found here rather than as a wrong verdict on a tool call.
#[test]
fn the_repositorys_bundles_answer_alike_compiled_and_interpreted() {
    common::scratch_state_root();
    let repo = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let resolved = batten::resolve::resolve(&repo, &batten::resolve::Overrides::default())
        .expect("this repository's config resolves");
    let rows: Vec<Rule> = resolved
        .rules
        .iter()
        .filter(|rule| rule.scope == batten::rules::RuleScope::MediatedCall)
        .cloned()
        .collect();
    let vocabulary = policy::Vocabulary {
        patterns: &resolved.patterns,
        verdicts: &resolved.verdicts,
        words: None,
        recorders: &resolved.recorders,
        registers: &resolved.registers,
        traversals: &resolved.traversals,
        records: &resolved.records,
    };
    let load = |checks| policy::load(&repo, &rows, vocabulary, checks, None).expect("loads");
    let interpreted = load(policy::ModuleChecks::RunOverSelection);
    let compiled = load(policy::ModuleChecks::SkipOnHotPath);
    assert_eq!(interpreted.len(), compiled.len());
    assert!(
        !compiled.is_empty(),
        "this repository enables mediated policy"
    );
    let calls = [
        "{}".to_owned(),
        serde_json::json!({"call": {
            "tool": "Bash", "event": "PreToolUse", "operation": "exec",
            "command": "git push --force origin main",
            "programs": ["git"], "segments": [["git", "push", "--force", "origin", "main"]],
        }})
        .to_string(),
        serde_json::json!({"call": {
            "tool": "Edit", "event": "PreToolUse", "operation": "write",
            "writes": ["batten.toml"], "arguments": {"file_path": "batten.toml"},
        }})
        .to_string(),
        serde_json::json!({"call": {
            "tool": "Agent", "event": "PreToolUse", "operation": "spawn",
            "arguments": {"prompt": "x", "subagent_type": "Explore"},
        }})
        .to_string(),
    ];
    for (left, right) in interpreted.iter().zip(&compiled) {
        assert_eq!(left.id(), right.id());
        for input in &calls {
            assert_eq!(
                decided(right, input),
                decided(left, input),
                "{} over {input}",
                left.id()
            );
        }
    }
}
