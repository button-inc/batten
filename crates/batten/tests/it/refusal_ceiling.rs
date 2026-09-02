//! The emitted mediated line, measured against the declared ceiling
//! (CLOUD-1286).
//!
//! **Over the compiled binary, against the committed `batten.toml`.** A
//! `with input as` case or a fixture registry would fabricate the very thing
//! under test: the question is what an agent in THIS repository actually sees
//! when a real row refuses a real command, and a fixture answers about a tree
//! nobody works in.
//!
//! The discriminating pair is the whole file. The deny half is that a line over
//! the ceiling is reported; the allow half — anti-vacuity, and the load-bearing
//! one (CLOUD-418) — is that every refusal this repository can actually emit
//! passes. A ceiling that refuses correct output is a gate somebody switches
//! off, and the converted `no-tool-substitution` refusal is the specific line
//! the row names.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::PathBuf;

use common::{run_with_stdin_at_real_root, stderr};

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn payload(command: &str) -> String {
    let encoded = serde_json::to_string(command).expect("a command is encodable");
    format!(
        "{{\"hook_event_name\":\"PreToolUse\",\"tool_name\":\"Bash\",\
         \"tool_input\":{{\"command\":{encoded}}}}}"
    )
}

/// The refusal text a mediated call produces, or `None` where it was allowed.
fn refusal(command: &str) -> Option<String> {
    let run = run_with_stdin_at_real_root(
        &root(),
        &["hook", "--harness", "exit-code"],
        &payload(command),
    );
    if run.status.code() == Some(2) {
        Some(stderr(&run).trim().to_owned())
    } else {
        None
    }
}

/// The declared ceiling, read from the committed config rather than re-typed.
///
/// Re-typing it here would make this suite pass over a `batten.toml` whose
/// ceiling had been raised or deleted, which is the whole failure the
/// `refusal-ceiling-raised` weakening exists to report.
fn declared_ceiling() -> usize {
    let text = std::fs::read_to_string(root().join("batten.toml"))
        .expect("the committed config is readable");
    let config: toml::Value = toml::from_str(&text).expect("the committed config parses");
    usize::try_from(
        config
            .get("refusal")
            .and_then(|table| table.get("max_tokens"))
            .and_then(toml::Value::as_integer)
            .expect("`[refusal] max_tokens` is declared"),
    )
    .expect("a ceiling is not negative")
}

/// `budget.rs`'s estimator, which is what the engine's own `Ceiling::over` uses.
fn estimated_tokens(line: &str) -> usize {
    line.len() / 4
}

/// The mediated commands this repository's rows actually refuse, one per
/// composer that can fire from a Bash call.
///
/// Not every declared class — the ones reachable from a mediated command line,
/// because those are what the ~300 firings a session are made of.
const CORPUS: &[&str] = &[
    // The row CLOUD-1286's acceptance names by name.
    "sed -n '1,40p' AGENTS.md",
    "head -40 batten.toml",
    "cat .serena/project.yml",
    // The three discard shapes.
    "mise run verify | tail -1",
    "mise run verify >log 2>&1; ls",
    "nohup mise run verify &",
];

#[test]
fn every_mediated_refusal_this_tree_emits_is_within_the_declared_ceiling() {
    // ANTI-VACUITY, and it is the case that decides whether the ceiling is a
    // gate or a switch waiting to be flipped. If this fails, the answer is
    // almost never to raise the number.
    let ceiling = declared_ceiling();
    let mut over: Vec<(usize, String)> = Vec::new();
    for command in CORPUS {
        let Some(line) = refusal(command) else {
            panic!("the corpus must refuse, or it measures nothing: {command}");
        };
        let cost = estimated_tokens(&line);
        if cost > ceiling {
            over.push((cost, line));
        }
    }
    assert!(
        over.is_empty(),
        "every emitted line must be within the declared ceiling of {ceiling}: {over:?}"
    );
}

#[test]
fn a_declared_refusal_emits_its_class_and_its_pointers_and_stops() {
    // The acceptance, asserted on the shape rather than on the count: no
    // `Refused by` prefix, no parenthetical gloss, no `Fix:` clause, and no
    // hatch sentence. Each of the four was a copy of something declared once.
    let line = refusal("sed -n '1,40p' AGENTS.md").expect("the row refuses");
    assert!(
        line.starts_with("tool run loose"),
        "the class leads the line: {line}"
    );
    for wrapper in ["Refused by", "Fix:", "Bypass with", " ("] {
        assert!(
            !line.contains(wrapper),
            "the emitted line must not carry `{wrapper}`: {line}"
        );
    }
}

#[test]
fn no_refusal_lost_its_pointer() {
    // The acceptance clause that keeps this from being achieved by saying less
    // about WHICH file. The prose is what shortened; the pointer is what the
    // reader acts on, and it stayed inline for exactly that reason.
    let line = refusal("head -40 batten.toml").expect("the row refuses");
    assert!(
        line.contains("batten.toml"),
        "the operand a caller can act on stays inline: {line}"
    );
}

#[test]
fn the_ceiling_can_fail() {
    // CLOUD-418: a gate nobody has seen fail is a gate nobody knows works. The
    // engine's own comparison is exercised here rather than the corpus above,
    // because the tree passing is the point of the corpus and a tree that could
    // fail it would be a defect rather than a fixture.
    let ceiling = declared_ceiling();
    let long = "path write refused ".to_owned() + &"a/very/deep/".repeat(20) + "file.rs";
    assert!(
        estimated_tokens(&long) > ceiling,
        "a line this long must be over the ceiling, or the comparison decides nothing"
    );
    let short = refusal("nohup mise run verify &").expect("the row refuses");
    assert!(
        estimated_tokens(&short) <= ceiling,
        "and a real one must be under it: {short}"
    );
}
