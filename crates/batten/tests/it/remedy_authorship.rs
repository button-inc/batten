//! `policy/remedy-authorship.rego` decides, over the compiled engine rather than
//! over a fabricated input (CLOUD-1050 defects A and B).
//!
//! WHY THIS IS RUST AND NOT BATS, since the defect it gates lives in a shell
//! gate and a bats suite is the reflex. Two reasons, and the second is the one
//! that matters:
//!
//! 1. A bats suite here would be new shell shipped to gate a shell defect, in a
//!    tree whose campaign is retiring shell gates (CLOUD-843 measured "the bash
//!    grew today" as that campaign's own defect).
//! 2. The module's own `test_` rules are the LOAD-TIME half only. A `with input
//!    as` block fabricates its own input, so it can be green over a shape the
//!    engine never produces — CLOUD-845's defect, and the reason `policy_tree.rs`
//!    exists. This file is the half that cannot lie about the input, because the
//!    engine builds it.
//!
//! The module read here is the COMMITTED one, copied into each scratch tree
//! rather than restated inline. An inline copy would drift from the shipped
//! module and pass while the real gate was broken — the same
//! two-authorities-that-drift defect the module itself refuses.
//!
//! It is also the first live exercise of `Fact::Lines` through a policy row:
//! CLOUD-846 landed the fact and no module read it, so "the schema says
//! `input.tree.lines` exists" was until now an untested claim about the engine.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::fs;
use std::path::{Path, PathBuf};

use batten::rules::{self, Rule};

/// The row as `batten.toml` declares it, deserialized rather than
/// struct-literalled: `Rule` carries `deny_unknown_fields`, so this exercises
/// the same column census a consumer's config goes through and a row the loader
/// would refuse cannot be smuggled in by hand.
fn row(line_sources: &[&str], documents: &[&str]) -> Rule {
    serde_json::from_value(serde_json::json!({
        "id": "remedy-authorship",
        "kind": "policy",
        "scope": "tree",
        "line_sources": line_sources,
        "documents": documents,
        "module": "policy/remedy-authorship.rego",
        "severity": "deny",
    }))
    .expect("the row batten.toml declares")
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("batten-remedy-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(dir.join("policy")).expect("scratch");
    fs::create_dir_all(dir.join("mise-tasks")).expect("scratch tasks");
    install_module(&dir);
    dir
}

/// Copy the committed module in. `CARGO_MANIFEST_DIR` is `crates/batten`, so the
/// corpus is two levels up.
fn install_module(root: &Path) {
    let source = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../policy/remedy-authorship.rego")
        .canonicalize()
        .expect("the committed module is where the row says it is");
    fs::copy(source, root.join("policy").join("remedy-authorship.rego"))
        .expect("install the committed module");
}

fn gate(root: &Path, lines: &[&str]) {
    fs::write(root.join("mise-tasks").join("g.sh"), lines.join("\n")).expect("write gate");
}

fn manifest(root: &Path, body: &str) {
    fs::write(root.join("mise.toml"), body).expect("write manifest");
}

/// The vocabulary the installed module needs, read off the module itself
/// (CLOUD-1050).
///
/// Derived rather than listed for the reason registry equality gives: it runs in
/// both directions, so a hand-written table drifts from the committed module the
/// moment that module gains or loses a class — and this fixture copies the
/// COMMITTED module in precisely so it cannot drift.
fn scan(root: &Path, rule: Rule) -> rules::Scan {
    let verdicts = common::verdicts_in(root);
    rules::run_static(
        &[rule],
        &[],
        batten::policy::Vocabulary {
            patterns: &[],
            verdicts: &verdicts,
            recorders: &[],
        },
        root,
    )
    .expect("the read surface runs a policy row")
}

// ---------------------------------------------------------------------------
// A: the remedy reaches the reader.
// ---------------------------------------------------------------------------

/// The measured defect, as a fixture: a stderr block whose last line — the
/// remedy — carries no `::error::` prefix, so `land`'s filter drops it.
#[test]
fn an_unprefixed_remedy_line_in_a_stderr_block_is_a_finding() {
    let root = scratch("unprefixed");
    gate(
        &root,
        &[
            "{",
            "\techo \"::error:: the diff is comments only\"",
            "\techo \"Put the content on the row that owns it\"",
            "} >&2",
            "exit 2",
        ],
    );

    let scan = scan(&root, row(&["mise-tasks/*.sh"], &[]));
    assert_eq!(
        scan.findings.len(),
        1,
        "the predicate fired: {:?}",
        scan.findings
    );
    assert_eq!(
        scan.findings[0].rule, "remedy-reaches-the-reader",
        "THE PREDICATE's id, not the row's (CLOUD-832)"
    );
}

/// The same fixture with the prefix added is clean — and EVALUATED, without
/// which the case above passes on a module that denies unconditionally.
#[test]
fn the_same_block_fully_prefixed_is_clean_and_was_evaluated() {
    let root = scratch("prefixed");
    gate(
        &root,
        &[
            "{",
            "\techo \"::error:: the diff is comments only\"",
            "\techo \"::error:: Put the content on the row that owns it\"",
            "} >&2",
        ],
    );

    let scan = scan(&root, row(&["mise-tasks/*.sh"], &[]));
    assert!(
        scan.findings.is_empty(),
        "the predicate decides both ways: {:?}",
        scan.findings
    );
    assert!(
        !scan.not_evaluated.contains_key("remedy-authorship"),
        "and it looked — a skip here would make the case above pass for the \
         wrong reason"
    );
}

/// `printf '::error:: …'` is the spelling `board-payloads` uses, and an earlier
/// draft of the predicate read the SOURCE line rather than the emitted string,
/// so every correctly prefixed line fired. This is that regression's fixture.
#[test]
fn a_single_quoted_printf_prefix_counts() {
    let root = scratch("printf");
    gate(
        &root,
        &["{", "\tprintf '::error:: %s\\n' \"$detail\"", "} >&2"],
    );

    let scan = scan(&root, row(&["mise-tasks/*.sh"], &[]));
    assert!(
        scan.findings.is_empty(),
        "a printf with the prefix is prefixed: {:?}",
        scan.findings
    );
}

/// THE ANTI-WIDENING ARM. A brace group NOT redirected to stderr is ordinary
/// output — a summary, a count — and judging it would fire on nearly every task
/// in the tree. Without this case the predicate could be "every echo carries the
/// prefix" and still pass everything above.
#[test]
fn a_block_that_does_not_redirect_to_stderr_is_not_judged() {
    let root = scratch("stdout");
    gate(&root, &["{", "\techo \"recovered 2 of 2 payload(s)\"", "}"]);

    let scan = scan(&root, row(&["mise-tasks/*.sh"], &[]));
    assert!(
        scan.findings.is_empty(),
        "stdout is not the refusal channel: {:?}",
        scan.findings
    );
}

/// A variable-only line carries no prose this gate can judge — the text is
/// wherever the variable was assigned, which is not this line's fact. Judging it
/// would make the rule unsatisfiable for every gate that builds a message first.
#[test]
fn a_variable_only_line_is_not_judged() {
    let root = scratch("variable");
    gate(&root, &["{", "\techo \"$note\"", "} >&2"]);

    let scan = scan(&root, row(&["mise-tasks/*.sh"], &[]));
    assert!(
        scan.findings.is_empty(),
        "no literal, nothing to decide: {:?}",
        scan.findings
    );
}

// ---------------------------------------------------------------------------
// B: exactly one program authors the remedy.
// ---------------------------------------------------------------------------

/// The measured defect: `verify` restated `prose-only-check`'s remedy, naming
/// its override variable, and the copy drifted.
#[test]
fn a_caller_naming_a_bypass_it_does_not_implement_is_a_finding() {
    let root = scratch("second-author");
    manifest(
        &root,
        "[tasks.verify]\nrun = \"echo 'or set BATTEN_PROSE_ONLY_OVERRIDE=1 to record the exception'\"\n",
    );

    let scan = scan(&root, row(&[], &["mise.toml"]));
    assert_eq!(
        scan.findings.len(),
        1,
        "the predicate fired: {:?}",
        scan.findings
    );
    assert_eq!(scan.findings[0].rule, "remedy-has-one-author");
}

/// THE DISCRIMINATING CASE for B. The gate that OWNS a hatch must be able to
/// name it, or the rule bans the only honest mention of it there is — and a rule
/// nobody can keep green gets switched off.
#[test]
fn the_task_whose_program_reads_the_bypass_may_name_it() {
    let root = scratch("owner");
    manifest(
        &root,
        "[tasks.prose-only-check]\nrun = \"mise-tasks/prose-only-check.sh\"\n",
    );
    fs::write(
        root.join("mise-tasks").join("prose-only-check.sh"),
        "if [[ -n \"${BATTEN_PROSE_ONLY_OVERRIDE:-}\" ]]; then\n\techo overridden\nfi\n",
    )
    .expect("the implementing program");

    let scan = scan(&root, row(&["mise-tasks/*.sh"], &["mise.toml"]));
    assert!(
        scan.findings.is_empty(),
        "the implementer is the one authority: {:?}",
        scan.findings
    );
}

/// Configuration is not a bypass. `BATTEN_TRANSCRIPT_FILE` and the rest of the
/// injection surface are inputs, and naming one in a caller is not a second
/// remedy — so the suffix set is part of the predicate, not decoration.
#[test]
fn a_batten_variable_that_is_not_a_bypass_is_not_judged() {
    let root = scratch("config-var");
    manifest(
        &root,
        "[tasks.board-payloads]\nrun = \"BATTEN_TRANSCRIPT_FILE=x mise-tasks/board-payloads.sh\"\n",
    );

    let scan = scan(&root, row(&[], &["mise.toml"]));
    assert!(
        scan.findings.is_empty(),
        "configuration is not a hatch: {:?}",
        scan.findings
    );
}

// ---------------------------------------------------------------------------
// Could-not-look, and rule 4.
// ---------------------------------------------------------------------------

/// **Load-bearing.** A declared line source matching nothing is could-not-look,
/// never an empty deny set. This is CLOUD-251's vacuous pass where it would be
/// least visible: the module is handed an input whose key is absent, every
/// predicate over it is silently undefined, and the row reports clean having
/// established nothing.
#[test]
fn a_declared_line_source_matching_nothing_is_not_a_pass() {
    let root = scratch("nothing-matched");
    // No `mise-tasks/*.sh` is written, and no manifest.

    let scan = scan(&root, row(&["mise-tasks/*.sh"], &["mise.toml"]));
    assert!(
        scan.findings.is_empty(),
        "a rule that could not look reports no finding"
    );
    assert!(
        scan.not_evaluated.contains_key("remedy-authorship"),
        "but it must be recorded NOT EVALUATED — silence here IS the vacuous pass"
    );
}

/// Rule 4: a module may SEE a line; a finding may not CARRY one. The refused
/// line's own text must not reach the finding, because everything this gate
/// reads is somebody's message text.
#[test]
fn a_finding_carries_no_byte_of_the_line_it_refuses() {
    let root = scratch("pointer-only");
    gate(
        &root,
        &[
            "{",
            "\techo \"::error:: it broke\"",
            "\techo \"CUSTOMER-SPECIFIC-DETAIL-HERE\"",
            "} >&2",
        ],
    );

    let scan = scan(&root, row(&["mise-tasks/*.sh"], &[]));
    assert_eq!(scan.findings.len(), 1, "the predicate fired");
    let rendered = format!("{:?}", scan.findings[0]);
    assert!(
        !rendered.contains("CUSTOMER-SPECIFIC-DETAIL-HERE"),
        "pointer-only (rule 4): the finding names path and line, never content \
         — got {rendered}"
    );
}
