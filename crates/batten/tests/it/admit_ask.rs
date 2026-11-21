//! `call ask loose` over the compiled binary (#1276, CLOUD-2775): a question
//! that asks to admit a finding is judged on its own words before it is asked,
//! so an answer the ledger could never bind is never collected.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

const VERDICT: &str = "call ask loose";

fn fixture(name: &str) -> std::path::PathBuf {
    let module = std::fs::read_to_string(common::at_root("policy/admit-ask.rego")).unwrap();
    common::Fixture::new(name)
        .config(
            "version = 1\n\n\
             [[rule]]\n\
             id = \"call ask loose\"\n\
             no_fix_reason = \"a fixture row\"\n\
             kind = \"policy\"\n\
             scope = \"mediated_call\"\n\
             module = \"policy/admit-ask.rego\"\n\
             severity = \"deny\"\n\n\
             [[pattern]]\n\
             id = \"admit-asked\"\n\
             regex = '(?i)\\badmit(s|ted|ting)?\\b'\n\n\
             [[pattern]]\n\
             id = \"finding-path\"\n\
             regex = '[A-Za-z0-9_./-]+\\.(rs|rego|toml|md|pkl|yml|yaml|json|sh|bats)(::[A-Za-z0-9_:]+)?'\n\n\
             [[verdict]]\n\
             id = \"call ask loose\"\n\
             gloss = \"a question asks to admit a finding in words the ledger cannot bind\"\n\
             class = \"\"\"\nan admission the ledger cannot bind\n\"\"\"\n\n\
             [[verdict.route]]\n\
             id = \"module read first\"\n\
             kind = \"document\"\n\
             target = \"policy/admit-ask.rego\"\n",
        )
        .file("policy/admit-ask.rego", &module)
        .base_commit()
        .build()
}

fn ask(dir: &std::path::Path, question: &str, labels: &[&str]) -> String {
    let options: Vec<serde_json::Value> = labels
        .iter()
        .map(|label| serde_json::json!({"label": label, "description": "d"}))
        .collect();
    let payload = serde_json::json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "AskUserQuestion",
        "tool_input": {"questions": [{
            "question": question,
            "header": "Admit",
            "multiSelect": false,
            "options": options,
        }]},
    });
    let said = common::stdout(&common::run_with_stdin(
        dir,
        &["adjudicate", "--harness", "claude-code"],
        &payload.to_string(),
    ));
    // A deny from a config that did not load names the verdict in its reason
    // too; only the module's own refusal counts.
    assert!(!said.contains("engine-cannot-adjudicate"), "{said}");
    said
}

/// The #1276 pair, spelled in full.
const FULL: &str = "test-expectation-changed crates/batten/tests/it/released.rs::the_committed_task_records_then_checks_the_one_row";

/// Fails by: an admission question whose option is not labelled `Admit…`, or
/// whose path is shortened, reaching the owner (the label or path check
/// dropped), or a well-formed one refused.
#[test]
fn an_admit_ask_without_the_exact_pair_is_refused() {
    let dir = fixture("admit-ask");
    let loose_label = ask(
        &dir,
        &format!("Admit this finding? {FULL}"),
        &["Yes, admit", "No"],
    );
    assert!(
        loose_label.contains("\"deny\"") && loose_label.contains(VERDICT),
        "an option the ledger does not read as admitting is refused: {loose_label}"
    );
    let shortened = ask(
        &dir,
        "Admit this finding? test-expectation-changed released.rs::the_committed_task_records_then_checks_the_one_row",
        &["Admit", "Refuse"],
    );
    assert!(
        shortened.contains("\"deny\"") && shortened.contains(VERDICT),
        "a shortened path never matches the finding's pair: {shortened}"
    );
    let exact = ask(
        &dir,
        &format!("Admit this finding? {FULL}"),
        &["Admit", "Refuse"],
    );
    assert!(
        !exact.contains(VERDICT),
        "the exact pair with an `Admit` option is asked: {exact}"
    );
}
