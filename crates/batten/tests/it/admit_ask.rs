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
             [[pattern]]\n\
             id = \"ledger-pair\"\n\
             regex = '\\b[a-z][a-z0-9]*(?:-[a-z0-9]+)+ (?:[A-Za-z0-9_./-]+\\.(?:rs|rego|toml|md|pkl|yml|yaml|json|sh|bats)(?:::[A-Za-z0-9_:]+)?|[A-Za-z_][A-Za-z0-9_.]*\\[[^\\]]+\\](?:\\.[A-Za-z0-9_]+)*)'\n\n\
             [[pattern]]\n\
             id = \"recommendation-marked\"\n\
             regex = '(?i)(?:\\bnot\\s+)?\\brecommended\\b'\n\n\
             [[pattern]]\n\
             id = \"recommendation-tagged\"\n\
             regex = '(?i)[(\\[]\\s*recommended\\s*[)\\]]'\n\n\
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
    let options: Vec<(&str, &str)> = labels.iter().map(|label| (*label, "d")).collect();
    described(dir, question, &options)
}

/// [`ask`] with each option's description given: `(label, description)`.
fn described(dir: &std::path::Path, question: &str, options: &[(&str, &str)]) -> String {
    let options: Vec<serde_json::Value> = options
        .iter()
        .map(|(label, description)| serde_json::json!({"label": label, "description": description}))
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

/// Fails by: a question naming the path and the rule id apart, with no
/// `<smell-id> <key>` pair side by side, reaching the owner (the #1276 fourth
/// round: its answer bound nothing), or a config-key pair refused.
#[test]
fn an_admit_ask_naming_no_ledger_pair_is_refused() {
    let dir = fixture("admit-ask-pair");
    let apart = ask(
        &dir,
        "Admit the change to layer place wrong's use_sources key in batten.toml?",
        &["Admit the change", "Refuse"],
    );
    assert!(
        apart.contains("\"deny\"") && apart.contains(VERDICT),
        "a path and an id in prose bind nothing: {apart}"
    );
    let paired = ask(
        &dir,
        "Admit rule-predicate-changed rule[layer place wrong].use_sources?",
        &["Admit the change", "Refuse"],
    );
    assert!(
        !paired.contains(VERDICT),
        "the ledger's own pair is asked: {paired}"
    );
}

/// Fails by: a question whose only alternative to the recommended option is a
/// non-action reaching the owner (the owner's ruling of 2026-11-23: "why the
/// fuck are you stopping to ask questions where there's only one useful
/// answer"), or a question between two real choices refused.
#[test]
fn a_question_with_one_useful_answer_is_refused() {
    let dir = fixture("admit-ask-single");
    let settled = ask(
        &dir,
        "Rewrite the PR range unsigned?",
        &["Yes, rewrite unsigned (Recommended)", "No"],
    );
    assert!(
        settled.contains("\"deny\"") && settled.contains(VERDICT),
        "a recommendation against staying blocked is refused: {settled}"
    );
    let reapproval = ask(
        &dir,
        "Send the batch?",
        &["Approve dispatch (Recommended)", "Revise first"],
    );
    assert!(
        reapproval.contains("\"deny\"") && reapproval.contains(VERDICT),
        "an approval against revising is refused: {reapproval}"
    );
    // CLOUD-2915: the 2026-11-24 question, whose alternative is an action.
    let action = ask(
        &dir,
        "Keep fix 2 and close CLOUD-2904 with #1276?",
        &["Keep fix 2 (Recommended)", "Split fix 2 out"],
    );
    assert!(
        action.contains("\"deny\"") && action.contains(VERDICT),
        "a recommendation settles it whatever the alternative is: {action}"
    );
    let choice = ask(
        &dir,
        "Where should the shards run?",
        &["Dispatched sessions", "CI matrix legs"],
    );
    assert!(
        !choice.contains(VERDICT),
        "two real choices are asked: {choice}"
    );
}

/// Fails by: the ledger's own question refused because it carries a
/// recommendation (a human answers it by design), or either half of that
/// exception dropped so a settled question with only an `Admit…` label, or
/// only a pair, reaches the owner (CLOUD-2915). Neither refused question's
/// text says "admit", so only the settled arm can decide it.
#[test]
fn a_ledger_question_with_a_recommendation_is_asked() {
    let dir = fixture("admit-ask-ledger");
    let ledger = ask(
        &dir,
        &format!("Admit this finding? {FULL}"),
        &["Admit (Recommended)", "Refuse"],
    );
    assert!(
        !ledger.contains(VERDICT),
        "the ledger's own question is asked: {ledger}"
    );
    let label_only = ask(
        &dir,
        "Keep fix 2?",
        &["Admit it (Recommended)", "Split fix 2 out"],
    );
    assert!(
        label_only.contains("\"deny\"") && label_only.contains(VERDICT),
        "an `Admit` label without the pair is not the ledger's question: {label_only}"
    );
    let pair_only = ask(
        &dir,
        &format!("Keep {FULL}?"),
        &["Keep it (Recommended)", "Split it out"],
    );
    assert!(
        pair_only.contains("\"deny\"") && pair_only.contains(VERDICT),
        "a pair without an `Admit` label is not the ledger's question: {pair_only}"
    );
}

/// Fails by: a recommendation spelled other than the harness's `(Recommended)`
/// label suffix reaching the owner — a `Recommended:` prefix, a description, the
/// text naming the option, a bare tag in the text — or an option described as
/// NOT recommended refusing a real choice (CLOUD-2915 review, item 2).
#[test]
fn every_spelling_of_a_recommendation_is_refused() {
    let dir = fixture("admit-ask-spelling");
    let refused = |said: &str, why: &str| {
        assert!(
            said.contains("\"deny\"") && said.contains(VERDICT),
            "{why}: {said}"
        );
    };
    refused(
        &ask(
            &dir,
            "Keep fix 2?",
            &["Recommended: Keep fix 2", "Split fix 2 out"],
        ),
        "a `Recommended:` label prefix settles it",
    );
    refused(
        &described(
            &dir,
            "Keep fix 2?",
            &[
                ("Keep fix 2", "Recommended: the evidence settles it"),
                ("Split fix 2 out", "a second PR"),
            ],
        ),
        "a recommendation in the description settles it",
    );
    refused(
        &ask(
            &dir,
            "I recommend keep fix 2. Which?",
            &["Keep fix 2", "Split fix 2 out"],
        ),
        "the text naming the recommended option settles it",
    );
    refused(
        &ask(&dir, "Keep fix 2? (Recommended)", &["Yes", "Split it out"]),
        "a `(Recommended)` tag in the text settles it",
    );
    let against = described(
        &dir,
        "Which crate goes first?",
        &[
            ("batten-model", "not recommended while the bundle is open"),
            ("batten-base", "the smaller cut"),
        ],
    );
    assert!(
        !against.contains(VERDICT),
        "an option marked NOT recommended settles nothing: {against}"
    );
}

/// Fails by: the ledger exemption granted to a question that merely carries
/// its tokens — a pair mentioned outside an admission, or an `Admit…`
/// alternative beside a recommendation of something else — so a settled
/// question reaches the owner; or a genuine admission refused (CLOUD-2915
/// review, item 3).
#[test]
fn the_exemption_is_tied_to_the_admission() {
    let dir = fixture("admit-ask-exemption");
    let mentioned = ask(
        &dir,
        &format!("Keep fix 2? It touches {FULL}"),
        &["Admit it (Recommended)", "Split it out"],
    );
    assert!(
        mentioned.contains("\"deny\"") && mentioned.contains(VERDICT),
        "a pair mentioned in a question that does not ask to admit is not the ledger's: {mentioned}"
    );
    let other = ask(
        &dir,
        &format!("Admit this finding? {FULL}"),
        &["Keep it (Recommended)", "Admit"],
    );
    assert!(
        other.contains("\"deny\"") && other.contains(VERDICT),
        "an admission recommending a non-admission is settled: {other}"
    );
    let genuine = ask(
        &dir,
        &format!("Admit this finding? {FULL}"),
        &["Admit it [Recommended]", "Refuse"],
    );
    assert!(
        !genuine.contains(VERDICT),
        "a genuine admission is asked however it marks the recommendation: {genuine}"
    );
}
