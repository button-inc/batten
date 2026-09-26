//! `prose own other` over the compiled binary and the REAL producer
//! (CLOUD-323, CLOUD-338, CLOUD-1717).
//!
//! The producer's body is read out of `mise.toml` and run against a fixture, the
//! engine then decides over what it recorded — so the paragraph split, the code
//! span neutralisation and the claimed-key subtraction are all under test, not a
//! copy of them. The fixture carries the committed `[[pattern]]` table, because
//! the claimed set is the engine grammar's answer and the grammar is built from
//! those rows.
//!
//! # RETIREMENT LEDGER, PER PATH — what `shell retire partial` reads
//!
// carried: mise-tasks/deferral-check.sh policy/deferral.rego kind:mechanism crates/batten/tests/it/deferral.rs
// carried: tests/deferral-check.bats policy/deferral.rego kind:mechanism crates/batten/tests/it/deferral.rs
// carried: "a deferral with no owner in its paragraph fails" policy/deferral.rego kind:mechanism
// carried: "a deferral that names its owning issue passes" policy/deferral.rego kind:mechanism
// carried: "the scope is the paragraph, not the body" policy/deferral.rego kind:mechanism
// carried: "a paragraph is read whole, so a key on another line of it still exempts" policy/deferral.rego kind:mechanism
// carried: "naming the phrase in a code span is not using it" policy/deferral.rego kind:mechanism
// carried: "a body with no deferral shape passes" policy/deferral.rego kind:mechanism
// carried: "an empty body passes rather than erroring" policy/deferral.rego kind:mechanism
// carried: "the American spelling is caught too" policy/deferral.rego kind:mechanism
// carried: "a deferral exempted only by the PR's own claimed issue fails" policy/deferral.rego kind:mechanism
// carried: "a deferral naming an issue the PR does not claim passes" policy/deferral.rego kind:mechanism
// carried: "naming both the claimed issue and a real owner passes" policy/deferral.rego kind:mechanism
// carried: "a closing keyword in the body claims that issue too" policy/deferral.rego kind:mechanism
// changed: "outside a git checkout the narrowing fails open" mise.toml the fail-open survives inside the producer — an unresolvable claim is recorded as `claimed -`, which subtracts nothing — but a producer outside a checkout has no repository to record INTO, so the old case's shape (a verdict with no checkout at all) no longer exists. `a_deferral_with_no_claim_is_owned_by_any_key_it_names` pins the half that remains
// carried: "an unverified claim with no owner fails — the second measured shape" policy/deferral.rego kind:mechanism
// carried: "an unverified claim that names its owner passes" policy/deferral.rego kind:mechanism
// carried: "a dropped candidate shape does not fire" policy/deferral.rego kind:mechanism
// changed: "the report is a pointer, never the paragraph" policy/deferral.rego the pointer is narrower now: the paragraph NUMBER, where the program printed the paragraph's first 60 characters. Those characters were prose on the decision surface, which rule 4 keeps off it; the case asserts the prose is absent
// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::{Path, PathBuf};
use std::process::Output;

use common::{at_root, git_in, init_repo, run, scratch, write};

/// The committed `[[pattern]]` rows, re-serialized, so the fixture's grammar is
/// the repository's own rather than a hand-copied subset.
fn committed_patterns() -> String {
    let config: toml::Value =
        toml::from_str(&std::fs::read_to_string(at_root("batten.toml")).expect("the config"))
            .expect("batten.toml parses");
    let mut table = toml::map::Map::new();
    table.insert(
        "pattern".to_owned(),
        config.get("pattern").expect("[[pattern]] rows").clone(),
    );
    toml::to_string(&toml::Value::Table(table)).expect("re-serializes")
}

/// A repository registering the real module on a keyless branch `branch`.
fn repo(name: &str, branch: &str) -> PathBuf {
    let dir = scratch(&format!("deferral-{name}"));
    let module = std::fs::read_to_string(at_root("policy/deferral.rego")).expect("the module");
    write(&dir, "policy/deferral.rego", &module);
    write(
        &dir,
        "batten.toml",
        &format!(
            r#"version = 1
scope = ["**"]

[[verdict]]
id = "prose own unnamed"
gloss = "a deferral names no owner"
class = "A PR body is not a durable home."

[[verdict.route]]
id = "task run first"
kind = "command"
target = "mise run deferral-record"

[[verdict]]
id = "prose read partial"
gloss = "the deferral record is torn"
class = "A torn record judges part of a body."

[[verdict.route]]
id = "task run first"
kind = "command"
target = "mise run deferral-record"

[[rule]]
id = "prose own other"
kind = "policy"
scope = "tree"
module = "policy/deferral.rego"
severity = "deny"

[[record]]
record = "deferral"
writer = "mise run deferral-record"

{}"#,
            committed_patterns()
        ),
    );
    init_repo(&dir);
    git_in(&dir, &["checkout", "-q", "-b", branch]);
    git_in(&dir, &["add", "-A"]);
    git_in(&dir, &["commit", "-qm", "chore: init"]);
    dir
}

/// Run `deferral-record` over `body`, in `dir`.
fn produce(dir: &Path, body: &str) -> Output {
    common::produce(dir, "deferral-record", body)
}

fn said(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

/// Produce over `body` on a keyless branch, then decide; the exit code.
fn verdict(name: &str, body: &str) -> (Option<i32>, String) {
    let dir = repo(name, "work");
    verdict_in(&dir, body)
}

fn verdict_in(dir: &Path, body: &str) -> (Option<i32>, String) {
    let produced = produce(dir, body);
    assert!(
        produced.status.success(),
        "the producer records: {}",
        said(&produced)
    );
    let decided = run(dir, &["check", "--rule", "prose own other"]);
    (decided.status.code(), said(&decided))
}

#[test]
fn a_deferral_with_no_owner_in_its_paragraph_is_refused() {
    let (code, text) = verdict("ownerless", "Intro.\n\nThis was a judgement call.\n");
    assert_eq!(code, Some(2), "{text}");
    assert!(
        text.contains("paragraph:2"),
        "the pointer is the paragraph: {text}"
    );
}

#[test]
fn a_deferral_naming_its_owner_passes_and_scope_is_the_paragraph() {
    let (owned, text) = verdict("owned", "This was a judgement call, owned by CLOUD-9.\n");
    assert_eq!(owned, Some(0), "{text}");
    let (elsewhere, text) = verdict(
        "elsewhere",
        "CLOUD-9 is named up here.\n\nThis was a judgement call.\n",
    );
    assert_eq!(
        elsewhere,
        Some(2),
        "a key in another paragraph does not own it: {text}"
    );
    let (whole, text) = verdict(
        "whole",
        "This was a judgement call\nthat CLOUD-9 now owns, on the next line.\n",
    );
    assert_eq!(whole, Some(0), "a paragraph is read whole: {text}");
}

#[test]
fn a_code_span_names_the_phrase_without_using_it_and_other_shapes_pass() {
    for (name, body) in [
        ("span", "The table row `judgement call` is a literal.\n"),
        ("none", "Nothing deferred here.\n"),
        ("empty", ""),
        ("dropped", "This was deliberately chosen.\n"),
    ] {
        let (code, text) = verdict(name, body);
        assert_eq!(code, Some(0), "{name}: {text}");
    }
}

#[test]
fn both_spellings_and_both_measured_shapes_fire() {
    for (name, body) in [
        ("american", "This was a judgment call.\n"),
        ("unverified", "The macOS half is not verified here.\n"),
    ] {
        let (code, text) = verdict(name, body);
        assert_eq!(code, Some(2), "{name}: {text}");
    }
    let (owned, text) = verdict(
        "unverified-owned",
        "Not verified here; CLOUD-282 owns it.\n",
    );
    assert_eq!(owned, Some(0), "{text}");
}

#[test]
fn a_deferral_owned_only_by_the_claimed_issue_is_refused() {
    // CLOUD-338, measured on #275: the natural key to write is the one the PR
    // already claims, which made the exemption self-satisfying. A closing
    // keyword in the body is a claim.
    let (claimed_only, text) = verdict(
        "claimed-only",
        "Closes CLOUD-286\n\nNot verified here, see CLOUD-286.\n",
    );
    assert_eq!(claimed_only, Some(2), "{text}");
    let (real_owner, text) = verdict(
        "real-owner",
        "Closes CLOUD-286\n\nNot verified here; CLOUD-286 hands it to CLOUD-282.\n",
    );
    assert_eq!(real_owner, Some(0), "{text}");
    let (unclaimed, text) = verdict("unclaimed", "Not verified here; CLOUD-282 owns it.\n");
    assert_eq!(unclaimed, Some(0), "{text}");
}

#[test]
fn a_deferral_with_no_claim_is_owned_by_any_key_it_names() {
    // The fail-open half that survives: nothing claimed subtracts nothing.
    let (code, text) = verdict("no-claim", "This was a judgement call for CLOUD-5.\n");
    assert_eq!(code, Some(0), "{text}");
}

#[test]
fn the_report_is_a_pointer_never_the_paragraph() {
    let (code, text) = verdict(
        "pointer",
        "A secret customer detail was a judgement call.\n",
    );
    assert_eq!(code, Some(2), "{text}");
    assert!(!text.contains("customer detail"), "{text}");
}

#[test]
fn a_record_without_its_census_is_torn_rather_than_clean() {
    let dir = repo("torn", "work");
    let written = common::run_with_stdin(
        &dir,
        &["record", "named", "deferral"],
        "claimed\t-\ndeferral\t1\tCLOUD-9\n",
    );
    assert!(written.status.success(), "{}", said(&written));
    let decided = run(&dir, &["check", "--rule", "prose own other"]);
    assert_eq!(decided.status.code(), Some(2), "{}", said(&decided));
}
