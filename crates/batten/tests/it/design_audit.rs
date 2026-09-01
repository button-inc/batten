//! End-to-end tests for `design audit` (CLOUD-53), over the compiled binary.
//!
//! One test per Acceptance bullet, driven through the real process so the exit
//! codes and the output shape a consumer depends on are what is asserted — not a
//! library return value that a dispatch arm could fail to hand back.
//!
//! Two properties are checked in almost every case rather than once:
//!
//! * **The exit is from the one table.** `2` is the policy verdict, `1` is a
//!   malformed corpus or invocation, and an advisory alone leaves `0` — which is
//!   the whole claim about where the strictness ladder sits.
//! * **No claim content travels.** Every fixture carries a [`SENTINEL`] inside a
//!   field the gate reads, and the assertions scan the output for it. A pointer
//!   is an id and a location; anything else is payload (rule 4).
//!
//! The corpus is stdin and nothing else (CLOUD-324), so the fixtures are
//! strings and no fixture needs a git repository — only a `batten.toml`, since
//! the verb resolves the §8 chain for its one ceiling.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::{Path, PathBuf};
use std::process::Output;

use common::{Fixture, run_with_stdin, stderr, stdout};

/// A string planted in claim fields the gate reads. If it ever reaches stdout or
/// stderr, the report stopped being a pointer.
const SENTINEL: &str = "SENTINEL-claim-prose-never-emitted";

/// The `sha256` of [`BODY`], so a fixture can be sound without the test
/// recomputing what the binary computes.
///
/// A literal rather than a call into the library: an E2E test that derived the
/// expected digest from the same code under test would agree with a broken
/// implementation.
const BODY: &str = "captured evidence";
const BODY_SHA256: &str = "27b27c4f51313b0af0dceee1ad660d872e01ccd24db7b437d17eec660a9a65cb";

/// A fixture repository. Only a config is needed: the corpus arrives on stdin.
fn repo(name: &str, config: &str) -> PathBuf {
    Fixture::new(name).config(config).build()
}

fn audit(dir: &Path, input: &str) -> Output {
    run_with_stdin(dir, &["design", "audit"], input)
}

fn code(output: &Output) -> i32 {
    output.status.code().expect("the process exited normally")
}

/// Assert that neither channel carries the sentinel.
fn carries_no_prose(output: &Output) {
    for channel in [stdout(output), stderr(output)] {
        assert!(
            !channel.contains(SENTINEL),
            "claim content reached an output channel: {channel}"
        );
    }
}

/// One claim record, spelled as the JSON the schema deserializes.
///
/// Written as text rather than built from the library's own types, deliberately:
/// the wire format is what a consumer writes, so a serde rename or a field made
/// required has to fail here.
struct Row {
    id: &'static str,
    status: &'static str,
    polarity: &'static str,
    claimant: Option<&'static str>,
    verifier: Option<&'static str>,
    capture: Option<String>,
}

impl Row {
    /// A row that trips nothing: verified, existence-shaped, two identities, a
    /// sound capture.
    fn clean(id: &'static str) -> Self {
        Row {
            id,
            status: "verified",
            polarity: "existence",
            claimant: Some("author"),
            verifier: Some("checker"),
            capture: Some(capture(BODY_SHA256, BODY.len(), Some(BODY))),
        }
    }

    fn line(&self) -> String {
        let mut fields = vec![
            format!("\"id\":\"{}\"", self.id),
            format!("\"status\":\"{}\"", self.status),
            format!("\"polarity\":\"{}\"", self.polarity),
            // The source is a pointer field, and it is where the sentinel sits:
            // the gate reads this record and must still emit none of it.
            format!("\"source\":\"https://example.invalid/{SENTINEL}\""),
        ];
        if let Some(claimant) = self.claimant {
            fields.push(format!("\"claimant\":\"{claimant}\""));
        }
        if let Some(verifier) = self.verifier {
            fields.push(format!("\"verifier\":\"{verifier}\""));
        }
        if let Some(capture) = &self.capture {
            fields.push(format!("\"capture\":{capture}"));
        }
        format!("{{{}}}", fields.join(","))
    }
}

fn capture(sha256: &str, byte_count: usize, bytes: Option<&str>) -> String {
    let body = match bytes {
        Some(bytes) => format!(",\"bytes\":\"{bytes}\""),
        None => String::new(),
    };
    format!("{{\"digest\":{{\"sha256\":\"{sha256}\"}},\"byte_count\":{byte_count}{body}}}")
}

fn corpus(rows: &[Row]) -> String {
    let mut text = String::new();
    for row in rows {
        text.push_str(&row.line());
        text.push('\n');
    }
    text
}

// --- the clean case -----------------------------------------------------

#[test]
fn a_clean_corpus_exits_zero_and_prints_nothing() {
    // §6, and the acceptance's own wording. A verb that announced its own
    // success on every run would cost an agent tokens for no information.
    let dir = repo("design-clean", "version = 1\n");
    let output = audit(&dir, &corpus(&[Row::clean("a"), Row::clean("b")]));

    assert_eq!(code(&output), 0);
    assert_eq!(stdout(&output), "", "a clean corpus prints nothing at all");
    carries_no_prose(&output);
}

#[test]
fn the_json_channel_answers_even_when_clean() {
    // The opposite discipline on the other channel: JSON that is sometimes
    // absent is unparseable, so the document is emitted for a clean corpus too.
    let dir = repo("design-clean-json", "version = 1\n");
    let output = run_with_stdin(
        &dir,
        &["design", "audit", "-J"],
        &corpus(&[Row::clean("a")]),
    );

    assert_eq!(code(&output), 0);
    let document: serde_json::Value = serde_json::from_str(&stdout(&output)).expect("valid JSON");
    assert_eq!(document["problems"].as_array().unwrap().len(), 0);
    carries_no_prose(&output);
}

#[test]
fn an_empty_corpus_is_clean() {
    // Nothing to audit is not a defect: `design audit` gates a stream a caller
    // produced, and an empty one is the state before the first claim.
    let dir = repo("design-empty", "version = 1\n");
    let output = audit(&dir, "");
    assert_eq!(code(&output), 0);
    assert_eq!(stdout(&output), "");
}

// --- the violations -----------------------------------------------------

#[test]
fn a_duplicate_claim_id_names_the_id_and_both_locations() {
    let dir = repo("design-duplicate", "version = 1\n");
    let output = audit(
        &dir,
        &corpus(&[Row::clean("dup"), Row::clean("other"), Row::clean("dup")]),
    );

    assert_eq!(code(&output), 2);
    let text = stdout(&output);
    assert!(text.contains("design-duplicate-claim-id"), "{text}");
    assert!(text.contains("claim=dup"), "the id is named: {text}");
    assert!(text.contains("-:3"), "the offending row: {text}");
    assert!(text.contains("-:1"), "and the first one: {text}");
    carries_no_prose(&output);
}

#[test]
fn a_verified_absence_claim_is_a_violation() {
    // The defect class the gate exists for: an absence is refuted by one
    // counterexample and attested by no capture, so `verified` over it is a
    // defect of the record whatever the claim's merits.
    let dir = repo("design-verified-absence", "version = 1\n");
    let mut row = Row::clean("a");
    row.polarity = "absence";
    let output = audit(&dir, &corpus(&[row]));

    assert_eq!(code(&output), 2);
    assert!(stdout(&output).contains("design-verified-absence"));
    carries_no_prose(&output);
}

#[test]
fn bytes_that_do_not_match_the_recorded_digest_are_a_violation() {
    let dir = repo("design-digest", "version = 1\n");
    let mut row = Row::clean("a");
    // A well-formed digest of something else — the capture that was swapped, or
    // the one that never succeeded (CLOUD-76's shape).
    row.capture = Some(capture(
        "0000000000000000000000000000000000000000000000000000000000000000",
        BODY.len(),
        Some(BODY),
    ));
    let output = audit(&dir, &corpus(&[row]));

    assert_eq!(code(&output), 2);
    let text = stdout(&output);
    assert!(text.contains("design-digest-mismatch"), "{text}");
    assert!(
        !text.contains(BODY),
        "the capture's bytes are payload and never travel: {text}"
    );
    carries_no_prose(&output);
}

#[test]
fn a_checked_claim_with_nobody_named_is_a_violation() {
    let dir = repo("design-verifier", "version = 1\n");
    let mut row = Row::clean("a");
    row.status = "refuted";
    row.verifier = None;
    let output = audit(&dir, &corpus(&[row]));

    assert_eq!(code(&output), 2);
    assert!(stdout(&output).contains("design-verifier-absent"));
}

#[test]
fn a_declared_byte_count_that_disagrees_with_the_bytes_is_a_violation() {
    let dir = repo("design-count", "version = 1\n");
    let mut row = Row::clean("a");
    row.capture = Some(capture(BODY_SHA256, BODY.len() + 10, Some(BODY)));
    let output = audit(&dir, &corpus(&[row]));

    assert_eq!(code(&output), 2);
    assert!(stdout(&output).contains("design-byte-count-mismatch"));
}

// --- the advisories, and their promotion --------------------------------

#[test]
fn an_absent_claimant_is_an_advisory_and_a_violation_under_strict() {
    let dir = repo("design-claimant", "version = 1\n");
    let mut row = Row::clean("a");
    row.claimant = None;
    let text = corpus(&[row]);

    let standard = audit(&dir, &text);
    assert_eq!(
        code(&standard),
        0,
        "an advisory alone does not fail the run"
    );
    assert!(stdout(&standard).contains("design-claimant-absent"));

    // The existing ladder, with no bespoke flag.
    let strict = run_with_stdin(&dir, &["--strictness", "strict", "design", "audit"], &text);
    assert_eq!(code(&strict), 2);
    assert!(stdout(&strict).contains("design-claimant-absent"));
}

#[test]
fn self_attestation_is_an_advisory_and_a_violation_under_strict() {
    let dir = repo("design-self", "version = 1\n");
    let mut row = Row::clean("a");
    row.verifier = row.claimant;
    let text = corpus(&[row]);

    assert_eq!(code(&audit(&dir, &text)), 0);
    assert!(stdout(&audit(&dir, &text)).contains("design-self-attested"));

    let strict = run_with_stdin(&dir, &["--strictness", "strict", "design", "audit"], &text);
    assert_eq!(code(&strict), 2);
}

#[test]
fn the_env_spelling_of_the_ladder_promotes_too() {
    // `--strictness strict` and `BATTEN_STRICTNESS` are one setting layered by
    // `resolve`, not two implementations — asserted rather than assumed, since
    // an agent's harness reaches for the variable and a human reaches for the
    // flag.
    let dir = repo("design-strict-env", "version = 1\n");
    let mut row = Row::clean("a");
    row.claimant = None;
    let output = common::batten()
        .args(["design", "audit"])
        .current_dir(&dir)
        .env("BATTEN_STRICTNESS", "strict")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            use std::io::Write as _;
            child
                .stdin
                .take()
                .expect("stdin is piped")
                .write_all(corpus(&[row]).as_bytes())?;
            child.wait_with_output()
        })
        .expect("run batten");

    assert_eq!(code(&output), 2);
}

#[test]
fn a_verified_claim_whose_binding_cannot_be_decided_is_an_advisory() {
    // CLOUD-76 in miniature: the record says verified and there is nothing to
    // check it against. Never a pass, and never a violation either — the record
    // is incomplete, not contradicted.
    let dir = repo("design-not-computable", "version = 1\n");
    let mut without = Row::clean("a");
    without.capture = None;
    let output = audit(&dir, &corpus(&[without]));

    assert_eq!(code(&output), 0);
    assert!(stdout(&output).contains("design-digest-not-computable"));

    // The other spelling: a digest with no bytes beside it.
    let mut bodyless = Row::clean("a");
    bodyless.capture = Some(capture(BODY_SHA256, BODY.len(), None));
    let second = audit(&dir, &corpus(&[bodyless]));
    assert_eq!(code(&second), 0);
    assert!(stdout(&second).contains("design-digest-not-computable"));
}

#[test]
fn a_capture_over_the_declared_budget_is_an_advisory() {
    // The config key's whole job, and the boundary is inclusive: exactly at the
    // ceiling passes.
    let at = repo(
        "design-budget-at",
        &format!(
            "version = 1\n\n[design]\nmax_capture_bytes = {}\n",
            BODY.len()
        ),
    );
    assert_eq!(code(&audit(&at, &corpus(&[Row::clean("a")]))), 0);

    let over = repo(
        "design-budget-over",
        &format!(
            "version = 1\n\n[design]\nmax_capture_bytes = {}\n",
            BODY.len() - 1
        ),
    );
    let output = audit(&over, &corpus(&[Row::clean("a")]));
    assert_eq!(code(&output), 0, "a budget overrun is advisory");
    let text = stdout(&output);
    assert!(text.contains("design-capture-over-budget"), "{text}");
    assert!(!text.contains(BODY), "still no capture bytes: {text}");

    let strict = run_with_stdin(
        &over,
        &["--strictness", "strict", "design", "audit"],
        &corpus(&[Row::clean("a")]),
    );
    assert_eq!(code(&strict), 2);
}

// --- the malformed corpus -----------------------------------------------

#[test]
fn a_row_that_does_not_parse_is_a_usage_error_naming_only_its_line() {
    // Exit 1, not 2: the policy verdict is a claim about the evidence, and "this
    // stream is not the format" is a claim about the invocation. A harness must
    // never read a corpus typo as a deny.
    let dir = repo("design-malformed", "version = 1\n");
    let text = format!(
        "{}\n{{\"id\":\"{SENTINEL}\", oops\n",
        Row::clean("a").line()
    );
    let output = audit(&dir, &text);

    assert_eq!(code(&output), 1);
    let message = stderr(&output);
    assert!(message.contains("line 2"), "{message}");
    carries_no_prose(&output);
}

#[test]
fn an_unknown_status_token_is_refused_rather_than_read_as_the_weakest() {
    // Closed enums: a corpus written against a newer schema is refused, never
    // silently audited as though every unreadable status were `claimed`.
    let dir = repo("design-unknown-token", "version = 1\n");
    let mut row = Row::clean("a");
    row.status = "attested";
    let output = audit(&dir, &corpus(&[row]));

    assert_eq!(code(&output), 1);
}

#[test]
fn an_unknown_field_is_refused() {
    let dir = repo("design-unknown-field", "version = 1\n");
    let text = "{\"id\":\"a\",\"status\":\"claimed\",\"polarity\":\"existence\",\"source\":\"s\",\"claimant\":\"x\",\"note\":\"?\"}\n";
    assert_eq!(code(&audit(&dir, text)), 1);
}

// --- byte stability ------------------------------------------------------

#[test]
fn two_runs_over_the_same_corpus_are_byte_identical_on_both_channels() {
    // §6. Nothing in the report derives from the clock, the environment, or
    // where the fixture lives, so an agent's prefix cache survives a re-run.
    let dir = repo("design-stable", "version = 1\n");
    let mut absent = Row::clean("dup");
    absent.claimant = None;
    let text = corpus(&[Row::clean("dup"), absent]);

    for args in [
        &["design", "audit"][..],
        &["design", "audit", "-J"][..],
        &["--strictness", "strict", "design", "audit", "-J"][..],
    ] {
        let first = run_with_stdin(&dir, args, &text);
        let second = run_with_stdin(&dir, args, &text);
        assert_eq!(first.stdout, second.stdout, "{args:?} is not byte-stable");
        assert_eq!(code(&first), code(&second));
    }
}

#[test]
fn the_json_document_carries_the_same_pointers_and_no_content() {
    let dir = repo("design-json", "version = 1\n");
    let output = run_with_stdin(
        &dir,
        &["design", "audit", "-J"],
        &corpus(&[Row::clean("dup"), Row::clean("dup")]),
    );

    assert_eq!(code(&output), 2);
    let document: serde_json::Value = serde_json::from_str(&stdout(&output)).expect("valid JSON");
    let problem = &document["problems"][0];
    assert_eq!(problem["id"], "design-duplicate-claim-id");
    assert_eq!(problem["claim"], "dup");
    assert_eq!(problem["at"], "-:2");
    assert_eq!(problem["first"], "-:1");
    assert_eq!(problem["severity"], "deny");
    carries_no_prose(&output);
}

// --- the surface ---------------------------------------------------------

#[test]
fn the_audit_verb_is_read_effect_on_the_derived_allowlist() {
    // The §5 claim, asserted against the spec the binary emits rather than the
    // table it was written in: a `read` verb is what an agent's allowlist is
    // derived from, and this one opens no file and spawns nothing.
    let dir = repo("design-spec", "version = 1\n");
    let output = common::run(&dir, &["spec", "--format", "json"]);
    let spec: serde_json::Value = serde_json::from_str(&stdout(&output)).expect("valid JSON");

    let noun = node(&spec, "design").expect("the noun is in the spec");
    assert_eq!(
        noun["effect"], "unclassified",
        "the noun stays conservative: `design attest` is the declared next verb"
    );
    let verb = node(&spec, "design audit").expect("the verb is in the spec");
    assert_eq!(
        verb["effect"], "read",
        "the audit reads a stream and decides; it writes nothing"
    );
}

/// The spec node at `path`, found by walking the emitted tree.
fn node<'a>(spec: &'a serde_json::Value, path: &str) -> Option<&'a serde_json::Value> {
    if spec["path"] == path {
        return Some(spec);
    }
    spec["subcommands"]
        .as_array()?
        .iter()
        .find_map(|child| node(child, path))
}
