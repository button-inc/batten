//! Recognized shell-tool failures, over the compiled engine (CLOUD-945).
//!
//! # The empirical precondition, settled rather than assumed
//!
//! CLOUD-945 makes one question a precondition: does the host's Bash post-tool
//! payload carry a structured exit status, and where does the outcome appear?
//! It is answered here from a MEASURED payload rather than from a fabricated
//! one — `crates/batten/tests/fixtures/hooks/claude-code-posttool-failure.json`
//! is the shape observed across 364 real results in one Claude Code session,
//! sanitized.
//!
//! The answer is that it does not. So the declared exit-127 and exit-126 arms
//! are unreached on this host, `classify` answers could-not-look, and nothing is
//! advised — which is the row's own "absent exit status fails open with no
//! advice", not a gap in it.
//!
//! # The discriminating case
//!
//! [`arbitrary_output_containing_the_phrase_advises_nothing`]. An unanchored
//! matcher passes every other negative here — the successful command, the
//! unsupported OS, the non-shell tool — and fails only that one, because it
//! would recognise the phrase inside an echo, a log line or a commit message.
//! That is why the structured code is read before any text is.
//!
//! # Why the fixture is loaded rather than restated
//!
//! A fixture inlined here would drift from the committed one and pass while the
//! real shape had moved. The `hooks/` README already states the principle for
//! this directory: a fixture pins what was measured, so a later edit argues with
//! an observation instead of a recollection.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::fs;

use batten::outcome::{self, Class, Signature};

/// The measured, sanitized failing payload this repository commits.
fn measured() -> serde_json::Value {
    let text = fs::read_to_string(common::at_root(
        "crates/batten/tests/fixtures/hooks/claude-code-posttool-failure.json",
    ))
    .expect("the measured failure payload is committed");
    serde_json::from_str(&text).expect("the fixture is JSON")
}

/// The signatures the committed config declares, read from it rather than
/// restated: a copy here would pass while the config said something else.
fn declared() -> Vec<Signature> {
    let text = fs::read_to_string(common::at_root("batten.toml")).expect("the config is committed");
    let config: toml::Value = toml::from_str(&text).expect("the config parses");
    let rows = config
        .get("outcome")
        .and_then(toml::Value::as_array)
        .expect("the config declares outcome signatures");
    rows.iter()
        .map(|row| row.clone().try_into().expect("a signature row"))
        .collect()
}

/// The committed config declares the two anchored arms, each with a code.
///
/// The `code` column is the anchoring, so a row without one would be the
/// unanchored matcher the row forbids by name — and `deny_unknown_fields` plus a
/// required column is what makes that unwritable rather than merely discouraged.
#[test]
fn the_declared_signatures_are_anchored_on_a_code() {
    let signatures = declared();
    assert!(
        !signatures.is_empty(),
        "an empty table recognises nothing, so a suite over it would assert nothing"
    );
    for signature in &signatures {
        assert!(
            !signature.class.is_empty(),
            "every signature names the class it establishes"
        );
        assert_eq!(signature.family, "unix");
    }
    let codes: Vec<i64> = signatures.iter().map(|signature| signature.code).collect();
    assert!(
        codes.contains(&127),
        "the command-not-found arm is declared"
    );
    assert!(codes.contains(&126), "the permission arm is declared");
}

/// **The measurement.** The real host payload carries no structured exit status.
///
/// This is the empirical precondition, asserted over the committed fixture so
/// that a host which gains a code moves this case rather than leaving the claim
/// to a comment.
#[test]
fn the_measured_host_payload_carries_no_structured_exit_status() {
    let payload = measured();
    let result = payload
        .get("tool_response")
        .expect("the measured payload carries a tool response");
    assert_eq!(
        outcome::structured_code(result),
        None,
        "measured over 364 real results: this host supplies no exit code"
    );
    assert!(
        result.get("stderr").is_some(),
        "the diagnostic arrives as text, which is precisely what may not be matched on"
    );
}

/// So the declared arms are unreached here, and nothing is advised.
#[test]
fn the_measured_failure_advises_nothing_on_this_host() {
    let payload = measured();
    let result = payload
        .get("tool_response")
        .expect("the measured payload carries a tool response");
    let command = payload
        .get("tool_input")
        .and_then(|input| input.get("command"))
        .and_then(serde_json::Value::as_str)
        .expect("the measured payload carries a command");

    let classified = outcome::classify(result, command, &declared());
    assert_eq!(classified.class, Class::Unknown);
    assert!(
        !classified.class.advisable(),
        "could-not-look never advises: this is the fail-open half"
    );
    assert_eq!(classified.code, None);
}

/// **The discriminating case.** Arbitrary output carrying the phrase advises
/// nothing.
///
/// An implementation that matched the diagnostic text passes every other
/// negative in this file and fails only this one.
#[test]
fn arbitrary_output_containing_the_phrase_advises_nothing() {
    let phrase = "sh: 1: example-program: not found";
    let echoed = serde_json::json!({
        "stdout": format!("{phrase}\n"),
        "stderr": "",
        "interrupted": false,
        "exitCode": 0,
    });
    assert_eq!(
        outcome::classify(&echoed, &format!("echo '{phrase}'"), &declared()).class,
        Class::Unknown,
        "a SUCCESSFUL command that prints the phrase is not a failure"
    );

    // And in a commit message, which is the shape that actually recurs here.
    let committing = serde_json::json!({
        "stdout": format!("[branch abc1234] fix: stop reporting `{phrase}` as a class\n"),
        "stderr": "",
        "exitCode": 0,
    });
    assert_eq!(
        outcome::classify(&committing, "git commit -m ...", &declared()).class,
        Class::Unknown
    );
}

/// A successful command advises nothing, whatever it printed.
#[test]
fn a_successful_command_advises_nothing() {
    let clean = serde_json::json!({"stdout": "ok\n", "stderr": "", "exitCode": 0});
    assert_eq!(
        outcome::classify(&clean, "true", &declared()).class,
        Class::Unknown
    );
}

/// A host that DOES supply a code is recognised — the anti-vacuity half.
///
/// Without this the refusals above would be unconditional and would prove
/// nothing: a classifier that always answered `Unknown` satisfies every negative
/// in this file.
#[test]
fn a_code_bearing_host_reaches_the_declared_arm() {
    let with_code = serde_json::json!({
        "stdout": "",
        "stderr": "sh: 1: example-program: not found",
        "interrupted": false,
        "exitCode": 127,
    });
    let classified = outcome::classify(&with_code, "example-program --version", &declared());
    assert_eq!(classified.class, Class::CommandNotFound);
    assert!(classified.class.advisable());
    assert_eq!(classified.token.as_deref(), Some("example-program"));
    assert_eq!(classified.code, Some(127));
}

/// Nothing the payload carried reaches the advisory (rule 4).
///
/// Load-bearing rather than formal here: a command's output is the likeliest
/// field in the whole envelope to hold a secret, and the advisory channel is
/// written to a log by construction.
#[test]
fn no_payload_byte_reaches_the_advisory() {
    let secretish = serde_json::json!({
        "stdout": "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI",
        "stderr": "sh: 1: example-program: not found",
        "exitCode": 127,
    });
    let classified = outcome::classify(&secretish, "example-program --flag", &declared());
    let rendered = serde_json::to_string(&classified).expect("the outcome serialises");
    for leaked in ["wJalrXUtnFEMI", "AWS_SECRET", "not found", "sh: 1"] {
        assert!(
            !rendered.contains(leaked),
            "the normalized outcome carries `{leaked}`, which is a payload byte"
        );
    }
    assert!(
        rendered.contains("example-program"),
        "the program token IS carried: a remedy names it"
    );
}

/// The same normalized outcome twice is one key, not two advisories.
#[test]
fn the_same_outcome_twice_is_rate_limited_by_one_key() {
    let first = outcome::advice_key("sess", "Bash", Class::CommandNotFound);
    let again = outcome::advice_key("sess", "Bash", Class::CommandNotFound);
    assert_eq!(first, again, "the same outcome resolves to the same key");
    assert_ne!(
        first,
        outcome::advice_key("other", "Bash", Class::CommandNotFound),
        "a different session is a different advisory"
    );
    assert!(
        !first.contains("sess"),
        "the raw session token is not the key"
    );
}

/// The committed measured fixture is the shape the hooks directory documents.
///
/// Its own tier: a fixture that drifted from the payload it claims to record
/// would make every assertion above true of nothing.
#[test]
fn the_committed_fixture_is_a_post_tool_bash_payload() {
    let payload = measured();
    assert_eq!(payload["hook_event_name"], "PostToolUse");
    assert_eq!(payload["tool_name"], "Bash");
    let response = &payload["tool_response"];
    for key in [
        "stdout",
        "stderr",
        "interrupted",
        "isImage",
        "noOutputExpected",
    ] {
        assert!(
            response.get(key).is_some(),
            "the measured shape carries `{key}`"
        );
    }
    assert!(
        response.get("exitCode").is_none() && response.get("exit_code").is_none(),
        "and it carries no exit code, which is the whole measurement"
    );
}
