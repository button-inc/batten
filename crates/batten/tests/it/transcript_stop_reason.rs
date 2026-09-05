//! `StopReason::Truncated` over the real parser (CLOUD-1464).
//!
//! The tier that matters: `normalize` is private, so a case here can only reach
//! it through [`batten::transcript::parse`] — the same route a consumer takes.
//! An in-module test can call the function directly; this one proves the token
//! survives the parse into the event a predicate reads.
//!
//! What the row splits: `Other` used to carry two unrelated meanings at once —
//! the host stopped at a token ceiling, and this build has never seen the token.
//! Neither is a completion, which is why the collapse survived while
//! `completion.rs` was the only reader. A Stop-family predicate that wants to
//! tell a host's ceiling from this build's currency cannot, and that is the
//! defect. `a_truncated_turn_is_still_not_a_completion` is the other half: the
//! split moves no verdict.

use batten::completion;
use batten::transcript::{Event, StopReason, parse};

/// The reasons a body yields, in stream order.
fn reasons(body: &str) -> Vec<StopReason> {
    parse(body, "t.jsonl")
        .expect("the fixture parses")
        .records
        .iter()
        .filter_map(|record| match record.event {
            Event::TurnEnd(reason) => Some(reason),
            _ => None,
        })
        .collect()
}

/// One assistant record ending on `token`.
fn ended_on(token: &str) -> String {
    format!(
        r#"{{"type":"assistant","message":{{"role":"assistant","content":[],"stop_reason":"{token}"}}}}"#
    )
}

#[test]
fn every_hosts_truncation_spelling_normalizes_to_truncated() {
    // The discriminating case, and it is red four ways against the `normalize`
    // this row changes: each of these landed on `Other` before, indistinguishable
    // from a token nobody has shipped yet.
    let body = ["max_tokens", "length", "MAX_TOKENS", "max_output_tokens"]
        .map(ended_on)
        .join("\n");
    assert_eq!(
        reasons(&body),
        vec![StopReason::Truncated; 4],
        "each literal is one host's spelling of the same ceiling"
    );
}

#[test]
fn an_unrecognised_token_is_still_other() {
    // The forward-compatibility half. `Other` keeps exactly one meaning now —
    // a token this build does not know — and the new arm must not have taken it.
    assert_eq!(
        reasons(&ended_on("brand_new_token")),
        vec![StopReason::Other]
    );
}

#[test]
fn the_tokens_this_row_does_not_touch_are_unmoved() {
    let body = ["end_turn", "stop_sequence", "tool_use"]
        .map(ended_on)
        .join("\n");
    assert_eq!(
        reasons(&body),
        vec![
            StopReason::EndTurn,
            StopReason::StopSequence,
            StopReason::ToolUse,
        ]
    );
}

#[test]
fn a_truncated_turn_is_still_not_a_completion() {
    // Verdict parity: a vocabulary split, not a behaviour change. A turn the
    // host cut off has declared no stopping point, exactly as before — so
    // `completion` finds no marker to anchor on and signals nothing.
    let stream = parse(&ended_on("max_tokens"), "t.jsonl").expect("the fixture parses");
    assert!(
        completion::signal(&stream).is_none(),
        "truncation is not the model ending its own turn"
    );
}
