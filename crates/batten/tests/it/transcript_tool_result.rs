//! A tool result's keyed observation identity, over the real parser (CLOUD-1348).
//!
//! The detector this unlocks is the same call returning the SAME answer — which
//! separates a stuck loop from a converging one, where counting repeated calls
//! cannot. So the cases below are about what makes two answers equal, and about
//! the one thing that must NOT make them equal across machines.
//!
//! **The discriminating case is `two_keys_over_the_same_bytes_do_not_collide`**,
//! and it is what the row's `digest-unkeyed` mutation reddens: replace the keyed
//! mint with a bare hash and identical bytes fingerprint identically everywhere,
//! which is the cross-clone correlatable identity the row refused. The
//! same-key-same-bytes case is the anti-vacuity half — without it, a mint that
//! returned a fresh random value per call would pass the first case for the wrong
//! reason.

use batten::identity::IdentityKey;
use batten::transcript::{Event, parse, parse_keyed};

/// A one-line transcript whose assistant turn carries one tool result.
fn result_line(call: &str, text: &str) -> String {
    let block = serde_json::json!({
        "type": "assistant",
        "message": {
            "role": "assistant",
            "content": [{"type": "tool_result", "tool_use_id": call, "content": text}],
        },
    });
    block.to_string()
}

/// The digests a body yields, in stream order.
fn digests(body: &str, key: Option<&IdentityKey>) -> Vec<Option<String>> {
    parse_keyed(body, "t.jsonl", key)
        .expect("the fixture parses")
        .records
        .iter()
        .filter_map(|record| match &record.event {
            Event::ToolResult { digest, .. } => Some(digest.as_ref().map(|id| id.to_hex())),
            _ => None,
        })
        .collect()
}

#[test]
fn the_same_answer_twice_is_one_identity() {
    // The equality the detector is built on: same call, same bytes, same key.
    let key = IdentityKey::new("k1", [7u8; 32]);
    let body = format!(
        "{}\n{}",
        result_line("call-1", "the same answer"),
        result_line("call-1", "the same answer")
    );
    let seen = digests(&body, Some(&key));
    assert_eq!(seen.len(), 2);
    assert_eq!(seen[0], seen[1], "the same answer must fingerprint alike");
    assert!(seen[0].is_some());
}

#[test]
fn a_changed_answer_is_a_different_identity() {
    // The other side of it, and the case that makes the detector worth having:
    // a converging loop's answers keep changing, so it must not read as stuck.
    let key = IdentityKey::new("k1", [7u8; 32]);
    let body = format!(
        "{}\n{}",
        result_line("call-1", "3 errors remain"),
        result_line("call-1", "1 error remains")
    );
    let seen = digests(&body, Some(&key));
    assert_ne!(seen[0], seen[1]);
}

#[test]
fn two_keys_over_the_same_bytes_do_not_collide() {
    // THE ROW'S DECISION, as a case. An unkeyed digest of a tool result is a
    // stable identity of file content that two clones could join on; under the
    // machine-scoped key they cannot. Fold the keying away and this reds.
    let body = result_line("call-1", "identical bytes on two machines");
    let one = digests(&body, Some(&IdentityKey::new("k1", [1u8; 32])));
    let two = digests(&body, Some(&IdentityKey::new("k2", [2u8; 32])));
    assert!(one[0].is_some() && two[0].is_some());
    assert_ne!(
        one, two,
        "the same bytes under two keys must not share an identity"
    );
}

#[test]
fn an_unkeyed_parse_mints_nothing_and_says_so() {
    // `None` here is this PARSE saying nothing, and `keyed` is where that is
    // recorded — so a consumer cannot read it as the host having written no
    // result content.
    let body = result_line("call-1", "an answer nobody keyed");
    let stream = parse(&body, "t.jsonl").expect("the fixture parses");
    assert!(!stream.keyed);
    assert_eq!(digests(&body, None), vec![None]);
}

#[test]
fn a_result_the_host_wrote_no_content_for_has_no_identity() {
    // The other cause of `None`, over a keyed parse: nothing to fingerprint, and
    // no digest of some other field invented in its place.
    let key = IdentityKey::new("k1", [7u8; 32]);
    let body = serde_json::json!({
        "type": "assistant",
        "message": {
            "role": "assistant",
            "content": [{"type": "tool_result", "tool_use_id": "call-1", "is_error": true}],
        },
    })
    .to_string();
    let stream = parse_keyed(&body, "t.jsonl", Some(&key)).expect("the fixture parses");
    assert!(stream.keyed, "the parse held a key");
    assert_eq!(digests(&body, Some(&key)), vec![None]);
}

#[test]
fn the_block_spelling_of_a_result_is_read_like_the_string_one() {
    // Hosts write a result either as a bare string or as typed content blocks.
    // Knowing only one spelling would mint no identity for the other, which
    // reads as "this host says nothing" — a silent hole in the detector.
    let key = IdentityKey::new("k1", [7u8; 32]);
    let blocks = serde_json::json!({
        "type": "assistant",
        "message": {
            "role": "assistant",
            "content": [{
                "type": "tool_result",
                "tool_use_id": "call-1",
                "content": [{"type": "text", "text": "an answer"}],
            }],
        },
    })
    .to_string();
    let plain = result_line("call-1", "an answer");
    assert_eq!(
        digests(&blocks, Some(&key)),
        digests(&plain, Some(&key)),
        "one answer, two spellings, one identity"
    );
}

#[test]
fn no_result_byte_reaches_the_record() {
    // Rule 4, structurally: the parsed record carries the call id, the host's
    // error flag and a digest — and `Debug` is every path a byte could ride out
    // on, so a rendering of the whole stream is where a leak would show.
    let key = IdentityKey::new("k1", [7u8; 32]);
    let secret = "sk-live-notarealsecret-000";
    let stream = parse_keyed(&result_line("call-1", secret), "t.jsonl", Some(&key))
        .expect("the fixture parses");
    assert!(!format!("{stream:?}").contains(secret));
}
