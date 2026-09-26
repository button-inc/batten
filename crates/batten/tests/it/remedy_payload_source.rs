//! Every remedy that sources a payload names the source that works on ANY host
//! (CLOUD-990), over the committed config and `[tasks.board-payloads]`' body.
//!
//! Measured before the rule existed: an agent read `board-payloads`' refusal on a
//! host that writes no transcript, concluded the board could not be written, and
//! could not even file that finding, because the filing gate wanted the same
//! bytes. The capture store held them the whole time. The predicate is narrow —
//! each message names `batten capture show … --raw` — and says nothing else about
//! the wording.
//!
//! # RETIREMENT LEDGER, PER PATH — what `shell retire partial` reads
//!
// carried: tests/remedy-payload-source.bats mise.toml kind:mechanism crates/batten/tests/it/remedy_payload_source.rs
// carried: "every message was found at all — this suite is not passing vacuously" batten.toml kind:mechanism
// carried: "THE PREDICATE: every refusal names the source that works on any host" batten.toml kind:mechanism
// carried: "THE STRONGER PREDICATE: the two board-write rows send the reader to no payload at all" batten.toml kind:mechanism
// carried: "every --grep in a remedy carries a pattern, since a bare flag is not a command" batten.toml kind:mechanism
// carried: "the absent-transcript path spells the recipe, since that is where the agent lands" mise.toml kind:mechanism
// carried: "the search recipe is followable in the ZERO-HIT case its own text blesses" batten.toml kind:mechanism
// carried: "no message invites the agent to re-type a payload" batten.toml kind:mechanism
// carried: "the capture route is described as equally valid, not as a fallback to apologise for" batten.toml kind:mechanism
// changed: "no apostrophe reaches the two jq-built denies, which is why the wording above is what it is" batten.toml each row is asserted to be a parsed TOML `reason` string; the `bash -n` half is gone with the file, since the body is now a manifest string every tier that runs it parses

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

/// The `reason` of the one config row whose `id` is `id`, from whichever
/// array of tables carries it. `None` when no row carries one as a string.
fn reason(id: &str) -> Option<String> {
    let text = std::fs::read_to_string(common::at_root("batten.toml")).expect("the config");
    let config: toml::Value = toml::from_str(&text).expect("batten.toml parses");
    let mut found = config
        .as_table()
        .expect("a table")
        .values()
        .filter_map(toml::Value::as_array)
        .flatten()
        .filter(|row| row.get("id").and_then(toml::Value::as_str) == Some(id))
        .filter_map(|row| row.get("reason").and_then(toml::Value::as_str))
        .map(str::to_owned);
    let first = found.next();
    assert!(found.next().is_none(), "one row carries `{id}`'s reason");
    first
}

/// `board-payloads`' absent-transcript refusal: from its message to the `fi`.
fn absent() -> String {
    let body = common::task_body("board-payloads");
    let start = body
        .find("no readable transcript")
        .expect("the absent-transcript refusal");
    let rest = &body[start..];
    let end = rest.find("\nfi\n").expect("the refusal's block closes");
    rest[..end].to_owned()
}

struct Messages {
    read_guard: String,
    search_guard: String,
    claim_row: String,
    absent: String,
}

fn messages() -> Messages {
    Messages {
        read_guard: reason("issue read stale").expect("the read guard's reason"),
        search_guard: reason("issue list unread").expect("the search guard's reason"),
        claim_row: reason("claim read unread").expect("the claim row's reason"),
        absent: absent(),
    }
}

/// Each slice is the refusal, not a neighbouring block.
#[test]
fn every_message_is_found_and_is_the_refusal() {
    let m = messages();
    assert!(m.read_guard.contains("get_issue"));
    assert!(m.search_guard.contains("list_issues"));
    assert!(m.claim_row.contains("claim-check"));
    assert!(m.absent.contains("not an empty harvest"));
}

/// THE PREDICATE, in its runnable shape: `show` names the verb and `--raw` makes
/// the bytes pipeable. Both, where naming only `board-payloads` dead-ends.
#[test]
fn every_payload_sourcing_refusal_names_the_capture_store_runnably() {
    let m = messages();
    for message in [&m.claim_row, &m.absent] {
        assert!(message.contains("batten capture show"), "{message}");
        assert!(message.contains("--raw"), "{message}");
        assert!(message.contains("re-type"), "{message}");
        assert!(message.contains("bytes the tracker returned"), "{message}");
    }
    assert!(m.absent.contains("batten capture list"));
    assert!(m.absent.contains("--grep"));
}

/// CLOUD-1024: the board-write rows ask for a call, never a payload, so they
/// name no recovery route at all.
#[test]
fn the_board_write_rows_send_the_reader_to_no_payload() {
    let m = messages();
    for message in [&m.read_guard, &m.search_guard] {
        for route in [
            "issue-read-check",
            "issue-search-check",
            "board-payloads",
            "batten capture",
        ] {
            assert!(!message.contains(route), "{route} in {message}");
        }
    }
    // The search row still says a zero-hit search is fine; the claim row keys
    // on an id every get_issue payload carries.
    assert!(m.search_guard.contains("zero hits"));
    assert!(m.claim_row.contains("CLOUD-N"));
}

/// A `--grep` value is quoted, and belongs to a `capture show` command.
#[test]
fn every_grep_in_a_remedy_is_typeable() {
    let m = messages();
    for message in [&m.read_guard, &m.search_guard, &m.claim_row, &m.absent] {
        let mut rest = message.as_str();
        while let Some(at) = rest.find("--grep") {
            let prefix = &rest[..at];
            let after = rest[at + "--grep".len()..].trim_start_matches(' ');
            let after = after.strip_prefix('\\').unwrap_or(after);
            assert!(
                after.starts_with('\'') || after.starts_with('"'),
                "an unquoted --grep in {message}"
            );
            let tail: String = prefix
                .chars()
                .rev()
                .take(60)
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .collect();
            assert!(
                tail.contains("capture show"),
                "a floating --grep in {message}"
            );
            rest = &rest[at + 1..];
        }
    }
}
