//! Agent-sourced facts (CLOUD-776): what a command the AGENT ran said, and the
//! three ways that can fail to be a fact.
//!
//! The channel these cover is the one that removes a choice rather than making
//! it. Every prior discussion of a fact the engine cannot reach weighed *the
//! engine spawns* against *we implement less*; here the engine denies with
//! `Fix::Run`, the agent's own tool runs the command, and the bytes come back on
//! the post-tool event. Batten executes nothing.
//!
//! What that buys has to be paid for in discipline, and these are the payments:
//! the agent picks WHICH command runs, so the recorded command is checked; a
//! buffer can carry anything, so no byte of it is stored; and "nobody looked"
//! must never read as "there are none".

use batten::facts::{self, Look, Sourced};

/// A record for a command that ran and reported `rows`.
fn ran(command: &str, rows: usize) -> Sourced {
    Sourced {
        command: command.to_owned(),
        seen_at: "2026-08-20T12:00:00Z".to_owned(),
        rows,
    }
}

const ASKED: &str = "gh pr list --state open --search CLOUD-776";

#[test]
fn never_ran_and_ran_with_no_rows_are_different_answers() {
    // CLOUD-251's vacuous pass, in the one place this channel could rebuild it.
    // A gate that cannot tell "the agent never ran it" from "it ran and there are
    // none" reports clean because nobody looked.
    let never = facts::sourced(None, ASKED);
    let empty = facts::sourced(Some(&ran(ASKED, 0)), ASKED);

    assert_eq!(never, Look::CouldNotLook);
    assert_eq!(empty, Look::Is(0));
    assert_ne!(
        never, empty,
        "the collapse this whole type exists to prevent"
    );
    assert!(never.could_not_look());
    assert!(!empty.could_not_look(), "zero rows IS an answer");
}

#[test]
fn ran_with_rows_is_a_third_outcome_and_no_two_collapse() {
    // CLOUD-776's §7 in full: three distinct outcomes, and the test fails if any
    // two of them become the same value.
    let answers = [
        facts::sourced(None, ASKED),
        facts::sourced(Some(&ran(ASKED, 0)), ASKED),
        facts::sourced(Some(&ran(ASKED, 2)), ASKED),
    ];
    assert_ne!(answers[0], answers[1]);
    assert_ne!(answers[1], answers[2]);
    assert_ne!(answers[0], answers[2]);
}

#[test]
fn a_record_naming_another_command_is_could_not_look_never_a_fact() {
    // THE residual attack this channel carries. The agent chooses which command
    // runs — it does not author what the output says — so a fact keyed to a
    // `Fix::Run` nobody verifies is CLOUD-526's forgery gradient rebuilt on a new
    // surface. `echo '[]'` is the convenient answer; it is not the asked answer.
    let convenient = ran("echo '[]'", 0);
    let answer = facts::sourced(Some(&convenient), ASKED);

    assert_eq!(answer, Look::CouldNotLook);
    assert!(
        answer.could_not_look(),
        "a mismatched command must not be usable as a fact"
    );
    // And it is NOT distinguishable from never-ran in the verdict, deliberately:
    // both call for the same remedy — run *the* command.
    assert_eq!(answer, facts::sourced(None, ASKED));
}

#[test]
fn the_comparison_is_byte_equality_so_a_near_miss_is_not_accepted() {
    // Any normalisation is a gap between what was asked and what is accepted.
    for near in [
        "gh pr list --state open --search CLOUD-776 ",
        "gh  pr list --state open --search CLOUD-776",
        "gh pr list --state all --search CLOUD-776",
        "GH PR LIST --STATE OPEN --SEARCH CLOUD-776",
    ] {
        assert_eq!(
            facts::sourced(Some(&ran(near, 0)), ASKED),
            Look::CouldNotLook,
            "`{near}` is not `{ASKED}`"
        );
    }
}

#[test]
fn a_half_written_record_reads_as_could_not_look() {
    // Fail closed. The dangerous reading is "rows absent, so zero" — a truncated
    // write would then answer "there are none".
    for broken in ["command gh pr list\n", "", "nonsense", "rows 3\n"] {
        assert_eq!(Sourced::parse(broken), None, "{broken:?} is not a record");
    }
    assert_eq!(facts::sourced(None, ASKED), Look::CouldNotLook);
}

#[test]
fn a_record_round_trips_through_its_on_disk_shape() {
    let record = ran(ASKED, 3);
    assert_eq!(Sourced::parse(&record.render()), Some(record));
}

#[test]
fn no_byte_of_the_buffer_reaches_the_stored_record() {
    // Rule 4, asserted on the bytes that actually reach disk. A command's stdout
    // can carry anything, which makes the result buffer the likeliest field in
    // the envelope to hold a secret.
    let secret = "ghp_PLANTEDSECRETVALUE";
    let buffer = serde_json::json!([
        { "type": "text", "text": format!("[{{\"title\":\"{secret}\"}}]") }
    ]);

    let Look::Is(rows) = facts::rows_in(&buffer) else {
        panic!("a content-block array is a shape this build reads");
    };
    assert_eq!(rows, 1);

    let rendered = ran(ASKED, rows).render();
    assert!(
        !rendered.contains(secret),
        "the record must carry a count, never the payload; got: {rendered}"
    );
    assert!(
        !rendered.contains("title"),
        "not even a key from the buffer; got: {rendered}"
    );
}

#[test]
fn no_buffer_is_ever_reported_as_zero_unless_it_really_carried_nothing() {
    // THE INVARIANT, and the reason the refusal this test used to assert could be
    // replaced (CLOUD-992). Answering `Is(0)` for a buffer this build cannot
    // decompose would be a guessed envelope becoming a silent fact. Normalising
    // to an array preserves that just as refusing did: an opaque buffer is one
    // row, never none, so a `rows == 0` predicate stays fail-closed.
    for wrapped in [
        serde_json::json!({ "stdout": "whatever" }),
        serde_json::json!("a string"),
        serde_json::json!(7),
        serde_json::json!(true),
        serde_json::json!([{ "type": "text", "text": "not json" }]),
    ] {
        assert_eq!(
            facts::rows_in(&wrapped),
            Look::Is(1),
            "{wrapped} carries one opaque row, and must never read as zero"
        );
    }
}

#[test]
fn only_an_absent_or_empty_buffer_is_could_not_look() {
    // `Null` is no buffer at all. An empty or whitespace-only one is the one
    // place the three-valued reading survives and earns it: a command that
    // failed silently and one that legitimately found nothing are
    // indistinguishable, so `0` would let an unreviewed head through and `1`
    // would deny a gate forever. Only could-not-look states what is known.
    for unknowable in [
        serde_json::Value::Null,
        serde_json::json!(""),
        serde_json::json!("   \n\t "),
        serde_json::json!([{ "type": "text", "text": "" }]),
    ] {
        assert_eq!(
            facts::rows_in(&unknowable),
            Look::CouldNotLook,
            "{unknowable} says nothing, and a count would be a guess"
        );
    }
}

#[test]
fn a_shell_buffer_carrying_json_is_counted_without_the_command_projecting_it() {
    // The whole point of CLOUD-992: a `gh … --json` buffer arrives as TEXT, and
    // the engine parses it rather than obliging every declared command to append
    // `--jq '[…]'`. Real lengths, not 1, or the suite would pass over a change
    // that made everything read as one row.
    assert_eq!(
        facts::rows_in(&serde_json::json!("[{\"n\":1},{\"n\":2},{\"n\":3}]")),
        Look::Is(3)
    );
    // An empty JSON array in text is a genuine zero — the reading a review gate
    // needs for "reviewed and addressed".
    assert_eq!(facts::rows_in(&serde_json::json!("[]")), Look::Is(0));
    // A single JSON object in text is one element, wrapped.
    assert_eq!(facts::rows_in(&serde_json::json!("{\"n\":1}")), Look::Is(1));
}

#[test]
fn both_measured_buffer_shapes_are_read() {
    // A bare row array...
    assert_eq!(
        facts::rows_in(&serde_json::json!([{ "a": 1 }, { "a": 2 }])),
        Look::Is(2)
    );
    // ...an empty one, which is a genuine zero rather than an unread shape...
    assert_eq!(facts::rows_in(&serde_json::json!([])), Look::Is(0));
    // ...and the content-block envelope an MCP tool actually returns, which
    // `tests/board-write-record.bats` measured and this borrows rather than
    // re-deriving.
    assert_eq!(
        facts::rows_in(&serde_json::json!([{ "type": "text", "text": "[]" }])),
        Look::Is(0)
    );
    assert_eq!(
        facts::rows_in(&serde_json::json!([
            { "type": "text", "text": "[{\"n\":1},{\"n\":2},{\"n\":3}]" }
        ])),
        Look::Is(3)
    );
}

#[test]
fn the_record_is_keyed_on_the_fact_not_on_a_branch_or_a_sha() {
    // CLOUD-776 decision 2: a claimed-key answer is a statement about one row at
    // one moment. Keying it to a branch would make the same answer unavailable to
    // the next branch that needs it, and stale-by-construction on this one.
    let path = facts::sourced_path(std::path::Path::new("/repo/.git"), "claimed-key");
    assert!(path.ends_with("batten-receipts/fact.claimed-key"));
    // A name that would escape the directory cannot.
    let nested = facts::sourced_path(std::path::Path::new("/repo/.git"), "a/b");
    assert!(nested.ends_with("batten-receipts/fact.a-b"));
}

#[test]
fn the_agent_sourced_class_sits_on_the_hook_surface_and_says_why() {
    // The row that makes the fact model's second axis pay for itself. A forge
    // fact is `read` x `verify-only` because reaching it means the ENGINE builds
    // an HTTP client. An agent-sourced fact is not the engine resolving anything,
    // so the same underlying answer is reachable on the mediated path.
    let class = batten::facts::Fact::AgentSourced.class();
    assert_eq!(class, batten::facts::AGENT_SOURCED);
    assert_eq!(class.cost, batten::facts::Cost::Read);
    assert_eq!(class.surface, batten::facts::Surface::Hook);
}
