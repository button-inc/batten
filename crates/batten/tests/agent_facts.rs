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

use batten::facts::{self, Look, Returns, Sourced};

/// A shell tool's response envelope, as Claude Code actually returns one.
///
/// Every case below that means "the command printed this" goes through here
/// rather than passing a bare string, because the bare-string reading is what
/// CLOUD-992 measured to be wrong: the buffer arrives as a MEMBER of an object,
/// and a suite that passes the member directly cannot see that.
fn shell(stdout: &str) -> serde_json::Value {
    serde_json::json!({ "stdout": stdout, "stderr": "" })
}

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
    // And an envelope AGGREGATES its blocks rather than reading the first: two
    // arrays of two and one sum to three. Without this the loop could return any
    // single block's count and the suite would not notice.
    assert_eq!(
        facts::rows_in(&serde_json::json!([
            { "type": "text", "text": "[{\"n\":1},{\"n\":2}]" },
            { "type": "text", "text": "[{\"n\":3}]" }
        ])),
        Look::Is(3)
    );
}

#[test]
fn a_mixed_array_is_a_row_array_and_never_an_envelope() {
    // THE INVARIANT'S OWN COUNTEREXAMPLE (CodeRabbit on PR #672, confirmed).
    // Envelope semantics used to be selected by ANY item being a content block,
    // which read the one block and dropped every other row — so an array
    // carrying two rows answered `Is(0)`, the exact fail-closed collapse this
    // function exists to prevent, produced by the code meant to prevent it.
    //
    // A row that merely LOOKS like a content block is an ordinary row: a tool
    // emitting `{"type":"text", …}` records is not thereby emitting an envelope.
    assert_eq!(
        facts::rows_in(&serde_json::json!([
            { "type": "text", "text": "[]" },
            { "id": 1 }
        ])),
        Look::Is(2),
        "an array whose items are not ALL content blocks counts its items"
    );
    // The same shape with a genuine zero-row envelope beside it: still two rows,
    // because the array is not an envelope at all.
    assert_eq!(
        facts::rows_in(&serde_json::json!([{ "id": 1 }, { "type": "text", "text": "[]" }])),
        Look::Is(2)
    );
    // A one-item array that IS wholly content blocks keeps envelope semantics —
    // the narrowing must not cost the shape an MCP tool actually returns.
    assert_eq!(
        facts::rows_in(&serde_json::json!([{ "type": "text", "text": "[]" }])),
        Look::Is(0)
    );
    // A `text` that is not a STRING is not a content block, so its array is not
    // an envelope. Keying the shape on `type` alone admitted this block and the
    // loop then skipped it, answering `Is(0)` for a buffer half of which was
    // never read (CodeRabbit on PR #672, confirmed).
    assert_eq!(
        facts::rows_in(&serde_json::json!([
            { "type": "text", "text": "[]" },
            { "type": "text", "text": 7 }
        ])),
        Look::Is(2),
        "a malformed block is an ordinary row, and two rows is what this carries"
    );
    // Likewise a block with no `text` field at all.
    assert_eq!(
        facts::rows_in(&serde_json::json!([
            { "type": "text", "text": "[]" },
            { "type": "text" }
        ])),
        Look::Is(2)
    );
}

#[test]
fn a_shell_tools_buffer_is_a_member_of_its_envelope_and_is_counted_there() {
    // THE ARM CLOUD-992 EXISTS FOR, and the one normalising buffers did not
    // reach. Claude Code hands a Bash call's response back as an OBJECT —
    // `capture::decode_response` states that shape against the measured corpus
    // — so `rows_in` never sees the stdout text as a buffer. Counting the
    // object gave `1` for every shell command ever declared.
    //
    // MEASURED, not reasoned: with a `[[fact]]` row declaring
    // `printf '[1,2,3]\n'`, the record written by the real hook read `rows 1`.
    // That is the whole capability failing, and no buffer-shaped test could see
    // it, because the buffer was never the value under test.
    assert_eq!(
        facts::rows_in(&serde_json::json!({ "stdout": "[1,2,3]\n", "stderr": "" })),
        Look::Is(3),
        "the count is what the command printed, not the envelope wrapping it"
    );
    // The reading a review gate needs: an empty JSON array on stdout is a
    // genuine zero, which is what makes `rows == 0` mean "reviewed and clear".
    assert_eq!(
        facts::rows_in(&serde_json::json!({ "stdout": "[]", "stderr": "" })),
        Look::Is(0)
    );
    // Prose on stdout is one opaque row — fail-closed, never zero.
    assert_eq!(
        facts::rows_in(&serde_json::json!({ "stdout": "gh version 2.97.0\n" })),
        Look::Is(1)
    );
    // A command that printed nothing at all is could-not-look, exactly as an
    // empty bare buffer is. `0` here would let an unreviewed head through.
    assert_eq!(
        facts::rows_in(&serde_json::json!({ "stdout": "", "stderr": "" })),
        Look::CouldNotLook
    );
    // An object with no stream member is NOT an envelope — it is a single JSON
    // row, and stays one element wrapped.
    assert_eq!(facts::rows_in(&serde_json::json!({ "n": 1 })), Look::Is(1));
}

#[test]
fn one_unreadable_block_condemns_the_whole_envelope() {
    // The sibling of the shape check above, on the axis `is_text_block` cannot
    // reach: every item IS a well-formed content block, and one of them says
    // nothing. Folding that in as `0` would be a guess presented as a reading,
    // so the buffer as a whole is could-not-look — never the sum of the rest,
    // which is what silently under-counted before.
    for envelope in [
        serde_json::json!([
            { "type": "text", "text": "[{\"n\":1},{\"n\":2},{\"n\":3}]" },
            { "type": "text", "text": "" }
        ]),
        serde_json::json!([
            { "type": "text", "text": "   \n\t " },
            { "type": "text", "text": "[{\"n\":1}]" }
        ]),
    ] {
        assert_eq!(
            facts::rows_in(&envelope),
            Look::CouldNotLook,
            "{envelope} carries a block that said nothing, so its total is unknown"
        );
    }
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
fn the_record_is_keyed_on_the_fact_and_on_its_rows_declared_subject() {
    // CLOUD-776 decision 2 held that a `claimed-key` answer is a statement about
    // one row at one moment, so keying it to a branch would make the same answer
    // unavailable to the next branch that needs it. That reading is now spelled
    // `key = "branch"` on the declaring row rather than built in (CLOUD-859), and
    // the subject is the other component of the filename.
    let git = std::path::Path::new("/repo/.git");
    assert!(
        facts::sourced_path(git, "claimed-key", "CLOUD-776")
            .ends_with("batten-receipts/fact.claimed-key.CLOUD-776")
    );
    // TWO KEYINGS, TWO FILES, which is the whole of what "the key is read" means
    // here: a record minted under one subject is simply absent under another, and
    // `facts::sourced` already turns absence into could-not-look.
    assert_ne!(
        facts::sourced_path(git, "review-answered", "0f1e2d3"),
        facts::sourced_path(git, "review-answered", "claude/some-branch")
    );
    // Neither component may escape the directory: a fact name may carry a `/` and
    // a branch name routinely does.
    assert!(
        facts::sourced_path(git, "a/b", "claude/c").ends_with("batten-receipts/fact.a-b.claude-c")
    );
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

// --- CLOUD-993: the declaration carries the expectation ---------------------
//
// Every case above asks what `rows_in` INFERS from a buffer. Every case below
// asks whether the buffer satisfies a shape somebody DECLARED. That is the whole
// distinction the row exists for: three inference defects in two days, each
// producing a plausible number rather than an error, is the argument for moving
// the contract to the dispatch.

#[test]
fn a_declared_json_array_counts_its_elements_and_an_empty_one_is_a_genuine_zero() {
    // The reading a review gate rests on. `rows == 0` has to mean "the command
    // looked and found none" rather than "nobody looked", or the predicate is
    // vacuous in exactly the direction that passes an unreviewed head.
    assert_eq!(
        facts::rows_declared(
            &shell("[{\"n\":1},{\"n\":2},{\"n\":3}]"),
            Returns::JsonArray
        ),
        Look::Is(3)
    );
    assert_eq!(
        facts::rows_declared(&shell("[]"), Returns::JsonArray),
        Look::Is(0)
    );
}

#[test]
fn prose_under_a_json_contract_is_could_not_look_and_never_one_row() {
    // THE CASE THIS ROW EXISTS FOR, and the one that separates it from
    // CLOUD-992's interim reading. That reading counted an unparseable buffer as
    // one opaque row — fail-closed, but it conflates "the command returned one
    // row" with "the command returned prose I could not read". A declared
    // command that quietly stops emitting JSON then reads as one row forever,
    // silently making a `rows == 0` gate unsatisfiable, and nothing reports it.
    for prose in [
        "gh version 2.97.0 (2026-07-31)\n",
        "error: could not resolve host\n",
        "[task] $ printf '[1,2,3]'\n[1,2,3]\n",
    ] {
        assert_eq!(
            facts::rows_declared(&shell(prose), Returns::JsonArray),
            Look::CouldNotLook,
            "{prose:?} does not satisfy the json-array it declares"
        );
        // And the interim reading really would have counted it, which is what
        // makes this a change rather than a restatement.
        assert_eq!(facts::rows_in(&shell(prose)), Look::Is(1));
    }
}

#[test]
fn a_json_object_under_json_array_is_refused_which_is_the_missing_projection() {
    // `gh api graphql` emits `{"data":{…}}`. Under the inferring reader that is
    // one row and looks entirely fine, so a fact whose command forgot its
    // `--jq '[…]'` projection reports a plausible count forever. Declaring the
    // array is what turns that from folklore into a refusal.
    assert_eq!(
        facts::rows_declared(&shell("{\"data\":{\"repository\":{}}}"), Returns::JsonArray),
        Look::CouldNotLook
    );
    // The same buffer under `json` is legitimate and counts as one element, so
    // the two vocabularies cannot collapse into each other.
    assert_eq!(
        facts::rows_declared(&shell("{\"data\":{\"repository\":{}}}"), Returns::Json),
        Look::Is(1)
    );
    // And `json` still counts an array's length, or it would just be `opaque`.
    assert_eq!(
        facts::rows_declared(&shell("[1,2,3,4]"), Returns::Json),
        Look::Is(4)
    );
}

#[test]
fn opaque_disclaims_the_shape_so_an_answer_is_one_row_whatever_it_looks_like() {
    // `Opaque` is a DECLARATION, not an escape back to inference. An answer is
    // one opaque answer; an empty buffer is could-not-look.
    assert_eq!(
        facts::rows_declared(&shell("gh version 2.97.0\n"), Returns::Opaque),
        Look::Is(1)
    );
    assert_eq!(
        facts::rows_declared(&shell(""), Returns::Opaque),
        Look::CouldNotLook
    );

    // THE DISCRIMINATING CASE, and the one this test used to get wrong by
    // asserting agreement with `rows_in`. A buffer that HAPPENS to look like a
    // JSON array is still a shape nobody declared, so counting its elements is
    // the inference `Returns` exists to end — `rows_in` says two, and two is a
    // claim about a contract the row explicitly declined to make. Asserting
    // equality with `rows_in` could not discriminate: it passed under any
    // behaviour `rows_in` had, which is a test of a copy rather than of a rule.
    assert_eq!(
        facts::rows_declared(&shell("[1,2]"), Returns::Opaque),
        Look::Is(1),
        "an opaque contract counts an answer, never the elements of a shape it disclaimed"
    );
    assert_eq!(
        facts::rows_in(&shell("[1,2]")),
        Look::Is(2),
        "the inferring reader still infers; that is what makes the two readings different"
    );
}

#[test]
fn an_empty_buffer_is_could_not_look_under_every_declaration() {
    // A command that printed nothing said nothing, whatever it promised. `0`
    // here would let an unreviewed head through under `json-array`, which is the
    // one place the three-valued reading is load-bearing.
    for returns in [Returns::JsonArray, Returns::Json, Returns::Opaque] {
        assert_eq!(
            facts::rows_declared(&shell("   \n\t "), returns),
            Look::CouldNotLook,
            "{returns:?} over whitespace"
        );
    }
}

#[test]
fn the_declared_reading_sees_an_mcp_envelope_too_not_only_a_shell_one() {
    // The declaration is about the COMMAND's output shape; where the harness
    // keeps that output is a different axis, and `decode_response` owns it. So a
    // content-block envelope carrying a JSON array satisfies `json-array` just
    // as a shell envelope does — otherwise the field would silently mean
    // "shell only" and an MCP-sourced fact could never declare a shape.
    let mcp = serde_json::json!([{ "type": "text", "text": "[{\"n\":1},{\"n\":2}]" }]);
    assert_eq!(facts::rows_declared(&mcp, Returns::JsonArray), Look::Is(2));
    let mcp_prose = serde_json::json!([{ "type": "text", "text": "not json" }]);
    assert_eq!(
        facts::rows_declared(&mcp_prose, Returns::JsonArray),
        Look::CouldNotLook
    );
}

#[test]
fn no_byte_of_a_mismatched_buffer_is_available_to_the_verdict() {
    // Rule 4 at the point it would break. A buffer that failed to parse is the
    // likeliest thing in the envelope to be holding a secret, so the mismatch
    // verdict must carry nothing from it — the caller renders the fact's name
    // and the declared shape, both of which come from config.
    let secret = "ghp_PLANTEDSECRETVALUE";
    let verdict = facts::rows_declared(&shell(secret), Returns::JsonArray);
    assert_eq!(verdict, Look::CouldNotLook);
    // `Look<usize>` has nowhere to put a byte, which is the structural half of
    // the guarantee rather than a promise about a format string.
    let rendered = format!("{verdict:?}");
    assert!(!rendered.contains(secret), "got: {rendered}");
}

// ---------------------------------------------------------------------------
// CLOUD-690: counting the elements of a result that match a predicate.
//
// The reading these cover is the one `rows_declared` cannot express. It counts
// EVERY element of a result, so a gate whose question is *how many are still
// unresolved* reads a head with all its threads answered as still blocking — the
// count is not inconvenient there, it is wrong. `[[mint]]`'s `requires` cannot
// stand in either: it asserts presence, never a number and never an absence.
//
// The discriminating pair is stated first and deliberately: a suite that only
// ever asserted a refusal would pass over a predicate that matched everything.
// ---------------------------------------------------------------------------

/// A row that counts `counts`'s elements satisfying `clauses`.
fn counting(counts: &str, clauses: &[(&str, facts::Literal)], returns: Returns) -> facts::Declared {
    facts::Declared {
        name: "review-answered".to_owned(),
        command: None,
        tool: Some("pull_request_read".to_owned()),
        counts: Some(counts.to_owned()),
        matching: clauses
            .iter()
            .map(|(path, wanted)| ((*path).to_owned(), wanted.clone()))
            .collect(),
        blocking: std::collections::BTreeMap::new(),
        returns,
    }
}

/// The same row with conditions declared beside the collection (CLOUD-690).
fn guarding(
    counts: &str,
    clauses: &[(&str, facts::Literal)],
    guards: &[(&str, facts::Literal)],
) -> facts::Declared {
    let mut declared = counting(counts, clauses, Returns::Json);
    declared.blocking = guards
        .iter()
        .map(|(path, wanted)| ((*path).to_owned(), wanted.clone()))
        .collect();
    declared
}

/// The measured shape: a thread as `pull_request_read` reports one.
fn threads(resolved: &[bool]) -> serde_json::Value {
    serde_json::json!({
        "review_threads": resolved
            .iter()
            .map(|is_resolved| serde_json::json!({
                "id": "PRRT_PLANTED", "is_resolved": is_resolved, "is_outdated": false,
            }))
            .collect::<Vec<_>>(),
    })
}

#[test]
fn the_discriminating_pair_counts_the_matching_elements_and_not_the_collection() {
    let declared = counting(
        "review_threads",
        &[("is_resolved", facts::Literal::Bool(false))],
        Returns::Json,
    );
    // Two unresolved beside three that are not.
    let result = threads(&[false, true, true, false, true]);
    assert_eq!(facts::counted(&result, &declared), Look::Is(2));
    // THE CONTRAST, stated rather than implied: the same collection with the
    // predicate removed counts every element. Five is what an unfiltered reading
    // answers, and a gate acting on five would refuse a head whose threads are
    // all answered — the defect this primitive exists for.
    let unfiltered = counting("review_threads", &[], Returns::Json);
    assert_eq!(facts::counted(&result, &unfiltered), Look::Is(5));
}

#[test]
fn a_predicate_matching_nothing_is_a_genuine_zero_and_never_could_not_look() {
    // THE OTHER HALF OF THE PAIR, and the one a deny-only suite would never
    // notice. A non-empty collection every element of which fails the predicate
    // is the only reading that may let a gate pass, so it must be `Is(0)` and not
    // the could-not-look every failure above answers.
    let declared = counting(
        "review_threads",
        &[("is_resolved", facts::Literal::Bool(false))],
        Returns::Json,
    );
    assert_eq!(
        facts::counted(&threads(&[true, true]), &declared),
        Look::Is(0)
    );
}

#[test]
fn an_absent_counts_path_is_could_not_look_and_never_zero() {
    // CLOUD-310 defect 1 — a scanner that found nothing and exited `0` — is this
    // row's own inherited constraint. The eight sibling methods of the declared
    // tool return no such member at all, so this is the shape a real session
    // produces by asking for the diff instead of the threads.
    let declared = counting(
        "review_threads",
        &[("is_resolved", facts::Literal::Bool(false))],
        Returns::Json,
    );
    let elsewhere = serde_json::json!({ "files": [{ "filename": "src/lib.rs" }] });
    assert_eq!(facts::counted(&elsewhere, &declared), Look::CouldNotLook);
}

#[test]
fn a_counts_path_that_is_not_an_array_is_could_not_look() {
    // Present and unreadable is not zero either: a tool whose response shape
    // changed under the row must not become a plausible count.
    let declared = counting(
        "review_threads",
        &[("is_resolved", facts::Literal::Bool(false))],
        Returns::Json,
    );
    let reshaped = serde_json::json!({ "review_threads": { "total": 0 } });
    assert_eq!(facts::counted(&reshaped, &declared), Look::CouldNotLook);
}

#[test]
fn a_path_selecting_several_collections_is_could_not_look() {
    // A path that selects more than one array is a path the consumer wrote
    // expecting one collection. Summing them would answer a question nobody
    // asked, and answering it silently is how a wrong number becomes a verdict.
    let declared = counting(
        "pages[].review_threads",
        &[("is_resolved", facts::Literal::Bool(false))],
        Returns::Json,
    );
    let paged = serde_json::json!({
        "pages": [
            { "review_threads": [{ "is_resolved": false }] },
            { "review_threads": [{ "is_resolved": false }] },
        ],
    });
    assert_eq!(facts::counted(&paged, &declared), Look::CouldNotLook);
}

#[test]
fn an_empty_where_counts_every_element_which_is_a_genuine_reading() {
    // *How many elements are there* is a real question, so an empty clause map is
    // not a missing predicate. Asserted because the alternative — treating it as
    // unconfigured and matching nothing — would make an omitted `where` a silent
    // permanent zero.
    let declared = counting("review_threads", &[], Returns::Json);
    assert_eq!(
        facts::counted(&threads(&[false, true, true]), &declared),
        Look::Is(3)
    );
}

#[test]
fn a_row_declaring_no_counts_behaves_exactly_as_it_did_before() {
    // CLOUD-690's Acceptance clause, and the reason `counted` is the one entry
    // point rather than a second reader beside `rows_declared`.
    let mut declared = counting("review_threads", &[], Returns::JsonArray);
    declared.counts = None;
    declared.matching.clear();
    let array = serde_json::json!(["PRRT_a", "PRRT_b"]);
    assert_eq!(
        facts::counted(&array, &declared),
        facts::rows_declared(&array, Returns::JsonArray)
    );
}

#[test]
fn the_clause_is_typed_so_a_quoted_false_does_not_match_a_boolean() {
    // The reason `Literal` is three variants rather than a string. A config that
    // spelled the value `"false"` would look right and decide wrong — every
    // thread matching, every head refusing — and the `where` a consumer reads
    // back would not tell them why.
    let typed = counting(
        "review_threads",
        &[("is_resolved", facts::Literal::Bool(false))],
        Returns::Json,
    );
    let stringly = counting(
        "review_threads",
        &[("is_resolved", facts::Literal::Text("false".to_owned()))],
        Returns::Json,
    );
    let result = threads(&[false, false]);
    assert_eq!(facts::counted(&result, &typed), Look::Is(2));
    assert_eq!(facts::counted(&result, &stringly), Look::Is(0));
}

#[test]
fn a_clause_over_an_absent_member_excludes_the_element_rather_than_matching_it() {
    // A `where` naming a member the element does not carry must not read as
    // vacuously true: that would make a mistyped path count everything, which is
    // the widest possible false green and the one hardest to see in config.
    let declared = counting(
        "review_threads",
        &[("resolved", facts::Literal::Bool(false))],
        Returns::Json,
    );
    assert_eq!(
        facts::counted(&threads(&[false, false]), &declared),
        Look::Is(0)
    );
}

#[test]
fn the_declared_shape_decides_before_the_path_does() {
    // `returns` stays READ on this path rather than becoming a column the
    // counting reading steps over — the accepted-and-unread defect this channel
    // has shipped twice (CLOUD-993, CLOUD-859). Under `json-array` the buffer
    // itself must be the array, so an object is a mismatch even though the path
    // would have resolved inside it.
    let object = threads(&[false, false]);
    let permissive = counting(
        "review_threads",
        &[("is_resolved", facts::Literal::Bool(false))],
        Returns::Json,
    );
    let strict = counting(
        "review_threads",
        &[("is_resolved", facts::Literal::Bool(false))],
        Returns::JsonArray,
    );
    assert_eq!(facts::counted(&object, &permissive), Look::Is(2));
    assert_eq!(facts::counted(&object, &strict), Look::CouldNotLook);
}

#[test]
fn counts_beside_an_opaque_contract_is_refused_at_load() {
    // The third value cannot be reconciled rather than merely being pointless: a
    // path is a claim about a shape `opaque` disclaims, so one of the two decides
    // and the other is read by nothing. Refused where a load error can still be
    // fixed, never resolved by precedence.
    let refused = counting(
        "review_threads",
        &[("is_resolved", facts::Literal::Bool(false))],
        Returns::Opaque,
    );
    // `let Err(..) else { panic! }` rather than `expect_err`: this file carries no
    // `clippy::expect_used` allow and does not need one — a panic on a shape the
    // test is about is the same failure, loudly, and is how the case above it
    // reads too.
    let Err(error) = facts::validate(std::slice::from_ref(&refused)) else {
        panic!("`counts` beside `opaque` must not load");
    };
    let rendered = error.to_string();
    assert!(rendered.contains("review-answered"), "got: {rendered}");
    assert!(rendered.contains("opaque"), "got: {rendered}");
    // And the two shapes it CAN carry both load, or the conjunct would be a ban
    // on counting rather than on the contradiction.
    for returns in [Returns::Json, Returns::JsonArray] {
        let allowed = counting(
            "review_threads",
            &[("is_resolved", facts::Literal::Bool(false))],
            returns,
        );
        assert!(facts::validate(std::slice::from_ref(&allowed)).is_ok());
    }
}

#[test]
fn the_mcp_envelope_is_lifted_before_the_path_is_walked() {
    // The measured half, and the reason `counted` reuses `payload_in` rather than
    // reading `result.get(..)`: a mint that skipped this passed every fixture and
    // matched nothing at all in production, because the connector wraps every
    // response in content blocks (CLOUD-1024). A fixture handing over a bare
    // object cannot see that, so the envelope is what this case hands over.
    let declared = counting(
        "review_threads",
        &[("is_resolved", facts::Literal::Bool(false))],
        Returns::Json,
    );
    let wrapped = serde_json::json!({
        "content": [{
            "type": "text",
            "text": threads(&[false, true, false]).to_string(),
        }],
    });
    assert_eq!(facts::counted(&wrapped, &declared), Look::Is(2));
}

#[test]
fn no_matched_element_reaches_the_verdict() {
    // Rule 4 at the point it would break. A `where` names a member by path, and
    // the values at those paths are exactly the kind of content a consumer might
    // be counting without wanting to carry — so the return is a count and there
    // is structurally nowhere for a byte to go.
    let secret = "ghp_PLANTEDSECRETVALUE";
    let declared = counting(
        "rows",
        &[("kind", facts::Literal::Text("token".to_owned()))],
        Returns::Json,
    );
    let result = serde_json::json!({ "rows": [{ "kind": "token", "value": secret }] });
    let verdict = facts::counted(&result, &declared);
    assert_eq!(verdict, Look::Is(1));
    let rendered = format!("{verdict:?}");
    assert!(!rendered.contains(secret), "got: {rendered}");
}

// ---------------------------------------------------------------------------
// A condition BESIDE the collection (CLOUD-690's `blocking`), which restores what
// CLOUD-859's `--jq` projection carried and `counts`/`where` structurally cannot.
// ---------------------------------------------------------------------------

/// The measured payload, with the page flag the guard reads.
fn paged(resolved: &[bool], truncated: bool) -> serde_json::Value {
    let mut payload = threads(resolved);
    payload["pageInfo"] = serde_json::json!({ "hasNextPage": truncated });
    payload
}

#[test]
fn the_discriminating_pair_for_a_guard_is_the_same_threads_and_a_different_page() {
    // THE CASE THE WHOLE COLUMN EXISTS FOR. Both heads have every thread resolved,
    // so the element count is zero on each; only the truncated one may refuse. If
    // `blocking` were not read, the two would be indistinguishable — which is
    // exactly the false green that shipped when the projection was dropped.
    let declared = guarding(
        "review_threads",
        &[("is_resolved", facts::Literal::Bool(false))],
        &[("pageInfo.hasNextPage", facts::Literal::Bool(true))],
    );
    assert_eq!(
        facts::counted(&paged(&[true, true], false), &declared),
        Look::Is(0),
        "a complete page with nothing unresolved is the genuine zero"
    );
    assert_eq!(
        facts::counted(&paged(&[true, true], true), &declared),
        Look::Is(1),
        "an unread page is one blocking condition, not a zero"
    );
}

#[test]
fn a_guard_adds_to_the_element_count_rather_than_replacing_it() {
    // The arithmetic the projection did by emitting one more element. Two
    // unresolved threads on a truncated page is three blocking conditions, and a
    // consumer's `rows > 0` reads all three the same way — which is why this adds
    // rather than short-circuiting to a refusal here.
    let declared = guarding(
        "review_threads",
        &[("is_resolved", facts::Literal::Bool(false))],
        &[("pageInfo.hasNextPage", facts::Literal::Bool(true))],
    );
    assert_eq!(
        facts::counted(&paged(&[false, true, false], true), &declared),
        Look::Is(3)
    );
}

#[test]
fn a_guard_over_an_absent_path_adds_nothing_rather_than_refusing() {
    // The fail-open direction, and deliberately the opposite of `counts`' own. A
    // mistyped `counts` path is could-not-look, because the collection is the
    // question; a mistyped `blocking` path leaves the gate exactly as strong as it
    // was without the column, rather than refusing every call over a clause
    // nothing can satisfy.
    let declared = guarding(
        "review_threads",
        &[],
        &[("pageInfo.hasMorePages", facts::Literal::Bool(true))],
    );
    assert_eq!(
        facts::counted(&paged(&[true], true), &declared),
        Look::Is(1),
        "one element, and the unresolvable guard contributes nothing"
    );
}

#[test]
fn a_guard_is_typed_and_directional_like_every_other_clause() {
    // `hasNextPage = false` must not match `true`, and the guard fires only on the
    // value the row named — otherwise a complete page would count as blocking and
    // the gate would refuse every head forever.
    let declared = guarding(
        "review_threads",
        &[],
        &[("pageInfo.hasNextPage", facts::Literal::Bool(false))],
    );
    assert_eq!(facts::counted(&paged(&[], true), &declared), Look::Is(0));
    assert_eq!(facts::counted(&paged(&[], false), &declared), Look::Is(1));
}

#[test]
fn blocking_without_counts_is_refused_at_load() {
    // `where`'s refusal for `where`'s reason: with no collection there is no count
    // for a condition to add to, so the clauses would be read by nothing.
    let mut orphaned = guarding(
        "review_threads",
        &[],
        &[("pageInfo.hasNextPage", facts::Literal::Bool(true))],
    );
    orphaned.counts = None;
    let Err(error) = facts::validate(std::slice::from_ref(&orphaned)) else {
        panic!("`blocking` with no `counts` must not load");
    };
    let rendered = error.to_string();
    assert!(rendered.contains("review-answered"), "got: {rendered}");
    assert!(rendered.contains("blocking"), "got: {rendered}");
}

#[test]
fn no_value_at_a_guard_path_reaches_the_verdict() {
    // Rule 4 on the new surface, asserted where it would break: a guard NAMES a
    // path, and what sits there is compared and dropped.
    let secret = "ghp_PLANTEDSECRETVALUE";
    let declared = guarding(
        "review_threads",
        &[],
        &[("token", facts::Literal::Text(secret.to_owned()))],
    );
    let mut payload = threads(&[true]);
    payload["token"] = serde_json::json!(secret);
    let verdict = facts::counted(&payload, &declared);
    assert_eq!(
        verdict,
        Look::Is(2),
        "one element plus the guard that holds"
    );
    let rendered = format!("{verdict:?}");
    assert!(!rendered.contains(secret), "got: {rendered}");
}

// ---------------------------------------------------------------------------
// `counts = "."` — the payload itself (CLOUD-690).
// ---------------------------------------------------------------------------

#[test]
fn the_root_spelling_counts_a_bare_top_level_array() {
    // The measured shape this exists for: `pull_request_read`'s `get_reviews`
    // answers with a bare array rather than an object, so there is no member to
    // name and the collection IS the payload.
    let declared = counting(".", &[], Returns::JsonArray);
    let reviews = serde_json::json!([
        { "state": "CHANGES_REQUESTED", "user": { "login": "a" } },
        { "state": "COMMENTED", "user": { "login": "b" } },
    ]);
    assert_eq!(facts::counted(&reviews, &declared), Look::Is(2));
    // And an empty array is the genuine zero the consuming predicate rests on.
    assert_eq!(
        facts::counted(&serde_json::json!([]), &declared),
        Look::Is(0)
    );
}

#[test]
fn the_root_spelling_still_takes_a_where_clause() {
    // Nothing about naming the root changes the element predicate, or the column
    // would be a second counting mode rather than a path.
    let declared = counting(
        ".",
        &[("state", facts::Literal::Text("APPROVED".to_owned()))],
        Returns::JsonArray,
    );
    let reviews = serde_json::json!([
        { "state": "APPROVED" },
        { "state": "COMMENTED" },
        { "state": "APPROVED" },
    ]);
    assert_eq!(facts::counted(&reviews, &declared), Look::Is(2));
}

#[test]
fn the_root_spelling_is_could_not_look_over_a_payload_that_is_not_an_array() {
    // `.` names the payload; it does not promise the payload is a collection. An
    // object there is the same could-not-look a named path holding one would be.
    let declared = counting(".", &[], Returns::Json);
    assert_eq!(
        facts::counted(&threads(&[true]), &declared),
        Look::CouldNotLook
    );
}

#[test]
fn an_empty_counts_path_is_still_refused_and_is_not_the_root() {
    // The root spelling is one explicit token, deliberately not the empty string:
    // an omitted value must stay a load error rather than silently meaning "the
    // whole payload".
    let mut empty = counting(".", &[], Returns::JsonArray);
    empty.counts = Some(String::new());
    let Err(error) = facts::validate(std::slice::from_ref(&empty)) else {
        panic!("an empty `counts` must not load");
    };
    assert!(error.to_string().contains("counts"), "{error}");
}
