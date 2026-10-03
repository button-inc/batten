//! No assertion reads the clock.
//!
//! # The rule, and what it replaced
//!
//! Time is an input to a case — a bound it imposes, a deadline its poll gives up
//! at — and never what it asserts. A ceiling on elapsed time asserts about the
//! scheduler and flakes on a loaded runner; a floor cannot flake that way, but it
//! still stands in for the outcome it guesses at, and that outcome is recorded.
//! CLOUD-2059 replaced every clock assertion this tree carried with the record:
//!
//! - a handler or session step killed at its bound: its `exceeded … and was
//!   killed` line (`cli.rs`, `session_provisioning.rs`);
//! - a second signal escalating: exec's `group escalated to SIGKILL
//!   (second-signal)`. The clock version of that case was vacuous — the group
//!   emptied on its own, inside the ceiling, with no escalation at all;
//! - two leaked pipes sharing one drain budget: the second's `within 0ns`;
//! - a fetch ended by its bound: `fetch: timed out`, where a fast failure
//!   names the request instead (`provision.rs`);
//! - a sweep's suite timing out: `suite-timed-out` (`mutate.rs`);
//! - a server's poll floor: the pause the loop records, in-process
//!   (`pr_watch::tests`).
//!
//! # Why `syn`
//!
//! "Is this clock read inside what the assertion asserts, or in its message" is
//! a syntax question (`rules/scanning.md` row two). A text search cannot tell an
//! `assert!`'s condition from its format arguments, nor a read from a string
//! quoting one. The predicates live in `batten::testing`, where the sweep shows
//! each one red.

use crate::common;

use batten::testing::{ClockCensus, clock_census};

fn census(source: &str) -> ClockCensus {
    clock_census(&syn::parse_file(source).expect("the fixture parses"))
}

#[test]
fn no_assertion_in_the_crate_reads_the_clock() {
    let root = common::at_root("crates/batten");
    let sources = common::rust_sources();
    let (mut judged, mut clocked, mut offenders) = (0, 0, Vec::new());
    for path in &sources {
        let source = std::fs::read_to_string(path).expect("read a crate source");
        let found = clock_census(&syn::parse_file(&source).expect("every crate source parses"));
        judged += found.judged;
        clocked += found.clocked;
        let relative = path.strip_prefix(&root).unwrap_or(path).display();
        offenders.extend(
            found
                .refused
                .iter()
                .map(|function| format!("{relative}: {function} asserts on the clock")),
        );
        offenders.extend(
            found
                .unparsed
                .iter()
                .map(|function| format!("{relative}: {function} holds an unparsed assertion")),
        );
    }

    // ANTI-VACUITY, on both halves the verdict rests on. Assertions are counted
    // in the tens of thousands; a census that stopped matching the macro sees
    // none. The clock is read into a local about 40 times across the crate —
    // every deadline a poll gives up at — and a census that stopped recognising
    // a read binds none, and would then pass every assertion it judged.
    assert!(
        judged > 10_000,
        "judged only {judged} assertions across {} sources — the census is not \
         reading the crate it guards",
        sources.len()
    );
    assert!(
        clocked > 20,
        "saw only {clocked} locals bound from a clock read — the census no longer \
         recognises one"
    );
    assert!(
        offenders.is_empty(),
        "an assertion reads the clock; assert the outcome it stands in for:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn an_upper_bound_on_elapsed_is_refused() {
    let found = census("fn case() { let s = start(); assert!(s.elapsed() < LIMIT); }");
    assert_eq!(found.refused, ["case"]);
}

#[test]
fn a_lower_bound_on_elapsed_is_refused_too() {
    // A floor cannot flake on a slow runner, but it guesses at an outcome the
    // code records, and every floor this tree had was replaced by that record.
    let found = census("fn case() { assert!(started.elapsed() >= bound, \"waited\"); }");
    assert_eq!(found.refused, ["case"]);
}

#[test]
fn a_deadline_asserted_against_now_is_refused() {
    let found = census("fn case() { assert!(std::time::Instant::now() < DEADLINE); }");
    assert_eq!(found.refused, ["case"]);
}

#[test]
fn a_clock_read_through_a_local_is_refused() {
    let found = census(
        "fn case() { let took = timer.elapsed(); assert!(took < LIMIT); }\n\
         fn poll() { let (deadline, limit) = (Instant::now() + P, 0); assert!(ready() || deadline > LIMIT); }",
    );
    assert_eq!(found.refused, ["case", "poll"]);
    assert_eq!(found.clocked, 3, "`took`, then both names the tuple binds");
}

#[test]
fn an_equality_on_the_clock_is_refused() {
    let found = census("fn case() { assert_eq!(0, s.elapsed().as_secs()); }");
    assert_eq!(found.refused, ["case"]);
}

#[test]
fn the_clock_in_a_message_is_not_asserted() {
    let found = census(
        "fn case() { assert!(n <= m, \"{:?}\", s.elapsed()); assert_eq!(a, b, \"{:?}\", Instant::now()); }",
    );
    assert_eq!(found.judged, 2);
    assert!(found.refused.is_empty(), "{:?}", found.refused);
}

#[test]
fn a_constant_duration_is_not_a_clock() {
    // `exec.rs`'s own shape: a constant compared with a constant.
    let found = census("fn case() { assert!(GROUP_GRACE >= Duration::from_secs(5)); }");
    assert!(found.refused.is_empty(), "{:?}", found.refused);
}

#[test]
fn a_clock_bounding_a_poll_is_an_input() {
    // The sanctioned shape: the clock ends the poll, and the case asserts the
    // state the poll found.
    let found = census(
        "fn case() { let deadline = Instant::now() + P; let mut found = None;\n\
         while found.is_none() && Instant::now() < deadline { found = probe(); }\n\
         assert!(found.is_some(), \"never appeared\"); }",
    );
    assert_eq!(found.clocked, 1);
    assert!(found.refused.is_empty(), "{:?}", found.refused);
}

#[test]
fn a_clocked_name_is_the_functions_own() {
    let found = census(
        "fn first() { let t = Instant::now(); drop(t); }\n\
         fn second() { let t = 3; assert_eq!(t, 3); }",
    );
    assert!(found.refused.is_empty(), "{:?}", found.refused);
}

#[test]
fn a_clock_quoted_in_a_string_is_not_a_reading() {
    let found = census("fn case() { assert!(text.contains(\"s.elapsed() < LIMIT\")); }");
    assert!(found.refused.is_empty(), "{:?}", found.refused);
}
