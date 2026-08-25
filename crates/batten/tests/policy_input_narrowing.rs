//! **A widened policy input must not widen what a call resolves** (CLOUD-834).
//!
//! # Why this is its own binary
//!
//! `git::queries_spawned()` is a process-global counter and cargo runs a test
//! file's cases inside one process. A delta measured beside cases that touch git
//! would pass or fail on scheduling. Cargo runs each integration test FILE as
//! its own process, so a file containing only these measures what it intends —
//! the same reason `policy_engine_count.rs` is separate.
//!
//! # Why a counter and not a clock
//!
//! CLOUD-834 §7(b) is explicit, and CLOUD-460 is why: one `receipt` row was
//! measured making *every* mediated call pay four git subprocesses, including
//! calls no receipt rule could gate. A git query is ~6.7ms against a 100ms
//! budget — inside the noise of a process start — so a timing assertion cannot
//! see it. `.claude/rules/rust.md` states the rule for this whole class.
//!
//! # The regression these cases bound
//!
//! Before CLOUD-834 the policy input was four `Cost::Free` envelope fields, and
//! its narrowness was mistaken for the safety property. It was not: the fact set
//! it now carries was **already resolved** at the boundary for the typed rule
//! table. The danger in projecting it is that someone later makes the projection
//! *acquire* — resolving a fact inside `call_document` because it is convenient
//! there. These are what would go red.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::Path;

use batten::hook::{Envelope, Harness, Policy};

/// A repository whose `batten.toml` registers one module and nothing else — no
/// receipt row, no keyed shape row, no waiver.
///
/// That is the pass-through shape the published `passthrough` figure describes:
/// a call the boundary has no question about. A repository with a policy row is
/// exactly the case CLOUD-834 changes, so it is the one measured here.
///
/// Built through `resolve` and [`Policy::from_resolved`] rather than by hand.
/// `Policy`'s fields are private, and that is the better shape anyway: this is
/// the route the binary takes, so the case cannot pass over a policy the
/// boundary would never assemble.
fn module_policy(dir: &Path) -> Policy {
    std::fs::create_dir_all(dir).expect("scratch");
    std::fs::write(
        dir.join("gate.rego"),
        "package batten.narrowing\n\
         import rego.v1\n\
         rules contains \"never\"\n\
         violation contains {\"rule\": \"never\", \"msg\": \"m\"} if {\n\
         \tinput.facts.receipts.verify == \"stale-head\"\n\
         }\n",
    )
    .expect("write module");
    std::fs::write(
        dir.join("batten.toml"),
        "version = 1\n\n\
         [[rule]]\n\
         id = \"narrowing\"\n\
         kind = \"policy\"\n\
         scope = \"mediated_call\"\n\
         module = \"gate.rego\"\n\
         severity = \"deny\"\n",
    )
    .expect("write config");
    let resolved = batten::resolve::resolve(dir, &batten::resolve::Overrides::default())
        .expect("the config resolves");
    Policy::from_resolved(&resolved, Harness::ExitCode, dir, None).expect("the policy assembles")
}

/// A pre-tool shell call, decoded from a real host payload.
///
/// `Envelope` is `#[non_exhaustive]`, so a struct literal is not available from
/// an integration test — and going through [`batten::hook::decode`] is the
/// better shape anyway: it is the route the binary itself takes, so this case
/// cannot pass over an envelope the decoder would never produce.
fn envelope(command: &str) -> Envelope {
    let payload = serde_json::json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": command},
    });
    batten::hook::decode(Harness::ClaudeCode, &payload.to_string()).expect("the payload decodes")
}

/// RETIRED (CLOUD-740). This measured the delta in `git::queries_spawned()`
/// across `adjudicate`, asserting the mediated path acquired no fact by spawning.
///
/// Its ANTI-VACUITY half is what retires it, and honourably: the case ended by
/// calling `git::repo_root` and asserting the counter MOVED, because "the count
/// did not change" is satisfied perfectly by a counter wired to nothing. Nothing
/// in this crate spawns `git` any more, so that half can never pass again — the
/// counter is gone with the spawns it counted, and a case that cannot discriminate
/// is exactly what CLOUD-418 refuses to ship as coverage.
///
/// What it asserted is now true of the WHOLE crate rather than of one function,
/// and is asserted where that is decidable: `git::tests::no_second_git_invoker_
/// exists` scans every `src/` file for a literal `git` spawn and finds none.

#[test]
fn a_mediated_call_policy_row_asks_the_boundary_for_no_fact_it_did_not_already_need() {
    // THE OTHER HALF, and the one a counter around `adjudicate` cannot see: the
    // boundary decides what to resolve BEFORE calling it, from
    // `required_checks_for` and `key_base_for`. Registering a policy row must
    // not add a question there — a module reads facts some other row paid for,
    // and never causes a read of its own.
    //
    // **SCOPED TO `RuleScope::MediatedCall`, AND THE SCOPE IS THE POINT**
    // (CLOUD-850). The fixture was mediated-call already, but the name and the
    // claim were unqualified, and the property MUST NOT generalize to the tree:
    // there, a policy row declaring `documents` or `sources` IS the demand
    // signal, and `acquire_declared` reads exactly what the rule set declared.
    // Read as a claim about policy rows in general, this would forbid the
    // capability CLOUD-850 exists to add.
    //
    // What survives unqualified is the narrower claim, which is the one worth
    // having: on the MEDIATED path a module is a passenger on facts some other
    // row already needed, because that path carries a 100ms budget per call and
    // the tree surface does not.
    //
    // Fails by: widening `matching_receipt_rows` to select policy rows, or
    // resolving the fact set unconditionally because "a module might want it".
    let dir = std::env::temp_dir().join(format!("batten-narrowing-rows-{}", std::process::id()));
    let policy = module_policy(&dir);
    let call = envelope("git status");

    assert!(
        policy.required_checks_for(&call).is_empty(),
        "a policy row must not make the boundary resolve a receipt"
    );
    assert_eq!(
        policy.key_base_for(&call),
        None,
        "a policy row must not make the boundary resolve key evidence"
    );
}
