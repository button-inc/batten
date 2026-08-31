//! The host's rule-injection event, and the census over it (CLOUD-1054, CLOUD-1052).
//!
//! # What was actually established, and how
//!
//! CLOUD-1054 asked one question: does the host expose a stable, source-bearing
//! event when it delivers a `.claude/rules/*.md` document, or does it not? The
//! answer is **yes**, and `memory-injection.jsonl.in` is the evidence — a real
//! transcript from a real session, minimally redacted, not a shape invented here.
//!
//! The record is:
//!
//! ```text
//! {"type":"attachment","attachment":{
//!   "type":"nested_memory",
//!   "displayPath":".claude/rules/scanning.md",
//!   "content":{"type":"Project","content":"<the whole document>"}}}
//! ```
//!
//! Two typed host fields — a tag and a source path — so nothing here reads prose.
//!
//! # Why the earlier answer was the opposite, and why that matters here
//!
//! A first probe of the same session said the host exposed no such event. It was
//! taken at 158 records, before any trigger had fired; at 1,915 records there were
//! six. **That is the whole argument for a captured fixture over an assertion**,
//! and it is why the negative control below is a real file rather than a claim:
//! an absence measured on too small a sample is indistinguishable from a
//! capability that is not there.
//!
//! # The redaction, and what survives it
//!
//! `content.content` and `rawContent` carry the delivered document in full — the
//! richest payload this engine can be pointed at. Both are replaced with a fixed
//! marker, and the absolute paths are rewritten to `/w/` so the fixture is not
//! tied to one container. The envelope, the tag and the source path survive,
//! because those are the fields the predicate reads.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::fs;

use batten::transcript::{self, Capability, Event};

/// Materialize a committed `.jsonl.in` fixture and parse it.
///
/// **The scratch directory is unique per CALL, not per fixture**, and that is a
/// correctness requirement rather than tidiness. `common::scratch` wipes before
/// it writes, and six cases in this file read `memory-injection` — so keyed by
/// fixture alone, any two of them running in parallel clear each other's
/// directory and the copy below fails `NotFound`. Measured: 9/9 green under
/// `--test-threads=1`, two cases red in parallel, and a different pair each run,
/// which is the signature of the race rather than of a fixture.
///
/// **The seat counter alone did not close that, and the claim that it had is why
/// it stood** (CLOUD-1243). `NEXT` is a per-PROCESS static, and `cargo nextest`
/// — the runner `mise run test:cargo` drives — gives every case its own process,
/// so all six computed seat 0 and the race stayed exactly as open. It reproduced
/// on a `verify` lap that followed one passing 3301/3301, which is the signature
/// again. `--test-threads=1` is a libtest reading and says nothing about the
/// runner actually in use, so the measurement above was true and irrelevant.
fn stream(fixture: &str) -> transcript::Stream {
    use std::sync::atomic::{AtomicUsize, Ordering};

    static NEXT: AtomicUsize = AtomicUsize::new(0);

    let source = common::at_root(&format!(
        "crates/batten/tests/fixtures/transcripts/{fixture}.jsonl.in"
    ));
    // THE PID IS THE LOAD-BEARING HALF, and the seat alone was not (CLOUD-1243).
    // `NEXT` is a per-PROCESS static, and `cargo nextest` runs every case in its
    // own process -- so all six cases reading this fixture computed seat 0,
    // landed on one directory, and `make_empty` wiped it under whichever was
    // mid-copy. The seat stays for the in-process runner, where two cases really
    // do share the counter; the pid is what makes the name unique under the
    // runner this repository actually uses.
    let seat = NEXT.fetch_add(1, Ordering::Relaxed);
    let dir = common::scratch(&format!(
        "memory-injection-{fixture}-{}-{seat}",
        std::process::id()
    ));
    let path = dir.join("transcript.jsonl");
    fs::copy(&source, &path).expect("materialize the committed fixture");
    match transcript::resolve(&dir, Some("transcript.jsonl")) {
        Capability::Present(stream) => stream,
        other => panic!("fixture did not parse: {}", other.as_str()),
    }
}

// ---------------------------------------------------------------------------
// CLOUD-1054: the event exists, and it is source-bearing.
// ---------------------------------------------------------------------------

#[test]
fn the_captured_host_transcript_carries_source_bearing_injections() {
    let stream = stream("memory-injection");
    let injected: Vec<&str> = stream
        .records
        .iter()
        .filter_map(|record| match &record.event {
            Event::MemoryInjection { path } => Some(path.as_str()),
            _ => None,
        })
        .collect();

    // The exact multiset the host emitted, in file order. Asserted whole rather
    // than by shape: six-of-something and a `.md` suffix would both pass over a
    // parser that read the wrong field, and the point of a CAPTURED fixture is
    // that the expected value is known rather than described.
    assert_eq!(
        injected,
        vec![
            ".claude/rules/scanning.md",
            ".claude/rules/toolchain.md",
            ".claude/rules/scanning.md",
            ".claude/rules/rust.md",
            ".claude/rules/scanning.md",
            ".claude/rules/rust.md",
        ],
        "the captured session's injections, in order"
    );
}

/// The discriminator that makes a zero readable.
#[test]
fn a_host_emitting_the_event_is_reported_as_reporting_them() {
    assert!(stream("memory-injection").reports_memory_injections());
}

// ---------------------------------------------------------------------------
// The negative controls. Without these the parser could be matching anything.
// ---------------------------------------------------------------------------

/// **The one that proves no prose is being read.** The unsupported fixture holds
/// an assistant turn that names `.claude/rules/toolchain.md` in ordinary text. A
/// predicate that pattern-matched message bodies would count it; this must not.
#[test]
fn prose_naming_a_rules_file_is_not_an_injection() {
    let stream = stream("memory-injection-unsupported");
    assert!(
        stream.memory_injections().is_empty(),
        "a mention is not a delivery: {:?}",
        stream.memory_injections()
    );
}

/// An attachment carrying the tag but no source path records nothing, rather
/// than an injection with an invented source. The unsupported fixture's last
/// record is exactly that shape.
#[test]
fn the_tag_without_a_source_path_yields_no_event() {
    assert!(!stream("memory-injection-unsupported").reports_memory_injections());
}

/// Other attachment types in the same file — a token reminder, a hook result —
/// yield no injection. Forward compatibility: an unrecognized tag is silent.
#[test]
fn unrelated_attachment_types_are_silent() {
    let stream = stream("memory-injection-unsupported");
    assert!(
        !stream.records.is_empty(),
        "the fixture parsed to something, so silence is a decision and not an empty read"
    );
    assert!(stream.memory_injections().is_empty());
}

// ---------------------------------------------------------------------------
// CLOUD-1052: the census.
// ---------------------------------------------------------------------------

/// The measured census, per document. The breakdown is the deliverable — a bare
/// total would hide that one file repeats and another does not.
#[test]
fn the_census_counts_each_document_separately() {
    let census = stream("memory-injection").memory_injections();
    assert_eq!(
        census.get(".claude/rules/scanning.md").copied(),
        Some(3),
        "census: {census:?}"
    );
    assert_eq!(census.get(".claude/rules/rust.md").copied(), Some(2));
    assert_eq!(census.get(".claude/rules/toolchain.md").copied(), Some(1));
    assert_eq!(census.values().sum::<usize>(), 6);
}

/// Byte-stable under §6: keyed lexicographically, whatever order the host wrote.
#[test]
fn the_census_is_ordered_by_path() {
    let census = stream("memory-injection").memory_injections();
    let keys: Vec<&String> = census.keys().collect();
    let mut sorted = keys.clone();
    sorted.sort();
    assert_eq!(keys, sorted, "a census a script reads must not reorder");
}

/// **A zero from a host that DOES report is a fact about the session**, and this
/// is the pairing that makes it readable. The same empty census means something
/// different depending on the discriminator, so both are asserted together
/// rather than one standing in for the other.
#[test]
fn an_empty_census_and_an_unsupported_host_are_distinguishable() {
    let supported = stream("memory-injection");
    let unsupported = stream("memory-injection-unsupported");

    assert!(supported.reports_memory_injections());
    assert!(!supported.memory_injections().is_empty());

    assert!(!unsupported.reports_memory_injections());
    assert!(unsupported.memory_injections().is_empty());
}

/// Rule 4 at the fixture: the delivered document never reaches a record. The
/// redaction marker is in the file, so if the parser ever started carrying
/// bodies this would catch it.
#[test]
fn no_delivered_document_body_reaches_a_record() {
    let raw = fs::read_to_string(common::at_root(
        "crates/batten/tests/fixtures/transcripts/memory-injection.jsonl.in",
    ))
    .expect("read the committed fixture");
    assert!(
        raw.contains("RULE-DOCUMENT-BODY-REDACTED"),
        "the fixture still carries its redaction marker"
    );

    let rendered = format!("{:?}", stream("memory-injection").records);
    assert!(
        !rendered.contains("RULE-DOCUMENT-BODY-REDACTED"),
        "a record carries the source path and never the delivered body"
    );
}
