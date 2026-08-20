//! CLOUD-773's §7 obligations: one rule reads another rule's derived **value**.
//!
//! The measured defect is a channel, not an author. 57 of 126 tasks in this
//! repository's shell layer invoke a sibling and branch on its exit code — one
//! predicate consuming another's verdict, over a channel carrying three states.
//! So a consumer that needs the producer's *structure* re-derives it:
//! `graph-check` spawns `ready-lint` and then re-spells the issue-key regex
//! three times, in a spelling that had already diverged.
//!
//! Every case here is about a value crossing the boundary, or about a refusal
//! landing at **load** rather than at adjudication.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use common::{Fixture, stderr, stdout};

/// A producer row deriving `rust-pin` from one document, and a reader row
/// comparing its own node against that value rather than against a literal.
fn agreeing_config() -> String {
    "version = 1\n\
     [[rule]]\n\
     id = \"pin-authority\"\n\
     kind = \"document\"\n\
     glob = \"pins.toml\"\n\
     format = \"toml\"\n\
     node = \"pin.rust\"\n\
     derives = \"rust-pin\"\n\
     pattern = \"1.97.1\"\n\
     severity = \"deny\"\n\
     [[rule]]\n\
     id = \"floor-agrees\"\n\
     kind = \"document\"\n\
     glob = \"floor.json\"\n\
     format = \"json\"\n\
     node = \"rust\"\n\
     reads = \"rust-pin\"\n\
     severity = \"deny\"\n"
        .to_owned()
}

#[test]
fn a_reader_agreeing_with_the_derived_value_is_clean() {
    // The capability itself: the second row never states `1.97.1`. It states
    // which value it must equal, and the engine resolves that once.
    let dir = Fixture::new("derived-agrees")
        .config(&agreeing_config())
        .file("pins.toml", "[pin]\nrust = \"1.97.1\"\n")
        .file("floor.json", "{\"rust\": \"1.97.1\"}")
        .build();
    let output = common::run(&dir, &["check"]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
}

#[test]
fn a_reader_disagreeing_with_the_derived_value_fails_and_points_at_itself() {
    // And the pointer is the READER's file, not the producer's: the row that is
    // wrong is the one that disagrees with the authority.
    let dir = Fixture::new("derived-disagrees")
        .config(&agreeing_config())
        .file("pins.toml", "[pin]\nrust = \"1.97.1\"\n")
        .file("floor.json", "{\"rust\": \"1.85.0\"}")
        .build();
    let output = common::run(&dir, &["check"]);
    assert_eq!(output.status.code(), Some(2));
    let both = format!("{}{}", stdout(&output), stderr(&output));
    assert!(both.contains("floor.json"), "the reader is the pointer");
    assert!(both.contains("floor-agrees"));
    // Pointer-only (rule 4): neither the derived value nor the read one travels.
    assert!(
        !both.contains("1.97.1"),
        "the derived value must not be reported"
    );
    assert!(!both.contains("1.85.0"), "nor the value it disagreed with");
}

#[test]
fn a_derivation_over_an_unlookable_base_is_could_not_look_and_not_false() {
    // CLOUD-251's vacuous pass, which is the case this whole issue turns on. The
    // producer's document does not parse, so `rust-pin` could not be looked at.
    // A comparison against "nothing" must NOT succeed — reading the absence as a
    // value that matches, or as a rule with nothing to say, is a gate reporting
    // agreement having seen nothing.
    //
    // Fails by: treating an unresolved derived value as "no finding" in
    // `document_in_file`, or by resolving it to an empty string.
    let dir = Fixture::new("derived-unlookable")
        .config(&agreeing_config())
        .file("pins.toml", "[pin\nrust = ")
        .file("floor.json", "{\"rust\": \"1.97.1\"}")
        .build();
    let output = common::run(&dir, &["check"]);
    assert_eq!(
        output.status.code(),
        Some(2),
        "a derivation that could not look must not read as agreement: {}",
        stderr(&output)
    );
    let both = format!("{}{}", stdout(&output), stderr(&output));
    assert!(both.contains("floor-agrees"), "the reader reports it");
}

#[test]
fn a_reference_nothing_derives_is_refused_at_load_with_a_located_pointer() {
    // house-style §8: a config fault is refused at load. Exit 1, the
    // config-or-usage class — never exit 2, which is a policy verdict about the
    // repository, and never at adjudication.
    let dir = Fixture::new("derived-undefined")
        .config(
            "version = 1\n\
             [[rule]]\n\
             id = \"floor-agrees\"\n\
             kind = \"document\"\n\
             glob = \"floor.json\"\n\
             format = \"json\"\n\
             node = \"rust\"\n\
             reads = \"rust-pin\"\n\
             severity = \"deny\"\n",
        )
        .file("floor.json", "{\"rust\": \"1.97.1\"}")
        .build();
    let output = common::run(&dir, &["check"]);
    assert_eq!(output.status.code(), Some(1), "a config fault is exit 1");
    let text = stderr(&output);
    assert!(text.contains("which no rule derives"));
    // The located half: `batten.toml:<line>`, the shape a finding already uses,
    // so a reader who can open one pointer can open this one.
    assert!(
        text.contains("batten.toml:3"),
        "the refusal points at the row's own line: {text}"
    );
}

#[test]
fn a_cycle_is_refused_at_load_with_both_sites_located() {
    // CLOUD-647 measured that the obvious candidate engine reports cycles at
    // EVALUATION. On the mediated path that is the worst possible time and the
    // wrong exit class, so this refusal lands where a config fault belongs — and
    // names BOTH ends, because a reader given one has to find the other by hand.
    //
    // Fails by: moving the cycle check into the runner, or naming one site.
    let dir = Fixture::new("derived-cycle")
        .config(
            "version = 1\n\
             [[rule]]\n\
             id = \"first\"\n\
             kind = \"document\"\n\
             glob = \"a.json\"\n\
             format = \"json\"\n\
             node = \"x\"\n\
             derives = \"a\"\n\
             reads = \"b\"\n\
             severity = \"deny\"\n\
             [[rule]]\n\
             id = \"second\"\n\
             kind = \"document\"\n\
             glob = \"b.json\"\n\
             format = \"json\"\n\
             node = \"x\"\n\
             derives = \"b\"\n\
             reads = \"a\"\n\
             severity = \"deny\"\n",
        )
        .file("a.json", "{\"x\": \"1\"}")
        .file("b.json", "{\"x\": \"1\"}")
        .build();
    let output = common::run(&dir, &["check"]);
    assert_eq!(output.status.code(), Some(1));
    let text = stderr(&output);
    assert!(text.contains("form a cycle"), "{text}");
    assert!(text.contains("batten.toml:3"), "one site located: {text}");
    assert!(text.contains("batten.toml:12"), "and the other: {text}");
}

#[test]
fn a_row_carrying_both_pattern_and_reads_is_refused() {
    // Two answers to one comparison. The same "one of" the forbid predicate
    // carries, refused rather than resolved by a precedence rule nobody can read.
    let dir = Fixture::new("derived-both")
        .config(
            "version = 1\n\
             [[rule]]\n\
             id = \"pin-authority\"\n\
             kind = \"document\"\n\
             glob = \"pins.toml\"\n\
             format = \"toml\"\n\
             node = \"pin.rust\"\n\
             derives = \"rust-pin\"\n\
             pattern = \"1.97.1\"\n\
             severity = \"deny\"\n\
             [[rule]]\n\
             id = \"floor-agrees\"\n\
             kind = \"document\"\n\
             glob = \"floor.json\"\n\
             format = \"json\"\n\
             node = \"rust\"\n\
             reads = \"rust-pin\"\n\
             pattern = \"1.97.1\"\n\
             severity = \"deny\"\n",
        )
        .file("pins.toml", "[pin]\nrust = \"1.97.1\"\n")
        .file("floor.json", "{\"rust\": \"1.97.1\"}")
        .build();
    let output = common::run(&dir, &["check"]);
    assert_eq!(output.status.code(), Some(1));
    assert!(stderr(&output).contains("are alternatives"));
}

#[test]
fn a_chain_of_derivations_resolves_in_dependency_order() {
    // A row may both derive and read, so resolution is not a single pass over
    // the table in declaration order. Written with the producer declared LAST,
    // which is the order a positional resolver gets wrong.
    let dir = Fixture::new("derived-chain")
        .config(
            "version = 1\n\
             [[rule]]\n\
             id = \"middle\"\n\
             kind = \"document\"\n\
             glob = \"b.json\"\n\
             format = \"json\"\n\
             node = \"x\"\n\
             derives = \"b\"\n\
             reads = \"a\"\n\
             severity = \"deny\"\n\
             [[rule]]\n\
             id = \"leaf\"\n\
             kind = \"document\"\n\
             glob = \"c.json\"\n\
             format = \"json\"\n\
             node = \"x\"\n\
             reads = \"b\"\n\
             severity = \"deny\"\n\
             [[rule]]\n\
             id = \"root\"\n\
             kind = \"document\"\n\
             glob = \"a.json\"\n\
             format = \"json\"\n\
             node = \"x\"\n\
             derives = \"a\"\n\
             pattern = \"1\"\n\
             severity = \"deny\"\n",
        )
        .file("a.json", "{\"x\": \"1\"}")
        .file("b.json", "{\"x\": \"1\"}")
        .file("c.json", "{\"x\": \"1\"}")
        .build();
    let output = common::run(&dir, &["check"]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
}
