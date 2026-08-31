//! The acquisition sweep's contract, over the compiled engine (CLOUD-935,
//! CLOUD-1229).
//!
//! # Why this tier
//!
//! `crates/batten/src/perf.rs` unit-tests the parse and the rendering directly,
//! which is the right home for both: each is pure, and keeping them exercisable
//! without a benchmark runner is what lets them be asserted at all. The cases over
//! what the fixture builder WRITES are here instead, and for a lint reason rather
//! than a design one — reading a file back is a `Result`, and no module under
//! `src/` waives `unwrap_used`.
//!
//! What those cases cannot establish is the thing the whole measurement rests on:
//! **that the generated fixture is a tree the ENGINE accepts.** A `[[verdict]]`
//! row nothing raises, a module publishing the wrong rule name, a `documents`
//! array the engine never reads — every one of those makes `batten check` refuse
//! or no-op, and every arm then times a broken tree and still draws a tidy curve.
//! `.claude/rules/policy-modules.md` names that class: a dead gate and a clean
//! tree are byte-identical on the decision surface, and only a case over the
//! compiled binary tells them apart.
//!
//! # What is deliberately not here, and why it is not a gap
//!
//! The sweep itself is not run. It needs hyperfine, and `crates/batten/src/perf.rs`
//! records the measurement behind that: **the `windows` job installs none**, so a
//! case that ran the sweep would pass on two hosts and fail on the third — which
//! is exactly how `a_skip_exits_zero_and_prints_no_record` was once broken. The
//! same fact is why the harness is `crates/batten/examples/acquisition-bench.rs`
//! rather than a `perf` sub-verb: `tests/pointer_only.rs` sweeps every leaf verb
//! over a bare corpus and refuses one that exits 3, and could-not-look is the only
//! honest answer a sweep has there.
//!
//! # What this replaced, and why there is no ledger arm for it
//!
//! `bench/acquisition/sweep.py` is retired here under CLOUD-1229. It was 327 lines
//! of Python driven by a one-line task, and its own header argued the shape was
//! forced by `shell-retirement` refusing an added shell rule. A second author read
//! that argument and added a third helper for the identical stated reason
//! (CLOUD-1208). The campaign's subject is authored SHELL because that is what it
//! was built to retire — a statement about its reach, never a licence for what
//! sits beside it.
//!
//! It carries **no** `// changed:` marker, and that absence is the point rather
//! than an omission. Those arms are `shell-retirement`'s and `[rule.conserves]`'s
//! ledger over a governed file's death, and the deleted path was governed by
//! neither — not under `mise-tasks/`, not a `.bats` suite, watched by nothing.
//! Writing an arm for it would put a row in a ledger whose subject it never was.
//! The helper also carried no test tier of its own; it was a script with a
//! docstring, and what moved is the reasoning in that docstring, into the doc
//! comments on `perf::acquire` and `perf::sweep_fixture` and into the cases here
//! and in `perf.rs`'s own module.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use common::{Fixture, run, stderr, stdout};

#[test]
fn the_generated_fixture_is_a_tree_the_engine_accepts() {
    // THE LOAD-BEARING CASE, and the reason this file exists. Every arm of the
    // sweep times `batten check` over one of these trees, so a fixture the engine
    // refuses is a measurement of the refusal — and a fixture whose row the engine
    // never reads is a measurement of nothing, reported at three decimal places.
    //
    // Built through the harness's OWN builder rather than re-spelled here: a
    // second spelling of the fixture is a second authority, and the two can
    // disagree about exactly the thing this asserts.
    let root = Fixture::new("perf-acquire-fixture").git().build();
    let tree = root.join("swept");
    batten::perf::sweep_fixture(&tree, 4).expect("the sweep's own fixture builder");

    let output = run(&tree, &["check"]);
    assert!(
        output.status.success(),
        "the swept fixture must be a tree `check` accepts, or every arm times a \
         refusal: {}",
        stderr(&output)
    );
}

/// ANTI-VACUITY for the case above, and it is the half that discriminates.
///
/// `check` exits 0 over a tree with no rules at all, so the success above proves
/// nothing on its own — a builder that wrote an empty `batten.toml` would satisfy
/// it, and so would one whose `documents` array the engine never read. That
/// second one is the defect `.claude/rules/policy-modules.md` records from the
/// field: OpenTelemetry's `weaver` printed `✔ No policy violation`, exit 0, over a
/// knowingly-broken registry, because its module read a key the schema never
/// built.
///
/// So this drives the predicate from the other side. The module fires on a
/// declared document carrying a `stray` key; the generated documents carry none,
/// which is why every arm is clean. Put the key into ONE of them and the finding
/// has to appear — which can only happen if the row loaded, the declared path was
/// acquired, and the module read the acquired node.
#[test]
fn the_swept_row_reads_the_documents_it_declares() {
    let root = Fixture::new("perf-acquire-registered").git().build();
    let tree = root.join("swept");
    batten::perf::sweep_fixture(&tree, 4).expect("the sweep's own fixture builder");
    std::fs::write(tree.join("config2.toml"), "quiet = true\nstray = true\n")
        .expect("seed the sentinel the module fires on");

    let output = run(&tree, &["check"]);
    assert_eq!(
        output.status.code(),
        Some(2),
        "a seeded sentinel is a policy verdict: {}",
        stderr(&output)
    );
    let said = stdout(&output) + &stderr(&output);
    assert!(
        said.contains("acquisition-bench"),
        "the swept row must be the one that fired — anything else means the sweep \
         is timing a rule that never reads its documents: {said}"
    );
    assert!(
        said.contains("config2.toml"),
        "and it must point at the seeded document, not at the row: {said}"
    );
}

#[test]
fn the_fixture_declares_exactly_the_documents_it_was_asked_for() {
    // The confound the experiment is built to avoid, asserted rather than trusted:
    // ONE rule, ONE bundle, ONE module, and only the `documents` array grows. A
    // builder that added a row per document would still draw a tidy curve while
    // pricing a module compile and an evaluation at every step.
    let root = Fixture::new("perf-acquire-shape").git().build();
    let tree = root.join("swept");
    batten::perf::sweep_fixture(&tree, 3).expect("the sweep's own fixture builder");

    let authority =
        std::fs::read_to_string(tree.join("batten.toml")).expect("the fixture authority");
    assert_eq!(authority.matches("[[rule]]").count(), 1, "{authority}");
    assert!(
        authority.contains(r#"documents = ["config0.toml", "config1.toml", "config2.toml"]"#),
        "{authority}"
    );
    assert!(tree.join("policy-acquisition/gate.rego").is_file());
    assert!(tree.join("config2.toml").is_file());
    assert!(!tree.join("config3.toml").exists());
}

#[test]
fn the_floor_arm_carries_neither_a_rule_nor_the_verdict_it_would_raise() {
    // Both halves in one case, because they are one requirement: `[[verdict]]` runs
    // in BOTH directions, so a floor arm declaring the class with no rule to raise
    // it would fail the load outright and time nothing at all.
    let root = Fixture::new("perf-acquire-floor").git().build();
    let tree = root.join("swept");
    batten::perf::sweep_fixture(&tree, 0).expect("the sweep's own fixture builder");

    let authority =
        std::fs::read_to_string(tree.join("batten.toml")).expect("the fixture authority");
    assert!(!authority.contains("[[rule]]"), "{authority}");
    assert!(!authority.contains("V-ACQUISITION-BENCH"), "{authority}");

    let output = run(&tree, &["check"]);
    assert!(
        output.status.success(),
        "the floor arm must load and run, or the baseline every ratio is taken \
         against is a refusal: {}",
        stderr(&output)
    );
}
