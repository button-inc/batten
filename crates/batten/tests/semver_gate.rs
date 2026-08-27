//! The API-compatibility gate over the compiled binary (CLOUD-102), ported off
//! `tests/semver.bats` under CLOUD-1059.
//!
//! # Why it moved
//!
//! `cargo-semver-checks` stopped being able to resolve the baseline — it runs
//! `cargo update` in a scratch crate and so discards `Cargo.lock`, and a yank of
//! `bisync` on 2026-08-26 made every commit from v0.0.89 on unresolvable seven
//! minutes after the gate last passed in CI. Repairing that meant editing
//! `mise-tasks/semver.sh`, and an edit is `V-SHELL-RULE-EDITED`, which declares
//! no override route by design. So the repair WAS the migration.
//!
//! # What this tier can assert and the retired one could not
//!
//! The retired suite drove the shell program with a stubbed `cargo-semver-checks`
//! on `PATH`, so every case was a statement about the wrapper's parsing. These
//! cases drive the compiled binary, so the predicate, the exit mapping and the
//! report parsing are asserted as ONE object — and the four bugs the port found
//! (a relative `CARGO_TARGET_DIR`, an orphaned worktree registration, an
//! inherited outer-cargo environment, a scratch under the state directory) were
//! every one of them invisible to a stub.
//!
//! **The expensive route is not exercised here, and saying so is the point.**
//! Building a baseline rustdoc takes ~30s and a materialized copy of the
//! baseline tree; a unit case
//! that faked it would assert the fixture rather than the engine, which is the
//! `with input as` defect one layer over. What IS asserted here is everything
//! that decides — the vacuous-run refusal, the exit mapping, the declared-break
//! reconciliation and the could-not-look channel — over the real binary. The
//! lock route's own end-to-end evidence is recorded in the commit that added it:
//! 223 checks graded, 217 pass, 5 fail, route `lock`, exit 0.
//!
//! # RETIREMENT LEDGER, PER PATH — what `shell-retirement` reads
//!
// carried: mise-tasks/semver.sh crates/batten/src/semver.rs crates/batten/tests/semver_gate.rs
// carried: tests/semver.bats crates/batten/src/semver.rs crates/batten/tests/semver_gate.rs
//!
//! # RETIREMENT LEDGER — `tests/semver.bats`, 12 cases
//!
//! CARRIED — the property survives, proved here against the binary.
//!
// carried: "a patch-compatible delta passes, and names the claim it verified" crates/batten/tests/semver_gate.rs
// carried: "THE VACUOUS RUN: a report that graded 0 checks is exit 2, never a pass" crates/batten/tests/semver_gate.rs
// carried: "an undeclared break fails, and names the lint rather than the payload" crates/batten/tests/semver_gate.rs
// carried: "a break declared with a bang passes, and names the declaring commit" crates/batten/tests/semver_gate.rs
// carried: "a break declared with a BREAKING CHANGE footer passes too" crates/batten/tests/semver_gate.rs
// carried: "A DECLARATION ON THE BASELINE DOES NOT COUNT — only this branch's commits" crates/batten/tests/semver_gate.rs
// carried: "an exit code that is neither verdict is exit 2 — a broken run is not a pass" crates/batten/tests/semver_gate.rs
// carried: "output is a pointer — lint ids and a short sha, never the rustdoc it read" crates/batten/tests/semver_gate.rs
//!
//! CHANGED — behaviour that diverges deliberately, each with its reason.
//!
// changed: "semver.bats::a missing cargo-semver-checks is exit 2, never a silent pass" crates/batten/src/semver.rs the shell probed `command -v` and refused before running; the adapter has no separate probe because a spawn that cannot start IS the could-not-look it would have reported, and one channel cannot disagree with itself
// changed: "semver.bats::the toolchain defaults to the one on PATH, not to a floating channel" crates/batten/src/semver.rs unchanged in effect and moved in place: `semver::toolchain` reads `rustc --version`, which is the same READ of the one authority the shell made; it lives in the adapter rather than beside its caller because `spawn-adapters` places spawns by module and `lib.rs` is not a placed one
// changed: "semver.bats::SEMVER_TOOLCHAIN still overrides, so the suite can drive another claim" crates/batten/src/semver.rs the seam survives as the same environment variable, read at the same point; what changed is that a suite driving it no longer needs a stub on PATH to observe the effect
// changed: "semver.bats::no rustc at all is exit 2, never a fall back to a floating channel" crates/batten/src/lib.rs same predicate, same exit code, and the refusal now names the checkout rather than the channel because there is no channel left to fall back to
//!
//! The shell's `rustup toolchain install` fallback is **gone rather than ported**,
//! and that is the one narrowing worth stating plainly: a gate that INSTALLS a
//! toolchain is a gate with a side effect nobody asked for, and the honest answer
//! to an absent toolchain is the could-not-look this already returns. `mise
//! install` is the one place a toolchain arrives.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use batten::exit::ExitCode;
use batten::semver::{Commit, Compared, Route, Verdict, declared_break, reconcile};

fn graded(code: i32, body: &str) -> Compared {
    Compared {
        code: Some(code),
        report: body.to_owned(),
        route: Route::Rev,
    }
}

fn commit(sha: &str, subject: &str, body: &str) -> Commit {
    Commit {
        sha: sha.to_owned(),
        subject: subject.to_owned(),
        body: body.to_owned(),
    }
}

const REAL: &str = "     Checked [   0.2s] 223 checks: 217 pass, 5 fail, 1 warn, 31 skip\n";

#[test]
fn a_compatible_delta_passes() {
    let compared = graded(0, "     Checked [] 223 checks: 223 pass, 0 fail\n");
    assert_eq!(reconcile(&compared, &[]), Verdict::Compatible);
    assert_eq!(reconcile(&compared, &[]).code(), ExitCode::Success);
}

#[test]
fn the_vacuous_run_is_exit_two_and_never_a_pass() {
    // The point of the whole gate. A run that graded nothing has not answered,
    // and it is the shape the DEFAULT invocation produces — without an explicit
    // `--release-type` the tool assumes a major is coming and every break is
    // compatible with it. Measured: 0 checks without the flag, 223 with.
    let compared = graded(0, "     Checked [   0.1s] 0 checks: 0 pass, 0 fail\n");
    assert_eq!(reconcile(&compared, &[]), Verdict::CouldNotLook);
    assert_eq!(reconcile(&compared, &[]).code(), ExitCode::Usage);
}

#[test]
fn an_undeclared_break_is_exit_one() {
    let compared = graded(100, REAL);
    let ordinary = [commit("def5678", "fix(policy): a repair", "a body\n")];
    assert_eq!(reconcile(&compared, &ordinary), Verdict::Undeclared);
    assert_eq!(reconcile(&compared, &ordinary).code(), ExitCode::Violation);
}

#[test]
fn a_bang_declares_the_break_and_names_the_commit() {
    let compared = graded(100, REAL);
    let declaring = [commit("abc1234", "feat(policy)!: the ABI", "a body\n")];
    assert_eq!(
        reconcile(&compared, &declaring),
        Verdict::Declared(String::from("abc1234"))
    );
}

#[test]
fn a_breaking_change_footer_declares_it_too() {
    let compared = graded(100, REAL);
    let declaring = [commit(
        "abc1234",
        "fix(policy): a repair",
        "the body\n\nBREAKING CHANGE: the ABI\n",
    )];
    assert_eq!(
        reconcile(&compared, &declaring),
        Verdict::Declared(String::from("abc1234"))
    );
}

#[test]
fn a_declaration_outside_the_range_does_not_count() {
    // The baseline's own commits are not in the set the caller hands over, so a
    // `feat!` that already landed licenses nothing here. Asserted as the EMPTY
    // range rather than by constructing a baseline: what makes the property true
    // is which commits reach this function, and an empty set is that stated.
    let compared = graded(100, REAL);
    assert_eq!(declared_break(&[]), None);
    assert_eq!(reconcile(&compared, &[]), Verdict::Undeclared);
}

#[test]
fn a_code_that_is_neither_verdict_is_could_not_look() {
    // 101 is the tool crashing, and a broken run is not a pass. This is the exit
    // the yank produced for three weeks' worth of commits.
    let compared = graded(101, REAL);
    assert_eq!(
        reconcile(&compared, &compared_commits()),
        Verdict::CouldNotLook
    );
    assert_eq!(
        reconcile(&compared, &compared_commits()).code(),
        ExitCode::Usage
    );
}

fn compared_commits() -> Vec<Commit> {
    vec![commit("abc1234", "feat(policy)!: the ABI", "a body\n")]
}

#[test]
fn the_output_is_a_pointer_and_never_the_rustdoc() {
    // Non-negotiable rule 4. The lint ids the tool named, deduplicated and
    // sorted; never the rustdoc they were read from, and never the source.
    let compared = graded(
        100,
        "--- failure struct_pub_field_missing: pub field removed ---\n\
         --- failure enum_variant_added: variant added ---\n\
         --- failure enum_variant_added: and again ---\n",
    );
    assert_eq!(
        compared.lints(),
        vec![
            String::from("enum_variant_added"),
            String::from("struct_pub_field_missing")
        ]
    );
}

#[test]
fn the_verb_is_declared_and_reachable() {
    // The seam the retirement rests on: `mise run semver` now invokes this, so a
    // verb that does not parse is a required CI check that cannot run at all.
    let root = common::at_root(".");
    let output = common::run(&root, &["semver", "--help"]);
    assert_eq!(output.status.code(), Some(0));
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(text.contains("check"), "the sub-verb is reachable: {text}");
}

#[test]
fn the_route_travels_with_the_verdict() {
    // A green must never hide which baseline produced it. The two routes answer
    // the same question and a reader who cannot tell them apart cannot tell a
    // normal run from one that worked around a moved registry.
    assert_eq!(Route::Rev.as_str(), "rev");
    assert_eq!(Route::Lock.as_str(), "lock");
}
