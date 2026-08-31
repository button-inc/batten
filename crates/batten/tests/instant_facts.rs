//! `input.tree.instant` — the SUPPLIED instant, over the compiled binary
//! (CLOUD-1170).
//!
//! **The discriminating case is `the_same_instant_yields_byte_identical_output`,
//! and it is worthless without its partner.** That assertion is the whole of
//! CLOUD-1170's question — a supplied instant is reproducible where a clock read
//! is not — but on its own it passes over a module that ignores the instant
//! entirely, and over an engine that never projects it. Any constant output is
//! byte-identical to itself. So `a_different_instant_changes_the_verdict` runs
//! beside it: together they say the output depends on the instant AND depends on
//! nothing else. Either alone is coverage rather than a gate (CLOUD-418).
//!
//! **`an_unsupplied_instant_holds_neither_way` is the case a module author gets
//! wrong**, and it is here because Rego makes the wrong answer the easy one. JSON
//! `null` is a VALUE, and Rego orders values across types with `null` before every
//! number — so `input.tree.instant < expires` is **true** when nobody supplied an
//! instant, and a naive liveness predicate reports every lease live on every run
//! that forgot the flag. The probe below guards with `is_number` for exactly that,
//! and this case is what proves the guard is load-bearing rather than decorative.
//!
//! **`a_malformed_instant_is_a_usage_error` is the same failure one layer out.**
//! Reading an unparseable `--instant` as "none supplied" would turn a typo into a
//! clean-looking run: the gate the caller meant to spend would report nothing and
//! exit `0`. `--rule` and `--since` both refuse rather than degrade, and so does
//! this.
//!
//! What this suite deliberately does NOT assert: that the engine reads no clock.
//! That is a property of the crate rather than of this fact, and asserting it from
//! a fixture would only ever show that one probe's output did not move — which a
//! module ignoring the instant also shows. `crates/batten/tests/clock_ban.rs`
//! carries it over the source, where it can discriminate.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::path::{Path, PathBuf};

use common::{batten, git_in, scratch, stderr, stdout, write};

/// A lease record and a module that judges it against the supplied instant.
const CONFIG: &str = r#"version = 1

[[rule]]
id = "probe"
kind = "policy"
scope = "tree"
module = "probe.rego"
severity = "deny"
documents = ["lease.toml"]

[[verdict]]
id = "V-LEASE-EXPIRED"
gloss = "the lease's expiry is at or before the supplied instant"
class = "A fixture class, raised only by this suite's probe module."

[[verdict.route]]
id = "R-PROBE-EXPIRED"
kind = "document"
target = "probe.rego"

[[verdict]]
id = "V-LEASE-LIVE"
gloss = "the lease's expiry is after the supplied instant"
class = "A fixture class, raised only by this suite's probe module."

[[verdict.route]]
id = "R-PROBE-LIVE"
kind = "document"
target = "probe.rego"

[[verdict]]
id = "V-INSTANT-UNSUPPLIED"
gloss = "no instant reached the module, so it judged nothing"
class = "A fixture class, raised only by this suite's probe module."

[[verdict.route]]
id = "R-PROBE-UNSUPPLIED"
kind = "document"
target = "probe.rego"
"#;

/// Three predicates over one key: expired, live, and could-not-look.
///
/// The trio is what discriminates. A single "did I see an instant" rule would be
/// green whether the engine handed back the caller's value or any other, and a
/// pair without the third would be green while an unsupplied instant silently
/// answered one way — which is the defect the module comment below names.
const PROBE: &str = r#"package batten.probe

import rego.v1

rules contains "lease-expired"

rules contains "lease-live"

rules contains "instant-unsupplied"

# `is_number` IS LOAD-BEARING, not a type-safety habit. Rego orders values across
# types and sorts `null` before every number, so `null < expires` HOLDS — and a
# liveness predicate written without this guard reports every lease live on every
# run that forgot `--instant`. The engine cannot fix this for a module: `null` is
# the honest projection of "the caller supplied none", and reading it as an
# instant of 0 would date every record to 1970 instead.
supplied := input.tree.instant if is_number(input.tree.instant)

violation contains {
	"rule": "lease-expired",
	"verdict": "V-LEASE-EXPIRED",
	"subjects": [{"path": "lease.toml"}],
} if {
	supplied >= input.tree.documents["lease.toml"].expires
}

violation contains {
	"rule": "lease-live",
	"verdict": "V-LEASE-LIVE",
	"subjects": [{"path": "lease.toml"}],
} if {
	supplied < input.tree.documents["lease.toml"].expires
}

violation contains {
	"rule": "instant-unsupplied",
	"verdict": "V-INSTANT-UNSUPPLIED",
} if {
	not is_number(input.tree.instant)
}

test_an_instant_past_the_expiry_fires_expired if {
	some v in violation with input as {"tree": {"instant": 200, "documents": {"lease.toml": {"expires": 100}}}}
	v.rule == "lease-expired"
}

test_an_instant_before_the_expiry_fires_live if {
	some v in violation with input as {"tree": {"instant": 50, "documents": {"lease.toml": {"expires": 100}}}}
	v.rule == "lease-live"
}

test_a_null_instant_fires_neither_lease_class if {
	count({v | some v in violation; startswith(v.rule, "lease-")}) == 0 with input as {"tree": {"instant": null, "documents": {"lease.toml": {"expires": 100}}}}
}

test_a_null_instant_reports_could_not_look if {
	some v in violation with input as {"tree": {"instant": null, "documents": {"lease.toml": {"expires": 100}}}}
	v.rule == "instant-unsupplied"
}
"#;

/// A repository holding one lease record that expires at `expires`.
fn fixture(name: &str, expires: i64) -> PathBuf {
    let dir = scratch(&format!("instant-facts-{name}"));
    write(&dir, "batten.toml", CONFIG);
    write(&dir, "probe.rego", PROBE);
    write(&dir, "lease.toml", &format!("expires = {expires}\n"));
    git_in(&dir, &["init", "-q", "-b", "main", "."]);
    git_in(&dir, &["config", "user.name", "Fixture Author"]);
    git_in(&dir, &["config", "user.email", "fixture@example.com"]);
    git_in(&dir, &["add", "-A"]);
    git_in(&dir, &["commit", "-q", "-m", "chore: base"]);
    dir
}

/// `batten check`, optionally handed an instant.
fn check(dir: &Path, instant: Option<&str>) -> std::process::Output {
    let mut command = batten();
    command.current_dir(dir).arg("check");
    if let Some(instant) = instant {
        command.args(["--instant", instant]);
    }
    command.output().expect("run batten check")
}

#[test]
fn an_expired_lease_is_reported() {
    // Half of CLOUD-1170's discriminating pair: the instant is PAST the recorded
    // expiry, so the lease is expired and the module says so.
    let dir = fixture("expired", 100);
    let outcome = check(&dir, Some("200"));
    let (answer, cause) = (stdout(&outcome), stderr(&outcome));
    assert!(
        answer.contains("lease-expired"),
        "an instant past the expiry must report the lease expired\n{answer}{cause}"
    );
    assert!(
        !answer.contains("lease-live"),
        "an expired lease must not also report live\n{answer}{cause}"
    );
}

#[test]
fn a_live_lease_is_not_reported_expired() {
    // The other half, and the one that makes the first a gate rather than a
    // module that reports unconditionally. Same tree, same module, same expiry —
    // only the supplied instant differs.
    let dir = fixture("live", 100);
    let outcome = check(&dir, Some("50"));
    let (answer, cause) = (stdout(&outcome), stderr(&outcome));
    assert!(
        answer.contains("lease-live"),
        "an instant before the expiry must report the lease live\n{answer}{cause}"
    );
    assert!(
        !answer.contains("lease-expired"),
        "a live lease reported as expired is the wrong answer in the costly \
         direction — it steals a lease somebody holds\n{answer}{cause}"
    );
}

#[test]
fn the_same_instant_yields_byte_identical_output() {
    // THE ROW'S CENTRAL ASSERTION. §6 asks for byte-stable output, and a clock
    // READ cannot give it: the value differs on every evaluation, so no fixture
    // pins it and `replay` can carry no case. A SUPPLIED instant can, and this is
    // the proof — two runs of the same binary over the same tree with the same
    // `--instant`, compared as bytes rather than as verdicts.
    //
    // Worthless alone. See `a_different_instant_changes_the_verdict`.
    let dir = fixture("stable", 100);
    let first = check(&dir, Some("200"));
    let second = check(&dir, Some("200"));
    assert_eq!(
        first.stdout, second.stdout,
        "the same instant over the same tree must produce byte-identical output"
    );
    assert_eq!(
        first.status.code(),
        second.status.code(),
        "and the same exit code"
    );
}

#[test]
fn a_different_instant_changes_the_verdict() {
    // THE ANTI-VACUITY PARTNER, and without it the assertion above is satisfied
    // by an engine that never projects the instant at all: any constant output is
    // byte-identical to itself, so a fact nothing fills passes that case
    // perfectly. This is what makes the pair say "depends on the instant, and on
    // nothing else" rather than only the second half.
    let dir = fixture("moves", 100);
    let before = stdout(&check(&dir, Some("50")));
    let after = stdout(&check(&dir, Some("200")));
    assert_ne!(
        before, after,
        "the verdict must depend on the supplied instant; identical output across \
         two different instants means the engine is not projecting it"
    );
    assert!(
        before.contains("lease-live") && after.contains("lease-expired"),
        "and it must move in the right direction: {before} then {after}"
    );
}

#[test]
fn an_unsupplied_instant_holds_neither_way() {
    // COULD-NOT-LOOK, and the case a module author gets wrong. `null` is not the
    // epoch: a caller that passed no flag has said nothing, so neither lease class
    // may hold. Reading it as `0` would report every lease expired; reading it
    // through Rego's cross-type ordering without a guard reports every lease LIVE,
    // because `null` sorts before every number. Both are silent wrong answers, and
    // this is the case that tells them from the right one.
    let dir = fixture("unsupplied", 100);
    let outcome = check(&dir, None);
    let (answer, cause) = (stdout(&outcome), stderr(&outcome));
    assert!(
        answer.contains("instant-unsupplied"),
        "an unsupplied instant must report could-not-look\n{answer}{cause}"
    );
    assert!(
        !answer.contains("lease-expired") && !answer.contains("lease-live"),
        "an unsupplied instant must decide NEITHER way — a gate that could not \
         read the clock it was meant to be handed has not judged the \
         lease\n{answer}{cause}"
    );
}

#[test]
fn a_malformed_instant_is_a_usage_error() {
    // A TYPO IS NOT COULD-NOT-LOOK. Degrading an unparseable value to `None` would
    // read to its caller as a gate that ran and found nothing — the vacuous pass
    // in its purest form, and the reason `--rule` and `--since` both refuse rather
    // than narrow to nothing.
    let dir = fixture("malformed", 100);
    let outcome = check(&dir, Some("not-an-epoch"));
    let cause = stderr(&outcome);
    assert_eq!(
        outcome.status.code(),
        Some(1),
        "a malformed instant is a usage error (exit 1), never a policy verdict and \
         never a clean run\n{cause}"
    );
    assert!(
        cause.contains("--instant"),
        "the refusal must name the flag the caller got wrong\n{cause}"
    );
}
