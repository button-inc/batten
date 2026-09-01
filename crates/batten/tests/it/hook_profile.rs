//! `policy/hook-profile.rego` over the compiled binary (CLOUD-509, retired under
//! CLOUD-1199).
//!
//! **The load-time tier pins the predicate and cannot pin that the engine builds
//! the key it reads.** `hook-profile.rego`'s own `test_` rules fabricate
//! `input.tree["tool-verdict"]["hk-plan"]` with `with input as`, which passes
//! whether or not anything can ever produce that shape — the exact class
//! `.claude/rules/policy-modules.md` opens with, and the class that let
//! `validator-verdict-clean` ship deciding nothing. This file runs the real
//! producer and the real engine.
//!
//! **The three record states are the whole subject**, and this module reads them
//! differently from its sibling on purpose: absent is could-not-look, PRESENT AND
//! EMPTY is the tier having evaporated (a finding), and present-with-a-stray is
//! the false green the split can produce.
//!
//! # RETIREMENT LEDGER, PER PATH — what `shell-retirement` reads
//!
//! `hook-profile-check` ran `hk check --all --plan` twice and adjudicated the two
//! plans in shell. The run stays outside — §9's prior art, and §5 makes `check`
//! `read` — so the plans are recorded by `mise run record-verdicts hk-plan` and
//! the adjudication moves here. The `hook-missing-profile-flag` half needs no
//! record at all: it is a property of a FILE, and `line_sources` carries it.

// carried: mise-tasks/hook-profile-check.sh policy/hook-profile.rego crates/batten/tests/hook_profile.rs
// carried: tests/hook-profile-check.bats policy/hook-profile.rego crates/batten/tests/hook_profile.rs

//! # RETIREMENT LEDGER — `tests/hook-profile-check.bats`, 11 cases
//!
//! CARRIED — the decision table, which is what the gate was for.

// carried: "a correctly wired split passes" crates/batten/tests/hook_profile.rs
// carried: "a slow step missing from the check plan is a violation" crates/batten/tests/hook_profile.rs
// carried: "every slow step missing from check is reported, not just the first" crates/batten/tests/hook_profile.rs
// carried: "no slow tier at all is could-not-look, never a pass" crates/batten/tests/hook_profile.rs
// carried: "this repository's own two-tier gate is correctly wired today" crates/batten/tests/hook_profile.rs

//! CHANGED — three cases whose SUBJECT moved from the gate to the producer, and
//! one whose verdict class changed with it.

// changed: "a plan with no steps is exit 2" crates/batten/tests/hook_profile.rs the shell gate read both plans itself, so an empty one was its own could-not-look. The producer reads them now, and a plan it cannot read is a producer failure that writes no record — leaving the id absent, which this module reads as could-not-look and refuses nothing. `no_record_at_all_is_could_not_look` is the successor; the arm is conserved and its exit code is the producer's rather than a gate's
// changed: "unparseable JSON is exit 2, not a verdict" crates/batten/tests/hook_profile.rs same move as the row above: parsing hk's plan is the producer's job now, and a plan that does not parse writes no record rather than reaching a verdict
// changed: "a missing plan file is exit 2" crates/batten/tests/hook_profile.rs same move again — there is no plan FILE in the successor at all, since the producer pipes hk's output straight into `record tool` rather than staging it
// changed: "a step skipped for a non-profile reason is not read as the slow tier" crates/batten/tests/hook_profile.rs the `profile_exclude` selection is the producer's `jq` now, so what reaches the module is already the tier. The distinction is conserved where it is made, and the module's own `test_every_slow_step_selected_by_check_is_clean` covers what arrives

//! WITHDRAWN — two cases whose subject does not survive the port, each for a
//! stated reason rather than for convenience.

// withdrawn: "a tier member cannot also be included in the same no-profile plan" the shell gate's own comment records this branch as UNREACHABLE by construction — the tier is DERIVED from the no-profile plan's exclusions, so "a tier member still included there" cannot be represented, and an earlier draft asserting it had a branch its own test caught as dead. The successor derives the tier the same way, so the case is unrepresentable there too
// withdrawn: "one argument is a usage error, not a half-judged run" the two-path fixture mode is gone with the program: the successor takes no plan arguments, because the producer reads hk directly and the module reads a record. There is no argument count left to get wrong

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::{Path, PathBuf};

use common::{batten, git_in, run_with_stdin, scratch, stderr, stdout, write};

/// The `hk` pin the row declares, and the one a record must be keyed to.
const DECLARED_VERSION: &str = "1.56.1";

/// The subject the plan is taken over.
const SUBJECT: &str = "amends \"package://example\"\n";

/// A hook that still disables the slow tier — the clean half of the economy arm.
const WIRED_HOOK: &str = "#!/usr/bin/env bash\nhk run pre-commit --profile '!slow'\n";

fn config() -> String {
    format!(
        r#"version = 1

[[rule]]
id = "hook-profile"
kind = "policy"
scope = "tree"
module = "hook-profile.rego"
line_sources = [".claude/hooks/git-hook.sh"]
severity = "deny"

[[rule.tools]]
id = "hk-plan"
tool = "hk"
version = "{DECLARED_VERSION}"
input = "hk.pkl"

[[verdict]]
id = "step declare missing"
gloss = "a step declaring the slow profile is not selected by the `check` hook"
class = "A fixture class, mirroring the committed row."

[[verdict.route]]
id = "gate read first"
kind = "document"
target = "hk.pkl"

[[verdict]]
id = "tier list empty"
gloss = "something planned this tree and no step declares the slow profile"
class = "A fixture class, mirroring the committed row."

[[verdict.route]]
id = "gate read first"
kind = "document"
target = "hk.pkl"

[[verdict]]
id = "hook declare missing"
gloss = "the git hook runs hk without the profile flag"
class = "A fixture class, mirroring the committed row."

[[verdict.route]]
id = "source read first"
kind = "document"
target = ".claude/hooks/git-hook.sh"
"#
    )
}

/// A repository carrying the committed module, the row that reads it, and a hook.
fn fixture(name: &str, hook: &str) -> PathBuf {
    let dir = scratch(&format!("hook-profile-{name}-{}", std::process::id()));
    write(&dir, "batten.toml", &config());
    write(
        &dir,
        "hook-profile.rego",
        &std::fs::read_to_string(at_repo("policy/hook-profile.rego")).expect("read the module"),
    );
    write(&dir, "hk.pkl", SUBJECT);
    write(&dir, ".claude/hooks/git-hook.sh", hook);
    git_in(&dir, &["init", "-q", "-b", "main", "."]);
    dir
}

/// A path inside this repository, resolved from the test binary's manifest dir.
fn at_repo(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(relative)
}

/// Record a plan through the real producer verb.
fn record(dir: &Path, plan: &str) -> std::process::Output {
    run_with_stdin(dir, &["record", "tool", "hk-plan"], plan)
}

fn check(dir: &Path) -> std::process::Output {
    let mut command = batten();
    command.current_dir(dir).arg("check");
    command.output().expect("run batten check")
}

#[test]
fn a_wired_split_is_clean() {
    // THE ANTI-VACUITY MIRROR, and it is listed first because every refusal below
    // is only evidence if this one passes: a module that denied unconditionally
    // would satisfy all of them.
    let dir = fixture("wired", WIRED_HOOK);
    assert_eq!(
        record(&dir, "test included\nbatten-check included\n")
            .status
            .code(),
        Some(0)
    );

    let outcome = check(&dir);
    let (answer, cause) = (stdout(&outcome), stderr(&outcome));
    assert_eq!(
        outcome.status.code(),
        Some(0),
        "a correctly wired split is clean\n{answer}{cause}"
    );
}

#[test]
fn a_slow_step_missing_from_check_is_refused() {
    // THE LOAD-BEARING DIRECTION. The step still declares the profile, so
    // pre-commit still skips it, and `mise run ci`, `verify` and CI have all
    // silently stopped running it — green everywhere, nothing tested.
    let dir = fixture("stray", WIRED_HOOK);
    assert_eq!(
        record(&dir, "test included\nbatten-check skipped\n")
            .status
            .code(),
        Some(0)
    );

    let outcome = check(&dir);
    let (answer, cause) = (stdout(&outcome), stderr(&outcome));
    assert_eq!(
        outcome.status.code(),
        Some(2),
        "a slow step outside the check plan is a policy verdict\n{answer}{cause}"
    );
    assert!(answer.contains("hook-profile"), "{answer}{cause}");
}

#[test]
fn an_evaporated_tier_is_refused_rather_than_read_as_clean() {
    // PRESENT AND EMPTY, which this module reads as a FINDING where its sibling
    // reads the same state as "the tool ran and found nothing". Every per-step
    // assertion above would pass over an empty set, so a tier that evaporated must
    // not be silent — the shell gate's own anti-vacuity arm, conserved.
    let dir = fixture("evaporated", WIRED_HOOK);
    assert_eq!(record(&dir, "").status.code(), Some(0));

    let outcome = check(&dir);
    let (answer, cause) = (stdout(&outcome), stderr(&outcome));
    assert_eq!(
        outcome.status.code(),
        Some(2),
        "an evaporated tier is a finding, not a clean read\n{answer}{cause}"
    );
}

#[test]
fn no_record_at_all_is_could_not_look() {
    // ABSENT, told apart from the empty case above by the only means that
    // discriminates: that one refuses and this one does not. Collapsing them
    // would refuse on every fresh checkout, which is the state of every clone
    // before a producer has run.
    let dir = fixture("unrecorded", WIRED_HOOK);
    let outcome = check(&dir);
    let (answer, cause) = (stdout(&outcome), stderr(&outcome));
    assert_ne!(
        outcome.status.code(),
        Some(2),
        "nothing has planned this tree, which is not a verdict\n{answer}{cause}"
    );
}

#[test]
fn a_plan_recorded_before_the_subject_moved_does_not_answer() {
    // THE KEYING, over this module's own row. A plan is an answer about the
    // `hk.pkl` it was taken over; edit that file and the key moves, so the record
    // is not found rather than found and wrong. Without this a stale `included`
    // for every step outlives the config that produced it.
    let dir = fixture("moved", WIRED_HOOK);
    assert_eq!(
        record(&dir, "batten-check skipped\n").status.code(),
        Some(0)
    );
    write(&dir, "hk.pkl", "amends \"package://example-two\"\n");

    let outcome = check(&dir);
    let (answer, cause) = (stdout(&outcome), stderr(&outcome));
    assert_ne!(
        outcome.status.code(),
        Some(2),
        "a plan must not survive the config it was taken over\n{answer}{cause}"
    );
}

#[test]
fn a_hook_that_stopped_passing_the_flag_is_refused() {
    // THE ECONOMY HALF, which needs no record: it is a property of a file, and
    // `line_sources` carries it.
    let dir = fixture("unflagged", "#!/usr/bin/env bash\nhk run pre-commit\n");
    assert_eq!(record(&dir, "test included\n").status.code(), Some(0));

    let outcome = check(&dir);
    let (answer, cause) = (stdout(&outcome), stderr(&outcome));
    assert_eq!(
        outcome.status.code(),
        Some(2),
        "a hook that stopped disabling the tier is a finding\n{answer}{cause}"
    );
}

#[test]
fn the_flag_in_a_comment_alone_does_not_satisfy_it() {
    // THE MEASURED CASE the shell gate's own comment records: deleting the flag
    // from the COMMAND left it green, because the explanatory comment above still
    // spelled it. Non-comment lines that actually run the hook, or the predicate
    // is satisfied by its own documentation.
    let dir = fixture(
        "commented",
        "#!/usr/bin/env bash\n# we pass --profile '!slow' here\nhk run pre-commit\n",
    );
    assert_eq!(record(&dir, "test included\n").status.code(), Some(0));

    let outcome = check(&dir);
    let (answer, cause) = (stdout(&outcome), stderr(&outcome));
    assert_eq!(
        outcome.status.code(),
        Some(2),
        "a flag named only in a comment is not a flag that is passed\n{answer}{cause}"
    );
}

#[test]
fn every_stray_is_counted_not_just_the_first() {
    // The shell gate reported each offender rather than stopping at one, and the
    // successor's subject is a COUNT (rule 4), so the property to conserve is that
    // the count reflects all of them.
    let dir = fixture("many", WIRED_HOOK);
    assert_eq!(
        record(&dir, "one skipped\ntwo skipped\nthree included\n")
            .status
            .code(),
        Some(0)
    );

    let outcome = check(&dir);
    let (answer, cause) = (stdout(&outcome), stderr(&outcome));
    assert_eq!(outcome.status.code(), Some(2), "{answer}{cause}");
    assert!(
        answer.contains('2'),
        "the finding counts every stray, not just the first\n{answer}{cause}"
    );
}
