//! `policy/hook-profile.rego` over the compiled binary (CLOUD-509, retired under
//! CLOUD-1199; its `hk-plan` record retired under CLOUD-843).
//!
//! **The load-time tier pins the predicate and cannot pin that the engine builds
//! the key it reads.** `hook-profile.rego`'s own `test_` rules fabricate
//! `input.tree.plan` with `with input as`, which passes whether or not anything
//! can ever produce that shape — the exact class `rules/policy-modules.md` opens
//! with. This file runs the real runner, the real acquisition and the real
//! engine: a scratch repository carries its own `hk.pkl`, and `batten check`
//! acquires both declared plans from it.
//!
//! # RETIREMENT LEDGER, PER PATH — what `shell retire partial` reads
//!
//! `hook-profile-check` ran `hk check --all --plan` twice and adjudicated the two
//! plans in shell; its first successor recorded a `jq` join of the two as the
//! `hk-plan` tool verdict from `[tasks.record-verdicts]`. The join is the
//! module's now, over two `[[rule.plan]]` rows the boundary acquires, and no
//! producer runs at all.

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
// carried: "a step skipped for a non-profile reason is not read as the slow tier" policy/hook-profile.rego

//! CHANGED — cases whose subject moved to the boundary's acquisition.

// changed: "a plan with no steps is exit 2" crates/batten/tests/hook_profile.rs the boundary acquires the plan, and `hk::planned_steps` answers could-not-look for an empty one, so the plan is `null` and the module refuses nothing — `no_plan_is_could_not_look` is the successor
// changed: "unparseable JSON is exit 2, not a verdict" crates/batten/tests/hook_profile.rs parsing hk's plan is the acquisition's, and a plan that does not parse is `null`
// changed: "a missing plan file is exit 2" crates/batten/tests/hook_profile.rs there is no plan FILE: the boundary asks hk directly

//! WITHDRAWN — two cases whose subject does not survive the port.

// withdrawn: "a tier member cannot also be included in the same no-profile plan" the shell gate's own comment records this branch as UNREACHABLE by construction — the tier is DERIVED from the no-profile plan's exclusions, so the case is unrepresentable in the successor too
// withdrawn: "one argument is a usage error, not a half-judged run" the successor takes no plan arguments; the rows name the plans

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::{Path, PathBuf};

use batten::facts::Look;
use batten::hk;
use common::{at_root, git_in, init_repo, run, scratch, stderr, stdout, write};

/// A hook that still disables the slow tier — the clean half of the economy arm.
const WIRED_HOOK: &str = "#!/usr/bin/env bash\nhk run pre-commit --profile '!slow'\n";

/// This repository's own `amends` line, so the scratch config resolves from the
/// package cache this checkout already warmed rather than from the network.
fn amends() -> String {
    std::fs::read_to_string(at_root("hk.pkl"))
        .expect("read hk.pkl")
        .lines()
        .find(|line| line.starts_with("amends "))
        .expect("hk.pkl amends the hk package")
        .to_owned()
}

/// A scratch `hk.pkl` enabling `slow`, with one ordinary step and the steps
/// `extra` declares.
fn hk_config(extra: &str) -> String {
    format!(
        "{}\n\nprofiles = List(\"slow\")\n\nhooks {{\n  [\"check\"] {{\n    steps {{\n      [\"fmt\"] {{\n        check = \"true\"\n      }}\n{extra}    }}\n  }}\n}}\n",
        amends()
    )
}

/// A step declaring `profile`, whose check does nothing.
fn step(name: &str, profile: &str) -> String {
    format!(
        "      [\"{name}\"] {{\n        profiles = List(\"{profile}\")\n        check = \"true\"\n      }}\n"
    )
}

fn config() -> String {
    String::from(
        r#"version = 1

[[rule]]
id = "hook declare other"
kind = "policy"
scope = "tree"
module = "hook-profile.rego"
line_sources = [".claude/hooks/git-hook.sh"]
severity = "deny"

[[rule.plan]]
id = "gate"
hook = "check"

[[rule.plan]]
id = "gate-fast"
hook = "check"
profile = ["!slow"]

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
gloss = "both plans were acquired and no step declares the slow profile"
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
"#,
    )
}

/// A committed repository carrying the module, the rows, a hook and an
/// `hk.pkl` with `steps` added — or none at all when `steps` is `None`.
fn fixture(name: &str, hook: &str, steps: Option<&str>) -> PathBuf {
    let dir = scratch(&format!("hook-profile-{name}"));
    write(&dir, "batten.toml", &config());
    write(
        &dir,
        "hook-profile.rego",
        &std::fs::read_to_string(at_root("policy/hook-profile.rego")).expect("read the module"),
    );
    if let Some(steps) = steps {
        write(&dir, "hk.pkl", &hk_config(steps));
    }
    write(&dir, ".claude/hooks/git-hook.sh", hook);
    init_repo(&dir);
    git_in(&dir, &["add", "-A"]);
    git_in(&dir, &["commit", "-qm", "fixture"]);
    dir
}

fn check(dir: &Path) -> std::process::Output {
    run(dir, &["check"])
}

fn said(outcome: &std::process::Output) -> String {
    format!("{}{}", stdout(outcome), stderr(outcome))
}

#[test]
fn a_wired_split_is_clean() {
    // THE ANTI-VACUITY MIRROR, and it is listed first because every refusal below
    // is only evidence if this one passes: a module that denied unconditionally
    // would satisfy all of them.
    let dir = fixture(
        "wired",
        WIRED_HOOK,
        Some(&format!(
            "{}{}",
            step("test", "slow"),
            step("batten-check", "slow")
        )),
    );
    let outcome = check(&dir);
    assert_eq!(
        outcome.status.code(),
        Some(0),
        "a correctly wired split is clean\n{}",
        said(&outcome)
    );
}

#[test]
fn a_slow_step_the_check_plan_does_not_select_is_refused() {
    // THE LOAD-BEARING DIRECTION. `stray` declares a profile the committed
    // config never enables, so pre-commit skips it AND `check` skips it — green
    // everywhere, nothing tested. The fast plan skips it for its profile, which
    // is what puts it in the tier.
    let dir = fixture(
        "stray",
        WIRED_HOOK,
        Some(&format!(
            "{}{}",
            step("test", "slow"),
            step("stray", "rare")
        )),
    );
    let outcome = check(&dir);
    assert_eq!(
        outcome.status.code(),
        Some(2),
        "a tier step outside the check plan is a policy verdict\n{}",
        said(&outcome)
    );
    assert!(
        said(&outcome).contains("hook declare other"),
        "{}",
        said(&outcome)
    );
}

#[test]
fn every_stray_is_counted_not_just_the_first() {
    let dir = fixture(
        "many",
        WIRED_HOOK,
        Some(&format!(
            "{}{}{}",
            step("one", "rare"),
            step("two", "rare"),
            step("three", "slow")
        )),
    );
    let outcome = check(&dir);
    assert_eq!(outcome.status.code(), Some(2), "{}", said(&outcome));
    assert!(
        said(&outcome).contains('2'),
        "the finding counts every stray, not just the first\n{}",
        said(&outcome)
    );
}

#[test]
fn an_evaporated_tier_is_refused_rather_than_read_as_clean() {
    // Both plans acquired and no step declares a profile: every per-step
    // assertion would pass over an empty set, so the tier's absence is a finding.
    let dir = fixture("evaporated", WIRED_HOOK, Some(""));
    let outcome = check(&dir);
    assert_eq!(
        outcome.status.code(),
        Some(2),
        "an evaporated tier is a finding, not a clean read\n{}",
        said(&outcome)
    );
}

#[test]
fn no_plan_is_could_not_look() {
    // No `hk.pkl` at all: neither plan can be acquired, which is not a verdict.
    // Collapsing this with the evaporated tier would refuse on every checkout
    // the runner cannot plan.
    let dir = fixture("unplanned", WIRED_HOOK, None);
    let outcome = check(&dir);
    assert_ne!(
        outcome.status.code(),
        Some(2),
        "nothing could plan this tree, which is not a verdict\n{}",
        said(&outcome)
    );
}

#[test]
fn a_hook_that_stopped_passing_the_flag_is_refused() {
    let dir = fixture(
        "unflagged",
        "#!/usr/bin/env bash\nhk run pre-commit\n",
        Some(&step("test", "slow")),
    );
    let outcome = check(&dir);
    assert_eq!(
        outcome.status.code(),
        Some(2),
        "a hook that stopped disabling the tier is a finding\n{}",
        said(&outcome)
    );
}

#[test]
fn the_flag_in_a_comment_alone_does_not_satisfy_it() {
    let dir = fixture(
        "commented",
        "#!/usr/bin/env bash\n# we pass --profile '!slow' here\nhk run pre-commit\n",
        Some(&step("test", "slow")),
    );
    let outcome = check(&dir);
    assert_eq!(
        outcome.status.code(),
        Some(2),
        "a flag named only in a comment is not a flag that is passed\n{}",
        said(&outcome)
    );
}

/// THE TIER IS A MEMBERSHIP QUESTION, so every reason answers it. The retired
/// `jq` join selected a step when ANY of its reasons was `profile_exclude`; the
/// acquisition carries every reason's kind so the module can ask the same, and a
/// step whose runner lists another reason first stays in the tier.
#[test]
fn a_step_whose_profile_is_not_its_first_reason_is_still_in_the_tier() {
    let plan = serde_json::json!({"steps": [{
        "name": "slow-and-unmatched",
        "status": "skipped",
        "orderIndex": 0,
        "parallelGroupId": "0",
        "reasons": [{"kind": "no_files"}, {"kind": "profile_exclude"}],
    }]});
    let Look::Is(steps) = hk::planned_steps(&plan) else {
        panic!("a well-formed plan projects")
    };
    let step = steps.first().expect("one step");
    assert_eq!(step.reason_kind.as_deref(), Some("no_files"));
    assert_eq!(step.reason_kinds, vec!["no_files", "profile_exclude"]);
}

#[test]
fn this_repositorys_two_tier_gate_is_wired_today() {
    // THE ACQUISITION OVER THIS CHECKOUT, and the profile words reaching hk: the
    // fast plan skips the committed slow steps for their profile, and the full
    // plan includes them.
    let root = at_root(".");
    let query = |value: serde_json::Value| -> hk::PlanQuery {
        serde_json::from_value(value).expect("a query a row declares")
    };
    let Look::Is(fast) = hk::acquire(
        &root,
        &query(serde_json::json!({"id": "gate-fast", "hook": "check", "profile": ["!slow"]})),
    ) else {
        panic!("the pinned runner plans this checkout with the tier off")
    };
    let Look::Is(full) = hk::acquire(
        &root,
        &query(serde_json::json!({"id": "gate", "hook": "check"})),
    ) else {
        panic!("the pinned runner plans this checkout")
    };
    assert!(
        fast.invocation
            .windows(2)
            .any(|pair| pair == ["--profile", "!slow"]),
        "the profile words reach the runner: {:?}",
        fast.invocation
    );
    for name in ["batten-check", "test", "policy-test"] {
        assert!(
            fast.steps.iter().any(|step| step.name == name
                && step.status == "skipped"
                && step
                    .reason_kinds
                    .iter()
                    .any(|kind| kind == "profile_exclude")),
            "`{name}` is in the slow tier"
        );
        assert!(
            full.steps
                .iter()
                .any(|step| step.name == name && step.status == "included"),
            "`{name}` is selected by `check`"
        );
    }
}
