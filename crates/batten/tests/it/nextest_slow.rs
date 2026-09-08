//! `policy/nextest-slow.rego` over the COMPILED engine (CLOUD-1571 follow-on).
//!
//! # Why this file exists when the module already has `test_` rules
//!
//! Those are the load-time tier and they pin the PREDICATE. They cannot pin that
//! the engine BUILDS the input the predicate reads: `with input as` fabricates
//! the very shape the engine may be unable to produce, so a module reading a key
//! nothing fills passes its own suite green and enforces nothing.
//!
//! # The absent-file case is the one that earns this file
//!
//! `landing-roster-guarded` shipped with a could-not-look arm that could never
//! fire: its row named a GLOB, and a glob matching zero files leaves the rule
//! SKIPPED rather than evaluated over an empty document, so a branch deleting the
//! subject passed clean. `.config/nextest.toml` is a literal path rather than a
//! glob, which should mean the declared source is still acquired and the refusal
//! still fires — but "should" is exactly what that module also believed.
//! `an_absent_runner_config_is_refused` is what decides it, and only a tier
//! driving the engine over a tree with the file removed can.
//!
//! It doubles as the channel probe `rules/policy-modules.md` prescribes: a clean
//! report and a module that never ran are byte-identical on the decision surface,
//! and a case that reddens when the subject is removed tells them apart.
//!
//! # And the fidelity case drives the REAL committed file
//!
//! `the_committed_config_declares_a_terminating_slow_timeout` scans this
//! repository's own `.config/nextest.toml`. A fixture-only suite would pass over
//! a tree whose slow-test ban had been quietly disarmed, which is the regression
//! this module exists to refuse.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::fs;
use std::path::{Path, PathBuf};

use batten::rules::{self, Rule};

/// The predicate ids the module declares.
const UNBOUNDED: &str = "nextest-slow-unbounded";
const RAISED: &str = "nextest-slow-raised";

/// The one path the module is anchored on.
const CONFIG: &str = ".config/nextest.toml";

/// `period` with no `terminate-after` only REPORTS. Not a ban.
const REPORT_ONLY: &str = "[profile.default]\nslow-timeout = \"10s\"\n";

/// Above the ceiling the module commits to.
const RAISED_BODY: &str =
    "[profile.default]\nslow-timeout = { period = \"30s\", terminate-after = 3 }\n";

/// A fixture tree carrying a runner config with `body`, or none at all when
/// `body` is `None`.
fn repo(name: &str, body: Option<&str>) -> PathBuf {
    let root = common::scratch(name);
    fs::create_dir_all(root.join(".config")).expect("scratch config dir");
    if let Some(body) = body {
        fs::write(root.join(CONFIG), body).expect("write the runner config");
    }
    install_module(&root);
    root
}

/// The COMMITTED module, copied rather than re-typed. A fixture carrying its own
/// copy of the predicate would pass while the shipped one was broken, which is
/// the fidelity failure this tier exists to catch.
fn install_module(root: &Path) {
    let source = common::at_root("policy/nextest-slow.rego")
        .canonicalize()
        .expect("the committed module is where the row says it is");
    fs::create_dir_all(root.join("policy")).expect("scratch policy dir");
    fs::copy(source, root.join("policy/nextest-slow.rego")).expect("install committed module");
}

/// The committed row's shape, so a registration the loader would reject cannot
/// pass here.
fn row() -> Rule {
    serde_json::from_value(serde_json::json!({
        "id": "nextest-slow",
        "kind": "policy",
        "scope": "tree",
        "lines": [CONFIG],
        "module": "policy/nextest-slow.rego",
        "severity": "deny",
    }))
    .expect("the loader accepts the committed row's shape")
}

fn scan(root: &Path) -> rules::Scan {
    let verdicts = common::verdicts_in(root);
    // NO PATTERN ROWS, and that is a statement rather than an omission: this
    // module resolves none — the period is read with string builtins precisely so
    // no inline regex and no registry row is needed — so supplying any would be
    // input no consumer supplies and the cases would pass for the wrong reason.
    rules::run_static(
        &[row()],
        &[],
        batten::policy::Vocabulary {
            patterns: &[],
            verdicts: &verdicts,
            recorders: &[],
        },
        root,
    )
    .expect("the read surface runs a policy row")
}

fn rules_fired(root: &Path) -> Vec<String> {
    scan(root)
        .findings
        .into_iter()
        .map(|finding| finding.rule)
        .collect()
}

/// THE FIDELITY CASE. The COMMITTED bytes of the file that actually bans slow
/// tests here, scanned by the engine in a fixture — the repo root itself cannot be
/// scanned with a one-rule subset, because `check_registry_is_exhausted` then
/// reports every class the other rules would have raised.
/// `#MUTANT declaration-unread` reddens exactly here.
#[test]
fn the_committed_config_declares_a_terminating_slow_timeout() {
    let committed = fs::read_to_string(common::at_root(CONFIG))
        .expect("the committed runner config is where the row says it is");
    let root = repo("nextest-slow-committed", Some(&committed));
    assert!(
        rules_fired(&root).is_empty(),
        "the committed {CONFIG} must declare a slow-timeout with terminate-after, at or \
         under the module's ceiling; if this fails the slow-test ban has been disarmed"
    );
}

/// THE CASE THIS TIER EXISTS FOR, and the one a `with input as` case cannot
/// decide. `landing-roster-guarded` carried a could-not-look arm that never fired
/// because its row named a glob and a glob matching nothing leaves the rule
/// SKIPPED. This row names a literal path; that it therefore still acquires the
/// source and still refuses is measured here rather than assumed.
///
/// It is also the channel probe: a clean report and a module that never ran are
/// byte-identical, and this reddening is what tells them apart.
#[test]
fn an_absent_runner_config_is_refused() {
    let root = repo("nextest-slow-absent", None);
    assert_eq!(
        rules_fired(&root),
        vec![UNBOUNDED.to_owned()],
        "deleting the runner config removes the ban, and must refuse rather than read clean"
    );
}

/// `period` ALONE ONLY REPORTS. Without `terminate-after` nextest marks a case
/// slow and lets it run, so this is not a ban and must not read as one.
#[test]
fn a_declaration_without_terminate_after_is_refused() {
    let root = repo("nextest-slow-report-only", Some(REPORT_ONLY));
    assert_eq!(rules_fired(&root), vec![UNBOUNDED.to_owned()]);
}

/// THE RATCHET, over the engine. A period above the committed ceiling is refused.
#[test]
fn a_period_above_the_ceiling_is_refused() {
    let root = repo("nextest-slow-raised", Some(RAISED_BODY));
    assert_eq!(rules_fired(&root), vec![RAISED.to_owned()]);
}

/// AND LOWERING IS FREE — the asymmetry that makes this a ratchet rather than an
/// equality check. Without this case the rule above is satisfied by a module that
/// refuses every value that is not exactly the ceiling, which would make every
/// speed-up negotiate with the gate.
#[test]
fn a_period_below_the_ceiling_is_clean() {
    let root = repo(
        "nextest-slow-lowered",
        Some("[profile.default]\nslow-timeout = { period = \"4s\", terminate-after = 9 }\n"),
    );
    assert!(rules_fired(&root).is_empty());
}

/// A UNIT THE MODULE CANNOT CONVERT REFUSES rather than leaving the comparison
/// unreachable. `2m` is a legal nextest value, and without this arm it would read
/// as a clean tree while no bound was being enforced at all — the silent hole the
/// module's header calls fail-closed.
#[test]
fn a_period_in_an_unconvertible_unit_is_refused() {
    let root = repo(
        "nextest-slow-minutes",
        Some("[profile.default]\nslow-timeout = { period = \"2m\", terminate-after = 3 }\n"),
    );
    assert_eq!(rules_fired(&root), vec![UNBOUNDED.to_owned()]);
}

/// AND A COMMENTED-OUT DECLARATION IS NOT ONE. The ordinary shape of "this was
/// flaky, disabling it for now" leaves the text in the file, which is exactly how
/// `landing-roster-guarded`'s first draft was defeated by its own documentation.
#[test]
fn a_commented_declaration_does_not_arm_the_ban() {
    let root = repo(
        "nextest-slow-commented",
        Some("[profile.default]\n# slow-timeout = { period = \"10s\", terminate-after = 9 }\n"),
    );
    assert_eq!(rules_fired(&root), vec![UNBOUNDED.to_owned()]);
}
