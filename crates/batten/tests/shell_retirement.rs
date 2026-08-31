//! `policy/shell-retirement.rego` decides over the compiled engine rather than
//! over a fabricated input (CLOUD-1059).
//!
//! **This is the tier the module's own `test_` rules cannot be.** A `with input
//! as` block writes the shape it then reads, so it is green over a key the engine
//! never fills — CLOUD-845's defect, and `.claude/rules/policy-modules.md` records
//! both live instances of it being found by adding this tier rather than by
//! reading. `Fact::BaseDelta` is brand new here, so "the schema says
//! `input.tree["base-delta"]` exists" is exactly the untested claim about the
//! engine that this file exists to test.
//!
//! And it is not merely a projection test: every fixture below builds a **real
//! repository with a real base ref**, so the delta is computed by
//! `git::base_delta` from two trees rather than handed in. A test that stubbed
//! the delta would prove the predicate and nothing about the fact.
//!
//! The module read here is the COMMITTED one, copied into each scratch tree
//! rather than restated inline — an inline copy would drift from the shipped
//! module and pass while the real gate was broken, which is the
//! two-authorities-that-drift defect the campaign is about.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::fs;
use std::path::{Path, PathBuf};

use batten::rules::{self, Rule};

/// The row as `batten.toml` declares it, deserialized rather than
/// struct-literalled: `Rule` carries `deny_unknown_fields`, so this goes through
/// the same column census a consumer's config does and a row the loader would
/// refuse cannot be smuggled in by hand.
fn row() -> Rule {
    serde_json::from_value(serde_json::json!({
        "id": "shell-retirement",
        "kind": "policy",
        "scope": "tree",
        "base": "origin/main",
        // `**` because the committed row carries it (CLOUD-1080): a withdrawal's
        // declared subject is routinely under neither governed prefix, and a
        // narrow delta hides its death rather than reporting it.
        "delta_sources": ["**"],
        "line_sources": ["mise-tasks/*.sh", "crates/batten/tests/*.rs"],
        "module": "policy/shell-retirement.rego",
        "severity": "deny",
    }))
    .expect("the row batten.toml declares")
}

/// A repository whose `origin/main` carries `base`, with `head` applied on top.
///
/// `origin/main` is a real remote-tracking ref rather than a local branch,
/// because that is the name the committed row declares and a fixture that
/// resolved a different one would be testing a different question.
fn repo(name: &str, base: &[(&str, &str)], head: &Head<'_>) -> PathBuf {
    let root = common::scratch(&format!("shell-retirement-{name}"));
    common::git_in(&root, &["init", "--initial-branch=main"]);
    write_all(&root, base);
    install_module(&root);
    common::git_in(&root, &["add", "-A"]);
    common::git_in(&root, &["commit", "-m", "base"]);
    // The remote-tracking ref the row names, pointed at the base commit. No
    // remote is configured: `base_delta` resolves a rev, and a fetch would make
    // the fixture depend on the network for a question that is local.
    let base_sha = common::git_in(&root, &["rev-parse", "HEAD"]);
    common::git_in(
        &root,
        &["update-ref", "refs/remotes/origin/main", &base_sha],
    );

    for path in head.removed {
        fs::remove_file(root.join(path)).expect("remove at head");
    }
    write_all(&root, head.written);
    root
}

/// What the working tree does to the base: files written, files removed.
struct Head<'a> {
    written: &'a [(&'a str, &'a str)],
    removed: &'a [&'a str],
}

fn write_all(root: &Path, files: &[(&str, &str)]) {
    for (path, body) in files {
        let full = root.join(path);
        if let Some(parent) = full.parent() {
            fs::create_dir_all(parent).expect("scratch parent");
        }
        fs::write(full, body).expect("write fixture file");
    }
}

fn install_module(root: &Path) {
    let source = common::at_root("policy/shell-retirement.rego")
        .canonicalize()
        .expect("the committed module is where the row says it is");
    fs::create_dir_all(root.join("policy")).expect("scratch policy dir");
    fs::copy(source, root.join("policy/shell-retirement.rego")).expect("install committed module");
}

/// The vocabulary the installed module needs, read off the module itself
/// (CLOUD-1050). Derived rather than listed: this fixture copies the COMMITTED
/// module in so it cannot drift, and a hand-written table beside it would.
fn scan(root: &Path) -> rules::Scan {
    let verdicts = common::verdicts_in(root);
    // THE COMMITTED PATTERN TABLE, and it stopped being optional the moment the
    // module started resolving `data.batten.patterns[…]` (CLOUD-1219). An empty
    // table makes `check_pattern_refs` refuse the load — every case in this file
    // goes red at once, over a module that is fine. Derived from the committed
    // config for `install_module`'s reason: a hand-written copy would drift and
    // pass here while the real gate was broken.
    let patterns = common::committed_patterns();
    rules::run_static(
        &[row()],
        &[],
        batten::policy::Vocabulary {
            patterns: &patterns,
            verdicts: &verdicts,
            recorders: &[],
        },
        root,
    )
    .expect("the read surface runs a policy row")
}

fn findings(root: &Path) -> Vec<String> {
    scan(root)
        .findings
        .into_iter()
        .map(|finding| finding.rule)
        .collect()
}

const GATE: &str = "#!/usr/bin/env bash\n#MISE description=\"a gate\"\necho hi\n";
const SUITE: &str = "# subject: mise-tasks/old-gate.sh\n@test \"it holds\" {\n  true\n}\n";

/// A mapped retirement, spelled the way the ledger spells one.
fn ledger(retired: &str) -> String {
    format!("// carried: {retired} policy/old-gate.rego crates/batten/tests/old_gate.rs\n")
}

/// The same arm, plus the INVOCATION field a caller may be repointed at
/// (CLOUD-1219). Spaces travel as `+`, because `arms_for` splits the row on " ".
fn ledger_running(retired: &str, invocation: &str) -> String {
    format!(
        "// carried: {retired} policy/old-gate.rego crates/batten/tests/old_gate.rs runs:{}\n",
        invocation.replace(' ', "+")
    )
}

// ---------------------------------------------------------------------------
// The positive arm first: without it every refusal below is satisfied by a
// module that refuses everything.
// ---------------------------------------------------------------------------

#[test]
fn a_deleted_and_fully_mapped_shell_rule_passes() {
    let root = repo(
        "mapped",
        &[("mise-tasks/old-gate.sh", GATE)],
        &Head {
            written: &[(
                "crates/batten/tests/old_gate.rs",
                &ledger("mise-tasks/old-gate.sh"),
            )],
            removed: &["mise-tasks/old-gate.sh"],
        },
    );
    assert!(
        findings(&root).is_empty(),
        "a conforming migration passes: {:?}",
        findings(&root)
    );
}

/// The truncation arm, over the engine — and it is the shape that forced the
/// clause rather than one imagined for it.
///
/// `hooks-wiring-check.sh` opened its `DECLARED` table with the first entry glued
/// to the assignment, so retiring the program that entry named SHORTENED the
/// opening line instead of deleting it. A line-set arm reads that as an addition
/// and refuses the cleanup the campaign itself mandates.
///
/// Over the binary because that is the only tier that shows the ENGINE builds
/// `base-lines` at all: a `with input as` case hands the module the very map the
/// boundary might be unable to produce.
#[test]
fn an_edit_truncating_a_line_at_a_retired_reference_is_admitted() {
    let root = repo(
        "truncated",
        &[
            ("mise-tasks/old-gate.sh", GATE),
            (
                "mise-tasks/wiring.sh",
                "#!/usr/bin/env bash\nDECLARED=\"${T-mise-tasks/old-gate.sh CLOUD-312\nmise-tasks/other.sh CLOUD-312}\"\n",
            ),
        ],
        &Head {
            written: &[
                (
                    "mise-tasks/wiring.sh",
                    "#!/usr/bin/env bash\nDECLARED=\"${T-\nmise-tasks/other.sh CLOUD-312}\"\n",
                ),
                (
                    "crates/batten/tests/old_gate.rs",
                    &ledger("mise-tasks/old-gate.sh"),
                ),
            ],
            removed: &["mise-tasks/old-gate.sh"],
        },
    );
    assert!(
        findings(&root).is_empty(),
        "shortening a line at the retired path it named is the campaign cleaning up after \
         itself: {:?}",
        findings(&root)
    );
}

/// ANTI-VACUITY for the case above, and it is not optional: a bare prefix
/// relation would admit any shortening at all. What this truncation drops names
/// a path that is still in the tree, so it is ordinary maintenance.
#[test]
fn an_edit_truncating_a_line_at_a_live_reference_is_refused() {
    let root = repo(
        "truncated-live",
        &[
            ("mise-tasks/old-gate.sh", GATE),
            ("mise-tasks/still-here.sh", GATE),
            (
                "mise-tasks/wiring.sh",
                "#!/usr/bin/env bash\nDECLARED=\"${T-mise-tasks/still-here.sh CLOUD-312\nmise-tasks/old-gate.sh CLOUD-312}\"\n",
            ),
        ],
        &Head {
            written: &[
                (
                    "mise-tasks/wiring.sh",
                    "#!/usr/bin/env bash\nDECLARED=\"${T-}\"\n",
                ),
                (
                    "crates/batten/tests/old_gate.rs",
                    &ledger("mise-tasks/old-gate.sh"),
                ),
            ],
            removed: &["mise-tasks/old-gate.sh"],
        },
    );
    assert_eq!(
        findings(&root),
        vec![String::from("shell-rule-retired")],
        "dropping a reference to a file that is still here is maintenance in place"
    );
}

#[test]
fn an_untouched_tree_is_silent() {
    let root = repo(
        "untouched",
        &[("mise-tasks/old-gate.sh", GATE)],
        &Head {
            written: &[],
            removed: &[],
        },
    );
    assert!(
        findings(&root).is_empty(),
        "nothing changed, nothing to say"
    );
}

// ---------------------------------------------------------------------------
// The refusals, one fixture each.
// ---------------------------------------------------------------------------

#[test]
fn an_added_shell_rule_is_refused() {
    let root = repo(
        "added",
        &[],
        &Head {
            written: &[("mise-tasks/new-gate.sh", GATE)],
            removed: &[],
        },
    );
    assert_eq!(findings(&root), vec!["shell-rule-retired".to_owned()]);
}

#[test]
fn an_added_bats_suite_is_refused() {
    let root = repo(
        "added-bats",
        &[],
        &Head {
            written: &[("tests/new-gate.bats", SUITE)],
            removed: &[],
        },
    );
    assert_eq!(findings(&root), vec!["shell-rule-retired".to_owned()]);
}

/// The load-bearing arm: an edit is invisible to every other sensor in the tree.
#[test]
fn a_shell_rule_edited_in_place_is_refused() {
    let root = repo(
        "edited",
        &[("mise-tasks/old-gate.sh", GATE)],
        &Head {
            written: &[(
                "mise-tasks/old-gate.sh",
                "#!/usr/bin/env bash\n#MISE description=\"a gate\"\necho changed\n",
            )],
            removed: &[],
        },
    );
    assert_eq!(findings(&root), vec!["shell-rule-retired".to_owned()]);
}

#[test]
fn a_bats_suite_edited_in_place_is_refused() {
    let root = repo(
        "edited-bats",
        &[("tests/old-gate.bats", SUITE)],
        &Head {
            written: &[(
                "tests/old-gate.bats",
                "# subject: mise-tasks/old-gate.sh\n@test \"it holds\" {\n  false\n}\n",
            )],
            removed: &[],
        },
    );
    assert_eq!(findings(&root), vec!["shell-rule-retired".to_owned()]);
}

#[test]
fn a_deletion_with_no_mapping_is_refused() {
    let root = repo(
        "unmapped",
        &[("mise-tasks/old-gate.sh", GATE)],
        &Head {
            written: &[],
            removed: &["mise-tasks/old-gate.sh"],
        },
    );
    assert_eq!(findings(&root), vec!["shell-rule-retired".to_owned()]);
}

#[test]
fn a_deletion_carrying_two_arms_is_refused() {
    let two = concat!(
        "// carried: mise-tasks/old-gate.sh policy/old-gate.rego crates/batten/tests/old_gate.rs\n",
        "// subsumed: mise-tasks/old-gate.sh policy/other.rego crates/batten/tests/other.rs\n",
    );
    let root = repo(
        "two-arms",
        &[("mise-tasks/old-gate.sh", GATE)],
        &Head {
            written: &[("crates/batten/tests/old_gate.rs", two)],
            removed: &["mise-tasks/old-gate.sh"],
        },
    );
    assert_eq!(findings(&root), vec!["shell-rule-retired".to_owned()]);
}

#[test]
fn a_mapping_naming_no_policy_surface_is_refused() {
    let root = repo(
        "no-surface",
        &[("mise-tasks/old-gate.sh", GATE)],
        &Head {
            written: &[(
                "crates/batten/tests/old_gate.rs",
                "// carried: mise-tasks/old-gate.sh crates/batten/tests/old_gate.rs\n",
            )],
            removed: &["mise-tasks/old-gate.sh"],
        },
    );
    assert_eq!(findings(&root), vec!["shell-rule-retired".to_owned()]);
}

#[test]
fn a_mapping_naming_no_compiled_binary_test_is_refused() {
    let root = repo(
        "no-test",
        &[("mise-tasks/old-gate.sh", GATE)],
        &Head {
            written: &[(
                "crates/batten/tests/old_gate.rs",
                "// carried: mise-tasks/old-gate.sh policy/old-gate.rego\n",
            )],
            removed: &["mise-tasks/old-gate.sh"],
        },
    );
    assert_eq!(findings(&root), vec!["shell-rule-retired".to_owned()]);
}

// ---------------------------------------------------------------------------
// The subject condition, on all four arms (CLOUD-1130).
//
// The withdrawal arm asked whether the row's subject went with it; the other
// three never asked at all, so one claim was refused under one marker and
// admitted under the other three. Over the binary rather than `with input as`
// for this tier's standing reason: the module reads the ledger out of
// `input.tree.lines`, and only a real run proves the engine builds it for a
// `crates/batten/tests/*.rs` path.
// ---------------------------------------------------------------------------

/// A suite retired onto real successors while the program it tested stands.
const CARRIED_OVER_A_LIVE_SUBJECT: &str = concat!(
    "// carried: tests/old-gate.bats mise-tasks/old-gate.sh ",
    "policy/old-gate.rego crates/batten/tests/old_gate.rs\n",
);

#[test]
fn a_carried_row_naming_a_live_subject_is_refused() {
    let root = repo(
        "carried-live-subject",
        &[
            ("tests/old-gate.bats", SUITE),
            ("mise-tasks/old-gate.sh", GATE),
        ],
        &Head {
            written: &[(
                "crates/batten/tests/old_gate.rs",
                CARRIED_OVER_A_LIVE_SUBJECT,
            )],
            removed: &["tests/old-gate.bats"],
        },
    );
    assert_eq!(
        findings(&root),
        vec!["shell-rule-retired".to_owned()],
        "every successor obligation is met and the subject is still standing"
    );
}

#[test]
fn a_carried_row_whose_named_subject_died_is_admitted() {
    // The other direction, and without it the case above would be satisfied by a
    // module that refuses any row naming a governed path at all. The same ledger
    // row, with the subject retired in the same change and carrying its own arm.
    let both = concat!(
        "// carried: tests/old-gate.bats mise-tasks/old-gate.sh ",
        "policy/old-gate.rego crates/batten/tests/old_gate.rs\n",
        "// carried: mise-tasks/old-gate.sh policy/old-gate.rego ",
        "crates/batten/tests/old_gate.rs\n",
    );
    let root = repo(
        "carried-dead-subject",
        &[
            ("tests/old-gate.bats", SUITE),
            ("mise-tasks/old-gate.sh", GATE),
        ],
        &Head {
            written: &[("crates/batten/tests/old_gate.rs", both)],
            removed: &["tests/old-gate.bats", "mise-tasks/old-gate.sh"],
        },
    );
    assert_eq!(
        findings(&root),
        Vec::<String>::new(),
        "a whole retirement names its subject and retires it: {:?}",
        findings(&root)
    );
}

// ---------------------------------------------------------------------------
// The fourth arm: a WITHDRAWAL names no successor (CLOUD-1080).
//
// THIS TIER IS THE POINT HERE, not a duplicate of the module's own `test_` rules.
// Those fabricate `base-lines` for the dying suite; only a run over the compiled
// binary proves the ENGINE builds that entry — and it did not until this row's
// `line_sources` learned `tests/**/*.bats`. With the module's cases alone the arm
// passed its own suite and refused every real withdrawal, which is exactly the
// class `.claude/rules/policy-modules.md` records both live instances of.
// ---------------------------------------------------------------------------

/// A dying suite declaring a subject that is not itself governed when deleted —
/// the real shape, since the wrapper this arm was built for lives under
/// `.claude/`. A governed subject would raise its own unmapped finding and the
/// assertion could not tell the two apart.
const WITHDRAWN_SUITE: &str =
    "# subject: .claude/old-wrapper.sh\n@test \"it holds\" {\n  true\n}\n";

#[test]
fn a_withdrawal_whose_subject_died_with_it_is_admitted() {
    let root = repo(
        "withdrawn",
        &[
            ("tests/old-gate.bats", WITHDRAWN_SUITE),
            (".claude/old-wrapper.sh", GATE),
        ],
        &Head {
            written: &[(
                "crates/batten/tests/old_gate.rs",
                "// withdrawn: tests/old-gate.bats .claude/old-wrapper.sh the feature should not exist\n",
            )],
            removed: &["tests/old-gate.bats", ".claude/old-wrapper.sh"],
        },
    );
    assert_eq!(
        findings(&root),
        Vec::<String>::new(),
        "a withdrawal whose subject died owes no policy surface and no binary test"
    );
}

#[test]
fn a_withdrawal_over_a_live_subject_is_refused() {
    // THE DISCRIMINATING CASE. The subject is left standing while its suite is
    // deleted and claimed withdrawn — a suite gutted with a note attached. Without
    // this condition the arm is a waiver over the path with better manners, and
    // the positive case above would pass against a module deciding nothing.
    let root = repo(
        "withdrawn-live",
        &[
            ("tests/old-gate.bats", WITHDRAWN_SUITE),
            (".claude/old-wrapper.sh", GATE),
        ],
        &Head {
            written: &[(
                "crates/batten/tests/old_gate.rs",
                "// withdrawn: tests/old-gate.bats .claude/old-wrapper.sh the feature should not exist\n",
            )],
            removed: &["tests/old-gate.bats"],
        },
    );
    assert_eq!(findings(&root), vec!["shell-rule-retired".to_owned()]);
}

#[test]
fn a_withdrawal_naming_no_reason_is_refused() {
    // It names no successor, so the reason is the only thing on the row a reader
    // can check the claim against.
    let root = repo(
        "withdrawn-bare",
        &[
            ("tests/old-gate.bats", WITHDRAWN_SUITE),
            (".claude/old-wrapper.sh", GATE),
        ],
        &Head {
            written: &[(
                "crates/batten/tests/old_gate.rs",
                "// withdrawn: tests/old-gate.bats .claude/old-wrapper.sh\n",
            )],
            removed: &["tests/old-gate.bats", ".claude/old-wrapper.sh"],
        },
    );
    assert_eq!(findings(&root), vec!["shell-rule-retired".to_owned()]);
}

#[test]
fn the_successor_obligation_still_binds_the_other_three_arms() {
    // The exemption is scoped to `withdrawn` rather than switched on for every
    // deletion whose subject died: the same fixture, mapped `carried` with no
    // policy surface, still refuses.
    let root = repo(
        "withdrawn-scope",
        &[
            ("tests/old-gate.bats", WITHDRAWN_SUITE),
            (".claude/old-wrapper.sh", GATE),
        ],
        &Head {
            written: &[(
                "crates/batten/tests/old_gate.rs",
                "// carried: tests/old-gate.bats crates/batten/tests/old_gate.rs\n",
            )],
            removed: &["tests/old-gate.bats", ".claude/old-wrapper.sh"],
        },
    );
    assert_eq!(findings(&root), vec!["shell-rule-retired".to_owned()]);
}

// ---------------------------------------------------------------------------
// The boundaries, which is where a gate nobody can keep green comes from.
// ---------------------------------------------------------------------------

/// A generated artifact and a non-shell path under `mise-tasks/` are excluded BY
/// PATH, so regenerating completions is not a retirement obligation.
#[test]
fn generated_and_non_shell_paths_are_not_governed() {
    let root = repo(
        "generated",
        &[("mise-tasks/replay-pointers.py", "print('x')\n")],
        &Head {
            written: &[
                ("completions/batten.bash", "# generated\n"),
                ("mise-tasks/replay-pointers.py", "print('y')\n"),
                ("crates/batten/src/lib.rs", "// code\n"),
            ],
            removed: &[],
        },
    );
    assert!(
        findings(&root).is_empty(),
        "derived output is not an authored shell rule: {:?}",
        findings(&root)
    );
}

/// An untouched shell rule elsewhere in the tree does not affect the result —
/// the predicate decides over the CHANGED set, not over the corpus.
#[test]
fn an_untouched_shell_rule_elsewhere_does_not_fire() {
    let root = repo(
        "bystander",
        &[
            ("mise-tasks/old-gate.sh", GATE),
            ("mise-tasks/bystander.sh", GATE),
        ],
        &Head {
            written: &[(
                "crates/batten/tests/old_gate.rs",
                &ledger("mise-tasks/old-gate.sh"),
            )],
            removed: &["mise-tasks/old-gate.sh"],
        },
    );
    assert!(
        findings(&root).is_empty(),
        "only the changed set is judged: {:?}",
        findings(&root)
    );
}

/// A file under `mise-tasks/` carrying neither a shebang nor a `#MISE
/// description=` is not an authored shell rule on the head side.
#[test]
fn a_mise_tasks_file_that_is_not_a_shell_rule_is_not_governed_at_head() {
    let root = repo(
        "not-a-rule",
        &[],
        &Head {
            written: &[("mise-tasks/notes.sh", "just some text\n")],
            removed: &[],
        },
    );
    assert!(
        findings(&root).is_empty(),
        "classification is the file's own first bytes: {:?}",
        findings(&root)
    );
}

/// The could-not-look arm, and it is the one a vacuous pass would hide. A base
/// that does not resolve must leave the fact `null` and every predicate
/// undefined — never an empty delta, which reads as a clean tree.
#[test]
fn an_unresolvable_base_reports_nothing_rather_than_clean() {
    let root = common::scratch("shell-retirement-no-base");
    common::git_in(&root, &["init", "--initial-branch=main"]);
    install_module(&root);
    write_all(&root, &[("mise-tasks/new-gate.sh", GATE)]);
    common::git_in(&root, &["add", "-A"]);
    common::git_in(&root, &["commit", "-m", "only commit"]);
    // No `refs/remotes/origin/main` was ever created, so the declared base does
    // not resolve. An added shell rule is present and would fire if the delta
    // had been fabricated as empty-but-present.
    assert!(
        findings(&root).is_empty(),
        "could-not-look yields no finding: {:?}",
        findings(&root)
    );
    assert!(
        scan(&root).findings.is_empty(),
        "and it is silence rather than a clean verdict"
    );
}

// ---------------------------------------------------------------------------
// CLOUD-1149 and CLOUD-1219: how a caller SPELLS the program it is losing, and
// what it may be repointed at.
//
// Over the binary rather than `with input as`, for this file's standing reason:
// these arms read `delta["base-lines"]`, and a fabricated input hands the module
// the very map the boundary might be unable to produce.
// ---------------------------------------------------------------------------

/// P1 — the sibling spelling alone. CLOUD-1149's gap, with nothing added.
#[test]
fn dropping_a_sibling_resolution_of_a_retired_program_is_admitted() {
    let root = repo(
        "sibling-dropped",
        &[
            ("mise-tasks/old-gate.sh", GATE),
            (
                "mise-tasks/caller.sh",
                "#!/usr/bin/env bash\nlint=\"$(dirname \"$0\")/old-gate.sh\"\necho done\n",
            ),
        ],
        &Head {
            written: &[
                ("mise-tasks/caller.sh", "#!/usr/bin/env bash\necho done\n"),
                (
                    "crates/batten/tests/old_gate.rs",
                    &ledger("mise-tasks/old-gate.sh"),
                ),
            ],
            removed: &["mise-tasks/old-gate.sh"],
        },
    );
    assert!(
        findings(&root).is_empty(),
        "a `$(dirname \"$0\")` sibling names a path this delta deletes: {:?}",
        findings(&root)
    );
}

/// P2 — THE SHAPE THAT MOTIVATED BOTH ROWS, end to end (CLOUD-1092).
///
/// The caller resolves its callee once into a variable and spends it many lines
/// later as a single word. Repointing it onto a verb changes the call's ARITY,
/// so the edit is two lines — and the spend line names no retired path at all,
/// which is why a pure string widening does not reach this.
#[test]
fn a_variable_borne_caller_repointed_at_the_declared_invocation_is_admitted() {
    let root = repo(
        "variable-borne",
        &[
            ("mise-tasks/old-gate.sh", GATE),
            (
                "mise-tasks/caller.sh",
                "#!/usr/bin/env bash\nlint=\"$(dirname \"$0\")/old-gate.sh\"\nprintf '%s' \"$x\" | \"$lint\" 2>/dev/null\n",
            ),
        ],
        &Head {
            written: &[
                (
                    "mise-tasks/caller.sh",
                    "#!/usr/bin/env bash\nprintf '%s' \"$x\" | mise run old-gate 2>/dev/null\n",
                ),
                (
                    "crates/batten/tests/old_gate.rs",
                    &ledger_running("mise-tasks/old-gate.sh", "mise run old-gate"),
                ),
            ],
            removed: &["mise-tasks/old-gate.sh"],
        },
    );
    assert!(
        findings(&root).is_empty(),
        "the caller may name the invocation its retirement declared: {:?}",
        findings(&root)
    );
}

/// P3 — the directory in a variable, bound once and spent by name.
#[test]
fn a_here_style_sibling_repointed_at_the_declared_invocation_is_admitted() {
    let root = repo(
        "here-style",
        &[
            ("mise-tasks/old-gate.sh", GATE),
            (
                "mise-tasks/caller.sh",
                "#!/usr/bin/env bash\nhere=\"$(dirname \"$0\")\"\nrun_gate g \"$here/old-gate.sh\"\n",
            ),
        ],
        &Head {
            written: &[
                (
                    "mise-tasks/caller.sh",
                    "#!/usr/bin/env bash\nhere=\"$(dirname \"$0\")\"\nrun_gate g mise run old-gate\n",
                ),
                (
                    "crates/batten/tests/old_gate.rs",
                    &ledger_running("mise-tasks/old-gate.sh", "mise run old-gate"),
                ),
            ],
            removed: &["mise-tasks/old-gate.sh"],
        },
    );
    assert!(
        findings(&root).is_empty(),
        "a `$here/` sibling resolves through the base binding: {:?}",
        findings(&root)
    );
}

/// P4 — the literal-path caller, repointed at an invocation rather than a path.
///
/// **THE SPAN IS THE REFERENCE AND NOTHING ADJACENT TO IT, and this case is
/// where that bound bites.** A base line of `bash mise-tasks/old-gate.sh
/// --strict` repointed to `mise run old-gate --strict` is REFUSED, because the
/// span the two lines disagree about is `bash mise-tasks/old-gate.sh` — the
/// interpreter word included — and that is not a reference to the retired path.
/// Measured here: the first version of this case spelled it that way and was
/// correctly refused.
///
/// That is the narrowing working rather than a gap to widen. Admitting it would
/// mean admitting a span that swallows arbitrary neighbouring words, which is
/// the licence the clause is built to refuse. A caller that also drops its
/// interpreter word is making two edits, and takes the whole-line route.
#[test]
fn a_literal_path_caller_repointed_at_the_declared_invocation_is_admitted() {
    let root = repo(
        "literal-invocation",
        &[
            ("mise-tasks/old-gate.sh", GATE),
            (
                "mise-tasks/caller.sh",
                "#!/usr/bin/env bash\nmise-tasks/old-gate.sh --strict\n",
            ),
        ],
        &Head {
            written: &[
                (
                    "mise-tasks/caller.sh",
                    "#!/usr/bin/env bash\nmise run old-gate --strict\n",
                ),
                (
                    "crates/batten/tests/old_gate.rs",
                    &ledger_running("mise-tasks/old-gate.sh", "mise run old-gate"),
                ),
            ],
            removed: &["mise-tasks/old-gate.sh"],
        },
    );
    assert!(
        findings(&root).is_empty(),
        "arm 1 reaches the invocation clause too: {:?}",
        findings(&root)
    );
}

/// N1 — THE ANTI-VACUITY CASE. Without it every positive above is satisfied by a
/// clause that admits anything.
#[test]
fn a_repointing_at_a_command_no_arm_declares_is_refused() {
    let root = repo(
        "forged-target",
        &[
            ("mise-tasks/old-gate.sh", GATE),
            (
                "mise-tasks/caller.sh",
                "#!/usr/bin/env bash\nlint=\"$(dirname \"$0\")/old-gate.sh\"\nprintf '%s' \"$x\" | \"$lint\" 2>/dev/null\n",
            ),
        ],
        &Head {
            written: &[
                (
                    "mise-tasks/caller.sh",
                    "#!/usr/bin/env bash\nprintf '%s' \"$x\" | mise run something-else 2>/dev/null\n",
                ),
                (
                    "crates/batten/tests/old_gate.rs",
                    &ledger_running("mise-tasks/old-gate.sh", "mise run old-gate"),
                ),
            ],
            removed: &["mise-tasks/old-gate.sh"],
        },
    );
    assert!(
        findings(&root).contains(&"shell-rule-retired".to_owned()),
        "the target must come from the ledger, never from the editor: {:?}",
        findings(&root)
    );
}

/// N2 — byte-exactness of the span decomposition: the rest of the line may not
/// move under cover of the repointing.
#[test]
fn a_repointing_that_also_changes_the_rest_of_the_line_is_refused() {
    let root = repo(
        "span-drift",
        &[
            ("mise-tasks/old-gate.sh", GATE),
            (
                "mise-tasks/caller.sh",
                "#!/usr/bin/env bash\nlint=\"$(dirname \"$0\")/old-gate.sh\"\nprintf '%s' \"$x\" | \"$lint\" 2>/dev/null\n",
            ),
        ],
        &Head {
            written: &[
                (
                    "mise-tasks/caller.sh",
                    "#!/usr/bin/env bash\nprintf '%s' \"$x\" | mise run old-gate\n",
                ),
                (
                    "crates/batten/tests/old_gate.rs",
                    &ledger_running("mise-tasks/old-gate.sh", "mise run old-gate"),
                ),
            ],
            removed: &["mise-tasks/old-gate.sh"],
        },
    );
    assert!(
        findings(&root).contains(&"shell-rule-retired".to_owned()),
        "dropping ` 2>/dev/null` alongside the repointing is a second edit: {:?}",
        findings(&root)
    );
}

/// N4 — THE LOAD-BEARING NEGATIVE. Without the "span is a reference to a deleted
/// path" conjunct, the prefix/suffix decomposition admits replacing ANY single
/// contiguous span of ANY line that accompanies a deletion.
///
/// `$REPO_ROOT` is bound to something that is not this script's directory, so the
/// span names somebody else's tree and is not a reference to the dying program.
#[test]
fn replacing_a_span_that_is_not_a_reference_to_the_retired_path_is_refused() {
    let root = repo(
        "unrelated-span",
        &[
            ("mise-tasks/old-gate.sh", GATE),
            (
                "mise-tasks/caller.sh",
                "#!/usr/bin/env bash\nREPO_ROOT=/srv/build\npayload=\"$REPO_ROOT/tools/old-gate.sh\"\n",
            ),
        ],
        &Head {
            written: &[
                (
                    "mise-tasks/caller.sh",
                    "#!/usr/bin/env bash\nREPO_ROOT=/srv/build\npayload=mise run old-gate\n",
                ),
                (
                    "crates/batten/tests/old_gate.rs",
                    &ledger_running("mise-tasks/old-gate.sh", "mise run old-gate"),
                ),
            ],
            removed: &["mise-tasks/old-gate.sh"],
        },
    );
    assert!(
        findings(&root).contains(&"shell-rule-retired".to_owned()),
        "a span in somebody else's tree is not a reference to the retired path: {:?}",
        findings(&root)
    );
}

/// N7 — a malformed invocation field is not an invocation, so nothing may be
/// repointed at it.
#[test]
fn a_malformed_invocation_field_declares_no_command() {
    let root = repo(
        "malformed-runs",
        &[
            ("mise-tasks/old-gate.sh", GATE),
            (
                "mise-tasks/caller.sh",
                "#!/usr/bin/env bash\nlint=\"$(dirname \"$0\")/old-gate.sh\"\nprintf '%s' \"$x\" | \"$lint\" 2>/dev/null\n",
            ),
        ],
        &Head {
            written: &[
                (
                    "mise-tasks/caller.sh",
                    "#!/usr/bin/env bash\nprintf '%s' \"$x\" | mise run old-gate 2>/dev/null\n",
                ),
                (
                    "crates/batten/tests/old_gate.rs",
                    "// carried: mise-tasks/old-gate.sh policy/old-gate.rego crates/batten/tests/old_gate.rs runs:\n",
                ),
            ],
            removed: &["mise-tasks/old-gate.sh"],
        },
    );
    assert!(
        findings(&root).contains(&"shell-rule-retired".to_owned()),
        "an empty `runs:` tail is not a command: {:?}",
        findings(&root)
    );
}

/// `board-sweep.sh`'s computed name — REFUSED under CLOUD-1149, admitted now.
///
/// This case was written as a stated refusal so the gap could not be discovered
/// mid-retirement, and CLOUD-1224 closed it. It is rewritten rather than
/// replaced, so the change of verdict is visible in one diff.
///
/// The shape is `board-sweep.sh:229` exactly: a loop that names TASKS and builds
/// the filename (CLOUD-865), so the line carries `old-gate` and no path at all.
/// Nothing is shortened, nothing is repointed — the honest edit is that a name
/// goes away and nothing replaces it.
#[test]
fn a_retired_name_dropped_from_a_list_is_admitted() {
    let root = repo(
        "computed-name",
        &[
            ("mise-tasks/old-gate.sh", GATE),
            (
                "mise-tasks/caller.sh",
                "#!/usr/bin/env bash\nhere=\"$(dirname \"$0\")\"\nfor gate in old-gate other-gate; do\n\t[[ -x \"$here/$gate.sh\" ]] || exit 1\ndone\n",
            ),
        ],
        &Head {
            written: &[
                (
                    "mise-tasks/caller.sh",
                    "#!/usr/bin/env bash\nhere=\"$(dirname \"$0\")\"\nfor gate in other-gate; do\n\t[[ -x \"$here/$gate.sh\" ]] || exit 1\ndone\n",
                ),
                (
                    "crates/batten/tests/old_gate.rs",
                    &ledger_running("mise-tasks/old-gate.sh", "mise run old-gate"),
                ),
            ],
            removed: &["mise-tasks/old-gate.sh"],
        },
    );
    assert!(
        !findings(&root).contains(&"shell-rule-retired".to_owned()),
        "dropping the name of a gate this delta retires is the honest edit, and \
         both halves see it: the removed line mentions `old-gate` and the added \
         line is that line minus exactly that name: {:?}",
        findings(&root)
    );
}

/// THE MUTATION'S DISCRIMINATOR — the name goes, and something else moves too.
///
/// `#MUTANT list-drop-not-exact` weakens the byte-exact join to `startswith`,
/// and this is the case that catches it: the retired name is dropped, which
/// satisfies every earlier conjunct, and a comment is appended, which the real
/// clause refuses and the weakened one would admit. Without it the mutation
/// survives — the negative below is excluded by `naming_forms` before the join
/// is ever reached, so it proves nothing about exactness.
#[test]
fn dropping_the_name_while_also_changing_the_line_is_refused() {
    let root = repo(
        "computed-name-and-more",
        &[
            ("mise-tasks/old-gate.sh", GATE),
            (
                "mise-tasks/caller.sh",
                "#!/usr/bin/env bash\nhere=\"$(dirname \"$0\")\"\nfor gate in old-gate other-gate; do\n\t[[ -x \"$here/$gate.sh\" ]] || exit 1\ndone\n",
            ),
        ],
        &Head {
            written: &[
                (
                    "mise-tasks/caller.sh",
                    "#!/usr/bin/env bash\nhere=\"$(dirname \"$0\")\"\nfor gate in other-gate; do # tidied\n\t[[ -x \"$here/$gate.sh\" ]] || exit 1\ndone\n",
                ),
                (
                    "crates/batten/tests/old_gate.rs",
                    &ledger_running("mise-tasks/old-gate.sh", "mise run old-gate"),
                ),
            ],
            removed: &["mise-tasks/old-gate.sh"],
        },
    );
    assert!(
        findings(&root).contains(&"shell-rule-retired".to_owned()),
        "the name is one this delta retires, so the arm is reached — and the added \
         line is not the removed one minus that name, so it is still refused: {:?}",
        findings(&root)
    );
}

/// THE NEGATIVE, and it is what stops the arm above being a licence to edit a
/// list. Same delta, same deleted program — but the name dropped is `other-gate`,
/// which this change retires nothing of. Without this case the arm is satisfied
/// by one that admits removing ANY token from a line accompanying a deletion.
#[test]
fn dropping_a_name_this_delta_does_not_retire_is_still_refused() {
    let root = repo(
        "computed-name-unrelated",
        &[
            ("mise-tasks/old-gate.sh", GATE),
            (
                "mise-tasks/caller.sh",
                "#!/usr/bin/env bash\nhere=\"$(dirname \"$0\")\"\nfor gate in old-gate other-gate; do\n\t[[ -x \"$here/$gate.sh\" ]] || exit 1\ndone\n",
            ),
        ],
        &Head {
            written: &[
                (
                    "mise-tasks/caller.sh",
                    "#!/usr/bin/env bash\nhere=\"$(dirname \"$0\")\"\nfor gate in old-gate; do\n\t[[ -x \"$here/$gate.sh\" ]] || exit 1\ndone\n",
                ),
                (
                    "crates/batten/tests/old_gate.rs",
                    &ledger_running("mise-tasks/old-gate.sh", "mise run old-gate"),
                ),
            ],
            removed: &["mise-tasks/old-gate.sh"],
        },
    );
    assert!(
        findings(&root).contains(&"shell-rule-retired".to_owned()),
        "`other-gate` names nothing this delta deletes, so dropping it is an \
         ordinary edit to a governed program and stays refused: {:?}",
        findings(&root)
    );
}

/// The invocation field is ADDITIVE: it satisfies neither successor obligation.
///
/// Without this the grammar could be spent as a cheaper way past the two
/// clauses that make a retirement owe a module and a compiled-binary test.
#[test]
fn an_invocation_field_does_not_satisfy_the_successor_obligations() {
    let root = repo(
        "runs-only",
        &[("mise-tasks/old-gate.sh", GATE)],
        &Head {
            written: &[(
                "crates/batten/tests/old_gate.rs",
                "// carried: mise-tasks/old-gate.sh runs:mise+run+old-gate\n",
            )],
            removed: &["mise-tasks/old-gate.sh"],
        },
    );
    assert!(
        !findings(&root).is_empty(),
        "a `runs:` field is not a policy surface and not a compiled-binary test: {:?}",
        findings(&root)
    );
}
