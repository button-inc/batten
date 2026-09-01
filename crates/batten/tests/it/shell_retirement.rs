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

use crate::common;

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
        // MIRRORS THE COMMITTED ROW, and `tests/**/*.bats` is load-bearing
        // rather than tidiness, for two independent reasons that both landed.
        // CLOUD-1294: without the entry a suite's lines are never read, so
        // `base-lines` has no entry for it and every case below would pass or
        // fail for the wrong reason. CLOUD-1088: the added arm's admission
        // clause reads `input.tree.lines[path]`, so a fixture whose
        // `line_sources` did not reach a bats path would evaluate that clause
        // over a key nothing fills and report the declaration ignored — on
        // exactly the surface the row is about.
        "line_sources": ["mise-tasks/*.sh", "crates/batten/tests/**/*.rs", "tests/**/*.bats"],
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

/// An arm whose only policy surface is ENGINE SOURCE, with no kind declared
/// (CLOUD-1182). This is the shape all 113 landed engine-source arms had before
/// this change annotated them.
fn ledger_engine(retired: &str) -> String {
    format!("// carried: {retired} crates/batten/src/old_gate.rs crates/batten/tests/old_gate.rs\n")
}

/// The same arm with its kind declared.
fn ledger_engine_kind(retired: &str, kind: &str) -> String {
    format!(
        "// carried: {retired} crates/batten/src/old_gate.rs kind:{kind} crates/batten/tests/old_gate.rs\n"
    )
}

/// A PORT-WITHOUT-RETIREMENT arm (CLOUD-1268): where the cases went, plus the
/// surviving subject the port still accounts for. It names no policy surface, and
/// that is the shape rather than an omission — a port lands none.
fn ledger_ported(retired: &str, subject: &str) -> String {
    format!("// ported: {retired} crates/batten/tests/old_gate.rs subject:{subject}\n")
}

/// A suite whose subject is one this campaign never retires — the 16-suite class
/// CLOUD-1268 exists for, in miniature.
const IMMORTAL_SUITE: &str = "# subject: tests/helpers.bash\n@test \"it holds\" {\n  true\n}\n";

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

// ---------------------------------------------------------------------------
// The fifth arm: a PORT whose subject survives (CLOUD-1268).
//
// Over the binary rather than as `with input as` cases, for this file's own
// reason: the arm reads `data.batten.patterns["retirement-subject-field"]`, and a
// fabricated vocabulary would pass over a pattern row the committed config does
// not carry — a dead gate byte-identical to a clean tree. `scan` derives the
// pattern table from the COMMITTED config, so these cases fail if the row is
// missing rather than quietly deciding nothing.
// ---------------------------------------------------------------------------

/// THE POSITIVE ARM, and the whole 16-suite class in miniature: the suite dies,
/// `tests/helpers.bash` does not, and the row names both where the cases went and
/// the survivor it still accounts for.
#[test]
fn a_port_naming_its_surviving_subject_passes() {
    let root = repo(
        "ported",
        &[
            ("tests/old-gate.bats", IMMORTAL_SUITE),
            ("tests/helpers.bash", "helpers\n"),
        ],
        &Head {
            written: &[(
                "crates/batten/tests/old_gate.rs",
                &ledger_ported("tests/old-gate.bats", "tests/helpers.bash"),
            )],
            removed: &["tests/old-gate.bats"],
        },
    );
    assert!(
        findings(&root).is_empty(),
        "a port that names where the cases went and what survived is accounted for: {:?}",
        findings(&root)
    );
}

/// THE ANTI-VACUITY MIRROR for the surface exemption. `ported_arm` waives the
/// policy-surface obligation, so without this the case above is satisfied by a
/// module that waived it for everyone — and the campaign's whole successor
/// discipline would be one word away from off.
#[test]
fn the_surface_obligation_still_binds_a_carried_row() {
    let root = repo(
        "ported-surface-still-binds",
        &[("tests/old-gate.bats", IMMORTAL_SUITE)],
        &Head {
            written: &[(
                "crates/batten/tests/old_gate.rs",
                "// carried: tests/old-gate.bats crates/batten/tests/old_gate.rs\n",
            )],
            removed: &["tests/old-gate.bats"],
        },
    );
    assert!(
        !findings(&root).is_empty(),
        "the exemption is scoped to the port arm, not granted to the ledger"
    );
}

/// AND THE COVERAGE OBLIGATION IS NOT WAIVED. The compiled-binary test is not
/// incidental to a port, it IS the port: the subject is alive and still needs
/// testing. So the arm that could be waived is, and the one carrying the coverage
/// is not — which is the difference this case exists to pin.
#[test]
fn a_port_naming_no_binary_test_is_refused() {
    let root = repo(
        "ported-no-test",
        &[
            ("tests/old-gate.bats", IMMORTAL_SUITE),
            ("tests/helpers.bash", "helpers\n"),
        ],
        &Head {
            written: &[(
                "crates/batten/tests/old_gate.rs",
                "// ported: tests/old-gate.bats policy/old-gate.rego subject:tests/helpers.bash\n",
            )],
            removed: &["tests/old-gate.bats"],
        },
    );
    assert!(
        !findings(&root).is_empty(),
        "a port that lands no test has deleted coverage and replaced nothing"
    );
}

/// A port that names no survivor is a `carried` row that has additionally been
/// excused its policy surface — strictly weaker than the marker it imitates.
#[test]
fn a_port_naming_no_subject_is_refused() {
    let root = repo(
        "ported-unnamed",
        &[("tests/old-gate.bats", IMMORTAL_SUITE)],
        &Head {
            written: &[(
                "crates/batten/tests/old_gate.rs",
                "// ported: tests/old-gate.bats crates/batten/tests/old_gate.rs\n",
            )],
            removed: &["tests/old-gate.bats"],
        },
    );
    assert!(
        !findings(&root).is_empty(),
        "naming the survivor is the whole arm"
    );
}

/// THE ARM THAT KEEPS CLOUD-1130 WHOLE. A live GOVERNED subject must be retired
/// rather than ported around: without this, naming `mise-tasks/old-gate.sh` as the
/// survivor buys exactly the deletion `shell retire never` refuses under
/// the other four markers — the same claim, decided by which word was typed.
#[test]
fn a_port_naming_a_live_governed_subject_is_refused() {
    let root = repo(
        "ported-governed",
        &[
            ("tests/old-gate.bats", SUITE),
            ("mise-tasks/old-gate.sh", GATE),
        ],
        &Head {
            written: &[(
                "crates/batten/tests/old_gate.rs",
                &ledger_ported("tests/old-gate.bats", "mise-tasks/old-gate.sh"),
            )],
            removed: &["tests/old-gate.bats"],
        },
    );
    assert!(
        !findings(&root).is_empty(),
        "a governed survivor is retired, never ported around"
    );
}

/// THE THIRD `ported` REFUSAL, and the one that shipped with no mutation over
/// it. A subject that DIED is not a surviving one: that is a plain retirement,
/// which `carried` already spells with less, and admitting the same event under
/// both markers lets the ledger record it in two vocabularies.
///
/// Its absence from THIS file is what the missing `#MUTANT` row was hiding, and
/// the gap was two-deep rather than one. The load-time tier pinned the predicate
/// and `ratchet.rs` pinned the case granularity, but neither is the suite
/// `#MUTANT-SUITE` names — so a mutation of this arm had nothing here to redden
/// and could only ever have been declared as a survivor (CLOUD-1302).
///
/// `tests/helpers.bash` is deliberately the dying subject. It is neither a
/// `.bats` nor under `mise-tasks/`, so `governed_when_deleted` does not select
/// it and its own deletion owes no arm — which leaves this arm the only one that
/// can fire, and is what makes the mutation discriminate rather than survive
/// behind a conjunct some other arm already excludes.
#[test]
fn a_port_over_a_subject_that_died_is_refused() {
    let root = repo(
        "ported-subject-died",
        &[
            ("tests/old-gate.bats", IMMORTAL_SUITE),
            ("tests/helpers.bash", "helpers\n"),
        ],
        &Head {
            written: &[(
                "crates/batten/tests/old_gate.rs",
                &ledger_ported("tests/old-gate.bats", "tests/helpers.bash"),
            )],
            removed: &["tests/old-gate.bats", "tests/helpers.bash"],
        },
    );
    assert!(
        !findings(&root).is_empty(),
        "a port whose subject died is a retirement, and `carried` is its spelling"
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
/// ARM 5 — a caller that names its callee as a TASK, not as a path (CLOUD-1299).
///
/// The measured instance is a governed `.bats` pinning a remedy's PROSE:
/// `tests/verify.bats` asserted that `verify`'s refusal names `bot-issue
/// receipt`. Retiring the program that names makes the remedy false, changing
/// the remedy fails the assertion, and editing a governed suite is refused with
/// no override route — so the retirement had no landable shape at all. Both
/// spellings are driven here because they are the two the tree carries and only
/// one of them is anchored at the name: the bare `<task> <sub>` span, and the
/// `mise run <task> <sub>` span a comment three lines away used.
#[test]
fn an_edit_repointing_a_task_name_at_the_declared_invocation_is_admitted() {
    let root = repo(
        "task-name-repointed",
        &[
            ("mise-tasks/old-gate.sh", GATE),
            (
                "tests/pinned.bats",
                "# minted by `mise run old-gate receipt` on a branch.\n@test \"it holds\" {\n  [[ \"$output\" == *\"old-gate receipt\"* ]]\n}\n",
            ),
        ],
        &Head {
            written: &[
                (
                    "tests/pinned.bats",
                    "# minted by `batten claim bot` on a branch.\n@test \"it holds\" {\n  [[ \"$output\" == *\"batten claim bot\"* ]]\n}\n",
                ),
                (
                    "crates/batten/tests/old_gate.rs",
                    &ledger_running("mise-tasks/old-gate.sh", "batten claim bot"),
                ),
            ],
            removed: &["mise-tasks/old-gate.sh"],
        },
    );
    assert!(
        findings(&root).is_empty(),
        "a caller naming its callee as a task may be repointed at the declared \
         invocation, same as one naming it by path: {:?}",
        findings(&root)
    );
}

/// ANTI-VACUITY for the case above, and the one CLOUD-1299 names by hand: an arm
/// that admitted any span merely CONTAINING a naming form would be the licence
/// the module refuses in as many words. This edit repoints the same span AND
/// flips the comparison on the same line, so nothing about the retirement
/// accounts for the second change.
#[test]
fn an_edit_repointing_a_task_name_while_rewriting_the_line_is_refused() {
    let root = repo(
        "task-name-rewritten",
        &[
            ("mise-tasks/old-gate.sh", GATE),
            (
                "tests/pinned.bats",
                "@test \"it holds\" {\n  [[ \"$output\" == *\"old-gate receipt\"* ]]\n}\n",
            ),
        ],
        &Head {
            written: &[
                (
                    "tests/pinned.bats",
                    "@test \"it holds\" {\n  [[ \"$output\" != *\"batten claim bot\"* ]]\n}\n",
                ),
                (
                    "crates/batten/tests/old_gate.rs",
                    &ledger_running("mise-tasks/old-gate.sh", "batten claim bot"),
                ),
            ],
            removed: &["mise-tasks/old-gate.sh"],
        },
    );
    assert_eq!(
        findings(&root),
        vec![String::from("shell-rule-retired")],
        "the span is derived from the diff, so a line that also changed elsewhere \
         has no single repointed span and is refused"
    );
}

/// The second anti-vacuity axis: the TARGET still comes from the ledger. A task
/// span may only be repointed at an invocation the retirement committed to, so
/// an arm carrying no `runs:` field admits nothing.
#[test]
fn a_task_name_repointed_at_an_undeclared_invocation_is_refused() {
    let root = repo(
        "task-name-undeclared",
        &[
            ("mise-tasks/old-gate.sh", GATE),
            (
                "tests/pinned.bats",
                "@test \"it holds\" {\n  [[ \"$output\" == *\"old-gate receipt\"* ]]\n}\n",
            ),
        ],
        &Head {
            written: &[
                (
                    "tests/pinned.bats",
                    "@test \"it holds\" {\n  [[ \"$output\" == *\"batten claim bot\"* ]]\n}\n",
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
        "without a `runs:` arm there is no declared invocation, so nothing admits \
         the repointing"
    );
}

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

/// CLOUD-1088, and this is the tier that matters for it.
///
/// The load-time cases prove the PREDICATE honours the declaration. Only this one
/// proves the ENGINE hands it the lines to honour: the clause reads
/// `input.tree.lines[path]`, and until this change `line_sources` reached
/// `mise-tasks/` and the Rust tests and nothing else — so on a `tests/**` suite
/// the key was empty, the clause could not hold, and the route `shell add
/// refused` advertises cleared a different rule while leaving this one standing.
/// A `with input as` case cannot see that, because it fabricates the very shape
/// the engine may be unable to produce.
#[test]
fn an_added_bats_suite_declaring_it_stays_bash_is_admitted() {
    let root = repo(
        "added-bats-stays",
        &[],
        &Head {
            written: &[(
                "tests/new-gate.bats",
                "# stays-bash: CLOUD-312 door-tier suite over the compiled binary\n@test \"x\" {\n  true\n}\n",
            )],
            removed: &[],
        },
    );
    assert!(
        findings(&root).is_empty(),
        "the declared route must clear the verdict that offers it: {:?}",
        findings(&root)
    );
}

/// The bound that keeps the case above from being a blanket allow.
///
/// An EDIT stays refused with the declaration present. `shell edit refused`
/// carries one route and no override on purpose — an edit is the move that reads
/// as progress and is not — so the admission must not reach it.
#[test]
fn the_stays_bash_declaration_does_not_admit_an_edit() {
    let root = repo(
        "edited-bats-stays",
        &[("tests/old-gate.bats", SUITE)],
        &Head {
            written: &[(
                "tests/old-gate.bats",
                "# stays-bash: CLOUD-843 not a licence to edit in place\n@test \"x\" {\n  true\n}\n",
            )],
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

/// The successor KIND obligation, over the engine (CLOUD-1182).
///
/// Over the binary rather than `with input as`, for `.claude/rules/policy-modules.md`'s
/// reason: the module's own cases fabricate the `lines` map, so they pass over a
/// field the boundary might never carry into `successors_for`. `kind:` rides the
/// same space-separated row the invocation field does, and this is what shows the
/// engine hands it through rather than swallowing it as a path.
#[test]
fn an_engine_source_arm_without_a_declared_kind_is_refused() {
    let root = repo(
        "kind-undeclared",
        &[("mise-tasks/old-gate.sh", GATE)],
        &Head {
            written: &[(
                "crates/batten/tests/old_gate.rs",
                &ledger_engine("mise-tasks/old-gate.sh"),
            )],
            removed: &["mise-tasks/old-gate.sh"],
        },
    );
    assert_eq!(findings(&root), vec!["shell-rule-retired".to_owned()]);
}

/// The anti-vacuity mirror, and the case that proves this gate does not ban a
/// verb — CLOUD-1182 puts "forbidding a verb successor" explicitly out of scope,
/// because a gate needing stdin or performing a write cannot be a tree-scoped
/// module. Without this case the refusal above is satisfied by a module that
/// refuses every engine-source retirement.
#[test]
fn a_declared_verb_successor_is_admitted() {
    let root = repo(
        "kind-verb",
        &[("mise-tasks/old-gate.sh", GATE)],
        &Head {
            written: &[(
                "crates/batten/tests/old_gate.rs",
                &ledger_engine_kind("mise-tasks/old-gate.sh", "verb"),
            )],
            removed: &["mise-tasks/old-gate.sh"],
        },
    );
    assert!(
        findings(&root).is_empty(),
        "a declared verb successor loads clean: {:?}",
        findings(&root)
    );
}

/// `mechanism` is the other admitted value, and it is here rather than folded
/// into the case above because a pattern accepting only `verb` would pass that
/// one while refusing the 36 landed arms this change annotates.
#[test]
fn a_declared_mechanism_successor_is_admitted() {
    let root = repo(
        "kind-mechanism",
        &[("mise-tasks/old-gate.sh", GATE)],
        &Head {
            written: &[(
                "crates/batten/tests/old_gate.rs",
                &ledger_engine_kind("mise-tasks/old-gate.sh", "mechanism"),
            )],
            removed: &["mise-tasks/old-gate.sh"],
        },
    );
    assert!(
        findings(&root).is_empty(),
        "a declared mechanism successor loads clean: {:?}",
        findings(&root)
    );
}

/// A consumer-module successor needs no declaration, because its path already
/// decides it. This is the conjunct that keeps the field off every other arm, and
/// `a_deleted_and_fully_mapped_shell_rule_passes` above would not catch its loss:
/// that case names a module too, so a rule demanding the field of EVERY arm is
/// caught here and by that case alike — which is why this one names the reason.
#[test]
fn a_module_successor_needs_no_declared_kind() {
    let root = repo(
        "kind-not-owed",
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
        "a module successor owes no kind: {:?}",
        findings(&root)
    );
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

/// A bats suite whose two cases differ only in what they name, so the pair below
/// is byte-identical apart from which one the head drops (CLOUD-1294).
///
/// The first case greps the path the delta retires; the second names nothing
/// this change touches. Both close with `}` at column 0 and both carry the same
/// assertion line, which is deliberate: `removed` is a set of LINES, so the
/// shared lines are still present at head and never enter it. What the arm has
/// to admit is the opener and the naming line, and nothing else.
const CASE_SUITE: &str = "#!/usr/bin/env bats\n\
# subject: mise-tasks/other.sh\n\
\n\
@test \"the gate is wired\" {\n\
\trun grep -q mise-tasks/old-gate.sh wiring\n\
\t[ \"$status\" -eq 0 ]\n\
}\n\
\n\
@test \"something unrelated\" {\n\
\trun true\n\
\t[ \"$status\" -eq 0 ]\n\
}\n";

/// The retired case dropped, the unrelated one kept.
const CASE_SUITE_RETIRED_DROPPED: &str = "#!/usr/bin/env bats\n\
# subject: mise-tasks/other.sh\n\
\n\
@test \"something unrelated\" {\n\
\trun true\n\
\t[ \"$status\" -eq 0 ]\n\
}\n";

/// The unrelated case dropped, the retired one kept. The anti-vacuity mirror.
const CASE_SUITE_LIVE_DROPPED: &str = "#!/usr/bin/env bats\n\
# subject: mise-tasks/other.sh\n\
\n\
@test \"the gate is wired\" {\n\
\trun grep -q mise-tasks/old-gate.sh wiring\n\
\t[ \"$status\" -eq 0 ]\n\
}\n";

/// Only the retired case's OPENER dropped; its body, naming line included, stays.
const CASE_SUITE_OPENER_ONLY: &str = "#!/usr/bin/env bats\n\
# subject: mise-tasks/other.sh\n\
\n\
\trun grep -q mise-tasks/old-gate.sh wiring\n\
\t[ \"$status\" -eq 0 ]\n\
}\n\
\n\
@test \"something unrelated\" {\n\
\trun true\n\
\t[ \"$status\" -eq 0 ]\n\
}\n";

fn suite_repo(name: &str, head_suite: &str) -> PathBuf {
    repo(
        name,
        &[
            ("mise-tasks/old-gate.sh", GATE),
            ("mise-tasks/other.sh", GATE),
            ("tests/suite.bats", CASE_SUITE),
        ],
        &Head {
            written: &[
                ("tests/suite.bats", head_suite),
                (
                    "crates/batten/tests/old_gate.rs",
                    &ledger("mise-tasks/old-gate.sh"),
                ),
            ],
            removed: &["mise-tasks/old-gate.sh"],
        },
    )
}

/// CLOUD-1294. Retiring a program leaves the suites that TESTED it greping a file
/// that is gone, and dropping those cases is the cleanup the campaign mandates.
///
/// The arm above it admits only a removed LINE that names the retired path; a
/// case's opener, its assertions and its closing brace name nothing. Measured on
/// CLOUD-312 row 10 — three cases in two suites, and neither landable shape
/// reached them, because both suites declare subjects that survive.
#[test]
fn a_bats_case_testing_a_retired_path_may_be_dropped_with_it() {
    let root = suite_repo("bats-case-retired", CASE_SUITE_RETIRED_DROPPED);
    assert!(
        findings(&root).is_empty(),
        "a case that tested the retired path goes with it, exactly as the line that \
         named it does: {:?}",
        findings(&root)
    );
}

/// ANTI-VACUITY, and without it this arm is a licence to delete any case during
/// any retirement — the maintaining-in-place arm B exists to refuse.
///
/// Byte-identical to the case above apart from WHICH block the head drops.
#[test]
fn a_bats_case_testing_a_live_path_is_still_refused() {
    let root = suite_repo("bats-case-live", CASE_SUITE_LIVE_DROPPED);
    assert_eq!(
        findings(&root),
        vec![String::from("shell-rule-retired")],
        "the surviving case names nothing this delta retires, so dropping it is an \
         ordinary edit to a governed suite"
    );
}

/// A case is admitted when it DIES, never when it is merely opened up.
///
/// Deleting the opener and keeping the body would otherwise pass: the opener is
/// absent from the head, which is what identifies a dead block. The clause that
/// refuses it is `body in removed` — the line that named the retired path has to
/// have gone too.
#[test]
fn a_half_deleted_bats_case_is_still_refused() {
    let root = suite_repo("bats-case-half", CASE_SUITE_OPENER_ONLY);
    assert_eq!(
        findings(&root),
        vec![String::from("shell-rule-retired")],
        "a case whose naming line survives was edited, not retired"
    );
}

/// CLOUD-1283's bound-and-spent shape, one arm over. `container-preflight.bats`
/// binds its program once in `setup()` and every case greps `"$HOOK"`, so no line
/// inside a case carries a path at all and the first arm cannot reach it.
const BIND_SUITE: &str = "#!/usr/bin/env bats\n\
# subject: mise-tasks/other.sh\n\
\n\
setup() {\n\
\tHOOK=\"$BATS_TEST_DIRNAME/../mise-tasks/old-gate.sh\"\n\
}\n\
\n\
@test \"the gate is wired\" {\n\
\trun grep -q \"$HOOK\" wiring\n\
\t[ \"$status\" -eq 0 ]\n\
}\n\
\n\
@test \"something unrelated\" {\n\
\trun true\n\
\t[ \"$status\" -eq 0 ]\n\
}\n";

/// The binding goes with the case that spent it.
const BIND_SUITE_DROPPED: &str = "#!/usr/bin/env bats\n\
# subject: mise-tasks/other.sh\n\
\n\
setup() {\n\
}\n\
\n\
@test \"something unrelated\" {\n\
\trun true\n\
\t[ \"$status\" -eq 0 ]\n\
}\n";

/// The case goes, the binding stays. The anti-vacuity mirror for the same arm.
const BIND_SUITE_BINDING_KEPT: &str = "#!/usr/bin/env bats\n\
# subject: mise-tasks/other.sh\n\
\n\
setup() {\n\
\tHOOK=\"$BATS_TEST_DIRNAME/../mise-tasks/old-gate.sh\"\n\
}\n\
\n\
@test \"something unrelated\" {\n\
\trun true\n\
\t[ \"$status\" -eq 0 ]\n\
}\n";

fn bind_repo(name: &str, head_suite: &str) -> PathBuf {
    repo(
        name,
        &[
            ("mise-tasks/old-gate.sh", GATE),
            ("mise-tasks/other.sh", GATE),
            ("tests/binding.bats", BIND_SUITE),
        ],
        &Head {
            written: &[
                ("tests/binding.bats", head_suite),
                (
                    "crates/batten/tests/old_gate.rs",
                    &ledger("mise-tasks/old-gate.sh"),
                ),
            ],
            removed: &["mise-tasks/old-gate.sh"],
        },
    )
}

/// A case naming the retired path only through a variable dies with it, provided
/// the binding dies too.
#[test]
fn a_bats_case_spending_a_retired_binding_may_be_dropped_with_it() {
    let root = bind_repo("bats-bind-retired", BIND_SUITE_DROPPED);
    assert!(
        findings(&root).is_empty(),
        "the case spent a binding this delta retires, and the binding went with \
         it: {:?}",
        findings(&root)
    );
}

/// ANTI-VACUITY for the binding arm: a variable that survives buys nothing, so
/// dropping a case that spends it is an ordinary edit to a governed suite.
#[test]
fn a_bats_case_spending_a_surviving_binding_is_refused() {
    let root = bind_repo("bats-bind-kept", BIND_SUITE_BINDING_KEPT);
    assert_eq!(
        findings(&root),
        vec![String::from("shell-rule-retired")],
        "the binding is still there, so nothing about this case is going away"
    );
}
