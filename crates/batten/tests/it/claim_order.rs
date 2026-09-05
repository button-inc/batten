//! `policy/claim-order-is-stated.rego` decides over the compiled engine (CLOUD-1343).
//!
//! # Why this tier
//!
//! The module's own `test_` cases hand themselves a `lines` object, so they are
//! green over a shape the engine may never build — the hazard
//! `rules/policy-modules.md` names, and the reason both of its measured
//! instances were found by adding a tier like this rather than by reading. What
//! only the real boundary can prove here is that two MARKDOWN files reach a module
//! through `input.tree.lines` at all: if the engine built nothing for them, every
//! clause would read undefined, Rego would take undefined as does-not-hold, and
//! the module would load clean while deciding nothing. A dead gate and a tree that
//! still states the order are byte-identical on the decision surface.
//!
//! So the three drift cases below are the channel confirmation, not merely
//! coverage: each one can only go red if the lines actually arrived.
//!
//! # The case that carries the most
//!
//! `this_repository_states_the_order_today` runs the row over this checkout. Every
//! other fixture is a shape somebody wrote to fail; that one is the shape that has
//! to keep passing, and it is what says the committed prose still carries the
//! order rather than that a fixture of it would.
//!
//! # What this row does NOT decide
//!
//! Whether a given session actually claimed before branching. That is not a
//! property of the tree, and a rule resolving to it would be the model verdict
//! non-negotiable rule 3 forbids. The prose carries the position; this keeps the
//! prose from evaporating.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::fs;
use std::path::{Path, PathBuf};

use batten::rules::{self, Rule};

/// The row as `batten.toml` declares it, deserialized rather than
/// struct-literalled: `Rule` carries `deny_unknown_fields`, so this goes through
/// the same column census a consumer's config does.
fn row() -> Rule {
    serde_json::from_value(serde_json::json!({
        "id": "claim-order-is-stated",
        "kind": "policy",
        "scope": "tree",
        "line_sources": ["AGENTS.md", "rules/toolchain.md"],
        "module": "policy/claim-order-is-stated.rego",
        "severity": "deny",
    }))
    .expect("the row batten.toml declares")
}

/// The always-loaded file's clause, as it is landed.
const SOUND_INDEX: &str = "\
Move the `CLOUD-*` issue in lockstep: **Todo** = the ready queue;
**In Progress** = pulled — **branch first, then claim
ONCE** (`mise run claim-check`), then assign yourself.
";

/// The triggered file's two failure directions, as they are landed.
const SOUND_RULES: &str = "\
## BRANCH FIRST, THEN CLAIM ONCE

- **Claim, then branch.** The receipt is minted against the branch you were
  standing on, and the first edit on the real branch is refused.
- **Claim twice.** The second run arrives after the row has left Todo, reads it
  as held, and refuses `not-todo` against your own claim.
";

/// A scratch tree carrying the two instruction files, plus the committed module.
fn tree(name: &str, index: Option<&str>, rules_doc: Option<&str>) -> PathBuf {
    let root = common::scratch(&format!("claim-order-{name}"));
    if let Some(body) = index {
        common::write(&root, "AGENTS.md", body);
    }
    if let Some(body) = rules_doc {
        common::write(&root, "rules/toolchain.md", body);
    }
    install_module(&root);
    root
}

/// The COMMITTED module, copied in rather than restated: an inline copy would
/// drift from the shipped one and pass while the real gate was broken.
fn install_module(root: &Path) {
    let source = common::at_root("policy/claim-order-is-stated.rego")
        .canonicalize()
        .expect("the committed module is where the row says it is");
    fs::create_dir_all(root.join("policy")).expect("scratch policy dir");
    fs::copy(source, root.join("policy/claim-order-is-stated.rego"))
        .expect("install committed module");
}

/// Every finding's path, which is the whole of what this row points at.
///
/// **An EMPTY pattern vocabulary, deliberately.** A harness that declared pattern
/// ids would be supplying input no consumer supplies, and the deny cases would
/// then pass for the wrong reason (`rules/policy-modules.md`).
fn findings(root: &Path) -> Vec<String> {
    // A fixture holds this module and no other, so its own tree is the honest
    // vocabulary.
    findings_declared_by(root, root)
}

/// The same run, with the vocabulary taken from somewhere else.
///
/// The real checkout cannot supply its own: `verdicts_in` would collect every
/// module's tokens while only this row is loaded, and registry equality runs in
/// BOTH directions — the load is refused for every token nothing here emits.
fn findings_declared_by(root: &Path, vocabulary_root: &Path) -> Vec<String> {
    let verdicts = common::verdicts_in(vocabulary_root);
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
    .findings
    .into_iter()
    .map(|finding| finding.path)
    .collect()
}

#[test]
fn a_tree_that_states_the_order_is_clean() {
    // THE SILENT ARM, and it is load-bearing: every clause in this module is a
    // refusal, so one that fired on everything would satisfy each deny case below
    // while deciding nothing.
    let root = tree("sound", Some(SOUND_INDEX), Some(SOUND_RULES));
    assert!(
        findings(&root).is_empty(),
        "a tree stating the order and carrying both directions must be silent"
    );
}

#[test]
fn an_index_that_does_not_state_the_order_is_refused() {
    // `#MUTANT order-may-go-unstated` names this case. It is also half the channel
    // confirmation: it can only go red if `input.tree.lines["AGENTS.md"]` arrived.
    let root = tree(
        "unstated",
        Some("**In Progress** = pulled — claim ONCE, then assign yourself.\n"),
        Some(SOUND_RULES),
    );
    assert!(
        findings(&root).iter().any(|path| path == "AGENTS.md"),
        "an index that dropped the order must be refused, pointing at the index"
    );
}

#[test]
fn an_index_that_does_not_ask_for_one_claim_is_refused() {
    // BRANCHING FIRST IS NECESSARY AND NOT SUFFICIENT. The refusal that actually
    // bit, twice, arrives on the re-run after the row has left Todo, so an index
    // stating only "branch first" leaves a reader walking into it.
    let root = tree(
        "twice",
        Some("**In Progress** = pulled — branch first, then claim it.\n"),
        Some(SOUND_RULES),
    );
    assert!(
        findings(&root).iter().any(|path| path == "AGENTS.md"),
        "an index that does not ask for exactly one claim must be refused"
    );
}

#[test]
fn a_rules_file_missing_a_failure_direction_is_refused() {
    // `#MUTANT reason-may-go-unwritten` names this case, and it is the other half
    // of the channel confirmation — a different path, under a different directory.
    let root = tree(
        "one-direction",
        Some(SOUND_INDEX),
        Some("- **Claim, then branch.** The receipt is stranded.\n"),
    );
    assert!(
        findings(&root)
            .iter()
            .any(|path| path == "rules/toolchain.md"),
        "one failure direction alone is half a warning and must be refused"
    );
}

#[test]
fn the_finding_names_the_file_that_drifted() {
    // A reader told "the claim order is gone" needs to know WHICH of the two files
    // to open, so the finding must not point at whichever sorts first.
    let root = tree(
        "pointer",
        Some(SOUND_INDEX),
        Some("- **Claim, then branch.** The receipt is stranded.\n"),
    );
    let found = findings(&root);
    assert_eq!(
        found,
        vec![String::from("rules/toolchain.md")],
        "only the file that lost the text may be named"
    );
}

#[test]
fn an_index_without_the_rules_file_is_not_judged() {
    // THE FIXTURE SHAPE, and the case that keeps the committed configuration
    // usable over one. `cli::the_committed_repo_config_gates_a_repository` runs
    // the whole committed ruleset over a repository whose `AGENTS.md` is the
    // single word `instructions` and which has no `.claude/rules/` surface at
    // all — a tree that never made the split this row is about. Without the
    // `governed` conjunct every arm fires there, and the committed config's own
    // output case goes red.
    let root = tree("index-only", Some("instructions\n"), None);
    assert!(
        findings(&root).is_empty(),
        "a tree with no triggered rules file has not made this split"
    );
}

#[test]
fn a_tree_carrying_neither_file_is_never_refused() {
    // NOT-APPLICABLE IS NOT A FINDING. This is what keeps the committed row usable
    // over a fixture repository that carries neither file — the "foreign tree"
    // lesson every tree-scoped row here has to answer.
    let root = tree("foreign", None, None);
    assert!(
        findings(&root).is_empty(),
        "a tree carrying neither instruction file is not this row's business"
    );
}

#[test]
fn this_repository_states_the_order_today() {
    // THE CASE THAT CARRIES THE MOST. Every fixture above is a shape somebody wrote
    // to fail; this is the one that has to keep passing, and it is what says the
    // committed prose and the committed predicate still agree.
    let root = common::at_root(".")
        .canonicalize()
        .expect("this checkout is where the manifest says it is");
    // The vocabulary comes from a directory holding only this module, for the
    // reason `findings_declared_by` states; the scratch name is this case's own,
    // because nextest runs each case in its own process and a shared name is a
    // wipe under another process's read.
    let only = common::scratch("claim-order-vocabulary-real-tree");
    install_module(&only);
    let found = findings_declared_by(&root, &only);
    assert!(
        found.is_empty(),
        "this checkout must still state the claim order: {found:?}"
    );
}
