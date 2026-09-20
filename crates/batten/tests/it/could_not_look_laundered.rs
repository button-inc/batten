//! CLOUD-1776's ratchet, over the ENGINE's own `base-delta` and line projection.
//!
//! # What this tier reaches and the load-time one cannot
//!
//! The module's own `test_` rules drive `with input as`, which fabricates the
//! very document the engine may be unable to produce. This rule turns on two
//! facts the engine builds and a fixture cannot vouch for: that
//! `input.tree["base-delta"]` resolves against a real base rev, and that
//! `input.tree.lines` is populated for the globs the row declares. A missing
//! `line_sources` glob is the live defect `batten.toml` records one row up — the
//! arm went undefined for half the corpus while every synthetic case passed.
//!
//! # The pair is the point
//!
//! `an_added_swallowing_call_is_refused` alone is satisfied by a module that
//! refuses every line. `an_existing_swallowing_call_is_grandfathered` is what
//! rules that out, and it is also the whole reason the row reads a delta rather
//! than the state: three occurrences are live on `main` and none of them is
//! repairable, because `mise-tasks/**` admits only retire-whole or leave-alone.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::fs;
use std::path::{Path, PathBuf};

use batten::rules::{self, Rule};

/// The class the module raises, and the pointer every refusal carries.
const LAUNDERED: &str = "gate run unsafe";

/// The defect, in the spelling `closing-key-check.sh:193` uses.
const SWALLOWING: &str = "\tserved=$(batten claim keys --refs-first-only 2>/dev/null || true)";

/// The same call keeping its status — the idiom the corpus already carries at
/// `landed-check.sh:214`, and the one the refusal's route points at.
const KEEPING: &str = "\tif ! served=$(batten claim keys --refs-first-only 2>/dev/null); then";

/// `command -v batten`, where an empty answer IS the answer. Live at
/// `payload-field.sh:72`, and a false positive until the module negated it.
const PROBE: &str = "\t\"$(command -v batten 2>/dev/null || true)\"; do";

/// The word inside a PATH rather than as a callee. Live at `graph-check.sh:924`,
/// and the false positive the pattern's trailing `[[:space:]]` exists to kill.
const RECEIPT_PATH: &str = "\t>\"$git_dir/batten-receipts/board-move.$id\" 2>/dev/null || true";

/// A swallowing call over a program that is not this engine. Roughly thirty sites
/// spell this, and refusing them would make the rule noise rather than a gate.
const OTHER_PROGRAM: &str = "\tbody=$(git log -1 --format=%B 2>/dev/null || true)";

/// A fixture repository whose base is one commit back, so the engine's own
/// `base-delta` resolution produces the fact under test.
///
/// `base` carries the files as the base rev had them; `head` is written after the
/// commit and left uncommitted, which is what puts a path in `added` or `edited`
/// rather than in neither.
///
/// `origin/main` is a local ref pointed at the base commit: `base_delta` resolves
/// a rev, and configuring a remote would make an entirely local question depend
/// on the network. Same shape as `fixture_forks.rs`.
// needs-real-fixture: CLOUD-1776 these fixtures need a real base ref for the
// engine to resolve `base-delta` against, so `repo` builds history with real
// git. A template copy carries no commits and this tier's whole point is driving
// the engine over a branch that has some.
fn repo(name: &str, base: &[(&str, &str)], head: &[(&str, &str)]) -> PathBuf {
    let root = common::scratch(name);
    common::git_in(&root, &["init", "--quiet"]);
    write_all(&root, base);
    // A seed so the base commit is never empty even when `base` is.
    fs::write(root.join("seed.txt"), "seed\n").expect("seed");
    common::git_in(&root, &["add", "-A"]);
    common::git_in(&root, &["commit", "--quiet", "-m", "base"]);
    let at = common::git_in(&root, &["rev-parse", "HEAD"]);
    common::git_in(&root, &["update-ref", "refs/remotes/origin/main", &at]);

    write_all(&root, head);
    install_module(&root);
    root
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

/// The COMMITTED module, copied rather than re-typed. A fixture carrying its own
/// copy of the predicate would pass while the shipped one was broken, which is
/// the fidelity failure this tier exists to catch.
fn install_module(root: &Path) {
    let source = common::at_root("policy/could-not-look-laundered.rego")
        .canonicalize()
        .expect("the committed module is where the row says it is");
    fs::create_dir_all(root.join("policy")).expect("scratch policy dir");
    fs::copy(source, root.join("policy/could-not-look-laundered.rego"))
        .expect("install committed module");
}

/// The committed row's shape, so a registration the loader would reject cannot
/// pass here.
fn row() -> Rule {
    serde_json::from_value(serde_json::json!({
        "id": LAUNDERED,
        "kind": "policy",
        "scope": "tree",
        "base": "origin/main",
        "delta_sources": ["mise-tasks/*.sh"],
        "line_sources": ["mise-tasks/*.sh"],
        "module": "policy/could-not-look-laundered.rego",
        "severity": "deny",
    }))
    .expect("the loader accepts the committed row's shape")
}

fn scan(root: &Path) -> rules::Scan {
    let verdicts = common::verdicts_in(root);
    // THE COMMITTED PATTERNS, never a fixture copy. The two rows this module
    // dereferences by name are half the predicate, and a re-typed regex here
    // would pass while the shipped one over-matched — which is exactly the
    // failure the two-row design was measured into existence to avoid.
    let patterns = common::committed_patterns();
    rules::run_static(
        &[row()],
        &[],
        batten::policy::Vocabulary {
            patterns: &patterns,
            verdicts: &verdicts,
            words: None,
            recorders: &[],
        },
        root,
    )
    .expect("the read surface runs a policy row")
}

fn verdicts(root: &Path) -> Vec<String> {
    scan(root)
        .findings
        .into_iter()
        .map(|finding| finding.rule)
        .collect()
}

// ---------------------------------------------------------------------------
// The pass side first: without it every refusal below is satisfied by a module
// that refuses everything.
// ---------------------------------------------------------------------------

#[test]
fn a_branch_adding_no_swallowing_call_passes_untouched() {
    let root = repo(
        "laundered-clean",
        &[],
        &[(
            "mise-tasks/probe.sh",
            &format!("#!/usr/bin/env bash\n{KEEPING}\n"),
        )],
    );
    assert!(
        verdicts(&root).is_empty(),
        "a call that keeps its status is the idiom the refusal points at"
    );
}

/// THE ROW `#MUTANT swallowed-resolver-unread` MUST REDDEN on this case.
#[test]
fn an_added_swallowing_call_is_refused() {
    let root = repo(
        "laundered-added",
        &[],
        &[(
            "mise-tasks/probe.sh",
            &format!("#!/usr/bin/env bash\n{SWALLOWING}\n"),
        )],
    );
    assert_eq!(
        verdicts(&root),
        vec![LAUNDERED.to_owned()],
        "a new call discarding this engine's status is refused, and the engine's \
         own base-delta plus line projection is what has to surface it"
    );
}

/// THE RATCHET'S OTHER HALF, and the reason the row reads a delta at all.
///
/// `#MUTANT laundered-delta-unbounded` widens the line walk from the added lines
/// to the whole file, which reddens exactly here and nowhere else.
#[test]
fn an_existing_swallowing_call_is_grandfathered() {
    let body = format!("#!/usr/bin/env bash\n{SWALLOWING}\n");
    let root = repo(
        "laundered-existing",
        &[("mise-tasks/probe.sh", &body)],
        &[(
            "mise-tasks/probe.sh",
            &format!("{body}# a later, harmless edit\n"),
        )],
    );
    assert!(
        verdicts(&root).is_empty(),
        "an occurrence this change did not introduce is not this change's to answer \
         for — three are live on main and none of them is repairable in place"
    );
}

/// Editing a governed file to ADD the line is refused, which keeps the case above
/// from being satisfied by a module that never fires on an edit at all.
#[test]
fn a_swallowing_call_added_by_an_edit_is_refused() {
    let root = repo(
        "laundered-edited",
        &[(
            "mise-tasks/probe.sh",
            "#!/usr/bin/env bash\n# nothing yet\n",
        )],
        &[(
            "mise-tasks/probe.sh",
            &format!("#!/usr/bin/env bash\n# nothing yet\n{SWALLOWING}\n"),
        )],
    );
    assert_eq!(
        verdicts(&root),
        vec![LAUNDERED.to_owned()],
        "the grandfather clause is about lines the base had, not about files it had"
    );
}

// ---------------------------------------------------------------------------
// The three shapes that look like the defect and are not. Each was a measured
// false positive against the real corpus before the pattern took its final form.
// ---------------------------------------------------------------------------

/// `#MUTANT probe-exclusion-dropped` reddens here: it is the whole reason the
/// exclusion is a second pattern rather than a narrowing of the first.
#[test]
fn an_existence_probe_is_not_refused() {
    let root = repo(
        "laundered-probe",
        &[],
        &[(
            "mise-tasks/probe.sh",
            &format!("#!/usr/bin/env bash\n{PROBE}\n"),
        )],
    );
    assert!(
        verdicts(&root).is_empty(),
        "`command -v batten` asks whether the binary resolves, so an empty answer \
         IS the answer and forcing success is how the question is spelled"
    );
}

#[test]
fn the_word_inside_a_path_is_not_a_call() {
    let root = repo(
        "laundered-path",
        &[],
        &[(
            "mise-tasks/probe.sh",
            &format!("#!/usr/bin/env bash\n{RECEIPT_PATH}\n"),
        )],
    );
    assert!(
        verdicts(&root).is_empty(),
        "this repository names its own directories after itself, so `batten-receipts` \
         in a redirect is not an invocation — the pattern's trailing space is what \
         tells them apart"
    );
}

#[test]
fn a_swallowing_call_over_another_program_is_not_refused() {
    let root = repo(
        "laundered-other",
        &[],
        &[(
            "mise-tasks/probe.sh",
            &format!("#!/usr/bin/env bash\n{OTHER_PROGRAM}\n"),
        )],
    );
    assert!(
        verdicts(&root).is_empty(),
        "`2>/dev/null || true` is not itself the defect: thirty-odd sites spell it \
         over git, jq, rm and printf, where an empty result genuinely is the answer"
    );
}

#[test]
fn an_ungoverned_path_is_not_judged() {
    let root = repo(
        "laundered-ungoverned",
        &[],
        &[("crates/batten/src/probe.rs", &format!("// {SWALLOWING}\n"))],
    );
    assert!(
        verdicts(&root).is_empty(),
        "the row governs mise-tasks shell and nothing else, however the line is spelled"
    );
}
