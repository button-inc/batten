//! `policy/hk-fix-selection.rego` decides over the compiled engine (CLOUD-681).
//!
//! # Why this tier
//!
//! The module's `test_` cases hand themselves a `lines` array and a `documents`
//! object, so they are green over a shape the engine may never build — the hazard
//! `.claude/rules/policy-modules.md` names, and the reason both of its measured
//! instances were found by adding this tier rather than by reading. Two things
//! here can only be proved against the real boundary: that a file the boundary
//! does NOT parse (`hk.pkl` is Pkl) still reaches a module through
//! `input.tree.lines`, and that `mise.toml`'s task table arrives as a keyed
//! object, so the unrouted-fixer class derives its subject from the repository's
//! own tasks rather than restating a list of tool names.
//!
//! # The case that carries the most
//!
//! `this_repository_is_clean_today` runs the row over this checkout. Every
//! fixture below is a shape somebody wrote to fail; that one is the shape that
//! has to keep passing, and it is what says the committed config and the
//! committed prose still agree rather than that a fixture of them would.
//!
//! # What this row does NOT decide, and where that half lives
//!
//! Whether hk's `fix` hook selects exactly the gate's fixer-bearing steps is
//! `fix-selection-complete`'s, a `command` row running `mise run
//! fix-selection-check`. It is not answerable from lines: it needs the config
//! evaluated, and evaluation is where the surprise was — the derived spelling
//! evaluates correctly under `pkl` while hk's own evaluator reads it as EMPTY.
//!
//! # The measurement behind the row
//!
//! Before the change, `hk fix --all --plan` on this checkout included 58 steps,
//! of which 7 declared a fixer: `test:bats`, the cargo `test` build,
//! `batten-check`, `policy-test`, `sbom-check` and `token-bench-check` all ran
//! under a task two authorities call the formatters-only subset. hk does not
//! no-op a step with no fixer under `fix`; it runs the step's check. Measured
//! end to end on one machine, `mise run fmt` went from **931s to 2s**.

// CLOUD-1268's fifth arm. `hk.pkl` is this repository's gate definition: it does
// not die and is not touched, so what is spelled here is a port WITHOUT a
// retirement, and every arm names the survivor it still accounts for.
//
// ported: tests/pre-commit-staging.bats crates/batten/tests/hk_fix_selection.rs subject:hk.pkl
// ported: "a commit contains only what was staged, with another change dirty in the tree" crates/batten/tests/hk_fix_selection.rs subject:hk.pkl
// ported: "THE DEFECT: the unstaged change survives the fixer byte-for-byte" crates/batten/tests/hk_fix_selection.rs subject:hk.pkl
// ported: "SHOWN ABLE TO FAIL: without the setting, the fixer clobbers the unstaged change" crates/batten/tests/hk_fix_selection.rs subject:hk.pkl
// ported: "the fixer's own change to a staged file reaches the commit" crates/batten/tests/hk_fix_selection.rs subject:hk.pkl
// ported: "an all-staged commit is unchanged in shape: every path still staged, fixes applied" crates/batten/tests/hk_fix_selection.rs subject:hk.pkl
// ported: "a clean tree with nothing staged commits nothing and rewrites nothing" crates/batten/tests/hk_fix_selection.rs subject:hk.pkl
// ported: "hk.pkl declares stash on the pre-commit hook" crates/batten/tests/hk_fix_selection.rs subject:hk.pkl

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
        "id": "hk-fix-selection",
        "kind": "policy",
        "scope": "tree",
        "sources": ["mise.toml"],
        "line_sources": ["hk.pkl", ".claude/rules/toolchain.md"],
        "module": "policy/hk-fix-selection.rego",
        "severity": "deny",
    }))
    .expect("the row batten.toml declares")
}

/// A scratch tree carrying a hook config, a manifest and the rules file, plus
/// the committed module.
fn tree(name: &str, config: &str, manifest: &str, rules_doc: &str) -> PathBuf {
    let root = common::scratch(&format!("hk-fix-selection-{name}"));
    common::write(&root, "hk.pkl", config);
    common::write(&root, "mise.toml", manifest);
    common::write(&root, ".claude/rules/toolchain.md", rules_doc);
    install_module(&root);
    root
}

/// The COMMITTED module, copied in rather than restated: an inline copy would
/// drift from the shipped one and pass while the real gate was broken.
fn install_module(root: &Path) {
    let source = common::at_root("policy/hk-fix-selection.rego")
        .canonicalize()
        .expect("the committed module is where the row says it is");
    fs::create_dir_all(root.join("policy")).expect("scratch policy dir");
    fs::copy(source, root.join("policy/hk-fix-selection.rego")).expect("install committed module");
}

fn findings(root: &Path) -> Vec<(String, Option<usize>)> {
    // A fixture holds this module and no other, so its own tree is the honest
    // vocabulary. The real checkout is not: `verdicts_in` would collect every
    // module's tokens while only this row is loaded, and registry equality runs
    // in BOTH directions — the load is refused for the tokens nothing here emits.
    findings_declared_by(root, root)
}

fn findings_declared_by(root: &Path, vocabulary_root: &Path) -> Vec<(String, Option<usize>)> {
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
    .map(|finding| (finding.path, finding.line))
    .collect()
}

/// A hook config whose `fix` hook selects the gate's fixer-bearing steps.
///
/// Assembled from the shipped config's own markers rather than copied wholesale:
/// a fixture that pasted the real 1100-line `hk.pkl` would be re-asserting the
/// file under test, and every edit to it would be a fixture edit too.
const SOUND_CONFIG: &str = r#"
local gate = new Mapping<String, Step> {
  ["deno-fmt"] {
    check = "mise run lint:deno"
    fix = "mise run fmt:deno"
  }
  ["rego"] {
    check = "mise run lint:rego"
    fix = "mise run fmt:rego"
  }
  ["test:bats"] {
    check = "mise run test:bats"
  }
}
local fixers = new Mapping<String, Step> {
  ["deno-fmt"] = gate["deno-fmt"]
  ["rego"] = gate["rego"]
}
hooks {
  ["pre-commit"] {
    steps = gate
  }
  ["fix"] {
    fix = true
    steps = fixers
  }
}
"#;

const SOUND_MANIFEST: &str = r#"
[tasks.fmt]
description = "Run every fixer over the tree (rustfmt, shfmt, taplo, deno fmt) — hk owns the step list"
run = "hk fix --all"

[tasks."fmt:rego"]
run = "opa fmt -w"

[tasks."fmt:deno"]
run = "deno fmt"
"#;

const SOUND_RULES: &str = "`fmt` remains the formatters-only subset.\n";

// ---------------------------------------------------------------------------
// The tree this row actually defends.
// ---------------------------------------------------------------------------

#[test]
fn this_repository_is_clean_today() {
    let root = common::at_root(".")
        .canonicalize()
        .expect("this checkout is where the manifest says it is");
    // The vocabulary comes from a directory holding only this module, for the
    // reason `findings` states; the scratch name is this case's own, because
    // nextest runs each case in its own process and a shared name is a wipe under
    // another process's read.
    let only = common::scratch("hk-fix-selection-vocabulary-real-tree");
    install_module(&only);
    let found = findings_declared_by(&root, &only);
    assert!(
        found.is_empty(),
        "the committed hook config should satisfy its own row: {found:?}"
    );
}

#[test]
fn the_fixture_shape_is_clean_too() {
    // Without this, every refusal below could be produced by a fixture the row
    // simply cannot read — a module that fires on everything looks identical to
    // one that discriminates, until something is supposed to pass.
    let root = tree("sound", SOUND_CONFIG, SOUND_MANIFEST, SOUND_RULES);
    assert!(
        findings(&root).is_empty(),
        "the sound fixture should be clean: {:?}",
        findings(&root)
    );
}

// ---------------------------------------------------------------------------
// The prose, which is this row's half. What the config DOES is
// `fix-selection-complete`'s, and it is a command rather than a line scan.
// ---------------------------------------------------------------------------

#[test]
fn a_task_description_that_names_the_gate_is_refused() {
    // Exactly one of the two sides was allowed to move; if a later change widens
    // `fmt` back to the gate, this is what obliges the description to be
    // corrected in the same commit rather than left describing something else.
    let manifest = SOUND_MANIFEST.replace(
        r#"description = "Run every fixer over the tree (rustfmt, shfmt, taplo, deno fmt) — hk owns the step list""#,
        r#"description = "Run the whole hk gate over the tree""#,
    );
    let root = tree("described-as-gate", SOUND_CONFIG, &manifest, SOUND_RULES);
    let found = findings(&root);
    assert!(
        found.iter().any(|(path, _)| path == "mise.toml"),
        "the manifest should be named as the place to fix it: {found:?}"
    );
}

#[test]
fn a_rules_file_that_dropped_the_clause_is_refused() {
    // Both authorities are asserted, because the defect is that they DISAGREE and
    // it does not matter which of them is the one that lied.
    let root = tree(
        "clause-dropped",
        SOUND_CONFIG,
        SOUND_MANIFEST,
        "`fmt` runs the whole gate.\n",
    );
    let found = findings(&root);
    assert!(
        found
            .iter()
            .any(|(path, _)| path == ".claude/rules/toolchain.md"),
        "the rules file should be named as the place to fix it: {found:?}"
    );
}

// ---------------------------------------------------------------------------
// The silent half: a fixer nobody routes.
// ---------------------------------------------------------------------------

#[test]
fn a_fixer_task_no_step_routes_is_refused() {
    // CLOUD-681's second defect, in the shape it actually had: `fmt:deno` existed
    // to be written and no step routed `mise run fmt` to it, so the one formatter
    // the task description promised was the one it could not perform. A fixer
    // nobody routes is indistinguishable from a tree that needs no fixing, which
    // is why no other sensor in this tree could see it.
    //
    // THIS IS THE CASE THAT NEEDS THE PARSED MANIFEST. The routed set is derived
    // from `mise.toml`'s own `fmt:*` task keys, so this passes only if the engine
    // hands the module a keyed task table — not lines it would have to scan.
    let config = SOUND_CONFIG.replace(
        r#"    fix = "mise run fmt:deno"
"#,
        "",
    );
    let root = tree("unrouted", &config, SOUND_MANIFEST, SOUND_RULES);
    let found = findings(&root);
    assert!(
        found.iter().any(|(path, _)| path == "hk.pkl"),
        "an unrouted fixer should be refused against the config: {found:?}"
    );
}

#[test]
fn a_manifest_with_no_fixer_tasks_leaves_the_config_alone() {
    // The half that pays for the class: a repository whose linters have no fixer
    // halves declares no `fmt:*` task, and nothing here is its business. Without
    // this the class would read as "every hk config must route something".
    let manifest = r#"
[tasks.fmt]
description = "Run every fixer over the tree (rustfmt, shfmt, taplo, deno fmt) — hk owns the step list"
run = "hk fix --all"
"#;
    let config = SOUND_CONFIG
        .replace(
            r#"    fix = "mise run fmt:deno"
"#,
            "",
        )
        .replace(
            r#"    fix = "mise run fmt:rego"
"#,
            "",
        );
    let root = tree("no-fixer-tasks", &config, manifest, SOUND_RULES);
    assert!(
        findings(&root).is_empty(),
        "a tree that declares no fixer task routes nothing: {:?}",
        findings(&root)
    );
}

// ---------------------------------------------------------------------------
// Not-applicable is not a pass, and is not a refusal either.
// ---------------------------------------------------------------------------

#[test]
fn a_tree_with_no_hook_config_is_not_judged() {
    // `command-task-defined`'s measured lesson, one row over: an unguarded module
    // reported seven findings against a fixture that copies this config without
    // its subject. A repository that runs no hk hooks has no selection to judge.
    let root = common::scratch("hk-fix-selection-foreign");
    common::write(&root, "mise.toml", SOUND_MANIFEST);
    common::write(&root, ".claude/rules/toolchain.md", SOUND_RULES);
    install_module(&root);
    assert!(
        findings(&root).is_empty(),
        "a tree with no hk config is answering for nothing: {:?}",
        findings(&root)
    );
}

// ---------------------------------------------------------------------------
// The pre-commit STAGING contract (CLOUD-250, ported under CLOUD-1268).
//
// PORTED, NOT RETIRED. `hk.pkl` is this repository's gate definition; it does not
// die and is not touched. What died is `tests/pre-commit-staging.bats`, whose
// seven cases are these — the second spend of the fifth ledger arm.
//
// THE DEFECT, measured 2026-08-08: two changesets in the tree, one staged, and
// the commit captured all five files — so the second issue got no `Refs:` trailer,
// no board transition, and landed anonymously. `hk`'s pre-commit runs the gate in
// FIX mode, and this repo's fixers are whole-tree by nature (`cargo fmt --all`
// ignores the file list it is handed), so a dirty tree at commit time is enough.
// AGENTS.md tells agents to commit early and often, which makes a dirty tree the
// normal case rather than an edge one.
//
// WHAT THE SETTING BUYS, measured rather than assumed: not that unstaged work gets
// STAGED, but that a whole-tree fixer REWRITES it in place. With `stash`, the
// untouched file comes out byte-identical; without it, the fixer has stamped a
// file the author never staged.
//
// SIX CASES DRIVE A THROWAWAY REPO with its own minimal `hk.pkl`, for the reason
// the suite gave: this repo's gate would cost a cargo build per case and would
// assert about whichever fixers happen to be configured. The seventh reads THIS
// repository's committed bytes, and it is the one that keeps the other six from
// being vacuous — they run a fixture config, so they would all stay green if the
// real `hk.pkl` dropped the line, which is exactly how the setting arrived
// unasserted in the first place.
// ---------------------------------------------------------------------------

/// Whether this checkout's own `hk.pkl` declares `stash` on the pre-commit hook.
///
/// The COMMITTED bytes, read the way the suite read them: the setting must sit
/// inside the `["pre-commit"]` block and not merely somewhere in the file, or a
/// `stash` on another hook would answer for this one.
#[test]
fn this_repositorys_hk_pkl_declares_stash_on_the_pre_commit_hook() {
    let source = fs::read_to_string(common::at_root("hk.pkl")).expect("read the committed gate");
    let mut inside = false;
    let mut declared = false;
    for line in source.lines() {
        if line == r#"  ["pre-commit"] {"# {
            inside = true;
            continue;
        }
        if inside {
            if line == "  }" {
                break;
            }
            if line == r#"    stash = "patch-file""# {
                declared = true;
                break;
            }
        }
    }
    assert!(
        declared,
        "the pre-commit hook must declare `stash`, or a whole-tree fixer rewrites what the author did not stage"
    );
}

/// Build a fixture repository whose pre-commit gate has one whole-tree fixer.
///
/// `stashing` decides the ONE line under test. The fixer deliberately globs
/// `*.txt` rather than using hk's `{{files}}`: that is the shape of this repo's
/// real fixers, and a fixer confined to the staged list cannot exhibit the defect
/// at all.
fn staging_fixture(name: &str, stashing: bool) -> PathBuf {
    let dir = common::scratch(&format!("pre-commit-staging-{name}"));
    common::git_in(&dir, &["init", "-q", "-b", "main"]);
    common::git_in(&dir, &["config", "user.name", "Fixture"]);
    common::git_in(&dir, &["config", "user.email", "fixture@example.test"]);
    let stash = if stashing {
        "    stash = \"patch-file\"\n"
    } else {
        ""
    };
    common::write(
        &dir,
        "hk.pkl",
        &format!(
            "amends \"package://github.com/jdx/hk/releases/download/v1.54.0/hk@1.54.0#/Config.pkl\"\n\
             \n\
             hooks {{\n\
             \x20 [\"pre-commit\"] {{\n\
             {stash}    fix = true\n\
             \x20   steps {{\n\
             \x20     [\"stamp\"] {{\n\
             \x20       glob = List(\"*.txt\")\n\
             \x20       check = \"! grep -L STAMPED *.txt | grep -q .\"\n\
             \x20       fix = \"sed -i s/^/STAMPED\\\\ /  *.txt\"\n\
             \x20     }}\n\
             \x20   }}\n\
             \x20 }}\n\
             }}\n"
        ),
    );
    common::write(&dir, "a.txt", "a\n");
    common::write(&dir, "b.txt", "b\n");
    common::git_in(&dir, &["add", "-A"]);
    common::git_in(&dir, &["commit", "-q", "-m", "chore: base", "--no-verify"]);
    dir
}

/// Run the fixture's pre-commit gate, or `None` where hk is not installed.
///
/// `BATTEN_GATE_PID` is cleared deliberately. This runs INSIDE the real gate, and
/// the installed hook body refuses to re-enter one already running (exit 9) — a
/// guard that exists because `doctor` runs inside the gate and would recurse. The
/// fixture's gate is one `sed` and reaches nothing of this repo's, so there is no
/// recursion to guard against here; leaving the marker set would make every case
/// refuse rather than measure.
fn run_fixture_gate(dir: &Path) -> Option<()> {
    let hk = hk_binary()?;
    #[expect(
        clippy::disallowed_types,
        reason = "CLOUD-1268: the subject is a gate definition, so exercising it means running hk — the same spawn tests/pre-commit-staging.bats made, moved rather than added"
    )]
    let status = std::process::Command::new(hk)
        .args(["run", "pre-commit"])
        .current_dir(dir)
        .env_remove("BATTEN_GATE_PID")
        .status()
        .expect("hk runs the fixture gate");
    // The gate's own verdict is not the property under test — the `stamp` step
    // fails its check before fixing and that is the run being measured. What each
    // case asserts is the TREE afterwards.
    let _ = status;
    Some(())
}

/// The hk this clone pins, or `None` where it is not installed — in which case a
/// case has learned nothing and says so rather than failing.
fn hk_binary() -> Option<PathBuf> {
    #[expect(
        clippy::disallowed_types,
        reason = "CLOUD-1268: resolving the pinned tool is what `mise which hk` did in the retired suite"
    )]
    let output = std::process::Command::new("mise")
        .args(["which", "hk"])
        .current_dir(common::at_root("."))
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let path = PathBuf::from(String::from_utf8(output.stdout).ok()?.trim());
    path.is_file().then_some(path)
}

/// What the next commit would contain, as `path:content` lines.
fn staged_content(dir: &Path) -> Vec<String> {
    let names = common::git_in(dir, &["diff", "--cached", "--name-only"]);
    names
        .lines()
        .filter(|line| !line.is_empty())
        .map(|path| {
            let blob = common::git_in(dir, &["show", &format!(":{path}")]);
            format!("{path}:{}", blob.trim_end())
        })
        .collect()
}

#[test]
fn a_commit_contains_only_what_was_staged_with_another_change_dirty() {
    let dir = staging_fixture("one-staged", true);
    common::write(&dir, "a.txt", "a-changed\n");
    common::write(&dir, "b.txt", "b-changed\n");
    common::git_in(&dir, &["add", "a.txt"]);

    if run_fixture_gate(&dir).is_none() {
        return;
    }
    let staged = common::git_in(&dir, &["diff", "--cached", "--name-only"]);
    assert_eq!(staged.trim(), "a.txt");
}

#[test]
fn the_unstaged_change_survives_the_fixer_byte_for_byte() {
    // THE DISCRIMINATING CASE. A fix that ate the second changeset would be worse
    // than the sweep it replaced, so "survives" means both halves: still unstaged,
    // and still exactly what the author wrote.
    let dir = staging_fixture("survives", true);
    common::write(&dir, "a.txt", "a-changed\n");
    common::write(&dir, "b.txt", "b-changed\n");
    common::git_in(&dir, &["add", "a.txt"]);

    if run_fixture_gate(&dir).is_none() {
        return;
    }
    assert_eq!(
        fs::read_to_string(dir.join("b.txt")).expect("read b.txt"),
        "b-changed\n"
    );
    let dirty = common::git_in(&dir, &["diff", "--name-only"]);
    assert_eq!(dirty.trim(), "b.txt");
}

#[test]
fn shown_able_to_fail_without_the_setting_the_fixer_clobbers_the_unstaged_change() {
    // THE NEGATIVE CONTROL, and the reason the case above is not vacuous. Identical
    // fixture, one line removed. If hk ever stops honouring `stash`, this case goes
    // green and its neighbour goes red — the pair saying the same thing from both
    // sides (CLOUD-418).
    let dir = staging_fixture("bare", false);
    common::write(&dir, "a.txt", "a-changed\n");
    common::write(&dir, "b.txt", "b-changed\n");
    common::git_in(&dir, &["add", "a.txt"]);

    if run_fixture_gate(&dir).is_none() {
        return;
    }
    assert_eq!(
        fs::read_to_string(dir.join("b.txt")).expect("read b.txt"),
        "STAMPED b-changed\n",
        "without `stash` the whole-tree fixer stamps a file the author never staged"
    );
}

#[test]
fn the_fixers_own_change_to_a_staged_file_reaches_the_commit() {
    // The behaviour worth keeping. A change that disabled formatting-on-commit
    // would satisfy every other case here and defeat the point of the hook.
    let dir = staging_fixture("staged-fix", true);
    common::write(&dir, "a.txt", "a-changed\n");
    common::git_in(&dir, &["add", "a.txt"]);

    if run_fixture_gate(&dir).is_none() {
        return;
    }
    assert_eq!(staged_content(&dir), vec!["a.txt:STAMPED a-changed"]);
}

#[test]
fn an_all_staged_commit_is_unchanged_in_shape() {
    let dir = staging_fixture("all-staged", true);
    common::write(&dir, "a.txt", "a-changed\n");
    common::write(&dir, "b.txt", "b-changed\n");
    common::git_in(&dir, &["add", "-A"]);

    if run_fixture_gate(&dir).is_none() {
        return;
    }
    assert_eq!(
        staged_content(&dir),
        vec!["a.txt:STAMPED a-changed", "b.txt:STAMPED b-changed"]
    );
    assert!(
        common::git_in(&dir, &["diff", "--name-only"])
            .trim()
            .is_empty(),
        "every path stays staged and nothing is left dirty"
    );
}

#[test]
fn a_clean_tree_with_nothing_staged_rewrites_nothing() {
    let dir = staging_fixture("clean", true);

    if run_fixture_gate(&dir).is_none() {
        return;
    }
    assert!(
        common::git_in(&dir, &["status", "--porcelain"])
            .trim()
            .is_empty(),
        "a gate with nothing to do leaves the tree alone"
    );
}
