//! `spawn-widening` over the compiled engine (CLOUD-1338).
//!
//! # Why this tier, and what the module's own suite structurally cannot prove
//!
//! The module's `test_` cases hand themselves a `base-delta` object, so they are
//! green over a shape the engine may never build — the hazard
//! `.claude/rules/policy-modules.md` names, and the hazard this particular rule
//! walked into four separate times while it was being written:
//!
//! 1. the two `[[pattern]]` ids were undeclared, so both lookups resolved to
//!    undefined and neither clause could hold;
//! 2. the row declared `sources` where the delta reader needs `delta_sources`,
//!    so no base side was acquired and every run reported could-not-look;
//! 3. it then declared `delta_sources` and no `line_sources`, so the WORKING
//!    side was empty and both clauses ran over nothing;
//! 4. and a comprehension over an absent `base-lines` key yields the EMPTY SET
//!    rather than undefined, which made every line of every unchanged file read
//!    as added — 81 of 81 engine modules refused on one run.
//!
//! Three of those four are byte-identical to a passing gate on the decision
//! surface. Every one was found by SEEDING a refusal and watching for it, never
//! by reading a clean exit — which is why the acceptance case below seeds rather
//! than asserts absence.
//!
//! # The pair that carries the rule
//!
//! `an_added_spawn_escape_is_refused` and `an_added_spawn_placement_is_refused`
//! are the two halves, and the second is the one that actually failed in the
//! field: the placement table is deny-by-omission, so widening it is a two-word
//! edit whose justification lives in a comment nothing reads.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::fs;
use std::path::{Path, PathBuf};

use batten::rules::{self, Rule};

/// The row as `batten.toml` declares it, deserialized rather than
/// struct-literalled: `Rule` carries `deny_unknown_fields`, so this goes through
/// the same column census a consumer's config does.
///
/// **BOTH SOURCE KEYS, because they fill different halves and the module
/// subtracts one from the other.** A row carrying only one of them is defect 2
/// or 3 above, and both reported clean.
fn row() -> Rule {
    serde_json::from_value(serde_json::json!({
        "id": "spawn-widening",
        "kind": "policy",
        "scope": "tree",
        "base": "origin/main",
        "delta_sources": ["crates/batten/src/*.rs", "policy/spawn-adapters.rego"],
        "line_sources": ["crates/batten/src/*.rs", "policy/spawn-adapters.rego"],
        "module": "policy/spawn-widening.rego",
        "severity": "deny",
    }))
    .expect("the row batten.toml declares")
}

/// What the working tree does to the base: files written, files removed.
struct Head<'a> {
    written: &'a [(&'a str, &'a str)],
    removed: &'a [&'a str],
}

/// A repository whose `origin/main` carries `base`, with `head` applied on top.
fn repo(name: &str, base: &[(&str, &str)], head: &Head<'_>) -> PathBuf {
    let root = common::scratch(&format!("spawn-widening-{name}"));
    common::git_in(&root, &["init", "--initial-branch=main"]);
    write_all(&root, base);
    install_module(&root);
    common::git_in(&root, &["add", "-A"]);
    common::git_in(&root, &["commit", "-m", "base"]);
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

fn write_all(root: &Path, files: &[(&str, &str)]) {
    for (path, body) in files {
        let full = root.join(path);
        if let Some(parent) = full.parent() {
            fs::create_dir_all(parent).expect("scratch parent");
        }
        fs::write(full, body).expect("write fixture file");
    }
}

/// The COMMITTED module, copied in rather than restated: an inline copy would
/// drift from the shipped one and pass while the real gate was broken.
fn install_module(root: &Path) {
    let source = common::at_root("policy/spawn-widening.rego")
        .canonicalize()
        .expect("the committed module is where the row says it is");
    fs::create_dir_all(root.join("policy")).expect("scratch policy dir");
    fs::copy(source, root.join("policy/spawn-widening.rego")).expect("install committed module");
}

fn verdicts(root: &Path) -> Vec<String> {
    // THE COMMITTED PATTERN TABLE, derived rather than listed — the same reason
    // `install_module` copies the module in: a hand-written copy would drift
    // from the shipped regex and let these cases pass over a broken one. An
    // empty table makes `check_pattern_refs` refuse the load outright, so the
    // whole file would go red over a module that is fine.
    //
    // A CONSUMER MODULE MAY READ THE REGISTRY, unlike a preset: the exemption
    // `.claude/rules/policy-modules.md` records is for compiled-in presets,
    // whose consumers cannot add rows on their behalf. This module ships beside
    // the `batten.toml` that declares its two, so supplying them here is the
    // shape a real consumer has rather than a harness inventing vocabulary.
    let patterns = common::committed_patterns();
    let declared = common::verdicts_in(root);
    rules::run_static(
        &[row()],
        &[],
        batten::policy::Vocabulary {
            patterns: &patterns,
            verdicts: &declared,
            recorders: &[],
        },
        root,
    )
    .expect("the read surface runs a policy row")
    .findings
    .into_iter()
    .map(|finding| finding.rule)
    .collect()
}

const CLEAN_MODULE: &str = "fn ordinary() {}\n";

const ADAPTERS: &str = "package batten.spawn_adapters\n\nadapters := {\n\t\"exec\",\n}\n";

/// **THE CASE THE RULE EXISTS FOR, half one — and it SEEDS.**
///
/// Asserting a clean tree stays clean would have passed over three of the four
/// defects this module shipped with. The only reading that tells a live gate
/// from a dead one is a refusal that arrives.
#[test]
fn an_added_spawn_escape_is_refused() {
    let root = repo(
        "escape-added",
        &[
            ("crates/batten/src/thing.rs", CLEAN_MODULE),
            ("policy/spawn-adapters.rego", ADAPTERS),
        ],
        &Head {
            written: &[(
                "crates/batten/src/thing.rs",
                "fn ordinary() {}\n#[expect(clippy::disallowed_types)]\nfn spawner() {}\n",
            )],
            removed: &[],
        },
    );
    assert_eq!(
        verdicts(&root),
        vec![String::from("spawn-widening")],
        "an escape this change added is the whole subject of the rule"
    );
}

/// **THE CASE THAT ACTUALLY FIRED IN THE FIELD, half two.**
///
/// `spawn-adapters` refuses a spawn in an unplaced module; adding the module to
/// its set answers that refusal in one edit, and nothing read the edit. Two
/// placements landed that way on the branch this rule was written for.
#[test]
fn an_added_spawn_placement_is_refused() {
    let root = repo(
        "placement-added",
        &[
            ("crates/batten/src/thing.rs", CLEAN_MODULE),
            ("policy/spawn-adapters.rego", ADAPTERS),
        ],
        &Head {
            written: &[(
                "policy/spawn-adapters.rego",
                "package batten.spawn_adapters\n\nadapters := {\n\t\"exec\",\n\t\"thing\",\n}\n",
            )],
            removed: &[],
        },
    );
    assert_eq!(
        verdicts(&root),
        vec![String::from("spawn-widening")],
        "the table is deny-by-omission, so widening it is the escape"
    );
}

/// **THE ANTI-VACUITY MIRROR.** Without it every case above is satisfied by a
/// module that refuses unconditionally, which is not a gate (CLOUD-418).
///
/// It is also the case that would have caught defect 4: an unchanged file whose
/// every line read as added refused 81 of 81 modules on one real run.
#[test]
fn an_unchanged_tree_carrying_escapes_is_clean() {
    let escaped = "#[expect(clippy::disallowed_types)]\nfn spawner() {}\n";
    let root = repo(
        "unchanged",
        &[
            ("crates/batten/src/thing.rs", escaped),
            ("policy/spawn-adapters.rego", ADAPTERS),
        ],
        &Head {
            written: &[],
            removed: &[],
        },
    );
    assert!(
        verdicts(&root).is_empty(),
        "the inventory is what a tree HOLDS; this rule decides only whether it GREW"
    );
}

/// Removing a placement is not widening, which is the direction the rule turns
/// on: the remedy for a refusal here is to delete the entry, and a symmetric
/// predicate would refuse the fix.
#[test]
fn removing_a_placement_is_clean() {
    let root = repo(
        "placement-removed",
        &[
            ("crates/batten/src/thing.rs", CLEAN_MODULE),
            (
                "policy/spawn-adapters.rego",
                "package batten.spawn_adapters\n\nadapters := {\n\t\"exec\",\n\t\"thing\",\n}\n",
            ),
        ],
        &Head {
            written: &[("policy/spawn-adapters.rego", ADAPTERS)],
            removed: &[],
        },
    );
    assert!(
        verdicts(&root).is_empty(),
        "the fix for this rule's own refusal must not be refused by it"
    );
}

/// The test-module idiom is exempt, and it has to be: every `mod tests` in this
/// crate opens with one, inside `crates/batten/src/**` where the path exclusion
/// cannot reach it. A rule firing on the universal case is one somebody switches
/// off.
#[test]
fn the_test_module_idiom_is_not_an_escape() {
    let root = repo(
        "idiom",
        &[
            ("crates/batten/src/thing.rs", CLEAN_MODULE),
            ("policy/spawn-adapters.rego", ADAPTERS),
        ],
        &Head {
            written: &[(
                "crates/batten/src/thing.rs",
                "fn ordinary() {}\n#[cfg(test)]\n#[allow(clippy::expect_used)]\nmod tests {}\n",
            )],
            removed: &[],
        },
    );
    assert!(
        verdicts(&root).is_empty(),
        "panicking loudly is how a test fails, and the whole crate says so this way"
    );
}

/// **AND THE EXEMPTION IS THREE NAMED LINTS RATHER THAN A SHAPE.** Without this
/// the case above is satisfied by an exemption that waives every `#[allow]`,
/// which would take the rule with it.
#[test]
fn another_lints_allow_is_still_an_escape() {
    let root = repo(
        "other-lint",
        &[
            ("crates/batten/src/thing.rs", CLEAN_MODULE),
            ("policy/spawn-adapters.rego", ADAPTERS),
        ],
        &Head {
            written: &[(
                "crates/batten/src/thing.rs",
                "fn ordinary() {}\n#[expect(clippy::too_many_arguments)]\nfn wide() {}\n",
            )],
            removed: &[],
        },
    );
    assert_eq!(
        verdicts(&root),
        vec![String::from("spawn-widening")],
        "`too_many_arguments` is a claim about the code, not about how a test reports failure"
    );
}

/// A doc comment naming a lint is not an escape.
///
/// The modules this rule reads discuss `clippy::disallowed_types` at length —
/// including the one it was written for — so a pattern without the leading
/// anchor would refuse every commit that explains itself.
#[test]
fn a_doc_comment_naming_a_lint_is_not_an_escape() {
    let root = repo(
        "prose",
        &[
            ("crates/batten/src/thing.rs", CLEAN_MODULE),
            ("policy/spawn-adapters.rego", ADAPTERS),
        ],
        &Head {
            written: &[(
                "crates/batten/src/thing.rs",
                "fn ordinary() {}\n/// `clippy::disallowed_types` refuses a spawn here.\nfn documented() {}\n",
            )],
            removed: &[],
        },
    );
    assert!(
        verdicts(&root).is_empty(),
        "explaining the lint is not escaping it"
    );
}
