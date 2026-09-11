//! `policy/rules-paths-trigger.rego` and `policy/skill-frontmatter-complete.rego`
//! decide over the compiled engine (CLOUD-1787).
//!
//! # Why this tier and not the modules' own rules
//!
//! Both modules' `test_` cases hand themselves a `documents` object, so they are
//! green over a shape the engine may never build — the hazard
//! `rules/policy-modules.md` names, and the reason both of its measured
//! instances were found by adding this tier rather than by reading. Here that
//! hazard is not hypothetical: until this change `Format::for_path` answered
//! `None` for `.md`, a declared markdown source reached no module at all, and
//! `with input as` would have fabricated every byte of the surface these
//! predicates read.
//!
//! Three things can only be proved against the real boundary:
//!
//! * a `.md` source reaches a module as a PARSED frontmatter node, keyed by
//!   path under `input.tree.documents`;
//! * the body is not in it — a file whose prose would sink a whole-stream YAML
//!   read still resolves its frontmatter, which is the defect CLOUD-1787 was
//!   filed on;
//! * a file with no fence reaches `input.tree.missing` under `no-document` and
//!   not under `unparsed`, so the arm that denies on it is reachable.
//!
//! # The case that carries the most
//!
//! `this_repository_is_clean_today` runs both rows over this checkout. Every
//! other fixture is a shape somebody wrote to fail; that one is the shape that
//! has to keep passing — and it is the one that was RED when this change began,
//! on `.claude/rules/policy-modules.md`, whose body asserted a `paths:` trigger
//! it did not carry.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::fs;
use std::path::{Path, PathBuf};

use batten::rules::{self, Rule};

/// The rows as `batten.toml` declares them, deserialized rather than
/// struct-literalled: `Rule` carries `deny_unknown_fields`, so these go through
/// the same column census a consumer's config does.
fn stub_row() -> Rule {
    serde_json::from_value(serde_json::json!({
        "id": "prose carry missing",
        "kind": "policy",
        "scope": "tree",
        "sources": [".claude/rules/*.md"],
        "module": "policy/rules-paths-trigger.rego",
        "severity": "deny",
    }))
    .expect("the row batten.toml declares")
}

fn skill_row() -> Rule {
    serde_json::from_value(serde_json::json!({
        "id": "prompt declare partial",
        "kind": "policy",
        "scope": "tree",
        "sources": ["skills/*/SKILL.md", ".claude/skills/*/SKILL.md"],
        "module": "policy/skill-frontmatter-complete.rego",
        "severity": "deny",
    }))
    .expect("the row batten.toml declares")
}

/// The COMMITTED module, copied in rather than restated: an inline copy would
/// drift from the shipped one and pass while the real gate was broken.
fn install_module(root: &Path, module: &str) {
    let source = common::at_root(module)
        .canonicalize()
        .expect("the committed module is where the row says it is");
    fs::create_dir_all(root.join("policy")).expect("scratch policy dir");
    fs::copy(source, root.join(module)).expect("install committed module");
}

fn scratch_for(name: &str, module: &str) -> PathBuf {
    let root = common::scratch(&format!("frontmatter-gates-{name}"));
    install_module(&root, module);
    root
}

fn findings_for(root: &Path, row: Rule, vocabulary_root: &Path) -> Vec<String> {
    let verdicts = common::verdicts_in(vocabulary_root);
    rules::run_static(
        &[row],
        &[],
        batten::policy::Vocabulary {
            patterns: &[],
            verdicts: &verdicts,
            // The scratch tree declares no `[vocabulary]` word lists, which is
            // the exemption the field documents rather than a gap in the setup.
            words: None,
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

/// The scratch tree's own vocabulary: registry equality runs in BOTH directions,
/// so collecting the real checkout's verdicts would refuse the load for every
/// token these two rows never emit.
fn findings(root: &Path, row: Rule) -> Vec<String> {
    findings_for(root, row, root)
}

/// A body that a whole-stream YAML read cannot survive — the four shapes
/// CLOUD-1787 measured failing, in one file.
const HOSTILE_BODY: &str = "# heading\n\n| a | b |\n| - | - |\n| 1 | 2 |\n\n- [ ] a task\n\n> **NOTE** text\n\n[[wikilink]] opening a line.\n";

#[test]
fn a_rules_stub_with_a_paths_trigger_is_clean() {
    // The engine half: a `.md` under a declared glob is PARSED, its frontmatter
    // becomes the node, and the body — which would sink a YAML read of the whole
    // file — does not reach the parser at all.
    //
    // Fails by: `Format::for_path` answering `None` for `.md` again, which puts
    // the path in `missing` under `unknown-format` and reddens this case.
    let root = scratch_for("stub-clean", "policy/rules-paths-trigger.rego");
    common::write(
        &root,
        ".claude/rules/rust.md",
        &format!("---\npaths:\n  - \"crates/**/*.rs\"\n---\n\n{HOSTILE_BODY}"),
    );
    assert_eq!(
        findings(&root, stub_row()),
        Vec::<String>::new(),
        "a stub carrying a trigger is clean, whatever its prose says"
    );
}

#[test]
fn a_rules_stub_without_a_paths_trigger_is_refused() {
    // THE MEASURED CASE, reproduced. A stub with no fence at all: the file is
    // read in full, there is no document in it, and the module denies on
    // `no-document` rather than abstaining.
    //
    // Fails by: routing the no-fence case to `unparsed` (which this module reads
    // as could-not-look and reports under the other verdict), or to an empty
    // document (which would satisfy nothing and deny nothing).
    let root = scratch_for("stub-no-fence", "policy/rules-paths-trigger.rego");
    common::write(
        &root,
        ".claude/rules/policy-modules.md",
        "# Moved to `rules/policy-modules.md`\n\nthe frontmatter above is the trigger.\n",
    );
    assert_eq!(
        findings(&root, stub_row()),
        vec![".claude/rules/policy-modules.md".to_owned()],
        "a stub asserting a trigger it does not carry is refused"
    );
}

#[test]
fn a_rules_stub_with_an_empty_trigger_is_refused() {
    // Present-and-empty reaches the module as a DOCUMENT rather than through
    // `missing`, which is the distinction the empty-fence arm exists for.
    let root = scratch_for("stub-empty", "policy/rules-paths-trigger.rego");
    common::write(&root, ".claude/rules/x.md", "---\npaths: []\n---\n\nbody\n");
    assert_eq!(
        findings(&root, stub_row()),
        vec![".claude/rules/x.md".to_owned()],
        "a trigger that fires on nothing is refused"
    );
}

#[test]
fn a_skill_missing_a_declared_field_is_refused() {
    let root = scratch_for("skill-missing", "policy/skill-frontmatter-complete.rego");
    common::write(
        &root,
        "skills/batten/SKILL.md",
        &format!("---\nname: batten\n---\n\n{HOSTILE_BODY}"),
    );
    assert_eq!(
        findings(&root, skill_row()),
        vec!["skills/batten/SKILL.md".to_owned()],
        "a skill with no description is refused"
    );
}

#[test]
fn a_complete_skill_is_clean_and_its_body_is_not_read() {
    let root = scratch_for("skill-clean", "policy/skill-frontmatter-complete.rego");
    common::write(
        &root,
        "skills/batten/SKILL.md",
        &format!("---\nname: batten\ndescription: what it does\n---\n\n{HOSTILE_BODY}"),
    );
    assert_eq!(
        findings(&root, skill_row()),
        Vec::<String>::new(),
        "a complete skill is clean, and its table-bearing body changed nothing"
    );
}

#[test]
fn a_skill_whose_name_disagrees_with_its_directory_is_refused() {
    let root = scratch_for("skill-misplaced", "policy/skill-frontmatter-complete.rego");
    common::write(
        &root,
        "skills/batten/SKILL.md",
        "---\nname: serena\ndescription: d\n---\n\nbody\n",
    );
    assert_eq!(
        findings(&root, skill_row()),
        vec!["skills/batten/SKILL.md".to_owned()],
        "a skill routed by one identity and displayed under another is refused"
    );
}

#[test]
fn this_repository_is_clean_today() {
    // The case that carries the most, and the one the change had to MAKE pass:
    // `.claude/rules/policy-modules.md` was the single stub without a trigger,
    // and nothing in this tree could see that until frontmatter was parseable.
    //
    // Fails by: any stub losing its `paths:` block, or any `SKILL.md` losing a
    // field or being renamed out of agreement with its directory.
    let root = common::at_root(".")
        .canonicalize()
        .expect("this checkout is where the manifest says it is");
    // The vocabulary comes from a directory holding only the module under test,
    // for the reason `findings` states: registry equality runs in BOTH
    // directions, so the real checkout's verdicts would refuse the load for
    // every token these two rows never raise.
    for (row, module) in [
        (stub_row(), "policy/rules-paths-trigger.rego"),
        (skill_row(), "policy/skill-frontmatter-complete.rego"),
    ] {
        let id = row.id.clone();
        let only = common::scratch(&format!("frontmatter-gates-vocabulary-{id}"));
        install_module(&only, module);
        assert_eq!(
            findings_for(&root, row, &only),
            Vec::<String>::new(),
            "{id} is clean over this checkout"
        );
    }
}
