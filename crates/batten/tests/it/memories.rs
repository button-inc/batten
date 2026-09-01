//! The memory graph's edges, over the compiled binary (CLOUD-183's predicate,
//! CLOUD-1163's retirement).
//!
//! **This is the tier `policy/memories.rego`'s own `test_` rules cannot be.** A
//! `with input as` block writes the shape it then reads, so it is green over a
//! key the engine never fills and over a channel nothing populates — the
//! dead-gate class `.claude/rules/policy-modules.md` opens with, measured twice
//! in this repository. Every fixture below builds a real repository and runs the
//! real binary against the committed module, so what is asserted is that the
//! ENGINE selects the markdown this row declares and hands it over as lines.
//!
//! Two properties in particular are only decidable here:
//!
//! * **The declared glob actually reaches a referrer.** The rule's
//!   `line_sources` is a union of includes with `literal_separator(true)`, so a
//!   nesting depth nobody spelled is silently outside the judged set — and a rule
//!   that selects nothing reports green exactly like a clean tree.
//! * **`missing` is populated for a file that would not read.** The module writes
//!   the could-not-look clause either way; only a run over the compiled boundary
//!   can say whether anything ever fills the channel it reads.
//!
//! The ledger for this member: two deleted paths and eleven deleted `@test`
//! cases. The successor is a consumer module, so no `kind:` field is owed — the
//! path decides it.
//
// carried: mise-tasks/memories-check.sh policy/memories.rego crates/batten/tests/memories.rs
// carried: tests/memories-check.bats policy/memories.rego crates/batten/tests/memories.rs
//
// carried: "a coherent graph exits 0" policy/memories.rego
// carried: "a stale reference is reported with a file:line pointer" policy/memories.rego
// carried: "references outside the memories tree are checked too" policy/memories.rego
// carried: "the convention template's example references are excluded" policy/memories.rego
// carried: "a .md.md memory is reported as shadowed" policy/memories.rego
// carried: "a memory name outside the reference charset is reported" policy/memories.rego
// carried: "a missing graph root is reported" policy/memories.rego
// changed: "an untracked memory is not judged" policy/memories.rego the predecessor listed memories with `git ls-files`, which reads the INDEX; `input.tree.tracked` is the WORKING-TREE walk ("repository-relative paths the working-tree walk yields"), so an untracked-but-not-ignored memory is now judged where it used to be skipped. Ignored paths are still excluded, structurally, because the walk never yields them
// carried: "a memory with neither an index row nor a reference passes" policy/memories.rego
// carried: "no index file is needed at all" policy/memories.rego
// carried: "a dangling reference is still the failure, pointer-only" policy/memories.rego

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::Path;

use common::{git_in, run, scratch, stdout, write};

/// The rule's own id, which is also what `--rule` selects.
const RULE: &str = "memory-graph";

/// Materialize a repository carrying the committed module and this row.
///
/// **The module is COPIED from the tree rather than restated inline**, on
/// `crates/batten/tests/shell_retirement.rs`' precedent: a fixture that re-typed
/// the predicate would be a second implementation, and it would pass over a
/// module the engine can no longer load.
fn fixture(name: &str, files: &[(&str, &str)]) -> std::path::PathBuf {
    let dir = scratch(name);
    let module = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join("policy/memories.rego"),
    )
    .expect("the committed module");
    write(&dir, "policy/memories.rego", &module);
    write(
        &dir,
        "batten.toml",
        &format!(
            r#"version = 1

[[pattern]]
id = "memory-name"
regex = '^[A-Za-z0-9_/-]+$'

[[pattern]]
id = "mem-reference"
regex = 'mem:[A-Za-z0-9_/-]+'

[[rule]]
id = "{RULE}"
kind = "policy"
scope = "tree"
line_sources = [
  "*.md",
  ".claude/*.md",
  ".claude/**/*.md",
  ".serena/memories/*.md",
  ".serena/memories/**/*.md",
]
module = "policy/memories.rego"
severity = "deny"

# EVERY VERDICT THE MODULE CAN RAISE, because the engine refuses at LOAD a
# module raising a token no `[[verdict]]` row declares -- "the refusal would
# carry no gloss, no class definition and no route, which is the bare no this
# ABI exists to refuse". A fixture declaring the rule and not its verdicts does
# not merely fail; it fails with a config error that looks nothing like the
# predicate being wrong, which is how it read the first time.
[[verdict]]
id = "memory resolve missing"
gloss = "the memory graph has no root"
class = "fixture"

[[verdict.route]]
id = "fixture probe probe"
kind = "document"
target = "policy/memories.rego"

[[verdict]]
id = "memory name duplicate"
gloss = "a memory name strips to another name"
class = "fixture"

[[verdict.route]]
id = "fixture shadowed probe"
kind = "document"
target = "policy/memories.rego"

[[verdict]]
id = "memory name unseen"
gloss = "a memory name carries a character no reference can spell"
class = "fixture"

[[verdict.route]]
id = "fixture charset probe"
kind = "document"
target = "policy/memories.rego"

[[verdict]]
id = "memory point stale"
gloss = "a mem: reference names a memory this tree does not carry"
class = "fixture"

[[verdict.route]]
id = "fixture stale probe"
kind = "document"
target = "policy/memories.rego"

[[verdict]]
id = "memory read unread"
gloss = "a declared referrer could not be read"
class = "fixture"

[[verdict.route]]
id = "fixture unread probe"
kind = "document"
target = "policy/memories.rego"
"#
        ),
    );
    for (path, body) in files {
        write(&dir, path, body);
    }
    git_in(&dir, &["init", "--initial-branch=main"]);
    git_in(&dir, &["add", "-A"]);
    git_in(&dir, &["commit", "-m", "fixture"]);
    dir
}

/// Judge the fixture on this one rule, and return what it said.
///
/// **Findings are on STDOUT**, which is where the pointer contract puts them:
/// `cli.rs` asserts the whole of a run's findings as `output.stdout`, and stderr
/// carries the engine's own notices instead. Reading the wrong stream here gave
/// two cases an EMPTY string to match against, so they failed on the pointer
/// while the exit code was already right — a false negative that looked like a
/// broken predicate.
fn judge(dir: &Path) -> (Option<i32>, String) {
    let out = run(dir, &["check", "--rule", RULE]);
    (out.status.code(), stdout(&out))
}

/// A memory tree whose graph is coherent.
fn coherent() -> Vec<(&'static str, &'static str)> {
    vec![
        (".serena/memories/core.md", "the root\n"),
        (".serena/memories/workflow/board-states.md", "states\n"),
        (
            "AGENTS.md",
            "start at mem:core, then mem:workflow/board-states\n",
        ),
    ]
}

#[test]
fn a_coherent_graph_is_clean() {
    // THE ANTI-VACUITY MIRROR for every case below. Without it, a rule that
    // refused everything would satisfy each of them.
    let (code, said) = judge(&fixture("memories-coherent", &coherent()));
    assert_eq!(code, Some(0), "a coherent graph is clean\n{said}");
}

#[test]
fn a_dangling_reference_is_reported_with_its_pointer() {
    // The predicate that produced the row, and the engine-side property that
    // matters: the referrer's LINE reached the module, so the finding can point
    // at it. A `with input as` case cannot show that.
    let dir = fixture(
        "memories-dangling",
        &[
            (".serena/memories/core.md", "the root\n"),
            ("AGENTS.md", "intro\nsee mem:gone-away for detail\n"),
        ],
    );
    let (code, said) = judge(&dir);
    assert_eq!(code, Some(2), "a dangling edge is a violation\n{said}");
    assert!(
        said.contains("AGENTS.md:2"),
        "the finding points at the referrer's own line\n{said}"
    );
}

#[test]
fn a_referrer_outside_the_memories_tree_is_judged() {
    // The glob's real reach, which is the half only this tier can assert: a
    // reference in a rules file is the same broken edge, and a `line_sources`
    // that did not select it would report green.
    let dir = fixture(
        "memories-outside",
        &[
            (".serena/memories/core.md", "the root\n"),
            (".claude/rules/toolchain.md", "detail in mem:gone-away\n"),
        ],
    );
    let (code, said) = judge(&dir);
    assert_eq!(code, Some(2), "a rules file is a referrer too\n{said}");
    assert!(
        said.contains(".claude/rules/toolchain.md"),
        "the finding names the referrer\n{said}"
    );
}

#[test]
fn the_excluded_referrers_are_not_judged() {
    // Each for its own reason: release-plz owns CHANGELOG.md, and the shipped
    // convention template's examples name memories that deliberately do not
    // exist here.
    let dir = fixture(
        "memories-excluded",
        &[
            (".serena/memories/core.md", "the root\n"),
            ("CHANGELOG.md", "mem:gone-away\n"),
            (
                ".serena/memories/memory_maintenance.md",
                "example: mem:gone-away\n",
            ),
        ],
    );
    let (code, said) = judge(&dir);
    assert_eq!(
        code,
        Some(0),
        "the excluded referrers are not scanned\n{said}"
    );
}

#[test]
fn a_shadowed_name_is_reported() {
    let dir = fixture(
        "memories-shadowed",
        &[
            (".serena/memories/core.md", "the root\n"),
            (".serena/memories/notes.md.md", "shadowed\n"),
        ],
    );
    let (code, said) = judge(&dir);
    assert_eq!(
        code,
        Some(2),
        "a name that strips to another is refused\n{said}"
    );
    assert!(
        said.contains("notes.md.md"),
        "the finding names the shadowed file\n{said}"
    );
}

#[test]
fn a_name_outside_the_reference_charset_is_reported() {
    let dir = fixture(
        "memories-charset",
        &[
            (".serena/memories/core.md", "the root\n"),
            (".serena/memories/a name.md", "unreferencable\n"),
        ],
    );
    let (code, said) = judge(&dir);
    assert_eq!(
        code,
        Some(2),
        "a name no reference can spell is refused\n{said}"
    );
}

#[test]
fn a_missing_graph_root_is_reported() {
    let dir = fixture(
        "memories-rootless",
        &[(".serena/memories/other.md", "no root beside me\n")],
    );
    let (code, said) = judge(&dir);
    assert_eq!(code, Some(2), "a graph with no root is refused\n{said}");
    assert!(
        said.contains("core.md"),
        "the finding names the root it wanted\n{said}"
    );
}

#[test]
fn a_repository_with_no_memories_is_not_judged() {
    // THE BOUND, and the reason it is here rather than only in the load-time
    // tier: a shipped ruleset that refuses an ordinary minimal repository is
    // unshippable, and this is the tier that runs over one.
    let dir = fixture("memories-none", &[("README.md", "no memories here\n")]);
    let (code, said) = judge(&dir);
    assert_eq!(
        code,
        Some(0),
        "a tree with no memory graph is not judged\n{said}"
    );
}

/// AN UNTRACKED MEMORY *IS* JUDGED NOW, and that is a changed verdict rather than
/// a bug.
///
/// The predecessor listed memories with `git ls-files`, which reads the INDEX, and
/// its suite asserted "an untracked memory is not judged". `input.tree.tracked` is
/// a different question: the schema calls it "repository-relative paths the
/// WORKING-TREE WALK yields". There is no index-wide fact to substitute —
/// `input.tree.staged` answers for DECLARED paths, not for a set — so the
/// semantics cannot be reproduced, only chosen.
///
/// Chosen deliberately, and it is the safer direction: an uncommitted memory whose
/// name cannot be addressed is broken now and will be broken the moment it is
/// committed, and the gate that would have caught it ran before the commit. The
/// case is recorded as a `// changed:` arm above rather than a `// carried:` one,
/// because a retirement that quietly re-decides a case has not conserved anything.
///
/// IGNORED paths are still excluded, and structurally: the walk never yields them,
/// so `target/` and the worktree dirs stay outside the judgement rather than being
/// tuned out of it.
#[test]
fn an_untracked_memory_is_judged_where_the_predecessor_skipped_it() {
    let dir = fixture("memories-untracked", &coherent());
    write(
        &dir,
        ".serena/memories/draft.md.md",
        "a shadowed scratch name\n",
    );
    let (code, said) = judge(&dir);
    assert_eq!(
        code,
        Some(2),
        "the working-tree walk yields it, so the graph carries it\n{said}"
    );
    assert!(
        said.contains("draft.md.md"),
        "and the finding names it\n{said}"
    );
}

/// The half that keeps the change above honest: an IGNORED file is still not
/// judged, so the widening reaches untracked work and stops there.
#[test]
fn an_ignored_memory_is_still_not_judged() {
    let dir = fixture("memories-ignored", &coherent());
    write(&dir, ".gitignore", ".serena/memories/scratch/\n");
    git_in(&dir, &["add", ".gitignore"]);
    git_in(&dir, &["commit", "-m", "ignore scratch"]);
    write(
        &dir,
        ".serena/memories/scratch/draft.md.md",
        "a shadowed scratch name\n",
    );
    let (code, said) = judge(&dir);
    assert_eq!(
        code,
        Some(0),
        "an ignored path is outside the walk, so outside the judgement\n{said}"
    );
}

#[test]
fn an_unreferenced_memory_is_not_a_defect() {
    // CLOUD-683's decision, asserted rather than left as prose: membership in an
    // index is NOT checked, and no memory is required to be referenced at all.
    let dir = fixture(
        "memories-unreferenced",
        &[
            (".serena/memories/core.md", "the root\n"),
            (".serena/memories/lonely.md", "nothing points here\n"),
        ],
    );
    let (code, said) = judge(&dir);
    assert_eq!(
        code,
        Some(0),
        "an unreferenced memory is not a defect\n{said}"
    );
}

#[test]
fn no_index_file_is_required() {
    // The other half of CLOUD-683: there is no required index or routing table,
    // so a graph with no index at all is coherent.
    let dir = fixture(
        "memories-no-index",
        &[(
            ".serena/memories/core.md",
            "the root, and no index anywhere\n",
        )],
    );
    let (code, said) = judge(&dir);
    assert_eq!(code, Some(0), "no index file is needed at all\n{said}");
}

/// COULD NOT LOOK — and this tier MEASURES the channel rather than assuming it.
///
/// `.claude/rules/policy-modules.md` asks for exactly this case and says why a
/// `with input as` version is worthless for it: that fabricates the shape the
/// engine may be unable to produce, so it passes over a channel nothing fills.
///
/// # It fires now, and this case is the inversion CLOUD-1276 asked for
///
/// This case used to assert the opposite — exit 0, silence — as MEASURED rather
/// than endorsed, and it carried its own instruction: *"If this case starts
/// failing, the boundary began populating `missing` for a `line_sources` miss
/// (CLOUD-1276) — delete this case and assert the finding instead."* It started
/// failing the moment CLOUD-1049's guard moved below `deny`, so this is that
/// instruction carried out rather than a new claim.
///
/// One guard closed both rows, which is worth recording because they were filed
/// as separate causes on separate surfaces: CLOUD-1049 was a `documents` path
/// that would not parse, CLOUD-1276 a `line_sources` glob whose selected file
/// would not decode. Neither was ever about acquisition — the projection built a
/// correct `missing` in both cases and `policy_rule` discarded the document
/// whole, so both surfaces went dark for the same one-line reason.
///
/// **The predecessor had no equivalent exposure**: `memories-check.sh:102` ran
/// `xargs grep` over the tracked set, and `grep` on binary bytes is loud. The
/// silence was the engine's, was new to the port, and is now gone.
#[test]
fn an_unreadable_referrer_reaches_the_could_not_look_channel() {
    let dir = fixture(
        "memories-unreadable",
        &[(".serena/memories/core.md", "the root\n")],
    );
    // Invalid UTF-8, written as bytes: `write` takes a `&str` and so cannot
    // express the case at all.
    std::fs::write(dir.join("BROKEN.md"), [0x6d, 0x65, 0x6d, 0x3a, 0xff, 0xfe])
        .expect("write the unreadable referrer");
    git_in(&dir, &["add", "-A"]);
    git_in(&dir, &["commit", "-m", "an unreadable referrer"]);

    let (code, said) = judge(&dir);
    assert_eq!(
        code,
        Some(2),
        "a referrer the boundary cannot decode is could-not-look, not a clean \
         tree — the whole point of the channel\n{said}"
    );
    assert!(
        said.contains("BROKEN.md"),
        "and the finding points at the file nobody could read\n{said}"
    );
}

#[test]
fn the_finding_carries_no_prose_from_the_referrer() {
    // Non-negotiable rule 4, asserted at the boundary rather than trusted from
    // the module. The referrer's line carries a distinctive phrase; the finding
    // must carry the pointer and not the sentence.
    let dir = fixture(
        "memories-pointer-only",
        &[
            (".serena/memories/core.md", "the root\n"),
            (
                "AGENTS.md",
                "a distinctive sentence nobody should see quoted: mem:gone-away\n",
            ),
        ],
    );
    let (_, said) = judge(&dir);
    assert!(
        !said.contains("a distinctive sentence nobody should see quoted"),
        "the finding is a pointer, never the line it pointed at\n{said}"
    );
}
