//! The rendered CLI reference and the command spec name the same flags, in both
//! directions (CLOUD-171), over the compiled binary.
//!
//! # Why this tier
//!
//! Coverage holds "by construction" only for today's renderer. `render::markdown`
//! walks `spec::CommandSpec` and emits a table row per flag — but it emits a NODE
//! at a time, and a node the walk skips, a table the writer drops on an
//! empty-flags branch, or a future renderer that summarises rather than
//! enumerates all produce a reference that is well-formed, non-empty,
//! byte-stable, and quietly missing a flag. Every other check this repository has
//! over that artifact would pass. This is the one that would not.
//!
//! Both directions, because they catch opposite failures and only one is obvious:
//!
//! * spec \ reference — a flag the surface declares that the reference omits, so
//!   the reader is told a flag does not exist.
//! * reference \ spec — a flag the reference names that the surface does not
//!   have, so the reader is told to type something that will not parse. This is
//!   the direction a "did we document everything" check misses entirely.
//!
//! # Why the renderer is not stubbed here
//!
//! The retired bats suite stubbed `mise-tasks/render/cli.sh`, because the gate it
//! drove resolved its renderer as a sibling program and could therefore be handed
//! a different one. That indirection does not survive the port: the renderer *is*
//! `batten generate markdown` (`mise-tasks/render/cli.sh` only moves its stdout to
//! a file), so this tier renders with the real binary and doctors the TEXT it
//! produced. Same discrimination, one fewer authority — and the doctored text is
//! exactly what the stub used to emit.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::collections::BTreeSet;

use common::{batten, scratch};

/// A scratch root unique to THIS PROCESS, not just to this case.
///
/// `common::scratch` roots at the shared `CARGO_TARGET_TMPDIR`, and since
/// CLOUD-1164 this binary runs TWICE CONCURRENTLY under `verify`: once through
/// `test:cargo` in the `hooks` task, and once through the narrow `test:*` task
/// the repointed `hk` step calls in `ci:quick`. Two processes running the same
/// case then share one directory, and `scratch`'s unconditional wipe deletes the
/// tree the other one is mid-case in — measured as a `NotFound` on a file the
/// fixture had just written. The pid makes the two runs disjoint.
fn isolated(name: &str) -> std::path::PathBuf {
    scratch(&format!("{name}-{}", std::process::id()))
}

// THE FILE-GRANULARITY RETIREMENT ARMS (CLOUD-1059). Two paths die, so two arms:
// a program and its suite are separate subjects, and one arm covering both would
// claim a conservation nobody checked. Their grammar is disjoint from the case
// arms below by construction — a case arm's first field after the marker is a
// QUOTED case name, a file arm's is a path. The suite's arm names its declared
// `# subject:` too (CLOUD-1130), which this same delta retires.
//
// carried: mise-tasks/reference-check.sh crates/batten/src/render.rs crates/batten/tests/reference_coverage.rs
// carried: tests/reference-check.bats mise-tasks/reference-check.sh crates/batten/src/render.rs crates/batten/tests/reference_coverage.rs
//
// CLOUD-908's case arms: every `@test` the retired suite declared, and where its
// predicate lives now. Eight carried and two changed, and both changes are the
// same SEAM — the renderer stopped being a separate program — rather than a
// predicate dropped. Arms are suite-qualified because a case TITLE is not unique
// across suites and this bundle retires four of them at once.
//
// carried: "reference-check.bats::a reference naming every declared flag passes" crates/batten/tests/reference_coverage.rs
// carried: "reference-check.bats::a flag the reference omits is reported with its name" crates/batten/tests/reference_coverage.rs
// carried: "reference-check.bats::a flag the reference invents is reported with its name" crates/batten/tests/reference_coverage.rs
// carried: "reference-check.bats::both directions are reported in one run, not just the first" crates/batten/tests/reference_coverage.rs
// carried: "reference-check.bats::output is pointer-only — no line of the reference echoed" crates/batten/tests/reference_coverage.rs
// carried: "reference-check.bats::a reference naming no flags at all is could-not-look, never a pass" crates/batten/tests/reference_coverage.rs
// carried: "reference-check.bats::the gate leaves no reference behind in the tree it judges" crates/batten/tests/reference_coverage.rs
// carried: "reference-check.bats::this repo's reference covers its surface — the gate on the real tree" crates/batten/tests/reference_coverage.rs
//
// changed: "reference-check.bats::a renderer that fails is could-not-look, never a pass" crates/batten/tests/reference_coverage.rs the suite stubbed a sibling program that exited 1, and there is no sibling to stub: the renderer is the binary under test. The property that survives is the one the stub stood in for — a render that did not produce a reference must not read as a covered one — asserted in `a_render_that_did_not_happen_is_never_read_as_coverage`, which drives the real binary to a non-zero exit and shows the empty reading is refused rather than passed
// changed: "reference-check.bats::an absent renderer is could-not-look, never a pass" crates/batten/tests/reference_coverage.rs same cause, one case further on: an ABSENT renderer is unreachable once the renderer is the binary, because a missing binary is a test harness that did not build rather than a verdict this tier can reach. The reading it protected — that an unusable render is not coverage — is the same one `a_render_that_did_not_happen_is_never_read_as_coverage` carries, so this arm records the collapse rather than claiming two cases survived

/// Every flag id the surface declares, at every depth.
///
/// Ids rather than long names: a positional has no `--long`, and a reference that
/// omitted one would otherwise be invisible here.
fn spec_flag_ids() -> BTreeSet<String> {
    let output = batten()
        .args(["spec", "--format", "json"])
        .output()
        .expect("run batten spec --format json");
    assert_eq!(
        output.status.code(),
        Some(0),
        "the binary could not emit its spec, so there is nothing to compare against"
    );
    let spec: serde_json::Value = serde_json::from_slice(&output.stdout).expect("the spec is JSON");
    let mut ids = BTreeSet::new();
    collect_flag_ids(&spec, &mut ids);
    ids
}

fn collect_flag_ids(node: &serde_json::Value, into: &mut BTreeSet<String>) {
    if let Some(flags) = node.get("flags").and_then(serde_json::Value::as_array) {
        for flag in flags {
            if let Some(name) = flag.get("name").and_then(serde_json::Value::as_str) {
                into.insert(name.to_owned());
            }
        }
    }
    if let Some(children) = node
        .get("subcommands")
        .and_then(serde_json::Value::as_array)
    {
        for child in children {
            collect_flag_ids(child, into);
        }
    }
}

/// The reference, rendered fresh by the binary.
///
/// Rendered rather than read from wherever a previous run left it: the artifact
/// is deliberately not committed, so there is no "current copy" to trust, and a
/// gate judging a stale render would answer about a surface that no longer
/// exists.
fn rendered_reference() -> String {
    let output = batten()
        .args(["generate", "markdown"])
        .output()
        .expect("run batten generate markdown");
    assert_eq!(
        output.status.code(),
        Some(0),
        "the reference could not be rendered, so its coverage is unknown"
    );
    String::from_utf8(output.stdout).expect("the reference is UTF-8")
}

/// Every flag the reference names.
///
/// The renderer writes each as the leading code span in the table's first column,
/// so the anchor is that column and not a bare backtick run — which would also
/// match the effect tokens, the command paths and any prose. One authority for
/// the row shape: `render::flag_table`.
fn flags_named_in(markdown: &str) -> BTreeSet<String> {
    markdown
        .lines()
        .filter_map(|line| line.strip_prefix("| `"))
        .filter_map(|rest| rest.split_once('`'))
        .filter(|(_, tail)| tail.starts_with(" |"))
        .map(|(name, _)| name.to_owned())
        .collect()
}

/// The two directions, as the flag ids each is missing.
///
/// Pointer-only (non-negotiable rule 4): flag ids and nothing else. The id is
/// Batten's own declaration rather than caller content — the same reasoning
/// `pointer_only.rs` records for why `generate markdown` is `Echoes` rather than
/// `PointerOnly`.
fn differences(
    declared: &BTreeSet<String>,
    named: &BTreeSet<String>,
) -> (Vec<String>, Vec<String>) {
    (
        declared.difference(named).cloned().collect(),
        named.difference(declared).cloned().collect(),
    )
}

/// A reference with the row naming `flag` removed.
fn without_row(markdown: &str, flag: &str) -> String {
    let row = format!("| `{flag}` |");
    let kept: Vec<&str> = markdown
        .lines()
        .filter(|line| !line.starts_with(&row))
        .collect();
    assert_ne!(
        kept.len(),
        markdown.lines().count(),
        "the doctored reference must actually drop `{flag}`, or the case asserts nothing"
    );
    kept.join("\n")
}

/// A reference with an extra row naming a flag the surface does not have.
fn with_invented_row(markdown: &str, description: &str) -> String {
    format!("{markdown}\n| `no-such-flag` | x | x | x | {description} |\n")
}

// --- the predicate, over the real tree ----------------------------------------

#[test]
fn the_reference_and_the_spec_name_the_same_flags() {
    // The self-consumption case: the committed surface and its renderer still
    // agree, in both directions, today.
    let declared = spec_flag_ids();
    let named = flags_named_in(&rendered_reference());
    let (omitted, invented) = differences(&declared, &named);
    assert!(
        omitted.is_empty(),
        "the reference omits {omitted:?}; it is derived, so this is a renderer defect \
         rather than a document to edit"
    );
    assert!(
        invented.is_empty(),
        "the reference names {invented:?}, which the surface does not declare"
    );
}

// --- anti-vacuity: neither reading may be empty --------------------------------

#[test]
fn neither_reading_is_empty_so_agreement_is_not_agreement_about_nothing() {
    // Two empty sets are equal, so without this the case above passes over a spec
    // that declares nothing and a parser pointed at the wrong shape. That is the
    // could-not-look answer the retired gate spelled as exit 2, and it is the one
    // verdict this predicate must never give silently.
    assert!(
        !spec_flag_ids().is_empty(),
        "the spec declares no flags at all. That is not a covered reference, it is a \
         reading that failed."
    );
    assert!(
        !flags_named_in(&rendered_reference()).is_empty(),
        "the reference names no flags at all, so this parser is pointed at the wrong \
         shape — and a check that checks nothing must not report green."
    );
}

#[test]
fn a_reference_naming_no_flags_at_all_is_never_read_as_coverage() {
    // The same reading from the comparator's side: an empty parse must report
    // every declared flag as omitted rather than as clean.
    let declared = spec_flag_ids();
    let named = flags_named_in("nothing here resembles a flag table");
    assert!(named.is_empty(), "the doctored text names no flags");
    let (omitted, invented) = differences(&declared, &named);
    assert_eq!(
        omitted.len(),
        declared.len(),
        "an unparseable reference omits every declared flag"
    );
    assert!(invented.is_empty());
}

// --- shown able to fail, in both directions (CLOUD-418) ------------------------

#[test]
fn a_flag_the_reference_omits_is_reported_by_name() {
    // The reader is told a flag does not exist.
    let declared = spec_flag_ids();
    let dropped = declared
        .iter()
        .next()
        .expect("the surface declares at least one flag")
        .clone();
    let doctored = without_row(&rendered_reference(), &dropped);
    let (omitted, invented) = differences(&declared, &flags_named_in(&doctored));
    assert_eq!(omitted, vec![dropped], "the omission is reported by name");
    assert!(invented.is_empty());
}

#[test]
fn a_flag_the_reference_invents_is_reported_by_name() {
    // The direction a "did we document everything" check misses entirely: the
    // reader is told to type something that will not parse.
    let declared = spec_flag_ids();
    let doctored = with_invented_row(&rendered_reference(), "x");
    let (omitted, invented) = differences(&declared, &flags_named_in(&doctored));
    assert!(omitted.is_empty());
    assert_eq!(invented, vec!["no-such-flag".to_owned()]);
}

#[test]
fn both_directions_are_reported_in_one_run_not_just_the_first() {
    let declared = spec_flag_ids();
    let dropped = declared
        .iter()
        .next()
        .expect("the surface declares at least one flag")
        .clone();
    let doctored = with_invented_row(&without_row(&rendered_reference(), &dropped), "x");
    let (omitted, invented) = differences(&declared, &flags_named_in(&doctored));
    assert_eq!(omitted, vec![dropped]);
    assert_eq!(invented, vec!["no-such-flag".to_owned()]);
}

#[test]
fn the_report_names_flag_ids_and_never_a_line_of_the_reference() {
    // rule 4: the remedy is always a renderer fix, so the reference body adds
    // nothing and would put the document itself into the log.
    const DISTINCTIVE: &str = "a very distinctive invented description";
    let declared = spec_flag_ids();
    let doctored = with_invented_row(&rendered_reference(), DISTINCTIVE);
    let (omitted, invented) = differences(&declared, &flags_named_in(&doctored));
    let report = format!("{omitted:?} {invented:?}");
    assert!(report.contains("no-such-flag"), "{report}");
    assert!(
        !report.contains(DISTINCTIVE),
        "the report carried a line of the reference: {report}"
    );
}

// --- the render is a reading, never a write ------------------------------------

#[test]
fn rendering_the_reference_leaves_nothing_behind_in_the_tree_it_judges() {
    // A check that writes the tree it judges is the shape `derived-check`'s header
    // refuses, and this one has no business leaving an artifact behind at all:
    // `generate markdown` writes to stdout, so there is nothing to clean up.
    let dir = isolated("reference-coverage-render");
    let output = batten()
        .args(["generate", "markdown"])
        .current_dir(&dir)
        .output()
        .expect("run batten generate markdown");
    assert_eq!(output.status.code(), Some(0));
    assert!(!output.stdout.is_empty(), "the render went to stdout");
    let left_behind: Vec<_> = std::fs::read_dir(&dir)
        .expect("read the scratch directory")
        .filter_map(Result::ok)
        .map(|entry| entry.file_name())
        .collect();
    assert!(
        left_behind.is_empty(),
        "the render left files behind: {left_behind:?}"
    );
}

#[test]
fn a_render_that_did_not_happen_is_never_read_as_coverage() {
    // What the retired suite's two stubbed-renderer cases stood for. There is no
    // sibling program to break any more, so the reachable failure is a render the
    // binary refuses to perform: it must exit non-zero and emit no table, and the
    // empty reading that leaves must report as missing coverage rather than as a
    // clean tree.
    let output = batten()
        .args(["generate", "markdown", "--no-such-flag"])
        .output()
        .expect("run batten generate markdown with a bad flag");
    assert_ne!(
        output.status.code(),
        Some(0),
        "a render that cannot run must not exit clean"
    );
    let emitted = String::from_utf8_lossy(&output.stdout);
    let named = flags_named_in(&emitted);
    assert!(
        named.is_empty(),
        "a failed render emitted a flag table: {named:?}"
    );
    let (omitted, _) = differences(&spec_flag_ids(), &named);
    assert!(
        !omitted.is_empty(),
        "an absent reference must read as missing coverage, never as agreement"
    );
}
