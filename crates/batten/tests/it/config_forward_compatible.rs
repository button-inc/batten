//! A row from a newer schema costs its own row, never the whole file (CLOUD-1428).
//!
//! # The defect this pins
//!
//! `deny_unknown_fields` on the row types made an unknown key a hard load error
//! for the ENTIRE config. `batten hook` could then resolve no rule set at all,
//! and a config load failure is exit `1` — which under this repository's exit
//! contract does not block a call. So one unknown key in one row switched off
//! the protected-path gate, the verb table, every `shape` row and the rest, and
//! did it silently while `batten --version` answered normally.
//!
//! Measured twice. 2026-09-04: a commit added `git = ["worktrees"]`, the
//! installed binary predated it, and every mediated call failed open for about
//! an hour — found only because an unrelated command happened to print the parse
//! error. 2026-09-05: `main` gained `decided_by` and `[[provision.env]]` while
//! the released binary was v0.0.142, reproducing it exactly.
//!
//! # Why the closed enums are not what changed
//!
//! `rules.rs` argues that an unknown variant must be a load error rather than a
//! fact resolving to undefined, because Rego reads undefined as *does not hold*
//! — a rule configured, typed and silently off. That argument is sound and is
//! about ONE ROW under-enforcing. It was applied at whole-file granularity,
//! where it produces the strictly worse outcome it exists to prevent.
//!
//! # The pair, and why neither case alone is enough
//!
//! A fixture carrying only the unresolvable row would pass against a build that
//! still failed the whole load — there would be nothing left to enforce either
//! way, so the case could not tell the fix from the defect. The discriminating
//! input is a good row BESIDE a bad one: the good row must still decide, and the
//! bad one must be named.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::fs;
use std::path::{Path, PathBuf};

use common::{batten, run_with_stdin, scratch};

/// A `shape` row that refuses `rm`, spelled the way the matcher accepts.
const GOOD: &str = r#"
[[rule]]
id = "good-row"
kind = "shape"
scope = "mediated_call"
pattern = "rm /"
severity = "deny"
reason = "this row must still decide"
"#;

/// The same shape carrying one key no build of this binary has ever had.
const FROM_A_NEWER_SCHEMA: &str = r#"
[[rule]]
id = "newer-schema-row"
kind = "shape"
scope = "mediated_call"
pattern = "nevermatches /"
severity = "deny"
reason = "a row this build cannot resolve"
this_key_does_not_exist_in_any_version = true
"#;

/// A repository whose `batten.toml` is exactly `body`.
fn repo(name: &str, body: &str) -> PathBuf {
    let dir = scratch(name);
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join("batten.toml"), format!("version = 1\n{body}")).unwrap();
    dir
}

/// Adjudicate the fixture's call and return `(exit code, stdout, stderr)`.
fn adjudicate(dir: &Path) -> (Option<i32>, String, String) {
    let out = run_with_stdin(
        dir,
        &["adjudicate", "--harness", "claude-code"],
        r#"{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"rm /"}}"#,
    );
    (
        out.status.code(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// THE CASE THE DEFECT FAILS. A good row beside an unresolvable one still
/// decides — before this, the whole file failed to load and the call was allowed
/// at exit `1`.
#[test]
fn a_row_from_a_newer_schema_does_not_take_the_other_rows_with_it() {
    let dir = repo(
        "config-forward-mixed",
        &format!("{GOOD}{FROM_A_NEWER_SCHEMA}"),
    );
    let (code, stdout, stderr) = adjudicate(&dir);

    // THE DENY IS THE JSON, NOT THE EXIT CODE. Under `--harness claude-code` a
    // refusal is `permissionDecision` on stdout and the process still exits 0 —
    // the host reads the document, not the status. Asserting on the code here
    // would pass against a build that refused for a reason of its own.
    assert_eq!(code, Some(0), "the hook answered: {stdout} {stderr}");
    assert!(
        stdout.contains(r#""permissionDecision":"deny""#),
        "the good row must still refuse the call: {stdout}"
    );
    assert!(
        stdout.contains("good-row"),
        "the deny names the row that decided: {stdout}"
    );
}

/// THE ANTI-VACUITY HALF. Without it the case above is satisfied by a build that
/// ignores unknown keys entirely — which would be the permissive fallback
/// CLOUD-251 names, and would leave a typo silently disabling a gate.
#[test]
fn the_dropped_row_is_named_rather_than_silently_discarded() {
    let dir = repo(
        "config-forward-named",
        &format!("{GOOD}{FROM_A_NEWER_SCHEMA}"),
    );
    let out = batten()
        .args(["config", "show"])
        .current_dir(&dir)
        .output()
        .expect("run batten config show");
    let said = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        said.contains("newer-schema-row"),
        "a dropped row is a gate that is OFF and must be reported by id: {said}"
    );
    assert!(
        !said.contains("this_key_does_not_exist_in_any_version"),
        "pointer-only: the report names the row, never the file's contents: {said}"
    );
}

/// A CONFIG THIS BUILD FULLY UNDERSTANDS IS UNTOUCHED. The prune must never run
/// for it — same verdict, no report, nothing dropped.
#[test]
fn a_config_this_build_understands_reports_nothing_dropped() {
    let dir = repo("config-forward-clean", GOOD);
    let (code, stdout, _) = adjudicate(&dir);
    assert_eq!(code, Some(0), "the hook answered: {stdout}");
    assert!(
        stdout.contains(r#""permissionDecision":"deny""#),
        "the good row decides: {stdout}"
    );

    let out = batten()
        .args(["config", "show"])
        .current_dir(&dir)
        .output()
        .expect("run batten config show");
    // BOTH CHANNELS, because the report is written to stderr: asserting only
    // stdout here made this half unable to fail, which review caught. The
    // sibling case above reads both for the same reason.
    let said = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        !said.contains("unresolved"),
        "a clean config must not report a drop it did not make: {said}"
    );
}

/// THE REFUSAL AFTER A PRUNE NAMES A LINE IN THE READER'S OWN FILE. The first
/// version re-serialised the document to drop a row, so the surviving error's
/// span was against `toml::to_string`'s output — keys sorted, comments gone —
/// and a key on line 11 was reported as line 4. A pointer into a file the reader
/// does not have is worse than no pointer.
#[test]
fn a_refusal_after_a_prune_points_at_the_source_line() {
    let dir = repo(
        "config-forward-line",
        &format!(
            "{FROM_A_NEWER_SCHEMA}\n# a comment the prune must not eat\n[worktree]\nnot_a_key_here_either = true\n"
        ),
    );
    let (code, _, stderr) = adjudicate(&dir);
    assert_eq!(code, Some(1), "the top-level fault is still refused");
    // Line 13 of the fixture: the `[worktree]` header, a top-level key this
    // build does not know and cannot charge to any row. The comment and the
    // blank line above it are what a re-serialising prune would have eaten,
    // which is how the reported line moved.
    assert!(
        stderr.contains("line 13"),
        "the refusal must name the line the reader has to edit: {stderr}"
    );
}

/// TWO DROPPED ROWS ARE TWO POINTERS. The index was computed against the
/// already-pruned text, so two id-less rows both reported `#0` — a report that
/// names one row twice is a report a reader cannot act on. `verb`, `redirect`,
/// `waiver` and `provision` rows declare no `id`, so the index is all they have.
#[test]
fn two_dropped_rows_in_one_section_report_distinct_pointers() {
    let row = |pattern: &str| {
        format!(
            "\n[[waiver]]\nrule = \"{pattern}\"\nreason = \"r\"\nexpires = \"2099-01-01\"\n\
             from_a_newer_schema = true\n"
        )
    };
    let dir = repo(
        "config-forward-two",
        &format!("{}{}", row("first"), row("second")),
    );
    let out = batten()
        .args(["config", "show"])
        .current_dir(&dir)
        .output()
        .expect("run batten config show");
    let said = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(
        said.contains("waiver #0") && said.contains("waiver #1"),
        "each dropped row needs its own pointer: {said}"
    );
}

/// A KEY UNDER A PLAIN `[section]` NO LONGER TAKES THE FILE, and this case
/// records the reversal rather than being deleted.
///
/// It used to assert the opposite — that such a key kept the hard refusal — and
/// that WAS the design until 2026-09-06, when `[capture]` on `main` grew
/// `inline_max_bytes`, every released binary predated it, the whole config
/// failed to load, and every mediated gate failed open for a day because a load
/// failure is exit `1` and exit `1` does not block a call. The refusal moved to
/// `config lint`, which names the key and exits `2`; what it no longer does is
/// take the rest of the file with it.
///
/// What it still holds is the OTHER half of the original claim: no `[[row]]` is
/// dropped for a fault that is not in one. That was the defect the old case was
/// really written for — `owning_row` charging a plain section's key to a
/// `[[rule]]` further up and deleting it.
#[test]
fn a_key_under_a_plain_section_drops_no_row() {
    let dir = repo(
        "config-forward-section",
        &format!("{GOOD}\n[ready]\nnot_a_key_this_build_knows = true\n"),
    );
    let (code, stdout, stderr) = adjudicate(&dir);
    assert_eq!(code, Some(0), "the file still loads: {stdout} {stderr}");
    assert!(
        stdout.contains(r#""permissionDecision":"deny""#) && stdout.contains("good-row"),
        "the rule beside it must still enforce: {stdout}"
    );
    assert!(
        !stderr.contains("unresolved rule"),
        "no ROW may be dropped for a fault that is not in one: {stderr}"
    );
}

/// A HEADER-SHAPED LINE INSIDE A MULTI-LINE STRING IS NOT A HEADER.
///
/// The line scan that finds a row's boundaries read raw lines, so a `[[rule]]`
/// written inside a `reason = """…"""` was taken for a section boundary: the
/// prune blanked from the wrong offset and the refusal quoted a fabricated
/// `invalid multi-line basic string` at a line the author's file does not have.
/// This repository's own `batten.toml` carries 363 multi-line `reason` strings,
/// so it is the common shape rather than an exotic one.
///
/// The good row must still DECIDE, which is what makes this more than a
/// no-crash case: a fix that simply refused the file would satisfy an assertion
/// about the error text and reinstate the fail-open this change removes.
#[test]
fn a_header_shaped_line_inside_a_multi_line_string_is_not_a_boundary() {
    let quoted = r#"
[[rule]]
id = "quotes-a-header"
kind = "shape"
scope = "mediated_call"
pattern = "nevermatches /"
severity = "deny"
reason = """
A row is spelled like this:
[[rule]]
and that line is prose, not a section.
"""
"#;
    let dir = repo(
        "config-forward-multiline",
        &format!("{GOOD}{quoted}{FROM_A_NEWER_SCHEMA}"),
    );
    let (code, stdout, stderr) = adjudicate(&dir);
    assert_eq!(code, Some(0), "the hook answered: {stdout} {stderr}");
    assert!(
        stdout.contains(r#""permissionDecision":"deny""#) && stdout.contains("good-row"),
        "the good row must still decide beside a quoted header: {stdout}"
    );
    assert!(
        !stderr.contains("multi-line basic string"),
        "the prune must not manufacture a lexing error: {stderr}"
    );
}

/// A SINGLE-LINE STRING CONTAINING `'''` MUST NOT OPEN A MULTI-LINE STRING.
///
/// The line scan toggled on any `"""`/`'''` byte-triple wherever it appeared, so
/// `batten.toml:4383` — `pattern = "run = '''"`, an ordinary row — opened a
/// literal-string state that never closed. Every header after it went unseen,
/// an unknown key anywhere past it resolved to the last row BEFORE it,
/// `row_end` returned the end of the file, and the prune blanked 349 KB: 646
/// sections, the whole `[[verdict]]` registry and `[attribution]`'s
/// `identity_deny` among them, while reporting exactly one dropped row.
///
/// **The discriminating assertion is that the LATER good row still decides.** A
/// case checking only that the file loads would pass against the truncation,
/// because a document cut at a section boundary is valid TOML — which is
/// precisely why the old "does it still parse" guard did not fire.
#[test]
fn a_single_line_string_holding_a_triple_quote_does_not_swallow_the_file() {
    let quoting = r#"
[[rule]]
id = "quotes-a-delimiter"
kind = "shape"
scope = "mediated_call"
pattern = "run = '''"
severity = "deny"
reason = "an ordinary row whose pattern contains a triple quote"
"#;
    // The unresolvable row comes FIRST, and the good row LAST, so the scan has
    // to stay synchronised across the quoting row to find either.
    let dir = repo(
        "config-forward-triple",
        &format!("{FROM_A_NEWER_SCHEMA}{quoting}{GOOD}"),
    );
    let (code, stdout, stderr) = adjudicate(&dir);
    assert_eq!(code, Some(0), "the hook answered: {stdout} {stderr}");
    assert!(
        stdout.contains(r#""permissionDecision":"deny""#) && stdout.contains("good-row"),
        "a row after the quoting one must still be enforced: {stdout}"
    );

    let out = batten()
        .args(["config", "show"])
        .current_dir(&dir)
        .output()
        .expect("run batten config show");
    let said = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(
        said.contains("newer-schema-row"),
        "the one unresolvable row is still named: {said}"
    );
    assert!(
        !said.contains("quotes-a-delimiter"),
        "and no other row may be taken with it: {said}"
    );
}

/// A HEADER MAY CARRY A TRAILING COMMENT, AND `[[ rule ]]` IS A HEADER.
///
/// The scan matched a line that EQUALS `[[name]]` after trimming, so an
/// ordinary `[[rule]] # note` was invisible: no header was seen, the prune could
/// not localise the fault, and the whole file was refused at exit `1` — which
/// under this repository's exit contract does not block a mediated call.
/// Measured over the compiled binary, one keystroke apart: with the comment,
/// exit 1 and no deny over `rm /`; without it, exit 0 and the deny.
///
/// Both spellings in one fixture, because the trimming and the bracket search
/// are the same defect from two sides.
#[test]
fn a_header_with_a_trailing_comment_is_still_a_header() {
    let spaced = r#"
[[ rule ]]   # a header written the other legal way
id = "spaced-row"
kind = "shape"
scope = "mediated_call"
pattern = "nevermatches /"
severity = "deny"
reason = "a row whose header carries whitespace and a comment"
"#;
    let dir = repo(
        "config-forward-header-comment",
        &format!(
            "{}{spaced}{FROM_A_NEWER_SCHEMA}",
            GOOD.replace("[[rule]]", "[[rule]] # trailing comment")
        ),
    );
    let (code, stdout, stderr) = adjudicate(&dir);
    assert_eq!(code, Some(0), "the hook answered: {stdout} {stderr}");
    assert!(
        stdout.contains(r#""permissionDecision":"deny""#) && stdout.contains("good-row"),
        "a row whose header carries a comment must still decide: {stdout}"
    );
}

/// A KEY IN A PLAIN `[section]` COSTS THE KEY, NOT THE FILE.
///
/// **This is the shape that actually took the fleet down, and the first version
/// of this whole change did not cover it.** On 2026-09-06 `main`'s `[capture]`
/// table grew `inline_max_bytes`; every released binary predated the field, the
/// whole config failed to load, and because a config load failure is exit `1`
/// — which does not block a call — every mediated gate failed open. No new
/// session could start for a day. `inline_max_bytes` is not in a `[[row]]`, so
/// the row-granular arm above could never have repaired it.
///
/// The good row must still DECIDE, which is what separates this from "the file
/// happened to load": a build that dropped the whole `[section]`, or that
/// swallowed the file wholesale, would satisfy a weaker assertion.
#[test]
fn a_key_in_a_plain_section_costs_the_key_not_the_file() {
    let dir = repo(
        "config-forward-section-key",
        &format!("{GOOD}\n[ready]\nfrom_a_newer_schema = 1024\n"),
    );
    let (code, stdout, stderr) = adjudicate(&dir);
    assert_eq!(code, Some(0), "the hook answered: {stdout} {stderr}");
    assert!(
        stdout.contains(r#""permissionDecision":"deny""#) && stdout.contains("good-row"),
        "a rule beside an unreadable section key must still enforce: {stdout}"
    );

    let out = batten()
        .args(["config", "show"])
        .current_dir(&dir)
        .output()
        .expect("run batten config show");
    let said = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(
        said.contains("ready") && said.contains("from_a_newer_schema"),
        "the dropped key is named by its table and its own name: {said}"
    );
}

/// AND THE REST OF THAT TABLE SURVIVES. Dropping the whole `[section]` would
/// also make the file load, so this is the half that says which granularity was
/// chosen: a settings table keeps every key this build does understand and runs
/// the unknown one on its own default.
#[test]
fn the_rest_of_the_section_still_applies() {
    let dir = repo(
        "config-forward-section-rest",
        &format!(
            "{GOOD}\n[ready]\nfrom_a_newer_schema = 1024\n\
             prose_dialect_required_from = \"2026-01-01T00:00:00Z\"\n"
        ),
    );
    let out = batten()
        .args(["config", "show"])
        .current_dir(&dir)
        .output()
        .expect("run batten config show");
    let shown = String::from_utf8_lossy(&out.stdout).into_owned();
    let said = String::from_utf8_lossy(&out.stderr).into_owned();
    // `config show` emits the table's resolved KEY COUNT, not its values, and
    // that count is the exact discriminator: `ready 1` is the known key
    // surviving, `ready 0` is the whole table having gone with the unknown one.
    assert!(
        shown.contains("ready 1"),
        "the key this build DOES know must survive the drop: {shown}"
    );
    assert!(
        said.contains("from_a_newer_schema") && !said.contains("prose_dialect_required_from"),
        "and only the unknown one is dropped: {said}"
    );
}

/// MALFORMED TOML STAYS A HARD REFUSAL. A file that is not TOML is a different
/// fault from a well-formed row naming a key from a newer schema, and collapsing
/// the two is what produced the defect — a prune that swallowed a syntax error
/// would load "no rules configured" over a broken file.
#[test]
fn a_file_that_is_not_toml_is_still_refused() {
    let dir = repo("config-forward-broken", "[[rule\nbroken\n");
    let (code, _, stderr) = adjudicate(&dir);
    assert_eq!(code, Some(1), "malformed TOML is a usage error: {stderr}");
    assert!(
        stderr.contains("TOML parse error"),
        "the refusal says the file is not TOML: {stderr}"
    );
}
