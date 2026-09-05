//! The board sweep over the compiled binary (CLOUD-186, CLOUD-1127).
//!
//! `landed.rs` carries the predicate's own tier, and this is the one that proves
//! the ENGINE builds the input the predicate reads: the argv, the three evidence
//! files, the stdin payload, the exit table and the pointer shape. A unit case
//! over `decide` cannot settle any of those — it constructs the `Evidence` the
//! verb is supposed to assemble, which is the fabricate-the-shape defect
//! `.claude/rules/policy-modules.md` records for `with input as`.
//!
//! **The controls are CLOUD-1127's own, drawn from real state rather than
//! invented.** PR #726 merged 2026-08-28 carrying `Closes CLOUD-1119`,
//! `Closes CLOUD-1120`, `DO-NOT-CLOSE CLOUD-1110` and `DO-NOT-CLOSE CLOUD-985`,
//! and `closing-key-check` passed. At the merge second CLOUD-1110 and CLOUD-985
//! — both explicitly declined — moved to In Review anyway.

use crate::common;

/// Write the three evidence files a sweep reads, returning the fixture dir.
///
/// Every case supplies `--merged-prs` because absent is could-not-look rather
/// than an empty set, which is itself a case below.
fn evidence(
    name: &str,
    merged: &[(&str, &str)],
    declined: &[&str],
    asserted: &[(&str, &str)],
) -> std::path::PathBuf {
    let dir = common::scratch(name);
    std::fs::write(dir.join("merged.tsv"), tsv(merged)).expect("write merged evidence");
    let declined_body = declined.iter().fold(String::new(), |mut acc, key| {
        acc.push_str(key);
        acc.push('\n');
        acc
    });
    std::fs::write(dir.join("declined.tsv"), declined_body).expect("write declined evidence");
    std::fs::write(dir.join("asserted.tsv"), tsv(asserted)).expect("write asserted evidence");
    dir
}

/// Two tab-separated columns per row.
///
/// Folded rather than `map(format!).collect()`, which `clippy::format_collect`
/// refuses: each `format!` allocates a `String` the collect immediately drops.
fn tsv(rows: &[(&str, &str)]) -> String {
    rows.iter().fold(String::new(), |mut acc, (left, right)| {
        acc.push_str(left);
        acc.push('\t');
        acc.push_str(right);
        acc.push('\n');
        acc
    })
}

fn board(rows: &[(&str, &str)]) -> String {
    let entries = rows.iter().fold(Vec::new(), |mut acc, (id, status)| {
        acc.push(format!(r#"{{"id":"{id}","status":"{status}"}}"#));
        acc
    });
    format!("[{}]", entries.join(","))
}

/// CLOUD-1127's negative control, and the reason the row exists. A key the body
/// DECLINED, sitting in a started column, is refused.
#[test]
fn a_declined_key_advanced_to_in_review_is_refused() {
    let dir = evidence(
        "landed-declined",
        &[("CLOUD-1119", "726")],
        &["CLOUD-1110"],
        &[],
    );
    let out = common::run_with_stdin(
        &dir,
        &[
            "landed",
            "check",
            "--merged-prs",
            "merged.tsv",
            "--declined",
            "declined.tsv",
        ],
        &board(&[("CLOUD-1110", "In Review")]),
    );

    assert_eq!(
        out.status.code(),
        Some(2),
        "a dishonest column is the policy verdict"
    );
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("CLOUD-1110"),
        "the finding names the key: {err}"
    );
    assert!(
        err.contains("declined-but-advanced"),
        "and the reason class: {err}"
    );
}

/// THE ARM THAT KEEPS THE MARKER USABLE. A declined row still in the queue is
/// the marker working, and a gate refusing it would make `DO-NOT-CLOSE`
/// unwritable.
#[test]
fn a_declined_key_still_in_the_queue_is_clean() {
    let dir = evidence(
        "landed-declined-queued",
        &[("CLOUD-1119", "726")],
        &["CLOUD-1110"],
        &[],
    );
    let out = common::run_with_stdin(
        &dir,
        &[
            "landed",
            "check",
            "--merged-prs",
            "merged.tsv",
            "--declined",
            "declined.tsv",
        ],
        &board(&[("CLOUD-1110", "Todo")]),
    );

    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// CLOUD-1127's positive control: a row closed in the body and merged is
/// honestly In Review, and the sweep says nothing about it.
#[test]
fn a_row_closed_in_the_body_and_merged_is_left_alone() {
    let dir = evidence("landed-closed", &[("CLOUD-1120", "726")], &[], &[]);
    let out = common::run_with_stdin(
        &dir,
        &["landed", "check", "--merged-prs", "merged.tsv"],
        &board(&[("CLOUD-1120", "In Review")]),
    );

    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// The other direction, unchanged from CLOUD-186: a row In Progress whose work
/// a merged pull request closed is behind git.
#[test]
fn an_in_progress_row_a_merged_pr_closed_is_behind_git() {
    let dir = evidence("landed-behind", &[("CLOUD-1120", "726")], &[], &[]);
    let out = common::run_with_stdin(
        &dir,
        &["landed", "check", "--merged-prs", "merged.tsv"],
        &board(&[("CLOUD-1120", "In Progress")]),
    );

    assert_eq!(out.status.code(), Some(2));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("In Progress -> In Review"), "{err}");
    assert!(err.contains("behind-git"), "{err}");
}

/// THE SUBSTRING TRAP, over the real argv rather than over a constructed set.
/// `CLOUD-17` must not be drained by `CLOUD-179` being closed.
#[test]
fn a_key_is_not_drained_by_a_longer_key_that_starts_with_it() {
    let dir = evidence("landed-substring", &[("CLOUD-179", "726")], &[], &[]);
    let out = common::run_with_stdin(
        &dir,
        &["landed", "check", "--merged-prs", "merged.tsv"],
        &board(&[("CLOUD-17", "In Progress")]),
    );

    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// WHICH ARM DRAINED IT IS PART OF THE FINDING, and only the compiled tier can
/// see that the ref survives the file read into the pointer line.
#[test]
fn an_asserted_landing_names_its_ref_in_the_finding() {
    let dir = evidence("landed-asserted", &[], &[], &[("CLOUD-903", "abc1234")]);
    let out = common::run_with_stdin(
        &dir,
        &[
            "landed",
            "check",
            "--merged-prs",
            "merged.tsv",
            "--landed-by",
            "asserted.tsv",
        ],
        &board(&[("CLOUD-903", "In Progress")]),
    );

    assert_eq!(out.status.code(), Some(2));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("asserted by --landed-by: abc1234"), "{err}");
}

/// ABSENT EVIDENCE IS COULD-NOT-LOOK, NEVER A CLEAN BOARD — and it is exit 1,
/// the Batten-failure code, rather than the policy verdict. This is the case the
/// whole reliability of the gate rests on: only 3% of this repository's commits
/// carry a closing keyword, so a sweep deciding on trailers alone would report a
/// clean column it never checked.
#[test]
fn a_sweep_with_no_merged_pr_evidence_refuses_rather_than_passing() {
    let dir = common::scratch("landed-no-evidence");
    let out = common::run_with_stdin(
        &dir,
        &["landed", "check"],
        &board(&[("CLOUD-1120", "In Progress")]),
    );

    assert_eq!(
        out.status.code(),
        Some(1),
        "could-not-look is not the verdict code"
    );
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("--merged-prs"), "{err}");
    assert!(
        !err.contains("every column agrees"),
        "a refusal must never print the clean line: {err}"
    );
}

/// A named file that cannot be opened is the caller's problem and is reported as
/// one — never an empty evidence set, which would silently halve the
/// disjunction and pass.
#[test]
fn evidence_that_cannot_be_read_refuses_rather_than_reading_as_empty() {
    let dir = common::scratch("landed-unreadable");
    let out = common::run_with_stdin(
        &dir,
        &["landed", "check", "--merged-prs", "nothing-here.tsv"],
        &board(&[("CLOUD-1120", "In Progress")]),
    );

    assert_eq!(out.status.code(), Some(1));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("cannot be read"), "{err}");
}

/// A payload that is not a board is could-not-look, so a caller piping the wrong
/// thing never looks like a clean sweep.
#[test]
fn a_payload_missing_status_is_could_not_look() {
    let dir = evidence("landed-bad-payload", &[("CLOUD-1", "1")], &[], &[]);
    let out = common::run_with_stdin(
        &dir,
        &["landed", "check", "--merged-prs", "merged.tsv"],
        r#"[{"id":"CLOUD-1"}]"#,
    );

    assert_eq!(out.status.code(), Some(1));
}

/// A STRAY LINE IS SKIPPED RATHER THAN REFUSING THE RUN. These files are
/// assembled from forge output by whatever fetched it, and a gate that refused
/// over an export header would be unrunnable for a reason unrelated to the
/// board. The key on the next line must still decide.
#[test]
fn a_header_line_in_the_evidence_does_not_stop_the_sweep() {
    let dir = common::scratch("landed-header");
    std::fs::write(dir.join("merged.tsv"), "issue\tpr\nCLOUD-1120\t726\n")
        .expect("write evidence with a header");
    let out = common::run_with_stdin(
        &dir,
        &["landed", "check", "--merged-prs", "merged.tsv"],
        &board(&[("CLOUD-1120", "In Progress")]),
    );

    assert_eq!(
        out.status.code(),
        Some(2),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// THE ARM THAT SHIPPED UNREACHABLE (CLOUD-1458).
///
/// `Evidence::claimed` was public, `landed()` branched on it, and four unit
/// cases constructed it — with no flag able to fill it, so the binary decided a
/// two-arm disjunction under a three-arm header. This is the case that could
/// not be written before the flag existed, which is exactly why the predicate's
/// own tier could not catch it.
///
/// SHOWN ABLE TO FAIL: `#MUTANT claimed-arm-unread` empties the arm, and
/// without it this row is not drained by anything else — the merged evidence
/// deliberately names a DIFFERENT key.
#[test]
fn a_key_closed_by_a_commit_on_main_is_behind_git() {
    let dir = common::scratch("landed-claimed");
    std::fs::write(dir.join("merged.tsv"), "CLOUD-999\t1\n").expect("write merged evidence");
    std::fs::write(dir.join("claimed.tsv"), "CLOUD-1120\n").expect("write claimed evidence");
    let out = common::run_with_stdin(
        &dir,
        &[
            "landed",
            "check",
            "--merged-prs",
            "merged.tsv",
            "--claimed",
            "claimed.tsv",
        ],
        &board(&[("CLOUD-1120", "In Progress")]),
    );

    assert_eq!(
        out.status.code(),
        Some(2),
        "the claimed arm must drain this row: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("In Progress -> In Review"), "{err}");
    assert!(err.contains("behind-git"), "{err}");
}

/// THE ANTI-VACUITY HALF of the case above: the same board and the same merged
/// evidence, with the claimed file withheld, must be CLEAN. Without this, a
/// `--claimed` flag the engine silently ignored would pass the case above for
/// the wrong reason — which is the shape that shipped.
#[test]
fn the_same_row_is_clean_when_the_claimed_evidence_is_withheld() {
    let dir = common::scratch("landed-claimed-null");
    std::fs::write(dir.join("merged.tsv"), "CLOUD-999\t1\n").expect("write merged evidence");
    let out = common::run_with_stdin(
        &dir,
        &["landed", "check", "--merged-prs", "merged.tsv"],
        &board(&[("CLOUD-1120", "In Progress")]),
    );

    assert_eq!(
        out.status.code(),
        Some(0),
        "nothing but the claimed arm drains this row, so withholding it must be clean: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// ABSENCE IS A READING (CLOUD-1458). `--claimed` is optional, so a caller can
/// omit it — and the bash predecessor could not reach that state at all, since
/// it read `main`'s log itself. An omitted arm that said nothing would be the
/// silently-halved disjunction this row fixed, moved one level out.
#[test]
fn a_sweep_without_the_claimed_arm_says_the_arm_is_unsupplied() {
    let dir = evidence("landed-claimed-unsaid", &[("CLOUD-1120", "726")], &[], &[]);
    let out = common::run_with_stdin(
        &dir,
        &["landed", "check", "--merged-prs", "merged.tsv"],
        &board(&[("CLOUD-9999", "Todo")]),
    );

    assert_eq!(
        out.status.code(),
        Some(0),
        "a clean board is still clean: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("--claimed"),
        "a two-arm sweep must not read as a three-arm one: {err}"
    );
}

/// The other direction: supplying the arm says nothing about it, because a
/// notice that fired either way would carry no information at all.
#[test]
fn a_sweep_with_the_claimed_arm_is_quiet_about_it() {
    let dir = common::scratch("landed-claimed-said");
    std::fs::write(dir.join("merged.tsv"), "CLOUD-1120\t726\n").expect("write merged evidence");
    std::fs::write(dir.join("claimed.tsv"), "CLOUD-903\n").expect("write claimed evidence");
    let out = common::run_with_stdin(
        &dir,
        &[
            "landed",
            "check",
            "--merged-prs",
            "merged.tsv",
            "--claimed",
            "claimed.tsv",
        ],
        &board(&[("CLOUD-9999", "Todo")]),
    );

    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        !err.contains("--claimed"),
        "the notice must fire only on the arm being absent: {err}"
    );
}

/// A DECLINED KEY THAT REACHED DONE (CLOUD-1458), which the predicate could not
/// see: `Row::STARTED` stopped at In Review, and Done is RELEASED — where the
/// claim is strongest and the lie costs most.
///
/// Measured rather than imagined: this gate's own two rows, CLOUD-186 and
/// CLOUD-1127, were declined in the body of the pull request that landed the
/// module and advanced to Done by a release the next morning.
///
/// SHOWN ABLE TO FAIL: `#MUTANT done-not-advanced` drops Done from the set.
#[test]
fn a_declined_key_released_to_done_is_refused() {
    let dir = evidence(
        "landed-declined-done",
        &[("CLOUD-1119", "726")],
        &["CLOUD-1110"],
        &[],
    );
    let out = common::run_with_stdin(
        &dir,
        &[
            "landed",
            "check",
            "--merged-prs",
            "merged.tsv",
            "--declined",
            "declined.tsv",
        ],
        &board(&[("CLOUD-1110", "Done")]),
    );

    assert_eq!(
        out.status.code(),
        Some(2),
        "a declined key that shipped is the strongest form of the lie: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("CLOUD-1110"), "{err}");
    assert!(err.contains("declined-but-advanced"), "{err}");
}

/*
THE TWO OBLIGATIONS CLOUD-1458's Ready block declares, in the shape
`crates/batten/tests/it/mcp_dispatch.rs` already uses: a block comment, the row
at column 0, mutating THIS file's own reading so the named case reddens only if
its assertion really binds.

Stated plainly rather than implied: `mutate::subjects()` enumerates the shell
programs under `mise-tasks`, the Rego modules under `policy`, and the preset
directories — never `crates/batten/tests`, so no sweep reaches these rows today,
exactly as none reaches `mcp_dispatch.rs`'s. `obligations-bound` is satisfied (a
tracked file carrying the slug) and the sweep half is not. That gap is the
mutation-tooling row's, and naming it here is what keeps the declaration from
reading as coverage it does not have.

(The globs are spelled out in words above because a Rust block comment NESTS,
and a literal star after a slash opens a second one.)

#MUTANT claimed-arm-unread|s@"CLOUD-1120\\n"@""@|a_key_closed_by_a_commit_on_main_is_behind_git
#MUTANT done-not-advanced|s@"CLOUD-1110", "Done"@"CLOUD-1110", "Todo"@|a_declined_key_released_to_done_is_refused
*/

/// POINTER-ONLY (rule 4). The sweep reads a board and three evidence files and
/// must emit keys, columns and reason classes — never a line of any body.
#[test]
fn the_finding_carries_no_body_text() {
    let dir = evidence(
        "landed-pointer",
        &[("CLOUD-1119", "726")],
        &["CLOUD-1110"],
        &[],
    );
    let out = common::run_with_stdin(
        &dir,
        &[
            "landed",
            "check",
            "--merged-prs",
            "merged.tsv",
            "--declined",
            "declined.tsv",
        ],
        // A body-shaped field the payload carries and the sweep must not echo.
        r#"[{"id":"CLOUD-1110","status":"In Review","description":"SECRET-CUSTOMER-DETAIL"}]"#,
    );

    let whole = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        !whole.contains("SECRET-CUSTOMER-DETAIL"),
        "the sweep echoed a body: {whole}"
    );
}
