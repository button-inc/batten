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

// --- the abandonment arm (CLOUD-1513) ------------------------------------
//
// THE SECOND TIER, and what it buys over the predicate's own unit cases. Those
// construct a `Claim` directly, which is the fabricate-the-shape defect
// `.claude/rules/policy-modules.md` records for `with input as`: they pass over
// a payload key the engine never reads and over an evidence file it never
// opens. Only a run of the compiled binary proves the boundary BUILDS what the
// predicate decides over.

/// A board payload with the three keys the abandonment arm reads.
fn dated_board(id: &str, updated: &str, attachment: Option<&str>, branch: &str) -> String {
    let attachments =
        attachment.map_or_else(|| "[]".to_owned(), |url| format!(r#"[{{"url":"{url}"}}]"#));
    format!(
        r#"[{{"id":"{id}","status":"In Progress","updatedAt":"{updated}",
             "attachments":{attachments},"gitBranchName":"{branch}"}}]"#
    )
}

/// Run the arm against a scratch dir carrying empty merged-PR evidence.
fn abandoned_run(name: &str, extra: &[&str], payload: &str) -> std::process::Output {
    let dir = common::scratch(name);
    std::fs::write(dir.join("merged.tsv"), "").expect("evidence is writable");
    let mut args = vec![
        "landed",
        "abandoned",
        "--merged-prs",
        "merged.tsv",
        "--instant",
        "2026-08-20",
    ];
    args.extend_from_slice(extra);
    common::run_with_stdin(&dir, &args, payload)
}

/// THE ENGINE READS THE THREE KEYS. A unit case cannot show this: it hands the
/// predicate a `Claim` already built, so it passes over a boundary that never
/// parsed `attachments` at all.
#[test]
fn the_boundary_builds_the_claim_the_predicate_decides_over() {
    let out = abandoned_run(
        "abandoned-reads-the-keys",
        &[],
        &dated_board("CLOUD-1", "2026-08-01", None, ""),
    );
    let whole = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        out.status.code(),
        Some(2),
        "a dead claim is the verdict: {whole}"
    );
    assert!(whole.contains("claimed-abandoned"), "{whole}");
    assert!(whole.contains("CLOUD-1"), "{whole}");
}

/// THE ANTI-VACUITY MIRROR. Without this the case above passes over an arm that
/// refuses everything, which is the direction that gets a sweep switched off.
///
/// **AND IT IS THE ONE SHAPE WHERE THIS ARM DELIBERATELY DISAGREES WITH THE
/// PROGRAM IT REPLACES** (CLOUD-1516). The branch here is EMPTY, which is what
/// makes the row interesting: `in-progress-drain.sh:275` reads its loop as
/// `while IFS=$'\t' read -r id branch has_pr`, tab is an IFS *whitespace*
/// character, so bash collapses `<id><TAB><TAB>true` into two fields — `branch`
/// takes `true` and `has_pr` is empty, the rescue never fires, and a row with an
/// open pull request reports as an abandoned claim.
///
/// Its own suite is green over that because both of its pull-request cases pass
/// a non-empty branch, so the combination is never constructed. This arm reads
/// typed fields and has no delimiter to collapse. Conserve the decision, not the
/// defect (CLOUD-1176) — so the divergence is deliberate, and this case is where
/// it is pinned rather than left for a reader to re-derive.
#[test]
fn a_claim_a_pull_request_is_serving_is_left_alone() {
    let out = abandoned_run(
        "abandoned-pr-rescues",
        &[],
        &dated_board(
            "CLOUD-1",
            "2026-08-01",
            Some("https://github.com/o/r/pull/12"),
            "",
        ),
    );
    let whole = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        out.status.code(),
        Some(0),
        "a served claim is clean: {whole}"
    );
    assert!(whole.contains("0 claimed-abandoned"), "{whole}");
}

/// THE REFS FILE IS EVIDENCE THE ENGINE OPENS. The predicate's unit case is
/// handed a set; this proves a `--refs` path is read and its lines become that
/// set — the arm that keeps this verb off a `git ls-remote` spawn.
#[test]
fn a_branch_named_in_the_refs_evidence_rescues_a_claim() {
    let dir = common::scratch("abandoned-refs-evidence");
    std::fs::write(dir.join("merged.tsv"), "").expect("evidence is writable");
    std::fs::write(
        dir.join("refs.txt"),
        "feat/live
",
    )
    .expect("refs are writable");
    let out = common::run_with_stdin(
        &dir,
        &[
            "landed",
            "abandoned",
            "--merged-prs",
            "merged.tsv",
            "--refs",
            "refs.txt",
            "--instant",
            "2026-08-20",
        ],
        &dated_board("CLOUD-1", "2026-08-01", None, "feat/live"),
    );
    assert_eq!(
        out.status.code(),
        Some(0),
        "a live branch rescues: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// THE BOUND THE RUN USED REACHES THE READER. A reader who cannot see which
/// number produced a finding has to look it up, and the one they find may not be
/// the one that ran.
#[test]
fn the_report_names_the_bound_it_used_rather_than_the_default() {
    let out = abandoned_run(
        "abandoned-names-its-bound",
        &["--max-idle-days", "5"],
        &dated_board("CLOUD-1", "2026-08-01", None, ""),
    );
    let whole = String::from_utf8_lossy(&out.stdout).to_string();
    assert!(whole.contains("idle > 5d"), "{whole}");
}

/// A KEY DEMANDED OF A ROW THAT OWES IT IS EXIT 1, NEVER A CLEAN COLUMN — and
/// the boundary is what turns an absent JSON key into that refusal.
#[test]
fn a_stale_row_missing_a_key_refuses_rather_than_sweeping_clean() {
    let out = abandoned_run(
        "abandoned-demands-its-keys",
        &[],
        r#"[{"id":"CLOUD-1","status":"In Progress","updatedAt":"2026-08-01"}]"#,
    );
    let whole = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(out.status.code(), Some(1), "could-not-look: {whole}");
    assert!(whole.contains("attachments"), "{whole}");
}

/// Missing merged-PR evidence refuses rather than reporting every merged row as
/// an abandoned claim. The over-reporting direction is the one that gets a drain
/// switched off, which is why this arm is required where `--claimed` is not.
#[test]
fn a_sweep_with_no_merged_pr_evidence_refuses_rather_than_over_reporting() {
    let dir = common::scratch("abandoned-needs-evidence");
    let out = common::run_with_stdin(
        &dir,
        &["landed", "abandoned", "--instant", "2026-08-20"],
        &dated_board("CLOUD-1", "2026-08-01", None, ""),
    );
    let whole = String::from_utf8_lossy(&out.stderr).to_string();
    assert_eq!(out.status.code(), Some(1), "{whole}");
    assert!(whole.contains("--merged-prs"), "{whole}");
}

/// The arm must not echo a body either. Asserted separately from the sibling's
/// case because this arm reads three more of the row's keys, so it has three
/// more places a payload could leak from.
#[test]
fn the_abandonment_finding_carries_no_body_text() {
    let out = abandoned_run(
        "abandoned-carries-no-body",
        &[],
        r#"[{"id":"CLOUD-1","status":"In Progress","updatedAt":"2026-08-01",
             "attachments":[],"gitBranchName":"",
             "description":"SECRET-CUSTOMER-DETAIL"}]"#,
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

/// ABSENCE IS A READING, AND IT LEANS THE UNSAFE WAY HERE. Paired so the notice
/// is asserted to fire on absence AND to stay quiet when the arm is supplied —
/// either half alone passes over a line that is always printed or never is.
#[test]
fn an_abandonment_sweep_without_the_claimed_arm_says_so() {
    let out = abandoned_run(
        "abandoned-claimed-absent",
        &[],
        &dated_board("CLOUD-1", "2026-08-20", None, ""),
    );
    let err = String::from_utf8_lossy(&out.stderr).to_string();
    assert!(err.contains("--claimed"), "{err}");
    assert!(err.contains("reads as abandoned"), "{err}");
}

#[test]
fn an_abandonment_sweep_with_the_claimed_arm_is_quiet_about_it() {
    let dir = common::scratch("abandoned-claimed-supplied");
    std::fs::write(dir.join("merged.tsv"), "").expect("evidence is writable");
    std::fs::write(dir.join("claimed.tsv"), "CLOUD-9\n").expect("evidence is writable");
    let out = common::run_with_stdin(
        &dir,
        &[
            "landed",
            "abandoned",
            "--merged-prs",
            "merged.tsv",
            "--claimed",
            "claimed.tsv",
            "--instant",
            "2026-08-20",
        ],
        &dated_board("CLOUD-1", "2026-08-20", None, ""),
    );
    let err = String::from_utf8_lossy(&out.stderr).to_string();
    assert!(!err.contains("--claimed"), "{err}");
}
