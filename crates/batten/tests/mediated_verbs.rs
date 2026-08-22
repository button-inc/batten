//! The write-shape corpus, over the compiled binary and the committed policy
//! (CLOUD-442).
//!
//! This is the acceptance corpus `tests/memory-guard.bats` carried, translated
//! into the surface that now decides it. That guard's table was the behavioural
//! spec for nine write shapes; CLOUD-312 could express four of them as `[[verb]]`
//! rows, CLOUD-442 adds the qualifier columns the other five needed, and the
//! guard is deleted in the same change — so this file is what keeps the
//! deletion honest. Without it, retiring the bash layer would take its corpus
//! with it and nothing would notice a shape that stopped being refused.
//!
//! **Judged against the committed `batten.toml`, not a fixture.** Every other
//! protected-path test supplies its own policy, which is right for testing the
//! engine and useless for testing the *table*: deleting a `[[verb]]` row or a
//! `protected` entry from the real file would break none of them. The census in
//! `tests/cli.rs` makes that point for the four rows that landed with CLOUD-312;
//! this one makes it for the five that land now, and for the reads each of them
//! must not refuse.
//!
//! **The allows are the load-bearing half.** A suite asserting only the denies
//! passes on a row that refuses everything, which is precisely the false positive
//! the qualifier columns exist to avoid — and a guard that refuses reads is one
//! people switch off, so a false positive here is a policy that stops being
//! enforced at all.
//!
//! A separate target rather than more of `tests/cli.rs`, on
//! `tests/advisory_drain.rs`'s precedent and for its stated reason: that file is
//! the exit-code and output-contract suite, and this is a corpus about one gate.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::path::PathBuf;

use common::{run_with_stdin, stderr};

/// A protected path this repository declares, and one it does not.
///
/// Named here rather than inlined per case so the corpus reads as shapes over a
/// guarded path — the shape is what is under test, and the path is the table's
/// answer.
const GUARDED: &str = ".serena/memories/core.md";
const AUTHORITY: &str = "batten.toml";
const ORDINARY: &str = "target/debug/scratch";

/// The repository root, whose committed `batten.toml` is the policy under test.
fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// A Claude Code `PreToolUse` envelope carrying a shell command.
fn bash_payload(command: &str) -> String {
    let escaped = serde_json::to_string(command).expect("a command is encodable");
    format!(
        "{{\"hook_event_name\":\"PreToolUse\",\"tool_name\":\"Bash\",\
         \"tool_input\":{{\"command\":{escaped}}}}}"
    )
}

/// Adjudicate one command against the committed policy, on the neutral adapter.
///
/// `exit-code` rather than `claude-code`: the code *is* the whole channel there,
/// so a verdict is read from the status without parsing a decision document.
fn verdict(command: &str) -> Option<i32> {
    run_with_stdin(
        &root(),
        &["hook", "--harness", "exit-code"],
        &bash_payload(command),
    )
    .status
    .code()
}

fn assert_denied(command: &str) {
    assert_eq!(
        verdict(command),
        Some(2),
        "the committed policy must refuse: {command}"
    );
}

fn assert_allowed(command: &str) {
    assert_eq!(
        verdict(command),
        Some(0),
        "the committed policy must allow: {command}"
    );
}

/// This command is not refused **as a write to a protected path**.
///
/// Weaker than [`assert_allowed`] on purpose, and only for commands where a
/// SECOND row legitimately fires. `sed -n 1p <memory>` is a read as far as the
/// `[[verb]]` table is concerned — the property these tests exist to pin — and
/// is also, correctly, a `no-tool-substitution` deny, because printing a range
/// of a tracked file is what `Read(offset, limit)` is for (CLOUD-864). Reading
/// the aggregate exit code would make one rule's arrival look like the other
/// rule's regression.
///
/// So the assertion is on WHICH row spoke. Every protected-path refusal carries
/// its `redirect` — the Serena tool to use instead — and those all end in
/// `_memory`; no other row's text does. A caller that stops emitting that token
/// fails this, which is the direction worth protecting.
fn assert_not_refused_as_a_write(command: &str) {
    let refusal = stderr(&run_with_stdin(
        &root(),
        &["hook", "--harness", "exit-code"],
        &bash_payload(command),
    ));
    assert!(
        !refusal.contains("_memory"),
        "the verb table must read this as a read, whatever else refuses it: \
         {command}\n{refusal}"
    );
}

#[test]
fn a_destination_only_copy_denies_the_write_and_allows_the_read() {
    // The bash table's own words: "only the destination is a write; copying a
    // memory OUT is a read." Both directions, because the row is only correct if
    // it distinguishes them — with the default every-operand reading it could not,
    // which is why `cp` stayed in bash through CLOUD-312.
    assert_denied(&format!("cp /tmp/draft.md {GUARDED}"));
    assert_denied(&format!("install -m 644 /tmp/draft.md {GUARDED}"));
    assert_allowed(&format!("cp {GUARDED} /tmp/copy.md"));
    assert_allowed(&format!("install -m 644 {GUARDED} /tmp/copy.md"));
    // The authority itself is guarded the same way, and backing it up is a read.
    assert_denied(&format!("cp /tmp/x.toml {AUTHORITY}"));
    assert_allowed(&format!("cp {AUTHORITY} /tmp/backup.toml"));
}

#[test]
fn an_in_place_stream_edit_is_a_write_and_every_other_one_is_a_read() {
    assert_denied(&format!("sed -i s/old/new/ {GUARDED}"));
    assert_denied(&format!("sed --in-place s/old/new/ {GUARDED}"));
    // The same switch carrying a backup suffix.
    assert_denied(&format!("sed -i.bak s/old/new/ {GUARDED}"));
    // The read half, which a row without `requires_flag` would have refused:
    // every filtering invocation in the repository.
    assert_allowed("sed --version");
    // A TRANSFORM, and allowed outright: `no-tool-substitution` qualifies its
    // `sed` entry with `-n` precisely so this stays allowed — no first-class
    // tool applies a substitution expression, so refusing it would state a
    // reason that does not hold.
    assert_allowed(&format!("sed s/old/new/ {GUARDED}"));
    // The PRINT form is a read here and a substitution there, and both are
    // right. See `assert_not_refused_as_a_write`.
    assert_not_refused_as_a_write(&format!("sed -n 1p {GUARDED}"));
}

#[test]
fn a_version_control_move_or_remove_is_a_write_and_a_query_is_not() {
    // The rename is the shape worth the most: it is the one that orphans every
    // `mem:` referrer in a single silent step.
    assert_denied(&format!("git mv {GUARDED} .serena/memories/renamed.md"));
    assert_denied(&format!("git rm {GUARDED}"));
    assert_denied(&format!("git rm --cached {AUTHORITY}"));
    // And the reads that share the front-end. A row keyed on the program alone
    // would have refused all of these, which is why the pair waited for the
    // subcommand column.
    for command in [
        "git log --oneline",
        "git status --short",
        "git diff",
        "git show HEAD",
    ] {
        assert_allowed(command);
    }
    // A move outside the guarded set is nobody's business here.
    assert_allowed("git mv crates/batten/src/a.rs crates/batten/src/b.rs");
}

#[test]
fn the_deny_names_the_whole_action_and_the_serena_tool_to_use_instead() {
    // The refusal contract (CLOUD-122) across the retirement: the remedy a reader
    // gets must still name the surface that owns the file, and for a subcommand
    // row it must name the action rather than only the front-end — a refusal
    // saying `git` would read as a ban on every use of version control.
    let refusal = stderr(&run_with_stdin(
        &root(),
        &["hook", "--harness", "exit-code"],
        &bash_payload(&format!("git mv {GUARDED} .serena/memories/renamed.md")),
    ));
    assert!(refusal.contains("git mv"), "names the action: {refusal}");
    assert!(refusal.contains(GUARDED), "names where: {refusal}");
    assert!(
        refusal.contains("rename_memory"),
        "names the route that rewrites referrers: {refusal}"
    );

    let edit = stderr(&run_with_stdin(
        &root(),
        &["hook", "--harness", "exit-code"],
        &bash_payload(&format!("sed -i s/a/b/ {GUARDED}")),
    ));
    assert!(
        edit.contains("edit_memory"),
        "an in-place edit names the editing tool: {edit}"
    );
}

#[test]
fn the_wrapper_form_is_resolved_rather_than_stopped_at() {
    // CLOUD-181's class, and the reason it matters here: in this sandbox the
    // wrapped spelling is often the only working one, so a gate that judges the
    // wrapper token sees none of the calls that matter. The qualifiers must
    // survive the lookthrough — the flag and the subcommand are read from the
    // WRAPPED argv, not the wrapper's.
    assert_denied(&format!("mise exec -- sed -i s/a/b/ {GUARDED}"));
    assert_denied(&format!("env FOO=1 git rm {GUARDED}"));
    assert_allowed("mise exec -- sed --version");
    assert_allowed("env FOO=1 git log");
}

#[test]
fn a_qualified_verb_is_judged_per_segment() {
    // A read in one segment must not be condemned by a write in another, and —
    // the direction that actually matters — a write must not be excused by a
    // read. Every other guard here judges per segment; the new rows are held to
    // it too.
    assert_not_refused_as_a_write(&format!("sed -n 1p {GUARDED}; cp {GUARDED} /tmp/x"));
    assert_denied(&format!("cat /tmp/x; sed -i s/a/b/ {GUARDED}"));
    assert_denied(&format!("git log; git rm {GUARDED}"));
}

#[test]
fn a_command_describing_a_shape_is_not_that_shape() {
    // The bats corpus's last case, and the one a naive substring gate fails: a
    // commit message or a heredoc body that WRITES DOWN one of these shapes is
    // documentation, not an invocation. The parser's quote handling is what makes
    // this hold, and it is worth pinning at this surface because every one of
    // these strings is something this repository's own commits legitimately say.
    assert_allowed(&format!(
        "git commit -m \"explain why cp x {GUARDED} is refused\""
    ));
    assert_allowed(&format!(
        "git commit -m \"note that sed -i over {GUARDED} denies\""
    ));
}

#[test]
fn the_unqualified_rows_still_deny_and_a_read_is_still_allowed() {
    // The regression the qualifier columns could have caused: every column
    // NARROWS, so the rows that carry none must mean exactly what they meant
    // before. Both directions of a move, which is the case the every-operand
    // default exists for.
    assert_denied(&format!("rm {GUARDED}"));
    assert_denied(&format!("mv {GUARDED} /tmp/elsewhere.md"));
    assert_denied(&format!("mv /tmp/draft.md {GUARDED}"));
    assert_denied(&format!("tee {GUARDED}"));
    assert_denied(&format!("cat x > {GUARDED}"));
    // Reads, and still reads to the VERB TABLE — which is what this case is
    // about. `no-tool-substitution` also refuses them now, correctly, since
    // `cat`/`grep` over a tracked path is what `Read` and `Grep` are for; the
    // weaker assertion is what keeps that from reading as a protected-path
    // regression.
    assert_not_refused_as_a_write(&format!("cat {GUARDED}"));
    assert_not_refused_as_a_write(&format!("grep -r mem: {GUARDED}"));
    // `rm` on an ordinary path is untouched by either row, so it stays the
    // strong assertion — the one that proves the protected set is a SET and not
    // "everything".
    assert_allowed(&format!("rm {ORDINARY}"));
}

#[test]
fn no_byte_of_the_mediated_command_reaches_either_stream() {
    // Non-negotiable rule 4 at the surface most likely to leak: the deny names
    // the rule, the action, the path and the remedy — never the command line,
    // which is the caller's own text and could carry anything.
    let canary = "CANARY-SECRET-VALUE";
    let output = run_with_stdin(
        &root(),
        &["hook", "--harness", "exit-code"],
        &bash_payload(&format!("sed -i s/a/{canary}/ {GUARDED}")),
    );
    let both = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.status.code(), Some(2), "the shape is still refused");
    assert!(
        !both.contains(canary),
        "a mediated command's own text must not be echoed: {both}"
    );
}
