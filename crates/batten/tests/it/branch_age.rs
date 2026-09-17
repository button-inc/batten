//! `branch watch loose` over the compiled binary (CLOUD-349, CLOUD-1717).
//!
//! # Why this tier exists and the module's own `test_` rules do not suffice
//!
//! `policy/branch-age.rego` carries eleven load-time cases, and every one of
//! them fabricates its input with `with input as`. That is the shape
//! `rules/policy-modules.md` warns about: a case can assert over a fact the
//! engine is unable to produce, and the module stays green while the row decides
//! nothing on any real checkout. This module spent a whole session in exactly
//! that state — registered, green, and reading a key `recorder_records` never
//! projected (CLOUD-1810) — so the case that matters here is the one no
//! `with input as` can reach: a record WRITTEN by the producer, read through the
//! engine's own projection, deciding.
//!
//! # RETIREMENT LEDGER, PER PATH — what `shell retire partial` reads
//!
//! The program's successor is `policy/branch-age.rego` for every DECISION it
//! made, and `[tasks.branch-age-record]` for the two steps that are not
//! decisions: the `gh` reads and the civil-calendar subtraction. That split is
//! forced rather than chosen — house style §5 makes `check` `read` and
//! structurally incapable of spawning, and `Fact::Instant` projects `null` to
//! every module, which `clippy.toml`'s `disallowed-methods` and
//! `crates/batten/tests/clock_ban.rs` hold the engine to. CLOUD-1559's reading
//! rule says the same thing from the other side: carry the decisions, not the
//! steps.
//!
//! Three cases below the file arms are NOT carried, and each says why in its own
//! row rather than being dropped quietly.
//!
// carried: mise-tasks/branch-age-check.sh policy/branch-age.rego kind:mechanism crates/batten/tests/it/branch_age.rs
// carried: tests/branch-age-check.bats policy/branch-age.rego kind:mechanism crates/batten/tests/it/branch_age.rs
// carried: "a remote carrying only fresh branches passes" policy/branch-age.rego kind:mechanism
// carried: "a branch past the threshold is refused, and named with its age" policy/branch-age.rego kind:mechanism
// The title is qualified because `perf-compare.bats` carried one spelled
// identically, and two arms claiming one title is what `bats count dropped`
// reported at `perf_compare.rs:56`. The `suite::case` form is the corpus's
// own, used in `connector_verbs.rs` for the same collision.
// carried: "branch-age-check.bats::the threshold is a boundary, not a suggestion" policy/branch-age.rego kind:mechanism
// carried: "a name heading more than one merged PR is refused, and counted" policy/branch-age.rego kind:mechanism
// carried: "a reused name whose branch is already gone is not counted" policy/branch-age.rego kind:mechanism
// carried: "a clean remote reaches green, which is the state the gate must be able to reach" policy/branch-age.rego kind:mechanism
// carried: "a remote reporting no branches at all is exit 2, not a pass" policy/branch-age.rego kind:mechanism
// changed: "the trunk is never counted, however old or however many PRs it heads" mise.toml the exclusion is a STEP rather than a decision, so it moved to the producer with the `gh` call that needs it: `[tasks.branch-age-record]` filters the trunk before recording, and the module never sees a trunk line to count. A case here would assert over input the producer cannot emit
// changed: "an unreadable refs reading is exit 2, not a pass" mise.toml the reading is the producer's and so is its failure: `[tasks.branch-age-record]` writes NOTHING when it cannot reach the forge, which is the could-not-look the module then reads as an absent record. The decision half is `an_absent_record_says_nothing_rather_than_passing`; what changed is that could-not-look is silence here rather than exit 2, because a module refusing there would refuse every checkout with no credential
// changed: "an unreadable PR reading is exit 2, not a pass" mise.toml the same split as the refs reading directly above, over the second of the producer's two forge calls: a failed read writes nothing, and nothing is could-not-look
// changed: "a custom threshold is honoured in both the verdict and the message" policy/branch-age.rego there is no custom threshold to honour: the figure is the practice's own "couple of days" and lives in the module, where moving it costs a diff a reviewer reads. A config knob invites raising it until nothing fires, which is `repetition-without-progress`'s reasoning one row over
// changed: "an unparseable tip date is reported rather than silently skipped" policy/branch-age.rego the producer refuses a malformed line at WRITE time, while its author is watching, so an unparseable line at read time is a torn store rather than a branch with a bad date. `a_line_this_reader_cannot_parse_is_skipped` pins the reader's half, and a surviving good line in that case is what stops it passing for want of any readable ref
// withdrawn: "a nonsense today is exit 2, not an arithmetic answer" there is no `today` for a caller to make nonsense of. The engine calls no clock on any evaluation path, so the module never subtracts dates at all — it compares a number the producer already computed against a threshold. The case asserted a property of an arithmetic step that no longer exists on this surface

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use common::{git_in, init_repo, run, run_with_stdin, scratch, write};

/// A repository registering the real module against a declared family.
///
/// The REAL module and the REAL row, never a fixture copy: the whole point of
/// this tier is that the module decides over the engine's own projection, and a
/// stand-in would be one more `with input as` wearing a different costume.
fn repo(name: &str) -> std::path::PathBuf {
    let dir = scratch(&format!("branch-age-{name}"));
    let module = std::fs::read_to_string("../../policy/branch-age.rego")
        .expect("the module this tier exists for");
    write(&dir, "policy/branch-age.rego", &module);
    write(
        &dir,
        "batten.toml",
        r#"version = 1
scope = ["**"]

[[pattern]]
id = "whole-number"
regex = '^[0-9]+$'

[[verdict]]
id = "branch watch stale"
gloss = "a remote branch has outlived the story it was cut for"
class = "A branch is either finished, in which case delete it, or it is not short-lived."

[[verdict.route]]
id = "task run first"
kind = "command"
target = "mise run branch-age-record"

[[verdict]]
id = "branch name duplicate"
gloss = "one branch name heads more than one merged pull request and is still on the remote"
class = "A short-lived branch sleepwalking into a long-lived one."

[[verdict.route]]
id = "task run first"
kind = "command"
target = "mise run branch-age-record"

[[verdict]]
id = "branch list empty"
gloss = "the producer looked and the remote reported no branches at all"
class = "A remote with a trunk cannot report no branches; the listing failed while exiting zero."

[[verdict.route]]
id = "task run first"
kind = "command"
target = "mise run branch-age-record"

[[rule]]
id = "branch watch loose"
kind = "policy"
scope = "tree"
module = "policy/branch-age.rego"
severity = "deny"

[[record]]
record = "branch-age"
writer = "mise run branch-age-record"
"#,
    );
    init_repo(&dir);
    git_in(&dir, &["add", "-A"]);
    git_in(&dir, &["commit", "-qm", "register the module"]);
    dir
}

/// Write the producer's record, as `mise run branch-age-record` would.
fn record(dir: &std::path::Path, lines: &str) {
    let written = run_with_stdin(dir, &["record", "named", "branch-age"], lines);
    assert!(
        written.status.success(),
        "the setup write lands: {}",
        String::from_utf8_lossy(&written.stderr)
    );
}

#[test]
fn a_recorded_branch_past_the_threshold_is_reported_through_the_engines_own_projection() {
    // THE CASE NO `with input as` CAN REACH, and the one that was false for a
    // whole session: the module was registered, its own suite green, and
    // `recorder_records` projected no `record named` family at all — so this
    // exact tree exited 0 over a 36-day branch (CLOUD-1810).
    let dir = repo("stale");
    record(&dir, "ref\tclaude/ancient\t36\nref\tclaude/fresh\t1\n");

    let decided = run(&dir, &["check"]);
    assert_eq!(
        decided.status.code(),
        Some(2),
        "a branch past the threshold decides\n{}",
        String::from_utf8_lossy(&decided.stderr)
    );
    // BOTH STREAMS, because which one a finding lands on is the output contract's
    // business and not this case's: what is asserted is that the pointer reaches
    // the reader at all.
    let said = format!(
        "{}{}",
        String::from_utf8_lossy(&decided.stdout),
        String::from_utf8_lossy(&decided.stderr)
    );
    assert!(
        said.contains("claude/ancient"),
        "the finding names the branch to delete\n{said}"
    );
    assert!(
        !said.contains("claude/fresh"),
        "and says nothing about one inside the threshold\n{said}"
    );
}

#[test]
fn an_absent_record_says_nothing_rather_than_passing() {
    // COULD NOT LOOK IS NOT A PASS, and on this surface it is also not a
    // refusal. The producer writes nothing when it cannot reach the forge, so a
    // module that refused here would refuse every checkout with no credential —
    // and one that PASSED would be the silent green the whole port exists to
    // remove. The discrimination is only visible with the record absent.
    let dir = repo("absent");

    let quiet = run(&dir, &["check"]);
    assert_eq!(
        quiet.status.code(),
        Some(0),
        "an absent record is could-not-look\n{}",
        String::from_utf8_lossy(&quiet.stderr)
    );
}

#[test]
fn a_present_record_naming_no_branch_is_refused_rather_than_read_as_clean() {
    // PRESENT-AND-EMPTY IS THE THIRD STATE, and collapsing it into the second is
    // where the whole gate evaporates: a remote reporting no branches "cannot be
    // true of a repository with a trunk", so the honest reading is that the
    // listing failed while exiting zero.
    let dir = repo("empty");
    record(&dir, "merged\tclaude/gone\n");

    let refused = run(&dir, &["check"]);
    assert_eq!(
        refused.status.code(),
        Some(2),
        "a record that looked and found no branch at all is refused\n{}",
        String::from_utf8_lossy(&refused.stderr)
    );
}

#[test]
fn a_reused_name_still_on_the_remote_is_reported_and_one_already_deleted_is_not() {
    // THE SURVIVOR CONJUNCT, as an exit code rather than as an argument. Merged
    // pull requests are immutable, so a name that headed two of them heads two
    // forever; without intersecting against what the remote still carries this
    // would be an alarm no action could clear, which is the shape that gets a
    // gate switched off.
    let live = repo("reused-live");
    record(
        &live,
        "ref\tclaude/reused\t1\nmerged\tclaude/reused\nmerged\tclaude/reused\n",
    );
    let reported = run(&live, &["check"]);
    assert_eq!(
        reported.status.code(),
        Some(2),
        "a reused name still on the remote is reported\n{}",
        String::from_utf8_lossy(&reported.stderr)
    );

    let gone = repo("reused-gone");
    record(
        &gone,
        "ref\tclaude/other\t1\nmerged\tclaude/deleted\nmerged\tclaude/deleted\n",
    );
    let quiet = run(&gone, &["check"]);
    assert_eq!(
        quiet.status.code(),
        Some(0),
        "and the same history with the branch deleted is clean — the remedy worked\n{}",
        String::from_utf8_lossy(&quiet.stderr)
    );
}
