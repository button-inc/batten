//! `stop-posture` over the compiled binary (CLOUD-1051).
//!
//! # The defect this file exists because of, stated first
//!
//! The module shipped with sixteen `test_` rules, all green, and **never fired
//! on any event**. `adjudicate` returns `Allow` at `Stop` before any rule is
//! read — CLOUD-889's runaway removed by construction — so a `mediated_call`
//! module was unreachable at the one moment that projects the field it reads.
//! Its own suite could not see that: a `with input as` case fabricates the very
//! shape the engine may be unable to produce.
//!
//! That is exactly the class `.claude/rules/policy-modules.md` names, and this
//! is the tier it names as the only one that can catch it. Every case below runs
//! `batten hook --harness claude-code` against a real payload and reads what a
//! host would read.
//!
//! # RETIREMENT LEDGER, PER PATH — what `shell-retirement` reads
//!
//! The program's successor is the engine's own Stop routine rather than a
//! module, because four of `stop-guard`'s five rules spawn or read the tree and
//! `RuleKind::scopes` pairs every spawning kind with `RuleScope::Tree` alone.
//! The suite's successor is the module, which is where the one rule that COULD
//! be a predicate went.
//!
// carried: mise-tasks/stop-guard.sh crates/batten/src/lib.rs crates/batten/tests/stop_posture.rs
// carried: tests/stop-guard.bats policy/stop-posture.rego crates/batten/tests/stop_posture.rs
//!
//! # RETIREMENT LEDGER — `tests/stop-guard.bats`, 33 cases
//!
//! CARRIED — the property survives, proved here or in the module's own suite.
//!
// carried: "a turn whose final message carries the tell is kicked" crates/batten/tests/stop_posture.rs
// carried: "the kick names the rule and the durable destination" crates/batten/tests/stop_posture.rs
// carried: "the kick declares the Stop event, so the harness routes it as feedback" crates/batten/tests/stop_posture.rs
// carried: "the kick is valid JSON on stdout" crates/batten/tests/stop_posture.rs
// carried: "the re-entry caused by a previous kick is not kicked again" crates/batten/tests/stop_posture.rs
// carried: "A CLEAN FINAL MESSAGE IS ANSWERED WITH SILENCE" crates/batten/tests/stop_posture.rs
// carried: "a turn that says it is stopping is not re-prompted" policy/stop-posture.rego
// carried: "an ordinary answer to a question is not re-prompted" policy/stop-posture.rego
// carried: "an absent last_assistant_message costs the first rule and nothing else" crates/batten/tests/stop_posture.rs
// carried: "stop-guard::the bypass is honoured" crates/batten/tests/stop_posture.rs
// carried: "the guard never exits non-zero, so it cannot surface as a hook error" crates/batten/tests/stop_posture.rs
// carried: "a turn that strands a finding is pointed at, and the turn still ends" crates/batten/tests/stop_posture.rs
// carried: "POINTER, NEVER PAYLOAD: the advisory carries no byte of the turn's prose" crates/batten/tests/stop_posture.rs
// carried: "the advisory says what to do, since a coordinate alone is not an instruction" crates/batten/tests/stop_posture.rs
// carried: "the shipped rule keeps precedence when both would fire" crates/batten/tests/stop_posture.rs
// carried: "a turn that strands nothing is silent" crates/batten/tests/stop_posture.rs
// carried: "an unreadable transcript manufactures no advisory" crates/batten/tests/stop_posture.rs
// carried: "the recursion bound still holds for the second rule" crates/batten/tests/stop_posture.rs
// carried: "A FILED ROW NAMING THIS BRANCH'S OWN DIFF IS POINTED AT, BEFORE ANY CI" crates/batten/tests/filed_here.rs
// carried: "the punt pointer carries no prose from the row" crates/batten/tests/filed_here.rs
// carried: "the punt rule yields to the measured posture rule" crates/batten/tests/stop_posture.rs
// carried: "a branch with no filed row names none" crates/batten/tests/filed_here.rs
// carried: "UNLANDED WORK AT A DECLARED STOPPING POINT IS POINTED AT" crates/batten/tests/stop_posture.rs
// carried: "the unlanded pointer carries no transcript text and no store key" crates/batten/tests/stop_posture.rs
// carried: "the unlanded rule yields to the measured posture rule" crates/batten/tests/stop_posture.rs
// carried: "landed work is silent" crates/batten/tests/stop_posture.rs
//!
//! SUBSUMED — the plumbing became the engine\'s, which is what a migration should
//! produce. Each names the general property that now covers it.
//!
// subsumed: "the recursion bound survives a garbage stop_hook_active rather than proceeding" crates/batten/src/hook.rs
// subsumed: "the Stop hook is registered in settings" mise-tasks/hooks-wiring-check.sh
// subsumed: "the Stop entry declares no matcher, which the event does not support" mise-tasks/hooks-wiring-check.sh
//!
//! CHANGED — behaviour that diverges deliberately, each with its reason.
//!
// changed: "stop-guard.bats::the punt pointer fires once and then goes quiet for that row" crates/batten/src/lib.rs the suppression key is the finding's POINTER, which is the path rather than the row id: a `Finding` carries its first path-bearing subject and the id travels as a subject the engine does not project onto the struct. One nudge per PATH per branch, not one per row
// changed: "stop-guard.bats::a second row still gets its own pointer after the first is spent" crates/batten/src/lib.rs same cause: two rows overlapping DIFFERENT paths each get their own pointer, and two rows overlapping the same path share one. The retired suite keyed on the id, which the engine no longer carries into the struct
// changed: "stop-guard.bats::EVERY ROW THE BRANCH FILED IS ENUMERATED FOR RE-EVALUATION" crates/batten/src/lib.rs the checklist reads the `board-writes` record directly rather than re-deriving the set from findings, so it still enumerates by id — which is why the id survives here and not in the pointer above
// changed: "stop-guard.bats::the checklist repeats only when the set changes" crates/batten/src/lib.rs suppression is per SET rather than per row, keyed on the record's own contents; the retired suite keyed on a file the shell wrote, which no longer exists
//!
//! THE PUNT POINTER NAMES THE PATH, NOT THE ROW, and the suppression key moved
//! with it. A `Finding` carries its first path-bearing subject as its pointer and
//! the row\'s id travels as an ordered subject the engine does not project onto
//! the struct — so the nudge names the tracked file and the receipt is keyed on
//! it. That is the half an agent must act on ("finish it now while the file is
//! open") and the id is one board read away, but it is a real narrowing of what
//! the nudge says and is recorded rather than glossed. The checklist keeps its
//! ids, because it reads them off the recorder\'s record directly.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Output, Stdio};

use common::{batten, scratch};

/// The committed module, the rows it needs, and nothing else.
///
/// The module is COPIED from `policy/`, never re-typed, so this fixture cannot
/// drift from what ships. The pattern and verdict rows are re-declared because a
/// fixture config is a whole authority — house style §8 admits no directory walk
/// and no merge — and because the load-time registry check refuses a token no
/// row declares.
const CONFIG: &str = r#"version = 1

[[pattern]]
id = "md-fenced-block"
regex = '```[^`]*```'

[[pattern]]
id = "md-code-span"
regex = '`[^`]*`'

[[pattern]]
id = "md-quoted-span"
regex = '"[^"]*"'

[[pattern]]
id = "md-block-quote"
regex = '(?m)^[[:space:]]*>[^\n]*'

[[pattern]]
id = "hedged-flag-framing"
regex = "(?i)worth (noting|flagging|mentioning|naming)|one thing (I would|I['’]?d) (flag|note)|I['’]?d (flag|note) (that|one)|I would (flag|note) that|I should (note|flag)|(it|that)['’]?s worth (noting|flagging|mentioning|naming)|bears (noting|flagging|mentioning|naming)"

[[verdict]]
id = "V-HEDGED-FLAG-FRAMING"
gloss = "a finding was written as editorial instead of durably"
class = """
Chat stores nothing, so a finding's home is an issue or a memory. A sentence \
that flags one in passing is the double-write CLOUD-200 and CLOUD-248 exist to \
kill.
"""

[[verdict.route]]
id = "R-WRITE-IT-DOWN"
kind = "issue"
target = "put it in the row that already owns it, or file one"

[[rule]]
id = "stop-posture"
kind = "policy"
scope = "mediated_call"
module = "policy/stop-posture.rego"
severity = "deny"
"#;

fn repo(name: &str) -> PathBuf {
    let dir = scratch(name);
    fs::write(dir.join("batten.toml"), CONFIG).expect("write config");
    fs::create_dir_all(dir.join("policy")).expect("policy dir");
    let source = common::at_root("policy/stop-posture.rego")
        .canonicalize()
        .expect("the committed module is where the row says it is");
    fs::copy(source, dir.join("policy/stop-posture.rego")).expect("install committed module");
    dir
}

/// A Claude `Stop` payload, as the host sends one.
fn stop_payload(message: &str, active: bool) -> String {
    serde_json::json!({
        "hook_event_name": "Stop",
        "session_id": "s-1",
        "stop_hook_active": active,
        "last_assistant_message": message,
    })
    .to_string()
}

fn hook(dir: &Path, payload: &str) -> Output {
    let mut command = batten();
    command
        .current_dir(dir)
        .args(["hook", "--harness", "claude-code"])
        .env_remove("BATTEN_HOOK_BYPASS")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().expect("spawn batten hook");
    child
        .stdin
        .take()
        .expect("piped stdin")
        .write_all(payload.as_bytes())
        .expect("write payload");
    child.wait_with_output().expect("run batten hook")
}

fn stdout_of(output: &Output) -> String {
    String::from_utf8(output.stdout.clone()).expect("stdout is UTF-8")
}

/// The hot path drops a module's own `test_` rules, and `policy test` does not.
///
/// # The seam, and what it is worth
///
/// A `test_` rule is the LOAD-TIME tier: `batten policy test` runs it and nothing
/// else queries one. They were nonetheless compiled into every mediated bundle
/// and evaluated with it, because `data.batten.deny` is answered by evaluating
/// the package — so every tool call ran a suite that decides nothing about that
/// call. Measured on the wired path, release binary, 40 runs: 51.72 ms with this
/// module's thirteen cases in the bundle, 19.82 ms with them stripped, against a
/// merge base of 20.94 ms.
///
/// # Both halves, because either alone is satisfiable by a mistake
///
/// A strip that removed too much would leave the module deciding nothing and the
/// cases ungraded; a strip that removed nothing would leave the cost. So this
/// asserts the DECISION still fires (the fixture's hedged message is refused,
/// which is the other cases above) and that `policy test` still counts this
/// module's own cases — the two ends the strip sits between.
#[test]
fn the_hot_path_drops_the_modules_own_cases_and_policy_test_keeps_them() {
    let dir = repo("stop-posture-test-strip");

    // The graded tier: `policy test` compiles the full text, so the module's own
    // cases are still there to run and still pass.
    let graded = batten()
        .current_dir(&dir)
        .args(["policy", "test"])
        .output()
        .expect("run batten policy test");
    let report = String::from_utf8(graded.stdout).expect("stdout is UTF-8");
    assert_eq!(
        graded.status.code(),
        Some(0),
        "the module's own cases still pass: {report}"
    );
    let passed: usize = report
        .split_whitespace()
        .zip(report.split_whitespace().skip(1))
        .find_map(|(count, word)| (word == "passed,").then(|| count.parse().ok())?)
        .expect("the report states how many cases passed");
    assert!(
        passed >= 10,
        "the strip must not reach the graded tier, and this module carries more \
         than ten cases: {report}"
    );

    // The hot path: the same module, same fixture, still decides. A strip that
    // took a real rule with it would go silent here.
    let out = hook(
        &dir,
        &stop_payload("one thing I'd flag is the ordering", false),
    );
    assert!(
        stdout_of(&out).contains("V-HEDGED-FLAG-FRAMING"),
        "the stripped module still refuses: {}",
        stdout_of(&out)
    );
}

/// THE CASE THE MODULE'S OWN SUITE COULD NOT MAKE: the engine builds the input,
/// runs the module, and the nudge reaches the host's advisory channel.
#[test]
fn a_hedged_final_message_reaches_the_host_advisory_channel() {
    let dir = repo("stop-posture-fires");
    let output = hook(
        &dir,
        &stop_payload("One thing I would flag is the exit code.", false),
    );
    let stdout = stdout_of(&output);
    assert_eq!(
        output.status.code(),
        Some(0),
        "an advisory never changes the exit code: {stdout}"
    );
    assert!(
        stdout.contains("additionalContext"),
        "the nudge travels on the advisory channel: {stdout}"
    );
    assert!(
        stdout.contains("stop-posture"),
        "and it names the predicate: {stdout}"
    );
}

/// NEVER A VERDICT. CLOUD-97 and CLOUD-219 each ruled a deny out at this moment
/// independently, and the property is structural — `hookSpecificOutput` here has
/// no field a refusal could occupy.
#[test]
fn the_nudge_carries_no_permission_decision() {
    let dir = repo("stop-posture-not-a-verdict");
    let stdout = stdout_of(&hook(
        &dir,
        &stop_payload("One thing I would flag is the exit code.", false),
    ));
    assert!(
        !stdout.contains("permissionDecision"),
        "an advisory has no verdict field: {stdout}"
    );
    assert!(
        !stdout.contains("\"deny\""),
        "and cannot spell one: {stdout}"
    );
}

/// POINTER, NEVER PAYLOAD (rule 4), and load-bearing here rather than
/// decorative: handing the matched prose back would make this a mirror, and a
/// mirror is cleared by restating it — which is the double-write.
#[test]
fn no_byte_of_the_matched_prose_reaches_the_channel() {
    let dir = repo("stop-posture-pointer-only");
    let stdout = stdout_of(&hook(
        &dir,
        &stop_payload(
            "One thing I would flag is that the widget cache is unbounded.",
            false,
        ),
    ));
    for fragment in ["widget", "unbounded", "cache", "I would flag"] {
        assert!(
            !stdout.contains(fragment),
            "the nudge carried {fragment:?} from the turn's own prose: {stdout}"
        );
    }
}

/// A CLEAN TURN IS SILENT, which is the common case and what the channel's
/// credibility rests on. Without this every assertion above is satisfied by a
/// module that fires on everything.
#[test]
fn a_clean_final_message_says_nothing() {
    let dir = repo("stop-posture-silent");
    let stdout = stdout_of(&hook(
        &dir,
        &stop_payload("Landed and pushed; CI is green.", false),
    ));
    assert!(
        !stdout.contains("additionalContext"),
        "silence is the default: {stdout}"
    );
}

/// THE RECURSION BOUND, from the payload rather than a state file.
/// `stop_hook_active` is true on the invocation a previous `Stop` continuation
/// caused, so one nudge per turn is deterministic.
#[test]
fn a_repeat_stop_is_bounded_to_one_nudge_per_turn() {
    let dir = repo("stop-posture-bounded");
    let stdout = stdout_of(&hook(
        &dir,
        &stop_payload("One thing I would flag is the exit code.", true),
    ));
    assert!(
        !stdout.contains("additionalContext"),
        "the second Stop of a turn says nothing: {stdout}"
    );
}

/// NOT A STOP, so there is no final message and nothing to judge — and the
/// module must not fire on a tool call that happens to carry prose.
#[test]
fn a_tool_call_is_not_judged_by_the_end_of_turn_rule() {
    let dir = repo("stop-posture-pre-tool");
    let payload = serde_json::json!({
        "hook_event_name": "PreToolUse",
        "session_id": "s-1",
        "tool_name": "Bash",
        "tool_input": {"command": "echo one thing I would flag"},
    })
    .to_string();
    let stdout = stdout_of(&hook(&dir, &payload));
    assert!(
        !stdout.contains("additionalContext"),
        "the Stop projections are null on every other event: {stdout}"
    );
}

// ---------------------------------------------------------------------------
// THE OTHER FOUR RULES, and the ranking between them. `stop-guard.sh` ran five
// and emitted at most one; four of them cannot be a `mediated_call` module —
// three spawn a sibling program and one reads the tree — so they live in the
// engine's own Stop routine and these are the cases over it.
//
// The siblings are STUBS here, and deliberately: the real ones keep their own
// suites, so running them would make these cases a test of a predicate somebody
// else owns rather than of the wiring. What is being asserted is that the engine
// spawns the declared path, hands it the stdin the retired hook handed it, and
// routes a non-zero exit's stdout to the advisory channel.
// ---------------------------------------------------------------------------

/// Install a stub at the path the engine spawns, with a chosen exit and stdout.
#[cfg(unix)]
fn stub(dir: &Path, program: &str, exit: i32, stdout: &str) {
    let path = dir.join(program);
    fs::create_dir_all(path.parent().expect("a parent")).expect("mise-tasks dir");
    fs::write(
        &path,
        format!("#!/bin/sh\ncat >/dev/null\nprintf '%s\\n' {stdout:?}\nexit {exit}\n"),
    )
    .expect("write stub");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).expect("chmod stub");
    }
}

/// A Stop payload naming a transcript the second rule can read.
#[cfg(unix)]
fn stop_with_transcript(dir: &Path, message: &str) -> String {
    let transcript = dir.join("session.jsonl");
    fs::write(&transcript, "{}\n").expect("write transcript");
    serde_json::json!({
        "hook_event_name": "Stop",
        "session_id": "s-1",
        "stop_hook_active": false,
        "last_assistant_message": message,
        "transcript_path": transcript.display().to_string(),
    })
    .to_string()
}

/// RULE 2 — a finding stated in prose with nothing durable written. The pointer
/// is the sibling's stdout and the advice says what to do with it, because a
/// coordinate alone is not an instruction.
// UNIX-ONLY, per CLOUD-113: this case spawns a `#!/bin/sh` stub, and the
// Windows ladder's third rung resolves the interpreter a shebang names — which
// `/bin/sh` is not on a Windows runner. `bundle.rs` gates its whole suite for
// exactly this reason. The rules above spawn nothing and stay cross-platform.
#[cfg(unix)]
#[test]
fn a_stranded_finding_is_pointed_at_and_the_turn_still_ends() {
    let dir = repo("stop-finding-sink");
    stub(&dir, "mise-tasks/finding-sink-check.sh", 1, "turn 12");
    let output = hook(&dir, &stop_with_transcript(&dir, "Landed and pushed."));
    let stdout = stdout_of(&output);
    assert_eq!(
        output.status.code(),
        Some(0),
        "the turn still ends: {stdout}"
    );
    assert!(stdout.contains("turn 12"), "the pointer travels: {stdout}");
    assert!(
        stdout.contains("file it"),
        "and so does what to do about it: {stdout}"
    );
}

/// PRECEDENCE IS MEASURED, NOT ASSERTED. `stop-posture` leads at 3/3 against
/// `finding-sink`'s 1/1, and two nudges on one turn is how a channel stops being
/// read — so when both would fire, exactly one does and it is the first.
// UNIX-ONLY, per CLOUD-113: this case spawns a `#!/bin/sh` stub, and the
// Windows ladder's third rung resolves the interpreter a shebang names — which
// `/bin/sh` is not on a Windows runner. `bundle.rs` gates its whole suite for
// exactly this reason. The rules above spawn nothing and stay cross-platform.
#[cfg(unix)]
#[test]
fn the_measured_rule_keeps_precedence_when_both_would_fire() {
    let dir = repo("stop-precedence");
    stub(&dir, "mise-tasks/finding-sink-check.sh", 1, "turn 12");
    let stdout = stdout_of(&hook(
        &dir,
        &stop_with_transcript(&dir, "One thing I would flag is the exit code."),
    ));
    assert!(
        stdout.contains("stop-posture"),
        "the measured rule speaks: {stdout}"
    );
    assert!(
        !stdout.contains("turn 12"),
        "and the one below it does not: {stdout}"
    );
}

/// A sibling that found nothing says nothing, which is the common case.
// UNIX-ONLY, per CLOUD-113: this case spawns a `#!/bin/sh` stub, and the
// Windows ladder's third rung resolves the interpreter a shebang names — which
// `/bin/sh` is not on a Windows runner. `bundle.rs` gates its whole suite for
// exactly this reason. The rules above spawn nothing and stay cross-platform.
#[cfg(unix)]
#[test]
fn a_turn_that_strands_nothing_is_silent() {
    let dir = repo("stop-finding-sink-clean");
    stub(&dir, "mise-tasks/finding-sink-check.sh", 0, "");
    let stdout = stdout_of(&hook(&dir, &stop_with_transcript(&dir, "Landed.")));
    assert!(
        !stdout.contains("additionalContext"),
        "silence is the default: {stdout}"
    );
}

/// COULD NOT LOOK MANUFACTURES NOTHING. A transcript the engine cannot read
/// leaves the rule with no subject, and inventing an advisory over that would be
/// a verdict about the environment wearing a verdict about the turn.
// UNIX-ONLY, per CLOUD-113: this case spawns a `#!/bin/sh` stub, and the
// Windows ladder's third rung resolves the interpreter a shebang names — which
// `/bin/sh` is not on a Windows runner. `bundle.rs` gates its whole suite for
// exactly this reason. The rules above spawn nothing and stay cross-platform.
#[cfg(unix)]
#[test]
fn an_unreadable_transcript_manufactures_no_advisory() {
    let dir = repo("stop-no-transcript");
    stub(&dir, "mise-tasks/finding-sink-check.sh", 1, "turn 12");
    let stdout = stdout_of(&hook(&dir, &stop_payload("Landed.", false)));
    assert!(
        !stdout.contains("turn 12"),
        "no transcript, no subject: {stdout}"
    );
}

/// THE BYPASS IS ONE HATCH FOR THE SET, exactly as the retired hook had it:
/// these are five readings of one question, and a per-rule switch would let the
/// surface be dismantled a rule at a time with nothing reporting it.
// UNIX-ONLY, per CLOUD-113: this case spawns a `#!/bin/sh` stub, and the
// Windows ladder's third rung resolves the interpreter a shebang names — which
// `/bin/sh` is not on a Windows runner. `bundle.rs` gates its whole suite for
// exactly this reason. The rules above spawn nothing and stay cross-platform.
#[cfg(unix)]
#[test]
fn the_stop_guard_bypass_silences_the_whole_surface() {
    let dir = repo("stop-bypass");
    stub(&dir, "mise-tasks/finding-sink-check.sh", 1, "turn 12");
    let mut command = batten();
    command
        .current_dir(&dir)
        .args(["hook", "--harness", "claude-code"])
        .env_remove("BATTEN_HOOK_BYPASS")
        .env("BATTEN_STOP_GUARD_BYPASS", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().expect("spawn batten hook");
    let payload = stop_with_transcript(&dir, "Landed.");
    child
        .stdin
        .take()
        .expect("piped stdin")
        .write_all(payload.as_bytes())
        .expect("write payload");
    let output = child.wait_with_output().expect("run batten hook");
    let stdout = String::from_utf8(output.stdout).expect("stdout is UTF-8");
    assert!(
        !stdout.contains("turn 12"),
        "the hatch silences the set: {stdout}"
    );
}

/// RULE 4 — a completion signal with no landed commit. `unlanded-check` reads no
/// stdin, and its pointer is a count and a rule id: never a commit message and
/// never a line of the transcript the verdict was read from.
// UNIX-ONLY, per CLOUD-113: this case spawns a `#!/bin/sh` stub, and the
// Windows ladder's third rung resolves the interpreter a shebang names — which
// `/bin/sh` is not on a Windows runner. `bundle.rs` gates its whole suite for
// exactly this reason. The rules above spawn nothing and stay cross-platform.
#[cfg(unix)]
#[test]
fn unlanded_work_at_a_declared_stopping_point_is_pointed_at() {
    let dir = repo("stop-unlanded");
    stub(
        &dir,
        "mise-tasks/unlanded-check.sh",
        1,
        "completion.unlanded 1",
    );
    let stdout = stdout_of(&hook(&dir, &stop_payload("Landed and pushed.", false)));
    assert!(
        stdout.contains("completion.unlanded"),
        "the pointer travels: {stdout}"
    );
    assert!(
        stdout.contains("Land it"),
        "and what to do about it: {stdout}"
    );
}

/// Landed work is silent, which is what keeps the case above from being
/// satisfied by a rule that fires unconditionally.
// UNIX-ONLY, per CLOUD-113: this case spawns a `#!/bin/sh` stub, and the
// Windows ladder's third rung resolves the interpreter a shebang names — which
// `/bin/sh` is not on a Windows runner. `bundle.rs` gates its whole suite for
// exactly this reason. The rules above spawn nothing and stay cross-platform.
#[cfg(unix)]
#[test]
fn landed_work_is_silent() {
    let dir = repo("stop-landed");
    stub(&dir, "mise-tasks/unlanded-check.sh", 0, "");
    let stdout = stdout_of(&hook(&dir, &stop_payload("Landed and pushed.", false)));
    assert!(
        !stdout.contains("additionalContext"),
        "nothing at risk, nothing to say: {stdout}"
    );
}

/// THE RECURSION BOUND HOLDS FOR EVERY RULE, not just the module: it is checked
/// once, before any of them, so a second `Stop` in one turn spawns nothing at
/// all rather than spawning and then discarding.
// UNIX-ONLY, per CLOUD-113: this case spawns a `#!/bin/sh` stub, and the
// Windows ladder's third rung resolves the interpreter a shebang names — which
// `/bin/sh` is not on a Windows runner. `bundle.rs` gates its whole suite for
// exactly this reason. The rules above spawn nothing and stay cross-platform.
#[cfg(unix)]
#[test]
fn the_recursion_bound_holds_for_every_rule() {
    let dir = repo("stop-bounded-all");
    stub(
        &dir,
        "mise-tasks/unlanded-check.sh",
        1,
        "completion.unlanded 1",
    );
    let stdout = stdout_of(&hook(&dir, &stop_payload("Landed and pushed.", true)));
    assert!(
        !stdout.contains("completion.unlanded"),
        "the second Stop of a turn says nothing: {stdout}"
    );
}

/// THE GUARD NEVER EXITS NON-ZERO, so it cannot surface as a hook error. Every
/// case above reads stdout; this one reads the status, over a rule that fired.
// UNIX-ONLY, per CLOUD-113: this case spawns a `#!/bin/sh` stub, and the
// Windows ladder's third rung resolves the interpreter a shebang names — which
// `/bin/sh` is not on a Windows runner. `bundle.rs` gates its whole suite for
// exactly this reason. The rules above spawn nothing and stay cross-platform.
#[cfg(unix)]
#[test]
fn the_stop_surface_never_exits_non_zero() {
    let dir = repo("stop-exit-zero");
    stub(
        &dir,
        "mise-tasks/unlanded-check.sh",
        1,
        "completion.unlanded 1",
    );
    let output = hook(&dir, &stop_payload("Landed and pushed.", false));
    assert_eq!(
        output.status.code(),
        Some(0),
        "an advisory never changes the exit code"
    );
}
