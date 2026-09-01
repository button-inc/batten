//! What this repository's hooks cost a session, over the compiled binary
//! (CLOUD-417).
//!
//! **The second tier, and it is not optional here for a specific reason.** The
//! module's own unit cases pin the predicate over a `Stream` a test constructed;
//! this tier proves the ENGINE builds that stream from a transcript a HOST wrote
//! — that `attachment.type` is read as a prefix, that `hookName` is the grouping
//! key, that the emitted text is hashed and dropped, and that a repeat survives
//! the whole path from JSONL bytes to a verdict. A case over a fabricated
//! `Stream` passes over a field the parse may be unable to fill, which is the
//! silent dead gate `.claude/rules/policy-modules.md` opens by warning about.
//!
//! **Fixture transcripts, in the host's real shape**, because a session's cost
//! is a property of the world rather than of the commit: a case reading this
//! container's own transcript would answer differently on every run, and in CI
//! there is no transcript at all.
//!
//! The discriminating half is the whole point. Three shapes the row names must
//! come out differently — a hook repeating itself is refused, a hook reporting
//! one change-set once is clean, and a hook silent on success is clean — and
//! without the two clean cases a rule that refused every emission would satisfy
//! the first and gate nothing.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::{Path, PathBuf};

use common::{run, scratch, stdout, write};

/// One `hook_success` attachment as the host writes it.
///
/// `stdout` carries the text, which is what the engine hashes and drops. The
/// helper takes it as a parameter so a case can say "the same thing twice"
/// literally, rather than asserting over a digest it computed itself.
fn emission(hook: &str, text: &str) -> String {
    let encoded = serde_json::to_string(text).expect("text is encodable");
    format!(
        "{{\"type\":\"attachment\",\"sessionId\":\"s-1\",\"attachment\":\
         {{\"type\":\"hook_success\",\"hookEvent\":\"PostToolUse\",\"hookName\":\"{hook}\",\
         \"stdout\":{encoded}}}}}"
    )
}

/// A repo whose `[transcript]` points at the given lines, with `ceiling` as its
/// `[hook_output]` table when one is given.
fn repo(name: &str, lines: &[String], ceiling: Option<&str>) -> PathBuf {
    let dir = scratch(name);
    let table = ceiling.unwrap_or("");
    write(
        &dir,
        "batten.toml",
        &format!(
            "version = 1\n\n[transcript]\npath = \".session.jsonl\"\n\n{table}\n\n\
             [[rule]]\nid = \"probe\"\nkind = \"forbid\"\nglob = \"never/**\"\n\
             pattern = \"never\"\nseverity = \"deny\"\nscope = \"tree\"\n"
        ),
    );
    write(&dir, ".session.jsonl", &format!("{}\n", lines.join("\n")));
    dir
}

/// `batten policy hooks` in `dir`: the one line, and the exit code.
fn measure(dir: &Path) -> (String, Option<i32>) {
    let output = run(dir, &["policy", "hooks"]);
    (stdout(&output), output.status.code())
}

/// A ceiling that refuses only a repeat, so a case can vary one predicate.
const REPEAT_ONCE: &str = "[hook_output]\nmax_tokens = 100000\nmax_repeats = 1\n";

#[test]
fn a_hook_that_says_the_same_thing_n_times_is_a_violation() {
    // THE ROW'S HEADLINE CASE, end to end: three byte-identical `hook_success`
    // records reach the engine as three `HookOutput` events under one producer
    // and one digest, and the verdict names the producer and the FIRST line.
    let dir = repo(
        "hook-cost-repeat",
        &[
            emission("SessionStart:mcp", "every enabled MCP server attached"),
            emission("SessionStart:mcp", "every enabled MCP server attached"),
            emission("SessionStart:mcp", "every enabled MCP server attached"),
        ],
        Some(REPEAT_ONCE),
    );
    let (text, code) = measure(&dir);
    assert_eq!(code, Some(2), "a repeat is a violation: {text}");
    assert!(
        text.contains("hook-repeat-pointer"),
        "the class names the defect: {text}"
    );
    assert!(
        text.contains("SessionStart:mcp"),
        "and names the producer, which is the pointer a reader follows: {text}"
    );
    assert!(
        !text.contains("every enabled MCP server attached"),
        "POINTER-ONLY (rule 4): a measurement of an over-wide channel must not \
         carry what the channel said: {text}"
    );
}

#[test]
fn a_hook_reporting_one_change_set_once_is_clean() {
    // The discriminator. Two emissions from one producer that say DIFFERENT
    // things are two findings, not one repeated — and a rule that refused every
    // emission would satisfy the case above and this one would catch it.
    let dir = repo(
        "hook-cost-distinct",
        &[
            emission("PostToolBatch:drift", "1 changed: hk.pkl"),
            emission("PostToolBatch:drift", "1 changed: mise.toml"),
        ],
        Some(REPEAT_ONCE),
    );
    let (text, code) = measure(&dir);
    assert_eq!(
        code,
        Some(0),
        "two different reports are not a repeat: {text}"
    );
    assert!(
        text.contains("2 producer(s)") || text.contains("1 producer(s)"),
        "{text}"
    );
    assert!(text.contains("0 repeat(s)"), "{text}");
}

#[test]
fn a_hook_silent_on_success_is_clean_and_is_not_an_empty_repeat() {
    // SILENCE IS THE DEFAULT, and this is the case that makes it a reading
    // rather than a posture. The host still writes a `hook_success` record for a
    // hook that said nothing; the engine must count it as no emission at all,
    // because three empty records under one producer would otherwise hash alike
    // and read as a hook repeating itself — a violation manufactured out of
    // exactly the behaviour this row is asking for.
    let dir = repo(
        "hook-cost-silent",
        &[
            emission("PreToolUse:Bash", ""),
            emission("PreToolUse:Bash", ""),
            emission("PreToolUse:Bash", ""),
        ],
        Some(REPEAT_ONCE),
    );
    let (text, code) = measure(&dir);
    assert_eq!(code, Some(0), "silence is clean: {text}");
    assert!(
        text.contains("hook output 0 token(s)"),
        "and costs nothing: {text}"
    );
    assert!(text.contains("0 producer(s)"), "{text}");
}

#[test]
fn the_reading_is_one_line_when_nothing_is_refused() {
    // THE SELF-APPLYING PROPERTY over the compiled binary. The unit tier asserts
    // `Reading::line` is one line; this asserts the VERB does not print anything
    // else around it — a per-producer breakdown here would make a gate about
    // hook volume grow with what it found.
    let dir = repo(
        "hook-cost-one-line",
        &[
            emission("a", "alpha"),
            emission("b", "beta"),
            emission("c", "gamma"),
        ],
        Some(REPEAT_ONCE),
    );
    let (text, code) = measure(&dir);
    assert_eq!(code, Some(0), "{text}");
    assert_eq!(text.lines().count(), 1, "one line, always: {text}");
}

#[test]
fn an_undeclared_ceiling_measures_and_refuses_nothing() {
    // ANTI-VACUITY (CLOUD-418), and the row's acceptance clause with it: the
    // measurement is re-runnable against ANY transcript, so a repository that
    // has declared no table still gets its number — which is how the 20% figure
    // is checked rather than believed, and how a consumer reads its own cost
    // before choosing a ceiling.
    let dir = repo(
        "hook-cost-unbudgeted",
        &[
            emission("loud", "the same thing"),
            emission("loud", "the same thing"),
        ],
        None,
    );
    let (text, code) = measure(&dir);
    assert_eq!(code, Some(0), "nothing declared refuses nothing: {text}");
    assert!(
        text.contains("1 repeat(s)"),
        "and the repeat is still MEASURED: {text}"
    );
}

#[test]
fn the_session_budget_arm_fires_on_the_total() {
    // The blunt predicate, and the half `max_repeats` cannot reach: a hook that
    // never repeats itself can still spend the window, which is what a ceiling
    // over the aggregate is for.
    let dir = repo(
        "hook-cost-over-budget",
        &[
            emission("verbose", &"a".repeat(4_000)),
            emission("verbose", &"b".repeat(4_000)),
        ],
        Some("[hook_output]\nmax_tokens = 100\nmax_repeats = 50\n"),
    );
    let (text, code) = measure(&dir);
    assert_eq!(code, Some(2), "{text}");
    assert!(text.contains("hook-output-budget"), "{text}");
    assert!(
        !text.contains("hook-repeat-pointer"),
        "and only that arm — the two thresholds are independent: {text}"
    );
}

#[test]
fn two_producers_saying_one_thing_are_not_one_repeat() {
    // The grouping key is (producer, digest), and this is the case that proves
    // the engine reads `hookName` rather than folding every hook into one
    // bucket. Without it, two hooks that happen to emit identical text would be
    // reported as one of them repeating itself.
    let dir = repo(
        "hook-cost-two-producers",
        &[
            emission("first", "identical"),
            emission("second", "identical"),
        ],
        Some(REPEAT_ONCE),
    );
    let (text, code) = measure(&dir);
    assert_eq!(code, Some(0), "{text}");
    assert!(text.contains("2 producer(s)"), "{text}");
    assert!(text.contains("0 repeat(s)"), "{text}");
}

#[test]
fn a_repository_with_no_transcript_is_a_usage_error_and_never_a_clean_pass() {
    // COULD-NOT-LOOK IS NOT A PASS. This verb's whole subject is that file, so a
    // missing one exiting 0 would report "no hook cost" about a session nobody
    // read — the vacuous green `[budget]`'s dead-glob refusal exists to stop one
    // verb up.
    let dir = scratch("hook-cost-no-transcript");
    write(
        &dir,
        "batten.toml",
        "version = 1\n\n[[rule]]\nid = \"probe\"\nkind = \"forbid\"\n\
         glob = \"never/**\"\npattern = \"never\"\nseverity = \"deny\"\nscope = \"tree\"\n",
    );
    let output = run(&dir, &["policy", "hooks"]);
    let reason = common::stderr(&output);
    assert_eq!(
        output.status.code(),
        Some(1),
        "a usage error, not a verdict: {reason}"
    );
    // AND FOR THE RIGHT REASON. Exit 1 is also what an unparseable config
    // produces, so a case asserting the code alone passes over a fixture that
    // never reached the verb — which is exactly what an earlier draft of this
    // file did, with `kind = "forbidden_path"` naming a variant the engine does
    // not have.
    assert!(
        reason.contains("[transcript]"),
        "the refusal names the missing declaration: {reason}"
    );
}
