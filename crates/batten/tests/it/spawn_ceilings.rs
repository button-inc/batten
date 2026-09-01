//! CLOUD-312 row 6: the subagent spawn's two ceilings, as config rather than as
//! `fanout-guard.sh`.
//!
//! The `Task` call was the only unmediated call in the wiring (CLOUD-287), while
//! the workflow contract had just been taught to price a spawn "above all" with no
//! mechanism behind it. Two conjuncts, both pure functions of the envelope: how
//! many tracked artifacts the prompt names, and how big the prompt is.
//!
//! **TWO ROWS, BECAUSE `max` IS SINGLE-VALUED and the conjuncts cap different
//! subjects of the same bytes.** A single row would have had to pick one, which is
//! what `CeilingUnit`'s own doc says the column exists to avoid.
//!
//! ─── CLOUD-908's MAPPING, row 6 ──────────────────────────────────────────────
//!
//! `tests/fanout-guard.bats`, twelve cases, every one placed and every arm
//! suite-qualified.
//!
// carried: "fanout-guard.bats::an ordinary single-target spawn is allowed" crates/batten/tests/it/spawn_ceilings.rs
// carried: "fanout-guard.bats::a manifest over the cap is refused, naming the cap and the count" crates/batten/tests/it/spawn_ceilings.rs
// carried: "fanout-guard.bats::a mem: reference counts as an artifact, resolved against the tree" crates/batten/tests/it/spawn_ceilings.rs
// carried: "fanout-guard.bats::a path-shaped token naming nothing tracked does not count" crates/batten/tests/it/spawn_ceilings.rs
// carried: "fanout-guard.bats::an oversize prompt is refused against the token budget" crates/batten/tests/it/spawn_ceilings.rs
// carried: "fanout-guard.bats::a tool that is not a spawn is never judged" crates/batten/tests/it/spawn_ceilings.rs
// carried: "fanout-guard.bats::an absent prompt fails open" crates/batten/tests/it/spawn_ceilings.rs
// carried: "fanout-guard.bats::the refusal is a pointer — it carries no prompt bytes" crates/batten/tests/it/spawn_ceilings.rs
//!
//! SUBSUMED — the plumbing became the engine's, which is what a migration should
//! produce.
//!
// subsumed: "fanout-guard.bats::unparseable stdin neither refuses nor errors" crates/batten/tests/it/cli.rs
// subsumed: "fanout-guard.bats::the Task hook is registered in settings, by shape" mise-tasks/hooks-wiring-check.sh
//!
//! CHANGED — two, and each is a capability moving rather than a property being
//! dropped.
//!
// changed: "fanout-guard.bats::the caps are configurable in both directions" crates/batten/tests/it/spawn_ceilings.rs BATTEN_FANOUT_READING_CAP and BATTEN_FANOUT_PROMPT_BUDGET are gone: each cap is `max` on its own row, configured where every other property of the row is. Per-call override is deliberately not carried — an agent that can raise the ceiling at the call being gated is not gated — and the two directions are carried as the at-cap and over-cap cases below
// changed: "fanout-guard.bats::the bypass is honoured" crates/batten/tests/it/guardrail_bypass.rs BATTEN_FANOUT_GUARD_BYPASS is gone; a mediated deny takes the engine's own hatch, the consolidation rows 1-3 record
//!
//! ─── CLOUD-909's REPLAY, row 6 ───────────────────────────────────────────────
//!
// replay-call: tests/fanout-guard.bats 5a1c1dc mise-tasks/fanout-guard.sh a-spawn-names-few-artifacts deny=2 allow=0

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::{Path, PathBuf};

use common::{Fixture, run_with_stdin, stderr};

/// This repository's own rows, as committed — never a fixture rewriting them.
///
/// The same `include_str!` contract `board_receipts.rs` uses, and for the same
/// reason: a suite asserting a hand-written copy of the row would pass over a
/// config that says something else.
fn repo(name: &str) -> PathBuf {
    let staged = Fixture::new(name).config(include_str!("../../../../batten.toml"));
    let modules = staged.path().join("policy");
    std::fs::create_dir_all(&modules).expect("the fixture's policy directory is creatable");
    let committed = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("policy");
    for entry in std::fs::read_dir(&committed).expect("the committed policy directory is readable")
    {
        let entry = entry.expect("a policy directory entry");
        let path = entry.path();
        if path
            .extension()
            .is_some_and(|extension| extension == "rego")
        {
            std::fs::copy(&path, modules.join(entry.file_name())).expect("copy a policy module");
        }
    }
    staged.git().base_commit().build()
}

/// Track `paths` in the fixture, so the manifest has something to intersect with.
///
/// The tracked set is the whole of what `tracked_artifacts` counts, so a case that
/// wants N artifacts has to commit N files — which is also what makes the
/// untracked case below discriminating rather than decorative.
fn tracked(repo: &Path, paths: &[&str]) {
    for path in paths {
        let full = repo.join(path);
        if let Some(parent) = full.parent() {
            std::fs::create_dir_all(parent).expect("the artifact's directory is creatable");
        }
        std::fs::write(&full, "x\n").expect("write the artifact");
    }
    common::git_in(repo, &["add", "-A"]);
    common::git_in(repo, &["commit", "-q", "-m", "artifacts"]);
    common::git_in(repo, &["update-ref", "refs/remotes/origin/main", "HEAD"]);
}

fn payload(tool: &str, prompt: &str) -> String {
    let tool = serde_json::to_string(tool).expect("a tool name is encodable");
    let prompt = serde_json::to_string(prompt).expect("a prompt is encodable");
    format!(
        "{{\"hook_event_name\":\"PreToolUse\",\"tool_name\":{tool},\"tool_input\":{{\"prompt\":{prompt}}}}}"
    )
}

fn verdict(repo: &Path, tool: &str, prompt: &str) -> Option<i32> {
    run_with_stdin(
        repo,
        &["hook", "--harness", "exit-code"],
        &payload(tool, prompt),
    )
    .status
    .code()
}

/// CARRIES: "a manifest over the cap is refused, naming the cap and the count",
/// "an ordinary single-target spawn is allowed", and the both-directions half of
/// "the caps are configurable in both directions".
///
/// THE MEASURED FAILURE (CLOUD-287): eight siblings, each prompt naming the same
/// eight artifacts as required reading, so the fixed per-agent cost was paid eight
/// times before any agent wrote a line — and the one that finished anything spent
/// 63,848 tokens to fetch one issue and run one lint.
///
/// Both directions, and the allow half is what stops this being a row that refuses
/// every spawn. The at-cap case pins the `<=` boundary the engine inherits from
/// `budget.rs` rather than re-deciding.
#[test]
fn a_manifest_over_the_cap_is_refused() {
    let repo = repo("row6-manifest");
    tracked(&repo, &["a.txt", "b.txt", "c.txt", "d.txt"]);

    let refusal = run_with_stdin(
        &repo,
        &["hook", "--harness", "exit-code"],
        &payload("Task", "read a.txt b.txt c.txt d.txt then act"),
    );
    assert_eq!(
        refusal.status.code(),
        Some(2),
        "four named artifacts is over the declared ceiling of three"
    );
    let text = stderr(&refusal);
    assert!(
        text.contains("a-spawn-names-few-artifacts"),
        "the row that refused, so a reader can find it in the config: {text}"
    );
    // The count AND the ceiling, which is what a reader acts on — one without the
    // other says either "too many" or "the limit is three" and not both.
    assert!(
        text.contains('4') && text.contains('3'),
        "the refusal names the measurement and the ceiling: {text}"
    );

    assert_eq!(
        verdict(&repo, "Task", "read a.txt b.txt c.txt then act"),
        Some(0),
        "three is AT the ceiling, and at is not over"
    );
    assert_eq!(
        verdict(&repo, "Task", "read a.txt then act"),
        Some(0),
        "and an ordinary single-target spawn is what this must not price"
    );
}

/// CARRIES: "a mem: reference counts as an artifact, resolved against the tree".
///
/// The `resolves` column is the consumer's, because a shorthand a repository
/// writes in its own prompts to name its own files is a property of that
/// repository (non-negotiable rule 1). Asserted through the ROW's own rewrite
/// rather than a fixture's, so a config that stopped resolving `mem:` would red
/// here.
#[test]
fn a_memory_reference_counts_as_an_artifact() {
    let repo = repo("row6-memories");
    tracked(
        &repo,
        &[
            "a.txt",
            "b.txt",
            ".serena/memories/core.md",
            ".serena/memories/workflow/landing-loop.md",
        ],
    );
    // Two tracked paths plus two resolvable memory references is four.
    assert_eq!(
        verdict(
            &repo,
            "Task",
            "read a.txt b.txt mem:core mem:workflow/landing-loop then act"
        ),
        Some(2),
        "a mem: reference names a file this repository carries, so it counts"
    );
    // The anti-vacuity twin: a reference resolving to nothing counts for nothing.
    assert_eq!(
        verdict(
            &repo,
            "Task",
            "read a.txt b.txt mem:nothing-here mem:also/absent then act"
        ),
        Some(0),
        "a reference the memories tree cannot resolve is naming nothing readable"
    );
}

/// CARRIES: "a path-shaped token naming nothing tracked does not count".
///
/// This is what makes the manifest decidable rather than a guess: the count is
/// path-shaped tokens INTERSECTED with the tracked set, so a URL, a branch name
/// and a prose slash drop out by construction. There is no allowlist to tune and
/// no false positive to appeal, which is the property an allowlist would destroy.
#[test]
fn only_tracked_paths_count() {
    let repo = repo("row6-untracked");
    tracked(&repo, &["a.txt"]);
    assert_eq!(
        verdict(
            &repo,
            "Task",
            "read nope.txt other/missing.rs https://example.com/x.md origin/main \
             and/or some prose then act"
        ),
        Some(0),
        "nothing here names a file this repository carries, so nothing counts"
    );
}

/// CARRIES: "an oversize prompt is refused against the token budget".
///
/// `tokens` is `budget.rs`'s estimator rather than a rival one — CLOUD-925 §1
/// requires one authority for what a ceiling is, so a per-call cap must not arrive
/// with its own arithmetic.
#[test]
fn an_oversize_prompt_is_refused() {
    let repo = repo("row6-budget");
    tracked(&repo, &["a.txt"]);

    // 6100 characters over four is 1525, past the declared 1500.
    let over = "x".repeat(6100);
    let refusal = run_with_stdin(
        &repo,
        &["hook", "--harness", "exit-code"],
        &payload("Task", &over),
    );
    assert_eq!(
        refusal.status.code(),
        Some(2),
        "a prompt past the declared token ceiling is refused"
    );
    let text = stderr(&refusal);
    assert!(
        text.contains("a-spawn-prompt-stays-in-budget"),
        "and the row that refused is the budget row, not the manifest one: {text}"
    );

    let under = "y".repeat(5000);
    assert_eq!(
        verdict(&repo, "Task", &under),
        Some(0),
        "a prompt inside the budget is what this must not price"
    );
}

/// CARRIES: "a tool that is not a spawn is never judged", and "an absent prompt
/// fails open".
///
/// The negative controls both ceilings need. A row that judged every tool would
/// pass every case above.
#[test]
fn only_a_spawn_is_judged() {
    let repo = repo("row6-selectors");
    tracked(&repo, &["a.txt", "b.txt", "c.txt", "d.txt"]);
    let over = "read a.txt b.txt c.txt d.txt then act";
    // ASSERTED BY THE ROWS THAT MUST STAY SILENT, not by the exit code. A tool
    // this row ignores may still be refused by a NEIGHBOUR — measured here:
    // `mcp__Linear__save_issue` carries no `id`, so `filing-needs-a-search`
    // refuses it and the exit 2 belongs to row 1. Reading that as row 6 judging a
    // non-spawn is the misattribution `replay.sh` calls `denied-by-another-row`,
    // one level in.
    for tool in [
        "Bash",
        "Edit",
        "Write",
        "mcp__Linear__save_issue",
        "mcp__Linear__list_issues",
    ] {
        let output = run_with_stdin(
            &repo,
            &["hook", "--harness", "exit-code"],
            &payload(tool, over),
        );
        let text = stderr(&output);
        for row in [
            "a-spawn-names-few-artifacts",
            "a-spawn-prompt-stays-in-budget",
        ] {
            assert!(
                !text.contains(row),
                "this call commits no fresh context window, so {row} owes it nothing: \
                 {tool}: {text}"
            );
        }
    }
    // The host may expose the spawn with a server prefix; `selects_tool` matches
    // the whole final `__`-delimited segment.
    assert_eq!(
        verdict(&repo, "mcp__someserver__Task", over),
        Some(2),
        "whatever prefix the host minted, this is the spawning verb"
    );
    // An absent projection is could-not-look, which allows.
    let no_prompt = run_with_stdin(
        &repo,
        &["hook", "--harness", "exit-code"],
        r#"{"hook_event_name":"PreToolUse","tool_name":"Task","tool_input":{}}"#,
    );
    assert_eq!(
        no_prompt.status.code(),
        Some(0),
        "a spawn carrying no prompt is nothing this can measure"
    );
}

/// CARRIES: "the refusal is a pointer — it carries no prompt bytes".
///
/// Non-negotiable rule 4, and the prompt is the likeliest place in this whole
/// wiring for consumer detail to appear. The PATHS are pointers and may be named;
/// the prose around them may not.
#[test]
fn the_refusal_carries_no_prompt_bytes() {
    let repo = repo("row6-pointer-only");
    tracked(&repo, &["a.txt", "b.txt", "c.txt", "d.txt"]);
    let secret = "hunter2-do-not-echo-me";
    let output = run_with_stdin(
        &repo,
        &["hook", "--harness", "exit-code"],
        &payload(
            "Task",
            &format!("read a.txt b.txt c.txt d.txt and remember {secret}"),
        ),
    );
    let rendered = format!(
        "{}{}",
        stderr(&output),
        String::from_utf8_lossy(&output.stdout)
    );
    assert_eq!(output.status.code(), Some(2), "the row must refuse");
    assert!(
        !rendered.contains(secret),
        "the refusal must not echo the prompt's prose: {rendered}"
    );
}
