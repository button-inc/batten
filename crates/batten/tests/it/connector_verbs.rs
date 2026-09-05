//! CLOUD-312 row 4: the three connector verbs AGENTS.md rules on, as config
//! rather than as `connector-verb-guard.sh`.
//!
//! A `.claude/settings.json` permission rule must name its server as a LITERAL,
//! and a claude.ai connector's exposed name is chosen per registration episode by
//! the host — readable at session start, a UUID after a reconnect. The literal
//! that would match the second is an account-specific identifier, which
//! non-negotiable rule 1 keeps out of committed config. So the verdict has to key
//! on the tool's final segment, which is what `Rule::selects_tool` does.
//!
//! **THE SUBSTRING HAZARD IS STRUCTURAL, NOT DEFENDED.**
//! `unsubscribe_pr_activity` ends with `subscribe_pr_activity`; the guard needed a
//! hand-rolled left bound on `__` to stop an unbounded suffix test denying a verb
//! it had no verdict on. `strip_suffix` leaves `un`, which does not end in `__`, so
//! the row cannot reach the wrong verb at all.
//!
//! ─── CLOUD-908's MAPPING, row 4 ──────────────────────────────────────────────
//!
//! `tests/connector-verb-guard.bats`, eighteen cases, every one placed.
//!
// carried: "connector-verb-guard.bats::a subscribe under the readable name is denied" crates/batten/tests/it/connector_verbs.rs
// carried: "connector-verb-guard.bats::send_later under the readable name is denied" crates/batten/tests/it/connector_verbs.rs
// carried: "connector-verb-guard.bats::create_trigger under the readable name is denied" crates/batten/tests/it/connector_verbs.rs
// carried: "connector-verb-guard.bats::a subscribe under a UUID server name is denied" crates/batten/tests/it/connector_verbs.rs
// carried: "connector-verb-guard.bats::send_later under a UUID server name is denied" crates/batten/tests/it/connector_verbs.rs
// carried: "connector-verb-guard.bats::an unsubscribe under the readable name is left undecided" crates/batten/tests/it/connector_verbs.rs
// carried: "connector-verb-guard.bats::an unsubscribe under a UUID server name is left undecided" crates/batten/tests/it/connector_verbs.rs
// carried: "connector-verb-guard.bats::the unsubscribe suffix is not swallowed by the subscribe suffix" crates/batten/tests/it/connector_verbs.rs
// carried: "connector-verb-guard.bats::a verb with no server prefix is still decided" crates/batten/tests/it/connector_verbs.rs
// carried: "connector-verb-guard.bats::a tool merely CONTAINING a decided verb is not decided" crates/batten/tests/it/connector_verbs.rs
// carried: "connector-verb-guard.bats::an unrelated tool gets no decision" crates/batten/tests/it/connector_verbs.rs
// carried: "connector-verb-guard.bats::every deny rule in the committed settings names a covered suffix" tests/mcp-allow-check.bats
//!
//! SUBSUMED — the plumbing became the engine's, which is what a migration should
//! produce.
//!
// subsumed: "connector-verb-guard.bats::a payload with no tool_name gets no decision" crates/batten/tests/it/cli.rs
// subsumed: "connector-verb-guard.bats::unparseable stdin gets no decision rather than a deny" crates/batten/tests/it/cli.rs
//!
//! CHANGED — four, and three of them are one cause: the coverage flags are gone,
//! because the fact they published is the engine's now (`batten policy tools`).
//!
// changed: "connector-verb-guard.bats::--covers prints every suffix the guard decides, and nothing else" crates/batten/tests/it/cli.rs the guard's `--covers` is `batten policy tools`, which reads the committed rows rather than a script's `case` arms — one authority for the fact instead of two. Asserted over the real config in `policy_tools_names_every_mediated_selector`
// changed: "connector-verb-guard.bats::--covers-allow publishes the arm a connector control can override" tests/mcp-allow-check.bats the engine has no allow arm to publish: a row is `deny` or `warn`, so the set this flag existed to expose is empty BY CONSTRUCTION rather than by measurement. `mcp-allow-check` still probes any surviving guard for it, and its own stand-in case is what keeps that half exercised
// changed: "connector-verb-guard.bats::no suffix is published as pre-approved and denied at once" crates/batten/tests/it/cli.rs unconstructible now, for the reason above: with no allow arm there is no second set to contradict the deny set. The property it protected — one verdict per verb — is the rule table's own, since two rows cannot both select one tool and disagree about severity without `config-lint` reporting it
// changed: "connector-verb-guard.bats::the bypass silences every arm" crates/batten/tests/it/guardrail_bypass.rs BATTEN_CONNECTOR_VERB_BYPASS is gone; a mediated deny takes the engine's own hatch, the consolidation rows 1-3 and 6 record
//!
//! THE SURVIVING GATE'S OWN RENAME OWES AN ARM, for the reason row 3's block
//! records: a renamed case is a deleted case to anything reading names.
//!
// changed: "mcp-allow-check.bats::a deny whose suffix a guard covers passes under any server spelling" tests/mcp-allow-check.bats what backs the coverage is a `tool`-keyed row rather than a guard now, so the case says so — and it doubles as the seam's end-to-end assertion, passing only if `batten policy tools` reaches that gate. The predicate is untouched
//!
//! ─── CLOUD-909's REPLAY, row 4 ───────────────────────────────────────────────
//!
// THE BASE REV WAS UNRESOLVABLE, and the class is worth naming rather than
// just repairing. It read `bdb2af6`, which is in no branch and no tag in this
// repository — a PRE-REBASE sha, written while the retiring branch was still on
// its own history and invalidated the moment `land` rebased it onto `main`. The
// row then points at a commit that will never exist again, so `mise run replay`
// exits 2 for every row in the tree, not only this one. Nothing catches that:
// `replay` is off the landing path by design, so a declaration can rot between
// runs with every gate green.
//
// `01e9534` is `773a8fc^` — the commit before the one that retired this guard —
// and both the dying suite and the dying program are present there, checked.
// replay-call: tests/connector-verb-guard.bats 01e9534 mise-tasks/connector-verb-guard.sh no-pr-activity-subscription deny=2 allow=0

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::{Path, PathBuf};

use common::{Fixture, run, run_with_stdin, stderr};

/// This repository's own rows, as committed — never a fixture rewriting them.
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

fn payload(tool: &str) -> String {
    let tool = serde_json::to_string(tool).expect("a tool name is encodable");
    format!("{{\"hook_event_name\":\"PreToolUse\",\"tool_name\":{tool},\"tool_input\":{{}}}}")
}

/// The three verbs, and the rows that decide them.
const DECIDED: &[(&str, &str)] = &[
    ("subscribe_pr_activity", "no-pr-activity-subscription"),
    ("send_later", "no-scheduled-self-wakeup"),
    ("create_trigger", "no-scheduled-trigger"),
];

/// CARRIES: every "is denied" case, under the readable name, under a UUID, and
/// with no server prefix at all.
///
/// MEASURED 2026-08-19 (CLOUD-178): the committed file allowed two connectors by
/// name while the host exposed both under UUIDs, so two calls answered "requires
/// approval" from inside an allow list that reads as covering them. A second
/// literal spelling is still a literal, which is why the verdict keys on the final
/// segment and never on the server.
#[test]
fn every_spelling_of_a_decided_verb_is_refused() {
    let repo = repo("row4-spellings");
    for (verb, rule) in DECIDED {
        for tool in [
            format!("mcp__Claude_Code_Remote__{verb}"),
            format!("mcp__bf7c680d-5fdc-5ef4-b4a0-abadb619bf0a__{verb}"),
            format!("mcp__claude_ai_Remote__{verb}"),
            // No server prefix at all, which is a shape a host may expose.
            (*verb).to_owned(),
        ] {
            let refusal = run_with_stdin(
                &repo,
                &["adjudicate", "--harness", "exit-code"],
                &payload(&tool),
            );
            assert_eq!(
                refusal.status.code(),
                Some(2),
                "whatever name the host minted, this verb is denied: {tool}"
            );
            let text = stderr(&refusal);
            // CLOUD-1286 took the `Refused by` framing off the line; the rule id
            // is still the engine's attribution and now ends it, which is the
            // stricter read of the same question.
            assert!(
                text.trim().ends_with(rule),
                "{tool} must be refused by {rule}, got: {text}"
            );
        }
    }
}

/// CARRIES: "an unsubscribe … is left undecided" (both spellings), "the
/// unsubscribe suffix is not swallowed by the subscribe suffix", "a tool merely
/// CONTAINING a decided verb is not decided", and "an unrelated tool gets no
/// decision".
///
/// **THE CASE THIS ROW COULD MOST EASILY GET WRONG.**
/// `unsubscribe_pr_activity` ends with `subscribe_pr_activity`, so an unbounded
/// suffix test denies a verb this policy has no verdict on — and it fails as the
/// INVERSE of the author's intent rather than as a refusal, which is the silent
/// direction. The guard carried a hand-rolled `__` bound for it; `selects_tool`
/// makes it structural.
#[test]
fn a_verb_merely_containing_a_decided_one_is_untouched() {
    let repo = repo("row4-bounds");
    for tool in [
        // The measured hazard, under both spellings.
        "mcp__Claude_Code_Remote__unsubscribe_pr_activity",
        "unsubscribe_pr_activity",
        "mcp__bf7c680d-5fdc-5ef4-b4a0-abadb619bf0a__unsubscribe_pr_activity",
        // Neighbours on the other side of the boundary.
        "mcp__x__resubscribe_pr_activity",
        "mcp__x__subscribe_pr_activity_v2",
        "mcp__x__send_later_maybe",
        "mcp__x__create_trigger_draft",
        // And an ordinary unrelated verb.
        "mcp__Linear__list_issues",
        "Read",
    ] {
        let output = run_with_stdin(
            &repo,
            &["adjudicate", "--harness", "exit-code"],
            &payload(tool),
        );
        let text = stderr(&output);
        for (_, rule) in DECIDED {
            assert!(
                !text.contains(rule),
                "{rule} has no verdict on {tool}, got: {text}"
            );
        }
        assert_eq!(
            output.status.code(),
            Some(0),
            "and nothing else in the committed policy decides it either: {tool}"
        );
    }
}

/// Each refusal names the remedy for the verb it refused, not a generic one.
///
/// CLOUD-437's clause: a migrated gate's refusal text must still name its remedy,
/// and a deny reaches the model as the entire explanation (CLOUD-122). Per row
/// rather than one phrase for all three, because that is what caught this test
/// being wrong: it demanded `mise run land` from the `send_later` refusal, where
/// that verb's actual remedy is to background the command and read its exit. A
/// generic assertion would have passed over the mismatch.
#[test]
fn each_refusal_names_its_own_remedy() {
    let repo = repo("row4-remedy");
    for (verb, remedy) in [
        // A subscription is what `land` replaces, so the loop is the remedy.
        ("subscribe_pr_activity", "mise run land"),
        // A timer is what a backgrounded task's exit replaces.
        ("send_later", "act on its exit"),
        ("create_trigger", "act on its exit"),
    ] {
        let refusal = run_with_stdin(
            &repo,
            &["adjudicate", "--harness", "exit-code"],
            &payload(&format!("mcp__Claude_Code_Remote__{verb}")),
        );
        assert_eq!(refusal.status.code(), Some(2), "{verb} is refused");
        let text = stderr(&refusal);
        // CLOUD-1286: the remedy is one hop from the rule id on the line, and
        // this case still asserts it PER ROW — which is what caught the test
        // being wrong before, when it demanded `mise run land` from a verb whose
        // remedy is to background the command. A generic assertion, or one that
        // only checked the hop resolved, would pass over the same mismatch.
        // THE ROUTE IS NOT PART OF THE POINTER (CLOUD-1386). A first sighting
        // appends the class's route after an em dash, so "the last word of the
        // line" stopped being the rule id — it became the last word of a
        // sentence. The pointer half is what this reads, and taking it
        // explicitly says so rather than relying on the route's absence.
        let pointer = text.split(" — ").next().unwrap_or(&text);
        let row = pointer
            .split_whitespace()
            .next_back()
            .expect("a deny names the rule that fired");
        let explained = run(&repo, &["policy", "explain", row]);
        assert_eq!(explained.status.code(), Some(0), "{verb}: the row resolves");
        let explained_text = String::from_utf8_lossy(&explained.stdout);
        assert!(
            explained_text.contains(remedy),
            "{verb}'s refusal must reach its own remedy ({remedy}), got: {explained_text}"
        );
    }
}
