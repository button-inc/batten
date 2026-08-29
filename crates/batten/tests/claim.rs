//! `batten claim check` over the compiled binary (CLOUD-1121).
//!
//! The pull-time gate's decision table, ported from `tests/claim-check.bats`
//! when CLOUD-1059 made editing a shell rule refusable.
//!
//! **The board's Todo → In Progress transition is publish-side only.** Measured:
//! a commit carrying a key moved nothing; the row went In Progress eight seconds
//! after the pull request was opened and ~105 seconds after that push. So the
//! automation issues a RECEIPT for work already written and structurally cannot
//! act as a claim — at pull time nothing has been pushed, so no key can travel.
//! What that costs, measured rather than hypothesised: CLOUD-49 went In Progress
//! at 04:29:34, a second session started writing it six minutes later, and the
//! result was thrown away. The board carried the claim the whole time.
//!
//! # TWO QUESTIONS, AND CONFLATING THEM IS HOW THE HOLE SHIPPED
//!
//! The competitor rules detect SOMEBODY ELSE and every one reads clear when
//! nobody else is involved, so all three are blind by construction to a sole
//! agent moving too fast. The sequence rules answer the other question — was this
//! story refined before the session implementing it. `--takeover` clears the
//! first set and never the second (CLOUD-816): they shared a counter once, so a
//! flag documented for "the competitor is this branch" also cleared the whole of
//! CLOUD-431.
//!
//! # THE EXIT CODES MOVED, ALL OF THEM, AND IT IS ONE DECISION RATHER THAN 76
//!
//! The shell answered `1` for a refusal and `2` for could-not-look. This verb
//! answers the crate's one table: `2` is the policy verdict everywhere and `1` is
//! a usage error, which is what could-not-look is. Non-negotiable rule 5 admits
//! no per-verb exception. The arms below stay CARRIED because the predicate is
//! identical in every one — the same payloads are refused, the same gaps are
//! gaps — and stating the remapping once here beats burying it in 76 entries.
//!
//! # RETIREMENT LEDGER, PER PATH — what `shell-retirement` reads
//!
// carried: mise-tasks/claim-check.sh crates/batten/src/claim.rs crates/batten/tests/claim.rs
// carried: tests/claim-check.bats crates/batten/src/claim.rs crates/batten/tests/claim.rs
//!
//! # RETIREMENT LEDGER — `tests/claim-check.bats`, 76 cases
//!
//! CARRIED — the property survives, proved here against the engine.
//!
// carried: "a Todo issue with nobody on it is pullable" crates/batten/tests/claim.rs
// carried: "the pullable message says to claim it, because the automation will not" crates/batten/tests/claim.rs
// carried: "an issue already In Progress is not pullable" crates/batten/tests/claim.rs
// carried: "In Review and Done are not pullable either" crates/batten/tests/claim.rs
// carried: "a Todo issue someone has already assigned is flagged" crates/batten/tests/claim.rs
// carried: "a Todo issue with a PR already attached is flagged, with the PR number" crates/batten/tests/claim.rs
// carried: "a non-PR attachment is not a claim" crates/batten/tests/claim.rs
// carried: "output is pointer-only — the issue id and the rule, never a body" crates/batten/tests/claim.rs
// carried: "a set of issues is judged as a set, and one bad apple blocks" crates/batten/tests/claim.rs
// carried: "a JSON array is accepted as well as a stream, matching graph-check" crates/batten/tests/claim.rs
// carried: "unreadable stdin is exit 2, distinct from a failing check" crates/batten/tests/claim.rs
// carried: "empty stdin is exit 2, not a silent pass" crates/batten/tests/claim.rs
// carried: "a payload missing status is unreadable rather than assumed Todo" crates/batten/tests/claim.rs
// carried: "not-todo, assigned and has-pr are each reachable on a payload with no description" crates/batten/tests/claim.rs
// carried: "a bodyless payload nothing else refuses is exit 2 naming description, never a pass" crates/batten/tests/claim.rs
// carried: "the pullable path mints a receipt for the current branch" crates/batten/tests/claim.rs
// carried: "a NOT-pullable issue mints nothing — the receipt is the claim, not the attempt" crates/batten/tests/claim.rs
// carried: "the id list stays line 1 with a clause recorded" crates/batten/tests/claim.rs
// carried: "unreadable stdin mints nothing either" crates/batten/tests/claim.rs
// carried: "outside a checkout the verdict still stands — the receipt is a side effect" crates/batten/tests/claim.rs
// carried: "THE INCIDENT REPLAY: an issue refined inside this session is refused at the claim" crates/batten/tests/claim.rs
// carried: "the legitimate path is not prompted, delayed or refused" crates/batten/tests/claim.rs
// carried: "a block ready-lint refuses mints no receipt" crates/batten/tests/claim.rs
// carried: "the refusal is pointer-only — the rule id, never the block it read" crates/batten/tests/claim.rs
// carried: "CLOUD-597 REPLAY: a row whose updatedAt moved but whose BODY did not is pullable" crates/batten/tests/claim.rs
// carried: "CLOUD-615 REPLAY: a body rewritten under this clone is refused even when the stamp is NEWER" crates/batten/tests/claim.rs
// carried: "a receipt minted the way the engine mints it is accepted" crates/batten/tests/claim.rs
// carried: "the baseline refusal is pointer-only — never a line of the body it compared" crates/batten/tests/claim.rs
// carried: "a missing session stamp REFUSES rather than passing" crates/batten/tests/claim.rs
// carried: "A DELETED READ RECEIPT IS A REFUSAL, never a fall-through to the clock" crates/batten/tests/claim.rs
// carried: "the refusal names its remedy, and it is one command over the payload in hand" crates/batten/tests/claim.rs
// carried: "a HOLLOW receipt is absence, not a weaker yes" crates/batten/tests/claim.rs
// carried: "OUTSIDE a checkout the question stays not-applicable, exactly as the stamp does" crates/batten/tests/claim.rs
// carried: "a receipt store this process cannot read is exit 2 — could not look, not absent" crates/batten/tests/claim.rs
// carried: "the bypass clears the absent baseline too, and says so in the receipt" crates/batten/tests/claim.rs
// carried: "--takeover does NOT clear an absent baseline" crates/batten/tests/claim.rs
// carried: "the bypass mints a receipt in BOTH refused cases, and says so" crates/batten/tests/claim.rs
// carried: "the receipt records the verdict and the revision it was taken against" crates/batten/tests/claim.rs
// carried: "the receipt records the origin/main it was claimed against" crates/batten/tests/claim.rs
// carried: "a bypassed claim says so IN the receipt, not only on stderr" crates/batten/tests/claim.rs
// carried: "an occupied issue is refused when no takeover is asked for" crates/batten/tests/claim.rs
// carried: "THE TAKEOVER: an occupied issue is claimable deliberately, and mints a receipt" crates/batten/tests/claim.rs
// carried: "a takeover receipt NAMES the refusals it overrode, never a bare flag" crates/batten/tests/claim.rs
// carried: "a clean claim records no takeover line" crates/batten/tests/claim.rs
// carried: "a sequence refusal is NOT cleared by --takeover" crates/batten/tests/claim.rs
// carried: "the sequence refusal names the bypass, not the takeover" crates/batten/tests/claim.rs
// carried: "the bypass DOES clear a sequence refusal, so the two hatches stay distinct" crates/batten/tests/claim.rs
// carried: "narrowing the takeover does not break it: a competitor refusal still clears" crates/batten/tests/claim.rs
// carried: "the takeover does not silence the refusals — they are still reported" crates/batten/tests/claim.rs
// carried: "CLOUD-520 clause a — a MERGED pull request is a predecessor, not a competitor" crates/batten/tests/claim.rs
// carried: "CLOUD-520 clause a — the SAME payload without the state still refuses" crates/batten/tests/claim.rs
// carried: "CLOUD-520 clause b — a CLOSED unmerged pull request does not refuse either" crates/batten/tests/claim.rs
// carried: "CLOUD-520 clause b — the merged BOOLEAN alone is enough, without a state string" crates/batten/tests/claim.rs
// carried: "CLOUD-520 clause c — an OPEN pull request still refuses — the rule is not deleted" crates/batten/tests/claim.rs
// carried: "CLOUD-520 clause d — a malformed state refuses rather than reading as merged" crates/batten/tests/claim.rs
// carried: "CLOUD-520 clause d — the state is read case-insensitively, as the API spells it" crates/batten/tests/claim.rs
// carried: "CLOUD-520 clause e — a non-PR attachment carrying a state is still ignored" crates/batten/tests/claim.rs
// carried: "CLOUD-520 remedy — the refusal names the remedy, not merely the refusal" crates/batten/tests/claim.rs
// carried: "the minted receipt records the branch it was minted for" crates/batten/tests/claim.rs
// carried: "A RENAMED BRANCH RECOVERS ITS CLAIM WITH --adopt" crates/batten/tests/claim.rs
// carried: "WITHOUT --adopt the rename is still unrecovered — the recovery is opt-in" crates/batten/tests/claim.rs
// carried: "the adoption is recorded, never silent" crates/batten/tests/claim.rs
// carried: "a receipt whose branch still exists is not adopted" crates/batten/tests/claim.rs
// carried: "adopting onto a branch that already has a receipt is refused" crates/batten/tests/claim.rs
// carried: "a receipt with no branch line is not adoptable, never grandfathered" crates/batten/tests/claim.rs
// carried: "two orphans refuse and name both rather than guessing" crates/batten/tests/claim.rs
// carried: "--adopt-from picks one when two orphans are present" crates/batten/tests/claim.rs
// carried: "a detached HEAD has no name to adopt onto" crates/batten/tests/claim.rs
// carried: "THE TAKEOVER AS A FLAG: reachable where an env-var bypass is classified" crates/batten/tests/claim.rs
// carried: "an unknown flag is a usage error, not a silent pull" crates/batten/tests/claim.rs
// carried: "--adopt-from with no value is refused, and does not hang" crates/batten/tests/claim.rs
// carried: "--adopt-from with an empty value is refused rather than silently defaulted" crates/batten/tests/claim.rs
//!
//! SUBSUMED — the plumbing became the engine's, which is what a migration should
//! produce. The base-absence case is here rather than above because this
//! checkout's own ref resolution answers for `origin/main` even where no remote
//! is configured, so the fixture that would discriminate cannot be built from a
//! git repository — the `-` is `claim::mint`'s own default and is unit-tested
//! there, and the compiled tier asserts the weaker property that survives: the
//! line is always present.
//!
// subsumed: "a clone with no origin/main records the base as absent, never as agreement" crates/batten/src/claim.rs
// subsumed: "a groomed Weakens clause reaches the receipt as a pointer" crates/batten/src/recorder.rs
// subsumed: "a body with no Weakens clause records no admission" crates/batten/src/recorder.rs
//!
//! CHANGED — the two environment variables are GONE rather than ported, and this
//! is the same decision CLOUD-1051 made for the filing gate's pair: a knowable
//! string anyone can spend without articulating anything is not an override, and
//! the flag half already carried the whole decision. `BATTEN_CLAIM_TAKEOVER` and
//! `BATTEN_CLAIM_CHECK_BYPASS` are `--takeover` and `--bypass-sequence`.
//!
// changed: "the flag and the env var record the identical line" crates/batten/tests/claim.rs the env var is gone rather than ported, so there is no second spelling for a receipt to record identically and the case describes a pair that no longer exists

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::path::{Path, PathBuf};
use std::process::Output;

use common::{Fixture, declared_patterns, git_in, run_with_stdin, stderr, stdout};

/// A checkout on a feature branch, with the workspace version the §6 arrows read.
fn repo(name: &str) -> PathBuf {
    let dir = Fixture::new(name)
        // THE GRAMMAR IS THE CONSUMER'S, so the fixture declares it (CLOUD-1100).
        // Without these rows `claim check` reports could-not-look naming the
        // first missing id — which is the correct answer for a repository that
        // has declared no Ready grammar, and not what this suite is about.
        .config(&format!("version = 1\n\n{}", declared_patterns()))
        .file(
            "Cargo.toml",
            "[workspace.package]\nversion = \"0.0.125\"\n\n[workspace.dependencies]\nserde = \"1\"\n",
        )
        .git()
        .base_commit()
        .build();
    git_in(&dir, &["checkout", "-q", "-b", "feature/claim"]);
    dir
}

/// The out-of-tree receipt store this checkout keys its claims under.
fn receipts(dir: &Path) -> PathBuf {
    dir.join(".git").join("batten-receipts")
}

/// Write the session boundary the `SessionStart` hook writes before anything else.
fn stamp(dir: &Path) {
    let store = receipts(dir);
    std::fs::create_dir_all(&store).expect("the receipt store");
    std::fs::write(store.join("session-start"), "").expect("the session stamp");
}

/// Mint the read receipt **the way the engine mints it**.
///
/// The digest is `git hash-object` of the description string EXACTLY as the
/// tracker returned it, with no trailing newline — which is what
/// `[[mint]] issue-read`'s `{digest:description}` writes. That one byte is the
/// whole of CLOUD-1121's defect: the shell hashed `jq -r`'s output, which appends
/// a newline, so the two could never agree for any body not already ending in
/// one, and the rule refused every claim in every clone. It stayed invisible
/// because the suite fabricated the baseline the same wrong way, so reader and
/// fixture agreed with each other and neither agreed with the writer.
fn read_receipt(dir: &Path, id: &str, description: &str) {
    let store = receipts(dir);
    std::fs::create_dir_all(&store).expect("the receipt store");
    let digest = blob_id(dir, description);
    std::fs::write(
        store.join(format!("issue-read.{id}")),
        format!("issue-read {id} - {digest}\n"),
    )
    .expect("the read receipt");
}

/// `git hash-object` of `text`, with no trailing newline added.
fn blob_id(dir: &Path, text: &str) -> String {
    let scratch = dir.join(".git").join("hash-input");
    std::fs::write(&scratch, text).expect("the hash input");
    let id = git_in(
        dir,
        &["hash-object", scratch.to_str().expect("a utf-8 path")],
    );
    std::fs::remove_file(&scratch).expect("clean up the hash input");
    id.trim().to_owned()
}

/// A body that passes the readiness rule, so the sequence rules are what decide.
fn refined_body() -> String {
    "**Refinement — Ready (a summary)**\n\n\
     * **Source of truth (§1).** One authoritative artifact.\n\
     * **Commit / bump (§6).** `ci` → **no bump**.\n"
        .to_owned()
}

/// A `get_issue` payload.
fn issue(id: &str, status: &str) -> serde_json::Value {
    serde_json::json!({
        "id": id,
        "status": status,
        "description": refined_body(),
        "updatedAt": "2026-08-01T00:00:00Z",
    })
}

fn check(dir: &Path, payload: &serde_json::Value, flags: &[&str]) -> Output {
    let mut args = vec!["claim", "check"];
    args.extend_from_slice(flags);
    run_with_stdin(dir, &args, &payload.to_string())
}

fn code(output: &Output) -> i32 {
    output
        .status
        .code()
        .expect("the verb exits rather than dying")
}

/// The claim receipt this branch's pull would mint.
fn claim_receipt(dir: &Path) -> Option<String> {
    std::fs::read_to_string(receipts(dir).join("claim.feature-claim")).ok()
}

/// A repository whose session stamp and read baseline both agree with the body —
/// the legitimate path, where only the competitor rules can have anything to say.
fn ready_to_pull(name: &str) -> (PathBuf, serde_json::Value) {
    let dir = repo(name);
    let payload = issue("CLOUD-1", "Todo");
    stamp(&dir);
    read_receipt(&dir, "CLOUD-1", &refined_body());
    (dir, payload)
}

// ---------------------------------------------------------------------------
// The competitor rules.
// ---------------------------------------------------------------------------

#[test]
fn a_todo_issue_with_nobody_on_it_is_pullable_and_the_message_says_to_claim_it() {
    // The message is part of the gate rather than decoration: the tracker's
    // automation fires on the PR event, which is the END of the work, so a reader
    // who takes silence for "it will be claimed for me" has read it wrong.
    let (dir, payload) = ready_to_pull("claim-pullable");
    let output = check(&dir, &payload, &[]);
    assert_eq!(code(&output), 0, "{}", stderr(&output));
    let text = stdout(&output);
    assert!(text.contains("pullable"), "{text}");
    assert!(text.contains("Todo -> In Progress"), "{text}");
    assert!(text.contains("automation"), "{text}");
}

#[test]
fn a_status_that_is_not_todo_is_not_pullable() {
    let (dir, _) = ready_to_pull("claim-not-todo");
    for status in ["In Progress", "In Review", "Done"] {
        let output = check(&dir, &issue("CLOUD-1", status), &[]);
        assert_eq!(code(&output), 2, "{status}");
        assert!(
            stderr(&output).contains(&format!("not-todo (in {status})")),
            "{}",
            stderr(&output)
        );
    }
}

#[test]
fn a_todo_issue_someone_has_already_assigned_is_flagged() {
    // `assigned` deliberately does NOT say "assigned to someone else", because in
    // this workspace it cannot: every agent authenticates as the same tracker
    // user, so self and other are indistinguishable in the payload. Reporting a
    // name comparison would be a check that looks like it discriminates and does
    // not.
    let (dir, _) = ready_to_pull("claim-assigned");
    let mut payload = issue("CLOUD-1", "Todo");
    payload["assignee"] = serde_json::json!("someone");
    let output = check(&dir, &payload, &[]);
    assert_eq!(code(&output), 2);
    assert!(
        stderr(&output).contains("CLOUD-1 assigned"),
        "{}",
        stderr(&output)
    );
}

/// One attachment, and whether the `has-pr` rule refuses on it.
struct Attachment {
    value: serde_json::Value,
    refuses: bool,
    why: &'static str,
}

#[test]
fn the_pull_request_rule_refuses_on_a_live_one_and_stands_down_on_a_finished_one() {
    // CLOUD-520. This rule's purpose is narrower than what it used to implement:
    // it catches somebody who published before the column moved, which is a claim
    // about an OPEN pull request. A MERGED one is the opposite signal — evidence
    // that work finished — and refusing on it makes a row released back to Todo
    // permanently unpullable. Measured on CLOUD-479: Todo, unassigned, its own
    // body inviting the next taker, refused on a PR that had merged the day
    // before.
    //
    // ABSENT REFUSES, and that default is load-bearing: the narrowing can only
    // ever turn a false refusal into a pull, never a real competitor into a
    // silent pass.
    let (dir, _) = ready_to_pull("claim-pr");
    let url = "https://github.com/o/r/pull/376";
    let cases = [
        Attachment {
            value: serde_json::json!({ "url": url, "state": "merged" }),
            refuses: false,
            why: "a merged pull request is a predecessor",
        },
        Attachment {
            value: serde_json::json!({ "url": url, "merged": true }),
            refuses: false,
            why: "the merged BOOLEAN alone is enough, without a state string",
        },
        Attachment {
            value: serde_json::json!({ "url": url, "state": "closed" }),
            refuses: false,
            why: "a closed unmerged pull request is not in flight either",
        },
        Attachment {
            value: serde_json::json!({ "url": url, "state": "MERGED" }),
            refuses: false,
            why: "the state is read case-insensitively, as the API spells it",
        },
        Attachment {
            value: serde_json::json!({ "url": url }),
            refuses: true,
            why: "the SAME payload without the state still refuses",
        },
        Attachment {
            value: serde_json::json!({ "url": url, "state": "open" }),
            refuses: true,
            why: "an open pull request still refuses — the rule is not deleted",
        },
        Attachment {
            value: serde_json::json!({ "url": url, "state": "nonsense" }),
            refuses: true,
            why: "a malformed state refuses rather than reading as merged",
        },
        Attachment {
            value: serde_json::json!({ "url": "https://example.com/doc", "state": "open" }),
            refuses: false,
            why: "a non-PR attachment carrying a state is still ignored",
        },
    ];
    for case in cases {
        let mut payload = issue("CLOUD-1", "Todo");
        payload["attachments"] = serde_json::json!([case.value]);
        let output = check(&dir, &payload, &[]);
        if case.refuses {
            assert_eq!(code(&output), 2, "{}", case.why);
            let text = stderr(&output);
            assert!(text.contains("has-pr (376)"), "{}: {text}", case.why);
            // THE REFUSAL NAMES THE REMEDY, and the remedy is the caller's to
            // supply: this gate is a pure function of what it was handed, and the
            // tracker's attachment objects carry no state at all.
            assert!(
                text.contains("\"state\": \"merged\""),
                "{}: {text}",
                case.why
            );
        } else {
            assert_eq!(code(&output), 0, "{}\n{}", case.why, stderr(&output));
        }
    }
}

#[test]
fn a_set_is_judged_as_a_set_and_one_bad_apple_blocks() {
    let (dir, _) = ready_to_pull("claim-set");
    let mut second = issue("CLOUD-2", "In Progress");
    second["description"] = serde_json::json!(refined_body());
    let payload = serde_json::json!([issue("CLOUD-1", "Todo"), second]);
    let output = check(&dir, &payload, &[]);
    assert_eq!(code(&output), 2);
    assert!(stderr(&output).contains("CLOUD-2 not-todo"));
    assert!(
        claim_receipt(&dir).is_none(),
        "a refused set mints no receipt"
    );
}

#[test]
fn a_bare_object_is_accepted_as_well_as_an_array() {
    // The same normalisation the board sweep performs, so a caller can pipe
    // either shape without reshaping what the tracker returned.
    let (dir, _) = ready_to_pull("claim-shapes");
    let one = check(&dir, &issue("CLOUD-1", "Todo"), &[]);
    assert_eq!(code(&one), 0, "{}", stderr(&one));
    let array = check(&dir, &serde_json::json!([issue("CLOUD-1", "Todo")]), &[]);
    assert_eq!(code(&array), 0, "{}", stderr(&array));
}

// ---------------------------------------------------------------------------
// The entry contract, and CLOUD-526's projection.
// ---------------------------------------------------------------------------

#[test]
fn unreadable_and_empty_input_are_could_not_look_and_mint_nothing() {
    let (dir, _) = ready_to_pull("claim-unreadable");
    for input in ["not json", ""] {
        let output = run_with_stdin(&dir, &["claim", "check"], input);
        assert_eq!(code(&output), 1, "{input:?}");
        assert!(claim_receipt(&dir).is_none(), "{input:?} minted a receipt");
    }
}

#[test]
fn a_payload_missing_status_is_unreadable_rather_than_assumed_todo() {
    // The entry contract is what EVERY issue needs: `id` and `status`. Assuming
    // the column is how a rule silently disappears when a field is absent, which
    // is a rule an agent turns off by sending less.
    let (dir, _) = ready_to_pull("claim-no-status");
    let output = check(&dir, &serde_json::json!({ "id": "CLOUD-1" }), &[]);
    assert_eq!(code(&output), 1);
    assert!(claim_receipt(&dir).is_none());
}

#[test]
fn the_three_competitor_rules_are_reachable_on_a_payload_with_no_body() {
    // CLOUD-526's projection, and it is only real if the body-free rules can
    // actually ANSWER without a body. Without the short-circuit an already
    // refused issue falls into the readiness rule, which cannot read a bodyless
    // payload — so the refusal it had already earned is replaced by "could not
    // look".
    let (dir, _) = ready_to_pull("claim-projection");
    let cases = [
        (
            serde_json::json!({ "id": "CLOUD-1", "status": "In Progress" }),
            "not-todo",
        ),
        (
            serde_json::json!({ "id": "CLOUD-1", "status": "Todo", "assignee": "x" }),
            "assigned",
        ),
        (
            serde_json::json!({
                "id": "CLOUD-1",
                "status": "Todo",
                "attachments": [{ "url": "https://github.com/o/r/pull/9" }],
            }),
            "has-pr",
        ),
    ];
    for (payload, rule) in cases {
        let output = check(&dir, &payload, &[]);
        assert_eq!(code(&output), 2, "{rule}");
        assert!(stderr(&output).contains(rule), "{}", stderr(&output));
    }
}

#[test]
fn a_bodyless_payload_nothing_else_refuses_is_could_not_look_naming_the_field() {
    // Refused BY NAME rather than through the readiness predicate's own message,
    // which would send the reader to the wrong question.
    let (dir, _) = ready_to_pull("claim-bodyless");
    let output = check(
        &dir,
        &serde_json::json!({ "id": "CLOUD-1", "status": "Todo" }),
        &[],
    );
    assert_eq!(code(&output), 1);
    assert!(
        stderr(&output).contains("description"),
        "{}",
        stderr(&output)
    );
    assert!(claim_receipt(&dir).is_none());
}

// ---------------------------------------------------------------------------
// The refinement-sequence rules — the forgery-resistant half.
// ---------------------------------------------------------------------------

#[test]
fn a_body_rewritten_under_this_clone_is_refused_at_the_claim() {
    // THE INCIDENT REPLAY (CLOUD-431). Measured on CLOUD-427: an agent asked to
    // discuss a design instead filed the issue, wrote its own Ready block, moved
    // it Todo, piped a hand-written payload to this gate, took the receipt, and
    // implemented ~600 lines. Every guard that fired gated the SHAPE of an action;
    // none gated the SEQUENCE.
    //
    // CLOUD-615's replay is the same case reached through a container restart: the
    // stamp is truncated on every `SessionStart`, so a clock comparison laundered a
    // self-refinement into a pass. The baseline lives under `$GIT_DIR`, so a
    // restart cannot reset it — and this case is written with the stamp NEWER
    // than the refinement, which is exactly the shape the clock got wrong.
    let dir = repo("claim-refined");
    read_receipt(&dir, "CLOUD-1", "the body as this clone first read it");
    stamp(&dir);
    let output = check(&dir, &issue("CLOUD-1", "Todo"), &[]);
    assert_eq!(code(&output), 2);
    let text = stderr(&output);
    assert!(text.contains("refined-this-session"), "{text}");
    // POINTER-ONLY: never a line of the body it compared.
    assert!(!text.contains("Source of truth"), "{text}");
    assert!(claim_receipt(&dir).is_none());
}

#[test]
fn a_row_whose_body_did_not_move_is_pullable_however_the_clock_reads() {
    // CLOUD-597's replay. `updatedAt` moves on ANY write to the row — a
    // reciprocal relation, a label, a bulk board touch — so the clock refused
    // claims nobody had refined. The baseline asks the question the rule is
    // NAMED for: did the body change under this clone.
    let dir = repo("claim-clock");
    stamp(&dir);
    read_receipt(&dir, "CLOUD-1", &refined_body());
    let mut payload = issue("CLOUD-1", "Todo");
    payload["updatedAt"] = serde_json::json!("2099-01-01T00:00:00Z");
    let output = check(&dir, &payload, &[]);
    assert_eq!(code(&output), 0, "{}", stderr(&output));
}

#[test]
fn a_missing_session_stamp_refuses_rather_than_passing() {
    // INSIDE a clone the sequence question is answerable and we simply cannot see
    // the answer, and a gate that silently clears everything it cannot see is the
    // false green this repository keeps re-meeting. The remedy is local and cheap.
    let dir = repo("claim-no-stamp");
    read_receipt(&dir, "CLOUD-1", &refined_body());
    let output = check(&dir, &issue("CLOUD-1", "Todo"), &[]);
    assert_eq!(code(&output), 2);
    assert!(
        stderr(&output).contains("no-session-stamp"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn an_absent_or_hollow_read_receipt_is_a_refusal_and_never_a_fall_through() {
    // CLOUD-820. The baseline cannot be reset; it can be DELETED, by an agent's
    // own clone, with no bypass and no record — and it used to fall through to
    // exactly the clock comparison it replaced. Three ordinary steps, none a
    // bypass and none reported: refine the row, remove the receipt, wait for a
    // `SessionStart` to move the stamp past the refinement. Worse than a hatch,
    // because it needs no attacker: the receipt was deleted for a legitimate
    // reason and the honest repair of one defect silently disarmed this gate.
    //
    // A HOLLOW receipt (`-`) certifies nothing, so it is absence rather than a
    // weaker yes — the distinction that made this rule opt-out in the first place.
    let dir = repo("claim-no-receipt");
    stamp(&dir);
    let absent = check(&dir, &issue("CLOUD-1", "Todo"), &[]);
    assert_eq!(code(&absent), 2);
    let text = stderr(&absent);
    assert!(text.contains("no-read-receipt"), "{text}");
    // THE REFUSAL NAMES ITS REMEDY, and it is one read the agent should have
    // taken anyway rather than a mechanism it has to go and build.
    assert!(text.contains("read the row"), "{text}");

    std::fs::write(
        receipts(&dir).join("issue-read.CLOUD-1"),
        "issue-read CLOUD-1 - -\n",
    )
    .expect("a hollow receipt");
    let hollow = check(&dir, &issue("CLOUD-1", "Todo"), &[]);
    assert_eq!(code(&hollow), 2);
    assert!(stderr(&hollow).contains("no-read-receipt"));
}

#[test]
fn a_receipt_that_exists_and_will_not_read_is_could_not_look_and_not_absence() {
    // COULD NOT LOOK IS ITS OWN ANSWER and must not collapse into either of the
    // other two: a receipt store this process cannot read is not a missing
    // receipt — the file may be there and say the body is unchanged.
    //
    // A path that EXISTS and is not a readable regular FILE is the shape a suite
    // can exercise without depending on whether the runner is root, where a
    // permission fixture would assert nothing (CLOUD-249).
    let dir = repo("claim-unreadable-receipt");
    stamp(&dir);
    std::fs::create_dir_all(receipts(&dir).join("issue-read.CLOUD-1"))
        .expect("a receipt path that is a directory");
    let output = check(&dir, &issue("CLOUD-1", "Todo"), &[]);
    assert_eq!(code(&output), 1, "{}", stderr(&output));
    assert!(
        stderr(&output).contains("cannot be read"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn outside_a_checkout_the_question_is_not_applicable_and_the_verdict_still_stands() {
    // The receipt is a side effect of being in a clone, so a run from anywhere
    // else mints nothing for any reader to honour — refusing there would only
    // break the composability this gate shares with the board sweep, and a caller
    // inspecting the board from anywhere still deserves the verdict.
    let dir = common::scratch_outside_tree("batten-claim-e2e", "outside");
    common::write(
        &dir,
        "batten.toml",
        &format!("version = 1\n\n{}", declared_patterns()),
    );
    // NO §6 CLAUSE, and that is the shape rather than a convenience: the version
    // the arrows depend on is a property of a TREE, read lazily inside the clause
    // — demanding one everywhere is precisely what would break linting a payload
    // from outside a checkout, which is the composability this case is about.
    let mut payload = issue("CLOUD-1", "Todo");
    payload["description"] =
        serde_json::json!("**Refinement — Ready**\n\n* **Source of truth (§1).** One artifact.\n");
    let output = check(&dir, &payload, &[]);
    assert_eq!(code(&output), 0, "{}", stderr(&output));
}

#[test]
fn a_block_the_readiness_rule_refuses_mints_no_receipt() {
    let dir = repo("claim-not-ready");
    stamp(&dir);
    let mut payload = issue("CLOUD-1", "Todo");
    payload["description"] = serde_json::json!("No Ready block here at all.\n");
    read_receipt(&dir, "CLOUD-1", "No Ready block here at all.\n");
    let output = check(&dir, &payload, &[]);
    assert_eq!(code(&output), 2);
    let text = stderr(&output);
    assert!(text.contains("not-ready"), "{text}");
    // POINTER-ONLY: the rule id, never the block it read.
    assert!(!text.contains("No Ready block here at all"), "{text}");
    assert!(claim_receipt(&dir).is_none());
}

// ---------------------------------------------------------------------------
// The two hatches, which answer different questions and never collapse.
// ---------------------------------------------------------------------------

#[test]
fn a_takeover_clears_a_competitor_refusal_and_records_what_it_overrode() {
    // A takeover rather than a bypass, and the distinction is what it WRITES
    // DOWN: the reason to allow one is that a resumed branch looks identical to a
    // collision, and the only thing that tells them apart afterwards is which
    // rules fired for which ids. Measured on this gate's own landing — the
    // receipt lives under `.git/` and never leaves the clone, which is the
    // property that makes it unforgeable and also the one that strands it.
    let (dir, _) = ready_to_pull("claim-takeover");
    let mut payload = issue("CLOUD-1", "Todo");
    payload["assignee"] = serde_json::json!("someone");

    let refused = check(&dir, &payload, &[]);
    assert_eq!(code(&refused), 2);
    assert!(claim_receipt(&dir).is_none());

    let taken = check(&dir, &payload, &["--takeover"]);
    assert_eq!(code(&taken), 0, "{}", stderr(&taken));
    // THE REFUSALS ARE STILL REPORTED: a takeover overrides them, it does not
    // silence them.
    assert!(
        stderr(&taken).contains("CLOUD-1 assigned"),
        "{}",
        stderr(&taken)
    );
    let receipt = claim_receipt(&dir).expect("the takeover mints a receipt");
    assert!(
        receipt.contains("takeover 1 refusal(s) overridden"),
        "{receipt}"
    );
    assert!(receipt.contains("CLOUD-1 assigned"), "{receipt}");
}

#[test]
fn a_clean_claim_records_no_takeover_line() {
    // The anti-vacuity half: a receipt that always claimed a takeover would make
    // the case above pass while measuring nothing.
    let (dir, payload) = ready_to_pull("claim-clean");
    let output = check(&dir, &payload, &["--takeover"]);
    assert_eq!(code(&output), 0, "{}", stderr(&output));
    let receipt = claim_receipt(&dir).expect("a receipt");
    assert!(!receipt.contains("takeover"), "{receipt}");
}

#[test]
fn a_sequence_refusal_survives_the_takeover_and_names_the_other_hatch() {
    // CLOUD-816. The two shared a counter once, so `--takeover` — documented for
    // "the competitor is this branch" — also cleared `refined-this-session`, which
    // is the whole of CLOUD-431. Measured on a payload with NO competitor at all:
    // without the flag the gate refused on the sequence rule; with it the gate
    // exited 0 and minted a receipt.
    //
    // The refusal names the OTHER hatch, because offering the takeover for this is
    // what shipped the hole: a remedy that works for the wrong reason reads as
    // permission.
    let dir = repo("claim-sequence");
    stamp(&dir);
    read_receipt(&dir, "CLOUD-1", "a different body entirely");
    let payload = issue("CLOUD-1", "Todo");

    let taken = check(&dir, &payload, &["--takeover"]);
    assert_eq!(code(&taken), 2, "{}", stderr(&taken));
    let text = stderr(&taken);
    assert!(text.contains("refined-this-session"), "{text}");
    assert!(text.contains("--bypass-sequence"), "{text}");
    assert!(claim_receipt(&dir).is_none());

    // And the OTHER hatch does clear it, so the two stay distinct.
    let bypassed = check(&dir, &payload, &["--bypass-sequence"]);
    assert_eq!(code(&bypassed), 0, "{}", stderr(&bypassed));
    let receipt = claim_receipt(&dir).expect("the bypass mints a receipt");
    assert!(receipt.contains("bypassed"), "{receipt}");
}

#[test]
fn the_takeover_does_not_clear_an_absent_baseline_and_the_bypass_does() {
    // The narrowing is per KIND rather than per rule, so a sequence refusal
    // reached by a different route behaves identically — which is what makes
    // CLOUD-816's collapse unexpressible rather than merely tested.
    let dir = repo("claim-absent-baseline");
    stamp(&dir);
    let payload = issue("CLOUD-1", "Todo");

    let taken = check(&dir, &payload, &["--takeover"]);
    assert_eq!(code(&taken), 2);
    assert!(stderr(&taken).contains("no-read-receipt"));
    assert!(claim_receipt(&dir).is_none());

    let bypassed = check(&dir, &payload, &["--bypass-sequence"]);
    assert_eq!(code(&bypassed), 0, "{}", stderr(&bypassed));
    assert!(
        claim_receipt(&dir).expect("a receipt").contains("bypassed"),
        "a bypassed claim says so IN the receipt, not only on stderr"
    );
}

// ---------------------------------------------------------------------------
// The receipt.
// ---------------------------------------------------------------------------

#[test]
fn the_receipt_records_the_ids_the_verdict_the_base_and_the_branch() {
    // LINE 1 STAYS THE ID LIST every existing reader parses, and everything else
    // is read BY KEY — a line added here must not move one somebody counts on.
    //
    // The base is CLOUD-516's: a branch NAME outlives the branch it described, and
    // a receipt recording nothing cannot notice, so one claim sat on a restarted
    // branch through four unrelated stories. The branch is CLOUD-733's: the
    // filename already encodes it, until a rename makes the filename the only
    // record and it names something that no longer exists.
    let (dir, payload) = ready_to_pull("claim-receipt");
    let output = check(&dir, &payload, &[]);
    assert_eq!(code(&output), 0, "{}", stderr(&output));
    let receipt = claim_receipt(&dir).expect("the pullable path mints a receipt");
    let mut lines = receipt.lines();
    assert_eq!(lines.next(), Some("CLOUD-1"), "line 1 is the id list");
    assert!(receipt.contains("ready-lint pass"), "{receipt}");
    assert!(receipt.contains("claimed-at "), "{receipt}");
    assert!(receipt.contains("branch feature/claim"), "{receipt}");
    // THE BASE LINE IS ALWAYS PRESENT, and that is the property rather than any
    // particular value: a claim whose base could not be read records `-`, which a
    // reader treats as void rather than as agreement, and one that could records
    // the commit. An OMITTED line is the state that cannot be told from either.
    let base = receipt
        .lines()
        .find_map(|line| line.strip_prefix("base "))
        .expect("the receipt records a base");
    assert!(
        base == "-" || base.len() == 40,
        "the base is a commit or an explicit absence, never a guess: {base}"
    );
}

#[test]
fn a_clone_with_an_origin_main_records_the_commit_it_was_claimed_against() {
    let (dir, payload) = ready_to_pull("claim-receipt-base");
    let head = git_in(&dir, &["rev-parse", "HEAD"]);
    let head = head.trim();
    git_in(&dir, &["update-ref", "refs/remotes/origin/main", head]);
    let output = check(&dir, &payload, &[]);
    assert_eq!(code(&output), 0, "{}", stderr(&output));
    let receipt = claim_receipt(&dir).expect("a receipt");
    assert!(receipt.contains(&format!("base {head}")), "{receipt}");
}

#[test]
fn no_byte_of_the_body_reaches_the_output_or_the_receipt() {
    // Rule 4, over both channels: the issue id and the rule id, plus a PR number
    // where there is one. Never a body and never a title.
    let dir = repo("claim-pointer-only");
    stamp(&dir);
    let secret = "ACME Corporation's production account 0123456789";
    let body = format!("**Refinement — Ready**\n\n* **Source of truth (§1).** {secret}\n");
    read_receipt(&dir, "CLOUD-1", &body);
    let mut payload = issue("CLOUD-1", "Todo");
    payload["description"] = serde_json::json!(body);
    payload["assignee"] = serde_json::json!("someone");

    let output = check(&dir, &payload, &["--takeover"]);
    assert_eq!(code(&output), 0, "{}", stderr(&output));
    let emitted = format!(
        "{}{}{}",
        stdout(&output),
        stderr(&output),
        claim_receipt(&dir).expect("a receipt")
    );
    assert!(
        !emitted.contains(secret),
        "the body reached the output: {emitted}"
    );
    // And it still SAID something.
    assert!(stderr(&output).contains("CLOUD-1 assigned"));
}

// ---------------------------------------------------------------------------
// Adoption: re-keying a stranded receipt after a rename (CLOUD-733).
// ---------------------------------------------------------------------------

/// A claim receipt minted under `branch`, left behind by a rename.
fn strand(dir: &Path, branch: &str) {
    let store = receipts(dir);
    std::fs::create_dir_all(&store).expect("the receipt store");
    std::fs::write(
        store.join(format!("claim.{}", branch.replace('/', "-"))),
        format!(
            "CLOUD-1\nready-lint pass\nclaimed-at 2026-08-01T00:00:00Z\nbase -\nbranch {branch}\n"
        ),
    )
    .expect("a stranded receipt");
}

fn adopt(dir: &Path, flags: &[&str]) -> Output {
    let mut args = vec!["claim", "check"];
    args.extend_from_slice(flags);
    run_with_stdin(dir, &args, "")
}

#[test]
fn a_renamed_branch_recovers_its_claim_and_the_recovery_is_recorded() {
    // A branch NAME outlives nothing, but the receipt keyed by it does: a rename
    // destroys the old ref and leaves the receipt on disk, describing this exact
    // work and unreachable by every reader. Measured on CLOUD-730, where it cost a
    // closed pull request to recover by hand.
    //
    // RECORDED, never silent: a recovery indistinguishable from a clean pull is a
    // bypass wearing a better name.
    let dir = repo("claim-adopt");
    strand(&dir, "feature/old-name");
    let output = adopt(&dir, &["--adopt"]);
    assert_eq!(code(&output), 0, "{}", stderr(&output));
    assert!(
        stdout(&output).contains("feature/old-name"),
        "{}",
        stdout(&output)
    );
    let receipt = claim_receipt(&dir).expect("the receipt lands on this branch");
    assert!(receipt.contains("branch feature/claim"), "{receipt}");
    assert!(
        receipt.contains("adopted-from feature/old-name"),
        "{receipt}"
    );
    assert_eq!(receipt.lines().next(), Some("CLOUD-1"), "line 1 survives");
    assert!(
        !receipts(&dir).join("claim.feature-old-name").exists(),
        "the stray is moved rather than copied"
    );
}

#[test]
fn without_the_flag_the_rename_stays_unrecovered() {
    // The recovery is OPT-IN, and that is the whole design: a reader left to infer
    // from the receipt alone would adopt a stray from a DELETED branch as readily
    // as one from a rename, which is a gate weakening itself on a guess. So the
    // author asserts it, once, and the assertion is recorded.
    let dir = repo("claim-adopt-optin");
    strand(&dir, "feature/old-name");
    assert!(claim_receipt(&dir).is_none());
    // A plain run over a payload judges and mints its own; it never adopts.
    stamp(&dir);
    read_receipt(&dir, "CLOUD-1", &refined_body());
    let output = check(&dir, &issue("CLOUD-1", "Todo"), &[]);
    assert_eq!(code(&output), 0, "{}", stderr(&output));
    let receipt = claim_receipt(&dir).expect("a fresh receipt");
    assert!(!receipt.contains("adopted-from"), "{receipt}");
    assert!(
        receipts(&dir).join("claim.feature-old-name").exists(),
        "the stray is untouched"
    );
}

#[test]
fn a_receipt_whose_branch_still_exists_is_not_adopted() {
    // ORPHAN, not "any other receipt". A rename destroys exactly one ref, so it
    // produces exactly one orphan, and a receipt belonging to a branch that still
    // exists is that branch's — adopting it would turn a recovery into a way to
    // steal another branch's claim.
    let dir = repo("claim-adopt-live");
    git_in(&dir, &["branch", "feature/live"]);
    strand(&dir, "feature/live");
    let output = adopt(&dir, &["--adopt"]);
    assert_eq!(code(&output), 1);
    assert!(
        stderr(&output).contains("no orphaned claim receipt"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn a_receipt_recording_no_branch_is_not_adoptable() {
    // Reading "no branch line" as "adopt me" would grandfather in every receipt
    // ever written, which is the direction that turns a recovery into a bypass.
    let dir = repo("claim-adopt-legacy");
    std::fs::create_dir_all(receipts(&dir)).expect("the store");
    std::fs::write(receipts(&dir).join("claim.feature-old"), "CLOUD-1\n")
        .expect("a pre-record receipt");
    let output = adopt(&dir, &["--adopt"]);
    assert_eq!(code(&output), 1);
    assert!(stderr(&output).contains("no orphaned claim receipt"));
}

#[test]
fn adopting_over_a_live_claim_is_refused() {
    let dir = repo("claim-adopt-occupied");
    strand(&dir, "feature/old-name");
    strand(&dir, "feature/claim");
    let output = adopt(&dir, &["--adopt"]);
    assert_eq!(code(&output), 1);
    assert!(
        stderr(&output).contains("already carries a claim receipt"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn two_orphans_refuse_and_adopt_from_picks_one() {
    let dir = repo("claim-adopt-two");
    strand(&dir, "feature/one");
    strand(&dir, "feature/two");

    let ambiguous = adopt(&dir, &["--adopt"]);
    assert_eq!(code(&ambiguous), 1);
    assert!(
        stderr(&ambiguous).contains("more than one orphaned receipt"),
        "{}",
        stderr(&ambiguous)
    );

    let picked = adopt(&dir, &["--adopt-from", "feature/two"]);
    assert_eq!(code(&picked), 0, "{}", stderr(&picked));
    let receipt = claim_receipt(&dir).expect("a receipt");
    assert!(receipt.contains("adopted-from feature/two"), "{receipt}");
    assert!(
        receipts(&dir).join("claim.feature-one").exists(),
        "the one that was not named is untouched"
    );
}

#[test]
fn a_detached_head_has_no_name_to_adopt_onto() {
    let dir = repo("claim-adopt-detached");
    let head = git_in(&dir, &["rev-parse", "HEAD"]);
    git_in(&dir, &["checkout", "-q", head.trim()]);
    strand(&dir, "feature/old-name");
    let output = adopt(&dir, &["--adopt"]);
    assert_eq!(code(&output), 1);
    assert!(stderr(&output).contains("detached"), "{}", stderr(&output));
}

#[test]
fn a_flag_arity_slip_is_a_usage_error_and_never_a_silent_pull() {
    // A gate that hangs never reports, and both the verification task and the hk
    // gate wait on this one — so the arity is checked rather than left to a shell
    // `set` line.
    let (dir, _) = ready_to_pull("claim-arity");
    for flags in [
        vec!["--nonsense"],
        vec!["--adopt-from"],
        vec!["--adopt-from", ""],
    ] {
        let output = adopt(&dir, &flags);
        assert_ne!(code(&output), 0, "{flags:?}");
        assert_ne!(
            code(&output),
            2,
            "{flags:?} must not read as a policy verdict"
        );
        assert!(claim_receipt(&dir).is_none(), "{flags:?} minted a receipt");
    }
}
