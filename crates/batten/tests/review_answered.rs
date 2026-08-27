//! The read-the-review gate over the compiled binary (CLOUD-859), ported off
//! `tests/review-answered.bats` under CLOUD-1059.
//!
//! # Why it moved, and it is the migration gate's own doing
//!
//! CLOUD-1050 deletes `msg` from every refusal: a refusal is
//! `{rule, verdict, subjects}` and its prose lives in a `[[verdict]]` row. The
//! retired suite asserted the refusal's PROSE — `*"4 blocking"*` — so the ABI
//! change reddened it, and `policy/shell-retirement.rego` refuses an authored
//! Bats suite edited in place. Retiring it is the specified remedy rather than a
//! consequence somebody chose: maintenance of a shell-tier rule is completed by
//! migrating it.
//!
//! # The tier is unchanged, which is the whole point of the port
//!
//! Every case still goes through TWO real hook calls in the order a session
//! makes them: a `PostToolUse` envelope carrying a tool's result, which mints the
//! record, then a `PreToolUse` `gh pr ready`, which reads it. Nothing writes a
//! receipt by hand. A module's own `test_` rules cannot do this — a `with input
//! as` case fabricates the very shape the engine may be unable to produce, the
//! defect class `.claude/rules/policy-modules.md` records twice.
//!
//! # THE FACT IS TOOL-SOURCED SINCE CLOUD-690, and that is what this tier covers
//!
//! The row declared a `command`, and this container's proxy answers it 403 — so
//! no record could ever be minted, the gate denied every `gh pr ready`, and
//! `land` merged #708 with no record in existence at all. It names a `tool` now
//! and counts the elements of that tool's result which match a predicate, plus a
//! guard beside the collection. Three things have to hold end to end and only the
//! binary can show any of them: the selector picks the call, `counts` finds the
//! collection inside a real MCP envelope, and `where`/`blocking` discriminate.
//!
//! The fixture still reads the declaration out of this repository's own
//! `batten.toml` rather than retyping it — now every policy-bearing column of
//! both rows (`tool`, `when`, `returns`, `counts`, `where`, `blocking`) rather
//! than one command, for the retired suite's reason: a copy that drifted would
//! leave every case passing over a predicate the real gate does not use. Each
//! row's own `tool` and `returns` are read separately even where the two rows
//! agree today, so repointing one of them reddens this rather than sliding past.
//!
//! **The forgery control changed shape rather than disappearing.** A `command`
//! row was protected by byte-equality against what the agent ran; a `tool` row is
//! protected by the selector, because the agent does not choose which name a host
//! reports a result under. It is `[[mint]]`'s control through the same
//! `selects_tool_name`, so there is no second matcher to drift.
//!
//! # RETIREMENT LEDGER, PER PATH — what `shell-retirement` reads
//!
// carried: tests/review-answered.bats policy/review-answered.rego crates/batten/tests/review_answered.rs
//!
//! # RETIREMENT LEDGER — `tests/review-answered.bats`, 12 cases
//!
//! CARRIED — the property survives, proved here against the same two calls.
//!
// carried: "a ready with no record at all is refused, and the receipt row names the command" crates/batten/tests/review_answered.rs
// carried: "a head whose threads are all answered is allowed" crates/batten/tests/review_answered.rs
// carried: "VACUITY: a buffer that is not the declared shape records nothing rather than one row" crates/batten/tests/review_answered.rs
// carried: "VACUITY: an empty buffer is not zero rows" crates/batten/tests/review_answered.rs
// carried: "a buffer from a command nobody asked for never becomes the record" crates/batten/tests/review_answered.rs
// carried: "a re-draft is not a ready, even on a head carrying findings" crates/batten/tests/review_answered.rs
// carried: "a commit message naming the command is prose, not a ready" crates/batten/tests/review_answered.rs
// carried: "reading the review is never refused, so the remedy is reachable" crates/batten/tests/review_answered.rs
//!
//! CHANGED — the property survives and what it ASSERTS moved. Four of these
//! asserted a count inside prose and now assert the same count as the
//! `Subject::Count` the engine renders beside the token (CLOUD-1050). Two of the
//! four moved AGAIN under CLOUD-690, because what produces the count changed:
//! each is noted below with what the number is now and why.
//!
// changed: "review-answered.bats::THE MEASURED SHAPE: a head carrying unresolved threads is refused, naming the count" crates/batten/tests/review_answered.rs the count is identical and where it is read from is not: `4 blocking` was a substring of a free string, and it is now the `Subject::Count` the engine renders beside the token (CLOUD-1050)
// changed: "review-answered.bats::VACUITY: zero threads and no review reads as unreviewed, not as all-addressed" crates/batten/tests/review_answered.rs the count is 0 now and the rule is `review-absent`: the condition was one element of a `--jq` projection and is a second fact with its own inverted comparison since CLOUD-690, so the assertion moved from prose to a different predicate's subject rather than only to a subject
// changed: "review-answered.bats::VACUITY: a page the command could not read refuses rather than passing" crates/batten/tests/review_answered.rs same number, different producer: the projection emitted an extra element and the `blocking` column adds one, so the discriminating pair with the all-answered case is now two identical thread sets under different page flags
// changed: "review-answered.bats::THE BYPASS: a compound command is still a ready" crates/batten/tests/review_answered.rs same cause, same number; what the case proves — that the receipt row's selection and this module's narrowing agree about one command — is unchanged
//!
//! # Two cases the retired suite could not have
//!
//! `an undeclared class refuses with the token and says the registry is silent`
//! is the ABI's own seam: a module may emit a verdict no `[[verdict]]` row
//! declares, and the engine must say so rather than print an empty gloss.
//!
//! `two rows sharing a selector each record from their own result` is
//! CLOUD-690's: one tool serves several methods, so two rows legitimately name it
//! and discriminate by the METHOD each declares. `record_agent_fact` took the
//! FIRST matching row, which was correct while a selector was a command and made
//! the second row's check deny forever once it was not.
//!
//! `a sibling method answering the same shape is not a review` is the second
//! defect that seam produced, and the reason `when` exists at all: the rows first
//! discriminated by SHAPE, and `get_files` answers with the same bare top-level
//! array `get_reviews` does — so a file listing minted the review-exists fact and
//! cleared the check. Its discriminating half posts the identical bytes under the
//! declared method.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::fs;
use std::path::{Path, PathBuf};

use common::{at_root, run_with_stdin, scratch};

/// The declaration both rows carry, read out of this repository's own committed
/// config.
///
/// BY NAME rather than by position: taking the first `[[fact]]` block would let a
/// row added above these silently repoint every case here at the wrong predicate.
/// Parsed with a line scan rather than a TOML crate for the reason the retired
/// suite used one — what is asserted is the literal bytes of a declaration, and a
/// parser that normalised them would dissolve the coupling this exists to hold.
struct Declared {
    /// `review-threads-clear`'s `tool` selector — the final `__`-delimited
    /// segment — and `review-happened`'s.
    ///
    /// TWO FIELDS rather than one, even while both rows name the same tool today:
    /// interpolating one row's selector into both fixture rows would leave every
    /// case here passing over a selector the real gate does not use the moment one
    /// of them is repointed. That is the drift this parser exists to prevent.
    selector: String,
    reviews_selector: String,
    /// The shape each row declares, which `counted` reads BEFORE the path and
    /// which `validate` now refuses one pairing of outright. Parsed rather than
    /// written here for the same reason as every other column: a fixture carrying
    /// its own value keeps passing while the committed row moves.
    returns: String,
    reviews_returns: String,
    /// `review-threads-clear`'s collection path and its element predicate.
    counts: String,
    matching: String,
    /// The guard beside that collection.
    blocking: String,
    /// `review-happened`'s collection path, which is the payload root.
    reviews_counts: String,
    /// The `when` clause each row declares, verbatim, and the METHOD each names.
    ///
    /// Read from the committed rows rather than written here, because the whole
    /// property under test is that the engine records from the invocation the
    /// config names — a fixture naming its own method would assert that two
    /// strings this file wrote are equal.
    threads_when: String,
    reviews_when: String,
    threads_method: String,
    reviews_method: String,
}

impl Declared {
    /// The name the HOST reports, which is what the selector is matched against.
    ///
    /// Deliberately the fully-qualified MCP spelling while the declaration names
    /// only the final segment: `selects_tool_name` matches a whole
    /// `__`-delimited segment precisely so a row survives the host rotating its
    /// server label (CLOUD-178, CLOUD-665, CLOUD-684), and a fixture naming the
    /// segment on both sides would assert equality and never that property.
    fn raw_tool(&self) -> String {
        format!("mcp__github__{}", self.selector)
    }

    /// The same, for the row that counts the reviews.
    fn raw_reviews_tool(&self) -> String {
        format!("mcp__github__{}", self.reviews_selector)
    }
}

fn declared() -> Declared {
    let text = fs::read_to_string(at_root("batten.toml")).expect("read the committed config");
    let mut rows: std::collections::BTreeMap<String, std::collections::BTreeMap<String, String>> =
        std::collections::BTreeMap::new();
    for block in text.split("[[fact]]").skip(1) {
        let mut name = None;
        let mut fields = std::collections::BTreeMap::new();
        for line in block.lines() {
            if line.starts_with("[[") {
                break;
            }
            let Some((key, value)) = line.split_once(" = ") else {
                continue;
            };
            if key == "name" {
                name = Some(value.trim_matches('"').to_owned());
            } else {
                fields.insert(key.to_owned(), value.to_owned());
            }
        }
        if let Some(name) = name {
            rows.insert(name, fields);
        }
    }
    let answered = rows
        .get("review-threads-clear")
        .expect("a [[fact]] row named review-threads-clear");
    let happened = rows
        .get("review-happened")
        .expect("a [[fact]] row named review-happened");
    let unquoted = |fields: &std::collections::BTreeMap<String, String>, key: &str| {
        fields
            .get(key)
            .unwrap_or_else(|| panic!("the row declares `{key}`"))
            .trim_matches('"')
            .to_owned()
    };
    // `when = { method = "x" }` — the literal the clause names, taken out of the
    // committed line rather than restated, for `unquoted`'s reason one row up.
    let method_in = |fields: &std::collections::BTreeMap<String, String>| {
        let clause = fields.get("when").expect("the row declares `when`");
        clause
            .rsplit_once(" = ")
            .map(|(_, literal)| {
                literal
                    .trim_end_matches('}')
                    .trim()
                    .trim_matches('"')
                    .to_owned()
            })
            .expect("the `when` clause names a literal")
    };
    Declared {
        selector: unquoted(answered, "tool"),
        reviews_selector: unquoted(happened, "tool"),
        returns: unquoted(answered, "returns"),
        reviews_returns: unquoted(happened, "returns"),
        threads_when: answered
            .get("when")
            .expect("the row declares `when`")
            .clone(),
        reviews_when: happened
            .get("when")
            .expect("the row declares `when`")
            .clone(),
        threads_method: method_in(answered),
        reviews_method: method_in(happened),
        counts: unquoted(answered, "counts"),
        matching: answered
            .get("where")
            .expect("the row declares `where`")
            .clone(),
        blocking: answered
            .get("blocking")
            .expect("the row declares `blocking`")
            .clone(),
        reviews_counts: unquoted(happened, "counts"),
    }
}

/// A fixture repository carrying the real module, the rows that judge it, and the
/// verdict classes the refusals resolve against.
///
/// `declared` is threaded in rather than re-read per call: the fixture's config
/// and every envelope below must name the same declaration, and reading it twice
/// is two chances to disagree.
fn repo(name: &str, declared: &Declared, declare_the_classes: bool) -> PathBuf {
    let dir = scratch(name);
    fs::create_dir_all(dir.join("policy")).expect("create the policy directory");
    fs::copy(
        at_root("policy/review-answered.rego"),
        dir.join("policy/review-answered.rego"),
    )
    .expect("copy the module under test");
    let classes = if declare_the_classes { CLASSES } else { "" };
    let config = format!(
        "version = 1\n\n\
         [[fact]]\n\
         name = \"review-threads-clear\"\n\
         returns = \"{returns}\"\n\
         tool = \"{selector}\"\n\
         when = {threads_when}\n\
         counts = \"{counts}\"\n\
         where = {matching}\n\
         blocking = {blocking}\n\
         \n\
         [[fact]]\n\
         name = \"review-happened\"\n\
         returns = \"{reviews_returns}\"\n\
         tool = \"{reviews_selector}\"\n\
         when = {reviews_when}\n\
         counts = \"{reviews}\"\n\
         {ROWS}{classes}",
        selector = declared.selector,
        counts = declared.counts,
        matching = declared.matching,
        blocking = declared.blocking,
        reviews = declared.reviews_counts,
        reviews_selector = declared.reviews_selector,
        returns = declared.returns,
        reviews_returns = declared.reviews_returns,
        threads_when = declared.threads_when,
        reviews_when = declared.reviews_when,
    );
    fs::write(dir.join("batten.toml"), config).expect("write the fixture config");
    git(&dir, &["init", "--quiet", "--initial-branch", "main"]);
    git(&dir, &["config", "user.email", "fixture@example.invalid"]);
    git(&dir, &["config", "user.name", "fixture"]);
    // AND A COMMIT. The record is filed under the subject the row's
    // `key = "head"` names, so a repository whose HEAD does not resolve has no
    // subject — the boundary answers could-not-look and every case here would be
    // ALLOWED, which is the fail-open posture working rather than the thing
    // these cases are about.
    git(
        &dir,
        &[
            "commit",
            "--quiet",
            "--allow-empty",
            "-m",
            "the head this gate judges",
        ],
    );
    dir
}

#[expect(
    clippy::disallowed_types,
    reason = "stays — the fixture needs real git history for the head the record is keyed to, and \
              `board_record.rs`'s fixture is the precedent. Test-only, so no shipped path spawns \
              here."
)]
fn git(dir: &Path, args: &[&str]) {
    let status = std::process::Command::new("git")
        .args(args)
        // A contributor's own git settings must not be able to move a verdict
        // here (CLOUD-282).
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .current_dir(dir)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .expect("run git");
    assert!(status.success(), "git {args:?} failed");
}

/// One review thread as the tool reports one, carrying the member the `where`
/// clause reads and one it does not — so a clause matching on presence rather
/// than on VALUE would pass every case here and fail the discriminating pair.
fn thread(resolved: bool) -> serde_json::Value {
    serde_json::json!({
        "id": "PRRT_PLANTED", "is_resolved": resolved, "is_outdated": false,
    })
}

/// A `get_review_comments` result: the threads plus the page flag `blocking`
/// reads.
///
/// The flag is always present rather than omitted on the false side, deliberately:
/// an unresolvable guard path adds nothing, so a fixture that left it out would
/// exercise that fail-open arm on every case and never the guard itself.
fn threads(truncated: bool, resolved: &[bool]) -> String {
    serde_json::json!({
        "review_threads": resolved.iter().map(|r| thread(*r)).collect::<Vec<_>>(),
        "pageInfo": {"hasNextPage": truncated},
    })
    .to_string()
}

/// A `get_reviews` result: a BARE TOP-LEVEL ARRAY, which is the shape the second
/// row's `counts = "."` exists for.
fn reviews(count: usize) -> String {
    serde_json::Value::Array(
        (0..count)
            .map(|i| serde_json::json!({"state": "COMMENTED", "user": {"login": format!("r{i}")}}))
            .collect(),
    )
    .to_string()
}

/// Mint a record the way a session does: a `PostToolUse` envelope carrying the
/// result the host handed back, under the name the host reports it under.
/// THE INPUT CARRIES THE METHOD, because the row's `when` clause reads it
/// (CLOUD-690). A fixture posting `{}` here would leave every case exercising the
/// no-clause arm and never the selection — which is the arm the defect this
/// column closes lived in.
fn record(dir: &Path, tool: &str, method: &str, result: &str) {
    let parsed: serde_json::Value = serde_json::from_str(result)
        .unwrap_or_else(|_| serde_json::Value::String(result.to_owned()));
    post(dir, tool, &serde_json::json!({"method": method}), &parsed);
}

/// A read of the review THREADS, under the selector and method that row declares.
fn record_threads(dir: &Path, declared: &Declared, result: &str) {
    record(dir, &declared.raw_tool(), &declared.threads_method, result);
}

/// A read of the REVIEWS, under the selector and method that row declares.
fn record_reviews(dir: &Path, declared: &Declared, result: &str) {
    record(
        dir,
        &declared.raw_reviews_tool(),
        &declared.reviews_method,
        result,
    );
}

/// The same event for a SHELL call, which is what the forgery control is about.
fn record_shell(dir: &Path, command: &str, stdout: &str) {
    post(
        dir,
        "Bash",
        &serde_json::json!({"command": command}),
        &serde_json::json!({"stdout": stdout, "stderr": ""}),
    );
}

fn post(dir: &Path, tool: &str, input: &serde_json::Value, response: &serde_json::Value) {
    let payload = serde_json::json!({
        "hook_event_name": "PostToolUse",
        "session_id": "sess-review",
        "cwd": "/repo",
        "tool_name": tool,
        "tool_input": input,
        "tool_response": response,
    });
    let output = run_with_stdin(
        dir,
        &["hook", "--harness", "claude-code"],
        &payload.to_string(),
    );
    assert_eq!(
        output.status.code(),
        Some(0),
        "recording is not a verdict, so the call is allowed"
    );
}

/// Read it: the call the gate exists to judge.
fn call(dir: &Path, command: &str) -> String {
    let payload = serde_json::json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": command},
    });
    let output = run_with_stdin(
        dir,
        &["hook", "--harness", "claude-code"],
        &payload.to_string(),
    );
    // THE STATUS IS ASSERTED, for the retired suite's measured reason: this
    // harness prints nothing on an allow and exits 0 either way, so a substring
    // check over an empty string is true — including the empty output of a
    // binary that died before it judged anything.
    assert_eq!(
        output.status.code(),
        Some(0),
        "the claude-code harness answers on stdout and exits 0"
    );
    String::from_utf8(output.stdout).expect("the decision document is UTF-8")
}

fn ready(dir: &Path) -> String {
    call(dir, "gh pr ready 702")
}

/// A head whose review half is satisfied, which every case about THREADS needs.
///
/// Without it `review-happened` is Missing and the receipt row refuses for a
/// reason the case is not about — the shape that would let a threads assertion
/// pass over a gate that never counted a thread.
fn reviewed(dir: &Path, declared: &Declared) {
    record_reviews(dir, declared, &reviews(1));
}

fn denied(decision: &str) {
    assert!(
        decision.contains(r#""permissionDecision":"deny""#),
        "expected a deny, got: {decision}"
    );
}

fn allowed(decision: &str) {
    assert!(
        !decision.contains(r#""deny""#),
        "expected an allow, got: {decision}"
    );
}

// --- the two refusals, and which row owns each ------------------------------

#[test]
fn a_ready_with_no_record_at_all_is_refused_and_the_remedy_names_the_read() {
    // The did-you-look half. The remedy is PROSE for a `tool` row and that is
    // forced rather than lazy: `Fix::Run` is built from a declared `command` and
    // this row has none to print. So the assertion is that it names a route which
    // can actually mint the record — a remedy naming a shell command would be
    // worse than prose, since no shell call satisfies this row's selector.
    let declared = declared();
    let dir = repo("review-answered-no-record", &declared, true);
    let decision = ready(&dir);
    denied(&decision);
    assert!(decision.contains(&declared.selector), "{decision}");
    assert!(decision.contains("get_review_comments"), "{decision}");
}

#[test]
fn the_measured_shape_a_head_carrying_unresolved_threads_is_refused_naming_the_count() {
    // #623's four open threads, as the tool reports them.
    let declared = declared();
    let dir = repo("review-answered-open-threads", &declared, true);
    record_threads(&dir, &declared, &threads(false, &[false; 4]));
    reviewed(&dir, &declared);
    let decision = ready(&dir);
    denied(&decision);
    assert!(decision.contains("review-unanswered"), "{decision}");
    // THE COUNT, as the typed ABI renders it: the token, its gloss, and the
    // `Subject::Count` beside them. The retired case read `4 blocking` out of a
    // free string; the number is the same and it is now a decoded subject.
    assert!(decision.contains("V-REVIEW-UNANSWERED"), "{decision}");
    assert!(
        decision.contains("unresolved review threads) 4"),
        "{decision}"
    );
    // Pointer-only (non-negotiable rule 4): the ids are not in the engine, so a
    // refusal naming one would be a payload this channel refuses to carry.
    assert!(!decision.contains("PRRT_"), "{decision}");
}

#[test]
fn a_head_whose_threads_are_all_answered_is_allowed() {
    // THE LOAD-BEARING HALF. A predicate that only ever denied would satisfy
    // every case above and gate nothing (CLOUD-418). Three resolved threads are
    // the genuine zero: the collection was there and nothing in it matched.
    let declared = declared();
    let dir = repo("review-answered-clean", &declared, true);
    record_threads(&dir, &declared, &threads(false, &[true; 3]));
    reviewed(&dir, &declared);
    allowed(&ready(&dir));
}

// --- CLOUD-690's discriminating pair for the element predicate ---------------

#[test]
fn the_discriminating_pair_two_matching_beside_three_that_do_not_records_two() {
    // The case that separates `counts` + `where` from every reader before it.
    // `rows_in` counts EVERY element, so this collection would read as five and a
    // head with three answered threads would refuse forever.
    let declared = declared();
    let dir = repo("review-answered-mixed", &declared, true);
    record_threads(
        &dir,
        &declared,
        &threads(false, &[false, true, true, false, true]),
    );
    reviewed(&dir, &declared);
    let decision = ready(&dir);
    denied(&decision);
    assert!(
        decision.contains("unresolved review threads) 2"),
        "{decision}"
    );
    assert!(!decision.contains(") 5"), "{decision}");
}

// --- the conditions the projection carried, restored ------------------------

#[test]
fn the_page_guard_an_unread_page_refuses_where_a_full_page_of_the_same_threads_allows() {
    // THE DISCRIMINATING PAIR for `blocking`, and the whole reason the column
    // exists. Both heads have every thread resolved, so the element count is zero
    // on each; only the truncated one may refuse. Before the guard these two
    // produced the same verdict, which is a false green over a head whose
    // unresolved threads fell outside the page the call asked for.
    let declared = declared();
    let complete = repo("review-answered-page-complete", &declared, true);
    record_threads(&complete, &declared, &threads(false, &[true, true]));
    reviewed(&complete, &declared);
    allowed(&ready(&complete));

    let truncated = repo("review-answered-page-capped", &declared, true);
    record_threads(&truncated, &declared, &threads(true, &[true, true]));
    reviewed(&truncated, &declared);
    let decision = ready(&truncated);
    denied(&decision);
    assert!(
        decision.contains("unresolved review threads) 1"),
        "{decision}"
    );
}

#[test]
fn the_page_guard_adds_to_the_thread_count_rather_than_replacing_it() {
    // The arithmetic the projection did by emitting one more element. Two
    // unresolved threads on an unread page is three blocking conditions, and a
    // reader must not see the guard swallow the threads or the threads swallow
    // the guard.
    let declared = declared();
    let dir = repo("review-answered-page-and-threads", &declared, true);
    record_threads(&dir, &declared, &threads(true, &[false, true, false]));
    reviewed(&dir, &declared);
    let decision = ready(&dir);
    denied(&decision);
    assert!(
        decision.contains("unresolved review threads) 3"),
        "{decision}"
    );
}

#[test]
fn vacuity_zero_threads_and_no_review_reads_as_unreviewed_not_as_all_addressed() {
    // #618's shape: no threads, no review. The thread count is a genuine zero, so
    // the first predicate is silent and what refuses is the review count. A gate
    // carrying only that predicate passes this head — the unreviewed one, and the
    // worst to pass.
    let declared = declared();
    let dir = repo("review-answered-unreviewed", &declared, true);
    record_threads(&dir, &declared, &threads(false, &[]));
    record_reviews(&dir, &declared, &reviews(0));
    let decision = ready(&dir);
    denied(&decision);
    assert!(decision.contains("V-REVIEW-ABSENT"), "{decision}");
    assert!(decision.contains("nobody has reviewed"), "{decision}");
}

#[test]
fn the_same_head_with_one_review_is_allowed() {
    // The discriminating half. Identical thread count, one review instead of
    // none. Without it the case above would pass over a predicate that refused
    // every head, which is CLOUD-418's shape.
    let declared = declared();
    let dir = repo("review-answered-reviewed-once", &declared, true);
    record_threads(&dir, &declared, &threads(false, &[]));
    reviewed(&dir, &declared);
    allowed(&ready(&dir));
}

#[test]
fn two_rows_sharing_a_selector_each_record_from_their_own_result() {
    // CLOUD-690's own defect, and the property that makes one selector serve two
    // rows. `record_agent_fact` took the FIRST matching row, so the second could
    // never record: its check denied forever and reading the reviews did not
    // satisfy it. What makes sharing safe is that each row names the METHOD it
    // answers to, so a call the other row's clause does not select mints nothing
    // for it — see the case below for what shape alone let through.
    //
    // Asserted through the verdict rather than by reading the store: with only
    // the reviews recorded, the threads check is still Missing and the call is
    // refused; with both, it is allowed. Two calls of one tool, two records.
    let declared = declared();
    let dir = repo("review-answered-two-rows", &declared, true);
    record_reviews(&dir, &declared, &reviews(2));
    let half = ready(&dir);
    denied(&half);
    assert!(half.contains("get_review_comments"), "{half}");

    record_threads(&dir, &declared, &threads(false, &[true]));
    allowed(&ready(&dir));
}

#[test]
fn a_sibling_method_answering_the_same_shape_is_not_a_review() {
    // THE DEFECT `when` CLOSES, measured on this branch before it existed. The
    // rows discriminated by SHAPE — `get_reviews` answers with a bare top-level
    // array and `get_review_comments` with an object — and the pair is not the
    // only pair: `pull_request_read`'s `get_files` also answers with a bare
    // top-level array, so one file listing minted `review-happened` with a
    // non-zero count and cleared the check that asks whether a review EXISTS.
    // That is a false green in the one direction this gate is for.
    //
    // The payload is deliberately the shape the reviews row counts, so nothing
    // here rests on the file listing looking different. Only the method differs.
    let declared = declared();
    let dir = repo("review-answered-sibling-method", &declared, true);
    record_threads(&dir, &declared, &threads(false, &[]));
    record(&dir, &declared.raw_reviews_tool(), "get_files", &reviews(3));
    let decision = ready(&dir);
    denied(&decision);
    // THE RECORD NEVER COMES INTO EXISTENCE, which is a stronger refusal than the
    // module's zero-count one: the receipt row reports the check as unrecorded, so
    // what the sibling call answered was never a fact about reviews at all. The
    // module cannot even be reached, which is why this asserts the receipt row.
    assert!(
        decision.contains("ready-needs-a-review-to-exist"),
        "{decision}"
    );
    assert!(decision.contains("get_reviews"), "{decision}");
}

#[test]
fn the_declared_method_on_the_same_payload_is_allowed() {
    // The discriminating half of the pair above: identical bytes, identical
    // shape, the method the row's `when` clause names. Without it the case above
    // would pass over a row that records from nothing at all.
    let declared = declared();
    let dir = repo("review-answered-declared-method", &declared, true);
    record_threads(&dir, &declared, &threads(false, &[]));
    record_reviews(&dir, &declared, &reviews(3));
    allowed(&ready(&dir));
}

// --- the vacuity cases the row enumerates -----------------------------------

#[test]
fn vacuity_a_result_that_is_not_the_declared_shape_records_nothing_rather_than_one_row() {
    // CLOUD-310 defect 1, which is this row's own inherited constraint: a scanner
    // that found nothing and exited `0` is a permanent silent green. The eight
    // sibling methods of this tool return no `review_threads` member at all, so
    // this is the shape a real session produces by asking for the diff instead of
    // the threads — and it must leave the did-you-look refusal standing.
    let declared = declared();
    let dir = repo("review-answered-wrong-shape", &declared, true);
    record_threads(&dir, &declared, r#"{"files":[{"filename":"src/lib.rs"}]}"#);
    reviewed(&dir, &declared);
    let decision = ready(&dir);
    denied(&decision);
    assert!(decision.contains("get_review_comments"), "{decision}");
}

#[test]
fn vacuity_a_counts_path_holding_an_object_rather_than_an_array_records_nothing() {
    // Present and unreadable is not zero either. A tool whose response shape
    // changed under the row — the same class `returns` exists for (CLOUD-993) —
    // must not become a plausible count.
    let declared = declared();
    let dir = repo("review-answered-reshaped", &declared, true);
    record_threads(&dir, &declared, r#"{"review_threads":{"total":0}}"#);
    reviewed(&dir, &declared);
    denied(&ready(&dir));
}

#[test]
fn vacuity_an_empty_result_is_not_zero_rows() {
    // A tool that answered with nothing is could-not-look, not "there are none".
    // Recording a zero here would turn silence into a pass.
    let declared = declared();
    let dir = repo("review-answered-empty", &declared, true);
    record_threads(&dir, &declared, "");
    reviewed(&dir, &declared);
    denied(&ready(&dir));
}

#[test]
fn the_forgery_control_a_shell_call_naming_the_same_string_is_not_the_tool() {
    // What a `tool` row has instead of byte-equality. `command` rows are
    // protected by comparing what the agent RAN; here the protection is that the
    // agent does not choose the name a host reports a result under. A `Bash` call
    // whose command line contains the selector, answering with exactly the
    // payload a clear head would produce, must mint nothing.
    let declared = declared();
    let dir = repo("review-answered-forged", &declared, true);
    record_shell(
        &dir,
        &format!("echo {}", declared.selector),
        &threads(false, &[true]),
    );
    reviewed(&dir, &declared);
    denied(&ready(&dir));
}

// --- what must NOT be refused ----------------------------------------------

#[test]
fn a_redraft_is_not_a_ready_even_on_a_head_carrying_findings() {
    // `land` re-drafts on a red run, and that is the one thing that stops the
    // next push buying another matrix (CLOUD-240). Refusing it would leave the
    // tap open on exactly the head this gate is keeping out of CI.
    let declared = declared();
    let dir = repo("review-answered-redraft", &declared, true);
    record_threads(&dir, &declared, &threads(false, &[false, false]));
    reviewed(&dir, &declared);
    allowed(&call(&dir, "gh pr ready 702 --undo"));
}

#[test]
fn the_bypass_a_compound_command_is_still_a_ready() {
    // The case an earlier draft did not have, and the reason it did not: this
    // module anchored on `startswith`, so `cd /repo && gh pr ready 702` went
    // unjudged. The receipt row DOES select it, so an existing record satisfies
    // the did-you-look half — and with the count half silent the call was
    // allowed carrying two unresolved threads. Measured exactly that before the
    // anchor came out.
    //
    // End to end rather than only in the module's `test_` rules, because what
    // was wrong was the interaction between two rows: the receipt row's
    // selection and this module's narrowing disagreeing about one command.
    let declared = declared();
    let dir = repo("review-answered-compound", &declared, true);
    record_threads(&dir, &declared, &threads(false, &[false, false]));
    reviewed(&dir, &declared);
    let decision = call(&dir, "cd /repo && gh pr ready 702");
    denied(&decision);
    assert!(
        decision.contains("unresolved review threads) 2"),
        "{decision}"
    );
}

#[test]
fn a_commit_message_naming_the_command_is_prose_not_a_ready() {
    // THE ANCHOR'S DISCRIMINATING CASE. This repository writes `gh pr ready`
    // down constantly — in commit messages, in issue bodies, in the module
    // itself — so a `contains` over the raw command would refuse its own
    // documentation, which is the hazard `run-shape.rego`'s header records for
    // the identical predicate.
    //
    // Over the binary rather than only in the module's own `test_` rules,
    // because what is at risk is the engine handing the whole command string
    // through: a `with input as` case fabricates that string and cannot show it
    // arrives raw.
    let declared = declared();
    let dir = repo("review-answered-prose", &declared, true);
    record_threads(&dir, &declared, &threads(false, &[false, false]));
    reviewed(&dir, &declared);
    allowed(&call(
        &dir,
        r#"git commit -m "run gh pr ready once the review is answered""#,
    ));
}

#[test]
fn reading_the_review_is_never_refused_so_the_remedy_is_reachable() {
    // A gate whose own remedy it blocks is unsatisfiable — and the remedy is a
    // TOOL call now, which is the shape this has to be re-asserted for: a
    // `mediated_call` row judges an MCP invocation as readily as a shell one, so
    // the call that mints the record must pass on a head with findings recorded.
    let declared = declared();
    let dir = repo("review-answered-remedy", &declared, true);
    record_threads(&dir, &declared, &threads(false, &[false]));
    reviewed(&dir, &declared);

    let payload = serde_json::json!({
        "hook_event_name": "PreToolUse",
        "tool_name": declared.raw_tool(),
        // NEUTRAL owner and repo, which `no-origin-literal-in-fixtures` is right
        // to insist on: what this case asserts is that a `mediated_call` row
        // judges an MCP invocation at all, and nothing about it depends on WHICH
        // repository the arguments name.
        "tool_input": {
            "method": "get_review_comments",
            "owner": "example-org",
            "repo": "example-repo",
            "pullNumber": 702,
            "perPage": 100,
        },
    });
    let output = run_with_stdin(
        &dir,
        &["hook", "--harness", "claude-code"],
        &payload.to_string(),
    );
    assert_eq!(output.status.code(), Some(0));
    allowed(&String::from_utf8(output.stdout).expect("UTF-8"));

    allowed(&call(&dir, "gh pr view 702 --json reviewDecision"));
}

// --- the ABI's own seam, which the retired suite had no registry to leave ----

#[test]
fn an_undeclared_class_refuses_with_the_token_and_says_the_registry_is_silent() {
    // A module may emit a verdict no `[[verdict]]` row declares. The refusal
    // still happens — the predicate decided — and the engine says the registry
    // is silent rather than printing an empty gloss, which would read as a class
    // with nothing to say about itself. The count still travels: a subject is
    // decoded from the violation, not from the registry.
    let declared = declared();
    let dir = repo("review-answered-no-class", &declared, false);
    record_threads(&dir, &declared, &threads(false, &[false, false, false]));
    reviewed(&dir, &declared);
    let decision = ready(&dir);
    denied(&decision);
    assert!(decision.contains("V-REVIEW-UNANSWERED"), "{decision}");
    assert!(
        decision.contains("no `[[verdict]]` row declares"),
        "{decision}"
    );
    assert!(decision.contains(") 3"), "{decision}");
}

/// The rows that judge the call: ONE RECEIPT ROW PER CHECK, as the committed
/// config declares them, and the policy row that reads what they found.
///
/// **A single row naming both checks would make three assertions here vacuous.**
/// Its one `reason` carries both method names, so a refusal for the missing
/// threads check and one for the missing reviews check render the same prose and
/// `contains("get_review_comments")` passes either way — which is precisely the
/// property `batten.toml`'s split exists to buy: a refusal names the read that
/// satisfies the check it names.
const ROWS: &str = r#"
[[rule]]
id = "ready-needs-the-threads-answered"
kind = "receipt"
scope = "mediated_call"
severity = "deny"
pattern = "gh pr ready"
checks = ["review-threads-clear"]
key = "head"
reason = "read the threads with the pull_request_read tool, method get_review_comments"

[[rule]]
id = "ready-needs-a-review-to-exist"
kind = "receipt"
scope = "mediated_call"
severity = "deny"
pattern = "gh pr ready"
checks = ["review-happened"]
key = "head"
reason = "read the reviews with the pull_request_read tool, method get_reviews"

[[rule]]
id = "review-answered"
kind = "policy"
scope = "mediated_call"
module = "policy/review-answered.rego"
severity = "deny"
"#;

/// The verdict classes the module's refusals resolve against, omitted by exactly
/// one case above so the registry-is-silent branch is reachable.
const CLASSES: &str = r#"
[[verdict]]
id = "V-REVIEW-UNANSWERED"
gloss = "readying would buy a CI matrix on a head carrying unresolved review threads"
class = """
Readying is the event that starts CI, and nothing in `land`'s pre-ready sequence \
asks about review.
"""

[[verdict.route]]
id = "R-ANSWER-THE-THREADS"
kind = "command"
target = "resolve each thread, then read them again and retry"

[[verdict]]
id = "V-REVIEW-ABSENT"
gloss = "readying would buy a CI matrix on a head nobody has reviewed"
class = """
The read found no review at all, which the thread count cannot say.
"""

[[verdict.route]]
id = "R-FORCE-A-FIRST-REVIEW"
kind = "command"
target = "@coderabbitai full review"
"#;
