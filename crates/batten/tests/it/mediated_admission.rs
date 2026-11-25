//! A mediated refusal is admissible by a spent admission, and only by one.
//!
//! The tier that proves the ENGINE honours what the route advertises. Without it
//! `path write refused`'s `articulate the write` is a promise made in a
//! refusal message: `batten override request` would answer, mint a real record,
//! and the write would still be refused — the exact defect `verdict.rs`'s header
//! exists to kill, one layer along.
//!
//! # Why a fixture rather than `mediated_verbs.rs`
//!
//! That suite adjudicates against the LIVE repository root, which is right for
//! asking what the committed policy decides. It cannot host these cases: they
//! must WRITE an admission, and the store lives under `$GIT_DIR`, so the case
//! would deposit records in the developer's own repository and bind its real
//! HEAD. A fixture owns its store and its head.
//!
//! # The premise case is not decoration
//!
//! `a_write_to_a_protected_path_is_refused` asserts the deny that the other two
//! cases are about. Without it a fixture whose `protected` glob silently matched
//! nothing would pass the admission case for the wrong reason — the gate never
//! fired, so nothing needed admitting.
//!
//! # The shape fixture
//!
//! `shape_fixture` holds two plain deny `shape` rows, the population
//! `call name refused` covers. Its cases pin that the class is admissible
//! (CLOUD-1806), that the rule id keeps one row's admission off another's call,
//! and that a request naming a subject the row cannot bind is refused.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::{Path, PathBuf};

use common::{Fixture, run, run_with_stdin, stdout};

/// The protected path under test, and one that is not.
const GUARDED: &str = "batten.toml";
const ORDINARY: &str = "notes.md";

/// The rule id the derived protected-path gate denies under, and its class.
///
/// Both are the engine's own constants rather than strings chosen here — a case
/// that spelled them itself would keep passing after a rename that broke every
/// consumer.
const RULE: &str = "protected-mutation";
const CLASS: &str = "path write refused";

/// A fixture whose committed authority protects itself.
///
/// `protected` naming `batten.toml` is this repository's own row, and it is the
/// case that matters: the file a registration has to edit is the file the gate
/// refuses, which is why `config read first` cannot reach it.
fn fixture(name: &str) -> PathBuf {
    Fixture::new(name)
        // THE `[[verb]]` ROW IS LOAD-BEARING AND DOES NOT MATCH THIS CALL, which
        // reads as contradictory until `Policy::is_empty` explains it: that
        // predicate is `verbs.is_empty() || protected.is_empty()`, and it
        // short-circuits `adjudicate` before any gate runs. So a repository with
        // protected paths and NO verb rows cannot refuse a write tool — even
        // though `protected_tool_write` needs no matching row and treats a verb
        // miss as "no verb-level remedy" rather than as a reason to allow.
        //
        // The row below is therefore what makes the policy adjudicable at all,
        // not what selects this call. A fixture that omitted it would allow the
        // write and the premise case would fail — which is how this was found.
        .config(
            "version = 1\n\
             protected = [\"batten.toml\"]\n\n\
             [[verb]]\n\
             verb = \"tee\"\n\
             effect = \"write\"\n\
             redirect = \"write through the surface that owns the file\"\n",
        )
        .file(ORDINARY, "not protected\n")
        .git()
        .base_commit()
        .build()
}

/// A Claude Code `PreToolUse` envelope for a write tool aimed at `path`.
///
/// The content is a config that loads: a write of `batten.toml` whose text
/// would not load is refused by the engine before any admission is consulted
/// (`config-write-unloadable`), and this suite is about the admission.
fn write_payload(path: &str) -> String {
    let escaped = serde_json::to_string(path).expect("a path is encodable");
    format!(
        "{{\"hook_event_name\":\"PreToolUse\",\"session_id\":\"{session}\",\"tool_name\":\"Write\",\
         \"tool_input\":{{\"file_path\":{escaped},\"content\":\"version = 1\\n\"}}}}",
        session = common::session_id("s1")
    )
}

/// Adjudicate one write against the fixture's policy, on the neutral adapter.
fn verdict(dir: &Path, path: &str) -> Option<i32> {
    run_with_stdin(
        dir,
        &["adjudicate", "--harness", "exit-code"],
        &write_payload(path),
    )
    .status
    .code()
}

/// Answer all three declared questions and return the issued address.
///
/// The ids are `admission.rs`'s own — `precondition`, `lost`, `rejected-route` —
/// and the request is NOT interactive: it reads `<id>=<text>` lines from stdin,
/// which is what makes an override reachable from an autonomous session at all.
fn request(dir: &Path, subject: &str, reason: &str) -> String {
    request_as(dir, RULE, CLASS, subject, reason)
}

/// [`request`] for any rule and class.
fn request_as(dir: &Path, rule: &str, class: &str, subject: &str, reason: &str) -> String {
    let answers = format!(
        "precondition=the owning surface is the file being refused, so it cannot express this\n\
         lost={reason}\n\
         rejected-route=config read first names batten.toml, which is the subject\n"
    );
    let output = run_with_stdin(
        dir,
        &[
            "override",
            "request",
            "--rule",
            rule,
            "--verdict",
            class,
            "--subject",
            subject,
        ],
        &answers,
    );
    assert!(
        output.status.success(),
        "request must issue: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    stdout(&output)
        .split_whitespace()
        .last()
        .unwrap_or_default()
        .to_owned()
}

/// Spend an issued admission against the situation it was issued for.
fn spend(dir: &Path, admission: &str, subject: &str) -> bool {
    spend_as(dir, admission, RULE, CLASS, subject)
}

/// [`spend`] for any rule and class.
fn spend_as(dir: &Path, admission: &str, rule: &str, class: &str, subject: &str) -> bool {
    // THE OWNER'S YES, which an owner-only override spends on (CLOUD-2926).
    common::owner_admits(dir, rule, class, subject);
    run(
        dir,
        &[
            "override",
            "spend",
            "--admission",
            admission,
            "--rule",
            rule,
            "--verdict",
            class,
            "--subject",
            subject,
        ],
    )
    .status
    .success()
}

/// Two plain deny `shape` rows, the population `call name refused` covers
/// (CLOUD-1806). A shape row alone makes the policy adjudicable, and the fixture
/// is committed because `admit_mediated` binds to HEAD.
const SHAPE_CONFIG: &str = "version = 1\n\n\
     [[rule]]\nid = \"no-merge\"\nkind = \"shape\"\nscope = \"mediated_call\"\n\
     pattern = \"gh pr merge\"\nreason = \"land by fast-forward\"\nseverity = \"deny\"\n\n\
     [[rule]]\nid = \"no-rebase\"\nkind = \"shape\"\nscope = \"mediated_call\"\n\
     pattern = \"git rebase\"\nreason = \"let land replay the branch\"\nseverity = \"deny\"\n";

const SHAPE_CLASS: &str = "call name refused";

/// The subject `no-merge`'s refusal names and binds: the shape its row declares
/// (CLOUD-2185), never the class's own words.
const MERGE_SHAPE: &str = "gh pr merge";

fn shape_fixture(name: &str) -> PathBuf {
    Fixture::new(name)
        .config(SHAPE_CONFIG)
        .git()
        .base_commit()
        .build()
}

/// Adjudicate one shell command, returning its exit code and stdout.
fn shell(dir: &Path, command: &str) -> (Option<i32>, String) {
    let escaped = serde_json::to_string(command).expect("a command is encodable");
    let output = run_with_stdin(
        dir,
        &["adjudicate", "--harness", "exit-code"],
        &format!(
            "{{\"hook_event_name\":\"PreToolUse\",\"tool_name\":\"Bash\",\
             \"tool_input\":{{\"command\":{escaped}}}}}"
        ),
    );
    (output.status.code(), stdout(&output))
}

/// A plain shape deny is admissible through its class's override (CLOUD-1806).
#[test]
fn a_shape_deny_is_admissible_through_its_class_override() {
    let dir = shape_fixture("mediated-admission-shape");
    assert_eq!(shell(&dir, "gh pr merge 5").0, Some(2), "the premise");
    let admission = request_as(
        &dir,
        "no-merge",
        SHAPE_CLASS,
        MERGE_SHAPE,
        "the remedy cannot perform this one merge",
    );
    assert!(
        spend_as(&dir, &admission, "no-merge", SHAPE_CLASS, MERGE_SHAPE),
        "spend must consume it"
    );
    let (code, said) = shell(&dir, "gh pr merge 5");
    assert_eq!(code, Some(0), "a spent admission admits the call: {said}");
    assert!(
        said.contains("batten: call name refused admitted by"),
        "and names the record that admitted it: {said}"
    );
}

/// The rule id is the only thing separating two rows that share the class
/// subject, so one row's admission must not admit another's call.
#[test]
fn a_shape_admission_does_not_admit_another_shape_row() {
    let dir = shape_fixture("mediated-admission-shape-other");
    let admission = request_as(
        &dir,
        "no-merge",
        SHAPE_CLASS,
        MERGE_SHAPE,
        "taken for the merge row only",
    );
    assert!(spend_as(
        &dir,
        &admission,
        "no-merge",
        SHAPE_CLASS,
        MERGE_SHAPE
    ));
    assert_eq!(
        shell(&dir, "git rebase origin/main").0,
        Some(2),
        "an admission for one shape row must not reach another"
    );
}

/// A shape row's subject is computable from the row, so a request naming one
/// no refusal binds is refused before it is issued (CLOUD-1806).
#[test]
fn a_shape_admission_for_an_unbindable_subject_is_refused() {
    let dir = shape_fixture("mediated-admission-shape-unbindable");
    let requested = run(
        &dir,
        &[
            "override",
            "request",
            "--rule",
            "no-merge",
            "--verdict",
            SHAPE_CLASS,
            "--subject",
            // THE OLD SPELLING (CLOUD-2185): before the shape was the subject, an
            // admission bound the class's own words. It names nothing now.
            SHAPE_CLASS,
        ],
    );
    let said = String::from_utf8_lossy(&requested.stderr);
    assert_eq!(requested.status.code(), Some(1), "{said}");
    assert!(requested.stdout.is_empty(), "no address may be issued");
    for needle in ["1 subject(s)", "gh,pr,merge"] {
        assert!(said.contains(needle), "{needle} missing from {said}");
    }
}

/// THE PREMISE. Every case below is about admitting this refusal, so a fixture
/// where it never fires would pass them vacuously.
#[test]
fn a_write_to_a_protected_path_is_refused() {
    let dir = fixture("mediated-admission-premise");
    assert_eq!(verdict(&dir, GUARDED), Some(2), "the gate must fire");
    assert_eq!(
        verdict(&dir, ORDINARY),
        Some(0),
        "and must not fire on an unprotected path"
    );
}

/// The whole point: articulate, spend, and the same write goes through.
#[test]
fn a_spent_admission_admits_the_write_it_was_taken_for() {
    let dir = fixture("mediated-admission-admits");
    assert_eq!(verdict(&dir, GUARDED), Some(2), "the premise");

    let admission = request(&dir, GUARDED, "the rule cannot be registered any other way");
    assert!(spend(&dir, &admission, GUARDED), "spend must consume it");

    assert_eq!(
        verdict(&dir, GUARDED),
        Some(0),
        "a spent admission must admit the write it was taken for"
    );
}

/// The spelling a reader has is the LINE, so pasting its pointers must admit
/// (CLOUD-1826). The line prints `batten.toml Write`; the binding used to be the
/// bare path, so the paste bound `batten.toml,Write` and admitted nothing.
#[test]
fn a_subject_copied_from_the_refusal_line_admits_the_write() {
    let dir = fixture("mediated-admission-pasted");
    let refused = run_with_stdin(
        &dir,
        &["adjudicate", "--harness", "exit-code"],
        &write_payload(GUARDED),
    );
    assert_eq!(refused.status.code(), Some(2), "the premise");
    let said = format!(
        "{}{}",
        String::from_utf8_lossy(&refused.stdout),
        String::from_utf8_lossy(&refused.stderr)
    );
    let pasted = common::printed_pointers(&said, CLASS, RULE);
    assert!(
        pasted.contains(' '),
        "the line must print more than one pointer, or this case cannot tell the \
         printed spelling from the bare path: {pasted:?}"
    );

    let admission = request(&dir, &pasted, "pasted straight off the refusal line");
    assert!(spend(&dir, &admission, &pasted), "spend must consume it");
    assert_eq!(
        verdict(&dir, GUARDED),
        Some(0),
        "a subject copied off the refusal line must admit the write it refused"
    );
}

/// The override route on the line IS the request that admits (CLOUD-2075 §7
/// case 12): on both arms, ready to run, with the subject the refusal binds.
#[test]
fn the_override_route_on_the_line_is_the_request_that_admits() {
    let dir = fixture("mediated-admission-route-on-line");
    let opener = format!(
        "admit with batten override request --rule '{RULE}' --verdict '{CLASS}' --subject '"
    );
    let mut subject = String::new();
    for _ in 0..2 {
        let refused = run_with_stdin(
            &dir,
            &["adjudicate", "--harness", "exit-code"],
            &write_payload(GUARDED),
        );
        assert_eq!(refused.status.code(), Some(2), "the premise");
        let said = String::from_utf8_lossy(&refused.stderr).into_owned();
        let rest = said
            .split(opener.as_str())
            .nth(1)
            .unwrap_or_else(|| panic!("no override route on the line: {said}"));
        subject = rest
            .split('\'')
            .next()
            .expect("a quoted subject")
            .to_owned();
    }
    let admission = request(&dir, &subject, "read straight off the override route");
    assert!(spend(&dir, &admission, &subject), "spend must consume it");
    assert_eq!(
        verdict(&dir, GUARDED),
        Some(0),
        "the route's request admits"
    );
}

/// An ISSUED admission does not admit — only a spent one does.
///
/// `admission.rs` calls this "the whole economy": a mint that suppressed on its
/// own would restore the bypass variable it replaced — hold the name, pay
/// nothing, override forever.
#[test]
fn an_issued_but_unspent_admission_does_not_admit() {
    let dir = fixture("mediated-admission-unspent");
    let _ = request(&dir, GUARDED, "issued and deliberately not spent");
    assert_eq!(
        verdict(&dir, GUARDED),
        Some(2),
        "articulating is not overriding until it is spent"
    );
}

/// The binding is per subject, so an admission cannot be harvested onto another.
#[test]
fn an_admission_for_another_subject_does_not_admit_this_one() {
    let dir = fixture("mediated-admission-subject");
    let admission = request(&dir, ORDINARY, "taken against a different path entirely");
    assert!(spend(&dir, &admission, ORDINARY), "spend must consume it");
    assert_eq!(
        verdict(&dir, GUARDED),
        Some(2),
        "an admission bound elsewhere must not reach this refusal"
    );
}

// ─── WHAT A PROTECTED ADMISSION IS BOUND TO (CLOUD-2779) ─────────────────────
//
// A `call:` anchor named the HEAD the call was refused at, so every commit voided
// every outstanding protected admission, whatever it touched — measured on #1276,
// `batten.toml,Edit` minted and spent at two HEADs one unrelated commit apart.
// The decision `path write refused` reads is the PATH: whether it is protected
// (the epoch's half) and what it holds (the anchor's half). So the anchor is the
// path's committed blob, or its absence, and nothing else the tree carries.

/// A protected path that is not the authority, so committing a change to it
/// moves the anchor without also moving the epoch — the two terms stay apart.
const DOC: &str = "guarded.md";

fn doc_fixture(name: &str) -> PathBuf {
    Fixture::new(name)
        .config(
            "version = 1\n\
             protected = [\"batten.toml\", \"guarded.md\"]\n\n\
             [[verb]]\n\
             verb = \"tee\"\n\
             effect = \"write\"\n\
             redirect = \"write through the surface that owns the file\"\n",
        )
        .file(DOC, "as reviewed\n")
        .file(ORDINARY, "not protected\n")
        .git()
        .base_commit()
        .build()
}

/// Request and spend one protected admission for [`DOC`], asserting it admits.
fn admit_doc(dir: &Path, reason: &str) {
    assert_eq!(verdict(dir, DOC), Some(2), "the premise");
    let admission = request(dir, DOC, reason);
    assert!(spend(dir, &admission, DOC), "spend must consume it");
    assert_eq!(verdict(dir, DOC), Some(0), "a spent admission admits");
}

fn commit_all(dir: &Path, message: &str) {
    common::git_in(dir, &["add", "-A"]);
    common::git_in(dir, &["commit", "-qm", message]);
}

/// Fails by: anchor the admission on HEAD, as `call:<sha>` did, and the
/// unrelated commit voids it.
#[test]
fn an_unrelated_commit_leaves_a_protected_admission_valid() {
    let dir = doc_fixture("mediated-admission-unrelated-commit");
    admit_doc(&dir, "the doc's owning surface cannot express this edit");
    common::write(&dir, ORDINARY, "an unrelated change\n");
    commit_all(&dir, "chore: an unrelated commit");
    assert_eq!(
        verdict(&dir, DOC),
        Some(0),
        "a commit that leaves the admitted path's blob alone leaves the admission bound"
    );
}

/// Fails by: an anchor that reads nothing of the path (a constant, or the
/// subject alone) keeps admitting after the path it was decided over changed.
#[test]
fn a_commit_touching_the_admitted_path_voids_its_admission() {
    let dir = doc_fixture("mediated-admission-touched-commit");
    admit_doc(&dir, "decided over the doc as it was reviewed");
    common::write(&dir, DOC, "changed since the decision\n");
    commit_all(&dir, "fix: change the guarded doc");
    assert_eq!(
        verdict(&dir, DOC),
        Some(2),
        "the decision read the path's blob, and that blob moved"
    );
}

/// The spend is what admits, not a commit: the admitted Edit lands in the
/// working tree, and the next Edit before any commit is still admitted.
///
/// Fails by: an anchor over the WORKING-TREE content, which the first admitted
/// write itself moves, so the second Edit of one change is refused.
#[test]
fn a_spent_admission_admits_the_next_edit_before_any_commit() {
    let dir = doc_fixture("mediated-admission-next-edit");
    admit_doc(&dir, "one change, written in two edits");
    common::write(&dir, DOC, "the first admitted edit landed\n");
    assert_eq!(
        verdict(&dir, DOC),
        Some(0),
        "the next Edit of the same change is admitted from the spend"
    );
}

/// An admission spent before this change carries `call:<head>`, and it still
/// reads and admits at that HEAD exactly as it did.
///
/// Fails by: drop the legacy lookup and a record minted by the previous binary
/// stops admitting mid-session, which is the re-mint this row removes.
#[test]
fn a_legacy_call_anchored_admission_still_admits_at_its_head() {
    use batten::admission::{self, Anchor, Binding, Situation};

    let dir = doc_fixture("mediated-admission-legacy-call");
    assert_eq!(verdict(&dir, DOC), Some(2), "the premise");
    let head = batten::git::head_commit(&dir).expect("a head");
    let epoch = batten::epoch::for_rule(&dir, None, RULE, CLASS).expect("an epoch");
    let anchor = Anchor::Call { head };
    let token = anchor.token();
    let issued = admission::issue(
        &dir,
        Binding {
            rule: RULE.to_owned(),
            verdict: CLASS.to_owned(),
            subject: DOC.to_owned(),
            anchor,
            epoch: epoch.clone(),
            answers: std::collections::BTreeMap::from([
                (
                    "precondition".to_owned(),
                    "minted by the previous binary".to_owned(),
                ),
                ("lost".to_owned(), "the legacy record".to_owned()),
                ("rejected-route".to_owned(), "none applies".to_owned()),
            ]),
            prev: None,
            author: "alec@wenzowski.com".to_owned(),
        },
    )
    .expect("issued");
    admission::consume(
        &dir,
        &issued,
        &Situation {
            rule: RULE,
            verdict: CLASS,
            subject: DOC,
            anchor: &token,
            epoch: &epoch,
        },
    )
    .expect("the store answered")
    .expect("spent");
    assert_eq!(
        verdict(&dir, DOC),
        Some(0),
        "a legacy record admits at its HEAD"
    );
}
