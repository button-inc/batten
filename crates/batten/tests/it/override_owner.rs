//! An owner-only override is the owner's to open (CLOUD-2926).
//!
//! `batten override request` takes the agent's own answers on stdin, and
//! `batten override spend` used to admit on the record's address and situation
//! hash alone, so an agent could admit its own `protected-mutation` write to
//! the rules it is judged by. Two sessions on #1276 did. The spend now also
//! requires the OWNER's yes, which the host's question hook records in
//! `.batten/asked.jsonl`, naming the same rule, verdict and path, recorded no
//! earlier than the admission was issued.
//!
//! The ledger lines here are written the way the hook writes them
//! (`asked::Entry` as one JSON line): a fixture standing in for the host.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::{Path, PathBuf};

use common::{Fixture, run, run_with_stdin, stdout};

const RULE: &str = "protected-mutation";
const VERDICT: &str = "path write refused";
const GUARDED: &str = "guarded.txt";

fn fixture(name: &str) -> PathBuf {
    Fixture::new(name)
        .config(
            "version = 1\n\
             protected = [\"guarded.txt\", \"other.txt\"]\n\n\
             [[verb]]\n\
             verb = \"shred\"\n\
             effect = \"write\"\n\
             redirect = \"write through the surface that owns the file\"\n",
        )
        .file(GUARDED, "guarded\n")
        .file("other.txt", "other\n")
        .git()
        .base_commit()
        .build()
}

/// `override request` with the agent's own answers: the admission's address.
fn request(dir: &Path, subject: &str) -> String {
    let answers = "precondition=the owning surface cannot express this write\n\
                   lost=the fixture's guarded file stays stale\n\
                   rejected-route=the redirect names a surface this case does not have\n";
    let issued = run_with_stdin(
        dir,
        &[
            "override",
            "request",
            "--rule",
            RULE,
            "--verdict",
            VERDICT,
            "--subject",
            subject,
        ],
        answers,
    );
    assert!(
        issued.status.success(),
        "{}",
        String::from_utf8_lossy(&issued.stderr)
    );
    stdout(&issued)
        .split_whitespace()
        .last()
        .unwrap_or_default()
        .to_owned()
}

/// `override spend` of `admission` for `subject`: the exit code and stderr.
fn spend(dir: &Path, admission: &str, subject: &str) -> (Option<i32>, String) {
    let spent = run(
        dir,
        &[
            "override",
            "spend",
            "--admission",
            admission,
            "--rule",
            RULE,
            "--verdict",
            VERDICT,
            "--subject",
            subject,
        ],
    );
    (
        spent.status.code(),
        format!(
            "{}{}",
            stdout(&spent),
            String::from_utf8_lossy(&spent.stderr)
        ),
    )
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| since.as_secs())
}

/// Append the owner's answer to `question` as the host's question hook does.
fn owner_answered(dir: &Path, question: &str, answer: &str, at: u64) {
    use std::io::Write as _;
    let entry = serde_json::json!({
        "question": question,
        "options": [
            {"label": "Admit the edit", "description": "Override and make the edit."},
            {"label": "Refuse", "description": "Leave the file alone."},
        ],
        "answer": answer,
        "at": at,
    });
    let ledger = dir.join(".batten/asked.jsonl");
    std::fs::create_dir_all(ledger.parent().expect("a parent")).expect("the ledger dir");
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&ledger)
        .expect("the ledger opens");
    writeln!(file, "{entry}").expect("the ledger line");
}

fn question(rule: &str, path: &str) -> String {
    format!("Override `{rule}` (verdict `{VERDICT}`) for {path}? The gate protects it.")
}

/// Fails by: a spend admitted on the agent's own stdin answers — mutation
/// `owner-answer-unread` — which is the self-admission #1276 measured.
#[test]
fn the_agents_own_answers_alone_never_spend() {
    let dir = fixture("override-owner-unanswered");
    let subject = "guarded.txt python3";
    let admission = request(&dir, subject);
    let (code, said) = spend(&dir, &admission, subject);
    assert_eq!(code, Some(3), "no owner answer is could-not-look: {said}");
    assert!(
        said.contains("ask the owner: one yes/no naming `protected-mutation guarded.txt`"),
        "the refusal names the owner's question: {said}"
    );
    // STILL ISSUED: the refused spend consumed nothing, so the owner's later
    // yes spends this same admission.
    owner_answered(&dir, &question(RULE, GUARDED), "Admit the edit", now());
    let (code, said) = spend(&dir, &admission, subject);
    assert_eq!(code, Some(0), "the record was left issued: {said}");
}

/// Fails by: the owner's matching yes, recorded after the ask, refused.
#[test]
fn the_owners_yes_after_the_ask_spends() {
    let dir = fixture("override-owner-answered");
    let subject = "guarded.txt python3";
    let admission = request(&dir, subject);
    owner_answered(&dir, &question(RULE, GUARDED), "Admit the edit", now());
    let (code, said) = spend(&dir, &admission, subject);
    assert_eq!(code, Some(0), "{said}");
    assert!(said.contains("spent"), "{said}");
}

/// Fails by: an owner's answer about another path, another rule, or a refusal
/// read as this admission's yes.
#[test]
fn an_answer_about_something_else_never_spends() {
    let dir = fixture("override-owner-elsewhere");
    let subject = "guarded.txt python3";
    let admission = request(&dir, subject);
    owner_answered(&dir, &question(RULE, "other.txt"), "Admit the edit", now());
    owner_answered(
        &dir,
        &question("another-rule", GUARDED),
        "Admit the edit",
        now(),
    );
    owner_answered(&dir, &question(RULE, GUARDED), "Refuse", now());
    owner_answered(&dir, &question(RULE, GUARDED), "sure, go ahead", now());
    let (code, said) = spend(&dir, &admission, subject);
    assert_eq!(code, Some(3), "{said}");
}

/// Fails by: an owner's yes recorded BEFORE the admission was issued read as
/// its authorization, so one old answer opens every later ask on that path.
#[test]
fn an_answer_older_than_the_ask_never_spends() {
    let dir = fixture("override-owner-earlier");
    owner_answered(&dir, &question(RULE, GUARDED), "Admit the edit", 1);
    let subject = "guarded.txt python3";
    let admission = request(&dir, subject);
    let (code, said) = spend(&dir, &admission, subject);
    assert_eq!(code, Some(3), "{said}");
}
