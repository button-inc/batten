//! A push never carries a private session store's bytes to a remote other than
//! the state repo (CLOUD-2887).
//!
//! Over the compiled binary: the hook resolves the `state-push` fact for a
//! `PreToolUse` `git push` and the `state-private` preset refuses one whose pushed
//! blobs equal a private store's file, or begin an append-only one, unless the
//! remote is `BATTEN_STATE_REPO`. Measured 2026-11-24: a dispatched session
//! pushed its 6,118-line mutant verdict journal to the public repository as
//! `verdicts/28-of-32.tsv`, and no gate saw it.
//!
//! A FIXTURE config rather than the committed table, for `forced_push.rs`'s
//! reason: a consumer row naming a preset the pinned engine does not ship is a
//! config that engine cannot load. The remotes are `https://example.invalid/…`
//! URLs: the hook decides before the push runs, so nothing touches a network.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::{Path, PathBuf};

use crate::common;

/// The preset at the mediated surface.
const CONFIG: &str = "version = 1\n\n\
[[rule]]\nid = \"path carry loose\"\nkind = \"policy\"\n\
scope = \"mediated_call\"\npreset = \"state-private\"\nseverity = \"deny\"\n";

/// The state repo every case names, so a match against it is the comparison
/// itself and never an unset variable.
const STATE_REPO: &str = "example/state";

/// The project remote: a slug that is not [`STATE_REPO`].
const PROJECT_URL: &str = "https://example.invalid/example/project";

/// The state repo's own URL.
const STATE_URL: &str = "https://example.invalid/example/state";

/// What the refusal is raised under.
const RULE: &str = "path carry loose";

/// A verdict journal of whole records, as `mutate::schema::journal` appends them.
const JOURNAL: &str = "mutant-1\tcaught\t12\nmutant-2\tmissed\t9\nmutant-3\tcaught\t30\n";

/// A repository on `main` whose `origin` is `url`, with `refs/remotes/origin/main`
/// at the base commit, so a push of `main` sends only what the case commits.
fn repo(name: &str, url: &str) -> PathBuf {
    let dir = common::Fixture::new(name)
        .config(CONFIG)
        .base_commit()
        .build();
    common::git_in(&dir, &["remote", "add", "origin", url]);
    dir
}

/// This checkout's state directory, in the root the spawned binary resolves.
fn state_dir(dir: &Path) -> PathBuf {
    let _ = common::scratch_state_root();
    batten::state::repo_state_dir(dir).expect("the fixture has a state dir")
}

/// Write `bytes` at `rel` under `base`, creating its parents.
fn put(base: &Path, rel: &str, bytes: &str) -> PathBuf {
    let path = base.join(rel);
    std::fs::create_dir_all(path.parent().expect("a file has a parent"))
        .expect("the parent is creatable");
    std::fs::write(&path, bytes).expect("the file is writable");
    path
}

/// Commit `rel` holding `bytes` in the checkout.
fn commit(dir: &Path, rel: &str, bytes: &str) {
    put(dir, rel, bytes);
    common::git_in(dir, &["add", "--", rel]);
    common::git_in(dir, &["commit", "-q", "-m", "carry"]);
}

/// The private verdict journal, written where the mutation sweep writes it.
fn journal(dir: &Path) {
    put(&state_dir(dir), "mutate/schema/verdicts", JOURNAL);
}

/// A `PreToolUse` `Bash` call running `command` in `dir`, with `transcript` as
/// the session's transcript when one is named.
fn push(dir: &Path, command: &str, transcript: Option<&Path>) -> std::process::Output {
    let mut envelope = serde_json::json!({
        "hook_event_name": "PreToolUse",
        "session_id": "state-push",
        "tool_name": "Bash",
        "tool_input": {"command": command},
        "cwd": dir,
    });
    if let Some(path) = transcript {
        envelope["transcript_path"] = serde_json::json!(path);
    }
    let mut invocation = common::batten();
    invocation.env(batten::session::STATE_REPO_ENV, STATE_REPO);
    common::stdin_run(
        &mut invocation,
        dir,
        &["adjudicate", "--harness", "exit-code"],
        &envelope.to_string(),
    )
}

fn refused(output: &std::process::Output, named: &[&str]) {
    let text = common::stderr(output);
    assert_eq!(output.status.code(), Some(2), "refused: {text}");
    assert_eq!(
        common::refusing_rule(&text).as_deref(),
        Some(RULE),
        "refused by {RULE}: {text}"
    );
    for word in named {
        assert!(text.contains(word), "the refusal names {word}: {text}");
    }
}

fn admitted(output: &std::process::Output) {
    let text = common::stderr(output);
    assert_ne!(
        common::refusing_rule(&text).as_deref(),
        Some(RULE),
        "admitted, yet refused: {text}"
    );
    assert_eq!(output.status.code(), Some(0), "admitted: {text}");
}

/// The incident: the journal copied into the tree and pushed to the project.
///
/// MUTANT `state-bytes-unread`: a module that never counts the carried blobs
/// refuses nothing. `BATTEN_STATE_REPO` is set and does not match, so a module
/// exempting every remote whenever the variable is set fails here too.
#[test]
fn a_state_journal_copied_into_the_project_tree_is_refused_at_push() {
    let dir = repo("state-push-journal", PROJECT_URL);
    journal(&dir);
    commit(&dir, "verdicts/28-of-32.tsv", JOURNAL);
    refused(
        &push(&dir, "git push origin HEAD", None),
        &["verdicts/28-of-32.tsv", "mutate-verdicts", "equal"],
    );
    // ANTI-VACUITY: the same tree admits a call that is not a push.
    admitted(&push(&dir, "git fetch origin", None));
}

/// The one allowed destination.
///
/// MUTANT `state-repo-exemption-unread`: the producer reports the carried
/// journal on every remote, so a module that never reads the exemption refuses
/// this push.
#[test]
fn the_same_file_pushed_to_the_state_repo_is_allowed() {
    let dir = repo("state-push-state-repo", STATE_URL);
    journal(&dir);
    commit(&dir, "verdicts/28-of-32.tsv", JOURNAL);
    admitted(&push(&dir, "git push origin HEAD", None));
}

/// An empty file holds no record.
///
/// MUTANT `empty-blob-counted`: the producer reports the size-0 match against
/// the empty `journal/merge.lock`, so a module that counts it refuses.
#[test]
fn an_empty_file_is_never_state_bytes() {
    let dir = repo("state-push-empty", PROJECT_URL);
    put(&state_dir(&dir), "journal/merge.lock", "");
    commit(&dir, "verdicts/.gitkeep", "");
    admitted(&push(&dir, "git push origin HEAD", None));
}

/// A transcript grows every turn, so by push time a copy of it is a prefix.
/// Fails against a producer with only the equality arm.
#[test]
fn a_transcript_copied_before_it_grew_is_refused_at_push() {
    let dir = repo("state-push-transcript", PROJECT_URL);
    let sessions = common::scratch("state-push-transcript-home");
    let record =
        "{\"type\":\"user\",\"text\":\"one\"}\n{\"type\":\"assistant\",\"text\":\"two\"}\n";
    let transcript = put(&sessions, "session.jsonl", record);
    commit(&dir, "notes/session.jsonl", record);
    put(
        &sessions,
        "session.jsonl",
        &format!("{record}{{\"type\":\"user\",\"text\":\"three\"}}\n"),
    );
    refused(
        &push(&dir, "git push origin HEAD", Some(&transcript)),
        &["notes/session.jsonl", "transcripts", "prefix"],
    );
}

/// The project's own bytes, mirrored in the state dir by a replay, are not
/// session state. Fails against a producer that walks the whole state root.
#[test]
fn a_push_of_project_bytes_mirrored_in_the_state_dir_is_allowed() {
    let dir = repo("state-push-mirror", PROJECT_URL);
    let project = "pub fn answer() -> u32 {\n    42\n}\n";
    put(&state_dir(&dir), "replay/tree/src/lib.rs", project);
    commit(&dir, "src/lib.rs", project);
    admitted(&push(&dir, "git push origin HEAD", None));
}

/// A bare push names no remote; git pushes to the branch's own. Fails against a
/// producer that answers could-not-look when no remote is named.
#[test]
fn a_bare_git_push_resolves_its_remote_and_is_refused() {
    let dir = repo("state-push-bare", PROJECT_URL);
    common::git_in(&dir, &["config", "branch.main.remote", "origin"]);
    common::git_in(&dir, &["config", "branch.main.merge", "refs/heads/main"]);
    journal(&dir);
    commit(&dir, "verdicts/28-of-32.tsv", JOURNAL);
    refused(
        &push(&dir, "git push", None),
        &["verdicts/28-of-32.tsv", "mutate-verdicts"],
    );
}
