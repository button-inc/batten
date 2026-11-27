//! A protected path a shell call changed without naming it, refused after the
//! fact (step 14).
//!
//! `protected-mutation` judges the operands a command NAMES. A program writing a
//! protected path its command line never spells — a `python3` script, a `sed`
//! inside a variable, a `cp` of a parent, a redirect the text does not show —
//! passed it, and did: a session wrote registered modules through a `python3`
//! script with nothing refusing. The engine now snapshots the protected set
//! on the call's `PreToolUse` and compares on its `PostToolUse`, keyed by the
//! call id.
//!
//! The write itself is the test process's, between the two hook calls: what the
//! command text says is irrelevant to the comparison, which is the point — each
//! row's text names no protected path, so the pre-call gate allows all of them.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;
use batten::capture::Streamed as _;

use std::path::{Path, PathBuf};

use common::{Fixture, run, run_with_stdin, stdout};

const GUARDED: &str = "guarded.txt";
const ORDINARY: &str = "notes.md";

fn fixture(name: &str) -> PathBuf {
    // The `[[verb]]` row makes the policy adjudicable (`mediated_admission.rs`
    // records why); it matches none of the calls below.
    Fixture::new(name)
        .config(
            "version = 1\n\
             protected = [\"guarded.txt\"]\n\n\
             [[verb]]\n\
             verb = \"shred\"\n\
             effect = \"write\"\n\
             redirect = \"write through the surface that owns the file\"\n",
        )
        .file(GUARDED, "guarded\n")
        .file(ORDINARY, "not protected\n")
        .git()
        .base_commit()
        .build()
}

fn payload(event: &str, call: &str, command: &str) -> String {
    let escaped = serde_json::to_string(command).expect("a command is encodable");
    let response = if event == "PostToolUse" {
        ",\"tool_response\":{\"stdout\":\"\",\"stderr\":\"\",\"interrupted\":false}"
    } else {
        ""
    };
    format!(
        "{{\"hook_event_name\":\"{event}\",\"session_id\":\"s1\",\"tool_use_id\":\"{call}\",\
         \"tool_name\":\"Bash\",\"tool_input\":{{\"command\":{escaped}}}{response}}}"
    )
}

/// Run one call through both hooks with `write` between them, returning the
/// post-call exit code and what it printed.
///
/// The bytes written are distinct per call: the comparison is by content
/// (CLOUD-2789), so rewriting the bytes a previous row already left is no write.
fn around(dir: &Path, call: &str, command: &str, write: &str) -> (Option<i32>, String) {
    around_with(dir, call, command, |dir| {
        std::fs::write(dir.join(write), format!("changed by {call}\n")).expect("the write lands");
    })
}

/// [`around`] with the between-hooks effect supplied by the caller.
fn around_with(
    dir: &Path,
    call: &str,
    command: &str,
    effect: impl FnOnce(&Path),
) -> (Option<i32>, String) {
    let pre = run_with_stdin(
        dir,
        &["adjudicate", "--harness", "claude-code"],
        &payload("PreToolUse", call, command),
    );
    assert!(
        !stdout(&pre).contains("\"deny\""),
        "the command names no protected path, so the pre-call gate allows it: {command}\n{}",
        stdout(&pre)
    );
    effect(dir);
    let post = run_with_stdin(
        dir,
        &["adjudicate", "--harness", "claude-code"],
        &payload("PostToolUse", call, command),
    );
    (
        post.status.code(),
        format!("{}{}", stdout(&post), String::from_utf8_lossy(&post.stderr)),
    )
}

/// Every spelling that writes the protected path without naming it is refused
/// after the fact, naming the path, the `git restore` that undoes it, and the
/// override route.
///
/// Fails by: `true` in place of `restorable.is_empty()`, which drops the restore
/// clause for a path whose bytes differ from `HEAD` (CLOUD-2923).
#[test]
fn an_unnamed_protected_write_is_refused_after_the_fact() {
    let dir = fixture("protected-escape-refused");
    for (at, command) in [
        "python3 tool.py",
        "sed -i s/guarded/changed/ \"$TARGET\"",
        "cp /tmp/draft ./",
        "printf changed | tee \"$TARGET\"",
        "echo changed > \"$TARGET\"",
    ]
    .into_iter()
    .enumerate()
    {
        let (code, said) = around(&dir, &format!("t{at}"), command, GUARDED);
        assert_eq!(code, Some(2), "{command}: {said}");
        assert!(said.contains("\"decision\":\"block\""), "{command}: {said}");
        assert!(
            said.contains("path write refused at guarded.txt"),
            "{command}: the refusal names the path: {said}"
        );
        assert!(
            said.contains("run git restore guarded.txt; "),
            "{command}: the bytes differ from HEAD, so the restore is prescribed (CLOUD-2923): {said}"
        );
        assert!(
            said.contains("batten override request --rule 'protected-mutation'"),
            "{command}: and the override route: {said}"
        );
    }
}

/// A write a spent admission names passes: the admission is the record a
/// deliberate protected write leaves.
#[test]
fn an_admitted_protected_write_passes() {
    let dir = fixture("protected-escape-admitted");
    let subject = "guarded.txt python3";
    let answers = "precondition=the owning surface cannot express this write\n\
                   lost=the fixture's guarded file stays stale\n\
                   rejected-route=the redirect names a surface this case does not have\n";
    let issued = run_with_stdin(
        &dir,
        &[
            "override",
            "request",
            "--rule",
            "protected-mutation",
            "--verdict",
            "path write refused",
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
    let admission = stdout(&issued)
        .split_whitespace()
        .last()
        .unwrap_or_default()
        .to_owned();
    let spent = run(
        &dir,
        &[
            "override",
            "spend",
            "--admission",
            &admission,
            "--rule",
            "protected-mutation",
            "--verdict",
            "path write refused",
            "--subject",
            subject,
        ],
    );
    assert!(
        spent.status.success(),
        "{}",
        String::from_utf8_lossy(&spent.stderr)
    );
    let (code, said) = around(&dir, "t-admitted", "python3 tool.py", GUARDED);
    assert_eq!(
        code,
        Some(0),
        "a spent admission naming the path admits it: {said}"
    );
}

/// A write to an unprotected path is none of this.
#[test]
fn an_unprotected_write_passes() {
    let dir = fixture("protected-escape-ordinary");
    let (code, said) = around(&dir, "t-ordinary", "python3 tool.py", ORDINARY);
    assert_eq!(code, Some(0), "{said}");
    assert!(!said.contains("path write refused"), "{said}");
}

/// A call that `cd`s below the root changes nothing protected, so its post-call
/// hook, which runs in the directory the call left behind, refuses nothing.
///
/// Measured on #1276: the snapshot carried its root as `.`, so a post-call hook
/// in `target/debug/incremental` re-read the protected set there, found none of
/// it, and refused every protected path as changed by a read-only `du`.
#[test]
fn a_call_that_moves_below_the_root_changes_nothing_protected() {
    let dir = fixture("protected-escape-moved-cwd");
    let below = dir.join("deep/below");
    std::fs::create_dir_all(&below).expect("a directory below the root");
    let command = "cd deep/below && ls";
    let pre = run_with_stdin(
        &dir,
        &["adjudicate", "--harness", "claude-code"],
        &payload("PreToolUse", "call-moved", command),
    );
    assert!(!stdout(&pre).contains("\"deny\""), "{}", stdout(&pre));
    let post = run_with_stdin(
        &below,
        &["adjudicate", "--harness", "claude-code"],
        &payload("PostToolUse", "call-moved", command),
    );
    let said = format!("{}{}", stdout(&post), String::from_utf8_lossy(&post.stderr));
    assert!(!said.contains("path write refused"), "{said}");
}

/// ONLY AN EXECUTED CALL'S POST-CALL HOOK COMPARES. A `PostToolUse` for any
/// other tool carrying the same call id refuses nothing and leaves the
/// snapshot standing, so the shell call's own post-call hook still judges it.
///
/// Fails by: the event-or-operation guard joined with `&&`, so a read's
/// post-call hook consumes the snapshot and refuses the write as its own.
#[test]
fn only_an_executed_calls_post_hook_compares() {
    let dir = fixture("protected-escape-other-tool");
    let command = "python3 tool.py";
    let pre = run_with_stdin(
        &dir,
        &["adjudicate", "--harness", "claude-code"],
        &payload("PreToolUse", "call-shared", command),
    );
    assert!(!stdout(&pre).contains("\"deny\""), "{}", stdout(&pre));
    std::fs::write(dir.join(GUARDED), "changed\n").expect("the write lands");
    let read = format!(
        "{{\"hook_event_name\":\"PostToolUse\",\"session_id\":\"s1\",\"tool_use_id\":\"call-shared\",\
         \"tool_name\":\"Read\",\"tool_input\":{{\"file_path\":{}}},\"tool_response\":{{}}}}",
        serde_json::to_string(ORDINARY).expect("a path is encodable")
    );
    let other = run_with_stdin(&dir, &["adjudicate", "--harness", "claude-code"], &read);
    let said = format!(
        "{}{}",
        stdout(&other),
        String::from_utf8_lossy(&other.stderr)
    );
    assert!(
        !said.contains("path write refused"),
        "a read refuses nothing: {said}"
    );
    let post = run_with_stdin(
        &dir,
        &["adjudicate", "--harness", "claude-code"],
        &payload("PostToolUse", "call-shared", command),
    );
    let said = format!("{}{}", stdout(&post), String::from_utf8_lossy(&post.stderr));
    assert!(
        said.contains("path write refused at guarded.txt"),
        "the shell call's own post-call hook still judges it: {said}"
    );
}

/// Replace the guarded file with `body` through a new inode, the way hk's
/// pre-commit stash/restore rewrites an unstaged change.
fn rewrite_via_rename(dir: &Path, body: &str) {
    let staging = dir.join("guarded.staging");
    std::fs::write(&staging, body).expect("the staging write lands");
    std::fs::rename(&staging, dir.join(GUARDED)).expect("the rename lands");
}

/// THE INCIDENT (CLOUD-2789). A backgrounded `git commit` is live; its hk
/// pre-commit hook stashes and restores the unstaged protected file while an
/// unrelated foreground call runs. The file's bytes after equal its bytes
/// before, so the foreground call wrote nothing protected.
///
/// Fails by: the comparison reading stat (mtime, inode) rather than content.
#[test]
fn a_protected_file_restored_to_its_own_bytes_is_no_write() {
    let dir = fixture("protected-escape-restored");
    std::fs::write(dir.join(GUARDED), "an admitted, unstaged edit\n").expect("the edit lands");
    let background = run_with_stdin(
        &dir,
        &["adjudicate", "--harness", "claude-code"],
        &payload("PreToolUse", "call-background", "git commit -m wip"),
    );
    assert!(
        !stdout(&background).contains("\"deny\""),
        "{}",
        stdout(&background)
    );
    let (code, said) = around_with(&dir, "call-foreground", "rm -rf scratch", |dir| {
        rewrite_via_rename(dir, "");
        rewrite_via_rename(dir, "an admitted, unstaged edit\n");
    });
    assert_eq!(code, Some(0), "same bytes before and after: {said}");
    assert!(!said.contains("path write refused"), "{said}");
}

/// THE DIGEST CACHE NEVER HIDES A WRITE. Call A warms the cache with the file
/// at X; the file is changed to Y between calls; call B writes X back. B's
/// pre-call must re-read Y (its stat moved since the cache), so B's change
/// Y -> X is a write.
///
/// Fails by: the pre-call snapshot reusing a cached digest without comparing
/// the stat it was taken under, which hands B the stale X and passes it.
#[test]
fn a_stale_digest_cache_never_hides_a_write() {
    let dir = fixture("protected-escape-stale-cache");
    std::fs::write(dir.join(GUARDED), "x\n").expect("the file starts at x");
    let (code, said) = around_with(&dir, "call-warm", "ls", |_| {});
    assert_eq!(code, Some(0), "nothing changed: {said}");
    rewrite_via_rename(&dir, "y\n");
    let (code, said) = around_with(&dir, "call-back", "python3 tool.py", |dir| {
        rewrite_via_rename(dir, "x\n");
    });
    assert_eq!(code, Some(2), "y -> x is a write: {said}");
    assert!(said.contains("path write refused at guarded.txt"), "{said}");
}

/// A pre-call snapshot keeps the digest cache it lends the next call.
///
/// Fails by: the cache path lost, or written only when unchanged.
#[test]
fn a_pre_call_snapshot_writes_its_digest_cache() {
    let dir = fixture("protected-escape-digest-cache");
    let cache = dir.join(".git/batten-facts/protected-watch/digests");
    assert!(!cache.exists(), "premise: no cache before the first call");
    let (code, said) = around_with(&dir, "call-cache", "ls", |_| {});
    assert_eq!(code, Some(0), "{said}");
    let digests: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&cache).expect("the cache is written"))
            .unwrap();
    assert!(digests.get(GUARDED).is_some(), "{digests}");
}

/// ONLY A SHELL CALL IS SNAPSHOTTED BEFORE IT RUNS. A pre-call hook for any
/// other tool leaves no snapshot under its call id; a shell call's does.
///
/// Fails by: the operation-or-denial guard of `snapshot_protected` joined with
/// `&&`, so a read's pre-call hook hashes the protected set and leaves a
/// snapshot no post-call hook ever consumes (CLOUD-2789).
#[test]
fn only_a_shell_calls_pre_hook_snapshots() {
    let dir = fixture("protected-escape-read-snapshot");
    let watch = dir.join(".git/batten-facts/protected-watch");
    let read = format!(
        "{{\"hook_event_name\":\"PreToolUse\",\"session_id\":\"s1\",\"tool_use_id\":\"call-read\",\
         \"tool_name\":\"Read\",\"tool_input\":{{\"file_path\":{}}}}}",
        serde_json::to_string(ORDINARY).expect("a path is encodable")
    );
    let pre = run_with_stdin(&dir, &["adjudicate", "--harness", "claude-code"], &read);
    assert!(!stdout(&pre).contains("\"deny\""), "{}", stdout(&pre));
    assert!(
        !watch.join("call-read.json").exists(),
        "a read's pre-call hook snapshots nothing"
    );
    let shell = run_with_stdin(
        &dir,
        &["adjudicate", "--harness", "claude-code"],
        &payload("PreToolUse", "call-shell", "ls"),
    );
    assert!(!stdout(&shell).contains("\"deny\""), "{}", stdout(&shell));
    assert!(
        watch.join("call-shell.json").exists(),
        "premise: a shell call's pre-call hook snapshots under its call id"
    );
}

/// NO HOLE FOR A LIVE BACKGROUND TASK. A foreground call that really changes a
/// protected file's bytes is refused whether or not a backgrounded call of the
/// same session is still running: nothing the hook can observe says which
/// process wrote, so a live background task is never a reason to look away.
///
/// Fails by: any rule that excuses a change while another call's snapshot is
/// outstanding.
#[test]
fn a_real_write_while_a_background_call_is_live_is_refused() {
    let dir = fixture("protected-escape-background-live");
    let background = run_with_stdin(
        &dir,
        &["adjudicate", "--harness", "claude-code"],
        &payload("PreToolUse", "call-background", "git commit -m wip"),
    );
    assert!(
        !stdout(&background).contains("\"deny\""),
        "{}",
        stdout(&background)
    );
    let (code, said) = around_with(&dir, "call-foreground", "python3 tool.py", |dir| {
        rewrite_via_rename(dir, "really changed\n");
    });
    assert_eq!(code, Some(2), "{said}");
    assert!(said.contains("path write refused at guarded.txt"), "{said}");
}

/// Commit the guarded file at `body` (or its removal, for `None`) on `main`,
/// as another session's pushed work arrives: committed, then published under
/// `refs/remotes/origin/main` (CLOUD-2923).
fn publish_guarded(dir: &Path, body: Option<&str>) {
    match body {
        Some(body) => {
            std::fs::write(dir.join(GUARDED), body).expect("the guarded write lands");
            common::git_in(dir, &["add", GUARDED]);
        }
        None => {
            common::git_in(dir, &["rm", "-q", GUARDED]);
        }
    }
    common::git_in(dir, &["commit", "-q", "-m", "pushed by another session"]);
    publish_origin_main(dir, Published::BeforeTheCall);
}

/// When a remote-tracking ref moved, as its reflog stamps it.
#[derive(Clone, Copy)]
enum Published<'call> {
    /// An hour before the call: history that was already on a remote.
    BeforeTheCall,
    /// Inside the named call, stamped at the very second its pre-call snapshot
    /// recorded as `at`: the boundary second, which must count as the call's.
    InTheCall(&'call str),
}

/// The `at` the pending pre-call snapshot of `call` recorded, read from where
/// `protected_snapshot_path` puts it (CLOUD-2923).
fn snapshot_at(dir: &Path, call: &str) -> i64 {
    let path = dir
        .join(".git/batten-facts/protected-watch")
        .join(format!("{call}.json"));
    let text = std::fs::read_to_string(&path).expect("the pre-call snapshot is pending");
    let snapshot: serde_json::Value = serde_json::from_str(&text).expect("a snapshot is JSON");
    snapshot["at"].as_i64().expect("the snapshot records `at`")
}

/// Point `refs/remotes/origin/main` at `HEAD` the way `git fetch` does, through
/// `update-ref`, so the move is in the ref's reflog — which is where the
/// post-call check reads the pre-call tips from (CLOUD-2923). A fixture whose
/// tip was written to the ref file directly has no reflog, and counts as no
/// tip at all.
fn publish_origin_main(dir: &Path, when: Published<'_>) {
    publish_ref(dir, "refs/remotes/origin/main", "HEAD", when);
}

/// Point `name` at `target` through `update-ref`, its reflog entry stamped as
/// `when` says.
///
/// A before-the-call publish DROPS THE REF FIRST. `base_commit` pins
/// `origin/main` at `HEAD` with no reflog, and an `update-ref` to the value a
/// ref already holds writes no entry — so a publish at the base commit left no
/// tip at all, and a case meant to stand on a pushed `HEAD` silently did not.
/// The reflog is asserted, so that premise fails by name.
fn publish_ref(dir: &Path, name: &str, target: &str, when: Published<'_>) {
    let stamp = match when {
        Published::BeforeTheCall => {
            common::git_in(dir, &["update-ref", "-d", name]);
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            i64::try_from(now).expect("the clock fits") - 3600
        }
        Published::InTheCall(call) => snapshot_at(dir, call),
    };
    let mut update = common::git_command(dir, &["update-ref", name, target]);
    update.env("GIT_COMMITTER_DATE", format!("@{stamp} +0000"));
    let output = update.streamed_output().expect("run git update-ref");
    assert!(output.status.success(), "{output:?}");
    assert!(
        dir.join(".git/logs").join(name).exists(),
        "premise: {name} has a reflog entry for this publish"
    );
}

/// THE INCIDENT (CLOUD-2923). Another session pushed a protected change; this
/// clone is behind it, and fast-forwards. The file now equals the committed blob
/// at a `HEAD` a pre-call remote tip already reached, so nobody wrote it here.
///
/// Fails by: the post-call comparison reading any digest change as an unnamed
/// write, which refused this and prescribed a `git restore` that restores nothing.
#[test]
fn a_fast_forward_to_a_remote_tip_is_no_protected_write() {
    let dir = fixture("protected-escape-fast-forward");
    publish_guarded(&dir, Some("pushed elsewhere\n"));
    common::git_in(&dir, &["reset", "-q", "--hard", "HEAD~1"]);
    let command = "git merge --ff-only -q origin/main";
    let (code, said) = around_with(&dir, "call-ff", command, |dir| {
        common::git_in(dir, &["merge", "--ff-only", "-q", "origin/main"]);
    });
    assert_eq!(code, Some(0), "a fast-forward to pushed history: {said}");
    assert!(!said.contains("path write refused"), "{said}");
}

/// A fast-forward that REMOVES a protected path is the same act: absent from the
/// working tree and from the committed tree alike.
///
/// Fails by: an absent file read as differing from `HEAD`.
#[test]
fn a_fast_forward_that_deletes_a_protected_path_is_no_protected_write() {
    let dir = fixture("protected-escape-fast-forward-delete");
    publish_guarded(&dir, None);
    common::git_in(&dir, &["reset", "-q", "--hard", "HEAD~1"]);
    let command = "git merge --ff-only -q origin/main";
    let (code, said) = around_with(&dir, "call-ff-delete", command, |dir| {
        common::git_in(dir, &["merge", "--ff-only", "-q", "origin/main"]);
    });
    assert_eq!(code, Some(0), "{said}");
    assert!(!said.contains("path write refused"), "{said}");
}

/// THE CLOUD-2304 ESCAPE STAYS SHUT. A call that writes a protected path and
/// commits it makes a commit no pre-call remote tip reaches, so it is refused —
/// and since the file equals `HEAD`, the refusal prescribes no `git restore`.
///
/// Fails by: excusing any change that equals `HEAD` (the refusal is lost), or
/// a reason that still prescribes the no-op restore.
#[test]
fn a_protected_write_committed_in_the_call_is_still_refused() {
    let dir = fixture("protected-escape-committed-in-call");
    let (code, said) = around_with(&dir, "call-commit", "python3 tool.py", |dir| {
        std::fs::write(dir.join(GUARDED), "authored in the call\n").expect("the write lands");
        common::git_in(dir, &["commit", "-q", "-am", "laundered"]);
    });
    assert_eq!(code, Some(2), "{said}");
    assert!(said.contains("path write refused at guarded.txt"), "{said}");
    assert!(
        !said.contains("run git restore"),
        "the file equals HEAD, so a restore is a no-op: {said}"
    );
    assert!(
        said.contains("batten override request --rule 'protected-mutation'"),
        "the override route stays: {said}"
    );
}

/// THE TIPS ARE THE PRE-CALL ONES. A call that commits a protected write and
/// then points a remote-tracking ref at it has not reached pushed history.
///
/// The ref's move is stamped at the snapshot's own `at`, the second the call
/// began in: reflog stamps are whole seconds, and that second is read the way
/// that excuses less, on every run rather than only when the clock ticks.
///
/// Fails by: reading the remote tips as they stand after the call, rather than
/// as their reflogs say they stood when it began; or `<=` in place of `<` at
/// `tip_before`'s stamp comparison, which counts the boundary second as before.
#[test]
fn a_commit_published_to_a_remote_ref_inside_the_call_is_still_refused() {
    let dir = fixture("protected-escape-forged-tip");
    let (code, said) = around_with(&dir, "call-forge", "python3 tool.py", |dir| {
        std::fs::write(dir.join(GUARDED), "authored in the call\n").expect("the write lands");
        common::git_in(dir, &["commit", "-q", "-am", "laundered"]);
        publish_origin_main(dir, Published::InTheCall("call-forge"));
    });
    assert_eq!(code, Some(2), "{said}");
    assert!(said.contains("path write refused at guarded.txt"), "{said}");
}

/// A REMOTE TIP WITH NO REFLOG IS NO TIP. A call that commits a protected write
/// and writes the ref file itself leaves no record of when the ref moved, so
/// nothing says the commit was on a remote before the call.
///
/// Fails by: reading a ref with no reflog at its current value.
#[test]
fn a_commit_written_into_a_remote_ref_file_inside_the_call_is_still_refused() {
    let dir = fixture("protected-escape-forged-loose-tip");
    let (code, said) = around_with(&dir, "call-forge-loose", "python3 tool.py", |dir| {
        std::fs::write(dir.join(GUARDED), "authored in the call\n").expect("the write lands");
        common::git_in(dir, &["commit", "-q", "-am", "laundered"]);
        common::pin_origin_main(dir);
    });
    assert_eq!(code, Some(2), "{said}");
    assert!(said.contains("path write refused at guarded.txt"), "{said}");
}

/// FORWARD ONLY. A reset back to an older pushed commit rolls the protected file
/// back to content nobody wrote in this call, and that is still a change to it.
///
/// Fails by: dropping the forward-only clause, so any ancestor of any remote tip
/// excuses a one-call policy rollback (the L2 cold read's hole).
#[test]
fn a_reset_backwards_to_a_pushed_ancestor_is_still_refused() {
    let dir = fixture("protected-escape-reset-back");
    publish_guarded(&dir, Some("the current policy\n"));
    let command = "git reset -q --hard HEAD~1";
    let (code, said) = around_with(&dir, "call-reset-back", command, |dir| {
        common::git_in(dir, &["reset", "-q", "--hard", "HEAD~1"]);
    });
    assert_eq!(code, Some(2), "{said}");
    assert!(said.contains("path write refused at guarded.txt"), "{said}");
}

/// FORWARD TO A STRICT ANCESTOR OF A PUSHED TIP. A move that lands short of the
/// tip, on a commit the tip already reaches, is still only history that was on
/// a remote before the call. The check reads `HEAD`, the refs and the file
/// bytes, never the command, so this stands for `switch` and `rebase` too.
///
/// Fails by: anything that excuses only a `HEAD` equal to a tip, which leaves
/// the walk below a tip (`head_moved_onto`'s hidden-tips walk) unreached.
#[test]
fn a_forward_move_to_a_strict_ancestor_of_a_pushed_tip_is_no_protected_write() {
    let dir = fixture("protected-escape-forward-ancestor");
    publish_guarded(&dir, Some("pushed elsewhere\n"));
    std::fs::write(dir.join(ORDINARY), "pushed after it\n").expect("the ordinary write lands");
    common::git_in(&dir, &["commit", "-q", "-am", "pushed after it"]);
    publish_origin_main(&dir, Published::BeforeTheCall);
    common::git_in(&dir, &["reset", "-q", "--hard", "HEAD~2"]);
    let command = "git reset -q --hard origin/main~1";
    let (code, said) = around_with(&dir, "call-forward-ancestor", command, |dir| {
        common::git_in(dir, &["reset", "-q", "--hard", "origin/main~1"]);
    });
    assert_eq!(code, Some(0), "a strict ancestor of a pushed tip: {said}");
    assert!(!said.contains("path write refused"), "{said}");
}

/// A REF THE CALL MOVED COUNTS AT ITS VALUE BEFORE THE CALL. The remote tip was
/// written with no reflog before the call; the call fast-forwards onto it and
/// then moves the ref away. The ref's one reflog entry is the call's own, and
/// its previous value is where the ref stood when the call began.
///
/// Fails by: reading a ref the call moved at its current value, or dropping the
/// oldest entry's previous value (`tip_before`'s `earliest_previous`), either of
/// which leaves no tip reaching `HEAD`.
#[test]
fn a_ref_the_call_moved_counts_at_its_value_before_the_call() {
    let dir = fixture("protected-escape-ref-moved-in-call");
    std::fs::write(dir.join(GUARDED), "pushed elsewhere\n").expect("the guarded write lands");
    common::git_in(&dir, &["commit", "-q", "-am", "pushed by another session"]);
    common::pin_origin_main(&dir);
    common::git_in(&dir, &["reset", "-q", "--hard", "HEAD~1"]);
    let call = "call-ref-moved";
    let command = "git merge --ff-only -q origin/main";
    let (code, said) = around_with(&dir, call, command, |dir| {
        common::git_in(dir, &["merge", "--ff-only", "-q", "origin/main"]);
        publish_ref(
            dir,
            "refs/remotes/origin/main",
            "HEAD~1",
            Published::InTheCall(call),
        );
    });
    assert_eq!(
        code,
        Some(0),
        "the tip stood at HEAD when the call began: {said}"
    );
    assert!(!said.contains("path write refused"), "{said}");
}

/// A SHELL DELETE OF A PROTECTED PATH `HEAD` STILL HAS is a change to it, even
/// on a pushed `HEAD`: the file is absent here and present in the committed
/// tree, so it differs from `HEAD`, and `git restore` brings it back.
///
/// Fails by: `||` in place of `&&` in `paths_at_head`'s absent-file arm, which
/// reads any absent file as equal to `HEAD` and drops the restore that undoes
/// the delete.
#[test]
fn a_shell_delete_of_a_protected_path_head_still_has_is_refused() {
    let dir = fixture("protected-escape-shell-delete");
    publish_origin_main(&dir, Published::BeforeTheCall);
    let (code, said) = around_with(&dir, "call-delete", "python3 tool.py", |dir| {
        std::fs::remove_file(dir.join(GUARDED)).expect("the delete lands");
    });
    assert_eq!(code, Some(2), "{said}");
    assert!(said.contains("path write refused at guarded.txt"), "{said}");
    assert!(
        said.contains("run git restore guarded.txt; "),
        "HEAD still has the file, so the restore is prescribed: {said}"
    );
}

/// NO MOVE, NO EXCUSE. On a `HEAD` already pushed, a call that rolls an
/// uncommitted protected edit back to `HEAD`'s bytes — `git checkout .`,
/// `git stash`, `git reset --hard`, or a script writing them back — brought no
/// history in, so the rollback is its own write to the path.
///
/// Fails by: reading a `HEAD` equal to the pre-call one as having moved forward
/// onto pushed history (`head_moved_onto`'s `head == before` arm), which excused
/// every path left at `HEAD`'s bytes and erased the edit unseen.
#[test]
fn a_rollback_to_head_bytes_with_head_unmoved_is_still_refused() {
    let dir = fixture("protected-escape-unmoved-rollback");
    publish_origin_main(&dir, Published::BeforeTheCall);
    std::fs::write(dir.join(GUARDED), "an edit in progress\n").expect("the edit lands");
    let (code, said) = around_with(&dir, "call-unmoved-rollback", "python3 tool.py", |dir| {
        common::git_in(dir, &["checkout", "-q", "--", GUARDED]);
    });
    assert_eq!(code, Some(2), "HEAD did not move: {said}");
    assert!(said.contains("path write refused at guarded.txt"), "{said}");
    assert!(
        !said.contains("run git restore"),
        "the file equals HEAD, so a restore is a no-op: {said}"
    );
}

/// An UNTRACKED protected file deleted with `HEAD` unmoved is the call's own
/// delete: absent from the tree and from `HEAD` alike, but no move removed it.
///
/// Fails by: excusing a path absent from both on an unmoved pushed `HEAD`.
#[test]
fn deleting_an_untracked_protected_file_with_head_unmoved_is_still_refused() {
    let dir = fixture("protected-escape-unmoved-untracked-delete");
    common::git_in(&dir, &["rm", "-q", "--cached", GUARDED]);
    common::git_in(&dir, &["commit", "-q", "-m", "untrack the guarded file"]);
    publish_origin_main(&dir, Published::BeforeTheCall);
    assert!(dir.join(GUARDED).exists(), "premise: on disk, untracked");
    let (code, said) = around_with(&dir, "call-untracked-delete", "python3 tool.py", |dir| {
        std::fs::remove_file(dir.join(GUARDED)).expect("the delete lands");
    });
    assert_eq!(code, Some(2), "{said}");
    assert!(said.contains("path write refused at guarded.txt"), "{said}");
}

/// A ROLLBACK BESIDE A FAST-FORWARD THAT LEFT THE PATH ALONE. The call moves
/// `HEAD` onto pushed history that never touched the protected file, and also
/// rolls an uncommitted edit to it back to `HEAD`'s bytes. Only what the move
/// changed is history's; this path it did not change.
///
/// Fails by: excusing every path at `HEAD`'s bytes once `HEAD` moved onto
/// pushed history, rather than the paths the move itself changed.
#[test]
fn a_rollback_beside_a_fast_forward_that_left_the_path_alone_is_still_refused() {
    let dir = fixture("protected-escape-rollback-beside-ff");
    std::fs::write(dir.join(ORDINARY), "pushed elsewhere\n").expect("the ordinary write lands");
    common::git_in(&dir, &["commit", "-q", "-am", "pushed by another session"]);
    publish_origin_main(&dir, Published::BeforeTheCall);
    common::git_in(&dir, &["reset", "-q", "--hard", "HEAD~1"]);
    std::fs::write(dir.join(GUARDED), "an edit in progress\n").expect("the edit lands");
    let (code, said) = around_with(&dir, "call-rollback-beside-ff", "python3 tool.py", |dir| {
        common::git_in(dir, &["checkout", "-q", "--", GUARDED]);
        common::git_in(dir, &["merge", "--ff-only", "-q", "origin/main"]);
    });
    assert_eq!(code, Some(2), "the move never touched guarded.txt: {said}");
    assert!(said.contains("path write refused at guarded.txt"), "{said}");
}
