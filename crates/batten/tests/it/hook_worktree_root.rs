//! Which directory `batten hook` reads its authority from (CLOUD-824).
//!
//! `load_policy` reads `./batten.toml` with no upward walk, so whichever
//! directory answers "where is the repository" decides whether a mediated call
//! is adjudicated at all. Until CLOUD-824 that answer came from a launcher in
//! shell — `.claude/hooks/batten-hook.sh` — which asked git the wrong question:
//!
//! ```text
//! cd "${CLAUDE_PROJECT_DIR:-$(git rev-parse --show-toplevel 2>/dev/null)}"
//! ```
//!
//! `--show-toplevel` is the **worktree's** toplevel. [`batten::git::repo_root`]
//! uses the common dir, which in a linked worktree is the **main** repository
//! root — deliberately, because that "keeps per-repository config and state
//! stable across worktrees". Measured on a constructed pair, the two answers are
//! different directories.
//!
//! So from a linked worktree whose checkout carries no `batten.toml`, the
//! launcher landed on `Policy::declaring_nothing` and allowed every mediated
//! call, silently — no deny, no error, no stderr line, because from the
//! launcher's point of view everything worked. That is verbatim the state the
//! launcher's own comment called the `cd` "the whole defence" against.
//!
//! **The first case here is red on `main`** (CLOUD-418), which is the evidence
//! this is a defect rather than a preference. The rest are the mirrors that stop
//! the fix from being a change only worktrees exercise: the main root, and a
//! subdirectory of it — the case the launcher was actually written for.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Output, Stdio};

use common::{Fixture, git_in};

/// A policy with exactly one deny, so the assertion is unambiguous.
///
/// Not this repository's own `batten.toml`: a test reading the committed file
/// would pass or fail with an edit to production policy.
const ONE_DENY: &str = r#"version = 1

[[rule]]
id = "no-gh-pr-merge"
kind = "shape"
scope = "mediated_call"
severity = "deny"
pattern = "gh pr merge"
reason = "use `mise run land`"
"#;

/// A payload the policy above refuses.
fn banned_payload() -> String {
    serde_json::json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": { "command": "gh pr merge 42" }
    })
    .to_string()
}

fn hook_from(dir: &Path) -> Output {
    let mut command = common::batten();
    command
        .current_dir(dir)
        .args(["adjudicate", "--harness", "claude-code"])
        .env_remove("CLAUDE_PROJECT_DIR")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().expect("spawn batten hook");
    child
        .stdin
        .take()
        .expect("piped stdin")
        .write_all(banned_payload().as_bytes())
        .expect("write payload");
    child.wait_with_output().expect("run batten hook")
}

/// Whether this run refused the call, read through both channels a host reads.
///
/// Exit `2` is the one contract (§7); the JSON body is what Claude Code parses.
/// Asserting on both is what stops a change that satisfies one and not the other.
fn denied(output: &Output) -> bool {
    output.status.code() == Some(2) || String::from_utf8_lossy(&output.stdout).contains("\"deny\"")
}

/// A repository with `batten.toml` committed on `main`, plus a **linked
/// worktree** checked out to a branch that carries none.
///
/// The worktree's emptiness is the normal case rather than a contrivance: a
/// worktree sits at a different ref, and a ref that predates the authority — or
/// a sparse checkout that excludes it — has no `batten.toml` to find.
fn repo_with_bare_worktree(name: &str) -> (PathBuf, PathBuf) {
    let main = Fixture::new(name).file("README.md", "base\n").git().build();
    git_in(&main, &["add", "-A"]);
    git_in(&main, &["commit", "-q", "-m", "base"]);
    // The branch the worktree will sit on, created BEFORE the authority lands,
    // so its tree genuinely lacks the file rather than having it deleted.
    git_in(&main, &["branch", "no-authority"]);
    common::write(&main, "batten.toml", ONE_DENY);
    git_in(&main, &["add", "-A"]);
    git_in(&main, &["commit", "-q", "-m", "authority"]);

    // `scratch` wipes and creates; `git worktree add` wants to create the
    // directory itself, so it is removed again straight away. Going through the
    // one helper is what keeps the path under `target/tmp` with every other
    // fixture rather than inventing a second convention.
    let linked = common::scratch(&format!("{name}-linked"));
    let _ = std::fs::remove_dir_all(&linked);
    git_in(
        &main,
        &[
            "worktree",
            "add",
            "--quiet",
            linked.to_str().unwrap_or_default(),
            "no-authority",
        ],
    );
    (main, linked)
}

#[test]
fn a_linked_worktree_adjudicates_against_the_repositorys_authority() {
    // THE REGRESSION. Red on `main`: the launcher `cd`'d to the worktree, found
    // no `batten.toml`, resolved `Policy::declaring_nothing`, and allowed.
    let (main, linked) = repo_with_bare_worktree("hook-root-linked");
    assert!(
        !linked.join("batten.toml").exists(),
        "the fixture is only a fixture if the worktree carries no authority"
    );
    assert!(
        main.join("batten.toml").exists(),
        "the repository must carry the authority the worktree is missing"
    );
    let output = hook_from(&linked);
    assert!(
        denied(&output),
        "a mediated call from a linked worktree must be judged by the \
         REPOSITORY's authority, not by the worktree's absence of one: {:?} {:?}",
        output.status.code(),
        common::stderr(&output)
    );
}

#[test]
fn the_two_git_questions_really_do_disagree_here() {
    // The premise of the case above, asserted rather than assumed (CLOUD-249):
    // if the fixture's worktree resolved the same directory under both questions
    // there would be nothing for the deny to prove, and the test would pass over
    // a condition it never created.
    let (main, linked) = repo_with_bare_worktree("hook-root-premise");
    let toplevel = git_in(&linked, &["rev-parse", "--show-toplevel"]);
    let common_root = batten::git::repo_root(&linked).expect("the worktree is inside a repository");
    assert_ne!(
        Path::new(toplevel.trim()).canonicalize().ok(),
        common_root.canonicalize().ok(),
        "the launcher's question and `repo_root`'s must differ here, or the \
         regression above is vacuous"
    );
    assert_eq!(
        common_root.canonicalize().ok(),
        main.canonicalize().ok(),
        "`repo_root` from a linked worktree is the main repository root"
    );
}

#[test]
fn the_main_root_is_unchanged() {
    // The mirror the row asks for: this must not become a change only worktrees
    // exercise.
    let (main, _linked) = repo_with_bare_worktree("hook-root-main");
    assert!(denied(&hook_from(&main)), "the main root still adjudicates");
}

#[test]
fn a_subdirectory_of_the_main_root_adjudicates_too() {
    // The case the launcher's `cd` was actually written for — "a hook fired
    // while the session's cwd is `crates/batten`" — and the reason deleting the
    // launcher is not a regression: the defence moved into the binary rather
    // than away.
    let (main, _linked) = repo_with_bare_worktree("hook-root-subdir");
    let nested = main.join("crates").join("batten");
    std::fs::create_dir_all(&nested).expect("create a nested directory");
    assert!(
        denied(&hook_from(&nested)),
        "a hook fired from a subdirectory must still find the repository's \
         authority — this is what the launcher's `cd` bought and what \
         `git::repo_root` buys now"
    );
}

#[test]
fn outside_a_repository_the_call_is_allowed_rather_than_refused() {
    // The fail-open half, unchanged and load-bearing. `batten hook` is
    // registered once and then mediates every call in whatever directory the
    // agent is in, most of them outside any repository. Refusing there would
    // make Batten the reason ordinary work stops (CLOUD-70) — the same posture
    // the launcher had at this point (`|| exit 0`).
    let dir = common::scratch_outside_tree("hook-root", "no-repository");
    let output = hook_from(&dir);
    assert!(
        !denied(&output),
        "a directory with no repository and no authority allows: {:?}",
        common::stderr(&output)
    );
}

/// A policy that declares nothing to refuse: the worktree's own authority in
/// [`worktree_with_its_own_authority`], so a call it judges is allowed.
const DECLARES_NOTHING: &str = "version = 1\n";

/// A repository whose `main` carries [`ONE_DENY`], plus a linked worktree on a
/// branch whose OWN `batten.toml` declares nothing (CLOUD-2532).
///
/// The opposite of [`repo_with_bare_worktree`]: there the worktree has no
/// authority and must fall through to the repository's; here it has one, and
/// must be judged by it from anywhere inside its tree.
fn worktree_with_its_own_authority(name: &str) -> (PathBuf, PathBuf) {
    let main = Fixture::new(name).file("README.md", "base\n").git().build();
    git_in(&main, &["add", "-A"]);
    git_in(&main, &["commit", "-q", "-m", "base"]);
    git_in(&main, &["branch", "own-authority"]);
    common::write(&main, "batten.toml", ONE_DENY);
    git_in(&main, &["add", "-A"]);
    git_in(&main, &["commit", "-q", "-m", "authority"]);

    let linked = common::scratch(&format!("{name}-linked"));
    let _ = std::fs::remove_dir_all(&linked);
    git_in(
        &main,
        &[
            "worktree",
            "add",
            "--quiet",
            linked.to_str().unwrap_or_default(),
            "own-authority",
        ],
    );
    common::write(&linked, "batten.toml", DECLARES_NOTHING);
    git_in(&linked, &["add", "-A"]);
    git_in(
        &linked,
        &["commit", "-q", "-m", "the branch's own authority"],
    );
    (main, linked)
}

#[test]
fn two_worktrees_with_different_configs_get_different_verdicts() {
    // THE REGRESSION (CLOUD-2532, reproduced 2026-11-04). A desktop session
    // runs in a linked worktree, and its shell stands wherever the agent last
    // `cd`'d. From a subdirectory `anchor` found no `./batten.toml` and fell
    // straight to `repo_root` — the MAIN checkout — so the branch's calls were
    // judged by another branch's config, and a fix written into the worktree's
    // own `batten.toml` could not unblock it.
    let (main, linked) = worktree_with_its_own_authority("hook-root-own");
    let nested = linked.join("src").join("deep");
    std::fs::create_dir_all(&nested).expect("create a nested directory");

    assert!(
        denied(&hook_from(&main)),
        "the main checkout is judged by its own deny"
    );
    assert!(
        !denied(&hook_from(&linked)),
        "the worktree's root is judged by the worktree's authority"
    );
    let output = hook_from(&nested);
    assert!(
        !denied(&output),
        "a call from a subdirectory of a linked worktree carrying its own \
         `batten.toml` must be judged by THAT file, not the main checkout's: \
         {:?} {:?}",
        output.status.code(),
        common::stderr(&output)
    );
}

#[test]
fn a_session_that_stood_in_the_main_checkout_is_judged_by_the_worktree_it_moves_to() {
    // The session-record shape of the same incident. The record answers only
    // when the cwd resolves no authority, so once the worktree's own file is
    // found from any depth, an earlier stand in the main checkout cannot
    // override it. Red before the fix: `anchor` resolved `src` to the main
    // checkout, which carries a file, so the record was never even consulted.
    let (main, linked) = worktree_with_its_own_authority("hook-root-own-session");
    let nested = linked.join("src");
    std::fs::create_dir_all(&nested).expect("create a nested directory");
    let session = "cloud-2532-moved";
    assert!(denied(&hook_in_session(&main, session)));
    assert!(
        !denied(&hook_in_session(&nested, session)),
        "the worktree's authority answers for a call made inside it"
    );
}

/// The same refused call, carrying the session it belongs to (CLOUD-2204).
fn hook_in_session(dir: &Path, session: &str) -> Output {
    let payload = serde_json::json!({
        "session_id": session,
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": { "command": "gh pr merge 42" }
    })
    .to_string();
    let mut command = common::batten();
    command
        .current_dir(dir)
        .args(["adjudicate", "--harness", "claude-code"])
        .env_remove("CLAUDE_PROJECT_DIR")
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

#[test]
fn a_call_outside_the_repository_is_judged_by_the_session_authority() {
    // THE REGRESSION, measured 2026-10-11. A host launched above its checkouts
    // snaps the shell back to that parent after a `cd` leaves a working
    // directory; from there the cwd resolves no authority, and every later call
    // in the session was allowed by a policy declaring nothing, silently.
    let (main, _linked) = repo_with_bare_worktree("hook-root-session");
    let parent = common::scratch_outside_tree("hook-root", "session-parent");
    let session = "cloud-2204-sticky";
    assert!(
        denied(&hook_in_session(&main, session)),
        "the session first stands in the repository and is judged there"
    );
    let output = hook_in_session(&parent, session);
    assert!(
        denied(&output),
        "a later call from outside any repository is judged by the authority \
         its session last stood in, not by none: {:?} {:?}",
        output.status.code(),
        common::stderr(&output)
    );
}

#[test]
fn a_session_that_never_stood_in_a_repository_stays_fail_open() {
    // CLOUD-70 preserved: the record is a fact about THIS session, so another
    // session's authority never reaches a call it did not make.
    let (main, _linked) = repo_with_bare_worktree("hook-root-other-session");
    let parent = common::scratch_outside_tree("hook-root", "other-session-parent");
    assert!(denied(&hook_in_session(&main, "cloud-2204-resident")));
    assert!(
        !denied(&hook_in_session(&parent, "cloud-2204-stranger")),
        "a session that never resolved an authority must not inherit another's"
    );
}

#[test]
fn a_recorded_root_that_lost_its_authority_is_not_used() {
    // A deleted or moved checkout is never answered for by its ghost.
    let (main, _linked) = repo_with_bare_worktree("hook-root-ghost");
    let parent = common::scratch_outside_tree("hook-root", "ghost-parent");
    let session = "cloud-2204-ghost";
    assert!(denied(&hook_in_session(&main, session)));
    std::fs::remove_file(main.join("batten.toml")).expect("remove the authority");
    assert!(
        !denied(&hook_in_session(&parent, session)),
        "a recorded root no longer carrying `batten.toml` must not be used"
    );
}

// --- CLOUD-2672: the call's target judges, and the session keeps its home ---

/// A repository config refusing `frobnicate`, for the home cases.
const FROBNICATE_DENY: &str = r#"version = 1

[[rule]]
id = "no-frobnicate"
kind = "shape"
scope = "mediated_call"
severity = "deny"
pattern = "frobnicate"
reason = "frobnicate is refused here"
"#;

/// A parent directory holding no repository, with repositories `a` and `b`
/// under it, each committing its own config.
fn two_repositories(name: &str, a: &str, b: &str) -> (PathBuf, PathBuf, PathBuf) {
    let parent = common::scratch_outside_tree("hook-reach", name);
    let mut made = Vec::new();
    for (sub, config) in [("a", a), ("b", b)] {
        let dir = parent.join(sub);
        std::fs::create_dir_all(&dir).expect("create repository");
        git_in(&dir, &["init", "-q", "-b", "main"]);
        std::fs::write(dir.join("batten.toml"), config).expect("write config");
        std::fs::write(dir.join("f"), "x\n").expect("write file");
        git_in(&dir, &["add", "-A"]);
        git_in(
            &dir,
            &[
                "-c",
                "user.name=t",
                "-c",
                "user.email=t@t",
                "commit",
                "-qm",
                "fix: base",
            ],
        );
        made.push(dir.canonicalize().expect("canonical repository"));
    }
    let parent = parent.canonicalize().expect("canonical parent");
    (parent, made.remove(0), made.remove(0))
}

/// One hook call from `process_cwd`, with the payload's `cwd` where given.
fn hook_call(
    process_cwd: &Path,
    payload_cwd: Option<&Path>,
    session: &str,
    tool: &str,
    tool_input: &serde_json::Value,
) -> Output {
    let mut payload = serde_json::json!({
        "session_id": session,
        "hook_event_name": "PreToolUse",
        "tool_name": tool,
        "tool_input": tool_input,
    });
    if let Some(cwd) = payload_cwd {
        payload["cwd"] = serde_json::json!(cwd);
    }
    let mut command = common::batten();
    command
        .current_dir(process_cwd)
        .args(["adjudicate", "--harness", "claude-code"])
        .env_remove("CLAUDE_PROJECT_DIR")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().expect("spawn batten hook");
    child
        .stdin
        .take()
        .expect("piped stdin")
        .write_all(payload.to_string().as_bytes())
        .expect("write payload");
    child.wait_with_output().expect("run batten hook")
}

fn bash(process_cwd: &Path, cwd: &Path, session: &str, command: &str) -> Output {
    hook_call(
        process_cwd,
        Some(cwd),
        session,
        "Bash",
        &serde_json::json!({ "command": command }),
    )
}

fn shown(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

#[test]
fn a_call_is_judged_by_the_repository_it_targets() {
    let (_, a, b) = two_repositories("reach-judging", DECLARES_NOTHING, ONE_DENY);
    // The payload's cwd beats the process cwd.
    assert!(denied(&bash(&a, &b, "judging", "gh pr merge 42")));
    // A followed `cd` moves the call into the repository that refuses it.
    let crossing = format!("cd {} && gh pr merge 42", b.display());
    assert!(denied(&bash(&a, &a, "judging", &crossing)));
    // Allow control: the same call at home in A.
    assert!(!denied(&bash(&a, &a, "judging", "gh pr merge 42")));
}

#[test]
fn a_visit_to_another_repository_does_not_rehome_the_session() {
    let (parent, a, b) = two_repositories("reach-home", FROBNICATE_DENY, DECLARES_NOTHING);
    let _ = bash(&parent, &a, "home-a", "ls");
    let _ = bash(&parent, &b, "home-a", "ls");
    assert!(
        denied(&bash(&parent, &parent, "home-a", "frobnicate")),
        "the visit to B must not re-home a session that started in A"
    );
    // Allow control: a session that started in B is judged by B from the parent.
    let _ = bash(&parent, &b, "home-b", "ls");
    assert!(!denied(&bash(&parent, &parent, "home-b", "frobnicate")));
}

/// A's config, arming the reach gate at `deny`.
fn armed() -> String {
    format!(
        "{DECLARES_NOTHING}\n{}",
        common::native_row("repository-reach", "deny")
    )
}

fn edit(path: &Path) -> serde_json::Value {
    serde_json::json!({"file_path": path, "old_string": "x", "new_string": "y"})
}

#[test]
fn a_reach_out_of_the_home_is_refused_only_where_the_home_arms_it() {
    let (parent, a, b) = two_repositories("reach-armed", &armed(), DECLARES_NOTHING);
    let (_, unarmed, _) = two_repositories("reach-unarmed", DECLARES_NOTHING, DECLARES_NOTHING);
    #[cfg(unix)]
    std::os::unix::fs::symlink(b.join("f"), a.join("link")).expect("symlink into B");
    let outside = parent.join("plain");
    std::fs::create_dir_all(&outside).expect("a directory in no repository");
    let crossings = [
        format!("cd {} && touch x", b.display()),
        format!("pushd {} && touch x", b.display()),
        format!("cd {}", b.display()),
        format!("cd {} || exit", b.display()),
        format!("git -C {} status", b.display()),
        format!("git -c a=b -C {} status", b.display()),
        format!("git --git-dir={}/.git status", b.display()),
        format!("git --work-tree {} status", b.display()),
    ];
    for (home, session, refused) in [(&a, "armed", true), (&unarmed, "unarmed", false)] {
        let _ = bash(home, home, session, "ls");
        for command in &crossings {
            let out = bash(home, home, session, command);
            assert_eq!(
                denied(&out),
                refused,
                "{session}: `{command}`\n{}",
                shown(&out)
            );
        }
        let edited = hook_call(home, Some(home), session, "Edit", &edit(&b.join("f")));
        assert_eq!(
            denied(&edited),
            refused,
            "{session}: Edit B/f\n{}",
            shown(&edited)
        );
        let written = hook_call(
            home,
            Some(home),
            session,
            "Write",
            &serde_json::json!({"file_path": b.join("new/x"), "content": "x"}),
        );
        assert_eq!(
            denied(&written),
            refused,
            "{session}: Write B/new/x\n{}",
            shown(&written)
        );
    }
    #[cfg(unix)]
    assert!(denied(&hook_call(
        &a,
        Some(&a),
        "armed",
        "Edit",
        &edit(&a.join("link"))
    )));
    // Allow controls in the armed session.
    assert!(!denied(&hook_call(
        &a,
        Some(&a),
        "armed",
        "Edit",
        &edit(&a.join("f"))
    )));
    std::fs::create_dir_all(a.join("sub")).expect("a subdirectory of the home");
    let inside = format!("cd {} && touch x", a.join("sub").display());
    assert!(!denied(&bash(&a, &a, "armed", &inside)));
    let nowhere = format!("cd {} && touch x", outside.display());
    assert!(!denied(&bash(&a, &a, "armed", &nowhere)));
}

#[test]
fn an_unplaceable_target_is_refused_where_reach_is_armed() {
    let (parent, a, b) = two_repositories("reach-unplaceable", &armed(), DECLARES_NOTHING);
    let bare = parent.join("bare.git");
    git_in(&parent, &["init", "-q", "--bare", "bare.git"]);
    std::fs::create_dir_all(a.join("sub")).expect("a subdirectory of the home");
    let _ = bash(&a, &a, "unplaceable", "ls");
    for command in [
        format!("cd -P {} && touch x", b.display()),
        format!("command cd {} && touch x", b.display()),
        format!("{{ cd {}; touch x; }}", b.display()),
        format!("git -C {} status", bare.display()),
        format!("cd -P {} && touch x", a.join("sub").display()),
    ] {
        let out = bash(&a, &a, "unplaceable", &command);
        assert!(denied(&out), "`{command}` must be refused\n{}", shown(&out));
    }
    let placed = format!("cd {} && touch x", a.join("sub").display());
    assert!(!denied(&bash(&a, &a, "unplaceable", &placed)));
}

const REACH_MODULE: &str = r#"package batten.fixture_reach

import rego.v1

rules contains "fixture-reach"

violation contains {
	"rule": "fixture-reach",
	"verdict": "fixture reach probe",
	"subjects": [{"path": "reach"}],
} if {
	some root in input.call.roots
	root != input.call.home
}

violation contains {
	"rule": "fixture-reach",
	"verdict": "fixture reach probe",
	"subjects": [{"path": "cwd"}],
} if {
	input.call.cwd != input.call.home
}
"#;

const REACH_CONFIG: &str = r#"version = 1

[[verdict]]
id = "fixture reach probe"
gloss = "the fixture reach predicate matched"
class = """
A fixture class, carrying one route so the registry's own shape rules are met.
"""

[[verdict.route]]
id = "fixture reach route"
kind = "command"
target = "stop reaching"

[[rule]]
id = "fixture-reach"
kind = "policy"
scope = "mediated_call"
module = "policy/fixture-reach.rego"
severity = "deny"
"#;

#[test]
fn a_policy_sees_the_call_cwd_roots_and_home() {
    // The module in both, because the TARGET's config judges: `Edit B/f` is
    // decided by B's rows, with A as the home the input names.
    let (_, a, b) = two_repositories("reach-module", REACH_CONFIG, REACH_CONFIG);
    for repository in [&a, &b] {
        std::fs::create_dir_all(repository.join("policy")).expect("policy dir");
        std::fs::write(repository.join("policy/fixture-reach.rego"), REACH_MODULE).expect("module");
        git_in(repository, &["add", "-A"]);
        git_in(
            repository,
            &[
                "-c",
                "user.name=t",
                "-c",
                "user.email=t@t",
                "commit",
                "-qm",
                "fix: module",
            ],
        );
    }
    let _ = bash(&a, &a, "module", "ls");
    let out = hook_call(&a, Some(&a), "module", "Edit", &edit(&b.join("f")));
    assert!(denied(&out), "Edit B/f leaves the home\n{}", shown(&out));
    let out = hook_call(&a, Some(&a), "module", "Edit", &edit(&a.join("f")));
    assert!(
        !denied(&out),
        "Edit A/f stays home, and cwd is the home\n{}",
        shown(&out)
    );
}

#[test]
fn a_visit_keeps_the_session_ledger_in_the_home() {
    let (parent, a, b) = two_repositories("reach-ledger", FROBNICATE_DENY, ONE_DENY);
    let first = bash(&parent, &a, "ledger", "frobnicate");
    assert!(denied(&first));
    assert!(
        shown(&first).contains("policy explain <class>"),
        "{}",
        shown(&first)
    );
    let second = bash(&parent, &b, "ledger", "gh pr merge 42");
    assert!(denied(&second), "{}", shown(&second));
    assert!(
        !shown(&second).contains("policy explain <class>"),
        "the legend is the session's, delivered once in its home\n{}",
        shown(&second)
    );
}
