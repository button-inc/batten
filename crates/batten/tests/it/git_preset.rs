//! The `git` preset: every git call batten allows is pre-approved, a destructive
//! one is left to the host, and no refusal names a route batten would refuse or
//! leave ungranted (CLOUD-2057).
//!
//! Driven through `batten adjudicate --harness claude-code` over the committed
//! `batten.toml`, as `preapprove.rs` is, because a module suite can be green over
//! a preset the live hook never consults.
//!
//! # The measurement it exists for
//!
//! A lap rebased a branch and its gate refused, leaving the head unpushed; a
//! write gate then refused every edit until the head was pushed; and the
//! explicit `--force-with-lease=<ref>:<sha>` push every batten rule allows was
//! denied by the host's auto-mode classifier. Meanwhile `trunk push forced`
//! routed its reader to a bare `--force-with-lease`, which `branch write unsafe`
//! refuses. Both are dead ends, and [`every_git_route_is_granted_or_left_to_the_host`]
//! is the gate over the second kind for every class the registry declares.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::PathBuf;

use common::{StateHome as _, run_with_stdin_at_real_root, stdout};

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn shell(mode: &str, command: &str) -> String {
    serde_json::json!({
        "hook_event_name": "PreToolUse",
        "permission_mode": mode,
        "tool_name": "Bash",
        "tool_input": { "command": command },
    })
    .to_string()
}

/// The hook's permission decision and its reason, or `None` when it said
/// nothing verdict-shaped — which is what "left to the host" looks like.
fn decision(mode: &str, command: &str) -> Option<(String, String)> {
    let outcome = run_with_stdin_at_real_root(
        &root(),
        &["adjudicate", "--harness", "claude-code"],
        &shell(mode, command),
    );
    stdout(&outcome)
        .lines()
        .filter(|line| !line.trim().is_empty())
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .find_map(|document| {
            let inner = document.get("hookSpecificOutput")?;
            Some((
                inner.get("permissionDecision")?.as_str()?.to_owned(),
                inner
                    .get("permissionDecisionReason")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or_default()
                    .to_owned(),
            ))
        })
}

fn granted(mode: &str, command: &str) -> bool {
    decision(mode, command).is_some_and(|(word, _)| word == "allow")
}

fn denied(mode: &str, command: &str) -> Option<String> {
    decision(mode, command).and_then(|(word, reason)| (word == "deny").then_some(reason))
}

/// The calls the preset deliberately leaves to the host, named by the same
/// words the module's `destructive` set reads. A route spelling one of these is
/// not a dead end when it is merely ungranted — the host asks — so it is held to
/// "never denied" alone.
fn left_to_the_host(command: &str) -> bool {
    let words: Vec<&str> = command.split_whitespace().collect();
    [
        "--delete", "--hard", "-D", "--", ".", "drop", "clear", "expire", "-fdx", "-f",
    ]
    .iter()
    .any(|marker| words.contains(marker))
}

/// A route target as a runnable call: cut at the prose that follows it, with
/// every `<placeholder>` filled.
fn runnable(target: &str) -> String {
    let head = target
        .split(" — ")
        .next()
        .unwrap_or(target)
        .split(',')
        .next()
        .unwrap_or(target)
        .trim();
    let mut filled = String::new();
    let mut rest = head;
    while let Some(open) = rest.find('<') {
        let Some(close) = rest[open..].find('>') else {
            break;
        };
        filled.push_str(&rest[..open]);
        let name = &rest[open + 1..open + close];
        filled.push_str(match name {
            "sha" => "0123456789abcdef0123456789abcdef01234567",
            "ref" | "branch" => "feat",
            _ => "f",
        });
        rest = &rest[open + close + 1..];
    }
    filled.push_str(rest);
    filled
}

/// Every `command` route that runs `git`, from the consumer's registry and the
/// vendored one, as `(class, route target)`.
fn git_routes() -> Vec<(String, String)> {
    let mut routes = Vec::new();
    let text = std::fs::read_to_string(common::at_root("batten.toml")).expect("read batten.toml");
    let config: toml::Value = toml::from_str(&text).expect("batten.toml parses");
    for verdict in config
        .get("verdict")
        .and_then(toml::Value::as_array)
        .into_iter()
        .flatten()
    {
        let class = verdict
            .get("id")
            .and_then(toml::Value::as_str)
            .unwrap_or_default();
        for route in verdict
            .get("route")
            .and_then(toml::Value::as_array)
            .into_iter()
            .flatten()
        {
            let kind = route.get("kind").and_then(toml::Value::as_str);
            let target = route
                .get("target")
                .and_then(toml::Value::as_str)
                .unwrap_or_default();
            if kind == Some("command") && target.starts_with("git ") {
                routes.push((class.to_owned(), target.to_owned()));
            }
        }
    }
    for verdict in batten::verdict::vendored() {
        for route in &verdict.routes {
            if route.kind == batten::verdict::RouteKind::Command && route.target.starts_with("git ")
            {
                routes.push((verdict.id.clone(), route.target.clone()));
            }
        }
    }
    routes
}

/// THE NO-DEAD-END GATE: every git route a refusal names is one batten neither
/// refuses nor leaves ungranted, unless it is a destructive call the host asks
/// about.
#[test]
fn every_git_route_is_granted_or_left_to_the_host() {
    let routes = git_routes();
    assert!(
        !routes.is_empty(),
        "a gate that read no route judged nothing"
    );
    let mut dead = Vec::new();
    for (class, target) in &routes {
        let call = runnable(target);
        if let Some(reason) = denied("auto", &call) {
            dead.push(format!("{class}: `{call}` is refused: {reason}"));
        } else if !left_to_the_host(&call) && !granted("auto", &call) {
            dead.push(format!("{class}: `{call}` is not pre-approved"));
        }
    }
    assert!(
        dead.is_empty(),
        "{} git route(s) judged; dead ends: {dead:#?}",
        routes.len()
    );
}

/// THE NO-OVER-REFUSAL GATE: the git a session runs all day is never refused and
/// never put to the host.
#[test]
fn an_everyday_git_call_is_granted() {
    for call in [
        "git status",
        "git add f",
        "git commit -m x",
        "git commit -F f",
        "git fetch origin",
        "git switch -c feat",
        "git push -u origin feat",
        "git push --force-with-lease=feat:0123456789abcdef0123456789abcdef01234567 origin feat",
        "git rebase --continue",
        "git stash",
        "git tag -a v -m x",
        "git reflog",
        "git log",
        "git reset --soft HEAD~1",
    ] {
        assert!(granted("auto", call), "must be pre-approved: {call}");
    }
}

#[test]
fn a_refused_git_call_names_a_granted_route() {
    for call in [
        "git push -f origin feat",
        "git push --force-with-lease origin feat",
    ] {
        assert!(denied("auto", call).is_some(), "must be refused: {call}");
    }
}

#[test]
fn a_destructive_git_call_is_left_to_the_host() {
    for call in ["git clean -fdx", "git branch -D feat"] {
        assert!(
            denied("auto", call).is_none(),
            "must not be refused: {call}"
        );
        assert!(!granted("auto", call), "must be left to the host: {call}");
    }
}

/// The preset alone, so its own plan-mode guard is what decides: in this
/// repository `claude-code-cloud`'s `plan write refused` denies a plan-mode write
/// first, and a case over the committed config could not tell the guard was gone.
const GIT_ONLY: &str = r#"version = 1

[[rule]]
id = "program grant now"
kind = "policy"
scope = "mediated_call"
preset = "git"
severity = "deny"
"#;

fn granted_under_the_preset_alone(name: &str, mode: &str, command: &str) -> bool {
    let dir = common::scratch(name);
    let home = common::scratch(&format!("{name}-home"));
    common::write(&dir, "batten.toml", GIT_ONLY);
    common::init_repo(&dir);
    let mut invocation = common::batten();
    invocation
        .current_dir(&dir)
        .state_home(&home)
        .args(["adjudicate", "--harness", "claude-code"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    let mut child = invocation.spawn().expect("spawn batten adjudicate");
    {
        use std::io::Write as _;
        child
            .stdin
            .take()
            .expect("the child's stdin")
            .write_all(shell(mode, command).as_bytes())
            .expect("write the envelope");
    }
    let outcome = child.wait_with_output().expect("run batten adjudicate");
    stdout(&outcome).contains(r#""permissionDecision":"allow""#)
}

#[test]
fn a_git_write_is_not_granted_in_plan_mode() {
    assert!(
        granted_under_the_preset_alone("git-preset-alone-auto", "auto", "git commit -m x"),
        "the anti-vacuity half: outside plan mode the preset grants it"
    );
    assert!(!granted_under_the_preset_alone(
        "git-preset-alone-plan",
        "plan",
        "git commit -m x"
    ));
}

#[test]
fn a_route_is_cut_at_its_prose_and_filled() {
    assert_eq!(
        runnable("git push --force-with-lease=<ref>:<sha> — name the commit you expect to replace"),
        "git push --force-with-lease=feat:0123456789abcdef0123456789abcdef01234567"
    );
    assert_eq!(
        runnable("git fetch, then rebase onto what is there"),
        "git fetch"
    );
}
