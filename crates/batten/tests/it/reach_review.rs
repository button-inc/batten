//! The CLOUD-2840 review of #1276, findings M3 to m9 (B2 is `hook.rs`'s own
//! `a_function_name_hides_only_a_later_unwrapped_call`): each case was written
//! against the tip before its fix and failed there.
//!
//! A WRITE here is a call the read-only grant must not cover, so plan mode
//! refuses it; a READ is one it covers. The harness is `preapprove.rs`'s, copied
//! rather than shared, because that file belongs to the CLOUD-2840 session.

use crate::common;

use std::path::PathBuf;

use common::{run_with_stdin, stdout};

fn root() -> PathBuf {
    static ROOT: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
    // Per PROCESS: nextest runs each case in its own, and a shared name races.
    ROOT.get_or_init(|| {
        common::committed_fixture_with_substitution(&format!("reach-review-{}", std::process::id()))
    })
    .clone()
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

/// The decision and its reason, on the Claude Code adapter.
fn verdict(payload: &str) -> Option<(String, String)> {
    let outcome = common::stdin_run(
        &mut common::batten(),
        &root(),
        &["adjudicate", "--harness", "claude-code"],
        payload,
    );
    stdout(&outcome)
        .lines()
        .filter(|line| !line.trim().is_empty())
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .find_map(|document| {
            let inner = document.get("hookSpecificOutput")?;
            Some((
                inner.get("permissionDecision")?.as_str()?.to_owned(),
                inner.get("permissionDecisionReason")?.as_str()?.to_owned(),
            ))
        })
}

/// Every `reads` line is granted as a read in plan mode; every `writes` line
/// is refused there.
fn reads_and_writes(reads: &[&str], writes: &[&str]) {
    for line in reads {
        let (decision, reason) = verdict(&shell("plan", line)).unwrap_or_default();
        assert!(
            decision == "allow" && reason.contains("call read now"),
            "must be granted as a read: {line}\n{decision} {reason}"
        );
    }
    for line in writes {
        let (decision, reason) = verdict(&shell("plan", line)).unwrap_or_default();
        assert!(
            decision == "deny" && reason.contains("plan write refused"),
            "must be refused in plan mode: {line}\n{decision} {reason}"
        );
    }
}

/// M3: an assignment on a LATER line of one segment, or inside `env -S`'s
/// string, is read as the assignment it is.
#[test]
fn an_assignment_on_a_joined_line_or_in_env_s_is_seen() {
    reads_and_writes(
        &[],
        &[
            "git status\nGIT_EXTERNAL_DIFF=./x git diff",
            "env -S'GIT_EXTERNAL_DIFF=./x git diff'",
            "env -S 'LC_ALL=C GIT_EXTERNAL_DIFF=./x git diff'",
        ],
    );
}

/// M4: only an inert assignment keeps a read a read, and a program spelled
/// with a path is never the allowlisted name it ends in.
#[test]
fn only_an_inert_assignment_or_a_bare_program_name_is_a_read() {
    reads_and_writes(
        &[
            "LC_ALL=C ls",
            "TZ=UTC date",
            "NO_COLOR=1 ls",
            "GIT_PAGER=cat git log",
        ],
        &[
            "PATH=./bin ls",
            "env PATH=./bin ls",
            "LD_PRELOAD=./x.so cat f",
            "RIPGREP_CONFIG_PATH=./rc rg x",
            "CURL_HOME=./d curl http://example.com",
            "HOME=./h git diff",
            "GH_BROWSER=./x gh pr view 1 --web",
            "GIT_PAGER=./x git log",
            "./ls",
            "/tmp/x/ls",
            "bin/cat f",
        ],
    );
}

/// M5: a redirection written on a compound command sends every command in it
/// to the file.
#[test]
fn a_redirect_on_a_compound_command_is_a_write() {
    reads_and_writes(
        &["{ cat f; } 2>&1"],
        &[
            "{ cat f; } > out.txt",
            "( cat f ) > out.txt",
            "for f in *; do cat \"$f\"; done > all.txt",
            "if true; then cat f; fi > o.txt",
            "case x in x) cat f;; esac > o.txt",
            "while read l; do echo \"$l\"; done < f > o.txt",
            "cat f {fd}>out.txt",
        ],
    );
}

/// M5's protected half: a compound command redirected onto the authority is a
/// write to it. The plain redirect leads as the control: refused here, so the
/// fixture's protected set is live and the compound cases fail for their own
/// reason.
#[test]
fn a_compound_redirect_onto_a_protected_path_is_refused() {
    for command in [
        "echo x > batten.toml",
        "{ echo x; } > batten.toml",
        "( echo x ) >> batten.toml",
        "for f in a; do echo x; done > batten.toml",
    ] {
        let outcome = run_with_stdin(
            &root(),
            &["adjudicate", "--harness", "exit-code"],
            &serde_json::json!({
                "hook_event_name": "PreToolUse",
                "tool_name": "Bash",
                "tool_input": { "command": command },
            })
            .to_string(),
        );
        assert_eq!(outcome.status.code(), Some(2), "must be refused: {command}");
    }
}

/// M6: a gawk directive in the program text loads code that writes, and
/// `--debug` is `-D` spelled long.
#[test]
fn an_awk_directive_or_long_debug_is_a_write() {
    reads_and_writes(
        &["awk '{print $1}' f"],
        &[
            "awk '@include \"inplace\"; {sub(/a/,\"b\")} 1' f",
            "awk '@load \"rwarray\"; BEGIN { writea(\"f\", a) }'",
            "awk --debug=out 1 f",
            "awk --deb=out 1 f",
        ],
    );
}

/// m7: honest reads the tip refused — an inert pager, a prompt switch, a
/// date cluster whose last flag takes the value, and a header whose value
/// carries an `X`.
#[test]
fn an_honest_read_the_tip_refused_is_granted() {
    reads_and_writes(
        &[
            "GIT_PAGER=cat git log",
            "GIT_TERMINAL_PROMPT=0 git fetch",
            "date -ud @0",
            "gh api -HX-GitHub-Api-Version:2022-11-28 repos/a/b",
        ],
        &["date -us 2020-01-01", "gh api -iXDELETE repos/a/b"],
    );
}

/// m9: one argument never yields two methods.
#[test]
fn a_gh_method_argument_has_one_reading() {
    reads_and_writes(
        &["gh api -XGET repos/a/b", "gh api -X GET repos/a/b"],
        &[
            "gh api -XGETX GET repos/a/b",
            "gh api -XPOSTX GET repos/a/b",
        ],
    );
}
