//! The neutral exit-code adapter runs the same handlers as every other adapter
//! (CLOUD-2674).
//!
//! Measured on v0.0.220: a `[[hook.handler]]` on `user-prompt-submit` ran under
//! `--harness claude-code` and did not run under `--harness exit-code`, which
//! exited 0. The adapter's capability row declared only the four converged
//! events, so the capability check answered before handler dispatch was reached.
//! A host whose only channel is an exit status silently lost every handler gate.

use crate::common;

use std::path::PathBuf;

use common::{scratch, write};

/// One handler on `user-prompt-submit`, and no `[[rule]]`, so nothing but the
/// handler can produce a verdict. Run through `sh` so the stub needs no mode bit.
const CONFIG: &str = r#"version = 1

[[hook.handler]]
id = "prompt-recorder"
on = "user-prompt-submit"
run = ["sh", "./handler.sh"]
timeout_ms = 5000
owner = "CLOUD-2674"
expires = "2027-03-31"
"#;

struct Bench {
    repo: PathBuf,
    ran: PathBuf,
}

/// A repository whose handler records that it ran, then exits `code` after
/// printing `say` to stderr.
fn bench(name: &str, code: i32, say: &str) -> Bench {
    let dir = scratch(name);
    let repo = dir.join("repo");
    std::fs::create_dir_all(&repo).expect("create the fixture");
    write(&repo, "batten.toml", CONFIG);
    common::init_repo(&repo);
    let ran = repo.join("handler-ran");
    write(
        &repo,
        "handler.sh",
        &format!(
            "touch {:?}\necho {say:?} >&2\nexit {code}\n",
            ran.to_string_lossy()
        ),
    );
    Bench { repo, ran }
}

/// Pipe one `UserPromptSubmit` envelope to `adjudicate --harness exit-code`.
fn submit(bench: &Bench) -> std::process::Output {
    let payload = serde_json::json!({
        "hook_event_name": "UserPromptSubmit",
        "session_id": "s1",
        "prompt": "hi",
        "cwd": bench.repo,
    })
    .to_string();
    common::run_with_stdin(
        &bench.repo,
        &["adjudicate", "--harness", "exit-code"],
        &payload,
    )
}

#[test]
fn exit_code_runs_a_user_prompt_submit_handler() {
    if cfg!(windows) {
        // The stub is a POSIX `sh` program; the subject is the adapter's
        // capability row, which the unit test pins on every target.
        return;
    }
    let bench = bench("exit-code-handler-runs", 0, "");
    let output = submit(&bench);
    assert!(
        bench.ran.exists(),
        "the handler must run on the neutral adapter: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.status.code(), Some(0), "a passing handler allows");
}

#[test]
fn exit_code_maps_a_handler_deny_to_exit_2_with_its_reason() {
    if cfg!(windows) {
        return;
    }
    let bench = bench("exit-code-handler-denies", 2, "blocked by fixture");
    let output = submit(&bench);
    let err = String::from_utf8_lossy(&output.stderr);
    assert!(bench.ran.exists(), "the handler must run: {err}");
    assert_eq!(
        output.status.code(),
        Some(2),
        "a handler's deny is exit 2 on the neutral contract: {err}"
    );
    assert!(
        err.contains("blocked by fixture"),
        "the handler's reason travels on stderr: {err}"
    );
}
