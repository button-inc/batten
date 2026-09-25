//! `event watch other` and `[tasks.pr-unsubscribed]` over the compiled binary
//! (CLOUD-518, CLOUD-790, CLOUD-1717).
//!
//! The task's body is read out of `mise.toml` and run with the `usage` spec's
//! `usage_verb` and `usage_pr` in the environment, against a throwaway repository
//! whose `batten.toml` registers the real module. `drop` meets a stub `curl`
//! that honours `-o` and prints the status asked for — which is why these cases
//! prove SHAPE and not effect: no suite can hold a per-session credential, and a
//! stub cannot observe GitHub's subscription state. Every failure that can wedge a
//! landing is a shape anyway: minting on a status that was not 200, or exiting
//! non-zero at all.
//!
//! `check` refuses at the engine's exit table now — `2` where the program said
//! `1` — which is CLOUD-1717's stated contract: port onto the engine's `0/1/2/3`,
//! never carry the shell's over.
//!
//! # RETIREMENT LEDGER, PER PATH — what `shell retire partial` reads
//!
// carried: mise-tasks/pr-unsubscribed.sh policy/pr-unsubscribed.rego kind:mechanism crates/batten/tests/it/pr_unsubscribed.rs
// carried: tests/pr-unsubscribed.bats policy/pr-unsubscribed.rego kind:mechanism crates/batten/tests/it/pr_unsubscribed.rs
// carried: "CLOUD-518: a clone with no session has nothing to drop, and check passes" policy/pr-unsubscribed.rego kind:mechanism
// carried: "CLOUD-518: a PR this session never unsubscribed is refused" policy/pr-unsubscribed.rego kind:mechanism
// carried: "CLOUD-518: the recorded drop is what makes check pass" policy/pr-unsubscribed.rego kind:mechanism
// carried: "CLOUD-518: an answer that does not name this PR is refused" mise.toml kind:mechanism
// carried: "CLOUD-518: a receipt for another PR does not satisfy this one" policy/pr-unsubscribed.rego kind:mechanism
// carried: "CLOUD-518: a receipt from another SESSION does not satisfy this one" policy/pr-unsubscribed.rego kind:mechanism
// carried: "CLOUD-518: an empty answer is could-not-look, never a refusal" mise.toml kind:mechanism
// carried: "CLOUD-518: recording off-harness mints nothing and says so" mise.toml kind:mechanism
// carried: "CLOUD-518: POINTER, NEVER PAYLOAD — no answer text is printed or stored" mise.toml kind:mechanism
// carried: "CLOUD-518: a bad verb or a non-numeric PR is could-not-look" mise.toml kind:mechanism
// carried: "CLOUD-790: an accepted call mints the receipt check demands, with no human in it" mise.toml kind:mechanism
// carried: "CLOUD-790: a refused call mints NOTHING, and the gate still refuses" mise.toml kind:mechanism
// carried: "CLOUD-790: a 200 carrying an MCP error is not an accepted call" mise.toml kind:mechanism
// carried: "CLOUD-790: drop NEVER blocks — every path it cannot establish exits 0" mise.toml kind:mechanism
// carried: "CLOUD-790: off harness there is no session, so there is nothing to drop" mise.toml kind:mechanism
// carried: "CLOUD-790: a clone with no origin is not a repo to guess an owner for" mise.toml kind:mechanism
// carried: "CLOUD-790: POINTER, NEVER PAYLOAD — the response body is neither printed nor stored" mise.toml kind:mechanism

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use common::{at_root, git_in, init_repo, scratch, write};

/// A throwaway repository registering the real module, with an empty injected
/// config directory (the off-harness reading) and no origin.
fn repo(name: &str) -> PathBuf {
    let dir = scratch(&format!("pr-unsubscribed-{name}"));
    let module =
        std::fs::read_to_string(at_root("policy/pr-unsubscribed.rego")).expect("the module");
    write(&dir, "policy/pr-unsubscribed.rego", &module);
    write(
        &dir,
        "batten.toml",
        r#"version = 1
scope = ["**"]

[[verdict]]
id = "event watch held"
gloss = "no receipt"
class = "fixture"

[[verdict.route]]
id = "task run first"
kind = "command"
target = "mise run pr-unsubscribed drop"

[[verdict]]
id = "event read partial"
gloss = "torn"
class = "fixture"

[[verdict.route]]
id = "task run first"
kind = "command"
target = "mise run pr-unsubscribed check"

[[rule]]
id = "event watch other"
kind = "policy"
scope = "tree"
module = "policy/pr-unsubscribed.rego"
severity = "deny"

[[record]]
record = "pr-unsubscribed"
writer = "mise run pr-unsubscribed check"
"#,
    );
    std::fs::create_dir_all(dir.join("cfg")).expect("cfg dir");
    init_repo(&dir);
    git_in(&dir, &["add", "-A"]);
    git_in(&dir, &["commit", "-qm", "register the module"]);
    dir
}

/// A session exists: only the injected config's NAME matters.
fn in_session(dir: &Path, session: &str) {
    write(dir, &format!("cfg/mcp-config-{session}.json"), "{}");
}

/// A stub `curl` answering `code` with `body`, a token file, and an origin.
fn with_endpoint(dir: &Path, code: &str, body: &str) {
    write(dir, "body", body);
    write(
        dir,
        "bin/curl",
        &format!(
            "#!/usr/bin/env bash\nout=\"\"; prev=\"\"\n\
             for a in \"$@\"; do [ \"$prev\" = \"-o\" ] && out=\"$a\"; prev=\"$a\"; done\n\
             cat >/dev/null 2>&1 || true\n\
             [ -n \"$out\" ] && cat '{}' >\"$out\"\nprintf '%s' '{code}'\n",
            dir.join("body").display()
        ),
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let path = dir.join("bin/curl");
        let mut permissions = std::fs::metadata(&path).expect("stat").permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&path, permissions).expect("chmod");
    }
    write(dir, "token", "not-a-real-token\n");
}

fn with_origin(dir: &Path) {
    git_in(
        dir,
        &[
            "remote",
            "add",
            "origin",
            "https://github.com/owner/repo.git",
        ],
    );
}

fn body() -> String {
    let manifest = std::fs::read_to_string(at_root("mise.toml")).expect("the manifest");
    let parsed: toml::Value = toml::from_str(&manifest).expect("mise.toml parses as TOML");
    parsed["tasks"]["pr-unsubscribed"]["run"]
        .as_str()
        .expect("[tasks.pr-unsubscribed] declares a run body")
        .lines()
        .filter(|line| !line.contains("{% raw %}") && !line.contains("{% endraw %}"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Run the task body as `mise run pr-unsubscribed <verb> <pr>` would.
fn task(dir: &Path, verb: &str, pr: &str, stdin: &str) -> Output {
    use std::io::Write as _;

    let template = common::batten();
    let mut command = Command::new("bash");
    for (name, value) in template.get_envs() {
        match value {
            Some(value) => command.env(name, value),
            None => command.env_remove(name),
        };
    }
    let mut paths = vec![dir.join("bin")];
    paths.extend(std::env::split_paths(
        &std::env::var_os("PATH").unwrap_or_default(),
    ));
    let path = std::env::join_paths(paths).expect("PATH");
    command
        .args(["-c", &body()])
        .current_dir(dir)
        .env("PATH", path)
        .env("BATTEN_MCP_CONFIG_DIR", dir.join("cfg"))
        .env("BATTEN_CCR_ENDPOINT", "https://stub.invalid")
        .env("usage_verb", verb)
        .env("usage_pr", pr);
    if dir.join("token").exists() {
        command.env("CLAUDE_SESSION_INGRESS_TOKEN_FILE", dir.join("token"));
    } else {
        command.env_remove("CLAUDE_SESSION_INGRESS_TOKEN_FILE");
    }
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn the task body");
    let _ = child
        .stdin
        .take()
        .expect("stdin")
        .write_all(stdin.as_bytes());
    child.wait_with_output().expect("run the task body")
}

fn said(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn answer_for(pr: &str) -> String {
    format!("No active subscription found for owner/repo#{pr} on this session.")
}

/// Everything under the receipt store, as one string.
fn receipts(dir: &Path) -> String {
    let store = dir.join(".git/batten-receipts");
    let Ok(entries) = std::fs::read_dir(&store) else {
        return String::new();
    };
    // This task's receipts only, by their shape: the engine keeps its own in the
    // same store, some under the same family prefix.
    entries
        .filter_map(Result::ok)
        .map(|entry| std::fs::read_to_string(entry.path()).unwrap_or_default())
        .filter(|text| text.starts_with("pr ") && text.contains("\nvia "))
        .collect()
}

#[test]
fn a_clone_with_no_session_has_nothing_to_drop() {
    let dir = repo("off-harness");
    let check = task(&dir, "check", "489", "");
    assert_eq!(check.status.code(), Some(0), "{}", said(&check));
    let recorded = task(&dir, "record", "489", &answer_for("489"));
    assert_eq!(recorded.status.code(), Some(0), "{}", said(&recorded));
    assert!(receipts(&dir).is_empty(), "off harness mints nothing");
    let dropped = task(&dir, "drop", "489", "");
    assert_eq!(dropped.status.code(), Some(0), "{}", said(&dropped));
}

#[test]
fn a_pr_this_session_never_unsubscribed_is_refused() {
    let dir = repo("refused");
    in_session(&dir, "cse_fixture");
    let check = task(&dir, "check", "489", "");
    assert_eq!(check.status.code(), Some(2), "{}", said(&check));
    assert!(said(&check).contains("#489"), "{}", said(&check));
}

#[test]
fn the_recorded_drop_is_what_makes_check_pass_for_that_pr_and_session_only() {
    let dir = repo("recorded");
    in_session(&dir, "cse_fixture");
    assert!(
        task(&dir, "record", "489", &answer_for("489"))
            .status
            .success()
    );
    assert_eq!(task(&dir, "check", "489", "").status.code(), Some(0));
    assert_eq!(
        task(&dir, "check", "490", "").status.code(),
        Some(2),
        "a receipt for another PR does not satisfy this one"
    );
    std::fs::remove_file(dir.join("cfg/mcp-config-cse_fixture.json")).expect("rm");
    in_session(&dir, "cse_other");
    assert_eq!(
        task(&dir, "check", "489", "").status.code(),
        Some(2),
        "nor one from another session"
    );
}

#[test]
fn record_refuses_an_answer_for_another_pr_and_an_empty_one_is_could_not_look() {
    let dir = repo("answers");
    in_session(&dir, "cse_fixture");
    assert_eq!(
        task(&dir, "record", "489", &answer_for("490"))
            .status
            .code(),
        Some(1)
    );
    assert_eq!(task(&dir, "record", "489", "  \n").status.code(), Some(2));
    assert!(receipts(&dir).is_empty());
}

#[test]
fn a_bad_verb_or_a_non_numeric_pr_is_could_not_look() {
    let dir = repo("usage");
    assert_eq!(task(&dir, "frob", "489", "").status.code(), Some(2));
    assert_eq!(task(&dir, "check", "abc", "").status.code(), Some(2));
}

#[test]
fn an_accepted_call_mints_the_receipt_check_demands() {
    let dir = repo("accepted");
    in_session(&dir, "cse_fixture");
    with_origin(&dir);
    with_endpoint(
        &dir,
        "200",
        r#"{"result":{"content":[{"type":"text","text":"secret body"}]}}"#,
    );
    let dropped = task(&dir, "drop", "489", "");
    assert_eq!(dropped.status.code(), Some(0), "{}", said(&dropped));
    assert_eq!(task(&dir, "check", "489", "").status.code(), Some(0));
    assert!(!said(&dropped).contains("secret body"), "pointer only");
    assert!(!receipts(&dir).contains("secret body"), "never stored");
}

#[test]
fn a_refused_or_errored_call_mints_nothing_and_drop_never_blocks() {
    for (name, code, reply) in [
        ("drop-refused", "403", "{}"),
        ("drop-errored", "200", r#"{"result":{"isError":true}}"#),
    ] {
        let dir = repo(name);
        in_session(&dir, "cse_fixture");
        with_origin(&dir);
        with_endpoint(&dir, code, reply);
        assert_eq!(
            task(&dir, "drop", "489", "").status.code(),
            Some(0),
            "{name}"
        );
        assert!(receipts(&dir).is_empty(), "{name} mints nothing");
        assert_eq!(
            task(&dir, "check", "489", "").status.code(),
            Some(2),
            "{name}"
        );
    }
    // No token file, no origin: every path it cannot establish exits 0.
    let bare = repo("bare");
    in_session(&bare, "cse_fixture");
    assert_eq!(task(&bare, "drop", "489", "").status.code(), Some(0));
    let no_origin = repo("no-origin");
    in_session(&no_origin, "cse_fixture");
    with_endpoint(&no_origin, "200", "{}");
    assert_eq!(task(&no_origin, "drop", "489", "").status.code(), Some(0));
    assert!(receipts(&no_origin).is_empty());
}

#[test]
fn a_recorded_answer_is_never_printed_or_stored() {
    let dir = repo("pointer");
    in_session(&dir, "cse_fixture");
    let answer = format!("{} customer detail", answer_for("489"));
    let recorded = task(&dir, "record", "489", &answer);
    assert!(recorded.status.success(), "{}", said(&recorded));
    assert!(!said(&recorded).contains("customer detail"));
    assert!(!receipts(&dir).contains("customer detail"));
}

#[test]
fn a_record_missing_a_reading_is_torn_rather_than_clean() {
    let dir = repo("torn");
    let written = common::run_with_stdin(
        &dir,
        &["record", "named", "pr-unsubscribed"],
        "session\tcse_x\n",
    );
    assert!(written.status.success(), "{}", said(&written));
    let decided = common::run(&dir, &["check", "--rule", "event watch other"]);
    assert_eq!(decided.status.code(), Some(2), "{}", said(&decided));
}
