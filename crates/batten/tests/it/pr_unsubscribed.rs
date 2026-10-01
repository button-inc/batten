//! `event watch other` and `batten pr unsubscribed` over the compiled binary
//! (CLOUD-518, CLOUD-790; the task body retired under CLOUD-843).
//!
//! Every case runs the COMMITTED `[tasks.pr-unsubscribed]` argv, read out of
//! `mise.toml`, with the arm and the pull request appended exactly as `land`'s
//! entry gates append them, against a throwaway repository whose `batten.toml`
//! registers the real module. The host's variables are set per case and removed
//! otherwise, so a live session's own id or credential can never decide one.
//!
//! What no suite can hold is a per-session credential and a stub of the host's
//! HTTPS endpoint, so the ACCEPTED-call arm is pinned where it is decidable
//! without either: `accepted` and `mint` in `crates/batten/src/unsubscribe.rs`'s
//! own tests. Every failure that can wedge a landing is still driven here — a
//! `drop` that could not establish its input or reach the endpoint mints nothing
//! and exits 0.
//!
//! # RETIREMENT LEDGER, PER PATH — what `shell retire partial` reads
//!
// carried: mise-tasks/pr-unsubscribed.sh policy/pr-unsubscribed.rego kind:mechanism crates/batten/tests/it/pr_unsubscribed.rs
// carried: tests/pr-unsubscribed.bats policy/pr-unsubscribed.rego kind:mechanism crates/batten/tests/it/pr_unsubscribed.rs
// carried: "[tasks.pr-unsubscribed] body" crates/batten/src/unsubscribe.rs kind:verb crates/batten/tests/it/pr_unsubscribed.rs
// carried: "CLOUD-518: a clone with no session has nothing to drop, and check passes" policy/pr-unsubscribed.rego kind:mechanism
// carried: "CLOUD-518: a PR this session never unsubscribed is refused" policy/pr-unsubscribed.rego kind:mechanism
// carried: "CLOUD-518: the recorded drop is what makes check pass" policy/pr-unsubscribed.rego kind:mechanism
// carried: "CLOUD-518: an answer that does not name this PR is refused" crates/batten/src/unsubscribe.rs kind:verb
// carried: "CLOUD-518: a receipt for another PR does not satisfy this one" policy/pr-unsubscribed.rego kind:mechanism
// carried: "CLOUD-518: a receipt from another SESSION does not satisfy this one" policy/pr-unsubscribed.rego kind:mechanism
// carried: "CLOUD-518: recording off-harness mints nothing and says so" crates/batten/src/unsubscribe.rs kind:verb
// carried: "CLOUD-518: POINTER, NEVER PAYLOAD — no answer text is printed or stored" crates/batten/src/unsubscribe.rs kind:verb
// carried: "CLOUD-790: a refused call mints NOTHING, and the gate still refuses" crates/batten/src/unsubscribe.rs kind:verb
// carried: "CLOUD-790: a 200 carrying an MCP error is not an accepted call" crates/batten/src/unsubscribe.rs kind:mechanism
// carried: "CLOUD-790: drop NEVER blocks — every path it cannot establish exits 0" crates/batten/src/unsubscribe.rs kind:verb
// carried: "CLOUD-790: off harness there is no session, so there is nothing to drop" crates/batten/src/unsubscribe.rs kind:verb
// carried: "CLOUD-790: a clone with no origin is not a repo to guess an owner for" crates/batten/src/unsubscribe.rs kind:verb
// carried: "CLOUD-790: POINTER, NEVER PAYLOAD — the response body is neither printed nor stored" crates/batten/src/unsubscribe.rs kind:mechanism
// changed: "CLOUD-518: an empty answer is could-not-look, never a refusal" crates/batten/src/unsubscribe.rs still could-not-look and never a refusal, now spelled exit 3 on the engine's table where the body said 2
// changed: "CLOUD-518: a bad verb or a non-numeric PR is could-not-look" crates/batten/src/unsubscribe.rs a malformed invocation is the engine's usage error, exit 1: one exit table, no per-verb exception
// changed: "CLOUD-518: a session is the name of an injected client config under BATTEN_MCP_CONFIG_DIR" crates/batten/src/unsubscribe.rs a session is the value of the variable the task names with --session-env, the id the committed `[[mcp.source]] claude-code-remote` row spells its wiring file with; the engine expands a declared variable and never scans a directory
// changed: "CLOUD-790: the call sends owner, repo and pullNumber" mise.toml the argument shape is the host's, so the task declares it with --arguments as a JSON template and the engine fills {owner}, {repo} and {pr}; a template naming the owner in a clone with no slug still sends nothing
// changed: "CLOUD-790: an accepted call mints the receipt check demands, with no human in it" crates/batten/src/unsubscribe.rs the endpoint is HTTPS through the engine's own client, which no stub `curl` can stand in for; `accepted` and `mint` carry the arm in the module's own tests, and the composition is listed for the integrator's live replay

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::{Path, PathBuf};
use std::process::{Output, Stdio};

use common::{at_root, git_in, init_repo, scratch, write};

/// The variable the committed task names for the session id.
const SESSION_ENV: &str = "CLAUDE_CODE_REMOTE_SESSION_ID";

/// The variable the committed task names for the credential file's path.
const TOKEN_ENV: &str = "CLAUDE_SESSION_INGRESS_TOKEN_FILE";

/// The committed task's argv after `cargo run --quiet -p batten --`, split the
/// way `sh` splits it: whitespace, and single quotes grouping.
fn committed_argv() -> Vec<String> {
    let text = std::fs::read_to_string(at_root("mise.toml")).expect("the manifest");
    let parsed: toml::Value = toml::from_str(&text).expect("mise.toml parses");
    let run = parsed["tasks"]["pr-unsubscribed"]["run"]
        .as_str()
        .expect("the task is one argv string");
    let (_, argv) = run
        .split_once(" -- ")
        .expect("the task runs the engine with `cargo run ... --`");
    let mut words = Vec::new();
    let mut word = String::new();
    let mut quoted = false;
    for c in argv.chars() {
        match c {
            '\'' => quoted = !quoted,
            ' ' if !quoted => {
                if !word.is_empty() {
                    words.push(std::mem::take(&mut word));
                }
            }
            _ => word.push(c),
        }
    }
    if !word.is_empty() {
        words.push(word);
    }
    words
}

/// A throwaway repository registering the real module, with no origin.
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
    init_repo(&dir);
    git_in(&dir, &["add", "-A"]);
    git_in(&dir, &["commit", "-qm", "register the module"]);
    dir
}

/// One run's host: the session id and the credential file, each absent unless set.
#[derive(Default)]
struct HostEnv<'a> {
    session: Option<&'a str>,
    token: Option<PathBuf>,
    endpoint: Option<&'a str>,
}

/// Run the committed argv with `verb` and `pr` appended, as `mise run` would.
fn task(dir: &Path, verb: &str, pr: &str, stdin: &str, host: &HostEnv<'_>) -> Output {
    use std::io::Write as _;

    let mut argv = committed_argv();
    if let Some(endpoint) = host.endpoint {
        let at = argv
            .iter()
            .position(|word| word == "--endpoint")
            .expect("the task declares an endpoint");
        endpoint.clone_into(&mut argv[at + 1]);
    }
    argv.push(verb.to_owned());
    argv.push(pr.to_owned());
    let mut command = common::batten();
    command
        .args(&argv)
        .current_dir(dir)
        .env_remove("GH_REPO")
        .env_remove("LAND_LOCK_REMOTE");
    match host.session {
        Some(session) => command.env(SESSION_ENV, session),
        None => command.env_remove(SESSION_ENV),
    };
    match &host.token {
        Some(token) => command.env(TOKEN_ENV, token),
        None => command.env_remove(TOKEN_ENV),
    };
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn the verb");
    let _ = child
        .stdin
        .take()
        .expect("stdin")
        .write_all(stdin.as_bytes());
    child.wait_with_output().expect("run the verb")
}

fn in_session(session: &str) -> HostEnv<'_> {
    HostEnv {
        session: Some(session),
        ..HostEnv::default()
    }
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
    // This verb's receipts only, by their shape: the engine keeps its own in the
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
    let off = HostEnv::default();
    let check = task(&dir, "check", "489", "", &off);
    assert_eq!(check.status.code(), Some(0), "{}", said(&check));
    let recorded = task(&dir, "record", "489", &answer_for("489"), &off);
    assert_eq!(recorded.status.code(), Some(0), "{}", said(&recorded));
    assert!(receipts(&dir).is_empty(), "off harness mints nothing");
    let dropped = task(&dir, "drop", "489", "", &off);
    assert_eq!(dropped.status.code(), Some(0), "{}", said(&dropped));
}

#[test]
fn a_pr_this_session_never_unsubscribed_is_refused() {
    let dir = repo("refused");
    let check = task(&dir, "check", "489", "", &in_session("cse_fixture"));
    assert_eq!(check.status.code(), Some(2), "{}", said(&check));
    assert!(said(&check).contains("#489"), "{}", said(&check));
}

#[test]
fn the_recorded_drop_is_what_makes_check_pass_for_that_pr_and_session_only() {
    let dir = repo("recorded");
    let session = in_session("cse_fixture");
    let recorded = task(&dir, "record", "489", &answer_for("489"), &session);
    assert!(recorded.status.success(), "{}", said(&recorded));
    assert_eq!(
        task(&dir, "check", "489", "", &session).status.code(),
        Some(0)
    );
    assert_eq!(
        task(&dir, "check", "490", "", &session).status.code(),
        Some(2),
        "a receipt for another PR does not satisfy this one"
    );
    assert_eq!(
        task(&dir, "check", "489", "", &in_session("cse_other"))
            .status
            .code(),
        Some(2),
        "nor one from another session"
    );
}

#[test]
fn record_refuses_an_answer_for_another_pr_and_an_empty_one_is_could_not_look() {
    let dir = repo("answers");
    let session = in_session("cse_fixture");
    assert_eq!(
        task(&dir, "record", "489", &answer_for("490"), &session)
            .status
            .code(),
        Some(1)
    );
    assert_eq!(
        task(&dir, "record", "489", "  \n", &session).status.code(),
        Some(3)
    );
    assert!(receipts(&dir).is_empty());
}

#[test]
fn a_bad_verb_or_a_non_numeric_pr_is_a_usage_error() {
    let dir = repo("usage");
    let off = HostEnv::default();
    assert_eq!(task(&dir, "frob", "489", "", &off).status.code(), Some(1));
    assert_eq!(task(&dir, "check", "abc", "", &off).status.code(), Some(1));
}

#[test]
fn a_refused_or_unreachable_call_mints_nothing_and_drop_never_blocks() {
    // No credential file: nothing to spend, so nothing is sent.
    let bare = repo("bare");
    let dropped = task(&bare, "drop", "489", "", &in_session("cse_fixture"));
    assert_eq!(dropped.status.code(), Some(0), "{}", said(&dropped));
    assert!(receipts(&bare).is_empty());
    // A credential but no origin: no owner/repo to guess, so nothing is sent.
    let no_origin = repo("no-origin");
    write(&no_origin, "token", "not-a-real-token\n");
    let host = HostEnv {
        session: Some("cse_fixture"),
        token: Some(no_origin.join("token")),
        endpoint: Some("https://127.0.0.1:9/{session}"),
    };
    let dropped = task(&no_origin, "drop", "489", "", &host);
    assert_eq!(dropped.status.code(), Some(0), "{}", said(&dropped));
    assert!(receipts(&no_origin).is_empty());
    // Everything established and the endpoint unreachable: still 0, still no
    // receipt, and the gate still refuses.
    let unreachable = repo("unreachable");
    write(&unreachable, "token", "not-a-real-token\n");
    git_in(
        &unreachable,
        &[
            "remote",
            "add",
            "origin",
            "https://github.com/owner/repo.git",
        ],
    );
    let host = HostEnv {
        session: Some("cse_fixture"),
        token: Some(unreachable.join("token")),
        endpoint: Some("https://127.0.0.1:9/{session}"),
    };
    let dropped = task(&unreachable, "drop", "489", "", &host);
    assert_eq!(dropped.status.code(), Some(0), "{}", said(&dropped));
    assert!(
        !said(&dropped).contains("not-a-real-token"),
        "never the credential"
    );
    assert!(receipts(&unreachable).is_empty());
    assert_eq!(
        task(&unreachable, "check", "489", "", &in_session("cse_fixture"))
            .status
            .code(),
        Some(2)
    );
}

#[test]
fn a_recorded_answer_is_never_printed_or_stored() {
    let dir = repo("pointer");
    let answer = format!("{} customer detail", answer_for("489"));
    let recorded = task(&dir, "record", "489", &answer, &in_session("cse_fixture"));
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

/// The task is the verb, one argv, and `land`'s entry gates still name the task.
#[test]
fn the_task_is_the_verb_and_land_still_names_it() {
    let argv = committed_argv();
    assert_eq!(
        argv.get(..2),
        Some(&["pr".to_owned(), "unsubscribed".to_owned()][..])
    );
    // The tool's argument shape is declared here, never spelled in the engine.
    let at = argv
        .iter()
        .position(|word| word == "--arguments")
        .expect("the task declares the tool's arguments");
    let template: serde_json::Value =
        serde_json::from_str(&argv[at + 1]).expect("the template is JSON");
    assert_eq!(
        template,
        serde_json::json!({"owner":"{owner}","repo":"{repo}","pullNumber":"{pr}"})
    );
    let gates = common::task_env("LAND_ENTRY_GATES");
    assert!(gates.contains("mise run pr-unsubscribed drop"), "{gates}");
    assert!(gates.contains("mise run pr-unsubscribed check"), "{gates}");
}
