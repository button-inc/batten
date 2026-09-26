//! `[tasks.connector-allow-resolve]` — the committed permissions applied to
//! whichever server name the host exposed (CLOUD-191), in its resolve and its
//! `--guard` modes, over the task's own body (CLOUD-1717).
//!
//! THE SPINE IS THE PAIR OF ARMS UNDER A FLIPPED NAME: an allow that
//! under-matches costs a prompt a human sees; a deny that under-matches enforces
//! NOTHING. THE SECOND SPINE IS THE CONNECTOR ROW: a claude.ai connector is
//! governed by the connector layer, so translating its name would widen policy.
//! Every key here is synthetic; the endpoints are the real public addresses.
//!
//! # RETIREMENT LEDGER, PER PATH — what `shell retire partial` reads
//!
// carried: mise-tasks/connector-allow-resolve.sh mise.toml kind:mechanism crates/batten/tests/it/connector_allow.rs
// carried: mise-tasks/connector-allow-guard.sh mise.toml kind:mechanism crates/batten/tests/it/connector_allow.rs
// carried: tests/connector-allow-resolve.bats mise.toml kind:mechanism crates/batten/tests/it/connector_allow.rs
// carried: tests/connector-allow-guard.bats mise.toml kind:mechanism crates/batten/tests/it/connector_allow.rs
// carried: "a committed allow reaches the toolbox server under a flipped name" mise.toml kind:mechanism
// carried: "a committed deny reaches the toolbox server under a flipped name" mise.toml kind:mechanism
// carried: "a verb the committed file says nothing about resolves to silence" mise.toml kind:mechanism
// carried: "a deny outranks an allow glob over the same server" mise.toml kind:mechanism
// carried: "a claude.ai connector resolves to silence, never to a grant" mise.toml kind:mechanism
// carried: "a server carrying no mcp_url resolves to silence" mise.toml kind:mechanism
// carried: "the readable spelling is left to the CLI's own matching" mise.toml kind:mechanism
// carried: "a non-MCP tool resolves to silence" mise.toml kind:mechanism
// carried: "an absent injected config resolves to silence" mise.toml kind:mechanism
// carried: "an absent settings file resolves to silence" mise.toml kind:mechanism
// carried: "an unparseable injected config resolves to silence" mise.toml kind:mechanism
// carried: "a server segment carrying jq metacharacters cannot reach the query" mise.toml kind:mechanism
// carried: "no account-specific identifier appears in the resolver's source" mise.toml kind:mechanism
// changed: "a committed allow is emitted as an allow under a flipped name" mise.toml the allow is the reason on stdout at exit 0, which the pre-approving handler row turns into the grant; the guard no longer writes a host document the door drops
// changed: "a committed deny is emitted as a deny under a flipped name" mise.toml the deny is the reason on stderr at exit 2, the door's refusal channel
// carried: "an unstated verb emits nothing, leaving the ordinary flow to decide" mise.toml kind:mechanism
// carried: "a claude.ai connector emits nothing" mise.toml kind:mechanism
// carried: "a non-MCP tool emits nothing" mise.toml kind:mechanism
// withdrawn: "the emitted envelope names the PreToolUse event" the guard writes no host envelope any more: the door renders it, and `connector_allow_door.rs` asserts the rendered document
// carried: "the reason is pointer-only: it names the alias and the verb, never the live key" mise.toml kind:mechanism
// carried: "the bypass gets the guard out of the way entirely" mise.toml kind:mechanism
// carried: "a payload carrying no tool name emits nothing and exits 0" mise.toml kind:mechanism
// carried: "unreadable stdin exits 0 rather than denying the event" mise.toml kind:mechanism

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::io::Write as _;
use std::path::PathBuf;
use std::process::Stdio;

const FLIPPED: &str = "mcp__bbbbbbbb-5555-6666-7777-888888888888";
const LINEAR: &str = "mcp__aaaaaaaa-1111-2222-3333-444444444444";

const CONFIG: &str = r#"{"mcpServers":{
  "github":{"url":"https://api.anthropic.com/v1/code/mcp/github"},
  "aaaaaaaa-1111-2222-3333-444444444444":{"url":"https://api.anthropic.com/v1/code/mcp/proxy?mcp_url=https%3A%2F%2Fmcp.linear.app%2Fmcp"},
  "bbbbbbbb-5555-6666-7777-888888888888":{"url":"https://api.anthropic.com/v1/code/mcp/proxy?mcp_url=https%3A%2F%2Fapi.anthropic.com%2Fv1%2Fcode%2Fmcp%2Fmeta&session=x"}
}}"#;

const SETTINGS: &str = r#"{"permissions":{
  "allow":["mcp__Claude_Code_Remote__create_session","mcp__Linear__save_issue"],
  "deny":["mcp__Claude_Code_Remote__send_later"]
}}"#;

struct Fixture {
    dir: PathBuf,
}

impl Fixture {
    fn new(name: &str) -> Self {
        let dir = common::scratch(&format!("connector-allow-{name}"));
        std::fs::write(dir.join("mcp-config.json"), CONFIG).expect("config");
        std::fs::write(dir.join("settings.json"), SETTINGS).expect("settings");
        Self { dir }
    }

    fn settings(self, text: &str) -> Self {
        std::fs::write(self.dir.join("settings.json"), text).expect("settings");
        self
    }

    fn path(&self, name: &str) -> String {
        self.dir.join(name).display().to_string()
    }

    fn run(
        &self,
        args: &[&str],
        stdin: &str,
        env: &[(&str, &str)],
    ) -> (Option<i32>, String, String) {
        let mut command =
            common::task_bash(&self.dir, &common::task_body("connector-allow-resolve"));
        command
            .arg("_")
            .args(args)
            .env_remove("usage_args")
            .env("BATTEN_MCP_CONFIG", self.path("mcp-config.json"))
            .env("BATTEN_MCP_SETTINGS", self.path("settings.json"))
            .env_remove("BATTEN_CONNECTOR_ALLOW_BYPASS")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        for (name, value) in env {
            command.env(name, value);
        }
        let mut child = command.spawn().expect("spawn the resolver");
        let _ = child
            .stdin
            .take()
            .expect("stdin")
            .write_all(stdin.as_bytes());
        let out = child.wait_with_output().expect("run the resolver");
        (
            out.status.code(),
            String::from_utf8_lossy(&out.stdout).trim_end().to_owned(),
            String::from_utf8_lossy(&out.stderr).trim_end().to_owned(),
        )
    }

    /// Resolve mode: `<verdict> <alias>`, always at exit 0.
    fn verdict(&self, tool: &str) -> String {
        let (code, out, err) = self.run(&[tool], "", &[]);
        assert_eq!(code, Some(0), "{err}");
        out
    }

    /// Guard mode over a host payload: `(exit, stdout, stderr)`.
    fn guard(&self, payload: &str, env: &[(&str, &str)]) -> (Option<i32>, String, String) {
        self.run(&["--guard"], payload, env)
    }
}

fn payload(tool: &str) -> String {
    serde_json::json!({ "tool_name": tool }).to_string()
}

#[test]
fn a_committed_allow_and_deny_reach_the_toolbox_under_a_flipped_name() {
    let f = Fixture::new("arms");
    assert_eq!(
        f.verdict(&format!("{FLIPPED}__create_session")),
        "allow Claude_Code_Remote"
    );
    // The load-bearing row: under-matching here enforces nothing, silently.
    assert_eq!(
        f.verdict(&format!("{FLIPPED}__send_later")),
        "deny Claude_Code_Remote"
    );
    assert_eq!(
        f.verdict(&format!("{FLIPPED}__archive_session")),
        "silence Claude_Code_Remote"
    );
}

#[test]
fn a_deny_outranks_an_allow_glob_over_the_same_server() {
    let f = Fixture::new("glob").settings(
        r#"{"permissions":{"allow":["mcp__Claude_Code_Remote__*"],"deny":["mcp__Claude_Code_Remote__send_later"]}}"#,
    );
    assert_eq!(
        f.verdict(&format!("{FLIPPED}__send_later")),
        "deny Claude_Code_Remote"
    );
    assert_eq!(
        f.verdict(&format!("{FLIPPED}__create_session")),
        "allow Claude_Code_Remote"
    );
}

#[test]
fn a_claude_ai_connector_resolves_to_silence_never_a_grant() {
    let f = Fixture::new("connector");
    assert_eq!(f.verdict(&format!("{LINEAR}__save_issue")), "silence -");
    assert_eq!(f.verdict("mcp__github__search_code"), "silence -");
    assert_eq!(
        f.verdict("mcp__Claude_Code_Remote__create_session"),
        "silence Claude_Code_Remote"
    );
    assert_eq!(f.verdict("Bash"), "silence -");
}

#[test]
fn every_degradation_reaches_silence() {
    let f = Fixture::new("degraded");
    std::fs::write(f.dir.join("bad.json"), "not json").expect("bad");
    let tool = format!("{FLIPPED}__create_session");
    for (config, settings) in [
        (f.path("nope.json"), f.path("settings.json")),
        (f.path("mcp-config.json"), f.path("nope.json")),
        (f.path("bad.json"), f.path("settings.json")),
    ] {
        let (code, out, _) = f.run(
            &[&tool, "--config", &config, "--settings", &settings],
            "",
            &[],
        );
        assert_eq!(
            (code, out.as_str()),
            (Some(0), "silence -"),
            "{config} {settings}"
        );
    }
    // A server segment carrying jq metacharacters is a lookup miss, never an
    // injection.
    assert_eq!(
        f.verdict(r#"mcp__" or true or "__create_session"#),
        "silence -"
    );
}

#[test]
fn no_account_specific_identifier_appears_in_the_resolvers_source() {
    let body = common::task_body("connector-allow-resolve");
    let uuid =
        regex::Regex::new(r"(?i)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
            .expect("a regex");
    assert!(!uuid.is_match(&body));
}

/// THE CHANNEL CLOUD-191 EXISTS FOR, on the door's contract: the reason on
/// stdout at exit 0, which the pre-approving row turns into the grant.
#[test]
fn a_committed_allow_is_a_preapproval_under_a_flipped_name() {
    let f = Fixture::new("guard-allow");
    let (code, out, err) = f.guard(&payload(&format!("{FLIPPED}__create_session")), &[]);
    assert_eq!(code, Some(0), "{err}");
    assert!(
        out.contains("already allows create_session on Claude_Code_Remote"),
        "{out}"
    );
    assert!(err.is_empty(), "{err}");
}

#[test]
fn a_committed_deny_is_the_doors_refusal_under_a_flipped_name() {
    let f = Fixture::new("guard-deny");
    let (code, out, err) = f.guard(&payload(&format!("{FLIPPED}__send_later")), &[]);
    assert_eq!(code, Some(2), "{out}");
    assert!(out.is_empty(), "{out}");
    // Pointer-only: the alias and the verb, never the live key.
    assert!(
        err.contains("Claude_Code_Remote") && err.contains("send_later"),
        "{err}"
    );
    assert!(!err.contains("bbbbbbbb"), "{err}");
    // The bypass gets the guard out of the way entirely.
    let bypassed = f.guard(
        &payload(&format!("{FLIPPED}__send_later")),
        &[("BATTEN_CONNECTOR_ALLOW_BYPASS", "1")],
    );
    assert_eq!(bypassed, (Some(0), String::new(), String::new()));
}

#[test]
fn everything_else_leaves_the_call_to_the_ordinary_flow() {
    let f = Fixture::new("guard-silent");
    for stdin in [
        payload(&format!("{FLIPPED}__archive_session")),
        payload(&format!("{LINEAR}__save_issue")),
        payload("Bash"),
        "{}".to_owned(),
        "not json".to_owned(),
    ] {
        assert_eq!(
            f.guard(&stdin, &[]),
            (Some(0), String::new(), String::new()),
            "{stdin}"
        );
    }
}

#[test]
fn the_aliases_mode_names_no_key() {
    let f = Fixture::new("aliases");
    let (code, out, err) = f.run(&["--aliases"], "", &[]);
    assert_eq!(code, Some(0), "{err}");
    // `keys` order: aaaaaaaa…, bbbbbbbb…, github.
    assert_eq!(out, "-\nClaude_Code_Remote\n-");
}
