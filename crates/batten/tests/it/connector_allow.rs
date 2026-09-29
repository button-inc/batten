//! `batten mcp grant` — the committed permissions applied to whichever server
//! name the host exposed (CLOUD-191), in its resolve and its `--guard` modes,
//! over the compiled binary (CLOUD-843).
//!
//! THE SPINE IS THE PAIR OF ARMS UNDER A FLIPPED NAME: an allow that
//! under-matches costs a prompt a human sees; a deny that under-matches enforces
//! NOTHING. THE SECOND SPINE IS THE CONNECTOR ROW: a server the host authorises
//! at its own connector layer is not a permission alias, so translating its name
//! would widen policy. Every key here is synthetic; the endpoints are the real
//! public addresses, and the fixture declares them the way `batten.toml` does —
//! the toolbox address as a governed `endpoint_contains` name, the connector's
//! as a dispatch-only one.
//!
//! # RETIREMENT LEDGER, PER PATH — what `shell retire partial` reads
//!
// carried: mise-tasks/connector-allow-resolve.sh crates/batten/src/mcp_grant.rs kind:verb crates/batten/tests/it/connector_allow.rs
// carried: mise-tasks/connector-allow-guard.sh crates/batten/src/mcp_grant.rs kind:verb crates/batten/tests/it/connector_allow.rs
// carried: tests/connector-allow-resolve.bats crates/batten/src/mcp_grant.rs kind:verb crates/batten/tests/it/connector_allow.rs
// carried: tests/connector-allow-guard.bats crates/batten/src/mcp_grant.rs kind:verb crates/batten/tests/it/connector_allow.rs
// carried: "a committed allow reaches the toolbox server under a flipped name" crates/batten/src/mcp_grant.rs kind:verb
// carried: "a committed deny reaches the toolbox server under a flipped name" crates/batten/src/mcp_grant.rs kind:verb
// carried: "a verb the committed file says nothing about resolves to silence" crates/batten/src/mcp_grant.rs kind:verb
// carried: "a deny outranks an allow glob over the same server" crates/batten/src/mcp_grant.rs kind:verb
// changed: "a claude.ai connector resolves to silence, never to a grant" crates/batten/src/mcp_grant.rs kind:verb still silence, and the reason moved from a hard-coded endpoint constant to the consumer's `[mcp] permission_aliases`: a server its selector names only for dispatch is not governed, so its name is never translated
// carried: "a server carrying no mcp_url resolves to silence" crates/batten/src/mcp_grant.rs kind:verb
// carried: "the readable spelling is left to the CLI's own matching" crates/batten/src/mcp_grant.rs kind:verb
// carried: "a non-MCP tool resolves to silence" crates/batten/src/mcp_grant.rs kind:verb
// changed: "an absent injected config resolves to silence" crates/batten/src/mcp_grant.rs kind:verb the injected config is found through the declared `[[mcp.source]]` rows rather than a `/tmp/mcp-config-cse_*.json` glob; `--config` still names one outright, and an absent one is still silence
// carried: "an absent settings file resolves to silence" crates/batten/src/mcp_grant.rs kind:verb
// carried: "an unparseable injected config resolves to silence" crates/batten/src/mcp_grant.rs kind:verb
// carried: "a server segment carrying jq metacharacters cannot reach the query" crates/batten/src/mcp_grant.rs kind:verb
// changed: "no account-specific identifier appears in the resolver's source" crates/batten/src/mcp_grant.rs kind:verb the source is the engine's now, and it names no address at all: the toolbox endpoint is the consumer's `endpoint_contains` row
// changed: "a committed allow is emitted as an allow under a flipped name" crates/batten/src/mcp_grant.rs kind:verb the allow is the reason on stdout at exit 0, which the pre-approving handler row turns into the grant
// changed: "a committed deny is emitted as a deny under a flipped name" crates/batten/src/mcp_grant.rs kind:verb the deny is the reason on stderr at exit 2, the door's refusal channel
// carried: "an unstated verb emits nothing, leaving the ordinary flow to decide" crates/batten/src/mcp_grant.rs kind:verb
// carried: "a claude.ai connector emits nothing" crates/batten/src/mcp_grant.rs kind:verb
// carried: "a non-MCP tool emits nothing" crates/batten/src/mcp_grant.rs kind:verb
// withdrawn: "the emitted envelope names the PreToolUse event" the guard writes no host envelope any more: the door renders it, and `connector_allow_door.rs` asserts the rendered document
// carried: "the reason is pointer-only: it names the alias and the verb, never the live key" crates/batten/src/mcp_grant.rs kind:verb
// changed: "the bypass gets the guard out of the way entirely" crates/batten/src/mcp_grant.rs kind:verb withdrawn: the guard applies only what the committed file already states, so a bypass would switch off the committed file rather than a guard's own judgement, and the tool-keyed deny rows it would leave standing refuse the denied verbs anyway
// carried: "a payload carrying no tool name emits nothing and exits 0" crates/batten/src/mcp_grant.rs kind:verb
// carried: "unreadable stdin exits 0 rather than denying the event" crates/batten/src/mcp_grant.rs kind:verb

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::io::Write as _;
use std::path::PathBuf;
use std::process::Stdio;

const FLIPPED: &str = "mcp__bbbbbbbb-5555-6666-7777-888888888888";
const LINEAR: &str = "mcp__aaaaaaaa-1111-2222-3333-444444444444";

/// The source shape `batten.toml` declares: the toolbox a GOVERNED name, the
/// connector a dispatch-only one.
const AUTHORITY: &str = r#"version = 1

[mcp]
permission_aliases = ["Claude_Code_Remote"]

[[mcp.source]]
id = "session"
path = "mcp-config.json"
node = "mcpServers"

[mcp.source.endpoint_contains]
Linear = "mcp.linear.app"
Claude_Code_Remote = "api.anthropic.com/v1/code/mcp/meta"
"#;

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
        common::write(&dir, "batten.toml", AUTHORITY);
        common::write(&dir, "mcp-config.json", CONFIG);
        common::write(&dir, "settings.json", SETTINGS);
        common::git_in(&dir, &["init", "-q", "-b", "main", "."]);
        Self { dir }
    }

    fn settings(self, text: &str) -> Self {
        common::write(&self.dir, "settings.json", text);
        self
    }

    fn path(&self, name: &str) -> String {
        self.dir.join(name).display().to_string()
    }

    /// `mcp grant` against this fixture's settings file.
    fn run(&self, args: &[&str], stdin: &str) -> (Option<i32>, String, String) {
        let settings = self.path("settings.json");
        let mut all: Vec<&str> = args.to_vec();
        all.extend(["--settings", settings.as_str()]);
        self.run_raw(&all, stdin)
    }

    /// `mcp grant` with exactly the arguments given.
    fn run_raw(&self, args: &[&str], stdin: &str) -> (Option<i32>, String, String) {
        let mut child = common::batten()
            .current_dir(&self.dir)
            .args(["mcp", "grant"])
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn the resolver");
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
        let (code, out, err) = self.run(&[tool], "");
        assert_eq!(code, Some(0), "{err}");
        out
    }

    /// Guard mode over a host payload: `(exit, stdout, stderr)`.
    fn guard(&self, payload: &str) -> (Option<i32>, String, String) {
        self.run(&["--guard"], payload)
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

/// THE OWNER'S RECORDED ANSWER (2026-09-28, CLOUD-843): the bare server rule
/// grants every tool of the server its endpoint resolves to, under any exposed
/// key — and the committed deny is still consulted first.
#[test]
fn a_bare_server_rule_grants_every_verb_and_a_deny_still_wins() {
    let f = Fixture::new("bare").settings(
        r#"{"permissions":{"allow":["mcp__Claude_Code_Remote"],"deny":["mcp__Claude_Code_Remote__send_later"]}}"#,
    );
    assert_eq!(
        f.verdict(&format!("{FLIPPED}__archive_session")),
        "allow Claude_Code_Remote"
    );
    assert_eq!(
        f.verdict(&format!("{FLIPPED}__send_later")),
        "deny Claude_Code_Remote"
    );
    // A server name that merely STARTS the same is another server.
    let f = Fixture::new("bare-prefix")
        .settings(r#"{"permissions":{"allow":["mcp__Claude_Code_Remote2"],"deny":[]}}"#);
    assert_eq!(
        f.verdict(&format!("{FLIPPED}__archive_session")),
        "silence Claude_Code_Remote"
    );
}

#[test]
fn a_claude_ai_connector_resolves_to_silence_never_a_grant() {
    let f = Fixture::new("connector");
    assert_eq!(f.verdict(&format!("{LINEAR}__save_issue")), "silence -");
    // A server carrying no wrapped upstream at all.
    assert_eq!(f.verdict("mcp__github__search_code"), "silence -");
    // The readable spelling is left to the host's own matching.
    assert_eq!(
        f.verdict("mcp__Claude_Code_Remote__create_session"),
        "silence Claude_Code_Remote"
    );
    assert_eq!(f.verdict("Bash"), "silence -");
}

#[test]
fn every_degradation_reaches_silence() {
    let f = Fixture::new("degraded");
    common::write(&f.dir, "bad.json", "not json");
    let tool = format!("{FLIPPED}__create_session");
    for (config, settings) in [
        (f.path("nope.json"), f.path("settings.json")),
        (f.path("mcp-config.json"), f.path("nope.json")),
        (f.path("bad.json"), f.path("settings.json")),
    ] {
        let (code, out, _) = f.run_raw(&[&tool, "--config", &config, "--settings", &settings], "");
        assert_eq!(
            (code, out.as_str()),
            (Some(0), "silence -"),
            "{config} {settings}"
        );
    }
    // A server segment carrying query metacharacters is a lookup miss, never an
    // injection.
    assert_eq!(
        f.verdict(r#"mcp__" or true or "__create_session"#),
        "silence -"
    );
}

#[test]
fn no_account_specific_identifier_appears_in_the_resolvers_source() {
    // The resolver names no address and no key: the toolbox endpoint is the
    // consumer's `endpoint_contains` row (non-negotiable rule 1).
    let source = include_str!("../../src/mcp_grant.rs");
    let uuid =
        regex::Regex::new(r"(?i)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
            .expect("a regex");
    assert!(!uuid.is_match(source));
    assert!(!source.contains("anthropic.com"));
}

/// THE CHANNEL CLOUD-191 EXISTS FOR, on the door's contract: the reason on
/// stdout at exit 0, which the pre-approving row turns into the grant.
#[test]
fn a_committed_allow_is_a_preapproval_under_a_flipped_name() {
    let f = Fixture::new("guard-allow");
    let (code, out, err) = f.guard(&payload(&format!("{FLIPPED}__create_session")));
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
    let (code, out, err) = f.guard(&payload(&format!("{FLIPPED}__send_later")));
    assert_eq!(code, Some(2), "{out}");
    assert!(out.is_empty(), "{out}");
    // Pointer-only: the alias and the verb, never the live key.
    assert!(
        err.contains("Claude_Code_Remote") && err.contains("send_later"),
        "{err}"
    );
    assert!(!err.contains("bbbbbbbb"), "{err}");
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
            f.guard(&stdin),
            (Some(0), String::new(), String::new()),
            "{stdin}"
        );
    }
}

#[test]
fn the_aliases_mode_names_no_key() {
    let f = Fixture::new("aliases");
    let (code, out, err) = f.run(&["--aliases"], "");
    assert_eq!(code, Some(0), "{err}");
    // Key order: aaaaaaaa…, bbbbbbbb…, github.
    assert_eq!(out, "-\nClaude_Code_Remote\n-");
}
