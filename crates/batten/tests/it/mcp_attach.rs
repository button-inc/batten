//! `batten mcp posture` — every server this repo enables actually ATTACHED this
//! session (CLOUD-316, CLOUD-714), and no committed grant is one the connector
//! would still prompt for (CLOUD-765), over the compiled binary (CLOUD-843).
//! Every log record shape is copied from a real log this repository's session
//! wrote, including the two that look like the signature and are not.
//!
//! # RETIREMENT LEDGER, PER PATH — what `shell retire partial` reads
//!
// carried: mise-tasks/mcp-attach-check.sh crates/batten/src/mcp_posture.rs kind:verb crates/batten/tests/it/mcp_attach.rs
// carried: tests/mcp-attach-check.bats crates/batten/src/mcp_posture.rs kind:verb crates/batten/tests/it/mcp_attach.rs
// carried: "a clean log passes" crates/batten/src/mcp_posture.rs kind:verb
// changed: "a -32000 failure fails and names the server and the code" crates/batten/src/mcp_posture.rs kind:verb still names both, at §7's verdict exit 2 where the task exited 1
// changed: "a CONNECT_TIMEOUT failure fails too — the code is not fixed at -32000" crates/batten/src/mcp_posture.rs kind:verb still any code, at §7's verdict exit 2
// carried: "a failure followed by a successful reconnect passes — the LAST outcome decides" crates/batten/src/mcp_posture.rs kind:verb
// carried: "only the NEWEST log is judged — a stale failure does not condemn a good session" crates/batten/src/mcp_posture.rs kind:verb
// changed: "an enabled server with no log directory at all fails" crates/batten/src/mcp_posture.rs kind:verb still a finding, at §7's verdict exit 2
// changed: "a log with no connection outcome at all fails rather than passing silently" crates/batten/src/mcp_posture.rs kind:verb still a finding, at §7's verdict exit 2
// carried: "a missing log root is not a live session — fail open" crates/batten/src/mcp_posture.rs kind:verb
// carried: "no enabled servers is nothing to check" crates/batten/src/mcp_posture.rs kind:verb
// changed: "an unreadable settings file is exit 2, never a clean pass" crates/batten/src/mcp_posture.rs kind:verb still never a clean pass: could-not-look is §7's exit 3 now, where 2 is the verdict a finding carries
// changed: "every enabled server is judged, not just the first" crates/batten/src/mcp_posture.rs kind:verb still every server, at §7's verdict exit 2
// changed: "a timeout WITH a matching spawn record reads as spawned-and-unresponsive" crates/batten/src/mcp_posture.rs kind:verb the same verdict; the ledger is `batten mcp spawn`'s, so the report names the ledger rather than a per-server shim
// carried: "a timeout with NO spawn record for that attempt reads as never-spawned" crates/batten/src/mcp_posture.rs kind:verb
// carried: "A TIMEOUT WITH NO LEDGER AT ALL IS UNRECORDED, NEVER never-spawned" crates/batten/src/mcp_posture.rs kind:verb
// changed: "a ledger that has never seen this server is unrecorded, not never-spawned" crates/batten/src/mcp_posture.rs kind:verb the same verdict; the remedy names `batten mcp spawn` rather than a `mise-tasks/<server>-mcp` shim
// carried: "a healthy attach is unaffected by the ledger in either state" crates/batten/src/mcp_posture.rs kind:verb
// changed: "the exit contract is unchanged — only the pointer detail is added" crates/batten/src/mcp_posture.rs kind:verb the exit contract is §7's now: 0 clean, 2 a finding, 3 could-not-look

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::PathBuf;

const STARTED: &str = r#"{"debug":"Starting connection with timeout of 30000ms","timestamp":"2026-08-11T06:19:12.814Z"}"#;
const CONNECTED: &str = r#"{"debug":"Successfully connected (transport: stdio) in 12495ms","timestamp":"2026-08-11T06:19:25.302Z"}"#;
/// Routine startup chatter, carried under an `error` KEY on a healthy launch.
const NOISE: &str = r#"{"error":"Server stderr: INFO 2026-08-11 06:19:23,467 serena.agent:__init__:631 - Starting Serena server (version=1.6.1)","timestamp":"2026-08-11T06:19:23.467Z"}"#;
const CLOSED: &str = r#"{"debug":"Connection failed after 29999ms (-32000): MCP error -32000: Connection closed","timestamp":"2026-08-11T04:17:52.696Z"}"#;
const TIMED_OUT: &str = r#"{"debug":"Connection failed after 28476ms (CONNECT_TIMEOUT): MCP server \"serena\" connection timed out after 30000ms","timestamp":"2026-08-19T07:05:45.000Z"}"#;

/// No `[mcp]` table: the attach half alone, so a CLOUD-765 reading cannot stand
/// in for one of these cases.
const BARE: &str = "version = 1\n";

/// The source shape `batten.toml` declares for the toolbox, over a wiring file
/// in the fixture.
const GOVERNED: &str = r#"version = 1

[mcp]
permission_aliases = ["Claude_Code_Remote"]

[[mcp.source]]
id = "session"
path = "mcp-config.json"
node = "mcpServers"

[mcp.source.endpoint_contains]
Claude_Code_Remote = "api.anthropic.com/v1/code/mcp/meta"
Linear = "mcp.linear.app"
"#;

const TOOLBOX_KEY: &str = "cccccccc-1111-2222-3333-444444444444";
const TOOLBOX_URL: &str = "https://api.anthropic.com/v1/code/mcp/proxy?mcp_url=https%3A%2F%2Fapi.anthropic.com%2Fv1%2Fcode%2Fmcp%2Fmeta";
const LINEAR_URL: &str =
    "https://api.anthropic.com/v1/code/mcp/proxy?mcp_url=https%3A%2F%2Fmcp.linear.app%2Fmcp";

struct Session {
    dir: PathBuf,
}

impl Session {
    fn with_config(name: &str, config: &str) -> Self {
        let dir = common::scratch(&format!("mcp-attach-{name}"));
        common::write(&dir, "batten.toml", config);
        std::fs::create_dir_all(dir.join("logs")).expect("logs");
        common::git_in(&dir, &["init", "-q", "-b", "main", "."]);
        Self { dir }
    }

    fn new(name: &str) -> Self {
        let session = Self::with_config(name, BARE);
        session.enabled(r#"["serena"]"#);
        session
    }

    fn enabled(&self, servers: &str) {
        common::write(
            &self.dir,
            "settings.json",
            &format!(r#"{{"enabledMcpjsonServers":{servers}}}"#),
        );
    }

    fn settings(&self, json: &str) -> &Self {
        common::write(&self.dir, "settings.json", json);
        self
    }

    /// A generated wiring file in the host's shape, with per-tool postures.
    fn wiring(&self, key: &str, url: &str, tools: &[(&str, &str)]) -> &Self {
        let tools: Vec<serde_json::Value> = tools
            .iter()
            .map(|(name, policy)| serde_json::json!({"name": name, "permission_policy": policy}))
            .collect();
        let config = serde_json::json!({"mcpServers": {key: {
            "type": "http", "url": url,
            "headers": {"authorization": "Bearer s3cr3t"},
            "tools": tools,
        }}});
        common::write(&self.dir, "mcp-config.json", &config.to_string());
        self
    }

    fn toolbox(&self, tools: &[(&str, &str)]) -> &Self {
        self.wiring(TOOLBOX_KEY, TOOLBOX_URL, tools)
    }

    fn log(&self, server: &str, stamp: &str, lines: &[&str]) -> PathBuf {
        let dir = self.dir.join("logs").join(format!("mcp-logs-{server}"));
        std::fs::create_dir_all(&dir).expect("server log dir");
        let path = dir.join(format!("{stamp}.jsonl"));
        std::fs::write(&path, format!("{}\n", lines.join("\n"))).expect("log");
        path
    }

    fn spawns(&self, rows: &str) -> String {
        let path = self.dir.join("spawns");
        std::fs::write(&path, rows).expect("ledger");
        path.display().to_string()
    }

    fn check_with(&self, extra: &[&str]) -> (Option<i32>, String) {
        let settings = self.dir.join("settings.json").display().to_string();
        let logs = self.dir.join("logs").display().to_string();
        let out = common::batten()
            .current_dir(&self.dir)
            .args(["mcp", "posture", "--settings", &settings, "--logs", &logs])
            .args(extra)
            .output()
            .expect("run the posture check");
        (
            out.status.code(),
            format!(
                "{}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            ),
        )
    }

    fn check(&self) -> (Option<i32>, String) {
        let absent = self.dir.join("absent-ledger").display().to_string();
        self.check_with(&["--spawns", &absent])
    }
}

/// The epoch the log NAME records, the key a spawn is matched against.
///
/// Computed here rather than by `date -d`, which is GNU-only and absent on the
/// macOS leg (CLOUD-1923): Howard Hinnant's days-from-civil over the UTC stamp.
fn attempt(stamp: &str) -> i64 {
    let field =
        |range: std::ops::Range<usize>| -> i64 { stamp[range].parse().expect("a digit field") };
    let (year, month, day) = (field(0..4), field(5..7), field(8..10));
    let (hour, minute, second) = (field(11..13), field(14..16), field(17..19));
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (month + if month > 2 { -3 } else { 9 }) + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    days * 86_400 + hour * 3_600 + minute * 60 + second
}

#[test]
fn a_clean_log_passes_silently() {
    let s = Session::new("clean");
    s.log(
        "serena",
        "2026-08-11T06-19-12-114Z",
        &[STARTED, NOISE, CONNECTED],
    );
    assert_eq!(s.check(), (Some(0), String::new()));
}

#[test]
fn a_failure_names_the_server_and_its_code_whatever_the_code() {
    let s = Session::new("closed");
    s.log("serena", "2026-08-11T04-17-22-000Z", &[STARTED, CLOSED]);
    let (code, text) = s.check();
    assert_eq!(code, Some(2), "{text}");
    assert!(text.contains("serena -32000"), "{text}");
    let s = Session::new("timeout");
    s.log(
        "serena",
        "2026-08-11T05-41-40-873Z",
        &[
            STARTED,
            r#"{"debug":"Connection timeout triggered after 30016ms (limit: 30000ms)","timestamp":"2026-08-11T05:42:11.316Z"}"#,
            TIMED_OUT,
            r#"{"error":"Connection failed (CONNECT_TIMEOUT): MCP server \"serena\" connection timed out after 30000ms","timestamp":"2026-08-11T05:42:11.321Z"}"#,
        ],
    );
    let (code, text) = s.check();
    assert_eq!(code, Some(2), "{text}");
    assert!(text.contains("serena CONNECT_TIMEOUT"), "{text}");
}

#[test]
fn a_failure_followed_by_a_reconnect_passes() {
    let s = Session::new("reconnect");
    s.log(
        "serena",
        "2026-08-11T05-52-50-396Z",
        &[STARTED, TIMED_OUT, STARTED, CONNECTED],
    );
    assert_eq!(s.check().0, Some(0));
}

/// The mtimes are set AGAINST the name order, so ordering by mtime fails here.
#[test]
fn only_the_newest_log_by_name_is_judged() {
    let s = Session::new("newest");
    let old = s.log("serena", "2026-08-07T05-04-29-250Z", &[STARTED, CLOSED]);
    let new = s.log("serena", "2026-08-11T06-19-12-114Z", &[STARTED, CONNECTED]);
    for (path, when) in [(&old, "2026-08-11 07:00:00"), (&new, "2026-08-07 05:04:29")] {
        let secs = u64::try_from(attempt(when)).expect("a post-epoch time");
        std::fs::File::options()
            .write(true)
            .open(path)
            .expect("open the log")
            .set_modified(std::time::UNIX_EPOCH + std::time::Duration::from_secs(secs))
            .expect("set the mtime");
    }
    assert_eq!(s.check().0, Some(0));
}

#[test]
fn a_missing_log_or_outcome_fails() {
    let s = Session::new("no-log");
    s.log("github", "x", &[STARTED, CONNECTED]);
    let (code, text) = s.check();
    assert_eq!(code, Some(2), "{text}");
    assert!(text.contains("serena no-log"), "{text}");
    let s = Session::new("no-outcome");
    s.log("serena", "2026-08-11T06-00-00-000Z", &[STARTED, NOISE]);
    let (code, text) = s.check();
    assert_eq!(code, Some(2), "{text}");
    assert!(text.contains("serena no-outcome"), "{text}");
}

#[test]
fn a_missing_log_root_is_not_a_live_session() {
    let s = Session::new("no-root");
    std::fs::remove_dir_all(s.dir.join("logs")).expect("drop the root");
    let (code, text) = s.check();
    assert_eq!(code, Some(0), "{text}");
    assert!(text.contains("not a live session"), "{text}");
}

#[test]
fn nothing_enabled_passes_and_unreadable_settings_cannot_look() {
    let s = Session::new("nothing");
    s.enabled("[]");
    assert_eq!(s.check().0, Some(0));
    common::write(&s.dir, "settings.json", "not json");
    assert_eq!(s.check().0, Some(3));
}

#[test]
fn every_enabled_server_is_judged() {
    let s = Session::new("every");
    s.enabled(r#"["serena","github"]"#);
    s.log("serena", "2026-08-11T06-19-12-114Z", &[STARTED, CONNECTED]);
    s.log(
        "github",
        "2026-08-11T06-19-12-114Z",
        &[
            STARTED,
            r#"{"debug":"Connection failed after 10ms (-32000): Connection closed","timestamp":"2026-08-11T06:19:12.900Z"}"#,
        ],
    );
    let (code, text) = s.check();
    assert_eq!(code, Some(2), "{text}");
    assert!(text.contains("github -32000"), "{text}");
}

#[test]
fn a_timeout_with_a_matching_spawn_record_reads_as_spawned_and_unresponsive() {
    let s = Session::new("spawned");
    let stamp = "2026-08-19T07-05-16-328Z";
    s.log("serena", stamp, &[STARTED, TIMED_OUT]);
    let ledger = s.spawns(&format!("{}\tserena\t4543\t2.10\t3\n", attempt(stamp)));
    let (code, text) = s.check_with(&["--spawns", &ledger]);
    assert_eq!(code, Some(2), "{text}");
    assert!(text.contains("serena CONNECT_TIMEOUT"), "{text}");
    assert!(text.contains("spawned-and-unresponsive"), "{text}");
    // Pointer-only: a state, never a log line.
    assert!(!text.contains("Server stderr"), "{text}");
    assert!(!text.contains("connection timed out after"), "{text}");
}

/// The ledger carries an OLDER serena launch, which is what licenses the verdict.
#[test]
fn a_timeout_with_no_spawn_record_for_that_attempt_reads_as_never_spawned() {
    let s = Session::new("never");
    let stamp = "2026-08-19T14-30-14-698Z";
    s.log("serena", stamp, &[STARTED, TIMED_OUT]);
    let ledger = s.spawns(&format!(
        "{}\tserena\t4543\t0.30\t0\n",
        attempt(stamp) - 26000
    ));
    let (code, text) = s.check_with(&["--spawns", &ledger]);
    assert_eq!(code, Some(2), "{text}");
    assert!(text.contains("never-spawned"), "{text}");
    assert!(text.contains("recorded none for this attempt"), "{text}");
}

#[test]
fn an_absent_or_unwired_ledger_is_unrecorded_never_a_verdict() {
    let s = Session::new("unrecorded");
    s.log("serena", "2026-08-19T07-41-58-210Z", &[STARTED, TIMED_OUT]);
    let (code, text) = s.check();
    assert_eq!(code, Some(2), "{text}");
    assert!(text.contains("unrecorded"), "{text}");
    assert!(!text.contains("never-spawned"), "{text}");
    let ledger = s.spawns("1\tgithub\t99\t0.10\t0\n");
    let (code, text) = s.check_with(&["--spawns", &ledger]);
    assert_eq!(code, Some(2), "{text}");
    assert!(text.contains("the ledger has never seen serena"), "{text}");
}

#[test]
fn a_healthy_attach_is_unaffected_by_the_ledger() {
    let s = Session::new("healthy");
    s.log("serena", "2026-08-19T15-04-19-000Z", &[STARTED, CONNECTED]);
    assert_eq!(s.check().0, Some(0));
    let ledger = s.spawns("1\tserena\t1\t0.10\t0\n");
    assert_eq!(
        s.check_with(&["--spawns", &ledger]),
        (Some(0), String::new())
    );
}

// --- CLOUD-765: a committed grant the connector would still prompt for -------

fn allow(rules: &str) -> String {
    format!(r#"{{"permissions":{{"allow":{rules},"deny":[]}}}}"#)
}

#[test]
fn an_allow_rule_whose_tool_the_connector_allows_passes() {
    let s = Session::with_config("765-allows", GOVERNED);
    s.settings(&allow(r#"["mcp__Claude_Code_Remote__list_sessions"]"#))
        .toolbox(&[("list_sessions", "always_allow")]);
    assert_eq!(s.check(), (Some(0), String::new()));
    // A tool no rule names is not reported, whatever its posture.
    s.toolbox(&[
        ("list_sessions", "always_allow"),
        ("create_session", "always_ask"),
    ]);
    assert_eq!(s.check(), (Some(0), String::new()));
}

/// THE DISCRIMINATOR (CLOUD-765): well-formed, committed alias, attached — and
/// the connector sets the tool to ask.
#[test]
fn an_allow_rule_whose_tool_the_connector_sets_to_ask_is_unenforceable() {
    let s = Session::with_config("765-ask", GOVERNED);
    s.settings(&allow(r#"["mcp__Claude_Code_Remote__list_sessions"]"#))
        .toolbox(&[("list_sessions", "always_ask")]);
    let (code, text) = s.check();
    assert_eq!(code, Some(2), "{text}");
    assert!(text.contains("always_ask"), "{text}");
    assert!(text.contains("Tool permissions"), "{text}");
    // Pointer-only: no tool name, key, URL or header value.
    assert!(!text.contains("list_sessions"), "{text}");
    assert!(!text.contains("cccccccc"), "{text}");
    assert!(!text.contains("s3cr3t"), "{text}");
    assert!(!text.contains("api.anthropic.com"), "{text}");
}

#[test]
fn a_deny_on_the_same_tool_is_never_reported() {
    let s = Session::with_config("765-deny", GOVERNED);
    s.settings(r#"{"permissions":{"allow":[],"deny":["mcp__Claude_Code_Remote__send_later"]}}"#)
        .toolbox(&[("send_later", "always_ask")]);
    assert_eq!(s.check(), (Some(0), String::new()));
}

#[test]
fn a_server_that_is_not_a_permission_alias_is_left_alone() {
    let s = Session::with_config("765-linear", GOVERNED);
    s.settings(&allow(r#"["mcp__Linear__list_issues"]"#))
        .wiring(
            "dddddddd-9999-8888-7777-666666666666",
            LINEAR_URL,
            &[("list_issues", "always_ask")],
        );
    assert_eq!(s.check(), (Some(0), String::new()));
}

#[test]
fn one_finding_per_alias_with_a_count() {
    let s = Session::with_config("765-count", GOVERNED);
    s.settings(&allow(
        r#"["mcp__Claude_Code_Remote__list_sessions","mcp__Claude_Code_Remote__get_session","mcp__Claude_Code_Remote__create_session"]"#,
    ))
    .toolbox(&[
        ("list_sessions", "always_ask"),
        ("get_session", "always_ask"),
        ("create_session", "always_ask"),
    ]);
    let (code, text) = s.check();
    assert_eq!(code, Some(2), "{text}");
    assert!(text.contains("3 allow rule(s)"), "{text}");
    assert_eq!(text.matches("Claude_Code_Remote").count(), 1, "{text}");
}

/// THE OWNER'S RECORDED ANSWER (2026-09-28): the bare server rule is a grant,
/// so the count reads it — once, as the one rule it is, when any tool asks.
#[test]
fn a_bare_server_rule_counts_once_when_any_tool_asks() {
    let s = Session::with_config("765-bare", GOVERNED);
    s.settings(&allow(
        r#"["mcp__Claude_Code_Remote","mcp__Claude_Code_Remote__get_session"]"#,
    ))
    .toolbox(&[
        ("get_session", "always_ask"),
        ("list_sessions", "always_ask"),
        ("send_later", "always_allow"),
    ]);
    let (code, text) = s.check();
    assert_eq!(code, Some(2), "{text}");
    assert!(text.contains("2 allow rule(s)"), "{text}");
    // And a bare rule over a server whose every tool is allowed is enforceable.
    s.toolbox(&[("get_session", "always_allow")]);
    assert_eq!(s.check(), (Some(0), String::new()));
}

#[test]
fn no_generated_config_means_no_verdict() {
    let s = Session::with_config("765-no-config", GOVERNED);
    s.settings(&allow(r#"["mcp__Claude_Code_Remote__list_sessions"]"#));
    assert_eq!(s.check(), (Some(0), String::new()));
}
