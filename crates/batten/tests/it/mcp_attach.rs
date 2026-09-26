//! `[tasks.mcp-attach-check]` — every server this repo enables actually
//! ATTACHED this session (CLOUD-316, CLOUD-714), over the task's own body
//! (CLOUD-1717). Every record shape is copied from a real log this repository's
//! session wrote, including the two that look like the signature and are not.
//!
//! # RETIREMENT LEDGER, PER PATH — what `shell retire partial` reads
//!
// carried: mise-tasks/mcp-attach-check.sh mise.toml kind:mechanism crates/batten/tests/it/mcp_attach.rs
// carried: tests/mcp-attach-check.bats mise.toml kind:mechanism crates/batten/tests/it/mcp_attach.rs
// carried: "a clean log passes" mise.toml kind:mechanism
// carried: "a -32000 failure fails and names the server and the code" mise.toml kind:mechanism
// carried: "a CONNECT_TIMEOUT failure fails too — the code is not fixed at -32000" mise.toml kind:mechanism
// carried: "a failure followed by a successful reconnect passes — the LAST outcome decides" mise.toml kind:mechanism
// carried: "only the NEWEST log is judged — a stale failure does not condemn a good session" mise.toml kind:mechanism
// carried: "an enabled server with no log directory at all fails" mise.toml kind:mechanism
// carried: "a log with no connection outcome at all fails rather than passing silently" mise.toml kind:mechanism
// carried: "a missing log root is not a live session — fail open" mise.toml kind:mechanism
// carried: "no enabled servers is nothing to check" mise.toml kind:mechanism
// carried: "an unreadable settings file is exit 2, never a clean pass" mise.toml kind:mechanism
// carried: "every enabled server is judged, not just the first" mise.toml kind:mechanism
// carried: "a timeout WITH a matching spawn record reads as spawned-and-unresponsive" mise.toml kind:mechanism
// carried: "a timeout with NO spawn record for that attempt reads as never-spawned" mise.toml kind:mechanism
// carried: "A TIMEOUT WITH NO LEDGER AT ALL IS UNRECORDED, NEVER never-spawned" mise.toml kind:mechanism
// carried: "a ledger that has never seen this server is unrecorded, not never-spawned" mise.toml kind:mechanism
// carried: "a healthy attach is unaffected by the ledger in either state" mise.toml kind:mechanism
// carried: "the exit contract is unchanged — only the pointer detail is added" mise.toml kind:mechanism

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

struct Session {
    dir: PathBuf,
}

impl Session {
    fn new(name: &str) -> Self {
        let dir = common::scratch(&format!("mcp-attach-{name}"));
        std::fs::create_dir_all(dir.join("logs")).expect("logs");
        let session = Self { dir };
        session.enabled(r#"["serena"]"#);
        session
    }

    fn enabled(&self, servers: &str) {
        std::fs::write(
            self.dir.join("settings.json"),
            format!(r#"{{"enabledMcpjsonServers":{servers}}}"#),
        )
        .expect("settings");
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
        let out = common::task_bash(&self.dir, &common::task_body("mcp-attach-check"))
            .arg("_")
            .args(["--settings", &settings, "--logs", &logs])
            .args(extra)
            .env_remove("usage_args")
            .output()
            .expect("run the gate");
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
fn attempt(stamp: &str) -> i64 {
    let iso = format!(
        "{}T{}:{}:{}Z",
        &stamp[..10],
        &stamp[11..13],
        &stamp[14..16],
        &stamp[17..19]
    );
    let out = common::program("date")
        .args(["-u", "-d", &iso, "+%s"])
        .output()
        .expect("date");
    String::from_utf8_lossy(&out.stdout)
        .trim()
        .parse()
        .expect("an epoch")
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
    assert_eq!(code, Some(1), "{text}");
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
    assert_eq!(code, Some(1), "{text}");
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
        let out = common::program("touch")
            .args(["-d", when])
            .arg(path)
            .output()
            .expect("touch");
        assert!(out.status.success());
    }
    assert_eq!(s.check().0, Some(0));
}

#[test]
fn a_missing_log_or_outcome_fails() {
    let s = Session::new("no-log");
    s.log("github", "x", &[STARTED, CONNECTED]);
    let (code, text) = s.check();
    assert_eq!(code, Some(1), "{text}");
    assert!(text.contains("serena no-log"), "{text}");
    let s = Session::new("no-outcome");
    s.log("serena", "2026-08-11T06-00-00-000Z", &[STARTED, NOISE]);
    let (code, text) = s.check();
    assert_eq!(code, Some(1), "{text}");
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
    std::fs::write(s.dir.join("settings.json"), "not json").expect("garbage");
    assert_eq!(s.check().0, Some(2));
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
    assert_eq!(code, Some(1), "{text}");
    assert!(text.contains("github -32000"), "{text}");
}

#[test]
fn a_timeout_with_a_matching_spawn_record_reads_as_spawned_and_unresponsive() {
    let s = Session::new("spawned");
    let stamp = "2026-08-19T07-05-16-328Z";
    s.log("serena", stamp, &[STARTED, TIMED_OUT]);
    let ledger = s.spawns(&format!("{}\tserena\t4543\t2.10\t3\n", attempt(stamp)));
    let (code, text) = s.check_with(&["--spawns", &ledger]);
    assert_eq!(code, Some(1), "{text}");
    assert!(text.contains("serena CONNECT_TIMEOUT"), "{text}");
    assert!(text.contains("the shim recorded the launch"), "{text}");
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
    assert_eq!(code, Some(1), "{text}");
    assert!(text.contains("never-spawned"), "{text}");
    assert!(text.contains("recorded none for this attempt"), "{text}");
}

#[test]
fn an_absent_or_unwired_ledger_is_unrecorded_never_a_verdict() {
    let s = Session::new("unrecorded");
    s.log("serena", "2026-08-19T07-41-58-210Z", &[STARTED, TIMED_OUT]);
    let (code, text) = s.check();
    assert_eq!(code, Some(1), "{text}");
    assert!(text.contains("unrecorded"), "{text}");
    assert!(!text.contains("never-spawned"), "{text}");
    let ledger = s.spawns("1\tgithub\t99\t0.10\t0\n");
    let (code, text) = s.check_with(&["--spawns", &ledger]);
    assert_eq!(code, Some(1), "{text}");
    assert!(text.contains("the shim is not wired for it"), "{text}");
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
