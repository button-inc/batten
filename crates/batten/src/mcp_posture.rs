//! `mcp posture`: whether this SESSION's MCP servers are granted in a way the
//! host honours, and whether they attached (CLOUD-843, retiring
//! `mcp-attach-check` and `mcp-allow-check --session`).
//!
//! # Two halves, one verb, and both are properties of the world
//!
//! * **CLOUD-765.** A committed allow rule on a governed server whose tool the
//!   connector sets to anything but `always_allow` skips no prompt. The posture
//!   is written into the host-injected wiring when the session starts, so this
//!   is [`crate::mcp::bound`]'s census over that wiring — its first production
//!   caller.
//! * **CLOUD-316, CLOUD-714.** Every server the settings enable actually
//!   attached, read from the host's own connection log, with the spawn ledger
//!   `mcp spawn` writes telling a launch that never happened from one that hung.
//!
//! The commit-scoped half of the retired gate — the predicates that are pure
//! functions of committed files — is `policy/mcp-allow.rego`, which runs where
//! every other tree rule runs.
//!
//! # Silence is the pass
//!
//! A clean session prints nothing and exits 0. A finding is one line on stderr
//! and the verdict exit. What could not be looked at — no settings file, no
//! enabled server, no log tree, no injected wiring — is said on stderr and is
//! never a finding, because a verdict from nothing is the defect CLOUD-714 fixed.

use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::Result;

use crate::exit::ExitCode;
use crate::facts::{Format, Look, Node};
use crate::mcp;
use crate::mcp_grant::Inputs;

/// Where the attach half looks, resolved by the caller.
#[derive(Debug, Clone, Default)]
pub struct Session {
    /// The host's per-project MCP connection log tree, or `None` where this
    /// host keeps none anybody surveyed.
    pub logs: Option<PathBuf>,
    /// The spawn ledger `mcp spawn` appends to, or `None` outside a checkout.
    pub spawns: Option<PathBuf>,
}

/// `mcp posture`.
///
/// # Errors
///
/// A settings file that exists and will not parse — could-not-look, which must
/// never read as a clean session — and a failed write.
pub fn run(inputs: &Inputs<'_>, session: &Session, err: &mut dyn Write) -> Result<ExitCode> {
    let settings = inputs.settings_label();
    if !inputs.settings.is_file() {
        writeln!(err, "mcp posture: no {settings} — nothing to check")?;
        return Ok(ExitCode::Success);
    }
    let text = std::fs::read_to_string(inputs.settings)?;
    let Ok(document) = crate::rules::parse_node(Format::Json, &text) else {
        anyhow::bail!(
            "mcp posture: {settings} is not readable JSON, so nothing about it was judged"
        );
    };
    let mut findings = unenforceable(inputs, &settings);
    findings.extend(unattached(&document, session, err)?);
    for finding in &findings {
        writeln!(err, "mcp posture: {finding}")?;
    }
    Ok(ExitCode::verdict(!findings.is_empty()))
}

/// CLOUD-765: allow rules on a governed name whose tool the connector sets to
/// anything but `always_allow`. No allow rule skips that prompt.
///
/// One finding per governed name, with a count. A name whose wiring this host
/// did not inject answers nothing — no generated config means no verdict.
//MUTANT-SUITE crates/batten/tests/it/mcp_attach.rs
//MUTANT allow-check-ignores-policy|s@^        if bound.unenforceable == 0 {@        if true {@|an_allow_rule_whose_tool_the_connector_sets_to_ask_is_unenforceable
fn unenforceable(inputs: &Inputs<'_>, settings: &str) -> Vec<String> {
    let mut findings = Vec::new();
    for alias in &inputs.config.permission_aliases {
        let Ok(bound) = mcp::bound_in(
            inputs.config,
            inputs.repo_root,
            alias,
            &[inputs.settings.to_path_buf()],
            inputs.wiring,
        ) else {
            continue;
        };
        if bound.unenforceable == 0 {
            continue;
        }
        findings.push(format!(
            "{alias} — {} allow rule(s) name a tool the connector sets to `{}`, and an allow \
             rule never skips that prompt. Nothing in {settings} fixes it: the connector's own \
             Tool permissions decide, where the host offers them (CLOUD-765).",
            bound.unenforceable,
            bound.postures.join(",")
        ));
    }
    findings
}

/// The last connection outcome a host log records.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Outcome {
    /// Connected.
    Attached,
    /// Failed, with the code the host put in parentheses, or `unknown`.
    Failed(String),
}

/// The text a successful connection record opens with.
const CONNECTED: &str = "Successfully connected";

/// The text a failed connection record opens with.
const FAILED: &str = "Connection failed";

/// The prefix the host gives each server's log directory.
const LOG_DIR_PREFIX: &str = "mcp-logs-";

/// CLOUD-316: every server the settings enable actually attached.
///
/// THE LAST connection outcome in the NEWEST log (by name, which is the
/// attempt's UTC start, never by mtime) decides, so a failure followed by a
/// reconnect is a session that has its server. The failure code is not fixed —
/// the next one after `-32000` was `CONNECT_TIMEOUT` — and an `error` KEY is
/// routine stderr chatter, not an outcome. A missing log ROOT is not a live
/// session and answers nothing; a root missing one server's directory is the
/// defect.
//MUTANT absent-root-judged|s@^    let Some(root) = session.logs.as_deref().filter(.root. root.is_dir()) else@    let Some(root) = session.logs.as_deref() else@|a_missing_log_root_is_not_a_live_session
fn unattached(document: &Node, session: &Session, err: &mut dyn Write) -> Result<Vec<String>> {
    let servers: Vec<String> = match document.at("enabledMcpjsonServers") {
        Look::Is(Node::List(items)) => items
            .iter()
            .filter_map(|item| match item {
                Node::Text(text) if !text.is_empty() => Some(text.clone()),
                _ => None,
            })
            .collect(),
        _ => Vec::new(),
    };
    if servers.is_empty() {
        return Ok(Vec::new());
    }
    let Some(root) = session.logs.as_deref().filter(|root| root.is_dir()) else {
        writeln!(
            err,
            "mcp posture: no MCP log tree for this project — not a live session, attach not judged"
        )?;
        return Ok(Vec::new());
    };
    let mut findings = Vec::new();
    for server in &servers {
        let dir = root.join(format!("{LOG_DIR_PREFIX}{server}"));
        if !dir.is_dir() {
            findings.push(format!(
                "{server} no-log — enabled, but this session logged no connection attempt for it"
            ));
            continue;
        }
        let Some((name, log)) = newest_log(&dir) else {
            findings.push(format!(
                "{server} no-log — its log directory holds no readable connection log"
            ));
            continue;
        };
        match last_outcome(&log) {
            Some(Outcome::Attached) => {}
            Some(Outcome::Failed(code)) => findings.push(format!(
                "{server} {code} — {}",
                spawn_verdict(server, &name, session.spawns.as_deref())
            )),
            None => findings.push(format!(
                "{server} no-outcome — its newest log records no connection result"
            )),
        }
    }
    Ok(findings)
}

/// The newest `.jsonl` log in `dir` by NAME, with its name, or `None`.
fn newest_log(dir: &Path) -> Option<(String, String)> {
    let newest = std::fs::read_dir(dir)
        .ok()?
        .filter_map(std::result::Result::ok)
        .filter(|entry| entry.path().is_file())
        .filter_map(|entry| entry.file_name().to_str().map(str::to_owned))
        .filter(|name| name.ends_with(".jsonl"))
        .max()?;
    let text = std::fs::read_to_string(dir.join(&newest)).ok()?;
    Some((newest, text))
}

/// The LAST connection outcome one log records, or `None` where it records none.
///
/// A line that is not a JSON record is skipped rather than ending the read: a
/// log the host was still writing ends in a torn line, and the outcomes before
/// it are still the session's.
//MUTANT last-outcome-ignored|s@^        .next_back()$@        .next()@|a_failure_followed_by_a_reconnect_passes
fn last_outcome(log: &str) -> Option<Outcome> {
    log.lines()
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .filter_map(|record| {
            let debug = record.get("debug")?.as_str()?.to_owned();
            if debug.starts_with(CONNECTED) {
                Some(Outcome::Attached)
            } else if debug.starts_with(FAILED) {
                Some(Outcome::Failed(failure_code(&debug)))
            } else {
                None
            }
        })
        .next_back()
}

/// The code a failure record carries in its first parentheses, or `unknown`.
fn failure_code(debug: &str) -> String {
    debug
        .split_once('(')
        .and_then(|(_, rest)| rest.split_once(')'))
        .map(|(code, _)| code)
        .filter(|code| !code.is_empty())
        .unwrap_or("unknown")
        .to_owned()
}

/// How long before an attempt's start a ledger record still counts as that
/// attempt's launch, in seconds — the retired gate's number.
const BEFORE_ATTEMPT: i64 = 5;

/// How long after an attempt's start a ledger record still counts as that
/// attempt's launch, in seconds — the retired gate's number.
const AFTER_ATTEMPT: i64 = 35;

/// Whether the spawn ledger saw this attempt's launch (CLOUD-714).
///
/// Its silence means something only once it has recorded the server at all, so
/// an absent ledger, or one that never saw this server, is `unrecorded` and
/// never `never-spawned` — a verdict from nothing.
//MUTANT spawn-window-ignored|s@ && (start - BEFORE_ATTEMPT..=start + AFTER_ATTEMPT).contains(.at)$@@|a_timeout_with_no_spawn_record_for_that_attempt_reads_as_never_spawned
//MUTANT ledger-wiring-inverted|s@^    if !records.iter().any(@    if records.iter().any(@|a_timeout_with_a_matching_spawn_record_reads_as_spawned_and_unresponsive
fn spawn_verdict(server: &str, log_name: &str, spawns: Option<&Path>) -> String {
    let Some(text) = spawns.and_then(|path| std::fs::read_to_string(path).ok()) else {
        return String::from(
            "unrecorded (no spawn ledger; launch the server through `batten mcp spawn` to tell a \
             launch that never happened from one that hung)",
        );
    };
    let records: Vec<(i64, &str)> = text
        .lines()
        .filter_map(|line| {
            let mut fields = line.split('\t');
            let at = fields.next()?.parse::<i64>().ok()?;
            Some((at, fields.next()?))
        })
        .collect();
    if !records.iter().any(|&(_, name)| name == server) {
        return format!(
            "unrecorded (the ledger has never seen {server}; its launch is not recorded through \
             `batten mcp spawn`)"
        );
    }
    let Some(start) = attempt_start(log_name) else {
        return String::from("unrecorded (the log name carries no parseable attempt time)");
    };
    let hits = records
        .iter()
        .filter(|&&(at, name)| {
            name == server && (start - BEFORE_ATTEMPT..=start + AFTER_ATTEMPT).contains(&at)
        })
        .count();
    if hits > 0 {
        String::from(
            "spawned-and-unresponsive (the ledger recorded the launch; the child ran and did not \
             answer)",
        )
    } else {
        String::from(
            "never-spawned (the ledger records every launch and recorded none for this attempt)",
        )
    }
}

/// The attempt's UTC start, from its log NAME: `2026-08-11T05-41-40-873Z.jsonl`
/// is `2026-08-11T05:41:40Z`.
fn attempt_start(log_name: &str) -> Option<i64> {
    let stem = log_name.strip_suffix(".jsonl")?;
    let (date, time) = stem.split_once('T')?;
    let fields: Vec<&str> = time.trim_end_matches('Z').split('-').collect();
    let [hour, minute, second, ..] = fields.as_slice() else {
        return None;
    };
    crate::landed::second_of(&format!("{date}T{hour}:{minute}:{second}Z"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_log_name_is_the_attempts_utc_start() {
        assert_eq!(
            attempt_start("1970-01-01T00-01-40-873Z.jsonl"),
            Some(100),
            "the milliseconds are dropped and the dashes read as the clock's colons"
        );
        assert_eq!(attempt_start("x.jsonl"), None);
        assert_eq!(attempt_start("1970-01-01T00-01-40-873Z.log"), None);
    }

    #[test]
    fn the_failure_code_is_whatever_the_parentheses_carry() {
        assert_eq!(
            failure_code("Connection failed after 10ms (-32000): closed"),
            "-32000"
        );
        assert_eq!(
            failure_code("Connection failed after 10ms (CONNECT_TIMEOUT): x"),
            "CONNECT_TIMEOUT"
        );
        assert_eq!(failure_code("Connection failed"), "unknown");
    }
}
