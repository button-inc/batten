//! `mcp grant`: apply the committed MCP permissions to whichever server name
//! the host exposed this session (CLOUD-191; CLOUD-843, retiring
//! `connector-allow-resolve`).
//!
//! # Why a verb and not a policy module
//!
//! The key a host exposes a server under is minted per registration episode
//! (CLOUD-178): `mcp__Claude_Code_Remote__*` in one, a UUID in the next. A deny
//! rule spelled with the committed name then enforces nothing, and an allow rule
//! grants nothing, silently. Which committed server a LIVE key refers to is a
//! property of the world — it is answered by the host-injected wiring's endpoint
//! — and a mediated-call module sees `input.call` and `input.facts` and no file
//! at all. So the read is here, and the decision it applies is the committed
//! file's own: this grants nothing the file does not already state.
//!
//! # Everything a host or a consumer knows arrives as data
//!
//! Which servers a permission file governs is `[mcp] permission_aliases`; which
//! endpoint identifies each is its `[[mcp.source]]` row's `endpoint_contains`;
//! where the settings live is resolved by the caller and handed in. Nothing here
//! names a server, a vendor address or a harness path (non-negotiable rule 1).
//!
//! # Every degradation is silence
//!
//! A guard that cannot read its inputs must neither grant nor refuse: an unread
//! file answering `allow` would pre-approve a call nobody committed, and one
//! answering `deny` would refuse a call the engine's own rows allow. The
//! tool-keyed deny rows still refuse a denied verb whatever the host calls the
//! server, so silence costs a prompt and never an enforcement.

use std::io::Write;
use std::path::Path;

use anyhow::Result;

use crate::exit::ExitCode;
use crate::facts::{Format, Look, Node};
use crate::mcp::{self, McpConfig};

/// What the committed permissions say about one exposed tool.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// A committed allow rule names it under its governed name.
    Allow,
    /// A committed deny rule names it under its governed name.
    Deny,
    /// Nothing to apply: an unrenamed key, an ungoverned server, an unstated
    /// verb, or an input that could not be read.
    Silence,
}

impl Verdict {
    /// The stable lowercase token a report prints.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Verdict::Allow => "allow",
            Verdict::Deny => "deny",
            Verdict::Silence => "silence",
        }
    }
}

/// A verdict, and the governed name it was reached under.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolution {
    /// What the committed file says.
    pub verdict: Verdict,
    /// The governed name the exposed key resolved to, or `None` where it
    /// resolved to none. Never the exposed key itself.
    pub alias: Option<String>,
}

impl Resolution {
    const fn silence(alias: Option<String>) -> Self {
        Self {
            verdict: Verdict::Silence,
            alias,
        }
    }
}

/// Where `mcp grant` and `mcp posture` read.
#[derive(Debug, Clone, Copy)]
pub struct Inputs<'a> {
    /// The resolved `[mcp]` table.
    pub config: &'a McpConfig,
    /// The repository root the sources resolve beneath.
    pub repo_root: &'a Path,
    /// The permission settings file to judge.
    pub settings: &'a Path,
    /// A host-injected wiring file read in place of each source's own path.
    pub wiring: Option<&'a Path>,
}

impl Inputs<'_> {
    /// The settings path as a report names it: relative to the root where it
    /// lies beneath it, so no report carries a machine's home directory.
    #[must_use]
    pub fn settings_label(&self) -> String {
        self.settings
            .strip_prefix(self.repo_root)
            .unwrap_or(self.settings)
            .display()
            .to_string()
    }
}

/// `mcp__<server>__<verb>` split into its server and verb, or `None`.
///
/// The verb is everything after the FIRST separator following the server, which
/// is the retired resolver's reading: a verb may itself carry `__`.
fn split_tool(tool: &str) -> Option<(&str, &str)> {
    let rest = tool.strip_prefix("mcp__")?;
    let (server, verb) = rest.split_once("__")?;
    (!server.is_empty() && !verb.is_empty()).then_some((server, verb))
}

/// Whether a permission rule names `verb` on the governed server `alias`.
///
/// Three spellings: the exact tool, the `__*` tool glob the retired resolver
/// honoured, and the bare server rule, honoured on the owner's recorded answer
/// through [`mcp::is_bare_server_rule`] so that decision lives in one place.
fn names_verb(rule: &str, alias: &str, verb: &str) -> bool {
    let Some(tail) = rule
        .strip_prefix("mcp__")
        .and_then(|rest| rest.strip_prefix(alias))
    else {
        return false;
    };
    match tail.strip_prefix("__") {
        Some(tool) => tool == verb || tool == "*",
        None => mcp::is_bare_server_rule(rule, alias),
    }
}

/// One `permissions.<arm>` list of string rules, or `None` where the settings
/// file cannot be read or parsed.
///
/// An absent arm is an empty list rather than `None`: a file that parses and
/// states no deny has answered.
fn rules_in(settings: &Path, arm: &str) -> Option<Vec<String>> {
    let text = std::fs::read_to_string(settings).ok()?;
    let document = crate::rules::parse_node(Format::Json, &text).ok()?;
    Some(match document.at(&format!("permissions.{arm}")) {
        Look::Is(Node::List(items)) => items
            .iter()
            .filter_map(|item| match item {
                Node::Text(text) => Some(text.clone()),
                _ => None,
            })
            .collect(),
        _ => Vec::new(),
    })
}

/// A governed server map and the selectors its source declares for governed
/// names, as `(name, needle)`.
type Governed<'a> = (Node, Vec<(&'a str, &'a str)>);

/// The server maps of every source that can translate a governed name, in
/// declaration order.
///
/// A source that will not read or parse is skipped: every degradation is
/// silence, and a map nobody could read translates nothing.
fn governed_maps<'a>(inputs: &Inputs<'a>) -> Vec<Governed<'a>> {
    let config: &'a McpConfig = inputs.config;
    let mut maps = Vec::new();
    for source in &config.sources {
        let selectors: Vec<(&'a str, &'a str)> = source
            .endpoint_contains
            .iter()
            .filter(|(name, _)| config.permission_aliases.contains(name))
            .map(|(name, needle)| (name.as_str(), needle.as_str()))
            .collect();
        if selectors.is_empty() {
            continue;
        }
        if let Ok(Some(map)) = mcp::server_map(source, inputs.repo_root, inputs.wiring) {
            maps.push((map, selectors));
        }
    }
    maps
}

/// The governed name one wiring entry resolves to, by its endpoint.
///
/// EXACTLY ONE selector must match: none is an ungoverned server, and several
/// would make the answer depend on the order the selectors were declared. Both
/// are silence.
//MUTANT-SUITE crates/batten/tests/it/connector_allow.rs
//MUTANT connector-translated|s@mcp::endpoint_carries(&endpoint, needle))$@true)@|a_claude_ai_connector_resolves_to_silence_never_a_grant
fn alias_in(entry: &Node, selectors: &[(&str, &str)]) -> Option<String> {
    let endpoint = mcp::endpoint_of(entry)?;
    let matched: Vec<&str> = selectors
        .iter()
        .filter(|(_, needle)| mcp::endpoint_carries(&endpoint, needle))
        .map(|(name, _)| *name)
        .collect();
    match matched.as_slice() {
        [one] => Some((*one).to_owned()),
        _ => None,
    }
}

/// The governed name an exposed server key resolves to, or `None`.
///
/// The FIRST map carrying the key answers, which is the source precedence
/// `mcp::wiring` applies.
fn alias_of(inputs: &Inputs<'_>, key: &str) -> Option<String> {
    for (map, selectors) in governed_maps(inputs) {
        let Node::Map(entries) = &map else {
            continue;
        };
        if let Some(entry) = entries.get(key) {
            return alias_in(entry, &selectors);
        }
    }
    None
}

/// Apply the committed permissions to one exposed tool name.
///
/// Deny is tested before allow, or an allow glob would pre-approve a verb the
/// same file denies.
//MUTANT deny-loses-to-allow-glob|s@^    let verdict = if states("deny") {@    let verdict = if false \&\& states("deny") {@|a_deny_outranks_an_allow_glob_over_the_same_server
//MUTANT bare-grant-unhonoured|s@^        None => mcp::is_bare_server_rule(rule, alias),@        None => false,@|a_bare_server_rule_grants_every_verb_and_a_deny_still_wins
#[must_use]
pub fn resolve(inputs: &Inputs<'_>, tool: &str) -> Resolution {
    let Some((server, verb)) = split_tool(tool) else {
        return Resolution::silence(None);
    };
    if !inputs.settings.is_file() {
        return Resolution::silence(None);
    }
    // A NAME THE COMMITTED FILE SPELLS NEEDS NO TRANSLATION: the host matches it
    // literally, so applying the file again would only restate its answer.
    if inputs
        .config
        .permission_aliases
        .iter()
        .any(|alias| alias == server)
    {
        return Resolution::silence(Some(server.to_owned()));
    }
    let Some(alias) = alias_of(inputs, server) else {
        return Resolution::silence(None);
    };
    let states = |arm: &str| {
        rules_in(inputs.settings, arm)
            .is_some_and(|rules| rules.iter().any(|rule| names_verb(rule, &alias, verb)))
    };
    let verdict = if states("deny") {
        Verdict::Deny
    } else if states("allow") {
        Verdict::Allow
    } else {
        Verdict::Silence
    };
    Resolution {
        verdict,
        alias: Some(alias),
    }
}

/// What `mcp grant` was asked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ask<'a> {
    /// Resolve one tool name and print `<verdict> <alias>`.
    Tool(&'a str),
    /// Read a hook payload on stdin and answer on the handler contract.
    Guard,
    /// Print each live key's governed name, or `-`, in key order.
    Aliases,
}

/// `mcp grant`.
///
/// `stdin` is read by the caller and only under [`Ask::Guard`], so a resolve or
/// an alias listing never blocks on a terminal.
///
/// # Errors
///
/// Only a failed write to `out` or `err`. Every unreadable input is silence.
pub fn run_grant(
    inputs: &Inputs<'_>,
    ask: Ask<'_>,
    stdin: &str,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Result<ExitCode> {
    match ask {
        Ask::Tool(tool) => {
            let answer = resolve(inputs, tool);
            writeln!(
                out,
                "{} {}",
                answer.verdict.as_str(),
                answer.alias.as_deref().unwrap_or("-")
            )?;
            Ok(ExitCode::Success)
        }
        Ask::Aliases => {
            // THE FIRST READABLE GOVERNED MAP, which is the injected config the
            // retired `--aliases` listed. A key never reaches the output: each
            // line is its governed name or `-`, in the map's own sorted order.
            if let Some((Node::Map(entries), selectors)) = governed_maps(inputs).into_iter().next()
            {
                for entry in entries.values() {
                    let alias = alias_in(entry, &selectors);
                    writeln!(out, "{}", alias.as_deref().unwrap_or("-"))?;
                }
            }
            Ok(ExitCode::Success)
        }
        Ask::Guard => guard(inputs, stdin, out, err),
    }
}

/// The handler contract: an allow is the reason on stdout at exit 0, which a
/// pre-approving row turns into the grant; a deny is the reason on stderr at
/// exit 2; silence is nothing at exit 0.
//MUTANT translated-allow-not-emitted|s@^        Verdict::Allow => {$@        Verdict::Allow => { return Ok(ExitCode::Success);@|a_committed_allow_is_a_preapproval_under_a_flipped_name
fn guard(
    inputs: &Inputs<'_>,
    stdin: &str,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Result<ExitCode> {
    let Ok(payload) = serde_json::from_str::<serde_json::Value>(stdin) else {
        return Ok(ExitCode::Success);
    };
    let Some(tool) = payload.get("tool_name").and_then(serde_json::Value::as_str) else {
        return Ok(ExitCode::Success);
    };
    let answer = resolve(inputs, tool);
    let (Some(alias), Some((_, verb))) = (answer.alias.as_deref(), split_tool(tool)) else {
        return Ok(ExitCode::Success);
    };
    let settings = inputs.settings_label();
    match answer.verdict {
        Verdict::Allow => {
            writeln!(
                out,
                "mcp grant: {settings} already allows {verb} on {alias}. The host is exposing \
                 that server under a different name this session, so the committed rule does \
                 not match it literally — this applies the committed verdict, and grants \
                 nothing the file does not already state (CLOUD-191)."
            )?;
            Ok(ExitCode::Success)
        }
        Verdict::Deny => {
            writeln!(
                err,
                "mcp grant: {settings} denies {verb} on {alias}, and the host is exposing that \
                 server under a different name this session, so the committed deny rule does not \
                 match it literally. This applies it (CLOUD-191)."
            )?;
            Ok(ExitCode::Violation)
        }
        Verdict::Silence => Ok(ExitCode::Success),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_tool_name_splits_at_the_first_separator_after_the_server() {
        assert_eq!(split_tool("mcp__box__verb"), Some(("box", "verb")));
        assert_eq!(split_tool("mcp__box__a__b"), Some(("box", "a__b")));
        assert_eq!(split_tool("mcp__box"), None);
        assert_eq!(split_tool("Bash"), None);
        assert_eq!(split_tool("mcp____verb"), None);
    }

    #[test]
    fn a_rule_names_a_verb_exactly_by_glob_or_by_the_bare_server() {
        assert!(names_verb("mcp__box__verb", "box", "verb"));
        assert!(names_verb("mcp__box__*", "box", "verb"));
        assert!(names_verb("mcp__box", "box", "verb"));
        assert!(!names_verb("mcp__box__other", "box", "verb"));
        assert!(!names_verb("mcp__box2", "box", "verb"));
        assert!(!names_verb("mcp__box2__verb", "box", "verb"));
        assert!(!names_verb("Bash(git:*)", "box", "verb"));
    }
}
