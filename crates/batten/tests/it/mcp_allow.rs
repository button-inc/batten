//! `[tasks.mcp-allow-check]` — no MCP permission rule is silently skipped by the
//! CLI, over the task's own body (CLOUD-1717). Coverage unions the engine's own
//! read (`batten policy tools`) with any guard, so every case runs with this
//! suite's compiled binary as `BATTEN_BIN` — never whichever one a container
//! happens to have installed, which reddened 31 cases on a runner once.
//!
//! # RETIREMENT LEDGER, PER PATH — what `shell retire partial` reads
//!
// carried: mise-tasks/mcp-allow-check.sh mise.toml kind:mechanism crates/batten/tests/it/mcp_allow.rs
// carried: tests/mcp-allow-check.bats mise.toml kind:mechanism crates/batten/tests/it/mcp_allow.rs
// carried: "this repo's own settings pass the gate today" mise.toml kind:mechanism
// carried: "a bare server rule with no connector companion passes — that is not this gate's claim" mise.toml kind:mechanism
// carried: "both spellings present is also fine" mise.toml kind:mechanism
// carried: "a connector-only allowlist needs no companion of its own" mise.toml kind:mechanism
// carried: "a glob in the server segment is reported, not accepted" mise.toml kind:mechanism
// carried: "a bare unanchored allow glob is reported" mise.toml kind:mechanism
// carried: "non-MCP allow rules are none of this gate's business" mise.toml kind:mechanism
// carried: "deny rules may glob freely — only allow rules are judged" mise.toml kind:mechanism
// carried: "output is a pointer — it names rules, never settings content at large" mise.toml kind:mechanism
// carried: "an enabled server that no allow rule names is reported" mise.toml kind:mechanism
// carried: "an enabled server granted by a tool-name glob passes" mise.toml kind:mechanism
// carried: "an enabled server granted tool by tool passes" mise.toml kind:mechanism
// carried: "a bare server-level rule grants an enabled server" mise.toml kind:mechanism
// carried: "every enabled server needs its own grant, not just one of them" mise.toml kind:mechanism
// carried: "an absent enabledMcpjsonServers leaves the predicate nothing to say" mise.toml kind:mechanism
// carried: "enabledMcpjsonServers set to true is not an enumerable list" mise.toml kind:mechanism
// carried: "unparseable settings exit 2, distinct from a failing allowlist" mise.toml kind:mechanism
// carried: "a missing settings file is not a failure this gate invents" mise.toml kind:mechanism
// carried: "a deny on a host-supplied connector with no guard coverage fails" mise.toml kind:mechanism
// carried: "a deny whose suffix the mediated rows cover passes under any server spelling" mise.toml kind:mechanism
// carried: "COULD NOT LOOK: an unavailable engine skips the coverage predicate rather than reporting it" mise.toml kind:mechanism
// carried: "a deny on a server the repo itself declares needs no guard" mise.toml kind:mechanism
// carried: "an under-matching ALLOW is deliberately not failed" mise.toml kind:mechanism
// carried: "a non-MCP deny is not this predicate's business" mise.toml kind:mechanism
// carried: "an allow rule whose tool the connector allows passes" mise.toml kind:mechanism
// carried: "an allow rule whose tool the connector sets to ask is unenforceable" mise.toml kind:mechanism
// carried: "a deny on the same tool is never reported" mise.toml kind:mechanism
// carried: "a tool no rule names is not reported, whatever its policy" mise.toml kind:mechanism
// carried: "a server that is not the toolbox is left alone" mise.toml kind:mechanism
// carried: "the finding carries no tool name, URL or header value" mise.toml kind:mechanism
// carried: "one finding per alias, with a count" mise.toml kind:mechanism
// carried: "no generated config means no verdict — the predicate is skipped, not assumed" mise.toml kind:mechanism
// carried: "without --session the connector control is not consulted" mise.toml kind:mechanism
// carried: "an enabled server with no grant keeps its own verdict" mise.toml kind:mechanism
// carried: "CLOUD-790: a pre-approved suffix the connector sets to ask is refused" mise.toml kind:mechanism
// carried: "CLOUD-790: a pre-approved suffix the connector allows is silent" mise.toml kind:mechanism
// carried: "CLOUD-790: a suffix on a server that is NOT the toolbox is judged too" mise.toml kind:mechanism
// carried: "CLOUD-790: a suffix the live config does not expose is not reported" mise.toml kind:mechanism
// carried: "CLOUD-790: no pre-approved suffix at all is a PASS, not an error" mise.toml kind:mechanism
// carried: "CLOUD-790: without --session the guard arm is not judged" mise.toml kind:mechanism
// carried: "CLOUD-790: no generated config means no verdict on the arm" mise.toml kind:mechanism
// carried: "CLOUD-790: the finding is a pointer — no server key or URL" mise.toml kind:mechanism

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::PathBuf;

const TOOLBOX_KEY: &str = "cccccccc-1111-2222-3333-444444444444";
const TOOLBOX_URL: &str = "https://api.anthropic.com/v1/code/mcp/proxy?mcp_url=https%3A%2F%2Fapi.anthropic.com%2Fv1%2Fcode%2Fmcp%2Fmeta";
const LINEAR_URL: &str =
    "https://api.anthropic.com/v1/code/mcp/proxy?mcp_url=https%3A%2F%2Fmcp.linear.app%2Fmcp";

struct Gate {
    dir: PathBuf,
    bin: String,
    guards: Option<PathBuf>,
}

impl Gate {
    fn new(name: &str) -> Self {
        // The committed config and modules, because `batten policy tools` answers
        // from the config in its working directory: coverage is a fact of THIS
        // repository's rows, and a bare directory has none.
        let dir = common::committed_fixture_with_protected(&format!("mcp-allow-{name}"));
        // No stray guards: an empty directory unless a case plants one.
        let empty = dir.join("no-guards");
        std::fs::create_dir_all(&empty).expect("guard dir");
        Self {
            dir,
            bin: env!("CARGO_BIN_EXE_batten").to_owned(),
            guards: Some(empty),
        }
    }

    fn settings(&self, json: &str) -> &Self {
        std::fs::write(self.dir.join("settings.json"), json).expect("settings");
        self
    }

    fn allow(&self, rules: &str) -> &Self {
        self.settings(&format!(
            r#"{{"permissions":{{"allow":{rules},"deny":[]}}}}"#
        ))
    }

    fn enabled(&self, servers: &str, rules: &str) -> &Self {
        self.settings(&format!(
            r#"{{"enabledMcpjsonServers":{servers},"permissions":{{"allow":{rules},"deny":[]}}}}"#
        ))
    }

    fn denies(&self, rules: &str) -> &Self {
        self.settings(&format!(
            r#"{{"permissions":{{"allow":[],"deny":{rules}}}}}"#
        ))
    }

    /// A generated config in the host's shape, with per-tool controls.
    fn config(&self, key: &str, url: &str, tools: &[(&str, &str)]) -> &Self {
        let tools: Vec<serde_json::Value> = tools
            .iter()
            .map(|(name, policy)| serde_json::json!({"name": name, "permission_policy": policy}))
            .collect();
        let config = serde_json::json!({"mcpServers": {key: {
            "type": "http", "url": url,
            "headers": {"authorization": "Bearer s3cr3t"},
            "tools": tools,
        }}});
        std::fs::write(self.dir.join("mcp-config.json"), config.to_string()).expect("config");
        self
    }

    fn toolbox(&self, tools: &[(&str, &str)]) -> &Self {
        self.config(TOOLBOX_KEY, TOOLBOX_URL, tools)
    }

    /// A stand-in guard publishing pre-approved suffixes via `--covers-allow`.
    fn guard(&mut self, suffixes: &[&str]) -> &mut Self {
        let dir = self.dir.join("guards");
        std::fs::create_dir_all(&dir).expect("guards");
        let mut body =
            String::from("#!/usr/bin/env bash\n[ \"${1:-}\" = \"--covers-allow\" ] || exit 0\n");
        for suffix in suffixes {
            body.push_str(&format!("printf '%s\\n' {suffix}\n"));
        }
        let path = dir.join("fixture-guard.sh");
        std::fs::write(&path, body).expect("guard");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        }
        self.guards = Some(dir);
        self
    }

    fn run_at(&self, settings: &str, session: bool) -> (Option<i32>, String) {
        let mut command = common::task_bash(&self.dir, &common::task_body("mcp-allow-check"));
        command.arg("_");
        if session {
            command.arg("--session");
        }
        command
            .arg(settings)
            .env_remove("usage_args")
            .env("MISE_CONFIG_FILE", common::at_root("mise.toml"))
            .env("BATTEN_BIN", &self.bin)
            .env("BATTEN_MCP_CONFIG", self.dir.join("mcp-config.json"));
        if let Some(guards) = &self.guards {
            command.env("BATTEN_GUARD_DIR", guards);
        }
        let out = command.output().expect("run the gate");
        (
            out.status.code(),
            format!(
                "{}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            ),
        )
    }

    fn run(&self) -> (Option<i32>, String) {
        self.run_at(&self.dir.join("settings.json").display().to_string(), false)
    }

    fn session(&self) -> (Option<i32>, String) {
        self.run_at(&self.dir.join("settings.json").display().to_string(), true)
    }
}

fn passes(result: (Option<i32>, String)) {
    assert_eq!(result.0, Some(0), "{}", result.1);
}

fn fails(result: (Option<i32>, String), needles: &[&str]) -> String {
    assert_eq!(result.0, Some(1), "{}", result.1);
    for needle in needles {
        assert!(result.1.contains(needle), "{needle}: {}", result.1);
    }
    result.1
}

#[test]
fn this_repos_own_settings_pass_the_gate_today() {
    let gate = Gate::new("own");
    passes(
        gate.run_at(
            &common::at_root(".claude/settings.json")
                .display()
                .to_string(),
            false,
        ),
    );
}

#[test]
fn well_formed_allow_rules_pass() {
    let gate = Gate::new("well-formed");
    for rules in [
        r#"["mcp__Linear"]"#,
        r#"["mcp__Linear", "mcp__claude_ai_Linear__*"]"#,
        r#"["mcp__claude_ai_Slack__slack_send_message"]"#,
        r#"["Bash(git:*)", "Bash(mise:*)"]"#,
        r#"["Bash(git:*)"]"#,
        // An under-matching ALLOW fails closed, into a prompt a human sees.
        r#"["mcp__Claude_Code_Remote__get_session"]"#,
    ] {
        gate.allow(rules);
        passes(gate.run());
    }
    // Output is a pointer: never the settings content at large.
    gate.allow(r#"["mcp__Linear"]"#);
    assert!(!gate.run().1.contains(r#""permissions""#));
}

#[test]
fn a_glob_in_the_server_segment_is_reported() {
    let gate = Gate::new("server-glob");
    gate.allow(r#"["mcp__claude_ai_*__read", "mcp__claude_ai_Linear__*", "mcp__Linear"]"#);
    fails(gate.run(), &["server segment cannot be a glob"]);
    gate.allow(r#"["*"]"#);
    fails(gate.run(), &["auto-approves nothing"]);
    // Deny rules may glob freely.
    gate.denies(r#"["mcp__*","*"]"#);
    passes(gate.run());
}

#[test]
fn an_enabled_server_that_no_allow_rule_names_is_reported() {
    let gate = Gate::new("enabled");
    gate.enabled(r#"["serena"]"#, r#"["Bash(git:*)", "mcp__Linear__*"]"#);
    fails(gate.run(), &["no allow rule names it", "serena"]);
    for rules in [
        r#"["mcp__serena__*"]"#,
        r#"["mcp__serena__read_memory", "mcp__serena__list_memories"]"#,
        r#"["mcp__serena"]"#,
    ] {
        gate.enabled(r#"["serena"]"#, rules);
        passes(gate.run());
    }
    gate.enabled(r#"["serena", "other"]"#, r#"["mcp__serena__*"]"#);
    fails(gate.run(), &["other"]);
    // A boolean there is not an enumerable list.
    gate.enabled("true", r#"["Bash(git:*)"]"#);
    passes(gate.run());
}

#[test]
fn unreadable_or_absent_settings_are_distinct_answers() {
    let gate = Gate::new("settings");
    gate.settings("not json\n");
    assert_eq!(gate.run().0, Some(2));
    let (code, text) = gate.run_at(&gate.dir.join("absent.json").display().to_string(), false);
    assert_eq!(code, Some(0), "{text}");
    assert!(text.contains("nothing to check"), "{text}");
}

#[test]
fn a_deny_on_a_host_supplied_connector_with_no_coverage_fails() {
    let gate = Gate::new("uncovered");
    gate.denies(r#"["mcp__Claude_Code_Remote__archive_session"]"#);
    fails(gate.run(), &["archive_session", "enforces nothing"]);
}

/// The seam's end-to-end assertion: passes only if the engine read reaches it.
#[test]
fn a_deny_whose_suffix_the_mediated_rows_cover_passes_under_any_server_spelling() {
    let gate = Gate::new("covered");
    gate.denies(
        r#"["mcp__Claude_Code_Remote__send_later","mcp__bf7c680d-5fdc-5ef4-b4a0-abadb619bf0a__send_later"]"#,
    );
    passes(gate.run());
}

#[test]
fn an_unavailable_engine_skips_the_coverage_predicate() {
    let mut gate = Gate::new("no-engine");
    gate.bin = gate.dir.join("does-not-exist").display().to_string();
    gate.denies(r#"["mcp__Claude_Code_Remote__archive_session"]"#);
    let (code, text) = gate.run();
    assert_eq!(code, Some(0), "{text}");
    assert!(text.contains("not judged"), "{text}");
    assert!(!text.contains("enforces nothing"), "{text}");
}

#[test]
fn a_deny_on_a_declared_or_non_mcp_server_is_not_this_predicates() {
    let gate = Gate::new("declared");
    gate.settings(
        r#"{"enabledMcpjsonServers":["serena"],"permissions":{"allow":["mcp__serena__*"],"deny":["mcp__serena__delete_memory"]}}"#,
    );
    passes(gate.run());
    gate.denies(r#"["Bash(rm -rf *)"]"#);
    passes(gate.run());
}

#[test]
fn an_allow_rule_whose_tool_the_connector_allows_passes() {
    let gate = Gate::new("allows");
    gate.allow(r#"["mcp__Claude_Code_Remote__list_sessions"]"#)
        .toolbox(&[("list_sessions", "always_allow")]);
    passes(gate.session());
    // A tool no rule names is not reported, whatever its policy.
    gate.toolbox(&[
        ("list_sessions", "always_allow"),
        ("create_session", "always_ask"),
    ]);
    passes(gate.session());
}

/// THE DISCRIMINATOR (CLOUD-765): well-formed, committed alias, attached — and
/// the connector sets the tool to ask.
#[test]
fn an_allow_rule_whose_tool_the_connector_sets_to_ask_is_unenforceable() {
    let gate = Gate::new("ask");
    gate.allow(r#"["mcp__Claude_Code_Remote__list_sessions"]"#)
        .toolbox(&[("list_sessions", "always_ask")]);
    let text = fails(gate.session(), &["always_ask", "Tool permissions"]);
    // Pointer-only: no tool name, URL or header value.
    assert!(!text.contains("list_sessions"), "{text}");
    assert!(!text.contains("s3cr3t"), "{text}");
    assert!(!text.contains("api.anthropic.com"), "{text}");
    // Without --session the connector control is not consulted.
    passes(gate.run());
}

#[test]
fn a_deny_on_the_same_tool_is_never_reported() {
    let gate = Gate::new("deny-ask");
    gate.denies(r#"["mcp__Claude_Code_Remote__send_later"]"#)
        .toolbox(&[("send_later", "always_ask")]);
    passes(gate.session());
}

#[test]
fn a_server_that_is_not_the_toolbox_is_left_alone() {
    let gate = Gate::new("linear");
    gate.allow(r#"["mcp__Linear__list_issues"]"#).config(
        "dddddddd-9999-8888-7777-666666666666",
        LINEAR_URL,
        &[("list_issues", "always_ask")],
    );
    passes(gate.session());
}

#[test]
fn one_finding_per_alias_with_a_count() {
    let gate = Gate::new("count");
    gate.allow(
        r#"["mcp__Claude_Code_Remote__list_sessions","mcp__Claude_Code_Remote__get_session","mcp__Claude_Code_Remote__create_session"]"#,
    )
    .toolbox(&[
        ("list_sessions", "always_ask"),
        ("get_session", "always_ask"),
        ("create_session", "always_ask"),
    ]);
    let text = fails(gate.session(), &["3 allow rule(s)"]);
    assert_eq!(text.matches("Claude_Code_Remote").count(), 1, "{text}");
}

#[test]
fn no_generated_config_means_no_verdict() {
    let mut gate = Gate::new("no-config");
    gate.allow(r#"["mcp__Claude_Code_Remote__list_sessions"]"#);
    passes(gate.session());
    gate.allow("[]");
    gate.guard(&["unsubscribe_pr_activity"]);
    passes(gate.session());
}

#[test]
fn an_enabled_server_with_no_grant_keeps_its_own_verdict() {
    let gate = Gate::new("keeps");
    gate.enabled(r#"["serena"]"#, r#"["mcp__github__create_pull_request"]"#)
        .toolbox(&[("create_pull_request", "always_allow")]);
    fails(gate.session(), &["every call to it prompts"]);
}

/// THE DISCRIMINATOR for CLOUD-790: no rule names the tool; a hook made the claim.
#[test]
fn a_preapproved_suffix_the_connector_sets_to_ask_is_refused() {
    let mut gate = Gate::new("arm-ask");
    gate.allow("[]")
        .toolbox(&[("unsubscribe_pr_activity", "always_ask")]);
    gate.guard(&["unsubscribe_pr_activity"]);
    let text = fails(
        gate.session(),
        &["unsubscribe_pr_activity", "always_ask", "Tool permissions"],
    );
    // A pointer: no server key or URL.
    assert!(!text.contains("cccccccc"), "{text}");
    assert!(!text.contains("http"), "{text}");
    assert!(!text.contains("s3cr3t"), "{text}");
    // Without --session the arm is not judged.
    passes(gate.run());
}

#[test]
fn a_preapproved_suffix_the_connector_allows_or_does_not_expose_is_silent() {
    let mut gate = Gate::new("arm-silent");
    gate.allow("[]")
        .toolbox(&[("unsubscribe_pr_activity", "always_allow")]);
    gate.guard(&["unsubscribe_pr_activity"]);
    passes(gate.session());
    gate.toolbox(&[("list_sessions", "always_ask")]);
    passes(gate.session());
}

/// A hook decides by suffix, so the arm spans every exposed server.
#[test]
fn a_suffix_on_a_server_that_is_not_the_toolbox_is_judged_too() {
    let mut gate = Gate::new("arm-linear");
    gate.allow("[]").config(
        "dddddddd-9999-8888-7777-666666666666",
        LINEAR_URL,
        &[("list_issues", "always_ask")],
    );
    gate.guard(&["list_issues"]);
    fails(gate.session(), &["list_issues"]);
}

#[test]
fn no_preapproved_suffix_at_all_is_a_silent_pass() {
    let gate = Gate::new("arm-none");
    gate.allow("[]")
        .toolbox(&[("unsubscribe_pr_activity", "always_ask")]);
    assert_eq!(gate.session(), (Some(0), String::new()));
}
