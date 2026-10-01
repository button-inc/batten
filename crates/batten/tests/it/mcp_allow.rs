//! `grant check other` — no MCP permission rule is silently skipped by the host
//! — over the compiled binary (CLOUD-843). The module is the `claude-code-cloud`
//! preset's tree half, `mcp-grants-are-honoured.rego`, reached exactly as a
//! consumer reaches it: a `preset = "claude-code-cloud"` row at `scope = "tree"`
//! in a scratch repository that is not this one, with the classes coming from
//! the manifest rather than from a `[[verdict]]` row the fixture wrote. Its own
//! `test_` rules pin the predicate; this tier pins that the ENGINE builds the
//! three documents it reads — a dotfile, a JSON project file and the authority,
//! found by shape wherever the consumer keeps it.
//!
//! The world-scoped half of the retired gate — the grants a connector would
//! still prompt for — is `batten mcp posture`, asserted in `mcp_attach.rs`.
//!
//! # RETIREMENT LEDGER, PER PATH — what `shell retire partial` reads
//!
// carried: mise-tasks/mcp-allow-check.sh crates/batten/src/policy/presets/claude-code-cloud/mcp-grants-are-honoured.rego crates/batten/tests/it/mcp_allow.rs
// carried: tests/mcp-allow-check.bats crates/batten/src/policy/presets/claude-code-cloud/mcp-grants-are-honoured.rego crates/batten/tests/it/mcp_allow.rs
// carried: "this repo's own settings pass the gate today" crates/batten/src/policy/presets/claude-code-cloud/mcp-grants-are-honoured.rego
// carried: "a bare server rule with no connector companion passes — that is not this gate's claim" crates/batten/src/policy/presets/claude-code-cloud/mcp-grants-are-honoured.rego
// carried: "both spellings present is also fine" crates/batten/src/policy/presets/claude-code-cloud/mcp-grants-are-honoured.rego
// carried: "a connector-only allowlist needs no companion of its own" crates/batten/src/policy/presets/claude-code-cloud/mcp-grants-are-honoured.rego
// carried: "a glob in the server segment is reported, not accepted" crates/batten/src/policy/presets/claude-code-cloud/mcp-grants-are-honoured.rego
// carried: "a bare unanchored allow glob is reported" crates/batten/src/policy/presets/claude-code-cloud/mcp-grants-are-honoured.rego
// carried: "non-MCP allow rules are none of this gate's business" crates/batten/src/policy/presets/claude-code-cloud/mcp-grants-are-honoured.rego
// carried: "deny rules may glob freely — only allow rules are judged" crates/batten/src/policy/presets/claude-code-cloud/mcp-grants-are-honoured.rego
// carried: "output is a pointer — it names rules, never settings content at large" crates/batten/src/policy/presets/claude-code-cloud/mcp-grants-are-honoured.rego
// carried: "an enabled server that no allow rule names is reported" crates/batten/src/policy/presets/claude-code-cloud/mcp-grants-are-honoured.rego
// carried: "an enabled server granted by a tool-name glob passes" crates/batten/src/policy/presets/claude-code-cloud/mcp-grants-are-honoured.rego
// carried: "an enabled server granted tool by tool passes" crates/batten/src/policy/presets/claude-code-cloud/mcp-grants-are-honoured.rego
// carried: "a bare server-level rule grants an enabled server" crates/batten/src/policy/presets/claude-code-cloud/mcp-grants-are-honoured.rego
// carried: "every enabled server needs its own grant, not just one of them" crates/batten/src/policy/presets/claude-code-cloud/mcp-grants-are-honoured.rego
// carried: "an absent enabledMcpjsonServers leaves the predicate nothing to say" crates/batten/src/policy/presets/claude-code-cloud/mcp-grants-are-honoured.rego
// carried: "enabledMcpjsonServers set to true is not an enumerable list" crates/batten/src/policy/presets/claude-code-cloud/mcp-grants-are-honoured.rego
// changed: "unparseable settings exit 2, distinct from a failing allowlist" crates/batten/src/policy/presets/claude-code-cloud/mcp-grants-are-honoured.rego still distinct from a failing allowlist, but as a verdict of its own: the engine reports the unparsed document on `input.tree.missing` and the module raises `grant read unread`, so `batten check` exits 2 naming the file rather than the task exiting 2 as a usage error
// carried: "a missing settings file is not a failure this gate invents" crates/batten/src/policy/presets/claude-code-cloud/mcp-grants-are-honoured.rego
// carried: "a deny on a host-supplied connector with no guard coverage fails" crates/batten/src/policy/presets/claude-code-cloud/mcp-grants-are-honoured.rego
// changed: "a deny whose suffix the mediated rows cover passes under any server spelling" crates/batten/src/policy/presets/claude-code-cloud/mcp-grants-are-honoured.rego the covered suffixes are read from the committed `batten.toml` as a document — every `mediated_call` row's `tool` — rather than spawned out of `batten policy tools` over the resolved config; the committed rows are the ones a deny may rest on, and the retired guard `--covers` probe is withdrawn because no `*-guard.sh` exists
// changed: "COULD NOT LOOK: an unavailable engine skips the coverage predicate rather than reporting it" crates/batten/src/policy/presets/claude-code-cloud/mcp-grants-are-honoured.rego there is no engine to be unavailable — the module runs inside it. The arm that survives is an authority the engine could not read, which skips the coverage predicate the same way (`test_an_unread_authority_skips_the_coverage_predicate`)
// carried: "a deny on a server the repo itself declares needs no guard" crates/batten/src/policy/presets/claude-code-cloud/mcp-grants-are-honoured.rego
// carried: "an under-matching ALLOW is deliberately not failed" crates/batten/src/policy/presets/claude-code-cloud/mcp-grants-are-honoured.rego
// carried: "a non-MCP deny is not this predicate's business" crates/batten/src/policy/presets/claude-code-cloud/mcp-grants-are-honoured.rego
// carried: "an allow rule whose tool the connector allows passes" crates/batten/src/mcp_posture.rs kind:verb
// carried: "an allow rule whose tool the connector sets to ask is unenforceable" crates/batten/src/mcp_posture.rs kind:verb
// carried: "a deny on the same tool is never reported" crates/batten/src/mcp_posture.rs kind:verb
// carried: "a tool no rule names is not reported, whatever its policy" crates/batten/src/mcp_posture.rs kind:verb
// changed: "a server that is not the toolbox is left alone" crates/batten/src/mcp_posture.rs kind:verb the toolbox is no longer a constant: a server is judged when `[mcp] permission_aliases` names it, and one it does not name is left alone
// carried: "the finding carries no tool name, URL or header value" crates/batten/src/mcp_posture.rs kind:verb
// changed: "one finding per alias, with a count" crates/batten/src/mcp_posture.rs kind:verb still one finding per governed name with a count; the bare `mcp__<server>` allow rule now counts as one rule when any declared tool asks, on the owner's recorded answer (2026-09-28) to honour the bare grant, so this repository's own finding reads 3 rules where the retired count read 2
// carried: "no generated config means no verdict — the predicate is skipped, not assumed" crates/batten/src/mcp_posture.rs kind:verb
// changed: "without --session the connector control is not consulted" crates/batten/src/mcp_posture.rs kind:verb the split is structural now rather than a flag: `batten check` runs the tree module, which cannot read the injected wiring at all, and `batten mcp posture` is the session half
// changed: "an enabled server with no grant keeps its own verdict" crates/batten/src/policy/presets/claude-code-cloud/mcp-grants-are-honoured.rego that verdict is the tree module's `grant name missing`, raised wherever `batten check` runs; `mcp posture` does not repeat it
// changed: "CLOUD-790: a pre-approved suffix the connector sets to ask is refused" crates/batten/src/mcp_posture.rs kind:verb withdrawn with the `--covers-allow` probe: no `*-guard.sh` exists and the engine has no allow arm to publish (`connector_verbs.rs`), so the set the arm judged is empty by construction
// changed: "CLOUD-790: a pre-approved suffix the connector allows is silent" crates/batten/src/mcp_posture.rs kind:verb withdrawn with the probe it judged; see the row above
// changed: "CLOUD-790: a suffix on a server that is NOT the toolbox is judged too" crates/batten/src/mcp_posture.rs kind:verb withdrawn with the probe it judged
// changed: "CLOUD-790: a suffix the live config does not expose is not reported" crates/batten/src/mcp_posture.rs kind:verb withdrawn with the probe it judged
// changed: "CLOUD-790: no pre-approved suffix at all is a PASS, not an error" crates/batten/src/mcp_posture.rs kind:verb withdrawn with the probe it judged; a clean posture is still silent at exit 0
// changed: "CLOUD-790: without --session the guard arm is not judged" crates/batten/src/mcp_posture.rs kind:verb withdrawn with the probe it judged
// changed: "CLOUD-790: no generated config means no verdict on the arm" crates/batten/src/mcp_posture.rs kind:verb withdrawn with the probe it judged
// changed: "CLOUD-790: the finding is a pointer — no server key or URL" crates/batten/src/mcp_posture.rs kind:verb withdrawn with the probe it judged; the surviving posture finding carries no key or URL (`an_allow_rule_whose_tool_the_connector_sets_to_ask_is_unenforceable`)

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::{Path, PathBuf};
use std::process::Output;

use common::{batten, git_in, scratch, stderr, stdout, write};

/// A consumer that is NOT this repository enabling the preset's tree half, and
/// ONE mediated-call row whose `tool` covers `send_later` — the coverage the deny
/// predicate reads out of this very file as a document. No module file and no
/// `[[verdict]]` row: both arrive with the preset, and a fixture copy of either
/// would test the copy.
const CONFIG: &str = r#"version = 1

[[rule]]
id = "grant check other"
kind = "policy"
scope = "tree"
preset = "claude-code-cloud"
documents = [".claude/settings.json", ".mcp.json", "batten.toml"]
severity = "deny"

[[rule]]
id = "timer mint refused"
kind = "shape"
scope = "mediated_call"
severity = "deny"
tool = "send_later"
reason = "a fixture row: its only job is to cover the send_later suffix"
"#;

/// A repository carrying the config above and — where given — a settings file
/// and a project file. Tracked, because a consumer's settings are committed and
/// a suite judging only an untracked one would not be asking a consumer's
/// question.
fn fixture(name: &str, settings: Option<&str>, project: Option<&str>) -> PathBuf {
    let repo = scratch(&format!("mcp-allow-{name}"));
    write(&repo, "batten.toml", CONFIG);
    if let Some(settings) = settings {
        write(&repo, ".claude/settings.json", settings);
    }
    if let Some(project) = project {
        write(&repo, ".mcp.json", project);
    }
    common::init_repo(&repo);
    git_in(&repo, &["add", "-A"]);
    repo
}

fn check(repo: &Path) -> Output {
    batten()
        .current_dir(repo)
        .args(["check", "--rule", "grant check other"])
        .output()
        .expect("run batten check")
}

fn allow(rules: &str) -> String {
    format!(r#"{{"permissions":{{"allow":{rules},"deny":[]}}}}"#)
}

fn enabled(servers: &str, rules: &str) -> String {
    format!(r#"{{"enabledMcpjsonServers":{servers},"permissions":{{"allow":{rules},"deny":[]}}}}"#)
}

fn denies(rules: &str) -> String {
    format!(r#"{{"permissions":{{"allow":[],"deny":{rules}}}}}"#)
}

fn passes(output: &Output) {
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}{}",
        stdout(output),
        stderr(output)
    );
}

fn refuses(output: &Output, token: &str) -> String {
    let text = format!("{}{}", stdout(output), stderr(output));
    assert_eq!(output.status.code(), Some(2), "{text}");
    assert!(text.contains(token), "{token}: {text}");
    text
}

#[test]
fn this_repos_own_settings_pass_the_gate_today() {
    // THE SELF-CONSUMPTION CASE, over the committed authority, settings and
    // project file together: the coverage this repository's denies rest on is
    // its own `mediated_call` rows.
    let output = common::run_at_real_root(
        &common::at_root(""),
        &["check", "--rule", "grant check other"],
    );
    passes(&output);
}

#[test]
fn well_formed_allow_rules_pass() {
    for (at, rules) in [
        r#"["mcp__Linear"]"#,
        r#"["mcp__Linear", "mcp__claude_ai_Linear__*"]"#,
        r#"["mcp__claude_ai_Slack__slack_send_message"]"#,
        r#"["Bash(git:*)", "Bash(mise:*)"]"#,
        // An under-matching ALLOW fails closed, into a prompt a human sees.
        r#"["mcp__Claude_Code_Remote__get_session"]"#,
    ]
    .into_iter()
    .enumerate()
    {
        let repo = fixture(&format!("well-formed-{at}"), Some(&allow(rules)), None);
        passes(&check(&repo));
    }
}

/// THE REACHABILITY PROOF IS STRUCTURAL: a refusal can only be raised if the
/// engine parsed the dotfile, so this firing is the evidence the document was
/// read.
#[test]
fn a_glob_in_the_server_segment_is_reported() {
    let repo = fixture(
        "server-glob",
        Some(&allow(
            r#"["mcp__claude_ai_*__read", "mcp__claude_ai_Linear__*", "mcp__Linear"]"#,
        )),
        None,
    );
    let text = refuses(&check(&repo), "grant spelling wrong");
    // Pointer-only: never the settings content at large.
    assert!(!text.contains(r#""permissions""#), "{text}");
    let repo = fixture("bare-glob", Some(&allow(r#"["*"]"#)), None);
    refuses(&check(&repo), "grant spelling wrong");
    // Deny rules may glob freely.
    let repo = fixture("deny-glob", Some(&denies(r#"["mcp__*","*"]"#)), None);
    passes(&check(&repo));
}

#[test]
fn an_enabled_server_that_no_allow_rule_names_is_reported() {
    let repo = fixture(
        "enabled",
        Some(&enabled(
            r#"["serena"]"#,
            r#"["Bash(git:*)", "mcp__Linear__*"]"#,
        )),
        None,
    );
    refuses(&check(&repo), "grant name missing");
    for (at, rules) in [
        r#"["mcp__serena__*"]"#,
        r#"["mcp__serena__read_memory", "mcp__serena__list_memories"]"#,
        r#"["mcp__serena"]"#,
    ]
    .into_iter()
    .enumerate()
    {
        let repo = fixture(
            &format!("enabled-granted-{at}"),
            Some(&enabled(r#"["serena"]"#, rules)),
            None,
        );
        passes(&check(&repo));
    }
    let repo = fixture(
        "enabled-two",
        Some(&enabled(r#"["serena", "other"]"#, r#"["mcp__serena__*"]"#)),
        None,
    );
    refuses(&check(&repo), "grant name missing");
    // A boolean there is not an enumerable list.
    let repo = fixture(
        "enabled-true",
        Some(&enabled("true", r#"["Bash(git:*)"]"#)),
        None,
    );
    passes(&check(&repo));
}

#[test]
fn unreadable_or_absent_settings_are_distinct_answers() {
    let repo = fixture("unparsed", Some("not json\n"), None);
    refuses(&check(&repo), "grant read unread");
    // Absent is a repository with nothing to check.
    let repo = fixture("absent", None, None);
    passes(&check(&repo));
}

#[test]
fn a_deny_on_a_host_supplied_connector_with_no_coverage_fails() {
    let repo = fixture(
        "uncovered",
        Some(&denies(r#"["mcp__Claude_Code_Remote__archive_session"]"#)),
        None,
    );
    refuses(&check(&repo), "connector deny loose");
}

/// The coverage read's end-to-end assertion: passes only if the engine parsed
/// the authority as a document and the module found the `mediated_call` row.
#[test]
fn a_deny_whose_suffix_the_mediated_rows_cover_passes_under_any_server_spelling() {
    let repo = fixture(
        "covered",
        Some(&denies(
            r#"["mcp__Claude_Code_Remote__send_later","mcp__bf7c680d-5fdc-5ef4-b4a0-abadb619bf0a__send_later"]"#,
        )),
        None,
    );
    passes(&check(&repo));
}

#[test]
fn a_deny_on_a_declared_or_non_mcp_server_is_not_this_predicates() {
    let repo = fixture(
        "declared",
        Some(
            r#"{"enabledMcpjsonServers":["serena"],"permissions":{"allow":["mcp__serena__*"],"deny":["mcp__serena__delete_memory"]}}"#,
        ),
        None,
    );
    passes(&check(&repo));
    // A server the PROJECT file declares is the repository's own name too.
    let repo = fixture(
        "project-declared",
        Some(&denies(r#"["mcp__local__drop_table"]"#)),
        Some(r#"{"mcpServers":{"local":{"command":"true"}}}"#),
    );
    passes(&check(&repo));
    let repo = fixture("non-mcp", Some(&denies(r#"["Bash(rm -rf *)"]"#)), None);
    passes(&check(&repo));
}

#[test]
fn an_unparsed_project_file_cannot_look() {
    let repo = fixture("project-unparsed", Some(&allow("[]")), Some("{ not json"));
    refuses(&check(&repo), "grant read unread");
}
