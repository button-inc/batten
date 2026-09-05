//! The connector tool census (CLOUD-1359).
//!
//! **What the two existing gates structurally cannot see.** `mcp-attach-check`
//! and `mcp-allow-check` both passed green through an entire session in which
//! every Linear write was denied, and through a second in which no
//! `mcp__Linear__*` tool was exposed at all. A gate over the settings file checks
//! that *a* name is allowed; it never checks that the name the host chose is the
//! one allowed, and it cannot see a tool that will stop for a human. So the green
//! is real about the object it inspects and silent about the object anyone cares
//! about.
//!
//! Every case drives `mcp::bound` over a wiring file on disk, through the same
//! source walk `wiring` uses, rather than constructing a `Bound` — a fabricated
//! value would assert a comparison the engine may be unable to perform, which is
//! the trap `.claude/rules/policy-modules.md` records for a second test tier.

use crate::common;

use std::path::PathBuf;

use batten::mcp::{self, McpConfig, Unresolved};
use common::Fixture;

/// A repository whose one source reads `wiring.json` beside it.
fn repo(name: &str, wiring: &str) -> PathBuf {
    Fixture::new(name)
        .config(
            r#"
version = 1

[[mcp.source]]
id = "project"
path = "wiring.json"
node = "mcpServers"
"#,
        )
        .file("wiring.json", wiring)
        .git()
        .build()
}

/// The declared source set, as the config surface parses it.
fn config() -> McpConfig {
    toml::from_str(
        r#"
[[source]]
id = "project"
path = "wiring.json"
node = "mcpServers"
"#,
    )
    .expect("the source table parses")
}

/// A wiring file declaring `tools` with the given postures.
fn wiring_with(postures: &[&str]) -> String {
    let tools: Vec<serde_json::Value> = postures
        .iter()
        .enumerate()
        .map(|(at, posture)| {
            serde_json::json!({ "name": format!("tool_{at}"), "permission_policy": posture })
        })
        .collect();
    serde_json::json!({
        "mcpServers": {
            "tracker": { "url": "https://example.test/mcp", "tools": tools }
        }
    })
    .to_string()
}

#[test]
fn a_connector_whose_tools_all_ask_is_mandatory_approval_not_an_ungranted_one() {
    // THE DISCRIMINATING TELL. `mem:connector-allowlist-recovery`: a grantable
    // connector shows a MIX — Linear measured 57 `always_allow` against 1
    // `always_ask` — where the session-management server measured 20 of 20
    // asking, read-only tools included. Reporting both the same way is what sent
    // somebody to a settings screen that does not exist for the second, which
    // that memory records happening more than once.
    let dir = repo("bound-mandatory", &wiring_with(&["always_ask"; 4]));
    let census = mcp::bound(&config(), &dir, "tracker", &[]).expect("the source answers");

    assert_eq!(census.declared, 4);
    assert_eq!(census.asks, 4);
    assert!(
        census.mandatory(),
        "every declared tool asking is a mandatory-approval connector, which no local grant moves"
    );
}

#[test]
fn a_connector_with_a_mix_is_ordinary_however_many_ask() {
    // The anti-vacuity mirror for the case above: without it, `mandatory()`
    // could be `asks > 0` and both cases would still pass.
    let dir = repo(
        "bound-mixed",
        &wiring_with(&["always_allow", "always_allow", "always_ask"]),
    );
    let census = mcp::bound(&config(), &dir, "tracker", &[]).expect("the source answers");

    assert_eq!(census.asks, 1, "one tool asks");
    assert!(
        !census.mandatory(),
        "a mix is an ordinary connector — the one asking tool is grantable"
    );
}

#[test]
fn a_wiring_file_that_will_not_parse_is_could_not_look_and_never_a_clean_census() {
    // §2's load-bearing arm, and the whole reason this row exists: reading "I
    // could not compare" as "they match" is the defect being fixed, one layer up.
    // A census of zero and a file nobody could read must not be the same answer.
    let dir = repo("bound-unreadable", "{ this is not json");

    assert_eq!(
        mcp::bound(&config(), &dir, "tracker", &[]),
        Err(Unresolved::Unreadable {
            source: "project".to_owned()
        }),
        "an unparseable wiring file is could-not-look"
    );
}

#[test]
fn a_server_no_source_names_is_not_found_rather_than_empty() {
    // The other could-not-look direction, kept distinct from the one above: the
    // file read and parsed fine and simply does not carry this server.
    let dir = repo("bound-absent", &wiring_with(&["always_allow"]));

    assert_eq!(
        mcp::bound(&config(), &dir, "absent", &[]),
        Err(Unresolved::NotFound {
            tried: vec!["project".to_owned()]
        })
    );
}

#[test]
fn a_present_but_empty_tools_array_is_a_real_reading_of_zero() {
    // Distinct from every could-not-look above. A server that genuinely declares
    // no tools is an answer, and `mandatory()` must not fire on it — otherwise
    // the emptiest possible wiring reads as the most locked-down connector.
    let dir = repo("bound-empty", &wiring_with(&[]));
    let census = mcp::bound(&config(), &dir, "tracker", &[]).expect("the source answers");

    assert_eq!(census.declared, 0);
    assert!(
        !census.mandatory(),
        "zero declared tools is not a mandatory-approval connector"
    );
}

#[test]
fn a_tool_declaring_no_posture_does_not_count_as_asking() {
    // Caught while building this: an absent `permission_policy` counted as
    // `always_ask` in the first draft, which would make every wiring that omits
    // the field read as mandatory-approval. The absent key is the host saying
    // nothing.
    let raw = serde_json::json!({
        "mcpServers": {
            "tracker": {
                "url": "https://example.test/mcp",
                "tools": [{ "name": "t" }, { "name": "u", "permission_policy": "always_ask" }]
            }
        }
    })
    .to_string();
    let dir = repo("bound-no-posture", &raw);
    let census = mcp::bound(&config(), &dir, "tracker", &[]).expect("the source answers");

    assert_eq!(census.declared, 2);
    assert_eq!(census.asks, 1, "only the tool that says so is counted");
}

// --- the user-level grant half -------------------------------------------

/// A settings file at `path` granting `rules`.
fn settings(dir: &std::path::Path, name: &str, rules: &[&str]) -> PathBuf {
    let at = dir.join(name);
    let body = serde_json::json!({ "permissions": { "allow": rules } });
    std::fs::write(&at, body.to_string()).expect("the settings file writes");
    at
}

#[test]
fn a_registered_server_with_no_grant_is_a_finding() {
    // The gap measured on CLOUD-178: nothing checks the grants, and that is where
    // the live server name goes.
    let dir = repo("bound-ungranted", &wiring_with(&["always_allow"]));
    let file = settings(&dir, "settings.json", &["mcp__other", "Read"]);
    let census = mcp::bound(&config(), &dir, "tracker", &[file]).expect("the source answers");

    assert_eq!(
        census.granted,
        Some(false),
        "a file that read and does not name the server is a real finding"
    );
}

#[test]
fn a_server_level_grant_answers_for_the_server() {
    let dir = repo("bound-granted", &wiring_with(&["always_allow"]));
    let file = settings(&dir, "settings.json", &["mcp__tracker"]);
    let census = mcp::bound(&config(), &dir, "tracker", &[file]).expect("the source answers");

    assert_eq!(census.granted, Some(true));
}

#[test]
fn a_per_tool_grant_answers_for_the_server_too() {
    let dir = repo("bound-granted-tool", &wiring_with(&["always_allow"]));
    let file = settings(&dir, "settings.json", &["mcp__tracker__get_issue"]);
    let census = mcp::bound(&config(), &dir, "tracker", &[file]).expect("the source answers");

    assert_eq!(census.granted, Some(true));
}

#[test]
fn the_wildcard_spelling_reads_as_a_grant_and_is_not_honoured() {
    // Measured 2026-09-05 (`mem:serena-setup`): `.claude/settings.json` carried
    // `mcp__serena__*`, which matches nothing, and every call prompted against a
    // file that looked correct to a reader. A census that honoured the wildcard
    // would report `granted` over exactly the configuration that does not grant.
    let dir = repo("bound-wildcard", &wiring_with(&["always_allow"]));
    let file = settings(&dir, "settings.json", &["mcp__tracker__*"]);
    let census = mcp::bound(&config(), &dir, "tracker", &[file]).expect("the source answers");

    assert_eq!(
        census.granted,
        Some(false),
        "a trailing `__*` is not one of the two MCP grant forms"
    );
}

#[test]
fn a_prefix_that_merely_starts_the_same_does_not_grant() {
    // `mcp__tracker2` starts with `mcp__tracker` as a string and names a
    // different server. Without the separator check this passes and the census
    // reports a grant nobody wrote.
    let dir = repo("bound-prefix", &wiring_with(&["always_allow"]));
    let file = settings(&dir, "settings.json", &["mcp__tracker2"]);
    let census = mcp::bound(&config(), &dir, "tracker", &[file]).expect("the source answers");

    assert_eq!(census.granted, Some(false));
}

#[test]
fn no_readable_settings_file_is_could_not_look_and_never_ungranted() {
    // The three-valued read on the grant half. An absent settings file means the
    // comparison did not happen; reporting `false` would be a finding about the
    // environment dressed as a finding about the session.
    let dir = repo("bound-nosettings", &wiring_with(&["always_allow"]));
    let census = mcp::bound(&config(), &dir, "tracker", &[dir.join("nothing.json")])
        .expect("the source answers");

    assert_eq!(
        census.granted, None,
        "no readable settings file is could-not-look"
    );
}

#[test]
fn an_unparseable_settings_file_is_could_not_look_too() {
    let dir = repo("bound-badsettings", &wiring_with(&["always_allow"]));
    let at = dir.join("settings.json");
    std::fs::write(&at, "{ not json").expect("the settings file writes");
    let census = mcp::bound(&config(), &dir, "tracker", &[at]).expect("the source answers");

    assert_eq!(census.granted, None);
}

#[test]
fn a_later_file_can_grant_what_an_earlier_one_does_not() {
    // The repo file and the user-level file are both candidates, and
    // `mem:connector-allowlist-recovery` step 2 names the user-level one as where
    // an account-specific live name goes — rule 1 keeps it out of the committed
    // file. So a grant in either answers.
    let dir = repo("bound-two-files", &wiring_with(&["always_allow"]));
    let repo_file = settings(&dir, "repo.json", &["Read"]);
    let user_file = settings(&dir, "user.json", &["mcp__tracker"]);
    let census = mcp::bound(&config(), &dir, "tracker", &[repo_file, user_file])
        .expect("the source answers");

    assert_eq!(census.granted, Some(true));
}

#[test]
fn no_finding_carries_a_tool_name_or_a_key() {
    // Non-negotiable rules 1 and 4, held in the TYPE rather than by each caller
    // remembering. `Bound` is three integers-or-bools wide and there is no field a
    // UUID, a tool name, a header or an endpoint could occupy — so this asserts
    // the shape stays that way rather than scanning an output for leaks.
    let dir = repo("bound-pointer", &wiring_with(&["always_ask"]));
    let census = mcp::bound(&config(), &dir, "tracker", &[]).expect("the source answers");

    let rendered = format!("{census:?}");
    assert!(
        !rendered.contains("tool_0") && !rendered.contains("example.test"),
        "the census carries counts, never a tool name or an endpoint: {rendered}"
    );
}
