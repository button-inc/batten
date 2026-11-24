//! The compiled-binary tier for `policy/harness-config-route.rego` and
//! `policy/harness-config-advisory.rego` (CLOUD-1636).
//!
//! The modules' own `test_` rules fabricate `input.call["write-targets"]` with
//! `with input as`, which is exactly the shape the engine may be unable to
//! produce. These cases drive `batten adjudicate --harness claude-code` over a
//! real envelope, so a projection that stopped emitting the key, or emitted it
//! in another shape, turns them red.
//!
//! The bench's config is the COMMITTED rows — the `harness-config-*` family,
//! the two content patterns, both rule rows and the four verdicts — read out of
//! the repository's own `batten.toml`, so the declarations under test are the
//! ones that ship rather than a copy that can drift from them.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::{Path, PathBuf};

use common::{Fixture, run_with_stdin, stderr, stdout};

const VERDICTS: &[&str] = &[
    "hook wire wrong",
    "hook edit early",
    "grant edit early",
    "hook edit partial",
];

const RULES: &[&str] = VERDICTS;

const MODULES: &[&str] = &[
    "policy/harness-config-route.rego",
    "policy/harness-config-advisory.rego",
    "policy/harness-grant-advisory.rego",
    "policy/harness-config-neutral.rego",
];

/// The committed rows this suite judges, as one config document.
fn committed_rows(skip_pattern: Option<&str>) -> String {
    let text = std::fs::read_to_string(common::at_root("batten.toml")).expect("batten.toml reads");
    let table: toml::Table = toml::from_str(&text).expect("batten.toml parses");
    let pick = |key: &str, keep: &dyn Fn(&str) -> bool| -> toml::Value {
        let rows = table[key].as_array().expect("an array of tables");
        toml::Value::Array(
            rows.iter()
                .filter(|row| keep(row["id"].as_str().unwrap_or_default()))
                .cloned()
                .collect(),
        )
    };
    let mut document = toml::Table::new();
    document.insert("version".to_owned(), toml::Value::Integer(1));
    document.insert(
        "pattern".to_owned(),
        pick("pattern", &|id: &str| {
            Some(id) != skip_pattern
                && (id.starts_with("harness-config-")
                    || id == "harness-hook-registration"
                    || id == "harness-permission-rule")
        }),
    );
    document.insert(
        "verdict".to_owned(),
        pick("verdict", &|id: &str| VERDICTS.contains(&id)),
    );
    document.insert(
        "rule".to_owned(),
        pick("rule", &|id: &str| RULES.contains(&id)),
    );
    toml::to_string(&document).expect("the rows serialise")
}

/// A bench registering ONLY this row's modules, so no other gate's deny
/// pre-empts or explains what these cases assert.
fn bench(name: &str, skip_pattern: Option<&str>) -> PathBuf {
    let mut fixture = Fixture::new(name).config(&committed_rows(skip_pattern));
    for path in MODULES {
        let text = std::fs::read_to_string(common::at_root(path)).expect("module reads");
        fixture = fixture.file(path, &text);
    }
    fixture
        .file("rules/harness-config.md", "the consumer's doctrine\n")
        .file(".serena/memories/serena-setup.md", "the measured forms\n")
        .file("notes.md", "unrelated\n")
        .git()
        .base_commit()
        .build()
}

fn bash(command: &str) -> String {
    serde_json::json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": command},
    })
    .to_string()
}

fn write(path: &str, content: &str) -> String {
    serde_json::json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Write",
        "tool_input": {"file_path": path, "content": content},
    })
    .to_string()
}

/// The exit code and everything the door said, on either stream: an advisory
/// travels on stdout where the channel is reachable, a deny's line on stderr.
fn adjudicate(dir: &Path, payload: &str) -> (Option<i32>, String) {
    let answer = run_with_stdin(dir, &["adjudicate", "--harness", "claude-code"], payload);
    (
        answer.status.code(),
        format!("{}{}", stdout(&answer), stderr(&answer)),
    )
}

/// The checkout's settings and a session root's, both absolute as the measured
/// instance spelled them.
///
/// The root lies INSIDE the bench: a write tool is judged by the repository
/// its target lands in, and a sibling of the bench resolves to whichever
/// checkout encloses the suite, whose own gates then answer instead.
fn spellings(dir: &Path) -> (String, String) {
    let checkout = dir.canonicalize().expect("the bench resolves");
    let root = checkout.join("session-root");
    (
        checkout.join(".claude/settings.json").display().to_string(),
        root.join(".claude/settings.json").display().to_string(),
    )
}

const REGISTRATION: &str = r#"{"hooks": {"PreToolUse": [{"matcher": "", "hooks": [{"type": "command", "command": "batten adjudicate --harness claude-code"}]}]}}"#;

/// Refused, naming batten's verb and never the vendor skill.
///
/// The decision is read off the body, not the exit code: Claude Code carries a
/// deny's reason IN BAND (`Capabilities::reason_travels_in_band`), so the call
/// is refused by `permissionDecision` at exit 0.
fn assert_routed_to_the_verb(code: Option<i32>, said: &str) {
    assert_eq!(code, Some(0), "{said}");
    assert!(
        said.contains(r#""permissionDecision":"deny""#),
        "a registration is refused: {said}"
    );
    // The pointer rides the line: the module's own subject, not a bare token.
    assert!(said.contains("hook wire wrong at "), "{said}");
    assert!(said.contains("session-root"), "the registered path: {said}");
    assert!(said.contains("batten startup --repair"), "{said}");
    assert!(!said.contains("/update-config"), "{said}");
}

#[test]
fn a_symlinked_registration_is_refused_naming_the_verb() {
    let dir = bench("hcr-symlink", None);
    let (checkout, root) = spellings(&dir);
    let (code, said) = adjudicate(&dir, &bash(&format!("ln -sfn {checkout} {root}")));
    assert_routed_to_the_verb(code, &said);
}

#[test]
fn a_copied_registration_is_refused_naming_the_verb() {
    let dir = bench("hcr-copy", None);
    let (checkout, root) = spellings(&dir);
    let (code, said) = adjudicate(&dir, &bash(&format!("cp {checkout} {root}")));
    assert_routed_to_the_verb(code, &said);
}

/// A copy into the surface's DIRECTORY lands on the surface too.
#[test]
fn a_copy_into_the_surface_directory_is_refused_naming_the_verb() {
    let dir = bench("hcr-copy-dir", None);
    let (checkout, root) = spellings(&dir);
    let directory = root.trim_end_matches("settings.json");
    let (code, said) = adjudicate(&dir, &bash(&format!("cp {checkout} {directory}")));
    assert_routed_to_the_verb(code, &said);
}

#[test]
fn a_written_registration_is_refused_naming_the_verb() {
    let dir = bench("hcr-write", None);
    let (_, root) = spellings(&dir);
    let (code, said) = adjudicate(&dir, &write(&root, REGISTRATION));
    assert_routed_to_the_verb(code, &said);
}

/// A link whose SOURCE is no harness surface is not a registration, even when
/// it lands on one: the original behaviour holds, an advisory and exit 0.
#[test]
fn an_unrelated_link_is_not_refused() {
    let dir = bench("hcr-unrelated-link", None);
    let (_, root) = spellings(&dir);
    let notes = dir
        .canonicalize()
        .unwrap()
        .join("notes.md")
        .display()
        .to_string();
    let (code, said) = adjudicate(&dir, &bash(&format!("ln -s {notes} {root}")));
    assert_eq!(code, Some(0), "{said}");
    assert!(!said.contains("hook wire wrong"), "{said}");
    assert!(said.contains("hook edit early"), "{said}");
}

#[test]
fn a_link_touching_no_surface_is_silent() {
    let dir = bench("hcr-plain-link", None);
    let (code, said) = adjudicate(&dir, &bash("ln -s notes.md other.md"));
    assert_eq!(code, Some(0), "{said}");
    for verdict in VERDICTS {
        assert!(!said.contains(verdict), "{verdict}: {said}");
    }
}

/// A body registering no hook keeps the original §Done behaviour: the vendor
/// route, and the memory since it touches `permissions.allow`.
#[test]
fn a_written_body_registering_no_hook_is_told_the_vendor_route() {
    let dir = bench("hcr-write-plain", None);
    let (_, root) = spellings(&dir);
    let body = r#"{"permissions": {"allow": ["Bash(git status)"]}}"#;
    let (code, said) = adjudicate(&dir, &write(&root, body));
    assert_eq!(code, Some(0), "an advisory moves no exit code: {said}");
    assert!(!said.contains("hook wire wrong"), "{said}");
    assert!(said.contains("hook edit early"), "{said}");
    assert!(said.contains("/update-config"), "{said}");
    assert!(said.contains("grant edit early"), "{said}");
    assert!(said.contains(".serena/memories/serena-setup.md"), "{said}");
}

#[test]
fn a_settings_write_is_told_the_vendor_route() {
    let dir = bench("hcr-vendor", None);
    let (code, said) = adjudicate(&dir, &write(".claude/settings.json", r#"{"model": "x"}"#));
    assert_eq!(code, Some(0), "{said}");
    assert!(said.contains("hook edit early"), "{said}");
    assert!(said.contains("/update-config"), "{said}");
    assert!(
        !said.contains("grant edit early"),
        "no permission list moved: {said}"
    );
}

/// The neutrality half: the harnesses whose declared surface the write did not
/// reach are named, and the one it reached is not.
#[test]
fn a_settings_write_names_the_harnesses_left_behind() {
    let dir = bench("hcr-neutral", None);
    let (_, said) = adjudicate(&dir, &write(".claude/settings.json", "{}"));
    // The class's own pointer span — its token up to the route — since several
    // advisories can share one body.
    let at = said
        .find("hook edit partial")
        .unwrap_or_else(|| panic!("no neutrality line: {said}"));
    let line = &said[at..];
    let line = &line[..line.find(';').unwrap_or(line.len())];
    for left in ["cursor", "copilot-cli", "gemini-cli", "codex-cli"] {
        assert!(line.contains(left), "{left}: {said}");
    }
    assert!(
        !line.contains("claude-code"),
        "the reached harness is not left behind: {line}"
    );
}

#[test]
fn an_unrelated_write_is_silent() {
    let dir = bench("hcr-unrelated", None);
    let (code, said) = adjudicate(&dir, &write("src/lib.rs", r#""allow": true"#));
    assert_eq!(code, Some(0), "{said}");
    for verdict in VERDICTS {
        assert!(!said.contains(verdict), "{verdict}: {said}");
    }
}

/// The census: a family that leaves out a harness with wiring is refused at
/// load, naming the row it is missing.
#[test]
fn a_family_leaving_a_harness_out_is_refused_at_load() {
    let dir = bench("hcr-census", Some("harness-config-cursor"));
    let (code, said) = adjudicate(&dir, &write("src/lib.rs", "x"));
    assert_ne!(code, Some(0), "an incomplete family must not load: {said}");
    assert!(said.contains("harness-config-cursor"), "{said}");
}
