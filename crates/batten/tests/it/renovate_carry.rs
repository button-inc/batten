//! Renovate carries an action's licence row in its own bump (CLOUD-2300), and
//! the root lock's resolution into the fuzz lock in its cargo bump (CLOUD-2538).
//!
//! Three pieces must agree, and each case pins one seam: the carry script
//! decides correctly, `renovate.json5` runs it on every update of its manager,
//! and the allowlist in `.github/workflows/renovate.yml` admits exactly that
//! command and nothing beside it. A wrong allowlist fails silently in the field —
//! Renovate skips a task that matches no pattern and still pushes the bump — so
//! the match is asserted here, over the real pattern and the real template.

use crate::common::at_root;

/// The template `renovate.json5` hands Renovate, filled as Renovate fills it.
fn templated(command: &str, dep: &str, old: &str, new: &str) -> String {
    command
        .replace("{{{depName}}}", dep)
        .replace("{{{currentDigest}}}", old)
        .replace("{{{newDigest}}}", new)
}

/// The single `postUpgradeTasks` block on the rule for `manager`.
fn post_upgrade_task(manager: &str) -> serde_json::Value {
    let text = std::fs::read_to_string(at_root("renovate.json5")).expect("read renovate.json5");
    let config: serde_json::Value = json5::from_str(&text).expect("renovate.json5 parses");
    let rules = config["packageRules"].as_array().expect("packageRules");
    let tasks: Vec<&serde_json::Value> = rules
        .iter()
        .filter(|rule| rule["matchManagers"] == serde_json::json!([manager]))
        .filter_map(|rule| rule.get("postUpgradeTasks"))
        .collect();
    assert_eq!(
        tasks.len(),
        1,
        "one {manager} rule carries the post-upgrade task"
    );
    tasks[0].clone()
}

/// The `github-actions` rule's single post-upgrade command.
fn carry_command() -> String {
    let task = post_upgrade_task("github-actions");
    assert_eq!(
        task["fileFilters"],
        serde_json::json!(["mise-tasks/sbom-actions.tsv"]),
        "Renovate commits the licence table and nothing else the task touches"
    );
    let commands = task["commands"].as_array().expect("commands");
    assert_eq!(commands.len(), 1, "exactly one command");
    commands[0].as_str().expect("a command string").to_owned()
}

/// The patterns `renovate.yml` hands Renovate as `RENOVATE_ALLOWED_COMMANDS`.
fn allowed() -> Vec<regex::Regex> {
    let text = std::fs::read_to_string(at_root(".github/workflows/renovate.yml"))
        .expect("read renovate.yml");
    let docs = yaml_rust2::YamlLoader::load_from_str(&text).expect("renovate.yml parses");
    let step = docs[0]["jobs"]["renovate"]["steps"]
        .as_vec()
        .expect("steps")
        .iter()
        .find(|step| {
            step["uses"]
                .as_str()
                .is_some_and(|uses| uses.starts_with("renovatebot/github-action@"))
        })
        .expect("a renovatebot/github-action step");
    let raw = step["env"]["RENOVATE_ALLOWED_COMMANDS"]
        .as_str()
        .expect("RENOVATE_ALLOWED_COMMANDS is set");
    let patterns: Vec<String> = serde_json::from_str(raw).expect("a JSON list of patterns");
    patterns
        .iter()
        .map(|pattern| {
            assert!(
                pattern.starts_with('^') && pattern.ends_with('$'),
                "every allowed command is anchored at both ends: {pattern}"
            );
            regex::Regex::new(pattern).expect("each pattern compiles")
        })
        .collect()
}

#[test]
fn renovate_runs_the_carry_on_every_action_bump_and_the_allowlist_admits_it() {
    let command = carry_command();
    let filled = templated(
        &command,
        "actions/checkout",
        &"a".repeat(40),
        &"b".repeat(40),
    );
    assert!(
        allowed().iter().any(|pattern| pattern.is_match(&filled)),
        "the carry as Renovate will run it is admitted: {filled}"
    );
}

/// CLOUD-2538: the `cargo` group re-seeds the fuzz lock once per branch, and
/// the allowlist admits exactly that command. Fails by: the rule or the
/// pattern drifting, which Renovate answers by skipping the task and pushing a
/// bump the fuzz-lock test refuses.
#[test]
fn renovate_carries_the_fuzz_lock_on_every_cargo_branch_and_the_allowlist_admits_it() {
    assert_eq!(
        post_upgrade_task("cargo"),
        serde_json::json!({
            "commands": ["node .github/renovate/fuzz-lock-carry.mjs"],
            "fileFilters": ["fuzz/Cargo.lock"],
            "executionMode": "branch",
            "installTools": { "rust": {} },
        })
    );
    assert!(
        allowed()
            .iter()
            .any(|pattern| pattern.is_match("node .github/renovate/fuzz-lock-carry.mjs")),
        "the fuzz-lock carry is admitted"
    );
}

#[test]
fn the_allowlist_admits_nothing_beside_the_carry() {
    let patterns = allowed();
    let old = "a".repeat(40);
    let new = "b".repeat(40);
    for refused in [
        format!("node .github/renovate/sbom-carry.mjs actions/checkout {old} {new}; curl evil"),
        format!("node .github/renovate/sbom-carry.mjs actions/checkout {old} {new} && sh"),
        format!("node .github/renovate/other.mjs actions/checkout {old} {new}"),
        format!("node .github/renovate/sbom-carry.mjs $(id) {old} {new}"),
        "node .github/renovate/fuzz-lock-carry.mjs; curl evil".to_owned(),
        "node .github/renovate/fuzz-lock-carry.mjs && sh".to_owned(),
        "node .github/renovate/fuzz-lock-carry.mjs $(id)".to_owned(),
        "sh -c true".to_owned(),
    ] {
        assert!(
            !patterns.iter().any(|pattern| pattern.is_match(&refused)),
            "an allowlist entry admits more than its carry: {refused}"
        );
    }
}

#[expect(
    clippy::disallowed_types,
    reason = "stays, and test-only: the carry scripts are Node, run by Renovate rather than by this engine, so their suites are spawned as the program they are"
)]
#[test]
fn the_carry_script_passes_its_own_suite() {
    let output = std::process::Command::new(crate::common::require_tool("node"))
        .args([
            "--test",
            ".github/renovate/sbom-carry.test.mjs",
            ".github/renovate/fuzz-lock-carry.test.mjs",
        ])
        .current_dir(at_root(""))
        .output()
        .expect("run node");
    assert!(
        output.status.success(),
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
