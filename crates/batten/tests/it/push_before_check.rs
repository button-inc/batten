//! A slow local check over committed, unpushed work is refused (CLOUD-2489).
//!
//! Over the compiled binary: the hook resolves `head-unpushed` from the clone's
//! own refs, and the COMMITTED module refuses `mise run verify` while HEAD holds
//! a commit no remote-tracking ref reaches. The module's own `test_` cases
//! fabricate the fact; this tier proves the engine builds it.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::{Path, PathBuf};

use crate::common;

/// The committed row's shape and its declared pattern, read from the committed
/// config rather than re-typed, so a regex edited there is the one tested here.
fn config() -> String {
    let committed: toml::Value = toml::from_str(
        &std::fs::read_to_string(common::at_root("batten.toml")).expect("the committed config"),
    )
    .expect("the committed config parses");
    let regex = committed["pattern"]
        .as_array()
        .expect("[[pattern]] rows")
        .iter()
        .find(|row| row["id"].as_str() == Some("slow-check"))
        .and_then(|row| row["regex"].as_str())
        .expect("slow-check is declared")
        .to_owned();
    format!(
        "version = 1\n\n[[rule]]\nid = \"check run early\"\nkind = \"policy\"\n\
         scope = \"mediated_call\"\nmodule = \"policy/push-before-check.rego\"\n\
         severity = \"deny\"\n\n[[pattern]]\nid = \"slow-check\"\nregex = '{regex}'\n"
    )
}

/// A repository whose HEAD carries one commit beyond its base; `pushed` pins
/// `origin/main` to that head, so the walk finds nothing unpushed.
fn repo(name: &str, pushed: bool) -> PathBuf {
    let dir = common::Fixture::new(name)
        .config(&config())
        .base_commit()
        .build();
    let module = common::at_root("policy/push-before-check.rego");
    std::fs::create_dir_all(dir.join("policy")).expect("scratch policy dir");
    std::fs::copy(module, dir.join("policy/push-before-check.rego"))
        .expect("install the committed module");
    common::git_in(&dir, &["add", "-A"]);
    common::git_in(&dir, &["commit", "--quiet", "-m", "work"]);
    if pushed {
        common::pin_origin_main(&dir);
    }
    dir
}

fn decision(dir: &Path, command: &str) -> String {
    let escaped = serde_json::to_string(command).expect("a command is encodable");
    let payload = format!(
        "{{\"hook_event_name\":\"PreToolUse\",\"tool_name\":\"Bash\",\
         \"tool_input\":{{\"command\":{escaped},\"run_in_background\":true}}}}"
    );
    common::stdout(&common::run_with_stdin(
        dir,
        &["adjudicate", "--harness", "claude-code"],
        &payload,
    ))
}

/// THE REFUSAL, over a fact the engine resolved. `#MUTANT unpushed-ignored`
/// reddens here.
#[test]
fn an_unpushed_head_refuses_a_slow_check() {
    let dir = repo("push-before-check-unpushed", false);
    let out = decision(&dir, "mise run verify");
    assert!(
        out.contains("\"deny\"") && out.contains("check run early"),
        "{out}"
    );
    // ANTI-VACUITY: the same tree admits `land`, the push that is the remedy.
    let land = decision(&dir, "mise run land");
    assert!(!land.contains("check run early"), "{land}");
}

/// The pass side: once every commit is on a remote, the check runs.
#[test]
fn a_pushed_head_runs_the_check() {
    let dir = repo("push-before-check-pushed", true);
    let out = decision(&dir, "mise run verify");
    assert!(!out.contains("check run early"), "{out}");
}

/// COULD NOT LOOK DECIDES NOTHING. An unborn HEAD has no commit to walk from, so
/// the fact is `null`, and a gate refusing on its own failed query is a wall. The
/// same repository's config loads, so the silence is the module's and not a load
/// failure's. `#MUTANT could-not-look-refuses` reddens here.
#[test]
fn a_head_that_could_not_be_read_decides_nothing() {
    let dir = common::Fixture::new("push-before-check-unborn")
        .config(&config())
        .build();
    let module = common::at_root("policy/push-before-check.rego");
    std::fs::create_dir_all(dir.join("policy")).expect("scratch policy dir");
    std::fs::copy(module, dir.join("policy/push-before-check.rego"))
        .expect("install the committed module");
    let out = decision(&dir, "mise run verify");
    assert!(!out.contains("check run early"), "{out}");
}
