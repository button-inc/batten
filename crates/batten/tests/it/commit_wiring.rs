//! The WIRING of the two commit gates — attribution (CLOUD-274) and the subject
//! convention (CLOUD-701) — ported from `tests/commit-attribution.bats` and
//! `tests/commit-convention.bats` under CLOUD-843.
//!
//! The predicates are tested over the compiled binary in `attribution.rs` and
//! `commit.rs`. What this file holds is that something actually INVOKES them, and
//! that each policy is data in `batten.toml` rather than a literal compiled into
//! the crate.
//!
//! # Why the wiring needs its own assertions
//!
//! CLOUD-435 removed six `PreToolUse` guards from `.claude/settings.json` and
//! every one of their suites stayed green, because each drove its task by path and
//! read no settings file. Before that, CLOUD-216 found `attribution-check` fully
//! implemented, fully tested, and wired to nothing. A gate's suite that never
//! asserts its call site measures only itself.
//!
//! # Read as commands, whichever way the task is spelled
//!
//! The retired suites matched `^run = .*batten -- …` on the task's first line,
//! which ties the pin to one quoting and one launcher. CLOUD-1397 wants the
//! commit-time steps to call the binary directly, and CLOUD-843 moves task bodies
//! to argv lists; so the engine is recognised by its VERB — `batten commit
//! check`, `batten attribution …` — in any command the task runs, whether it is
//! reached through `cargo run -p batten --` or a resolved binary.

// CLOUD-1268's fifth arm. Both suites' subjects survive — `hk.pkl` and
// `mise.toml` for the first, `batten.toml` and `mise.toml` for the second — so
// every `ported` arm names the survivor it accounts for, and between them each
// declared subject is named.
//
// ported: tests/commit-attribution.bats subject:hk.pkl subject:mise.toml crates/batten/tests/it/commit_wiring.rs
// changed: "commit-attribution.bats::the commit-time seam is wired: hk.pkl's commit-msg hook runs the gate" crates/batten/tests/it/commit_wiring.rs the step may call the engine's `attribution check --message` directly as well as through `mise run commit-attribution-msg`, which is the respelling CLOUD-1397 waits on; either is the gate, and a step running neither is still refused
// ported: "commit-attribution.bats::the range seam is wired: commit-lint depends on the gate" crates/batten/tests/it/commit_wiring.rs subject:mise.toml
// ported: "commit-attribution.bats::both tasks resolve to the engine, not to a second implementation" crates/batten/tests/it/commit_wiring.rs subject:mise.toml
// ported: "commit-attribution.bats::the policy is data: no configured pattern appears anywhere under crates/" crates/batten/tests/it/commit_wiring.rs subject:hk.pkl
// ported: "commit-attribution.bats::the accountable identity is config too, and not compiled in" crates/batten/tests/it/commit_wiring.rs subject:hk.pkl
// ported: "commit-attribution.bats::this repo's posture is silent: the allow-set is empty" crates/batten/tests/it/commit_wiring.rs subject:hk.pkl
//
// ported: tests/commit-convention.bats subject:batten.toml subject:mise.toml crates/batten/tests/it/commit_wiring.rs
// ported: "commit-convention.bats::the variable is gone: no CONVENTIONAL_RE survives in mise.toml" crates/batten/tests/it/commit_wiring.rs subject:mise.toml
// ported: "commit-convention.bats::the pattern lives in batten.toml, and exactly once" crates/batten/tests/it/commit_wiring.rs subject:batten.toml
// ported: "commit-convention.bats::the range seam is wired: commit-lint depends on the gate" crates/batten/tests/it/commit_wiring.rs subject:mise.toml
// changed: "commit-convention.bats::the commit-time seam is wired: hk.pkl's commit-msg hook runs commit-msg" crates/batten/tests/it/commit_wiring.rs the step may call the engine's `commit check --message` directly as well as through `mise run commit-msg`, which is the respelling CLOUD-1397 waits on; either is the gate, and a step running neither is still refused
// ported: "commit-convention.bats::both tasks resolve to the engine, not to a second implementation" crates/batten/tests/it/commit_wiring.rs subject:mise.toml
// ported: "commit-convention.bats::no task greps a subject pattern of its own" crates/batten/tests/it/commit_wiring.rs subject:mise.toml
// ported: "commit-convention.bats::this repo's own history satisfies its committed convention" crates/batten/tests/it/commit_wiring.rs subject:batten.toml

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::fs;
use std::path::{Path, PathBuf};

/// The repository root, canonical, for the cases whose subject is this checkout.
fn root() -> PathBuf {
    common::at_root(".")
        .canonicalize()
        .expect("this checkout is where the manifest says it is")
}

/// The committed `batten.toml`, parsed.
fn authority() -> toml::Value {
    let text = fs::read_to_string(common::at_root("batten.toml")).expect("the committed config");
    toml::from_str(&text).expect("batten.toml parses as TOML")
}

/// `[attribution].<key>` as a list of strings, empty where the key is absent.
fn attribution_list(authority: &toml::Value, key: &str) -> Vec<String> {
    authority
        .get("attribution")
        .and_then(|table| table.get(key))
        .and_then(toml::Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(toml::Value::as_str)
        .map(str::to_owned)
        .collect()
}

/// The lines of the hk step block `["<step>"] {`, up to its closing brace.
///
/// Asserted on the step block rather than on the whole file: the surrounding
/// comments name the tasks too, and a comment is not a call site.
fn hk_step(step: &str) -> Vec<String> {
    let config = fs::read_to_string(common::at_root("hk.pkl")).expect("the hook config");
    let opener = format!("[\"{step}\"] {{");
    config
        .lines()
        .skip_while(|line| line.trim() != opener)
        .skip(1)
        .take_while(|line| line.trim() != "}")
        .map(str::to_owned)
        .collect()
}

/// Whether some command of `[tasks.<task>]` invokes the engine's `verb`.
///
/// `batten -- <verb>` through `cargo run -p batten` and `batten <verb>` through a
/// resolved binary are the same engine, so both spellings count.
fn resolves_to_the_engine(task: &str, verb: &str) -> bool {
    let engine =
        regex::Regex::new(&format!(r"\bbatten(\s+--)?\s+{verb}\b")).expect("a valid expression");
    common::task_commands(task)
        .iter()
        .any(|command| engine.is_match(command))
}

/// Every file git tracks under `crates/`, as paths relative to the root.
fn tracked_under_crates(root: &Path) -> Vec<String> {
    common::git_in(root, &["ls-files", "--", "crates/"])
        .lines()
        .filter(|line| !line.is_empty())
        .map(str::to_owned)
        .collect()
}

// --- commit-attribution ------------------------------------------------------

#[test]
fn the_commit_time_seam_is_wired_hk_runs_the_attribution_gate() {
    let block = hk_step("commit-attribution");
    assert!(
        !block.is_empty(),
        "hk.pkl declares no commit-attribution step"
    );
    assert!(
        block.iter().any(|line| {
            let line = line.trim_start();
            !line.starts_with("//")
                && (line.contains("mise run commit-attribution-msg")
                    || line.contains("attribution check --message"))
        }),
        "the commit-attribution step runs no gate: {block:?}"
    );
}

#[test]
fn the_range_seam_is_wired_commit_lint_depends_on_the_attribution_gate() {
    // This dependency is what gives the gate both seams — `verify` and CI's
    // commit-lint job each already run `mise run commit-lint` with BASE_SHA and
    // HEAD_SHA exported — without adding a task name to a workflow, which
    // `ci-local-parity` would then require `verify` to run too.
    let depends = common::task_depends("commit-lint");
    assert!(
        depends.iter().any(|task| task == "commit-attribution"),
        "commit-lint no longer depends on the attribution gate: {depends:?}"
    );
}

#[test]
fn the_attribution_tasks_resolve_to_the_engine() {
    // The policy has exactly one evaluator. A task that re-implemented any part
    // of the predicate would be the second authority this issue moved the rule
    // into `batten.toml` to avoid.
    for task in [
        "commit-attribution",
        "commit-attribution-msg",
        "attribution-identity",
    ] {
        assert!(
            resolves_to_the_engine(task, "attribution"),
            "[tasks.{task}] does not reach `batten attribution`"
        );
    }
}

#[test]
fn the_policy_is_data_no_configured_pattern_appears_under_crates() {
    // CLOUD-274's third acceptance bullet, and non-negotiable rule 1 extended from
    // consumers to vendors. THE PREDICATE IS THE CONFIGURED PATTERNS, NOT THE
    // VENDOR'S NAME: `hook.rs` names a harness as a coordinate, which is how the
    // engine addresses a host. What rule 1 forbids is an attribution POLICY
    // literal compiled in, and that is what these patterns are.
    let authority = authority();
    let patterns: Vec<regex::Regex> = ["identity_deny", "trailer_deny", "body_deny"]
        .into_iter()
        .flat_map(|key| attribution_list(&authority, key))
        .filter(|pattern| !pattern.is_empty())
        .map(|pattern| regex::Regex::new(&pattern).expect("a configured pattern compiles"))
        .collect();
    assert!(
        !patterns.is_empty(),
        "[attribution] declares no pattern at all"
    );
    let root = root();
    let mut hits = Vec::new();
    for path in tracked_under_crates(&root) {
        // A binary fixture is not text a pattern can be compiled into.
        let Ok(text) = fs::read_to_string(root.join(&path)) else {
            continue;
        };
        for (index, line) in text.lines().enumerate() {
            if patterns.iter().any(|pattern| pattern.is_match(line)) {
                hits.push(format!("{path}:{}", index + 1));
            }
        }
    }
    assert!(
        hits.is_empty(),
        "a configured pattern matches under crates/: {hits:?}"
    );
}

#[test]
fn the_accountable_identity_is_config_too_and_not_compiled_in() {
    let name = authority()
        .get("attribution")
        .and_then(|table| table.get("identity"))
        .and_then(|identity| identity.get("name"))
        .and_then(toml::Value::as_str)
        .map(str::to_owned)
        .unwrap_or_default();
    assert!(!name.is_empty(), "[attribution.identity] names nobody");
    let root = root();
    let hits: Vec<String> = tracked_under_crates(&root)
        .into_iter()
        .filter(|path| {
            fs::read_to_string(root.join(path)).is_ok_and(|text| text.contains(name.as_str()))
        })
        .collect();
    assert!(hits.is_empty(), "the identity is compiled in: {hits:?}");
}

#[test]
fn this_repos_posture_is_silent_the_allow_set_is_empty() {
    // The decision record's §2.2 chose silent-with-records, and the emptiness of
    // this list IS that decision. A change here is a change of posture and should
    // fail this case, loudly.
    let authority = authority();
    let allow = authority
        .get("attribution")
        .and_then(|table| table.get("trailer_allow"));
    assert!(allow.is_some(), "[attribution] declares no trailer_allow");
    assert!(
        attribution_list(&authority, "trailer_allow").is_empty(),
        "the trailer allow-set is not empty"
    );
}

// --- commit-convention -------------------------------------------------------

#[test]
fn the_variable_is_gone_no_conventional_re_survives_in_mise_toml() {
    // THE ASSERTION THAT KEEPS THIS DONE. A re-added variable read by a re-added
    // grep passes every other check in this repo.
    let manifest = fs::read_to_string(common::at_root("mise.toml")).expect("the manifest");
    assert!(!manifest.contains("CONVENTIONAL_RE"));
}

#[test]
fn the_pattern_lives_in_batten_toml_and_exactly_once() {
    let text = fs::read_to_string(common::at_root("batten.toml")).expect("the committed config");
    let declared = text
        .lines()
        .filter(|line| line.starts_with("subject_pattern = "))
        .count();
    assert_eq!(declared, 1);
}

#[test]
fn the_range_seam_is_wired_commit_lint_depends_on_commit_check() {
    let depends = common::task_depends("commit-lint");
    assert!(
        depends.iter().any(|task| task == "commit-check"),
        "commit-lint no longer depends on the convention gate: {depends:?}"
    );
}

#[test]
fn the_commit_time_seam_is_wired_hk_runs_commit_msg() {
    let block = hk_step("conventional-commit");
    assert!(
        !block.is_empty(),
        "hk.pkl declares no conventional-commit step"
    );
    assert!(
        block.iter().any(|line| {
            let line = line.trim_start();
            !line.starts_with("//")
                && (line.contains("mise run commit-msg") || line.contains("commit check --message"))
        }),
        "the conventional-commit step runs no gate: {block:?}"
    );
}

#[test]
fn the_convention_tasks_resolve_to_the_engine() {
    // The convention has exactly one evaluator. A task re-implementing the match
    // would be the second authority this issue moved the pattern to batten.toml
    // to avoid — and it is how the variable got there originally.
    for task in ["commit-check", "commit-msg"] {
        assert!(
            resolves_to_the_engine(task, r"commit\s+check"),
            "[tasks.{task}] does not reach `batten commit check`"
        );
    }
}

#[test]
fn no_task_greps_a_subject_pattern_of_its_own() {
    // The shape that would reintroduce the defect without naming the variable: a
    // task inlining the regex rather than reading the config.
    let inline =
        regex::Regex::new(r"grep -Eq .*(feat\|fix|fix\|feat)").expect("a valid expression");
    let root = root();
    let mut sources = vec!["mise.toml".to_owned()];
    sources.extend(
        common::git_in(&root, &["ls-files", "--", "mise-tasks/"])
            .lines()
            .filter(|line| !line.is_empty())
            .map(str::to_owned),
    );
    let hits: Vec<String> = sources
        .into_iter()
        .filter(|path| fs::read_to_string(root.join(path)).is_ok_and(|text| inline.is_match(&text)))
        .collect();
    assert!(
        hits.is_empty(),
        "a task greps its own subject pattern: {hits:?}"
    );
}

#[test]
fn this_repos_own_history_satisfies_its_committed_convention() {
    // Consumer #1, end to end: the pattern in batten.toml is the one this
    // repository's commits actually follow, so the move changed where the rule
    // lives and not which commits it admits. A clone with no parent commit has no
    // range to judge, so HEAD's own message is judged instead — it used to return,
    // passing over nothing, on every shallow clone (CLOUD-2059).
    let root = root();
    let parent = common::git_command(&root, &["rev-parse", "HEAD~1"])
        .output()
        .expect("run git");
    let parents = common::git_in(&root, &["cat-file", "-p", "HEAD"])
        .lines()
        .filter(|line| line.starts_with("parent "))
        .count();
    let output = if parent.status.success() {
        let base = String::from_utf8_lossy(&parent.stdout).trim().to_owned();
        let head = common::git_in(&root, &["rev-parse", "HEAD"]);
        Some(common::run(
            &root,
            &["commit", "check", &format!("{base}..{head}")],
        ))
    } else if parents > 1 {
        // THE FORGE'S OWN MERGE, on a pull request's depth-1 checkout: nobody
        // authored it, this repository lands by fast-forward so it never
        // reaches `main`, and the commit that WAS authored is a parent the fetch
        // did not bring. Asserted to be exactly that, so this arm cannot absorb
        // an authored commit that fails the convention (measured on the musl
        // leg, which judged `Merge <sha> into <sha>`).
        let subject = common::git_in(&root, &["log", "-1", "--format=%s"]);
        assert!(
            subject.starts_with("Merge ") && subject.contains(" into "),
            "a merge HEAD here is the forge's synthetic one, never authored: {subject}"
        );
        None
    } else {
        let message = common::scratch("commit-wiring-head").join("MESSAGE");
        fs::create_dir_all(message.parent().expect("a parent")).expect("the scratch dir");
        fs::write(
            &message,
            common::git_in(&root, &["log", "-1", "--format=%B"]),
        )
        .expect("write HEAD's message");
        Some(common::run(
            &root,
            &[
                "commit",
                "check",
                "--message",
                message.to_str().expect("utf-8"),
            ],
        ))
    };
    if let Some(output) = output {
        assert!(
            output.status.success(),
            "the committed convention refuses this repository's own last commit: {}{}",
            common::stdout(&output),
            common::stderr(&output)
        );
    }
}
