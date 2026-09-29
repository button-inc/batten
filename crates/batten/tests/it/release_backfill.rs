//! `batten release backfill`, the CLOUD-618 sweep, over the compiled binary and
//! a fixture forge (CLOUD-1717, CLOUD-843).
//!
//! `[tasks.release-backfill]`'s body retired onto the engine: the tags come from
//! the repository through the git facts' own listing, ordered by version, and
//! each is dispatched through the REST tier and waited on by RUN id. The forge is
//! `BATTEN_REST_FIXTURE`: every request is appended to `args`, so a case asserts
//! the COUNT of dispatches as a fact about the wire, and the ORDER through what
//! the sweep reports per tag — order being the property with an argument behind
//! it, since the action derives a release's issues from the tag's commit range.
//!
//! The workflow it dispatches is judged by `policy/release-tracking.rego`; this
//! verb decides nothing about the tree and is not a gate.
//!
//! # RETIREMENT LEDGER, PER PATH — what `shell retire partial` reads
//!
// carried: mise-tasks/release-backfill.sh crates/batten/src/release.rs kind:verb crates/batten/tests/it/release_backfill.rs
// carried: tests/release-backfill.bats crates/batten/src/release.rs kind:verb crates/batten/tests/it/release_backfill.rs
// carried: "tags are dispatched oldest first, by version and not lexically" crates/batten/src/release.rs kind:verb
// changed: "explicit arguments win over the injected list" crates/batten/src/release.rs kind:verb there is no injected list any more: the repository's own tags are the default and `--tag` wins over them, which the case asserts
// carried: "one dispatch per tag, and no more" crates/batten/src/release.rs kind:verb
// changed: "an empty tag list is a refusal" crates/batten/src/release.rs kind:verb still a refusal that dispatches nothing, at the engine's usage code 1
// changed: "an argument that is not a release tag is refused before anything is dispatched" crates/batten/src/release.rs kind:verb refused whole before any dispatch as before, at the engine's usage code 1 rather than 2, and held to the declared `--pattern` rather than a literal `v[0-9]*`
// changed: "an unknown flag is a usage error, not a tag" crates/batten/src/release.rs kind:verb clap refuses it at 1 before the verb runs; the case asserts nothing was asked of the forge
// carried: "a dry run prints the plan and dispatches nothing" crates/batten/src/release.rs kind:verb
// carried: "a dry run lists the tags in the order it would use" crates/batten/src/release.rs kind:verb
// changed: "a dry run needs no forge client" crates/batten/src/release.rs kind:verb there is no forge client to lack: a dry run asks the forge nothing, which the case asserts off the fixture's request log
// changed: "an absent forge client is could-not-look for a real sweep" crates/batten/src/release.rs kind:verb the client is in the binary; the could-not-look that survives is no forge remote to name the repository, exit 3 with nothing dispatched
// carried: "each tag's run is viewed, not just dispatched" crates/batten/src/release.rs kind:verb
// carried: "a completed previous run is not mistaken for this tag's run" crates/batten/src/release.rs kind:verb
// carried: "the summary names how many tags were recorded" crates/batten/src/release.rs kind:verb
// changed: "a failing run stops the sweep" crates/batten/src/release.rs kind:verb stops at the first failure as before, at the engine's could-not-look code 3 rather than 1
// carried: "the refusal names how many tags were recorded before it" crates/batten/src/release.rs kind:verb
// changed: "a cancelled run stops the sweep too" crates/batten/src/release.rs kind:verb the same move to 3
// changed: "a refused dispatch stops the sweep" crates/batten/src/release.rs kind:verb the same move to 3
// changed: "a run that never appears is bounded, not an infinite poll" crates/batten/src/release.rs kind:verb bounded by the same poll COUNT, now `--max-polls`, at 3
// changed: "a run that never finishes is bounded too" crates/batten/src/release.rs kind:verb the same, at 3

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::{Path, PathBuf};
use std::process::Output;

use common::{git_in, init_repo, scratch, stdout, write};

/// The repository a case names — deliberately not this one.
const REPO: &str = "acme/widgets";

/// How the fixture forge answers.
#[derive(Clone, Copy)]
enum Forge {
    /// Each dispatch mints a new run id, and every run concludes `<state>`.
    Concludes(&'static str),
    /// The dispatch is refused.
    Refuses,
    /// The run list never moves past the id read before the dispatch.
    NeverAppears,
    /// A new run appears and stays `in_progress`.
    NeverFinishes,
}

/// A committed repository carrying `tags`, and a fixture forge beside it.
fn sweep(name: &str, tags: &[&str], forge: Forge, dispatches: usize) -> (PathBuf, PathBuf) {
    let dir = scratch(&format!("release-backfill-{name}"));
    init_repo(&dir);
    write(&dir, "README", "fixture\n");
    git_in(&dir, &["add", "-A"]);
    git_in(&dir, &["commit", "-qm", "a commit to tag"]);
    for tag in tags {
        git_in(&dir, &["tag", tag]);
    }
    let fixture = scratch(&format!("release-backfill-{name}-forge"));
    let answer = |file: &str, status: u16, body: &str| {
        write(
            &fixture,
            file,
            &format!("HTTP/2 {status}\ncontent-type: application/json\n\n{body}\n"),
        );
    };
    let runs = |id: u64| format!(r#"{{"total_count": 1, "workflow_runs": [{{"id": {id}}}]}}"#);
    // The newest-run reads are the UNROUTED ones, answered in call order: before
    // each dispatch the newest run is the previous tag's, after it this tag's.
    let mut n = 0;
    for tag in 0..dispatches.max(1) {
        let before = 100 + u64::try_from(tag).expect("a small count");
        let after = match forge {
            Forge::NeverAppears | Forge::Refuses => before,
            Forge::Concludes(_) | Forge::NeverFinishes => before + 1,
        };
        n += 1;
        answer(&format!("resp.{n}"), 200, &runs(before));
        n += 1;
        answer(&format!("resp.{n}"), 200, &runs(after));
    }
    let last = match forge {
        Forge::NeverAppears | Forge::Refuses => 100,
        Forge::Concludes(_) | Forge::NeverFinishes => {
            101 + u64::try_from(dispatches).expect("a small count")
        }
    };
    answer("resp.last", 200, &runs(last));
    let (dispatch_status, state) = match forge {
        Forge::Concludes(state) => (
            204,
            format!(r#"{{"status": "completed", "conclusion": "{state}"}}"#),
        ),
        Forge::Refuses => (403, String::from("{}")),
        Forge::NeverAppears => (
            204,
            String::from(r#"{"status": "completed", "conclusion": "success"}"#),
        ),
        Forge::NeverFinishes => (
            204,
            String::from(r#"{"status": "in_progress", "conclusion": null}"#),
        ),
    };
    answer("dispatch", dispatch_status, "");
    answer("run", 200, &state);
    write(
        &fixture,
        "routes",
        "/dispatches\tdispatch\n/actions/runs/\trun\n",
    );
    (dir, fixture)
}

/// `batten release backfill` with the declared workflow, branch and pattern.
fn backfill(dir: &Path, forge: &Path, extra: &[&str]) -> Output {
    common::batten()
        .args([
            "release",
            "backfill",
            "--workflow",
            "backfill.yml",
            "--ref",
            "main",
            "--pattern",
            "v[0-9]*",
            "--poll-interval",
            "0",
            "--max-polls",
            "4",
        ])
        .args(extra)
        .env("GH_REPO", REPO)
        .env("BATTEN_REST_FIXTURE", forge)
        .current_dir(dir)
        .output()
        .expect("the compiled binary runs")
}

fn said(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn requests(forge: &Path) -> Vec<String> {
    std::fs::read_to_string(forge.join("args"))
        .unwrap_or_default()
        .lines()
        .map(str::to_owned)
        .collect()
}

fn dispatched(forge: &Path) -> usize {
    requests(forge)
        .iter()
        .filter(|line| line.starts_with("POST ") && line.ends_with("/dispatches"))
        .count()
}

/// The tags the sweep reported recording, in order.
fn recorded(output: &Output) -> Vec<String> {
    stdout(output)
        .lines()
        .filter_map(|line| line.strip_prefix("release backfill: "))
        .filter_map(|rest| rest.strip_suffix(')'))
        .filter_map(|rest| rest.split_once(" recorded (run "))
        .map(|(tag, _)| tag.to_owned())
        .collect()
}

#[test]
fn the_repository_tags_are_swept_oldest_first_by_version() {
    let (dir, forge) = sweep(
        "order",
        &["v0.0.110", "v0.0.78", "v0.0.9", "not-a-release"],
        Forge::Concludes("success"),
        3,
    );
    let out = backfill(&dir, &forge, &[]);
    assert_eq!(out.status.code(), Some(0), "{}", said(&out));
    assert_eq!(recorded(&out), ["v0.0.9", "v0.0.78", "v0.0.110"]);
    assert_eq!(dispatched(&forge), 3, "one dispatch per tag, and no more");
    assert!(said(&out).contains("3 tag(s) recorded"), "{}", said(&out));
}

#[test]
fn named_tags_win_over_the_repository_tags() {
    let (dir, forge) = sweep(
        "named",
        &["v0.0.9", "v0.0.78"],
        Forge::Concludes("success"),
        1,
    );
    let out = backfill(&dir, &forge, &["--tag", "v0.0.78"]);
    assert_eq!(out.status.code(), Some(0), "{}", said(&out));
    assert_eq!(recorded(&out), ["v0.0.78"]);
    assert_eq!(dispatched(&forge), 1);
    let body = std::fs::read_to_string(forge.join("dispatch.request")).expect("the dispatch body");
    let body: serde_json::Value = serde_json::from_str(&body).expect("JSON");
    assert_eq!(body["ref"], "main");
    assert_eq!(body["inputs"]["tag"], "v0.0.78");
}

#[test]
fn an_empty_tag_list_is_a_refusal() {
    let (dir, forge) = sweep("empty", &["not-a-release"], Forge::Concludes("success"), 0);
    let out = backfill(&dir, &forge, &[]);
    assert_eq!(out.status.code(), Some(1), "{}", said(&out));
    assert!(said(&out).contains("no tag to record"), "{}", said(&out));
    assert!(requests(&forge).is_empty());
}

#[test]
fn a_non_tag_argument_is_refused_before_anything_is_dispatched() {
    let (dir, forge) = sweep("bad", &[], Forge::Concludes("success"), 0);
    let out = backfill(&dir, &forge, &["--tag", "v0.0.1", "--tag", "latest"]);
    assert_eq!(out.status.code(), Some(1), "{}", said(&out));
    assert!(
        said(&out).contains("latest"),
        "names the bad one: {}",
        said(&out)
    );
    assert!(requests(&forge).is_empty());
    let unknown = backfill(&dir, &forge, &["--no-such-flag"]);
    assert_eq!(unknown.status.code(), Some(1), "{}", said(&unknown));
    assert!(requests(&forge).is_empty());
}

#[test]
fn a_dry_run_prints_the_plan_in_order_and_asks_the_forge_nothing() {
    let (dir, forge) = sweep("dry", &["v0.0.110", "v0.0.9"], Forge::Refuses, 0);
    let out = common::batten()
        .args([
            "release",
            "backfill",
            "--workflow",
            "backfill.yml",
            "--ref",
            "main",
            "--pattern",
            "v[0-9]*",
            "--dry-run",
        ])
        .env_remove("GH_REPO")
        .env("BATTEN_REST_FIXTURE", &forge)
        .current_dir(&dir)
        .output()
        .expect("the compiled binary runs");
    assert_eq!(out.status.code(), Some(0), "{}", said(&out));
    let text = stdout(&out);
    assert!(text.contains("would dispatch"), "{text}");
    let plan: Vec<&str> = text
        .lines()
        .filter_map(|line| line.strip_prefix("  "))
        .collect();
    assert_eq!(plan, ["v0.0.9", "v0.0.110"]);
    assert!(requests(&forge).is_empty());
}

#[test]
fn each_tag_is_waited_on_under_its_own_run_id() {
    let (dir, forge) = sweep("ids", &["v0.0.1", "v0.0.2"], Forge::Concludes("success"), 2);
    let out = backfill(&dir, &forge, &[]);
    assert_eq!(out.status.code(), Some(0), "{}", said(&out));
    let viewed: Vec<String> = requests(&forge)
        .iter()
        .filter_map(|line| {
            line.rsplit_once("/actions/runs/")
                .map(|(_, id)| id.to_owned())
        })
        .collect();
    assert_eq!(viewed, ["101", "102"], "never the previous tag's run");
}

#[test]
fn a_failed_run_stops_the_sweep_naming_the_tag() {
    let (dir, forge) = sweep(
        "failed",
        &["v0.0.1", "v0.0.2"],
        Forge::Concludes("failure"),
        2,
    );
    let out = backfill(&dir, &forge, &[]);
    assert_eq!(out.status.code(), Some(3), "{}", said(&out));
    assert_eq!(dispatched(&forge), 1, "the sweep stops at the first");
    let text = said(&out);
    assert!(text.contains("v0.0.1"), "{text}");
    assert!(text.contains("`failure`"), "{text}");
    assert!(text.contains("0 tag(s) were recorded"), "{text}");
    let (dir, forge) = sweep("cancelled", &["v0.0.1"], Forge::Concludes("cancelled"), 1);
    let out = backfill(&dir, &forge, &[]);
    assert_eq!(out.status.code(), Some(3), "{}", said(&out));
    assert!(said(&out).contains("`cancelled`"), "{}", said(&out));
}

#[test]
fn a_refused_dispatch_stops_the_sweep() {
    let (dir, forge) = sweep("refused", &["v0.0.1", "v0.0.2"], Forge::Refuses, 2);
    let out = backfill(&dir, &forge, &[]);
    assert_eq!(out.status.code(), Some(3), "{}", said(&out));
    assert!(said(&out).contains("was refused"), "{}", said(&out));
    assert_eq!(dispatched(&forge), 1);
}

#[test]
fn a_run_that_never_appears_or_never_finishes_is_bounded() {
    let (dir, forge) = sweep("never-appears", &["v0.0.1"], Forge::NeverAppears, 1);
    let out = backfill(&dir, &forge, &[]);
    assert_eq!(out.status.code(), Some(3), "{}", said(&out));
    assert!(said(&out).contains("never appeared"), "{}", said(&out));
    let (dir, forge) = sweep("never-finishes", &["v0.0.1"], Forge::NeverFinishes, 1);
    let out = backfill(&dir, &forge, &[]);
    assert_eq!(out.status.code(), Some(3), "{}", said(&out));
    assert!(said(&out).contains("did not finish"), "{}", said(&out));
}

#[test]
fn no_forge_remote_is_could_not_look_and_dispatches_nothing() {
    let (dir, forge) = sweep("no-remote", &["v0.0.1"], Forge::Concludes("success"), 1);
    let out = common::batten()
        .args([
            "release",
            "backfill",
            "--workflow",
            "backfill.yml",
            "--ref",
            "main",
            "--pattern",
            "v[0-9]*",
        ])
        .env_remove("GH_REPO")
        .env("BATTEN_REST_FIXTURE", &forge)
        .current_dir(&dir)
        .output()
        .expect("the compiled binary runs");
    assert_eq!(out.status.code(), Some(3), "{}", said(&out));
    assert_eq!(dispatched(&forge), 0);
}

#[test]
fn the_committed_task_is_the_verb_with_the_consumers_facts_as_arguments() {
    let block = common::task_block("release-backfill").expect("[tasks.release-backfill]");
    assert!(!block.contains("'''"), "no body: {block}");
    let run = common::task_value(&block, "run");
    for word in [
        "release backfill",
        "--workflow linear-release-backfill.yml",
        "--ref main",
        "--pattern",
    ] {
        assert!(run.contains(word), "{word}: {run}");
    }
}
