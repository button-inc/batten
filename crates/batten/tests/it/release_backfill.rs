//! `mise run release-backfill`, the CLOUD-618 sweep, over its REAL body
//! (CLOUD-1717).
//!
//! `[tasks.release-backfill]` is read out of `mise.toml` and run with `bash -c`,
//! its arguments handed over as `usage` hands them, and a stub `gh` first on
//! `PATH`. The stub is a LEDGER, not a mock: it appends every argv it is given,
//! so a case asserts the ORDER tags were dispatched in and the COUNT of
//! dispatches — order being the property with an argument behind it, since the
//! action derives a release's issues from the tag's commit range.
//!
//! The workflow it dispatches is judged by `policy/release-tracking.rego`; this
//! task decides nothing about the tree and is not a gate.
//!
//! # RETIREMENT LEDGER, PER PATH — what `shell retire partial` reads
//!
// carried: mise-tasks/release-backfill.sh policy/release-tracking.rego kind:mechanism crates/batten/tests/it/release_backfill.rs
// carried: tests/release-backfill.bats policy/release-tracking.rego kind:mechanism crates/batten/tests/it/release_backfill.rs
// carried: "tags are dispatched oldest first, by version and not lexically" policy/release-tracking.rego kind:mechanism
// carried: "explicit arguments win over the injected list" policy/release-tracking.rego kind:mechanism
// carried: "one dispatch per tag, and no more" policy/release-tracking.rego kind:mechanism
// carried: "an empty tag list is a refusal" policy/release-tracking.rego kind:mechanism
// carried: "an argument that is not a release tag is refused before anything is dispatched" policy/release-tracking.rego kind:mechanism
// changed: "an unknown flag is a usage error, not a tag" mise.toml the flag is refused by the task's `usage` spec before the body runs, so the exit code and the message are mise's rather than the program's 2 and its own `usage:` line; it is still a refusal that dispatches nothing
// carried: "a dry run prints the plan and dispatches nothing" policy/release-tracking.rego kind:mechanism
// carried: "a dry run lists the tags in the order it would use" policy/release-tracking.rego kind:mechanism
// carried: "a dry run needs no forge client" policy/release-tracking.rego kind:mechanism
// carried: "an absent forge client is could-not-look for a real sweep" policy/release-tracking.rego kind:mechanism
// carried: "each tag's run is viewed, not just dispatched" policy/release-tracking.rego kind:mechanism
// carried: "a completed previous run is not mistaken for this tag's run" policy/release-tracking.rego kind:mechanism
// carried: "the summary names how many tags were recorded" policy/release-tracking.rego kind:mechanism
// carried: "a failing run stops the sweep" policy/release-tracking.rego kind:mechanism
// carried: "the refusal names how many tags were recorded before it" policy/release-tracking.rego kind:mechanism
// carried: "a cancelled run stops the sweep too" policy/release-tracking.rego kind:mechanism
// carried: "a refused dispatch stops the sweep" policy/release-tracking.rego kind:mechanism
// carried: "a run that never appears is bounded, not an infinite poll" policy/release-tracking.rego kind:mechanism
// carried: "a run that never finishes is bounded too" policy/release-tracking.rego kind:mechanism

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};

use common::{at_root, scratch, write};

fn body() -> String {
    let manifest = std::fs::read_to_string(at_root("mise.toml")).expect("the manifest");
    let parsed: toml::Value = toml::from_str(&manifest).expect("mise.toml parses as TOML");
    parsed["tasks"]["release-backfill"]["run"]
        .as_str()
        .expect("[tasks.release-backfill] declares a run body")
        .lines()
        .filter(|line| !line.contains("{% raw %}") && !line.contains("{% endraw %}"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// How the stub `gh` answers.
#[derive(Clone, Copy)]
enum Forge {
    /// Each dispatch mints a new run id; `run view` reports `completed <state>`.
    Concludes(&'static str),
    /// `workflow run` exits 1.
    Refuses,
    /// The run list never moves past 100.
    NeverAppears,
    /// A new run appears and stays `in_progress`.
    NeverFinishes,
}

struct Sweep {
    dir: PathBuf,
}

impl Sweep {
    fn new(name: &str, forge: Forge) -> Self {
        let dir = scratch(&format!("release-backfill-{name}"));
        let ledger = dir.join("argv");
        let counter = dir.join("counter");
        write(&dir, "argv", "");
        let (list, dispatch, view) = match forge {
            Forge::Concludes(state) => (
                "cat \"$counter\"",
                "echo $(( $(cat \"$counter\") + 1 )) >\"$counter\"",
                format!("printf 'completed %s\\n' '{state}'"),
            ),
            Forge::Refuses => ("echo 100", "exit 1", String::new()),
            Forge::NeverAppears => ("echo 100", ":", "printf 'completed success\\n'".to_owned()),
            Forge::NeverFinishes => (
                "cat \"$counter\"",
                "echo $(( $(cat \"$counter\") + 1 )) >\"$counter\"",
                "printf 'in_progress \\n'".to_owned(),
            ),
        };
        let stub = format!(
            "#!/usr/bin/env bash\nprintf '%s\\n' \"$*\" >>'{ledger}'\ncounter='{counter}'\n\
             [ -f \"$counter\" ] || echo 100 >\"$counter\"\ncase \"$1 $2\" in\n\
             \"run list\") {list} ;;\n\"workflow run\") {dispatch} ;;\n\"run view\") {view} ;;\nesac\n",
            ledger = ledger.display(),
            counter = counter.display(),
        );
        write(&dir, "bin/gh", &stub);
        let gh = dir.join("bin/gh");
        std::fs::set_permissions(&gh, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        Self { dir }
    }

    /// Run the task body with `usage`'s variables and the injected knobs.
    fn run(&self, tags: &str, dry_run: bool, env: &[(&str, &str)]) -> Output {
        let path = format!(
            "{}:{}",
            self.dir.join("bin").display(),
            std::env::var("PATH").unwrap_or_default()
        );
        let mut command = Command::new("bash");
        command
            .args(["-c", &body()])
            .current_dir(&self.dir)
            .env("PATH", path)
            .env("usage_tag", tags)
            .env("usage_dry_run", if dry_run { "true" } else { "false" })
            .env("RELEASE_BACKFILL_POLL_INTERVAL", "0")
            .env_remove("RELEASE_BACKFILL_GH")
            .env_remove("RELEASE_BACKFILL_TAGS")
            .env_remove("RELEASE_BACKFILL_MAX_POLLS")
            .env_remove("RELEASE_BACKFILL_WORKFLOW")
            .stdin(Stdio::null());
        for (name, value) in env {
            command.env(name, value);
        }
        command.output().expect("run the task body")
    }

    fn ledger(&self) -> Vec<String> {
        std::fs::read_to_string(self.dir.join("argv"))
            .expect("the ledger")
            .lines()
            .map(str::to_owned)
            .collect()
    }

    fn dispatched(&self) -> Vec<String> {
        self.ledger()
            .iter()
            .filter(|line| line.starts_with("workflow run"))
            .filter_map(|line| line.split("-f tag=").nth(1).map(str::to_owned))
            .collect()
    }

    fn missing(&self) -> String {
        self.dir.join("nonesuch").display().to_string()
    }
}

fn said(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn tags(list: &str) -> [(&'static str, &str); 1] {
    [("RELEASE_BACKFILL_TAGS", list)]
}

#[test]
fn tags_are_dispatched_oldest_first_by_version_not_lexically() {
    let sweep = Sweep::new("order", Forge::Concludes("success"));
    let out = sweep.run("", false, &tags("v0.0.110 v0.0.78 v0.0.9 v0.1.0"));
    assert_eq!(out.status.code(), Some(0), "{}", said(&out));
    assert_eq!(
        sweep.dispatched(),
        ["v0.0.9", "v0.0.78", "v0.0.110", "v0.1.0"]
    );
}

#[test]
fn explicit_arguments_win_over_the_injected_list() {
    let sweep = Sweep::new("args-win", Forge::Concludes("success"));
    let out = sweep.run("v0.0.78", false, &tags("v0.0.1 v0.0.2"));
    assert_eq!(out.status.code(), Some(0), "{}", said(&out));
    assert_eq!(sweep.dispatched(), ["v0.0.78"]);
}

#[test]
fn one_dispatch_per_tag_and_no_more() {
    let sweep = Sweep::new("one-each", Forge::Concludes("success"));
    let out = sweep.run("", false, &tags("v0.0.1 v0.0.2 v0.0.3"));
    assert_eq!(out.status.code(), Some(0), "{}", said(&out));
    assert_eq!(sweep.dispatched().len(), 3);
}

#[test]
fn an_empty_tag_list_is_a_refusal() {
    let sweep = Sweep::new("empty", Forge::Concludes("success"));
    let out = sweep.run("", false, &tags(" "));
    assert_eq!(out.status.code(), Some(1), "{}", said(&out));
    assert!(said(&out).contains("no tags to record"));
    assert!(sweep.ledger().is_empty());
}

#[test]
fn a_non_tag_argument_is_refused_before_anything_is_dispatched() {
    let sweep = Sweep::new("bad-args", Forge::Concludes("success"));
    let out = sweep.run("v0.0.78 not-a-tag also-not", false, &[]);
    assert_eq!(out.status.code(), Some(2), "{}", said(&out));
    let text = said(&out);
    assert!(
        text.contains("not-a-tag") && text.contains("also-not"),
        "{text}"
    );
    assert!(sweep.ledger().is_empty());
}

#[test]
fn the_usage_spec_declares_the_flag_and_the_variadic_tags() {
    // The unknown-flag refusal moved to mise's `usage` parser; what this tree
    // owns is the spec that makes any other flag unknown.
    let manifest = std::fs::read_to_string(at_root("mise.toml")).expect("the manifest");
    let parsed: toml::Value = toml::from_str(&manifest).expect("mise.toml parses as TOML");
    let usage = parsed["tasks"]["release-backfill"]["usage"]
        .as_str()
        .expect("[tasks.release-backfill] declares a usage spec");
    assert!(usage.contains("flag \"--dry-run\""), "{usage}");
    assert!(usage.contains("arg \"[tag]...\""), "{usage}");
}

#[test]
fn a_dry_run_prints_the_plan_in_order_and_dispatches_nothing() {
    let sweep = Sweep::new("dry", Forge::Concludes("success"));
    let out = sweep.run("", true, &tags("v0.0.110 v0.0.9"));
    assert_eq!(out.status.code(), Some(0), "{}", said(&out));
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    assert!(text.contains("would dispatch"), "{text}");
    let plan: Vec<&str> = text
        .lines()
        .filter_map(|line| line.strip_prefix("  "))
        .collect();
    assert_eq!(plan, ["v0.0.9", "v0.0.110"]);
    assert!(sweep.ledger().is_empty());
}

#[test]
fn a_dry_run_needs_no_forge_client() {
    let sweep = Sweep::new("dry-no-gh", Forge::Concludes("success"));
    let missing = sweep.missing();
    let out = sweep.run(
        "",
        true,
        &[
            ("RELEASE_BACKFILL_GH", &missing),
            ("RELEASE_BACKFILL_TAGS", "v0.0.78"),
        ],
    );
    assert_eq!(out.status.code(), Some(0), "{}", said(&out));
}

#[test]
fn an_absent_forge_client_is_could_not_look_for_a_real_sweep() {
    let sweep = Sweep::new("no-gh", Forge::Concludes("success"));
    let missing = sweep.missing();
    let out = sweep.run(
        "",
        false,
        &[
            ("RELEASE_BACKFILL_GH", &missing),
            ("RELEASE_BACKFILL_TAGS", "v0.0.78"),
        ],
    );
    assert_eq!(out.status.code(), Some(2), "{}", said(&out));
    assert!(said(&out).contains("no forge client"));
}

#[test]
fn each_tag_is_waited_on_under_its_own_run_id() {
    let sweep = Sweep::new("waits", Forge::Concludes("success"));
    let out = sweep.run("", false, &tags("v0.0.78 v0.0.79"));
    assert_eq!(out.status.code(), Some(0), "{}", said(&out));
    // Two distinct run ids viewed, one per tag — never the previous one twice.
    let mut viewed: Vec<String> = sweep
        .ledger()
        .iter()
        .filter_map(|line| line.strip_prefix("run view "))
        .filter_map(|rest| rest.split(' ').next().map(str::to_owned))
        .collect();
    viewed.sort();
    viewed.dedup();
    assert_eq!(viewed, ["101", "102"]);
}

#[test]
fn the_summary_names_how_many_tags_were_recorded() {
    let sweep = Sweep::new("summary", Forge::Concludes("success"));
    let out = sweep.run("", false, &tags("v0.0.78 v0.0.79 v0.0.80"));
    assert_eq!(out.status.code(), Some(0), "{}", said(&out));
    assert!(said(&out).contains("3 tag(s) recorded"));
}

#[test]
fn a_failing_run_stops_the_sweep_and_says_how_far_it_got() {
    let sweep = Sweep::new("failure", Forge::Concludes("failure"));
    let out = sweep.run("", false, &tags("v0.0.78 v0.0.79 v0.0.80"));
    assert_eq!(out.status.code(), Some(1), "{}", said(&out));
    assert_eq!(sweep.dispatched().len(), 1);
    let text = said(&out);
    assert!(text.contains("0 tag(s) recorded"), "{text}");
    assert!(text.contains("'failure'"), "{text}");
}

#[test]
fn a_cancelled_run_stops_the_sweep_too() {
    let sweep = Sweep::new("cancelled", Forge::Concludes("cancelled"));
    let out = sweep.run("", false, &tags("v0.0.78"));
    assert_eq!(out.status.code(), Some(1), "{}", said(&out));
    assert!(said(&out).contains("'cancelled'"));
}

#[test]
fn a_refused_dispatch_stops_the_sweep() {
    let sweep = Sweep::new("refused", Forge::Refuses);
    let out = sweep.run("", false, &tags("v0.0.78 v0.0.79"));
    assert_eq!(out.status.code(), Some(1), "{}", said(&out));
    assert!(said(&out).contains("was refused"));
    assert_eq!(sweep.dispatched().len(), 1);
}

#[test]
fn a_run_that_never_appears_is_bounded() {
    let sweep = Sweep::new("never-appears", Forge::NeverAppears);
    let out = sweep.run(
        "",
        false,
        &[
            ("RELEASE_BACKFILL_MAX_POLLS", "3"),
            ("RELEASE_BACKFILL_TAGS", "v0.0.78"),
        ],
    );
    assert_eq!(out.status.code(), Some(1), "{}", said(&out));
    assert!(said(&out).contains("never appeared"));
}

#[test]
fn a_run_that_never_finishes_is_bounded_too() {
    let sweep = Sweep::new("never-finishes", Forge::NeverFinishes);
    let out = sweep.run(
        "",
        false,
        &[
            ("RELEASE_BACKFILL_MAX_POLLS", "3"),
            ("RELEASE_BACKFILL_TAGS", "v0.0.78"),
        ],
    );
    assert_eq!(out.status.code(), Some(1), "{}", said(&out));
    assert!(said(&out).contains("did not finish"));
}
