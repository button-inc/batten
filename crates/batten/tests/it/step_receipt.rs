//! `batten step` — per-step receipts keyed by input content (CLOUD-424), over the
//! compiled binary, with a tool and the step's commands stubbed first on `PATH`
//! so every component of the key is a lever one case pulls alone.
//!
//! # RETIREMENT LEDGER — what `shell retire partial` reads
//!
//! Twice ported. CLOUD-1752 moved `mise-tasks/step-receipt.sh` and its bats suite
//! into `[tasks.step-receipt]`; CLOUD-843 retires that body onto the `batten step`
//! verb (`crates/batten/src/step.rs`), and this tier moves with it from the task's
//! bash onto the binary. What changed for every case, stated once:
//!
//! * the step table is `[[step]]` rows in the fixture's committed `batten.toml`,
//!   where the task's `BATTEN_STEP_SPECS`/`BATTEN_STEP_TOOLS` overrides were the
//!   lever — a caller naming its own inputs could key a receipt to files the step
//!   never read, so the override did not survive;
//! * the task body's key component (`mise tasks info`) is a declared TOOL argv
//!   whose stdout is keyed, and under `step run` the command's own argv is keyed;
//! * a `record` refusal is exit 2 (a statement about the tree, `EXITS_VERDICT`)
//!   where the task's was exit 1.
//!
// ported: mise-tasks/step-receipt.sh subject:mise.toml crates/batten/tests/it/step_receipt.rs
// ported: tests/step-receipt.bats subject:mise.toml crates/batten/tests/it/step_receipt.rs
// carried: "[tasks.step-receipt]" crates/batten/src/step.rs batten.toml kind:verb crates/batten/tests/it/step_receipt.rs runs:batten+step
// carried: "no receipt: the step runs" crates/batten/src/step.rs kind:verb
// carried: "identical inputs, command and tools hit" crates/batten/src/step.rs kind:verb
// carried: "a changed input file misses" crates/batten/src/step.rs kind:verb
// changed: "a changed command misses" crates/batten/src/step.rs kind:verb the command is the argv `step run` is handed, keyed directly, where the task keyed the `mise tasks info` body of the task that called it
// carried: "a changed tool version misses" crates/batten/src/step.rs kind:verb
// carried: "a changed argument misses — a receipt for one target must not answer for another" crates/batten/src/step.rs kind:verb
// changed: "a file task's bytes are key material" crates/batten/src/step.rs kind:verb a task's declaration reaches the key as a declared tool argv's stdout; the case keys a file's bytes through a stub tool that prints them
// carried: "a tool that cannot answer is no key, and no key runs the step" crates/batten/src/step.rs kind:verb
// changed: "a spec that resolves to nothing runs the step" crates/batten/src/step.rs kind:verb the spec is a `[[step]]` row's `inputs`, not `BATTEN_STEP_SPECS`
// carried: "a deleted input runs the step" crates/batten/src/step.rs kind:verb
// carried: "unstaged divergence is no key — the index is what the key hashes, so the worktree must agree with it" crates/batten/src/step.rs kind:verb
// changed: "an untracked file inside the specs is no key" crates/batten/src/step.rs kind:verb the whole-tree spec is a row declaring `.`
// changed: "an unknown step with no override always runs" crates/batten/src/step.rs kind:verb there is no override to withhold; an undeclared step is the whole case
// changed: "a corrupted receipt store runs everything and records nothing — never skips" crates/batten/src/step.rs kind:verb the record's refusal is exit 2
// changed: "a record with no paired check refuses" crates/batten/src/step.rs kind:verb exit 2 rather than 1
// changed: "inputs changing while the step ran refuse the record — no receipt may attest bytes the run never judged" crates/batten/src/step.rs kind:verb exit 2 rather than 1
// carried: "under CI the cache neither hits nor records — CI's job is to confirm independently" crates/batten/src/step.rs kind:verb
// carried: "the bypass behaves like CI, so a measurement can see the uncached cost" crates/batten/src/step.rs kind:verb
// carried: "one receipt per step: a new pass prunes the old key" crates/batten/src/step.rs kind:verb
// carried: "the receipt is pointer-only: a timestamp and a key, never input content" crates/batten/src/step.rs kind:verb
// carried: "CLOUD-498: a miss is exit 1 and says so in words, with no failure-shaped line" crates/batten/src/step.rs kind:verb
// carried: "two concurrent runs of one step both record" crates/batten/src/step.rs kind:verb
// carried: "a hit beside a running twin does not strand its record" crates/batten/src/step.rs kind:verb

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::{Path, PathBuf};
use std::process::Output;

/// A tool whose answer the case controls or breaks.
const TOOL: &str = "#!/bin/sh\nif [ -n \"${STUB_TOOL_FAIL:-}\" ]; then exit 9; fi\necho \"${STUB_TOOL:-tool-1.0}\"\n";

/// A tool printing a declaration file's bytes, as `mise tasks info` prints a task.
const DECL: &str = "#!/bin/sh\ncat \"$1\"\n";

/// A step command that leaves a mark each time it RUNS, so a hit is observable.
const OK: &str = "#!/bin/sh\necho ran >>bin/ran.log\n";

/// A step command that fails with the code the case chooses.
const FAIL: &str = "#!/bin/sh\nexit \"${STUB_CODE:-2}\"\n";

/// The fixture's committed step table.
const TABLE: &str = r#"version = 1

[[step]]
id = "mystep"
inputs = ["input.txt"]
tools = [["toolv"]]

[[step]]
id = "whole"
inputs = ["."]
tools = [["toolv"]]

[[step]]
id = "empty"
inputs = ["absent-*.txt"]
tools = [["toolv"]]

[[step]]
id = "declared"
inputs = ["input.txt"]
tools = [["toolv"], ["decl", "bin/taskfile"]]
"#;

/// Where the keyed family keeps its records.
const STORE: &str = ".git/batten-records";

struct Repo {
    dir: PathBuf,
}

impl Repo {
    fn new(name: &str) -> Self {
        let dir = common::scratch(&format!("step-receipt-{name}"));
        for (file, body) in [
            ("bin/toolv", TOOL),
            ("bin/decl", DECL),
            ("bin/ok", OK),
            ("bin/fail", FAIL),
        ] {
            common::write(&dir, file, body);
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                std::fs::set_permissions(dir.join(file), std::fs::Permissions::from_mode(0o755))
                    .expect("chmod");
            }
        }
        common::write(&dir, "bin/taskfile", "body bytes v1\n");
        common::write(&dir, "input.txt", "one\n");
        common::write(&dir, ".gitignore", "bin/\n");
        common::write(&dir, "batten.toml", TABLE);
        common::init_repo(&dir);
        common::git_in(&dir, &["add", "-A"]);
        common::git_in(&dir, &["commit", "-qm", "init"]);
        Self { dir }
    }

    /// `batten <args>` in the fixture, its `bin/` first on `PATH`, the cache on.
    fn batten(&self, args: &[&str], env: &[(&str, &str)]) -> Output {
        let inherited = std::env::var_os("PATH").unwrap_or_default();
        let path = std::env::join_paths(
            std::iter::once(self.dir.join("bin")).chain(std::env::split_paths(&inherited)),
        )
        .expect("a joinable PATH");
        let mut command = common::batten();
        command
            .args(args)
            .current_dir(&self.dir)
            .env("PATH", path)
            .env_remove("CI")
            .env_remove("BATTEN_STEP_RECEIPT_BYPASS")
            .env_remove("BATTEN_TASK_PID");
        for (name, value) in env {
            command.env(name, value);
        }
        command.output().expect("run batten")
    }

    /// `step check`, asserting the exit-0 contract and returning the first word.
    fn check_with(&self, step: &[&str], env: &[(&str, &str)]) -> String {
        let args: Vec<&str> = ["step", "check"].iter().chain(step).copied().collect();
        let out = self.batten(&args, env);
        assert_eq!(
            out.status.code(),
            Some(0),
            "a check always exits 0: {}{}",
            common::stdout(&out),
            common::stderr(&out)
        );
        common::stdout(&out)
            .split_whitespace()
            .next()
            .unwrap_or_default()
            .to_owned()
    }

    fn check(&self, step: &[&str]) -> String {
        self.check_with(step, &[])
    }

    fn record_with(&self, step: &[&str], env: &[(&str, &str)]) -> Output {
        let args: Vec<&str> = ["step", "record"].iter().chain(step).copied().collect();
        self.batten(&args, env)
    }

    fn record(&self, step: &[&str]) -> Option<i32> {
        self.record_with(step, &[]).status.code()
    }

    /// `step run <step> -- <command>`.
    fn run_step(&self, step: &[&str], command: &[&str], env: &[(&str, &str)]) -> Output {
        let args: Vec<&str> = ["step", "run"]
            .iter()
            .chain(step)
            .chain(["--"].iter())
            .chain(command)
            .copied()
            .collect();
        self.batten(&args, env)
    }

    /// One full pass: a miss, the run's stand-in, and the record.
    fn pass_once(&self) {
        assert_eq!(self.check(&["mystep"]), "miss");
        assert_eq!(self.record(&["mystep"]), Some(0));
    }

    fn receipts(&self) -> Vec<PathBuf> {
        std::fs::read_dir(self.dir.join(STORE).join("steps"))
            .map(|entries| entries.map(|entry| entry.unwrap().path()).collect())
            .unwrap_or_default()
    }

    fn stage(&self, contents: &str) {
        common::write(&self.dir, "input.txt", contents);
        common::git_in(&self.dir, &["add", "input.txt"]);
    }

    fn path(&self, rel: &str) -> PathBuf {
        self.dir.join(rel)
    }

    /// How many times the `ok` stub has run.
    fn runs(&self) -> usize {
        read(&self.path("bin/ran.log")).lines().count()
    }
}

fn read(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_default()
}

#[test]
fn no_receipt_the_step_runs() {
    let repo = Repo::new("none");
    let out = repo.batten(&["step", "check", "mystep"], &[]);
    let said = common::stdout(&out);
    assert_eq!(out.status.code(), Some(0));
    assert!(said.starts_with("miss"), "{said}");
    assert!(said.contains("running the step"), "{said}");
}

#[test]
fn identical_inputs_command_and_tools_hit() {
    let repo = Repo::new("hit");
    repo.pass_once();
    let said = common::stdout(&repo.batten(&["step", "check", "mystep"], &[]));
    assert!(said.starts_with("hit"), "{said}");
    assert!(said.contains("not re-deriving"), "{said}");
}

#[test]
fn a_changed_input_file_misses() {
    let repo = Repo::new("input");
    repo.pass_once();
    assert_eq!(
        repo.check(&["mystep"]),
        "hit",
        "the premise: an unchanged tree hits"
    );
    repo.stage("two\n");
    assert_eq!(repo.check(&["mystep"]), "miss");
}

#[test]
fn a_changed_command_misses() {
    let repo = Repo::new("command");
    assert_eq!(
        repo.run_step(&["mystep"], &["ok"], &[]).status.code(),
        Some(0)
    );
    let same = repo.run_step(&["mystep"], &["ok"], &[]);
    assert_eq!(first_word(&same), "hit", "{}", common::stderr(&same));
    let other = repo.run_step(&["mystep"], &["ok", "again"], &[]);
    assert_eq!(
        first_word(&other),
        "miss",
        "a receipt for one command must not answer for another: {}",
        common::stderr(&other)
    );
}

/// The first word of the `hit`/`miss` line `step run` writes to stderr, found by
/// its shape rather than its position, so a diagnostic some other layer printed
/// first cannot stand in for it.
fn first_word(out: &Output) -> String {
    common::stderr(out)
        .lines()
        .find(|line| line.starts_with("hit ") || line.starts_with("miss "))
        .and_then(|line| line.split_whitespace().next())
        .unwrap_or_default()
        .to_owned()
}

#[test]
fn a_changed_tool_version_misses() {
    let repo = Repo::new("tool");
    repo.pass_once();
    assert_eq!(
        repo.check(&["mystep"]),
        "hit",
        "the premise: an unchanged tool hits"
    );
    assert_eq!(
        repo.check_with(&["mystep"], &[("STUB_TOOL", "tool-2.0")]),
        "miss"
    );
}

#[test]
fn a_changed_argument_misses() {
    // A receipt for one target must not answer for another.
    let repo = Repo::new("argument");
    assert_eq!(repo.check(&["mystep", "--arg", "one"]), "miss");
    assert_eq!(repo.record(&["mystep", "--arg", "one"]), Some(0));
    assert_eq!(repo.check(&["mystep", "--arg", "one"]), "hit");
    assert_eq!(repo.check(&["mystep", "--arg", "two"]), "miss");
}

#[test]
fn a_declaration_a_tool_prints_is_key_material() {
    let repo = Repo::new("declared");
    assert_eq!(repo.check(&["declared"]), "miss");
    assert_eq!(repo.record(&["declared"]), Some(0));
    assert_eq!(repo.check(&["declared"]), "hit");
    std::fs::write(repo.path("bin/taskfile"), "body bytes v2\n").unwrap();
    assert_eq!(repo.check(&["declared"]), "miss");
}

#[test]
fn a_tool_that_cannot_answer_is_no_key_and_no_key_runs_the_step() {
    let repo = Repo::new("tool-fails");
    repo.pass_once();
    let said =
        common::stdout(&repo.batten(&["step", "check", "mystep"], &[("STUB_TOOL_FAIL", "1")]));
    assert!(said.starts_with("miss"), "{said}");
    assert!(said.contains("no key"), "{said}");
}

#[test]
fn a_spec_that_resolves_to_nothing_runs_the_step() {
    let repo = Repo::new("spec-empty");
    let said = common::stdout(&repo.batten(&["step", "check", "empty"], &[]));
    assert!(said.starts_with("miss"), "{said}");
    assert!(said.contains("no key"), "{said}");
}

#[test]
fn a_deleted_input_runs_the_step() {
    let repo = Repo::new("deleted");
    repo.pass_once();
    std::fs::remove_file(repo.path("input.txt")).unwrap();
    assert_eq!(repo.check(&["mystep"]), "miss");
}

#[test]
fn unstaged_divergence_is_no_key() {
    // The index is what the key hashes, so the worktree must agree with it.
    let repo = Repo::new("unstaged");
    repo.pass_once();
    common::write(&repo.dir, "input.txt", "one\ndrift\n");
    let said = common::stdout(&repo.batten(&["step", "check", "mystep"], &[]));
    assert!(said.starts_with("miss"), "{said}");
    assert!(said.contains("no key"), "{said}");
}

#[test]
fn an_untracked_file_inside_the_specs_is_no_key() {
    let repo = Repo::new("untracked");
    assert_eq!(repo.check(&["whole"]), "miss");
    assert_eq!(repo.record(&["whole"]), Some(0));
    assert_eq!(repo.check(&["whole"]), "hit");
    common::write(&repo.dir, "stray", "");
    assert_eq!(repo.check(&["whole"]), "miss");
}

#[test]
fn an_undeclared_step_always_runs() {
    let repo = Repo::new("unknown");
    let out = repo.batten(&["step", "check", "never-declared"], &[]);
    let said = common::stdout(&out);
    assert_eq!(out.status.code(), Some(0));
    assert!(said.starts_with("miss"), "{said}");
    assert!(said.contains("no key"), "{said}");
}

#[test]
fn a_corrupted_receipt_store_runs_everything_and_records_nothing() {
    // Never skips.
    let repo = Repo::new("corrupt");
    repo.pass_once();
    std::fs::remove_dir_all(repo.path(STORE)).unwrap();
    std::fs::write(repo.path(STORE), "").unwrap();
    assert_eq!(repo.check(&["mystep"]), "miss");
    assert_eq!(repo.record(&["mystep"]), Some(2));
}

#[test]
fn a_record_with_no_paired_check_refuses() {
    let repo = Repo::new("unpaired");
    let out = repo.record_with(&["mystep"], &[]);
    assert_eq!(out.status.code(), Some(2));
    assert!(
        common::stderr(&out).contains("no pending key"),
        "{}",
        common::stderr(&out)
    );
}

/// TWO RUNS OF ONE STEP AT ONCE BOTH RECORD. `verify` runs some steps twice
/// concurrently — `cargo-clippy` finished twice inside `[hooks]` on #1036 — and
/// they share the one pending slot. The first `record` used to blank it, so the
/// second refused a green step with "no pending key".
#[test]
fn two_concurrent_runs_of_one_step_both_record() {
    let repo = Repo::new("twins");
    assert_eq!(repo.check(&["mystep"]), "miss");
    assert_eq!(repo.check(&["mystep"]), "miss");
    assert_eq!(repo.record(&["mystep"]), Some(0));
    assert_eq!(
        repo.record(&["mystep"]),
        Some(0),
        "the twin's record found its pending key"
    );
}

/// And a hit beside a running twin does not strand it: the hit reads the same
/// key, so it must not blank the slot the twin's `record` is about to match.
#[test]
fn a_hit_beside_a_running_twin_does_not_strand_its_record() {
    let repo = Repo::new("hit-twin");
    repo.pass_once();
    assert_eq!(repo.check(&["mystep"]), "hit");
    assert_eq!(repo.record(&["mystep"]), Some(0));
}

#[test]
fn inputs_changing_while_the_step_ran_refuse_the_record() {
    // No receipt may attest bytes the run never judged.
    let repo = Repo::new("weld");
    assert_eq!(repo.check(&["mystep"]), "miss");
    repo.stage("two\n");
    assert_eq!(repo.record(&["mystep"]), Some(2));
    assert!(repo.receipts().is_empty(), "{:?}", repo.receipts());
}

#[test]
fn under_ci_the_cache_neither_hits_nor_records() {
    // CI's job is to confirm independently.
    let repo = Repo::new("ci");
    repo.pass_once();
    assert_eq!(repo.check_with(&["mystep"], &[("CI", "true")]), "miss");
    let before = repo
        .receipts()
        .iter()
        .map(|path| read(path))
        .collect::<Vec<_>>();
    repo.stage("two\n");
    assert_eq!(
        repo.record_with(&["mystep"], &[("CI", "true")])
            .status
            .code(),
        Some(0)
    );
    let after = repo
        .receipts()
        .iter()
        .map(|path| read(path))
        .collect::<Vec<_>>();
    assert_eq!(before, after, "a record under CI writes nothing");
}

#[test]
fn the_bypass_behaves_like_ci() {
    // So a measurement can see the uncached cost.
    let repo = Repo::new("bypass");
    repo.pass_once();
    assert_eq!(
        repo.check_with(&["mystep"], &[("BATTEN_STEP_RECEIPT_BYPASS", "1")]),
        "miss"
    );
}

#[test]
fn one_receipt_per_step_a_new_pass_replaces_the_old_key() {
    let repo = Repo::new("one-per-step");
    repo.pass_once();
    let first = read(&repo.receipts()[0]);
    repo.stage("two\n");
    repo.pass_once();
    let receipts = repo.receipts();
    assert_eq!(receipts.len(), 1, "{receipts:?}");
    assert_ne!(read(&receipts[0]), first, "the new pass replaced the key");
}

#[test]
fn the_receipt_is_pointer_only() {
    // A timestamp and a key, never input content.
    let repo = Repo::new("pointer");
    repo.pass_once();
    let receipts = repo.receipts();
    assert_eq!(receipts.len(), 1);
    let body = read(&receipts[0]);
    assert!(!body.contains("one"), "{body}");
    assert!(!body.contains("input.txt"), "{body}");
    assert!(!body.contains("tool-1.0"), "{body}");
    assert_eq!(body.lines().count(), 1, "{body}");
}

#[test]
fn cloud_498_a_miss_says_so_in_words_with_no_failure_shaped_line() {
    let repo = Repo::new("cloud-498");
    let out = repo.batten(&["step", "check", "some-step"], &[]);
    let (said, err) = (common::stdout(&out), common::stderr(&out));
    assert_eq!(
        out.status.code(),
        Some(0),
        "a miss is not a failure, so `mise run` prints none"
    );
    assert!(said.contains("running the step"), "{said}");
    for text in [&said, &err] {
        assert!(!text.contains("ERROR"), "{text}");
        assert!(!text.contains("::error::"), "{text}");
    }
}

// --- `step run`: the pair composed, so a caller writes no shell -----------------

#[test]
fn run_on_a_miss_runs_the_command_and_records_on_success() {
    let repo = Repo::new("run-records");
    let out = repo.run_step(&["mystep"], &["ok"], &[]);
    assert_eq!(out.status.code(), Some(0), "{}", common::stderr(&out));
    assert_eq!(repo.runs(), 1, "a miss runs the command");
    assert_eq!(repo.receipts().len(), 1, "and a zero exit records");
}

#[test]
fn a_hit_does_not_run_the_command() {
    let repo = Repo::new("run-hit");
    assert_eq!(
        repo.run_step(&["mystep"], &["ok"], &[]).status.code(),
        Some(0)
    );
    assert_eq!(repo.runs(), 1);
    let again = repo.run_step(&["mystep"], &["ok"], &[]);
    assert_eq!(again.status.code(), Some(0));
    assert_eq!(
        repo.runs(),
        1,
        "a hit answers from the receipt: {}",
        common::stderr(&again)
    );
}

#[test]
fn a_failing_command_passes_its_code_through_and_records_nothing() {
    // CLOUD-1090's property, now the verb's: the child's `2` stays `2` rather
    // than folding onto a runner's `1`, and a denied run leaves no receipt the
    // next run could answer from.
    let repo = Repo::new("run-fails");
    for code in ["2", "7"] {
        let out = repo.run_step(&["mystep"], &["fail"], &[("STUB_CODE", code)]);
        assert_eq!(
            out.status.code().map(|code| code.to_string()).as_deref(),
            Some(code),
            "{}",
            common::stderr(&out)
        );
    }
    assert!(repo.receipts().is_empty(), "{:?}", repo.receipts());
    assert_eq!(repo.check(&["mystep"]), "miss");
}

#[test]
fn an_undeclared_step_still_runs_its_command_and_records_nothing() {
    // Fail closed: no key is "run the step", never "skip it".
    let repo = Repo::new("run-undeclared");
    let out = repo.run_step(&["never-declared"], &["ok"], &[]);
    assert_eq!(out.status.code(), Some(0), "{}", common::stderr(&out));
    assert_eq!(repo.runs(), 1);
    assert!(repo.receipts().is_empty(), "{:?}", repo.receipts());
}

// --- the consumer: this repository's own tasks --------------------------------

/// Every step name a task in the committed `mise.toml` hands `batten step` is a
/// `[[step]]` row in the committed `batten.toml`, and the retired task is gone.
///
/// An undeclared name is a miss that records nothing — the safe direction, which
/// is exactly why nothing else would notice a name drifting between the two files:
/// the step would silently stop caching. And a caller still spelling the retired
/// task would fail at the task runner rather than at a gate.
#[test]
fn every_step_a_task_names_is_declared_and_the_retired_task_is_gone() {
    let manifest = std::fs::read_to_string(common::at_root("mise.toml")).expect("mise.toml");
    let config = std::fs::read_to_string(common::at_root("batten.toml")).expect("batten.toml");
    let declared: toml::Value = toml::from_str(&config).expect("batten.toml parses");
    let ids: Vec<&str> = declared["step"]
        .as_array()
        .expect("batten.toml declares a step table")
        .iter()
        .filter_map(|row| row["id"].as_str())
        .collect();

    assert!(
        common::task_block("step-receipt").is_none(),
        "`[tasks.step-receipt]` retired onto `batten step`"
    );
    let mut named = Vec::new();
    for line in manifest
        .lines()
        .filter(|line| !line.trim_start().starts_with('#'))
    {
        assert!(
            !line.contains("run -q step-receipt"),
            "a caller still spells the retired task: {line}"
        );
        for verb in ["step check ", "step record ", "step run "] {
            for (at, _) in line.match_indices(verb) {
                let rest = &line[at + verb.len()..];
                let name: String = rest
                    .chars()
                    .take_while(|c| !c.is_whitespace() && *c != '|' && *c != '"')
                    .collect();
                named.push(name);
            }
        }
    }
    assert!(
        named.len() >= 10,
        "the scan must find the repointed call sites: {named:?}"
    );
    for name in &named {
        assert!(
            ids.contains(&name.as_str()),
            "`batten step … {name}` names no `[[step]]` row, so it can never hit"
        );
    }
}
