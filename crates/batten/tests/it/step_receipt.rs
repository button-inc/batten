//! `[tasks.step-receipt]` — per-step receipts keyed by input content (CLOUD-424),
//! over the task's own body with `mise` and a tool stubbed first on `PATH`, so
//! every component of the key is a lever one case pulls alone (CLOUD-1752).
//!
//! # RETIREMENT LEDGER, PER PATH — what `shell retire partial` reads
//!
//! The store moved onto CLOUD-1713's keyed family and the miss moved from exit 1
//! to a WORD at exit 0, because the call site moved behind `mise run`, which wraps
//! an exit 1 in `ERROR task failed` (CLOUD-498). Every case that asserted a miss by
//! exit code is `changed:` to assert it by word; every case that named the old
//! `batten-receipts/step.*` files is `changed:` to name the keyed store.
//!
// ported: mise-tasks/step-receipt.sh subject:mise.toml crates/batten/tests/it/step_receipt.rs
// ported: tests/step-receipt.bats subject:mise.toml crates/batten/tests/it/step_receipt.rs
// changed: "no receipt: the step runs" mise.toml a miss is the word `miss` at exit 0, since `mise run` would print a failure line over exit 1 (CLOUD-498)
// carried: "identical inputs, command and tools hit" mise.toml kind:mechanism
// changed: "a changed input file misses" mise.toml the miss is read as the word, not exit 1
// changed: "a changed command misses" mise.toml the miss is read as the word, not exit 1
// changed: "a changed tool version misses" mise.toml the miss is read as the word, not exit 1
// changed: "a changed argument misses — a receipt for one target must not answer for another" mise.toml the miss is read as the word, not exit 1
// changed: "a file task's bytes are key material" mise.toml the miss is read as the word, not exit 1
// changed: "a tool that cannot answer is no key, and no key runs the step" mise.toml the miss is read as the word, not exit 1
// changed: "a spec that resolves to nothing runs the step" mise.toml the miss is read as the word, not exit 1
// changed: "a deleted input runs the step" mise.toml the miss is read as the word, not exit 1
// changed: "unstaged divergence is no key — the index is what the key hashes, so the worktree must agree with it" mise.toml the miss is read as the word, not exit 1
// changed: "an untracked file inside the specs is no key" mise.toml the miss is read as the word, not exit 1
// changed: "an unknown step with no override always runs" mise.toml the miss is read as the word, not exit 1
// changed: "a corrupted receipt store runs everything and records nothing — never skips" mise.toml the store corrupted is the keyed family's directory, and the check's miss is read as the word
// carried: "a record with no paired check refuses" mise.toml kind:mechanism
// changed: "inputs changing while the step ran refuse the record — no receipt may attest bytes the run never judged" mise.toml the absence of a receipt is read from the keyed store rather than a `step.*` glob
// changed: "under CI the cache neither hits nor records — CI's job is to confirm independently" mise.toml the miss is read as the word, not exit 1
// changed: "the bypass behaves like CI, so a measurement can see the uncached cost" mise.toml the miss is read as the word, not exit 1
// changed: "one receipt per step: a new pass prunes the old key" mise.toml the family is keyed by step, so one record per step holds by construction and the case asserts the store holds exactly one
// changed: "the receipt is pointer-only: a timestamp and a key, never input content" mise.toml the record is read from the keyed store rather than a `step.*` glob
// changed: "CLOUD-498: a miss is exit 1 and says so in words, with no failure-shaped line" mise.toml the miss is now exit 0 as well as in words, which is what lets the call site go through `mise run` at all

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::{Path, PathBuf};

/// A `mise` answering `tasks info` with a body the case controls, and a tool
/// whose `--version` the case controls or breaks.
const MISE: &str = "#!/bin/sh\necho \"{\\\"run\\\":[\\\"${STUB_BODY:-echo body-v1}\\\"],\\\"file\\\":${STUB_FILE:-null},\\\"shell\\\":null}\"\n";
const TOOL: &str = "#!/bin/sh\nif [ -n \"${STUB_TOOL_FAIL:-}\" ]; then exit 9; fi\necho \"${STUB_TOOL:-tool-1.0}\"\n";

/// Where the keyed family keeps its records.
const STORE: &str = ".git/batten-records";

struct Repo {
    dir: PathBuf,
}

impl Repo {
    fn new(name: &str) -> Self {
        let dir = common::scratch(&format!("step-receipt-{name}"));
        for (file, body) in [("bin/mise", MISE), ("bin/toolv", TOOL)] {
            common::write(&dir, file, body);
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                std::fs::set_permissions(dir.join(file), std::fs::Permissions::from_mode(0o755))
                    .expect("chmod");
            }
        }
        common::write(&dir, "input.txt", "one\n");
        common::write(&dir, ".gitignore", "bin/\n");
        common::init_repo(&dir);
        common::git_in(&dir, &["add", "-A"]);
        common::git_in(&dir, &["commit", "-qm", "init"]);
        Self { dir }
    }

    fn run_with(&self, args: &str, env: &[(&str, &str)]) -> (Option<i32>, String, String) {
        let mut command = common::task_command(&self.dir, "step-receipt");
        command
            .env("usage_args", args)
            .env("BATTEN_STEP_SPECS", "input.txt")
            .env("BATTEN_STEP_TOOLS", "toolv")
            .env_remove("CI")
            .env_remove("BATTEN_STEP_RECEIPT_BYPASS")
            .env_remove("BATTEN_TASK_PID");
        for (name, value) in env {
            command.env(name, value);
        }
        let out = command.output().expect("run step-receipt");
        (
            out.status.code(),
            String::from_utf8_lossy(&out.stdout).into_owned(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        )
    }

    fn run(&self, args: &str) -> (Option<i32>, String, String) {
        self.run_with(args, &[])
    }

    /// `check`, asserting the exit-0 contract and returning the first word.
    fn check_with(&self, step: &str, env: &[(&str, &str)]) -> String {
        let (code, out, err) = self.run_with(&format!("check {step}"), env);
        assert_eq!(code, Some(0), "a check always exits 0: {out}{err}");
        out.split_whitespace().next().unwrap_or_default().to_owned()
    }

    fn check(&self, step: &str) -> String {
        self.check_with(step, &[])
    }

    fn record(&self, step: &str) -> Option<i32> {
        self.run(&format!("record {step}")).0
    }

    /// One full pass: a miss, the run's stand-in, and the record.
    fn pass_once(&self) {
        assert_eq!(self.check("mystep"), "miss");
        assert_eq!(self.record("mystep"), Some(0));
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
}

fn read(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_default()
}

#[test]
fn no_receipt_the_step_runs() {
    let repo = Repo::new("none");
    let (code, out, _) = repo.run("check mystep");
    assert_eq!(code, Some(0));
    assert!(out.starts_with("miss"), "{out}");
    assert!(out.contains("running the step"), "{out}");
}

#[test]
fn identical_inputs_command_and_tools_hit() {
    let repo = Repo::new("hit");
    repo.pass_once();
    let (_, out, _) = repo.run("check mystep");
    assert!(out.starts_with("hit"), "{out}");
    assert!(out.contains("not re-deriving"), "{out}");
}

#[test]
fn a_changed_input_file_misses() {
    let repo = Repo::new("input");
    repo.pass_once();
    repo.stage("two\n");
    assert_eq!(repo.check("mystep"), "miss");
}

#[test]
fn a_changed_command_misses() {
    let repo = Repo::new("command");
    repo.pass_once();
    assert_eq!(
        repo.check_with("mystep", &[("STUB_BODY", "echo body-v2")]),
        "miss"
    );
}

#[test]
fn a_changed_tool_version_misses() {
    let repo = Repo::new("tool");
    repo.pass_once();
    assert_eq!(
        repo.check_with("mystep", &[("STUB_TOOL", "tool-2.0")]),
        "miss"
    );
}

#[test]
fn a_changed_argument_misses() {
    // A receipt for one target must not answer for another.
    let repo = Repo::new("argument");
    assert_eq!(repo.check("mystep --arg one"), "miss");
    assert_eq!(repo.record("mystep --arg one"), Some(0));
    assert_eq!(repo.check("mystep --arg one"), "hit");
    assert_eq!(repo.check("mystep --arg two"), "miss");
}

#[test]
fn a_file_tasks_bytes_are_key_material() {
    let repo = Repo::new("file-task");
    let taskfile = repo.path("bin/taskfile");
    std::fs::write(&taskfile, "body bytes v1\n").unwrap();
    let file = format!("\"{}\"", taskfile.display());
    let env = [("STUB_FILE", file.as_str())];
    assert_eq!(repo.check_with("mystep", &env), "miss");
    assert_eq!(repo.run_with("record mystep", &env).0, Some(0));
    assert_eq!(repo.check_with("mystep", &env), "hit");
    std::fs::write(&taskfile, "body bytes v2\n").unwrap();
    assert_eq!(repo.check_with("mystep", &env), "miss");
}

#[test]
fn a_tool_that_cannot_answer_is_no_key_and_no_key_runs_the_step() {
    let repo = Repo::new("tool-fails");
    repo.pass_once();
    let (_, out, _) = repo.run_with("check mystep", &[("STUB_TOOL_FAIL", "1")]);
    assert!(out.starts_with("miss"), "{out}");
    assert!(out.contains("no key"), "{out}");
}

#[test]
fn a_spec_that_resolves_to_nothing_runs_the_step() {
    let repo = Repo::new("spec-empty");
    let (_, out, _) = repo.run_with("check mystep", &[("BATTEN_STEP_SPECS", "absent-*.txt")]);
    assert!(out.starts_with("miss"), "{out}");
    assert!(out.contains("no key"), "{out}");
}

#[test]
fn a_deleted_input_runs_the_step() {
    let repo = Repo::new("deleted");
    repo.pass_once();
    std::fs::remove_file(repo.path("input.txt")).unwrap();
    assert_eq!(repo.check("mystep"), "miss");
}

#[test]
fn unstaged_divergence_is_no_key() {
    // The index is what the key hashes, so the worktree must agree with it.
    let repo = Repo::new("unstaged");
    repo.pass_once();
    common::write(&repo.dir, "input.txt", "one\ndrift\n");
    let (_, out, _) = repo.run("check mystep");
    assert!(out.starts_with("miss"), "{out}");
    assert!(out.contains("no key"), "{out}");
}

#[test]
fn an_untracked_file_inside_the_specs_is_no_key() {
    let repo = Repo::new("untracked");
    let env = [("BATTEN_STEP_SPECS", ".")];
    assert_eq!(repo.check_with("mystep", &env), "miss");
    assert_eq!(repo.run_with("record mystep", &env).0, Some(0));
    assert_eq!(repo.check_with("mystep", &env), "hit");
    common::write(&repo.dir, "stray", "");
    assert_eq!(repo.check_with("mystep", &env), "miss");
}

#[test]
fn an_unknown_step_with_no_override_always_runs() {
    let repo = Repo::new("unknown");
    let mut command = common::task_command(&repo.dir, "step-receipt");
    let out = command
        .env("usage_args", "check never-declared")
        .env_remove("BATTEN_STEP_SPECS")
        .env_remove("BATTEN_STEP_TOOLS")
        .env_remove("CI")
        .env_remove("BATTEN_STEP_RECEIPT_BYPASS")
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    assert_eq!(out.status.code(), Some(0));
    assert!(text.starts_with("miss"), "{text}");
    assert!(text.contains("no key"), "{text}");
}

#[test]
fn a_corrupted_receipt_store_runs_everything_and_records_nothing() {
    // Never skips.
    let repo = Repo::new("corrupt");
    repo.pass_once();
    std::fs::remove_dir_all(repo.path(STORE)).unwrap();
    std::fs::write(repo.path(STORE), "").unwrap();
    assert_eq!(repo.check("mystep"), "miss");
    assert_eq!(repo.record("mystep"), Some(1));
}

#[test]
fn a_record_with_no_paired_check_refuses() {
    let repo = Repo::new("unpaired");
    let (code, _, err) = repo.run("record mystep");
    assert_eq!(code, Some(1));
    assert!(err.contains("no pending key"), "{err}");
}

/// TWO RUNS OF ONE STEP AT ONCE BOTH RECORD. `verify` runs some steps twice
/// concurrently — `cargo-clippy` finished twice inside `[hooks]` on #1036 — and
/// they share the one pending slot. The first `record` used to blank it, so the
/// second refused a green step with "no pending key".
#[test]
fn two_concurrent_runs_of_one_step_both_record() {
    let repo = Repo::new("twins");
    assert_eq!(repo.check("mystep"), "miss");
    assert_eq!(repo.check("mystep"), "miss");
    assert_eq!(repo.record("mystep"), Some(0));
    assert_eq!(
        repo.record("mystep"),
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
    assert_eq!(repo.check("mystep"), "hit");
    assert_eq!(repo.record("mystep"), Some(0));
}

#[test]
fn inputs_changing_while_the_step_ran_refuse_the_record() {
    // No receipt may attest bytes the run never judged.
    let repo = Repo::new("weld");
    assert_eq!(repo.check("mystep"), "miss");
    repo.stage("two\n");
    assert_eq!(repo.record("mystep"), Some(1));
    assert!(repo.receipts().is_empty(), "{:?}", repo.receipts());
}

#[test]
fn under_ci_the_cache_neither_hits_nor_records() {
    // CI's job is to confirm independently.
    let repo = Repo::new("ci");
    repo.pass_once();
    assert_eq!(repo.check_with("mystep", &[("CI", "true")]), "miss");
    assert_eq!(repo.run_with("record mystep", &[("CI", "true")]).0, Some(0));
}

#[test]
fn the_bypass_behaves_like_ci() {
    // So a measurement can see the uncached cost.
    let repo = Repo::new("bypass");
    repo.pass_once();
    assert_eq!(
        repo.check_with("mystep", &[("BATTEN_STEP_RECEIPT_BYPASS", "1")]),
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
    assert_eq!(body.lines().count(), 1, "{body}");
}

#[test]
fn cloud_498_a_miss_says_so_in_words_with_no_failure_shaped_line() {
    let repo = Repo::new("cloud-498");
    let (code, out, err) = repo.run("check some-step");
    assert_eq!(
        code,
        Some(0),
        "a miss is not a failure, so `mise run` prints none"
    );
    assert!(out.contains("running the step"), "{out}");
    for text in [&out, &err] {
        assert!(!text.contains("ERROR"), "{text}");
        assert!(!text.contains("::error::"), "{text}");
    }
}
