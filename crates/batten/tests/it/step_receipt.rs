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
//!   never read, so the override did not survive, and the verb's own
//!   `--config-in`/`--config-from` do not reach the table either;
//! * the task body's key component (`mise tasks info`) is a declared TOOL argv
//!   whose stdout is keyed, and under `step run` the command's own argv is keyed;
//! * a `record` refusal is exit 2 (a statement about the tree, `EXITS_VERDICT`)
//!   where the task's was exit 1.
//!
//! The ledger below is the retired suite's cases. The cases after it that no arm
//! names are new with the verb, which reads a config the task never did: the
//! table is the keyed tree's own whatever `--config-in` names, an edited row is a
//! miss, and an authority that will not load runs the step (CLOUD-843 review).
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
const FAIL: &str = "#!/bin/sh\necho 'stub failure detail' >&2\nexit \"${STUB_CODE:-2}\"\n";

/// A step command that leaves a mark each time it RUNS and exits with the code
/// the case chooses, so a failure answered from its receipt is observable.
const RED: &str =
    "#!/bin/sh\necho ran >>bin/red.log\necho 'red detail' >&2\nexit \"${STUB_CODE:-0}\"\n";

/// A step command that PASSES after leaving the committed authority unloadable,
/// so the record after it cannot recompute the key.
const BREAK: &str = "#!/bin/sh\necho ran >>bin/ran.log\nprintf 'version = [\\n' >batten.toml\n";

/// A `cargo` standing in for nextest: it logs the argv it was handed, so a
/// case can see whether the journal's `--config-file` was added to it.
const CARGO: &str = "#!/bin/sh\necho \"$@\" >>bin/cargo.log\n";

/// A committed authority that will not parse.
const UNLOADABLE: &str = "version = [\n";

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

[[step]]
id = "traced"
inputs = ["input.txt"]
tools = [["toolv"]]

[[step]]
id = "based"
inputs = ["input.txt"]
tools = [["toolv"], ["batten", "step", "base", "--ref", "trunk", "--", "src"]]

[[step]]
id = "based-by-commit"
inputs = ["input.txt"]
tools = [["toolv"], ["git", "merge-base", "HEAD", "trunk"]]

[[step]]
id = "journaled"
inputs = ["input.txt"]
tools = [["toolv"]]
journal = "nextest"
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
            ("bin/red", RED),
            ("bin/break", BREAK),
            ("bin/cargo", CARGO),
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
        command.streamed_output().expect("run batten")
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

    /// Every receipt file, across the step groups of the grouped family
    /// (CLOUD-2784): `step-receipts/<digest(step)>/<digest(key)>`.
    fn receipts(&self) -> Vec<PathBuf> {
        let mut found: Vec<PathBuf> = std::fs::read_dir(self.dir.join(STORE).join("step-receipts"))
            .map(|groups| {
                groups
                    .flat_map(|group| std::fs::read_dir(group.unwrap().path()).unwrap())
                    .map(|entry| entry.unwrap().path())
                    .collect()
            })
            .unwrap_or_default();
        found.sort();
        found
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

/// A SUPERVISING TASK LEARNS WHICH STEP IT IS ON (CLOUD-425). The pid it
/// exports names its registry record, and a check moves that record's phase to
/// the step — the bookkeeping `task alive` reads to say where a lap stands.
#[test]
fn a_check_under_a_supervising_task_names_its_step_as_the_phase() {
    let repo = Repo::new("announce");
    let git_dir = repo.path(".git");
    batten::task::register(&git_dir, "verify", "4242", "boot", 1);
    assert_eq!(
        repo.check_with(&["mystep"], &[("BATTEN_TASK_PID", "4242")]),
        "miss"
    );
    assert_eq!(
        batten::task::read_field(&git_dir, "4242", "phase").as_deref(),
        Some("mystep"),
        "the registered task's phase is the step being checked"
    );
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

/// ONE RUNNER PER STEP (CLOUD-2783): the step's command runs under the
/// step's lock, so the lock's file is in the git dir while it runs.
///
/// Fails by: no lock taken, so a second runner of the same step would run
/// beside this one instead of waiting for its receipt.
#[test]
fn a_step_runs_under_its_lock() {
    let repo = Repo::new("locked");
    let out = repo.run_step(
        &["never-declared"],
        &["sh", "-c", "ls .git | grep -q '^batten-step-lock-'"],
        &[],
    );
    assert_eq!(
        out.status.code(),
        Some(0),
        "the lock is held while the command runs: {}",
        common::stderr(&out)
    );
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

// A RETURN TO A JUDGED TREE IS A HIT (CLOUD-2784). This case used to pin the
// opposite, `one_receipt_per_step_a_new_pass_replaces_the_old_key`: one record
// per step, so passing B discarded A's receipt and a lap on A, B, A re-ran every
// step on the third. Keeping a receipt per key is the change.
#[test]
fn a_step_keeps_a_receipt_per_key_so_a_return_hits() {
    let repo = Repo::new("per-key");
    repo.pass_once();
    repo.stage("two\n");
    repo.pass_once();
    assert_eq!(repo.receipts().len(), 2, "{:?}", repo.receipts());
    repo.stage("one\n");
    assert_eq!(
        repo.check(&["mystep"]),
        "hit",
        "the first tree's receipt answers"
    );
}

// THE SUPERSEDED STORE IS EMPTIED, NOT ORPHANED (CLOUD-2784): one receipt per
// step lived at `steps/<digest(step)>`, and nothing reads it now.
#[test]
fn old_receipts_are_removed_on_the_first_new_write() {
    let repo = Repo::new("old-store");
    let old = repo.dir.join(STORE).join("steps");
    std::fs::create_dir_all(&old).unwrap();
    let digest = batten::tools::digest(b"mystep");
    std::fs::write(old.join(&digest), "2026-01-01T00:00:00Z deadbeef\n").unwrap();
    repo.pass_once();
    assert!(!old.join(&digest).exists(), "the old receipt is gone");
    assert_eq!(repo.receipts().len(), 1, "and the step recorded");
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
fn a_failing_command_passes_its_code_through_and_records_no_pass() {
    // CLOUD-1090's property, now the verb's: the child's `2` stays `2` rather
    // than folding onto a runner's `1`, and a denied run leaves no PASS receipt
    // the next run could answer from. Each code is a different input state:
    // over the same one the second run would be answered from the first's
    // failure receipt (CLOUD-2253).
    let repo = Repo::new("run-fails");
    for (input, code) in [("one\n", "2"), ("two\n", "7")] {
        repo.stage(input);
        let out = repo.run_step(&["mystep"], &["fail"], &[("STUB_CODE", code)]);
        assert_eq!(
            out.status.code().map(|code| code.to_string()).as_deref(),
            Some(code),
            "{}",
            common::stderr(&out)
        );
    }
    let receipts = repo.receipts();
    assert_eq!(
        receipts.len(),
        2,
        "one failure receipt per key: {receipts:?}"
    );
    for receipt in &receipts {
        assert!(read(receipt).contains(" exit "), "{}", read(receipt));
    }
    assert_eq!(repo.check(&["mystep"]), "miss");
}

/// CLOUD-2091: a step is a gate whose reader is a log, so the command's own
/// failure output reaches the caller's stderr rather than only the capture store
/// — on a CI runner that store dies with the job.
#[test]
fn a_failing_step_shows_the_commands_own_output() {
    let repo = Repo::new("run-shows-output");
    let out = repo.run_step(&["mystep"], &["fail"], &[("STUB_CODE", "2")]);
    assert_eq!(out.status.code(), Some(2), "{}", common::stderr(&out));
    assert!(
        common::stderr(&out).contains("stub failure detail"),
        "the step's own failure output must reach the caller: {}",
        common::stderr(&out)
    );
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

// --- the case journal is the row's choice, never the argv's (CLOUD-2785) ----

/// Fails by: the journal keyed off anything but the row, so a row that
/// declares `journal = "nextest"` runs its nextest argv without the journal's
/// config, and a stopped run re-runs every case it had passed.
#[test]
fn a_declared_nextest_row_journals() {
    let repo = Repo::new("journal-declared");
    let out = repo.run_step(&["journaled"], &["cargo", "nextest", "run"], &[]);
    assert_eq!(out.status.code(), Some(0), "{}", common::stderr(&out));
    let argv = read(&repo.path("bin/cargo.log"));
    assert!(
        argv.starts_with("nextest run --config-file "),
        "the declared row runs under the journal's config: {argv:?}"
    );
}

/// Fails by: the argv sniff coming back, so a row that declares no journal is
/// journaled because its command happens to start `cargo nextest run`.
#[test]
fn an_undeclared_nextest_argv_is_not_journaled() {
    let repo = Repo::new("journal-undeclared");
    let out = repo.run_step(&["mystep"], &["cargo", "nextest", "run"], &[]);
    assert_eq!(out.status.code(), Some(0), "{}", common::stderr(&out));
    assert_eq!(
        read(&repo.path("bin/cargo.log")),
        "nextest run\n",
        "a row with no `journal` runs its command exactly as declared"
    );
}

// --- the table is the keyed tree's own, and a failure to read it runs the step -

#[test]
fn a_config_source_override_does_not_reach_the_step_table() {
    // `--config-in` moves where a POLICY is read from; this table is a claim
    // about the tree being keyed. A directory declaring `mystep` over a file the
    // step never reads must not mint a receipt that survives an input change.
    let repo = Repo::new("config-in");
    let elsewhere = common::scratch("step-receipt-config-in-elsewhere");
    common::write(
        &elsewhere,
        "batten.toml",
        "version = 1\n\n[[step]]\nid = \"mystep\"\ninputs = [\".gitignore\"]\ntools = [[\"toolv\"]]\n",
    );
    let there = elsewhere.to_str().expect("a UTF-8 scratch path");
    let env = [("BATTEN_CONFIG_IN", there)];
    assert_eq!(repo.check_with(&["mystep"], &env), "miss");
    assert_eq!(repo.record_with(&["mystep"], &env).status.code(), Some(0));
    assert_eq!(repo.check_with(&["mystep"], &env), "hit", "the premise");
    repo.stage("two\n");
    assert_eq!(
        repo.check_with(&["mystep"], &env),
        "miss",
        "the tree's own row keys `input.txt`, whatever directory the flag names"
    );
}

#[test]
fn an_edited_row_is_a_miss() {
    // A receipt earned under one declaration never answers under another, even
    // where the index entries it selects are the same bytes.
    let repo = Repo::new("row-edit");
    repo.pass_once();
    assert_eq!(repo.check(&["mystep"]), "hit", "the premise");
    let widened = TABLE.replacen(
        "inputs = [\"input.txt\"]",
        "inputs = [\"input.txt\", \"absent-*.txt\"]",
        1,
    );
    assert_ne!(widened, TABLE, "the edit landed");
    common::write(&repo.dir, "batten.toml", &widened);
    assert_eq!(repo.check(&["mystep"]), "miss");
}

#[test]
fn an_authority_that_will_not_load_still_runs_the_step() {
    // Fail closed: a config the verb cannot read is no key, and no key runs the
    // step -- never a usage error standing where the step's verdict belongs.
    let repo = Repo::new("unloadable");
    common::write(&repo.dir, "batten.toml", UNLOADABLE);
    let checked = repo.batten(&["step", "check", "mystep"], &[]);
    assert_eq!(
        checked.status.code(),
        Some(0),
        "{}",
        common::stderr(&checked)
    );
    assert!(
        common::stdout(&checked).contains("no key"),
        "{}",
        common::stdout(&checked)
    );
    let ran = repo.run_step(&["mystep"], &["ok"], &[]);
    assert_eq!(ran.status.code(), Some(0), "{}", common::stderr(&ran));
    assert_eq!(repo.runs(), 1, "the command ran");
    assert!(repo.receipts().is_empty(), "{:?}", repo.receipts());
    let failed = repo.run_step(&["mystep"], &["fail"], &[("STUB_CODE", "2")]);
    assert_eq!(
        failed.status.code(),
        Some(2),
        "the step's own code, not a config error's: {}",
        common::stderr(&failed)
    );
}

#[test]
fn a_passing_step_whose_record_refuses_stays_green() {
    // The record after a pass is an economy: here the command itself leaves the
    // authority unloadable, so the record cannot recompute the key and refuses.
    // The step passed, and exits 0.
    let repo = Repo::new("record-refuses");
    let out = repo.run_step(&["mystep"], &["break"], &[]);
    assert_eq!(out.status.code(), Some(0), "{}", common::stderr(&out));
    assert_eq!(repo.runs(), 1);
    assert!(
        common::stderr(&out).contains("Not recording"),
        "{}",
        common::stderr(&out)
    );
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
    // THE TWO SETS ARE ONE SET, which is stronger than any count: a call site
    // naming no row can never hit, and a row no call site names is an orphan
    // caching nothing. The count this replaced (`>= 10`) dated from the paired
    // `step check`/`step record` spelling, which `step run` collapsed to one line
    // per task.
    for name in &named {
        assert!(
            ids.contains(&name.as_str()),
            "`batten step … {name}` names no `[[step]]` row, so it can never hit"
        );
    }
    // A GRAPH NODE IS NAMED BY ITS GROUP (CLOUD-2785): a schedule-only row is
    // reached through `step graph run <group>`, never `step run <id>`, so it is
    // an orphan only when no line runs its group.
    let groups: Vec<String> = manifest
        .lines()
        .filter(|line| !line.trim_start().starts_with('#'))
        .flat_map(common::graph_groups)
        .collect();
    let reached = |id: &str| {
        declared["step"]
            .as_array()
            .into_iter()
            .flatten()
            .any(|row| {
                row["id"].as_str() == Some(id)
                    && row
                        .get("group")
                        .and_then(toml::Value::as_str)
                        .is_some_and(|group| groups.iter().any(|named| named == group))
            })
    };
    for id in &ids {
        assert!(
            named.iter().any(|name| name == id) || reached(id),
            "`[[step]] {id}` is named by no task and in no group a task runs, so it \
             does nothing: {named:?} {groups:?}"
        );
    }
    assert!(!named.is_empty(), "the scan must find the call sites");
    // THE LAP'S FOUR TIERS ARE `verify:gated`'s RUN ENTRIES, IN ORDER, while the
    // engine pin cannot read the graph rows' `group` (they are withheld until
    // the pin bump restores `step graph run verify-1 … verify-4`). Each tier is
    // one entry, found by a task only it runs.
    let gated =
        common::task_block_template("verify:gated").expect("`[tasks.\"verify:gated\"]` exists");
    let entry = |task: &str| {
        let found: Vec<usize> = gated
            .lines()
            .filter(|line| line.trim_start().starts_with("\"mise run "))
            .enumerate()
            .filter(|(_, line)| {
                line.trim()
                    .trim_matches(|c| c == '"' || c == ',')
                    .split(" ::: ")
                    .any(|member| member.split_whitespace().any(|word| word == task))
            })
            .map(|(index, _)| index)
            .collect();
        assert_eq!(found.len(), 1, "one run entry runs {task}: {gated}");
        found[0]
    };
    let tiers = [
        entry("batten-check"),
        entry("semver"),
        entry("verify:ci-suite"),
        entry("perf-gate"),
    ];
    assert!(
        tiers.windows(2).all(|pair| pair[0] < pair[1]),
        "the lap runs its four tiers in order: {tiers:?}\n{gated}"
    );
    assert!(
        gated.contains("--continue-on-error verify:commit-lint")
            && gated.contains("--continue-on-error --jobs 2 semver")
            && gated.contains("--continue-on-error --jobs 1 test:traced ::: verify:ci-suite"),
        "every multi-task tier is a `--continue-on-error` fan: {gated}"
    );
}

/// The seconds a `stage <step> <how> <seconds>` line on stderr reports.
fn stage_seconds(err: &str, step: &str, how: &str) -> Option<f64> {
    let prefix = format!("stage {step} {how} ");
    err.lines()
        .find_map(|line| line.strip_prefix(&prefix)?.trim().parse().ok())
}

/// A step command held open on an EVENT rather than a clock (CLOUD-2789), and
/// the span this test itself saw it held for: a lower bound on its wall time.
///
/// The command `cat`s a FIFO this side fills. Opening the write end returns
/// only once the command has opened the read end, so the span starts with the
/// command running; it ends when the last byte is written and the end closed,
/// and the command cannot exit before the EOF that close sends. So the
/// command's own wall time is at least the span, whatever the host's speed, and
/// nothing here waits on a duration.
fn held_step(repo: &Repo) -> (Output, u64) {
    use batten::capture::Streamed as _;
    // BESIDE the repository, never in it: a read of the tree that opened a
    // FIFO would block on it, and that is no subject of this case.
    let gate = repo.dir.with_extension("gate");
    let _ = std::fs::remove_file(&gate);
    #[expect(
        clippy::disallowed_types,
        reason = "stays, test-only: a FIFO is made by `mkfifo`, and no door in `common` makes one"
    )]
    let made = std::process::Command::new("mkfifo")
        .arg(&gate)
        .streamed_output()
        .expect("mkfifo runs");
    assert!(made.status.success(), "{}", common::stderr(&made));
    let fill = gate.clone();
    let filler = std::thread::spawn(move || {
        use std::io::Write as _;
        let mut end = std::fs::OpenOptions::new()
            .write(true)
            .open(&fill)
            .expect("the step opens the gate's read end");
        let opened = std::time::Instant::now();
        // Enough bytes that the span is milliseconds on any host: a pipe
        // moves them only as fast as the command drains them.
        let chunk = vec![0_u8; 1 << 20];
        for _ in 0..64 {
            end.write_all(&chunk).expect("the step drains the gate");
        }
        drop(end);
        u64::try_from(opened.elapsed().as_millis()).expect("a span in u64 millis")
    });
    let gate = gate.to_str().expect("a UTF-8 temp path");
    let script = format!("cat '{gate}' > /dev/null");
    let out = repo.run_step(&["mystep"], &["sh", "-c", &script], &[]);
    let held = filler.join().expect("the filler thread");
    (out, held)
}

/// The `stage` line's seconds as the whole milliseconds it renders exactly.
fn stage_millis(err: &str, step: &str, how: &str) -> Option<u64> {
    let prefix = format!("stage {step} {how} ");
    err.lines().find_map(|line| {
        let (whole, frac) = line.strip_prefix(&prefix)?.trim().split_once('.')?;
        Some(whole.parse::<u64>().ok()? * 1000 + frac.parse::<u64>().ok()?)
    })
}

/// Fails by: a run's wall time not written onto its receipt, or the `stage`
/// line reporting something other than the time the command took (CLOUD-2776).
#[test]
fn a_step_record_carries_its_wall_time() {
    // `sh`, `cat` and `mkfifo`: a unix contract, compiled everywhere.
    if !cfg!(unix) {
        return;
    }
    let repo = Repo::new("wall-time");
    let (out, held) = held_step(&repo);
    assert_eq!(out.status.code(), Some(0), "{}", common::stderr(&out));
    assert!(held > 0, "the gate held the step for a measurable span");
    let body = read(&repo.receipts()[0]);
    let millis: u64 = body
        .split_whitespace()
        .find_map(|field| field.strip_suffix("ms")?.parse().ok())
        .unwrap_or_else(|| panic!("the receipt carries its run's time: {body}"));
    assert!(millis >= held, "the run was held {held}ms: {body}");
    let said = stage_millis(&common::stderr(&out), "mystep", "ran")
        .unwrap_or_else(|| panic!("a stage line: {}", common::stderr(&out)));
    assert!(said >= held, "{said}ms against a {held}ms hold");
}

/// Fails by: a hit reporting its own few milliseconds, which makes a resumed
/// lap look faster than the work it stands for, or reporting nothing.
#[test]
fn a_hit_reports_the_recorded_runs_time_not_its_own() {
    if !cfg!(unix) {
        return;
    }
    let repo = Repo::new("hit-time");
    let (first, held) = held_step(&repo);
    assert_eq!(first.status.code(), Some(0), "{}", common::stderr(&first));
    assert!(held > 0, "the gate held the step for a measurable span");
    // The same argv, so the same key: a hit, which opens no gate and runs
    // nothing, so it cannot block on the FIFO left behind.
    let gate = repo.dir.with_extension("gate");
    let script = format!("cat '{}' > /dev/null", gate.to_str().expect("UTF-8"));
    let hit = repo.run_step(&["mystep"], &["sh", "-c", &script], &[]);
    let err = common::stderr(&hit);
    assert!(
        stage_seconds(&err, "mystep", "ran").is_none(),
        "a hit runs nothing: {err}"
    );
    let said =
        stage_millis(&err, "mystep", "hit").unwrap_or_else(|| panic!("a hit's stage line: {err}"));
    assert!(said >= held, "the hit reports the recorded run: {err}");
}

// ---- the trace lint (CLOUD-2784) -------------------------------------------
//
// Each case branches on the tracer INSIDE the case and never returns early: on
// a host with `strace` the lint is what is asserted, and on one without it the
// untraced arm is, so no host passes a case by skipping it.

impl Repo {
    /// A step command at `bin/<name>`, git-ignored with the rest of `bin/`.
    fn script(&self, name: &str, body: &str) {
        common::write(&self.dir, &format!("bin/{name}"), body);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(
                self.dir.join("bin").join(name),
                std::fs::Permissions::from_mode(0o755),
            )
            .expect("chmod");
        }
    }

    /// `step run traced -- <name>`, then the first word of the same run again:
    /// `hit` iff the first recorded. The same command, because `step run`
    /// keys on it and a bare `step check` does not.
    fn traced_run(&self, name: &str) -> (Output, String) {
        let out = self.run_step(&["traced"], &[name], &[]);
        let again = self.run_step(&["traced"], &[name], &[]);
        let after = common::stderr(&again)
            .split_whitespace()
            .next()
            .unwrap_or_default()
            .to_owned();
        (out, after)
    }
}

#[test]
fn an_undeclared_read_fails_a_traced_miss() {
    let repo = Repo::new("trace-undeclared");
    common::write(&repo.dir, "other.txt", "other\n");
    common::git_in(&repo.dir, &["add", "other.txt"]);
    repo.script("readb", "#!/bin/sh\ncat input.txt other.txt >/dev/null\n");
    let (out, after) = repo.traced_run("readb");
    if batten::mutate::trace::Host::here().tracer().is_some() {
        assert_eq!(out.status.code(), Some(2), "{}", common::stderr(&out));
        let stderr = common::stderr(&out);
        assert!(
            stderr.contains("step run: traced read 1 path(s) outside its inputs; read "),
            "{stderr}"
        );
        let listing = stderr
            .lines()
            .find_map(|line| {
                line.split_once("outside its inputs; read ")
                    .map(|(_, at)| at)
            })
            .expect("the line points at the listing");
        assert_eq!(
            std::fs::read_to_string(listing.trim()).unwrap(),
            "other.txt\n"
        );
        assert!(
            !std::path::Path::new(listing.trim())
                .with_extension("trace")
                .exists(),
            "the trace is removed once read; only the listing stays"
        );
        assert_eq!(after, "miss", "an undeclared read records nothing");
    } else {
        assert_eq!(out.status.code(), Some(0), "{}", common::stderr(&out));
        assert_eq!(after, "hit", "untraced, the step records as before");
    }
}

/// A STEP RUN ALREADY UNDER A TRACER RUNS UNTRACED (CLOUD-2784): ptrace takes
/// one tracer, so a second `strace` cannot attach. The read is undeclared, so a
/// run that tried to trace anyway fails either way — it could not attach, or it
/// saw the read — and only the untraced arm exits 0.
#[test]
fn a_step_run_already_under_a_tracer_runs_untraced() {
    let repo = Repo::new("trace-nested");
    common::write(&repo.dir, "other.txt", "other\n");
    common::git_in(&repo.dir, &["add", "other.txt"]);
    repo.script("readb", "#!/bin/sh\ncat input.txt other.txt >/dev/null\n");
    // NO TRACER ON THIS HOST: nothing is nested, and the plain run records.
    // Both arms assert; neither returns early (`silent_skip`).
    if let Some(strace) = batten::mutate::trace::Host::here().tracer() {
        nested_run_passes(&repo, &strace);
    } else {
        let (out, after) = repo.traced_run("readb");
        assert_eq!(out.status.code(), Some(0), "{}", common::stderr(&out));
        assert_eq!(after, "hit");
    }
}

/// `readb` run by batten under `strace -f`: the nested run is untraced.
fn nested_run_passes(repo: &Repo, strace: &str) {
    let out = common::task_bash(
        &repo.dir,
        &format!(
            "exec {strace} -f -qq -o /dev/null {} step run traced -- readb",
            env!("CARGO_BIN_EXE_batten")
        ),
    )
    .env_remove("CI")
    .env_remove("BATTEN_STEP_RECEIPT_BYPASS")
    .env_remove("BATTEN_TASK_PID")
    .streamed_output()
    .expect("run batten under a tracer");
    assert_eq!(
        out.status.code(),
        Some(0),
        "a nested run is untraced and passes: {}",
        common::stderr(&out)
    );
    // UNTRACED, NOT TRACED BADLY: a nested run that tried a second tracer
    // could not attach, read its trace as unfinished and minted no receipt
    // (lap 27's survivors in `tracer`/`traced_already`), so the next run must
    // be a hit.
    let again = repo.run_step(&["traced"], &["readb"], &[]);
    assert_eq!(
        common::stderr(&again).split_whitespace().next(),
        Some("hit"),
        "the nested run recorded its receipt: {}",
        common::stderr(&out)
    );
}

#[test]
fn a_probe_for_a_missing_path_outside_the_inputs_is_undeclared() {
    let repo = Repo::new("trace-probe");
    repo.script(
        "probe",
        "#!/bin/sh\ncat input.txt >/dev/null\ntest -e c\nexit 0\n",
    );
    let (out, after) = repo.traced_run("probe");
    if batten::mutate::trace::Host::here().tracer().is_some() {
        assert_eq!(out.status.code(), Some(2), "{}", common::stderr(&out));
        assert!(
            common::stderr(&out).contains("read 1 path(s) outside its inputs"),
            "{}",
            common::stderr(&out)
        );
        assert_eq!(after, "miss");
    } else {
        assert_eq!(out.status.code(), Some(0), "{}", common::stderr(&out));
        assert_eq!(after, "hit");
    }
}

#[test]
fn a_declared_ignored_or_outside_read_records_under_trace() {
    // `input.txt` is declared, `bin/taskfile` is git-ignored, `/etc/passwd` is
    // outside the worktree, and `.` is the root: none is undeclared.
    let repo = Repo::new("trace-declared");
    repo.script(
        "readok",
        "#!/bin/sh\ncat input.txt bin/taskfile /etc/passwd >/dev/null\ntest -d .\n",
    );
    let (out, after) = repo.traced_run("readok");
    assert_eq!(out.status.code(), Some(0), "{}", common::stderr(&out));
    assert!(
        !common::stderr(&out).contains("outside its inputs"),
        "{}",
        common::stderr(&out)
    );
    assert_eq!(after, "hit", "traced or not, a declared run records");
}

/// A TWO-TREE STEP KEYS ITS BASE BY CONTENT (CLOUD-2787): `based` declares its
/// base half as `step base` over `src`, so a rebase onto a trunk commit that
/// touched only `docs` hits. `based-by-commit` keys the merge base's commit id,
/// the shape this replaces, and misses on the same rebase — which is what makes
/// the first assertion discriminate.
#[test]
fn a_rebase_onto_an_unrelated_trunk_commit_hits() {
    let repo = Repo::new("rebase-unrelated");
    common::write(&repo.dir, "src/a.rs", "fn a() {}\n");
    common::write(&repo.dir, "docs/a.md", "one\n");
    common::git_in(&repo.dir, &["add", "-A"]);
    common::git_in(&repo.dir, &["commit", "-qm", "trunk"]);
    let branch = common::git_in(&repo.dir, &["rev-parse", "--abbrev-ref", "HEAD"]);
    common::git_in(&repo.dir, &["branch", "trunk"]);
    common::write(&repo.dir, "feature.txt", "work\n");
    common::git_in(&repo.dir, &["add", "feature.txt"]);
    common::git_in(&repo.dir, &["commit", "-qm", "feature"]);

    for step in ["based", "based-by-commit"] {
        let first = repo.run_step(&[step], &["ok"], &[]);
        assert_eq!(first_word(&first), "miss", "{}", common::stderr(&first));
        let again = repo.run_step(&[step], &["ok"], &[]);
        assert_eq!(
            first_word(&again),
            "hit",
            "the premise: {}",
            common::stderr(&again)
        );
    }

    common::git_in(&repo.dir, &["checkout", "-q", "trunk"]);
    common::write(&repo.dir, "docs/a.md", "two\n");
    common::git_in(&repo.dir, &["commit", "-qam", "docs only"]);
    common::git_in(&repo.dir, &["checkout", "-q", &branch]);
    common::git_in(&repo.dir, &["rebase", "-q", "trunk"]);

    let based = repo.run_step(&["based"], &["ok"], &[]);
    assert_eq!(first_word(&based), "hit", "{}", common::stderr(&based));
    let by_commit = repo.run_step(&["based-by-commit"], &["ok"], &[]);
    assert_eq!(
        first_word(&by_commit),
        "miss",
        "the control: a commit-id base moves on the same rebase: {}",
        common::stderr(&by_commit)
    );
}

// ---- a commit-metadata step keys its commits (CLOUD-2897) ------------------

/// This repository's own `[[step]]` row `id`, as a fixture authority holding it
/// alone: the case judges the row as declared, never a copy of it.
fn declared_step_table(id: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../batten.toml");
    let authority: toml::Table = std::fs::read_to_string(path)
        .expect("this repository's batten.toml")
        .parse()
        .expect("this repository's batten.toml parses");
    let row = authority["step"]
        .as_array()
        .expect("a [[step]] table")
        .iter()
        .find(|row| row.get("id").and_then(toml::Value::as_str) == Some(id))
        .unwrap_or_else(|| panic!("a [[step]] row `{id}`"))
        .clone();
    let mut table = toml::Table::new();
    table.insert(String::from("version"), toml::Value::Integer(1));
    table.insert(String::from("step"), toml::Value::Array(vec![row]));
    toml::to_string(&table).expect("the row renders")
}

/// A COMMIT-METADATA STEP KEYS WHAT IT JUDGES (CLOUD-2897). `commit-attribution`
/// judges each commit's author and committer identity and its message;
/// `commit-check` judges each message. Both are handed refs (`origin/main..HEAD`),
/// so a row keyed on files and tool versions alone keeps its key across a rewrite
/// that leaves the tree identical, and replays the verdict of commits that no
/// longer exist: measured on #1276, a committer rewrite replayed `commit own
/// refused` for the rewritten sha while `attribution check` over the range
/// exited 0.
///
/// Fails by: either row's key unmoved by a rewrite of exactly what it judges,
/// so the second run answers from the first run's failure instead of running.
#[test]
fn a_rewrite_of_what_a_commit_step_judges_misses_though_the_tree_is_identical() {
    // (row, the rewrite of only what that row judges)
    let rewrites: [(&str, &[&str]); 2] = [
        (
            "commit-attribution",
            &[
                "-c",
                "user.name=Owner",
                "-c",
                "user.email=owner@example.com",
                "commit",
                "-q",
                "--amend",
                "--no-edit",
                "--reset-author",
            ],
        ),
        (
            "commit-check",
            &[
                "commit",
                "-q",
                "--amend",
                "-m",
                "feat: the subject, rewritten",
            ],
        ),
    ];
    for (step, rewrite) in rewrites {
        let repo = Repo::new(&format!("commit-keyed-{step}"));
        common::write(&repo.dir, "batten.toml", &declared_step_table(step));
        // A `cargo` that answers its version, as the row's tool probe asks.
        common::write(&repo.dir, "bin/cargo", "#!/bin/sh\necho 'cargo 1.0.0'\n");
        common::git_in(&repo.dir, &["commit", "-qam", "the row"]);
        common::git_in(
            &repo.dir,
            &["update-ref", "refs/remotes/origin/main", "HEAD"],
        );
        common::write(&repo.dir, "input.txt", "two\n");
        common::git_in(
            &repo.dir,
            &[
                "-c",
                "user.name=Vendor",
                "-c",
                "user.email=vendor@example.com",
                "commit",
                "-qam",
                "feat: the subject",
            ],
        );
        let tree = common::git_in(&repo.dir, &["rev-parse", "HEAD^{tree}"]);

        let refused = repo.run_step(&[step], &["red"], &[("STUB_CODE", "1")]);
        assert_eq!(
            refused.status.code(),
            Some(1),
            "{step}: {}",
            common::stderr(&refused)
        );
        let replayed = repo.run_step(&[step], &["red"], &[("STUB_CODE", "0")]);
        assert_eq!(
            read(&repo.path("bin/red.log")).lines().count(),
            1,
            "{step}: the premise: an unchanged range answers from its receipt: {}",
            common::stderr(&replayed)
        );

        common::git_in(&repo.dir, rewrite);
        assert_eq!(
            common::git_in(&repo.dir, &["rev-parse", "HEAD^{tree}"]),
            tree,
            "{step}: the rewrite leaves the tree identical"
        );
        let rerun = repo.run_step(&[step], &["red"], &[("STUB_CODE", "0")]);
        assert_eq!(
            (
                rerun.status.code(),
                read(&repo.path("bin/red.log")).lines().count()
            ),
            (Some(0), 2),
            "{step}: a rewrite of what the step judges runs it again: {}",
            common::stderr(&rerun)
        );
    }
}

// ---- the write hazard (CLOUD-2786) -----------------------------------------
//
// The read half was already there: `record` refuses when the key moved while
// the step ran. A step that writes a declared input and restores it before it
// exits leaves the key unmoved, so only the trace can see it.

/// Fails by: a write to a declared input that was put back minting a receipt
/// (its verdict judged bytes the tree never held), the line not pointing at a
/// listing naming the input, or an untraced host refusing a run it cannot see.
#[test]
fn a_step_that_rewrites_a_declared_input_and_restores_it_takes_no_receipt() {
    let repo = Repo::new("trace-rewrite");
    repo.script(
        "rewrite",
        "#!/bin/sh\ncp input.txt bin/saved\necho changed >input.txt\ncp bin/saved input.txt\n",
    );
    let (out, after) = repo.traced_run("rewrite");
    assert_eq!(
        read(&repo.path("input.txt")),
        "one\n",
        "the premise: restored"
    );
    if batten::mutate::trace::Host::here().tracer().is_some() {
        let stderr = common::stderr(&out);
        assert_eq!(out.status.code(), Some(2), "{stderr}");
        let listing = stderr
            .lines()
            .find_map(|line| line.split_once("step run: traced wrote 1 declared input(s); read "))
            .map_or_else(
                || panic!("the line points at the listing: {stderr}"),
                |(_, at)| at.trim().to_owned(),
            );
        assert_eq!(std::fs::read_to_string(&listing).unwrap(), "input.txt\n");
        assert!(
            !stderr.contains("outside its inputs"),
            "the write is reported before any read: {stderr}"
        );
        assert_eq!(after, "miss", "a written input records nothing");
    } else {
        assert_eq!(out.status.code(), Some(0), "{}", common::stderr(&out));
        assert_eq!(after, "hit", "untraced, the step records as before");
    }
}

/// Fails by: a write under a git-ignored path that a declared pathspec
/// selects (a build's `target/`) read as a hazard, so no whole-tree step ever
/// recorded again.
#[test]
fn a_write_under_an_ignored_path_is_not_a_hazard() {
    let repo = Repo::new("trace-ignored-write");
    repo.script(
        "build",
        // A PLAIN `mkdir`, NEVER `-p`: coreutils' `-p` changes directory to
        // make each component, and a `chdir` leaves every bare relative path
        // in the trace unresolvable — the reader's stated limit, not this case.
        // `unlink` and `rmdir`, NEVER `rm -r`, for the same reason: `rm` is
        // whatever `PATH` resolves, and a hosted session puts a shell stand-in
        // first that changes directory (measured: two `chdir`s from it turned
        // this trace unread). The writes are the same two syscalls.
        "#!/bin/sh\ncat input.txt >/dev/null\nmkdir bin/out\necho artefact >bin/out/a\nunlink bin/out/a\nrmdir bin/out\n",
    );
    let out = repo.run_step(&["whole"], &["build"], &[]);
    let again = repo.run_step(&["whole"], &["build"], &[]);
    assert_eq!(out.status.code(), Some(0), "{}", common::stderr(&out));
    assert!(
        !common::stderr(&out).contains("declared input(s)"),
        "{}",
        common::stderr(&out)
    );
    assert_eq!(
        common::stderr(&again).split_whitespace().next(),
        Some("hit"),
        "traced or not, an ignored write records: {}",
        common::stderr(&out)
    );
}

// --- a failed run is a verdict too (CLOUD-2253) --------------------------------
//
// A receipt written only on success left a failed check with no record of its
// inputs, so a lap on a known-red tree re-ran the whole fan to say red again.

/// The `step run` of the `red` stub over `mystep`, exiting `code` if it runs.
fn red_run(repo: &Repo, code: &str, env: &[(&str, &str)]) -> Output {
    let mut env = env.to_vec();
    env.push(("STUB_CODE", code));
    repo.run_step(&["mystep"], &["red"], &env)
}

/// How many times the `red` stub has run.
fn red_runs(repo: &Repo) -> usize {
    read(&repo.path("bin/red.log")).lines().count()
}

/// Fails by: a failure leaving no receipt (the command re-runs and its new
/// code wins), the recorded code not the one returned, or the answer printing
/// the log's bytes rather than a pointer to them.
#[test]
fn a_failed_run_is_not_re_run_on_unchanged_inputs_and_returns_its_code() {
    let repo = Repo::new("red-kept");
    let first = red_run(&repo, "7", &[]);
    assert_eq!(first.status.code(), Some(7), "{}", common::stderr(&first));
    let again = red_run(&repo, "0", &[]);
    let err = common::stderr(&again);
    assert_eq!(again.status.code(), Some(7), "the recorded code: {err}");
    assert_eq!(
        red_runs(&repo),
        1,
        "answered from the failure receipt: {err}"
    );
    assert_eq!(
        err.split_whitespace().next(),
        Some("red"),
        "the answer says red first: {err}"
    );
    let pointer = err
        .lines()
        .find_map(|line| line.strip_prefix("step run: mystep failed with exit 7; read "))
        .unwrap_or_else(|| panic!("the answer points at the failed run's log: {err}"));
    assert!(pointer.contains("stderr:"), "a capture handle: {pointer}");
    assert!(
        !err.contains("red detail"),
        "a pointer, never the log: {err}"
    );
}

/// Fails by: a failure receipt answering for inputs it never judged.
#[test]
fn a_changed_input_re_runs_a_failed_step() {
    let repo = Repo::new("red-moved");
    assert_eq!(red_run(&repo, "7", &[]).status.code(), Some(7));
    repo.stage("two\n");
    let out = red_run(&repo, "0", &[]);
    assert_eq!(out.status.code(), Some(0), "{}", common::stderr(&out));
    assert_eq!(red_runs(&repo), 2);
}

/// Fails by: the bypass answered from a failure receipt, or a bypassed run
/// writing a receipt over the failure.
#[test]
fn the_bypass_re_runs_a_failed_step() {
    let repo = Repo::new("red-bypass");
    assert_eq!(red_run(&repo, "7", &[]).status.code(), Some(7));
    let bypassed = red_run(&repo, "0", &[("BATTEN_STEP_RECEIPT_BYPASS", "1")]);
    assert_eq!(
        bypassed.status.code(),
        Some(0),
        "{}",
        common::stderr(&bypassed)
    );
    assert_eq!(red_runs(&repo), 2, "the bypass forces a run");
    let after = red_run(&repo, "0", &[]);
    assert_eq!(
        after.status.code(),
        Some(7),
        "a bypassed pass records nothing"
    );
    assert_eq!(red_runs(&repo), 2);
}

/// Fails by: a failure receipt the engine released before it (which reads the
/// key as the last field of the first line) would read as a PASS.
#[test]
fn a_failure_receipt_never_reads_as_a_pass_to_the_key_reader() {
    let repo = Repo::new("red-shape");
    assert_eq!(red_run(&repo, "7", &[]).status.code(), Some(7));
    let receipts = repo.receipts();
    assert_eq!(receipts.len(), 1, "{receipts:?}");
    let body = read(&receipts[0]);
    let first = body.lines().next().unwrap_or_default();
    let key = first.split_whitespace().nth(2).unwrap_or_default();
    assert_eq!(key.len(), 64, "the key rides the first line: {body}");
    assert_ne!(first.split_whitespace().last(), Some(key), "{body}");
}

/// What in a `tests/it` module's source makes one of its cases reach a tracer
/// (CLOUD-2789): the case asks itself, or it spawns a `step run` (which traces
/// a miss) or a mutation sweep (whose reach traces each case).
const REACHES_A_TRACER: [&str; 6] = [
    "common::traced()",
    "trace::Host::here()",
    "\"step\", \"run\"",
    "\"mutate\"",
    "RUN_ARG",
    "__mutate-schema",
];

/// Every `tests/it` module whose source holds a [`REACHES_A_TRACER`] marker,
/// sorted.
fn modules_reaching_a_tracer() -> Vec<String> {
    let dir = common::at_root("crates/batten/tests/it");
    let mut out: Vec<String> = std::fs::read_dir(&dir)
        .expect("list tests/it")
        .map(|entry| entry.expect("a tests/it entry").path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "rs"))
        .filter(|path| path.file_stem().is_some_and(|stem| stem != "main"))
        .filter(|path| {
            let source = std::fs::read_to_string(path).expect("read a tests/it module");
            REACHES_A_TRACER
                .iter()
                .any(|marker| source.contains(marker))
        })
        .map(|path| path.file_stem().unwrap().to_string_lossy().into_owned())
        .collect();
    out.sort();
    out
}

/// THE TRACED LANE RUNS EVERY MODULE THAT REACHES A TRACER, as CI's `ci` job
/// does (CLOUD-2789). There, under `CI=true`, the suite runs outside `step run`
/// and each such case takes its traced branch; locally the suite runs under
/// `step run`'s tracer and takes only the fallback, so `test:traced` is the
/// one local place those branches run.
///
/// THE LANE SETS NO `CI` (CLOUD-2789): cargo tracks the `CI` that
/// `ra_ap_stdx` reads at compile time, so a lane-wide `CI=true` rebuilt seven
/// crates against `test:cargo` once each way per lap. A case whose branch
/// depends on a runtime `CI` sets or clears it on what it spawns.
///
/// Fails by: a module that reaches a tracer missing from the lane (its traced
/// branch first judged on CI), a module the lane names that no longer does, the
/// lane setting `CI` for its whole build again, or the required-trace guard
/// dropped.
#[test]
fn the_traced_lane_runs_every_module_that_reaches_a_tracer() {
    let manifest: toml::Table = std::fs::read_to_string(common::at_root("mise.toml"))
        .expect("read mise.toml")
        .parse()
        .expect("mise.toml is TOML");
    let task = manifest
        .get("tasks")
        .and_then(|tasks| tasks.get("test:traced"))
        .expect("a `test:traced` task");
    let suite = task
        .get("run")
        .and_then(toml::Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(toml::Value::as_str)
        .find(|argv| argv.contains("--test it"))
        .expect("a `test:traced` argv over the `it` binary");
    let mut named: Vec<String> = suite
        .split_whitespace()
        .filter_map(|word| word.strip_suffix("::"))
        .map(str::to_owned)
        .collect();
    named.sort();
    assert_eq!(named, modules_reaching_a_tracer());
    let env = task.get("env").expect("`test:traced` sets its env");
    assert!(
        env.get("CI").is_none(),
        "the lane's env carries no `CI`, so its build is the suite's: {env}"
    );
    assert_eq!(
        env.get(common::TRACED_REQUIRED)
            .and_then(toml::Value::as_str),
        Some("1")
    );
}
