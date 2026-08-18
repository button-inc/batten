//! The advisory-only `judge` rule kind, over the compiled binary (CLOUD-56).
//!
//! Every test here is one bullet of the issue's acceptance, and the first one is
//! the whole issue: a judge that **raises** leaves `batten enforce` exiting `0`.
//! House style §0.3 and non-negotiable rule 3 say an advisory surface must be
//! structurally unable to block, and the only way to show "structurally" from
//! outside the binary is to make a judge say the worst thing it can say and
//! watch the exit code not move.
//!
//! The judge is a **fixture stub on `PATH`**, not a model: the engine's contract
//! with a judge command is an exit code, so a stub that exits on demand
//! exercises the whole of it. Nothing here reaches a network, which is also why
//! these run in CI at all.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::path::{Path, PathBuf};
use std::process::Output;

use common::{Fixture, StateHome, batten, scratch, stderr, stdout, write};

/// The rule id every fixture below declares, so assertions can name it.
const RULE: &str = "reads-intentional";

/// Planted in a matched file. A judge payload may carry it — that is what the
/// row asked for — but no *engine* output may, on either channel.
const FILE_SENTINEL: &str = "FILE-BYTES-SENTINEL-should-never-be-echoed";

/// The row's committed question. Also never echoed: `criteria` is config, and
/// Batten prints pointers, not payloads (non-negotiable rule 4).
const CRITERIA: &str = "CRITERIA-SENTINEL-does-this-assert-behaviour";

/// What the stub writes to its own stdout and stderr. The engine captures and
/// drops both, so seeing this anywhere means the judge's prose leaked into
/// Batten's channels — the gate/judge line (CLOUD-93) failing in the direction
/// nobody watches.
const JUDGE_CHATTER: &str = "JUDGE-PROSE-SENTINEL-the-model-said-this";

/// A repository with one judge row, plus a `bin/` holding a stub that exits
/// `code`.
///
/// The stub echoes on both its streams before exiting, so every test here is
/// also a test that the engine drops what a judge says.
fn fixture(name: &str, code: i32, extra_config: &str) -> (PathBuf, PathBuf) {
    let root = scratch(name);
    let config = format!(
        "version = 1\n\n[judge]\nrun = \"judge-stub\"\n\n[[rule]]\nid = \"{RULE}\"\nkind = \
         \"judge\"\nglob = \"**/*.rs\"\ncriteria = \"{CRITERIA}\"\nno_fix_reason = \"a judge \
         finding is answered by a human, not a command\"\n{extra_config}"
    );
    let repo = Fixture::at(root.join("repo"))
        .config(&config)
        .file("src/a.rs", &format!("fn main() {{}}\n// {FILE_SENTINEL}\n"))
        .git()
        .base_commit()
        .build();
    let home = Fixture::at(root.join("home")).build();
    let bin = root.join("bin");
    write(
        &bin,
        "judge-stub",
        &format!(
            "#!/bin/sh\ncat >/dev/null\necho '{JUDGE_CHATTER}'\necho '{JUDGE_CHATTER}' \
             >&2\nexit {code}\n"
        ),
    );
    make_executable(&bin.join("judge-stub"));
    (repo, home)
}

#[cfg(unix)]
fn make_executable(path: &Path) {
    use std::os::unix::fs::PermissionsExt as _;
    let mut mode = std::fs::metadata(path)
        .expect("stat the stub")
        .permissions();
    mode.set_mode(0o755);
    std::fs::set_permissions(path, mode).expect("chmod the stub");
}

#[cfg(not(unix))]
fn make_executable(_path: &Path) {}

/// Run `batten` in `repo` with the fixture's own store and, when `with_stub`,
/// its `bin/` on `PATH`.
///
/// `with_stub == false` is not a convenience: "the program is absent from
/// `PATH`" is one of the acceptance bullets, and the only honest way to build
/// that case is to run the very same fixture without its `bin/`.
fn judge_cmd(repo: &Path, home: &Path, args: &[&str], with_stub: bool) -> Output {
    let bin = repo.parent().expect("the fixture root").join("bin");
    let inherited = std::env::var_os("PATH").unwrap_or_default();
    // `join_paths`, never a hardcoded `:`. The separator is `;` on Windows and a
    // path there begins `D:\`, so the interpolated form did not merely fail to
    // separate — it produced a PATH whose first entry was `D` and whose second
    // swallowed the rest, leaving the stub unreachable and every case that needs
    // it reporting `cannot run judge program` in place of its subject. Seven of
    // fourteen, on CLOUD-113's twentieth Windows run, and the misattribution cost
    // a round trip: the engine's own PATH lookup was correct throughout, because
    // it has always used `split_paths`.
    let path = if with_stub {
        let mut entries = vec![bin.into_os_string()];
        entries.extend(std::env::split_paths(&inherited).map(PathBuf::into_os_string));
        std::env::join_paths(entries).expect("join the fixture bin onto PATH")
    } else {
        inherited
    };
    batten()
        .state_home(home)
        .args(args)
        .current_dir(repo)
        .env("PATH", path)
        .env("GIT_CEILING_DIRECTORIES", env!("CARGO_TARGET_TMPDIR"))
        .output()
        .expect("run batten")
}

/// The store's records, as `state list -J` reports them.
fn stored(repo: &Path, home: &Path) -> Vec<serde_json::Value> {
    let output = judge_cmd(repo, home, &["state", "list", "-J"], true);
    assert_eq!(output.status.code(), Some(0), "state list always succeeds");
    serde_json::from_str::<serde_json::Value>(&stdout(&output))
        .expect("state list -J is JSON")
        .as_array()
        .expect("a JSON array")
        .clone()
}

/// Neither channel carries a sentinel. Run on every case, not a chosen one:
/// a leak that only happens on the unresolved path is still a leak.
fn assert_pointer_only(output: &Output) {
    for (channel, text) in [("stdout", stdout(output)), ("stderr", stderr(output))] {
        for sentinel in [FILE_SENTINEL, CRITERIA, JUDGE_CHATTER] {
            assert!(
                !text.contains(sentinel),
                "{channel} carried {sentinel}; Batten emits pointers, never payloads:\n{text}"
            );
        }
    }
}

#[test]
fn a_judge_that_raises_cannot_move_the_exit_code() {
    // THE acceptance case. The stub exits 2 — the strongest thing a judge can
    // say — and `enforce` still exits 0, because a judge outcome never becomes
    // a `Finding` and so `any_blocking` never sees it. If this test ever goes
    // red, the advisory bound has been lost, whatever the code says.
    let (repo, home) = fixture("judge-raises", 2, "");
    let output = judge_cmd(&repo, &home, &["enforce"], true);
    assert_eq!(
        output.status.code(),
        Some(0),
        "a judge verdict may inform, never gate (house style §0.3):\n{}",
        stderr(&output)
    );
    assert_pointer_only(&output);

    let records = stored(&repo, &home);
    assert_eq!(
        records.len(),
        1,
        "the raise is recorded, it just cannot block"
    );
    assert_eq!(records[0]["rule"].as_str(), Some(RULE));
}

#[test]
fn fail_on_warning_cannot_promote_a_judge_outcome_either() {
    // The other half of "structurally unable to block": `--fail-on-warning` is
    // the engine's one promotion path, and it promotes *findings*. A judge
    // outcome is not one, so there is nothing here to promote.
    let (repo, home) = fixture("judge-no-promotion", 2, "");
    let output = judge_cmd(&repo, &home, &["enforce", "--fail-on-warning"], true);
    assert_eq!(
        output.status.code(),
        Some(0),
        "promotion applies to findings, and a judge outcome is not one:\n{}",
        stderr(&output)
    );
}

#[test]
fn a_clean_judge_registers_nothing() {
    let (repo, home) = fixture("judge-clean", 0, "");
    let output = judge_cmd(&repo, &home, &["enforce"], true);
    assert_eq!(output.status.code(), Some(0));
    assert_pointer_only(&output);
    assert!(
        stored(&repo, &home).is_empty(),
        "exit 0 is a pass, and a pass is not a record"
    );
}

#[test]
fn a_judge_that_did_not_deliver_a_verdict_registers_rather_than_passing() {
    // The arm a naive mapping loses. Exit 1 and exit 3 are neither "clean" nor
    // "raised" — they are a judge that failed to answer, and reading either as
    // a pass is the false green this engine exists to catch. Both codes, because
    // one of them is Batten's own usage code and the temptation to special-case
    // it is exactly the bug.
    for (name, code) in [("judge-odd-1", 1), ("judge-odd-3", 3)] {
        let (repo, home) = fixture(name, code, "");
        let output = judge_cmd(&repo, &home, &["enforce"], true);
        assert_eq!(
            output.status.code(),
            Some(0),
            "a judge's plumbing failure is not a policy verdict either:\n{}",
            stderr(&output)
        );
        assert_pointer_only(&output);
        assert!(
            stderr(&output).contains("unresolved"),
            "exit {code} must report as unresolved:\n{}",
            stderr(&output)
        );
        assert_eq!(
            stored(&repo, &home).len(),
            1,
            "an unresolved judge is recorded, not forgotten"
        );
    }
}

#[test]
fn a_program_absent_from_path_is_a_usage_error_naming_it() {
    // The `command`-kind precedent: a program the config names and `PATH` does
    // not have is a statement about the invocation (exit 1), never a verdict
    // about the repository (exit 2) — so a mediating harness reads it as "do
    // not block", which is right, because nothing was judged.
    let (repo, home) = fixture("judge-absent", 0, "");
    let output = judge_cmd(&repo, &home, &["enforce"], false);
    assert_eq!(output.status.code(), Some(1));
    assert!(
        stderr(&output).contains("judge-stub"),
        "the refusal must name the program:\n{}",
        stderr(&output)
    );
}

#[test]
fn check_refuses_a_judge_row_and_names_the_verb_that_runs_it() {
    // `check` is declared `read` (§5), and a judge spawns a configured command,
    // so the read-only surface refuses the whole run rather than skipping the
    // row. Skipping would exit 0 over a gate that did not run.
    let (repo, home) = fixture("judge-on-check", 0, "");
    let output = judge_cmd(&repo, &home, &["check"], true);
    assert_eq!(output.status.code(), Some(1));
    assert!(
        stderr(&output).contains("batten enforce"),
        "a refusal names the fix, not merely the refusal (CLOUD-122):\n{}",
        stderr(&output)
    );
}

#[test]
fn a_judge_row_declaring_severity_is_refused_at_load() {
    // `severity` is the column that decides the exit contract, and a judge must
    // not reach it by any path. Refused rather than ignored: a key that parses
    // and does nothing reads to a reviewer as a setting that applies.
    let (repo, home) = fixture("judge-severity", 0, "severity = \"deny\"\n");
    for verb in [["enforce"], ["check"]] {
        let output = judge_cmd(&repo, &home, &verb, true);
        assert_eq!(
            output.status.code(),
            Some(1),
            "a config error is exit 1 on every surface that loads it"
        );
        assert!(
            stderr(&output).contains("severity") && stderr(&output).contains(RULE),
            "the refusal names the row and the key:\n{}",
            stderr(&output)
        );
    }
}

#[test]
fn a_judge_row_with_no_command_is_refused_at_load() {
    let root = scratch("judge-no-run");
    let repo = Fixture::at(root.join("repo"))
        .config(&format!(
            "version = 1\n\n[[rule]]\nid = \"{RULE}\"\nkind = \"judge\"\nglob = \
             \"**/*.rs\"\ncriteria = \"{CRITERIA}\"\nno_fix_reason = \"by hand\"\n"
        ))
        .file("src/a.rs", "fn main() {}\n")
        .git()
        .base_commit()
        .build();
    let home = Fixture::at(root.join("home")).build();
    let output = judge_cmd(&repo, &home, &["enforce"], true);
    assert_eq!(output.status.code(), Some(1));
    assert!(
        stderr(&output).contains("[judge]"),
        "the refusal names the table that has to exist:\n{}",
        stderr(&output)
    );
}

#[test]
fn a_judge_row_with_no_stated_reason_is_refused_at_load() {
    // A judge finding reaches the store, and CLOUD-81 refuses a stored finding
    // nothing can close. A judge has no mechanical fix by construction, so the
    // authored reason is the only remediation it can carry — required at load,
    // which is what keeps that ingest refusal unreachable from a config that
    // parses.
    let root = scratch("judge-no-reason");
    let repo = Fixture::at(root.join("repo"))
        .config(&format!(
            "version = 1\n\n[judge]\nrun = \"judge-stub\"\n\n[[rule]]\nid = \
             \"{RULE}\"\nkind = \"judge\"\nglob = \"**/*.rs\"\ncriteria = \"{CRITERIA}\"\n"
        ))
        .file("src/a.rs", "fn main() {}\n")
        .git()
        .base_commit()
        .build();
    let home = Fixture::at(root.join("home")).build();
    let output = judge_cmd(&repo, &home, &["enforce"], true);
    assert_eq!(output.status.code(), Some(1));
    assert!(
        stderr(&output).contains("no_fix_reason"),
        "the refusal names the missing column:\n{}",
        stderr(&output)
    );
}

#[test]
fn a_protected_match_refuses_the_invocation_before_any_byte_is_read() {
    // CLOUD-135's decision 2, reaching the binary for the first time here — the
    // half that issue's own Ready block said would land with this one. One
    // protected member refuses the WHOLE invocation, so no payload containing
    // the other files exists either, and the diagnostic is a count rather than
    // a path: which file is secret is itself worth not printing.
    let root = scratch("judge-protected");
    let repo = Fixture::at(root.join("repo"))
        .config(&format!(
            "version = 1\nprotected = [\"secrets/**\"]\n\n[judge]\nrun = \"judge-stub\"\n\n\
             [[rule]]\nid = \"{RULE}\"\nkind = \"judge\"\nglob = \"**/*\"\ncriteria = \
             \"{CRITERIA}\"\nno_fix_reason = \"by hand\"\n"
        ))
        .file("src/a.rs", "fn main() {}\n")
        .file("secrets/prod.env", &format!("TOKEN={FILE_SENTINEL}\n"))
        .git()
        .base_commit()
        .build();
    let home = Fixture::at(root.join("home")).build();
    let output = judge_cmd(&repo, &home, &["enforce"], true);
    assert_eq!(output.status.code(), Some(1));
    assert_pointer_only(&output);
    assert!(
        stderr(&output).contains("protected"),
        "the refusal says why:\n{}",
        stderr(&output)
    );
    assert!(
        !stderr(&output).contains("prod.env"),
        "a count, never the path:\n{}",
        stderr(&output)
    );
}

#[test]
fn two_runs_over_one_tree_are_byte_identical_and_hold_one_identity() {
    // Byte-stability (§6) and idempotent registration (CLOUD-123) are one test
    // because they fail together: an identity derived from anything that moves
    // between runs shows up as both a second record and a different line.
    let (repo, home) = fixture("judge-stable", 2, "");
    // Bind the store first. The run that mints one says so — a one-time
    // statement about Batten's own state, not about the tree — and comparing
    // across that boundary would measure the store's birth rather than the
    // judge's stability, which is the property under test.
    let minting = judge_cmd(&repo, &home, &["enforce"], true);
    assert_eq!(minting.status.code(), Some(0));

    let first = judge_cmd(&repo, &home, &["enforce"], true);
    let second = judge_cmd(&repo, &home, &["enforce"], true);
    assert_eq!(first.stdout, second.stdout);
    assert_eq!(first.stderr, second.stderr);

    let records = stored(&repo, &home);
    assert_eq!(
        records.len(),
        1,
        "judging the same tree twice is one finding, observed twice"
    );
    assert_eq!(
        records[0]["instances"].as_array().map(Vec::len),
        Some(1),
        "one context, one instance"
    );
}

#[test]
fn the_stored_finding_carries_the_rows_tier_and_settles_by_re_running_the_judge() {
    // The two fields that make a judge record different from every other. The
    // tier comes off the ROW — there is no severity to derive one from — and the
    // settling check is the judge's own argv, because re-running the judge is
    // the only thing that can re-decide what a model decided (CLOUD-81).
    let (repo, home) = fixture("judge-tier", 2, "tier = \"caution\"\n");
    let output = judge_cmd(&repo, &home, &["enforce"], true);
    assert_eq!(output.status.code(), Some(0));

    let records = stored(&repo, &home);
    assert_eq!(records.len(), 1);
    assert_eq!(
        records[0]["tier"].as_str(),
        Some("caution"),
        "the declared tier, not one derived through the rank table"
    );
    assert_eq!(
        records[0]["check"]["argv"][0].as_str(),
        Some("judge-stub"),
        "a judge finding settles by re-running its judge"
    );
}

#[test]
fn an_absent_tier_defaults_to_the_least_urgent_rank() {
    // A response deadline nobody stated is the weakest one. Defaulting upward
    // would let an omitted key manufacture urgency, which is the same class of
    // mistake as an omitted severity defaulting to `deny`.
    let (repo, home) = fixture("judge-default-tier", 2, "");
    assert_eq!(
        judge_cmd(&repo, &home, &["enforce"], true).status.code(),
        Some(0)
    );
    let records = stored(&repo, &home);
    assert_eq!(records[0]["tier"].as_str(), Some("advisory"));
}

#[test]
fn a_row_whose_glob_matches_nothing_spends_no_model_call() {
    // A metered call to be told there was nothing to look at. The glob is a
    // gate before it is a payload source — the same reading `run_rule` gives a
    // command row — and the stub here exits 2, so a spent call would be visible
    // as a stored finding.
    let root = scratch("judge-no-match");
    let repo = Fixture::at(root.join("repo"))
        .config(&format!(
            "version = 1\n\n[judge]\nrun = \"judge-stub\"\n\n[[rule]]\nid = \
             \"{RULE}\"\nkind = \"judge\"\nglob = \"**/*.nothing-matches-this\"\ncriteria = \
             \"{CRITERIA}\"\nno_fix_reason = \"by hand\"\n"
        ))
        .file("src/a.rs", "fn main() {}\n")
        .git()
        .base_commit()
        .build();
    let home = Fixture::at(root.join("home")).build();
    let bin = root.join("bin");
    write(&bin, "judge-stub", "#!/bin/sh\nexit 2\n");
    make_executable(&bin.join("judge-stub"));

    let output = judge_cmd(&repo, &home, &["enforce"], true);
    assert_eq!(output.status.code(), Some(0));
    assert!(
        stored(&repo, &home).is_empty(),
        "no match is no question, so there is nothing to record"
    );
}
