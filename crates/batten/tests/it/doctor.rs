//! End-to-end tests over the compiled binary for `batten doctor` and the
//! documented exit-code table (CLOUD-66).
//!
//! Two obligations from the issue, and one property that carries both:
//!
//! * `doctor --json` works, and is byte-stable;
//! * the exit codes are documented **and** test-backed — where "documented"
//!   means *derived from* `exit.rs`, never a second copy that drifts. The
//!   README assertion below is what makes that claim true rather than stated.
//!
//! Kept out of `tests/cli.rs` deliberately — that file is the exit-code and
//! output-contract suite, and other work appends to it.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Output;

use common::{at_root, batten, stdout};

/// A scratch directory, optionally a git repository, optionally with a config.
///
/// Rooted in the **system** temp dir rather than `CARGO_TARGET_TMPDIR`, which
/// lives under this repository's `target/`. `git::repo_root` scrubs
/// `GIT_CEILING_DIRECTORIES` from its child on purpose — discovery must depend
/// on the path and the filesystem, never on ambient state — so a "not a
/// repository" fixture inside the tree would discover *this* repository and the
/// check would pass by accident.
fn scratch(name: &str, git: bool, config: Option<&str>) -> PathBuf {
    let dir = common::scratch_outside_tree("batten-doctor-e2e", name);
    if git {
        common::git_in(&dir, &["init", "-q"]);
    }
    if let Some(text) = config {
        common::write(&dir, "batten.toml", text);
    }
    dir
}

fn doctor(dir: &Path, extra: &[&str]) -> Output {
    let mut command = batten();
    command.arg("doctor");
    command.args(extra);
    command
        .current_dir(dir)
        .env_remove("BATTEN_STRICTNESS")
        .env_remove("BATTEN_FAIL_ON_WARNING")
        .env_remove("BATTEN_CONFIG_FROM")
        .output()
        .expect("run batten doctor")
}

// --- the diagnosis -----------------------------------------------------------

#[test]
fn a_healthy_repository_exits_zero() {
    let dir = scratch("doctor-healthy", true, Some("version = 1\n"));
    let output = doctor(&dir, &[]);
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(
        stdout(&output),
        "config ok\ngit-repo ok\ncommand-programs ok\npin-record ok\nhook-handlers ok\nplan-surface ok\ndoctor: 6 check(s), 0 failed\n"
    );
}

#[test]
fn a_missing_config_exits_one_and_names_the_reason() {
    let dir = scratch("doctor-no-config", true, None);
    let output = doctor(&dir, &[]);
    assert_eq!(output.status.code(), Some(1));
    assert!(
        stdout(&output).contains("config failed config-missing"),
        "got: {}",
        stdout(&output)
    );
}

#[test]
fn an_invalid_config_is_named_distinctly_from_a_missing_one() {
    // Two different remedies — write one, or fix one — so one reason id for both
    // would send the reader to the wrong place.
    let dir = scratch("doctor-bad-config", true, Some("this is not toml\n"));
    let output = doctor(&dir, &[]);
    assert_eq!(output.status.code(), Some(1));
    assert!(
        stdout(&output).contains("config failed config-invalid"),
        "got: {}",
        stdout(&output)
    );
}

#[test]
fn a_directory_outside_a_repository_is_reported() {
    let dir = scratch("doctor-not-a-repo", false, Some("version = 1\n"));
    let output = doctor(&dir, &[]);
    assert_eq!(output.status.code(), Some(1));
    assert!(
        stdout(&output).contains("git-repo failed not-a-repository"),
        "got: {}",
        stdout(&output)
    );
}

#[test]
fn every_check_is_reported_not_just_the_first_failure() {
    // A diagnostic that stops at the first problem reports one symptom when the
    // operator wants the list.
    let dir = scratch("doctor-all-fail", false, None);
    let output = doctor(&dir, &[]);
    assert_eq!(output.status.code(), Some(1));
    let text = stdout(&output);
    assert!(text.contains("config failed"), "got: {text}");
    assert!(text.contains("git-repo failed"), "got: {text}");
    // Five checks now; still two failures, because a checkout with no config
    // declares no handlers and `hook-handlers` passes vacuously over an empty
    // table, and a checkout with no pin record has no stale one. That is the
    // honest answer — there is nothing there to be wrong — and it is why the
    // count moved while the failure count did not.
    //
    // `plan-surface` passes for a different reason worth keeping distinct: it
    // reads the COMMITTED harness table rather than this checkout, so it says
    // the same thing in every scratch repository. What it can fail on is a
    // harness declaring neither a fetched spelling nor the row that owes the
    // survey (CLOUD-472), which is a defect in the crate and not in a tree.
    assert!(text.contains("doctor: 6 check(s), 2 failed"), "got: {text}");
}

// --- doctor never renders a policy verdict -----------------------------------

#[test]
fn no_reachable_input_makes_doctor_exit_two() {
    // The load-bearing guarantee (§7): a mediating harness reads `2` as deny,
    // and "this checkout is misconfigured" is not "policy says no". Asserted
    // across every failure shape doctor can reach, not argued from the code.
    let cases = [
        ("doctor-verdict-none", false, None),
        ("doctor-verdict-nogit", false, Some("version = 1\n")),
        ("doctor-verdict-bad", true, Some("nonsense\n")),
        ("doctor-verdict-version", true, Some("version = 99\n")),
        (
            "doctor-verdict-minver",
            true,
            Some("version = 1\nmin_batten_version = \"99.0.0\"\n"),
        ),
        // A config carrying a policy smell: `config lint` calls this exit 2, and
        // doctor deliberately does not run that check — folding it in would make
        // the same condition answer 1 here and 2 there.
        (
            "doctor-verdict-smell",
            true,
            Some("version = 1\nprotected = []\n"),
        ),
    ];
    for (name, git, config) in cases {
        let dir = scratch(name, git, config);
        let code = doctor(&dir, &[]).status.code();
        assert_ne!(code, Some(2), "{name} produced a policy verdict");
        assert!(
            matches!(code, Some(0 | 1)),
            "{name} produced an unexpected code: {code:?}"
        );
    }
}

#[test]
fn a_command_rule_naming_a_missing_program_is_reported() {
    // §9's premise is that a rule "names a command already on the operator's
    // PATH". This is the probe that says whether it holds — before `enforce`
    // discovers it mid-run as a failure of the gate rather than of the setup.
    let dir = scratch(
        "doctor-missing-program",
        true,
        Some(
            "version = 1\n\n[[rule]]\nid = \"r\"\nkind = \"command\"\nglob = \"**/*.rs\"\n             check = \"definitely-not-a-real-program-xyz\"\nseverity = \"deny\"\n",
        ),
    );
    let output = doctor(&dir, &[]);
    assert_eq!(output.status.code(), Some(1));
    assert!(
        stdout(&output).contains("command-programs failed program-not-on-path"),
        "got: {}",
        stdout(&output)
    );
}

#[test]
fn a_command_rule_naming_a_present_program_passes() {
    // `sh` is on PATH anywhere this suite can run.
    let dir = scratch(
        "doctor-present-program",
        true,
        Some(
            "version = 1\n\n[[rule]]\nid = \"r\"\nkind = \"command\"\nglob = \"**/*.rs\"\n             check = \"sh -c true\"\nseverity = \"deny\"\n",
        ),
    );
    let output = doctor(&dir, &[]);
    assert_eq!(output.status.code(), Some(0), "got: {}", stdout(&output));
}

#[test]
fn the_probe_never_executes_the_program_it_checks() {
    // A `read` verb may not reach user-supplied code (§5, CLOUD-170), so the
    // probe stats and never spawns. Asserted by naming a program that would
    // leave a file behind if it ran, and finding no file.
    let dir = scratch("doctor-no-exec", true, None);
    let marker = dir.join("ran");
    let script = dir.join("writes-a-file");
    fs::write(&script, format!("#!/bin/sh\ntouch {}\n", marker.display())).expect("write script");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).expect("chmod");
    }
    // A TOML *literal* string for the path, and that is not style. A basic
    // string processes escapes, so a Windows path interpolated into one —
    // `D:\a\batten\…` — reads `\a` and `\b` as control characters and rejects
    // `\U` outright. The config then fails to parse, `doctor` reports
    // `config-invalid`, and this case fails having never reached the probe it
    // is about (CLOUD-113's Windows job). Literal strings process nothing,
    // which is what a path wants.
    fs::write(
        dir.join("batten.toml"),
        format!(
            "version = 1\n\n[[rule]]\nid = \"r\"\nkind = \"command\"\nglob = \"**/*.rs\"\n             check = '{}'\nseverity = \"deny\"\n",
            script.display()
        ),
    )
    .expect("write config");

    let output = doctor(&dir, &[]);
    assert_eq!(output.status.code(), Some(0), "got: {}", stdout(&output));
    assert!(
        !marker.exists(),
        "the probe executed the program instead of stat-ing it"
    );
}

// --- the JSON channel --------------------------------------------------------

#[test]
fn json_is_valid_and_carries_every_check() {
    let dir = scratch("doctor-json", true, Some("version = 1\n"));
    let output = doctor(&dir, &["--json"]);
    assert_eq!(output.status.code(), Some(0));
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("the report is JSON");
    assert_eq!(report["ok"], true);
    let checks = report["checks"].as_array().expect("checks is an array");
    let names: Vec<&str> = checks.iter().filter_map(|c| c["name"].as_str()).collect();
    assert_eq!(
        names,
        vec![
            "config",
            "git-repo",
            "command-programs",
            "pin-record",
            "hook-handlers",
            "plan-surface"
        ]
    );
}

#[test]
fn json_is_emitted_even_for_a_healthy_repository() {
    // A data channel emits its document unconditionally: JSON that is sometimes
    // absent is unparseable. "Prints nothing when clean" is the human channel's
    // contract, not this one.
    let dir = scratch("doctor-json-healthy", true, Some("version = 1\n"));
    let output = doctor(&dir, &["--json"]);
    assert!(!output.stdout.is_empty());
}

#[test]
fn json_is_byte_stable_across_runs() {
    let dir = scratch("doctor-json-stable", true, Some("version = 1\n"));
    let first = doctor(&dir, &["--json"]);
    let second = doctor(&dir, &["--json"]);
    assert_eq!(first.stdout, second.stdout);
}

#[test]
fn json_carries_a_failure_reason_and_no_path() {
    // Rule 4 and §6 together: a message would embed an absolute path, which
    // differs per machine and leaks disk layout into a log.
    let dir = scratch("doctor-json-reason", false, None);
    let output = doctor(&dir, &["--json"]);
    let text = String::from_utf8_lossy(&output.stdout);
    let report: serde_json::Value = serde_json::from_str(&text).expect("the report is JSON");
    assert_eq!(report["ok"], false);
    assert_eq!(report["checks"][0]["reason"], "config-missing");
    assert!(
        !text.contains('/'),
        "the report leaked a filesystem path: {text}"
    );
}

#[test]
fn a_passing_check_omits_the_reason_rather_than_nulling_it() {
    // An absent field says "there is no reason"; a null one invites a consumer
    // to render the word "null" as though it were one.
    let dir = scratch("doctor-json-omit", true, Some("version = 1\n"));
    let report: serde_json::Value =
        serde_json::from_slice(&doctor(&dir, &["--json"]).stdout).expect("JSON");
    assert!(report["checks"][0].get("reason").is_none());
}

// --- the exit-code table is documented by derivation -------------------------

/// The table as the binary itself renders it, read out of `--help`.
fn rendered_table() -> String {
    let output = batten().arg("--help").output().expect("run batten --help");
    String::from_utf8_lossy(&output.stdout).into_owned()
}

#[test]
fn help_prints_the_exit_code_table() {
    let help = rendered_table();
    assert!(help.contains("Exit codes:"), "got: {help}");
    for (code, meaning) in EXPECTED {
        assert!(
            help.contains(&format!("{code}  {meaning}")),
            "`--help` is missing exit {code}: {help}"
        );
    }
}

#[test]
fn the_readme_documents_every_code_the_binary_renders() {
    // The drift gate behind "documented". A hand-written second copy of the
    // table is exactly what renumbering (CLOUD-226) left silently wrong across
    // every issue body that had restated it; this makes the same mistake in the
    // README a failing test instead.
    let readme = fs::read_to_string(at_root("README.md")).expect("read README.md");
    for (code, meaning) in EXPECTED {
        assert!(
            readme.contains(meaning),
            "README.md does not carry exit {code}'s meaning as the binary renders it: {meaning:?}"
        );
        assert!(
            readme.contains(&format!("`{code}`")),
            "README.md does not name exit code {code}"
        );
    }
}

/// Every code and the meaning the binary renders for it.
///
/// Duplicated here **on purpose**: this is the assertion's independent side. If
/// it merely read `exit::table()`, a wrong meaning changed in one place would
/// still match itself and the test would pass over the drift.
const EXPECTED: [(i32, &str); 4] = [
    (0, "clean — nothing to report; a mediated call is allowed"),
    (1, "config or usage error — fail loud, do not block"),
    (2, "policy verdict — a violation, or a mediated call denied"),
    (3, "internal error — fail loud, do not block"),
];

// --- the surface -------------------------------------------------------------

#[test]
fn doctor_is_declared_read_in_the_spec() {
    let output = batten().arg("spec").output().expect("run batten spec");
    let spec: serde_json::Value = serde_json::from_slice(&output.stdout).expect("spec is JSON");
    let doctor = spec["subcommands"]
        .as_array()
        .expect("subcommands")
        .iter()
        .find(|node| node["path"] == "doctor")
        .expect("doctor is in the spec");
    assert_eq!(doctor["effect"], "read");
    assert_eq!(doctor["flags"][0]["long"], "json");
}

#[test]
fn doctor_writes_no_file() {
    // `read` is structural, not a promise: run it in a directory with nothing in
    // it and the directory stays empty.
    let dir = scratch("doctor-writes-nothing", false, None);
    let before = fs::read_dir(&dir).expect("read dir").count();
    let _ = doctor(&dir, &[]);
    assert_eq!(fs::read_dir(&dir).expect("read dir").count(), before);
}

#[test]
fn this_repository_is_healthy() {
    // Consumer #1: the self-check Batten ships, run against Batten's own tree.
    let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let output = batten()
        .arg("doctor")
        .current_dir(&repo)
        .output()
        .expect("run batten doctor");
    assert_eq!(
        output.status.code(),
        Some(0),
        "this repository fails its own doctor: {}",
        stdout(&output)
    );
}
