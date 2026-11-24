//! `batten step cover` (CLOUD-2788): every required CI check either passed
//! locally at `HEAD`'s tree, through the step `CI_LOCAL_PROOF` maps it to, or
//! is exempt in `CI_EXEMPT_CHECKS`; otherwise the verb refuses and names each.
//!
//! The pass is made by the binary itself (`step run`), so what `cover` reads is
//! what a lap writes, never a record a case forged.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::PathBuf;
use std::process::Output;

/// A step command that passes.
const OK: &str = "#!/bin/sh\nexit 0\n";

/// A tool whose version line keys the row.
const TOOL: &str = "#!/bin/sh\necho tool-1.0\n";

/// Row `a` is a keyed step; nothing in the table names a CI check.
const TABLE: &str = r#"version = 1

[[step]]
id = "a"
inputs = ["input.txt"]
tools = [["toolv"]]
"#;

/// `check-a` stands on step `a`.
const PROOF: &str = "check-a=a";

/// `windows` exactly, and every `dist (…)` by prefix.
const EXEMPT: &str = "windows, dist (*";

struct Repo {
    dir: PathBuf,
}

impl Repo {
    fn new(name: &str) -> Self {
        let dir = common::scratch(&format!("step-cover-{name}"));
        for (file, body) in [("bin/toolv", TOOL), ("bin/ok", OK)] {
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
        common::write(&dir, "batten.toml", TABLE);
        common::init_repo(&dir);
        common::git_in(&dir, &["add", "-A"]);
        common::git_in(&dir, &["commit", "-qm", "init"]);
        Self { dir }
    }

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
            .env_remove("BATTEN_TASK_PID")
            .env_remove("CI_REQUIRED_CHECKS")
            .env_remove("CI_LOCAL_PROOF")
            .env_remove("CI_EXEMPT_CHECKS");
        for (name, value) in env {
            command.env(name, value);
        }
        command.streamed_output().expect("run batten")
    }

    /// Pass step `a` at the current `HEAD`.
    fn pass_a(&self) {
        let out = self.batten(&["step", "run", "a", "--", "ok"], &[]);
        assert_eq!(out.status.code(), Some(0), "{}", common::stderr(&out));
    }

    /// `step cover` over `roster`, with this fixture's mapping and exemptions.
    fn cover(&self, roster: &str) -> Output {
        self.batten(
            &["step", "cover"],
            &[
                ("CI_REQUIRED_CHECKS", roster),
                ("CI_LOCAL_PROOF", PROOF),
                ("CI_EXEMPT_CHECKS", EXEMPT),
            ],
        )
    }
}

/// The plan's proof (CLOUD-2781 decision 7). Fails by: an unmapped check
/// counted covered, or the refusal naming nothing.
#[test]
fn one_unmapped_check_refuses() {
    let repo = Repo::new("unmapped");
    repo.pass_a();
    let out = repo.cover("check-a,check-b");
    assert_eq!(out.status.code(), Some(2), "{}", common::stderr(&out));
    assert_eq!(common::stdout(&out).trim(), "uncovered check-b");
    assert!(
        common::stderr(&out).contains("1 required check(s) without a pass or exemption"),
        "{}",
        common::stderr(&out)
    );
}

/// Fails by: an exemption ignored, or a prefix exemption matched only exactly.
#[test]
fn an_exempted_check_passes() {
    let repo = Repo::new("exempt");
    repo.pass_a();
    let out = repo.cover("check-a, windows, dist (x86_64-unknown-linux-gnu)");
    assert_eq!(out.status.code(), Some(0), "{}", common::stderr(&out));
    assert_eq!(common::stdout(&out), "");
}

/// Fails by: a pass at another tree counted for this one, or a mapping
/// counted without any pass.
#[test]
fn a_mapped_check_without_a_pass_at_head_refuses() {
    let repo = Repo::new("stale-pass");
    let none = repo.cover("check-a");
    assert_eq!(
        none.status.code(),
        Some(2),
        "never passed: {}",
        common::stderr(&none)
    );
    repo.pass_a();
    common::write(&repo.dir, "input.txt", "two\n");
    common::git_in(&repo.dir, &["commit", "-qam", "move"]);
    let moved = repo.cover("check-a");
    assert_eq!(moved.status.code(), Some(2), "{}", common::stderr(&moved));
    assert_eq!(common::stdout(&moved).trim(), "uncovered check-a");
}

/// Fails by: a passed, mapped check refused.
#[test]
fn a_mapped_check_with_a_pass_passes() {
    let repo = Repo::new("passed");
    repo.pass_a();
    let out = repo.cover("check-a");
    assert_eq!(out.status.code(), Some(0), "{}", common::stderr(&out));
}

/// Fails by: a mapping for a check outside the roster read as harmless, which
/// claims coverage for a check nobody requires.
#[test]
fn a_mapped_check_outside_the_roster_refuses() {
    let repo = Repo::new("stale-name");
    repo.pass_a();
    let out = repo.cover("windows");
    assert_eq!(out.status.code(), Some(2), "{}", common::stderr(&out));
    assert_eq!(
        common::stdout(&out).trim(),
        "stale CI_LOCAL_PROOF maps check-a"
    );
}

/// Fails by: an unset roster read as an empty one, which covers trivially.
#[test]
fn an_unset_roster_is_exit_3() {
    let repo = Repo::new("unset");
    let out = repo.batten(&["step", "cover"], &[]);
    assert_eq!(out.status.code(), Some(3), "{}", common::stderr(&out));
}

/// Fails by: a mapping entry with no `=` read as a mapping to nothing.
#[test]
fn a_malformed_mapping_is_a_usage_error() {
    let repo = Repo::new("malformed");
    let out = repo.batten(
        &["step", "cover"],
        &[
            ("CI_REQUIRED_CHECKS", "check-a"),
            ("CI_LOCAL_PROOF", "check-a"),
        ],
    );
    assert_eq!(out.status.code(), Some(1), "{}", common::stderr(&out));
}

/// Fails by: an entry with one side empty (`check=` or `=step`) read as a
/// mapping, where either half alone names nothing to cover.
#[test]
fn a_mapping_with_an_empty_side_is_a_usage_error() {
    let repo = Repo::new("half-empty");
    for proof in ["check-a=", "=a"] {
        let out = repo.batten(
            &["step", "cover"],
            &[("CI_REQUIRED_CHECKS", "check-a"), ("CI_LOCAL_PROOF", proof)],
        );
        assert_eq!(
            out.status.code(),
            Some(1),
            "{proof}: {}",
            common::stderr(&out)
        );
    }
}
