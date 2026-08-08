//! `batten doctor` — the designated post-install self-check (house-style §12).
//!
//! It answers one question: **can Batten do its job in this repository?** Not
//! "is the policy any good" — that is `config lint`'s question and it renders a
//! verdict. Keeping the two apart is what lets `doctor` promise something
//! stronger than a convention.
//!
//! # `doctor` never returns a policy verdict
//!
//! Every failure it can report — no config, an unparseable one, a working
//! directory that is not a repository — is the *config or usage* class, so
//! `doctor` returns [`ExitCode::Success`] or [`ExitCode::Usage`] and never
//! [`ExitCode::Violation`]. That is deliberate rather than incidental: a
//! diagnostic that could emit `2` would be read by a mediating harness as a
//! deny, and "your checkout is misconfigured" is not "policy says no" (§7).
//! [`crate::doctor::tests`] and the end-to-end suite both pin it.
//!
//! This is also why `config lint` is *not* one of the diagnostics, tempting as
//! it is: a smell is exit `2` when `config lint` reports it, and folding it in
//! here would force either a code collision or two different answers to the same
//! question.
//!
//! # Output is byte-stable and carries no paths
//!
//! A check reports a name, a boolean, and — when it fails — a **stable reason
//! id**, never the underlying message. Messages carry absolute paths, which
//! differ per machine and would defeat byte-stability (§6) while leaking the
//! layout of someone's disk into a log (rule 4).
//!
//! Not to be confused with `mise-tasks/doctor`, which gates *this repository's*
//! own provisioning (the bats submodule, rustup cross targets). That one is
//! repo tooling; this is the product verb.

use std::path::Path;

use crate::exit::ExitCode;
use crate::rules::Rule;
use crate::{config, git, resolve};

/// One diagnostic's outcome.
///
/// The reason is a stable id rather than the error text, so the report is
/// byte-stable across machines and never carries a path.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Check {
    /// The diagnostic's stable name.
    pub name: &'static str,
    /// Whether it passed.
    pub ok: bool,
    /// A stable reason id when it failed; absent when it passed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<&'static str>,
}

impl Check {
    const fn passed(name: &'static str) -> Self {
        Check {
            name,
            ok: true,
            reason: None,
        }
    }

    const fn failed(name: &'static str, reason: &'static str) -> Self {
        Check {
            name,
            ok: false,
            reason: Some(reason),
        }
    }

    /// The pointer line this check renders as (§6), without a trailing newline.
    #[must_use]
    pub fn line(&self) -> String {
        match self.reason {
            Some(reason) => format!("{} failed {reason}", self.name),
            None => format!("{} ok", self.name),
        }
    }
}

/// The whole diagnosis, as the `-J` data channel renders it.
///
/// Deliberately carries no timestamp, no duration and no path: identical input
/// must yield identical bytes (§6).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Report {
    /// The running binary's version.
    pub version: &'static str,
    /// The content hash of the governing config surface (CLOUD-32), when it
    /// could be computed.
    ///
    /// Absent rather than empty when the config did not load or a tracked path
    /// is unreadable: a placeholder would be a *stable* value over an unknown
    /// surface, which is exactly what the epoch exists to prevent. `doctor` does
    /// not fail on that — the `config` check above already names the cause, and
    /// a diagnostic that could exit 3 for a missing file would stop being the
    /// config-or-usage-only verb §7 needs it to be.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config_epoch: Option<String>,
    /// Whether every diagnostic passed.
    pub ok: bool,
    /// Each diagnostic, in a fixed order.
    pub checks: Vec<Check>,
}

impl Report {
    /// The exit code this report maps to.
    ///
    /// [`ExitCode::Violation`] is unreachable by construction — see the module
    /// docs. The range is the guarantee, not the branch.
    #[must_use]
    pub fn code(&self) -> ExitCode {
        if self.ok {
            ExitCode::Success
        } else {
            ExitCode::Usage
        }
    }
}

/// The committed authority is present, parses, and resolves through the §8
/// chain — including the `min_batten_version` gate (CLOUD-33).
const CONFIG: &str = "config";
/// The working directory is inside a git repository with a derivable root.
///
/// Not cosmetic: `--config-from` (CLOUD-31) and the receipt verbs both resolve
/// against it, so a checkout where this fails is one where those silently have
/// nothing to stand on.
const GIT_REPO: &str = "git-repo";
/// Every `command`-kind rule names a program that resolves on `PATH`.
///
/// A missing binary is otherwise discovered at `enforce` time, mid-run, as a
/// failure of the gate rather than of the setup. §9 is explicit that a rule
/// "names a command already on the operator's PATH" — this is the probe that
/// says whether that premise holds, before anything depends on it.
const COMMAND_PROGRAMS: &str = "command-programs";

/// Whether `program` resolves to an existing file on `PATH`.
///
/// **Stats, never executes.** Running the program to see whether it exists is
/// precisely what a `read` verb may not do (§5, CLOUD-170): it would reach
/// user-supplied code from the read-only surface. A path-bearing token
/// (`./bin/tool`) is checked where it points; a bare name is looked up across
/// `PATH` entries.
fn on_path(program: &str) -> bool {
    if program.contains(std::path::MAIN_SEPARATOR) || program.contains('/') {
        return Path::new(program).is_file();
    }
    std::env::var_os("PATH")
        .is_some_and(|paths| std::env::split_paths(&paths).any(|dir| dir.join(program).is_file()))
}

/// Diagnose the repository rooted at `dir`.
///
/// Infallible by construction: every failure becomes a [`Check`] rather than an
/// error, because a diagnostic that aborts on the first problem reports one
/// symptom when the operator wants the list.
#[must_use]
pub fn diagnose(dir: &Path) -> Report {
    let mut checks = Vec::new();

    checks.push(match config::load(&dir.join(config::CONFIG_FILE)) {
        // Loading proves the file parses and the version gates pass; resolving
        // proves the §8 chain (including a `batten.local.toml`) is coherent too.
        // Both are wanted — a config that parses but whose local override is
        // refused is not a working setup.
        Ok(_) => match resolve::resolve(dir, &crate::Overrides::default()) {
            Ok(_) => Check::passed(CONFIG),
            Err(_) => Check::failed(CONFIG, "config-unresolvable"),
        },
        Err(_) if !dir.join(config::CONFIG_FILE).exists() => {
            Check::failed(CONFIG, "config-missing")
        }
        Err(_) => Check::failed(CONFIG, "config-invalid"),
    });

    checks.push(match git::repo_root(dir) {
        Ok(_) => Check::passed(GIT_REPO),
        Err(_) => Check::failed(GIT_REPO, "not-a-repository"),
    });

    // Probed off the *resolved* rule set, so a rule a local override added is
    // covered too — those are gates a run actually applies. A config that did
    // not load reports no rules rather than a second failure: `config` above
    // already named that, and repeating it would double-count one problem.
    let rules = resolve::resolve(dir, &crate::Overrides::default())
        .map(|resolved| resolved.rules)
        .unwrap_or_default();
    let missing = rules
        .iter()
        .filter_map(Rule::program)
        .any(|program| !on_path(program));
    checks.push(if missing {
        Check::failed(COMMAND_PROGRAMS, "program-not-on-path")
    } else {
        Check::passed(COMMAND_PROGRAMS)
    });

    // The working-tree authority: `doctor` diagnoses the checkout in front of
    // it, so it does not take a base ref.
    let config_epoch = crate::epoch::compute(dir, None).ok();

    Report {
        version: config::VERSION,
        config_epoch,
        ok: checks.iter().all(|check| check.ok),
        checks,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::fs;

    use super::*;

    fn scratch(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join("batten-doctor-tests").join(name);
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn a_missing_config_is_named_rather_than_lumped_in() {
        let dir = scratch("missing-config");
        let report = diagnose(&dir);
        let config = report.checks.iter().find(|c| c.name == CONFIG).unwrap();
        assert!(!config.ok);
        assert_eq!(config.reason, Some("config-missing"));
    }

    #[test]
    fn an_invalid_config_is_named_distinctly_from_a_missing_one() {
        // Two different remedies — write one, or fix one — so one reason id for
        // both would send the reader to the wrong place.
        let dir = scratch("invalid-config");
        fs::write(dir.join("batten.toml"), "this is not toml\n").unwrap();
        let report = diagnose(&dir);
        let config = report.checks.iter().find(|c| c.name == CONFIG).unwrap();
        assert_eq!(config.reason, Some("config-invalid"));
    }

    #[test]
    fn a_failing_diagnosis_is_never_a_policy_verdict() {
        // The load-bearing guarantee: a harness reads `2` as deny, and "your
        // checkout is misconfigured" must never say that.
        let dir = scratch("never-a-verdict");
        let report = diagnose(&dir);
        assert!(!report.ok);
        assert_ne!(report.code(), ExitCode::Violation);
        assert_eq!(report.code(), ExitCode::Usage);
    }

    #[test]
    fn every_check_is_reported_not_just_the_first_failure() {
        // A diagnostic that stops at the first problem reports one symptom when
        // the operator wants the list.
        let dir = scratch("all-checks");
        let report = diagnose(&dir);
        // Asserted on the named checks rather than a count, so adding a
        // diagnostic does not turn this into a bookkeeping edit — what matters
        // is that a later check still runs after an earlier one failed.
        let failed: Vec<&str> = report
            .checks
            .iter()
            .filter(|check| !check.ok)
            .map(|check| check.name)
            .collect();
        assert_eq!(failed, vec![CONFIG, GIT_REPO]);
    }

    #[test]
    fn a_reason_id_never_carries_a_path() {
        // Rule 4 and §6 together: a message would embed an absolute path, which
        // differs per machine and leaks disk layout into a log.
        let dir = scratch("no-paths");
        for check in diagnose(&dir).checks {
            let Some(reason) = check.reason else { continue };
            assert!(!reason.contains('/'), "{reason} looks like a path");
        }
    }

    #[test]
    fn a_check_line_is_pointer_shaped() {
        assert_eq!(Check::passed("config").line(), "config ok");
        assert_eq!(
            Check::failed("config", "config-missing").line(),
            "config failed config-missing"
        );
    }
}
