//! Repo-committed rules governing what a container must be, and how it is
//! repaired (CLOUD-1324).
//!
//! # The gap this closes
//!
//! Everything about a session's environment that was checkable lived in one of
//! two places, and neither was a rule. `doctor` carried a hardcoded list of
//! engine-level checks, and one repair — putting the merged hook surfaces back —
//! was a `bool` in the `[hook]` table. So a consumer could not say what ITS
//! container needs, and every new precondition meant an engine change.
//!
//! The container these rules exist for is provisioned by a single **Setup
//! script** field and a single **Environment variables** field on a hosting
//! platform. Nothing in a repository writes those fields and nothing in a
//! repository can read them back. What a repository CAN do is state, in its
//! committed authority, what the RESULT has to look like — and then check it,
//! and repair it. That is what a `[[startup]]` row is.
//!
//! # Sibling to `[[provision]]`, and the split is the subject
//!
//! [`crate::provision`] is CLOUD-90's binary manifest: a pinned version, a URL
//! and a checksum for one fetched tool, with `provision status` deciding and
//! `provision apply` fixing. It answers *is this artifact the one we pinned*.
//! This table answers *is this container the one we declared* — a question whose
//! subject is the machine rather than a file, and whose repairs are commands
//! rather than downloads.
//!
//! **The check/fix duality is `provision`'s, deliberately reused rather than
//! reinvented.** House-style §9 states it, `provision status`/`provision apply`
//! established it here first, and `batten startup` / `batten startup --repair`
//! is the same shape one noun over. What is new is only the subject.
//!
//! # Harness-agnostic by construction, which is the point of the table
//!
//! A row names a command and an exit code. It does not know which agent harness
//! is running, which platform provisioned the box, or what the setup script
//! said. Even the one repair the engine itself owns — putting the merged hook
//! surfaces back — is declared as an ordinary row whose repair is a `batten`
//! invocation, and that verb is ranged over every adapter rather than keyed to
//! one, so a seventh harness is covered the day it lands.
//!
//! That is deliberately the opposite of what this replaced. `[hook]
//! reclaim_at_session_start` was a boolean about one harness-shaped repair,
//! living in a table about hook events; a second repair would have meant a
//! second boolean, and a consumer with a repair of its own had nowhere to put
//! it.
//!
//! # Gates decide, never estimate (non-negotiable rule 3)
//!
//! A row's `check` resolves to a command and an exit code over a real object.
//! There is no model verdict, no heuristic, and no "looks fine". A check that
//! could not be SPAWNED is a could-not-look and is reported as such — never as
//! passing, which would be the false green this whole tool exists to refuse, and
//! never as a reason to repair, which would make an unreadable check into a
//! licence to mutate.
//!
//! # Report by default; repair when asked, or when the rule already said so
//!
//! [`evaluate`] runs the checks and nothing else. [`repair`] additionally runs
//! each failing row's repair and **re-runs its check**. A repair whose own check
//! still fails afterwards is reported as `repair-failed` rather than assumed to
//! have worked: a repair that reports success without re-deciding is a sensor
//! wearing a gate's clothes, and it is the difference between this and a script.
//!
//! At session start the repairs run without anyone passing a flag, and the
//! reason is not convenience: **declaring a repair in the committed authority IS
//! the consumer's authorisation to run it.** The flag exists because a verb that
//! mutates must say so on its own surface, and because a person or a setup
//! script invoking this out of band should have to name what they are asking
//! for.
//!
//! # Output is a pointer (non-negotiable rule 4)
//!
//! A row renders as its own declared `id` and a verdict token. The command it
//! ran, that command's output, and any path it touched are never emitted — the
//! id is a token out of the reader's own committed config, and what it means is
//! written down there, once, in the row's `gloss`.

use std::path::Path;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use anyhow::Result;

use crate::error::UsageError;

/// One declared precondition, and optionally the fix for it.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Startup {
    /// The stable token a report names.
    ///
    /// Separate from the command for [`crate::markers::Marker`]'s reason: the
    /// argv is free to change without the thing it is called in reports changing
    /// with it.
    pub id: String,
    /// What this row is about, in one line, for a reader of the config.
    ///
    /// Required rather than optional: a precondition nobody wrote the meaning of
    /// down is one the next reader cannot decide whether to keep — and since the
    /// report is pointer-only, this is the only place that meaning can live.
    pub gloss: String,
    /// The command deciding whether the environment is right, as argv.
    ///
    /// Exit `0` is provisioned; anything else is not. argv rather than a shell
    /// string for `[[hook.action]]`'s reason — there is then no quoting layer
    /// between what an operator wrote and what runs: no word splitting, no glob
    /// expansion, no `$(…)`.
    pub check: Vec<String>,
    /// How the check's run becomes a verdict.
    ///
    /// Absent is [`Decided::ExitStatus`], which is the ordinary case and the one
    /// every row before CLOUD-1454 assumed.
    #[serde(default, skip_serializing_if = "Decided::is_default")]
    pub decided_by: Decided,
    /// The command that fixes it, as argv. Absent means diagnose-only.
    ///
    /// A row with no repair is not a lesser row: some preconditions genuinely
    /// cannot be fixed from inside the container, and a row saying so is more
    /// use than a repair that silently does nothing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repair: Option<Vec<String>>,
}

/// How a check's run is read as an answer.
///
/// **This exists because a program can be a perfectly good reporter and a
/// useless gate**, and a row declaring one as its check is dead rather than
/// wrong-looking (CLOUD-1454). Measured on the row this was added for:
/// `mise ls --current` prints `(missing)` beside a tool that is not installed
/// and exits `0`, so `toolchain-is-provisioned` reported `ok` over a container
/// with nothing installed — and because a `[[startup]]` row only repairs when
/// its check FAILS, the `mise install --yes` that would have fixed it never ran.
/// A dead gate and a provisioned container were byte-identical on the report.
///
/// The remedy stays inside the argv bound rather than growing a shell: the same
/// program has a spelling that says nothing when there is nothing to say
/// (`mise ls --current --missing`), so what the row needed was a way to declare
/// that SILENCE is the pass — not a pipeline, a `test`, or a wrapper task.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum Decided {
    /// Exit `0` is provisioned. The default, and what every row means unless it
    /// says otherwise.
    #[default]
    ExitStatus,
    /// Exit `0` **and** nothing written to stdout is provisioned.
    ///
    /// Rule 4 holds here in the TYPE rather than by care: what crosses back is a
    /// `bool` over the child's stdout, never a byte of it, so a check whose
    /// output names paths, versions or hosts still cannot put any of that in a
    /// report. That is the same bound [`Outcome`] already carries, one layer
    /// earlier.
    SilentExit,
}

impl Decided {
    /// Whether this is the value an absent key means, so the derived schema and
    /// the round-tripped config both stay quiet about the ordinary case.
    #[must_use]
    #[expect(
        clippy::trivially_copy_pass_by_ref,
        reason = "serde's `skip_serializing_if` calls this with a reference to the field, so the signature is the derive's rather than this author's; taking `self` by value does not compile"
    )]
    const fn is_default(&self) -> bool {
        matches!(self, Self::ExitStatus)
    }
}

/// What one row decided, in the §6 pointer shape.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Outcome {
    /// The row's declared id.
    pub id: String,
    /// Whether the environment is right, after any repair this run performed.
    pub ok: bool,
    /// The verdict token, absent when the row passed on the first look.
    ///
    /// Omitted rather than nulled on a plain pass, matching
    /// [`crate::doctor::Check`]'s rendering: a key whose only value is null is a
    /// field every reader has to learn to ignore.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<&'static str>,
}

/// The check failed on the first look and passed after this run's repair.
pub const REPAIRED: &str = "repaired";
/// The check failed and the row declares no repair.
pub const NOT_PROVISIONED: &str = "not-provisioned";
/// The check failed, the repair ran, and the check still fails.
pub const REPAIR_FAILED: &str = "repair-failed";
/// The repair itself could not be spawned.
pub const REPAIR_UNRUNNABLE: &str = "repair-unrunnable";
/// The check itself could not be spawned — a could-not-look, never a pass.
pub const CHECK_UNRUNNABLE: &str = "check-unrunnable";

impl Outcome {
    /// The pointer line this outcome renders as (§6), without a trailing newline.
    ///
    /// A repaired row renders `ok` **and says so**: a reader who ran `--repair`
    /// should be able to see which rows it actually moved, because a repair that
    /// runs every time is a repair whose check is wrong.
    #[must_use]
    pub fn line(&self) -> String {
        match (self.ok, self.reason) {
            (true, Some(reason)) => format!("{} ok {reason}", self.id),
            (true, None) => format!("{} ok", self.id),
            (false, Some(reason)) => format!("{} failed {reason}", self.id),
            // Unreachable through the constructors below, and rendered rather
            // than panicked on for the reason library code never panics here: a
            // startup report that aborted the session would be a diagnostic
            // taking the run down with it.
            (false, None) => format!("{} failed", self.id),
        }
    }

    fn passed(id: &str) -> Self {
        Self {
            id: id.to_owned(),
            ok: true,
            reason: None,
        }
    }

    fn repaired(id: &str) -> Self {
        Self {
            id: id.to_owned(),
            ok: true,
            reason: Some(REPAIRED),
        }
    }

    fn failed(id: &str, reason: &'static str) -> Self {
        Self {
            id: id.to_owned(),
            ok: false,
            reason: Some(reason),
        }
    }
}

/// `startup`'s human arm, EVERY row rather than only the failing ones: a silent
/// pass over a row whose check never ran is indistinguishable from a row that
/// was never declared.
///
/// Forwards to [`Outcome::line`] rather than restating it: CLOUD-371 unifies
/// which types may reach the data channel, never what any of them renders, so
/// the bytes here are the bytes this type already emitted.
impl crate::output::Line for Outcome {
    fn line(&self) -> String {
        Outcome::line(self).to_string()
    }
}

/// Run one declared argv under `root` and report whether it exited zero.
///
/// `None` is could-not-look: the program could not be spawned at all, which is
/// a different answer from "it ran and said no" and must not be spelled the
/// same way.
///
/// Resolved through [`crate::rules::spawn_resolving`], which is what lets a row
/// name a program the project's pin provides rather than one that happens to be
/// on bare `PATH`. A second spawn path here would be a second authority over
/// that question, and the pinned program would be reached around the pin.
///
/// The child's streams are discarded, which is rule 4 holding at the boundary
/// rather than by convention: there is no path by which a check's output can
/// reach a report. Under [`Decided::SilentExit`] stdout is read rather than
/// discarded, and the bound is unchanged — the only thing that leaves this
/// function is still a `bool`.
fn ran_clean(root: &Path, argv: &[String], decided_by: Decided) -> Option<bool> {
    let (program, operands) = argv.split_first()?;
    let rest: Vec<&str> = operands.iter().map(String::as_str).collect();
    crate::rules::spawn_resolving(Some(root), program, |program, extra| {
        #[expect(
            clippy::disallowed_types,
            reason = "stays: a `[[startup]]` row IS a program the operator declared in the committed authority, so there is no in-process form of it to prefer (CLOUD-320)"
        )]
        let mut command = std::process::Command::new(program);
        command
            .args(extra)
            .args(&rest)
            .current_dir(root)
            .stdin(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        match decided_by {
            Decided::ExitStatus => command
                .stdout(std::process::Stdio::null())
                .status()
                .map(|status| status.success()),
            // `output()` rather than a piped `status()`: a check that writes more
            // than a pipe buffer and is never drained deadlocks, and a gate that
            // hangs is worse than one that answers wrong.
            Decided::SilentExit => command.output().map(|out| {
                out.status.success() && out.stdout.iter().all(u8::is_ascii_whitespace)
            }),
        }
    })
    .ok()
}

/// Decide every row without repairing anything.
///
/// This is what bare `batten startup` does. It SPAWNS — a row's check is a
/// command the operator declared — so the verb is classified the way `enforce`
/// is rather than the way `check` is, and §5's reading of that is unchanged
/// here. What it does not do is mutate, which is the whole of `--repair`.
#[must_use]
pub fn evaluate(root: &Path, rows: &[Startup]) -> Vec<Outcome> {
    rows.iter()
        .map(|row| match ran_clean(root, &row.check, row.decided_by) {
            Some(true) => Outcome::passed(&row.id),
            // `not-provisioned` WHETHER OR NOT A REPAIR IS DECLARED, because
            // that is what is true: this path ran no repair, so it cannot report
            // one as having failed. An earlier draft said `repair-failed` here
            // whenever a repair existed, which reads as "we tried and could not"
            // over a run that never tried — and it made the token useless for
            // the case it is actually for, a repair that runs and does not
            // satisfy its own check.
            Some(false) => Outcome::failed(&row.id, NOT_PROVISIONED),
            None => Outcome::failed(&row.id, CHECK_UNRUNNABLE),
        })
        .collect()
}

/// Decide every row, repairing the ones that fail and declare a repair.
///
/// **The check is re-run after the repair**, and that is the property that makes
/// this a rule rather than a script. A repair reports what it did; a rule
/// reports what is now true. So `repair-failed` is a real outcome rather than an
/// unreachable branch — it is the one that tells a reader the repair does not
/// address its own check.
///
/// A row whose check could not be spawned is NOT repaired: the engine has no
/// evidence anything is wrong, and mutating on a could-not-look is the inverse
/// of the direction every other fact in this tree fails in.
#[must_use]
pub fn repair(root: &Path, rows: &[Startup]) -> Vec<Outcome> {
    rows.iter()
        .map(|row| {
            let first = ran_clean(root, &row.check, row.decided_by);
            if first == Some(true) {
                return Outcome::passed(&row.id);
            }
            let (Some(false), Some(fix)) = (first, row.repair.as_ref()) else {
                return Outcome::failed(
                    &row.id,
                    if first.is_none() {
                        CHECK_UNRUNNABLE
                    } else {
                        NOT_PROVISIONED
                    },
                );
            };
            // A REPAIR IS ALWAYS READ BY ITS EXIT STATUS, whatever the row says
            // about its check. `decided_by` is a statement about a program that
            // reports rather than gates, and only the check has to gate; a repair
            // that legitimately narrates what it installed would otherwise be
            // read as having failed for having spoken.
            if ran_clean(root, fix, Decided::ExitStatus).is_none() {
                return Outcome::failed(&row.id, REPAIR_UNRUNNABLE);
            }
            // THE REPAIR'S OWN EXIT CODE IS DELIBERATELY NOT THE ANSWER. A repair
            // that exits zero having fixed nothing is exactly the false green a
            // rule exists to catch, and one that exits non-zero having fixed the
            // thing anyway is not a failure worth reporting. The check decides,
            // both times.
            if ran_clean(root, &row.check, row.decided_by) == Some(true) {
                Outcome::repaired(&row.id)
            } else {
                Outcome::failed(&row.id, REPAIR_FAILED)
            }
        })
        .collect()
}

/// Refuse a row the engine cannot act on, at LOAD rather than at the first run.
///
/// An empty `check` is the one that matters: [`ran_clean`] would answer
/// could-not-look forever, so the row would report a failure nobody can fix and
/// its repair would never run. Refusing it at load says which row and why, once,
/// instead of once per session — the same direction `[[pattern]]`'s load-time
/// refusal takes one surface over.
///
/// # Errors
///
/// A [`UsageError`] naming the offending row's id.
pub fn validate(rows: &[Startup]) -> Result<()> {
    let mut seen: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();
    for row in rows {
        if row.check.is_empty() {
            return Err(UsageError::raise(format!(
                "[[startup]] {}: `check` is empty, so the row could never decide anything",
                row.id
            )));
        }
        if row.repair.as_ref().is_some_and(Vec::is_empty) {
            return Err(UsageError::raise(format!(
                "[[startup]] {}: `repair` is present and empty — omit the key for a \
                 diagnose-only row rather than declaring a repair that runs nothing",
                row.id
            )));
        }
        if row.gloss.trim().is_empty() {
            return Err(UsageError::raise(format!(
                "[[startup]] {}: `gloss` is empty, and the report is pointer-only — this is \
                 the one place the row's meaning can be written down",
                row.id
            )));
        }
        if !seen.insert(row.id.as_str()) {
            return Err(UsageError::raise(format!(
                "[[startup]] {}: declared twice — one id, one row, or a report names a \
                 verdict a reader cannot trace back",
                row.id
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn row(id: &str, check: &[&str], repair: Option<&[&str]>) -> Startup {
        Startup {
            id: id.to_owned(),
            gloss: "a fixture row".to_owned(),
            check: check.iter().map(|s| (*s).to_owned()).collect(),
            decided_by: Decided::ExitStatus,
            repair: repair.map(|argv| argv.iter().map(|s| (*s).to_owned()).collect()),
        }
    }

    /// A scratch directory this case owns, wiped first.
    fn scratch(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("batten-startup-{name}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn a_passing_check_is_left_alone_and_its_repair_never_runs() {
        let dir = scratch("clean");
        let marker = dir.join("would-have-run");
        let rows = [row(
            "clean",
            &["true"],
            Some(&["touch", marker.to_str().unwrap()]),
        )];
        let out = repair(&dir, &rows);
        assert_eq!(out[0].line(), "clean ok");
        // The load-bearing half: without it this passes over a build that runs
        // every repair unconditionally and reports the check afterwards.
        assert!(!marker.exists(), "a passing row's repair must not run");
    }

    /// A reporter that says something and exits `0` is what
    /// [`Decided::SilentExit`] exists for, and this is the case the shipped
    /// `toolchain-is-provisioned` row was failing in production: `echo` here
    /// stands for `mise ls --current`, which names every missing tool and still
    /// exits zero.
    #[test]
    fn a_check_that_speaks_and_exits_zero_is_a_pass_by_status_and_a_failure_by_silence() {
        let dir = scratch("speaks");
        let mut talkative = row("speaks", &["echo", "aqua:some/tool (missing)"], None);

        assert_eq!(
            evaluate(&dir, std::slice::from_ref(&talkative))[0].line(),
            "speaks ok",
            "read by exit status alone, a reporter is indistinguishable from a gate"
        );

        talkative.decided_by = Decided::SilentExit;
        assert_eq!(
            evaluate(&dir, std::slice::from_ref(&talkative))[0].line(),
            "speaks failed not-provisioned"
        );
    }

    /// The other arm, so the mode is not merely "always fails": a command that
    /// exits `0` and says nothing still passes under it.
    #[test]
    fn silence_and_a_zero_exit_is_still_provisioned() {
        let rows = [Startup {
            decided_by: Decided::SilentExit,
            ..row("quiet", &["true"], None)
        }];
        assert_eq!(evaluate(&scratch("quiet"), &rows)[0].line(), "quiet ok");
    }

    /// Trailing whitespace is not speech. `mise ls --current --missing` writes a
    /// bare newline on some builds, and a row that failed on it would report a
    /// provisioned container as broken and then repair it every session.
    #[test]
    fn a_check_writing_only_whitespace_is_silent() {
        let rows = [Startup {
            decided_by: Decided::SilentExit,
            ..row("blank", &["echo", ""], None)
        }];
        assert_eq!(evaluate(&scratch("blank"), &rows)[0].line(), "blank ok");
    }

    /// A NON-ZERO EXIT IS STILL A FAILURE UNDER `SilentExit`, silence or not.
    /// The mode ADDS a way to fail; reading it as "only stdout decides" would
    /// turn a check that crashed before printing anything into a pass, which is
    /// the could-not-look-as-green direction the whole module refuses.
    #[test]
    fn silence_does_not_rescue_a_non_zero_exit() {
        let rows = [Startup {
            decided_by: Decided::SilentExit,
            ..row("failed-quietly", &["false"], None)
        }];
        assert_eq!(
            evaluate(&scratch("failed-quietly"), &rows)[0].line(),
            "failed-quietly failed not-provisioned"
        );
    }

    /// A REPAIR IS READ BY ITS EXIT STATUS EVEN ON A `SilentExit` ROW. Installers
    /// narrate; `mise install --yes` prints a line per tool. A build that carried
    /// the row's mode into the repair would call every successful install a
    /// failure.
    #[test]
    fn a_talkative_repair_still_satisfies_a_silent_exit_row() {
        let dir = scratch("talkative-repair");
        // `ls` over a directory is the same shape as the row this is for: it
        // names what is outstanding, says nothing once nothing is, and exits `0`
        // either way. `rm -v` is the narrating repair.
        let staging = dir.join("outstanding");
        std::fs::create_dir_all(&staging).unwrap();
        let outstanding = staging.join("absent-tool");
        std::fs::write(&outstanding, b"").unwrap();
        let (staging, outstanding) = (
            staging.to_str().unwrap().to_owned(),
            outstanding.to_str().unwrap().to_owned(),
        );

        let rows = [Startup {
            decided_by: Decided::SilentExit,
            ..row(
                "installs",
                &["ls", staging.as_str()],
                Some(&["rm", "-v", outstanding.as_str()]),
            )
        }];
        assert_eq!(repair(&dir, &rows)[0].line(), "installs ok repaired");
    }

    #[test]
    fn a_failing_check_with_no_repair_says_so_rather_than_pretending() {
        let rows = [row("bare", &["false"], None)];
        let out = evaluate(&scratch("bare"), &rows);
        assert_eq!(out[0].line(), "bare failed not-provisioned");
        assert!(!out[0].ok);
    }

    /// A CHECK THAT COULD NOT BE SPAWNED IS NOT A PASS, and it is not a repair
    /// trigger either.
    ///
    /// Both halves are load-bearing. Reading could-not-look as ok is the false
    /// green the fact model refuses everywhere; reading it as "broken, fix it"
    /// would turn an unreadable check into a licence to mutate, which is the one
    /// direction a repair must never fail in.
    #[test]
    fn an_unspawnable_check_is_could_not_look_and_repairs_nothing() {
        let dir = scratch("unspawnable");
        let marker = dir.join("would-have-run");
        let rows = [row(
            "gone",
            &["batten-no-such-program-exists-here"],
            Some(&["touch", marker.to_str().unwrap()]),
        )];
        let out = repair(&dir, &rows);
        assert_eq!(out[0].line(), "gone failed check-unrunnable");
        assert!(
            !marker.exists(),
            "could-not-look is not a licence to mutate"
        );
    }

    /// THE PROPERTY THAT MAKES THIS A RULE RATHER THAN A SCRIPT: the check is
    /// re-run, so a repair that exits zero having fixed nothing is caught.
    #[test]
    fn a_repair_that_does_not_satisfy_its_own_check_is_reported() {
        let rows = [row("stuck", &["false"], Some(&["true"]))];
        let out = repair(&scratch("stuck"), &rows);
        assert_eq!(out[0].line(), "stuck failed repair-failed");
    }

    /// THE MIRROR, and without it the case above is satisfied by a build that
    /// never reports a repair as working.
    ///
    /// The check is a file test and the repair creates the file, so the second
    /// reading genuinely differs from the first — which a pair of constant
    /// commands could not demonstrate.
    #[test]
    fn a_repair_that_satisfies_its_check_is_reported_as_repaired() {
        let dir = scratch("repaired");
        let target = dir.join("marker");
        let path = target.to_str().unwrap().to_owned();
        let rows = [row(
            "makes-it",
            &["test", "-f", &path],
            Some(&["touch", &path]),
        )];
        let out = repair(&dir, &rows);
        assert_eq!(
            out[0].line(),
            "makes-it ok repaired",
            "a reader running --repair should see which rows it moved"
        );
        assert!(target.exists(), "the repair actually ran");
    }

    #[test]
    fn evaluate_never_repairs_even_when_a_repair_is_declared() {
        let dir = scratch("readonly");
        let target = dir.join("marker");
        let path = target.to_str().unwrap().to_owned();
        let rows = [row(
            "untouched",
            &["test", "-f", &path],
            Some(&["touch", &path]),
        )];
        let out = evaluate(&dir, &rows);
        assert_eq!(
            out[0].line(),
            "untouched failed not-provisioned",
            "the read path ran no repair, so it may not report one as failed"
        );
        assert!(
            !target.exists(),
            "the read path must not mutate — that is the whole of `--repair`"
        );
    }

    #[test]
    fn an_unspawnable_repair_is_named_apart_from_one_that_ran_and_failed() {
        let rows = [row(
            "no-fixer",
            &["false"],
            Some(&["batten-no-such-program-exists-here"]),
        )];
        let out = repair(&scratch("no-fixer"), &rows);
        assert_eq!(out[0].line(), "no-fixer failed repair-unrunnable");
    }

    #[test]
    fn a_row_that_could_never_decide_is_refused_at_load() {
        let rows = [row("empty", &[], None)];
        let err = validate(&rows).expect_err("an empty check is unusable");
        assert!(format!("{err}").contains("empty"), "{err}");
    }

    #[test]
    fn one_id_means_one_row() {
        let rows = [row("same", &["true"], None), row("same", &["false"], None)];
        assert!(validate(&rows).is_err());
    }

    #[test]
    fn a_row_with_no_gloss_is_refused_because_the_report_cannot_carry_one() {
        let mut rows = [row("mute", &["true"], None)];
        rows[0].gloss = "   ".to_owned();
        assert!(validate(&rows).is_err());
    }
}
