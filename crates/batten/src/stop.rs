//! The end-of-turn gate (CLOUD-85) — house-style §10's "the stop hook is the
//! reconciliation point".
//!
//! Every other mediated event asks about a call that is *about* to happen. This
//! one asks about a turn that is about to end, which is the moment Batten's
//! whole thesis is aimed at: "done" drifting away from landed-and-verified. The
//! predicate is a disjunction of two facts that already exist —
//!
//! ```text
//! deny-stop  ⇔  at-risk work  ∨  an undischarged denial
//! ```
//!
//! — and **both inputs are consumed, never re-derived**. At-risk work is
//! [`crate::worktree::status`], the same answer `worktree status` prints; a
//! pending denial is a record in the findings store with no disposition. A
//! second implementation of either would be a second answer to a question that
//! already has one, which is the drift this engine exists to refuse.
//!
//! ## It forces continuation; it does not veto completion
//!
//! [`crate::hook::Capabilities::stop_vetoes_completion`] is `false` on **every**
//! surveyed host, Claude included. A deny here cannot prevent a turn ending — it
//! makes the host continue the turn instead, with the reason handed back. That is
//! the honest ceiling, and it is why the refusal names what to run rather than
//! merely reporting a state: the agent is being asked to do one more thing, so
//! the refusal has to say what.
//!
//! ## Distinct from a pre-tool deny by EVENT, never by code
//!
//! §7's table is total and has no per-verb exception, so a stop deny is exit `2`
//! exactly as a pre-tool deny is. What distinguishes them is the event they
//! answer on, and that is the whole point: two decisions of the same *kind*
//! (policy said no) at two different moments. A separate code would have made a
//! host translate, which is the coupling CLOUD-40 removed.
//!
//! ## Cannot-look is never a deny
//!
//! A repository with no bound findings store has no pending denials — that is an
//! answer, not an absence, and it is the ordinary state for most checkouts. A
//! store that exists and cannot be read propagates as an error (exit `3`, fail
//! loud) rather than becoming either verdict: guessing *allow* would be the false
//! green, and guessing *deny* would wedge every turn on a broken store.

use std::path::Path;

use anyhow::Result;
use serde::Serialize;

use crate::findings::{self, Check};
use crate::refusal::{Fix, Refusal};
use crate::severity::RuleSeverity;
use crate::worktree::AtRisk;

/// The gate's declared id, as it appears in a refusal a reader greps for.
pub const RULE: &str = "stop.unfinished";

/// One undischarged denial, as a pointer.
///
/// Carries the rule that produced it and the command that settles it — never the
/// finding's own evidence, which is content (rule 4). A denial the agent cannot
/// discharge is a turn it cannot end, so naming the discharging command is not a
/// courtesy but the thing that makes the block escapable in one hop.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct Pending {
    /// The rule whose finding is undischarged.
    pub rule: String,
    /// What settles it, rendered as a command where the record names an argv.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub discharge: Option<String>,
}

/// The facts the end-of-turn decision is a function of.
///
/// Assembled by [`facts`] at the boundary, so the verdict below stays a pure
/// function of values — the same split [`crate::hook::adjudicate`] uses for
/// receipts, and for the same reason: a decision that reads the world is a
/// decision nobody can test without one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Default)]
#[non_exhaustive]
pub struct StopFacts {
    /// The at-risk report, or `None` where this is not a repository Batten
    /// governs. `None` is not "clean": it is "not asked", and it contributes
    /// nothing to the disjunction because there is nothing here to be at risk.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub at_risk: Option<AtRisk>,
    /// Undischarged denials, sorted by rule so the report is byte-stable.
    pub pending: Vec<Pending>,
}

impl StopFacts {
    /// Whether the turn must not end yet.
    ///
    /// The disjunction, and nothing else. Note what is absent: no count, no
    /// threshold, no severity ladder of its own. Either input firing is enough,
    /// because both already encode their own bar — [`AtRisk::any`] is the
    /// worktree gate's verdict and a pending denial is one the *rule's* severity
    /// already rated as blocking.
    #[must_use]
    pub fn blocks(&self) -> bool {
        self.at_risk.as_ref().is_some_and(AtRisk::any) || !self.pending.is_empty()
    }

    /// The blocking facts, as pointer lines, in a fixed order.
    ///
    /// At-risk lines first and unchanged — they are
    /// [`crate::worktree::AtRisk::lines`]'s, not a second rendering — then one
    /// `denial: <rule>` per undischarged finding. Empty exactly when
    /// [`StopFacts::blocks`] is false, so silence is structural rather than a
    /// branch that could disagree with the verdict.
    #[must_use]
    pub fn lines(&self) -> Vec<String> {
        if !self.blocks() {
            return Vec::new();
        }
        let mut lines = self.at_risk.as_ref().map(AtRisk::lines).unwrap_or_default();
        lines.extend(
            self.pending
                .iter()
                .map(|pending| format!("denial: {}", pending.rule)),
        );
        lines
    }

    /// The refusal a deny-stop travels as, or `None` when the turn may end.
    ///
    /// The `Fix` is the **first** discharging command any pending denial names,
    /// falling back to the at-risk half's own remedy. One command rather than a
    /// list: a refusal's contract is to get an agent to right in one hop, and a
    /// menu is what makes a caller pick.
    #[must_use]
    pub fn refusal(&self) -> Option<Refusal> {
        if !self.blocks() {
            return None;
        }
        // The blocking lines become tagged pointers rather than a joined
        // sentence (CLOUD-1050). They were already pointer-only — `AtRisk::lines`
        // and `denial: <rule>` — so this is a change of shape, not of content,
        // and the class's own gloss now carries the "the turn is not finished"
        // half that used to be prose at this call site.
        let subjects: Vec<crate::verdict::Subject> = self
            .lines()
            .into_iter()
            .map(|line| crate::verdict::Subject::Artifact { artifact: line })
            .collect();
        let fix = self
            .pending
            .iter()
            .find_map(|pending| pending.discharge.clone())
            .map_or_else(
                || {
                    // No denial named a command, so what is left is the at-risk
                    // half. `worktree status` is the verb that prints exactly
                    // these lines, so it is both the diagnosis and the re-check.
                    Fix::Run(
                        "commit and push the outstanding work, then `batten worktree status`"
                            .to_owned(),
                    )
                },
                Fix::Run,
            );
        Some(Refusal::declared(
            RULE,
            crate::verdict::Native::StopConditionUnmet,
            &subjects,
            fix,
        ))
    }
}

/// Assemble the end-of-turn facts: the I/O half.
///
/// `store_dir` is the bound findings store, or `None` where this checkout has
/// none — which is an answer (no denials can be pending) rather than a gap.
///
/// # Errors
///
/// Propagates a `git` or store failure. Deliberately: a stop gate that could not
/// look must fail loud (exit `3`, non-blocking per §7) rather than guess either
/// verdict. Raises a [`crate::UsageError`] (→ exit `1`) when a configured
/// `must_land_on` resolves to no commit, the same reading `worktree status`
/// gives a target its author named and got wrong.
pub fn facts(
    repo: Option<&Path>,
    must_land_on: Option<&str>,
    store_dir: Option<&Path>,
) -> Result<StopFacts> {
    let at_risk = match repo {
        Some(repo) => Some(crate::worktree::status(repo, must_land_on)?),
        None => None,
    };
    let pending = match store_dir {
        Some(dir) => pending_denials(dir)?,
        None => Vec::new(),
    };
    Ok(StopFacts { at_risk, pending })
}

/// What the Stop watchdog decided about one crashed task (CLOUD-2370).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Watch {
    /// It lived long enough, or died with the container: relaunch it.
    Relaunch(crate::task::Entry),
    /// It died under the floor in this boot: a relaunch would die the same way.
    Advise {
        /// The crashed record.
        entry: crate::task::Entry,
        /// Its proven lifetime in seconds, zero where a stamp does not parse.
        lived: u64,
    },
}

/// The watchdog sentinel: a native refusal at `Stop`, beside CLOUD-2441's
/// unlanded one (CLOUD-2370).
///
/// A function of values, as this module's header requires. `abandoned` is the
/// crashed records the caller has not yet spoken about, newest first; `live`
/// the tasks a relaunch of which is already under way; `boot` this
/// container's boot second.
///
/// # Rate, never a count
///
/// The operator's ruling: "too fast" is the criterion. A record registered
/// before this boot died with the container, which does not repeat, so it
/// relaunches whatever its age. In this boot, the proven lifetime —
/// [`crate::task::Entry::last_alive`] less its registration, which can only
/// underestimate — must reach `min_lifetime_secs`; under it, the crash is
/// advice, because a relaunch would crash the same way and the turn would loop.
/// A stamp that does not parse proves nothing, so it is advice too.
///
/// The bound across Stops is the caller's receipt, not this: one refusal per
/// crashed record, which `stop_hook_active` cannot provide (it resets whenever
/// a reminder lands between Stops). The caller drops the records already
/// spoken about before asking, so one old corpse cannot hide a newer crash.
//MUTANT watchdog-undeclared|s@^        .find(\x7centry\x7c table.relaunch.contains(\&entry.task) \&\& !live.contains(\&entry.task))?;$@        .find(\x7centry\x7c !live.contains(\&entry.task))?;@|an_undeclared_crash_is_quiet
//MUTANT watchdog-relaunch-ignored|s@ \&\& !live.contains(\&entry.task))?;$@)?;@|a_relaunch_under_way_is_quiet
//MUTANT watchdog-reboot-ignored|s@^    if started.is_some_and(\x7cstarted\x7c started < boot) {$@    if false {@|a_crash_before_this_boot_relaunches
//MUTANT watchdog-too-fast|s@^    if lived.is_some_and(\x7clived\x7c lived >= table.min_lifetime_secs) {$@    if lived.is_some() {@|a_crash_under_the_floor_is_advice
#[must_use]
pub fn watchdog(
    abandoned: &[crate::task::Entry],
    live: &[String],
    table: &crate::task::TaskTable,
    boot: u64,
) -> Option<Watch> {
    let entry = abandoned
        .iter()
        .find(|entry| table.relaunch.contains(&entry.task) && !live.contains(&entry.task))?;
    let started = entry.started();
    let lived = started
        .zip(entry.last_alive())
        .map(|(started, last)| last.saturating_sub(started));
    if started.is_some_and(|started| started < boot) {
        return Some(Watch::Relaunch(entry.clone()));
    }
    if lived.is_some_and(|lived| lived >= table.min_lifetime_secs) {
        return Some(Watch::Relaunch(entry.clone()));
    }
    Some(Watch::Advise {
        entry: entry.clone(),
        lived: lived.unwrap_or_default(),
    })
}

/// The undischarged denials in a bound store.
///
/// **Undischarged means no disposition**, which is the store's own three-valued
/// reading (`None` is "not yet settled", distinct from all three settled
/// answers). A finding the engine withheld still counts: it is undischarged, and
/// the stop event is the reconciliation point where a withheld finding is
/// finally due — surfacing it here is the opposite of the drain suppressing it
/// forever.
///
/// Only `deny`-severity findings block. A `warn` that has not been settled is
/// exactly what an advisory is for, and blocking a turn on one would make the
/// severity axis meaningless.
fn pending_denials(store_dir: &Path) -> Result<Vec<Pending>> {
    let mut pending: Vec<Pending> = findings::load_all(store_dir)?
        .into_iter()
        .filter(|record| record.severity == RuleSeverity::Deny)
        .filter(|record| record.disposition.is_none())
        .map(|record| Pending {
            discharge: record.check.as_ref().and_then(discharge_of),
            rule: record.rule,
        })
        .collect();
    // Byte-stable: the store's file order is the filesystem's.
    pending.sort_by(|a, b| a.rule.cmp(&b.rule));
    Ok(pending)
}

/// The command that settles a finding, where its check names one.
///
/// [`Check::Reevaluate`] names none — the discharging action is "run the engine
/// again", which the refusal's fallback already says — so it yields `None`
/// rather than a synthesised command a caller could copy and have fail.
fn discharge_of(check: &Check) -> Option<String> {
    match check {
        Check::Reevaluate => None,
        Check::Argv(argv) if argv.is_empty() => None,
        Check::Argv(argv) => Some(argv.join(" ")),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::worktree::Unlanded;

    fn clean() -> AtRisk {
        AtRisk {
            uncommitted: 0,
            unpushed: None,
            no_upstream: None,
            unlanded: Unlanded::Landed,
        }
    }

    fn dirty() -> AtRisk {
        AtRisk {
            uncommitted: 2,
            ..clean()
        }
    }

    fn pending(rule: &str, discharge: Option<&str>) -> Pending {
        Pending {
            rule: rule.to_owned(),
            discharge: discharge.map(ToOwned::to_owned),
        }
    }

    #[test]
    fn a_clean_tree_and_an_empty_store_let_the_turn_end() {
        let facts = StopFacts {
            at_risk: Some(clean()),
            pending: Vec::new(),
        };
        assert!(!facts.blocks());
        assert!(facts.lines().is_empty(), "an allow says nothing");
        assert!(facts.refusal().is_none());
    }

    #[test]
    fn either_input_alone_blocks_the_turn() {
        // A disjunction, asserted from both sides: the two inputs are
        // independent, and a gate that needed both would let a dirty tree with
        // no findings end a turn.
        let at_risk_only = StopFacts {
            at_risk: Some(dirty()),
            pending: Vec::new(),
        };
        let denial_only = StopFacts {
            at_risk: Some(clean()),
            pending: vec![pending("no-conflict-markers", None)],
        };
        assert!(at_risk_only.blocks());
        assert!(denial_only.blocks());
    }

    #[test]
    fn a_deny_stop_names_every_blocking_fact_as_a_pointer() {
        let facts = StopFacts {
            at_risk: Some(dirty()),
            pending: vec![
                pending("zeta-rule", None),
                pending("alpha-rule", Some("mise run check")),
            ],
        };
        assert_eq!(
            facts.lines(),
            vec![
                "uncommitted: 2 paths".to_owned(),
                "denial: zeta-rule".to_owned(),
                "denial: alpha-rule".to_owned(),
            ],
            "the at-risk lines are the worktree gate's own, then one per denial"
        );
    }

    #[test]
    fn the_refusal_names_a_discharging_command_when_a_denial_has_one() {
        let facts = StopFacts {
            at_risk: Some(clean()),
            pending: vec![
                pending("first", Some("mise run check")),
                pending("second", Some("cargo test")),
            ],
        };
        let refusal = facts.refusal().expect("a pending denial blocks");
        assert_eq!(refusal.rule(), RULE);
        // One command, not a menu: the contract is one hop to right.
        assert_eq!(refusal.fix(), &Fix::Run("mise run check".to_owned()));
        assert!(
            refusal
                .render_finding(crate::refusal::Arm::Full)
                .contains("denial: first")
        );
    }

    #[test]
    fn a_refusal_with_no_named_command_still_owes_a_remedy() {
        // `Fix` is mandatory by construction, so the at-risk-only case cannot
        // silently degrade to a bare "no".
        let facts = StopFacts {
            at_risk: Some(dirty()),
            pending: Vec::new(),
        };
        let refusal = facts.refusal().expect("at-risk work blocks");
        let Fix::Run(fix) = refusal.fix() else {
            panic!("at-risk work names a fix");
        };
        assert!(
            refusal
                .render_finding(crate::refusal::Arm::Full)
                .contains(fix.as_str())
        );
    }

    #[test]
    fn an_unasked_repository_contributes_nothing_rather_than_clean() {
        // `None` is "not asked". It must not block, and it must not be readable
        // as a positive statement that the tree is clean.
        let facts = StopFacts {
            at_risk: None,
            pending: Vec::new(),
        };
        assert!(!facts.blocks());
        assert!(facts.lines().is_empty());
    }

    #[test]
    fn only_a_check_that_names_an_argv_yields_a_command() {
        assert_eq!(discharge_of(&Check::Reevaluate), None);
        assert_eq!(discharge_of(&Check::Argv(Vec::new())), None);
        assert_eq!(
            discharge_of(&Check::Argv(vec!["mise".to_owned(), "run".to_owned()])),
            Some("mise run".to_owned())
        );
    }

    /// Fails by: the store not read, a settled or a warn-severity finding read
    /// as pending, or a pending denial's discharge dropped.
    #[test]
    fn only_an_unsettled_denial_in_the_store_is_pending() {
        let dir = crate::scratch::scratch("stop-pending");
        let stored = |rule: &str,
                      severity: RuleSeverity,
                      disposition: Option<crate::findings::Disposition>| {
            crate::findings::FindingRecord {
                schema: crate::findings::FINDINGS_SCHEMA,
                identity: crate::identity::StoredIdentity::new(
                    crate::identity::FindingKind::Code,
                    crate::identity::code_fingerprint(
                        rule,
                        "src/a.rs",
                        "span",
                        crate::identity::SpanNormalization::Collapsed,
                    )
                    .unwrap(),
                ),
                rule: rule.to_owned(),
                severity,
                tier: crate::severity::row_for_rule(severity).tier,
                disposition,
                presentation: crate::findings::Presentation::Shown,
                check: Some(Check::Argv(vec!["mise".to_owned(), "run".to_owned()])),
                remediation: Some(crate::findings::Remediation::NoFix("fixture".to_owned())),
                instances: Vec::new(),
            }
        };
        for record in [
            stored("open-denial", RuleSeverity::Deny, None),
            stored(
                "settled-denial",
                RuleSeverity::Deny,
                Some(crate::findings::Disposition::Acted),
            ),
            stored("open-warning", RuleSeverity::Warn, None),
        ] {
            findings::save_one(&dir, &record).unwrap();
        }
        let facts = facts(None, None, Some(&dir)).unwrap();
        assert_eq!(
            facts.pending,
            vec![pending("open-denial", Some("mise run"))]
        );
    }

    /// A crashed record registered at `started` and last stamped at `last`.
    fn crashed(task: &str, started: u64, last: u64) -> crate::task::Entry {
        crate::task::Entry {
            task: task.to_owned(),
            pid: "4242".to_owned(),
            pgid: "4242".to_owned(),
            phase: "verify".to_owned(),
            started_at: started.to_string(),
            phase_since: last.to_string(),
            ..crate::task::Entry::default()
        }
    }

    fn table() -> crate::task::TaskTable {
        crate::task::TaskTable {
            program_root: "programs".to_owned(),
            relaunch: vec!["land".to_owned()],
            min_lifetime_secs: 3600,
        }
    }

    const BOOT: u64 = 1_000_000;

    #[test]
    fn a_crash_after_real_work_relaunches() {
        let entry = crashed("land", BOOT + 10, BOOT + 7010);
        assert_eq!(
            watchdog(std::slice::from_ref(&entry), &[], &table(), BOOT),
            Some(Watch::Relaunch(entry))
        );
    }

    #[test]
    fn a_crash_under_the_floor_is_advice() {
        let entry = crashed("land", BOOT + 10, BOOT + 130);
        assert_eq!(
            watchdog(std::slice::from_ref(&entry), &[], &table(), BOOT),
            Some(Watch::Advise { entry, lived: 120 }),
            "a lap that died in two minutes would die again"
        );
    }

    #[test]
    fn a_crash_before_this_boot_relaunches() {
        // Under the floor, but the container went with it: that does not repeat.
        let entry = crashed("land", BOOT - 100, BOOT - 40);
        assert_eq!(
            watchdog(std::slice::from_ref(&entry), &[], &table(), BOOT),
            Some(Watch::Relaunch(entry))
        );
    }

    #[test]
    fn an_undeclared_crash_is_quiet() {
        let entry = crashed("snapshots", BOOT + 10, BOOT + 7010);
        assert_eq!(watchdog(&[entry], &[], &table(), BOOT), None);
    }

    #[test]
    fn a_relaunch_under_way_is_quiet() {
        let entry = crashed("land", BOOT + 10, BOOT + 7010);
        assert_eq!(
            watchdog(&[entry], &["land".to_owned()], &table(), BOOT),
            None,
            "a land already relaunched is the remedy running"
        );
    }

    #[test]
    fn an_unparseable_stamp_proves_nothing() {
        let mut entry = crashed("land", BOOT + 10, BOOT + 7010);
        entry.started_at = "soon".to_owned();
        assert_eq!(
            watchdog(std::slice::from_ref(&entry), &[], &table(), BOOT),
            Some(Watch::Advise { entry, lived: 0 })
        );
    }

    #[test]
    fn a_settled_disposition_is_not_pending() {
        // The store's three-valued reading is the whole predicate: `None` is
        // undischarged, and every settled answer — including a rejection — is
        // discharged. A gate that blocked on `rejected-by-design` would refuse
        // to accept an answer the agent already gave.
        for settled in crate::findings::Disposition::ALL {
            assert!(!settled.as_str().is_empty(), "{settled:?} has a token");
        }
        assert_eq!(
            crate::findings::Disposition::RejectedByDesign.as_str(),
            "rejected-by-design"
        );
    }
}
