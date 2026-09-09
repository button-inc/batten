//! The exit-code contract (§7) — one table, total, with no per-verb exception.
//!
//! Batten's exit codes are part of its public interface: local shells, CI, and
//! agent hook adapters all branch on them, so they are defined once here and
//! documented in `doctor`'s exit-code table rather than scattered as literals.
//!
//! The numbering is chosen so the mediation channel needs no translation. Every
//! host with a pre-tool hook reads `0` as allow, `2` as deny (with stderr as the
//! reason), and anything else as "the hook itself failed, let the call through".
//! Aligning the general table with that makes a deny and a violation the same
//! code because they are the same kind of answer — a policy verdict — and it
//! makes fail-open **structural**: [`ExitCode::Usage`] and [`ExitCode::Internal`]
//! are the only codes a failure of Batten's own can produce, and neither blocks.
//!
//! ## The one verb whose code is not in this table
//!
//! `batten exec` is a transparent passthrough (CLOUD-285): it returns the wrapped
//! command's exit code unchanged, so `batten exec -- sh -c 'exit 7'` exits `7`.
//! That code is **the child's answer, not Batten's**, and it is deliberately not a
//! variant here — the table stays total over the four codes Batten *chooses*, and
//! a code it did not choose travels as [`crate::Passthrough`] instead of being
//! smuggled in as a fifth row.
//!
//! The property fail-open rests on is untouched: **Batten never mints a `2` on
//! that path.** A `2` from `exec` came from the child, and a mediated call is
//! adjudicated by [`crate::hook`], which is not reachable from `exec`. So no host
//! can read a wrapped command's status as a policy verdict of Batten's.
//!
//! ### The two codes Batten *does* mint there, and why both are `1` (CLOUD-292)
//!
//! A passthrough channel that carried only the child's codes would need no
//! paragraph. This one mints exactly two of its own, and both are [`Usage`]:
//!
//! * the named program cannot be started — there is no child, so there is no
//!   code of the child's to report;
//! * a declared `exec_pattern` matched on an otherwise-clean exit `0`
//!   (CLOUD-117): the command reported success while its own output betrays that
//!   it is not done.
//!
//! Both are **a statement about the invocation**, which is what [`Usage`] means —
//! not a verdict about the repository, which is what [`Violation`] means. So
//! neither is a per-verb exception to the table above; they are the table applied.
//! §7's "no per-verb exception" holds here unqualified, and the thing that was
//! wrong was the *characterisation*: an output match was once tabled beside a rule
//! finding as though the two were one kind of answer wearing two numbers.
//!
//! This is also why the second one is not renumbered to `2` for symmetry. Doing
//! that would mint a `2` on the one channel whose whole readability rests on
//! **never a `2`** — spending the guarantee above to buy an agreement the table
//! does not actually ask for. The decision and the three rejected alternatives are
//! recorded on CLOUD-292; `crates/batten/tests/extension_surfaces.rs` gates it.
//!
//! [`Usage`]: ExitCode::Usage
//! [`Violation`]: ExitCode::Violation
//!
//! The cost, accepted deliberately: this inverts the `grep`/`eslint` habit of
//! `1` for findings and `2` for tool error. The two conventions collide on one
//! byte, and the mediation channel wins it — that is the surface where a wrong
//! code changes an enforcement outcome rather than a report.

/// A process exit status with a stable, documented numeric value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum ExitCode {
    /// The check passed, or the command completed with nothing to report.
    /// Under `hook`, the mediated call is allowed.
    Success = 0,
    /// The invocation was malformed: bad flags, unreadable config, or usage error.
    Usage = 1,
    /// The policy verdict: a violation was found, or a mediated call was denied.
    /// The invocation itself was well-formed — this is an answer, not a failure.
    Violation = 2,
    /// Batten could not complete the check (I/O failure, missing tool, internal error).
    Internal = 3,
}

impl ExitCode {
    /// The raw integer value handed to the operating system.
    #[must_use]
    pub const fn code(self) -> i32 {
        self as i32
    }

    /// The code the checks/advisory pipeline returns for a run that did or did
    /// not find something blocking.
    ///
    /// The pipeline's outcome is two-valued, so it gets one home here rather
    /// than a `if … Violation else Success` at each call site. The range is the
    /// point: `Usage` and `Internal` are unreachable through this function, so a
    /// finding — however it was rated — can never be reported as a failure of
    /// Batten's own.
    ///
    /// A **promoted** `warn` (CLOUD-49, [`crate::severity::promote`]) returns the
    /// same [`ExitCode::Violation`] a `deny` finding returns, because it is the
    /// same kind of answer: a policy verdict. Promotion changes which findings
    /// block, never which code a blocking run reports.
    /// Every code in the contract, in numeric order.
    ///
    /// The totality source for [`table`]: a new variant that is not added here
    /// fails [`tests::the_rendered_table_covers_every_code`], so a code cannot
    /// be minted without being documented.
    pub const ALL: [ExitCode; 4] = [
        ExitCode::Success,
        ExitCode::Usage,
        ExitCode::Violation,
        ExitCode::Internal,
    ];

    /// The one-line meaning this code carries in the §7 table.
    ///
    /// Declared once, here, beside the numeric value — the rendered table and
    /// any documentation of it are *derived* from this, so a code's meaning
    /// cannot be described one way in the binary and another in the README.
    #[must_use]
    pub const fn meaning(self) -> &'static str {
        match self {
            ExitCode::Success => "clean — nothing to report; a mediated call is allowed",
            ExitCode::Usage => "config or usage error — fail loud, do not block",
            ExitCode::Violation => "policy verdict — a violation, or a mediated call denied",
            ExitCode::Internal => "internal error — fail loud, do not block",
        }
    }

    /// The one fold from "what did the run see" to "what code does it take"
    /// (CLOUD-1718).
    ///
    /// [`verdict`] answers the two-valued question a findings pipeline asks.
    /// This answers the THREE-valued one every gate epilogue actually has, and
    /// it exists because 82 shell programs were each re-spelling it by hand —
    /// on a table that is the INVERSE of this one, where `1` is a violation and
    /// `2` is could-not-look. A caller reading the wrong table does not get a
    /// worse message, it gets the opposite verdict: a blind spot read as a
    /// finding, or a finding read as a blind spot. Those are the two things a
    /// completion gate most needs to keep apart, which is what
    /// [`crate::findings::Observation::NotObserved`] exists to say.
    ///
    /// # A BLIND SPOT OUTRANKS A FINDING, and this is the one place that is
    /// decided
    ///
    /// CLOUD-251 settled it and one shell program deliberately inverted it, so
    /// two files could disagree about which wins with nothing noticing. The
    /// direction is not a preference: a run that could not read part of its
    /// subject has an INCOMPLETE answer, and reporting the findings it did reach
    /// as though they were the whole answer is the vacuous green this repository
    /// refuses everywhere else. A caller told `Violation` fixes what it names
    /// and sees green; a caller told `Internal` learns the gate did not run. The
    /// findings are on stderr either way, so nothing is lost by ranking the
    /// blind spot first.
    ///
    /// # Never [`Usage`]
    ///
    /// Its range is `Success`, `Violation` and `Internal` — the three answers
    /// ABOUT THE REPOSITORY. `Usage` is a statement about the invocation, and no
    /// count of findings or of unreadable subjects can make an invocation
    /// malformed.
    ///
    /// [`verdict`]: ExitCode::verdict
    /// [`Usage`]: ExitCode::Usage
    #[must_use]
    pub const fn combine(findings: usize, unjudgeable: usize) -> Self {
        if unjudgeable > 0 {
            ExitCode::Internal
        } else if findings > 0 {
            ExitCode::Violation
        } else {
            ExitCode::Success
        }
    }

    #[must_use]
    pub const fn verdict(blocking: bool) -> Self {
        if blocking {
            ExitCode::Violation
        } else {
            ExitCode::Success
        }
    }
}

/// The §7 exit-code table, rendered from [`ExitCode::ALL`].
///
/// This is what "documented" means here: the table a reader sees is *generated*
/// from the same variants the binary returns, so the two cannot disagree. A
/// hand-written second copy is exactly the drift this project exists to prevent
/// — and it is not hypothetical, since renumbering the table (CLOUD-226) left
/// every issue body that had restated it silently wrong.
#[must_use]
pub fn table() -> String {
    ExitCode::ALL
        .iter()
        .map(|code| format!("  {}  {}", code.code(), code.meaning()))
        .collect::<Vec<_>>()
        .join("\n")
}

impl From<ExitCode> for std::process::ExitCode {
    fn from(value: ExitCode) -> Self {
        // ExitCode is constrained to the 0..=255 process-exit range, so this
        // conversion is total. Tie the out-of-range fallback to Internal's code
        // rather than a bare literal, so the two cannot silently drift apart.
        Self::from(u8::try_from(value.code()).unwrap_or(ExitCode::Internal as u8))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every documented variant, paired with its contracted numeric value (§7).
    /// The command-level table test (`tests/cli.rs`) asserts which *invocations*
    /// reach each code; this pins the codes themselves.
    ///
    /// **All four are reached by a command** (CLOUD-421). This comment used to
    /// name `Violation` and `Internal` as unreached "at this scaffold stage", and
    /// both halves were stale: `check` has returned `Violation` since the forbid
    /// rules landed, and `Internal` is what [`crate::run`] produces for any error
    /// that is neither a [`crate::Passthrough`], a [`crate::Denial`] nor a
    /// [`crate::UsageError`] — a could-not-look, of which `config deprecations`
    /// against an unpublished ref is the cheapest, and `rules::forbid_in_file`
    /// surfacing a non-`NotFound` I/O error is the one CLOUD-110 measured.
    const CONTRACT: [(ExitCode, i32); 4] = [
        (ExitCode::Success, 0),
        (ExitCode::Usage, 1),
        (ExitCode::Violation, 2),
        (ExitCode::Internal, 3),
    ];

    #[test]
    fn codes_match_the_documented_contract() {
        // The numeric values are public interface: a reorder or renumber must be
        // caught here rather than by a consumer branching on the wrong code.
        for (code, raw) in CONTRACT {
            assert_eq!(code.code(), raw, "{code:?} must map to exit {raw}");
        }
    }

    #[test]
    fn the_rendered_table_covers_every_code() {
        // The totality gate behind "documented": every variant must appear in
        // the rendered table with its number and its meaning, so a new code
        // cannot be added without documenting it.
        let rendered = table();
        for code in ExitCode::ALL {
            assert!(
                rendered.contains(&format!("  {}  {}", code.code(), code.meaning())),
                "{code:?} is missing from the rendered table:\n{rendered}"
            );
        }
        assert_eq!(
            rendered.lines().count(),
            ExitCode::ALL.len(),
            "the table must have exactly one line per code"
        );
    }

    #[test]
    fn every_code_has_a_distinct_meaning() {
        let mut meanings: Vec<&str> = ExitCode::ALL.iter().map(|c| c.meaning()).collect();
        meanings.sort_unstable();
        let total = meanings.len();
        meanings.dedup();
        assert_eq!(meanings.len(), total, "two codes share a meaning");
    }

    #[test]
    fn no_failure_code_can_deny_a_mediated_call() {
        // Fail-open is structural, not a careful branch in `run_hook`: the two
        // codes a failure of Batten's own can produce must both differ from the
        // one a harness reads as "deny". If a renumbering ever collides them, a
        // crashing guard starts blocking tool calls, silently.
        for failure in [ExitCode::Usage, ExitCode::Internal] {
            assert_ne!(
                failure.code(),
                ExitCode::Violation.code(),
                "{failure:?} must not be the deny code"
            );
        }
    }

    #[test]
    fn a_findings_verdict_is_never_a_failure_of_battens_own() {
        // The range of `verdict` is the whole guarantee: whatever the resolved
        // `fail_on_warning` setting does to a finding's rank, the code it
        // produces is an answer (0 or 2) and never `Usage` or `Internal`. A
        // promotion that could exit 1 would read to a harness as "the gate is
        // misconfigured", which is a different claim from "policy says no".
        assert_eq!(ExitCode::verdict(true), ExitCode::Violation);
        assert_eq!(ExitCode::verdict(false), ExitCode::Success);
        for blocking in [false, true] {
            let code = ExitCode::verdict(blocking);
            assert_ne!(code, ExitCode::Usage);
            assert_ne!(code, ExitCode::Internal);
        }
    }

    #[test]
    fn combine_ranks_a_blind_spot_above_a_finding() {
        // THE PRECEDENCE, ASSERTED ONCE (CLOUD-251, CLOUD-1718). One shell
        // program deliberately inverted this and nothing could notice, because
        // the rule lived in prose in each epilogue rather than in a function.
        // A run that could not read part of its subject has an incomplete
        // answer, and reporting the findings it did reach as the whole answer is
        // the vacuous green refused everywhere else here.
        assert_eq!(ExitCode::combine(3, 1), ExitCode::Internal);
        assert_eq!(ExitCode::combine(0, 1), ExitCode::Internal);
        assert_eq!(ExitCode::combine(3, 0), ExitCode::Violation);
        assert_eq!(ExitCode::combine(0, 0), ExitCode::Success);
    }

    #[test]
    fn combine_never_reports_a_failure_of_battens_own() {
        // The range is the guarantee, exactly as it is for `verdict`: no count
        // of findings or of unreadable subjects makes an INVOCATION malformed,
        // so `Usage` is unreachable through this fold.
        for findings in [0_usize, 1, 7] {
            for unjudgeable in [0_usize, 1, 7] {
                let code = ExitCode::combine(findings, unjudgeable);
                assert_ne!(code, ExitCode::Usage, "{findings}/{unjudgeable}");
            }
        }
    }

    #[test]
    fn combine_and_the_shell_convention_disagree_on_every_nonclean_answer() {
        // THE INVERSION ITSELF, which is CLOUD-1718's discriminating case. The
        // retiring corpus reads `1` as a violation and `2` as could-not-look;
        // this table reads `2` as a violation and `3` as could-not-look. A port
        // that carried the old fold across would not report a worse code, it
        // would report the OPPOSITE meaning — so the two codes are asserted
        // different here rather than left to a reader to notice.
        let shell_violation = 1;
        let shell_could_not_look = 2;
        assert_ne!(ExitCode::combine(1, 0).code(), shell_violation);
        assert_ne!(ExitCode::combine(0, 1).code(), shell_could_not_look);
        // And the collision that makes the inversion dangerous rather than
        // merely different: the shell's could-not-look IS this table's violation.
        assert_eq!(ExitCode::Violation.code(), shell_could_not_look);
    }

    #[test]
    fn every_documented_code_fits_the_process_exit_range() {
        // The From<ExitCode> conversion falls back to Internal only for a code
        // outside 0..=255. Assert every variant fits, so that fallback is dead
        // code and the conversion never silently remaps a real code.
        for (code, _) in CONTRACT {
            assert!(u8::try_from(code.code()).is_ok(), "{code:?} must fit u8");
        }
    }
}
