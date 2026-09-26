//! Which of three things a probe build did, from its exit status and its log
//! (CLOUD-418, CLOUD-1717).
//!
//! # Why this is a reading and not a comparison against zero
//!
//! THE VERDICT IS THE HARNESS'S OWN LINE, NEVER THE EXIT CODE ALONE. `cargo
//! test` exits non-zero for a compile error, an unresolved feature, an absent
//! toolchain and a panic in some other test — every one of which would read as
//! "the probe falsified the assertion" and hand the gate a pass it did not
//! earn. Worse, that pass gets MORE likely as the crate breaks, so a gate
//! written to the obvious shape is loudest exactly when it is lying.
//!
//! # Why the `failures:` listing rather than the per-test line
//!
//! The per-test line is not stable across harness modes: plain prints `test
//! <name> ... FAILED` and `--quiet` prints `<name> --- FAILED`. The listing is
//! one indented name in both, and anchoring on it is what stops this going
//! quietly could-not-look the day someone adds or drops `--quiet`.
//!
//! # Pointer-only
//!
//! The log carries module bodies and paths; [`verdict`] returns one token and no
//! byte of the log reaches it (non-negotiable rule 4).

/// The three things a probe build can have done.
///
/// An enum rather than the record's own strings, so the reading cannot emit a
/// token no module reads: the spelling lives in one place, on [`Verdict::token`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// The build succeeded, so the test stayed green and discriminates nothing.
    Passed,
    /// The named test RAN and FAILED, which is the discrimination wanted.
    Failed,
    /// Non-zero for some other reason: could not look.
    Unread,
}

impl Verdict {
    /// The record line a module reads this under.
    #[must_use]
    pub const fn token(self) -> &'static str {
        match self {
            Verdict::Passed => "probe passed",
            Verdict::Failed => "probe failed",
            Verdict::Unread => "probe unread",
        }
    }
}

/// Classify a probe build from its exit status and the log it wrote.
///
/// `log` is the TEXT rather than a path, deliberately: the caller owns it, which
/// is what makes "no byte of the log escapes" a property a test can assert.
#[must_use]
pub fn verdict(status: i32, log: &str, test: &str) -> Verdict {
    if status == 0 {
        return Verdict::Passed;
    }
    if ran_to_a_failure(log) && listed_as_failing(log, test) {
        return Verdict::Failed;
    }
    Verdict::Unread
}

/// The harness's own summary line, anchored at column 0.
fn ran_to_a_failure(log: &str) -> bool {
    log.lines()
        .any(|line| line.starts_with("test result: FAILED"))
}

/// The name in the `failures:` listing: indented, alone on its line.
///
/// THE INDENT IS THE WHOLE TEST, and dropping it is what would make this match
/// the summary line, a path, or a name that merely contains this one.
fn listed_as_failing(log: &str, test: &str) -> bool {
    log.lines().any(|line| {
        let trimmed = line.trim_matches([' ', '\t']);
        trimmed == test && line != trimmed
    })
}

#[cfg(test)]
mod tests {
    use super::{Verdict, verdict};

    const TEST: &str = "no_evaluator_feature_admits_io";

    #[test]
    fn a_probe_build_that_succeeds_classifies_as_passed() {
        assert_eq!(verdict(0, "", TEST), Verdict::Passed);
    }

    #[test]
    fn a_probe_build_that_ran_the_named_test_to_a_failure_classifies_as_failed() {
        let harness = "failures:\n    no_evaluator_feature_admits_io\n\ntest result: FAILED. 0 passed; 1 failed\n";
        assert_eq!(verdict(101, harness, TEST), Verdict::Failed);
    }

    /// THE ARM A GATE WRITTEN TO THE OBVIOUS SHAPE GETS WRONG: non-zero, and no
    /// harness line at all.
    #[test]
    fn a_probe_build_that_failed_to_compile_classifies_as_unread() {
        assert_eq!(
            verdict(101, "error[E0432]: unresolved import\n", TEST),
            Verdict::Unread
        );
    }

    /// A different test failed, so the harness says FAILED and the listing names
    /// somebody else. Reading the exit code would call this the discrimination
    /// this gate is looking for.
    #[test]
    fn a_probe_build_where_the_named_test_never_ran_classifies_as_unread() {
        let other = "failures:\n    some_other_test\n\ntest result: FAILED. 3 passed; 1 failed\n";
        assert_eq!(verdict(101, other, TEST), Verdict::Unread);
    }

    /// The summary line carries the token too, and it is NOT indented. Without
    /// the indent test a log naming nothing would read as the named failure.
    #[test]
    fn an_unindented_occurrence_of_the_name_is_not_the_listing() {
        let flat = format!("test result: FAILED. 0 passed; 1 failed\n{TEST}\n");
        assert_eq!(verdict(101, &flat, TEST), Verdict::Unread);
    }

    /// A name that merely CONTAINS the probe's name is a different test.
    #[test]
    fn a_longer_name_containing_this_one_is_not_this_test() {
        let near = "failures:\n    no_evaluator_feature_admits_io_at_all\n\ntest result: FAILED. 0 passed; 1 failed\n";
        assert_eq!(verdict(101, near, TEST), Verdict::Unread);
    }

    /// Pointer-only (rule 4): the log carries module bodies and paths, and what
    /// comes back is one token.
    #[test]
    fn the_probe_builds_own_output_never_reaches_the_verdict() {
        let noisy = "SECRET_MODULE_BODY\nerror: build failed\n";
        let classified = verdict(101, noisy, TEST);
        assert_eq!(classified, Verdict::Unread);
        assert!(
            !classified.token().contains("SECRET_MODULE_BODY"),
            "no byte of the probe log reaches the record"
        );
    }
}
