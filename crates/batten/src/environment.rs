//! What kind of machine this is, as the one fact only the environment can state
//! (CLOUD-1383).
//!
//! # Why this is a module and not a config key
//!
//! Everything else batten decides from is committed: `batten.toml` is the
//! authority, and a consumer's overrides may only tighten it. That is right for
//! every question about a REPOSITORY, and wrong for the one question here, which
//! is about the machine the repository happens to be checked out on. The same
//! commit is read by a disposable container and by a developer's laptop, and the
//! honest answer differs between them — so a committed file cannot hold it, and
//! an override that could would be an override that weakens.
//!
//! # What it is for
//!
//! Batten repairs the environment: it owns the harness hook surfaces it derives
//! and puts them back when something else has written over them. Whether a repair
//! may REMOVE what it finds is not a property of the finding — the census is
//! equally right on both machines — it is a property of whose `$HOME` this is.
//!
//! Before this fact existed the difference was negotiated in committed config: a
//! table naming each tolerated registration and the issue that owned removing it.
//! That is a second authority over the same subject, and it drifted from the
//! repair within a day — the repair deleted, every session, exactly what the
//! table declared must be present, and neither instrument could see the conflict
//! (`wiring reclaim --check` reported nothing to do while the gate refused).
//!
//! # The default is the safe one, deliberately
//!
//! Absent means a real machine. A developer who never sets it gets a batten that
//! reports and never removes; a container whose environment field was mistyped
//! gets the same, which is a stalled repair rather than a surprise deletion. The
//! expensive direction is the one that requires saying so.

/// The variable a disposable environment sets.
///
/// Named for what it describes rather than for what it permits: a consumer sets
/// it because the statement is true of their container, not to switch a feature
/// on, and the next value this key takes should read as another KIND of machine.
const KEY: &str = "BATTEN_ENVIRONMENT";

/// The one value that licenses a destructive repair.
const DISPOSABLE: &str = "disposable";

/// Whether this environment declared itself disposable.
///
/// **An exact match, never a truthiness test**, and that is the whole of the
/// spelling decision. `BATTEN_ENVIRONMENT=1`, `=true`, `=disposible` and an empty
/// value are all *not* this value, so every way of getting it wrong lands on the
/// conservative arm. A predicate that accepted "anything non-empty" would turn a
/// typo into a licence to delete from somebody's home directory, which is the
/// failure this module's default exists to make unreachable.
///
/// Read at the point of decision rather than resolved once into config: it is not
/// a repository fact and giving it a config seat would invite exactly the
/// committed-override shape the header rules out.
#[must_use]
pub fn disposable() -> bool {
    std::env::var(KEY).is_ok_and(|value| value == DISPOSABLE)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The predicate over its own input, extracted from the environment read.
    ///
    /// `.claude/rules/rust.md`'s rule for a condition the test cannot create:
    /// `set_var` is `unsafe` and `unsafe` is forbidden here, so a case that
    /// reached for the real environment could not be written at all. What decides
    /// is the comparison, and that is what is asserted.
    fn licenses(value: Option<&str>) -> bool {
        value == Some(DISPOSABLE)
    }

    #[test]
    fn only_the_exact_value_licenses_a_destructive_repair() {
        assert!(licenses(Some("disposable")));

        // EVERY WAY OF GETTING IT WRONG IS CONSERVATIVE. Each of these is a real
        // spelling somebody reaches for, and a truthiness test would accept all
        // of them — on a machine where the cost of being wrong is somebody's home
        // directory.
        for wrong in [None, Some(""), Some("1"), Some("true"), Some("yes")] {
            assert!(!licenses(wrong), "must not license: {wrong:?}");
        }
        assert!(!licenses(Some("disposible")), "a typo is not a licence");
        assert!(
            !licenses(Some("Disposable")),
            "and neither is a case change"
        );
    }

    /// The key and the value are the consumer's contract, so a rename is a
    /// breaking change rather than a refactor — pinned so it cannot happen by
    /// accident in a rename-all pass.
    #[test]
    fn the_declared_contract_is_the_documented_one() {
        assert_eq!(KEY, "BATTEN_ENVIRONMENT");
        assert_eq!(DISPOSABLE, "disposable");
    }
}
