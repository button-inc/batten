//! The break-glass a locked-out container can reach, and the record that keeps
//! it from being a password (CLOUD-1847).
//!
//! # The state this exists for, which is not a parse verdict
//!
//! CLOUD-1842 gave the unreadable-config arm a floor: over a `batten.toml` that
//! is not TOML, a `Read` still answers and a write to the authority still lands.
//! That floor is scoped to [`crate::verdict::Native::ConfigUnreadable`] and says
//! so — *"everywhere else a policy exists and this question is not asked"*.
//!
//! **A config that loads perfectly can brick the container just as completely.**
//! Measured in a live session (CLOUD-1847): a `mediated_call` `policy` row whose
//! module body was bare truthiness on `input.call` passed `batten config lint`
//! at rc=0, *"0 smell(s)"*, and then refused every subsequent call — `Bash`,
//! `Read`, an `Edit` of `batten.toml`, every MCP tool. The author could not
//! commit, could not revert, could not read and could not report; the session
//! ended by abandonment, and a fresh container was clean only because nothing had
//! been committed. Recovery by luck.
//!
//! So the scope is **"the boundary is refusing the calls that would repair the
//! boundary"**, which is a state rather than a verdict about a file. CLOUD-1844
//! proposed this sentinel scoped to the unreadable arm; this instance refutes that
//! scoping, because there the config loads.
//!
//! # Why a file, and why it is not `BATTEN_HOOK_BYPASS`
//!
//! The environment hatch is unreachable from inside the state it is advertised
//! for. It is read from the hook process's own environment, and an agent driving
//! `Edit`/`Write` has no channel to set one; on the `Bash` surface that does
//! advertise it, the call carrying it is itself adjudicated and denied
//! (CLOUD-1605). A sentinel the **`Write` tool can create** is reachable from the
//! one surface that still works, which is what makes it a route rather than a
//! sentence about a route.
//!
//! # Honoured whenever present, and that is the decidable half
//!
//! *"Honoured when the session has no other route"* is undecidable — nothing at
//! the boundary can enumerate the routes a session has left. *"Honoured whenever
//! present, recorded, and refused by CI"* is a predicate. **The audit is what
//! keeps it from being a password**: every pull is an anchored record an operator
//! sees, and a tracked sentinel fails its own gate, so it cannot ship.
//!
//! # It opens the repair floor, never everything
//!
//! A pull admits exactly what CLOUD-1842's floor admits — a classified read, and
//! a write onto the authority — plus the sentinel's own creation. `Bash`, MCP and
//! subagent spawns stay refused with the sentinel in place, which is the falsifier
//! the row names: *"a fixture where the sentinel is present and the row denies
//! only `Bash`: `Bash` must still deny. If it does not, the ripcord is a global
//! allow and must not land."*
//!
//! # The finding does not self-clear
//!
//! [`crate::identity::FindingKind::Sequence`], on [`crate::completion`]'s
//! precedent and for its reason: a pull that happened, happened, and no later
//! state makes it not have happened. Deleting the sentinel does not retract the
//! record. It settles by disposition, which is where an operator's judgement
//! belongs.

use std::path::Path;

/// The sentinel's name, at the repository root.
///
/// Dotfile-prefixed so it sorts with the other machine-facing entries, and named
/// for what it does rather than for the state it is pulled in — an operator
/// finding one in a tree needs to know what it is without reading this module.
pub const SENTINEL: &str = ".batten-ripcord";

/// The rule id this detector's findings are stored under.
///
/// Engine-side, like [`crate::completion::RULE_ID`] and for the same reason:
/// there is no `[[rule]]` row to take an id from, because the predicate is a
/// property of the boundary rather than of any consumer's declared policy.
pub const RULE_ID: &str = "ripcord.pulled";

/// The pattern half of the identity.
const PATTERN_KEY: &str = "ripcord-admitted-a-refused-call";

/// Whether the sentinel is present in this tree.
///
/// **An unreadable path is "absent", and the direction is deliberate.** This
/// question gates a WEAKENING, so a could-not-look must not grant one — the
/// opposite polarity to the receipt reads, where a could-not-look allows. A
/// filesystem that cannot answer leaves the refusal exactly as it was.
#[must_use]
pub fn present(root: &Path) -> bool {
    root.join(SENTINEL).is_file()
}

/// Whether this call is the one that CREATES the sentinel.
///
/// **The bootstrap, and without it the mechanism is circular.** A config that
/// denies every write denies the write that would create the sentinel, so a
/// sentinel honoured only once it exists could never come into existence in the
/// state it is for. This arm is therefore open whether or not the file is there.
///
/// It is safe precisely because creating the file *does nothing by itself*: it
/// grants no call, and the next call still has to be inside the repair floor to
/// be admitted. What it costs is one record, which is the point.
///
/// The path is compared after `relativise_writes`, so it is the repository's own
/// spelling and never an absolute one.
///
/// **Takes the write target alone; the caller owns the operation check.**
/// `Envelope::writes` is populated only for a classified write, so a `Some` here
/// already means "a write names this path". Taking `hook::Operation` as well would
/// give this leaf an edge onto the adjudicator for a fact its caller already holds.
#[must_use]
pub fn creates_the_sentinel(writes: Option<&str>) -> bool {
    writes.is_some_and(|path| {
        let normalized = path.replace('\\', "/");
        normalized.strip_prefix("./").unwrap_or(&normalized) == SENTINEL
    })
}

/// The identity a pull is recorded under.
///
/// [`crate::identity::FindingKind::Sequence`] on [`crate::completion::identity`]'s
/// precedent: the subject is something that HAPPENED in a session, not a place in
/// a tree, so the fingerprint carries the session and nothing the remedy can mint.
#[must_use]
pub fn identity(session: Option<&str>) -> crate::identity::StoredIdentity {
    crate::identity::StoredIdentity::new(
        crate::identity::FindingKind::Sequence,
        crate::identity::sequence_fingerprint(RULE_ID, PATTERN_KEY, session),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    // `present` IS NOT DRIVEN HERE, and the absence is the purity rule rather
    // than an omission: it reads a filesystem, so its cases live beside the
    // floor's in `tests/it/adjudicate_absent.rs`, over a fixture that owns a
    // tree. What stays here is the half that is a pure function of the write
    // target. The operation half is the caller's, and `adjudicate_absent.rs`'s
    // `the_ripcord_is_not_a_global_allow` is what drives it.

    #[test]
    fn the_bootstrap_admits_only_the_sentinels_own_creation() {
        assert!(creates_the_sentinel(Some(SENTINEL)));
        assert!(creates_the_sentinel(Some("./.batten-ripcord")));
        // The mirrors: a neighbour, another path, and no write target at all.
        assert!(!creates_the_sentinel(Some("crates/.batten-ripcord")));
        assert!(!creates_the_sentinel(Some("batten.toml")));
        assert!(!creates_the_sentinel(None));
    }
}
