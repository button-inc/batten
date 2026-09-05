//! The forge's verdict for a commit, read back from a record something else
//! wrote (CLOUD-1154).
//!
//! # The engine opens no socket, and that is the whole design
//!
//! House style §5 forbids an HTTP client on the `check` surface and CLOUD-689's
//! ~100ms budget forbids one on the mediated path, so ~22 governed gates that
//! read the forge had no expressible successor. The answer is not to widen the
//! engine but to move WHO RESOLVES: the producer fetches once, outside — a
//! workflow step, an agent call — and writes a keyed record this reads back.
//!
//! That is exactly [`crate::facts::AGENT_SOURCED`]'s argument, moved from the
//! hook surface to the tree one: *the same answer that is `verify-only` when the
//! ENGINE would fetch it is not when something else already did.* The table is
//! about who resolves, never about what is known — the second axis earning
//! itself a third time. `evaluator-io-check` stays the gate on the engine
//! opening nothing.
//!
//! # Keyed by SHA, which is the safety property rather than a convenience
//!
//! A record taken against a different commit is not evidence about this one. A
//! family that merged every record into one listing would let a gate inherit a
//! green verdict from a commit nobody is asking about — which is worse than no
//! gate, because it reports a judgement that was never made. So the reading is
//! per declared SHA and a record under any other key is invisible.
//!
//! # Three answers, kept apart
//!
//! * **no record for a declared SHA** — absent from the map. Nothing has judged
//!   this commit yet.
//! * **a record holding no checks** — present, empty. The producer looked and
//!   the forge had nothing to say.
//! * **no store at all** — the whole fact is `None`, projected as `null`.
//!
//! Collapsing any pair reports green on a commit nothing ever judged, which is
//! CLOUD-845's dead gate on the surface that decides whether work lands.
//!
//! # Pointer-only, at the boundary
//!
//! A check's NAME and its CONCLUSION, both tokens. Never a check-run's body, its
//! annotations, or the log it points at — non-negotiable rule 4 is decided here
//! rather than at the report, because a check-run body is the likeliest place in
//! this whole surface for a secret to appear.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Where a producer leaves its records, under the git directory.
///
/// Beside `receipt.rs`'s `batten-receipts` and the recorder's own store, for
/// their reason: it is per-checkout state that must never be committed, and the
/// git directory is the one place this crate already treats that way.
const DIRECTORY: &str = "batten-forge";

/// The record file for one commit.
#[must_use]
pub fn record_path(git_dir: &Path, sha: &str) -> PathBuf {
    git_dir.join(DIRECTORY).join(sha)
}

/// Read the forge's verdicts for each DECLARED sha.
///
/// A record is lines of `<check name> <conclusion>`, which is the shape a
/// producer can write with no serializer and a reader can parse with no schema —
/// the same reasoning `findings::pointer_lines` records one family over.
///
/// **A sha with no record is absent from the result**, never present with an
/// empty map: "nothing has judged this commit" and "the forge judged it and said
/// nothing" are different answers, and a landing gate acts on the second.
///
/// Unreadable records and malformed lines are skipped rather than fatal: one
/// torn record is not evidence about the others, and a whole family refused for
/// one bad line would take a gate offline for a producer's transient failure.
#[must_use]
pub fn verdicts(git_dir: &Path, declared: &[String]) -> BTreeMap<String, BTreeMap<String, String>> {
    let mut found = BTreeMap::new();
    for sha in declared {
        let Ok(text) = std::fs::read_to_string(record_path(git_dir, sha)) else {
            // ABSENT, not empty. This is the arm the whole family turns on.
            continue;
        };
        found.insert(sha.clone(), parse(&text));
    }
    found
}

/// One keyed record's lines, as `name -> token`.
///
/// `pub(crate)` because [`crate::tools`] reads the same shape (CLOUD-1171): this
/// family and the tool-verdict one differ in their KEY and in nothing else, so
/// two parsers would be two authorities over one byte format that can disagree
/// about a torn line — the shape `rules/policy-modules.md` records for
/// patterns, one layer down.
///
/// Split on the FIRST whitespace run only: a conclusion is a token, and a name
/// that somehow carries a space would otherwise silently become two records.
/// A line with no conclusion is skipped — a name with no verdict is not a
/// verdict, and recording it as an empty string would let a predicate comparing
/// against `""` succeed.
pub(crate) fn parse(text: &str) -> BTreeMap<String, String> {
    let mut checks = BTreeMap::new();
    for line in text.lines() {
        let mut parts = line.split_whitespace();
        let (Some(name), Some(conclusion)) = (parts.next(), parts.next()) else {
            continue;
        };
        checks.insert(name.to_owned(), conclusion.to_owned());
    }
    checks
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn a_record_for_another_sha_does_not_answer() {
        // THE ANTI-FORGERY CASE, and the property the whole family rests on: a
        // verdict taken against a different commit is not evidence about this
        // one. Without the per-sha key a gate could inherit a green reading from
        // a commit nobody asked about — a judgement that was never made,
        // reported as one that was.
        let dir = std::env::temp_dir().join("batten-forge-keying");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join(DIRECTORY)).unwrap();
        std::fs::write(record_path(&dir, "aaaa"), "final success\n").unwrap();

        let asked = verdicts(&dir, &[String::from("bbbb")]);
        assert!(
            !asked.contains_key("bbbb"),
            "a record keyed to another sha must not answer: {asked:?}"
        );

        let own = verdicts(&dir, &[String::from("aaaa")]);
        assert_eq!(
            own.get("aaaa").and_then(|checks| checks.get("final")),
            Some(&String::from("success")),
            "the sha's own record must answer"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_absent_record_is_not_an_empty_one() {
        // The two answers a landing gate must never confuse. `verdicts` leaves a
        // sha with no record ABSENT; a record that exists and holds no checks is
        // present and empty.
        let dir = std::env::temp_dir().join("batten-forge-absent");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join(DIRECTORY)).unwrap();
        std::fs::write(record_path(&dir, "empty"), "").unwrap();

        let found = verdicts(&dir, &[String::from("empty"), String::from("missing")]);
        assert_eq!(
            found.get("empty").map(BTreeMap::len),
            Some(0),
            "a record that exists and holds nothing is present and empty"
        );
        assert!(
            !found.contains_key("missing"),
            "a sha with no record is absent, never an empty map"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_name_with_no_conclusion_is_not_a_verdict() {
        // Recording it as an empty string would let a predicate comparing against
        // `""` succeed, which is a verdict nobody wrote.
        let checks = parse("final success\nlonely\n  \nother failure\n");
        assert_eq!(checks.len(), 2, "{checks:?}");
        assert!(!checks.contains_key("lonely"), "{checks:?}");
    }
}
