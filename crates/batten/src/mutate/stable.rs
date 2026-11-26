//! A case's reach is a function of its inputs, or the case is refused
//! (CLOUD-2904).
//!
//! The schema keys a case's verdicts on the content digests of the functions
//! it executed. A case that runs different functions on two runs over the same
//! inputs moves its key with no code change: its mutants are re-judged for
//! nothing, and a verdict reached on one draw can depend on luck. Two sealed
//! recordings of unchanged code moved 43 cases this way, through a clock read
//! deciding which function ran, threads cut off at process exit, and state
//! shared across cases.
//!
//! SUCH A CASE IS A FLAKY TEST, AND IS REFUSED, NEVER WAIVED. The oracle is the
//! reach recording itself: a case recorded twice over an identical input set
//! — every function it ran still there by digest and its dependency digest
//! unchanged, which is exactly what lets a record be carried — must execute the
//! same functions both times. There is no exclusion list and no retry.
//!
//! RECORDED TWICE ONLY WHERE THE SECOND RECORDING IS CHEAP. A record the carry
//! would trust but clears anyway — under CI, which carries nothing, or for a
//! mutant new to the listing in a function it ran — is about to be recorded
//! again regardless, so its executed functions are kept here as a WITNESS and
//! compared with the new recording. [`TWICE`] records the whole suite twice,
//! once, to prove it clean.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

/// A case: its name and its nextest binary id.
pub type Case = (String, String);

/// The function digests each witnessed case executed on its first recording.
pub type Witness = BTreeMap<Case, BTreeSet<String>>;

/// The variable that records the whole suite twice and compares every case.
pub const TWICE: &str = "MUTANT_REACH_TWICE";

/// The directory under the reach directory holding witnesses, one file per
/// case. Beside the case records, never in one: the recorder clears a case's
/// directory before it runs it.
const WITNESSES: &str = "witness";

/// The verdict a refusal names.
pub const UNSTABLE: &str = "reach unstable";

/// Whether [`TWICE`] asks for the whole suite to be recorded twice.
#[must_use]
pub fn twice() -> bool {
    asks_twice(super::overlay_var(TWICE).as_deref())
}

/// Whether a [`TWICE`] of `value` asks: any value but none, empty or `0`.
fn asks_twice(value: Option<&str>) -> bool {
    value.is_some_and(|value| !value.is_empty() && value != "0")
}

/// Keep `functions` as the witness of `case` under the reach directory `base`.
///
/// # Errors
///
/// The witness cannot be written.
pub fn keep(base: &Path, case: &Case, functions: &BTreeSet<String>) -> anyhow::Result<()> {
    let dir = base.join(WITNESSES);
    std::fs::create_dir_all(&dir)?;
    let mut body = format!("{}\t{}\n", case.0, case.1);
    for function in functions {
        let _ = writeln!(body, "{function}");
    }
    crate::durable::replace(witness_path(&dir, case), body)?;
    Ok(())
}

/// The file `case`'s witness is kept in under `dir`.
fn witness_path(dir: &Path, case: &Case) -> PathBuf {
    let key = blake3::hash(format!("{}\u{1f}{}", case.0, case.1).as_bytes()).to_hex();
    dir.join(&key[..16])
}

/// Every witness kept under the reach directory `base`; a file that does not
/// parse is no witness.
#[must_use]
pub fn witnesses(base: &Path) -> Witness {
    let mut held = Witness::new();
    for entry in std::fs::read_dir(base.join(WITNESSES))
        .into_iter()
        .flatten()
        .flatten()
    {
        let Ok(body) = crate::fsio::read_to_string(entry.path()) else {
            continue;
        };
        let mut lines = body.lines();
        let Some((name, binary)) = lines.next().and_then(|head| head.split_once('\t')) else {
            continue;
        };
        held.insert(
            (name.to_owned(), binary.to_owned()),
            lines.map(str::to_owned).collect(),
        );
    }
    held
}

/// Drop every witness under the reach directory `base`, once compared.
///
/// # Errors
///
/// The witnesses cannot be removed.
pub fn clear(base: &Path) -> anyhow::Result<()> {
    match std::fs::remove_dir_all(base.join(WITNESSES)) {
        Err(gone) if gone.kind() != std::io::ErrorKind::NotFound => Err(gone.into()),
        _ => Ok(()),
    }
}

/// The function digests of each case in `executed`, by probe id over `probes`.
#[must_use]
pub fn by_digest(executed: &BTreeMap<Case, BTreeSet<usize>>, probes: &[String]) -> Witness {
    executed
        .iter()
        .map(|(case, ids)| {
            (
                case.clone(),
                ids.iter()
                    .filter_map(|id| probes.get(*id).cloned())
                    .collect(),
            )
        })
        .collect()
}

/// [`by_digest`] over the cases that passed: a case `red` holds has its own
/// verdict, so it is neither a witness nor compared with one.
#[must_use]
pub fn passing(
    executed: &BTreeMap<Case, BTreeSet<usize>>,
    probes: &[String],
    red: &BTreeSet<Case>,
) -> Witness {
    let mut witness = by_digest(executed, probes);
    witness.retain(|case, _| !red.contains(case));
    witness
}

/// One case that executed different functions on two recordings over the
/// same inputs: how many it ran only the first time, and only the second.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Moved {
    /// The case.
    pub case: Case,
    /// Functions only the witness ran.
    pub before: usize,
    /// Functions only the new recording ran.
    pub after: usize,
}

/// Every case witnessed in `before` and recorded in `after` whose executed
/// functions differ, in case order. A case missing from either is not
/// compared: one the new run did not record passing has its own verdict.
#[must_use]
pub fn moved(before: &Witness, after: &Witness) -> Vec<Moved> {
    before
        .iter()
        .filter_map(|(case, first)| {
            let second = after.get(case)?;
            let only_first = first.difference(second).count();
            let only_second = second.difference(first).count();
            (only_first + only_second > 0).then(|| Moved {
                case: case.clone(),
                before: only_first,
                after: only_second,
            })
        })
        .collect()
}

/// Refuse when any case in `moved` ran different functions over the same
/// inputs, naming [`UNSTABLE`], how many cases of `compared`, and each case
/// with its counts: pointers, never a function's digest or text.
///
/// # Errors
///
/// At least one case moved.
pub fn refuse(moved: &[Moved], compared: usize) -> anyhow::Result<()> {
    if moved.is_empty() {
        return Ok(());
    }
    let cases: Vec<String> = moved
        .iter()
        .map(|moved| {
            format!(
                "{} {} (-{} +{})",
                moved.case.1, moved.case.0, moved.before, moved.after
            )
        })
        .collect();
    anyhow::bail!(
        "{UNSTABLE}: {} of {compared} case(s) recorded twice over identical inputs executed \
         different functions, so each is a flaky test whose verdicts key on luck; make each \
         deterministic, since no case is waived: {}",
        moved.len(),
        cases.join(", ")
    )
}

/// Compare every witness under `base` with `after`, drop the witnesses, and
/// refuse as [`refuse`] does. How many cases were compared, when none moved.
///
/// # Errors
///
/// A case moved, or the witnesses cannot be removed.
pub fn judge(base: &Path, after: &Witness) -> anyhow::Result<usize> {
    let before = witnesses(base);
    let compared = before
        .keys()
        .filter(|case| after.contains_key(*case))
        .count();
    let moved = moved(&before, after);
    clear(base)?;
    refuse(&moved, compared)?;
    Ok(compared)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn case(name: &str) -> Case {
        (name.to_owned(), String::from("batten::it"))
    }

    fn set(digests: &[&str]) -> BTreeSet<String> {
        digests.iter().map(|digest| (*digest).to_owned()).collect()
    }

    /// Fails by: a witness that does not read back as written (a moved case
    /// compared against nothing, so never refused), or one left behind after
    /// a judgement (the next run compared against a stale draw).
    #[test]
    fn a_witness_reads_back_as_kept_and_is_cleared_once_judged() {
        let base = crate::scratch::scratch("stable-witness-roundtrip");
        keep(&base, &case("a"), &set(&["f1", "f2"])).unwrap();
        keep(&base, &case("b"), &set(&[])).unwrap();
        let held = witnesses(&base);
        assert_eq!(held.get(&case("a")), Some(&set(&["f1", "f2"])));
        assert_eq!(held.get(&case("b")), Some(&set(&[])));
        assert_eq!(judge(&base, &held).unwrap(), 2);
        assert!(witnesses(&base).is_empty(), "cleared once judged");
    }

    /// THE GATE FAILS ON A NONDETERMINISTIC CASE. `flaky` ran `timer` on one
    /// draw and `exit` on the other over the same inputs; `steady` ran the same
    /// both times. Fails by: the comparison skipped (a flaky case keyed on
    /// luck), a refusal not naming the verdict or the case, or a steady case
    /// named with it.
    #[test]
    fn a_case_running_different_functions_over_the_same_inputs_is_refused() {
        let base = crate::scratch::scratch("stable-witness-flaky");
        keep(&base, &case("flaky"), &set(&["f", "timer"])).unwrap();
        keep(&base, &case("steady"), &set(&["g"])).unwrap();
        let after = Witness::from([
            (case("flaky"), set(&["f", "exit"])),
            (case("steady"), set(&["g"])),
        ]);
        let refused = judge(&base, &after).expect_err("a flaky case is refused");
        let said = format!("{refused:#}");
        assert!(said.starts_with(UNSTABLE), "{said}");
        assert!(said.contains("1 of 2 case(s)"), "{said}");
        assert!(said.contains("batten::it flaky (-1 +1)"), "{said}");
        assert!(!said.contains("steady"), "{said}");
        assert!(!said.contains("timer"), "pointers, never a digest: {said}");
    }

    /// A CASE THAT MOVED ON ONE SIDE ONLY HAS MOVED: one that ran an extra
    /// function the second time, and dropped none, is as flaky as one that
    /// traded a function for another. Fails by: the move counted as the
    /// product of its sides, so a one-sided move reads as none (CLOUD-2789).
    #[test]
    fn a_case_that_moved_on_one_side_only_has_moved() {
        let before = Witness::from([
            (case("grew"), set(&["f"])),
            (case("shrank"), set(&["f", "g"])),
        ]);
        let after = Witness::from([
            (case("grew"), set(&["f", "g"])),
            (case("shrank"), set(&["f"])),
        ]);
        assert_eq!(
            moved(&before, &after),
            vec![
                Moved {
                    case: case("grew"),
                    before: 0,
                    after: 1,
                },
                Moved {
                    case: case("shrank"),
                    before: 1,
                    after: 0,
                },
            ]
        );
    }

    /// A case only one recording holds is not compared: one the second run did
    /// not record passing has the baseline's verdict, and one never witnessed
    /// has nothing to compare against. Fails by: a red or new case read as
    /// having moved.
    #[test]
    fn a_case_missing_from_either_recording_is_not_compared() {
        let before = Witness::from([(case("red"), set(&["f"]))]);
        let after = Witness::from([(case("new"), set(&["g"]))]);
        assert!(moved(&before, &after).is_empty());
    }

    /// Probe ids are read through the rendering's probes, an id it does not
    /// hold dropped. Fails by: ids compared as numbers across two renderings,
    /// whose ids differ for the same function.
    #[test]
    fn executed_ids_are_compared_by_digest() {
        let probes = vec![String::from("d0"), String::from("d1")];
        let executed = BTreeMap::from([(case("a"), BTreeSet::from([1, 7]))]);
        assert_eq!(
            by_digest(&executed, &probes),
            Witness::from([(case("a"), set(&["d1"]))])
        );
    }

    /// Fails by: an unset, empty or `0` value read as asking for a double
    /// recording (every local sweep paying the suite twice), or a set one not.
    #[test]
    fn twice_is_asked_only_by_a_value() {
        assert!(!asks_twice(None));
        assert!(!asks_twice(Some("")));
        assert!(!asks_twice(Some("0")));
        assert!(asks_twice(Some("1")));
    }

    /// [`twice`] reads [`TWICE`] from the environment. Fails by: the variable
    /// ignored, so a sweep asked to prove the suite clean records it once.
    #[test]
    fn twice_reads_its_variable() {
        assert!(super::super::with_overlay_vars(&[(TWICE, "1")], twice));
        assert!(!super::super::with_overlay_vars(&[], twice));
    }

    /// A red case is dropped from what a recording witnesses, a passing one
    /// kept. Fails by: the filter inverted, so only red cases were witnessed
    /// and compared (bootstrap shard 7/8 at 34c6e4d1f survived the `!` in
    /// `record_reach`'s `retain`).
    #[test]
    fn only_a_passing_case_is_witnessed() {
        let probes = vec![String::from("d0")];
        let executed = BTreeMap::from([
            (case("green"), BTreeSet::from([0])),
            (case("red"), BTreeSet::from([0])),
        ]);
        let red = BTreeSet::from([case("red")]);
        assert_eq!(
            passing(&executed, &probes, &red),
            Witness::from([(case("green"), set(&["d0"]))])
        );
    }

    /// Fails by: a witness directory that cannot be removed read as cleared
    /// (`clear`'s refusal guard answering `false`, a mutant missed at
    /// 34c6e4d1f, CLOUD-2789), so the next run compares against a stale draw
    /// it was told was gone. A FILE where the directory belongs is the failure
    /// a root sandbox can still produce; an absent one is cleared already.
    #[test]
    fn a_witness_store_that_cannot_be_removed_is_an_error() {
        let base = crate::scratch::scratch("stable-witness-unremovable");
        assert!(clear(&base).is_ok(), "nothing to clear is cleared");
        std::fs::write(base.join(WITNESSES), "not a directory").unwrap();
        assert!(base.join(WITNESSES).is_file(), "the store is a file");
        assert!(
            clear(&base).is_err(),
            "a store that cannot be removed is refused"
        );
    }
}
