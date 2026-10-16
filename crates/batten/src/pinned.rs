//! The programs the project's pin puts on `PATH` (CLOUD-1028).
//!
//! # The defect this fact exists for
//!
//! Measured 2026-08-23: a session reproducing an in-gate failure ran
//! `./tests/bats/bin/bats --filter … tests/land.bats`. That invocation reaches
//! the same binary the declared task reaches, with the same argv — what it drops
//! is the pin's ENVIRONMENT, so `CI_REQUIRED_CHECKS` was unset and sixty runs
//! died on the unset variable rather than on the assertion under test. An
//! unset-variable death under `set -u` is indistinguishable from an assertion
//! failure at the resolution a caller reads, so the tool most likely to be
//! reached for when investigating a flaky gate is the one that manufactures a
//! fake one. Three false claims and one false Urgent row followed.
//!
//! # Why the set is resolved and not written down
//!
//! A `shape` row matches its program token by equality, so covering the defect
//! with rows means one literal per spelling — and the set is not a repository's
//! to state: every consuming project pins different programs, and the set moves
//! whenever the manifest or the lockfile does. So it is asked for.
//!
//! # What "the pin provides" means, measured rather than assumed
//!
//! **Not the install list.** A pin can report the directories of the tools it
//! INSTALLED — 62 program names on the checkout this was measured against, and
//! the runner from the incident above is not one of them, because it is a git
//! submodule the manifest puts on `PATH` rather than a tool the pin installs. A
//! fact built on the install list would have missed the exact invocation that
//! produced the incident.
//!
//! What the pin actually provides is the difference between the `PATH` it
//! composes and the one this process already has: 49 names here, `bats` among
//! them. Names in directories the ambient `PATH` already carries are excluded by
//! construction — a program you would have reached anyway is not one the pin
//! supplies, and `cargo` drops out for exactly that reason (its directory is
//! ambient, and `no-bare-cargo` covers it by name).
//!
//! **Executable regular files only.** An install directory is often an extracted
//! archive root, so `LICENSE`, `README.md`, `docs/` and `man/` sit beside the
//! binary. Six of the 49 were that; a set carrying them would refuse
//! `README.md` as though it were a program.
//!
//! # Two costs, and the split is the whole design
//!
//! Resolving this runs a program, which is [`crate::facts::Cost::Effect`], and
//! an `Effect` fact may not be resolved on the mediated path — that is the fact
//! model's own statement, not a preference. So the answer is resolved ONCE, off
//! the hot path, and the mediated call reads what was recorded:
//!
//! * [`refresh`] asks the pin and records. It spawns.
//! * [`cached`] reads the record and never spawns, which is what makes the fact
//!   [`crate::facts::Cost::Read`] where a call is being adjudicated.
//!
//! # The key is what can invalidate the answer, and THE PIN NAMES IT
//!
//! The record is filed under a digest of the pin's own configuration files, so a
//! session that adds a tool changes one of them, the next read misses, and the
//! next refresh re-resolves. Keying on a timestamp instead would either re-spawn
//! on a clock nobody set or serve a stale set after an install, and both are
//! answers about the wrong thing.
//!
//! **Which files those are is asked, never written down.** Non-negotiable rule 1
//! forbids a consuming project's artifact names inside this crate, and
//! `no_artifact_name_reaches_the_core` is the gate that computes it — so a
//! `const` naming a manifest and a lockfile is unwritable here, and the obvious
//! escape (a `sources` list on the enabling row) is refused one layer down:
//! `rules.rs` denies `sources` on a `scope = "mediated_call"` row at LOAD,
//! because that column is what a tree row hands its bundle. Both refusals point
//! the same way. The pin already knows which files configure it, so [`configs`]
//! asks it, and the answer is recorded beside the set it keys.
//!
//! **Plus their siblings, re-read every time.** A pin's *lockfile* is not one of
//! the files it lists as configuration, and a lockfile moving without its
//! manifest — an install resolving a floating version — is exactly the change
//! this key exists to catch. So each reported config contributes every file
//! beside it sharing its name up to the first `.`, computed at READ time rather
//! than stored: a lockfile that appears after the record was written changes the
//! key, instead of being invisible until the next session.
//!
//! # Every failure is could-not-look, and could-not-look allows
//!
//! No pin, no checkout, a spawn that fails, a record under a different key, a
//! composed `PATH` that adds nothing: all [`Look::CouldNotLook`]. A gate that
//! refuses where it cannot see becomes the reason work cannot proceed, and this
//! one would refuse every program in the project.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use crate::facts::Look;

/// The programs the pin provides, or could-not-look.
///
/// A named alias rather than a bare `Look<BTreeSet<String>>` for the reason
/// [`crate::hook::ReceiptFacts`] carries one: the three-valued answer is the
/// point, and a reader should see it named at every call site.
pub type PinnedFacts = Look<BTreeSet<String>>;

/// The store, beside `batten-receipts/` and deliberately not inside it.
///
/// `pub(crate)` for [`key`]'s reason: [`crate::taskset`] files a second record
/// beside this one, and two spellings of one directory is a second thing to
/// drift.
///
/// A receipt attests that a DECISION was taken and is keyed to the subject it
/// was taken about; this is a memoised reading of the world, keyed to what can
/// change it. Filing the second under the first's name would put a fact where
/// every reader expects a claim.
pub(crate) const STORE: &str = "batten-facts";

/// The record's name inside [`STORE`].
const RECORD: &str = "pinned-programs";

/// The mediator this fact asks. One name, matching [`crate::rules::RequireVia`]'s
/// single variant — a second spelling of "which pin" is a second thing to drift.
pub(crate) const MEDIATOR: &str = "mise";

/// The argv that reaches `program` through the pin: the mediator, and the
/// arguments that must precede the program's own.
///
/// **One spelling, because two callers now compose it** (CLOUD-1324): the
/// engine's spawn ladder, and the analyser acquisition that must run under the
/// pin's environment rather than merely at its `PATH`. A second composition is a
/// second authority over an argv, which is the class
/// `rules/policy-modules.md` records for the mediated surface and which
/// holds here for the same reason.
#[must_use]
pub fn mediated(program: &str) -> (&'static str, Vec<String>) {
    (
        MEDIATOR,
        vec!["exec".to_owned(), "--".to_owned(), program.to_owned()],
    )
}

/// The record, as one writer writes it and one reader reads it.
///
/// A struct rather than a hand-rolled line format for the reason CLOUD-1093
/// measured one layer over: a fixture that spells the bytes itself passes while
/// the real writer and the real reader disagree. Serde owns both directions, so
/// there is one shape and no second parser.
#[derive(serde::Serialize, serde::Deserialize)]
struct Record {
    /// The digest of the pin's configuration at the moment the set was resolved.
    key: String,
    /// The files the pin named as configuring it, so the reader can recompute
    /// the key without asking the pin again.
    configs: Vec<PathBuf>,
    /// The answer.
    programs: BTreeSet<String>,
    /// The keyed files' stat identity when `key` was derived ([`stamped`]).
    /// Absent from a record written before CLOUD-2440, which is then believed
    /// only by its key.
    #[serde(default)]
    stamps: Stamps,
}

/// Each keyed path with its stat identity, an absent file as `None` — what a
/// record was keyed over, as `crate::cache::stamp` sees it (CLOUD-2440).
pub(crate) type Stamps = Vec<(PathBuf, Option<String>)>;

/// The keyed files' stamps as they stand.
fn stamps_now(configs: &[PathBuf]) -> Vec<(PathBuf, Option<crate::cache::Stamp>)> {
    keyed_paths(configs)
        .into_iter()
        .map(|path| {
            let stamp = crate::cache::stamp(&path);
            (path, stamp)
        })
        .collect()
}

/// The stamps to record beside a key derived at `at`, taken BEFORE the key's
/// read — or none, where a file changed too close to `at` for a later change in
/// the same timestamp tick to show in its stamp (git's racy rule,
/// `crate::cache::Stamp::racily_clean`). A record with no stamps is believed
/// by its key alone.
//MUTANT stamped-record-believes-racy|s@^    if racy {$@    if false {@|a_record_stamped_in_its_racy_window_is_hashed
pub(crate) fn stamped(configs: &[PathBuf], at: std::time::Duration) -> Stamps {
    let now = stamps_now(configs);
    let racy = now
        .iter()
        .any(|(_, stamp)| stamp.as_ref().is_some_and(|stamp| stamp.racily_clean(at)));
    if racy {
        return Stamps::new();
    }
    now.into_iter()
        .map(|(path, stamp)| (path, stamp.map(|stamp| stamp.fields)))
        .collect()
}

/// Whether a record keyed `key` over `configs`, with `stamps`, is about the
/// files as they stand (CLOUD-2440).
///
/// BY STAT IDENTITY FIRST: the hook believed two records a call by re-reading
/// and re-hashing the manifests whole, 2.07M of 43.2M instructions, though
/// nothing had changed. Recorded stamps that equal the files' stamps now prove
/// the same in a few `stat`s; anything else — no stamps, or any one moved — is
/// today's answer, the key recomputed from the bytes.
//MUTANT stamped-record-never-believed|s@^    if !stamps.is_empty() \&\& current == stamps {$@    if false {@|a_record_whose_configs_are_unchanged_is_believed_without_reading
//MUTANT stamped-record-ignores-stamps|s@^    if !stamps.is_empty() \&\& current == stamps {$@    if !stamps.is_empty() {@|a_config_edited_after_the_record_is_a_miss
pub(crate) fn still_keyed(
    configs: &[PathBuf],
    key: &str,
    stamps: &[(PathBuf, Option<String>)],
) -> bool {
    let current: Stamps = stamps_now(configs)
        .into_iter()
        .map(|(path, stamp)| (path, stamp.map(|stamp| stamp.fields)))
        .collect();
    if !stamps.is_empty() && current == stamps {
        return true;
    }
    self::key(configs).as_deref() == Some(key)
}

/// Every file that decides the key, given the configs the pin reported.
///
/// Each reported path contributes itself and every file beside it whose name
/// agrees up to the first `.` — the lockfile beside the manifest, and any local
/// overlay beside both. Sorted and deduplicated, because a key that depended on
/// directory order would miss on a tree nothing changed.
pub(crate) fn keyed_paths(configs: &[PathBuf]) -> BTreeSet<PathBuf> {
    let mut out: BTreeSet<PathBuf> = configs.iter().cloned().collect();
    for config in configs {
        let (Some(dir), Some(stem)) =
            (config.parent(), config.file_name().and_then(|n| n.to_str()))
        else {
            continue;
        };
        let prefix = stem.split('.').next().unwrap_or(stem);
        let Ok(entries) = std::fs::read_dir(dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            if name.split('.').next() == Some(prefix) && entry.path().is_file() {
                out.insert(entry.path());
            }
        }
    }
    out
}

/// The digest the record is filed under, or `None` where nothing could be read.
///
/// `pub(crate)` because [`crate::taskset`] files its own record under the SAME
/// key (CLOUD-856): both are memoised readings of the toolchain manifest, so two
/// derivations would be two answers to "has the manifest moved" that can
/// disagree — and the one that says "no" wins by being read first.
///
/// An absent member contributes a stable token rather than voiding the key — a
/// project with a manifest and no lockfile is a real project. Every member
/// absent is a different answer, and is `None`: a key over nothing would file
/// every project's set under one name.
//MUTANT pinned-key-unframed-absence|s@^            Err(_) => owned.push((path_bytes, None)),$@            Err(_) => owned.push((path_bytes, Some(b"-".to_vec()))),@|an_absent_member_never_collides_with_a_present_one
pub(crate) fn key(configs: &[PathBuf]) -> Option<String> {
    let mut owned: Vec<(Vec<u8>, Option<Vec<u8>>)> = Vec::new();
    let mut any = false;
    for path in keyed_paths(configs) {
        let path_bytes = path.to_string_lossy().into_owned().into_bytes();
        match std::fs::read(&path) {
            Ok(bytes) => {
                any = true;
                owned.push((path_bytes, Some(bytes)));
            }
            // An absent member contributes a stable token, so a lockfile that
            // appears LATER changes the key rather than being absorbed by it.
            Err(_) => owned.push((path_bytes, None)),
        }
    }
    // THE CRATE'S ONE FRAMING (CLOUD-2315), not a concatenation. This was
    // `path ‖ bytes ‖ path ‖ bytes` with no boundary, so moving bytes between a
    // path and its contents left the digest unchanged, and an absent member's
    // `-` token equalled a present file holding `-`. Each part is now its own
    // length-prefixed field, and presence is a field of its own.
    let mut fields: Vec<&[u8]> = Vec::with_capacity(3 * owned.len());
    for (path, bytes) in &owned {
        fields.push(path);
        match bytes {
            Some(bytes) => {
                fields.push(b"present");
                fields.push(bytes);
            }
            None => fields.push(b"absent"),
        }
    }
    any.then(|| crate::identity::cache_key(&fields).to_hex())
}

/// Where the record lives for `root`'s checkout.
fn record_path(root: &Path) -> Option<PathBuf> {
    crate::git::git_dir(root)
        .ok()
        .map(|dir| dir.join(STORE).join(RECORD))
}

/// The recorded answer, or could-not-look. Never spawns.
///
/// This is the reading the mediated path takes. A record whose key does not
/// match the pin's configuration as it stands NOW is not a stale answer to be
/// trusted a little — it is an answer about a different toolchain, and reading
/// it would be the fact model's own could-not-look-as-a-pass failure.
#[must_use]
pub fn cached(root: &Path) -> PinnedFacts {
    let Some(path) = record_path(root) else {
        return Look::CouldNotLook;
    };
    let Ok(text) = std::fs::read_to_string(path) else {
        return Look::CouldNotLook;
    };
    let Ok(record) = serde_json::from_str::<Record>(&text) else {
        return Look::CouldNotLook;
    };
    // Recomputed from the RECORDED configs rather than by asking the pin again,
    // which is what keeps this function free of the `Effect` its own doc says it
    // may not pay.
    if !still_keyed(&record.configs, &record.key, &record.stamps) {
        return Look::CouldNotLook;
    }
    // An EMPTY recorded set is could-not-look rather than "the pin provides
    // nothing". The only way a real pin adds no program is that the composed
    // PATH matched the ambient one, which `resolve` already refuses to call an
    // answer; a record that says otherwise is one this code did not write.
    if record.programs.is_empty() {
        Look::CouldNotLook
    } else {
        Look::Is(record.programs)
    }
}

/// Whether a record exists that can no longer answer (CLOUD-1324). Never spawns.
///
/// **The two could-not-looks have different remedies, and only one of them is a
/// fault.** A project with no pin at all has no record and nothing to repair;
/// a project whose record stopped validating has a real thing to fix, and until
/// it is fixed every pinned program reads as absent. [`cached`] correctly answers
/// could-not-look to both, which is right for a fact and useless for a diagnosis.
///
/// So the question is asked as a file read over the two things a reader can act
/// on: a record is THERE, and it does not answer. Measured — one of the pin's own
/// configuration files was edited mid-session and a record written the previous
/// day stopped validating, leaving `doctor` able to say only that some declared
/// program was missing. Which files those are is [`configs`]'s answer and never a
/// name here (non-negotiable rule 1).
///
/// A record that cannot be located at all is not stale: it is absent, which this
/// reports as `false` for the same reason the fact allows on could-not-look.
#[must_use]
pub fn record_is_stale(root: &Path) -> bool {
    record_exists(root) && matches!(cached(root), Look::CouldNotLook)
}

// THE OBLIGATION IS BOUND HERE, AND THE SWEEP NOW APPLIES IT (CLOUD-1371, then
// CLOUD-1369).
//
// `obligations-bound` asks that a §7 obligation name a tracked file carrying its
// slug as a `#MUTANT` row, and this is that file: `record_is_stale` above is what
// CLOUD-1371 changed, so mutating it is what a case must catch.
//
// **This paragraph used to say the sweep could not reach it, and that is now
// false rather than merely stale.** It read: `mutate`'s source resolution offers
// "a task name, a module stem, or a preset name", with no arm for a Rust source,
// so the row was declared and never applied — named as a gap instead of hidden,
// which was the right call and is what made the gap findable. CLOUD-1369 landed
// the arm it named. The subject is `engine-pinned`, registered in
// `$MUTANT_GATES`, and a survivor here is a finding like any other.
//
// Worth keeping rather than deleting: this declaration is what proved the route
// on a predicate nobody wrote for it. The census reported it `uncovered` the
// moment the opener widened — a row declared, swept by nothing — which is the
// arm that would otherwise have read as coverage.
//MUTANT-SUITE crates/batten/tests/it/pinned_programs.rs
//MUTANT absent-record-unrepaired|s@^    record_exists(root) && matches!(cached(root), Look::CouldNotLook)$@    false@|an_absent_record_is_not_stale_and_says_so_separately

/// Whether a record is on disk at all, whatever it says (CLOUD-1371).
///
/// The half of [`record_is_stale`] that is about EXISTENCE, named so a caller
/// asking the other question — *is this tree missing a record it needs* — reads
/// the same file through the same helper rather than spelling the path a second
/// time. Never spawns and never parses: presence is all it claims.
#[must_use]
pub fn record_exists(root: &Path) -> bool {
    record_path(root).is_some_and(|path| path.is_file())
}

/// Ask the pin, record the answer, and return it. Spawns.
///
/// Called where an `Effect` is admissible — at session start, once — so that
/// every mediated call afterwards pays a file read. A failure to record is not a
/// failure to answer: the caller still gets the resolved set, and the next
/// session resolves again.
#[must_use]
pub fn refresh(root: &Path) -> PinnedFacts {
    let resolved = resolve(root);
    if let Look::Is(programs) = &resolved {
        // Discarded deliberately: a record that could not be written is not a
        // failure to answer. The caller still gets the resolved set, and the next
        // session resolves again — which is the same could-not-look the reader
        // already handles.
        let _recorded = record(root, &configs(root), programs);
    }
    resolved
}

/// [`refresh`] whatever the record's state, at most once per root per process
/// (CLOUD-1371).
///
/// **The sibling below is the EAGER entry point and this is the LAZY one**, and
/// the difference is entirely in what the caller has already established. Asking
/// the pin costs two runner spawns, so who may ask, and when, is the whole design:
/// [`repaired`] is safe to call before a spawn because it first establishes there
/// is a stale record to fix, and this one is safe only AFTER a spawn has failed,
/// because by then the cost is bounded by how rarely that happens.
///
/// Both share the one memo, so a root that asks either way asks once.
#[must_use]
pub fn re_resolved(root: &Path) -> PinnedFacts {
    memoised(root, refresh)
}

/// [`refresh`], at most once per root per process, and only where a record
/// EXISTS and has stopped answering (CLOUD-1324).
///
/// **The bound is not an optimisation.** `refresh` spawns the runner twice, and
/// `record` may be unable to write the answer down — no git directory, a
/// read-only tree — in which case [`cached`] still cannot answer on the next
/// call. An unbounded repair would then pay those two spawns for EVERY program
/// of EVERY rule. Measured as flakiness first: without it, one `enforce` over a
/// fixture became slow enough under a parallel suite to be indistinguishable
/// from a broken gate.
///
/// **Keyed by root rather than a bare once-cell**, which is the part a first
/// draft got wrong: one process judges many trees — every fixture in the suite,
/// and any tool driving several checkouts — so a single cached answer would hand
/// the second tree the first tree's toolchain. The map is small and lives for the
/// process, matching how long the answer is good for.
///
/// A poisoned lock answers could-not-look rather than panicking: this is a repair,
/// and a repair that kills the run is worse than one that declines.
#[must_use]
pub fn repaired(root: &Path) -> PinnedFacts {
    // NO RECORD IS NOT A STALE ONE, and this narrowing is what keeps the EAGER
    // repair from being a spawn storm. `cached` answers could-not-look for two
    // very different trees: one whose record stopped validating, and one that
    // simply has none — a fresh clone, and EVERY FIXTURE REPOSITORY. Re-asking
    // the pin in the second case buys nothing HERE, because this is called
    // before a spawn is attempted and so pays on every program of every rule.
    //
    // Measured: without it, a full test binary paid two runner spawns per fixture
    // root — the per-root memo bounds a repeat, not the first ask, and a suite
    // creates hundreds of roots. Concurrent `git commit`s inside those fixtures
    // began failing under the load, at ~50x their isolated duration.
    //
    // **AND AN ABSENT RECORD IS STILL A FAULT — it is simply not THIS entry
    // point's to repair** (CLOUD-1371). The premise this narrowing rested on was
    // written here as "`refresh_pinned` writes the first record at session start",
    // which holds for a record never written and fails for one that STOPS
    // EXISTING mid-session: nothing re-created it, so every pinned program read
    // as absent for the rest of the session. That case is [`re_resolved`]'s, off
    // a spawn that has already failed, where the cost is bounded by rarity
    // instead of by this guard.
    if !record_is_stale(root) {
        return Look::CouldNotLook;
    }
    re_resolved(root)
}

/// [`refresh`] behind the shared per-root memo.
///
/// **Keyed by root rather than a bare once-cell**, which is the part a first
/// draft got wrong: one process judges many trees — every fixture in the suite,
/// and any tool driving several checkouts — so a single cached answer would hand
/// the second tree the first tree's toolchain. The map is small and lives for the
/// process, matching how long the answer is good for.
///
/// A poisoned lock answers could-not-look rather than panicking: this is a repair,
/// and a repair that kills the run is worse than one that declines.
///
/// ONE MEMO FOR BOTH ENTRY POINTS, so a root that asks eagerly and then lazily —
/// or the reverse — still asks the pin once. Two memos would make the bound
/// depend on which door the caller came through.
fn memoised(root: &Path, ask: impl FnOnce(&Path) -> PinnedFacts) -> PinnedFacts {
    static MEMO: std::sync::OnceLock<
        std::sync::Mutex<std::collections::BTreeMap<PathBuf, PinnedFacts>>,
    > = std::sync::OnceLock::new();
    let memo = MEMO.get_or_init(|| std::sync::Mutex::new(std::collections::BTreeMap::new()));
    if let Ok(seen) = memo.lock()
        && let Some(answer) = seen.get(root)
    {
        return answer.clone();
    }
    let resolved = ask(root);
    // A RECORD THAT CANNOT BE REWRITTEN AND CANNOT ANSWER IS GARBAGE, and the
    // repair clears it rather than leaving `doctor` to report it forever.
    //
    // Measured: a container whose ambient `PATH` already carries the pin's shim
    // directory. `resolve` answers could-not-look there BY DESIGN — a program you
    // would have reached anyway is not one the pin supplies — so `refresh` writes
    // nothing, and a record written before that directory was on `PATH` stays on
    // disk keyed to a state that will never recur. `record_is_stale` then reports
    // a fault with no remedy, over a container where every declared program is in
    // fact reachable.
    //
    // Removing it is the honest repair and it costs nothing: the record is
    // engine bookkeeping under `$GIT_DIR`, keyed so a non-matching one is never
    // read, and the next resolvable state writes a fresh one.
    if matches!(resolved, Look::CouldNotLook)
        && let Some(path) = record_path(root)
    {
        // Discarded for `record`'s reason: a file that could not be removed is
        // not a failure to answer. The reading stays could-not-look either way.
        let _removed = std::fs::remove_file(path);
    }
    if let Ok(mut seen) = memo.lock() {
        seen.insert(root.to_owned(), resolved.clone());
    }
    resolved
}

/// Write `programs` as `root`'s record, keyed to `configs` as they stand.
///
/// Public because the alternative is a test that hand-spells the record's
/// format: a fixture writing those bytes itself would pass while the real writer
/// and the real reader disagreed, which is the shape that let a whole suite pass
/// over a receipt no producer could write (CLOUD-1093). One writer, one reader,
/// and the test drives both.
///
/// Returns whether the record was written. A `false` is not an error the caller
/// must handle — the fact simply answers could-not-look next time — but it is the
/// difference between "recorded" and "resolved", and a caller asserting the first
/// should not have to infer it.
#[must_use]
pub fn record(root: &Path, configs: &[PathBuf], programs: &BTreeSet<String>) -> bool {
    let stamps = stamped(configs, crate::cache::now());
    let (Some(key), Some(path)) = (key(configs), record_path(root)) else {
        return false;
    };
    let record = Record {
        key,
        configs: configs.to_vec(),
        programs: programs.clone(),
        stamps,
    };
    let Ok(body) = serde_json::to_string(&record) else {
        return false;
    };
    if let Some(parent) = path.parent()
        && std::fs::create_dir_all(parent).is_err()
    {
        return false;
    }
    crate::durable::replace(path, body).is_ok()
}

/// The files the pin reports as configuring it. Spawns.
///
/// Asked rather than assumed, which is the whole of this module's answer to
/// non-negotiable rule 1: the core learns which files key the answer from the
/// thing that reads them, so no consuming project's artifact name is written
/// here. An empty answer is a real one — a directory the pin does not configure
/// — and produces no key, hence no record.
#[must_use]
pub fn configs(root: &Path) -> Vec<PathBuf> {
    let Some(out) = mediator(root, &["config", "ls", "--json"]) else {
        return Vec::new();
    };
    let Ok(parsed) = serde_json::from_slice::<serde_json::Value>(&out) else {
        return Vec::new();
    };
    parsed
        .as_array()
        .map(|rows| {
            rows.iter()
                .filter_map(|row| row.get("path").and_then(serde_json::Value::as_str))
                .map(PathBuf::from)
                .collect()
        })
        .unwrap_or_default()
}

/// Run the mediator and hand back its stdout, or `None` on any failure.
///
/// One spawn site for both questions this module asks, so the `Cost::Effect`
/// classification has exactly one place to be true of.
fn mediator(root: &Path, args: &[&str]) -> Option<Vec<u8>> {
    #[expect(
        clippy::disallowed_types,
        reason = "stays: this fact IS Cost::Effect — resolving it runs the mediator, which is the classification rather than an accident of it (CLOUD-1028). It is why `cached` exists and why the mediated path never reaches this function"
    )]
    let spawned = std::process::Command::new(MEDIATOR)
        .args(args)
        .current_dir(root)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output()
        .ok()?;
    spawned.status.success().then_some(spawned.stdout)
}

/// The composed environment, as the mediator reports it.
fn composed_path(root: &Path) -> Option<String> {
    let parsed: serde_json::Value =
        serde_json::from_slice(&mediator(root, &["env", "--json"])?).ok()?;
    parsed
        .get("PATH")
        .and_then(serde_json::Value::as_str)
        .map(ToOwned::to_owned)
}

/// Resolve the set by asking the mediator.
fn resolve(root: &Path) -> PinnedFacts {
    let Some(composed) = composed_path(root) else {
        return Look::CouldNotLook;
    };
    let ambient = std::env::var("PATH").unwrap_or_default();
    let added = added_directories(&composed, &ambient);
    // NOTHING ADDED IS COULD-NOT-LOOK, NOT AN EMPTY ANSWER. The honest reading
    // of an identical composed and ambient PATH is that this process is already
    // running under the pin, so the difference cannot see what the pin supplies
    // — which is a failure to look, and reporting it as "the pin provides
    // nothing" would silently disarm every predicate built on this fact.
    if added.is_empty() {
        return Look::CouldNotLook;
    }
    let programs = programs_in(&added);
    if programs.is_empty() {
        Look::CouldNotLook
    } else {
        Look::Is(programs)
    }
}

/// The directories the composed `PATH` has and the ambient one does not.
///
/// Pure, and separated from the spawn for that reason: the interesting decision
/// here is the difference, and a test that had to install a toolchain to reach
/// it would be asserting its own premise (`rules/rust.md`).
fn added_directories(composed: &str, ambient: &str) -> Vec<PathBuf> {
    let already: BTreeSet<&str> = ambient.split(':').filter(|dir| !dir.is_empty()).collect();
    composed
        .split(':')
        .filter(|dir| !dir.is_empty() && !already.contains(dir))
        .map(PathBuf::from)
        .collect()
}

/// The executable regular files in `dirs`, by name.
///
/// The executable bit is read as METADATA, never enforced: this process may well
/// be root, where a permission test decides nothing. What it distinguishes is a
/// program from the `LICENSE` and `README.md` an extracted archive leaves beside
/// one — six of the 49 names on this checkout.
fn programs_in(dirs: &[PathBuf]) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for dir in dirs {
        let Ok(entries) = std::fs::read_dir(dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let Ok(kind) = entry.file_type() else {
                continue;
            };
            // A symlink is followed rather than skipped: a shim directory is
            // links to real binaries, and reading the link as "not a file" would
            // empty the set on exactly the layout the pin most often produces.
            if kind.is_dir() {
                continue;
            }
            if !executable(&entry.path()) {
                continue;
            }
            if let Some(name) = entry.file_name().to_str() {
                out.insert(name.to_owned());
            }
        }
    }
    out
}

/// Does any execute bit stand on this path?
#[cfg(unix)]
fn executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::metadata(path).is_ok_and(|meta| meta.permissions().mode() & 0o111 != 0)
}

/// Windows has no execute bit; a regular file on a `PATH` directory is the
/// closest honest reading, and the alternative — an extension allowlist — is a
/// second authority over what counts as a program.
#[cfg(not(unix))]
fn executable(path: &Path) -> bool {
    std::fs::metadata(path).is_ok_and(|meta| meta.is_file())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// CLOUD-2315: an absent member and a present member holding the absence
    /// token's bytes are two different keys. Unframed, both concatenated to the
    /// same material, so a record keyed over one answered for the other.
    #[test]
    #[expect(
        clippy::expect_used,
        reason = "a fixture that cannot be written is a broken test"
    )]
    fn an_absent_member_never_collides_with_a_present_one() {
        let dir = crate::scratch::scratch("pinned-key");
        std::fs::write(dir.join("a.cfg"), "A").expect("a");
        let configs = vec![dir.join("a.cfg"), dir.join("b.cfg")];
        let absent = key(&configs);
        std::fs::write(dir.join("b.cfg"), "-").expect("b");
        let present = key(&configs);
        assert!(
            absent.is_some() && present.is_some(),
            "one member present keys"
        );
        assert_ne!(absent, present, "absent and present-as-`-` are two answers");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A manifest in a scratch directory, and the moment well past its racy
    /// window that a record "written later" is stamped at.
    #[expect(
        clippy::expect_used,
        reason = "a fixture that cannot be written is a broken test"
    )]
    fn manifest(name: &str) -> (PathBuf, Vec<PathBuf>, std::time::Duration) {
        let dir = crate::scratch::scratch(name);
        std::fs::write(dir.join("mise.toml"), "[tools]\n").expect("manifest");
        let configs = vec![dir.join("mise.toml")];
        let later = crate::cache::now() + std::time::Duration::from_hours(1);
        (dir, configs, later)
    }

    /// CLOUD-2440: unchanged stamps believe the record without the hash — a key
    /// the bytes would refuse still answers, because nothing was read.
    #[test]
    fn a_record_whose_configs_are_unchanged_is_believed_without_reading() {
        let (dir, configs, later) = manifest("pinned-stamped-hit");
        let stamps = stamped(&configs, later);
        assert!(!stamps.is_empty(), "the premise: stamps were recorded");
        assert!(
            still_keyed(&configs, "not-the-key", &stamps),
            "unchanged stamps are believed without recomputing the key"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// An edit after the stamps were taken is a miss, so the key decides.
    #[test]
    #[expect(
        clippy::expect_used,
        reason = "a fixture that cannot be written is a broken test"
    )]
    fn a_config_edited_after_the_record_is_a_miss() {
        let (dir, configs, later) = manifest("pinned-stamped-edited");
        let stamps = stamped(&configs, later);
        std::fs::write(dir.join("mise.toml"), "[tools]\nnode = \"22\"\n").expect("edit");
        assert!(
            !still_keyed(&configs, "not-the-key", &stamps),
            "an edited manifest falls through to the key, which refuses"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Stamps taken within a timestamp tick of the files' last change are not
    /// recorded: a second change in that tick would not show in them.
    #[test]
    fn a_record_stamped_in_its_racy_window_is_hashed() {
        let (dir, configs, _) = manifest("pinned-stamped-racy");
        let stamps = stamped(&configs, crate::cache::now());
        assert!(
            !still_keyed(&configs, "not-the-key", &stamps),
            "racy stamps are not recorded, so the key decides"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_program_is_reached_through_the_mediators_exec() {
        assert_eq!(
            mediated("tool"),
            (
                "mise",
                vec!["exec".to_owned(), "--".to_owned(), "tool".to_owned()]
            )
        );
    }

    /// A config keys itself and the FILES beside it sharing its stem, never a
    /// directory of that stem and never an unrelated file.
    #[test]
    #[expect(
        clippy::expect_used,
        reason = "a fixture that cannot be written is a broken test"
    )]
    fn a_config_keys_the_files_sharing_its_stem_and_nothing_else() {
        let dir = crate::scratch::scratch("pinned-keyed-paths");
        for file in ["tool.toml", "tool.lock", "other.txt"] {
            std::fs::write(dir.join(file), file).expect("file");
        }
        std::fs::create_dir_all(dir.join("tool.d")).expect("dir");
        assert_eq!(
            keyed_paths(&[dir.join("tool.toml")]),
            BTreeSet::from([dir.join("tool.lock"), dir.join("tool.toml")])
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Only an executable regular file is a program: not the README an archive
    /// leaves beside one, and not a directory.
    #[test]
    #[expect(
        clippy::expect_used,
        reason = "a fixture that cannot be written is a broken test"
    )]
    fn only_an_executable_file_is_a_program() {
        let dir = crate::scratch::scratch("pinned-programs-in");
        // A copy keeps its source's mode, so copying a small system executable
        // needs no platform's permission API. Off unix every regular file is a
        // program, so any bytes will do.
        if cfg!(unix) {
            std::fs::copy("/bin/sh", dir.join("tool")).expect("copy");
        } else {
            std::fs::write(dir.join("tool"), "x").expect("tool");
        }
        std::fs::write(dir.join("README"), "read me").expect("readme");
        std::fs::create_dir_all(dir.join("sub")).expect("dir");
        let expected: BTreeSet<String> = if cfg!(unix) {
            BTreeSet::from(["tool".to_owned()])
        } else {
            BTreeSet::from(["README".to_owned(), "tool".to_owned()])
        };
        assert_eq!(programs_in(std::slice::from_ref(&dir)), expected);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The eager repair repairs a stale record: afterwards it is gone or fresh,
    /// never still stale.
    #[test]
    #[expect(
        clippy::expect_used,
        reason = "a fixture that cannot be written is a broken test"
    )]
    fn a_stale_record_does_not_survive_its_repair() {
        let root = crate::scratch::scratch("pinned-repaired");
        crate::gitwrite::init_on_main(&root).expect("init");
        let config = root.join("pin.toml");
        std::fs::write(&config, "before").expect("config");
        assert!(record(
            &root,
            std::slice::from_ref(&config),
            &BTreeSet::from(["tool".to_owned()])
        ));
        std::fs::write(&config, "after").expect("config");
        assert!(record_is_stale(&root), "the premise: the record is stale");
        let _ = repaired(&root);
        assert!(!record_is_stale(&root));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn the_difference_is_what_the_pin_adds() {
        let added = added_directories("/pin/bin:/usr/bin:/tests/bats/bin", "/usr/bin");
        assert_eq!(
            added,
            vec![PathBuf::from("/pin/bin"), PathBuf::from("/tests/bats/bin")]
        );
    }

    #[test]
    fn an_ambient_directory_is_never_added() {
        // `cargo`'s directory is on both here, which is why the fact does not
        // carry cargo and `no-bare-cargo` still does.
        assert!(added_directories("/root/.cargo/bin", "/root/.cargo/bin:/usr/bin").is_empty());
    }

    #[test]
    fn an_empty_component_is_not_a_directory() {
        // A trailing or doubled `:` is a real spelling of PATH and means "this
        // directory", which is not something the pin added.
        assert!(added_directories(":", "").is_empty());
        assert_eq!(
            added_directories("/pin/bin::", ""),
            vec![PathBuf::from("/pin/bin")]
        );
    }
}
