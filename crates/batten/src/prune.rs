//! Reclaim superseded build artifacts, and refuse below a measured disk floor
//! (CLOUD-766, CLOUD-861, CLOUD-1030).
//!
//! # What it reclaims, and what it deliberately will not
//!
//! Cargo keys every artifact on a metadata hash and never reclaims a superseded
//! one. A `land` lap rebases, which mints a new SHA, which changes the hash,
//! which writes a fresh copy of every integration-test binary while all previous
//! copies stay. Growth is monotonic and nothing bounded it. Measured 2026-08-20:
//! `target/` 26 GB, 283 files over 40 MB under `deps` totalling 16.6 GB, ~41
//! distinct stems retaining 6 copies each, 13.2 GB reclaimable at no rebuild
//! cost.
//!
//! **This is not `cargo clean`, and the distinction is the whole task.** `clean`
//! takes the caches too, and those REGROW — a session that cleans pays a full
//! rebuild and is back at the wall a lap later, measured twice before this
//! existed. The rule is *keep what the next build will read, delete what it will
//! not*.
//!
//! **`keep` is 2 rather than 1, and it is a hedge with a stated cost.** The
//! newest artifact per stem is what the current build reads; the one before it is
//! what a rebase that reverts would otherwise rebuild from scratch. Keeping two
//! costs one copy per stem and buys back the common undo.
//!
//! # The group key is `(stem, kind)`, and both halves are load-bearing
//!
//! CLOUD-1157. The predecessor split a filename on its last `-` and required the
//! tail to be all hex, so `libbatten-42061777d57a0311.rlib` produced a "hash" of
//! `42061777d57a0311.rlib`, failed on the `.`, and became **its own stem**. Every
//! extensioned artifact was therefore a group of one, and nothing in a group of
//! one is ever past `keep`: `.rlib`, `.rmeta` and `.so` were unreachable however
//! many copies accumulated. Measured in one `deps` directory, 2026-08-29: 794.7 MB
//! of `.rlib` over 270 files, 345.2 MB of `.rmeta` over 644, 171.1 MB of `.so`
//! over 20 — against 315.7 MB of extension-less executables, the only class the
//! pass could see.
//!
//! So the header used to say `.d`, `.rlib` and `.rmeta` "are left alone: they are
//! small, and a dangling one only makes cargo rebuild". **The first half is
//! refuted** — `.rmeta` is the fastest-accumulating class in the tree, because
//! `check` and `clippy` write metadata every lap without producing a binary. The
//! second half is why the reclaim is safe rather than why it is narrow, and it
//! still holds.
//!
//! **The extension must not collapse into the stem**, which is the correction that
//! makes this a `(stem, kind)` key rather than a wider `stem_of`. `libbatten`
//! carries 2 `.rlib` and 6 `.rmeta`; one group of eight under `keep = 2` can
//! retain two `.rmeta` and delete the **live** `.rlib` — the `keep = 0` failure
//! [`Prune::validate`] already refuses, arriving through the grouping instead of
//! through the count. Retention is therefore per kind.
//!
//! `.d` stays out, and that is a measurement rather than caution: 2.8 MB across
//! 666 files, which is below the noise of everything else here.
//!
//! # Two floors, because the escalation changes which one applies
//!
//! CLOUD-1030, and it is the defect this module was ported to fix. The
//! predecessor declared ONE floor — `worst-lap=6242mb x1`, measured over a
//! **warm** lap — and moved its safety factor into the escalation, the branch
//! that drops the incremental cache when free space is short.
//!
//! But dropping `incremental` is precisely what makes the next build COLD. So
//! the floor was certified against a basis the reclaim it depends on had just
//! destroyed: the escalation bought headroom now and enlarged the very demand
//! the headroom was sized against.
//!
//! So there are two, they are measured separately, and neither is a scaled
//! version of the other:
//!
//! - **warm** — a lap whose incremental cache survives.
//! - **cold** — a lap that has to rebuild from nothing, which is what the
//!   escalation guarantees.
//!
//! **Which floor is in force is a consequence, never a setting.** It is the warm
//! one until the escalation runs and the cold one afterwards, because that is
//! when the next build's basis actually changes. Both numbers and both
//! measurement dates are the consumer's, declared in `[prune]` — which project
//! this is decides how big its build is, and that is not the core's to know.
//!
//! # The escalation's roots are declared, and each says whether it moves the basis
//!
//! CLOUD-1157's other half. The escalation used to know one directory name,
//! `incremental`, written into this crate — so `target/semver-checks` (2.6 GB
//! measured), `target/perf` (401 MB), `target/debug/build` (156 MB) and
//! `target/flycheck*` were outside the walk entirely, on any tree. They are caches
//! of `incremental`'s exact kind: regrowable, unbounded, and superseded by
//! nothing, so no retention rule can ever reach them.
//!
//! Which directories a build tree grows is a fact about THIS project, so the list
//! is `[prune.regrowable]` and not a constant here (non-negotiable rule 1).
//!
//! **Each row declares whether dropping it moves the basis, because they do not
//! all cost the same thing.** [`Basis::Cold`] means the next **cargo** build is
//! full, and the cold floor is budgeted for precisely that. Dropping `incremental`
//! or `build` creates that demand; dropping `semver-checks`, `perf` or `flycheck*`
//! makes only *their own* next run cold and leaves the cargo build warm — so
//! marking those `cold` would judge the lap against a demand that never arrives,
//! which is over-refusal wearing the shape of caution.
//!
//! # `df` is the quantity that binds, and that was tested rather than assumed
//!
//! CLOUD-1030's body argues the floors should read "the session's writable
//! allowance" rather than device free space, on the grounds that `df` reports a
//! number that "cannot refuse". **Probed on this container, 2026-08-29, and it
//! refuses:** with `df` reporting 3419 MB available, a 2735 MB allocation
//! succeeded and a 10257 MB allocation failed with `No space left on device`.
//! The single observation behind that clause — 21041 MB reported free during an
//! active exhaustion — is a concurrent run consuming the space between two
//! readings, not a blind instrument.
//!
//! So the floors read `df`, and the clause is refuted on the row rather than
//! designed around. A host where the allowance and the device genuinely disagree
//! would be a new measurement and a new mechanism.
//!
//! # The refusal is the point (CLOUD-766's second half)
//!
//! Exhaustion does not announce itself as a disk problem. It arrives as a rustc
//! IO error inside a test run, under a `land` line saying "verify failed on
//! <sha> — reproduce and fix locally", which sends an author after a defect in
//! their own diff that does not exist. A named refusal, before anything is
//! spent, is what stops the misattribution.
//!
//! # The effect class
//!
//! `Cost::Effect` on `Surface::VerifyOnly`, and `Effect::Destructive` on the
//! verb — the row `capture prune` already carries, for the same reason: what it
//! removes is recoverable only by re-running the work. None of it may ever be
//! reachable from the mediated call.
//!
//! Pointer-only per non-negotiable rule 4: a file count, bytes, the floor, and
//! which floor. Never a path listing — that is unbounded, and a caller who wants
//! one can run `du`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::error::UsageError;

/// The `[prune]` table: what this project's build costs, and what to keep.
///
/// CONSUMER CONFIG, NOT A CONST, and non-negotiable rule 1 is the reason as much
/// as taste is: how many megabytes a full rebuild writes is a fact about THIS
/// project, and the predecessor carried it as a shell variable inside the program
/// that enforced it. Declaring it means the engine validates the arithmetic at
/// load — which is what the predecessor's runtime self-parse was reaching for,
/// one tier earlier and without a program reading its own source.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Prune {
    /// The build directory, relative to the repository root.
    #[serde(default = "default_root")]
    pub root: String,
    /// Copies retained per stem. See the module header for why this is 2.
    ///
    /// The bound is in the SCHEMA as well as in [`Prune::validate`] (raised on
    /// #734): an editor validating against the published schema is the surface
    /// most consumers meet first, and one that accepts `keep = 0` there and
    /// refuses it at load teaches the wrong bound at the cheaper moment.
    #[serde(default = "default_keep")]
    #[schemars(range(min = 1))]
    pub keep: usize,
    /// What a lap needs when its incremental cache survives.
    pub warm: Floor,
    /// What a lap needs after the escalation has dropped that cache.
    pub cold: Floor,
    /// The regrowable roots the escalation may drop, in the order it drops them.
    ///
    /// Empty by default rather than defaulting to `incremental`: a default here
    /// would be this crate holding a fact about somebody else's build tree, which
    /// is the constant CLOUD-1157 removed wearing a different hat. A repository
    /// that declares none simply has no escalation — its floor is judged over
    /// whatever the superseded pass reclaimed.
    #[serde(default)]
    pub regrowable: Vec<Regrowable>,
}

/// One regrowable root, and what dropping it costs.
///
/// Regrowable, never superseded: nothing supersedes a cache, so no retention rule
/// can reach one and the only honest reclaim is "drop it whole, and only when the
/// floor is already breached".
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Regrowable {
    /// The directory NAME, matched anywhere under the root — never a path.
    ///
    /// A single trailing `*` makes it a prefix, which is what `flycheck*` needs:
    /// rust-analyzer numbers a directory per instance, so the set is open and no
    /// enumeration of it stays true. Anything richer is a glob language, and this
    /// key does not need one.
    pub name: String,
    /// Whether dropping this root makes the next CARGO build a full one.
    ///
    /// The basis is a consequence of what was reclaimed, so this is the row's
    /// answer to "does the cold floor now apply", not a preference.
    pub cold: bool,
}

fn default_root() -> String {
    String::from("target")
}

const fn default_keep() -> usize {
    2
}

/// One floor, and the measurement that justifies it.
///
/// The basis travels WITH the number, in the shape `timeout-check` uses for
/// workflow jobs and `mcp-timeout-budget` for the MCP startup budget (CLOUD-266).
/// A limit with no recorded measurement is boilerplate, and a stale measurement
/// reads exactly like a fresh one — which is why the date is required rather than
/// commentary.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Floor {
    /// The floor itself, in megabytes.
    pub mb: u64,
    /// The worst lap this basis was measured over, in megabytes.
    pub worst_mb: u64,
    /// The safety factor applied to it.
    #[serde(default = "default_multiplier")]
    pub multiplier: u64,
    /// When the worst lap was measured, `YYYY-MM-DD`.
    pub measured: String,
}

const fn default_multiplier() -> u64 {
    1
}

impl Prune {
    /// Validate the table at load.
    ///
    /// # Errors
    ///
    /// When a floor disagrees with the basis it declares, when a date is not a
    /// date, or when the cold floor is not above the warm one — which would mean
    /// the escalation makes the next build cheaper, and is the shape of a number
    /// somebody copied rather than measured.
    pub fn validate(&self) -> Result<()> {
        for (name, floor) in [("warm", &self.warm), ("cold", &self.cold)] {
            floor.validate(name)?;
        }
        if self.cold.mb <= self.warm.mb {
            return Err(UsageError::raise(format!(
                "[prune]: the cold floor ({}MB) is not above the warm one ({}MB) — the escalation drops the incremental cache, so a cold lap cannot need less. A cold floor at or below the warm one is a number copied rather than measured, and it would make the second floor decide nothing.",
                self.cold.mb, self.warm.mb
            )));
        }
        if self.keep == 0 {
            return Err(UsageError::raise(
                "[prune]: `keep = 0` deletes the artifact the next build reads, which is a clean rather than a prune",
            ));
        }
        for root in &self.regrowable {
            root.validate()?;
        }
        Ok(())
    }
}

impl Regrowable {
    /// Validate one declared root at load.
    ///
    /// The refusals are all about the same failure: a name that is not a name.
    /// `remove_dir_all` is what runs at the far end of this key, so a declaration
    /// that means something wider than its author thinks is the one class worth
    /// refusing before anything is spent. A bare `*` matches every directory under
    /// the root, which is `cargo clean` spelled as a prefix.
    fn validate(&self) -> Result<()> {
        let refuse = |why: String| Err(UsageError::raise(format!("[prune.regrowable]: {why}")));
        if self.name.is_empty() {
            return refuse(
                "a root with an empty `name` matches nothing and reads as an oversight".to_owned(),
            );
        }
        if self.name == "*" {
            return refuse(
                "`name = \"*\"` matches every directory under the root, which is a clean rather than a reclaim"
                    .to_owned(),
            );
        }
        if self.name.contains('/') || self.name.contains('\\') {
            return refuse(format!(
                "`{}` is a path, and this key is a directory NAME matched anywhere under the root",
                self.name
            ));
        }
        if self.name.trim_end_matches('*').contains('*') || self.name.ends_with("**") {
            return refuse(format!(
                "`{}` uses `*` as a glob — the only wildcard here is a single trailing one, which makes the name a prefix",
                self.name
            ));
        }
        Ok(())
    }
}

impl Floor {
    fn validate(&self, name: &str) -> Result<()> {
        // `checked_mul`, NOT `saturating_mul` (raised on #734). Saturating makes
        // the check agree with itself on a declaration it should refuse:
        // `worst_mb = u64::MAX, multiplier = 2` saturates to `u64::MAX`, which
        // equals an `mb` of `u64::MAX` — so a floor whose stated basis does not
        // and cannot produce it passes the one assertion that exists to catch
        // exactly that.
        let Some(basis) = self.worst_mb.checked_mul(self.multiplier) else {
            return Err(UsageError::raise(format!(
                "[prune.{name}]: the declared basis overflows — {} x{} is not a number of megabytes any disk has",
                self.worst_mb, self.multiplier
            )));
        };
        if self.mb != basis {
            return Err(UsageError::raise(format!(
                "[prune.{name}]: the floor disagrees with the basis it declares — {}MB against {} x{} = {basis}MB",
                self.mb, self.worst_mb, self.multiplier
            )));
        }
        if !is_a_calendar_date(&self.measured) {
            return Err(UsageError::raise(format!(
                "[prune.{name}]: `measured` is not a YYYY-MM-DD date, so the floor carries no recorded measurement"
            )));
        }
        Ok(())
    }
}

/// Whether `text` is a `YYYY-MM-DD` date that actually happened.
///
/// The CALENDAR and not only the shape (raised on #734): `2026-02-31` matches
/// the character pattern and names no day, and the whole point of this field is
/// that a reader can go and ask what was measured then. A date nobody could have
/// taken a measurement on is the same defect as a missing one, wearing a shape
/// that passes.
///
/// Hand-rolled rather than a date crate, because this is the only date this
/// engine parses and a dependency for one field is a dependency the whole
/// workspace then carries.
fn is_a_calendar_date(text: &str) -> bool {
    let bytes = text.as_bytes();
    if bytes.len() != 10 || bytes[4] != b'-' || bytes[7] != b'-' {
        return false;
    }
    let field = |from: usize, to: usize| text.get(from..to)?.parse::<u32>().ok();
    let (Some(year), Some(month), Some(day)) = (field(0, 4), field(5, 7), field(8, 10)) else {
        return false;
    };
    // Proleptic Gregorian, which is what a `YYYY-MM-DD` string means and what
    // every date this field will ever carry is written in.
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let last = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return false,
    };
    (1..=last).contains(&day)
}

/// The seam a suite needs to set free space exactly as it sets the tree.
///
/// CLOUD-778, and it is the root override's twin: free space is an INPUT to the
/// floor decision, so without this a suite claims a hermeticity it does not have
/// and every case asserting a successful run is answered by how full the host's
/// disk happens to be. Measured twice — once as a case that flipped across two
/// readings minutes apart with no fixture change, once as nine cases going red in
/// CI at a single floor change.
///
/// **A COMMA-SEPARATED SEQUENCE, not one number, and CLOUD-1030 is why.** A run
/// reads free space up to twice — once before the escalation and once after it —
/// and the whole defect being repaired lives in the gap between those two
/// readings. A single-valued seam makes the second reading equal the first, which
/// is a fixture in which the escalation reclaims nothing: the discriminating case
/// (a lap that clears the warm floor only BECAUSE the reclaim ran, and is then
/// judged against the cold one) is not expressible at all. So the value is the
/// readings this run will see, in order, and the last one repeats — which keeps
/// every single-valued caller meaning exactly what it meant before.
const FREE_MB_VAR: &str = "TARGET_PRUNE_FREE_MB";

/// The free-space readings one run takes, in the order it takes them.
///
/// A struct rather than a function called twice, because "how many readings have
/// been taken" is state, and the only honest place for it is the run that takes
/// them. A thread-local counter would be the same state one scope wider, where a
/// second run in the same process inherits it.
struct Readings {
    /// The declared sequence, or `None` where the volume is the authority.
    declared: Option<Vec<u64>>,
    /// How many readings this run has already taken.
    taken: usize,
}

impl Readings {
    /// Read the declaration, or defer to the volume.
    fn declare() -> Result<Self> {
        let Ok(raw) = std::env::var(FREE_MB_VAR) else {
            return Ok(Readings {
                declared: None,
                taken: 0,
            });
        };
        let declared = raw
            .split(',')
            .map(|field| {
                field.trim().parse::<u64>().with_context(|| {
                    format!("target-prune: {FREE_MB_VAR} is not a comma-separated list of numbers")
                })
            })
            .collect::<Result<Vec<u64>>>()?;
        if declared.is_empty() {
            bail!("target-prune: {FREE_MB_VAR} declares no reading");
        }
        Ok(Readings {
            declared: Some(declared),
            taken: 0,
        })
    }

    /// The next reading, in megabytes.
    fn take(&mut self, path: &Path) -> Result<u64> {
        let Some(declared) = self.declared.as_ref() else {
            return available_megabytes(path);
        };
        // The last reading REPEATS rather than running out. A sequence shorter
        // than the run is a fixture that said "the number stops moving here",
        // which is what a single value has always meant; an error would make
        // every existing one-value caller depend on the reading count.
        let index = self.taken.min(declared.len() - 1);
        self.taken += 1;
        Ok(declared[index])
    }
}

/// Where the lap journal lives, and what to record the lap against.
///
/// A struct rather than two parameters because they are one thing — "this run is
/// part of a repository's lap history" — and because the absence of that history
/// is the honest state on a checkout with no `.git`, where `Option<LapStore>` says
/// so and a pair of `Option`s would let one be present without the other.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LapStore {
    /// `$GIT_DIR`, beside `batten-receipts/` for that store's own reasons: out of
    /// the tree, per checkout, and gone when the checkout is.
    pub git_dir: PathBuf,
    /// The commit this run sees, so a recorded lap points at something.
    pub head: String,
}

/// The lap journal: the lap now open, and the worst consumption ever observed.
///
/// # Why a journal at all (CLOUD-861)
///
/// The floor used to be a PRECONDITION — read once, at the head of `verify`,
/// answering "is there room to begin". Nothing re-read during the phase that
/// actually consumes the disk, so a build whose growth exceeded the headroom the
/// check had just certified was structurally invisible. Measured three times in
/// one session: the prune passed at 6242MB free, the `cargo test` link step
/// inside the same lap took all of it, and the exhaustion arrived as
/// `rustc-LLVM ERROR: IO failure on output stream` under a `land` line telling
/// the author to fix their own diff.
///
/// So the reading at the end of the lap is what makes the floor an INVARIANT: the
/// same verb runs at both boundaries, the second run closes what the first
/// opened, and a lap that ended below the floor it was admitted under is refused
/// there rather than discovered by the next one.
///
/// # And the basis ratchets, because a hand-declared one goes stale silently
///
/// `[prune.warm].worst_mb` was `x1` — the floor was exactly the worst lap somebody
/// wrote down, so a lap merely equalling it breached by construction, and a
/// measurement taken once reads exactly like a fresh one forever. The journal
/// records what a lap ACTUALLY consumed and raises the floor to it. The declared
/// number becomes the seed and a lower bound rather than the whole answer.
///
/// # One file, rewritten by rename, holding two records rather than a history
///
/// CLOUD-1032's class — a half-record from an interrupted append makes the whole
/// file unparseable — is unwritable here: the file is written to a temporary
/// beside it and `rename`d over, so a reader sees the old bytes or the new ones.
/// It stays bounded because nothing accumulates: one open lap, and one observed
/// worst per basis.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
struct LapJournal {
    /// The lap awaiting its closing reading, if a run opened one.
    open: Option<OpenLap>,
    /// The worst consumption observed, per basis.
    ratchet: Ratchet,
}

/// A lap that has been admitted and not yet closed.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct OpenLap {
    /// Free megabytes when it opened, after that run's reclaim.
    free_mb: u64,
    /// Which basis the lap opened under.
    ///
    /// NO `floor_mb` BESIDE IT, and its absence is a repair rather than an
    /// omission. Carrying "the floor it was admitted under" made the journal a
    /// SECOND authority on a number the ratchet already answers: between an open
    /// and its close nothing else writes this file, so the recorded floor could
    /// only ever equal what the closing run recomputes. Measured as a surviving
    /// mutation — blanking the recorded floor changed no verdict, which is the
    /// only way a redundant conjunct announces itself.
    basis: String,
    /// The commit it opened on.
    head: String,
    /// The day it opened, `YYYY-MM-DD`.
    measured: String,
}

/// The observed worst consumption, per basis.
///
/// PER BASIS, never one number: a warm lap's consumption is a statement about an
/// incremental build and says nothing about what a cold one writes, so folding
/// them together would raise the warm floor by a cold lap's demand and refuse
/// every ordinary lap after one escalation.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
struct Ratchet {
    /// The worst warm lap seen.
    warm: Option<Observed>,
    /// The worst cold lap seen.
    cold: Option<Observed>,
}

/// One observation, and the lap that produced it.
///
/// The lap travels WITH the number for [`Floor`]'s reason: a limit whose basis a
/// reader cannot go and look at is boilerplate, and here the basis is not a
/// human's note but a lap that actually ran.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Observed {
    /// Megabytes that lap consumed.
    mb: u64,
    /// The commit it ran on.
    head: String,
    /// The day it ran, `YYYY-MM-DD`.
    measured: String,
}

impl Ratchet {
    /// What this basis has been observed to cost, if anything.
    fn of(&self, basis: Basis) -> Option<&Observed> {
        match basis {
            Basis::Warm => self.warm.as_ref(),
            Basis::Cold => self.cold.as_ref(),
        }
    }

    /// Raise this basis to `observed` if it is worse than what stands.
    fn raise(&mut self, basis: Basis, observed: Observed) -> bool {
        let slot = match basis {
            Basis::Warm => &mut self.warm,
            Basis::Cold => &mut self.cold,
        };
        if slot
            .as_ref()
            .is_some_and(|standing| standing.mb >= observed.mb)
        {
            return false;
        }
        *slot = Some(observed);
        true
    }
}

impl LapJournal {
    /// The journal's path under `$GIT_DIR`.
    fn path(git_dir: &Path) -> PathBuf {
        git_dir.join("batten-prune").join("laps.json")
    }

    /// Read it, or start empty.
    ///
    /// An unreadable or unparseable journal reads as EMPTY rather than as an
    /// error, and the report says so. The alternative directions are both worse:
    /// failing stops `verify` over a scratch file no commit depends on, and
    /// staying silent would let a lap history vanish with nothing said.
    fn read(git_dir: &Path) -> (Self, bool) {
        let path = Self::path(git_dir);
        let Ok(raw) = std::fs::read_to_string(&path) else {
            return (Self::default(), false);
        };
        serde_json::from_str(&raw).map_or_else(|_| (Self::default(), true), |read| (read, false))
    }

    /// Write it by rename, so a reader sees whole bytes or none.
    ///
    /// # Errors
    ///
    /// When the store cannot be created or written. A journal that cannot be
    /// recorded is a lap nothing will close, so this fails rather than passing —
    /// the same call `verify` already makes about its own receipt.
    fn write(&self, git_dir: &Path) -> Result<()> {
        let path = Self::path(git_dir);
        let store = path.parent().unwrap_or(git_dir);
        std::fs::create_dir_all(store)
            .with_context(|| format!("target-prune: create the lap journal {}", store.display()))?;
        let rendered =
            serde_json::to_string(self).context("target-prune: render the lap journal")?;
        let staged = path.with_extension("json.writing");
        std::fs::write(&staged, rendered)
            .with_context(|| format!("target-prune: write the lap journal {}", staged.display()))?;
        std::fs::rename(&staged, &path)
            .with_context(|| format!("target-prune: replace the lap journal {}", path.display()))
    }
}

/// Which boundary of a lap this run stood at.
///
/// DERIVED FROM THE JOURNAL rather than declared by a flag, so it cannot disagree
/// with what happened: a run that found an open lap closed one, and a run that did
/// not opened the first.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    /// No lap was open: this run admits one.
    LapOpen,
    /// A lap was open: this run closed it and admitted the next.
    LapClose,
}

impl Phase {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Phase::LapOpen => "lap-open",
            Phase::LapClose => "lap-close",
        }
    }
}

/// What a closed lap turned out to cost.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Consumed {
    /// Megabytes the lap consumed, reclaim included.
    pub mb: u64,
    /// The commit the lap opened on.
    pub head: String,
    /// The day it opened.
    pub measured: String,
    /// Whether this observation raised the floor for its basis.
    pub raised: bool,
}

/// Where the floor in force came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FloorSource {
    /// The `[prune]` table's declared number, unmoved by observation.
    Declared,
    /// A lap that was observed to cost more than the declaration.
    Observed {
        /// The commit that lap ran on.
        head: String,
        /// The day it ran.
        measured: String,
    },
}

/// Which basis the floor in force was measured against.
///
/// A consequence of whether the escalation ran, never a setting. An enum rather
/// than a bool so the report can name it, which is what CLOUD-1030's §5 asks for:
/// a number alone cannot say why it is that number.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Basis {
    /// The incremental cache survived, so the next build is incremental.
    Warm,
    /// The escalation dropped the incremental cache, so the next build is full.
    Cold,
}

impl Basis {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Basis::Warm => "warm",
            Basis::Cold => "cold",
        }
    }
}

/// What the prune did, and what it decided.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    /// Superseded artifacts removed.
    pub pruned: usize,
    /// Megabytes those artifacts held.
    pub reclaimed_mb: u64,
    /// Megabytes the escalation reclaimed, or `None` where it did not run.
    pub escalated_mb: Option<u64>,
    /// Megabytes free after everything this run reclaimed.
    pub free_mb: u64,
    /// The floor in force.
    pub floor_mb: u64,
    /// The basis that floor was measured against.
    pub basis: Basis,
    /// Whether the default root simply has not been built yet.
    ///
    /// Carried rather than inferred from `pruned == 0`, which is a different
    /// claim: an unbuilt tree and a tree with nothing superseded both reclaim
    /// nothing, and only one of them means the caller should stop looking for a
    /// reclaim that did not happen. Measured 2026-08-25, when conflating an
    /// unbuilt tree with a wrong directory made `verify` unrunnable on a fresh
    /// clone for three consecutive laps.
    pub unbuilt: bool,
    /// Which boundary of a lap this run stood at (CLOUD-861).
    pub phase: Phase,
    /// What the lap this run closed turned out to cost, where it closed one.
    pub consumed: Option<Consumed>,
    /// Where the floor in force came from.
    pub floor_source: FloorSource,
    /// Whether a lap journal was there and could not be read.
    ///
    /// Reported rather than swallowed: a run that silently started a fresh
    /// history looks exactly like the first run on a new checkout, and the whole
    /// point of the ratchet is that its basis is auditable.
    pub journal_unreadable: bool,
}

impl Outcome {
    /// Whether the tree is above the floor that now applies.
    #[must_use]
    pub const fn clears_the_floor(&self) -> bool {
        self.free_mb >= self.floor_mb
    }

    /// The report line. Pointer-only: counts, bytes, and the floor's own basis.
    #[must_use]
    pub fn report(&self) -> String {
        let mut line = String::new();
        if self.journal_unreadable {
            line.push_str(
                "target-prune: the lap journal could not be read, so this run starts a fresh lap history and the declared floors are the only basis\n",
            );
        }
        if self.unbuilt {
            line.push_str(
                "target-prune: nothing built at the configured root yet, so nothing to prune — the floor below is still judged\n",
            );
        }
        let counted = format!(
            "target-prune: {} {} superseded artifact(s) removed, {}MB reclaimed, {}MB free ({} floor {}MB{})",
            self.phase.as_str(),
            self.pruned,
            self.reclaimed_mb,
            self.free_mb,
            self.basis.as_str(),
            self.floor_mb,
            self.floor_provenance()
        );
        line.push_str(&counted);
        // THE CLOSED LAP'S OWN NUMBER, on its own line and only where a lap was
        // closed. This is the quantity the floor is supposed to be about, and
        // until CLOUD-861 nothing in the system had ever printed it: the floor was
        // a hand-declared `worst_mb` that no run could confirm or refute.
        if let Some(consumed) = &self.consumed {
            line.push('\n');
            line.push_str(&format!(
                "target-prune: the lap opened on {} ({}) consumed {}MB",
                consumed.head, consumed.measured, consumed.mb
            ));
            if consumed.raised {
                line.push('\n');
                line.push_str(&format!(
                    "target-prune: that is worse than any {} lap on record, so the observed {} floor rises to {}MB from the next lap",
                    self.basis.as_str(),
                    self.basis.as_str(),
                    consumed.mb
                ));
            }
        }
        if let Some(dropped) = self.escalated_mb {
            // A SECOND LINE RATHER THAN A CLAUSE ON THE FIRST, because the two
            // say different things: the first is what was reclaimed, the second
            // is what the reclaim did to the BASIS. A reader who sees the cold
            // floor named above and no reason for it would have to know this
            // module to guess.
            //
            // TWO SHAPES, because CLOUD-1157's roots do not all cost the same
            // thing: a warm-basis escalation is not a quieter version of a cold
            // one, it is the case where the floor deliberately did NOT move, and
            // saying only "dropped" would leave a reader to infer the stricter
            // reading that does not apply.
            let escalated = match self.basis {
                Basis::Cold => format!(
                    "target-prune: escalated below the warm floor — {dropped}MB of regrowable cache dropped, and one of those roots is the cargo build's own basis, so the next build is COLD and the cold floor is what now applies"
                ),
                Basis::Warm => format!(
                    "target-prune: escalated below the warm floor — {dropped}MB of regrowable cache dropped; none of those roots is the cargo build's basis, so the next build is still warm and the warm floor is what applies"
                ),
            };
            line.push('\n');
            line.push_str(&escalated);
        }
        line
    }

    /// Where the floor in force came from, as a clause or nothing.
    ///
    /// EMPTY FOR A DECLARED FLOOR, so the ordinary line is the line it always
    /// was. The clause appears exactly when the number stopped being the one in
    /// `batten.toml` — which is the moment a reader needs to be told, and the
    /// moment a hand-declared basis would have gone quiet.
    fn floor_provenance(&self) -> String {
        match &self.floor_source {
            FloorSource::Declared => String::new(),
            FloorSource::Observed { head, measured } => {
                format!(", observed on {head} ({measured}) rather than declared")
            }
        }
    }

    /// The refusal, naming the floor in force and why it is that one.
    #[must_use]
    pub fn refusal(&self, root: &Path) -> String {
        let because = match self.basis {
            Basis::Warm => {
                "nothing left to reclaim that would change the basis — the regrowable roots `[prune]` declares are already gone, were never there, or none of them is the cargo build's own"
            }
            Basis::Cold => {
                "the escalation dropped the incremental cache, so the next build is a full rebuild and the cold floor is what it has to fit in"
            }
        };
        // WHICH BOUNDARY THIS IS, first, because the two refusals mean different
        // things to the reader. `lap-open` is the precondition the floor has
        // always been — there is not room to begin. `lap-close` is CLOUD-861's
        // whole point: there WAS room to begin, the phase in between spent it,
        // and the run that certified the headroom is the one now reporting that
        // it was not enough.
        let boundary = match self.phase {
            Phase::LapOpen => {
                "no lap was open, so this is the precondition: there is not room to begin"
            }
            Phase::LapClose => {
                "this is the CLOSING reading of a lap that was admitted above the floor — the phase in between consumed the headroom that admission certified, which is the failure a once-per-lap precondition cannot see"
            }
        };
        let lap = self.consumed.as_ref().map_or_else(String::new, |consumed| {
            format!(
                "\n  lap opened on {} ({}), consumed {}MB",
                consumed.head, consumed.measured, consumed.mb
            )
        });
        format!(
            "target-prune: below the measured {basis} disk floor, and {because}\n  {boundary}\n  free {free}MB\n  floor {floor}MB ({basis} basis{provenance}){lap}\n  A build started here fails as a rustc IO error inside a test run, which reads as a suite regression rather than a full disk. Free space outside {root}, or start a fresh session.",
            basis = self.basis.as_str(),
            free = self.free_mb,
            floor = self.floor_mb,
            provenance = self.floor_provenance(),
            root = root.display()
        )
    }
}

/// Reclaim, escalate if the warm floor is breached, then judge against the floor
/// that now applies.
///
/// # Errors
///
/// Could-not-look: a named root that is absent, a cwd that is not a workspace
/// root, or free space that cannot be read. Each is a property of the checkout
/// rather than a verdict about the tree, and reporting one as a clean prune is
/// the silent false green this repository treats as worse than no gate.
pub fn prune(
    root: &Path,
    config: &Prune,
    named: bool,
    store: Option<&LapStore>,
) -> Result<Outcome> {
    // NO BUILD DIRECTORY IS "could not look", never "nothing to prune" — but a
    // tree that has never been BUILT is not a wrong directory, and conflating the
    // two made `verify` unrunnable on a fresh clone (measured 2026-08-25: three
    // consecutive `land` laps refused on a tree whose only fault was having
    // nothing built yet).
    //
    // Two discriminators, and both are needed. A root the caller NAMED and that
    // is absent is could-not-look whatever the cwd holds. For the DEFAULT root,
    // the manifest beside it decides: present means nothing has been built, which
    // has nothing to prune and a floor that still has to be judged — a clone
    // starting with less space than a lap needs must still be told so; absent
    // means the cwd is not a workspace root.
    let unbuilt = !root.is_dir();
    let measured_at = if root.is_dir() {
        root.to_path_buf()
    } else {
        let workspace = root
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or(Path::new("."))
            .join("Cargo.toml");
        if named || !workspace.exists() {
            bail!(
                "target-prune: no build directory at {} — nothing was examined, and that is not the same as nothing to prune",
                root.display()
            );
        }
        // The floor is about the volume, and an unbuilt tree is on the same one.
        root.parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or(Path::new("."))
            .to_path_buf()
    };

    let (pruned, reclaimed) = reclaim_superseded(root, config.keep);

    let mut readings = Readings::declare()?;
    let mut free_mb = readings.take(&measured_at)?;
    let mut basis = Basis::Warm;
    let mut escalated_mb = None;

    // ESCALATION, AND ONLY WHEN THE WARM FLOOR IS ALREADY BREACHED.
    //
    // The pass above reclaims SUPERSEDED artifacts, and a cache is not superseded
    // by anything — it is simply unbounded. Measured three times in one session:
    // the superseded pass reclaimed 0MB while `incremental` held 3.8G, the lap
    // exhausted the volume, and a human deleted it by hand.
    //
    // CONDITIONAL, never unconditional. Dropping a cache costs the work that
    // wrote it, so paying that every lap would trade a rare stall for a permanent
    // tax.
    if free_mb < config.warm.mb {
        let (dropped, bytes, basis_moved) = drop_regrowable(root, &config.regrowable);
        if dropped > 0 {
            escalated_mb = Some(bytes / 1024 / 1024);
            // THE BASIS MOVES WITH THE RECLAIM, and this is the whole of
            // CLOUD-1030. The predecessor re-read free space after escalating and
            // compared it against the WARM floor, so a lap could clear the check
            // on its way into a cold build far larger than the number it had just
            // cleared.
            //
            // AND IT MOVES ONLY FOR A ROOT THAT SAYS SO (CLOUD-1157). Taking
            // `semver-checks` does not make the next cargo build full, so judging
            // that lap against a full rebuild's floor refuses a lap that would
            // have run — the same error as CLOUD-1030's, pointing the other way.
            if basis_moved {
                basis = Basis::Cold;
            }
            free_mb = readings.take(&measured_at)?;
        }
    }

    let declared_mb = match basis {
        Basis::Warm => config.warm.mb,
        Basis::Cold => config.cold.mb,
    };
    let reclaimed_mb = reclaimed / 1024 / 1024;

    // THE LAP, and everything below it is CLOUD-861. A checkout with no `$GIT_DIR`
    // has nowhere to keep a history, so it decides on the declared floor alone —
    // which is exactly what every run did before this, and is why the journal
    // being absent is a state rather than a failure.
    let Some(store) = store else {
        return Ok(Outcome {
            pruned,
            reclaimed_mb,
            escalated_mb,
            free_mb,
            floor_mb: declared_mb,
            basis,
            unbuilt,
            phase: Phase::LapOpen,
            consumed: None,
            floor_source: FloorSource::Declared,
            journal_unreadable: false,
        });
    };

    let (mut journal, journal_unreadable) = LapJournal::read(&store.git_dir);
    let today = crate::waiver::today()?.text();

    // THE FLOOR AS IT STOOD BEFORE THIS RUN OBSERVED ANYTHING. Taken here, ahead
    // of the ratchet below, and that ordering is the whole of it: a lap judged
    // against a number its own consumption had just raised would refuse the first
    // lap on every machine, for the crime of being the thing that measured it.
    let standing = journal.ratchet.of(basis).cloned();
    let floor_mb = standing
        .as_ref()
        .map_or(declared_mb, |observed| declared_mb.max(observed.mb));
    let floor_source = match &standing {
        Some(observed) if observed.mb > declared_mb => FloorSource::Observed {
            head: observed.head.clone(),
            measured: observed.measured.clone(),
        },
        _ => FloorSource::Declared,
    };

    let mut phase = Phase::LapOpen;
    let mut consumed = None;
    if let Some(open) = journal.open.take() {
        phase = Phase::LapClose;
        // THE ROW'S OWN ARITHMETIC: `start - end + reclaimed_in_between`. The
        // reclaim's bytes are IN it rather than subtracted from it — space this
        // run handed back is space the lap had spent, and a difference of two
        // readings alone would report a lap that reclaimed 5GB as having consumed
        // nothing at all.
        let spent =
            open.free_mb.saturating_sub(free_mb) + reclaimed_mb + escalated_mb.unwrap_or_default();
        // THE BASIS THE LAP OPENED UNDER owns the observation, never the one this
        // run ended on: what a lap cost is a fact about the build it ran, and a
        // run that escalated at the close did not turn the lap behind it into a
        // cold one.
        let opened_basis = if open.basis == Basis::Cold.as_str() {
            Basis::Cold
        } else {
            Basis::Warm
        };
        // THE DECLARATION IS A LOWER BOUND, so an observation under it moves
        // nothing and must not be reported as though it had. The journal still
        // RECORDS it — the worst lap seen is the history's answer whatever the
        // seed says — but `raised` is about the floor in force, and a run
        // announcing "the observed floor rises to 1000MB" while the declared
        // 6000MB still binds is a number a reader would act on and be wrong.
        let opened_declared = match opened_basis {
            Basis::Warm => config.warm.mb,
            Basis::Cold => config.cold.mb,
        };
        let recorded = journal.ratchet.raise(
            opened_basis,
            Observed {
                mb: spent,
                head: open.head.clone(),
                measured: open.measured.clone(),
            },
        );
        let raised = recorded && spent > opened_declared;
        consumed = Some(Consumed {
            mb: spent,
            head: open.head,
            measured: open.measured,
            raised,
        });
    }

    // The next lap is admitted under whatever the ratchet now says — which is
    // where an observation takes effect, from the lap after the one that made it,
    // because the closing run above read `standing` before folding its own in.
    journal.open = Some(OpenLap {
        free_mb,
        basis: basis.as_str().to_owned(),
        head: store.head.clone(),
        measured: today,
    });
    journal.write(&store.git_dir)?;

    Ok(Outcome {
        pruned,
        reclaimed_mb,
        escalated_mb,
        free_mb,
        floor_mb,
        basis,
        unbuilt,
        phase,
        consumed,
        floor_source,
        journal_unreadable,
    })
}

/// Remove every superseded artifact under the root's `deps` directories.
///
/// ONLY UNDER `deps`, and only names cargo hashed. Everything else in the build
/// tree is either a cache that regrows — so deleting it costs the work that wrote
/// it — or a live artifact addressed by a stable name.
///
/// Which kinds are in scope is [`RECLAIMED_KINDS`], and the retention is per kind:
/// see the module header for why the extension cannot collapse into the stem.
fn reclaim_superseded(root: &Path, keep: usize) -> (usize, u64) {
    let mut pruned = 0;
    let mut bytes = 0;
    for deps in directories_named(root, "deps") {
        for victims in superseded_in(&deps, keep).values() {
            for victim in victims {
                let size = victim.metadata().map_or(0, |meta| meta.len());
                if std::fs::remove_file(victim).is_ok() {
                    pruned += 1;
                    bytes += size;
                }
            }
        }
    }
    (pruned, bytes)
}

/// The artifact kinds the superseded pass groups, beside the extension-less one.
///
/// A CLOSED LIST rather than "every extension", and that is the safety property:
/// an unrecognised name is invisible to the pass instead of becoming a group of
/// its own, so a file class nobody has reasoned about is never a deletion
/// candidate. `.d` is deliberately absent — 2.8 MB across 666 files, measured,
/// which is below the noise of everything this reclaims.
const RECLAIMED_KINDS: &[&str] = &["rlib", "rmeta", "so"];

/// Files grouped by `(stem, kind)`, each group holding only what is past `keep`.
///
/// Sorted newest-first by mtime, so the tail is what the next build will not
/// read.
fn superseded_in(deps: &Path, keep: usize) -> BTreeMap<(String, String), Vec<PathBuf>> {
    let mut by_key: BTreeMap<(String, String), Vec<(std::time::SystemTime, PathBuf)>> =
        BTreeMap::new();
    let Ok(entries) = std::fs::read_dir(deps) else {
        return BTreeMap::new();
    };
    for entry in entries.flatten() {
        // A REGULAR FILE BY THE ENTRY'S OWN TYPE, never through a link. `find
        // -type f` did not follow either, and removing a link because its target
        // looks superseded deletes something that is not in this tree at all.
        if !entry.file_type().is_ok_and(|kind| kind.is_file()) {
            continue;
        }
        let Ok(meta) = entry.metadata() else { continue };
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        let Some((stem, kind)) = artifact_key(name) else {
            continue;
        };
        // THE EXECUTABLE BIT NOW GATES ONE CLASS RATHER THAN ALL OF THEM. For an
        // extension-less name it is the only signal that the file is an artifact
        // and not somebody's scratch, so it stays; for `.rlib`/`.rmeta` the
        // extension already carries that, and requiring the bit there is what
        // made the whole class unreachable while reading as a safety check.
        if kind.is_empty() && !is_executable(&meta) {
            continue;
        }
        by_key
            .entry((stem.to_owned(), kind.to_owned()))
            .or_default()
            .push((meta.modified().unwrap_or(std::time::UNIX_EPOCH), path));
    }

    by_key
        .into_iter()
        .map(|(key, mut copies)| {
            copies.sort_by_key(|copy| std::cmp::Reverse(copy.0));
            (
                key,
                copies
                    .into_iter()
                    .skip(keep)
                    .map(|(_, path)| path)
                    .collect(),
            )
        })
        .collect()
}

/// `(stem, kind)` for a name cargo hashed, or `None` where it is not one.
///
/// The kind is stripped BEFORE the hash test and then carried, which is the whole
/// of CLOUD-1157's first half: `libbatten-42061777d57a0311.rlib` otherwise splits
/// to a "hash" of `42061777d57a0311.rlib`, fails on the `.`, and becomes its own
/// stem. An extension-less name has kind `""`.
///
/// `None` rather than "its own stem" for anything else, and the two are not the
/// same claim even though a group of one is never past `keep` today: `None` says
/// this file is not a hashed artifact, which stays true if `keep` ever reaches 0
/// through some other route.
fn artifact_key(name: &str) -> Option<(&str, &str)> {
    let (head, kind) = match name.rsplit_once('.') {
        Some((head, kind)) if RECLAIMED_KINDS.contains(&kind) => (head, kind),
        // A KNOWN-SHAPE NAME THIS PASS DOES NOT RECLAIM, `.d` above all. Falling
        // through to the hash test instead would read `cli-aaaaaaaaaaaa.d` as an
        // unhashed name and — under any future rule that grouped those — put a
        // depfile in a deletion candidate's group.
        Some(_) => return None,
        None => (name, ""),
    };
    let (stem, hash) = head.rsplit_once('-')?;
    // A SUFFIX THAT MERELY CONTAINS A DASH MUST NOT BE EATEN, or two unrelated
    // binaries collapse into one group and the newer one deletes the older.
    if hash.len() >= 8 && hash.chars().all(|c| c.is_ascii_hexdigit()) {
        Some((stem, kind))
    } else {
        None
    }
}

#[cfg(unix)]
fn is_executable(meta: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt as _;
    meta.permissions().mode() & 0o111 != 0
}

#[cfg(not(unix))]
fn is_executable(_meta: &std::fs::Metadata) -> bool {
    // No executable bit to read. The stem grouping and the retention still hold,
    // so the pass is correct here and merely wider than on unix.
    true
}

/// Drop every declared regrowable root under the tree.
///
/// Returns how many caches were REMOVED, how many bytes they held, and whether
/// any of them was one the CARGO build reads — three separate answers on purpose.
/// What makes the next build cold is that a basis-moving cache is gone, not that
/// something large was deleted, so the third is what moves the basis and the bytes
/// are only for the report.
///
/// Collapsing them is a real defect and this suite caught it: an earlier form
/// returned megabytes and the caller escalated on `> 0`, so a 200 KB cache was
/// deleted and then reported as an escalation that never happened. The run was
/// judged against the warm floor after a reclaim that had already made the next
/// build cold — CLOUD-1030's own class, reintroduced by an integer division.
/// A FAILED REMOVAL STILL COUNTS, and that is the same class again on the
/// failure path (raised on #734). `remove_dir_all` is not atomic: it can unlink
/// most of a cache and then return `Err` on one entry. A half-removed
/// incremental cache is not a cache — the next build is cold either way — so
/// leaving `removed` at zero there judges that build against the warm floor,
/// which is exactly the defect this module was ported to fix.
///
/// So the count moves on the ATTEMPT rather than the outcome, and the bytes move
/// only on success: the stricter floor is the safe direction for a reclaim whose
/// extent is unknown, and claiming megabytes that may still be on disk is not.
fn drop_regrowable(root: &Path, declared: &[Regrowable]) -> (usize, u64, bool) {
    let mut removed = 0;
    let mut freed = 0;
    let mut basis_moved = false;
    // IN DECLARED ORDER, one walk per row. The order is the consumer's and is
    // preserved so a reader can predict what goes first; the walk is repeated
    // rather than fused because "do not descend into a match" is a per-name
    // property, and a single pass matching several names would have to answer
    // that question for a directory two rows disagree about.
    for declared_root in declared {
        for cache in directories_named(root, &declared_root.name) {
            let size = directory_bytes(&cache);
            // `directories_named` only yields directories that exist, so reaching
            // here means a cache was there and this run went at it.
            removed += 1;
            if declared_root.cold {
                basis_moved = true;
            }
            if std::fs::remove_dir_all(&cache).is_ok() {
                freed += size;
            }
        }
    }
    (removed, freed, basis_moved)
}

/// Whether a directory entry's own name satisfies a declared one.
///
/// A SINGLE TRAILING `*` IS THE WHOLE WILDCARD LANGUAGE, and `Prune::validate`
/// refuses every other spelling at load rather than here — an unmatched pattern
/// and a refused one are indistinguishable at this depth, and the caller of this
/// function is about to run `remove_dir_all`.
fn name_matches(candidate: &std::ffi::OsStr, declared: &str) -> bool {
    match declared.strip_suffix('*') {
        // `to_str` and not a lossy compare: a name this platform cannot render as
        // UTF-8 is not one a `[prune]` row spelled, and treating it as a match
        // would widen a prefix past what its author could have written.
        Some(prefix) => candidate
            .to_str()
            .is_some_and(|name| name.starts_with(prefix)),
        None => candidate == declared,
    }
}

/// Every directory under `root` matching this declared name, not descending into
/// a match.
///
/// A SYMLINK IS NEVER A DIRECTORY HERE, and that is the whole of this function's
/// safety. `entry.file_type()` comes from the directory entry itself and does not
/// follow, where `Path::is_dir` does — so a link under the build tree pointing at
/// somebody's home directory would otherwise be descended into and, for the
/// escalation, handed to `remove_dir_all`. The predecessor was safe by accident
/// of its instrument (`find -type d` does not follow without `-L`); the port made
/// it a decision, and review caught the window between the two on #734.
fn directories_named(root: &Path, name: &str) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            if !entry.file_type().is_ok_and(|kind| kind.is_dir()) {
                continue;
            }
            let path = entry.path();
            if path
                .file_name()
                .is_some_and(|found| name_matches(found, name))
            {
                found.push(path);
            } else {
                stack.push(path);
            }
        }
    }
    found
}

/// The bytes a directory tree holds.
///
/// Summed rather than read from any one entry, because the whole point is that a
/// cache's size is not a property of a file in it.
fn directory_bytes(dir: &Path) -> u64 {
    let mut total = 0;
    let mut stack = vec![dir.to_path_buf()];
    while let Some(next) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&next) else {
            continue;
        };
        for entry in entries.flatten() {
            // `file_type` rather than `metadata`, for `directories_named`'s
            // reason: following a link here would count somebody else's tree
            // toward a reclaim this repository is about to claim credit for.
            let Ok(kind) = entry.file_type() else {
                continue;
            };
            if kind.is_symlink() {
                continue;
            }
            if kind.is_dir() {
                stack.push(entry.path());
            } else if let Ok(meta) = entry.metadata() {
                total += meta.len();
            }
        }
    }
    total
}

#[cfg(unix)]
fn available_megabytes(path: &Path) -> Result<u64> {
    #[expect(
        clippy::disallowed_types,
        reason = "stays: this module IS Cost::Effect, and free space is the one question it cannot answer from the tree it prunes (CLOUD-1030). `df` is the portable reading, and it was PROBED rather than trusted — the module header carries the numbers"
    )]
    let spawned = std::process::Command::new("df")
        .arg("-Pm")
        .arg(path)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output()
        .context("target-prune: could not read free space")?;
    if !spawned.status.success() {
        bail!(
            "target-prune: could not read free space for {}",
            path.display()
        );
    }
    String::from_utf8_lossy(&spawned.stdout)
        .lines()
        .nth(1)
        .and_then(|line| line.split_whitespace().nth(3))
        .and_then(|field| field.parse().ok())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "target-prune: could not read free space for {}",
                path.display()
            )
        })
}

#[cfg(not(unix))]
fn available_megabytes(path: &Path) -> Result<u64> {
    bail!(
        "target-prune: no free-space reading on this platform for {}",
        path.display()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_cargo_hash_suffix_groups_the_copies_of_one_binary() {
        // The grouping the whole retention rests on: without it every copy is its
        // own key and nothing is ever superseded.
        assert_eq!(
            artifact_key("batten-1a2b3c4d5e6f7890"),
            Some(("batten", ""))
        );
        assert_eq!(artifact_key("cli-0123456789abcdef"), Some(("cli", "")));
    }

    #[test]
    fn an_extensioned_artifact_groups_under_its_own_kind() {
        // CLOUD-1157's first half. The predecessor split on the last `-`, read
        // `42061777d57a0311.rlib` as the hash, failed on the `.`, and made the
        // whole filename its own stem — so no `.rlib`, `.rmeta` or `.so` was ever
        // past `keep` however many copies accumulated.
        assert_eq!(
            artifact_key("libbatten-42061777d57a0311.rlib"),
            Some(("libbatten", "rlib"))
        );
        assert_eq!(
            artifact_key("libbatten-f8edd060dc0f6832.rmeta"),
            Some(("libbatten", "rmeta"))
        );
        assert_eq!(
            artifact_key("libserde_derive-0123456789abcdef.so"),
            Some(("libserde_derive", "so"))
        );
    }

    #[test]
    fn the_kind_is_part_of_the_key_rather_than_folded_into_the_stem() {
        // THE DATA-LOSS CASE, as an assertion about the key itself. `libbatten`
        // carries 2 `.rlib` and 6 `.rmeta` in a real `deps`; one group of eight
        // under `keep = 2` can retain two `.rmeta` and delete the LIVE `.rlib`,
        // which is the `keep = 0` failure arriving through the grouping.
        let rlib = artifact_key("libbatten-42061777d57a0311.rlib");
        let rmeta = artifact_key("libbatten-42061777d57a0311.rmeta");
        assert_ne!(rlib, rmeta, "same stem, different kind, different group");
        assert_eq!(rlib.map(|key| key.0), rmeta.map(|key| key.0));
    }

    #[test]
    fn a_name_that_is_not_a_hashed_artifact_is_not_grouped_at_all() {
        // The anti-vacuity twin, and the one that keeps the prune from deleting
        // an unrelated binary that happens to share a prefix.
        assert_eq!(artifact_key("target-prune"), None);
        assert_eq!(artifact_key("batten"), None);
        assert_eq!(artifact_key("some-tool-xyz"), None);
        // A kind this pass does not reclaim is invisible rather than its own
        // group — `.d` above all, which is 2.8 MB across 666 files here.
        assert_eq!(artifact_key("cli-0123456789abcdef.d"), None);
        assert_eq!(artifact_key("cli-0123456789abcdef.rcgu.o"), None);
    }

    #[test]
    fn a_declared_regrowable_root_that_is_not_a_name_is_refused() {
        // `remove_dir_all` runs at the far end of this key, so the refusals are
        // about a declaration meaning something wider than its author thinks.
        let row = |name: &str| Regrowable {
            name: name.to_owned(),
            cold: false,
        };
        assert!(row("incremental").validate().is_ok());
        assert!(row("flycheck*").validate().is_ok(), "the one wildcard");
        assert!(row("").validate().is_err(), "an empty name matches nothing");
        assert!(row("*").validate().is_err(), "a bare `*` is a clean");
        assert!(
            row("target/debug").validate().is_err(),
            "a path, not a name"
        );
        assert!(row("fly*check").validate().is_err(), "not a glob language");
        assert!(row("flycheck**").validate().is_err(), "nor a deep one");
    }

    #[test]
    fn a_trailing_star_is_a_prefix_and_nothing_else_is() {
        use std::ffi::OsStr;
        assert!(name_matches(OsStr::new("flycheck0"), "flycheck*"));
        assert!(name_matches(OsStr::new("flycheck12"), "flycheck*"));
        assert!(name_matches(OsStr::new("flycheck"), "flycheck*"));
        assert!(!name_matches(OsStr::new("fly"), "flycheck*"));
        assert!(name_matches(OsStr::new("incremental"), "incremental"));
        assert!(
            !name_matches(OsStr::new("incremental2"), "incremental"),
            "a name without the star is exact, or every root is a prefix of another"
        );
    }

    #[test]
    fn an_escalation_that_moves_no_basis_says_which_floor_still_applies() {
        // CLOUD-1157's second half, in the report. A warm-basis escalation is not
        // a quieter cold one: `semver-checks` regrows without making the next
        // CARGO build full, so the warm floor is still the honest number and the
        // line has to say so rather than leaving the stricter reading to be
        // inferred from the word "escalated".
        let warm = Outcome {
            pruned: 0,
            reclaimed_mb: 0,
            escalated_mb: Some(2600),
            free_mb: 9000,
            floor_mb: 6242,
            basis: Basis::Warm,
            unbuilt: false,
            phase: Phase::LapOpen,
            consumed: None,
            floor_source: FloorSource::Declared,
            journal_unreadable: false,
        };
        let said = warm.report();
        assert!(
            said.contains("2600MB of regrowable cache dropped"),
            "{said}"
        );
        assert!(!said.contains("COLD"), "the basis did not move: {said}");
        assert!(warm.clears_the_floor(), "and the warm floor is what it met");
    }

    #[test]
    fn a_date_that_names_no_day_is_refused() {
        // THE CALENDAR HALF, and it needs its own cases (raised on #734): the
        // character shape passes for every refusal below, so a suite that only
        // drives `"recently"` is exercising the length check and reporting on the
        // calendar one. The module header claims this tier pins the date shape,
        // which is what made the gap worth closing rather than arguing about.
        assert!(is_a_calendar_date("2026-08-29"));
        assert!(is_a_calendar_date("2024-02-29"), "2024 is a leap year");
        assert!(!is_a_calendar_date("2026-02-29"), "2026 is not");
        assert!(!is_a_calendar_date("2100-02-29"), "nor is a bare century");
        assert!(is_a_calendar_date("2000-02-29"), "but 2000 is, on the 400");
        assert!(!is_a_calendar_date("2026-02-31"));
        assert!(!is_a_calendar_date("2026-04-31"), "April has 30");
        assert!(!is_a_calendar_date("2026-13-01"), "no thirteenth month");
        assert!(!is_a_calendar_date("2026-00-10"), "nor a zeroth");
        assert!(!is_a_calendar_date("2026-08-00"), "nor a zeroth day");
        // The shape half still holds, which is what makes the two separable.
        assert!(!is_a_calendar_date("recently"));
        assert!(!is_a_calendar_date("2026/08/29"));
        assert!(!is_a_calendar_date("2026-8-29"));
    }

    #[test]
    fn the_basis_names_itself_in_the_report() {
        // CLOUD-1030 §5: which of the two floors is in force has to reach the
        // reader, because the number alone cannot say why it is that number.
        let warm = Outcome {
            pruned: 0,
            reclaimed_mb: 0,
            escalated_mb: None,
            free_mb: 9000,
            floor_mb: 6242,
            basis: Basis::Warm,
            unbuilt: false,
            phase: Phase::LapOpen,
            consumed: None,
            floor_source: FloorSource::Declared,
            journal_unreadable: false,
        };
        assert!(
            warm.report().contains("warm floor 6242MB"),
            "{}",
            warm.report()
        );
        assert!(warm.clears_the_floor());
    }

    #[test]
    fn the_escalation_moves_the_floor_it_is_judged_against() {
        // THE DEFECT, as an assertion. 9000MB clears the warm floor and does not
        // clear the cold one, so a run that escalated and then re-read against the
        // warm number would pass here — which is exactly what the predecessor did.
        let cold = Outcome {
            pruned: 0,
            reclaimed_mb: 0,
            escalated_mb: Some(3800),
            free_mb: 9000,
            floor_mb: 14914,
            basis: Basis::Cold,
            unbuilt: false,
            phase: Phase::LapOpen,
            consumed: None,
            floor_source: FloorSource::Declared,
            journal_unreadable: false,
        };
        assert!(!cold.clears_the_floor(), "9000MB does not fit a cold build");
        assert!(cold.report().contains("COLD"), "{}", cold.report());
        assert!(
            cold.refusal(Path::new("target")).contains("full rebuild"),
            "the refusal says why this floor applies"
        );
    }
}
