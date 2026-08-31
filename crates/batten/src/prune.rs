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
//! **That is true of a NAME and not of a SHAPE, and the distinction is CLOUD-1240's**
//! — the paragraph above used to be the whole answer, and it left 2.1 GB
//! unreclaimable on a lap that then had to be rescued by hand. `semver-checks`,
//! `perf` and `flycheck*` are names somebody chose, so they are the consumer's and
//! they stay in the config. `target/<triple>/` is not: it is what cargo lays down
//! for every `--target`, in every project, and a nested `CARGO_TARGET_DIR` has the
//! identical shape. [`nested_build_trees`] recognises that shape — a directory one
//! level under the root that holds a profile directory — which compiles in no
//! consumer identifier and matches nothing at all in a project that never
//! cross-compiles. So the rule is: **a name is declared, a cargo layout is
//! derived.**
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
use std::fmt::Write as _;
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
    /// What the tree looked like when that lap was measured (CLOUD-1158).
    ///
    /// OPTIONAL IN THE TYPE AND REFUSED ON THE VERIFY SURFACE, which is not the
    /// same as optional in the contract — an absent basis is refused by
    /// [`basis_drift`], on `measured`'s own ground, and the only thing that moved
    /// is WHERE.
    ///
    /// It has to move, and the reason is measured rather than stylistic. A
    /// required field means the NEW engine cannot parse the OLD config, and
    /// `config-lint` loads `origin/main:batten.toml` with the working tree's
    /// binary precisely so a branch cannot lower the bar it is judged by. So a
    /// newly-required key makes its own PR unlandable: the base ref has no such
    /// key, the load fails with `missing field`, and the gate reports
    /// could-not-look rather than a verdict. Measured on this row's own landing
    /// lap, after the whole gate was otherwise green.
    ///
    /// The refusal is not weakened by the move — it is the same refusal one
    /// surface later, on the surface CLOUD-1158 §2 already puts the live
    /// comparison on, and `an_undeclared_basis_is_refused_on_the_verify_surface`
    /// is what holds it there.
    pub basis: Option<Measured>,
}

/// The world the floor was measured against, so a reader can tell when it moved.
///
/// # A date is a POINTER to a basis, not the basis (CLOUD-1158)
///
/// [`Floor::measured`] discharges CLOUD-266 — a limit carries its measurement —
/// and stops there: nothing could say whether the world under the number had
/// changed since. It had, and it changes on a schedule this repository sets for
/// itself.
///
/// Retained bytes after a perfectly successful prune are `keep x stems x size`.
/// `keep` is 2 and `size` is stable; `stems` is not. CLOUD-766 recorded ~41
/// distinct integration-test stems resident in `deps` on 2026-08-20;
/// `crates/batten/tests/*.rs` was 110 tracked files on 2026-08-29, each an
/// independent cargo test target, and CLOUD-843's retirement campaign adds one per
/// retired gate with 147 shell suites still standing. Measured on this container
/// the same day: 114 extension-less test binaries holding 13411.9 MB, 86.8% of
/// `deps`.
///
/// A floor taken against a smaller count fails in the direction that fails
/// SILENTLY — the check passes, the build writes more than the basis anticipated,
/// and the exhaustion arrives as a rustc IO error inside a test run, which is the
/// presentation this module's refusal exists to prevent.
///
/// # The comparison is not here, and that is the whole of §2
///
/// `config.rs` calls [`Prune::validate`] on the shared config-load path, which
/// EVERY `batten` invocation runs — `batten hook`, on every mediated tool call,
/// included. Enumerating tracked paths there would tax a tree read onto the
/// mediated call against `perf-assert`'s ceiling, which is the exact shape
/// `claim-race-check` was moved off that path for.
///
/// So this type is CONFIG — validated for shape at load, which is free — and the
/// comparison against the live tree runs on `Surface::VerifyOnly`, in
/// `batten target prune`, which that budget deliberately has no ceiling for.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Measured {
    /// The glob whose tracked-file count is the basis.
    pub glob: String,
    /// How many tracked files matched it when the floor was measured.
    pub count: usize,
    /// How far the count may drift before the floor is stale.
    ///
    /// A TOLERANCE RATHER THAN EQUALITY, because a gate that reds on the first
    /// added test file is one somebody switches off — and the thing being watched
    /// is a trend, not an edit. It is required rather than defaulted: what counts
    /// as drift is a fact about how fast THIS consumer's suite grows.
    pub tolerance: usize,
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
        // SHAPE ONLY. Whether the live tree still matches the declared count is a
        // question for `Surface::VerifyOnly` — see [`Measured`] for why it may not
        // be asked here.
        //
        // AND ONLY WHEN ONE IS DECLARED. Refusing an absent basis here would make
        // this engine unable to load a config written before the key existed —
        // `config-lint`'s own base ref, among others — so that half is
        // `basis_drift`'s. See [`Floor::basis`].
        let Some(basis) = self.basis.as_ref() else {
            return Ok(());
        };
        if basis.glob.is_empty() {
            return Err(UsageError::raise(format!(
                "[prune.{name}.basis]: `glob` is empty, so the floor names no basis — and an absent basis reads exactly like a satisfied one, which is the whole of `measured`'s own reason"
            )));
        }
        if crate::rules::Selector::new(&basis.glob).is_err() {
            return Err(UsageError::raise(format!(
                "[prune.{name}.basis]: `glob` does not compile, so it matches nothing and the count it declares can never be checked"
            )));
        }
        Ok(())
    }
}

/// What the basis comparison found.
///
/// A struct rather than a bool because the refusal has to carry both numbers: a
/// gate saying only "stale" leaves a reader to go and take the measurement it
/// already took.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BasisDrift {
    /// Which floor drifted.
    pub floor: String,
    /// The glob the basis is counted over.
    pub glob: String,
    /// What the floor declares that count was.
    pub declared: usize,
    /// What it is now.
    pub live: usize,
    /// How far it was allowed to move.
    pub tolerance: usize,
    /// When the floor was measured.
    pub measured: String,
}

impl BasisDrift {
    /// The refusal, pointer-only: two counts, a tolerance and a date.
    ///
    /// NEVER A FILE LISTING (non-negotiable rule 4). The count IS the finding, and
    /// the paths behind it are unbounded — a caller who wants them can run the
    /// same glob themselves.
    #[must_use]
    pub fn refusal(&self) -> String {
        format!(
            "target-prune: [prune.{floor}] was measured against a tree that no longer exists
  basis {glob}
  declared {declared}, live {live}, tolerance {tolerance}
  measured {measured}
  Retained bytes are `keep x stems x size`, so a floor taken against a smaller stem count passes and then lets the build write more than it budgeted for — which arrives as a rustc IO error inside a test run rather than as a disk fault. Re-measure the floor and move `count` and `measured` together: a count refreshed without a new measurement is the same staleness wearing a newer number.",
            floor = self.floor,
            glob = self.glob,
            declared = self.declared,
            live = self.live,
            tolerance = self.tolerance,
            measured = self.measured
        )
    }
}

/// What the verify-surface basis check found, and the two are different findings.
///
/// An undeclared basis and a drifted one have different remedies — write the row,
/// versus re-measure the floor — so they are two refusals rather than one wearing
/// two numbers. [`BasisDrift`] keeps the drifted half's shape unchanged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BasisFinding {
    /// A floor declares no basis at all.
    Undeclared {
        /// Which floor.
        floor: String,
        /// The date it claims, which is the pointer with nothing behind it.
        measured: String,
    },
    /// A floor's declared basis no longer matches the tree.
    Drifted(BasisDrift),
}

impl BasisFinding {
    /// The refusal, pointer-only for both arms.
    #[must_use]
    pub fn refusal(&self) -> String {
        match self {
            Self::Drifted(drift) => drift.refusal(),
            Self::Undeclared { floor, measured } => format!(
                "target-prune: [prune.{floor}] declares no basis, so `measured` points at nothing
  measured {measured}
  A date says WHEN a floor was taken and not WHAT it was taken against, so an absent basis reads exactly like a satisfied one — which is the whole of `measured`'s own reason. Declare `[prune.{floor}.basis]` with the glob, the count it held, and a tolerance."
            ),
        }
    }
}

/// Whether either floor's declared basis is absent, or has drifted past its
/// tolerance.
///
/// `tracked` is the repository's index — the same membership test `ls-files`
/// prints — so a path the build never sees cannot move the count, and a checkout
/// with no index has no answer to give rather than a refusal to make.
///
/// One [`crate::rules::Selector`] per floor rather than a match per path: the type
/// exists to compile a pattern once, and a per-path `glob_match` would recompile
/// it for every tracked file in the tree.
#[must_use]
pub fn basis_drift(config: &Prune, tracked: &[&str]) -> Option<BasisFinding> {
    for (name, floor) in [("warm", &config.warm), ("cold", &config.cold)] {
        let Some(basis) = floor.basis.as_ref() else {
            return Some(BasisFinding::Undeclared {
                floor: name.to_owned(),
                measured: floor.measured.clone(),
            });
        };
        let Ok(selector) = crate::rules::Selector::new(&basis.glob) else {
            // Refused at load, so unreachable through the CLI. Skipping is the
            // safe direction for the one caller that could reach it anyway: a
            // pattern that matches nothing must not read as a count of zero.
            continue;
        };
        let live = tracked.iter().filter(|path| selector.matches(path)).count();
        if live.abs_diff(basis.count) > basis.tolerance {
            return Some(BasisFinding::Drifted(BasisDrift {
                floor: name.to_owned(),
                glob: basis.glob.clone(),
                declared: basis.count,
                live,
                tolerance: basis.tolerance,
                measured: floor.measured.clone(),
            }));
        }
    }
    None
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
    /// Which READING took the observations below (CLOUD-1246).
    ///
    /// A ratchet is a memory of a measurement, and a measurement is only as good
    /// as the instrument that took it. Without this key nothing distinguishes an
    /// observation that is still true from one whose reading has since been
    /// corrected — and because [`Ratchet::raise`] only ever climbs, the second
    /// kind binds for the life of the clone.
    ///
    /// See [`JOURNAL_GENERATION`] for what a stamp means and when it moves.
    #[serde(default)]
    taken_by: String,
    /// The lap awaiting its closing reading, if a run opened one.
    open: Option<OpenLap>,
    /// The worst consumption observed, per basis.
    ratchet: Ratchet,
}

/// The reading this engine takes lap observations with.
///
/// # It moves when a fix changes what a reading MEANS, and never otherwise
///
/// Bumped BY HAND, which is the whole point of not keying it on the crate
/// version: a patch release that changes nothing about how a lap is measured
/// must not throw away a history that is still true. The log below is the record
/// of which fix each generation is for, so bumping it costs writing down why.
///
/// * `2026-08-31.basis-every-deps` — CLOUD-1241. Before it, [`basis_of`] asked
///   whether ANY `deps` under the root held anything, so a cold lap beside a
///   surviving `target/release/deps` was recorded against the WARM basis. The
///   observations that reading took are not weaker facts, they are not facts:
///   measured here, a declared warm floor of 7264MB stood at 10997MB from one
///   such lap, and `land` was refused at 8356MB free by the artifact of the bug
///   it had just fixed.
const JOURNAL_GENERATION: &str = "2026-08-31.basis-every-deps";

/// What a journal read produced, and what it had to throw away to produce it.
///
/// Two discards, reported separately because they are different claims about the
/// world: bytes that would not parse say the store is damaged, and a superseded
/// stamp says the store is intact and its contents are no longer meaningful.
#[derive(Default)]
struct JournalRead {
    /// What the run should use — the file's contents, or a fresh history.
    journal: LapJournal,
    /// A journal was there and would not parse.
    unreadable: bool,
    /// A journal was there, parsed, and a superseded reading had taken it.
    superseded: bool,
}

/// Read the journal where there is somewhere to keep one.
///
/// A checkout with no `$GIT_DIR` decides on the declared floor alone — which is
/// what every run did before the ratchet existed, and is why an absent journal is
/// a state rather than a failure. Neither discard can have happened there, so the
/// default is the honest answer rather than a placeholder.
fn read_journal(store: Option<&LapStore>) -> JournalRead {
    store.map_or_else(JournalRead::default, |store| {
        LapJournal::read(&store.git_dir)
    })
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
    /// What the TREE read when it opened, where the opening run recorded one.
    ///
    /// BESIDE `basis` RATHER THAN INSTEAD OF IT, because the two can disagree and
    /// the disagreement is the whole datum (CLOUD-1218). `basis` is the EFFECTIVE
    /// reading — the tree's, OR'd with a basis-moving root the escalation dropped
    /// — and `basis_of` structurally cannot see that second half: dropping
    /// `incremental` leaves `deps` full, so the tree still reads warm while the
    /// next build is cold.
    ///
    /// So a lap that opened Cold is two different situations, and only the tree's
    /// own reading tells them apart: a tree that was EMPTY (this is `Cold`, and a
    /// lap that ends with `deps` populated has genuinely built it warm), or a full
    /// tree carrying a standing escalation (this is `Warm`, and the lap ending
    /// with `deps` still full has changed nothing the tree can show).
    ///
    /// OPTIONAL, so a journal written before this field parses rather than
    /// resetting a clone's whole lap history over an added key. `None` means the
    /// opening run did not record one, and the close then falls back to exactly
    /// the reading it used before this field existed.
    #[serde(default)]
    tree_basis: Option<String>,
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
    ///
    /// A journal a SUPERSEDED reading took is discarded on exactly that ground
    /// and on exactly those terms (CLOUD-1246) — same empty result, same said-out-
    /// loud report, a different precondition.
    ///
    /// THE OPEN LAP GOES WITH THE RATCHET, never one without the other. A lap
    /// opened by the old reading would close into the new one, and its `spent`
    /// arithmetic would land in whichever basis the two engines disagree about —
    /// which is the very misfiling the discard exists to undo, performed once more
    /// on the way out.
    fn read(git_dir: &Path) -> JournalRead {
        let fresh = |unreadable, superseded| JournalRead {
            journal: Self::default(),
            unreadable,
            superseded,
        };
        let path = Self::path(git_dir);
        let Ok(raw) = std::fs::read_to_string(&path) else {
            return fresh(false, false);
        };
        let Ok(read): std::result::Result<Self, _> = serde_json::from_str(&raw) else {
            return fresh(true, false);
        };
        // COMPARED FOR EQUALITY, never "equal or absent". Every journal written
        // before this key existed carries no stamp, and those are exactly the ones
        // the corrected reading did not take — so an absent stamp must not pass.
        if read.taken_by != JOURNAL_GENERATION {
            return fresh(false, true);
        }
        JournalRead {
            journal: read,
            unreadable: false,
            superseded: false,
        }
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
        // STAMPED BY THE WRITER, never carried through from the read. A run that
        // discarded a superseded history and then wrote its successor back under
        // the old stamp would discard it again on the next read, forever.
        let rendered = serde_json::to_string(&Self {
            taken_by: String::from(JOURNAL_GENERATION),
            ..self.clone()
        })
        .context("target-prune: render the lap journal")?;
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
    /// The floor this observation raised its basis to, where it raised one.
    ///
    /// **Not always `mb`**, because the observation is capped by what the lap
    /// left free: a lap can cost more than the volume can ever leave over, and a
    /// floor set to the larger number refuses every later lap. So the spend and
    /// the floor are two different facts and are reported as two numbers — see
    /// the cap at the `raise` call site.
    pub raised: Option<u64>,
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
    /// The next cargo build is a full one — a basis-moving root is gone, or
    /// `deps` holds nothing to build on.
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
///
/// # `#[non_exhaustive]` because this struct's job is to GROW
///
/// Every field here is something a run observed and a reader may need, and each
/// new class of observation adds one: `journal_superseded` is the second discard
/// flag, and it arrived because fixing a reading turned out not to retire what
/// the reading had written. Nothing outside this crate builds an `Outcome` —
/// [`prune`] does, and callers read it — so a struct literal was never the
/// contract, only an accident of it being available.
///
/// Declaring that makes this the LAST break of its kind rather than the second:
/// without it every future report flag is a `constructible_struct_adds_field`
/// break, which prices an honest observation at a version bump and teaches the
/// next author to fold two claims into one boolean instead.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
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
    /// The basis the NEXT lap is admitted under, which is not the same question.
    ///
    /// [`Outcome::basis`] is the basis of RECORD — the one the closed lap ran
    /// under, and therefore the one the floor in force belongs to. This is what
    /// the tree and this run's own escalation leave behind.
    ///
    /// They diverge exactly where the closing reclaim escalates, and reporting
    /// the escalation from the wrong one is a lie a reader acts on: measured on
    /// this row's own landing lap, a close that dropped `incremental` printed
    /// *"none of those roots is the cargo build's basis, so the next build is
    /// still warm"* — because the message was keyed on the closed lap's basis —
    /// while the journal recorded the next lap as cold, and the run after it was
    /// refused against a 14914MB floor with no line anywhere saying why.
    pub next_basis: Basis,
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
    /// Whether a lap journal was there, readable, and taken by a superseded
    /// reading (CLOUD-1246).
    ///
    /// SEPARATE FROM [`Self::journal_unreadable`] rather than folded into it,
    /// because the two are different claims: unreadable says the store is
    /// damaged, and this says the store is intact and its numbers stopped being
    /// facts when the reading that took them was corrected. A reader who cannot
    /// tell those apart cannot tell a disk problem from an upgrade.
    pub journal_superseded: bool,
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
        if self.journal_superseded {
            // POINTER-ONLY, AND DELIBERATELY WITHOUT THE DISCARDED NUMBER. The
            // whole claim is that those megabytes were never a measurement of
            // anything this engine reads; printing them invites a reader to act
            // on the one figure the line exists to retire.
            line.push_str(
                "target-prune: the lap journal's observations were taken by a superseded reading, so they were discarded and the declared floors are the only basis\n",
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
            let _ = write!(
                line,
                "target-prune: the lap opened on {} ({}) consumed {}MB",
                consumed.head, consumed.measured, consumed.mb
            );
            if let Some(floor) = consumed.raised {
                line.push('\n');
                let _ = write!(
                    line,
                    "target-prune: that is worse than any {} lap on record, so the observed {} floor rises to {}MB from the next lap",
                    self.basis.as_str(),
                    self.basis.as_str(),
                    floor
                );
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
            let escalated = match self.next_basis {
                Basis::Cold => format!(
                    "target-prune: escalated below the warm floor — {dropped}MB of regrowable cache dropped. The next cargo build is COLD — a basis-moving root is gone, or `deps` holds nothing to build on — so the cold floor is what now applies"
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
    /// NAMING THE JOURNAL IS THE OTHER HALF, and its absence had a measured price
    /// (CLOUD-1218). A reader told the floor is "observed" still has nowhere to go:
    /// the number lives in a file no message mentions, so the recovery is
    /// undiscoverable from the refusal. One agent paid a full cold rebuild —
    /// 21519MB and ~20 minutes — reaching for `rm -rf target` because that is what
    /// the refusal DOES name, when deleting the journal alone would have sufficed
    /// at the first refusal. The path is a pointer, not a payload (rule 4).
    fn floor_provenance(&self) -> String {
        match &self.floor_source {
            FloorSource::Declared => String::new(),
            FloorSource::Observed { head, measured } => {
                format!(
                    ", observed on {head} ({measured}) rather than declared — this floor was learned, and it lives in $GIT_DIR/batten-prune/laps.json"
                )
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
                "the next cargo build is a full rebuild — a basis-moving root is gone, or `deps` holds nothing to build on — and the cold floor is what it has to fit in"
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

    // THE JOURNAL IS READ BEFORE THE ESCALATION, because the phase is what
    // decides whether the escalation may run at all — see the guard below.
    let read = read_journal(store);
    let mut readings = Readings::declare()?;
    let mut free_mb = readings.take(&measured_at)?;
    // THE BASIS IS ALSO A PROPERTY OF THE TREE, NOT ONLY OF THIS INVOCATION. It
    // was read from the escalation alone — `Cold` iff THIS run dropped a
    // basis-moving root — so a tree emptied by anything else was invisible.
    //
    // Measured live on this row's own branch, and it poisoned the ratchet rather
    // than merely mis-reporting: a human deleted `target/debug` by hand to satisfy
    // the floor, the lap that followed built 110 test binaries from nothing, and
    // the journal recorded that 21226MB COLD lap as the worst WARM one on record.
    // Every warm lap after it is then admitted against a full rebuild's demand —
    // the floor nothing can satisfy that CLOUD-861's own §8 names as the failure
    // which gets a gate switched off.
    //
    // AN EMPTY `deps` IS THE SIGNAL, and it is the artifacts themselves rather
    // than a cache: with nothing there the next build writes all of it, whoever
    // removed it and whether or not this run did. The escalation's flag stays as
    // the other half — a dropped `incremental` leaves `deps` full and still makes
    // the next build cold — so the two are OR'd rather than one replacing the
    // other.
    let mut basis = basis_of(root);
    // THE TREE'S OWN READING, KEPT BEFORE THE ESCALATION CAN MOVE IT, because the
    // closing boundary needs a basis this run did not create. `basis` below is
    // what the NEXT lap is admitted under and the escalation is entitled to move
    // it; this is what the tree says, and the two answer different questions.
    // Which question each one belongs to is argued at `lap`'s `floor_basis`.
    let tree_basis = basis;
    // AGAINST THE FLOOR IN FORCE, NOT THE DECLARATION (CLOUD-1244). Resolved here
    // rather than inside `escalate`, because the journal is the caller's — see
    // [`warm_floor_in_force`] for what the two disagreeing cost.
    let warm_in_force = warm_floor_in_force(config, &read.journal);
    let escalated_mb = escalate(
        root,
        config,
        warm_in_force,
        &mut free_mb,
        &mut basis,
        &mut readings,
        &measured_at,
    )?;

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
            next_basis: basis,
            unbuilt,
            phase: Phase::LapOpen,
            consumed: None,
            floor_source: FloorSource::Declared,
            journal_unreadable: false,
            // Both false and not merely defaulted: with no `$GIT_DIR` there was
            // no journal to read, so neither discard can have happened.
            journal_superseded: false,
        });
    };

    lap(
        store,
        config,
        read.journal,
        read.unreadable,
        &Tally {
            free_mb,
            reclaimed_mb,
            escalated_mb,
            basis,
            tree_basis,
        },
    )
    .map(|lap| Outcome {
        pruned,
        reclaimed_mb,
        escalated_mb,
        free_mb,
        floor_mb: lap.floor_mb,
        basis: lap.judged,
        next_basis: basis,
        unbuilt,
        phase: lap.phase,
        consumed: lap.consumed,
        floor_source: lap.floor_source,
        journal_unreadable: lap.journal_unreadable,
        // Taken from the read rather than routed through `lap`, which is where
        // the answer is: `lap` decides the floor and the ratchet and has nothing
        // to say about either discard. Its `journal_unreadable` parameter is a
        // pass-through, and a second one would only double that.
        journal_superseded: read.superseded,
    })
}

/// Drop regrowable caches, but only where the warm floor is already breached.
///
/// Returns the megabytes dropped, where anything was, and advances `free_mb` and
/// `basis` in place — the two readings the caller's own accounting is built on.
///
/// ESCALATION, AND ONLY WHEN THE WARM FLOOR IS ALREADY BREACHED. The superseded
/// pass reclaims artifacts one build made obsolete, and a cache is not superseded
/// by anything — it is simply unbounded. Measured three times in one session: the
/// superseded pass reclaimed 0MB while `incremental` held 3.8G, the lap exhausted
/// the volume, and a human deleted it by hand.
///
/// CONDITIONAL, never unconditional. Dropping a cache costs the work that wrote
/// it, so paying that every lap would trade a rare stall for a permanent tax.
fn escalate(
    root: &Path,
    config: &Prune,
    warm_in_force: u64,
    free_mb: &mut u64,
    basis: &mut Basis,
    readings: &mut Readings,
    measured_at: &Path,
) -> Result<Option<u64>> {
    if *free_mb >= warm_in_force {
        return Ok(None);
    }
    // TWO TIERS, CHEAP FIRST, AND THE EXPENSIVE ONE ONLY IF IT IS STILL SHORT
    // (CLOUD-861, measured twice on that row's own landing lap).
    //
    // The escalation used to take every declared root at once, so a run needing
    // 2GB took `incremental` along with the rest — and dropping `incremental` is
    // what makes the NEXT cargo build a full one, which raises the floor that
    // build has to clear from the warm number to the cold one. Measured: a closing
    // reclaim freed 5711MB, of which the non-basis roots were most, and thereby
    // moved the floor the next lap faced from 6242MB to 14914MB on a tree a full
    // lap leaves at ~8.7GB. Every second `land` lap was then refused for a full
    // rebuild nothing had asked for. The escalation created the demand that
    // refused it.
    //
    // So the rows that cost only their own next run go first, free space is
    // re-read, and the basis-moving rows are taken only if the floor is still
    // breached. That is not a phase rule and deliberately so: a run cannot tell the
    // head of `verify` from the tail of `verify:gated` — both are the same
    // invocation — but it can always tell whether it still needs the space.
    let (cheap, cheap_bytes, _) = drop_regrowable(root, &config.regrowable, false);
    let mut dropped = cheap;
    let mut bytes = cheap_bytes;
    if cheap > 0 {
        *free_mb = readings.take(measured_at)?;
    }
    // THE SAME FLOOR THE CHEAP TIER OPENED ON (CLOUD-1244). The re-read decides
    // whether the cheap pass was enough; the number it is compared against has to
    // be the one that will judge the lap, or this tier inherits the identical gap
    // one step later.
    if *free_mb < warm_in_force {
        let (costly, costly_bytes, basis_moved) = drop_regrowable(root, &config.regrowable, true);
        dropped += costly;
        bytes += costly_bytes;
        // THE BASIS MOVES WITH THE RECLAIM, and this is the whole of CLOUD-1030.
        // The predecessor re-read free space after escalating and compared it
        // against the WARM floor, so a lap could clear the check on its way into a
        // cold build far larger than the number it had just cleared.
        //
        // AND IT MOVES ONLY FOR A ROOT THAT SAYS SO (CLOUD-1157). Taking
        // `semver-checks` does not make the next cargo build full, so judging that
        // lap against a full rebuild's floor refuses a lap that would have run —
        // the same error as CLOUD-1030's, pointing the other way.
        if basis_moved {
            *basis = Basis::Cold;
        }
        if costly > 0 {
            *free_mb = readings.take(measured_at)?;
        }
    }
    Ok((dropped > 0).then_some(bytes / 1024 / 1024))
}

/// What this run's reclaim came to, as the lap accounting needs it.
///
/// A struct rather than five parameters, and the workspace's own argument-count
/// lint is what asked for it — correctly, because these are one thing: the state
/// a lap is closed and opened against.
struct Tally {
    /// Free megabytes after everything this run reclaimed.
    free_mb: u64,
    /// Megabytes the superseded pass handed back.
    reclaimed_mb: u64,
    /// Megabytes the escalation handed back, where it ran.
    escalated_mb: Option<u64>,
    /// The basis now in force — the one the NEXT lap is admitted under.
    basis: Basis,
    /// What the TREE read before this run's own reclaim could move it.
    ///
    /// Beside `basis` rather than derived from it, because the escalation is
    /// entitled to move one and not the other: `basis` answers "what will the
    /// next lap be admitted under", which a reclaim this run performed is part
    /// of, and this answers "what does the build tree currently hold", which it
    /// is not. `lap`'s `floor_basis` is where the two are told apart.
    tree_basis: Basis,
}

/// What the lap accounting decided.
struct Lap {
    /// The basis that floor belongs to.
    ///
    /// At the opening boundary that is the basis now in force, this run's own
    /// escalation included; at the closing boundary it is what the TREE reads,
    /// because the floor is about the build that comes next and the lap being
    /// closed has already run. `lap`'s `floor_basis` carries the argument.
    judged: Basis,
    /// The floor this run is judged against.
    floor_mb: u64,
    /// Where that floor came from.
    floor_source: FloorSource,
    /// Which boundary this run stood at.
    phase: Phase,
    /// What the closed lap cost, where one closed.
    consumed: Option<Consumed>,
    /// Whether a journal was there and unreadable.
    journal_unreadable: bool,
}

/// Close the open lap, ratchet what it cost, and admit the next (CLOUD-861).
///
/// # Errors
///
/// When the clock is before the epoch, or the journal cannot be written — a lap
/// nothing will close is not a lap, so that fails rather than passing.
fn lap(
    store: &LapStore,
    config: &Prune,
    mut journal: LapJournal,
    journal_unreadable: bool,
    tally: &Tally,
) -> Result<Lap> {
    let today = crate::waiver::today()?.text();
    let Tally {
        free_mb,
        reclaimed_mb,
        escalated_mb,
        basis,
        tree_basis,
    } = *tally;

    // THE FLOOR AS IT STOOD BEFORE THIS RUN OBSERVED ANYTHING. Taken here, ahead
    // of the ratchet below, and that ordering is the whole of it: a lap judged
    // against a number its own consumption had just raised would refuse the first
    // lap on every machine, for the crime of being the thing that measured it.
    //
    // WHICH BASIS OWNS THE OBSERVATION IS THE ONE THE LAP RAN UNDER (CLOUD-861,
    // found on that row's own first live lap), and that is what this value is for
    // — the ratchet bucket the consumption lands in, and the declaration it is
    // compared against. What a lap COST is a fact about the build that ran, so a
    // closing run whose reclaim escalated cannot retroactively make the lap behind
    // it a cold one.
    //
    // It is no longer also the floor's basis; `floor_basis` below is, and the
    // argument for splitting them is there.
    let opened_basis = journal.open.as_ref().map_or(basis, |open| {
        if open.basis == Basis::Cold.as_str() {
            Basis::Cold
        } else {
            Basis::Warm
        }
    });
    // WHICH BASIS THE FLOOR BELONGS TO, and it is NOT the one the observation
    // belongs to. Those were one value until CLOUD-1218's third failure mode, and
    // separating them is the whole of that repair.
    //
    // The floor asks "is there room for the build that comes NEXT". At the OPENING
    // boundary that build is the one this invocation is about to run, so this
    // run's own escalation counts against it — CLOUD-1030, where a lap cleared the
    // warm check on its way into a cold build far larger than the number it had
    // just cleared. At the CLOSING boundary the lap has already run, so the
    // question is what the tree it LEFT can build from.
    //
    // Measured, five consecutive `land` laps on a ~38GB allowance: a lap opened on
    // an empty `target/` — correctly Cold — and closed on a fully built tree with
    // 14839MB free. It was refused against the 17357MB COLD floor, and `verify`
    // had SUCCEEDED: a full cargo build, the whole cargo suite and all 2491 bats
    // cases, with no disk error anywhere. That floor is unreachable by
    // construction at the close, because building the tree is precisely what
    // spends the headroom a cold floor demands, so every cold-started lap refuses
    // at its own close forever, however much is reclaimed first. Every `rm -rf
    // target` recovery an agent performs opens exactly that lap.
    //
    // AND THE TREE'S READING ALONE CANNOT DECIDE IT, which is what the first
    // attempt at this repair got wrong and what
    // `a_warm_laps_consumption_does_not_raise_the_cold_floor` caught. `basis_of`
    // reads `deps`, so a lap that opened Cold because an EARLIER escalation
    // dropped `incremental` has a full `deps` and reads Warm — while its next
    // build really is a full one. That is the OR `basis_of`'s own header
    // describes, and the tree is structurally blind to half of it.
    //
    // So the discriminator is the tree's reading AT OPEN, which the journal now
    // carries. A lap that opened on a cold TREE and ends on a warm one has built
    // it; a lap that opened on a warm tree under a standing escalation has changed
    // nothing the tree can show, and stays cold.
    //
    // THE OPPOSITE SPIRAL IS PRESERVED THROUGHOUT: a close whose own reclaim
    // escalated opened warm, so it is judged warm, which is what
    // `a_closing_escalation_does_not_make_the_lap_it_closes_a_cold_one` has pinned
    // since CLOUD-861. That escalation's consequence lands one lap later, where
    // `journal.open` records `basis` below.
    let floor_basis = match journal.open.as_ref() {
        None => basis,
        Some(_) if tree_basis == Basis::Cold => Basis::Cold,
        Some(open) => match open.tree_basis.as_deref() {
            // A journal written before the field existed cannot answer, so the
            // close falls back to exactly the reading it used before it existed.
            None => opened_basis,
            Some(recorded) if recorded == Basis::Warm.as_str() => opened_basis,
            Some(_) => Basis::Warm,
        },
    };
    let declared_mb = match floor_basis {
        Basis::Warm => config.warm.mb,
        Basis::Cold => config.cold.mb,
    };
    let standing = journal.ratchet.of(floor_basis).cloned();
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
        // CAPPED BY WHAT THIS LAP LEFT, and that cap is what keeps the ratchet
        // satisfiable. The floor means "leave room for another lap like the last
        // one", so clearing it needs `free_at_open >= floor + spent` — twice a
        // lap's cost. On a volume that cannot hold two laps the observation
        // therefore sets a number the very measurement it came from has already
        // shown unreachable, and every later lap is refused at its own close
        // however much is reclaimed first.
        //
        // Measured on a ~38GB allowance (~11GB of it toolchains): a full gated lap
        // consumed 18541MB and closed at 7887MB, the ratchet stood at 20228MB, and
        // eight consecutive laps built cleanly and were refused. Emptying `target/`
        // and the cargo registry entirely moved the close reading not at all,
        // because the build simply spends what it is given.
        //
        // `free_mb` is the ceiling this lap DEMONSTRATED: a lap of this cost leaves
        // that much and no more. Capping there keeps the invariant wherever the
        // volume can honour it, and makes the number self-correcting instead of
        // one-way — an expensive lap used to poison a clone permanently, since
        // `raise` only ever climbs. Where the volume is roomy the cap does not
        // bite: the suite's own ratchet lap spends 8000MB and leaves 12000MB.
        let observed_mb = spent.min(free_mb);
        let recorded = journal.ratchet.raise(
            opened_basis,
            Observed {
                mb: observed_mb,
                head: open.head.clone(),
                measured: open.measured.clone(),
            },
        );
        let raised = (recorded && observed_mb > opened_declared).then_some(observed_mb);
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
        tree_basis: Some(tree_basis.as_str().to_owned()),
        head: store.head.clone(),
        measured: today,
    });
    journal.write(&store.git_dir)?;

    Ok(Lap {
        judged: floor_basis,
        floor_mb,
        floor_source,
        phase,
        consumed,
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

/// The warm floor as it actually stands: the declaration, raised by any
/// observation the ratchet holds above it (CLOUD-1244).
///
/// # Why this exists rather than reading `config.warm.mb` at the gate
///
/// The escalation used to open on the DECLARATION while the refusal is judged
/// against `declared.max(observed)`. Those are the same number only until a
/// ratchet observation stands above the declaration — and from then on there is
/// a band, between the two, where a run **refuses without ever attempting the
/// reclaim that would have cleared it**.
///
/// Measured across one session, and every refusal in it fell in that band: free
/// 7896, 8777, 9064 and 10931 MB, against a declared 7264 and an in-force floor
/// of 9970 and then 10997. Four refusals, zero escalations, and a human deleting
/// directories by hand each time. Ballasting the same tree to 6600 MB — below the
/// DECLARATION — escalated immediately and reclaimed 6061 MB without moving the
/// basis. The reclaim was never unable; it was never asked.
///
/// # Why the WARM standing, even where the cold floor is what will apply
///
/// This opens the cheap tier, whose rows cost only their own next run, and the
/// costly tier re-reads free space behind its own guard. Reading the cold
/// standing here would make a basis-moving drop the entry condition for a pass
/// whose whole contract is that it does not move the basis.
fn warm_floor_in_force(config: &Prune, journal: &LapJournal) -> u64 {
    journal
        .ratchet
        .of(Basis::Warm)
        .map_or(config.warm.mb, |observed| config.warm.mb.max(observed.mb))
}

/// Whether the next cargo build has anything to build ON.
///
/// EMPTINESS IS THE SIGNAL, and it is deliberately the artifacts rather than a
/// cache. `deps` is where every compiled unit lands, so a tree whose `deps`
/// directories are empty or absent writes all of it next time — that is what
/// `Basis::Cold` means, and it is true whoever emptied them.
///
/// A PROFILE THAT SHOULD CARRY `deps` AND DOES NOT IS COLD, and reaching that is
/// what CLOUD-1218 cost three containers. Reading only the `deps` directories that
/// EXIST cannot see a profile whose `deps` was removed — and removal is what an
/// agent following the refusal's own advice actually does. Measured here: a
/// reclaim took `target/debug/deps`, so that profile dropped out of the walk
/// entirely and the surviving `target/release/deps` reported the tree WARM. The
/// full debug rebuild that followed was charged to the warm ratchet, taught it
/// 24715MB against a 6242MB declaration, and wedged every later lap.
///
/// `.fingerprint` IS THE MARKER, because cargo writes one per profile it has
/// built and leaves it behind when `deps` goes. So the question "is there a
/// profile that has been built and now has nothing to build on" is answerable
/// from the tree without being told which profile the caller will build next —
/// which is the guess this function still refuses to make. It is the same KIND of
/// claim about cargo's layout that looking for `deps` at all already is.
///
/// NO `.fingerprint` ANYWHERE FALLS BACK to the older reading, so a tree cargo has
/// never touched — every fixture that writes a bare `deps` directory, and any
/// consumer whose layout this does not describe — is judged exactly as before.
/// The fallback is what keeps this a narrowing rather than a new requirement.
///
/// The direction is what makes it safe: this can turn a warm reading cold and
/// never the reverse, and cold is the stricter floor, so the failure mode is a lap
/// held to a larger budget than it needs rather than one taught a number nothing
/// can satisfy. The first is a delay; the second is the wedge above.
///
/// NOT THE REGROWABLE ROOTS, which cannot answer this. A `[prune]` row's `cold`
/// flag says *dropping this makes the next build full*, which is a claim about a
/// removal rather than about a state: `incremental` is simply absent on a tree
/// that has never built incrementally, and reading that absence as cold would
/// judge every CI lap against a full rebuild's floor.
fn basis_of(root: &Path) -> Basis {
    let built_profiles = cargo_owned(root, directories_named(root, ".fingerprint"));
    if built_profiles.is_empty() {
        let populated = cargo_owned(root, directories_named(root, "deps"))
            .iter()
            .any(|deps| populated_directory(deps));
        return if populated { Basis::Warm } else { Basis::Cold };
    }
    // EVERY built profile must still have something to build on. `.parent()` is
    // the profile directory `.fingerprint` sits in, so its sibling `deps` is the
    // one that profile's next build reads — and a profile whose `deps` was removed
    // answers here rather than vanishing from the walk.
    let every_profile_ready = built_profiles.iter().all(|fingerprint| {
        fingerprint
            .parent()
            .is_some_and(|profile| populated_directory(&profile.join("deps")))
    });
    if every_profile_ready {
        Basis::Warm
    } else {
        Basis::Cold
    }
}

/// The build directories cargo itself owns, from every directory of that name
/// anywhere under the root.
///
/// THE BASIS IS A QUESTION ABOUT ONE BUILD TREE, and the walk that answers it is
/// unbounded, so it also reaches every build tree NESTED inside the root. Cargo
/// writes `<root>/<profile>/` and, cross-compiling, `<root>/<triple>/<profile>/`
/// — two levels and three. Anything deeper is a different tree that happens to
/// live here.
///
/// MEASURED ON THIS ROW'S OWN BRANCH, and it wedged the branch that introduced
/// the `.fingerprint` reading. This repository's own suite writes its fixtures
/// under `target/tmp/<case>/`, and one of them —
/// `a_profile_whose_deps_was_removed_is_cold_though_another_profile_is_built` —
/// exists precisely to model a profile whose `deps` was removed. Its fixture
/// therefore sits at `target/tmp/<case>/target/debug/.fingerprint` with an empty
/// sibling, and the "every built profile must be ready" reading found it and
/// judged the WHOLE REPOSITORY cold. `verify` then refused its own precondition
/// against a full rebuild's floor on a tree that had just built cleanly.
///
/// The predecessor had the same exposure pointing the other way and hid it: an
/// `.any()` over fixture `deps` directories that happen to be populated read the
/// tree warm, so the litter masked instead of refusing. Neither is a reading of
/// this repository's build.
fn cargo_owned(root: &Path, found: Vec<PathBuf>) -> Vec<PathBuf> {
    found
        .into_iter()
        .filter(|path| {
            path.strip_prefix(root)
                .is_ok_and(|below| matches!(below.components().count(), 2 | 3))
        })
        .collect()
}

/// Does this directory exist and hold at least one entry?
///
/// ABSENT AND EMPTY ARE THE SAME ANSWER here — both mean the next build writes
/// what would have been there — and collapsing them is the point rather than a
/// convenience: reading them differently is how a removed `deps` became invisible.
fn populated_directory(path: &Path) -> bool {
    std::fs::read_dir(path).is_ok_and(|mut entries| entries.next().is_some())
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
fn drop_regrowable(root: &Path, declared: &[Regrowable], basis_moving: bool) -> (usize, u64, bool) {
    let mut removed = 0;
    let mut freed = 0;
    let mut basis_moved = false;
    // IN DECLARED ORDER, one walk per row. The order is the consumer's and is
    // preserved so a reader can predict what goes first; the walk is repeated
    // rather than fused because "do not descend into a match" is a per-name
    // property, and a single pass matching several names would have to answer
    // that question for a directory two rows disagree about.
    for declared_root in declared {
        // See the call site: one tier per pass, cheap first.
        if declared_root.cold != basis_moving {
            continue;
        }
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

    // THE DERIVED ROOTS, AFTER THE DECLARED ONES AND ONLY IN THE WARM TIER
    // (CLOUD-1240). A nested build tree costs only its own next build, exactly as
    // `semver-checks` and `perf` do, so it belongs to the cheap pass and never
    // moves the basis — the call site takes this tier first and re-reads free
    // space before it considers anything that would.
    //
    // Last, because the declared list is the consumer's and its ORDER is a
    // statement they made; a derived root has no such claim on going first.
    if !basis_moving {
        for tree in nested_build_trees(root) {
            // A declared row may name the same directory — `semver-checks` and
            // `perf` are themselves nested build trees, so today they are matched
            // twice. Reaching a path the pass above already removed would count a
            // reclaim that did not happen and add zero bytes, so the existence
            // check is the accounting rather than a guard.
            //
            // `symlink_metadata` for `directories_named`'s reason: `is_dir`
            // follows, and a link left where a tree was is not a tree.
            if !std::fs::symlink_metadata(&tree).is_ok_and(|meta| meta.is_dir()) {
                continue;
            }
            let size = directory_bytes(&tree);
            removed += 1;
            if std::fs::remove_dir_all(&tree).is_ok() {
                freed += size;
            }
        }
    }

    (removed, freed, basis_moved)
}

/// The profile directories cargo lays down inside any build tree.
///
/// Their presence one level in is what makes a directory a build tree rather
/// than something a consumer happened to put under `target/`, and their names at
/// the top level are what makes `target/debug` the HOST's rather than a nested
/// one.
const PROFILE_DIRS: [&str; 2] = ["debug", "release"];

/// Every nested cargo build tree directly under `root` (CLOUD-1240).
///
/// # Why this is the engine's and not a `[[prune.regrowable]]` row
///
/// The module header argues that which directories a build tree grows is a fact
/// about the consumer's project, and for `semver-checks`, `perf` and `flycheck*`
/// that is exactly right — those are task names somebody chose. **`target/<triple>/`
/// is not.** It is what cargo does for every `--target`, in every project, and
/// the identical layout appears under a nested `CARGO_TARGET_DIR`. So recognising
/// it here is repo-agnostic in the sense non-negotiable rule 1 means: no consumer
/// identifier is compiled in, and a consumer that never cross-compiles has no
/// such directory to match.
///
/// Measured on this repository (CLOUD-1240): `aarch64-apple-darwin` at 1378 MB
/// and `x86_64-pc-windows-gnu` at 721 MB were outside the escalation entirely,
/// on a lap that consumed 11684 MB against a 9970 MB floor — so the only thing
/// that cleared a lap was a human deleting them by hand.
///
/// # The predicate, and the one case it must not match
///
/// A directory DIRECTLY under `root` that itself holds a [`PROFILE_DIRS`] entry.
/// One level only: a build tree's own `deps/` and `.fingerprint/` are not build
/// trees, and descending would let a fixture nested three deep be handed to
/// `remove_dir_all`.
///
/// **`target/debug` is the case that decides this function is safe**, and it is
/// excluded twice over. Structurally it does not match — it holds `deps/`,
/// `build/`, `incremental/` and `.fingerprint/`, never a nested `debug/` or
/// `release/` — and the name check below refuses it regardless. The redundancy is
/// deliberate: matching it would `remove_dir_all` the host build every time the
/// floor was breached and report it as a reclaim, so a structural argument alone
/// is a thinner thing than this call deserves. `prune.rs`'s tests assert both the
/// structural miss and the named refusal, because a case that passed only because
/// of the name would say nothing about the predicate.
fn nested_build_trees(root: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let Ok(entries) = std::fs::read_dir(root) else {
        return found;
    };
    for entry in entries.flatten() {
        // `file_type` and not `Path::is_dir`, which follows: a symlink under the
        // build tree pointing at somebody's home directory must never reach
        // `remove_dir_all`. This is `directories_named`'s own safety argument,
        // and it applies here for the same reason (#734).
        if !entry.file_type().is_ok_and(|kind| kind.is_dir()) {
            continue;
        }
        let path = entry.path();
        let Some(name) = path.file_name() else {
            continue;
        };
        if PROFILE_DIRS.iter().any(|profile| name == *profile) {
            continue;
        }
        if PROFILE_DIRS.iter().any(|profile| {
            std::fs::symlink_metadata(path.join(profile)).is_ok_and(|meta| meta.is_dir())
        }) {
            found.push(path);
        }
    }
    // Sorted so the reclaim order is stable across runs: the count and the bytes
    // are reported, and a reader diffing two runs of a partly-failing reclaim
    // should not be reading directory-iteration order.
    found.sort();
    found
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

    // --- the derived nested build trees (CLOUD-1240) -------------------------
    //
    // `unwrap` and `expect` are denied under `src/`, so the fixtures panic
    // explicitly. A setup failure is still a loud failure; what it is not is a
    // lint waiver this module does not otherwise need.

    fn mkdir(path: &Path) {
        if let Err(why) = std::fs::create_dir_all(path) {
            panic!("fixture: could not create {}: {why}", path.display());
        }
    }

    /// A build root of this test's own, emptied first so a previous run cannot
    /// decide this one. Named per case because the suite runs concurrently.
    fn build_root(name: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!("batten-prune-{name}"));
        let _ = std::fs::remove_dir_all(&root);
        mkdir(&root);
        root
    }

    #[test]
    fn a_cross_target_tree_is_recognised_with_no_declared_row_naming_it() {
        // The whole point: `aarch64-apple-darwin` is nobody's chosen name, so the
        // consumer never declares it, and before this the escalation could not see
        // it at all — 1378 MB of it, measured.
        let root = build_root("derived-cross");
        mkdir(&root.join("aarch64-apple-darwin/debug/deps"));
        mkdir(&root.join("x86_64-pc-windows-gnu/release"));

        let found = nested_build_trees(&root);
        assert_eq!(
            found,
            vec![
                root.join("aarch64-apple-darwin"),
                root.join("x86_64-pc-windows-gnu"),
            ],
            "a directory holding a profile directory is a nested build tree"
        );
    }

    /// SHOWN ABLE TO FAIL, and this is the case the function's safety rests on.
    ///
    /// A predicate that matched `target/debug` would hand the HOST build to
    /// `remove_dir_all` every time the floor was breached, and report it as a
    /// reclaim. Both exclusions are asserted, because the redundancy is the point:
    /// the structural miss is the real argument, and the named refusal is what
    /// holds if a tree ever grows `target/debug/release/`.
    #[test]
    fn the_host_profile_directories_are_never_taken_as_nested_trees() {
        let root = build_root("derived-host");
        // The structural arm: a real `target/debug` holds these and no nested
        // profile directory, so it does not match on shape.
        mkdir(&root.join("debug/deps"));
        mkdir(&root.join("debug/build"));
        mkdir(&root.join("debug/incremental"));
        mkdir(&root.join("debug/.fingerprint"));
        assert!(
            nested_build_trees(&root).is_empty(),
            "target/debug holds no nested profile directory, so it must not match"
        );

        // The named arm: even given the shape, the host roots are refused.
        mkdir(&root.join("debug/release"));
        mkdir(&root.join("release/debug"));
        assert!(
            nested_build_trees(&root).is_empty(),
            "the host profile directories are refused by name as well as by shape"
        );
    }

    #[test]
    fn a_directory_with_no_profile_directory_inside_it_is_left_alone() {
        // The anti-vacuity twin: the predicate is not "any directory under the
        // root", which would be `cargo clean` spelled as a reclaim.
        let root = build_root("derived-unrelated");
        mkdir(&root.join("tmp/some-fixture"));
        mkdir(&root.join("bats-report"));
        assert!(
            nested_build_trees(&root).is_empty(),
            "nothing here holds a profile directory"
        );
    }

    #[test]
    fn one_level_only_so_a_trees_own_deps_is_not_itself_a_tree() {
        // Descending would let `deps/` — or a fixture nested three deep — reach
        // `remove_dir_all`. The walk is deliberately not recursive.
        let root = build_root("derived-depth");
        mkdir(&root.join("nested/debug"));
        mkdir(&root.join("nested/debug/deps/inner/release"));
        assert_eq!(
            nested_build_trees(&root),
            vec![root.join("nested")],
            "only the directory one level under the root is a candidate"
        );
    }

    #[test]
    fn the_warm_tier_reclaims_a_derived_tree_and_leaves_the_basis_warm() {
        // The acceptance clause, over the escalation rather than the predicate:
        // no declared row at all, and the tree still goes — with the basis warm,
        // because dropping it makes only its OWN next build full.
        let root = build_root("derived-warm");
        let tree = root.join("aarch64-apple-darwin");
        mkdir(&tree.join("debug/deps"));

        let (removed, _, basis_moved) = drop_regrowable(&root, &[], false);
        assert_eq!(removed, 1, "the derived tree is reclaimed");
        assert!(
            !basis_moved,
            "a nested tree costs only its own next build, so the cargo basis stays warm"
        );
        assert!(!tree.exists(), "and it is actually gone");
    }

    #[test]
    fn the_cold_tier_never_takes_a_derived_tree() {
        // The tier split, asserted rather than assumed. The call site takes the
        // cheap tier, re-reads free space, and only then considers the costly one
        // — a derived root appearing in the second pass would be reclaimed after
        // the run had already decided it needed a basis-moving drop.
        let root = build_root("derived-cold");
        let tree = root.join("x86_64-pc-windows-gnu");
        mkdir(&tree.join("release"));

        let (removed, freed, basis_moved) = drop_regrowable(&root, &[], true);
        assert_eq!(removed, 0, "the cold pass takes no derived root");
        assert_eq!(freed, 0);
        assert!(!basis_moved);
        assert!(tree.exists(), "and leaves it on disk for the warm pass");
    }

    #[test]
    fn a_tree_a_declared_row_already_took_is_not_counted_twice() {
        // `semver-checks` and `perf` are themselves nested build trees, so they
        // match both passes. Counting the second attempt would report a reclaim
        // that freed nothing, which is the accounting error the existence check
        // exists to prevent.
        let root = build_root("derived-twice");
        mkdir(&root.join("semver-checks/debug/deps"));

        let declared = vec![Regrowable {
            name: String::from("semver-checks"),
            cold: false,
        }];
        let (removed, _, _) = drop_regrowable(&root, &declared, false);
        assert_eq!(
            removed, 1,
            "one directory, one reclaim — not one per pass that matched it"
        );
    }

    // --- observations a superseded reading took (CLOUD-1246) -----------------

    /// The bytes this container was actually carrying, kept verbatim.
    ///
    /// A hand-written equivalent would drift; these are the exact contents of
    /// `$GIT_DIR/batten-prune/laps.json` at the moment `land` was refused at
    /// 8356MB free against a floor of 10997MB, with `[prune.warm]` declaring 7264.
    const POISONED_JOURNAL: &str = r#"{"open":{"free_mb":12192,"basis":"warm","head":"2b7f57b2","measured":"2026-08-31"},"ratchet":{"warm":{"mb":10997,"head":"45601adc","measured":"2026-08-31"},"cold":{"mb":98,"head":"2b7f57b2","measured":"2026-08-31"}}}"#;

    /// Write `raw` where [`LapJournal::read`] will look, and hand back the dir.
    fn journal_dir(name: &str, raw: &str) -> PathBuf {
        let git_dir = build_root(name);
        let path = LapJournal::path(&git_dir);
        if let Some(store) = path.parent() {
            mkdir(store);
        }
        if let Err(why) = std::fs::write(&path, raw) {
            panic!("fixture: could not write {}: {why}", path.display());
        }
        git_dir
    }

    /// SHOWN ABLE TO FAIL (CLOUD-418), and on the number that produced the row.
    ///
    /// The stamp is compared for EQUALITY, so a journal written before the key
    /// existed carries none and cannot match. Relaxing that to "equal or absent"
    /// — the one plausible weakening — lets exactly these bytes through, and the
    /// 10997MB warm observation the corrected reading would never have taken is
    /// back in force. That is the assertion, over the real file.
    #[test]
    fn the_journal_that_refused_this_container_does_not_survive_the_read() {
        let git_dir = journal_dir("journal-poisoned", POISONED_JOURNAL);
        let read = LapJournal::read(&git_dir);

        assert!(read.superseded, "an unstamped journal is a superseded one");
        assert!(!read.unreadable, "it parses perfectly — that is the point");
        assert_eq!(
            read.journal.ratchet.of(Basis::Warm),
            None,
            "the 10997MB observation must not reach the floor calculation"
        );
        assert_eq!(
            read.journal.ratchet.of(Basis::Cold),
            None,
            "and neither basis is kept — the reading was wrong about which is which"
        );
        assert!(
            read.journal.open.is_none(),
            "the open lap goes with it: it would close into a reading that disagrees about its basis"
        );
    }

    #[test]
    fn a_journal_this_reading_took_is_read_unchanged() {
        // The inertness clause. Every clone whose history the CURRENT reading did
        // produce must be untouched, or the ratchet would reset on every run and
        // the floor would never be observed at all.
        let stamped = format!(
            r#"{{"taken_by":"{JOURNAL_GENERATION}","open":null,"ratchet":{{"warm":{{"mb":8000,"head":"abcdef12","measured":"2026-08-31"}},"cold":null}}}}"#
        );
        let git_dir = journal_dir("journal-current", &stamped);
        let read = LapJournal::read(&git_dir);

        assert!(!read.superseded);
        assert!(!read.unreadable);
        assert_eq!(
            read.journal
                .ratchet
                .of(Basis::Warm)
                .map(|observed| observed.mb),
            Some(8000),
            "a standing observation this reading took still stands"
        );
    }

    #[test]
    fn a_stamp_from_some_other_reading_is_discarded_too() {
        // Not only the ABSENT stamp: the mechanism has to work forwards, or the
        // next bump would be inert and the next author would find that out the way
        // this one did.
        let git_dir = journal_dir(
            "journal-foreign",
            r#"{"taken_by":"1999-01-01.some-other-reading","open":null,"ratchet":{"warm":{"mb":9999,"head":"abcdef12","measured":"2026-08-31"},"cold":null}}"#,
        );
        let read = LapJournal::read(&git_dir);

        assert!(read.superseded);
        assert_eq!(read.journal.ratchet.of(Basis::Warm), None);
    }

    #[test]
    fn the_writer_stamps_it_so_a_discard_happens_once_and_not_every_run() {
        // The self-healing half. A run that discarded a superseded history writes
        // its successor back under the CURRENT stamp; without that the same
        // discard would repeat forever and no observation could ever stand.
        let git_dir = journal_dir("journal-restamp", POISONED_JOURNAL);
        let discarded = LapJournal::read(&git_dir);
        assert!(discarded.superseded);

        let mut next = discarded.journal;
        next.ratchet.raise(
            Basis::Warm,
            Observed {
                mb: 7500,
                head: String::from("abcdef12"),
                measured: String::from("2026-08-31"),
            },
        );
        if let Err(why) = next.write(&git_dir) {
            panic!("fixture: could not write the journal back: {why}");
        }

        let again = LapJournal::read(&git_dir);
        assert!(!again.superseded, "the second read finds its own reading");
        assert_eq!(
            again
                .journal
                .ratchet
                .of(Basis::Warm)
                .map(|observed| observed.mb),
            Some(7500)
        );
    }

    #[test]
    fn the_discard_is_reported_and_names_no_number_from_what_it_discarded() {
        // Non-negotiable rule 4 on this line specifically: the whole claim is that
        // the discarded megabytes were never a measurement, so printing them would
        // hand a reader the one figure the line exists to retire.
        let outcome = Outcome {
            pruned: 0,
            reclaimed_mb: 0,
            escalated_mb: None,
            free_mb: 8356,
            floor_mb: 7264,
            basis: Basis::Warm,
            next_basis: Basis::Warm,
            unbuilt: false,
            phase: Phase::LapOpen,
            consumed: None,
            floor_source: FloorSource::Declared,
            journal_unreadable: false,
            journal_superseded: true,
        };
        let said = outcome.report();
        assert!(
            said.contains("superseded reading"),
            "the discard is said out loud: {said}"
        );
        assert!(
            !said.contains("10997"),
            "and it carries no number out of the record it threw away: {said}"
        );
        assert!(
            outcome.clears_the_floor(),
            "8356MB clears the DECLARATION, which is what binds after a discard"
        );
    }

    // --- the floor the escalation opens against (CLOUD-1244) -----------------

    fn floor(mb: u64) -> Floor {
        Floor {
            mb,
            worst_mb: mb,
            multiplier: default_multiplier(),
            measured: String::from("2026-08-31"),
            basis: None,
        }
    }

    // Spelled out rather than derived from `Default`: neither type has one, and
    // adding one would put a floor of 0 within reach of a config that forgot the
    // key — the opposite of what `deny_unknown_fields` buys at load.
    fn floors(warm_mb: u64) -> Prune {
        Prune {
            root: default_root(),
            keep: default_keep(),
            warm: floor(warm_mb),
            cold: floor(warm_mb * 2),
            regrowable: Vec::new(),
        }
    }

    fn journal_standing(warm_mb: u64) -> LapJournal {
        let mut journal = LapJournal::default();
        journal.ratchet.raise(
            Basis::Warm,
            Observed {
                mb: warm_mb,
                head: String::from("abcdef12"),
                measured: String::from("2026-08-31"),
            },
        );
        journal
    }

    /// THE BAND THAT COST A WHOLE SESSION, as an assertion about the number.
    ///
    /// Declared 7264, observed 10997: every refusal measured that day sat between
    /// them — 7896, 8777, 9064, 10931 MB free — and the escalation, gated on the
    /// DECLARATION, never ran once. The reclaim had gigabytes available and was
    /// never asked for them.
    #[test]
    fn the_escalation_opens_against_the_standing_observation_not_the_declaration() {
        let config = floors(7264);
        let journal = journal_standing(10997);
        assert_eq!(warm_floor_in_force(&config, &journal), 10997);

        for free_mb in [7896_u64, 8777, 9064, 10931] {
            assert!(
                free_mb < warm_floor_in_force(&config, &journal),
                "{free_mb}MB is under the floor in force, so the reclaim must be attempted"
            );
        }
    }

    /// SHOWN ABLE TO FAIL: the predecessor's reading, spelled out.
    ///
    /// Against `config.warm.mb` alone, all four of those readings are ABOVE the
    /// gate and none of them escalates — which is precisely the observed
    /// behaviour this replaces. Keeping it as an assertion means the two numbers
    /// can never quietly become one again.
    #[test]
    fn the_declaration_alone_would_have_refused_every_one_of_them_without_trying() {
        let config = floors(7264);
        for free_mb in [7896_u64, 8777, 9064, 10931] {
            assert!(
                free_mb >= config.warm.mb,
                "the declaration is what let these through ungated"
            );
        }
    }

    #[test]
    fn with_no_observation_standing_the_declaration_is_the_floor_in_force() {
        // The unratcheted case, which is every fresh clone: nothing observed, so
        // the gate is exactly what it always was and this change is inert.
        let config = floors(7264);
        assert_eq!(
            warm_floor_in_force(&config, &LapJournal::default()),
            7264,
            "an absent observation must not invent a floor"
        );
    }

    #[test]
    fn an_observation_below_the_declaration_does_not_lower_the_floor() {
        // The declaration is a lower bound, which the reporting half already
        // states. The gate has to agree with it, or a cheap lap would quietly
        // relax the number a later lap is judged against.
        let config = floors(7264);
        assert_eq!(warm_floor_in_force(&config, &journal_standing(4000)), 7264);
    }

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
            next_basis: Basis::Warm,
            unbuilt: false,
            phase: Phase::LapOpen,
            consumed: None,
            floor_source: FloorSource::Declared,
            journal_unreadable: false,
            journal_superseded: false,
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
            next_basis: Basis::Warm,
            unbuilt: false,
            phase: Phase::LapOpen,
            consumed: None,
            floor_source: FloorSource::Declared,
            journal_unreadable: false,
            journal_superseded: false,
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
            next_basis: Basis::Cold,
            unbuilt: false,
            phase: Phase::LapOpen,
            consumed: None,
            floor_source: FloorSource::Declared,
            journal_unreadable: false,
            journal_superseded: false,
        };
        assert!(!cold.clears_the_floor(), "9000MB does not fit a cold build");
        assert!(cold.report().contains("COLD"), "{}", cold.report());
        assert!(
            cold.refusal(Path::new("target")).contains("full rebuild"),
            "the refusal says why this floor applies"
        );
    }
}
