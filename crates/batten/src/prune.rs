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
        if self.unbuilt {
            line.push_str(
                "target-prune: nothing built at the configured root yet, so nothing to prune — the floor below is still judged\n",
            );
        }
        let counted = format!(
            "target-prune: {} superseded artifact(s) removed, {}MB reclaimed, {}MB free ({} floor {}MB)",
            self.pruned,
            self.reclaimed_mb,
            self.free_mb,
            self.basis.as_str(),
            self.floor_mb
        );
        line.push_str(&counted);
        if let Some(dropped) = self.escalated_mb {
            // A SECOND LINE RATHER THAN A CLAUSE ON THE FIRST, because the two
            // say different things: the first is what was reclaimed, the second
            // is that the BASIS moved. A reader who sees the cold floor named
            // above and no reason for it would have to know this module to guess.
            let escalated = format!(
                "target-prune: escalated below the warm floor — {dropped}MB of incremental cache dropped, so the next build is COLD and the cold floor is what now applies"
            );
            line.push('\n');
            line.push_str(&escalated);
        }
        line
    }

    /// The refusal, naming the floor in force and why it is that one.
    #[must_use]
    pub fn refusal(&self, root: &Path) -> String {
        let because = match self.basis {
            Basis::Warm => {
                "nothing left to reclaim — the incremental cache is already gone or was never there"
            }
            Basis::Cold => {
                "the escalation dropped the incremental cache, so the next build is a full rebuild and the cold floor is what it has to fit in"
            }
        };
        format!(
            "target-prune: below the measured {basis} disk floor, and {because}\n  free {free}MB\n  floor {floor}MB ({basis} basis)\n  A build started here fails as a rustc IO error inside a test run, which reads as a suite regression rather than a full disk. Free space outside {root}, or start a fresh session.",
            basis = self.basis.as_str(),
            free = self.free_mb,
            floor = self.floor_mb,
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
pub fn prune(root: &Path, config: &Prune, named: bool) -> Result<Outcome> {
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
    // The pass above reclaims SUPERSEDED artifacts, and incremental state is not
    // superseded by anything — it is simply unbounded. Measured three times in
    // one session: the superseded pass reclaimed 0MB while `incremental` held
    // 3.8G, the lap exhausted the volume, and a human deleted it by hand.
    //
    // CONDITIONAL, never unconditional. Dropping the cache costs a full rebuild,
    // so paying it every lap would trade a rare stall for a permanent tax.
    if free_mb < config.warm.mb {
        let (dropped, bytes) = drop_incremental(root);
        if dropped > 0 {
            escalated_mb = Some(bytes / 1024 / 1024);
            // THE BASIS MOVES WITH THE RECLAIM, and this is the whole of
            // CLOUD-1030. The predecessor re-read free space after escalating and
            // compared it against the WARM floor, so a lap could clear the check
            // on its way into a cold build far larger than the number it had just
            // cleared.
            basis = Basis::Cold;
            free_mb = readings.take(&measured_at)?;
        }
    }

    let floor_mb = match basis {
        Basis::Warm => config.warm.mb,
        Basis::Cold => config.cold.mb,
    };

    Ok(Outcome {
        pruned,
        reclaimed_mb: reclaimed / 1024 / 1024,
        escalated_mb,
        free_mb,
        floor_mb,
        basis,
        unbuilt,
    })
}

/// Remove every superseded artifact under the root's `deps` directories.
///
/// ONLY UNDER `deps`, and only executable regular files. Everything else in the
/// build tree is either a cache that regrows — so deleting it costs a rebuild —
/// or a live artifact addressed by a stable name. `.d`, `.rlib` and `.rmeta` are
/// left alone: they are small, and a dangling one only makes cargo rebuild.
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

/// Files grouped by stem, each group holding only what is past `keep`.
///
/// Sorted newest-first by mtime, so the tail is what the next build will not
/// read.
fn superseded_in(deps: &Path, keep: usize) -> BTreeMap<String, Vec<PathBuf>> {
    let mut by_stem: BTreeMap<String, Vec<(std::time::SystemTime, PathBuf)>> = BTreeMap::new();
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
        if !is_executable(&meta) {
            continue;
        }
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        by_stem
            .entry(stem_of(name).to_owned())
            .or_default()
            .push((meta.modified().unwrap_or(std::time::UNIX_EPOCH), path));
    }

    by_stem
        .into_iter()
        .map(|(stem, mut copies)| {
            copies.sort_by_key(|copy| std::cmp::Reverse(copy.0));
            (
                stem,
                copies
                    .into_iter()
                    .skip(keep)
                    .map(|(_, path)| path)
                    .collect(),
            )
        })
        .collect()
}

/// The filename with cargo's trailing `-<hash>` removed, which is what groups
/// the copies of one binary.
fn stem_of(name: &str) -> &str {
    let Some((head, hash)) = name.rsplit_once('-') else {
        return name;
    };
    // A SUFFIX THAT MERELY CONTAINS A DASH MUST NOT BE EATEN, or two unrelated
    // binaries collapse into one group and the newer one deletes the older.
    if hash.len() >= 8 && hash.chars().all(|c| c.is_ascii_hexdigit()) {
        head
    } else {
        name
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

/// Drop every incremental cache under the root.
///
/// Returns how many caches were REMOVED and how many bytes they held, and the
/// two are separate answers on purpose. What makes the next build cold is that
/// the cache is gone, not that it was large — so the count is what decides
/// whether the basis moves and the bytes are only for the report.
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
fn drop_incremental(root: &Path) -> (usize, u64) {
    let mut removed = 0;
    let mut freed = 0;
    for cache in directories_named(root, "incremental") {
        let size = directory_bytes(&cache);
        // `directories_named` only yields directories that exist, so reaching
        // here means a cache was there and this run went at it.
        removed += 1;
        if std::fs::remove_dir_all(&cache).is_ok() {
            freed += size;
        }
    }
    (removed, freed)
}

/// Every directory under `root` with this name, not descending into a match.
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
            if path.file_name().is_some_and(|found| found == name) {
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
        // own stem and nothing is ever superseded.
        assert_eq!(stem_of("batten-1a2b3c4d5e6f7890"), "batten");
        assert_eq!(stem_of("cli-0123456789abcdef"), "cli");
    }

    #[test]
    fn a_name_whose_tail_is_not_a_hash_is_its_own_stem() {
        // The anti-vacuity twin, and the one that keeps the prune from deleting
        // an unrelated binary that happens to share a prefix.
        assert_eq!(stem_of("target-prune"), "target-prune");
        assert_eq!(stem_of("batten"), "batten");
        assert_eq!(stem_of("some-tool-xyz"), "some-tool-xyz");
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
        };
        assert!(!cold.clears_the_floor(), "9000MB does not fit a cold build");
        assert!(cold.report().contains("COLD"), "{}", cold.report());
        assert!(
            cold.refusal(Path::new("target")).contains("full rebuild"),
            "the refusal says why this floor applies"
        );
    }
}
