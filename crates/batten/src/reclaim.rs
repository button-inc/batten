//! The reclaim census (CLOUD-451): was a LANDING in flight when this container
//! replaced the last one?
//!
//! Retired off `[tasks.reclaim-census]` and `[tasks."session:census"]` under
//! CLOUD-843. A SENSOR AND NOTHING ELSE: it denies, gates and occupies nothing.
//!
//! # Structural, not temporal (CLOUD-491)
//!
//! The last seconds of writes do not survive a measured replacement, so no clock
//! is in the predicate. An `h` per heartbeat, an `x` only where something CHOSE
//! to stop, and the verdict is the kind of the last record written UNDER THE
//! BOOT BEING JUDGED — per transition, never the store's newest line, which
//! re-answered one event forever.
//!
//! # Narrower than CLOUD-451, and said (CLOUD-696)
//!
//! It records only while a landing holds the lease, so a boot that recorded
//! nothing is UNOBSERVED, never idle: idleness reported from a coverage gap is
//! evidence manufactured from silence.
//!
//! # The stores
//!
//! Two journal families under the per-worktree git directory, written through
//! [`crate::journal::append_line`] (the one durable append path) and read through
//! [`crate::journal::fold_lines`], which drops a torn tail — the value a torn
//! tail would corrupt is exactly the kind this census classifies by. The
//! once-per-boot mark sits beside the beats, outside the journal's shards.
//!
//! [`classify`], [`previous`] and [`tally`] are pure functions of the folded
//! lines; everything that touches a file or the clock is in the `run_*` arms.

//MUTANT-SUITE crates/batten/src/reclaim.rs
//MUTANT active-reads-as-idle|s@^        Some(("h", epoch)) => Verdict::Active(epoch.to_owned()),$@        Some(("h", epoch)) => Verdict::Idle(epoch.to_owned()),@|a_beat_under_the_judged_boot_is_active
//MUTANT stop-reads-as-beat|s@\.then_some((kind, epoch))$@.then_some(("h", epoch))@|a_stop_after_the_beats_is_idle
//MUTANT absence-reads-as-idle|s@^        None => Verdict::Unobserved,$@        None => Verdict::Idle(String::new()),@|absence_is_unobserved_never_idle
//MUTANT newest-line-answers|s@^\(        .*\) && under == boot)@\1 \&\& !under.is_empty())@|the_newest_line_overall_does_not_answer_for_an_older_boot
//MUTANT-SUITE crates/batten/tests/it/reclaim_census.rs
//MUTANT boot-recorded-every-time|s@^    if boots.last().map(String::as_str) != Some(boot) {$@    if true {@|record_boot_is_idempotent_by_the_last_line
//MUTANT malformed-override-falls-through|s@^        return value.ok_or(BootUnreadable::Malformed);$@        if let Some(value) = value { return Ok(value); }@|a_fresh_disk_or_a_malformed_boot_time_cannot_look
//MUTANT kind-unchecked|s@^    if !matches!(kind, @    if false \&\& !matches!(kind, @|the_notes_carry_epoch_boot_and_only_a_given_reason
//MUTANT reason-with-space-accepted|s@^    if reason.is_some_and(@    if false \&\& reason.is_some_and(@|the_notes_carry_epoch_boot_and_only_a_given_reason
//MUTANT-SUITE crates/batten/tests/it/reclaim_report_once.rs
//MUTANT mark-ignored|s@^    seen.trim_end() == boot$@    seen.trim_end() == "never-a-boot"@|a_reclaim_is_reported_once_and_the_repeat_is_silent
//MUTANT mark-not-keyed-to-boot|s@^    seen.trim_end() == boot$@    !seen.is_empty()@|a_new_boot_is_reported_though_an_older_one_was_already_marked
//MUTANT boot-unrecorded-at-session-start|s@^        let _ = record_boot(&git_dir, &boot);$@        let _ = (\&git_dir, \&boot);@|report_once_records_this_boot_before_it_reads

use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::Result;

use crate::error::UsageError;
use crate::exit::ExitCode;

/// The journal family carrying the beats and the deliberate stops.
pub const BEATS: &str = "reclaim-beats";

/// The journal family carrying every boot this git directory has seen.
pub const BOOTS: &str = "reclaim-boots";

/// The once-per-boot mark, a file beside the beats' journal.
const MARK: &str = "reported";

/// The override for this container's boot time, authoritative when set.
pub const BOOT_TIME_ENV: &str = "BATTEN_BOOT_TIME";

/// Why the boot time could not be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BootUnreadable {
    /// The override is set and is not a run of ASCII digits (CLOUD-418): a
    /// malformed override is could-not-look, never a silent `/proc/stat` fallback.
    Malformed,
    /// No override, and no `btime` line this process can read.
    Unavailable,
}

/// The override's value as a boot time: digits only, and at least one.
#[must_use]
pub fn parse_override(value: &str) -> Option<String> {
    (!value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit())).then(|| value.to_owned())
}

/// The `btime` field of a `/proc/stat` document.
#[must_use]
pub fn parse_btime(stat: &str) -> Option<String> {
    stat.lines().find_map(|line| {
        let mut fields = line.split_whitespace();
        (fields.next() == Some("btime"))
            .then(|| fields.next())
            .flatten()
            .and_then(parse_override)
    })
}

/// This container's boot time, as the decimal seconds the stores key on.
///
/// `BATTEN_BOOT_TIME` first, and when it is SET it is the answer or the refusal:
/// a suite that cannot vary the boot time cannot exercise a single row of the
/// verdict table, and a malformed one that fell through to `/proc/stat` would
/// hide the typo behind a real reading. Then `/proc/stat`'s `btime`. There is no
/// `uptime` fallback: its output is a local wall-clock string that needs a second
/// program to turn into seconds, and a platform without `/proc/stat` is
/// could-not-look rather than a guess.
///
/// # Errors
///
/// [`BootUnreadable`] as above.
pub fn boot_time() -> std::result::Result<String, BootUnreadable> {
    if let Some(value) = std::env::var_os(BOOT_TIME_ENV) {
        let value = value.to_str().and_then(parse_override);
        return value.ok_or(BootUnreadable::Malformed);
    }
    std::fs::read_to_string("/proc/stat")
        .ok()
        .as_deref()
        .and_then(parse_btime)
        .ok_or(BootUnreadable::Unavailable)
}

/// What the last record under one boot says about that boot's end.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Its last record is a beat: a landing was in flight when it went.
    Active(String),
    /// Its last record is a deliberate stop: nothing was in flight.
    Idle(String),
    /// It recorded nothing. Never idle (CLOUD-696).
    Unobserved,
}

/// Classify one boot from the last `h`/`x` record written UNDER it.
///
/// Over the whole store, because the newest line overall may belong to a
/// different container entirely — that was the defect. A record is
/// `<kind> <epoch> <boot> [reason]`; anything else is not a record.
#[must_use]
pub fn classify(beats: &[String], boot: &str) -> Verdict {
    let last = beats.iter().rev().find_map(|line| {
        let mut fields = line.split(' ');
        let kind = fields.next()?;
        let epoch = fields.next()?;
        let under = fields.next()?;
        (matches!(kind, "h" | "x") && under == boot).then_some((kind, epoch))
    });
    match last {
        Some(("h", epoch)) => Verdict::Active(epoch.to_owned()),
        Some((_, epoch)) => Verdict::Idle(epoch.to_owned()),
        None => Verdict::Unobserved,
    }
}

/// The boots a store records, in order: digit lines only.
fn boot_list(boots: &[String]) -> impl Iterator<Item = &str> {
    boots
        .iter()
        .map(String::as_str)
        .filter(|line| parse_override(line).is_some())
}

/// The boot this one replaced: the newest recorded boot that is not `this`.
#[must_use]
pub fn previous<'a>(boots: &'a [String], this: &str) -> Option<&'a str> {
    boot_list(boots).filter(|boot| *boot != this).last()
}

/// Every recorded replacement, by what it interrupted.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Tally {
    /// Consecutive boot pairs.
    pub transitions: usize,
    /// Of those, the ones whose outgoing boot's last record is a beat.
    pub active: usize,
    /// The ones whose outgoing boot stopped on purpose.
    pub idle: usize,
    /// The ones whose outgoing boot recorded nothing.
    pub unobserved: usize,
}

/// Classify every boundary in one pass, so counting cannot accumulate: the same
/// history read twice gives the same answer.
#[must_use]
pub fn tally(boots: &[String], beats: &[String]) -> Tally {
    let list: Vec<&str> = boot_list(boots).collect();
    let mut counted = Tally::default();
    for pair in list.windows(2) {
        counted.transitions += 1;
        match classify(beats, pair[0]) {
            Verdict::Active(_) => counted.active += 1,
            Verdict::Idle(_) => counted.idle += 1,
            Verdict::Unobserved => counted.unobserved += 1,
        }
    }
    counted
}

/// A family's journal directory under `git_dir`.
fn store(git_dir: &Path, family: &str) -> PathBuf {
    crate::record::journal_store(git_dir, family)
}

/// Every whole record of a family, or `None` when its store cannot be read.
fn fold(git_dir: &Path, family: &str) -> Option<Vec<String>> {
    match crate::journal::fold_lines(&store(git_dir, family)) {
        crate::journal::Fold::Nothing => Some(Vec::new()),
        crate::journal::Fold::Records(records) => Some(records),
        crate::journal::Fold::Unreadable(_) => None,
    }
}

/// The one shard each family is written to.
///
/// ONE, and named rather than derived: the stores already hang off the
/// per-worktree git directory, so a worktree is the only writer either way — and
/// "the last boot recorded" is only a meaningful phrase over one append order.
/// Two shards would fold back sorted by shard name, not by time.
pub const SHARD: &str = "census";

/// Append one record to a family, durably.
fn append(git_dir: &Path, family: &str, line: &str) -> Result<()> {
    crate::journal::append_line(&store(git_dir, family), SHARD, line)
}

/// The per-worktree git directory, or `None` outside a repository.
fn git_dir() -> Option<PathBuf> {
    crate::git::git_dir(Path::new(".")).ok()
}

/// Seconds since the epoch; `0` when the clock will not answer.
fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| since.as_secs())
}

/// `record census note <h|x> [reason]`.
///
/// **ALWAYS EXIT 0 once the invocation is well-formed**: it is called from inside
/// the lease's renewal loop, and a census that could abort a landing is worse than
/// the evidence it fails to collect. The reason is OMITTED rather than empty,
/// because a trailing space is a byte difference (rule 5).
///
/// # Errors
///
/// A [`UsageError`] when the kind is neither `h` nor `x`, or the reason is not
/// one word — a reason with a space would fold back as a record with extra
/// fields, and one with a newline as two records.
pub fn run_note(kind: &str, reason: Option<&str>) -> Result<ExitCode> {
    if !matches!(kind, "h" | "x") {
        return Err(UsageError::raise(format!(
            "record census note: the kind is h or x, not {kind:?}"
        )));
    }
    let reason = reason.filter(|reason| !reason.is_empty());
    if reason.is_some_and(|reason| reason.chars().any(char::is_whitespace)) {
        return Err(UsageError::raise(String::from(
            "record census note: the reason is one word",
        )));
    }
    let (Some(git_dir), Ok(boot)) = (git_dir(), boot_time()) else {
        return Ok(ExitCode::Success);
    };
    let epoch = now();
    let line = match reason {
        Some(reason) => format!("{kind} {epoch} {boot} {reason}"),
        None => format!("{kind} {epoch} {boot}"),
    };
    let _ = append(&git_dir, BEATS, &line);
    Ok(ExitCode::Success)
}

/// Record this boot unless the store's last boot already is it.
///
/// Idempotent by the LAST line rather than by membership: a boot time that
/// recurs after a different one is a genuine new boundary.
fn record_boot(git_dir: &Path, boot: &str) -> Option<()> {
    let boots = fold(git_dir, BOOTS)?;
    if boots.last().map(String::as_str) != Some(boot) {
        append(git_dir, BOOTS, boot).ok()?;
    }
    Some(())
}

/// `record census record-boot`.
///
/// # Errors
///
/// Never: could-not-look is exit 3 on stderr, and a store that cannot be
/// written is exit 0 for [`run_note`]'s reason.
pub fn run_record_boot(err: &mut dyn Write) -> Result<ExitCode> {
    let Ok(boot) = boot_time() else {
        writeln!(
            err,
            "batten: record census: cannot read this container's boot time — not recording it"
        )?;
        return Ok(ExitCode::Internal);
    };
    let Some(git_dir) = git_dir() else {
        writeln!(
            err,
            "batten: record census: not a git repository — cannot record this boot"
        )?;
        return Ok(ExitCode::Internal);
    };
    let _ = record_boot(&git_dir, &boot);
    Ok(ExitCode::Success)
}

/// The report for the boundary this container sits on.
enum Reading {
    /// The verdict, the boot it judged, and this boot.
    Judged(Verdict, String, String),
    /// Nothing to judge, with the reason.
    CannotLook(String),
}

fn read_boundary() -> Reading {
    let Ok(boot) = boot_time() else {
        return Reading::CannotLook(String::from(
            "cannot read this container's boot time — cannot say what the last replacement \
             interrupted",
        ));
    };
    let Some(git_dir) = git_dir() else {
        return Reading::CannotLook(String::from(
            "not a git repository — cannot say what the last replacement interrupted",
        ));
    };
    let (Some(boots), Some(beats)) = (fold(&git_dir, BOOTS), fold(&git_dir, BEATS)) else {
        return Reading::CannotLook(String::from("the census store cannot be read"));
    };
    let Some(prev) = previous(&boots, &boot) else {
        return Reading::CannotLook(format!(
            "no boot predates {boot} — this container's disk carries no evidence either way"
        ));
    };
    Reading::Judged(classify(&beats, prev), prev.to_owned(), boot)
}

/// The line the positive reading prints.
fn in_flight(epoch: &str, prev: &str, boot: &str) -> String {
    format!(
        "record census: A LANDING WAS IN FLIGHT when this container replaced the last one \
         (last beat {epoch} under boot {prev}, now {boot})"
    )
}

/// `record census report [--once]`.
///
/// Without `--once` the predecessor's codes are kept: `0` a landing was in
/// flight (stdout), `1` it stopped on purpose (stdout), `2` unobserved or nothing
/// to judge (stderr).
///
/// `--once` is the session-start form (CLOUD-1301), and it absorbs what
/// `[tasks."session:census"]` did around the report. RECORD BEFORE READ, because
/// recording after reading would make this boot part of the evidence it is
/// compared against. Only the positive reading speaks, and only once per BOOT:
/// the previous boot is immutable history, so after the first read the verdict is
/// noise. The mark is keyed to the boot, which is what makes it self-clearing on
/// a new container. It prints BEFORE the mark is written, so a mark that cannot be
/// written still reports — suppression is what must fail closed, never the
/// report. Always exit `0`: a verdict about a past container is not a failure of
/// this session.
///
/// # Errors
///
/// When stdout or stderr cannot be written.
pub fn run_report(once: bool, out: &mut dyn Write, err: &mut dyn Write) -> Result<ExitCode> {
    if once {
        return run_report_once(out);
    }
    match read_boundary() {
        Reading::Judged(Verdict::Active(epoch), prev, boot) => {
            writeln!(out, "{}", in_flight(&epoch, &prev, &boot))?;
            Ok(ExitCode::Success)
        }
        Reading::Judged(Verdict::Idle(epoch), prev, _) => {
            writeln!(
                out,
                "record census: the last landing stopped on purpose at {epoch} — no landing was \
                 in flight when boot {prev} was replaced"
            )?;
            Ok(ExitCode::Usage)
        }
        Reading::Judged(Verdict::Unobserved, prev, _) => {
            writeln!(
                err,
                "batten: record census: boot {prev} recorded nothing — UNOBSERVED, not idle; \
                 this sensor only sees landings and none ran there"
            )?;
            Ok(ExitCode::Violation)
        }
        Reading::CannotLook(why) => {
            writeln!(err, "batten: record census: {why}")?;
            Ok(ExitCode::Violation)
        }
    }
}

/// Whether the once-per-boot mark says `boot`'s verdict was already read. An
/// absent or unreadable mark says nothing, so the report speaks.
fn marked_for(mark: &Path, boot: &str) -> bool {
    let seen = std::fs::read_to_string(mark).unwrap_or_default();
    seen.trim_end() == boot
}

fn run_report_once(out: &mut dyn Write) -> Result<ExitCode> {
    if let (Ok(boot), Some(git_dir)) = (boot_time(), git_dir()) {
        let _ = record_boot(&git_dir, &boot);
    }
    let Reading::Judged(Verdict::Active(epoch), prev, boot) = read_boundary() else {
        return Ok(ExitCode::Success);
    };
    let mark = git_dir().map(|git_dir| store(&git_dir, BEATS).join(MARK));
    if let Some(mark) = &mark
        && marked_for(mark, &boot)
    {
        return Ok(ExitCode::Success);
    }
    writeln!(out, "{}", in_flight(&epoch, &prev, &boot))?;
    if let Some(mark) = mark
        && let Some(dir) = mark.parent()
        && std::fs::create_dir_all(dir).is_ok()
    {
        let _ = crate::durable::replace(&mark, format!("{boot}\n"));
    }
    Ok(ExitCode::Success)
}

/// `record census tally`.
///
/// **A disk that records no replacement is a count of zero, and zero is an
/// answer** (exit 0): the predecessor exited 2 there, which under §7 is a
/// verdict about the repository, and a tally renders none. Could-not-look — no
/// git directory, a store that cannot be read — is exit 3.
///
/// # Errors
///
/// When stdout or stderr cannot be written.
pub fn run_tally(out: &mut dyn Write, err: &mut dyn Write) -> Result<ExitCode> {
    let Some(git_dir) = git_dir() else {
        writeln!(
            err,
            "batten: record census: not a git repository — nothing to tally"
        )?;
        return Ok(ExitCode::Internal);
    };
    let (Some(boots), Some(beats)) = (fold(&git_dir, BOOTS), fold(&git_dir, BEATS)) else {
        writeln!(
            err,
            "batten: record census: the census store cannot be read"
        )?;
        return Ok(ExitCode::Internal);
    };
    let counted = tally(&boots, &beats);
    writeln!(
        out,
        "record census: {} replacement(s) recorded — {} with a landing in flight, {} idle of \
         landings, {} unobserved",
        counted.transitions, counted.active, counted.idle, counted.unobserved
    )?;
    Ok(ExitCode::Success)
}

/// Dispatch `record census`.
///
/// # Errors
///
/// As the chosen arm.
pub fn run(
    command: crate::cli::RecordCensusCommand,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Result<ExitCode> {
    match command {
        crate::cli::RecordCensusCommand::Note { kind, reason } => {
            run_note(&kind, reason.as_deref())
        }
        crate::cli::RecordCensusCommand::RecordBoot => run_record_boot(err),
        crate::cli::RecordCensusCommand::Report { once } => run_report(once, out, err),
        crate::cli::RecordCensusCommand::Tally => run_tally(out, err),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lines(text: &[&str]) -> Vec<String> {
        text.iter().map(|line| (*line).to_owned()).collect()
    }

    #[test]
    fn a_beat_under_the_judged_boot_is_active() {
        assert_eq!(
            classify(&lines(&["h 1400 1500"]), "1500"),
            Verdict::Active(String::from("1400"))
        );
    }

    #[test]
    fn a_stop_after_the_beats_is_idle() {
        assert_eq!(
            classify(&lines(&["h 1300 1500", "x 1400 1500 land-stopped"]), "1500"),
            Verdict::Idle(String::from("1400"))
        );
    }

    #[test]
    fn absence_is_unobserved_never_idle() {
        assert_eq!(classify(&[], "1500"), Verdict::Unobserved);
        assert_eq!(
            classify(&lines(&["h 2100 2000"]), "1500"),
            Verdict::Unobserved,
            "records under ANOTHER boot do not answer for this one"
        );
    }

    #[test]
    fn the_newest_line_overall_does_not_answer_for_an_older_boot() {
        // The defect: the store's newest line is real, and belongs elsewhere.
        assert_eq!(
            classify(&lines(&["h 900 1000", "x 1600 2000 land-stopped"]), "1000"),
            Verdict::Active(String::from("900"))
        );
    }

    #[test]
    fn previous_is_the_newest_boot_that_is_not_this_one() {
        let boots = lines(&["1000", "1500", "2000"]);
        assert_eq!(previous(&boots, "2000"), Some("1500"));
        assert_eq!(previous(&lines(&["2000"]), "2000"), None);
        assert_eq!(previous(&lines(&["1000", "junk"]), "2000"), Some("1000"));
    }

    #[test]
    fn tally_classifies_every_boundary() {
        let counted = tally(&lines(&["1000", "1500", "2000"]), &lines(&["h 900 1000"]));
        assert_eq!(
            counted,
            Tally {
                transitions: 2,
                active: 1,
                idle: 0,
                unobserved: 1
            }
        );
        assert_eq!(tally(&lines(&["2000"]), &[]).transitions, 0);
    }

    #[test]
    fn the_boot_override_takes_digits_only() {
        assert_eq!(parse_override("2000"), Some(String::from("2000")));
        assert_eq!(parse_override(""), None);
        assert_eq!(parse_override("nonsense"), None);
        assert_eq!(parse_override("20 00"), None);
    }

    #[test]
    fn btime_is_read_from_its_own_line() {
        assert_eq!(
            parse_btime("cpu 1 2 3\nbtime 1700000000\nprocesses 9\n"),
            Some(String::from("1700000000"))
        );
        assert_eq!(parse_btime("cpu 1 2 3\n"), None);
        assert_eq!(parse_btime("btime x\n"), None);
    }
}
