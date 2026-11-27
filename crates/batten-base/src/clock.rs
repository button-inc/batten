//! The boundary's wall clock, in whole seconds since the epoch.
//!
//! A leaf: it names nothing in this crate, so a module that only needs the time
//! does not reach up into the crate root for it. The decision path may not take
//! a clock (`ambient_authority.rs` gates that); a READER at the boundary may, and
//! what it feeds is a recorded or rendered age, never a verdict.

/// Seconds since the epoch, or zero where the clock will not read — a timestamp
/// nobody can produce is recorded as one rather than refusing the caller.
#[must_use]
pub fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| since.as_secs())
}

/// The civil `(year, month, day)` of an instant given as seconds since the
/// Unix epoch, UTC.
///
/// The standard era-based civil-from-days algorithm, hand-written so a date
/// costs no dependency, and kept ONCE: `waiver::Date::from_unix_seconds` and
/// [`rfc3339_utc`] both read their date from here, so it cannot be right in
/// one module and wrong in the other.
#[must_use]
pub fn civil(seconds: u64) -> (u64, u64, u64) {
    // Shift to the era starting 0000-03-01; every quantity below is
    // non-negative, so the arithmetic stays in u64.
    let z = seconds / 86_400 + 719_468;
    let era = z / 146_097;
    let day_of_era = z % 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let mp = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = year_of_era + era * 400 + u64::from(month <= 2);
    (year, month, day)
}

/// An instant as an RFC 3339 UTC timestamp, `YYYY-MM-DDTHH:MM:SSZ`.
///
/// The date half is [`civil`]; only the time-of-day arithmetic is here.
///
/// **A receipt's validity never reads this timestamp — expiry is a git fact,
/// never a clock.** That is right for a receipt and does not generalise: a
/// receipt's claim is about a specific SHA, so a SHA comparison is the
/// invalidator. A waiver's claim is a human judgement whose warrant decays in
/// calendar time and leaves no git trace, which is why `waiver` does evaluate a
/// clock — at its boundary, with the date threaded in as data (CLOUD-208).
#[must_use]
pub fn rfc3339_utc(unix_seconds: u64) -> String {
    let (year, month, day) = civil(unix_seconds);
    let second_of_day = unix_seconds % 86_400;
    let (hour, minute, second) = (
        second_of_day / 3_600,
        (second_of_day % 3_600) / 60,
        second_of_day % 60,
    );
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}
