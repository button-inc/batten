//! The `/proc` layouts Batten reads, as pure functions so every platform's suite
//! checks them, and the one reader built on them that `land`'s reaper needs
//! ([`group_predates`], CLOUD-2366). The disk collector dates a process by the
//! same layouts. A leaf, so neither reader drags the other's closure in — `exec`
//! least of all, whose closure every spawning module inherits.

//MUTANT-SUITE crates/batten/src/proc_stat.rs
//MUTANT stat-start-misread|s@^        rest.split_whitespace().nth(19)?.parse().ok()$@        rest.split_whitespace().nth(18)?.parse().ok()@|a_stat_line_yields_its_start_ticks
//MUTANT member-predates-tie|s@ 1 < alive_at@ 1 <= alive_at@|a_group_member_predates_only_strictly_before

/// Field 22 of a `/proc/<pid>/stat` line, `starttime`: read after the LAST
/// `)`, since the command name in field 2 may itself hold spaces and parens.
#[cfg(any(target_os = "linux", target_os = "android", test))]
pub(crate) fn start_ticks(stat: &str) -> Option<u64> {
    let (_, rest) = stat.rsplit_once(')')?;
    rest.split_whitespace().nth(19)?.parse().ok()
}

/// Field 5 of a `/proc/<pid>/stat` line, `pgrp`, read after the last `)`
/// for [`start_ticks`]'s reason.
#[cfg(any(target_os = "linux", target_os = "android", test))]
pub(crate) fn process_group(stat: &str) -> Option<i64> {
    let (_, rest) = stat.rsplit_once(')')?;
    rest.split_whitespace().nth(2)?.parse().ok()
}

/// Whether a `/proc/<pid>/stat` line is a member of `group` that began
/// strictly before second `alive_at`, against the boot instant and clock
/// rate. One second of slack absorbs `btime`'s own rounding, so a tie is no.
#[cfg(any(target_os = "linux", target_os = "android", test))]
pub(crate) fn member_predates(
    stat: &str,
    group: i64,
    boot: u64,
    ticks: u64,
    alive_at: u64,
) -> bool {
    process_group(stat) == Some(group)
        && start_ticks(stat).is_some_and(|since| boot + since / ticks.max(1) + 1 < alive_at)
}

/// `/proc/stat`'s `btime`: the boot instant, in seconds since the epoch.
#[cfg(any(target_os = "linux", target_os = "android", test))]
pub(crate) fn boot_seconds(stat: &str) -> Option<u64> {
    stat.lines()
        .find_map(|line| line.strip_prefix("btime "))?
        .trim()
        .parse()
        .ok()
}

/// Whether a recorded group still holds a process that began before second
/// `alive_at`, which is what makes it the orphan rather than somebody's live
/// group under a reused number.
///
/// **AGE IS THE DISCRIMINATOR** (CLOUD-2366). Linux keeps a pid number reserved
/// while any live process still uses it as a process-group id, so the number is
/// reusable only once the group is EMPTY. The registrant was a member and was
/// alive at `alive_at`, its latest stamp, so the original group was not empty
/// then: every member of a reused group began after that second. A member that
/// began before it can only be the original's. A leader test cannot say this —
/// a reused group loses its leader as easily as an orphan does
/// (`setsid sh -c 'server &'`), and a zombie leader still answers a probe.
///
/// The caller's own group is never the orphan, however old: a second run in
/// the shell that ran the first shares its group. What it misses is safe: an
/// orphan whose every survivor was spawned after the last stamp is not
/// signalled. Across a reboot every process began after `btime`, so a stale
/// record never qualifies. `false` for an unparseable or
/// non-positive pgid and wherever `/proc` cannot be read: a reap may only
/// proceed on proof.
#[cfg(any(target_os = "linux", target_os = "android"))]
pub(crate) fn group_predates(pgid: &str, alive_at: u64) -> bool {
    let Some(group) = pgid.parse::<i64>().ok().filter(|group| *group > 0) else {
        return false;
    };
    if group == i64::from(rustix::process::getpgrp().as_raw_nonzero().get()) {
        return false;
    }
    let Some(boot) = std::fs::read_to_string("/proc/stat")
        .ok()
        .and_then(|stat| boot_seconds(&stat))
    else {
        return false;
    };
    let ticks = rustix::param::clock_ticks_per_second();
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return false;
    };
    entries.filter_map(Result::ok).any(|entry| {
        std::fs::read_to_string(entry.path().join("stat"))
            .is_ok_and(|stat| member_predates(&stat, group, boot, ticks, alive_at))
    })
}

/// No `/proc` to date a member by, so none is ever proven the orphan's and
/// nothing is reaped.
#[cfg(not(any(target_os = "linux", target_os = "android")))]
pub(crate) fn group_predates(_pgid: &str, _alive_at: u64) -> bool {
    false
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    #[test]
    fn a_stat_line_yields_its_start_ticks() {
        // A command name holding a space and a paren, as `(cargo nextest)` and
        // worse can: the fields are read after the LAST `)`.
        let stat =
            "4242 (a) b) S 1 4242 4242 0 -1 4194560 100 0 0 0 5 3 0 0 20 0 1 0 987654 1000 100";
        assert_eq!(super::start_ticks(stat), Some(987_654));
        assert_eq!(super::start_ticks("4242 (cut"), None);
        assert_eq!(
            super::boot_seconds("cpu  1 2 3\nbtime 1700000000\nprocesses 9\n"),
            Some(1_700_000_000)
        );
    }

    /// CLOUD-2366: started at `1_700_009_876` (9876 s after boot at 100 Hz), in
    /// group 4242; a member predates only a second it began strictly before.
    #[test]
    fn a_group_member_predates_only_strictly_before() {
        let stat =
            "4243 (a) b) S 1 4242 4242 0 -1 4194560 100 0 0 0 5 3 0 0 20 0 1 0 987654 1000 100";
        assert_eq!(super::process_group(stat), Some(4242));
        let boot = 1_700_000_000;
        assert!(super::member_predates(stat, 4242, boot, 100, 1_700_009_878));
        assert!(!super::member_predates(
            stat,
            4242,
            boot,
            100,
            1_700_009_877
        ));
        assert!(!super::member_predates(
            stat,
            4243,
            boot,
            100,
            1_700_009_999
        ));
    }

    /// CLOUD-2366: a child leading its own group began before any later second
    /// wherever `/proc` dates it and nowhere else; nothing began before the
    /// epoch, and the caller's own group is never the orphan.
    #[test]
    fn a_group_predates_only_a_second_after_its_member_began() {
        for nonsense in ["0", "-1", "not-a-number"] {
            assert!(!super::group_predates(nonsense, u64::MAX), "{nonsense}");
        }
        #[cfg(unix)]
        #[expect(
            clippy::disallowed_types,
            reason = "stays: the case needs a real group led by a live process, which only a spawn makes"
        )]
        {
            use std::os::unix::process::CommandExt as _;
            let mut child = std::process::Command::new("cat")
                .stdin(std::process::Stdio::piped())
                .process_group(0)
                .spawn()
                .expect("spawn a group leader");
            let group = child.id().to_string();
            let began = super::group_predates(&group, u64::MAX);
            let epoch = super::group_predates(&group, 0);
            let own = rustix::process::getpgrp()
                .as_raw_nonzero()
                .get()
                .to_string();
            let own_group = super::group_predates(&own, u64::MAX);
            let _ = child.kill();
            let _ = child.wait();
            assert_eq!(began, cfg!(any(target_os = "linux", target_os = "android")));
            assert!(!epoch, "nothing began before the epoch");
            assert!(!own_group, "the caller's own group is never the orphan");
        }
    }
}
