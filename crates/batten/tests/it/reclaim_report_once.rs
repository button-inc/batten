//! The reclaim verdict is reported once per BOOT, not once per session
//! (CLOUD-1301), by `batten record census report --once` (CLOUD-843).
//!
//! # The defect
//!
//! `report` classifies the PREVIOUS boot, resolved as the newest recorded boot
//! that is not this one. That is immutable history: recording this boot does not
//! move it, and no landing completed here changes what the last container was
//! doing when it died. So on a container whose predecessor was reclaimed
//! mid-landing the verdict is TRUE and repeats at every session start for the
//! life of the container — and after the first read it is exactly the noise
//! CLOUD-891 removed.
//!
//! # Why the verb, and what moved into it
//!
//! The suppression lived in `[tasks."session:census"]`'s shell body, which called
//! the census four times to rebuild the mark path from `log-path` and `boot`. The
//! mark is now written by the verb that knows where its own store is, so there is
//! no second opinion about the path to drift — and the handler row is argv.
//!
//! # The isolation
//!
//! Both stores hang off the clone's git directory and the boot time is
//! `BATTEN_BOOT_TIME`-injectable, so every verdict is driven without touching
//! the container's real record — which matters more than usual here: this
//! container's own store may carry a live reclaim, and a suite that read it
//! would suppress the very verdict a human still needs.
//!
//! # RETIREMENT LEDGER
//!
// carried: "a reclaim is reported once and the repeat is silent" crates/batten/src/reclaim.rs kind:verb
// carried: "a predecessor that stopped on purpose is silent throughout" crates/batten/src/reclaim.rs kind:verb
// carried: "a new boot is reported though an older one was already marked" crates/batten/src/reclaim.rs kind:verb
// changed: "the mark is $GIT_DIR/batten-reclaim-log.reported" crates/batten/src/reclaim.rs kind:verb the mark sits beside the beats' journal, outside its shards, and is still keyed to the boot; the planted "older boot" mark below is written there
// changed: "session:census exits 0 whatever the report says" crates/batten/src/reclaim.rs kind:verb carried as `report --once`'s own contract rather than a shell `|| exit 0`: every reading, including could-not-look, is exit 0 and only the positive one speaks

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::{Path, PathBuf};

/// The boot this fixture claims to be running under. Any value works; it only
/// has to differ from the recorded predecessor.
const NOW: &str = "9000";

/// The predecessor boot the seeded records belong to.
const BEFORE: &str = "500";

/// `batten record census <args>` in `repo` under `boot`.
fn census(repo: &Path, boot: &str, args: &[&str]) -> (Option<i32>, String, String) {
    let out = common::batten()
        .args(["record", "census"])
        .args(args)
        .current_dir(repo)
        .env("BATTEN_BOOT_TIME", boot)
        .output()
        .expect("run the census");
    (
        out.status.code(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// A clone whose predecessor boot `BEFORE` beat and then wrote `last`: `h` is
/// another heartbeat, so it was mid-landing when it went; `x` is a deliberate
/// stop.
fn seeded(name: &str, last: &str) -> PathBuf {
    let repo = common::scratch(&format!("reclaim-report-once-{name}"));
    common::init_repo(&repo);
    assert_eq!(census(&repo, BEFORE, &["record-boot"]).0, Some(0));
    assert_eq!(census(&repo, BEFORE, &["note", "h"]).0, Some(0));
    let tail: &[&str] = if last == "x" {
        &["note", "x", "land-stopped"]
    } else {
        &["note", "h"]
    };
    assert_eq!(census(&repo, BEFORE, tail).0, Some(0));
    repo
}

/// One session start, as the handler row invokes it. Always exit 0: a verdict
/// about a PAST container is never a failure of this session.
fn session_start(repo: &Path) -> String {
    let (code, out, err) = census(repo, NOW, &["report", "--once"]);
    assert_eq!(code, Some(0), "{out}{err}");
    out
}

/// Does this session's output carry the reclaim verdict?
fn reported(output: &str) -> bool {
    output.contains("A LANDING WAS IN FLIGHT")
}

#[test]
fn a_reclaim_is_reported_once_and_the_repeat_is_silent() {
    let repo = seeded("reported-once", "h");

    assert!(
        reported(&session_start(&repo)),
        "the first session on a container whose predecessor was reclaimed \
         mid-landing must still be told"
    );
    assert!(
        !reported(&session_start(&repo)),
        "the fact is once per boot, so every session after the first is noise"
    );
}

#[test]
fn a_predecessor_that_stopped_on_purpose_is_silent_throughout() {
    // The negative reading, asserted so it stays that way: an ordinary stop is
    // not news, and a fix that started announcing one would be louder than the
    // defect it replaced.
    let repo = seeded("intentional-stop", "x");

    assert_eq!(session_start(&repo), "", "first session");
    assert_eq!(session_start(&repo), "", "second session");
}

#[test]
fn a_new_boot_is_reported_though_an_older_one_was_already_marked() {
    // THE VACUITY CASE. Suppression keyed to anything but the boot — a flag, a
    // once-per-clone marker — would silence the NEXT container's genuine reclaim
    // too, which deletes the instrument CLOUD-451 built rather than quietening
    // it. A mark left by another boot must not suppress this one's verdict.
    let repo = seeded("new-boot", "h");
    std::fs::write(
        repo.join(".git/batten-journals/reclaim-beats/reported"),
        "1\n",
    )
    .expect("plant a mark from an older boot");

    assert!(
        reported(&session_start(&repo)),
        "a mark from a different boot says nothing about this one"
    );
    assert!(
        !reported(&session_start(&repo)),
        "and this boot's own mark then suppresses the repeat"
    );
}

#[test]
fn report_once_records_this_boot_before_it_reads() {
    // RECORD BEFORE READ, and the order is load-bearing: recording after reading
    // would make this boot part of the evidence it is compared against. What is
    // observable from outside is that the session start RECORDED it — the next
    // container's census has this boundary to judge.
    let repo = seeded("records", "h");
    let _ = session_start(&repo);
    let (code, out, err) = census(&repo, NOW, &["tally"]);
    assert_eq!(code, Some(0), "{out}{err}");
    assert!(
        out.contains("1 replacement(s)") && out.contains("1 with a landing in flight"),
        "{out}"
    );
}

#[test]
fn every_reading_is_exit_zero_and_only_the_positive_one_speaks() {
    // A fresh disk has no predecessor to judge: the plain `report` says so on
    // stderr at exit 3 (could-not-look), and the session-start form stays
    // silent at exit 0.
    let repo = common::scratch("reclaim-report-once-fresh");
    common::init_repo(&repo);
    assert_eq!(census(&repo, NOW, &["report"]).0, Some(3));
    assert_eq!(session_start(&repo), "");
    // And a malformed boot time is could-not-look, which is still silent.
    let (code, out, _) = census(&repo, "nonsense", &["report", "--once"]);
    assert_eq!((code, out.as_str()), (Some(0), ""));
}
