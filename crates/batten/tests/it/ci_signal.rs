//! A run's state is classified once, and an unfinished run is never graded
//! (CLOUD-2243).

use batten::forge::{Conclusion, RunState};

#[test]
fn an_in_progress_run_is_never_concluded() {
    // `ci_signal` stored `status` into `conclusion` when the latter was null,
    // so a running run carried the conclusion `in_progress` and was graded.
    for status in [
        "in_progress",
        "queued",
        "waiting",
        "requested",
        "pending",
        "novel",
    ] {
        let state = RunState::of(Some(status), None);
        assert_eq!(state.conclusion(), None, "{status} read as concluded");
    }
    assert_eq!(RunState::of(None, Some("success")).conclusion(), None);
}

#[test]
fn every_conclusion_is_read_from_its_own_field() {
    for (text, conclusion) in [
        ("success", Conclusion::Success),
        ("neutral", Conclusion::Neutral),
        ("skipped", Conclusion::Skipped),
        ("failure", Conclusion::Failure),
        ("cancelled", Conclusion::Cancelled),
        ("timed_out", Conclusion::TimedOut),
        ("action_required", Conclusion::ActionRequired),
        ("stale", Conclusion::Stale),
        (
            "invented_tomorrow",
            Conclusion::Unknown(String::from("invented_tomorrow")),
        ),
    ] {
        assert_eq!(
            RunState::of(Some("completed"), Some(text)),
            RunState::Completed(conclusion),
            "{text}"
        );
    }
    // A completed run with no conclusion is unknown, never its status.
    assert_eq!(
        RunState::of(Some("completed"), None),
        RunState::Completed(Conclusion::Unknown(String::new()))
    );
}

#[test]
fn the_two_verdicts_are_named_once() {
    // The merge gate takes neutral; a release publishes on success alone.
    assert!(Conclusion::Success.passes_gate() && Conclusion::Success.publishes());
    assert!(Conclusion::Neutral.passes_gate() && !Conclusion::Neutral.publishes());
    for other in [
        Conclusion::Skipped,
        Conclusion::Failure,
        Conclusion::Cancelled,
        Conclusion::TimedOut,
        Conclusion::ActionRequired,
        Conclusion::Stale,
        Conclusion::Unknown(String::new()),
    ] {
        assert!(!other.passes_gate() && !other.publishes(), "{other:?}");
    }
}
