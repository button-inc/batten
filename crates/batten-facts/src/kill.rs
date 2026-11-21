//! The kill-at-a-step hook crash-only code is tested with (CLOUD-2722).
//!
//! In the lowest crate because the lowest durable write is here
//! ([`crate::durable`]); `batten_core::testing` re-exports it, so every caller
//! above names one hook.

thread_local! {
    /// How many more durable steps this thread may take before it is "killed",
    /// or `None` where no case has armed it ([`kill_after`]).
    static STEPS_LEFT: std::cell::Cell<Option<u64>> = const { std::cell::Cell::new(None) };
    /// Whether an armed thread has reached its kill.
    static KILLED: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Arm this thread to be "killed" at its `steps`-th durable step from now, or
/// disarm it with `None`.
///
/// WHAT A CRASH-ONLY CLAIM IS TESTED WITH. A case that kills a run at the
/// points its author thought of proves those points. Armed with every count
/// from zero until a run finishes unkilled, a case has stopped the run before
/// EVERY step that changes a file, a ref or the remote, and can assert that the
/// next start reaches the one end state from each.
///
/// A killed thread stays killed: every later step fails too, so nothing is
/// written after the kill, as nothing is after a real one. Nothing outside a
/// test can arm it — it reads no environment variable and the binary never
/// calls it — and unarmed, [`step`] is one thread-local read.
#[doc(hidden)]
pub fn kill_after(steps: Option<u64>) {
    STEPS_LEFT.with(|left| left.set(steps));
    KILLED.with(|killed| killed.set(false));
}

/// Whether this thread was killed since it was last armed.
#[doc(hidden)]
#[must_use]
pub fn killed() -> bool {
    KILLED.with(std::cell::Cell::get)
}

/// One durable step is about to be taken: a file replaced, a ref moved, a
/// request sent. Called by the code that takes it, before it does.
///
/// # Errors
///
/// Where a case armed this thread ([`kill_after`]) and its steps are spent.
#[doc(hidden)]
pub fn step() -> std::io::Result<()> {
    STEPS_LEFT.with(|left| match left.get() {
        None => Ok(()),
        Some(0) => {
            KILLED.with(|killed| killed.set(true));
            Err(std::io::Error::other("killed at a durable step"))
        }
        Some(more) => {
            left.set(Some(more - 1));
            Ok(())
        }
    })
}
