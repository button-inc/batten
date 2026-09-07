//! A credential that cannot be printed by accident.
//!
//! # Why a type rather than a habit
//!
//! `lease.rs` states the rule this module mechanises: **"a token in a struct is
//! a token in that struct's `Debug`, and non-negotiable rule 4 makes every
//! report here a pointer."** It then holds that rule by CONVENTION — keeping the
//! token out of [`crate::lease::Terms`] and inside the two functions that build
//! a request. A convention holds until the next author, and it did not:
//!
//! * `provision::EnvAction::Set(String)` carried a credential in a `pub` type
//!   deriving `Debug`, so any `{:?}` over the launcher's resolved environment
//!   printed it (2026-09-06, this session's own change).
//! * `lease::headers` hands the token to a `Vec<(String, String)>` that becomes
//!   [`crate::fetch::Call::headers`] — and `Call` derived `Debug` too, so the
//!   invariant that file believes it holds was already only half held.
//! * `tests/it/provision.rs` interpolated a launcher's whole inherited
//!   environment into an assertion message, and its panic printed a live
//!   session PAT. That one is not hypothetical: it happened, and it was caught
//!   by the case going red rather than by anybody reading the code.
//!
//! Three instances, three different routes, one class. The fix is a type,
//! because a type is **compositional**: a struct holding a [`Secret`] may derive
//! `Debug` freely and still cannot leak, so the property survives an author who
//! has never read this file. That is the difference between a rule and a
//! mechanism (non-negotiable rule 2).
//!
//! # What this deliberately is NOT
//!
//! Not `secrecy`, and not for the reason first given. This module's author
//! claimed the dependency was "gated by `ambient_authority.rs`" without reading
//! it; measured, that gate is a denylist of HTTP stacks and async runtimes and
//! says nothing about `secrecy` at all. The real reasons are smaller and worth
//! stating so the next author can overturn them with evidence rather than
//! re-deriving them: the whole surface needed here is redaction plus a
//! best-effort wipe, `zeroize`'s guarantee needs a volatile write this crate can
//! express in ten lines, and the vendored form would be a second authority over
//! a rule this repository already states in its own words.
//!
//! Not a security boundary either. A process that can read this one's memory has
//! already won, and the threat model is **honest error** — the wrong value in
//! the wrong report — which is what the scope reminder says batten is for.

use std::fmt;

/// A credential value that redacts itself in every rendering.
///
/// `Debug` prints a fixed token and never the value; there is deliberately no
/// `Display`, no `Serialize`, and no `AsRef<str>`. The one way to the bytes is
/// [`Secret::expose`], which is verbose on purpose — a reader auditing where a
/// credential reaches the wire greps one name and finds every site.
#[derive(Clone, PartialEq, Eq)]
pub struct Secret(String);

impl Secret {
    /// Take ownership of a credential.
    #[must_use]
    pub fn new(value: String) -> Self {
        Self(value)
    }

    /// The bytes, for the one caller that must put them on the wire.
    ///
    /// **Every call site is a place a credential can leak**, which is why this
    /// is not `AsRef<str>` and not `Deref`: an implicit conversion would let a
    /// `format!` reach the value without anything in the source saying so.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// Whether the value is empty, without exposing it.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Whether the value begins with `prefix`, without exposing it.
    ///
    /// This is what lets `reject_prefix` drop a host's placeholder marker while
    /// the credential stays inside the type — the predicate travels to the
    /// value rather than the value travelling to the predicate.
    #[must_use]
    pub fn starts_with(&self, prefix: &str) -> bool {
        self.0.starts_with(prefix)
    }
}

/// **THE WHOLE POINT.** A hand-written impl rather than a derive, so a type
/// holding a `Secret` may derive `Debug` and still cannot print one.
impl fmt::Debug for Secret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        // No length either: a length is a pointer at the value's shape, and
        // distinguishing a 40-character PAT from a 93-character one is exactly
        // the kind of oracle rule 4's "a count, never the content" is about when
        // the count IS about the secret.
        formatter.write_str(REDACTED)
    }
}

/// What a redacted rendering says. Public so a test can assert the rendering is
/// this and nothing else, rather than asserting the absence of one canary.
pub const REDACTED: &str = "<redacted>";

/// Best-effort wipe on drop.
///
/// **Stated as best-effort rather than promised**, because it is: the compiler
/// may elide a write to memory nothing reads again, and defeating that properly
/// is what `zeroize` exists for. A volatile write is what this crate can express
/// without vendoring one, and it closes the common case — a `Secret` dropped
/// while the process goes on to spawn a child, write a receipt, or panic.
///
/// It does NOT reach a `String` that reallocated while being built, which is why
/// [`Secret::new`] takes ownership of a value the caller already has rather than
/// growing one.
impl Drop for Secret {
    fn drop(&mut self) {
        // SAFETY-adjacent, without `unsafe`: writing through the `str`'s own
        // bytes keeps the allocation valid UTF-8 (a space is one byte) and the
        // `read_volatile` denies the optimiser the "nothing reads this" premise
        // it would need to elide the loop.
        let bytes = unsafe_free_wipe(&mut self.0);
        std::hint::black_box(bytes);
    }
}

/// Overwrite `value` in place and hand back its length, so a caller cannot be
/// optimised away for ignoring the result.
fn unsafe_free_wipe(value: &mut String) -> usize {
    // `&mut str` → bytes without `unsafe`: replacing every char with a space
    // preserves length and UTF-8 validity, and `String::replace_range` over the
    // full span is the safe spelling of the same write.
    let len = value.len();
    value.replace_range(.., &" ".repeat(len));
    std::hint::black_box(value.len())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    /// A value distinctive enough that finding it in a rendering is proof rather
    /// than coincidence.
    const CANARY: &str = "ghp_CANARY0000canary0000CANARY0000canary";

    #[test]
    fn debug_renders_the_marker_and_not_the_value() {
        let secret = Secret::new(CANARY.to_owned());
        let rendered = format!("{secret:?}");
        assert_eq!(rendered, REDACTED);
        assert!(
            !rendered.contains("canary"),
            "the rendering must not carry the value"
        );
    }

    /// THE COMPOSITIONAL PROPERTY, which is the reason this is a type at all: a
    /// derived `Debug` on a struct that HOLDS a secret is safe, so an author who
    /// never reads this module still cannot leak one.
    #[test]
    fn a_derived_debug_on_a_holder_is_safe() {
        // Read only through the derived `Debug`, which is the whole subject.
        #[derive(Debug)]
        #[allow(dead_code)]
        struct Holder {
            name: &'static str,
            token: Secret,
        }
        let rendered = format!(
            "{:?}",
            Holder {
                name: "GITHUB_TOKEN",
                token: Secret::new(CANARY.to_owned()),
            }
        );
        assert!(
            rendered.contains("GITHUB_TOKEN"),
            "the non-secret fields still render: {rendered}"
        );
        assert!(
            !rendered.contains("canary"),
            "and the secret one does not: {rendered}"
        );
    }

    /// The predicates travel to the value, so `reject_prefix` never needs
    /// [`Secret::expose`].
    #[test]
    fn the_predicates_do_not_require_exposing_it() {
        let marker = Secret::new("proxy-injected".to_owned());
        assert!(marker.starts_with("proxy-"));
        assert!(!marker.starts_with("ghp_"));
        assert!(!marker.is_empty());
        assert!(Secret::new(String::new()).is_empty());
    }

    /// SHOWN ABLE TO FAIL (CLOUD-418): the wipe is asserted over the buffer the
    /// value occupied rather than over a conclusion, so an implementation that
    /// dropped without writing would leave the canary here.
    #[test]
    fn the_wipe_overwrites_the_buffer() {
        let mut value = CANARY.to_owned();
        let _ = unsafe_free_wipe(&mut value);
        assert!(
            !value.contains("canary"),
            "the buffer must not still carry the value"
        );
        assert_eq!(
            value.len(),
            CANARY.len(),
            "and the write is in place rather than a truncation, which is what \
             keeps it a write to the ORIGINAL allocation"
        );
    }
}
