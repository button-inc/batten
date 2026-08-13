//! `batten init` — scaffold the committed authority (house style §2, §12).
//!
//! The opt-in half of onboarding: `init` writes a starter `batten.toml` and
//! stops. It is the **first verb whose write target is a path inside the
//! repository** — every other writer in the tree (`state`, `journal`,
//! `findings`, `receipt`, `capture`, `provision`) writes out-of-tree state — so
//! the two properties that make that safe are stated here rather than left to
//! be inferred.
//!
//! ## Where it writes, and why that is the working directory
//!
//! `dir.join(config::CONFIG_FILE)`, with `dir` the process's working directory.
//! Not [`crate::git::repo_root`]: §8 defines the authority as *the* `batten.toml`
//! with **no upward directory walk**, and [`crate::resolve`] and
//! [`crate::lint`] both read it from the working directory. A verb that
//! scaffolded to the repository root while the loader read the working
//! directory would write a file Batten then ignores. It also means `init` needs
//! no repository at all, which is what makes the empty-directory case honest.
//!
//! ## Why an existing config is exit `2` and not exit `1`
//!
//! §7 is one table with no per-verb exception, so this needs an argument rather
//! than a preference. `batten.toml` is the committed authority §8 makes the
//! trust boundary — the file whose bytes decide every other verdict, and the
//! one a `protected` set names first. Refusing to overwrite it is a **policy
//! answer about the state of the repository**, the same class of answer
//! [`crate::hook`] returns `2` for, not a statement that the invocation was
//! malformed. Exit `1` would say the caller typed something wrong; they did not.
//!
//! The refusal is therefore carried as [`crate::ExitCode::Violation`] returned
//! from the verb — what `check` does with its findings — and **not** as a
//! [`crate::Denial`], whose documented scope is a mediated call. Its reason goes
//! to stderr unprefixed, because §7 is explicit that a `2` is a verdict and must
//! not read as a `batten:`-prefixed crash.
//!
//! Its *text* is a [`crate::Refusal`] ([`CONFIG_EXISTS`]), like every other deny
//! site in the crate. That is not decoration: CLOUD-122's contract is that a deny
//! points to the fix **structurally**, and the fix here is a real one a caller can
//! act on — edit the file, or move it aside — which a bare "already exists" leaves
//! them to guess at.
//!
//! ## Order of the two questions
//!
//! Existence is decided **before** `--dry-run`, mirroring
//! [`crate::provision::apply`]. A preview of a write that would never happen is
//! not a preview; `-n` over an existing config reports the same refusal the real
//! run would, which is the only reading that makes `-n` a safe rehearsal.
//!
//! ## The template
//!
//! [`STARTER`] is `starter.toml`, embedded at compile time. It lives beside this
//! module rather than at the repository root because `crates/batten` is the
//! published package and `include_str!` cannot reach outside it.
//!
//! It is deliberately **not** `batten.example.toml`, which stays where it is for
//! now. The example is a teaching document a reader copies by hand, and it had
//! drifted into a state a fresh consumer could not use — `unlanded = []` is a
//! smell [`crate::lint`] reports, so a repository started from it failed
//! `config lint` on its first day, and its conflict-marker rule is now a
//! `command` kind delegating to `hk`, which `check` refuses outright and which a
//! fresh consumer has no binary for. A scaffold has to run clean under the
//! read-effect verb with nothing else installed, so the two artifacts answer
//! different questions and are gated separately. Retiring the example in favour
//! of this one is a follow-up, kept out of this change because that file takes a
//! commit from nearly every feature that adds config surface — deleting it here
//! would put a hand-resolved conflict on every lap of the landing loop.
//!
//! The template carries no consumer-specific identifier (non-negotiable rule 1):
//! every path in it is either Batten's own file name or a glob a reader is told
//! to replace.

use std::path::Path;

use anyhow::Result;

use crate::config;

/// The starter `batten.toml` this verb writes.
///
/// Public so the test suite can assert the emitted bytes are the committed ones
/// rather than re-typing a copy to compare against.
pub const STARTER: &str = include_str!("starter.toml");

/// The rule id the refusal carries when a config is already present.
///
/// A constant rather than a literal at the deny site: it is the stable token a
/// caller keys on, so it belongs beside the outcome that produces it rather than
/// inside the one `format!` that happens to render it today.
pub const CONFIG_EXISTS: &str = "init.config-exists";

/// What one `init` did, or would have done.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Outcome {
    /// The starter was written.
    Created,
    /// `--dry-run`: nothing was written, and nothing was in the way.
    WouldCreate,
    /// A config is already there. Nothing was read, and nothing was written.
    Exists,
}

/// Scaffold `batten.toml` into `dir`.
///
/// Returns [`Outcome::Exists`] without touching the file when one is already
/// present — including under `dry_run`, since a preview must answer the question
/// the real run would answer.
///
/// # Errors
///
/// Propagates the write failure. An I/O error here is Batten's own failure to
/// complete (exit `3`), never a verdict: the caller asked for something
/// well-formed and the filesystem refused.
pub fn apply(dir: &Path, dry_run: bool) -> Result<Outcome> {
    let path = dir.join(config::CONFIG_FILE);
    // `try_exists` rather than `exists`: a path that cannot be interrogated is an
    // I/O error, and reading that as "absent" would overwrite on exactly the
    // filesystem least able to say what is there.
    if path.try_exists()? {
        return Ok(Outcome::Exists);
    }
    if dry_run {
        return Ok(Outcome::WouldCreate);
    }
    std::fs::write(&path, STARTER)?;
    Ok(Outcome::Created)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    /// The template has to survive the loader it is written for. A starter that
    /// does not parse is the one defect that makes every other property moot.
    #[test]
    fn the_starter_parses_as_a_config() {
        let config = config::parse(STARTER, config::CONFIG_FILE).expect("the starter parses");
        assert_eq!(config.version, config::SUPPORTED_VERSION);
    }

    /// `check` on a freshly scaffolded repository must gate something. An empty
    /// rule set exits `0` for the same reason a clean one does, which is exactly
    /// the "did it even run" ambiguity a starter should not ship with.
    #[test]
    fn the_starter_declares_a_live_rule() {
        let config = config::parse(STARTER, config::CONFIG_FILE).expect("the starter parses");
        assert!(
            !config.rules.is_empty(),
            "the starter ships no rule: the first `check` would report on nothing"
        );
    }

    /// The rule the starter ships must not fire on the starter. A day-one `check`
    /// that reports the file `init` just wrote is worse than no rule at all, and
    /// the trap is specific: a `forbid` pattern is a literal, so it appears in
    /// the config that declares it.
    #[test]
    fn no_starter_rule_fires_on_the_starter_itself() {
        let config = config::parse(STARTER, config::CONFIG_FILE).expect("the starter parses");
        for rule in &config.rules {
            let Some(glob) = rule.glob.as_deref() else {
                continue;
            };
            if !crate::rules::glob_match(glob, config::CONFIG_FILE) {
                continue;
            }
            let Some(pattern) = rule.pattern.as_deref() else {
                continue;
            };
            assert!(
                !STARTER.contains(pattern),
                "rule {} globs {} and its pattern appears in it",
                rule.id,
                config::CONFIG_FILE
            );
        }
    }
}
