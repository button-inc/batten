//! G2: the one predicate a write of `main` is graded by (CLOUD-2033).
//!
//! `batten release path <sha> [--post]` prints `success` or `failure` for the
//! head `<sha>`, and `--post` posts it as the `release-path` commit status that
//! `main`'s ruleset requires.
//!
//! * **success** — the pin and version at `<sha>` equal those at its merge-base
//!   with `origin/main`. The invariant is inherited, and nothing is read from the
//!   forge.
//! * **success** — the diff from the merge-base touches only the release paths
//!   ([`RELEASE_PATHS`]; in `batten.toml`, only the `engine` line), the pin is
//!   `v{version}`, G1 verifies that release as published, and its tag commit is
//!   `<sha>` or an ancestor of it. A burned release, built from a commit that
//!   never reached this head, is never admitted.
//! * **failure** — otherwise.
//!
//! [`judge`] is pure over what the shell read, so each arm is driven alone.

use std::collections::BTreeSet;

/// The paths a release head may change, and nothing else (P1), beside any
/// `CHANGELOG.md`: the manifest, its lockfile and the config carrying the pin.
pub const RELEASE_PATHS: [&str; 3] = ["Cargo.toml", "Cargo.lock", "batten.toml"];

/// Whether `path` is one a release head may change: a [`RELEASE_PATHS`] entry,
/// or a changelog — wherever the consumer keeps it, which is its own fact.
#[must_use]
pub fn is_release_path(path: &str) -> bool {
    RELEASE_PATHS.contains(&path) || path.rsplit('/').next() == Some("CHANGELOG.md")
}

/// The status context `main`'s ruleset requires.
pub const CONTEXT: &str = "release-path";

/// The pin and version one commit carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Side {
    /// `batten.toml`'s `engine = { release = "…" }`, or `None` where the
    /// engine is not pinned to a release.
    pub pin: Option<String>,
    /// `Cargo.toml`'s workspace (or package) version.
    pub version: Option<String>,
}

/// What G2 decided.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// The head may write `main`, and why, as a pointer.
    Success(String),
    /// It may not, with every reason, as pointers.
    Failure(Vec<String>),
    /// A read that could not be made.
    CouldNotLook(String),
}

impl Verdict {
    /// The commit-status state this verdict posts, if it posts one.
    #[must_use]
    pub const fn state(&self) -> Option<&'static str> {
        match self {
            Self::Success(_) => Some("success"),
            Self::Failure(_) => Some("failure"),
            Self::CouldNotLook(_) => None,
        }
    }

    /// The one-line description a posted status carries.
    #[must_use]
    pub fn description(&self) -> String {
        match self {
            Self::Success(why) => why.clone(),
            Self::Failure(why) => why.join("; "),
            Self::CouldNotLook(why) => format!("could not look: {why}"),
        }
    }
}

/// What G1 and the ancestry read answered about the pinned release.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Published {
    /// G1 verified it published; its tag commit.
    Verified(String),
    /// G1 refused it, with its pointers.
    Refused(Vec<String>),
}

/// The text of `batten.toml` with its `engine` line removed, so two sides can
/// be compared for "changed only the pin".
#[must_use]
pub fn without_engine_line(config: &str) -> String {
    config
        .lines()
        .filter(|line| !line.trim_start().starts_with("engine ="))
        .collect::<Vec<_>>()
        .join("\n")
}

/// G2 over what the shell read.
///
/// `changed` is the diff from the merge-base; `other_config_change` is whether
/// `batten.toml` changed outside its `engine` line. `verify` runs G1 in
/// published mode on the pin; `is_ancestor` answers whether a tag commit is the
/// head or reachable from it. Neither is called for an inherited pin.
//MUTANT-SUITE crates/batten/tests/it/release_verify.rs
//MUTANT pin-change-path-green|s@^        Ok(Published::Refused(why)) => failures.extend(why),$@        Ok(Published::Refused(_)) => {}@|a_pin_change_is_failure_until_its_release_verifies
//MUTANT release-head-extra-path-green|s@^        failures.push(format!("touches {path}, outside the release paths"));$@@|a_release_head_touching_another_path_is_failure
//MUTANT burned-tag-admitted|s@^            Ok(Some(false)) => failures.push(format!($@            Ok(Some(false)) => drop(format!(@|a_burned_release_is_failure
pub fn judge(
    base: &Side,
    head: &Side,
    changed: &BTreeSet<String>,
    other_config_change: bool,
    verify: &mut dyn FnMut(&str) -> Result<Published, String>,
    is_ancestor: &mut dyn FnMut(&str) -> Result<Option<bool>, String>,
) -> Verdict {
    if base == head {
        return Verdict::Success(String::from(
            "the pin and version are inherited from the merge-base",
        ));
    }
    let mut failures = Vec::new();
    for path in changed {
        if is_release_path(path) {
            continue;
        }
        failures.push(format!("touches {path}, outside the release paths"));
    }
    if other_config_change {
        failures.push(String::from("changes batten.toml outside its engine line"));
    }
    let (Some(pin), Some(version)) = (&head.pin, &head.version) else {
        failures.push(String::from(
            "the head carries no release pin or no version",
        ));
        return Verdict::Failure(failures);
    };
    if *pin != format!("v{version}") {
        failures.push(format!("the pin {pin} is not v{version}"));
        return Verdict::Failure(failures);
    }
    match verify(pin) {
        Err(why) => return Verdict::CouldNotLook(why),
        Ok(Published::Refused(why)) => failures.extend(why),
        Ok(Published::Verified(tag_commit)) => match is_ancestor(&tag_commit) {
            Err(why) => return Verdict::CouldNotLook(why),
            Ok(Some(true)) => {}
            Ok(Some(false)) => failures.push(format!(
                "{pin}'s tag commit {tag_commit} is not this head or its ancestor"
            )),
            Ok(None) => failures.push(format!(
                "{pin}'s tag commit {tag_commit} is not in this head's history"
            )),
        },
    }
    if failures.is_empty() {
        Verdict::Success(format!("{pin} is published, immutable and verified"))
    } else {
        Verdict::Failure(failures)
    }
}

/// Whether a head's diff is release-shaped: only the release paths, and in
/// `batten.toml` only the `engine` line.
#[must_use]
pub fn release_shaped(changed: &BTreeSet<String>, other_config_change: bool) -> bool {
    !other_config_change && changed.iter().all(|path| is_release_path(path))
}

/// The pre-B2 seal (B1): `final` fails when G2 says failure and either the
/// head is not release-shaped or the release guard's `settings` job is not
/// green on the trunk. So before the server requires `release-path`, no head
/// that pins an unverified release passes the one check it does require; after
/// it, a release-shaped head is excused, because `release-path` itself is the
/// gate and its pre-publication failure must not refuse `land`.
//MUTANT final-seal-dropped|s@^    matches!(verdict, Verdict::Failure(_)) \&\& (!release_shaped \x7c\x7c !settings_green)$@    false@|the_seal_holds_an_unverified_pin_until_the_settings_are_green
#[must_use]
pub fn seals(verdict: &Verdict, release_shaped: bool, settings_green: bool) -> bool {
    matches!(verdict, Verdict::Failure(_)) && (!release_shaped || !settings_green)
}

/// The release pin `batten.toml` carries, or `None` where it pins none.
#[must_use]
pub fn pin_of(config: &str) -> Option<String> {
    let table: toml::Table = config.parse().ok()?;
    table
        .get("engine")?
        .get("release")?
        .as_str()
        .map(ToOwned::to_owned)
}

/// `Cargo.toml`'s workspace version, or its package version.
#[must_use]
pub fn version_of(manifest: &str) -> Option<String> {
    let table: toml::Table = manifest.parse().ok()?;
    table
        .get("workspace")
        .and_then(|workspace| workspace.get("package"))
        .or_else(|| table.get("package"))?
        .get("version")?
        .as_str()
        .map(ToOwned::to_owned)
}
