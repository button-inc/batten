//! What kind of machine this is, as the one fact only the environment can state
//! (CLOUD-1383).
//!
//! # Why this is a module and not a config key
//!
//! Everything else batten decides from is committed: `batten.toml` is the
//! authority, and a consumer's overrides may only tighten it. That is right for
//! every question about a REPOSITORY, and wrong for the one question here, which
//! is about the machine the repository happens to be checked out on. The same
//! commit is read by a disposable container and by a developer's laptop, and the
//! honest answer differs between them — so a committed file cannot hold it, and
//! an override that could would be an override that weakens.
//!
//! # What it is for
//!
//! Batten repairs the environment: it owns the harness hook surfaces it derives
//! and puts them back when something else has written over them. Whether a repair
//! may REMOVE what it finds is not a property of the finding — the census is
//! equally right on both machines — it is a property of whose `$HOME` this is.
//!
//! Before this fact existed the difference was negotiated in committed config: a
//! table naming each tolerated registration and the issue that owned removing it.
//! That is a second authority over the same subject, and it drifted from the
//! repair within a day — the repair deleted, every session, exactly what the
//! table declared must be present, and neither instrument could see the conflict
//! (`wiring reclaim --check` reported nothing to do while the gate refused).
//!
//! # The default is the safe one, deliberately
//!
//! Absent, and with no hosted harness stating otherwise, means a real machine. A
//! developer who never sets it gets a batten that reports and never removes; a
//! container whose environment field was mistyped gets the same, since any
//! explicit value but the licence refuses, which is a stalled repair rather than
//! a surprise deletion. What a hosted harness states about itself is the one
//! exception, detected rather than declared (CLOUD-2953).

/// The variable a disposable environment sets.
///
/// Named for what it describes rather than for what it permits: a consumer sets
/// it because the statement is true of their container, not to switch a feature
/// on, and the next value this key takes should read as another KIND of machine.
const KEY: &str = "BATTEN_ENVIRONMENT";

/// The one value that licenses a destructive repair.
const DISPOSABLE: &str = "disposable";

/// Whether this environment is disposable: declared so, or, with nothing
/// declared, a hosted harness session that states it is one (CLOUD-2953).
///
/// **An explicit value decides, and only the exact one licenses.**
/// `BATTEN_ENVIRONMENT=1`, `=true`, `=disposible`, `=machine` and an empty value
/// are all *not* this value, so every explicit way of getting it wrong lands on
/// the conservative arm — over a harness that says it is hosted too. A predicate
/// that accepted "anything non-empty" would turn a typo into a licence to delete
/// from somebody's home directory.
///
/// **With the variable unset, the harness's own statement decides**: `signal`,
/// the variable its hosted form exports, or `marker`, a directory under its user
/// config directory that its hosted setup run writes into (the variable is not
/// known to be exported while a setup script runs). The owner's ruling of
/// 2026-11-27: a hosted container is detected, never declared by hand, because
/// one forgotten export left a whole cloud session's hooks unregistered.
///
/// Read at the point of decision rather than resolved once into config: it is not
/// a repository fact and giving it a config seat would invite exactly the
/// committed-override shape the header rules out.
///
/// The read itself is judged over the compiled binary (CLOUD-2497, CLOUD-2953):
/// the reclaim and registration suites run benches declared, detected and
/// neither, and each repairs only as its environment licenses.
#[must_use]
pub fn disposable(signal: Option<HostSignal>, marker: Option<&std::path::Path>) -> bool {
    let read = |key: &str| std::env::var(key).ok();
    disposable_of(signal, marker.is_some_and(std::path::Path::is_dir), &read)
}

/// [`disposable`]'s decision over an environment reader and whether the marker
/// directory exists, split for the unit cases (`set_var` is `unsafe`).
fn disposable_of(
    signal: Option<HostSignal>,
    marked: bool,
    read: &dyn Fn(&str) -> Option<String>,
) -> bool {
    match read(KEY) {
        Some(value) => licenses(Some(&value)),
        None => marked || stated(signal, read),
    }
}

/// Whether the harness's variable carries its hosted value.
fn stated(signal: Option<HostSignal>, read: &dyn Fn(&str) -> Option<String>) -> bool {
    signal.is_some_and(|(key, value)| read(key).as_deref() == Some(value))
}

/// The predicate over the variable's value, split from the environment read.
///
/// `rules/rust.md`'s rule for a condition the test cannot create: `set_var` is
/// `unsafe` and `unsafe` is forbidden here, so the unit cases assert the
/// comparison THIS function makes — the one [`disposable`] calls, never a copy
/// of it kept beside the tests.
fn licenses(value: Option<&str>) -> bool {
    value == Some(DISPOSABLE)
}

/// What kind of machine a mediated call runs on, as a policy reads it
/// (`input.call.host`, CLOUD-2709).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Host {
    /// A hosted, disposable session: a harness's cloud container.
    Disposable,
    /// Anything else, a developer's own machine included.
    Machine,
}

impl Host {
    /// The token a policy module compares.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Disposable => "disposable",
            Self::Machine => "machine",
        }
    }
}

/// The host a call runs on: DETECTED from the harness first, declared second.
///
/// **THE HARNESS SAYS WHERE IT RUNS, AND BATTEN IS THE LAYER THAT READS EACH
/// HARNESS** (CLOUD-2709). A hand-set variable is a second authority over a fact
/// the host already states, and one forgotten export reads a cloud session as a
/// laptop. So each harness's own signal decides, and [`disposable`]'s explicit
/// declaration is the fallback for a harness whose hosted form states nothing.
///
/// Distinct from [`disposable`] in one arm: an explicit value other than the
/// licence does not stop this answer following detection, because a policy that
/// only refuses a practice may err toward the hosted reading. The repair's
/// predicate lets an explicit value overrule detection, since that is the
/// operator stating what this machine is. (CLOUD-2953 retired the earlier ruling
/// that a destructive repair needs the declaration at all: a hosted container is
/// detected, on the owner's instruction.)
#[must_use]
pub fn host(signal: Option<HostSignal>) -> Host {
    let read = |key: &str| std::env::var(key).ok();
    host_of(signal, &read)
}

/// A harness's own statement that it runs hosted: the variable it exports and
/// the value that means a hosted session (CLOUD-2709). Named per harness by
/// `Harness::host_signal` in the hook adapter, so this module reads a signal and
/// never a harness — it stays plumbing.
pub type HostSignal = (&'static str, &'static str);

/// [`host`]'s decision over an environment reader, split for the unit cases
/// (`set_var` is `unsafe`, and `unsafe` is forbidden here).
fn host_of(signal: Option<HostSignal>, read: &dyn Fn(&str) -> Option<String>) -> Host {
    if licenses(read(KEY).as_deref()) || stated(signal, read) {
        Host::Disposable
    } else {
        Host::Machine
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// CLOUD-2709. Fails by: a cloud session read as a machine because nobody
    /// exported the declaration, or a local session read as disposable.
    #[test]
    fn the_harness_states_its_host_and_the_declaration_is_the_fallback() {
        let claude: Option<HostSignal> = Some(("CLAUDE_CODE_REMOTE", "true"));
        let env = |pairs: &'static [(&'static str, &'static str)]| {
            move |key: &str| {
                pairs
                    .iter()
                    .find(|(name, _)| *name == key)
                    .map(|(_, value)| (*value).to_owned())
            }
        };
        let cloud = env(&[("CLAUDE_CODE_REMOTE", "true")]);
        let local = env(&[]);
        let declared = env(&[("BATTEN_ENVIRONMENT", "disposable")]);
        assert_eq!(host_of(claude, &cloud), Host::Disposable);
        assert_eq!(host_of(claude, &local), Host::Machine);
        // A harness with no signal of its own is not read through another one's.
        assert_eq!(host_of(None, &cloud), Host::Machine);
        // The declaration decides wherever detection says nothing.
        assert_eq!(host_of(None, &declared), Host::Disposable);
        assert_eq!(host_of(None, &local), Host::Machine);
    }

    /// CLOUD-2953. Fails by: a hosted container read as a machine because the
    /// variable was unset, or an explicit value overruled by detection.
    #[test]
    fn detection_decides_only_where_nothing_is_declared() {
        let claude: Option<HostSignal> = Some(("CLAUDE_CODE_REMOTE", "true"));
        let env = |pairs: &'static [(&'static str, &'static str)]| {
            move |key: &str| {
                pairs
                    .iter()
                    .find(|(name, _)| *name == key)
                    .map(|(_, value)| (*value).to_owned())
            }
        };
        let remote = env(&[("CLAUDE_CODE_REMOTE", "true")]);
        assert!(disposable_of(claude, false, &remote));
        assert!(!disposable_of(
            claude,
            false,
            &env(&[("CLAUDE_CODE_REMOTE", "1")])
        ));
        assert!(disposable_of(claude, true, &env(&[])));
        assert!(!disposable_of(claude, false, &env(&[])));
        assert!(!disposable_of(None, false, &remote));
        let refused = env(&[
            ("CLAUDE_CODE_REMOTE", "true"),
            ("BATTEN_ENVIRONMENT", "machine"),
        ]);
        assert!(!disposable_of(claude, true, &refused));
        assert!(!disposable_of(
            claude,
            true,
            &env(&[("BATTEN_ENVIRONMENT", "")])
        ));
        let declared = env(&[("BATTEN_ENVIRONMENT", "disposable")]);
        assert!(disposable_of(None, false, &declared));
    }

    #[test]
    fn only_the_exact_value_licenses_a_destructive_repair() {
        assert!(licenses(Some("disposable")));

        // EVERY WAY OF GETTING IT WRONG IS CONSERVATIVE. Each of these is a real
        // spelling somebody reaches for, and a truthiness test would accept all
        // of them — on a machine where the cost of being wrong is somebody's home
        // directory.
        for wrong in [None, Some(""), Some("1"), Some("true"), Some("yes")] {
            assert!(!licenses(wrong), "must not license: {wrong:?}");
        }
        assert!(!licenses(Some("disposible")), "a typo is not a licence");
        assert!(
            !licenses(Some("Disposable")),
            "and neither is a case change"
        );
    }

    /// The key and the value are the consumer's contract, so a rename is a
    /// breaking change rather than a refactor — pinned so it cannot happen by
    /// accident in a rename-all pass.
    #[test]
    fn the_declared_contract_is_the_documented_one() {
        assert_eq!(KEY, "BATTEN_ENVIRONMENT");
        assert_eq!(DISPOSABLE, "disposable");
    }
}
