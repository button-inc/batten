//! The command surface as data (house-style §11).
//!
//! The surface — verbs, sub-verbs, flags, and their [`Effect`] annotations — is
//! a spec compiled *into* the binary and emitted *at runtime* by introspecting
//! the live [`clap::Command`] tree and merging in the effect model (§5).
//! Completions, man pages, and markdown are downstream derivations of this same
//! spec, so the shipped binary and the generated docs can never drift.
//!
//! Output is byte-stable (§6): flags and subcommands are sorted, so identical
//! input yields identical bytes.

use clap::{Arg, ArgAction, Command};
use serde::Serialize;

use crate::effect::Effect;
use crate::surface::effect_for;

/// A single flag or positional argument in the emitted spec.
#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct FlagSpec {
    /// The argument's identifier.
    pub name: String,
    /// The short form (`-J`), if any.
    pub short: Option<char>,
    /// The long form (`--json`), if any.
    pub long: Option<String>,
    /// Whether the argument consumes a value (a bare boolean flag does not).
    pub takes_value: bool,
    /// The one-line human summary, if the command declares one.
    pub help: Option<String>,
}

/// A node in the emitted command tree: one command, its effect, its flags, and
/// its subcommands.
#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct CommandSpec {
    /// The full, root-relative command path (`config show`); the bare program
    /// name for the root node.
    pub path: String,
    /// The one-line human summary, if the command declares one.
    pub about: Option<String>,
    /// The declared effect, resolved from the §5 table (`ask` when absent).
    pub effect: Effect,
    /// Flags and positionals, sorted by name for byte-stability.
    pub flags: Vec<FlagSpec>,
    /// Subcommands, sorted by path for byte-stability.
    pub subcommands: Vec<CommandSpec>,
}

fn flag_of(arg: &Arg) -> FlagSpec {
    FlagSpec {
        name: arg.get_id().as_str().to_owned(),
        short: arg.get_short(),
        long: arg.get_long().map(str::to_owned),
        // A flag that only flips a boolean consumes no value; anything else does.
        // `Count` belongs here with the boolean actions: `-v` flips a rung, it
        // does not consume a token. Omitting it reported `takes_value: true` for
        // every ladder flag, which is a lie a completion script acts on.
        // `Append` is deliberately NOT in this list: a trailing variadic consumes
        // every remaining token, so `takes_value: true` is the honest answer.
        takes_value: !matches!(
            arg.get_action(),
            ArgAction::SetTrue | ArgAction::SetFalse | ArgAction::Count
        ),
        help: arg.get_help().map(ToString::to_string),
    }
}

fn flags_of(command: &Command) -> Vec<FlagSpec> {
    let mut flags: Vec<FlagSpec> = command
        .get_arguments()
        // `help` and `version` are clap's own affordances, not part of the surface.
        .filter(|arg| arg.get_id() != "help" && arg.get_id() != "version")
        .map(flag_of)
        .collect();
    flags.sort_by(|a, b| a.name.cmp(&b.name));
    flags
}

/// Walk a clap subcommand into a [`CommandSpec`], keyed by its root-relative
/// path (`prefix` is the parent path, empty at the top level).
fn walk(command: &Command, prefix: &str) -> CommandSpec {
    let name = command.get_name();
    let path = if prefix.is_empty() {
        name.to_owned()
    } else {
        format!("{prefix} {name}")
    };

    let mut subcommands: Vec<CommandSpec> = command
        .get_subcommands()
        .map(|sub| walk(sub, &path))
        .collect();
    subcommands.sort_by(|a, b| a.path.cmp(&b.path));

    CommandSpec {
        effect: effect_for(&path),
        about: command.get_about().map(ToString::to_string),
        flags: flags_of(command),
        subcommands,
        path,
    }
}

/// Describe the whole surface, rooted at the top-level [`clap::Command`].
///
/// The root node carries the program name and its global flags; its children are
/// walked root-relative, so effect keys are `check` / `config show`, never
/// `batten check`. The root itself declares no effect of its own.
#[must_use]
pub fn describe(root: &Command) -> CommandSpec {
    let mut subcommands: Vec<CommandSpec> =
        root.get_subcommands().map(|sub| walk(sub, "")).collect();
    subcommands.sort_by(|a, b| a.path.cmp(&b.path));

    CommandSpec {
        path: root.get_name().to_owned(),
        about: root.get_about().map(ToString::to_string),
        effect: Effect::Ask,
        flags: flags_of(root),
        subcommands,
    }
}

/// Serialize a spec to byte-stable pretty JSON (`batten spec --format json`).
///
/// # Errors
///
/// Returns an error only if serialization itself fails, which for this
/// data-only tree does not occur in practice.
pub fn to_json(spec: &CommandSpec) -> anyhow::Result<String> {
    Ok(serde_json::to_string_pretty(spec)?)
}

/// The derived agent read-only allowlist (CLOUD-28): every command path whose
/// effect is [`Effect::Read`], sorted. Derived from the same walk as the spec —
/// there is no second, hand-maintained list — so an unclassified command can
/// never leak in.
#[must_use]
pub fn read_only_allowlist(spec: &CommandSpec) -> Vec<String> {
    let mut paths = Vec::new();
    collect_read_only(spec, spec.path.as_str(), &mut paths);
    paths.sort();
    paths
}

fn collect_read_only(node: &CommandSpec, root_name: &str, out: &mut Vec<String>) {
    // The bare root program declares no effect of its own; skip it.
    if node.path != root_name && node.effect.is_read_only() {
        out.push(node.path.clone());
    }
    for sub in &node.subcommands {
        collect_read_only(sub, root_name, out);
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::surface;

    fn spec() -> CommandSpec {
        describe(&surface::command())
    }

    /// Collect every command path in the tree whose effect resolves to `ask`
    /// (i.e. is missing from the §5 table). Used by the completeness gate.
    fn unclassified_paths(node: &CommandSpec, root_name: &str, out: &mut Vec<String>) {
        if node.path != root_name && node.effect == Effect::Ask {
            out.push(node.path.clone());
        }
        for sub in &node.subcommands {
            unclassified_paths(sub, root_name, out);
        }
    }

    #[test]
    fn json_is_byte_stable() {
        // Same input, identical bytes (§6): the ordering is fixed, no timestamps.
        let a = to_json(&spec()).unwrap();
        let b = to_json(&spec()).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn json_parses_and_names_the_root() {
        let json = to_json(&spec()).unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(value["path"], "batten");
    }

    #[test]
    fn every_command_has_a_declared_effect() {
        // Completeness gate: no command in the surface may resolve to `ask`
        // (a missing effect-table entry). This is what lets the tree grow
        // verb-by-verb without a command ever shipping unclassified.
        let root = spec();
        let mut missing = Vec::new();
        unclassified_paths(&root, root.path.as_str(), &mut missing);
        assert!(
            missing.is_empty(),
            "commands missing an effect: {missing:?}"
        );
    }

    #[test]
    fn allowlist_is_exactly_the_read_commands() {
        // The derived allowlist is every read-effect command path, sorted.
        assert_eq!(
            read_only_allowlist(&spec()),
            vec![
                "check".to_owned(),
                "config".to_owned(),
                "config epoch".to_owned(),
                "config lint".to_owned(),
                "config show".to_owned(),
                "doctor".to_owned(),
                "generate".to_owned(),
                "generate completions".to_owned(),
                "generate schema".to_owned(),
                // The `policy` noun is on the list with its verbs, unlike
                // `receipt`: every verb in its §2 subtree is read, so there is
                // no write for the noun row to smuggle on (CLOUD-50).
                "policy".to_owned(),
                "policy budget".to_owned(),
                "receipt status".to_owned(),
                "spec".to_owned(),
            ]
        );
    }

    #[test]
    fn the_process_spawning_verb_is_never_read_only() {
        // CLOUD-170's allowlist gate. `enforce` may execute commands declared
        // in `batten.toml`; §5 lists user-supplied code as unclassified, so the
        // derived agent allowlist must never advertise it as read-only. Asserted
        // on the derivation itself rather than on the effect table, because the
        // allowlist is the artifact an agent actually consumes.
        let allowlist = read_only_allowlist(&spec());
        assert!(
            !allowlist.contains(&"enforce".to_owned()),
            "the process-spawning verb leaked into the read-only allowlist: {allowlist:?}"
        );
        assert_eq!(effect_for("enforce"), Effect::Unclassified);
        assert!(!effect_for("enforce").is_read_only());
    }
}
