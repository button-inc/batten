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

/// The whole emitted document: the command tree, plus every derivation that is
/// a pure function of it.
///
/// The tree is flattened rather than nested under a key, so the root keys a
/// consumer already reads (`path`, `subcommands`, …) stay exactly where they
/// were and a derivation can be added beside them without moving anything.
#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct SpecDocument {
    /// The command tree itself, at the document root.
    #[serde(flatten)]
    pub command: CommandSpec,
    /// The derived agent read-only allowlist — see [`read_only_allowlist`].
    /// Emitted rather than left to each consumer to re-derive: a second
    /// implementation of the `effect == read` filter is a second place for it
    /// to be wrong, and this one is wrong in the unsafe direction.
    pub read_only_allowlist: Vec<String>,
}

/// Describe the whole surface as the emitted document: [`describe`] plus the
/// derivations taken from that same walk.
#[must_use]
pub fn document(root: &Command) -> SpecDocument {
    let command = describe(root);
    SpecDocument {
        read_only_allowlist: read_only_allowlist(&command),
        command,
    }
}

/// Serialize a spec document to byte-stable pretty JSON
/// (`batten spec --format json`).
///
/// # Errors
///
/// Returns an error only if serialization itself fails, which for this
/// data-only tree does not occur in practice.
pub fn to_json(spec: &SpecDocument) -> anyhow::Result<String> {
    Ok(serde_json::to_string_pretty(spec)?)
}

/// The derived agent read-only allowlist (CLOUD-28): every command path whose
/// effect is [`Effect::Read`], sorted. Derived from the same walk as the spec —
/// there is no second, hand-maintained list — so an unclassified command can
/// never leak in. Emitted as [`SpecDocument::read_only_allowlist`], which is
/// what makes the derivation reachable by the agent that has to honour it
/// rather than only by this crate's own tests.
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

    fn doc() -> SpecDocument {
        document(&surface::command())
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

    /// Every command path the binary emits, sorted; the bare root is skipped
    /// because it declares no verb of its own.
    fn emitted_paths(node: &CommandSpec, root_name: &str, out: &mut Vec<String>) {
        if node.path != root_name {
            out.push(node.path.clone());
        }
        for sub in &node.subcommands {
            emitted_paths(sub, root_name, out);
        }
    }

    #[test]
    fn json_is_byte_stable() {
        // Same input, identical bytes (§6): the ordering is fixed, no timestamps.
        let a = to_json(&doc()).unwrap();
        let b = to_json(&doc()).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn json_parses_and_names_the_root() {
        let json = to_json(&doc()).unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        // Flattened, so the tree's own keys stay at the document root: adding a
        // derivation beside them must not re-nest what a consumer already reads.
        assert_eq!(value["path"], "batten");
        assert!(value["subcommands"].is_array());
    }

    #[test]
    fn the_emitted_allowlist_is_exactly_the_read_effect_filter() {
        // The point of emitting the derivation is that a consumer stops
        // re-deriving it, so what has to be pinned is that the emitted key *is*
        // the `effect == read` filter over the emitted tree — not a list of
        // paths, which `allowlist_is_exactly_the_read_commands` already holds
        // and which a second copy here would only duplicate. Recomputed from
        // the tree the same document carries, so a walk that ever stopped
        // agreeing with the filter fails here.
        let document = doc();
        let mut expected: Vec<String> = Vec::new();
        emitted_paths(
            &document.command,
            document.command.path.as_str(),
            &mut expected,
        );
        expected.retain(|path| effect_for(path).is_read_only());
        expected.sort();

        assert_eq!(document.read_only_allowlist, expected);
        assert_eq!(
            document.read_only_allowlist,
            read_only_allowlist(&document.command)
        );
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
                // The gate half of the attribution pair. It reads commit metadata
                // through git's read-only plumbing and matches configured patterns
                // against it, so it is `read`; `attribution identity` writes
                // .git/config and is deliberately absent, as is the noun above it.
                "attribution check".to_owned(),
                // Both navigation verbs are on it, and the `capture` noun above
                // them is not: the noun is unclassified because `capture prune`
                // removes, which is the fail-safe reading a consumer treating an
                // entry as a prefix depends on (CLOUD-121).
                "capture list".to_owned(),
                "capture show".to_owned(),
                "check".to_owned(),
                // Both `commit` rows, unlike attribution's. The noun IS `read`
                // here because its whole subtree is — nothing under it writes —
                // so it can make the claim `attribution` cannot (CLOUD-701).
                "commit".to_owned(),
                "commit check".to_owned(),
                "config".to_owned(),
                "config deprecations".to_owned(),
                "config epoch".to_owned(),
                "config lint".to_owned(),
                "config show".to_owned(),
                "defects query".to_owned(),
                // A pure function of stdin: it opens no file, spawns nothing,
                // and reaches no configured command, so it is the narrowest
                // possible `read` (CLOUD-53). The `design` noun is absent for
                // `receipt`'s reason — `design attest` is the declared next verb
                // under it.
                "design audit".to_owned(),
                "doctor".to_owned(),
                // The one row that is both a parent and a `read` verb of its own
                // (CLOUD-777). House style §2 spells the verb `doctor <SUB>` and
                // §8 promises what bare `doctor` does, so both are on the list —
                // unlike every other noun here, which performs no default action
                // and is absent for that reason. Both read committed files and
                // spawn nothing: the sub-verb compares each harness's wiring
                // against a derivation computed in-process.
                "doctor hooks".to_owned(),
                "generate".to_owned(),
                "generate completions".to_owned(),
                // §11's third derivation (CLOUD-62): the hook wiring a host
                // needs, derived from the same `Harness` data the adapters are
                // built from. On the list for the structural reason the others
                // are — it returns bytes and writes nothing. Emphatically NOT
                // the verb that installs them: `generate` stays stdout-only,
                // and the install surface is `init`'s.
                "generate hooks".to_owned(),
                // The two human renderings (CLOUD-69) are on the list for the
                // same structural reason the shell one is: they return bytes
                // and write nothing.
                "generate man".to_owned(),
                "generate markdown".to_owned(),
                "generate schema".to_owned(),
                // The `lint` noun is on the list with its kind, for the same
                // reason as `policy` below: `lint <kind>` reads text the caller
                // names and answers about its shape, so the whole subtree is
                // read and the noun row smuggles no write (CLOUD-84).
                "lint".to_owned(),
                "lint brief".to_owned(),
                // CLOUD-479. `payload field` is a decoder, not a mediator: it
                // reads stdin, projects one allowlisted field, and renders no
                // verdict — so `read` is the honest classification and the
                // derived allowlist is where it belongs. `hook` next door stays
                // unclassified because its DECISION mediates writes.
                "payload".to_owned(),
                "payload field".to_owned(),
                // The `policy` noun is on the list with its verbs, unlike
                // `receipt`: every verb in its §2 subtree is read, so there is
                // no write for the noun row to smuggle on (CLOUD-50).
                "policy".to_owned(),
                "policy budget".to_owned(),
                "policy explain".to_owned(),
                "policy test".to_owned(),
                "policy tools".to_owned(),
                // The freshness verb, never the `provision` noun or `apply`:
                // that subtree writes, so the noun takes the conservative
                // reading (CLOUD-90).
                "provision status".to_owned(),
                "receipt status".to_owned(),
                "spec".to_owned(),
                "state list".to_owned(),
                // The verb, never the `worktree` noun: the noun stays
                // `Unclassified`, so it is off this list (CLOUD-51, CLOUD-780).
                "worktree status".to_owned(),
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

    #[test]
    fn the_mediation_entrypoint_is_never_read_only() {
        // CLOUD-244. House-style §2 listed `hook` as `(read)`, and that is the
        // one row where the document is simply wrong — wrong in the unsafe
        // direction, because §5 makes the agent allowlist *derived* from
        // `effect == read`, so implementing §2 as written would have advertised
        // the deny-issuing mediator as agent-safe. §5's promise about a `read`
        // verb ("structurally incapable, not merely well-behaved") cannot be
        // made about a verb whose whole job is adjudicating someone else's
        // write. Pinned here so the correction cannot be undone by a row edit.
        let allowlist = read_only_allowlist(&spec());
        assert!(
            !allowlist.contains(&"hook".to_owned()),
            "the mediation entrypoint leaked into the read-only allowlist: {allowlist:?}"
        );
        assert_eq!(effect_for("hook"), Effect::Unclassified);
        assert!(!effect_for("hook").is_read_only());
    }

    #[test]
    fn the_stdout_only_emitter_stays_read() {
        // CLOUD-244, the one row where the decision was real rather than
        // bookkeeping: §2 declared `generate` `(write)`, main declares it
        // `Read`. Settled against what the verb *does* — emission is
        // stdout-only, so the redirect that refreshes a committed artifact is
        // the caller's (`mise run completions`), never the binary's. `read` is
        // therefore structurally honest and not a promise about behaviour, and
        // §2 is corrected rather than the code. If a sub-verb ever opens a file
        // itself, this is the assertion that has to be deleted deliberately.
        for path in [
            "generate",
            "generate completions",
            "generate hooks",
            "generate man",
            "generate markdown",
            "generate schema",
        ] {
            assert_eq!(
                effect_for(path),
                Effect::Read,
                "{path} no longer emits on stdout only: reclassify it and drop it from the allowlist"
            );
        }
    }

    #[test]
    fn the_emitted_surface_is_exactly_the_committed_row_set() {
        // CLOUD-244's in-tree half. §2 and the emitted spec disagreed on four
        // rows for want of anything comparing them, and the comparison itself
        // cannot be automated yet: §2 lives in a Linear document, out of tree,
        // and `batten check` evaluates a file tree (that gap is CLOUD-95). What
        // *is* checkable in-tree is that the emitted row set never moves
        // silently — so a verb added, renamed, or re-parented (`config schema`
        // -> `generate schema` was one of the four) fails here and has to be
        // stated, which is the prompt to reconcile §2 in the same change.
        let root = spec();
        let mut paths = Vec::new();
        emitted_paths(&root, root.path.as_str(), &mut paths);
        paths.sort();
        assert_eq!(
            paths,
            vec![
                "attribution".to_owned(),
                "attribution check".to_owned(),
                "attribution identity".to_owned(),
                // The adoption path for an already-dirty repository (CLOUD-67).
                // §2's listing gained the row in the same change, which is what
                // this assertion exists to prompt.
                "baseline".to_owned(),
                // The handle-navigation noun (CLOUD-121). `capture show`, not a
                // bare `show`: §2 is noun-verb and lists no bare `show`, and the
                // noun is what gives lifecycle (`prune`) somewhere to live.
                "capture".to_owned(),
                "capture list".to_owned(),
                "capture prune".to_owned(),
                "capture show".to_owned(),
                "check".to_owned(),
                "commit".to_owned(),
                "commit check".to_owned(),
                "config".to_owned(),
                "config deprecations".to_owned(),
                "config epoch".to_owned(),
                "config lint".to_owned(),
                "config show".to_owned(),
                "defects".to_owned(),
                "defects add".to_owned(),
                "defects query".to_owned(),
                "design".to_owned(),
                "design audit".to_owned(),
                "doctor".to_owned(),
                "doctor hooks".to_owned(),
                "enforce".to_owned(),
                "exec".to_owned(),
                // The schema is emitted by `generate`, not `config`: it is a
                // derivation of the config types, and §11 gives every
                // derivation the one emitter (CLOUD-244).
                "generate".to_owned(),
                "generate completions".to_owned(),
                // §11's third derivation, the hook wiring (CLOUD-62).
                "generate hooks".to_owned(),
                // §11's other two derivations, landed together (CLOUD-69): the
                // document has named man pages and markdown as derivations of
                // this spec since the spine, and until now only the shell one
                // existed. §2 needs no reconciliation for them — it never
                // listed a row either way.
                "generate man".to_owned(),
                "generate markdown".to_owned(),
                "generate schema".to_owned(),
                "hook".to_owned(),
                // §2 already reserved this row (`init [-n] … (write)`); CLOUD-206
                // landed the verb behind it, so the document needed no edit.
                "init".to_owned(),
                // A top-level verb-with-kind, not a `brief` noun: what varies
                // across `lint <kind>` is the artifact, and `config lint` stays
                // where it is because it lints the one committed authority
                // rather than something the caller names (CLOUD-84).
                "lint".to_owned(),
                "lint brief".to_owned(),
                // CLOUD-479. `payload field` is a decoder, not a mediator: it
                // reads stdin, projects one allowlisted field, and renders no
                // verdict — so `read` is the honest classification and the
                // derived allowlist is where it belongs. `hook` next door stays
                // unclassified because its DECISION mediates writes.
                // CLOUD-1051, and this assertion doing its job: a new noun fails
                // here and has to be stated, which is the prompt to reconcile §2
                // in the same change. `override` is UNCLASSIFIED and deliberately
                // absent from the read-only allowlist above — its subtree writes,
                // so a `read` noun would leak onto that allowlist for any
                // consumer reading an entry as a prefix (CLOUD-90). `override
                // request` is `write`, because what authorizes is the record's
                // existence and state; a verb that only computed an address would
                // authorize nothing.
                "override".to_owned(),
                "override request".to_owned(),
                "override spend".to_owned(),
                "payload".to_owned(),
                "payload field".to_owned(),
                // The paired latency measurement (CLOUD-875), retired out of
                // `mise-tasks/perf-pair.sh` under CLOUD-1059. §2 gains the noun
                // and its one verb in the same change, which is exactly what
                // this assertion exists to prompt — and the row is `write`, so
                // it is deliberately absent from the read allowlist above.
                "perf".to_owned(),
                "perf pair".to_owned(),
                "policy".to_owned(),
                "policy budget".to_owned(),
                "policy explain".to_owned(),
                "policy test".to_owned(),
                "policy tools".to_owned(),
                "provision".to_owned(),
                "provision apply".to_owned(),
                "provision status".to_owned(),
                "receipt".to_owned(),
                "receipt record".to_owned(),
                "receipt status".to_owned(),
                // The API-compatibility noun (CLOUD-1050), ported off
                // `mise-tasks/semver.sh` when CLOUD-1059 made editing a shell
                // rule refusable. §2 gains the noun in the same change, which is
                // what this assertion exists to prompt.
                "semver".to_owned(),
                "semver check".to_owned(),
                "spec".to_owned(),
                "state".to_owned(),
                "state adopt".to_owned(),
                "state list".to_owned(),
                "state migrate".to_owned(),
                "state record".to_owned(),
                // The build-tree noun (CLOUD-1030), ported off
                // `mise-tasks/target-prune.sh` for `semver`'s reason above. Both
                // rows are `Effect::Destructive` and so are deliberately absent
                // from the read allowlist — this is the second destructive verb
                // on the surface, beside `capture prune`, and it earns the same
                // `-y` binding rather than a new exception.
                "target".to_owned(),
                "target prune".to_owned(),
                "worktree".to_owned(),
                "worktree status".to_owned(),
            ]
        );
    }

    #[test]
    fn the_spec_emits_exactly_the_committed_formats() {
        // CLOUD-244's fourth row. §2 and §11 advertised `spec --format
        // kdl|json`; only `json` was ever implemented, and a format named in
        // the spec and absent from the binary is a promise an agent's argv
        // discovers is false. Settled as: JSON is the agent-facing contract
        // (§6, byte-stable), KDL had no consumer, so it is removed from the
        // document rather than implemented. Committed here so re-adding a
        // format is a deliberate edit to this list and to §2 together.
        let formats: Vec<String> = <crate::cli::SpecFormat as clap::ValueEnum>::value_variants()
            .iter()
            .filter_map(|format| {
                clap::ValueEnum::to_possible_value(format).map(|value| value.get_name().to_owned())
            })
            .collect();
        assert_eq!(formats, vec!["json".to_owned()]);
    }
}
