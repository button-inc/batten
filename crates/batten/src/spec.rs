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
use crate::surface::{data_channel_for, effect_for, id_for};

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
    /// Whether the argument is POSITIONAL rather than a named flag (CLOUD-969).
    ///
    /// Without this a positional emits as `long: null, takes_value: true`, which
    /// is byte-identical to a flag that lost its long form — so a consumer
    /// reconstructing an invocation from this document writes `--<name> <value>`
    /// for something that takes neither, produces a broken command line, and
    /// gets no signal that it did.
    pub positional: bool,
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
    /// The stable id declared on this command's `SURFACE` row (CLOUD-969).
    ///
    /// `None` only for the root program node, which declares no row of its own.
    /// This is what a consumer pins against; `path` is the spelling and moves.
    pub id: Option<String>,
    /// The one-line human summary, if the command declares one.
    pub about: Option<String>,
    /// The declared effect, resolved from the §5 table (`ask` when absent).
    pub effect: Effect,
    /// Whether this command answers through the `-J` data channel (§6).
    ///
    /// Published since CLOUD-969. It was a build-time-only column, so a consumer
    /// had to infer the channel by looking for a flag named `json` — a second
    /// derivation of something the surface already declares, and one that reads
    /// `spec` (whose switch is `--format`) wrong in both directions.
    pub data_channel: bool,
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
        // clap's own answer, not a heuristic over the long/short pair: a flag
        // may legitimately carry neither.
        positional: arg.is_positional(),
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
        data_channel: data_channel_for(&path),
        id: id_for(&path).map(ToOwned::to_owned),
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
        // The root is the binary, which the release tag already identifies; an
        // id here would be a second name for the same thing.
        id: None,
        about: root.get_about().map(ToString::to_string),
        effect: Effect::Ask,
        data_channel: false,
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
    /// The shape this document is in (CLOUD-969).
    ///
    /// Emitted FIRST because it is what a consumer reads before deciding whether
    /// it understands the rest.
    pub spec_version: u32,
    /// The command tree itself, at the document root.
    #[serde(flatten)]
    pub command: CommandSpec,
    /// The derived agent read-only allowlist — see [`read_only_allowlist`].
    /// Emitted rather than left to each consumer to re-derive: a second
    /// implementation of the `effect == read` filter is a second place for it
    /// to be wrong, and this one is wrong in the unsafe direction.
    ///
    /// Each entry carries the stable id ALONGSIDE the path since CLOUD-969, and
    /// that reconciliation is the point rather than a convenience: this is §5's
    /// safety-critical derivation, and keyed on the spelling alone a rename
    /// silently stops a consumer's pinned allowlist from matching — in the
    /// direction where a path it still trusts no longer means what it did.
    pub read_only_allowlist: Vec<ReadOnlyEntry>,
}

/// One row of the derived read-only allowlist: the stable identity, and the
/// spelling to invoke today.
///
/// A struct rather than a bare path (CLOUD-969). Two keys rather than two
/// parallel lists, because two lists can disagree about their own ordering and
/// a consumer would have to zip them to find out.
#[derive(Debug, Serialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct ReadOnlyEntry {
    /// The stable id declared on the command's `SURFACE` row. Pin against this.
    pub id: String,
    /// The path to invoke today. Human-facing, and expected to move.
    pub path: String,
}

/// The shape of the emitted document.
///
/// A SOURCE LITERAL, deliberately, and never `CARGO_PKG_VERSION`: a version that
/// moves with the crate says "the binary changed", which is what the release tag
/// already says, and tells a consumer nothing about whether the document it is
/// about to parse is one it understands.
///
/// **When it moves:** on any change to the emitted shape a consumer could
/// notice — a key added, removed or renamed, or a value's type changed. It does
/// NOT move when a command row is added, removed or renamed: that is the
/// surface changing, not the document's shape, and it is exactly what the
/// per-row `id` exists to let a consumer track. Pre-`0.1.0` there is no
/// back-compatibility surface (house style §2), so this is a statement about the
/// document rather than a promise about old ones.
pub const SPEC_VERSION: u32 = 1;

/// Describe the whole surface as the emitted document: [`describe`] plus the
/// derivations taken from that same walk.
#[must_use]
pub fn document(root: &Command) -> SpecDocument {
    let command = describe(root);
    SpecDocument {
        spec_version: SPEC_VERSION,
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
pub fn read_only_allowlist(spec: &CommandSpec) -> Vec<ReadOnlyEntry> {
    let mut entries = Vec::new();
    collect_read_only(spec, spec.path.as_str(), &mut entries);
    // By ID, not by path: the sort key has to be the stable half, or the
    // document's byte order moves under a rename that changed nothing about
    // which commands are read-only.
    entries.sort();
    entries
}

fn collect_read_only(node: &CommandSpec, root_name: &str, out: &mut Vec<ReadOnlyEntry>) {
    // The bare root program declares no effect of its own; skip it.
    if node.path != root_name && node.effect.is_read_only() {
        // A read-only row with no declared id cannot be listed: the whole value
        // of this list is that a consumer can pin it, and an entry it cannot pin
        // is one it must re-derive by path — the second derivation this list
        // exists to remove. `every_declared_path_has_an_id` is what makes the
        // case unreachable rather than merely unlikely.
        if let Some(id) = &node.id {
            out.push(ReadOnlyEntry {
                id: id.clone(),
                path: node.path.clone(),
            });
        }
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

        // Compared as PATHS, sorted by id — because the emitted list is ordered
        // by its stable half (CLOUD-969) and re-sorting the expectation by path
        // would assert an order the document deliberately does not have.
        let emitted: Vec<String> = document
            .read_only_allowlist
            .iter()
            .map(|entry| entry.path.clone())
            .collect();
        let mut emitted_sorted = emitted.clone();
        emitted_sorted.sort();
        expected.sort();
        assert_eq!(emitted_sorted, expected);

        // And every entry's id is the one its own row declares, so the pair a
        // consumer pins against cannot drift apart inside the document.
        for entry in &document.read_only_allowlist {
            assert_eq!(
                crate::surface::id_for(&entry.path),
                Some(entry.id.as_str()),
                "the allowlist entry for `{}` must carry its declared id",
                entry.path
            );
        }

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
        //
        // Compared as paths since CLOUD-969: the emitted entry is `{id, path}`
        // and ordered by its stable half, so this literal is sorted by path and
        // the emitted paths are sorted to meet it. What the list pins is WHICH
        // commands are read-only, which is the safety-critical half; that each
        // entry carries its declared id is pinned by
        // `the_emitted_allowlist_is_exactly_the_read_effect_filter`.
        let mut emitted: Vec<String> = read_only_allowlist(&spec())
            .into_iter()
            .map(|entry| entry.path)
            .collect();
        emitted.sort();
        assert_eq!(
            emitted,
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
                "capture find".to_owned(),
                "capture list".to_owned(),
                "capture show".to_owned(),
                "check".to_owned(),
                // The VERB only, and the `checks` noun above it is not here
                // (CLOUD-1143). The noun is unclassified for `capture`'s reason
                // one row up: a consumer treating an entry as a prefix must not
                // inherit a claim the whole subtree has not earned. The verb is
                // `read` structurally — it decides over a reading handed to it on
                // stdin and cannot start a program, because the FETCH stays with
                // the poller that already holds the body.
                "checks green".to_owned(),
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
                // FIVE OF THE TEN LEASE ARMS, and the noun is NOT among them
                // (CLOUD-1274). `lease acquire|renew|hold|release|reserve` each
                // reach `swap`, which is a compare-and-swap against a REMOTE ref
                // — the only remote write in this crate — so the noun stays
                // unclassified for `capture`'s reason two rows up: a consumer
                // treating an entry as a prefix must not be handed the writes.
                //
                // `check` is a separate row from `status` rather than a flag on
                // it, and this list is why: the allowlist is
                // `filter(effect == read)` with no second list, so a refusing
                // flag on a reporting row would drop the reporting invocation
                // every consumer already uses.
                "lease authorises".to_owned(),
                "lease check".to_owned(),
                "lease held".to_owned(),
                "lease peek".to_owned(),
                "lease status".to_owned(),
                // The `lint` noun is on the list with its kind, for the same
                // reason as `policy` below: `lint <kind>` reads text the caller
                // names and answers about its shape, so the whole subtree is
                // read and the noun row smuggles no write (CLOUD-84).
                "lint".to_owned(),
                "lint brief".to_owned(),
                // CLOUD-1267. Only the CENSUS is on the allowlist: it is one
                // pass over the declarations, reading what each gate declares
                // and answering whether every one is enforced or exempt. Both
                // `mutate sweep` and the noun above it are `write` and so are
                // absent — the sweep stages a tree and spawns a suite runner
                // against it, and the noun STATES that rather than inheriting
                // it, which is the fail-safe reading for a consumer treating an
                // allowlist entry as a prefix (CLOUD-121).
                "mutate census".to_owned(),
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
                "policy hooks".to_owned(),
                "policy test".to_owned(),
                "policy tools".to_owned(),
                // The freshness verb, never the `provision` noun or `apply`:
                // that subtree writes, so the noun takes the conservative
                // reading (CLOUD-90).
                "provision status".to_owned(),
                // The lint verb, never the `ready` noun: the noun performs no
                // default action and is `Unclassified` for the reason every other
                // bare noun here is. `claim check` is absent from BOTH lists —
                // its pullable path mints a receipt, so it is `write`, and a row
                // claiming otherwise would advertise a writing verb as read-only.
                "ready lint".to_owned(),
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
            !allowlist.iter().any(|entry| entry.path == "enforce"),
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
            !allowlist.iter().any(|entry| entry.path == "hook"),
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

    /// The row set [`the_emitted_surface_is_exactly_the_committed_row_set`]
    /// compares against, and the reasoning for each row that has one.
    ///
    /// Lifted out of the assertion rather than inlined, for the same reason
    /// `cli.rs`'s census config was: the list grows by a row every time a verb
    /// is added, and it pushed the assertion past the line ceiling. The
    /// comments travel WITH the rows rather than staying behind, because each
    /// one explains why that row is spelled the way it is — a reader who has to
    /// look somewhere else for that has the same problem the extraction was
    /// meant to solve.
    // A ledger with a comment per row, which is the point of it — every row is a
    // decision somebody wrote down. Splitting it to satisfy a line count would
    // put the rows somewhere the assertion does not read them.
    #[allow(clippy::too_many_lines)]
    fn committed_rows() -> Vec<String> {
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
            "capture find".to_owned(),
            "capture list".to_owned(),
            "capture prune".to_owned(),
            "capture show".to_owned(),
            "check".to_owned(),
            // The green-verdict noun and its verb (CLOUD-1143), ported off
            // `mise-tasks/checks-green.sh` on the terms `claim` below
            // records. Stated here rather than regenerated, which is what
            // this assertion is for: the row set moving is the prompt to
            // reconcile §2 in the same change.
            //
            // Only `checks green` reaches the read-only allowlist above. The
            // exit table it answers in is NOT the predecessor's — red and
            // not-yet share `Violation`, because they differ in whether to
            // ask again and never in whether the head may land, so a caller
            // that reads the code alone holds instead of landing.
            "checks".to_owned(),
            "checks green".to_owned(),
            // The pull-time claim noun (CLOUD-1121), ported off
            // `mise-tasks/claim-check.sh` on the terms `semver` below
            // records: CLOUD-1059 made editing a shell rule refusable, so a
            // migration replaces one or does not land. It is absent from the
            // read-only allowlist above, deliberately: the pullable path
            // MINTS a receipt.
            "claim".to_owned(),
            "claim bot".to_owned(),
            "claim carry".to_owned(),
            "claim check".to_owned(),
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
            // THE LANDING LEASE, ten arms and a noun (CLOUD-1274, CLOUD-393).
            // The noun is UNCLASSIFIED rather than read, because half the
            // subtree writes: `acquire|renew|hold|release|reserve` each reach
            // the compare-and-swap against the remote ref, which is the only
            // remote write this crate performs. Classifying the noun `read`
            // would hand a consumer treating an entry as a prefix exactly those
            // five (CLOUD-121's reading, and `capture`'s precedent).
            //
            // `check` is its own row rather than a flag on `status` because the
            // read-only allowlist is `filter(effect == read)` with no second
            // list, so a refusing flag on a reporting row would drop the
            // reporting invocation every consumer already uses.
            "lease".to_owned(),
            "lease acquire".to_owned(),
            "lease authorises".to_owned(),
            "lease check".to_owned(),
            "lease held".to_owned(),
            "lease hold".to_owned(),
            "lease peek".to_owned(),
            "lease release".to_owned(),
            "lease renew".to_owned(),
            "lease reserve".to_owned(),
            "lease status".to_owned(),
            // A top-level verb-with-kind, not a `brief` noun: what varies
            // across `lint <kind>` is the artifact, and `config lint` stays
            // where it is because it lints the one committed authority
            // rather than something the caller names (CLOUD-84).
            "lint".to_owned(),
            "lint brief".to_owned(),
            // CLOUD-1260, and this assertion doing its job again: a new noun
            // fails here and has to be stated, which is the prompt to
            // reconcile §2 in the same change. Both rows are UNCLASSIFIED and
            // deliberately absent from the read-only allowlist above — `mcp
            // call` makes an OUTBOUND CALL and writes the capture store, so
            // an optimistic `read` would widen §5's derived allowlist
            // silently, and the noun over it would leak onto the same list
            // for any consumer reading an entry as a prefix (CLOUD-121).
            "mcp".to_owned(),
            "mcp call".to_owned(),
            // CLOUD-1267's noun and its two verbs, retired out of
            // `mise-tasks/mutant.sh` and `mise-tasks/mutant-census.sh`.
            // Stated here rather than regenerated, on the terms `checks`
            // above records: the row set moving is the prompt to reconcile
            // §2 in the same change.
            //
            // The noun is `write` and only `mutate census` reaches the
            // read-only allowlist. `mutate sweep` stages a copy of the tree
            // and spawns a suite runner against it, so it is `write` — the
            // disposition CLOUD-1171 settled for `perf pair`, and the reason
            // this could not be a `check` row at all. The noun STATES that
            // rather than inheriting it: `every_command_has_a_declared_effect`
            // refuses an `ask`, and a `write` noun is what a consumer reading
            // an allowlist entry as a prefix should find (CLOUD-121).
            "mutate".to_owned(),
            "mutate census".to_owned(),
            "mutate sweep".to_owned(),
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
            "policy hooks".to_owned(),
            "policy test".to_owned(),
            "policy tools".to_owned(),
            // The poll around `checks green`'s verdict (CLOUD-1143), ported
            // off `mise-tasks/ci-wait.sh` and renamed onto §2's declared
            // spelling by CLOUD-1214. THIS LIST IS SORTED, which is why the
            // pair sits here rather than beside the verdict it polls, and
            // why leaving them where `ci` had been failed the assertion.
            //
            // NEITHER row is in the read-only allowlist above: the verb runs
            // two programs the caller names — the forge's client to take the
            // reading, and a recorder for the progress signals — and "runs a
            // program somebody else chose" is not `read`, whatever the
            // reading itself costs.
            "pr".to_owned(),
            "pr closes".to_owned(),
            "pr derive".to_owned(),
            "pr ensure".to_owned(),
            "pr file".to_owned(),
            "pr link".to_owned(),
            "pr watch".to_owned(),
            "provision".to_owned(),
            "provision apply".to_owned(),
            "provision status".to_owned(),
            // The refinement gate, ported off `mise-tasks/ready-lint.sh` in
            // the same change and for the same reason.
            "ready".to_owned(),
            "ready lint".to_owned(),
            "receipt".to_owned(),
            "receipt record".to_owned(),
            "receipt status".to_owned(),
            // The out-of-tree verdict stores' write half (CLOUD-1265). §2
            // gains the noun and its two leaves in the same change, which is
            // what this assertion exists to prompt.
            //
            // TWO LEAVES AND NOT ONE, because the two stores share the
            // record's line shape and nothing else: `tools::record_key`
            // composes a triple from a declared row plus bytes read off disk,
            // `forge::record_path` is a resolved sha. A single verb with a
            // mode flag would be a second authority over which key gets
            // composed — and building both is what keeps this off
            // CLOUD-1184's singleton-noun list.
            //
            // Spelled `record <object>` rather than `<object> record`, unlike
            // its `receipt record` and `state record` neighbours above:
            // CLOUD-1190 inverts those when the imperative grammar lands, and
            // a third row spelled the old way would be a third row to invert.
            "record".to_owned(),
            "record closes".to_owned(),
            "record forge".to_owned(),
            // The plan a branch declared, so `plan-complete` decides over a
            // record rather than over a transcript it cannot re-read.
            "record plan".to_owned(),
            "record tool".to_owned(),
            // The API-compatibility noun (CLOUD-1050), ported off
            // `mise-tasks/semver.sh` when CLOUD-1059 made editing a shell
            // rule refusable. §2 gains the noun in the same change, which is
            // what this assertion exists to prompt.
            "semver".to_owned(),
            "semver check".to_owned(),
            "spec".to_owned(),
            // The container's declared preconditions (CLOUD-1324) — §9's
            // check/fix pair, as one verb and a `--repair` flag rather than two
            // sub-verbs, because both halves decide the same rows and the fix
            // half's report IS the check re-run. §2 gains the row in the same
            // change, which is what this assertion exists to prompt. Absent from
            // the read-only list above and correctly so: a row's `check` is a
            // command the operator declared, so bare `startup` runs
            // user-supplied code even though it writes nothing itself.
            "startup".to_owned(),
            "state".to_owned(),
            "state adopt".to_owned(),
            "state list".to_owned(),
            "state migrate".to_owned(),
            "state record".to_owned(),
            "state settle".to_owned(),
            // The build-tree noun (CLOUD-1030), ported off
            // `mise-tasks/target-prune.sh` for `semver`'s reason above. Both
            // rows are `Effect::Destructive` and so are deliberately absent
            // from the read allowlist — this is the second destructive verb
            // on the surface, beside `capture prune`, and it earns the same
            // `-y` binding rather than a new exception.
            "target".to_owned(),
            "target prune".to_owned(),
            // The one write path over a host's hook registrations
            // (CLOUD-893). Both rows are here and NEITHER is on the
            // read-only allowlist above: the noun is `Unclassified` because
            // its subtree carries a destructive verb, and the verb is
            // `Destructive` because its subject is a file shared by every
            // checkout on the box.
            "wiring".to_owned(),
            "wiring reclaim".to_owned(),
            "worktree".to_owned(),
            "worktree status".to_owned(),
        ]
    }

    #[test]
    // The ledger is 100+ rows with a comment each, which is the point of it —
    // every row is a decision somebody wrote down. Splitting it to satisfy a line
    // count would put the rows somewhere the assertion does not read them.
    #[allow(clippy::too_many_lines)]
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
        assert_eq!(paths, committed_rows());
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
