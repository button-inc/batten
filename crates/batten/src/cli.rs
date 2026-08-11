//! Parsing the command surface into the typed values `run` dispatches on.
//!
//! The surface itself is *not* defined here — it is one declaration in
//! [`crate::surface`], from which the live [`clap::Command`] tree is built
//! (house-style §11). This module owns the other half: turning the parsed
//! [`clap::ArgMatches`] into a typed [`Cli`], so dispatch stays an exhaustive
//! `match` over enums rather than a lookup on strings.
//!
//! The split is what keeps the tree honest. A verb's path, summary, effect, and
//! flags exist once, as data; adding one is adding a [`crate::surface::SURFACE`]
//! row plus the arm here that gives it a typed shape.
//! [`tests::every_leaf_verb_dispatches`] fails if a row ever ships without its
//! arm, so a declared command can never parse into `None` and silently succeed.

use clap::{ArgMatches, ValueEnum};

use crate::config::Strictness;
use crate::hook::Harness;
use crate::surface;

/// The parsed invocation: the global flags plus the chosen command.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Cli {
    /// `--strictness`, when passed.
    ///
    /// `BATTEN_STRICTNESS` is the env equivalent, resolved by
    /// [`crate::resolve`] as its own layer rather than by `clap`, so `config
    /// show` can attribute the value to `env` or `flag` and not conflate them.
    pub strictness: Option<Strictness>,
    /// `--fail-on-warning`, promoting a warn-severity finding to a violation.
    ///
    /// One setting, not a per-verb flag: `BATTEN_FAIL_ON_WARNING` and the
    /// `fail_on_warning` key are the same setting, layered by
    /// [`crate::resolve`]. Raise-only and with no negative form, so a committed
    /// `true` cannot be turned off for a run.
    pub fail_on_warning: bool,
    /// `--config-from <ref>`, when passed: read the committed authority from
    /// this git ref instead of the working tree (CLOUD-31).
    pub config_from: Option<String>,
    /// The chosen command, or `None` for a bare invocation.
    pub command: Option<Command>,
}

/// The top-level subcommands.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Command {
    /// Run the applicable read-only gates against the repository.
    Check {
        /// Emit findings as byte-stable JSON instead of pointer lines.
        json: bool,
    },
    /// Run every configured rule, including kinds that execute a configured command.
    Enforce {
        /// Emit findings as byte-stable JSON instead of pointer lines.
        json: bool,
    },
    /// Inspect configuration.
    Config {
        /// The chosen sub-verb.
        command: ConfigCommand,
    },
    /// Print the tool's own command spec.
    Spec {
        /// The output format for the spec.
        format: SpecFormat,
    },
    /// Diagnose whether Batten can run in this repository.
    Doctor {
        /// Emit the diagnosis as byte-stable JSON instead of pointer lines.
        json: bool,
    },
    /// Emit an artifact derived from the command spec.
    Generate {
        /// The chosen sub-verb.
        command: GenerateCommand,
    },
    /// Run a command, passing its streams and exit code through unchanged.
    Exec {
        /// The command and its arguments, exactly as the caller wrote them.
        command: Vec<String>,
    },
    /// Adjudicate a mediated tool call read from stdin.
    Hook {
        /// The harness whose payload to decode and whose decision channel to answer in.
        harness: Harness,
    },
    /// Verification receipts, keyed by SHA.
    Receipt {
        /// The chosen sub-verb.
        command: ReceiptCommand,
    },
    /// Inspect the thresholds and path sets this repository holds itself to.
    Policy {
        /// The chosen sub-verb.
        command: PolicyCommand,
    },
    /// Worktrees and the work in them.
    Worktree {
        /// The chosen sub-verb.
        command: WorktreeCommand,
    },
    /// The out-of-tree findings store.
    State {
        /// The chosen sub-verb.
        command: StateCommand,
    },
    /// The append-only defect ledger.
    Defects {
        /// The chosen sub-verb.
        command: DefectsCommand,
    },
    /// Pinned tools this repository provisions.
    Provision {
        /// The chosen sub-verb.
        command: ProvisionCommand,
    },
    /// Lint an artifact against a declared schema.
    Lint {
        /// The chosen kind.
        command: LintCommand,
    },
    /// Design-evidence claims and the integrity of the record behind them.
    Design {
        /// The chosen sub-verb.
        command: DesignCommand,
    },
}

/// Subcommands of `lint` — one arm per *kind* of artifact, which is what the
/// house-style `lint <kind>` shape names (CLOUD-84).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum LintCommand {
    /// Check a delegation brief against the handoff schema.
    Brief {
        /// The brief to read. `None` or `-` reads stdin, so a brief can be piped
        /// straight from whatever composed it without a temporary file.
        path: Option<String>,
        /// Emit the report as byte-stable JSON instead of pointer lines.
        json: bool,
    },
}

/// Subcommands of `design`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum DesignCommand {
    /// Audit a JSONL claim stream read on stdin.
    Audit {
        /// Emit the problems as byte-stable JSON instead of pointer lines.
        json: bool,
    },
}

/// Subcommands of `defects`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum DefectsCommand {
    /// List recorded defects as pointers.
    Query {
        /// Emit the records as byte-stable JSON instead of pointer lines.
        json: bool,
        /// Only records in this taxonomy class.
        class: Option<String>,
        /// Only the record with this id.
        id: Option<String>,
        /// Only records nothing gates yet.
        ungated: bool,
    },
    /// Append records read as JSONL on stdin.
    Add {
        /// Validate and report the would-append count without writing.
        dry_run: bool,
    },
}

/// Subcommands of `provision`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProvisionCommand {
    /// Report which provisioned tools do not match the manifest.
    Status {
        /// Emit the report as byte-stable JSON instead of pointer lines.
        json: bool,
    },
    /// Fetch, verify, and install into the out-of-tree cache.
    Apply {
        /// Preview what would be applied, writing nothing.
        dry_run: bool,
    },
}

/// Subcommands of `worktree`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum WorktreeCommand {
    /// Report work that is uncommitted, unpushed, or not landed.
    Status {
        /// Emit the report as byte-stable JSON instead of pointer lines.
        json: bool,
    },
    /// Snapshot and abandon worktrees that are dirty and unreapable.
    Reclaim {
        /// Preview what would be reclaimed, writing and removing nothing.
        dry_run: bool,
    },
}

/// Subcommands of `policy`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum PolicyCommand {
    /// Judge the always-loaded instruction set against its token budget.
    Budget {
        /// Emit the measurement as byte-stable JSON instead of pointer lines.
        json: bool,
    },
}

/// Subcommands of `state`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum StateCommand {
    /// Bind this checkout to its findings store.
    Adopt {
        /// The store id to bind. `None` binds whatever resolution found, which
        /// is the ordinary case; naming one is how an operator overrides a
        /// resolution that refused to decide for itself.
        store: Option<String>,
    },
    /// Record this ref's findings into the store.
    Record,
    /// Upgrade the store's record version. The only upgrade path.
    Migrate,
    /// List stored findings.
    List {
        /// Emit the listing as byte-stable JSON instead of pointer lines.
        json: bool,
    },
}

/// Subcommands of `receipt`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ReceiptCommand {
    /// Record that the named check concluded pass against the current HEAD.
    Record {
        /// The check whose conclusion is being recorded.
        check: String,
    },
    /// Judge the named check's recorded receipt against HEAD and origin/main.
    Status {
        /// The check whose receipt is judged.
        check: String,
        /// Emit the verdict as byte-stable JSON instead of a pointer line.
        json: bool,
    },
}

/// Subcommands of `config`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ConfigCommand {
    /// Print the effective configuration.
    Show {
        /// Emit the full `{value, source}` document instead of pointer lines.
        json: bool,
    },
    /// Report policy smells in `batten.toml`.
    Lint {
        /// Emit the smells as byte-stable JSON instead of pointer lines.
        json: bool,
        /// Where to read the host ruleset payload from, when the caller asked
        /// for the drift comparison. `-` is stdin.
        host_rules: Option<String>,
    },
    /// Print the content hash of the governing config surface.
    Epoch {
        /// Emit the epoch and the surface it covers as byte-stable JSON.
        json: bool,
        /// Ignore the cached value and rehash the tracked files' bytes.
        no_cache: bool,
    },
}

/// Subcommands of `generate`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum GenerateCommand {
    /// Emit the completion script for one shell.
    Completions {
        /// The shell whose completion script to emit.
        shell: clap_complete::Shell,
    },
    /// Emit the roff man page for one command.
    Man {
        /// The root-relative path of the command to document (`config show`),
        /// or `None` for the root page. Optional rather than required because
        /// the root page is the one a caller asks for by default.
        command: Option<String>,
    },
    /// Emit the whole surface as one markdown reference.
    Markdown,
    /// Emit the JSON Schema for a config surface.
    Schema {
        /// Which surface to describe: the committed authority, or the
        /// raise-only override layer.
        surface: ConfigSurface,
    },
}

/// The formats `batten spec` can emit.
///
/// One, deliberately. House-style §2 and §11 advertised `kdl|json`; KDL was
/// never implemented and never had a consumer, and JSON is the agent-facing
/// contract (§6). The document is corrected rather than the binary, and
/// `spec::tests::the_spec_emits_exactly_the_committed_formats` pins the list so
/// a second format is added to both at once (CLOUD-244).
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
#[non_exhaustive]
pub enum SpecFormat {
    /// Byte-stable JSON — the agent-facing contract (§6).
    Json,
}

/// The two config surfaces a schema can describe (CLOUD-239).
///
/// Two surfaces, two derivations. `batten.toml` is the committed authority;
/// `batten.local.toml` is the raise-only override, which accepts a strict subset
/// and refuses the rest. One schema describing both is what let a validator
/// green-light keys the loader drops.
///
/// A flag on the existing emitter rather than a second sub-verb: CLOUD-244
/// records that §2 and the landed surface already disagree about where schema
/// emission lives, and adding a verb would deepen that before it is settled.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
#[non_exhaustive]
pub enum ConfigSurface {
    /// The committed authority: `batten.toml`.
    Authority,
    /// The raise-only override layer: `batten.local.toml`.
    Override,
}

/// Parse the process arguments into a [`Cli`].
///
/// # Errors
///
/// Returns `clap`'s error for a malformed invocation, and for `--help` and
/// `--version`, which `clap` reports through the same channel. The binary
/// distinguishes them with [`clap::Error::use_stderr`] so a help request is not
/// charged as a usage error.
pub fn try_parse() -> Result<Cli, clap::Error> {
    Ok(from_matches(&surface::command().try_get_matches()?))
}

/// Give the parsed matches their typed shape.
///
/// Total by construction: an unrecognised subcommand yields `None`, which `run`
/// treats as the bare invocation. `clap` has already refused anything the
/// surface does not declare, so `None` here is unreachable for a declared verb —
/// and [`tests::every_leaf_verb_dispatches`] is what keeps that true as the
/// surface grows.
fn from_matches(matches: &ArgMatches) -> Cli {
    Cli {
        // `--strictness` is global, so `clap` records it on the root regardless
        // of where on the command line it appeared.
        strictness: matches.get_one::<Strictness>("strictness").copied(),
        fail_on_warning: matches.get_flag("fail_on_warning"),
        config_from: matches.get_one::<String>("config_from").cloned(),
        command: matches.subcommand().and_then(command_of),
    }
}

/// Read a boolean flag that `clap` records on the subcommand it was passed to.
fn flag(matches: &ArgMatches, id: &str) -> bool {
    matches.try_get_one::<bool>(id).ok().flatten() == Some(&true)
}

/// The nesting nouns, each mapping its own sub-verb.
///
/// Split out of [`command_of`] one function per noun rather than inlined as
/// closures: the flat match grew past `clippy::too_many_lines` when `provision`
/// landed, and a noun's sub-verbs are the natural seam. Each stays total —
/// an unrecognised sub-verb is `None`, which `clap` has already made
/// unreachable for a declared surface.
fn config_of(matches: &ArgMatches) -> Option<ConfigCommand> {
    match matches.subcommand()? {
        ("show", matches) => Some(ConfigCommand::Show {
            json: flag(matches, "json"),
        }),
        ("lint", matches) => Some(ConfigCommand::Lint {
            json: flag(matches, "json"),
            host_rules: matches
                .get_one::<String>("host_rules")
                .map(ToOwned::to_owned),
        }),
        ("epoch", matches) => Some(ConfigCommand::Epoch {
            json: flag(matches, "json"),
            no_cache: flag(matches, "no_cache"),
        }),
        _ => None,
    }
}

/// The positional is optional and belongs to one kind, so it is read inside the
/// arm — the shape [`state_of`] uses for `state adopt`.
fn lint_of(matches: &ArgMatches) -> Option<LintCommand> {
    match matches.subcommand()? {
        ("brief", matches) => Some(LintCommand::Brief {
            path: matches.get_one::<String>("brief").cloned(),
            json: flag(matches, "json"),
        }),
        _ => None,
    }
}

fn policy_of(matches: &ArgMatches) -> Option<PolicyCommand> {
    match matches.subcommand()? {
        ("budget", matches) => Some(PolicyCommand::Budget {
            json: flag(matches, "json"),
        }),
        _ => None,
    }
}

fn provision_of(matches: &ArgMatches) -> Option<ProvisionCommand> {
    match matches.subcommand()? {
        ("status", matches) => Some(ProvisionCommand::Status {
            json: flag(matches, "json"),
        }),
        ("apply", matches) => Some(ProvisionCommand::Apply {
            dry_run: flag(matches, "dry_run"),
        }),
        _ => None,
    }
}

fn defects_of(matches: &ArgMatches) -> Option<DefectsCommand> {
    match matches.subcommand()? {
        ("query", matches) => Some(DefectsCommand::Query {
            json: flag(matches, "json"),
            class: matches.get_one::<String>("class").cloned(),
            id: matches.get_one::<String>("id").cloned(),
            ungated: flag(matches, "ungated"),
        }),
        ("add", matches) => Some(DefectsCommand::Add {
            dry_run: flag(matches, "dry_run"),
        }),
        _ => None,
    }
}

fn design_of(matches: &ArgMatches) -> Option<DesignCommand> {
    match matches.subcommand()? {
        ("audit", matches) => Some(DesignCommand::Audit {
            json: flag(matches, "json"),
        }),
        _ => None,
    }
}

fn worktree_of(matches: &ArgMatches) -> Option<WorktreeCommand> {
    match matches.subcommand()? {
        ("status", matches) => Some(WorktreeCommand::Status {
            json: flag(matches, "json"),
        }),
        ("reclaim", matches) => Some(WorktreeCommand::Reclaim {
            dry_run: flag(matches, "dry_run"),
        }),
        _ => None,
    }
}

fn generate_of(matches: &ArgMatches) -> Option<GenerateCommand> {
    match matches.subcommand()? {
        ("completions", matches) => matches
            .get_one::<clap_complete::Shell>("shell")
            .map(|shell| GenerateCommand::Completions { shell: *shell }),
        ("man", matches) => Some(GenerateCommand::Man {
            command: matches.get_one::<String>("command").cloned(),
        }),
        ("markdown", _) => Some(GenerateCommand::Markdown),
        ("schema", matches) => Some(GenerateCommand::Schema {
            surface: matches
                .get_one::<ConfigSurface>("surface")
                .copied()
                .unwrap_or(ConfigSurface::Authority),
        }),
        _ => None,
    }
}

fn receipt_of(matches: &ArgMatches) -> Option<ReceiptCommand> {
    let (name, matches) = matches.subcommand()?;
    let check = matches.get_one::<String>("check")?.clone();
    match name {
        "record" => Some(ReceiptCommand::Record { check }),
        "status" => Some(ReceiptCommand::Status {
            check,
            json: flag(matches, "json"),
        }),
        _ => None,
    }
}

/// Unlike [`receipt_of`], the positional is optional and belongs to one
/// sub-verb, so it is read inside the arm rather than ahead of the match.
fn state_of(matches: &ArgMatches) -> Option<StateCommand> {
    match matches.subcommand()? {
        ("adopt", matches) => Some(StateCommand::Adopt {
            store: matches.get_one::<String>("store").cloned(),
        }),
        ("record", _) => Some(StateCommand::Record),
        ("migrate", _) => Some(StateCommand::Migrate),
        ("list", matches) => Some(StateCommand::List {
            json: flag(matches, "json"),
        }),
        _ => None,
    }
}

fn command_of((name, matches): (&str, &ArgMatches)) -> Option<Command> {
    match name {
        "check" => Some(Command::Check {
            json: flag(matches, "json"),
        }),
        "enforce" => Some(Command::Enforce {
            json: flag(matches, "json"),
        }),
        "config" => config_of(matches).map(|command| Command::Config { command }),
        "lint" => lint_of(matches).map(|command| Command::Lint { command }),
        "spec" => matches
            .get_one::<SpecFormat>("format")
            .map(|format| Command::Spec { format: *format }),
        "doctor" => Some(Command::Doctor {
            json: flag(matches, "json"),
        }),
        "policy" => policy_of(matches).map(|command| Command::Policy { command }),
        "provision" => provision_of(matches).map(|command| Command::Provision { command }),
        "defects" => defects_of(matches).map(|command| Command::Defects { command }),
        "design" => design_of(matches).map(|command| Command::Design { command }),
        "worktree" => worktree_of(matches).map(|command| Command::Worktree { command }),
        "generate" => generate_of(matches).map(|command| Command::Generate { command }),
        // `get_many`, not `get_one`: the tail is an `Append` action, so every
        // token after `--` is a separate value and the child's argv is the whole
        // list. An empty list is unreachable — clap enforces `num_args(1..)` —
        // and is mapped to `None` rather than an empty exec.
        "exec" => {
            let command: Vec<String> = matches
                .get_many::<String>("command")
                .map(|values| values.cloned().collect())
                .unwrap_or_default();
            if command.is_empty() {
                None
            } else {
                Some(Command::Exec { command })
            }
        }
        "hook" => matches
            .get_one::<Harness>("harness")
            .map(|harness| Command::Hook { harness: *harness }),
        "receipt" => receipt_of(matches).map(|command| Command::Receipt { command }),
        "state" => state_of(matches).map(|command| Command::State { command }),
        _ => None,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::surface::{SURFACE, ValueDecl};

    /// Parse an argv the way the binary does, through the built tree.
    fn parse(argv: &[&str]) -> Cli {
        let matches = surface::command()
            .try_get_matches_from(std::iter::once("batten").chain(argv.iter().copied()))
            .expect("argv parses");
        from_matches(&matches)
    }

    /// The smallest argv that satisfies a declared command's required arguments.
    ///
    /// Values come from the declaration itself — a `ValueEnum` flag is given its
    /// first accepted token — so a new required flag needs no edit here.
    fn argv_for(path: &str) -> Vec<String> {
        let mut argv: Vec<String> = path.split(' ').map(ToOwned::to_owned).collect();
        let decl = SURFACE
            .iter()
            .find(|decl| decl.path == path)
            .expect("path is declared");
        for flag in decl.flags {
            let value = match flag.value {
                // A counted flag consumes nothing, so it never contributes a
                // token to the minimal argv — and it is never required.
                ValueDecl::Count => continue,
                // A trailing variadic is required and positional, so the minimal
                // argv needs `--` plus one token for the child.
                ValueDecl::Trailing => {
                    argv.push("--".to_owned());
                    argv.push("true".to_owned());
                    continue;
                }
                ValueDecl::Bool => {
                    if flag.required {
                        argv.push(format!("--{}", flag.long.expect("a bool flag has a long")));
                    }
                    continue;
                }
                ValueDecl::Str => "placeholder".to_owned(),
                ValueDecl::Enum { parser, default } => match default {
                    Some(_) => continue,
                    None => parser()
                        .possible_values()
                        .and_then(|mut values| values.next())
                        .map(|value| value.get_name().to_owned())
                        .expect("a ValueEnum flag offers at least one token"),
                },
            };
            if !flag.required {
                continue;
            }
            if let Some(long) = flag.long {
                argv.push(format!("--{long}"));
            }
            argv.push(value);
        }
        argv
    }

    #[test]
    fn every_leaf_verb_dispatches() {
        // The other half of the derivation gate. `surface.rs` pins that every
        // declared path reaches the parser; this pins that every *leaf* path
        // reaches a typed arm. Without it a new row parses fine and then falls
        // through `command_of` to `None`, which `run` reads as a bare
        // invocation — a declared verb silently exiting 0 having done nothing.
        for decl in SURFACE {
            if SURFACE
                .iter()
                .any(|other| other.path.starts_with(&format!("{} ", decl.path)))
            {
                continue; // a noun; its leaves carry the dispatch
            }
            let argv = argv_for(decl.path);
            let borrowed: Vec<&str> = argv.iter().map(String::as_str).collect();
            assert!(
                parse(&borrowed).command.is_some(),
                "{} parses but does not dispatch",
                decl.path
            );
        }
    }

    #[test]
    fn a_bare_invocation_chooses_no_command() {
        let matches = surface::command()
            .try_get_matches_from(["batten"].iter())
            .expect_err("a bare invocation is clap's help path");
        assert!(matches.use_stderr(), "the listing is a usage error, exit 1");
    }

    #[test]
    fn the_global_flag_is_read_after_a_subcommand() {
        // `--strictness` is global, so it must resolve identically whether it
        // precedes or follows the verb — otherwise a flag would apply to one
        // verb and not another, which §8's precedence chain forbids.
        let before = parse(&["--strictness", "strict", "check"]);
        let after = parse(&["check", "--strictness", "strict"]);
        assert_eq!(before, after);
        assert_eq!(before.strictness, Some(Strictness::Strict));
    }

    #[test]
    fn spec_format_defaults_to_json() {
        assert_eq!(
            parse(&["spec"]).command,
            Some(Command::Spec {
                format: SpecFormat::Json
            })
        );
    }

    #[test]
    fn a_positional_reaches_its_typed_arm() {
        assert_eq!(
            parse(&["receipt", "status", "verify"]).command,
            Some(Command::Receipt {
                command: ReceiptCommand::Status {
                    check: "verify".to_owned(),
                    json: false,
                }
            })
        );
    }
}
