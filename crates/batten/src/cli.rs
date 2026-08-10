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
    },
    /// Print the content hash of the governing config surface.
    Epoch {
        /// Emit the epoch and the surface it covers as byte-stable JSON.
        json: bool,
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
    /// Emit the JSON Schema for `batten.toml`.
    Schema,
}

/// The formats `batten spec` can emit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
#[non_exhaustive]
pub enum SpecFormat {
    /// Byte-stable JSON — the agent-facing contract (§6).
    Json,
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

fn command_of((name, matches): (&str, &ArgMatches)) -> Option<Command> {
    match name {
        "check" => Some(Command::Check {
            json: flag(matches, "json"),
        }),
        "enforce" => Some(Command::Enforce {
            json: flag(matches, "json"),
        }),
        "config" => matches
            .subcommand()
            .and_then(|(name, matches)| match name {
                "show" => Some(ConfigCommand::Show {
                    json: flag(matches, "json"),
                }),
                "lint" => Some(ConfigCommand::Lint {
                    json: flag(matches, "json"),
                }),
                "epoch" => Some(ConfigCommand::Epoch {
                    json: flag(matches, "json"),
                }),
                _ => None,
            })
            .map(|command| Command::Config { command }),
        "spec" => matches
            .get_one::<SpecFormat>("format")
            .map(|format| Command::Spec { format: *format }),
        "doctor" => Some(Command::Doctor {
            json: flag(matches, "json"),
        }),
        "generate" => matches
            .subcommand()
            .and_then(|(name, matches)| match name {
                "completions" => matches
                    .get_one::<clap_complete::Shell>("shell")
                    .map(|shell| GenerateCommand::Completions { shell: *shell }),
                "schema" => Some(GenerateCommand::Schema),
                _ => None,
            })
            .map(|command| Command::Generate { command }),
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
        "receipt" => matches
            .subcommand()
            .and_then(|(name, matches)| {
                let check = matches.get_one::<String>("check")?.clone();
                match name {
                    "record" => Some(ReceiptCommand::Record { check }),
                    "status" => Some(ReceiptCommand::Status {
                        check,
                        json: flag(matches, "json"),
                    }),
                    _ => None,
                }
            })
            .map(|command| Command::Receipt { command }),
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
