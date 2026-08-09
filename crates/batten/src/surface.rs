//! The command surface, declared once as data (house-style §11, CLOUD-27).
//!
//! [`SURFACE`] is the single source of truth for the command tree: every verb's
//! path, its human summary, its declared [`Effect`] (§5), and its flags —
//! including each flag's env equivalent, so the §8 precedence chain is
//! inspectable data rather than resolution logic buried in the binary.
//!
//! Everything downstream is *derived* from it and nothing is re-typed:
//!
//! * [`command`] builds the live [`clap::Command`] tree, so the parser cannot
//!   disagree with the declaration.
//! * [`crate::spec`] walks that same tree to emit `batten spec`, and
//!   `batten generate completions` derives the shell completions from it — which
//!   is why the shipped binary and the generated artifacts can never drift.
//! * [`effect_for`] resolves the effect model, and the agent read-only allowlist
//!   is `filter(effect == read)` over the same walk. There is never a second,
//!   hand-maintained list.
//!
//! Two invariants make the effect model fail-safe, and both live here because
//! this is where a command is declared:
//!
//! * **Absence means "ask", never "safe".** A path with no row resolves to
//!   [`Effect::Ask`]; the conservative reading is to prompt/deny, never to
//!   silently treat it as [`Effect::Read`].
//! * **No inheritance.** Every command self-declares. A noun whose subtree
//!   carries a write verb is listed with its own conservative effect rather than
//!   allowed to inherit `read` from a sibling.
//!
//! Adding a verb is adding a row here plus the arm that dispatches it;
//! [`crate::cli::tests`] and [`crate::spec::tests`] fail if either half is
//! missing.

use clap::builder::ValueParser;
use clap::{Arg, ArgAction, Command};

use crate::effect::Effect;

/// How an argument takes its value.
#[derive(Debug)]
#[non_exhaustive]
pub enum ValueDecl {
    /// A boolean flag: present or absent, consuming nothing.
    Bool,
    /// Consumes a free-form string.
    Str,
    /// Consumes one token of a `ValueEnum`.
    ///
    /// The parser is a pointer to the derive itself rather than a list of
    /// tokens copied into this table, so the accepted spelling of a value can
    /// never drift from the type that receives it.
    Enum {
        /// Builds the `ValueEnum`-derived parser for the receiving type.
        parser: fn() -> ValueParser,
        /// The value used when the flag is absent, if the flag has one.
        default: Option<&'static str>,
    },
}

/// A flag's `BATTEN_`-prefixed environment equivalent (§3), and which mechanism
/// reads it.
///
/// One enum rather than a name plus a boolean, so "declared but read by nobody"
/// and "read by both" are states that cannot be written down. That matters:
/// `--config-from` shipped with `BATTEN_CONFIG_FROM` declared and read nowhere,
/// and only an end-to-end test noticed (CLOUD-31). A decorative declaration
/// documents an override that silently does nothing.
#[derive(Debug)]
#[non_exhaustive]
pub enum EnvDecl {
    /// The flag has no environment equivalent.
    None,
    /// `clap` applies the variable itself.
    ///
    /// For a flag that selects *behaviour* rather than a config value —
    /// `--config-from` names where the authority is read from, and there is no
    /// precedence layer to attribute it to.
    Clap(&'static str),
    /// [`crate::resolve`] layers the variable as its own §8 precedence layer.
    ///
    /// For a policy-bearing key (`--strictness`, `--fail-on-warning`): env and
    /// flag must reach the resolver as *distinct* layers, or `config show` could
    /// not attribute a value to one rather than the other, and the raise-only
    /// clamp would compare a layer against itself.
    Layered(&'static str),
}

impl EnvDecl {
    /// The variable's name, whoever reads it.
    #[must_use]
    pub const fn name(&self) -> Option<&'static str> {
        match self {
            EnvDecl::None => None,
            EnvDecl::Clap(name) | EnvDecl::Layered(name) => Some(*name),
        }
    }
}

/// One argument of one command, declared as data.
#[derive(Debug)]
#[non_exhaustive]
pub struct FlagDecl {
    /// The argument's identifier, and the key `ArgMatches` is read by.
    pub id: &'static str,
    /// The long form, without dashes (`config-from`). `None` for a positional.
    pub long: Option<&'static str>,
    /// The short form, if any.
    pub short: Option<char>,
    /// The one-line human summary.
    pub help: &'static str,
    /// The flag's `BATTEN_`-prefixed environment equivalent (§3), and **who
    /// applies it**.
    pub env: EnvDecl,
    /// Whether the flag applies to the whole invocation rather than one verb.
    pub global: bool,
    /// Whether this is a positional argument rather than a flag.
    pub positional: bool,
    /// Whether the command refuses to run without it.
    pub required: bool,
    /// How the argument takes its value.
    pub value: ValueDecl,
}

impl FlagDecl {
    /// A positional argument the command requires.
    const fn positional(id: &'static str, help: &'static str) -> Self {
        FlagDecl {
            id,
            long: None,
            short: None,
            help,
            env: EnvDecl::None,
            global: false,
            positional: true,
            required: true,
            value: ValueDecl::Str,
        }
    }

    /// A required flag taking one token of a `ValueEnum`.
    const fn required_enum(
        id: &'static str,
        long: &'static str,
        help: &'static str,
        parser: fn() -> ValueParser,
    ) -> Self {
        FlagDecl {
            id,
            long: Some(long),
            short: None,
            help,
            env: EnvDecl::None,
            global: false,
            positional: false,
            required: true,
            value: ValueDecl::Enum {
                parser,
                default: None,
            },
        }
    }

    /// An optional flag taking one token of a `ValueEnum`, with a default.
    const fn defaulted_enum(
        id: &'static str,
        long: &'static str,
        help: &'static str,
        parser: fn() -> ValueParser,
        default: &'static str,
    ) -> Self {
        FlagDecl {
            id,
            long: Some(long),
            short: None,
            help,
            env: EnvDecl::None,
            global: false,
            positional: false,
            required: false,
            value: ValueDecl::Enum {
                parser,
                default: Some(default),
            },
        }
    }
}

/// One command, declared as data.
#[derive(Debug)]
#[non_exhaustive]
pub struct CommandDecl {
    /// The full, root-relative path (`config show`, never `batten config show`).
    pub path: &'static str,
    /// The one-line human summary, rendered as `clap`'s `about`.
    pub about: &'static str,
    /// The declared effect (§5). Self-declared, never inherited.
    pub effect: Effect,
    /// The command's own arguments.
    pub flags: &'static [FlagDecl],
}

/// `--strictness`, the one global flag.
///
/// The highest-precedence config layer (§8: flag > env > local file > repo
/// config > default), and still raise-only: it can tighten a gate for one run,
/// never disable one for it.
const STRICTNESS: FlagDecl = FlagDecl {
    id: "strictness",
    long: Some("strictness"),
    short: None,
    help: "Raise how strictly gates apply (an override may only tighten policy)",
    env: EnvDecl::Layered("BATTEN_STRICTNESS"),
    global: true,
    positional: false,
    required: false,
    value: ValueDecl::Enum {
        parser: strictness_parser,
        default: None,
    },
};

/// `--fail-on-warning`, the other global setting.
///
/// One setting, not a per-verb flag: it names one resolved value every verb
/// reads, which is what stops a verb from acquiring its own copy. Raise-only
/// and with no negative form — a committed `true` cannot be turned off for a
/// run (CLOUD-49).
const FAIL_ON_WARNING: FlagDecl = FlagDecl {
    // The id is the key `ArgMatches` is read by *and* the `name` the emitted
    // spec carries, so it is snake_case like every other id here while the long
    // form stays kebab-case. `fail_on_warning` is what a consumer of `batten
    // spec` matches on (asserted by `tests/fail_on_warning.rs`).
    id: "fail_on_warning",
    long: Some("fail-on-warning"),
    short: None,
    help: "Promote a warn-severity finding to a violation (an override may only turn this on)",
    env: EnvDecl::Layered("BATTEN_FAIL_ON_WARNING"),
    global: true,
    positional: false,
    required: false,
    value: ValueDecl::Bool,
};

/// `--config-from <ref>`, the config trust boundary (CLOUD-31).
///
/// Reads the committed authority from a git ref instead of the working tree, so
/// a branch that edits `batten.toml` cannot lower the bar it is judged by.
/// Global because it selects *which* config the whole run resolves from —
/// scoping it per verb would let one verb be judged by the base and another by
/// the working tree in the same invocation.
const CONFIG_FROM: FlagDecl = FlagDecl {
    id: "config_from",
    long: Some("config-from"),
    short: None,
    help: "Read the committed config from a git ref (e.g. origin/main) instead of the working tree",
    env: EnvDecl::Clap("BATTEN_CONFIG_FROM"),
    global: true,
    positional: false,
    required: false,
    value: ValueDecl::Str,
};

/// `-J`/`--json`, declared **per data-emitting command** (§6).
///
/// Deliberately not global: a global output mode would be silently accepted by
/// verbs that emit no data — a flag that looks applied and isn't.
const JSON: FlagDecl = FlagDecl {
    id: "json",
    long: Some("json"),
    short: Some('J'),
    help: "Emit byte-stable JSON instead of pointer lines",
    env: EnvDecl::None,
    global: false,
    positional: false,
    required: false,
    value: ValueDecl::Bool,
};

fn strictness_parser() -> ValueParser {
    ValueParser::new(clap::builder::EnumValueParser::<crate::config::Strictness>::new())
}

fn harness_parser() -> ValueParser {
    ValueParser::new(clap::builder::EnumValueParser::<crate::hook::Harness>::new())
}

fn spec_format_parser() -> ValueParser {
    ValueParser::new(clap::builder::EnumValueParser::<crate::cli::SpecFormat>::new())
}

fn shell_parser() -> ValueParser {
    ValueParser::new(clap::builder::EnumValueParser::<clap_complete::Shell>::new())
}

/// The root command: the program itself, carrying the global flags.
///
/// The root declares no effect of its own — a bare invocation lists the
/// subcommands and never performs a default action (§2) — so it is
/// [`Effect::Ask`], the same conservative reading an undeclared path gets.
pub const ROOT: CommandDecl = CommandDecl {
    path: "",
    about: "Repo-agnostic policy engine that keeps \"done\" aligned with landed-and-verified work.",
    effect: Effect::Ask,
    flags: &[STRICTNESS, FAIL_ON_WARNING, CONFIG_FROM],
};

/// The command tree: every subcommand, with its summary, effect, and flags.
///
/// Order is declaration order and does not matter — [`command`] groups rows by
/// path, and every derived artifact sorts. What matters is that a path appears
/// exactly once, which [`tests::every_path_is_declared_once`] pins.
pub const SURFACE: &[CommandDecl] = &[
    // `check` only inspects the tree and reports findings; it mutates nothing.
    // It refuses to run any rule kind that spawns a process
    // (`rules::run_static`), which is what keeps this `read` honest and this
    // path off the process-spawning surface.
    CommandDecl {
        path: "check",
        about: "Run the applicable read-only gates against the repository",
        effect: Effect::Read,
        flags: &[JSON],
    },
    // `enforce` runs rule kinds that execute commands declared in
    // `batten.toml`. Per §5 a command that runs user-supplied code is listed
    // unclassified with a stated reason, never guessed — so it is excluded from
    // the derived read-only allowlist by construction.
    CommandDecl {
        path: "enforce",
        about: "Run every configured rule, including kinds that execute a configured command",
        effect: Effect::Unclassified,
        flags: &[JSON],
    },
    CommandDecl {
        path: "config",
        about: "Inspect configuration",
        effect: Effect::Read,
        flags: &[],
    },
    CommandDecl {
        path: "config show",
        about: "Print the effective configuration",
        effect: Effect::Read,
        // The same per-command declaration `check` carries, not a second flag:
        // selecting an encoding reaches no user-supplied code, so it raises
        // nothing under §5 and the `read` classification stays honest.
        flags: &[JSON],
    },
    // Complements `--config-from` rather than replacing it (CLOUD-87): that
    // makes a weakening *ineffective*, this makes it *visible*.
    // The value only (CLOUD-32). Stamping it onto guard/decision records is
    // CLOUD-133's, which defines the record it would be stamped on.
    CommandDecl {
        path: "config epoch",
        about: "Print the content hash of the governing config surface",
        effect: Effect::Read,
        flags: &[],
    },
    CommandDecl {
        path: "config lint",
        about: "Report policy smells in batten.toml (any smell is a violation)",
        effect: Effect::Read,
        flags: &[],
    },
    CommandDecl {
        path: "spec",
        about: "Print the tool's own command spec",
        effect: Effect::Read,
        flags: &[FlagDecl::defaulted_enum(
            "format",
            "format",
            "The output format for the spec",
            spec_format_parser,
            "json",
        )],
    },
    // Emission is stdout-only — `generate` writes no file, so the redirect that
    // refreshes a committed artifact is the caller's (`mise run completions`),
    // never the binary's. That is what makes `read` structurally honest here
    // rather than a promise about behaviour.
    // The designated post-install self-check (§12). Diagnoses whether Batten can
    // do its job here; it never renders a policy verdict, which is why `config
    // lint` is not one of its diagnostics (CLOUD-66).
    CommandDecl {
        path: "doctor",
        about: "Diagnose whether Batten can run in this repository",
        effect: Effect::Read,
        flags: &[JSON],
    },
    CommandDecl {
        path: "generate",
        about: "Emit artifacts derived from the command spec, on stdout",
        effect: Effect::Read,
        flags: &[],
    },
    CommandDecl {
        path: "generate completions",
        about: "Emit the shell completion script for one shell",
        effect: Effect::Read,
        flags: &[FlagDecl::required_enum(
            "shell",
            "shell",
            "The shell whose completion script to emit",
            shell_parser,
        )],
    },
    // Derived from the config types themselves, never hand-authored (CLOUD-33),
    // so the schema cannot describe a `batten.toml` the binary would refuse.
    CommandDecl {
        path: "generate schema",
        about: "Emit the JSON Schema for batten.toml, derived from the config types",
        effect: Effect::Read,
        flags: &[],
    },
    // `hook` adjudicates another tool's call: its own execution only reads
    // stdin and config, but its *decision* mediates writes, so it is listed
    // unclassified rather than allowed to leak into the derived read-only
    // allowlist (CLOUD-202).
    CommandDecl {
        path: "hook",
        about: "Adjudicate a mediated tool call read from stdin (a deny is exit 2, the one contract)",
        effect: Effect::Unclassified,
        flags: &[FlagDecl::required_enum(
            "harness",
            "harness",
            "The harness whose payload to decode and whose decision channel to answer in",
            harness_parser,
        )],
    },
    // The `receipt` noun only dispatches, but its subtree carries a write verb;
    // classifying it `read` would put a write-bearing subtree onto the derived
    // allowlist for any consumer that treats entries as prefixes. Same fail-safe
    // posture as `hook`: listed with a reason, never allowed to leak
    // (CLOUD-203).
    CommandDecl {
        path: "receipt",
        about: "Verification receipts: SHA-keyed claims a named check passed, invalidated by git facts",
        effect: Effect::Unclassified,
        flags: &[],
    },
    // Creates state the caller can recreate by re-running the check.
    CommandDecl {
        path: "receipt record",
        about: "Record that the named check concluded pass against the current HEAD",
        effect: Effect::Write,
        flags: &[FlagDecl::positional(
            "check",
            "The check whose conclusion is being recorded",
        )],
    },
    // Inspection only: fixed read-only git queries (`rev-parse`) plus a
    // state-dir read. A `read` verb may run a fixed VCS query; what it must
    // never reach is user-supplied code (CLOUD-170's invariant), and no
    // configured command is reachable from this path.
    CommandDecl {
        path: "receipt status",
        about: "Judge the named check's recorded receipt against HEAD and origin/main",
        effect: Effect::Read,
        flags: &[FlagDecl::positional(
            "check",
            "The check whose receipt is judged",
        )],
    },
];

/// Resolve the declared effect for a full command path.
///
/// A path absent from [`SURFACE`] resolves to [`Effect::Ask`] — the conservative
/// reading required by §5 — never silently to [`Effect::Read`].
#[must_use]
pub fn effect_for(path: &str) -> Effect {
    SURFACE
        .iter()
        .find(|decl| decl.path == path)
        .map_or(Effect::Ask, |decl| decl.effect)
}

/// The parent path of a command path: `"config show"` → `"config"`, and a
/// top-level verb → `""` (the root).
fn parent_of(path: &str) -> &str {
    path.rsplit_once(' ').map_or("", |(parent, _)| parent)
}

/// The trailing segment of a command path, which is the name `clap` knows it by.
fn leaf_of(path: &str) -> &str {
    path.rsplit_once(' ').map_or(path, |(_, leaf)| leaf)
}

/// Build one [`clap::Arg`] from its declaration.
fn arg_of(decl: &FlagDecl) -> Arg {
    let mut arg = Arg::new(decl.id).help(decl.help);
    if decl.positional {
        arg = arg.required(decl.required);
    } else {
        if let Some(long) = decl.long {
            arg = arg.long(long);
        }
        if let Some(short) = decl.short {
            arg = arg.short(short);
        }
        // A global arg may not also be required; the declarations honour that
        // and `tests::a_global_flag_is_never_required` holds it shut.
        arg = arg.global(decl.global).required(decl.required);
        // Only a `Clap` env is applied here; a `Layered` one must reach the
        // resolver as its own layer instead.
        if let EnvDecl::Clap(name) = decl.env {
            arg = arg.env(name);
        }
    }
    match decl.value {
        ValueDecl::Bool => arg.action(ArgAction::SetTrue),
        ValueDecl::Str => arg.action(ArgAction::Set),
        ValueDecl::Enum { parser, default } => {
            let arg = arg.action(ArgAction::Set).value_parser(parser());
            match default {
                Some(value) => arg.default_value(value),
                None => arg,
            }
        }
    }
}

/// Whether any row declares `path` as its parent — i.e. `path` is a noun that
/// dispatches rather than a verb that acts.
fn has_children(path: &str) -> bool {
    SURFACE.iter().any(|decl| parent_of(decl.path) == path)
}

/// Attach every direct child of `prefix` to `parent`, recursively.
fn attach(parent: Command, prefix: &str) -> Command {
    SURFACE
        .iter()
        .filter(|decl| parent_of(decl.path) == prefix)
        .fold(parent, |parent, decl| {
            let sub = Command::new(leaf_of(decl.path)).about(decl.about);
            let sub = decl
                .flags
                .iter()
                .fold(sub, |sub, flag| sub.arg(arg_of(flag)));
            let sub = attach(sub, decl.path);
            // A noun performs no default action: it lists its sub-verbs (§2).
            let sub = if has_children(decl.path) {
                sub.subcommand_required(true).arg_required_else_help(true)
            } else {
                sub
            };
            parent.subcommand(sub)
        })
}

/// The live [`clap::Command`] tree, built from [`ROOT`] and [`SURFACE`].
///
/// This is the only place a `clap` command is constructed: the parser, the
/// emitted spec, and the generated completions all read this one tree, so none
/// of them can disagree with the declaration.
#[must_use]
pub fn command() -> Command {
    // arg_required_else_help: a bare invocation lists the subcommands and never
    // performs a default action (§2). clap renders the listing on its error path
    // (stderr, exit 1), so stdout stays the answer channel.
    let root = Command::new("batten")
        .version(env!("CARGO_PKG_VERSION"))
        .about(ROOT.about)
        // The §7 table, rendered from `ExitCode`'s own variants rather than
        // re-typed here, so `--help` and the binary can never disagree about
        // what a code means (CLOUD-66).
        .after_help(format!("Exit codes:\n{}", crate::exit::table()))
        .arg_required_else_help(true);
    let root = ROOT
        .flags
        .iter()
        .fold(root, |root, flag| root.arg(arg_of(flag)));
    attach(root, "")
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn every_path_is_declared_once() {
        // A duplicated path would give `effect_for` a silent winner and `command`
        // two subcommands of the same name — both invisible without this.
        let mut seen: Vec<&str> = SURFACE.iter().map(|decl| decl.path).collect();
        let total = seen.len();
        seen.sort_unstable();
        seen.dedup();
        assert_eq!(seen.len(), total, "a command path is declared twice");
    }

    #[test]
    fn every_declared_parent_is_itself_declared() {
        // `config show` without a `config` row would build a subcommand tree
        // whose intermediate node carries no effect and no summary.
        for decl in SURFACE {
            let parent = parent_of(decl.path);
            assert!(
                parent.is_empty() || SURFACE.iter().any(|other| other.path == parent),
                "{} has no declared parent {parent:?}",
                decl.path
            );
        }
    }

    #[test]
    fn unknown_path_is_ask_never_read() {
        // The load-bearing fail-safe: an unclassified path must not be read-only.
        let effect = effect_for("some-command-not-in-the-surface");
        assert_eq!(effect, Effect::Ask);
        assert!(!effect.is_read_only());
    }

    #[test]
    fn known_path_resolves_to_its_declared_effect() {
        assert_eq!(effect_for("spec"), Effect::Read);
        assert_eq!(effect_for("receipt record"), Effect::Write);
    }

    #[test]
    fn a_global_flag_is_never_required() {
        // clap panics when an arg is both; the declaration is the place to catch
        // it, since `command()` is called on every single invocation.
        for decl in std::iter::once(&ROOT).chain(SURFACE) {
            for flag in decl.flags {
                assert!(
                    !(flag.global && flag.required),
                    "{}: --{} is both global and required",
                    decl.path,
                    flag.id
                );
            }
        }
    }

    #[test]
    fn every_flag_id_is_snake_case() {
        // An id is not an internal detail: `spec.rs` emits it as the flag's
        // `name`, so a consumer of `batten spec` matches on it. Mixing
        // `fail-on-warning` and `fail_on_warning` across rows would make that
        // contract depend on how each row happened to be typed — which is
        // exactly the drift this one-declaration design exists to remove. The
        // long form stays kebab-case; only the id is pinned here.
        for decl in std::iter::once(&ROOT).chain(SURFACE) {
            for flag in decl.flags {
                assert!(
                    !flag.id.contains('-'),
                    "{}: flag id {:?} is kebab-case; ids are snake_case because \
                     they are the emitted spec's `name`",
                    decl.path,
                    flag.id
                );
            }
        }
    }

    #[test]
    fn every_declared_env_is_actually_read() {
        // A declared-but-unread env var is the drift this design exists to
        // remove: it documents an override that silently does nothing, and the
        // only symptom is a user whose `BATTEN_*` export is ignored. Measured
        // on `--config-from`, which declared `BATTEN_CONFIG_FROM` and read it
        // nowhere until an E2E test caught it (CLOUD-31).
        //
        // `EnvDecl` makes "declared and read by nobody" unrepresentable for the
        // clap half; this covers the other half — a `Layered` name the resolver
        // does not actually have a row for.
        for decl in std::iter::once(&ROOT).chain(SURFACE) {
            for flag in decl.flags {
                let EnvDecl::Layered(env) = flag.env else {
                    continue;
                };
                assert!(
                    crate::resolve::SETTINGS
                        .iter()
                        .any(|setting| setting.env == Some(env)),
                    "{}: {env} is declared Layered but no SETTINGS row reads it",
                    decl.path
                );
            }
        }
    }

    #[test]
    fn the_built_tree_matches_the_declaration() {
        // The derivation gate: every declared path exists in the built `clap`
        // tree with the declared summary, and the tree contains nothing the
        // declaration does not name.
        let root = command();
        let mut built = Vec::new();
        collect(&root, "", &mut built);
        built.sort_unstable();
        let mut declared: Vec<String> = SURFACE.iter().map(|decl| decl.path.to_owned()).collect();
        declared.sort_unstable();
        assert_eq!(built, declared);

        for decl in SURFACE {
            let about = about_of(&root, decl.path).expect("declared path is in the tree");
            assert_eq!(about, decl.about, "{} summary drifted", decl.path);
        }
    }

    fn collect(command: &Command, prefix: &str, out: &mut Vec<String>) {
        for sub in command.get_subcommands() {
            let path = if prefix.is_empty() {
                sub.get_name().to_owned()
            } else {
                format!("{prefix} {}", sub.get_name())
            };
            collect(sub, &path, out);
            out.push(path);
        }
    }

    fn about_of(command: &Command, path: &str) -> Option<String> {
        let mut current = command;
        for segment in path.split(' ') {
            current = current.find_subcommand(segment)?;
        }
        current.get_about().map(ToString::to_string)
    }

    #[test]
    fn clap_accepts_the_built_tree() {
        // `debug_assert` walks the whole tree and panics on a malformed arg —
        // the cheapest total check that a new declaration is constructible.
        command().debug_assert();
    }
}
