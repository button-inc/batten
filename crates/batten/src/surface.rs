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
use crate::output::Verbosity;

/// How an argument takes its value.
#[derive(Debug)]
#[non_exhaustive]
pub enum ValueDecl {
    /// A boolean flag: present or absent, consuming nothing.
    Bool,
    /// A repeatable boolean flag, whose occurrences are counted.
    ///
    /// Deliberately not [`ValueDecl::Bool`]: `ArgAction::SetTrue` errors on a
    /// *second* occurrence, so `-vv` would be a usage error rather than the
    /// next rung up the §3 ladder.
    Count,
    /// Consumes a free-form string.
    Str,
    /// Consumes every remaining token, verbatim — a trailing variadic.
    ///
    /// For a passthrough (`batten exec -- <cmd> <args>...`), where the tail is
    /// another program's argv and not Batten's to interpret. `allow_hyphen_values`
    /// is load-bearing rather than defensive: without it a child's own `-v` parses
    /// as Batten's verbosity rung, which the §3 ladder makes an active hazard.
    Trailing,
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
    /// [`crate::output`] reads the variable when resolving the output mode.
    ///
    /// For a §3/§4 presentation flag. Neither of the other two fits:
    /// `Clap` cannot, because `ArgAction::SetTrue`'s value parser accepts
    /// exactly `"true"`/`"false"` — so `BATTEN_NO_COLOR=1`, or an empty
    /// `BATTEN_NO_COLOR=`, would be a *usage error* instead of the empty-means-
    /// unset reading every other layer uses. `Layered` cannot, because
    /// [`crate::resolve::SETTINGS`] is policy-bearing and clamped raise-only,
    /// and verbosity has no weakening ordering to clamp along: `--quiet` does
    /// not lower a gate, it lowers a word count.
    Presentation(&'static str),
}

impl EnvDecl {
    /// The variable's name, whoever reads it.
    #[must_use]
    pub const fn name(&self) -> Option<&'static str> {
        match self {
            EnvDecl::None => None,
            EnvDecl::Clap(name) | EnvDecl::Layered(name) | EnvDecl::Presentation(name) => {
                Some(*name)
            }
        }
    }
}

/// Which rung of the §3 verbosity ladder a flag selects, if any.
///
/// A column rather than a naming convention, so the ladder can be *audited*:
/// [`tests::the_ladder_declares_every_rung_but_normal_exactly_once`] reads it and
/// fails if a rung is declared twice or goes missing, and
/// [`tests::a_ladder_rung_declares_no_boolean_env_equivalent`] reads it to hold
/// the one-variable rule shut. Without it "is this a ladder flag" would be a
/// question answered by looking at the long name.
#[derive(Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Rung {
    /// Not a ladder flag.
    None,
    /// Selects one fixed rung; repeating it steps one further from `normal`.
    Fixed(Verbosity),
    /// Names a rung by token (`--log-level trace`) rather than selecting one.
    Named,
}

/// One argument of one command, declared as data.
// Four booleans, and deliberately four: this is a declaration *table*, and each
// column is an independent axis of one argument — where it applies (`global`),
// how it is written (`positional`), whether it may be omitted (`required`), and
// whether `--help` lists it (`hidden`). Collapsing them into two-variant enums
// would make every row read as four type names instead of four answers, which is
// the opposite of the reviewability §11 declares the table for.
#[allow(clippy::struct_excessive_bools)]
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
    /// Whether `--help` omits the flag.
    ///
    /// For the diagnostic tiers: `--debug` and `--trace` are real, supported
    /// flags, but listing all five rungs in every `--help` buries the two a
    /// caller actually reaches for (§3). Hidden is not undeclared — the flag is
    /// still in the emitted spec and still in the completions.
    pub hidden: bool,
    /// Which §3 ladder rung the flag selects, if any.
    pub rung: Rung,
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
            hidden: false,
            rung: Rung::None,
            value: ValueDecl::Str,
        }
    }

    /// A positional argument the command runs without.
    ///
    /// Distinct from [`FlagDecl::positional`] in exactly one column, which is
    /// why it is a second constructor rather than a boolean at every call site:
    /// an optional positional is how a verb offers a *deliberate* override of an
    /// answer it can otherwise work out for itself.
    const fn positional_optional(id: &'static str, help: &'static str) -> Self {
        FlagDecl {
            required: false,
            ..FlagDecl::positional(id, help)
        }
    }

    /// A required trailing variadic: every remaining token, verbatim.
    const fn trailing(id: &'static str, help: &'static str) -> Self {
        FlagDecl {
            id,
            long: None,
            short: None,
            help,
            env: EnvDecl::None,
            global: false,
            positional: true,
            required: true,
            hidden: false,
            rung: Rung::None,
            value: ValueDecl::Trailing,
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
            hidden: false,
            rung: Rung::None,
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
            hidden: false,
            rung: Rung::None,
            value: ValueDecl::Enum {
                parser,
                default: Some(default),
            },
        }
    }

    /// A global counted ladder flag (§3).
    const fn ladder(
        id: &'static str,
        long: &'static str,
        short: Option<char>,
        help: &'static str,
        rung: Verbosity,
        hidden: bool,
    ) -> Self {
        FlagDecl {
            id,
            long: Some(long),
            short,
            help,
            // Only the level-naming variable carries an env equivalent; see
            // `crate::output::LOG_LEVEL_ENV` for why five booleans would not.
            env: EnvDecl::None,
            global: true,
            positional: false,
            required: false,
            hidden,
            rung: Rung::Fixed(rung),
            value: ValueDecl::Count,
        }
    }

    /// A global presentation boolean with its own env equivalent (§4).
    const fn presentation(
        id: &'static str,
        long: &'static str,
        help: &'static str,
        env: &'static str,
    ) -> Self {
        FlagDecl {
            id,
            long: Some(long),
            short: None,
            help,
            env: EnvDecl::Presentation(env),
            global: true,
            positional: false,
            required: false,
            hidden: false,
            rung: Rung::None,
            value: ValueDecl::Bool,
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
    /// Whether the command emits a data document through the `-J` switch (§6).
    ///
    /// A separate declaration from the flag list on purpose: without it,
    /// "every data-emitting verb declares `-J`" would be a hand-kept list in a
    /// test — the exact thing this table exists to eliminate. Declaring the
    /// *intent* here means a row that forgets the flag fails
    /// [`tests::every_data_emitting_verb_declares_the_json_flag`], and a row that
    /// carries the flag without declaring the intent fails it too.
    ///
    /// `spec` is deliberately `false`: it emits data, but its switch is
    /// `--format`, which selects an encoding rather than toggling a channel.
    /// `generate schema` and `generate completions` are `false` because their
    /// only output *is* the artifact — there is no human rendering to switch away
    /// from.
    pub data_channel: bool,
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
    hidden: false,
    rung: Rung::None,
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
    hidden: false,
    rung: Rung::None,
    value: ValueDecl::Bool,
};

/// `--config-from <ref>`, the config trust boundary (CLOUD-31).
///
/// Reads the committed authority from a git ref instead of the working tree, so
/// a branch that edits `batten.toml` cannot lower the bar it is judged by.
/// Global because it selects *which* config the whole run resolves from —
/// scoping it per verb would let one verb be judged by the base and another by
/// the working tree in the same invocation.
/// `--host-rules <path|->` on `config lint` (CLOUD-54).
///
/// Data in, verdict out. The payload is the host ruleset the caller already
/// fetched, so the gate stays pure, credential-free and byte-stable — a gate that
/// could fail because a token expired is not a gate.
const HOST_RULES: FlagDecl = FlagDecl {
    id: "host_rules",
    long: Some("host-rules"),
    short: None,
    help: "Compare the committed [ci] table against a host ruleset payload (path, or - for stdin)",
    env: EnvDecl::None,
    global: false,
    positional: false,
    required: false,
    hidden: false,
    rung: Rung::None,
    value: ValueDecl::Str,
};

const CONFIG_FROM: FlagDecl = FlagDecl {
    id: "config_from",
    long: Some("config-from"),
    short: None,
    help: "Read the committed config from a git ref (e.g. origin/main) instead of the working tree",
    env: EnvDecl::Clap("BATTEN_CONFIG_FROM"),
    global: true,
    positional: false,
    required: false,
    hidden: false,
    rung: Rung::None,
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
    hidden: false,
    rung: Rung::None,
    value: ValueDecl::Bool,
};

/// `--no-cache` on `config epoch` (CLOUD-232).
///
/// The escape from the stat-based revalidation, and the reference oracle the
/// cache is tested against: a hit must equal what this prints, byte for byte.
/// Without it the equality could only be asserted by reading the code, and a
/// cache whose correctness is an argument rather than a test is not one.
///
/// It buys no policy — the epoch is identical either way — so it raises nothing
/// under §5 and `config epoch` stays `read`.
const NO_CACHE: FlagDecl = FlagDecl {
    id: "no_cache",
    long: Some("no-cache"),
    short: None,
    help: "Recompute the epoch from the tracked files' bytes, ignoring the cached value",
    env: EnvDecl::None,
    global: false,
    positional: false,
    required: false,
    hidden: false,
    rung: Rung::None,
    value: ValueDecl::Bool,
};

/// `--class <token>`: narrow a defect query to one taxonomy class.
const CLASS: FlagDecl = FlagDecl {
    id: "class",
    long: Some("class"),
    short: None,
    help: "Only records in this taxonomy class",
    env: EnvDecl::None,
    global: false,
    positional: false,
    required: false,
    hidden: false,
    rung: Rung::None,
    value: ValueDecl::Str,
};

/// `--id <token>`: narrow a defect query to one record.
const RECORD_ID: FlagDecl = FlagDecl {
    id: "id",
    long: Some("id"),
    short: None,
    help: "Only the record with this id",
    env: EnvDecl::None,
    global: false,
    positional: false,
    required: false,
    hidden: false,
    rung: Rung::None,
    value: ValueDecl::Str,
};

/// `--ungated`: the lessons still carried by prose alone.
///
/// The filter worth having: rule 2 says a rule without a runnable gate is half a
/// change, and this enumerates exactly the rows that are still that half.
const UNGATED: FlagDecl = FlagDecl {
    id: "ungated",
    long: Some("ungated"),
    short: None,
    help: "Only records no rule or gate discharges yet",
    env: EnvDecl::None,
    global: false,
    positional: false,
    required: false,
    hidden: false,
    rung: Rung::None,
    value: ValueDecl::Bool,
};

/// `-n --dry-run`: preview the change and write nothing.
///
/// Per-command rather than global (§3), because a preview is only meaningful for
/// a verb that writes. It changes *behaviour*, never the declared effect — §5's
/// raise-only rule is explicit that a bug in a dry-run path must not be able to
/// claim safety the verb does not have, so `provision apply` stays `write` with
/// or without it.
const DRY_RUN: FlagDecl = FlagDecl {
    id: "dry_run",
    long: Some("dry-run"),
    short: Some('n'),
    help: "Preview what would be applied, writing nothing",
    env: EnvDecl::None,
    global: false,
    positional: false,
    required: false,
    hidden: false,
    rung: Rung::None,
    value: ValueDecl::Bool,
};

fn verbosity_parser() -> ValueParser {
    ValueParser::new(clap::builder::EnumValueParser::<Verbosity>::new())
}

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
    // A bare invocation performs no default action, so there is no answer to
    // encode and `-J` would be a flag that looks applied and isn't.
    data_channel: false,
    flags: ROOT_FLAGS,
};

/// [`ROOT`]'s arguments: the config overrides, then the §3 verbosity ladder and
/// the §4 presentation booleans (CLOUD-42).
///
/// Every one is **global**, because verbosity and attendedness are properties of
/// the *invocation*, not of one verb: scoping them would let one verb in a
/// pipeline be quiet and the next not.
///
/// The rungs are **counted** rather than boolean so `-vv` is the next rung up
/// rather than a usage error, and deliberately **not** an `ArgGroup` or a
/// `conflicts_with` pair — both of those make `-q -v` an *error*, which is
/// exactly the shape §3's last-flag-wins rule exists to resolve. Which rung wins
/// is resolved from raw argument order by [`crate::output`]; see that module for
/// why `clap`'s recorded indices cannot supply it.
const ROOT_FLAGS: &[FlagDecl] = &[
    STRICTNESS,
    FAIL_ON_WARNING,
    CONFIG_FROM,
    FlagDecl::ladder(
        "silent",
        "silent",
        None,
        "Say nothing but a verdict or a usage error",
        Verbosity::Silent,
        false,
    ),
    FlagDecl::ladder(
        "quiet",
        "quiet",
        Some('q'),
        "Suppress ordinary progress (repeatable: -qq is silent)",
        Verbosity::Quiet,
        false,
    ),
    FlagDecl::ladder(
        "verbose",
        "verbose",
        Some('v'),
        "Explain what is being checked (repeatable: -vv is debug)",
        Verbosity::Verbose,
        false,
    ),
    // Hidden: real and supported, but listing five rungs in every `--help`
    // buries the two a caller reaches for.
    FlagDecl::ladder(
        "debug",
        "debug",
        None,
        "Add resolution detail",
        Verbosity::Debug,
        true,
    ),
    FlagDecl::ladder(
        "trace",
        "trace",
        None,
        "Add everything",
        Verbosity::Trace,
        true,
    ),
    // The one env-bearing rung, and the only flag that names a rung rather than
    // selecting one. Hidden because the ladder above is the human surface.
    FlagDecl {
        id: "log_level",
        long: Some("log-level"),
        short: None,
        help: "Set the verbosity rung by name",
        env: EnvDecl::Presentation(crate::output::LOG_LEVEL_ENV),
        global: true,
        positional: false,
        required: false,
        hidden: true,
        rung: Rung::Named,
        value: ValueDecl::Enum {
            parser: verbosity_parser,
            default: None,
        },
    },
    FlagDecl::presentation(
        "no_color",
        "no-color",
        "Never colour stderr, whatever it is attached to",
        crate::output::NO_COLOR_ENV,
    ),
    FlagDecl::presentation(
        "no_input",
        "no-input",
        "Never prompt; treat the run as unattended",
        crate::output::NO_INPUT_ENV,
    ),
];

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
        data_channel: true,
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
        data_channel: true,
        effect: Effect::Unclassified,
        flags: &[JSON],
    },
    // `exec` runs a command the caller names, so it is the second process-spawning
    // verb after `enforce` and takes the same conservative reading. It is a
    // TRANSPARENT verb: the child's streams are inherited and the child's exit
    // code is returned unchanged, which makes it the one place a code outside the
    // §7 table can appear — see `crate::exit`'s note. Batten still never invents a
    // `2` here, which is the property fail-open actually depends on.
    CommandDecl {
        path: "exec",
        about: "Run a command, passing its streams and its exit code through unchanged",
        // The child owns stdout, so Batten must not interleave a document of its
        // own with the child's bytes. The pointer surface over captured output is
        // CLOUD-162's, on stderr.
        data_channel: false,
        effect: Effect::Unclassified,
        flags: &[FlagDecl::trailing(
            "command",
            "The command to run, after `--`, with its own arguments intact",
        )],
    },
    CommandDecl {
        path: "config",
        about: "Inspect configuration",
        data_channel: false,
        effect: Effect::Read,
        flags: &[],
    },
    CommandDecl {
        path: "config show",
        about: "Print the effective configuration",
        data_channel: true,
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
        data_channel: true,
        effect: Effect::Read,
        // The value alone is already machine-readable, so `-J` is not a second
        // rendering of it: it names *which surface* the hash covers, which a
        // caller stamping a record needs and a bare digest cannot carry.
        flags: &[JSON, NO_CACHE],
    },
    CommandDecl {
        path: "config lint",
        about: "Report policy smells in batten.toml (any smell is a violation)",
        data_channel: true,
        // Still `read` with `--host-rules`: the flag names a file or `-` the
        // CALLER supplies. Agents fetch, gates decide — nothing here reaches the
        // network, so the verb stays on the derived read-only allowlist.
        effect: Effect::Read,
        flags: &[JSON, HOST_RULES],
    },
    CommandDecl {
        path: "spec",
        about: "Print the tool's own command spec",
        // Emits data, but through `--format`: an encoding selector, not a
        // channel toggle. `tests::spec_switches_format_rather_than_declaring_json`
        // pins the distinction so a future row cannot acquire both.
        data_channel: false,
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
    // rather than a promise about behaviour. House-style §2 read `(write)`;
    // settled against the implementation and corrected in the document, with
    // `spec::tests::the_stdout_only_emitter_stays_read` holding the decision
    // (CLOUD-244).
    // The designated post-install self-check (§12). Diagnoses whether Batten can
    // do its job here; it never renders a policy verdict, which is why `config
    // lint` is not one of its diagnostics (CLOUD-66).
    CommandDecl {
        path: "doctor",
        about: "Diagnose whether Batten can run in this repository",
        data_channel: true,
        effect: Effect::Read,
        flags: &[JSON],
    },
    CommandDecl {
        path: "generate",
        about: "Emit artifacts derived from the command spec, on stdout",
        data_channel: false,
        effect: Effect::Read,
        flags: &[],
    },
    CommandDecl {
        path: "generate completions",
        about: "Emit the shell completion script for one shell",
        // The artifact *is* the output; there is no human rendering to switch
        // away from, and a shell script is not JSON.
        data_channel: false,
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
        data_channel: false,
        effect: Effect::Read,
        flags: &[],
    },
    // The `policy` noun only dispatches, and unlike `receipt` it is declared
    // `read`: every verb in its house-style §2 subtree — scope, protect,
    // budget — is read, so there is no write for the noun row to smuggle onto
    // the derived allowlist. Stated rather than assumed, because §5 forbids
    // inheritance in both directions: this row is a claim about the whole
    // subtree, and the day a mutating verb joins it, this row changes with it.
    CommandDecl {
        path: "policy",
        about: "Inspect the thresholds and path sets this repository holds itself to",
        data_channel: false,
        effect: Effect::Read,
        flags: &[],
    },
    // File reads over the configured set and arithmetic over what they contain.
    // Nothing is spawned and no user-supplied code is reachable, which is what
    // the `read` structural promise requires (CLOUD-50).
    CommandDecl {
        path: "policy budget",
        about: "Judge the always-loaded instruction set against its declared token budget",
        data_channel: true,
        effect: Effect::Read,
        flags: &[JSON],
    },
    // The `worktree` noun only dispatches, and unlike `policy` it cannot be
    // `read`: its house-style §2 subtree (new, adopt, prune, reclaim) is
    // write-bearing, and a `read` noun over a mutating subtree would leak onto
    // the derived allowlist for any consumer that treats an entry as a prefix.
    // Same fail-safe posture as `receipt`: listed with its reason, never guessed
    // (CLOUD-51). The mutating verbs themselves are other work and absent here.
    CommandDecl {
        path: "worktree",
        about: "Worktrees and the work in them: what is at risk, and the hygiene verbs over them",
        data_channel: false,
        effect: Effect::Unclassified,
        flags: &[],
    },
    // Fixed, read-only VCS queries plus arithmetic over their output. A `read`
    // verb may run a fixed git query — `receipt status` already does — and what
    // it must never reach is user-supplied code, which no path here does.
    CommandDecl {
        path: "worktree status",
        about: "Report work that is uncommitted, unpushed, or not landed on the configured target",
        data_channel: true,
        effect: Effect::Read,
        flags: &[JSON],
    },
    // The `provision` noun only dispatches, and its subtree carries a write
    // verb, so it takes `receipt`'s conservative reading rather than `policy`'s:
    // a write-bearing subtree under a `read` noun would leak onto the derived
    // allowlist for any consumer that treats an entry as a prefix (CLOUD-90).
    CommandDecl {
        path: "provision",
        about: "Pinned tools this repository provisions, cached out of tree",
        data_channel: false,
        effect: Effect::Unclassified,
        flags: &[],
    },
    // The freshness half of §9's check/fix pair, and `read` for a structural
    // reason rather than a behavioural one: the whole equality test is a
    // checksum over cached bytes, so **the provisioned binary is never
    // executed**. A freshness check that ran `--version` would be a `read` verb
    // executing an artifact fetched from the internet.
    CommandDecl {
        path: "provision status",
        about: "Report which provisioned tools do not match the manifest",
        data_channel: true,
        effect: Effect::Read,
        flags: &[JSON],
    },
    // The fix half. `write` rather than `destructive`: everything it creates is
    // recreatable by running it again, and it replaces nothing the caller
    // authored — the cache is out of tree and Batten's own.
    CommandDecl {
        path: "provision apply",
        about: "Fetch, verify against the pinned checksum, and install into the out-of-tree cache",
        data_channel: false,
        effect: Effect::Write,
        flags: &[DRY_RUN],
    },
    // `hook` adjudicates another tool's call: its own execution only reads
    // stdin and config, but its *decision* mediates writes, so it is listed
    // unclassified rather than allowed to leak into the derived read-only
    // allowlist (CLOUD-202). Re-examined when CLOUD-48 made the policy config:
    // `hook` still reaches no user-supplied code — `RuleKind::scopes` pairs every
    // spawning kind with `RuleScope::Tree` alone, and `Policy::from_resolved`
    // filters on scope, which `rules::tests::no_mediated_call_kind_spawns_a_process`
    // pins. So `read` would now be *defensible*; it stays `Unclassified` because
    // the classification is load-bearing in one place only — the derived
    // allowlist — and putting a deny-issuing mediator on the agent's read-only
    // list buys nothing an agent needs. §5's rule is that an unclassified command
    // is listed with a stated reason rather than guessed; this is that reason.
    CommandDecl {
        path: "hook",
        about: "Adjudicate a mediated tool call read from stdin (a deny is exit 2, the one contract)",
        // Excluded deliberately: `hook`'s stdout is already a harness-shaped
        // decision document that the host parses. A second JSON shape on the
        // same stream, selected by a flag the host does not pass, could only
        // ever be an ambiguity — and it would break the per-harness decision
        // channel CLOUD-40 pinned.
        data_channel: false,
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
        data_channel: false,
        effect: Effect::Unclassified,
        flags: &[],
    },
    // Creates state the caller can recreate by re-running the check.
    CommandDecl {
        path: "receipt record",
        about: "Record that the named check concluded pass against the current HEAD",
        // Records state and reports nothing; there is no document to emit.
        data_channel: false,
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
        data_channel: true,
        effect: Effect::Read,
        flags: &[
            FlagDecl::positional("check", "The check whose receipt is judged"),
            JSON,
        ],
    },
    // The noun only dispatches; its subtree carries a write verb, so the parent
    // stays unclassified rather than advertising a write-bearing `read` prefix
    // on the derived allowlist (CLOUD-170) — the posture `receipt` and `state`
    // already take.
    CommandDecl {
        path: "defects",
        about: "The append-only defect ledger: the lessons this repository has already paid for",
        data_channel: false,
        effect: Effect::Unclassified,
        flags: &[],
    },
    // Inspection only: reads the committed ledger and reports pointers. Joins
    // the derived read-only allowlist.
    CommandDecl {
        path: "defects query",
        about: "List recorded defects, as pointers",
        data_channel: true,
        effect: Effect::Read,
        flags: &[JSON, CLASS, RECORD_ID, UNGATED],
    },
    // Appends to a committed file. `write`, not `destructive`: it adds rows and
    // removes none — the append-only gate makes removal impossible by
    // construction — and `-n` previews without touching the tree.
    CommandDecl {
        path: "defects add",
        about: "Append defect records read as JSONL on stdin",
        // Reports counts on stderr under -n; there is no document to emit.
        data_channel: false,
        effect: Effect::Write,
        flags: &[DRY_RUN],
    },
    // The noun only dispatches, and it takes the same posture `receipt` does:
    // its subtree carries a write verb, so classifying the parent `read` would
    // advertise a write-bearing prefix on the derived allowlist (CLOUD-170).
    CommandDecl {
        path: "state",
        about: "The out-of-tree findings store: which store belongs to this checkout",
        data_channel: false,
        effect: Effect::Unclassified,
        flags: &[],
    },
    // Re-binds recorded key material to the minted store id. `write`, not
    // `destructive`: it creates state the caller can recreate by re-running it,
    // and it removes nothing — the store it binds is the one that already
    // existed.
    CommandDecl {
        path: "state adopt",
        about: "Bind this checkout to its findings store, minting one only if none exists",
        // Reports what it bound on stderr; there is no document to emit.
        data_channel: false,
        effect: Effect::Write,
        flags: &[FlagDecl::positional_optional(
            "store",
            "The store id to bind, when resolution cannot decide for itself",
        )],
    },
    // Folds a scan into the store as the current ref's instances. A writer, and
    // deliberately its own verb rather than a flag on `check`: a `--record` there
    // would flip `check` from `read` to `write` and drop it out of the derived
    // agent allowlist, for a side effect nobody asked that invocation for.
    CommandDecl {
        path: "state record",
        about: "Record this ref's findings into the store, and GC instances whose ref is gone",
        data_channel: false,
        effect: Effect::Write,
        flags: &[],
    },
    // Rewrites every record into the current version. `write`, not
    // `destructive`: it upgrades records in place and removes none. Its own verb
    // rather than an implicit upgrade on a read path — a `check` that silently
    // rewrote the store would break an older binary reading it from a sibling
    // worktree (CLOUD-78's no-implicit-upgrade rule).
    CommandDecl {
        path: "state migrate",
        about: "Upgrade the findings store to this binary's record version",
        // Reports counts on stderr; there is no document to emit.
        data_channel: false,
        effect: Effect::Write,
        flags: &[],
    },
    // Store reads plus fixed read-only git plumbing. A `read` verb may run a
    // fixed VCS query; what it must never reach is user-supplied code, and no
    // configured command is reachable from this path (CLOUD-170).
    CommandDecl {
        path: "state list",
        about: "List stored findings and the refs they were observed in",
        data_channel: true,
        effect: Effect::Read,
        flags: &[JSON],
    },
];

/// Whether `token` is a declared spelling of a flag that consumes the *next*
/// argument.
///
/// Derived from the declaration, so [`crate::output`]'s raw-argv scan cannot
/// mistake a flag's value for a ladder flag, and a new value-taking flag needs no
/// second list to be added to. Positionals are excluded: they consume nothing
/// that follows them.
#[must_use]
pub fn consumes_a_value(token: &str) -> bool {
    std::iter::once(&ROOT)
        .chain(SURFACE)
        .flat_map(|decl| decl.flags)
        .filter(|flag| !flag.positional)
        // `Trailing` consumes the whole tail rather than one token, and it is a
        // positional besides, so the argv scan has nothing to skip for it.
        .filter(|flag| {
            !matches!(
                flag.value,
                ValueDecl::Bool | ValueDecl::Count | ValueDecl::Trailing
            )
        })
        .any(|flag| {
            flag.long.is_some_and(|long| token == format!("--{long}"))
                || flag.short.is_some_and(|short| token == format!("-{short}"))
        })
}

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
        // Hidden is a `--help` property only: the flag still parses, still
        // appears in `batten spec`, and still reaches the completions.
        arg = arg.hide(decl.hidden);
    }
    match decl.value {
        ValueDecl::Bool => arg.action(ArgAction::SetTrue),
        // `Count` rather than `SetTrue` so a second occurrence is the next rung
        // rather than a usage error.
        ValueDecl::Count => arg.action(ArgAction::Count),
        // The tail belongs to another program, so clap must stop parsing once it
        // starts: `trailing_var_arg` takes every remaining token as a value and
        // `allow_hyphen_values` keeps a child's own flags out of Batten's parser.
        //
        // `last(true)` rather than `trailing_var_arg(true)` — clap refuses to
        // combine the two, and `last` is the one that makes `--` MANDATORY. That
        // matters beyond taste: [`crate::output`] reads the §3 ladder from raw
        // argv, and without a guaranteed separator it cannot tell a child's `-v`
        // from Batten's. Measured before this was pinned down: `batten exec cargo
        // test -v` raised Batten's own verbosity. A required `--` makes the
        // boundary unambiguous for both parsers.
        ValueDecl::Trailing => arg
            .action(ArgAction::Append)
            .num_args(1..)
            .last(true)
            .allow_hyphen_values(true),
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

    // -- The §3/§4 ladder census (CLOUD-42). --

    /// Every declared ladder flag, root and verbs alike.
    fn rungs() -> Vec<&'static FlagDecl> {
        std::iter::once(&ROOT)
            .chain(SURFACE)
            .flat_map(|decl| decl.flags)
            .filter(|flag| flag.rung != Rung::None)
            .collect()
    }

    #[test]
    fn every_ladder_rung_is_global_and_counted() {
        // A per-verb rung would let one verb in a pipeline be quiet and the next
        // not; a `Bool` one would make `-vv` a usage error instead of `debug`.
        for flag in rungs() {
            assert!(flag.global, "--{} is a rung but not global", flag.id);
            let counted =
                matches!(flag.value, ValueDecl::Count) || matches!(flag.rung, Rung::Named);
            assert!(counted, "--{} is a fixed rung but not counted", flag.id);
        }
    }

    #[test]
    fn the_ladder_declares_every_rung_but_normal_exactly_once() {
        // The census that keeps the ladder total. `normal` is the origin and is
        // deliberately unselectable: a flag for it would mean "step zero rungs",
        // which is the absence of a flag.
        let mut declared: Vec<Verbosity> = rungs()
            .iter()
            .filter_map(|flag| match flag.rung {
                Rung::Fixed(rung) => Some(rung),
                _ => None,
            })
            .collect();
        let total = declared.len();
        declared.sort_unstable();
        declared.dedup();
        assert_eq!(declared.len(), total, "a rung is declared twice");
        let expected: Vec<Verbosity> = Verbosity::ALL
            .iter()
            .copied()
            .filter(|rung| *rung != Verbosity::DEFAULT)
            .collect();
        assert_eq!(declared, expected, "the ladder is not total");
        assert_eq!(
            rungs()
                .iter()
                .filter(|flag| matches!(flag.rung, Rung::Named))
                .count(),
            1,
            "exactly one flag names a rung rather than selecting one"
        );
    }

    #[test]
    fn a_ladder_rung_declares_no_boolean_env_equivalent() {
        // §3's "a key where it makes sense": on a command line the ladder's
        // tie-break is position, and the environment has none — so five
        // booleans would reintroduce exactly the ambiguity the ladder removes.
        // Only the rung-*naming* flag carries a variable.
        for flag in rungs() {
            match flag.rung {
                Rung::Fixed(_) => assert!(
                    flag.env.name().is_none(),
                    "--{} is a fixed rung and must carry no env equivalent",
                    flag.id
                ),
                Rung::Named => assert!(
                    matches!(flag.env, EnvDecl::Presentation(_)),
                    "--{} names a rung, so its variable is read by `output`",
                    flag.id
                ),
                Rung::None => unreachable!("filtered above"),
            }
        }
    }

    #[test]
    fn every_presentation_env_is_read_by_the_output_resolver() {
        // The `Layered` half of this is `every_declared_env_is_actually_read`;
        // this is the presentation half. A `Presentation` name `output` does not
        // consult is the CLOUD-31 defect class again.
        let known = [
            crate::output::LOG_LEVEL_ENV,
            crate::output::NO_COLOR_ENV,
            crate::output::NO_INPUT_ENV,
        ];
        for decl in std::iter::once(&ROOT).chain(SURFACE) {
            for flag in decl.flags {
                let EnvDecl::Presentation(env) = flag.env else {
                    continue;
                };
                assert!(
                    known.contains(&env),
                    "{}: {env} is declared Presentation but `output` reads no such variable",
                    decl.path
                );
            }
        }
    }

    #[test]
    fn the_data_channel_declares_no_env_equivalent() {
        // `-J` selects the answer's encoding. An env equivalent would make a
        // caller's stdout shape depend on ambient state, which is the one thing
        // a byte-stable data channel cannot allow.
        for decl in std::iter::once(&ROOT).chain(SURFACE) {
            for flag in decl.flags {
                if flag.id != "json" {
                    continue;
                }
                assert!(
                    flag.env.name().is_none(),
                    "{}: -J must have no env equivalent",
                    decl.path
                );
            }
        }
    }

    #[test]
    fn every_data_emitting_verb_declares_the_json_flag() {
        // Derived from the `data_channel` column in both directions, so neither
        // half can be forgotten: a verb that declares the intent and omits the
        // flag fails, and so does one that carries the flag undeclared.
        for decl in std::iter::once(&ROOT).chain(SURFACE) {
            let carries = decl.flags.iter().any(|flag| flag.id == "json");
            assert_eq!(
                decl.data_channel,
                carries,
                "{:?}: data_channel is {} but -J is {}",
                decl.path,
                decl.data_channel,
                if carries { "declared" } else { "absent" }
            );
        }
    }

    #[test]
    fn spec_switches_format_rather_than_declaring_json() {
        // `spec` emits data and still declares no data channel: `--format` picks
        // an encoding, and a row must not acquire both switches for one answer.
        let spec = SURFACE
            .iter()
            .find(|decl| decl.path == "spec")
            .expect("spec is declared");
        assert!(!spec.data_channel);
        assert!(spec.flags.iter().any(|flag| flag.id == "format"));
    }

    #[test]
    fn no_row_declares_destructive_so_yes_and_dry_run_are_not_owed() {
        // §3 owes `-y`/`-n` and `--dry-run` to a *destructive* verb. None exists
        // yet, so shipping them now would be a confirmation prompt for nothing —
        // filed as G11 and pinned here, so the first destructive row fails this
        // test rather than landing unguarded.
        for decl in std::iter::once(&ROOT).chain(SURFACE) {
            assert_ne!(
                decl.effect,
                Effect::Destructive,
                "{:?} is destructive: it owes -y/-n and --dry-run (CLOUD-42, G11)",
                decl.path
            );
        }
    }

    #[test]
    fn only_a_diagnostic_rung_is_hidden() {
        // Hidden is for the tiers below the human surface. A hidden flag that a
        // caller is expected to reach for is an undocumented feature.
        for decl in std::iter::once(&ROOT).chain(SURFACE) {
            for flag in decl.flags {
                if !flag.hidden {
                    continue;
                }
                let diagnostic = matches!(
                    flag.rung,
                    Rung::Fixed(Verbosity::Debug | Verbosity::Trace) | Rung::Named
                );
                assert!(
                    diagnostic,
                    "{}: --{} is hidden for no reason",
                    decl.path, flag.id
                );
            }
        }
    }

    #[test]
    fn a_value_taking_flag_is_recognised_by_its_declared_spellings() {
        // `output`'s argv scan depends on this being derived rather than listed.
        assert!(consumes_a_value("--strictness"));
        assert!(consumes_a_value("--config-from"));
        assert!(consumes_a_value("--log-level"));
        // Counted and boolean flags consume nothing, so the token after them is
        // still a token the scan must read.
        assert!(!consumes_a_value("-v"));
        assert!(!consumes_a_value("--fail-on-warning"));
        assert!(!consumes_a_value("-J"));
        assert!(!consumes_a_value("check"));
    }

    #[test]
    fn clap_accepts_the_built_tree() {
        // `debug_assert` walks the whole tree and panics on a malformed arg —
        // the cheapest total check that a new declaration is constructible.
        command().debug_assert();
    }
}
