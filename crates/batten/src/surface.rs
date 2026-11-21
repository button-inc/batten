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
#[cfg(test)]
use crate::surface_table::BACKFILL_TAG;
#[cfg(test)]
use crate::surface_table::BOARD_ISSUE;
#[cfg(test)]
use crate::surface_table::CI_STEP_ARG_ENV;
#[cfg(test)]
use crate::surface_table::CI_STEP_ON;
#[cfg(test)]
use crate::surface_table::CI_STEP_REQUIRE_ENV;
#[cfg(test)]
use crate::surface_table::IN_FLIGHT_WORKFLOW;
#[cfg(test)]
use crate::surface_table::NONVERDICT_EXCLUDE;
#[cfg(test)]
use crate::surface_table::NONVERDICT_REQUIRED;
#[cfg(test)]
use crate::surface_table::NONVERDICT_STEP;
#[cfg(test)]
use crate::surface_table::RECEIPT_OR;
#[cfg(test)]
use crate::surface_table::STEP_ARG;
use crate::surface_table::Verbosity;
use crate::surface_table::{
    CommandDecl, EXITS_DISPATCHES, EnvDecl, FlagDecl, Rung, SURFACE, ValueDecl,
};

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

const CONFIG_FROM: FlagDecl = FlagDecl {
    id: "config_from",
    long: Some("config-from"),
    short: None,
    help: "Read the committed config from a git ref (e.g. origin/<trunk>) instead of the working tree",
    env: EnvDecl::Clap("BATTEN_CONFIG_FROM"),
    global: true,
    positional: false,
    required: false,
    hidden: false,
    rung: Rung::None,
    value: ValueDecl::Str,
};

/// `--config-in <dir>` (CLOUD-1228).
///
/// The sibling of [`CONFIG_FROM`], and the distinction is the whole reason it
/// exists: `--config-from` names a git **ref**, resolved inside the repository
/// the run discovered. A verb run inside a `git init`-ed scratch repository —
/// which 50 of 144 `tests/*.bats` suites create, to keep receipt writes off the
/// real checkout (CLOUD-512) — has no ref to name and no `batten.toml` to read,
/// so no spelling of the existing flag reaches that case.
///
/// `global: true` for the same reason `--config-from` is: which repository
/// supplies the authority is a property of the run, not of one verb, so a flag
/// that applied to `check` and not to `ready lint` would be the drift §8 is
/// about.
const CONFIG_IN: FlagDecl = FlagDecl {
    id: "config_in",
    long: Some("config-in"),
    short: None,
    help: "Read the committed config from this directory instead of the directory being judged",
    env: EnvDecl::Clap("BATTEN_CONFIG_IN"),
    global: true,
    positional: false,
    required: false,
    hidden: false,
    rung: Rung::None,
    value: ValueDecl::Str,
};

// --- CLOUD-843's foundation surface ------------------------------------------
//
// The verbs the bash retirement's packages fill, declared ONCE with their final
// arguments so every package builds against a fixed surface rather than each
// inventing its own spelling. A row may answer "unimplemented" (exit 3) until its
// package lands; its arguments may not move. Two shapes recur, so they are
// constructors here rather than eleven struct literals repeating nine columns.

fn verbosity_parser() -> ValueParser {
    ValueParser::new(clap::builder::EnumValueParser::<Verbosity>::new())
}

fn strictness_parser() -> ValueParser {
    ValueParser::new(clap::builder::EnumValueParser::<
        crate::config_model::Strictness,
    >::new())
}

/// The root command: the program itself, carrying the global flags.
///
/// The root declares no effect of its own — a bare invocation lists the
/// subcommands and never performs a default action (§2) — so it is
/// [`Effect::Ask`], the same conservative reading an undeclared path gets.
///
/// `about` is the crate manifest's `description`, read through
/// `CARGO_PKG_DESCRIPTION` rather than restated (CLOUD-402). The two were a
/// second copy of one fact with nothing asserting they agreed, and the copy
/// here kept the category claim the positioning register retired while the
/// manifest moved on. A copy that cannot exist cannot drift — the same
/// one-authority move `completions-check` and `schema-check` protect by
/// diffing.
pub const ROOT: CommandDecl = CommandDecl {
    path: "",
    // The root is the binary; the release tag is its identity (CLOUD-969).
    id: "",
    about: env!("CARGO_PKG_DESCRIPTION"),
    effect: Effect::Ask,
    // A bare invocation performs no default action, so there is no answer to
    // encode and `-J` would be a flag that looks applied and isn't.
    data_channel: false,
    // THE ROOT DISPATCHES AND DECIDES NOTHING, which is a noun's answer and is
    // this row's for a noun's reason. A bare invocation performs no action, so
    // every code a caller sees under `batten` belongs to a leaf or to clap —
    // including the `1` a bare invocation itself returns, which is clap's
    // "subcommand required" and not a verdict of the root's.
    exits: EXITS_DISPATCHES,
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
    CONFIG_IN,
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
    // §3 lists `-y --yes` among the globals, and §5 binds it to `destructive`:
    // it pre-answers the confirmation only that effect triggers. Global for
    // ROOT_FLAGS' stated reason — whether this invocation is authorized to
    // destroy something is a property of the invocation, not of one verb — and
    // it carries the short form the spec names, which is why it is spelled out
    // here rather than built by `FlagDecl::presentation`.
    FlagDecl {
        id: "yes",
        long: Some("yes"),
        short: Some('y'),
        help: "Confirm a destructive operation that would otherwise refuse",
        env: EnvDecl::Presentation(crate::output::YES_ENV),
        global: true,
        positional: false,
        required: false,
        hidden: false,
        rung: Rung::None,
        value: ValueDecl::Bool,
    },
];

/// The binary's own name, as a wiring entry spells it.
///
/// Here rather than beside each consumer for [`mediation`]'s reason: the
/// generator emits it and the diagnostic matches a token's file stem against it,
/// and those two agreeing is what makes a registration reach the engine.
pub const BINARY: &str = "batten";

/// The stable id of the row that adjudicates a mediated tool call.
///
/// **The anchor is the id and never the path**, which is [`CommandDecl::id`]'s
/// whole contract: the path is "the one thing about a row that is expected to
/// change", so a derivation keyed on it re-breaks on exactly the rename it
/// exists to survive.
pub const MEDIATION_ID: &str = "hook";

/// The flags clap answers by printing and exiting, on every command
/// [`command`] builds (CLOUD-2206). Its own `help` subcommand does the same.
pub const INFORMATIONAL_FLAGS: &[&str] = &["-h", "--help", "-V", "--version"];

/// The mediation row, resolved from [`SURFACE`] by [`MEDIATION_ID`].
///
/// **One authority for how the mediator is invoked** (CLOUD-1191). Before this,
/// the argv was spelled independently in three places with nothing linking them
/// — the row here, the generator in [`crate::hook::wiring_command`], and the
/// diagnostic in `doctor`'s `reaches_engine` — plus five committed wiring files
/// carrying it as data.
///
/// # Why a disagreement between them is worse than ordinary drift
///
/// It is a **silent fail-open**. An unknown subcommand is a clap error, which is
/// [`crate::exit::ExitCode::Usage`] (`1`), and `exit.rs` states the consequence
/// as a design property: every host reads anything but `0`/`2` as "the hook
/// itself failed, let the call through". So three literals that disagree do not
/// break loudly — they turn enforcement off across every harness while `doctor`
/// reports green. Renaming the row was measured safe on paper and would have
/// done exactly that.
///
/// Returns `None` only if the row is absent, which
/// [`tests::the_mediation_row_resolves`] refuses. Callers treat `None` as "no
/// declared mediation path" and fail loud rather than falling back to a literal
/// — a fallback would reintroduce the fourth spelling this exists to remove.
#[must_use]
pub fn mediation() -> Option<&'static CommandDecl> {
    SURFACE.iter().find(|row| row.id == MEDIATION_ID)
}

/// The mediation row's argv as the wiring spells it: the path, then each
/// required flag as `--long`.
///
/// Derived rather than formatted, so a change to the row's `path` or to its
/// required flags moves the emitted wiring and the diagnostic's expectation in
/// the same build.
/// The value each required flag takes is the CALLER's — the harness — so this
/// stops at the flag and the caller appends it. That keeps the one thing that
/// varies per registration out of a function whose whole job is the part that
/// does not.
#[must_use]
pub fn mediation_argv() -> Option<Vec<String>> {
    let row = mediation()?;
    let mut argv = vec![row.path.to_owned()];
    for flag in row.flags.iter().filter(|flag| flag.required) {
        if let Some(long) = flag.long {
            argv.push(format!("--{long}"));
        }
    }
    Some(argv)
}

/// The declared command path `arguments` names, and how many of them it spends.
///
/// `arguments` is the argv AFTER the program name. The answer is the LONGEST
/// fully-declared path those words spell, plus the number of leading tokens it
/// consumed — flags and their values included, so a caller can treat the
/// remainder as the command's own operands.
///
/// # Why the mediated boundary needs this (CLOUD-1804)
///
/// `hook`'s operand walk reads every non-flag word as a path, which is right for
/// a program whose argv grammar the boundary does not know and wrong for THIS
/// one, whose grammar is the table above. A consumer that keeps its policy
/// modules in a directory sharing a name with one of our subcommands — which is
/// the layout our own starter config recommends — had `batten policy budget`
/// refused, because the word `policy` resolved as a path enclosing the registered
/// modules. Adopting the documented convention was what triggered it.
///
/// # Fully declared, never a prefix
///
/// A prefix that bottoms out in no row consumes NOTHING. Stopping at the longest
/// declared ancestor would let an undeclared trailing word be read as that
/// command's operand, and the conservative reading of an unrecognised path is
/// [`Effect::Ask`] rather than a guess — §5's rule, applied to the walk that
/// finds the path as well as to the effect it resolves.
#[must_use]
pub fn command_path(arguments: &[&str]) -> Option<(&'static str, usize)> {
    let mut words: Vec<&str> = Vec::new();
    let mut best: Option<(&'static str, usize)> = None;
    let mut index = 0;
    while index < arguments.len() {
        let token = arguments[index];
        // A `--` ends option parsing, and everything after it is an operand — so
        // no command path continues through one.
        if token == "--" {
            break;
        }
        if token.starts_with('-') {
            index += 1;
            if consumes_a_value(token) {
                index += 1;
            }
            continue;
        }
        words.push(token);
        index += 1;
        let candidate = words.join(" ");
        // A miss is not the end of the walk: a longer path may still be declared
        // where its prefix is not, so the loop keeps going and `best` only ever
        // moves forward onto a row that exists.
        if let Some(decl) = SURFACE.iter().find(|decl| decl.path == candidate) {
            best = Some((decl.path, index));
        }
    }
    best
}

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
        .filter(|flag| !flag.positional && takes_value(flag))
        // Long spelling only: `no_value_taking_flag_declares_a_short_spelling`
        // holds that no value-taking flag has a short one.
        .any(|flag| flag.long.is_some_and(|long| token == format!("--{long}")))
}

/// Whether `flag` consumes the token after it.
///
/// `Trailing` consumes the whole tail rather than one token, and it is a
/// positional besides, so an argv scan has nothing to skip for it.
const fn takes_value(flag: &FlagDecl) -> bool {
    !matches!(
        flag.value,
        ValueDecl::Bool | ValueDecl::Count | ValueDecl::Trailing
    )
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

/// Resolve the declared stable id for a full command path (CLOUD-969).
///
/// `None` for a path [`SURFACE`] does not declare — the root program node is the
/// only one in practice, and it is deliberately not given an identity of its
/// own: it is the binary, which the tag already names.
#[must_use]
pub fn id_for(path: &str) -> Option<&'static str> {
    SURFACE
        .iter()
        .find(|decl| decl.path == path)
        .map(|decl| decl.id)
}

/// Whether a command answers through the `-J` data channel (§6).
///
/// A path absent from [`SURFACE`] is `false`, which is the same conservative
/// reading [`effect_for`] takes: an unrecognised command is not asserted to
/// carry a machine channel it may not have.
///
/// Published since CLOUD-969, because it was a build-time-only column before —
/// so a spec consumer could only INFER the data channel by scanning a row's
/// flags for one named `json`, which is a second derivation of a fact the
/// surface already declares.
#[must_use]
pub fn data_channel_for(path: &str) -> bool {
    SURFACE
        .iter()
        .find(|decl| decl.path == path)
        .is_some_and(|decl| decl.data_channel)
}

/// The parent path of a command path: `"config show"` → `"config"`, and a
/// top-level verb → `""` (the root).
fn parent_of(path: &str) -> &str {
    path.rsplit_once(' ').map_or("", |(parent, _)| parent)
}

/// Whether `prefix` is `path`'s parent: `parent_of(path) == prefix`, decided
/// without searching `path` backwards for its last space.
///
/// Building the tree asks this of every row for every node, twice (attach and
/// [`has_children`]), and the backward search was 74% of the instructions
/// `batten --version` ran (CLOUD-2315). A row under another parent fails here
/// on its first differing byte.
fn is_child_of(path: &str, prefix: &str) -> bool {
    let rest = if prefix.is_empty() {
        Some(path)
    } else {
        path.strip_prefix(prefix)
            .and_then(|rest| rest.strip_prefix(' '))
    };
    rest.is_some_and(|rest| !rest.contains(' '))
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
        // **THE METAVARIABLE IS EXPLICIT** (review of #928). clap defaults it for
        // `--help` but `clap_mangen` does not, so the committed SYNOPSIS rendered
        // every value-taking flag as if it took none: `[--lock] [--lock-path]
        // [--lock-attempts] [--lock-label]`, from which no valid command can be
        // formed. `--jobs`, `--format` and `--style` carried the same defect, so
        // this is set where the arg is BUILT rather than on the four flags the
        // review happened to name.
        //
        // THE ID ITSELF, rather than a `value_name` field on `FlagDecl`: a second
        // column would be a second place to forget, and the id is ALREADY what
        // `--help` renders — so the page and the help agree instead of carrying
        // two vocabularies for one value. A semantic name per flag (`<KEY>`,
        // `<PATH>`, `<N>`) reads better and is not free: it is a per-flag
        // decision across the whole surface, and one nobody is forced to make
        // correctly. Consistency with `--help` is the property worth having.
        ValueDecl::Str => arg.action(ArgAction::Set).value_name(decl.id),
        // `Append` rather than `Set`: every occurrence is kept, in the order
        // written, so a caller widening a selection gets the union rather than
        // the last one silently winning.
        ValueDecl::StrMany => arg.action(ArgAction::Append).value_name(decl.id),
        ValueDecl::Enum { parser, default } => {
            let arg = arg.action(ArgAction::Set).value_parser(parser());
            match default {
                Some(value) => arg.default_value(value),
                None => arg,
            }
        }
    }
}

/// Whether any row declares `path` as its parent.
fn has_children(path: &str) -> bool {
    SURFACE.iter().any(|decl| is_child_of(decl.path, path))
}

/// The effect a `batten` argv runs with: the declared effect of the deepest
/// subcommand it names, walking the non-flag arguments while each extension is
/// a declared path, so `batten override spend --rule x` resolves
/// `override spend`. A NOUN IS NEVER THE ANSWER WHEN A LEAF IS NAMED: the nouns
/// are `unclassified` precisely so a write-bearing subtree cannot leak onto a
/// read list (CLOUD-170). An argv naming no path is `unclassified`.
///
/// AN INFORMATIONAL FLAG IS A READ wherever clap answers it by printing
/// (CLOUD-2206): anywhere before `--`, once the first word clap sees is a
/// declared subcommand or a flag. No value-taking flag accepts a hyphen value
/// (only a `Trailing` tail does, and that needs the `--`), so `--help` is never
/// swallowed as a value; a declared value-taking flag's own value is skipped so
/// it is not mistaken for a subcommand. Clap's `help` subcommand reads too,
/// where the path so far still has subcommands to parse. A FIRST WORD THAT IS
/// NOT A SUBCOMMAND grants nothing: `provision-exec` and the rustc wrapper run
/// before clap parses anything.
#[must_use]
pub fn effect_of_argv(arguments: &[&str]) -> Effect {
    let mut path = String::new();
    let mut resolving = true;
    let mut skip = false;
    for argument in arguments {
        if std::mem::take(&mut skip) {
            continue;
        }
        if *argument == "--" {
            break;
        }
        if INFORMATIONAL_FLAGS.contains(argument) {
            return Effect::Read;
        }
        if argument.starts_with('-') {
            skip = consumes_a_value(argument);
            continue;
        }
        if !resolving {
            continue;
        }
        if *argument == "help" && has_children(&path) {
            return Effect::Read;
        }
        let candidate = if path.is_empty() {
            (*argument).to_owned()
        } else {
            format!("{path} {argument}")
        };
        if id_for(&candidate).is_none() {
            if path.is_empty() {
                return Effect::Unclassified;
            }
            resolving = false;
            continue;
        }
        path = candidate;
    }
    if path.is_empty() {
        Effect::Unclassified
    } else {
        effect_for(&path)
    }
}

/// Whether `decl` is a **noun** — a row that dispatches and performs no default
/// action of its own (§2).
///
/// Derived from the row rather than declared beside it, and the discriminator is
/// the row's own answer: a noun emits nothing and takes nothing, so it carries no
/// data channel and no flags. Every noun on this surface satisfies both today
/// (`config`, `lint`, `generate`, `policy`, `capture`, `commit`, `attribution`,
/// `worktree`, `provision`, `payload`, `receipt`, `defects`, `design`, `state`),
/// and `tests::a_noun_declares_no_answer_of_its_own` is what keeps that true.
///
/// **The row that is both is `doctor`, and house style says so in two places.**
/// §2 spells the verb `doctor <SUB>` — "diagnose environment; nests focused
/// sub-diagnostics" — while §8 says "`batten doctor` validates the resolved
/// config against the schema", which is a promise about the BARE invocation. A
/// parent marked `subcommand_required` would break the second to satisfy the
/// first, and that is not hypothetical: `payload` exists as a top-level noun
/// precisely because nesting it under `hook` turned the `PreToolUse` mediator
/// into a noun that refused to adjudicate (see that row's comment). So the test
/// is what the row declares, not what it is called.
#[must_use]
pub fn is_noun(decl: &CommandDecl) -> bool {
    has_children(decl.path) && !decl.data_channel && decl.flags.is_empty()
}

/// Attach every direct child of `prefix` to `parent`, recursively, keeping
/// only the child named `only` when one is given.
//
// ONE MOVE PER NODE, NOT ONE PER FLAG. `clap`'s builder takes `Command` by
// value, so folding `.arg` over a row's flags and `.subcommand` over its
// children copied the whole node once per flag and once per child; on
// `batten --version` that was half of every instruction the process ran, in
// `memcpy` (CLOUD-2315). `args` and `subcommands` take the lot in one move.
fn attach_only(parent: Command, prefix: &str, only: Option<&str>) -> Command {
    parent.subcommands(
        SURFACE
            .iter()
            .filter(|decl| is_child_of(decl.path, prefix))
            .filter(|decl| only.is_none_or(|name| leaf_of(decl.path) == name))
            .map(|decl| {
                let sub = Command::new(leaf_of(decl.path))
                    .about(decl.about)
                    .args(decl.flags.iter().map(arg_of));
                let sub = attach_only(sub, decl.path, None);
                // A noun performs no default action: it lists its sub-verbs (§2).
                // A row that nests AND declares an answer keeps acting bare.
                if is_noun(decl) {
                    sub.subcommand_required(true).arg_required_else_help(true)
                } else {
                    sub
                }
            }),
    )
}

/// The live [`clap::Command`] tree, built from [`ROOT`] and [`SURFACE`].
///
/// This is the only place a `clap` command is constructed: the parser, the
/// emitted spec, and the generated completions all read this one tree, so none
/// of them can disagree with the declaration.
#[must_use]
pub fn command() -> Command {
    command_for(None)
}

/// The tree [`command`] builds, with only the top-level verb `verb` attached
/// when `verb` names one — the same declaration, the same parser, a subset of
/// the nodes (CLOUD-2315).
///
/// Every invocation built the WHOLE tree to dispatch one verb, and the hook runs
/// one invocation per tool call: building it was most of the ~4 ms between
/// `main` and the dispatch, against a 10 ms per-call budget. A caller hands the
/// first argument only when it is EXACTLY a declared top-level verb; anything
/// else — a leading flag, a misspelling clap would suggest a fix for, `help`, a
/// bare invocation — builds the whole tree, so every answer that needs the
/// siblings still has them. `a_narrowed_tree_parses_as_the_whole_one` holds the
/// two to one parse for every declared top-level verb.
#[must_use]
pub fn command_for(verb: Option<&str>) -> Command {
    let only = verb.filter(|name| {
        SURFACE
            .iter()
            .any(|decl| parent_of(decl.path).is_empty() && decl.path == *name)
    });
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
    attach_only(root.args(ROOT.flags.iter().map(arg_of)), "", only)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod narrowed_tests {
    use super::{command, command_for, is_child_of, parent_of};
    use crate::surface_table::SURFACE;

    /// The prefix test answers as the backward search it replaced, for every
    /// declared path against every declared parent (and the root).
    #[test]
    fn the_prefix_test_answers_as_the_parent_search() {
        let prefixes: Vec<&str> = std::iter::once("")
            .chain(SURFACE.iter().map(|decl| decl.path))
            .chain(["adjudicat", "config "])
            .collect();
        for decl in SURFACE {
            for prefix in &prefixes {
                assert_eq!(
                    is_child_of(decl.path, prefix),
                    parent_of(decl.path) == *prefix,
                    "{:?} under {prefix:?}",
                    decl.path
                );
            }
        }
    }

    /// CLOUD-2315: the narrowed tree is the whole tree's subtree for that verb,
    /// node for node — the same help, every flag, every sub-verb — and a first
    /// argument that is not exactly a top-level verb builds the whole tree.
    #[test]
    fn a_narrowed_tree_parses_as_the_whole_one() {
        let mut whole = command();
        let verbs: Vec<&str> = SURFACE
            .iter()
            .filter(|decl| parent_of(decl.path).is_empty())
            .map(|decl| decl.path)
            .collect();
        assert!(
            verbs.contains(&"adjudicate"),
            "the hook's verb is top-level"
        );
        for verb in &verbs {
            let mut narrowed = command_for(Some(verb));
            assert_eq!(
                narrowed.get_subcommands().count(),
                1,
                "`{verb}` alone is attached"
            );
            let in_whole = whole
                .find_subcommand_mut(verb)
                .expect("declared")
                .render_long_help();
            let alone = narrowed
                .find_subcommand_mut(verb)
                .expect("attached")
                .render_long_help();
            assert_eq!(in_whole.to_string(), alone.to_string(), "`{verb}`");
        }
        let total = whole.get_subcommands().count();
        for other in [None, Some("--strictness"), Some("adjudicat"), Some("help")] {
            assert_eq!(
                command_for(other).get_subcommands().count(),
                total,
                "{other:?} builds the whole tree"
            );
        }
    }

    /// The hook reads [`super::INFORMATIONAL_FLAGS`] as reads at any depth of the
    /// subcommand path, so on EVERY built command a word in that list must be one
    /// clap answers by printing: a subcommand that gave `-V` to a flag of its own
    /// would be a write granted in plan mode. The root answers all of them.
    #[test]
    fn the_informational_flags_are_claps_help_and_version() {
        fn prints(arg: &clap::Arg) -> bool {
            matches!(
                arg.get_action(),
                clap::ArgAction::Help
                    | clap::ArgAction::HelpShort
                    | clap::ArgAction::HelpLong
                    | clap::ArgAction::Version
            )
        }
        fn spellings(arg: &clap::Arg) -> Vec<String> {
            arg.get_short()
                .map(|short| format!("-{short}"))
                .into_iter()
                .chain(arg.get_long().map(|long| format!("--{long}")))
                .collect()
        }
        fn walk(command: &clap::Command, path: &str) {
            for arg in command.get_arguments() {
                for spelling in spellings(arg) {
                    assert!(
                        prints(arg) || !super::INFORMATIONAL_FLAGS.contains(&spelling.as_str()),
                        "`{path}` gives `{spelling}` to a flag clap runs"
                    );
                }
            }
            for sub in command.get_subcommands() {
                walk(sub, &format!("{path} {}", sub.get_name()));
            }
        }
        let mut root = command();
        root.build();
        walk(&root, "batten");
        let mut answered: Vec<String> = root
            .get_arguments()
            .filter(|arg| prints(arg))
            .flat_map(spellings)
            .collect();
        answered.sort();
        let mut declared: Vec<String> = super::INFORMATIONAL_FLAGS
            .iter()
            .map(|f| (*f).to_owned())
            .collect();
        declared.sort();
        assert_eq!(answered, declared);
    }

    /// CLOUD-2206: clap answers an informational flag, or its `help`
    /// subcommand, by printing, so each is a read wherever clap would reach it;
    /// past `--`, before clap runs, or as a leaf's positional, the leaf decides.
    #[test]
    fn an_informational_flag_is_a_read_wherever_clap_answers_it() {
        use super::{effect_for, effect_of_argv, has_children};
        use crate::effect::Effect;
        use crate::surface_table::SURFACE;
        for argv in [
            &["--version"][..],
            &["-V"],
            &["-h"],
            &["help", "check"],
            &["-v", "help", "check"],
            &["override", "help", "spend"],
            &["override", "spend", "--help"],
            &["override", "spend", "--rule", "x", "--help"],
            &["-v", "--version"],
            &["--strictness", "strict", "--help"],
            &["--strictness=strict", "--help"],
            &["check", "-q", "--help"],
        ] {
            assert_eq!(effect_of_argv(argv), Effect::Read, "{argv:?}");
        }
        let spend = effect_for("override spend");
        assert_eq!(
            effect_of_argv(&["override", "spend", "--", "--help"]),
            spend
        );
        assert_eq!(
            effect_of_argv(&["provision-exec", "--help"]),
            Effect::Unclassified
        );
        // `--strictness` takes `help` as its value; it is not the subcommand.
        assert_eq!(
            effect_of_argv(&["--strictness", "help", "override", "spend"]),
            spend
        );
        let leaf = SURFACE
            .iter()
            .find(|decl| decl.effect != Effect::Read && !has_children(decl.path))
            .expect("a non-read leaf is declared");
        let argv: Vec<&str> = leaf.path.split(' ').chain(["help"]).collect();
        assert_eq!(
            effect_of_argv(&argv),
            leaf.effect,
            "`help` under a leaf is a positional, not clap's subcommand"
        );
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod identity_tests {
    use super::ROOT;
    use crate::surface_table::SURFACE;

    /// Every declared command carries a stable id (CLOUD-969).
    ///
    /// The root is exempt and is the ONLY exemption: it is the binary, which the
    /// release tag already identifies. Naming it here rather than testing
    /// `path != ""` keeps the exemption a decision a reader can see.
    #[test]
    fn every_declared_path_has_an_id() {
        let unidentified: Vec<&str> = SURFACE
            .iter()
            .filter(|decl| decl.id.is_empty())
            .map(|decl| decl.path)
            .collect();
        assert!(
            unidentified.is_empty(),
            "commands with no stable id, so nothing a consumer can pin: {unidentified:?}"
        );
        assert!(
            ROOT.id.is_empty(),
            "the root is the binary and takes no identity of its own"
        );
    }

    /// No two commands share an id.
    ///
    /// A duplicate is worse than a missing id: two rows answer to one handle, so
    /// a consumer pinning it gets whichever the lookup reaches first — and
    /// `id_for` finds the first, which makes the second silently unreachable.
    #[test]
    fn no_id_is_declared_twice() {
        let mut duplicated: Vec<(&str, &str)> = Vec::new();
        for (at, decl) in SURFACE.iter().enumerate() {
            if let Some(other) = SURFACE[..at].iter().find(|prior| prior.id == decl.id) {
                duplicated.push((other.path, decl.path));
            }
        }
        assert!(
            duplicated.is_empty(),
            "two commands share a stable id, so one of them is unreachable through it: \
             {duplicated:?}"
        );
    }

    /// An id is not the path, and this is what stops it drifting back into one.
    ///
    /// The seeds resemble their paths because they were seeded from them once
    /// (see [`crate::surface_table::CommandDecl::id`]), and the failure mode is a later author
    /// reading that resemblance as a RULE and "fixing" an id during a rename —
    /// which undoes the whole field. There is no honest exit code over intent,
    /// so what is asserted is the reachable half: the lookup answers by path and
    /// returns the declared literal, never a computed one.
    #[test]
    fn the_lookup_returns_the_declared_literal_rather_than_a_computed_one() {
        for decl in SURFACE {
            assert_eq!(
                super::id_for(decl.path),
                Some(decl.id),
                "`{}` must resolve to the id its own row declares",
                decl.path
            );
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    /// [`command_path`]'s argv handling, which the mediated boundary depends on
    /// to stop reading our own subcommand words as paths (CLOUD-1804).
    #[test]
    fn a_command_path_spends_its_flags_and_stops_at_the_operands() {
        // The longest declared path wins, and it spends exactly its own words.
        assert_eq!(
            command_path(&["policy", "budget"]),
            Some(("policy budget", 2))
        );
        // A global flag before the path is spent with it, so the count is an
        // index into argv rather than a count of path words.
        assert_eq!(
            command_path(&["-q", "policy", "budget"]),
            Some(("policy budget", 3))
        );
        // A value-taking flag spends its value too, or the value would be read
        // as the next path word.
        assert_eq!(
            command_path(&["--strictness", "strict", "policy", "budget"]),
            Some(("policy budget", 4))
        );
        // What follows a declared path is the command's own argument and is left
        // where the operand walk can still see it.
        assert_eq!(
            command_path(&["policy", "explain", "some token"]),
            Some(("policy explain", 2))
        );
        // NOT A PREFIX. An undeclared trailing word leaves the answer on the
        // longest row that exists, never on a guess past it.
        assert_eq!(command_path(&["config", "frobnicate"]), Some(("config", 1)));
        // And an undeclared path spends nothing at all, which is the reading
        // that keeps the narrowing to where the surface actually answers.
        assert_eq!(command_path(&["frobnicate", "policy"]), None);
        assert_eq!(command_path(&[]), None);
        // A `--` ends option parsing, so no path continues through one.
        assert_eq!(command_path(&["--", "policy", "budget"]), None);
    }

    /// Every committed man page is the page the declared surface renders, so a
    /// flag's help, its requiredness and whether it takes a value are each held
    /// by an artifact a reader installs rather than by the declaration alone.
    #[test]
    fn every_committed_man_page_is_the_one_the_surface_renders() {
        let root = command();
        let dir = std::path::Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/../../man"));
        let paths = std::iter::once("").chain(SURFACE.iter().map(|decl| decl.path));
        for path in paths {
            let name = crate::render::page_name("batten", path);
            let committed = crate::fsio::read_to_string(dir.join(format!("{name}.1")))
                .unwrap_or_else(|_| panic!("man/{name}.1 is committed"));
            let rendered = crate::render::man(&root, Some(path)).expect("the page renders");
            assert!(rendered == committed, "man/{name}.1 is stale");
        }
    }

    /// Every flag declared REPEATABLE keeps each occurrence: a second one is
    /// appended, never a usage error and never a silent replacement.
    #[test]
    fn a_repeatable_flag_keeps_every_occurrence() {
        let repeatable = [
            RECEIPT_OR,
            CI_STEP_ON,
            CI_STEP_REQUIRE_ENV,
            CI_STEP_ARG_ENV,
            STEP_ARG,
            BOARD_ISSUE,
            NONVERDICT_REQUIRED,
            NONVERDICT_EXCLUDE,
            NONVERDICT_STEP,
            IN_FLIGHT_WORKFLOW,
            BACKFILL_TAG,
        ];
        for flag in repeatable {
            let decl = SURFACE
                .iter()
                .find(|decl| {
                    decl.flags
                        .iter()
                        .any(|f| f.id == flag.id && f.long == flag.long && f.help == flag.help)
                })
                .unwrap_or_else(|| panic!("`{}` is declared on a row", flag.id));
            let long = format!(
                "--{}",
                flag.long.expect("a repeatable flag has a long spelling")
            );
            let mut argv: Vec<String> = vec!["batten".to_owned()];
            argv.extend(decl.path.split(' ').map(str::to_owned));
            let mut positionals = Vec::new();
            let mut trailing = false;
            for other in decl.flags.iter().filter(|f| f.required && f.id != flag.id) {
                match (other.positional, &other.value) {
                    (_, ValueDecl::Trailing) => trailing = true,
                    (true, _) => positionals.push("x".to_owned()),
                    (false, ValueDecl::Bool | ValueDecl::Count) => {
                        argv.push(format!("--{}", other.long.unwrap_or_default()));
                    }
                    (false, _) => {
                        argv.push(format!("--{}", other.long.unwrap_or_default()));
                        argv.push("x".to_owned());
                    }
                }
            }
            argv.extend([long.clone(), "a".to_owned(), long, "b".to_owned()]);
            argv.extend(positionals);
            if trailing {
                argv.extend(["--".to_owned(), "true".to_owned()]);
            }
            let matches = command()
                .try_get_matches_from(&argv)
                .unwrap_or_else(|error| panic!("{}: {error}", argv.join(" ")));
            let mut leaf = &matches;
            while let Some((_, sub)) = leaf.subcommand() {
                leaf = sub;
            }
            let values: Vec<&String> = leaf
                .get_many::<String>(flag.id)
                .map(Iterator::collect)
                .unwrap_or_default();
            assert_eq!(values, ["a", "b"], "{}", argv.join(" "));
        }
    }

    #[test]
    fn only_a_declared_value_flag_consumes_the_next_word() {
        assert!(consumes_a_value("--strictness"));
        assert!(!consumes_a_value("--quiet"));
        assert!(!consumes_a_value("--no-such-flag"));
        assert!(!consumes_a_value("-Z"));
    }

    #[test]
    fn each_row_answers_its_own_data_channel_and_an_unknown_path_none() {
        for decl in SURFACE {
            assert_eq!(
                data_channel_for(decl.path),
                decl.data_channel,
                "{}",
                decl.path
            );
        }
        assert!(!data_channel_for("no such path"));
    }

    #[test]
    fn a_noun_has_children_and_no_answer_of_its_own() {
        let row = |path: &str| SURFACE.iter().find(|decl| decl.path == path).expect(path);
        assert!(is_noun(row("config")));
        assert!(!is_noun(row("config show")));
        assert!(!is_noun(row("doctor")));
        assert!(
            SURFACE
                .iter()
                .any(|decl| decl.data_channel && has_children(decl.path))
        );
    }

    #[test]
    fn an_env_declaration_names_its_variable_whoever_reads_it() {
        assert_eq!(EnvDecl::None.name(), None);
        assert_eq!(EnvDecl::Clap("A").name(), Some("A"));
        assert_eq!(EnvDecl::Layered("B").name(), Some("B"));
        assert_eq!(EnvDecl::Presentation("C").name(), Some("C"));
    }

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

    /// The mediation row resolves, which is what lets every consumer treat a
    /// `None` from [`mediation`] as "the surface declares none" rather than as a
    /// bug it has to guard.
    ///
    /// Fails by: renaming or deleting the row's `id`. That is the one edit
    /// [`MEDIATION_ID`] does not survive, and it must be loud — the id is the
    /// stable anchor precisely so the `path` can move without touching it.
    #[test]
    fn the_mediation_row_resolves() {
        let row = mediation().expect("the surface declares a mediation row");
        assert_eq!(row.id, MEDIATION_ID);
        assert!(
            row.flags.iter().any(|flag| flag.required),
            "the mediation row must carry a required flag, or `mediation_argv` \
             emits a bare path and every registration reads as drift"
        );
    }

    /// The emitted argv follows the row's `path`, not a literal.
    ///
    /// **This is the case that would have caught the defect.** With three
    /// independent spellings, renaming the row left the generator and the
    /// diagnostic behind, and the resulting unknown subcommand exits `1` — which
    /// every host reads as allow. Fails by: reverting either consumer to a
    /// `"hook"` literal.
    #[test]
    fn the_emitted_argv_is_the_rows_path_and_its_required_flags() {
        let row = mediation().expect("declared");
        let argv = mediation_argv().expect("declared");
        assert_eq!(
            argv.first().map(String::as_str),
            Some(row.path),
            "the argv must open with the row's path"
        );
        for flag in row.flags.iter().filter(|flag| flag.required) {
            if let Some(long) = flag.long {
                assert!(
                    argv.iter().any(|word| word == &format!("--{long}")),
                    "a required flag the row declares is missing from the argv: {long}"
                );
            }
        }
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

    /// The positional shape of one row's flag list, as a verdict (CLOUD-1185).
    ///
    /// Extracted as a function over the flag slice rather than written as a loop
    /// inside each test, and that is what makes the cases below able to fail:
    /// a fixture slice is judged by the SAME code as the real surface, so a test
    /// that passes over `SURFACE` cannot be passing because it never looked
    /// (CLOUD-418).
    ///
    /// Returns the first violation, or `None`.
    fn positional_violation(flags: &[FlagDecl]) -> Option<String> {
        let positionals: Vec<&FlagDecl> = flags.iter().filter(|flag| flag.positional).collect();

        // A trailing positional swallows every remaining token, so anything
        // declared after it is unreachable. `exec`'s comment is the only place
        // this was written down before, and it was prose.
        if let Some(index) = positionals
            .iter()
            .position(|flag| matches!(flag.value, ValueDecl::Trailing))
        {
            if index != positionals.len() - 1 {
                return Some(format!(
                    "trailing positional {:?} is not last; everything after it is unreachable",
                    positionals[index].id
                ));
            }
            if positionals
                .iter()
                .filter(|flag| matches!(flag.value, ValueDecl::Trailing))
                .count()
                > 1
            {
                return Some(String::from("more than one trailing positional"));
            }
        }

        // An OPTIONAL positional before a REQUIRED one cannot be parsed
        // unambiguously — clap has no way to know whether a single token filled
        // the optional or the required slot. This is the invariant that makes
        // several positionals on one row safe, and it is why the assertion is
        // shaped this way rather than as a bare count (see the census below).
        let mut seen_optional: Option<&str> = None;
        for flag in &positionals {
            if flag.required {
                if let Some(earlier) = seen_optional {
                    return Some(format!(
                        "required positional {:?} follows optional {:?}; a single token \
                         could fill either slot",
                        flag.id, earlier
                    ));
                }
            } else {
                seen_optional = Some(flag.id);
            }
        }

        // `arg_of` applies only `required` on the positional branch and drops
        // the rest with no diagnostic, so a row setting these is documenting
        // behaviour the parser does not implement.
        for flag in &positionals {
            if flag.global {
                return Some(format!("positional {:?} declares `global`", flag.id));
            }
            if !matches!(flag.env, EnvDecl::None) {
                return Some(format!(
                    "positional {:?} declares an env equivalent",
                    flag.id
                ));
            }
            if flag.hidden {
                return Some(format!("positional {:?} declares `hidden`", flag.id));
            }
            if flag.long.is_some() || flag.short.is_some() {
                return Some(format!(
                    "positional {:?} declares a long or short spelling",
                    flag.id
                ));
            }
        }
        None
    }

    /// Every row's positionals are in an order clap can parse, and declare only
    /// the columns `arg_of` actually applies to them (CLOUD-1185).
    ///
    /// **There is deliberately no "at most one positional" rule, and the row that
    /// asked for one is corrected rather than obeyed.** CLOUD-1185's §2 asked for
    /// "at most one non-trailing positional per row", on a premise its own Why
    /// states: *"No row does either today, so the mixed case is an untested clap
    /// configuration."* That premise expired when `mcp call` landed (CLOUD-1260)
    /// with three — `server`, `method`, and an optional `params` — which is the
    /// `VERB OBJECT` grammar working as intended, not a defect.
    ///
    /// So what is asserted is the hazard the row was actually pointing at. Several
    /// positionals are safe exactly when a token cannot be ambiguous about which
    /// slot it fills: required before optional, and a trailing variadic last. A
    /// count would have refused a landed, correct row while catching nothing the
    /// ordering rules miss.
    #[test]
    fn every_rows_positionals_are_unambiguous() {
        for decl in std::iter::once(&ROOT).chain(SURFACE) {
            assert!(
                positional_violation(decl.flags).is_none(),
                "{}: {}",
                decl.path,
                positional_violation(decl.flags).unwrap_or_default()
            );
        }
    }

    /// The census above is shown able to fail, one fixture per clause.
    ///
    /// Each fixture is the real defect rather than an imitation of it: the
    /// trailing case is `exec`'s flag list with one flag appended after it, and
    /// the ordering case is `mcp call`'s with its optional moved ahead of a
    /// required one.
    #[test]
    fn the_positional_census_discriminates() {
        // `const` rather than `let`: `FlagDecl` is not `Copy` (its `Rung` and
        // `ValueDecl` are not), and each fixture is used several times below.
        // A const item instantiates fresh at every use, so the cases read as the
        // shapes they are testing rather than as clones of one binding.
        const REQUIRED: FlagDecl = FlagDecl::positional("first", "a required positional");
        const OPTIONAL: FlagDecl =
            FlagDecl::positional_optional("second", "an optional positional");
        const TAIL: FlagDecl = FlagDecl::trailing("rest", "every remaining token");

        // The real surface's own shapes stay clean, including `mcp call`'s three.
        assert!(positional_violation(&[REQUIRED, OPTIONAL]).is_none());
        assert!(positional_violation(&[REQUIRED, REQUIRED, OPTIONAL]).is_none());
        assert!(positional_violation(&[REQUIRED, TAIL]).is_none());

        // Something after the trailing variadic is unreachable.
        assert!(positional_violation(&[TAIL, REQUIRED]).is_some());
        assert!(positional_violation(&[TAIL, TAIL]).is_some());

        // A required slot after an optional one cannot be filled unambiguously.
        assert!(positional_violation(&[OPTIONAL, REQUIRED]).is_some());

        // Columns `arg_of` silently drops on the positional branch.
        assert!(
            positional_violation(&[FlagDecl {
                global: true,
                ..REQUIRED
            }])
            .is_some()
        );
        assert!(
            positional_violation(&[FlagDecl {
                env: EnvDecl::Clap("BATTEN_SOMETHING"),
                ..REQUIRED
            }])
            .is_some()
        );
        assert!(
            positional_violation(&[FlagDecl {
                hidden: true,
                ..REQUIRED
            }])
            .is_some()
        );
        assert!(
            positional_violation(&[FlagDecl {
                long: Some("first"),
                ..REQUIRED
            }])
            .is_some()
        );
    }

    /// A row that dispatches to children declares no positional (CLOUD-1185).
    ///
    /// [`is_noun`] reads `flags.is_empty()`, so a positional on a parent flips it
    /// from noun to verb and silently drops `subcommand_required(true)` and
    /// `arg_required_else_help(true)` — a real behaviour change with no compile
    /// error. The bare invocation stops listing its sub-verbs and starts trying to
    /// act.
    #[test]
    fn a_row_with_children_declares_no_positional() {
        for decl in SURFACE {
            if !has_children(decl.path) {
                continue;
            }
            assert!(
                !decl.flags.iter().any(|flag| flag.positional),
                "{} has children and declares a positional; that flips `is_noun` \
                 and drops `subcommand_required`",
                decl.path
            );
        }
    }

    /// Every leaf under `show` is `read` (CLOUD-1180, CLOUD-1184).
    ///
    /// `show` is declared `read` rather than `unclassified`, unlike `record`,
    /// `capture` and `receipt`, and this assertion is the entire reason that is
    /// safe. Those nouns sit over write-bearing subtrees, so a `read` noun there
    /// would leak onto the derived agent allowlist for any consumer treating an
    /// entry as a prefix (CLOUD-170). `show` is different by CONSTRUCTION rather
    /// than by luck: CLOUD-1184's grammar puts the effect band on the verb, so a
    /// write under `show` is a grammar violation and not merely an oversight.
    ///
    /// Without this, that is a promise. With it, it is a property — which is the
    /// same distinction CLOUD-244 caught on `hook` and CLOUD-1180's §2 calls
    /// "the negative half is the point".
    ///
    /// Fails by: adding any leaf under `show` whose effect is not `read`.
    #[test]
    fn every_leaf_under_show_is_read() {
        let leaves: Vec<&CommandDecl> = SURFACE
            .iter()
            .filter(|decl| parent_of(decl.path) == "show")
            .collect();
        assert!(
            !leaves.is_empty(),
            "no leaf under `show`, so this assertion is vacuous — it must not \
             pass by having nothing to judge"
        );
        for decl in leaves {
            assert_eq!(
                decl.effect,
                Effect::Read,
                "{}: `show` is the read band, so every leaf under it is `read`; \
                 a writer here reaches the derived agent allowlist through the \
                 noun's own `read`",
                decl.path
            );
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
            crate::output::YES_ENV,
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
    fn every_destructive_row_owes_dry_run_and_yes() {
        // §3 owes `-y` and `-n --dry-run` to a *destructive* verb. This used to
        // assert that no such row existed — CLOUD-42's G11, pinned so the first
        // destructive row would fail rather than land unguarded. CLOUD-46 is
        // that row, so the pin becomes the obligation it was standing in for:
        // the preview flag on the row itself, the confirmation flag among the
        // globals, and both reachable from the same invocation.
        let confirmation = ROOT_FLAGS
            .iter()
            .find(|flag| flag.id == "yes")
            .expect("§3 declares -y --yes among the globals");
        assert_eq!(confirmation.short, Some('y'));
        assert!(
            confirmation.global,
            "-y is global: whether an invocation may destroy something is a property of the \
             invocation, not of one verb"
        );

        // Counted, so the loop cannot pass by finding nothing to judge. The
        // predecessor asserted the set was EMPTY, so emptiness was the pass; this
        // one asserts a property OF the set, and the same emptiness would make it
        // vacuous. `capture prune` (CLOUD-121) is the second row it covers.
        let mut destructive = 0;
        for decl in std::iter::once(&ROOT).chain(SURFACE) {
            if decl.effect != Effect::Destructive {
                continue;
            }
            destructive += 1;
            assert!(
                decl.flags.iter().any(|flag| flag.id == "dry_run"),
                "{:?} is destructive and declares no --dry-run (CLOUD-42, G11)",
                decl.path
            );
        }
        assert!(
            destructive > 0,
            "no destructive row: this test would pass vacuously"
        );
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
    fn no_value_taking_flag_declares_a_short_spelling() {
        // `consumes_a_value` reads the long spelling alone; a short one on a
        // value-taking flag would make `-x VALUE` read its value as a token.
        for decl in std::iter::once(&ROOT).chain(SURFACE) {
            for flag in decl.flags.iter().filter(|flag| !flag.positional) {
                assert!(
                    !(takes_value(flag) && flag.short.is_some()),
                    "{}: -{:?} takes a value; give `consumes_a_value` its short arm back",
                    decl.path,
                    flag.short
                );
            }
        }
    }

    #[test]
    fn clap_accepts_the_built_tree() {
        // `debug_assert` walks the whole tree and panics on a malformed arg —
        // the cheapest total check that a new declaration is constructible.
        command().debug_assert();
    }
}
