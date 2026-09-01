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
    /// A repeatable free-form string, whose occurrences accumulate in order.
    ///
    /// Deliberately not [`ValueDecl::Str`], for [`ValueDecl::Count`]'s reason one
    /// type over: `ArgAction::Set` keeps only the LAST occurrence, so a second
    /// `--tool` would silently discard the first rather than widening the
    /// selection. Silently, because clap reports nothing — which is the shape
    /// that makes a narrowed selector look like a clean answer.
    ///
    /// The alternative — one string the verb splits on a separator — was
    /// rejected: it puts a second parser in front of a value a caller wrote, and
    /// a tool name containing the separator would then be unrepresentable.
    ///
    /// APPENDED rather than placed beside [`ValueDecl::Str`], where it belongs by
    /// meaning. This enum carries no `repr`, so a variant inserted in the middle
    /// shifts every later discriminant and `mise run semver` reads that as a break
    /// the crate has to declare — measured here, as
    /// `enum_no_repr_variant_discriminant_changed` over `Trailing` and `Enum`.
    /// Declaration order is a contract with nothing: the table is matched
    /// exhaustively and the order a reader sees is `SURFACE`'s.
    StrMany,
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

    /// An optional flag taking one token of a `ValueEnum`, with **no** default.
    ///
    /// Distinct from [`FlagDecl::defaulted_enum`] on purpose: a default would
    /// make "the caller named no host" indistinguishable from "the caller named
    /// this one", and that distinction is the whole contract of
    /// `attribution check --harness` — an unnamed host declares nothing, which is
    /// not the same claim as any host's row (CLOUD-276).
    const fn optional_enum(
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
            required: false,
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
    ///
    /// The HUMAN spelling, and the one thing about a row that is expected to
    /// change. Pin a consumer against [`CommandDecl::id`] instead.
    pub path: &'static str,
    /// The stable identity a third party pins against (CLOUD-969).
    ///
    /// # Why this is declared rather than derived
    ///
    /// An id computed from `path` is the path with extra steps: it re-breaks on
    /// exactly the rename it exists to survive. This is a LITERAL, and the whole
    /// of its contract is that **it is not edited when `path` changes** — a
    /// rename moves the spelling and leaves the identity alone, which is what
    /// lets a consumer's pinned read-only allowlist keep matching.
    ///
    /// The initial values were seeded from the paths as they stood when this
    /// field landed, because a seed has to come from somewhere and an arbitrary
    /// one would be unreadable in `spec.rs`'s committed row set. That seeding is
    /// a one-time event and emphatically not a rule: the resemblance between an
    /// id and its path today is history, not a derivation, and re-deriving one
    /// later would undo the field.
    pub id: &'static str,
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
/// `--range <base>..<head>` on `attribution check` (CLOUD-274).
///
/// The range is the caller's, never derived here: `verify` and CI's commit-lint
/// job already agree on which commits a branch produced, and a second derivation
/// would be a second authority for that. Absent means message mode.
/// Positional, because the range IS the verb's object — the thing being judged,
/// the way `lint brief <path>` names its file. A flag would read as a modifier on
/// a verb that has some other default subject, and there is deliberately no such
/// default: deriving one here would be a second authority for "which commits did
/// this branch produce".
const RANGE: FlagDecl = FlagDecl {
    id: "range",
    long: None,
    short: None,
    help: "Judge every non-merge commit in this range (<base>..<head>)",
    env: EnvDecl::None,
    global: false,
    positional: true,
    required: false,
    hidden: false,
    rung: Rung::None,
    value: ValueDecl::Str,
};

/// The pull request every `pr` bot-lane verb is about (CLOUD-1295).
///
/// Positional and required, for `RANGE`'s reason: the pull request IS the verb's
/// object, and there is deliberately no default. Deriving one from the checked-out
/// branch would be a second authority for "which PR is this", and the lander that
/// calls these verbs already knows the number — it is the thing the tick is about.
const PR_NUMBER: FlagDecl =
    FlagDecl::positional("pr", "The pull request number this verb is about");

/// The tracker key `pr link` writes into a body.
///
/// Also positional and also required: `link` takes two objects and neither is
/// derivable here. The key comes from the tracker's own sync, which `pr ensure`
/// reads and this verb is handed.
const ISSUE_KEY: FlagDecl =
    FlagDecl::positional("key", "The tracker key the pull request should close");

/// `--root <dir>` on `target prune`.
///
/// The suite's seam for WHICH TREE, and the twin of the free-space override the
/// module reads: a case has to be able to set the tree as exactly as it sets the
/// space, or it is answered by whatever the host's real build directory happens
/// to hold. Naming a root also changes how an absent one READS — somebody asked
/// about a specific tree and it is not there, which is could-not-look, where the
/// default may simply not have been built yet.
const PRUNE_ROOT: FlagDecl = FlagDecl {
    id: "root",
    long: Some("root"),
    short: None,
    help: "The build directory to prune, instead of the configured one",
    env: EnvDecl::None,
    global: false,
    positional: false,
    required: false,
    hidden: false,
    rung: Rung::None,
    value: ValueDecl::Str,
};

/// `--baseline <rev>` on `semver check` (CLOUD-1050).
///
/// The rev the API delta is measured against. Overridable because the suite has
/// to drive a resolvable baseline and an unresolvable one to tell the two routes
/// apart — never so a caller can weaken the gate in passing, which is why the
/// RELEASE TYPE below carries the stronger warning of the two.
const SEMVER_BASELINE: FlagDecl = FlagDecl {
    id: "baseline",
    long: Some("baseline"),
    short: None,
    help: "The rev to measure the API delta against (default: origin/main)",
    env: EnvDecl::None,
    global: false,
    positional: false,
    required: false,
    hidden: false,
    rung: Rung::None,
    value: ValueDecl::Str,
};

/// `--release-type <patch|minor|major>` on `semver check` (CLOUD-1050).
///
/// The bump being CLAIMED, and stating it is what makes the comparison real: a
/// branch carries the same version as its baseline — release-plz bumps on
/// landing, not before — so without this the tool assumes a major release is
/// coming and every break is compatible with it. Measured: 0 checks graded
/// without it, 223 with.
const SEMVER_RELEASE_TYPE: FlagDecl = FlagDecl {
    id: "release_type",
    long: Some("release-type"),
    short: None,
    help: "The bump being claimed, which is what the delta is judged against",
    env: EnvDecl::None,
    global: false,
    positional: false,
    required: false,
    hidden: false,
    rung: Rung::None,
    value: ValueDecl::Str,
};

/// `--package <name>` on `semver check` (CLOUD-1050).
const SEMVER_PACKAGE: FlagDecl = FlagDecl {
    id: "package",
    long: Some("package"),
    short: None,
    help: "The package whose public API is compared (default: batten)",
    env: EnvDecl::None,
    global: false,
    positional: false,
    required: false,
    hidden: false,
    rung: Rung::None,
    value: ValueDecl::Str,
};

/// `--message <file>` on `attribution check` (CLOUD-274) and `commit check`
/// (CLOUD-701).
///
/// The commit-time seam. The message is on disk and git already resolves the
/// identity it will stamp, so a refusal here means the offending commit is never
/// created rather than created and found later in a range.
const MESSAGE: FlagDecl = FlagDecl {
    id: "message",
    long: Some("message"),
    short: None,
    help: "Judge one pending commit message file, before the commit exists",
    env: EnvDecl::None,
    global: false,
    positional: false,
    required: false,
    hidden: false,
    rung: Rung::None,
    value: ValueDecl::Str,
};

/// `--harness <host>` on `attribution check` (CLOUD-276).
///
/// Optional, and it changes **no verdict**. The findings and the exit code are
/// identical with it and without it, on every host — that is the invariant the
/// row set exists to protect: enforcement seams are git-native and cannot vary by
/// host, because a produced commit carries no record of which host made it. What
/// the flag selects is the *capture* half: which declarations the emitted document
/// reports, and at what fidelity a caller field may be recorded.
///
/// Absent means no host was named, which is its own answer — three degraded
/// provenance values and no declarations — and not a stand-in for some default
/// host.
const ATTRIBUTION_HARNESS: FlagDecl = FlagDecl::optional_enum(
    "harness",
    "harness",
    "Report the attribution capabilities this host declares, and capture at that fidelity",
    harness_parser,
);

/// `--against <ref>` on `config deprecations` (CLOUD-360).
///
/// The ref whose PUBLISHED schema the current one is compared against — normally
/// the latest release tag, which the `mise` task resolves and passes rather than
/// this binary enumerating tags. Named rather than defaulted: a gate that picked
/// its own baseline could quietly compare against something that makes it pass.
const AGAINST: FlagDecl = FlagDecl {
    id: "against",
    long: None,
    short: None,
    help: "The git ref whose published schema is the baseline (e.g. v0.0.111)",
    env: EnvDecl::None,
    global: false,
    // POSITIONAL and required, which is how every other verb takes the one input
    // it cannot work without. Not defaulted: a gate that picked its own baseline
    // could quietly choose one that makes it pass.
    positional: true,
    required: true,
    hidden: false,
    rung: Rung::None,
    value: ValueDecl::Str,
};

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

/// `--tee` on `exec` (CLOUD-429).
///
/// The escape from the token-kind default, and it restores the previous
/// behaviour **verbatim** rather than approximating it — which is why
/// `exec_inherits_both_child_streams_unchanged` was re-pointed at this flag
/// rather than deleted. The property it asserts still holds; it just needs
/// asking for now.
const TEE: FlagDecl = FlagDecl {
    id: "tee",
    long: Some("tee"),
    short: None,
    help: "Copy the child's streams onto Batten's own, as well as capturing them",
    env: EnvDecl::None,
    global: false,
    positional: false,
    required: false,
    hidden: false,
    rung: Rung::None,
    value: ValueDecl::Bool,
};

/// `--jobs` on `exec` (CLOUD-430), with mise's name and mise's meaning.
///
/// Declared with no default so "the caller did not ask" stays distinguishable
/// from "the caller asked for one" — the committed `[exec]` table sets the
/// default, and a flag clap filled in would outrank it on every call.
const JOBS: FlagDecl = FlagDecl {
    id: "jobs",
    long: Some("jobs"),
    short: None,
    help: "How many of a `:::` bundle's commands run at once",
    env: EnvDecl::None,
    global: false,
    positional: false,
    required: false,
    hidden: false,
    rung: Rung::None,
    value: ValueDecl::Str,
};

/// `--continue-on-error` on `exec` (CLOUD-430), likewise mise's.
const CONTINUE_ON_ERROR: FlagDecl = FlagDecl {
    id: "continue_on_error",
    long: Some("continue-on-error"),
    short: None,
    help: "Run the rest of a `:::` bundle after a command fails",
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
/// The verdict token `policy explain` resolves (CLOUD-1053).
///
/// Positional and REQUIRED. `explain` with no token would have to either print
/// the whole registry — a payload nobody asked for, on a surface whose payload
/// exception is narrow and deliberate — or exit 0 having answered nothing, which
/// is the vacuous pass in a documentation verb.
const VERDICT_TOKEN: FlagDecl = FlagDecl {
    id: "token",
    long: None,
    short: None,
    help: "The verdict token to resolve, e.g. task name undefined",
    env: EnvDecl::None,
    global: false,
    positional: true,
    required: true,
    hidden: false,
    rung: Rung::None,
    value: ValueDecl::Str,
};

/// `--rule <id>` on `check`: run one declared row rather than all of them
/// (CLOUD-1051).
///
/// # What this is for, and it is not a convenience
///
/// A gate ported out of `mise-tasks/` into a `[[rule]]` row loses its task name,
/// and every lifecycle step that invoked it by name breaks. The alternative was
/// to edit those callers — which for `land.sh` means editing an authored shell
/// rule `shell-retirement` refuses to see edited, so the migration would have had
/// to retire the landing loop to move one gate. This is the narrowing that makes
/// a migrated row invocable by name instead, so a caller stays byte-identical
/// and out of the changed-file set.
///
/// **A `--rule` naming no declared row is a usage error, never a clean run.** A
/// filter that matched nothing and exited 0 is the vacuous pass in its purest
/// form: the caller would read "the gate passed" from a gate that was never
/// selected, and a renamed row would silently stop being enforced.
const CHECK_RULE: FlagDecl = FlagDecl {
    id: "rule",
    long: Some("rule"),
    short: None,
    help: "Run only the declared rules with these ids (repeatable)",
    env: EnvDecl::None,
    global: false,
    positional: false,
    required: false,
    hidden: false,
    rung: Rung::None,
    value: ValueDecl::StrMany,
};

/// `--rule <id>` on `enforce`: the same narrowing, on the verb that spawns.
///
/// # This reverses a recorded decision, and that decision named its condition
///
/// `RunRequest::spawning` said `enforce` was "deliberately NOT narrowable",
/// because "every caller that needs it is a `check` caller" and offering it here
/// "would be surface nobody asked for, on the verb that spawns". The reasoning
/// was sound and the condition it rested on has since failed: a caller exists.
///
/// `the_committed_delegating_rule_spawns_nothing_when_its_glob_misses` asserts a
/// property OF a `kind = "command"` row — that a glob miss spawns nothing — so
/// `check` must refuse it by construction (`V-SPAWN-ON-READ-VERB`, and the verb
/// is the thing that is wrong there, not the rule). It therefore cannot take the
/// `check` narrowing, and without one it evaluates all 103 rows to assert one.
/// Measured on the Windows runner, 2026-09-01: 206s of a 1482s suite, on the
/// job that is the critical path and bills at 2x.
///
/// So the surface is no longer unasked-for. It is asked for by the one shape the
/// original reasoning could not have covered — a case whose SUBJECT is a
/// spawning row.
///
/// # Everything `CHECK_RULE` refuses, this refuses identically
///
/// A `--rule` naming no declared row is a usage error, never a clean run. That
/// property matters more here, not less: a narrowed spawn that silently selected
/// nothing would report "the gate passed" from a gate that never ran, on the
/// surface that is allowed to execute configured commands.
const ENFORCE_RULE: FlagDecl = FlagDecl {
    id: "rule",
    long: Some("rule"),
    short: None,
    help: "Run only the declared rules with these ids (repeatable)",
    env: EnvDecl::None,
    global: false,
    positional: false,
    required: false,
    hidden: false,
    rung: Rung::None,
    value: ValueDecl::StrMany,
};

/// `--staged` on `check`: judge the index rather than the whole tree (CLOUD-519).
///
/// A pre-commit hook, or an agent's mediated call, re-reads every file in the
/// repository to judge the two the caller just touched. House style §4 asks a
/// gate to be cheap when it is irrelevant, and the caller's own change-set is the
/// mechanism that makes it so.
///
/// **It narrows the INPUTS and never the verdict.** A file this selects is judged
/// byte-identically to how an unnarrowed run judges it, and one it does not
/// select is not reported as clean — it is not looked at, which is what the
/// caller asked for. A ratchet is exempt; `rules::Scope` carries why.
const CHECK_STAGED: FlagDecl = FlagDecl {
    id: "staged",
    long: Some("staged"),
    short: None,
    help: "Judge only the paths staged in the git index",
    env: EnvDecl::None,
    global: false,
    positional: false,
    required: false,
    hidden: false,
    rung: Rung::None,
    value: ValueDecl::Bool,
};

/// `--instant <epoch>`: the clock time-dependent records are read against,
/// handed in rather than taken (CLOUD-1170).
///
/// **This flag supplies a value the boundary already needs and today reads for
/// itself.** `Rule::max_age` declares how old a receipt may be, and
/// `receipt::verdicts` is handed a `now` to compare against — *"the waiver
/// table's precedent, so the decision this feeds stays a pure function of facts
/// somebody else resolved"*. Everything about that division is landed; the one
/// remaining clock READ is the boundary filling `now` in from the system clock,
/// and that is what makes a `max_age` verdict differ between two evaluations over
/// an identical tree.
///
/// Handing it in closes that. The module still reads a resolved
/// `receipt::Validity` — `Valid`, `Expired`, `Missing` — and never an integer, so
/// no predicate does arithmetic over a timestamp and there is no second authority
/// over time.
///
/// **On `hook` and on `task alive`, never on `check`.** `check` compares no
/// receipts and reads no ages, so the flag would have been dead surface there.
/// The two commands that carry it are the two that measure elapsed time: a
/// mediated call reading a `max_age` bound, and the registry reader rendering
/// how long a task has been where it is.
///
/// **Absent means what it always meant.** A caller that passes none gets the
/// boundary clock and today's behaviour exactly, so no committed row changes
/// meaning by this flag arriving — `max_age`'s own doc takes the same care for
/// the same reason. What the flag buys is a caller that WANTS reproducibility
/// being able to have it.
///
/// The caller reads the clock, which is prior art and stays outside: `date -u
/// +%s` in whatever wrapper the consumer invokes this through is exactly where
/// that read belongs.
const HOOK_INSTANT: FlagDecl = FlagDecl {
    id: "instant",
    long: Some("instant"),
    short: None,
    help: "The epoch second to judge time-dependent records against, supplied as data",
    env: EnvDecl::None,
    global: false,
    positional: false,
    required: false,
    hidden: false,
    rung: Rung::None,
    value: ValueDecl::Str,
};

/// The task name a registration records.
const TASK_NAME: FlagDecl = FlagDecl::positional("task", "The task's name, as its callers know it");

/// The process a record is keyed by.
///
/// Positional and required on every leaf, because the pid IS the record's
/// identity — the thing being written or read — the way `lint brief <path>` names
/// its file. A flag would read as a modifier on a verb with some other default
/// subject, and there deliberately is no default: guessing a pid is how a prober
/// ends up reporting on the asking process, which is the measured defect the
/// registry exists to replace.
const TASK_PID: FlagDecl = FlagDecl::positional("pid", "The process the record is keyed by");

/// What a task is doing at registration.
///
/// Optional, and defaulted in the verb rather than here: an empty phase renders
/// as `unknown`, which is a claim about the record, and a task that has only just
/// registered is `starting`, which is a fact about it.
const TASK_PHASE: FlagDecl =
    FlagDecl::positional_optional("phase", "What the task is doing; absent is `starting`");

/// The value a `phase`, `tick` or `sig` push carries.
///
/// One spelling across the three, because the stamp rule is one rule: a stamp
/// moves only when its value CHANGES (CLOUD-499), whichever field it belongs to.
const TASK_VALUE: FlagDecl = FlagDecl::positional(
    "value",
    "The value to record; its stamp moves only when it changes",
);

/// Which field of a record to print.
const TASK_FIELD: FlagDecl = FlagDecl::positional("field", "The record field to print");

/// `--program-root <dir>` on `task alive`: where the CONSUMER keeps its programs.
///
/// Non-negotiable rule 1, as a flag. Corroborating that a live pid is still the
/// task that registered it means matching the task's own name inside the
/// process's `cmdline`, and *where a consumer keeps its programs* is a fact about
/// that consumer — `document_facts::no_artifact_name_reaches_the_core` refuses a
/// manifest name in this crate for exactly the same reason.
///
/// Required rather than defaulted. A default would be one consumer's layout
/// promoted to the engine's, and it would fail SILENTLY everywhere else: an
/// unmatched corroboration reads as alive, so a wrong root produces a registry
/// that never reports a crash and looks like one that has nothing to report.
const TASK_PROGRAM_ROOT: FlagDecl = FlagDecl {
    id: "program_root",
    long: Some("program-root"),
    short: None,
    help: "The directory this consumer keeps its task programs in, matched inside a live process's cmdline",
    env: EnvDecl::None,
    global: false,
    positional: false,
    required: true,
    hidden: false,
    rung: Rung::None,
    value: ValueDecl::Str,
};

/// `--since <rev>` on `check`: judge what changed against a rev (CLOUD-519).
///
/// [`CHECK_STAGED`]'s sibling, for the caller who knows a base rather than an
/// index — a CI step judging a branch, or a hook judging a push range.
///
/// **An unresolvable rev is a usage error, never a clean run over nothing**, for
/// the reason [`CHECK_RULE`] states at greater length: a narrowing that matched
/// nothing and exited `0` reads to its caller as a gate that passed.
const CHECK_SINCE: FlagDecl = FlagDecl {
    id: "since",
    long: Some("since"),
    short: None,
    help: "Judge only the paths changed against this rev",
    env: EnvDecl::None,
    global: false,
    positional: false,
    required: false,
    hidden: false,
    rung: Rung::None,
    value: ValueDecl::Str,
};

/// `--admission <address>`: which issued record is being spent.
///
/// A positional would have read better, and it is a flag for the reason the
/// three beside it are: `spend` names a SITUATION as well as a record, and a
/// caller who transposed two positionals would present a valid admission against
/// the wrong subject. Every term is named at the call site.
const OVERRIDE_ADMISSION: FlagDecl = FlagDecl {
    id: "admission",
    long: Some("admission"),
    short: None,
    help: "The admission address to spend",
    env: EnvDecl::None,
    global: false,
    positional: false,
    required: true,
    hidden: false,
    rung: Rung::None,
    value: ValueDecl::Str,
};

/// `--rule <id>`: which gate's refusal an admission is requested against.
const OVERRIDE_RULE: FlagDecl = FlagDecl {
    id: "rule",
    long: Some("rule"),
    short: None,
    help: "The rule whose refusal is being overridden",
    env: EnvDecl::None,
    global: false,
    positional: false,
    required: true,
    hidden: false,
    rung: Rung::None,
    value: ValueDecl::Str,
};

/// `--verdict <token>`: which declared class that refusal belongs to.
///
/// Required rather than derived from the rule, because one rule can refuse under
/// more than one class and an admission minted against one must not be
/// presentable against another (CLOUD-1051's binding).
const OVERRIDE_VERDICT: FlagDecl = FlagDecl {
    id: "verdict",
    long: Some("verdict"),
    short: None,
    help: "The verdict token that refusal carries, e.g. diff ship early",
    env: EnvDecl::None,
    global: false,
    positional: false,
    required: true,
    hidden: false,
    rung: Rung::None,
    value: ValueDecl::Str,
};

/// `<branch>`: the branch a lease verb is asked about.
///
/// **Positional and REQUIRED, and the requirement is the point.** A lease verb
/// with no branch cannot answer, and a verb that cannot answer must say so rather
/// than defaulting to either verdict — defaulting to the checkout's own branch
/// would be worse than either, since the caller may legitimately be asking on
/// behalf of a checkout this process is not in.
const LEASE_BRANCH: FlagDecl = FlagDecl::positional("branch", "The branch being asked about");

/// `<reference>`: the remote reference `land replay` replays onto.
///
/// **Positional and REQUIRED, for [`LEASE_BRANCH`]'s reason and one more.**
/// Defaulting to the remote's own default branch would make the verb guess which
/// trunk this consumer lands on, and a wrong guess replays the branch onto the
/// wrong base and mints a head nobody asked for — a write, not a report. The
/// caller knows; the engine does not.
const LAND_REFERENCE: FlagDecl =
    FlagDecl::positional("reference", "The remote reference to replay onto");

/// `<field>`: which advisory field `lease peek` prints.
///
/// A closed set, because the whole value of `peek` over reading the status prose
/// is that a caller can ACT on the answer: a field name that is merely echoed back
/// would make an unknown one print nothing and read as an unset field.
const LEASE_FIELD: FlagDecl = FlagDecl::positional(
    "field",
    "Which advisory field to print: branch, head or next",
);

/// `--subject <s>`: the gate's own canonical spelling of what it refused about.
const OVERRIDE_SUBJECT: FlagDecl = FlagDecl {
    id: "subject",
    long: Some("subject"),
    short: None,
    help: "The gate's canonical subject, exactly as its refusal names it",
    env: EnvDecl::None,
    global: false,
    positional: false,
    required: true,
    hidden: false,
    rung: Rung::None,
    value: ValueDecl::Str,
};

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
/// `--prune` on `baseline` (CLOUD-67).
///
/// The staleness half of the baseline lifecycle, and a flag rather than a
/// `baseline prune` sub-verb because the Ready block spells it that way and
/// because both spellings do the same thing to the same artifact: re-evaluate,
/// then write. A sub-verb would put one store behind two paths.
///
/// It does **not** raise the effect (§5's `max_effect` is a monotone maximum, and
/// this stays at `write`): pruning removes only entries whose backing finding no
/// longer exists, and every one of them is recreated by running `baseline` again.
const PRUNE: FlagDecl = FlagDecl {
    id: "prune",
    long: Some("prune"),
    short: None,
    help: "Drop baseline entries whose finding no longer exists, and ratchet reduced counts down",
    env: EnvDecl::None,
    global: false,
    positional: false,
    required: false,
    hidden: false,
    rung: Rung::None,
    value: ValueDecl::Bool,
};

/// `--repair` on `startup` (CLOUD-1324): make the environment fixes, do not
/// only report them.
///
/// **Opt-in, and the opt-in is the point.** Bare `batten startup` decides every
/// `[[startup]]` row and mutates nothing; this flag is what turns the same rows
/// into repairs. A person or a setup script reaching for it has to say so, which
/// is what makes "batten will change your environment" a thing written on the
/// command line rather than a thing a reader has to infer from a config file.
///
/// It is deliberately NOT `--yes`. `-y` pre-answers a confirmation a destructive
/// verb would otherwise refuse without; this selects a different mode of a verb
/// that is perfectly useful without it.
/// `--check` on `wiring reclaim` (CLOUD-1324): decide whether a repair is owed.
///
/// The CHECK HALF of a verb that was only ever the fix half. `doctor hooks`
/// reports `merged_siblings` as a COUNT and deliberately never as a failure —
/// whether a hook beside batten's is legitimate is a consumer's judgement, which
/// the engine may not make. A `[[startup]]` row is where a consumer now makes
/// it, and a row needs a command that DECIDES; this is that command, over the
/// same surfaces and the same selector the repair uses.
///
/// It reuses `--dry-run`'s whole computation and differs only in the exit code,
/// which is what keeps the two answers from being able to disagree.
const CHECK: FlagDecl = FlagDecl {
    id: "check",
    long: Some("check"),
    short: None,
    help: "Exit non-zero if a repair is owed, and remove nothing",
    env: EnvDecl::None,
    global: false,
    positional: false,
    required: false,
    hidden: false,
    rung: Rung::None,
    value: ValueDecl::Bool,
};

const REPAIR: FlagDecl = FlagDecl {
    id: "repair",
    long: Some("repair"),
    short: None,
    help: "Run each failing row's declared repair, then re-decide its check",
    env: EnvDecl::None,
    global: false,
    positional: false,
    required: false,
    hidden: false,
    rung: Rung::None,
    value: ValueDecl::Bool,
};

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

/// `--capture-only` on `exec` (CLOUD-121): handles instead of the bytes.
///
/// Opt-in, and it must stay opt-in. `exec`'s transparency is a promise every
/// wrapped command's caller relies on (CLOUD-285), so a wrapper that decided for
/// itself when to swallow a build's output would be unpredictable exactly where
/// predictability matters most. Inferring it from output size was considered and
/// rejected for that reason: the threshold would be a policy nobody declared.
///
/// It raises nothing under §5 — `exec` is already unclassified, and this changes
/// where the child's bytes go, never what may run.
const CAPTURE_ONLY: FlagDecl = FlagDecl {
    id: "capture_only",
    long: Some("capture-only"),
    short: None,
    help: "Store the child's streams and report their handles instead of passing the bytes through",
    env: EnvDecl::None,
    global: false,
    positional: false,
    required: false,
    hidden: false,
    rung: Rung::None,
    value: ValueDecl::Bool,
};

/// `--lines A:B` on `capture show`: a 1-indexed, inclusive, clamped window.
///
/// One flag taking a range rather than `--from`/`--to`, because the two are never
/// meaningful apart and a pair of flags would need a rule for each half being
/// absent. Clamped rather than validated against the capture's length: widening a
/// window is the point, and an out-of-range end is a caller who wants the rest.
const LINES: FlagDecl = FlagDecl {
    id: "lines",
    long: Some("lines"),
    short: None,
    help: "A 1-indexed inclusive line range, `FROM:TO`, clamped to the capture",
    env: EnvDecl::None,
    global: false,
    positional: false,
    required: false,
    hidden: false,
    rung: Rung::None,
    value: ValueDecl::Str,
};

/// `--grep <literal>` on `capture show`: a case-sensitive literal substring.
///
/// Literal, not regex, for the reason [`crate::outputs`] gives about its own
/// predicate: a reader should be able to see what would match without evaluating
/// an expression. CLOUD-283 took the regex decision narrowly, for `forbid` alone,
/// and this is one of the places it was deliberately not taken.
const GREP: FlagDecl = FlagDecl {
    id: "grep",
    long: Some("grep"),
    short: None,
    help: "Only lines containing this literal substring",
    env: EnvDecl::None,
    global: false,
    positional: false,
    required: false,
    hidden: false,
    rung: Rung::None,
    value: ValueDecl::Str,
};

/// `--raw` on `capture show`: the selected bytes, verbatim (CLOUD-918).
///
/// **The one operation in this binary whose output is not text**, and therefore
/// the one that must never appear under `-J`: a raw byte stream and a byte-stable
/// JSON document are different contracts, and a flag combination that had to pick
/// one silently is how a caller ends up with base64 where it wanted bytes. So
/// `--raw` with `--json`, `--lines` or `--grep` is refused rather than resolved.
///
/// It is an ENCODING rather than a selector: `--bytes` chooses what to read and
/// this chooses how it leaves the process. `--raw` alone is the whole capture.
const RAW: FlagDecl = FlagDecl {
    id: "raw",
    long: Some("raw"),
    short: None,
    help: "Write the selected bytes to stdout verbatim, with no decode and no added newline",
    env: EnvDecl::None,
    global: false,
    positional: false,
    required: false,
    hidden: false,
    rung: Rung::None,
    value: ValueDecl::Bool,
};

/// `--bytes FROM:TO` on `capture show`: a byte range (CLOUD-918).
///
/// 0-indexed and half-open where [`LINES`] is 1-indexed and inclusive, which is
/// deliberate: byte ranges have to tile, so `0:N` then `N:M` must cover a record
/// exactly once. Either half may be omitted. Clamped for [`LINES`]'s reason — an
/// out-of-range end is a caller who wants the rest — while a MALFORMED bound is a
/// usage error, because a caller who wrote nonsense should be told rather than
/// handed a plausible answer.
const BYTES: FlagDecl = FlagDecl {
    id: "bytes",
    long: Some("bytes"),
    short: None,
    help: "A 0-indexed half-open byte range, `FROM:TO`, either side omittable, clamped to the \
           capture",
    env: EnvDecl::None,
    global: false,
    positional: false,
    required: false,
    hidden: false,
    rung: Rung::None,
    value: ValueDecl::Str,
};

/// `--calls` on `capture list`: the per-call provenance view (CLOUD-918).
///
/// A second view over the same store rather than a second verb, because the
/// question is the same one — what does this repository hold — asked on the
/// invocation axis instead of the content axis. The blob listing answers "which
/// bytes", this answers "which calls", and dedup collapses the first without
/// collapsing the second.
const CALLS: FlagDecl = FlagDecl {
    id: "calls",
    long: Some("calls"),
    short: None,
    help: "List recorded calls instead of stored captures, in a byte-stable order",
    env: EnvDecl::None,
    global: false,
    positional: false,
    required: false,
    hidden: false,
    rung: Rung::None,
    value: ValueDecl::Bool,
};

/// `--stream <stdout|stderr>` on `capture list`: narrow the listing.
///
/// A plain string rather than a `ValueEnum`, because the set it validates against
/// is [`crate::capture::Stream::ALL`] — the same list the store keys by. A second
/// enum here would be a place for the two to disagree about what a stream is.
const STREAM: FlagDecl = FlagDecl {
    id: "stream",
    long: Some("stream"),
    short: None,
    help: "Only captures of this stream",
    env: EnvDecl::None,
    global: false,
    positional: false,
    required: false,
    hidden: false,
    rung: Rung::None,
    value: ValueDecl::Str,
};

/// `--tool <name>` on `capture find` (CLOUD-1121): repeatable, and required.
///
/// Required rather than defaulted, because the default that suggests itself —
/// "any tool" — is the one that silently resolves an issue key out of whatever
/// response happened to carry it. Naming the tool is what makes the answer a
/// statement about a read rather than about a coincidence.
///
/// Repeatable because the newest response carrying a key is not always a read:
/// a lint straight after a write must see the body the write stored (CLOUD-1118).
const TOOL: FlagDecl = FlagDecl {
    id: "tool",
    long: Some("tool"),
    short: None,
    help: "The tool whose response to resolve, matched whole or as a `__`-delimited final segment; \
           repeatable",
    env: EnvDecl::None,
    global: false,
    positional: false,
    required: true,
    hidden: false,
    rung: Rung::None,
    value: ValueDecl::StrMany,
};

/// `--key-at <path>` on `capture find`: where the key sits in the response.
///
/// Defaulted to `id` because that is what every tracker payload this repository
/// reads spells it, and the same dotted-path selector `[[mint]]` keys a receipt
/// on resolves it — one addressing scheme, so a resolver cannot look a payload up
/// under a key nothing filed it by.
const KEY_AT: FlagDecl = FlagDecl {
    id: "key_at",
    long: Some("key-at"),
    short: None,
    help: "The dotted path the key sits at in the response",
    env: EnvDecl::None,
    global: false,
    positional: false,
    required: false,
    hidden: false,
    rung: Rung::None,
    value: ValueDecl::Str,
};

/// `--issue <KEY>` on `ready lint` (CLOUD-1121): resolve the payload by key.
///
/// **The point of the flag is what does NOT happen.** Without it the payload
/// arrives on stdin, which means somebody read it — and a read a model performs
/// is a payload in context, re-sent every turn for the rest of the session. With
/// it the bytes come off the capture store, where the engine already wrote them,
/// and nothing enters context at all.
///
/// **Never a silent fallback to stdin.** A resolve that fails is could-not-look,
/// because falling through on an empty stdin would report a refined issue as
/// carrying no Ready block — a verdict about the store wearing the costume of a
/// verdict about the issue.
const ISSUE: FlagDecl = FlagDecl {
    id: "issue",
    long: Some("issue"),
    short: None,
    help: "Resolve the payload from the capture store by this issue key instead of reading stdin",
    env: EnvDecl::None,
    global: false,
    positional: false,
    required: false,
    hidden: false,
    rung: Rung::None,
    value: ValueDecl::Str,
};

/// The roster `checks green` decides against (CLOUD-1143).
///
/// **Flags rather than environment variables, and that is rule 1 rather than
/// taste.** The predecessor read four environment variables directly, which put
/// a consumer's env contract inside the decision. Here the caller passes what it
/// declares and keeps its own authority for where that is written down, so the
/// crate holds no name belonging to anybody's CI — including the name of the
/// file they keep it in, which is what this comment previously got wrong.
///
/// Required, because an empty roster makes every check unrequired, which is the
/// false green the whole verb exists to stop. `--absent-ok` is deliberately
/// optional: absent means the STRICT direction, where every roster name must be
/// present (CLOUD-337).
const REQUIRED_CHECKS: FlagDecl = FlagDecl {
    id: "required",
    long: Some("required"),
    short: None,
    help: "Comma-separated check names that carry a verdict about this repository",
    env: EnvDecl::None,
    global: false,
    positional: false,
    required: true,
    hidden: false,
    rung: Rung::None,
    value: ValueDecl::Str,
};

/// `--absent-ok` on `checks green`: the names for which NO run is legitimate.
///
/// A path-filtered workflow produces no check-run at all, so requiring every
/// name would hang the poll. Unset is the strict direction on purpose: the two
/// failures are not symmetric — a name this waits for that never arrives is a
/// visible, self-naming stall, while a name it forgives that had merely not
/// registered yet is a landing nobody judged.
const ABSENT_OK_CHECKS: FlagDecl = FlagDecl {
    id: "absent_ok",
    long: Some("absent-ok"),
    short: None,
    help: "Comma-separated check names for which having no run at all is a legitimate reading",
    env: EnvDecl::None,
    global: false,
    positional: false,
    required: false,
    hidden: false,
    rung: Rung::None,
    value: ValueDecl::Str,
};

/// `--answered` on `checks green`: the conclusions that constitute an answer.
///
/// Required for the same reason the roster is. Membership rather than a literal
/// pair (CLOUD-376): naming `skipped` and `cancelled` and letting everything
/// else fall through to red would report a conclusion the forge adds tomorrow as
/// a verdict against a head it never judged.
const ANSWERED_CONCLUSIONS: FlagDecl = FlagDecl {
    id: "answered",
    long: Some("answered"),
    short: None,
    help: "Comma-separated conclusions that constitute an answer; anything else is not yet one",
    env: EnvDecl::None,
    global: false,
    positional: false,
    required: true,
    hidden: false,
    rung: Rung::None,
    value: ValueDecl::Str,
};

/// `--fanin` on `checks green`: the one check whose failure is manufacturable.
///
/// A fan-in declares `needs:` over its siblings, so cancelling them makes it
/// fail without judging anything (CLOUD-363, measured on #293). That is true of
/// the fan-in and of nothing else — `ci` failing judges the tree directly and no
/// cancellation can produce it (CLOUD-900).
///
/// **Optional, and the unset direction is the safe one.** With no name given
/// every failure stays manufacturable, which is CLOUD-363's ordering intact:
/// forgetting it costs a poll that holds too long, where the opposite default
/// would report a manufactured failure as a verdict and wedge the branch.
/// `--sha` on `pr watch`: the commit whose check runs are read.
///
/// Required, and deliberately not defaulted to a resolved `HEAD`. A poll that
/// picks its own subject would answer about a commit the caller never named, and
/// the caller — which knows whether it means its working tree, a lease holder's
/// head, or a commit it just pushed — is the one place that distinction exists.
const WAIT_SHA: FlagDecl = FlagDecl {
    id: "sha",
    long: Some("sha"),
    short: None,
    help: "The commit whose check runs to read",
    env: EnvDecl::None,
    global: false,
    positional: false,
    required: true,
    hidden: false,
    rung: Rung::None,
    value: ValueDecl::Str,
};

/// `--repo` on `pr watch`: which repository, in the client's own spelling.
///
/// Optional, because the client resolves its own placeholder from the checkout's
/// remote — which is the right answer wherever a checkout exists. A caller that
/// has no checkout, or that means a different repository than the one it stands
/// in, says so here.
const WAIT_REPO: FlagDecl = FlagDecl {
    id: "repo",
    long: Some("repo"),
    short: None,
    help: "The repository to read, in the forge client's own spelling",
    env: EnvDecl::None,
    global: false,
    positional: false,
    required: false,
    hidden: false,
    rung: Rung::None,
    value: ValueDecl::Str,
};

/// `--interval` on `pr watch`: seconds between requests.
///
/// A FLOOR, never a schedule: a server that asks to be polled less often raises
/// it and nothing lowers it. The poll is conditional, so an unchanged reading
/// costs no rate limit at all — which is what makes a short interval affordable
/// and why the news no longer has to arrive late.
const WAIT_INTERVAL: FlagDecl = FlagDecl {
    id: "interval",
    long: Some("interval"),
    short: None,
    help: "Seconds between requests; a server-requested floor raises it and nothing lowers it",
    env: EnvDecl::None,
    global: false,
    positional: false,
    required: false,
    hidden: false,
    rung: Rung::None,
    value: ValueDecl::Str,
};

/// `--progress` on `pr watch`: the program that records the two poll signals.
///
/// The signals are facts about the poll, so the verb produces them; WHICH
/// program writes them down is the caller's, which is what keeps a recorder's
/// path out of this crate (non-negotiable rule 1). Absent means nobody is
/// listening, which is every caller but a supervised landing.
const WAIT_PROGRESS: FlagDecl = FlagDecl {
    id: "progress",
    long: Some("progress"),
    short: None,
    help: "Program to record the poll's tick and reading-change signals",
    env: EnvDecl::None,
    global: false,
    positional: false,
    required: false,
    hidden: false,
    rung: Rung::None,
    value: ValueDecl::Str,
};

/// `--progress-id` on `pr watch`: the identity the recorder files under.
const WAIT_PROGRESS_ID: FlagDecl = FlagDecl {
    id: "progress_id",
    long: Some("progress-id"),
    short: None,
    help: "The identity the progress recorder keys its entries on",
    env: EnvDecl::None,
    global: false,
    positional: false,
    required: false,
    hidden: false,
    rung: Rung::None,
    value: ValueDecl::Str,
};

const FANIN_CHECK: FlagDecl = FlagDecl {
    id: "fanin",
    long: Some("fanin"),
    short: None,
    help: "The fan-in check whose failure a cancelled sibling can manufacture",
    env: EnvDecl::None,
    global: false,
    positional: false,
    required: false,
    hidden: false,
    rung: Rung::None,
    value: ValueDecl::Str,
};

/// `--takeover` on `claim check`: claim over the COMPETITOR refusals.
///
/// The three competitor rules read a RESUMED branch exactly as they read a
/// collision, and they are right about the facts every time — work in flight is
/// In Progress, assigned, and carries its own pull request. What they cannot see
/// is that the competitor is this branch. Measured: the receipt lives under
/// `$GIT_DIR` and never leaves the clone, which is what makes it unforgeable and
/// also what strands it, so a branch picked up in a fresh container can never
/// mint one. In a fleet of disposable containers that is the second session on any
/// branch, not an edge case.
///
/// A takeover rather than a bypass, and the distinction is what it writes down:
/// the receipt records which rules fired for which ids.
const TAKEOVER: FlagDecl = FlagDecl {
    id: "takeover",
    long: Some("takeover"),
    short: None,
    help: "Claim over the competitor refusals, recording in the receipt which ones were overridden",
    env: EnvDecl::None,
    global: false,
    positional: false,
    required: false,
    hidden: false,
    rung: Rung::None,
    value: ValueDecl::Bool,
};

/// `--bypass-sequence` on `claim check`: "I refined this story myself, on
/// purpose."
///
/// Deliberately NOT folded into `--takeover` (CLOUD-816). "This story was refined
/// in my session" and "I am resuming work that already looks occupied" are
/// different decisions, and one switch for both grants the second while a human
/// only meant the first — which is how a takeover came to clear the whole of
/// CLOUD-431.
const BYPASS_SEQUENCE: FlagDecl = FlagDecl {
    id: "bypass_sequence",
    long: Some("bypass-sequence"),
    short: None,
    help: "Skip the refinement-sequence rules, recorded in the receipt as a bypass",
    env: EnvDecl::None,
    global: false,
    positional: false,
    required: false,
    hidden: false,
    rung: Rung::None,
    value: ValueDecl::Bool,
};

/// `--adopt` on `claim check`: re-key a stranded receipt onto this branch.
const ADOPT: FlagDecl = FlagDecl {
    id: "adopt",
    long: Some("adopt"),
    short: None,
    help: "Re-key an orphaned claim receipt onto this branch instead of judging a payload",
    env: EnvDecl::None,
    global: false,
    positional: false,
    required: false,
    hidden: false,
    rung: Rung::None,
    value: ValueDecl::Bool,
};

/// `--adopt-from <branch>` on `claim check`: which orphan to adopt.
///
/// A separate flag rather than an optional value on `--adopt`, because an
/// optional-value flag cannot tell `--adopt --takeover` from `--adopt <name>`
/// without a rule about which tokens look like branch names — and a rule about
/// rules is what this repository's config posture refuses.
const ADOPT_FROM: FlagDecl = FlagDecl {
    id: "adopt_from",
    long: Some("adopt-from"),
    short: None,
    help: "The branch name the receipt being adopted was minted under",
    env: EnvDecl::None,
    global: false,
    positional: false,
    required: false,
    hidden: false,
    rung: Rung::None,
    value: ValueDecl::Str,
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

/// CLOUD-479's field allowlist, as a pointer to the derive rather than a list of
/// tokens copied here — the same discipline every other parser in this section
/// follows, so the accepted spelling can never drift from the type that
/// receives it.
fn hook_field_parser() -> ValueParser {
    ValueParser::new(clap::builder::EnumValueParser::<crate::hook::Field>::new())
}

/// hk's format axis, as a pointer to the type rather than a list of tokens —
/// the discipline every parser here follows, so an accepted spelling cannot
/// drift from the enum that receives it.
fn exec_format_parser() -> ValueParser {
    ValueParser::new(clap::builder::EnumValueParser::<crate::exec::OutputFormat>::new())
}

/// mise's style axis, on the same terms.
fn exec_style_parser() -> ValueParser {
    ValueParser::new(clap::builder::EnumValueParser::<crate::exec::OutputStyle>::new())
}

fn spec_format_parser() -> ValueParser {
    ValueParser::new(clap::builder::EnumValueParser::<crate::cli::SpecFormat>::new())
}

fn schema_surface_parser() -> ValueParser {
    ValueParser::new(clap::builder::EnumValueParser::<crate::cli::SchemaSurface>::new())
}

/// Which git fact `receipt status` judges the receipt against, as a pointer to
/// the type the config already uses rather than a second list of tokens — so the
/// CLI and a `[[rule]]`'s `key` column cannot come to mean different things
/// (CLOUD-741).
fn receipt_key_parser() -> ValueParser {
    ValueParser::new(clap::builder::EnumValueParser::<crate::rules::ReceiptKey>::new())
}

fn shell_parser() -> ValueParser {
    ValueParser::new(clap::builder::EnumValueParser::<clap_complete::Shell>::new())
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
        id: "check",
        about: "Run the applicable read-only gates against the repository",
        data_channel: true,
        effect: Effect::Read,
        flags: &[CHECK_RULE, CHECK_STAGED, CHECK_SINCE, JSON],
    },
    // `enforce` runs rule kinds that execute commands declared in
    // `batten.toml`. Per §5 a command that runs user-supplied code is listed
    // unclassified with a stated reason, never guessed — so it is excluded from
    // the derived read-only allowlist by construction.
    CommandDecl {
        path: "enforce",
        id: "enforce",
        about: "Run every configured rule, including kinds that execute a configured command",
        data_channel: true,
        effect: Effect::Unclassified,
        flags: &[ENFORCE_RULE, JSON],
    },
    // `exec` runs a command the caller names, so it is the second process-spawning
    // verb after `enforce` and takes the same conservative reading. It is a
    // TRANSPARENT verb: the child's streams are inherited and the child's exit
    // code is returned unchanged, which makes it the one place a code outside the
    // §7 table can appear — see `crate::exit`'s note. Batten still never invents a
    // `2` here, which is the property fail-open actually depends on.
    CommandDecl {
        path: "exec",
        id: "exec",
        about: "Run a command — or a `:::` bundle — and report a pointer to what it wrote",
        // The child owns stdout, so Batten must not interleave a document of its
        // own with the child's bytes. The pointer surface over captured output is
        // CLOUD-162's, on stderr.
        data_channel: false,
        effect: Effect::Unclassified,
        flags: &[
            // Declared BEFORE the trailing argv: `trailing_var_arg` swallows
            // everything after the first free token, so a flag listed after it
            // would parse as one of the child's arguments.
            //
            // `--capture-only` is now what happens by default (CLOUD-429) and is
            // kept as `--tee`'s inverse spelling rather than removed: a caller who
            // learned it should not be told a flag disappeared.
            CAPTURE_ONLY,
            TEE,
            JOBS,
            CONTINUE_ON_ERROR,
            FlagDecl::defaulted_enum(
                "format",
                "format",
                "How Batten's own record is encoded (hk's axis)",
                exec_format_parser,
                "human",
            ),
            FlagDecl::defaulted_enum(
                "style",
                "style",
                "How a teed child's bytes are presented, and whose output is suppressed (mise's axis)",
                exec_style_parser,
                "interleave",
            ),
            FlagDecl::trailing(
                "command",
                "The command to run, after `--`, with its own arguments intact",
            ),
        ],
    },
    // The `capture` noun only dispatches, and its subtree carries a `destructive`
    // verb, so it takes the `receipt`/`provision` fail-safe reading rather than
    // `policy`'s: §5 derives the agent allowlist from `effect == read`, and a noun
    // over a removing subtree would leak onto it for any consumer that treats an
    // entry as a prefix (CLOUD-121).
    CommandDecl {
        path: "capture",
        id: "capture",
        about: "Captured command output: navigate what `exec` already ran, without running it again",
        data_channel: false,
        effect: Effect::Unclassified,
        flags: &[],
    },
    // `read`, and structurally so rather than by good behaviour: it opens one file
    // under the out-of-tree state dir, addressed by a handle whose digest the
    // parser refuses unless it is hex. No path here reaches user-supplied code —
    // the *child* ran long ago, under `exec`, and this verb cannot start one.
    //
    // It is also the one verb in the tool whose product is CONTENT, and the
    // boundary is worth stating where it lives: non-negotiable rule 4 governs
    // checks over sensitive content, and this renders no verdict. The bytes are
    // the child's own and were already paid for once; withholding them would leave
    // re-running the command as the only way to see more, which is the behaviour
    // this issue exists to delete. The default selection is still the pointer.
    //
    // Since CLOUD-918 it is also the one verb whose product is not TEXT. `--raw`
    // writes bytes to stdout verbatim, which is why it is refused alongside
    // `--json`: the two are different contracts over the same selection, and the
    // `-J` ladder is byte-stable text by construction.
    CommandDecl {
        path: "capture show",
        id: "capture.show",
        about: "Print a capture's pointer, or the lines a selection asks for, with no second run",
        data_channel: true,
        effect: Effect::Read,
        flags: &[
            FlagDecl::positional("handle", "The `<stream>:<digest>` handle to read"),
            LINES,
            GREP,
            RAW,
            BYTES,
            JSON,
        ],
    },
    // `read`, on the same structural grounds as `capture show`: it opens the
    // store's own log and the blobs it names, and cannot start a program.
    //
    // THE ONE VERB WHOSE POINT IS WHAT IT DOES NOT PRINT (CLOUD-1121). Without
    // `--raw` it emits a handle, a byte count and the tool — a pointer, and never
    // a byte of the response, because a verb that exists to keep a payload out of
    // context would defeat itself by printing one. `--raw` is the deliberate
    // exception and is the same contract `capture show --raw` already carries:
    // bytes to stdout for a program to consume, which is why it is refused
    // alongside `--json`.
    CommandDecl {
        path: "capture find",
        id: "capture.find",
        about: "Resolve a stored tool response by the key it carries, with no handle to look up first",
        data_channel: true,
        effect: Effect::Read,
        flags: &[
            FlagDecl::positional("key", "The key the response must carry, e.g. an issue id"),
            TOOL,
            KEY_AT,
            RAW,
            JSON,
        ],
    },
    // Fixed reads of the store's own directory plus arithmetic over the entries.
    CommandDecl {
        path: "capture list",
        id: "capture.list",
        about: "List this repository's captures as handles, in a fixed order",
        data_channel: true,
        effect: Effect::Read,
        flags: &[STREAM, CALLS, JSON],
    },
    // `destructive`, not `write`: what it removes is a record of a run that has
    // already happened, and recovering one means re-running the command — which is
    // precisely the cost this whole capability exists to avoid paying. §5 binds
    // `-y --yes` to this effect, so a non-interactive caller is told the flag it
    // needs rather than prompted into the void.
    CommandDecl {
        path: "capture prune",
        id: "capture.prune",
        about: "Remove this repository's captures — the one removal path; captures never expire on their own",
        data_channel: false,
        effect: Effect::Destructive,
        // `-y` comes from the globals (CLOUD-46 landed it there), and this row
        // requires it UNCONDITIONALLY rather than only when unattended — stricter
        // than §4's minimum and deliberate: §4's own words are that a policy
        // engine which blocks a loop waiting for a Y/N is a dead gate, and the
        // primary caller here is a program. A rule that never prompts cannot hang,
        // and needs no attendedness to be true.
        flags: &[DRY_RUN],
    },
    // The `mcp` noun only dispatches, and takes the same fail-safe reading
    // `capture` and `target` take: its subtree carries a verb that is not `read`,
    // and §5 derives the agent allowlist from `effect == read`, so a `read` noun
    // over it would leak onto that allowlist for any consumer treating an entry
    // as a prefix (CLOUD-121).
    CommandDecl {
        path: "mcp",
        id: "mcp",
        about: "Dispatch a declared MCP call and hand back a reduction instead of the payload",
        data_channel: false,
        effect: Effect::Unclassified,
        flags: &[],
    },
    // `mcp call` makes an OUTBOUND CALL, WRITES the capture store, and — since
    // CLOUD-1261 — READS operator-supplied key material and SPENDS it on that
    // call, so it is not `Effect::Read` and it is not guessed (CLOUD-1260).
    //
    // The credential half is worth naming separately rather than folding into
    // "outbound call", because it is the one that a future reclassification would
    // get wrong: a reader who decided the network reach was acceptable might still
    // not have priced a verb that reads a token out of a file the operator named.
    // Both reaches are this row's, and both keep it off the derived allowlist.
    // It takes `enforce`'s
    // shape above rather than inventing a classification: a command whose reach
    // extends past this repository's own state is listed unclassified with a
    // stated reason, never optimistically, so it is excluded from the derived
    // read-only allowlist by construction. House style §5's allowlist is DERIVED
    // from this field, which is why an optimistic `read` here would silently
    // widen it.
    //
    // `data_channel` is FALSE, on `exec`'s precedent and for its reason. That
    // contract is that a `-J` document is emitted UNCONDITIONALLY — "including
    // when the answer is empty, because JSON that is sometimes absent is
    // unparseable". This verb cannot keep it: its document is a SERVER's answer,
    // so there is none at all when the exchange did not happen, and declaring the
    // channel would promise something only the network can deliver. The census
    // that asserts the contract is what caught it.
    //
    // So the split is `exec`'s: the product goes to stdout, Batten's own record
    // to stderr. stdout carries the reduction — one JSON document, nothing
    // interleaved — and the pointer plus the delta go to stderr, where a record
    // ABOUT the call belongs rather than inside the answer to it. There is no
    // `--json` because there is no second encoding to choose between.
    CommandDecl {
        path: "mcp call",
        id: "mcp.call",
        about: "Dispatch one declared method, store the response, and print the declared reduction",
        data_channel: false,
        effect: Effect::Unclassified,
        flags: &[
            FlagDecl::positional(
                "server",
                "The server to dispatch to, as a `[[mcp.source]]` names it",
            ),
            FlagDecl::positional("method", "The method to call"),
            FlagDecl::positional_optional(
                "params",
                "The method's arguments, as a JSON object; omitted is `{}`",
            ),
        ],
    },
    // The `target` noun only dispatches, and takes `capture`'s reading one row
    // family up rather than `policy`'s: its subtree carries a `destructive` verb,
    // §5 derives the agent allowlist from `effect == read`, and a `read` noun over
    // a removing subtree would leak onto that allowlist for any consumer treating
    // an entry as a prefix (CLOUD-121). `Unclassified` rather than `Destructive`
    // for the same reason it is not `Read`: the noun itself removes nothing, so a
    // `--dry-run` on it would be a flag over an action that does not exist.
    CommandDecl {
        path: "target",
        id: "target",
        about: "Inspect and reclaim this repository's build tree",
        data_channel: false,
        effect: Effect::Unclassified,
        flags: &[],
    },
    // The disk floor and the reclaim (CLOUD-766, CLOUD-861, CLOUD-1030), ported
    // out of `mise-tasks/target-prune.sh` under CLOUD-1059.
    //
    // `destructive`, not `write`, and for `capture prune`'s reason one row up:
    // what it removes is recoverable only by re-running the build that produced
    // it — which is precisely the cost the retention policy exists to avoid
    // paying. So `-y` binds here too, and the primary caller is `verify`, a
    // program that must never be prompted into the void.
    CommandDecl {
        path: "target prune",
        id: "target.prune",
        about: "Reclaim superseded build artifacts, and refuse below the measured disk floor for the build the next lap will run",
        data_channel: false,
        effect: Effect::Destructive,
        flags: &[DRY_RUN, PRUNE_ROOT],
    },
    CommandDecl {
        path: "config",
        id: "config",
        about: "Inspect configuration",
        data_channel: false,
        effect: Effect::Read,
        flags: &[],
    },
    CommandDecl {
        path: "config show",
        id: "config.show",
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
        id: "config.epoch",
        about: "Print the content hash of the governing config surface",
        data_channel: true,
        effect: Effect::Read,
        // The value alone is already machine-readable, so `-J` is not a second
        // rendering of it: it names *which surface* the hash covers, which a
        // caller stamping a record needs and a bare digest cannot carry.
        flags: &[JSON, NO_CACHE],
    },
    // The removal half of the deprecation grammar (CLOUD-360). `config lint`
    // judges the config in front of you; this judges the SURFACE across a
    // release boundary, which is a different subject and so a sibling verb
    // rather than a flag on that one.
    CommandDecl {
        path: "config deprecations",
        id: "config.deprecations",
        about: "Report schema keys removed since a published release with no deprecation window",
        data_channel: true,
        // Reads committed bytes at a ref and the schema this binary derives.
        // Nothing is written and no process is spawned.
        effect: Effect::Read,
        flags: &[JSON, AGAINST],
    },
    CommandDecl {
        path: "config lint",
        id: "config.lint",
        about: "Report policy smells in batten.toml (any smell is a violation)",
        data_channel: true,
        // Still `read` with `--host-rules`: the flag names a file or `-` the
        // CALLER supplies. Agents fetch, gates decide — nothing here reaches the
        // network, so the verb stays on the derived read-only allowlist.
        effect: Effect::Read,
        flags: &[JSON, HOST_RULES],
    },
    // `lint <kind>` (house-style §2, CLOUD-84): a family of text-shape lints over
    // artifacts that are NOT `batten.toml`. Deliberately a top-level verb rather
    // than a `brief` noun — the issue's own §1 refuses a standalone noun, and the
    // kind is what varies. `config lint` stays where it is: it lints the one
    // committed authority, which is a different subject, not a second kind.
    CommandDecl {
        path: "lint",
        id: "lint",
        about: "Lint an artifact against a declared schema",
        data_channel: false,
        effect: Effect::Read,
        flags: &[],
    },
    // Reads a delegation brief and answers whether it carries the facts that do
    // not inherit across a handoff. `read` in the strongest sense: the input is
    // text the caller names, nothing on disk changes, and no process is spawned.
    CommandDecl {
        path: "lint brief",
        id: "lint.brief",
        about: "Check a delegation brief against the handoff schema (any missing section is a violation)",
        data_channel: true,
        effect: Effect::Read,
        flags: &[
            JSON,
            FlagDecl::positional_optional("brief", "The brief to read; omitted or `-` reads stdin"),
        ],
    },
    CommandDecl {
        path: "spec",
        id: "spec",
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
        id: "doctor",
        about: "Diagnose whether Batten can run in this repository",
        data_channel: true,
        effect: Effect::Read,
        flags: &[JSON],
    },
    // §2 spells the verb `doctor <SUB>` — "nests focused sub-diagnostics" — so a
    // named sub-verb is the SPECIFIED shape rather than a new idea (CLOUD-777).
    // The alternative considered and rejected was a fourth anonymous check inside
    // `diagnose()`: a consumer asking *am I wired?* would then have to read one
    // line out of a report about config and PATH, and per-harness detail would
    // have nowhere to live, because that shape forces one boolean and one reason
    // id for the whole question.
    //
    // Bare `doctor` keeps its own report unchanged — §8 promises it validates the
    // resolved config, and `is_noun` is what stops this row turning the parent
    // into a noun that refuses to answer.
    //
    // `read`, and structurally: it reads committed wiring files and compares them
    // against a derivation computed in-process. Nothing is spawned, and §2's own
    // row already classifies the verb this way.
    // WHICH engine the registrations reach, where `doctor hooks` answers whether
    // they reach one at all (CLOUD-1349). It reported `5 harness(es), 0 unwired`
    // over a binary 16 versions behind the tree it was adjudicating.
    //
    // A SUB-VERB BECAUSE THE SUBJECT IS THE WORLD, NOT THE CHECKOUT. This landed
    // once as a fourth check inside `diagnose()` and `verify` refused it: bare
    // `doctor` is asserted green over this repository by a compiled-binary case,
    // and an install that has not caught up with a rebuild made that case a
    // function of install recency. `.claude/rules/toolchain.md` states the rule
    // from `lock-check`'s post-mortem — a property of the commit belongs in the
    // gate, a property of the world belongs to its own caller — and §2's
    // `doctor <SUB>` is the shape that was already specified for it.
    //
    // `read`, and structurally: it reads two files and hashes them. Nothing is
    // spawned, which is what keeps it off the wrong side of CLOUD-170 while
    // sitting on the `filter(effect == read)` allowlist.
    CommandDecl {
        path: "doctor mediator",
        id: "doctor.mediator",
        about: "Diagnose whether the engine the registrations reach was built from this tree",
        data_channel: true,
        effect: Effect::Read,
        flags: &[JSON],
    },
    CommandDecl {
        path: "doctor hooks",
        id: "doctor.hooks",
        about: "Diagnose whether batten is wired on every hook surface of every harness",
        // Per-harness detail is the whole reason this is a sub-verb rather than a
        // line in `doctor`'s summary, and `-J` is where that detail goes.
        data_channel: true,
        effect: Effect::Read,
        flags: &[JSON],
    },
    // THE VERB "IS THIS SESSION SAFE TO END" DID NOT HAVE (CLOUD-1376).
    //
    // Every other completion question resolves to a command: `verify` decides
    // the tree, `land` the PR, `done-check` the release, `claim-check` the pull.
    // Nothing decided the SESSION, so the one completion claim with no command
    // behind it was answered by estimate — measured, with the store on disk
    // reading `pending` and the answer given as "safe". Non-negotiable rule 3
    // says gates decide and never estimate; a rule needs an instance to bind to,
    // and this is that instance.
    //
    // A SUB-VERB OF `doctor` rather than a new top-level verb, for the reason
    // `doctor hooks` already carries: §2 spells `doctor <SUB>` as the shape for a
    // focused sub-diagnostic, and *can batten's operator stop here* is a question
    // about whether this setup is finished, not a policy verdict over the tree.
    //
    // `read`, structurally: it opens the session's own task store and counts. It
    // spawns nothing and writes nothing.
    CommandDecl {
        path: "doctor session",
        id: "doctor.session",
        about: "Diagnose whether this session has declared work it has not finished",
        // The open ids are the pointer set a reader acts on, and `-J` is where
        // they go — never a task's subject line (rule 4).
        data_channel: true,
        effect: Effect::Read,
        flags: &[JSON],
    },
    // The scaffolding half of §12's onboarding pair, and the one verb whose
    // write target is inside the repository. `write` rather than `destructive`:
    // it creates a file and replaces nothing — an existing config is refused
    // (exit 2) rather than overwritten — so there is nothing to confirm and
    // nothing whose recovery means redoing work. `-n` previews without writing,
    // and per §5 does not lower the declared effect.
    CommandDecl {
        path: "init",
        id: "init",
        about: "Write a starter batten.toml, refusing to overwrite an existing one",
        // The pointer it emits is one path; a JSON document of one field would
        // be a second shape for the same answer.
        data_channel: false,
        effect: Effect::Write,
        flags: &[DRY_RUN],
    },
    // The adoption path for a repository that is already dirty (CLOUD-67).
    // `write` for the same reason `provision apply` is: everything it creates is
    // recreatable by running it again, and it replaces nothing the caller
    // authored — the artifact is out of tree and Batten's own. `--prune` does not
    // raise that, per the flag's own note.
    //
    // A baseline is a bulk suppression, so what keeps it inside the threat model
    // is not the classification but the minting predicate `crate::baseline`
    // enforces: only landed, committed state can be baselined. `-n` previews the
    // set without writing it, which is the affordance a reviewer needs before a
    // suppression that size.
    CommandDecl {
        path: "baseline",
        id: "baseline",
        about: "Record the findings that already exist, so only new ones fail",
        // No `-J`, matching every other write row (`init`, `defects add`,
        // `provision apply`). The set a baseline holds is read back through
        // `check -J`, which is where the verdict about it lives; a second
        // document emitted by the *mutating* verb would be a second authority
        // over one set, and byte-stability is not a claim a mutating verb can
        // make about two consecutive runs.
        data_channel: false,
        effect: Effect::Write,
        flags: &[PRUNE, DRY_RUN],
    },
    CommandDecl {
        path: "generate",
        id: "generate",
        about: "Emit artifacts derived from the command spec, on stdout",
        data_channel: false,
        effect: Effect::Read,
        flags: &[],
    },
    CommandDecl {
        path: "generate completions",
        id: "generate.completions",
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
    // The two human renderings of the same tree (CLOUD-69). House-style §11
    // already named them derivations of the spec; until now only the shell one
    // existed, so the claim was prose. Both stay stdout-only and `read` for the
    // reason the `generate` header states: the redirect belongs to the caller.
    // CLOUD-62. The wiring a host needs is a derivation of the same `Harness`
    // data the adapters are built from, so it is emitted here rather than
    // hand-kept in each host's config — the failure `derived-check` already
    // covers for completions and man pages.
    CommandDecl {
        path: "generate hooks",
        id: "generate.hooks",
        about: "Emit one harness's hook registrations, on stdout",
        // The registrations ARE the output, and they are JSON because the hosts'
        // config files are — not because this is a batten document with a human
        // rendering to switch away from.
        data_channel: false,
        effect: Effect::Read,
        flags: &[FlagDecl::required_enum(
            "harness",
            "harness",
            "The harness whose hook registrations to emit",
            harness_parser,
        )],
    },
    CommandDecl {
        path: "generate man",
        id: "generate.man",
        about: "Emit the roff man page for one command, on stdout",
        // The page IS the output, and roff is not JSON.
        data_channel: false,
        effect: Effect::Read,
        // A positional rather than a flag: the page selector is the command's
        // one argument, and `batten generate man 'config show'` reads as the
        // question it asks. Optional because the root page is the default
        // answer, which is the `positional_optional` case exactly — a
        // deliberate override of something the verb works out for itself.
        flags: &[FlagDecl::positional_optional(
            "command",
            "The root-relative command path to document ('config show'); omit for the root page",
        )],
    },
    CommandDecl {
        path: "generate markdown",
        id: "generate.markdown",
        about: "Emit the whole command surface as one markdown reference, on stdout",
        // One document, no human/machine split to toggle between.
        data_channel: false,
        effect: Effect::Read,
        // No selector: the reference is the whole surface by definition, and a
        // subtree flag would invite a partial reference to be published as a
        // complete one (CLOUD-171).
        flags: &[],
    },
    // Derived from the config types themselves, never hand-authored (CLOUD-33),
    // so the schema cannot describe a `batten.toml` the binary would refuse — and
    // since CLOUD-879 the same holds for the two POLICY-INPUT surfaces, derived
    // from `Fact::ALL` rather than the config types, so a schema cannot describe
    // an `input` document the engine never emits.
    CommandDecl {
        path: "generate schema",
        id: "generate.schema",
        about: "Emit the JSON Schema for a config or policy-input surface, derived from the types that define it",
        data_channel: false,
        effect: Effect::Read,
        // `--surface`, not a `generate override-schema` sub-verb: the override
        // layer is a second SURFACE of the same artifact, and §2 and the landed
        // tree already disagree about where schema emission lives (CLOUD-244).
        // A selector adds no row to the command table; a verb would deepen a
        // divergence that is not settled yet.
        flags: &[FlagDecl::defaulted_enum(
            "surface",
            "surface",
            "Which surface to describe: the committed authority, the override layer, or a policy-input document",
            schema_surface_parser,
            "authority",
        )],
    },
    // The `perf` noun only dispatches (§2). Declared `write` rather than `read`
    // because §5 forbids inheritance in both directions and this row is a claim
    // about the whole subtree: `pair` builds two release binaries and
    // materialises a worktree, so there is no reading of this noun under which
    // it belongs on the derived read-only allowlist.
    CommandDecl {
        path: "perf",
        id: "perf",
        about: "Measure this repository's own invocation cost",
        data_channel: false,
        effect: Effect::Write,
        flags: &[],
    },
    // The paired measurement, retired out of `mise-tasks/perf-pair.sh` under
    // CLOUD-1059 and widened by CLOUD-875 on the way.
    //
    // `write`, and the honest class rather than the convenient one: it builds
    // into `target/`, adds and removes a detached worktree, and clears its own
    // output directory. NOT `destructive`, which would bind `-y` — everything it
    // removes is a build artifact it created, and `perf gate` below invokes the
    // same measurement with no flags, so a prompt would wedge the gate rather
    // than protect anything.
    //
    // `data_channel: false`: the records are a line protocol, and `perf compare`
    // still reads exactly that protocol on stdin, so a `--json` here would be a
    // second encoding of a contract rather than a channel. (Until CLOUD-1163 unit
    // 10 the readers were two shell programs; retiring them removed the second
    // implementation, not the protocol.)
    CommandDecl {
        path: "perf pair",
        id: "perf.pair",
        about: "Measure this branch and its merge base back to back on one machine, and print both arms as paired records",
        data_channel: false,
        effect: Effect::Write,
        flags: &[FlagDecl {
            id: "null",
            long: Some("null"),
            short: None,
            help: "Measure HEAD against itself, so the ratio is the noise floor rather than a comparison",
            env: EnvDecl::None,
            global: false,
            positional: false,
            required: false,
            hidden: false,
            rung: Rung::None,
            value: ValueDecl::Bool,
        }],
    },
    // The verdict over a pair, retired out of `mise-tasks/perf-compare.sh` under
    // CLOUD-1163 unit 10.
    //
    // `read`, and it is the only member of this subtree that is: it opens no file,
    // spawns nothing and builds nothing — it reads paired records on stdin and
    // decides a ratio. The noun above is declared `write` precisely because §5
    // forbids inheritance in both directions, so this row states its own class
    // rather than taking the subtree's.
    //
    // `data_channel: false`, like every other member of this subtree, and the
    // reason is that a verdict is not data. THE EXIT CODE IS THE CONTRACT — 0, 2,
    // 3 — and the lines are pointers a human reads. Declaring a channel here would
    // oblige a `--json` flag (`every_data_emitting_verb_declares_the_json_flag`),
    // which would be a second rendering of the same decision with no caller
    // asking for it: `verify` and the `perf` CI job both test for zero.
    CommandDecl {
        path: "perf compare",
        id: "perf.compare",
        about: "Decide whether a paired measurement read on stdin regressed past the threshold",
        data_channel: false,
        effect: Effect::Read,
        flags: &[],
    },
    // The composition `verify` and CI call, retired out of `mise-tasks/perf-gate.sh`
    // in the same delta. `write`, because it runs the pair.
    CommandDecl {
        path: "perf gate",
        id: "perf.gate",
        about: "Measure this branch against its merge base and refuse a regression",
        data_channel: false,
        effect: Effect::Write,
        flags: &[FlagDecl {
            id: "null",
            long: Some("null"),
            short: None,
            help: "Measure HEAD against itself, so the ratio is the noise floor rather than a comparison",
            env: EnvDecl::None,
            global: false,
            positional: false,
            required: false,
            hidden: false,
            rung: Rung::None,
            value: ValueDecl::Bool,
        }],
    },
    // The `mutate` noun only dispatches (§2), and it is declared `write` for the
    // reason `perf` states: §5 forbids inheritance in both directions, so the
    // noun row is a claim about the whole subtree, and `sweep` stages a tracked
    // tree and runs suites against it. There is no reading of this noun under
    // which it belongs on the derived read-only allowlist.
    CommandDecl {
        path: "mutate",
        id: "mutate",
        about: "Decide whether this repository's gates discriminate, rather than merely parse",
        data_channel: false,
        effect: Effect::Write,
        flags: &[],
    },
    // CLOUD-418's mechanism, retired out of `mise-tasks/mutant.sh` under
    // CLOUD-1267 so a gate's suite can be a DECLARED path rather than
    // `tests/<gate>.bats` — which is what lets a policy module name the
    // compiled-binary tier that actually drives the engine.
    //
    // `write`, and the honest class rather than the convenient one: it stages a
    // copy of the tracked tree, makes it a repository, corrupts a file in it and
    // spawns a test runner. NOT `destructive` — everything it removes is inside
    // a directory it created, and the frozen workflow step invokes this with no
    // flags, so a prompt would wedge the job rather than protect anything.
    //
    // `data_channel: false`: the report is a line protocol a workflow already
    // cats into a step summary, so a `--json` here would be a second encoding of
    // a contract rather than a channel.
    CommandDecl {
        path: "mutate sweep",
        id: "mutate.sweep",
        about: "Apply every declared mutation to its source and report the ones its declared suite did not catch",
        data_channel: false,
        effect: Effect::Write,
        flags: &[],
    },
    // The complement, and it is `read` structurally: one pass over the
    // declaration lines the tree already carries. No spawn, no network, and the
    // only I/O is reading the sources it censuses — so it joins the derived
    // read-only allowlist through `filter(effect == read)` with no second list.
    //
    // THE PAIR IS THE VERDICT, never either alone. `sweep` asks whether each
    // declared mutation is caught; this asks whether every gate in the tree is
    // declared or carries a filed exemption. A change that dropped a gate from
    // the enforced set and wrote no exemption would make the first greener and
    // the second red, and is indistinguishable from doing the work if only the
    // first runs.
    CommandDecl {
        path: "mutate census",
        id: "mutate.census",
        about: "Report every gate in the tree that is neither mutation-enforced nor carrying a filed exemption",
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
        id: "policy",
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
        id: "policy.budget",
        about: "Judge the always-loaded instruction set against its declared token budget",
        data_channel: true,
        effect: Effect::Read,
        flags: &[JSON],
    },
    // The aggregate half of the same question one verb up (CLOUD-417):
    // `policy budget` judges what loads once per session, this judges what the
    // hooks put in front of the model over the whole of it.
    //
    // A SIBLING VERB rather than a flag on `policy budget`, because the subjects
    // are different objects: one measures files this repository commits, the
    // other measures a transcript a host wrote. One verb answering both would
    // make a single verdict unattributable to either (`commit` beside
    // `attribution` records that reasoning for its own pair).
    //
    // `read` structurally: one file read at the configured transcript path plus
    // arithmetic over what it contains. Nothing is spawned and no user-supplied
    // code is reachable, which is what the `read` promise CLOUD-50 requires — and
    // the transcript's bytes are hashed and dropped at the parse, so the payload
    // rule 4 keeps off every channel never reaches this verb at all.
    CommandDecl {
        path: "policy hooks",
        id: "policy.hooks",
        about: "Judge this session's hook output against its declared per-session budget",
        data_channel: true,
        effect: Effect::Read,
        flags: &[JSON],
    },
    // Compiles the registered modules and evaluates their own `test_` rules
    // in-process (CLOUD-835). `read` structurally, not by assertion: the
    // evaluator is `Authority::Supplied` — it cannot open a file, start a
    // process or reach the network, which `evaluator-closure-check` gates rather
    // than asserts — and the only I/O is reading the modules and the documents
    // the row already declares. Nothing is spawned, so the `read` promise
    // CLOUD-50 requires holds, and this joins the derived allowlist through
    // `filter(effect == read)` with no second list to maintain.
    CommandDecl {
        path: "policy test",
        id: "policy.test",
        about: "Run each registered module's own `test_` rules and report the predicates none exercised",
        data_channel: true,
        effect: Effect::Read,
        flags: &[JSON],
    },
    // Reads the committed authority and prints one field of the rows it already
    // loaded. `read` structurally: no spawn, no network, and the only I/O is the
    // config load every verb here performs.
    //
    // WHY IT IS PUBLISHED RATHER THAN GREPPED (CLOUD-312 row 4). A consumer gate
    // has to know which tool names the mediated table decides, because a deny it
    // wrote against a host-supplied connector enforces nothing unless something
    // matches that connector's rotating name by SUFFIX. That fact lived in a
    // guard's `--covers` flag; retiring the guard into rows would have left the
    // gate grepping `batten.toml`, which is a second authority for a fact the
    // engine already holds. One read, one answer.
    CommandDecl {
        path: "policy tools",
        id: "policy.tools",
        about: "Print the tool names the mediated-call rows decide, one per line",
        data_channel: true,
        effect: Effect::Read,
        flags: &[JSON],
    },
    // The dereference half of CLOUD-1053: the hot path prints a token, a gloss
    // and a pointer, and this is what the token resolves to.
    //
    // `read` structurally, and more narrowly than its siblings: it resolves from
    // the COMMITTED registry with no network, no spawn and no tree walk — a
    // config read and a lookup. That is what lets it be the one place the class
    // definition is carried without the hot path paying for it.
    //
    // **Its payload is a DELIBERATE, STATED exception to pointer-only output**
    // (house style §6, non-negotiable rule 4). `explain` is local documentation
    // rather than a finding; carrying the text the hot path no longer does is
    // its entire purpose, and the text is the config author's own declaration —
    // the class `config show` exists to echo — not content read out of a subject
    // file.
    CommandDecl {
        path: "policy explain",
        id: "policy.explain",
        about: "Resolve a verdict token to its class definition and the routes out of it",
        data_channel: true,
        effect: Effect::Read,
        flags: &[VERDICT_TOKEN, JSON],
    },
    // The `attribution` noun only dispatches, and like `worktree` it cannot be
    // `read`: its subtree carries `identity`, which writes `.git/config`. It is
    // deliberately NOT a verb under `policy` for exactly the reason that row
    // states — `policy` is declared `read` as a claim about its whole subtree,
    // and hanging a mutating verb there would either falsify that claim or force
    // `policy` off the derived read-only allowlist, taking `policy budget` with
    // it. A separate noun keeps both claims true (CLOUD-274).
    // The `commit` noun. Unlike `attribution` beside it, this one CAN be `read`:
    // its whole subtree is a predicate over commit text and nothing under it
    // writes, so the row makes the stronger claim the subtree actually satisfies.
    //
    // A sibling noun rather than a verb under `attribution`, deliberately. Both
    // judge produced commits, but they answer different questions — "is this
    // subject conventional" and "does this metadata carry vendor branding" — and
    // one verb answering two would make a single verdict unattributable to
    // either (CLOUD-701).
    CommandDecl {
        path: "commit",
        id: "commit",
        about: "The shape a commit must take here: what its subject may say",
        data_channel: false,
        effect: Effect::Read,
        flags: &[],
    },
    // Reads subjects through git's own read-only plumbing and matches one
    // configured pattern against them. Nothing is spawned but that walk, and no
    // user-supplied code is reachable, which is what the `read` structural
    // promise requires.
    CommandDecl {
        path: "commit check",
        id: "commit.check",
        about: "Refuse a commit subject that does not follow the configured convention",
        data_channel: true,
        effect: Effect::Read,
        flags: &[JSON, RANGE, MESSAGE],
    },
    // The `semver` noun (CLOUD-1050), ported off `mise-tasks/semver.sh` when
    // CLOUD-1059 made editing a shell rule refusable.
    //
    // NOT `read`, and the distinction is the point: this subtree spawns
    // `cargo-semver-checks`, and its fallback materializes the baseline tree and
    // runs a doc build over it. A row claiming `read` here would put a spawning
    // verb on the derived read-only allowlist, which is the claim that allowlist
    // exists to make true.
    // The `ready` noun (CLOUD-1121), ported off `mise-tasks/ready-lint.sh` when
    // CLOUD-1059 made editing a shell rule refusable.
    CommandDecl {
        path: "ready",
        id: "ready",
        about: "Whether an issue's Ready block satisfies the checkable clauses of the gate",
        data_channel: false,
        effect: Effect::Unclassified,
        flags: &[],
    },
    // `read`, structurally: it reads a payload, this workspace's own manifest for
    // the version regime, and — under `--issue` — the capture store. It opens
    // files and starts no program.
    //
    // POINTER-ONLY IS THE WHOLE OUTPUT (rule 4). Findings are `<id>:<line> <rule>`
    // and never the prose that matched: issue bodies carry consumer detail, and a
    // lint that echoed them would leak it through CI logs.
    CommandDecl {
        path: "ready lint",
        id: "ready.lint",
        about: "Refuse an issue whose Ready block fails a checkable clause of the Definition of Ready",
        data_channel: true,
        effect: Effect::Read,
        flags: &[ISSUE, JSON],
    },
    // The `checks` noun (CLOUD-1143), ported off `mise-tasks/checks-green.sh`.
    CommandDecl {
        path: "checks",
        id: "checks",
        about: "Whether a commit's check runs answer the question a landing depends on",
        data_channel: false,
        effect: Effect::Unclassified,
        flags: &[],
    },
    // `read`, and structurally so: it decides over a reading handed to it on
    // stdin and cannot start a program. The FETCH stays with the caller — the
    // poller already holds the body it got conditionally — which is the
    // agents-fetch-gates-decide split the board gates use, and what lets every
    // case run offline.
    //
    // THE EXIT CODES ARE THIS TABLE'S, NOT THE PREDECESSOR'S (CLOUD-1143).
    // `checks-green.sh` used `0` green / `1` red / `2` could-not-look / `3`
    // not-yet, and three of those mean something else here. So: green is
    // `Success`; a head that is red OR not yet answered is `Violation`, because
    // both mean the same thing to a lander and they differ only in whether to
    // ask again; an unusable roster is `Usage`; a reading that could not be
    // taken is `Internal`.
    //
    // Collapsing red and not-yet is what makes the fail-safe direction
    // STRUCTURAL rather than a convention every reader has to keep: a caller
    // that branches on the code alone and ignores stdout holds. Any mapping
    // giving not-yet a `0` would let that same caller fast-forward a head
    // nothing had judged, which is CLOUD-337's defect re-introduced by the port
    // meant to preserve it.
    CommandDecl {
        path: "checks green",
        id: "checks.green",
        about: "Refuse a head whose required checks are red, still running, or not yet registered",
        data_channel: true,
        effect: Effect::Read,
        flags: &[
            REQUIRED_CHECKS,
            ABSENT_OK_CHECKS,
            ANSWERED_CONCLUSIONS,
            FANIN_CHECK,
            JSON,
        ],
    },
    // The `pr` noun (CLOUD-1143), ported off `mise-tasks/ci-wait.sh` and renamed
    // onto §2's declared spelling by CLOUD-1214.
    //
    // WHY `pr` AND NOT `ci`, on two counts that are separate. §2 declares
    // `pr create|ready|land|watch|dispatch` and declares no `ci` at all, and
    // `SURFACE` is authoritative for what SHIPS while §2 is authoritative for
    // what is INTENDED (CLOUD-244) — so a verb §2 already names is an unshipped
    // row to fulfil rather than a widening. And `ci` was a SINGLETON NOUN, one
    // of the twelve CLOUD-1184 counts as a defect and the shape Azure's guidance
    // says to collapse; `pr` is a noun §2 gives five leaves, so this populates a
    // declared family instead of stranding another namespace on one leaf.
    CommandDecl {
        path: "pr",
        id: "pr",
        about: "The pull request a landing drives, and the answers it waits on",
        data_channel: false,
        effect: Effect::Unclassified,
        flags: &[],
    },
    // `unclassified`, and STATED rather than guessed (see `effect.rs`): the poll
    // runs two programs the caller names — the forge's client to take the
    // reading, and a recorder for the progress signals — so what it does cannot
    // be known from this row. Reading check runs is idempotent and the verb
    // writes nothing itself, but "runs a program somebody else chose" is not
    // `read`, and a row that claimed it would put this verb in the derived
    // read-only allowlist on a promise it cannot keep.
    //
    // THE EXIT TABLE IS THE ENGINE'S. Green is `Success`, a red head is
    // `Violation`, an unusable roster is `Usage`, a reading that could not be
    // taken is `Internal`. "Not yet" never reaches the caller: that is the state
    // the loop exists to sit in, which is the whole difference between this verb
    // and `checks green`.
    CommandDecl {
        path: "pr watch",
        id: "pr.watch",
        about: "Poll a head's check runs until the required set answers, then report the verdict",
        data_channel: false,
        effect: Effect::Unclassified,
        flags: &[
            WAIT_SHA,
            WAIT_REPO,
            WAIT_INTERVAL,
            WAIT_PROGRESS,
            WAIT_PROGRESS_ID,
            REQUIRED_CHECKS,
            ABSENT_OK_CHECKS,
            ANSWERED_CONCLUSIONS,
            FANIN_CHECK,
        ],
    },
    // The bot lane (CLOUD-1295), ported off `mise-tasks/bot-issue.sh`. Five verbs
    // rather than one with a mode word, because they have different effects and
    // house style §5 declares an effect per row: `derive` and `closes` write
    // nothing, the other three write to the forge.
    //
    // `unclassified`, for `pr watch`'s reason and not for want of thought: this
    // verb writes nothing at all, and if effect were about MUTATION it would be
    // `read`. It runs the forge's client — a program the caller named — and
    // "runs a program somebody else chose" is not `read`, so a row claiming it
    // would put this verb on the derived read-only allowlist on a promise the
    // row cannot keep.
    //
    // NO `-J`, AND THE DOCUMENT IS UNCONDITIONAL, which is the same call
    // `pr watch` makes one row down. Its stdout is one JSON payload and there is
    // no second encoding for a flag to select — the refinement gate reads it
    // unchanged, which is the whole point. Declaring the channel anyway would
    // enrol it in the `-J` census, whose contract is byte-stability and
    // whole-or-nothing across two runs; here that is a property of the FORGE's
    // answer rather than of this verb, so the row would promise something no
    // reading of this code can keep.
    CommandDecl {
        path: "pr derive",
        id: "pr.derive",
        about: "The tracker row a bot's pull request implies, as a payload the refinement gate reads",
        data_channel: false,
        effect: Effect::Unclassified,
        flags: &[PR_NUMBER],
    },
    // `write`: it opens an issue on the forge. Stated rather than guessed — a row
    // claiming `read` would put a verb that creates a tracker row on the derived
    // read-only allowlist.
    CommandDecl {
        path: "pr file",
        id: "pr.file",
        about: "Open the mirror issue a bot's pull request implies, and report its number",
        data_channel: false,
        effect: Effect::Write,
        flags: &[PR_NUMBER],
    },
    // `write`: it rewrites the pull request's body so the merge moves the row.
    CommandDecl {
        path: "pr link",
        id: "pr.link",
        about: "Write the closing key into a bot pull request's body, so its merge moves the row",
        data_channel: false,
        effect: Effect::Write,
        flags: &[PR_NUMBER, ISSUE_KEY],
    },
    // `write`, because it composes the two above. Idempotent at every step, which
    // is what makes it safe on a lander tick.
    CommandDecl {
        path: "pr ensure",
        id: "pr.ensure",
        about: "File the row and link it, doing whatever this tick can and saying what it did",
        data_channel: false,
        effect: Effect::Write,
        flags: &[PR_NUMBER],
    },
    // `unclassified` for the same reason as `pr derive`, and it is the
    // last-moment question a landing asks: a bot regenerates its body on every
    // rebase and the closing line goes with it, so the answer read a step earlier
    // is not the answer at the ref move.
    CommandDecl {
        path: "pr closes",
        id: "pr.closes",
        about: "Whether a pull request's body still closes a tracker key, asked at the last moment",
        data_channel: false,
        effect: Effect::Unclassified,
        flags: &[PR_NUMBER],
    // The `task` noun (CLOUD-425), ported off `mise-tasks/alive.sh` under
    // CLOUD-843.
    //
    // ONE LEAF, WHICH IS A COST RATHER THAN A DESIGN. A noun with a single verb
    // is the singleton shape CLOUD-1184 counts as a defect, and the writer half
    // that would have populated it could not land: `mise-tasks/land-lock.sh`
    // binds the retiring writer to a variable and spends it with arguments, and
    // `shell-retirement` has no admitted addition for a spend site (CLOUD-1283).
    // Shipping the writer verbs unconsumed would be dead surface every gate here
    // would then certify, so they are not shipped.
    // The `task` noun (CLOUD-425), ported off `mise-tasks/task-registry.sh` and
    // `mise-tasks/alive.sh` under CLOUD-843. Both halves, because the registry is
    // one mechanism read from both ends.
    CommandDecl {
        path: "task",
        about: "What long-running tasks are doing, recorded where it can be read without a log",
        data_channel: false,
        effect: Effect::Unclassified,
        flags: &[],
    },
    // `write`, all five of them, and declared rather than inferred: each edits a
    // record under the git dir. A row claiming `read` would put a writing verb on
    // the derived read-only allowlist.
    CommandDecl {
        path: "task register",
        about: "Record that a task has started, under its pid",
        data_channel: false,
        effect: Effect::Write,
        flags: &[TASK_NAME, TASK_PID, TASK_PHASE],
    },
    CommandDecl {
        path: "task phase",
        about: "Record what a registered task is now doing",
        data_channel: false,
        effect: Effect::Write,
        flags: &[TASK_PID, TASK_VALUE],
    },
    // The two loop signals, and they are separate verbs because they answer
    // different questions (CLOUD-499). `tick` moves on every iteration including
    // the ones that learn nothing, so a frozen tick means the loop is blocked
    // rather than waiting; `sig` moves only when a watched thing does, so a
    // frozen sig under a moving tick is a poll that will never resolve — the
    // livelock a hang detector cannot see.
    CommandDecl {
        path: "task tick",
        about: "Record that a task's loop went round",
        data_channel: false,
        effect: Effect::Write,
        flags: &[TASK_PID, TASK_VALUE],
    },
    CommandDecl {
        path: "task sig",
        about: "Record that the world a task is watching moved",
        data_channel: false,
        effect: Effect::Write,
        flags: &[TASK_PID, TASK_VALUE],
    },
    CommandDecl {
        path: "task unregister",
        about: "Drop a task's record, which its exit path does and a kill cannot",
        data_channel: false,
        effect: Effect::Write,
        flags: &[TASK_PID],
    },
    // `read`, structurally: one field out of one record, opening nothing else.
    CommandDecl {
        path: "task read",
        about: "One field of one task's record, so a prober composes rather than parsing the layout",
        data_channel: false,
        effect: Effect::Read,
        flags: &[TASK_PID, TASK_FIELD],
    },
    // `write`, and the classification is the interesting one: `alive` READS the
    // registry and is nonetheless a write, because reporting a corpse also REAPS
    // it — a headstone read once is a diagnosis, read forever it is a registry
    // that fills up and stops being read. A row claiming `read` here would be
    // false in the one direction the derived allowlist exists to prevent.
    CommandDecl {
        path: "task alive",
        about: "What tasks are running right now and what phase each is in — one call, no log reading",
        data_channel: false,
        effect: Effect::Write,
        flags: &[TASK_PROGRAM_ROOT, HOOK_INSTANT],
    },
    // The `claim` noun (CLOUD-1121), ported off `mise-tasks/claim-check.sh` on the
    // same terms.
    CommandDecl {
        path: "claim",
        id: "claim",
        about: "Whether the issue you are about to pull is actually unclaimed",
        data_channel: false,
        effect: Effect::Unclassified,
        flags: &[],
    },
    // `write`, and declared rather than inferred: the pullable path MINTS a claim
    // receipt under the git dir, which is the whole reason this verb exists rather
    // than a pure read — the mediated claim gate needs a claimed branch to be
    // distinguishable from an unclaimed one. A row claiming `read` here would put
    // a writing verb on the derived read-only allowlist.
    CommandDecl {
        path: "claim check",
        id: "claim.check",
        about: "Refuse a pull of an issue somebody is already on, and mint the receipt when it is free",
        data_channel: true,
        effect: Effect::Write,
        flags: &[TAKEOVER, BYPASS_SEQUENCE, ADOPT, ADOPT_FROM, ISSUE, JSON],
    },
    // `write`, for `claim check`'s reason one row up: the derivable path MINTS a
    // receipt under the git dir. A row claiming `read` would put a writing verb on
    // the derived read-only allowlist.
    // `write`, for `claim check`'s reason two rows up, and it is the SECOND
    // receipt kind because the two attest different things (CLOUD-693,
    // CLOUD-431). The agent receipt says a human or agent read the issue and
    // confirmed the refinement predates this session; nothing on a bot branch can
    // honestly say that, so widening it would make it mean less everywhere. This
    // attests what IS decidable from public facts: the head was opened by a bot
    // the lane declares, its diff touches only manifests the lane owns, and its
    // body names the row derived from that diff.
    //
    // NO `-J`, for `pr derive`'s reason: what this verb can say depends on what
    // the forge answers about the branch's open pull request, so the `-J`
    // census's byte-stability term would be a claim about the forge. Its sibling
    // `claim carry` one row down DOES declare the channel, and the difference is
    // exactly that: that predicate is decided offline against the merge base.
    CommandDecl {
        path: "claim bot",
        id: "claim.bot",
        about: "Attest a bot branch from the lane's public facts, and mint the receipt when they hold",
        data_channel: false,
        effect: Effect::Write,
        flags: &[],
    },
    CommandDecl {
        path: "claim carry",
        id: "claim.carry",
        about: "Attest that this branch only carries licence rows forward, and mint the receipt when it does",
        data_channel: true,
        effect: Effect::Write,
        flags: &[JSON],
    },
    CommandDecl {
        path: "semver",
        id: "semver",
        about: "Whether this branch's API delta is compatible with the bump it claims",
        data_channel: false,
        effect: Effect::Unclassified,
        flags: &[],
    },
    CommandDecl {
        path: "semver check",
        id: "semver.check",
        about: "Refuse an API break this branch's commits do not declare",
        // NO DATA CHANNEL, declared rather than defaulted. The verdict is one
        // human line naming the route and the failing lint ids; there is no `-J`
        // emitter behind it, and claiming the channel without one is the drift
        // `every_data_emitting_verb_declares_the_json_flag` exists to catch — it
        // caught this.
        data_channel: false,
        effect: Effect::Write,
        flags: &[SEMVER_BASELINE, SEMVER_RELEASE_TYPE, SEMVER_PACKAGE],
    },
    CommandDecl {
        path: "attribution",
        id: "attribution",
        about: "What produced commits may carry about the tooling that made them",
        data_channel: false,
        effect: Effect::Unclassified,
        flags: &[],
    },
    // Reads commit metadata through git and matches configured patterns against
    // it. Nothing is spawned but git's own read-only plumbing and no user-supplied
    // code is reachable, which is what the `read` structural promise requires.
    CommandDecl {
        path: "attribution check",
        id: "attribution.check",
        about: "Refuse vendor authorship, branding or session links in commit metadata",
        data_channel: true,
        effect: Effect::Read,
        flags: &[JSON, RANGE, MESSAGE, ATTRIBUTION_HARNESS],
    },
    // The one write this subject introduces, self-declared (§5). Repo-local only:
    // it writes `.git/config` in this checkout and never `--global`, which covers
    // a developer's own unrelated repositories.
    CommandDecl {
        path: "attribution identity",
        id: "attribution.identity",
        about: "Set this clone's repo-local git identity when it is unset or denied",
        data_channel: false,
        effect: Effect::Write,
        flags: &[],
    },
    // The `worktree` noun only dispatches, and it stays `Unclassified` even
    // now that `status` is the whole subtree (CLOUD-780 retired `reclaim`).
    // Absence is `Ask`, never `Read`, and classifying the noun `read` would put
    // a PREFIX on the derived allowlist for any consumer that treats an entry
    // as one — a widening this deletion has no business making. Same fail-safe
    // posture as `receipt`: listed with its reason, never guessed (CLOUD-51).
    CommandDecl {
        path: "worktree",
        id: "worktree",
        about: "Worktrees and the work in them: what is at risk",
        data_channel: false,
        effect: Effect::Unclassified,
        flags: &[],
    },
    // Fixed, read-only VCS queries plus arithmetic over their output. A `read`
    // verb may run a fixed git query — `receipt status` already does — and what
    // it must never reach is user-supplied code, which no path here does.
    CommandDecl {
        path: "worktree status",
        id: "worktree.status",
        about: "Report work that is uncommitted, unpushed, or not landed on the configured target",
        data_channel: true,
        effect: Effect::Read,
        flags: &[JSON],
    },
    // The `override` noun only dispatches, and its subtree writes, so it takes
    // `provision`'s conservative reading rather than `policy`'s: a write-bearing
    // subtree under a `read` noun would leak onto the derived allowlist for any
    // consumer that treats an entry as a prefix (CLOUD-90).
    CommandDecl {
        path: "override",
        id: "override",
        about: "Issued admissions: an override is a record, never a variable somebody knows",
        data_channel: false,
        effect: Effect::Unclassified,
        flags: &[],
    },
    // CLOUD-1051. `write`, and the write is the whole point: what authorizes is
    // the RECORD's existence and state, so a verb that only computed an address
    // would authorize nothing.
    //
    // **THE ANSWERS ARRIVE ON STDIN, NOT IN ARGV**, and that is a decision rather
    // than a convenience. Three reasons, in order of weight. A mediated call sees
    // `input.call.command`, so answers in argv would put the author's own
    // reasoning into every hook's input document — and this is the one surface
    // whose payload is deliberately NOT pointer-only, which makes the exposure
    // real. An answer is a sentence, and argv is the wrong shape for prose that
    // may carry quotes and newlines. And the tree already reads its gate inputs
    // this way — `ready-lint`, `claim-check` and `deferral-check` are all pure
    // functions of stdin — so this is the established seam rather than a new one.
    //
    // No `-J`: it matches every other write row (`init`, `baseline`, `defects
    // add`, `provision apply`), and the answer a caller needs is one admission on
    // stdout, which a JSON document of one field would not improve.
    CommandDecl {
        path: "override request",
        id: "override.request",
        about: "Answer a class's declared precondition and receive an admission for one situation",
        data_channel: false,
        effect: Effect::Write,
        flags: &[OVERRIDE_RULE, OVERRIDE_VERDICT, OVERRIDE_SUBJECT],
    },
    // CLOUD-1051's other half, and the acceptance clause `request` alone cannot
    // meet: "no gate honours a bare env var" needs something that CONSUMES.
    //
    // **A SEPARATE VERB RATHER THAN A FLAG ON THE GATE**, on house-style §5's
    // line. `check` is declared `read`, and `perform_requested_sinks` states why
    // that has to stay true: a read-effect verb that left a record behind would
    // be a verb that changes what it is judging. Spending moves a record from
    // issued to spent, which is a write, so it is its own verb — called by the
    // gate's task AFTER the refusal rather than folded into the thing that
    // refused. The effect model stays honest and the gate stays a pure read.
    //
    // **THE SITUATION IS RE-STATED, NOT REMEMBERED.** A caller passes the rule,
    // the class and the subject again rather than having them read out of the
    // record, because the whole binding is that an admission is valid for ONE
    // situation: reading them from the record would make every spend
    // self-consistent by construction and the binding decorative.
    //
    // No `-J`, matching every other write row: the answer is a verdict, and the
    // exit code carries it.
    CommandDecl {
        path: "override spend",
        id: "override.spend",
        about: "Spend an issued admission against the situation it was issued for",
        data_channel: false,
        effect: Effect::Write,
        flags: &[
            OVERRIDE_ADMISSION,
            OVERRIDE_RULE,
            OVERRIDE_VERDICT,
            OVERRIDE_SUBJECT,
        ],
    },
    // The `provision` noun only dispatches, and its subtree carries a write
    // verb, so it takes `receipt`'s conservative reading rather than `policy`'s:
    // a write-bearing subtree under a `read` noun would leak onto the derived
    // allowlist for any consumer that treats an entry as a prefix (CLOUD-90).
    CommandDecl {
        path: "provision",
        id: "provision",
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
        id: "provision.status",
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
        id: "provision.apply",
        about: "Fetch, verify against the pinned checksum, and install into the out-of-tree cache",
        data_channel: false,
        effect: Effect::Write,
        flags: &[DRY_RUN],
    },
    // The container's own preconditions (CLOUD-1324), as `[[startup]]` rows
    // declare them. §9's check/fix pair again — `provision status`/`provision
    // apply` established the shape here first — with the two halves as one verb
    // and a flag rather than two sub-verbs, because unlike the manifest above
    // there is exactly one subject and re-deciding IS the fix half's report.
    //
    // `Unclassified` rather than `Read`, and for `enforce`'s stated reason: a
    // row's `check` is a command the operator declared, so bare `startup` runs
    // user-supplied code even though it writes nothing itself. §5 says such a
    // verb is listed unclassified with a stated reason rather than guessed, and
    // it is excluded from the derived read-only allowlist by construction.
    CommandDecl {
        path: "startup",
        id: "startup",
        about: "Report whether this container matches what the repository declares",
        data_channel: true,
        effect: Effect::Unclassified,
        flags: &[REPAIR, JSON],
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
        id: "hook",
        about: "Adjudicate a mediated tool call read from stdin (a deny is exit 2, the one contract)",
        // Excluded deliberately: `hook`'s stdout is already a harness-shaped
        // decision document that the host parses. A second JSON shape on the
        // same stream, selected by a flag the host does not pass, could only
        // ever be an ambiguity — and it would break the per-harness decision
        // channel CLOUD-40 pinned.
        data_channel: false,
        effect: Effect::Unclassified,
        flags: &[
            HOOK_INSTANT,
            FlagDecl::required_enum(
                "harness",
                "harness",
                "The harness whose payload to decode and whose decision channel to answer in",
                harness_parser,
            ),
        ],
    },
    // The payload noun exists so the extractor is NOT `hook field` (CLOUD-479).
    // `attach` marks any path with children `subcommand_required`, because §2
    // says a noun performs no default action — so nesting under `hook` would
    // have turned the PreToolUse mediator itself into a noun that refuses to
    // adjudicate. Measured while writing this: `batten hook --harness
    // claude-code` began answering `requires a subcommand`, which is policy
    // unenforced for every mediated call.
    CommandDecl {
        path: "payload",
        id: "payload",
        about: "Read a hook payload from stdin",
        data_channel: false,
        effect: Effect::Read,
        flags: &[],
    },
    // A DECODER, not a mediator, and the classification is the honest one rather
    // than one inherited from `hook`: this reads stdin, projects one named
    // field, and renders no verdict, so it is `read` and belongs on the derived
    // read-only allowlist.
    //
    // `data_channel: false` deliberately. The channel column means "this verb
    // emits a DOCUMENT", and the census that column drives requires the document
    // to be emitted unconditionally — including when the answer is empty. This
    // verb must print exactly nothing for an absent field, because its callers
    // are shell hooks reading `[ -n "$x" ]`, so it emits a bare value and not a
    // document. There is correspondingly no `-J`: there is no shape to encode.
    //
    // It exists because three registrations paid ~203ms of `mise` startup each
    // to run `jq` for single-digit milliseconds of work, and invoking them by
    // path would have resolved an unpinned `jq` — turning a pinned dependency
    // into a silent fail-open, which is worse than the latency.
    CommandDecl {
        path: "payload field",
        id: "payload.field",
        about: "Print one field of a hook payload read from stdin, for a shell hook that must not depend on jq",
        data_channel: false,
        effect: Effect::Read,
        flags: &[
            FlagDecl::required_enum(
                "harness",
                "harness",
                "The harness whose payload dialect to decode",
                harness_parser,
            ),
            FlagDecl::required_enum(
                "name",
                "name",
                "Which payload field to print; an allowlist, never a JSON path",
                hook_field_parser,
            ),
        ],
    },
    // The `receipt` noun only dispatches, but its subtree carries a write verb;
    // classifying it `read` would put a write-bearing subtree onto the derived
    // allowlist for any consumer that treats entries as prefixes. Same fail-safe
    // posture as `hook`: listed with a reason, never allowed to leak
    // (CLOUD-203).
    CommandDecl {
        path: "receipt",
        id: "receipt",
        about: "Verification receipts: SHA-keyed claims a named check passed, invalidated by git facts",
        data_channel: false,
        effect: Effect::Unclassified,
        flags: &[],
    },
    // Creates state the caller can recreate by re-running the check.
    CommandDecl {
        path: "receipt record",
        id: "receipt.record",
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
    // `--key`, and it is what lets the tree surface reach this predicate at all
    // (CLOUD-741). A `receipt` rule is pinned to `RuleScope::MediatedCall`, so
    // `batten check` cannot evaluate one and `verify` had re-implemented the
    // branch-keyed question in shell — as a presence test, which is strictly
    // weaker than the engine's and passed the very incident CLOUD-516 was filed
    // for. This flag is the seam that lets both callers run ONE implementation.
    //
    // Defaulted to `head` rather than required, so every caller predating it is
    // byte-identical: the SHA keying was the only keying this verb had.
    CommandDecl {
        path: "receipt status",
        id: "receipt.status",
        about: "Judge the named check's recorded receipt against HEAD and origin/main",
        data_channel: true,
        effect: Effect::Read,
        flags: &[
            FlagDecl::positional("check", "The check whose receipt is judged"),
            FlagDecl::defaulted_enum(
                "key",
                "key",
                "Which git fact the receipt is judged against: the exact commit, or the branch",
                receipt_key_parser,
                "head",
            ),
            JSON,
        ],
    },
    // The noun only dispatches; its subtree carries a write verb, so the parent
    // stays unclassified rather than advertising a write-bearing `read` prefix
    // on the derived allowlist (CLOUD-170) — the posture `receipt` and `state`
    // already take.
    CommandDecl {
        path: "defects",
        id: "defects",
        about: "The append-only defect ledger: the lessons this repository has already paid for",
        data_channel: false,
        effect: Effect::Unclassified,
        flags: &[],
    },
    // Inspection only: reads the committed ledger and reports pointers. Joins
    // the derived read-only allowlist.
    CommandDecl {
        path: "defects query",
        id: "defects.query",
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
        id: "defects.add",
        about: "Append defect records read as JSONL on stdin",
        // Reports counts on stderr under -n; there is no document to emit.
        data_channel: false,
        effect: Effect::Write,
        flags: &[DRY_RUN],
    },
    // The noun only dispatches, and takes `receipt`'s conservative posture for
    // the reason that posture exists: `design attest` (write) is the declared
    // next verb under this path, and a `read` parent would advertise a
    // write-bearing prefix to any consumer treating allowlist entries as
    // prefixes (CLOUD-170).
    CommandDecl {
        path: "design",
        id: "design",
        about: "Design-evidence claims: the integrity of the record behind a decision",
        data_channel: false,
        effect: Effect::Unclassified,
        flags: &[],
    },
    // Reads a claim stream on stdin and reports pointers. No file is opened, no
    // process is spawned, and nothing configured is executed — the narrowest
    // possible `read`, so it joins the derived read-only allowlist.
    CommandDecl {
        path: "design audit",
        id: "design.audit",
        about: "Audit a JSONL design-evidence claim stream on stdin for record integrity",
        data_channel: true,
        effect: Effect::Read,
        flags: &[JSON],
    },
    // The noun only dispatches, and it takes the same posture `receipt` does:
    // its subtree carries a write verb, so classifying the parent `read` would
    // advertise a write-bearing prefix on the derived allowlist (CLOUD-170).
    CommandDecl {
        path: "state",
        id: "state",
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
        id: "state.adopt",
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
        id: "state.record",
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
        id: "state.migrate",
        about: "Upgrade the findings store to this binary's record version",
        // Reports counts on stderr; there is no document to emit.
        data_channel: false,
        effect: Effect::Write,
        flags: &[],
    },
    // The ANSWER channel for a finding the condition cannot clear (CLOUD-587).
    //
    // A verb under `state` rather than a new noun: the findings store has one
    // noun, and `record` is already a per-observation write into the journal, so
    // a disposition is the same kind of act against the same object. A second
    // noun would give one store two entry points and every later reader would
    // have to work out which owns settlement.
    //
    // `write`, declared rather than smuggled into a read verb — it appends to
    // the journal. The append is the one that already exists, so no new write
    // path and no new lock arrives with it.
    //
    // WHY THIS IS NEEDED AT ALL: an EVENT-anchored finding cannot self-clear. A
    // bypass that happened, happened, so re-evaluation keeps finding it and the
    // observation never resolves to zero — CLOUD-98's own assumption says such a
    // finding "clears by disposition in the store, not by the condition
    // vanishing", which was correct as a design and unreachable as a mechanism:
    // `stop.rs` READS `disposition`, `journal::merge` FOLDS it, and nothing
    // outside a unit test ever wrote one.
    CommandDecl {
        path: "state settle",
        id: "state.settle",
        about: "Record what was decided about a stored finding",
        // Reports the identity and the token on stderr; there is no document.
        data_channel: false,
        effect: Effect::Write,
        // Both REQUIRED, unlike `adopt`'s optional store: there is no defensible
        // default for either. An omitted identity would have to mean "every
        // finding", and an omitted disposition would have to guess what an agent
        // decided — and a guessed disposition is exactly the un-auditable
        // settlement this verb exists to make explicit.
        flags: &[
            FlagDecl::positional(
                "identity",
                "The stored finding's identity, as `state list` prints it",
            ),
            FlagDecl::positional(
                "disposition",
                "What was decided: acted, rejected-by-design or rejected-wrong",
            ),
        ],
    },
    // Store reads plus fixed read-only git plumbing. A `read` verb may run a
    // fixed VCS query; what it must never reach is user-supplied code, and no
    // configured command is reachable from this path (CLOUD-170).
    CommandDecl {
        path: "state list",
        id: "state.list",
        about: "List stored findings and the refs they were observed in",
        data_channel: true,
        effect: Effect::Read,
        flags: &[JSON],
    },
    // The out-of-tree verdict stores' WRITE half, and the reason it is one noun
    // with two leaves is that the two stores share a body format and nothing else
    // (CLOUD-1265).
    //
    // [`crate::tools`] and [`crate::forge`] both READ a keyed record and both
    // shipped with no writer, so `validator-verdict-clean` and
    // `forge-verdict-required` — two registered `severity = "deny"` rows — have
    // decided nothing on any real checkout since the day they merged. That is
    // CLOUD-845's dead gate, twice, and each row already says so in `batten.toml`:
    // "SILENT UNTIL A PRODUCER WRITES."
    //
    // TWO LEAVES RATHER THAN ONE VERB WITH A MODE FLAG. The key derivations share
    // nothing: `tools::record_key` composes `<tool>@<version>@<digest>` from a
    // declared row plus bytes read off disk, and `forge::record_path` is a resolved
    // sha. A flag deciding WHICH key gets composed would be a second authority over
    // one byte format, which is the shape this family exists to refuse.
    //
    // `record <object>` rather than `tool record`, because CLOUD-1190 moves the
    // surface onto imperative `VERB OBJECT` and inverts `receipt record` and
    // `state record` when it lands. A `tool record` added today would be a third row
    // to invert; this spelling is already the target. The transitional
    // inconsistency is real, and it is the cost of not growing the backlog.
    //
    // `unclassified`, taking `receipt`'s and `state`'s reading rather than
    // `policy`'s: the whole subtree writes, and a `read` noun over a write-bearing
    // subtree leaks onto the derived allowlist for any consumer that treats an entry
    // as a prefix (CLOUD-170).
    CommandDecl {
        path: "record",
        id: "record",
        about: "Out-of-tree verdict stores: what something else judged, keyed so a stale answer cannot answer",
        data_channel: false,
        effect: Effect::Unclassified,
        flags: &[],
    },
    // Its own verb rather than a flag on `check`, for `state record`'s reason: a
    // `--record` there would flip `check` from `read` to `write` and drop it out of
    // the derived agent allowlist, for a side effect nobody asked that invocation
    // for.
    //
    // THE RUN STAYS OUTSIDE. This ingests a verdict on stdin and spawns no
    // validator. §5 makes `check` `read`, and the whole family is built on the tool
    // staying a command on PATH — §9's prior-art disposition, which `batten.toml`
    // and `policy/validator-verdict-clean.rego` both state at their own sites.
    //
    // ONE POSITIONAL AND NO FLAGS, and that is the anti-staleness property rather
    // than minimalism. There is no `--digest`, `--tool`, `--version` or `--input`:
    // the id names a `[[rule.tools]]` row, and the tool, its pin and the input path
    // all come from the committed config. So a caller cannot supply a digest at all.
    // [`crate::tools::verdicts`] digests the subject itself "because the digest is
    // what makes the record stale-by-construction and a caller that supplied one
    // could supply the wrong one", and this composes the same key with the same two
    // functions. The negative half falls out for free: a record for a tool nobody
    // declared is unspellable.
    CommandDecl {
        path: "record tool",
        id: "record.tool",
        about: "Record a declared tool row's verdict, read as `<name> <token>` lines on stdin",
        // Records state and reports nothing; there is no document to emit.
        data_channel: false,
        effect: Effect::Write,
        flags: &[FlagDecl::positional(
            "id",
            "The `[[rule.tools]]` id whose verdict is being recorded",
        )],
    },
    // The sibling half, and what keeps this noun from being the thirteenth singleton
    // CLOUD-1184 counts. The two stores differ in their KEY and in nothing else
    // (CLOUD-1171), so they are two leaves over one concept rather than two nouns —
    // and building both is what wakes `forge-verdict-required` up.
    CommandDecl {
        path: "record forge",
        id: "record.forge",
        about: "Record the forge's check verdicts for one commit, read as `<check> <conclusion>` lines on stdin",
        data_channel: false,
        effect: Effect::Write,
        flags: &[FlagDecl::positional(
            "ref",
            "The ref or sha the verdict was taken against",
        )],
    },
    // CLOUD-472. A VERB rather than a `[[recorder]]` on the harness's own todo
    // tool, and the direction is the point: a hook mediates a call to somebody
    // else's tool and is per-harness by nature, so an unsurveyed host, a tool a
    // setting disabled, and an agent that did as it was told all record nothing and the gate
    // reads clean. Telling the engine fails closed everywhere instead.
    //
    // No positional: the branch is the key and the engine resolves it, so a
    // caller cannot record against a branch it is not on — `record tool`'s
    // anti-staleness argument, applied to a different key.
    CommandDecl {
        path: "record plan",
        id: "record.plan",
        about: "Record this branch's plan, read as `<id> <status>` lines on stdin",
        data_channel: false,
        effect: Effect::Write,
        flags: &[],
    },
    // The same argument one layer over, and here the envelope route is not merely
    // per-harness — it is unreliable in the ordinary case. `filed-over-own-diff`
    // exempts a row the PR CLOSES, and reads that from a `pr-closes` record the
    // `pr-body-closes` recorder mints from an observed `gh pr view --jq .body`
    // envelope. `land` fetches exactly that body and pipes it to
    // `filed-here-check`, whose task body is `batten check`, which is declared
    // `read` and has no stdin channel — so on the landing path the body is
    // fetched, handed over, and dropped, and the exemption depends on an agent
    // having separately made the same call as a mediated tool. Measured on this
    // branch: three rows it closes, refused, with no record in the store at all.
    //
    // No positional, for `record plan`'s reason: the branch is the key.
    CommandDecl {
        path: "record closes",
        id: "record.closes",
        about: "Record which rows this branch's pull request body closes, read on stdin",
        data_channel: false,
        effect: Effect::Write,
        flags: &[],
    },
    // A NEW NOUN rather than a flag on an existing verb, and two shapes were
    // considered and died on the same rule (CLOUD-893). `generate hooks --write`
    // and `doctor hooks --repair` both hang the effect off a FLAG, where §5 hangs
    // it off a ROW — and the agent read-only allowlist is `filter(effect ==
    // read)` with no second list, so a write flag on either row would drop the
    // pure-stdout invocation every consumer already uses out of the allowlist.
    // `batten hook install` died on settled precedent instead: nesting a noun
    // under `hook` "turned the `PreToolUse` mediator into a noun that refused to
    // adjudicate", which is why `payload` is top-level.
    //
    // `unclassified`, taking `provision`'s reading rather than `policy`'s: the
    // subtree carries a destructive verb, and a write-bearing subtree under a
    // `read` noun leaks onto the derived allowlist for any consumer that treats an
    // entry as a prefix (CLOUD-90).
    CommandDecl {
        path: "wiring",
        id: "wiring",
        about: "Repair a host's hook registrations",
        data_channel: false,
        effect: Effect::Unclassified,
        flags: &[],
    },
    // `destructive`, not `write`, and the precedent is `attribution identity`'s
    // own recorded reasoning: that verb refused a `--global` write precisely
    // because one file is shared by every checkout on the box. This edits exactly
    // such files. What it removes is also somebody else's registration rather than
    // batten's own artifact, and recovering one means knowing what it was — which
    // is what the at-load record exists to preserve and what §6 forbids the report
    // from printing. §5 binds `-y --yes` to this effect, so a non-interactive
    // caller is told the flag rather than prompted into the void.
    //
    // Required UNCONDITIONALLY rather than only when unattended, following
    // `capture prune`: §4's own words are that a policy engine which blocks a loop
    // waiting for Y/N is a dead gate, and the primary caller here is a program. A
    // rule that never prompts cannot hang.
    CommandDecl {
        path: "wiring reclaim",
        id: "wiring.reclaim",
        about: "Remove non-batten hook registrations from this host's merged surfaces",
        data_channel: false,
        // `Destructive` is the VERB's classification and stays so, even though
        // `--check` and `--dry-run` write nothing: §5 classifies a command by
        // what it may do, not by what a particular invocation chose. A reader
        // must not learn that a destructive verb is sometimes safe.
        effect: Effect::Destructive,
        flags: &[DRY_RUN, CHECK],
    },
    // CLOUD-1274. THE LANDING LEASE, and the noun is `unclassified` for
    // `provision`'s reason rather than `policy`'s: the subtree writes — a
    // compare-and-swap over a remote ref is a write to somebody else's server —
    // and a write-bearing subtree under a `read` noun leaks onto the derived
    // allowlist for any consumer that treats an entry as a prefix (CLOUD-90).
    CommandDecl {
        path: "lease",
        id: "lease",
        about: "The landing lease: one branch spends a matrix at a time",
        data_channel: false,
        effect: Effect::Unclassified,
        flags: &[],
    },
    // `read`, and it is the ONE row a GitHub runner calls. Every other verb here
    // answers about a CLONE — ownership is a holder id minted per clone, which a
    // runner has nothing to compare against — so this is the only question the
    // thing spending the money can ask for itself.
    //
    // **The predecessor's own exit vocabulary is NOT carried, and dropping it is
    // the correction rather than a loss.** `land-lock authorises` answered `0`
    // run / `3` stop / `2` could not look, because its file's `1` already meant
    // "held by someone else". The engine has one table and no per-verb exception
    // (non-negotiable rule 5): `2` is the policy verdict everywhere and `1`/`3`
    // are the only codes a Batten failure produces. So a stop is `2` and a lease
    // that cannot be read is `3`, which is what every other verb here already
    // means by those codes — and a CI caller keying on the old numbers reads a
    // refusal as an error, which is why the workflow moves in the same change.
    CommandDecl {
        path: "lease authorises",
        id: "lease.authorises",
        about: "May this branch spend a matrix right now?",
        data_channel: false,
        effect: Effect::Read,
        flags: &[LEASE_BRANCH],
    },
    // `read`, and it is a GATE rather than a report — the distinction the status
    // row cannot carry, because hanging a verdict off a flag is exactly what §5
    // refuses: the read-only allowlist is `filter(effect == read)` with no second
    // list, so a refusing flag on a reporting row would drop the reporting
    // invocation every consumer already uses.
    //
    // **It belongs on a CLOCK, never on the landing path.** Neither refusal is a
    // correctness hazard for the trunk — the lease decides who goes first, never
    // what may land — so on the landing path it would fail whichever PR happened
    // to be in flight over a condition that PR did not cause and cannot fix.
    CommandDecl {
        path: "lease check",
        id: "lease.check",
        about: "Gate: the lease is free or a live, well-formed hold — never a wedge and never garbage",
        data_channel: false,
        effect: Effect::Read,
        flags: &[],
    },
    // `read`. Prose for a human, and `-J` for everyone else — which is what stops
    // a caller parsing the sentence and turning a message into an interface, where
    // the next edit to the wording would be a silent breakage.
    CommandDecl {
        path: "lease status",
        id: "lease.status",
        about: "Report who holds the lease, for how much longer, and who is admitted behind them",
        data_channel: true,
        effect: Effect::Read,
        flags: &[JSON],
    },
    // `read`. ONE ADVISORY FIELD, ON STDOUT, FOR A CALLER THAT MEANS TO ACT ON IT
    // — the machine-readable half of `status` for the fields a waiter reads.
    // Silent and `0` when the lease is absent, released or expired: "no lease
    // names a head" is a legitimate reading a waiter handles by staying on trunk,
    // not an error it should report.
    CommandDecl {
        path: "lease peek",
        id: "lease.peek",
        about: "Print one advisory field of the held lease, or nothing",
        data_channel: false,
        effect: Effect::Read,
        flags: &[LEASE_FIELD],
    },
    // `read`, and it is a read despite being the fence a holder checks before it
    // acts: it mints nothing and swaps nothing. It demands MARGIN rather than
    // merely a lease that has not expired — "not expired" is a fact about the
    // instant of the check, and the caller then goes on to post a comment or wait
    // for a bot, so a lease with one second left passes and is gone before the
    // action it authorised takes effect. One beat is the right margin because it
    // is the interval at which the holder proves it is alive.
    CommandDecl {
        path: "lease held",
        id: "lease.held",
        about: "Is this clone's lease still held, with a beat of margin to act on?",
        data_channel: false,
        effect: Effect::Read,
        flags: &[],
    },
    // `write`: a compare-and-swap over a remote ref.
    CommandDecl {
        path: "lease acquire",
        id: "lease.acquire",
        about: "Take the lease, waiting out a live holder and reaping a dead one",
        data_channel: false,
        effect: Effect::Write,
        flags: &[LEASE_BRANCH],
    },
    // `write`. One-shot, as against `hold`'s loop.
    CommandDecl {
        path: "lease renew",
        id: "lease.renew",
        about: "Extend this clone's lease by one term",
        data_channel: false,
        effect: Effect::Write,
        flags: &[],
    },
    // `write`. The heartbeat, which a caller backgrounds for the length of a hold
    // and kills from the same trap that releases.
    CommandDecl {
        path: "lease hold",
        id: "lease.hold",
        about: "Renew this clone's lease every beat until it is lost or the hold ends",
        data_channel: false,
        effect: Effect::Write,
        flags: &[],
    },
    // `write` rather than `destructive`, and the distinction is the tombstone's:
    // a release CASes the expiry to a sentinel and deletes nothing, so there is no
    // ref to recover and nothing a `-y` would be protecting. Releasing a lease
    // this clone does not hold is not an error either — the trap that calls it
    // fires on every exit path, including ones that never acquired.
    CommandDecl {
        path: "lease release",
        id: "lease.release",
        about: "Hand the lease back, leaving a tombstone rather than deleting the ref",
        data_channel: false,
        effect: Effect::Write,
        flags: &[],
    },
    // `write`. The second matrix, and the only one: admitting one successor while
    // the holder is still merging is what overlaps the window in which the queue
    // would otherwise be cold.
    CommandDecl {
        path: "lease reserve",
        id: "lease.reserve",
        about: "Take the one slot behind the current holder",
        data_channel: false,
        effect: Effect::Write,
        flags: &[LEASE_BRANCH],
    },
    // CLOUD-1335. THE LANDING LAP, and the noun is `unclassified` for the reason
    // the lease subtree carries: it writes. A write-bearing subtree under a `read`
    // noun leaks onto the derived allowlist for any consumer that treats an entry
    // as a prefix (CLOUD-90), and this one writes the odb, a tracking ref, the
    // worktree and a record.
    CommandDecl {
        path: "land",
        id: "land",
        about: "The landing lap: replay this branch onto a base that moved",
        data_channel: false,
        effect: Effect::Unclassified,
        flags: &[],
    },
    // `write`, and it is the widest write in the tree: the odb, a remote-tracking
    // ref, the WORKTREE, and the lap record. It is not `destructive` — a replay
    // that cannot complete refuses and moves nothing, so there is no half-applied
    // state for a `--dry-run` to protect against, and declaring one would offer a
    // rehearsal this verb cannot perform.
    CommandDecl {
        path: "land replay",
        id: "land.replay",
        about: "Advance the base and replay this branch onto it, recording the outcome",
        data_channel: false,
        effect: Effect::Write,
        flags: &[LAND_REFERENCE],
    },
    // `write`, and the write is the RECORD rather than the wait: asking two
    // questions is a read, and what this leaves behind is both arms' answers for
    // a module to decide over. It is `write` rather than `read` for that reason
    // alone, which is the effect model working — the allowlist is derived from
    // the declaration, so a verb that writes anywhere may not sit under `read`.
    CommandDecl {
        path: "land wait",
        id: "land.wait",
        about: "Ask whether this head is green and whether its base still holds; the first answer decides",
        data_channel: false,
        effect: Effect::Write,
        flags: &[LAND_REFERENCE],
    },
    // `write`, and here the write is REMOTE — the only other place in this crate
    // that moves a ref somebody else can read is `lease`'s swap. It takes no
    // reference flag on purpose: a lap pushes the branch it is standing on, and
    // a positional would let a caller aim this head at a ref the rest of the lap
    // is not watching.
    //
    // Not `destructive`: receive-pack's compare-and-swap refuses outright when
    // the ref has moved, so the losing case writes nothing and there is no
    // half-applied state a rehearsal would protect against.
    CommandDecl {
        path: "land push",
        id: "land.push",
        about: "Push this branch to its own ref, under receive-pack's compare-and-swap",
        data_channel: false,
        effect: Effect::Write,
        flags: &[],
    },
    // `write`, and the write is the RECORD — the gate itself does whatever it
    // does, and this verb neither knows nor claims. It is `write` rather than
    // `read` for the allowlist's reason: the effect model is derived from this
    // declaration, so a verb that appends to the lap record may not sit under a
    // `read` noun however read-like its subject looks.
    //
    // NO FLAGS. The command is the consumer's and arrives from the environment,
    // for the reason `land wait` reads its roster there: a lap is always asking
    // about THIS repository, and a flag would be a second spelling of a name the
    // consumer already declares once.
    CommandDecl {
        path: "land verify",
        id: "land.verify",
        about: "Run the configured gate over this head and record what it answered",
        data_channel: false,
        effect: Effect::Write,
        flags: &[],
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
        // `Append` rather than `Set`: every occurrence is kept, in the order
        // written, so a caller widening a selection gets the union rather than
        // the last one silently winning.
        ValueDecl::StrMany => arg.action(ArgAction::Append),
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
    SURFACE.iter().any(|decl| parent_of(decl.path) == path)
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
            // A row that nests AND declares an answer keeps acting bare.
            let sub = if is_noun(decl) {
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
mod identity_tests {
    use super::{ROOT, SURFACE};

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
    /// (see [`super::CommandDecl::id`]), and the failure mode is a later author
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
    fn clap_accepts_the_built_tree() {
        // `debug_assert` walks the whole tree and panics on a malformed arg —
        // the cheapest total check that a new declaration is constructible.
        command().debug_assert();
    }
}
