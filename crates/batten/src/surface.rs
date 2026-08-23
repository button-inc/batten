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

fn config_surface_parser() -> ValueParser {
    ValueParser::new(clap::builder::EnumValueParser::<crate::cli::ConfigSurface>::new())
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
    // Fixed reads of the store's own directory plus arithmetic over the entries.
    CommandDecl {
        path: "capture list",
        about: "List this repository's captures as handles, in a fixed order",
        data_channel: true,
        effect: Effect::Read,
        flags: &[STREAM, JSON],
    },
    // `destructive`, not `write`: what it removes is a record of a run that has
    // already happened, and recovering one means re-running the command — which is
    // precisely the cost this whole capability exists to avoid paying. §5 binds
    // `-y --yes` to this effect, so a non-interactive caller is told the flag it
    // needs rather than prompted into the void.
    CommandDecl {
        path: "capture prune",
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
    // `lint <kind>` (house-style §2, CLOUD-84): a family of text-shape lints over
    // artifacts that are NOT `batten.toml`. Deliberately a top-level verb rather
    // than a `brief` noun — the issue's own §1 refuses a standalone noun, and the
    // kind is what varies. `config lint` stays where it is: it lints the one
    // committed authority, which is a different subject, not a second kind.
    CommandDecl {
        path: "lint",
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
    CommandDecl {
        path: "doctor hooks",
        about: "Diagnose whether batten is wired on every hook surface of every harness",
        // Per-harness detail is the whole reason this is a sub-verb rather than a
        // line in `doctor`'s summary, and `-J` is where that detail goes.
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
    // so the schema cannot describe a `batten.toml` the binary would refuse.
    CommandDecl {
        path: "generate schema",
        about: "Emit the JSON Schema for a config surface, derived from the config types",
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
            "Which config surface to describe: the committed authority, or the override layer",
            config_surface_parser,
            "authority",
        )],
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
        about: "Run each registered module's own `test_` rules and report the predicates none exercised",
        data_channel: true,
        effect: Effect::Read,
        flags: &[JSON],
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
        about: "Refuse a commit subject that does not follow the configured convention",
        data_channel: true,
        effect: Effect::Read,
        flags: &[JSON, RANGE, MESSAGE],
    },
    CommandDecl {
        path: "attribution",
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
    // The payload noun exists so the extractor is NOT `hook field` (CLOUD-479).
    // `attach` marks any path with children `subcommand_required`, because §2
    // says a noun performs no default action — so nesting under `hook` would
    // have turned the PreToolUse mediator itself into a noun that refuses to
    // adjudicate. Measured while writing this: `batten hook --harness
    // claude-code` began answering `requires a subcommand`, which is policy
    // unenforced for every mediated call.
    CommandDecl {
        path: "payload",
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
    // The noun only dispatches, and takes `receipt`'s conservative posture for
    // the reason that posture exists: `design attest` (write) is the declared
    // next verb under this path, and a `read` parent would advertise a
    // write-bearing prefix to any consumer treating allowlist entries as
    // prefixes (CLOUD-170).
    CommandDecl {
        path: "design",
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
