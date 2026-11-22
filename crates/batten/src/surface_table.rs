//! The command surface as data (house style §11, CLOUD-2789): every verb, its
//! flags, environment, values and exit codes.
//!
//! A table, not behaviour: the config checks that a row names a real command
//! read it, and so do the parser, the help renderer and the golden census.
//! Keeping it apart from [`crate::surface`], which interprets it, lets the
//! readers below the command layer name the table without naming the layer.

use clap::ValueEnum;
use clap::builder::ValueParser;

use crate::effect::Effect;

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
    /// The exit codes this row may produce (§7).
    ///
    /// # Why a declaration exists at all
    ///
    /// §7 is stated as total — [`crate::exit`]'s first line, "one table, total,
    /// with no per-verb exception" — and until CLOUD-1646 **nothing checked it
    /// per verb**. The contract was gated in three places and none asked which
    /// codes a verb may produce: [`crate::exit`]'s own tests pin the four
    /// NUMBERS, `cli.rs`'s `exit_code_contract` was a fixed corpus of
    /// hand-written invocations, and `pointer_only.rs`'s census governs
    /// EMISSION. So no machine-checkable statement existed that a verb's
    /// behaviour could contradict, and the law was broken twice — CLOUD-292 in
    /// `exec`, CLOUD-1645 in `mcp call` — with nothing in between that would
    /// have failed. Rule 2: a rule without a runnable gate is half a change.
    ///
    /// # The empty slice is "undeclared", not "declares nothing"
    ///
    /// A struct literal must name every field, so a new row cannot OMIT this —
    /// but it can write `&[]`, and an empty slice that passed would be the
    /// dead-gate class this field exists to close. So `&[]` is reserved for a
    /// NOUN, which dispatches to a subtree and returns nothing of its own, and
    /// `tests::every_leaf_verb_declares_its_exit_set` refuses it on a leaf. Both
    /// directions are checked, so a leaf cannot hide as a noun either.
    ///
    /// # The fill rule
    ///
    /// [`EXITS_STANDARD`] unless there is a reason otherwise, and the reason is
    /// [`ExitCode::Violation`]: only a verb that renders a POLICY VERDICT may
    /// declare it. An over-wide declaration is a gate that decides nothing, so
    /// `2` is the code an author has to justify rather than the one they get for
    /// free.
    ///
    /// This is not a second authority over the codes or their meanings. Those
    /// stay [`crate::exit::ExitCode`]'s alone, which is what keeps the published
    /// table in `--help`, `man/batten.1` and `README.md` rendering from
    /// [`crate::exit::table`] with nothing to drift against.
    pub exits: &'static [crate::exit::ExitCode],
    /// The command's own arguments.
    pub flags: &'static [FlagDecl],
}

/// What a verb declares when it renders no policy verdict.
///
/// `1` and `3` are on every row that runs at all: clap rejects a malformed
/// invocation before the verb is reached, and any verb can fail to look. `0` is
/// the ordinary completion. What is absent is [`ExitCode::Violation`], and its
/// absence is the whole content of this constant.
pub const EXITS_STANDARD: &[crate::exit::ExitCode] = &[
    crate::exit::ExitCode::Success,
    crate::exit::ExitCode::Usage,
    crate::exit::ExitCode::Internal,
];

/// What a verb declares when it renders a policy verdict.
///
/// [`EXITS_STANDARD`] plus [`ExitCode::Violation`] — a rule finding, a denied
/// mediated call, or any other answer ABOUT the repository rather than about the
/// invocation. A verb reaching this through [`crate::exit::ExitCode::verdict`]
/// or by raising [`crate::Denial`] is one of these; nothing else is.
pub const EXITS_VERDICT: &[crate::exit::ExitCode] = &[
    crate::exit::ExitCode::Success,
    crate::exit::ExitCode::Usage,
    crate::exit::ExitCode::Violation,
    crate::exit::ExitCode::Internal,
];

/// What a NOUN declares: nothing, because it decides nothing.
///
/// A noun dispatches to its subtree and prints help when invoked bare, so every
/// code a caller sees under it belongs to a leaf or to clap. Declaring a set
/// here would be a claim about the subtree, which is exactly the inheritance
/// [`CommandDecl::effect`] refuses one field up.
pub const EXITS_DISPATCHES: &[crate::exit::ExitCode] = &[];

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
pub(crate) const RANGE: FlagDecl = FlagDecl {
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

/// The tag `attribution tagger` judges (CLOUD-1794).
///
/// Positional and REQUIRED, which is `RANGE`'s reasoning taken one step further.
/// The tag is the verb's object, and there is no defensible default: resolving
/// "the latest" would need an ordering the history surface deliberately does not
/// carry, and guessing one would make the verb answer about a tag the caller did
/// not name. A missing tag is a usage error, never a vacuous pass.
pub(crate) const TAG: FlagDecl = FlagDecl {
    id: "tag",
    long: None,
    short: None,
    help: "The tag to judge, by short name (v0.0.162)",
    env: EnvDecl::None,
    global: false,
    positional: true,
    required: true,
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
pub(crate) const PR_NUMBER: FlagDecl =
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
pub(crate) const SEMVER_BASELINE: FlagDecl = FlagDecl {
    id: "baseline",
    long: Some("baseline"),
    short: None,
    help: "The rev to measure the API delta against (default: the trunk (`must_land_on`, else the remote's default branch))",
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
pub(crate) const SEMVER_RELEASE_TYPE: FlagDecl = FlagDecl {
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
pub(crate) const SEMVER_PACKAGE: FlagDecl = FlagDecl {
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
pub(crate) const MESSAGE: FlagDecl = FlagDecl {
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
pub(crate) const ATTRIBUTION_HARNESS: FlagDecl = FlagDecl::optional_enum(
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
pub(crate) const AGAINST: FlagDecl = FlagDecl {
    id: "against",
    long: None,
    short: None,
    help: "The git ref whose published schema is the baseline (e.g. v0.0.111), or `latest` for the newest v* tag by version order",
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
pub(crate) const HOST_RULES: FlagDecl = FlagDecl {
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

/// `-J`/`--json`, declared **per data-emitting command** (§6).
///
/// Deliberately not global: a global output mode would be silently accepted by
/// verbs that emit no data — a flag that looks applied and isn't.
/// The fetch bound `claim merged` refuses at, rather than answering short.
pub(crate) const MERGED_LIMIT: FlagDecl = FlagDecl {
    id: "limit",
    long: Some("limit"),
    short: None,
    help: "The most pull requests to read before the answer is truncated (default 5000)",
    env: EnvDecl::None,
    global: false,
    positional: false,
    required: false,
    hidden: false,
    rung: Rung::None,
    value: ValueDecl::Str,
};

/// The explicit sources `claim keys` may be handed for a pull request this
/// checkout did not author (CLOUD-378, carried by CLOUD-1711).
///
/// Passing ANY of them switches to explicit mode: git is not consulted at all and
/// an unsupplied source is empty. All-or-nothing rather than per-source fallback,
/// because a remote pull request silently answered from the LOCAL branch is the
/// worst kind of wrong — a confident verdict about the wrong repository state.
pub(crate) const CLAIM_BRANCH: FlagDecl = FlagDecl {
    id: "branch",
    long: Some("branch"),
    short: None,
    help: "The head branch, standing in for source 2",
    env: EnvDecl::None,
    global: false,
    positional: false,
    required: false,
    hidden: false,
    rung: Rung::None,
    value: ValueDecl::Str,
};

pub(crate) const CLAIM_TITLE: FlagDecl = FlagDecl {
    id: "title",
    long: Some("title"),
    short: None,
    help: "The pull request title, also source 2 — a body is not, because a body cites evidence",
    env: EnvDecl::None,
    global: false,
    positional: false,
    required: false,
    hidden: false,
    rung: Rung::None,
    value: ValueDecl::Str,
};

pub(crate) const CLAIM_LOG: FlagDecl = FlagDecl {
    id: "log",
    long: Some("log"),
    short: None,
    help: "Commit messages, standing in for sources 1 and 3",
    env: EnvDecl::None,
    global: false,
    positional: false,
    required: false,
    hidden: false,
    rung: Rung::None,
    value: ValueDecl::Str,
};

/// Source 1 alone. Mutually exclusive with [`REFS_FIRST_ONLY`]: each names a
/// different SINGLE source, so both together is a caller that has not decided
/// which question it is asking, never an intersection to compute.
pub(crate) const CLOSING_ONLY: FlagDecl = FlagDecl {
    id: "closing_only",
    long: Some("closing-only"),
    short: None,
    help: "Answer from a closing keyword alone, never falling through to the branch or a trailer",
    env: EnvDecl::None,
    global: false,
    positional: false,
    required: false,
    hidden: false,
    rung: Rung::None,
    value: ValueDecl::Bool,
};

/// Source 3 alone — `closing-key-check`'s need (CLOUD-674).
pub(crate) const REFS_FIRST_ONLY: FlagDecl = FlagDecl {
    id: "refs_first_only",
    long: Some("refs-first-only"),
    short: None,
    help: "Answer from the first key of each `Refs:` trailer alone, never sources 1 or 2",
    env: EnvDecl::None,
    global: false,
    positional: false,
    required: false,
    hidden: false,
    rung: Rung::None,
    value: ValueDecl::Bool,
};

/// The manifest `doctor toolchain` reads its declared tool table out of.
///
/// Required and positional: the path is the consumer's, and a default would put
/// a consumer artifact's name in the engine (non-negotiable rule 1).
pub(crate) const MANIFEST: FlagDecl =
    FlagDecl::positional("manifest", "The manifest whose declared tool table to read");

/// `engine pin`'s value (CLOUD-2063): a release tag, `source`, or `version`.
const ENGINE_PIN_VALUE: FlagDecl = FlagDecl::positional_optional(
    "value",
    "The pin to write: a release tag (v0.0.201), `source` for this tree's digest, or `version` for this engine's own release; omitted, refresh a declared source pin",
);

/// `engine pin --check`: say whether the file would change, and change nothing.
pub(crate) const ENGINE_PIN_CHECK: FlagDecl = FlagDecl {
    id: "check",
    long: Some("check"),
    short: None,
    help: "Exit 1 when the pin would change, and write nothing",
    env: EnvDecl::None,
    global: false,
    positional: false,
    required: false,
    hidden: false,
    rung: Rung::None,
    value: ValueDecl::Bool,
};

/// `engine outdated --notice` (CLOUD-2279): the session's half.
pub(crate) const ENGINE_OUTDATED_NOTICE: FlagDecl = FlagDecl {
    id: "notice",
    long: Some("notice"),
    short: None,
    help: "Print one line naming `batten engine update` at most once a day, never in CI, and always exit 0",
    env: EnvDecl::None,
    global: false,
    positional: false,
    required: false,
    hidden: false,
    rung: Rung::None,
    value: ValueDecl::Bool,
};

/// `engine outdated --record <family>` (CLOUD-2279).
pub(crate) const ENGINE_OUTDATED_RECORD: FlagDecl = FlagDecl {
    id: "record",
    long: Some("record"),
    short: None,
    help: "Write the `engine-fresh` line into this declared record family, judged by --max-releases and --max-days",
    env: EnvDecl::None,
    global: false,
    positional: false,
    required: false,
    hidden: false,
    rung: Rung::None,
    value: ValueDecl::Str,
};

/// `engine outdated --max-releases <n>` (CLOUD-2279).
pub(crate) const ENGINE_OUTDATED_MAX_RELEASES: FlagDecl = FlagDecl {
    id: "max_releases",
    long: Some("max-releases"),
    short: None,
    help: "With --record: more releases behind than this is stale",
    env: EnvDecl::None,
    global: false,
    positional: false,
    required: false,
    hidden: false,
    rung: Rung::None,
    value: ValueDecl::Str,
};

/// `engine outdated --max-days <n>` (CLOUD-2279).
pub(crate) const ENGINE_OUTDATED_MAX_DAYS: FlagDecl = FlagDecl {
    id: "max_days",
    long: Some("max-days"),
    short: None,
    help: "With --record: more days behind the first newer release than this is stale",
    env: EnvDecl::None,
    global: false,
    positional: false,
    required: false,
    hidden: false,
    rung: Rung::None,
    value: ValueDecl::Str,
};

/// `engine gate --lane`: a workflow whose command lines run the released binary.
pub(crate) const ENGINE_LANE: FlagDecl = FlagDecl {
    id: "lane",
    long: Some("lane"),
    short: None,
    help: "A workflow that runs the released binary; every verb its command lines invoke must exist in the pinned release (repeatable)",
    env: EnvDecl::None,
    global: false,
    positional: false,
    required: false,
    hidden: false,
    rung: Rung::None,
    value: ValueDecl::StrMany,
};

pub(crate) const JSON: FlagDecl = FlagDecl {
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
pub(crate) const TEE: FlagDecl = FlagDecl {
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
pub(crate) const JOBS: FlagDecl = FlagDecl {
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

/// `--lock` on `exec` (CLOUD-1710), the key one clone's singleton lock is named
/// by.
///
/// A KEY, never a path. `mise-tasks/with-lock.sh` took a lock directory and its
/// callers pointed one at the rust sysroot, so a toolchain swap could not
/// deadlock on a stale path. The key carries that distinction where it belongs —
/// in the name (`target-ensure-<triple>`) — and lets the lock live under
/// `$GIT_DIR` with every other one this clone holds, which is what
/// `batten singleton` and `mise run alive` already read.
pub(crate) const LOCK: FlagDecl = FlagDecl {
    id: "lock",
    long: Some("lock"),
    short: None,
    help: "Hold this clone's named singleton lock for the child's lifetime",
    env: EnvDecl::None,
    global: false,
    positional: false,
    required: false,
    hidden: false,
    rung: Rung::None,
    value: ValueDecl::Str,
};

/// `--lock-path` on `exec` (CLOUD-1710): a lock guarding something the clone
/// does not own.
///
/// The sibling of `--lock`, and the two are not interchangeable. A KEY names a
/// lock under `$GIT_DIR`, which is right for "one task per clone". A PATH names
/// one wherever the resource being serialized actually lives — the retiring
/// shell's two callers both needed that, `doctor`'s lock sitting under
/// `$MISE_DATA_DIR` and `target-ensure`'s inside the rust sysroot, because a
/// mise install tree and a rustup toolchain are the MACHINE's and are shared by
/// every clone on it. Keying those per clone would let two checkouts install a
/// target concurrently and roll each other back (CLOUD-220).
pub(crate) const LOCK_PATH: FlagDecl = FlagDecl {
    id: "lock_path",
    long: Some("lock-path"),
    short: None,
    help: "Hold the lock at this path, for a resource the clone does not own",
    env: EnvDecl::None,
    global: false,
    positional: false,
    required: false,
    hidden: false,
    rung: Rung::None,
    value: ValueDecl::Str,
};

/// `--lock-attempts` on `exec` (CLOUD-1710): how long the queue is, as a COUNT.
///
/// The bound is a number of asks separated by a declared interval, never a wall
/// clock — `land`'s shape, for `land`'s reason. The shell spelled it
/// `WITH_LOCK_TIMEOUT` in seconds and divided by its own `sleep 0.1`; the
/// default here is that same arithmetic already done (600s ⇒ 6000 asks).
pub(crate) const LOCK_ATTEMPTS: FlagDecl = FlagDecl {
    id: "lock_attempts",
    long: Some("lock-attempts"),
    short: None,
    help: "How many times to ask for the lock before reporting it held",
    env: EnvDecl::None,
    global: false,
    positional: false,
    required: false,
    hidden: false,
    rung: Rung::None,
    value: ValueDecl::Str,
};

/// `--lock-label` on `exec` (CLOUD-1710): what the wait was FOR.
///
/// Carried verbatim from the shell, which states why: *"A lock path is a pointer
/// to a file; 'the toolchain lock (aarch64-apple-darwin)' is a pointer to the
/// thing a reader has to reason about, and moving the wait out of the caller
/// must not cost that."*
pub(crate) const LOCK_LABEL: FlagDecl = FlagDecl {
    id: "lock_label",
    long: Some("lock-label"),
    short: None,
    help: "What the wait is for, named by the caller for the refusal line",
    env: EnvDecl::None,
    global: false,
    positional: false,
    required: false,
    hidden: false,
    rung: Rung::None,
    value: ValueDecl::Str,
};

/// `--continue-on-error` on `exec` (CLOUD-430), likewise mise's.
pub(crate) const CONTINUE_ON_ERROR: FlagDecl = FlagDecl {
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
pub(crate) const NO_CACHE: FlagDecl = FlagDecl {
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
/// The rule id `policy rule` resolves (CLOUD-1637).
///
/// Positional and REQUIRED, for the reason [`VERDICT_TOKEN`] is: with no id the
/// verb would print every row — a payload nobody asked for — or exit 0 having
/// answered nothing.
///
/// A distinct declaration from `check`'s `--rule` rather than a reuse of it.
/// That one SELECTS a row to run and is optional; this one NAMES a row to print
/// and is required, so sharing a `FlagDecl` would make one row's `required` a
/// lie about the other.
/// `--findings <n>`: how many blocking findings the caller's own run produced.
///
/// A COUNT rather than a boolean, because the caller already has one and a
/// boolean would make it fold twice — once to a flag and once here — which is the
/// hand-fold this verb exists to remove.
pub(crate) const VERDICT_FINDINGS: FlagDecl = FlagDecl {
    id: "findings",
    long: Some("findings"),
    short: None,
    help: "How many blocking findings the run produced",
    env: EnvDecl::None,
    global: false,
    positional: false,
    required: false,
    hidden: false,
    rung: Rung::None,
    value: ValueDecl::Str,
};

/// `--unjudgeable <n>`: how many subjects the caller could not read.
///
/// Separate from `--findings` rather than folded into it, because the whole
/// point of the verb is that the two are DIFFERENT answers: a blind spot is not
/// a small finding, and a caller that adds them together has already lost the
/// distinction this decides.
pub(crate) const VERDICT_UNJUDGEABLE: FlagDecl = FlagDecl {
    id: "unjudgeable",
    long: Some("unjudgeable"),
    short: None,
    help: "How many subjects the run could not read",
    env: EnvDecl::None,
    global: false,
    positional: false,
    required: false,
    hidden: false,
    rung: Rung::None,
    value: ValueDecl::Str,
};

pub(crate) const RULE_ID_ARG: FlagDecl = FlagDecl {
    id: "id",
    long: None,
    short: None,
    help: "The rule id to resolve, e.g. no-raw-issue-read",
    env: EnvDecl::None,
    global: false,
    positional: true,
    required: true,
    hidden: false,
    rung: Rung::None,
    value: ValueDecl::Str,
};

/// `--history` on `policy explain` (CLOUD-2144): print each named row's history
/// — its comment block, keys and class paragraph at HEAD, then the commits that
/// changed it — which is the read a change to the row owes.
pub(crate) const EXPLAIN_HISTORY: FlagDecl = FlagDecl {
    id: "history",
    long: Some("history"),
    short: None,
    help: "Print each named config row's history: the row at HEAD, then the commits that changed it",
    env: EnvDecl::None,
    global: false,
    positional: false,
    required: false,
    hidden: false,
    rung: Rung::None,
    value: ValueDecl::Bool,
};

pub(crate) const VERDICT_TOKEN: FlagDecl = FlagDecl {
    id: "token",
    long: None,
    short: None,
    help: "The names to resolve, as a finding line prints them: a rule, a class, an engine id, a \
           smell",
    env: EnvDecl::None,
    global: false,
    positional: true,
    required: true,
    hidden: false,
    rung: Rung::None,
    value: ValueDecl::StrMany,
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
pub(crate) const CHECK_RULE: FlagDecl = FlagDecl {
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

/// The non-document inputs a `record derive` family needs, as `<key>=<value>`.
///
/// ONE DECLARED FLAG RATHER THAN A COLUMN PER FAMILY, and the alternative is
/// what makes this the narrow choice: `--status`, `--test`, `--root`,
/// `--threshold`, `--exclude`, `--signingkey` and `--ssh-program` on one leaf
/// would declare seven flags of which every caller uses at most three, and each
/// new producer would widen the committed surface again. The keys a family
/// accepts are that family's own contract, documented on its reader, and a key
/// no family declares is a usage error rather than a silent default.
///
/// `StrMany` for `LAND_RESOLVE`'s reason: `Str` keeps only the LAST occurrence,
/// so a caller naming two inputs would silently lose the first — and a producer
/// running on a partial input is precisely the could-not-look this family's
/// three-valued read exists to keep loud.
pub(crate) const DERIVE_INPUT: FlagDecl = FlagDecl {
    id: "input",
    long: Some("input"),
    short: None,
    help: "A `<key>=<value>` input this family needs beyond stdin (repeatable)",
    env: EnvDecl::None,
    global: false,
    positional: false,
    required: false,
    hidden: false,
    rung: Rung::None,
    value: ValueDecl::StrMany,
};

/// `record forge --fetch`: read the commit's check-runs in process rather than
/// take reduced lines on stdin (CLOUD-843, retiring the forge arm of
/// `[tasks.record-verdicts]`).
pub(crate) const FORGE_FETCH: FlagDecl = FlagDecl {
    id: "fetch",
    long: Some("fetch"),
    short: None,
    help: "Read the commit's check-runs from the forge instead of `<check> <conclusion>` lines on stdin",
    env: EnvDecl::None,
    global: false,
    positional: false,
    required: false,
    hidden: false,
    rung: Rung::None,
    value: ValueDecl::Bool,
};

/// `record forge --fetch --fanin <check>`: the check whose answered conclusion
/// gates writing any record at all.
pub(crate) const FORGE_FANIN: FlagDecl = FlagDecl {
    id: "fanin",
    long: Some("fanin"),
    short: None,
    help: "With --fetch: record nothing until this check has an answered conclusion",
    env: EnvDecl::None,
    global: false,
    positional: false,
    required: false,
    hidden: false,
    rung: Rung::None,
    value: ValueDecl::Str,
};

/// `record forge --fetch --answered <list>`: the conclusions that constitute an
/// answer, the consumer's own set and never a list spelled in this crate.
pub(crate) const FORGE_ANSWERED: FlagDecl = FlagDecl {
    id: "answered",
    long: Some("answered"),
    short: None,
    help: "With --fetch: comma-separated conclusions that constitute an answer; anything else is not recorded",
    env: EnvDecl::None,
    global: false,
    positional: false,
    required: false,
    hidden: false,
    rung: Rung::None,
    value: ValueDecl::Str,
};

/// A `<name>=<value>` binding for one of a `[[forge.query]]` row's own
/// placeholders (CLOUD-843).
///
/// `DERIVE_INPUT`'s spelling and its `StrMany` reason, with its own help: what a
/// key MEANS here is a placeholder in the row's endpoint or parameters, and a key
/// the row names no placeholder for is a usage error rather than an ignored
/// value. `owner`, `repo` and `since` are the engine's to bind and are refused.
pub(crate) const QUERY_INPUT: FlagDecl = FlagDecl {
    id: "input",
    long: Some("input"),
    short: None,
    help: "A `<name>=<value>` binding for one of the query's own placeholders (repeatable)",
    env: EnvDecl::None,
    global: false,
    positional: false,
    required: false,
    hidden: false,
    rung: Rung::None,
    value: ValueDecl::StrMany,
};

/// The probe command on `record probe`, after the mandatory `--` (CLOUD-843).
pub(crate) const PROBE_COMMAND: FlagDecl = FlagDecl::trailing(
    "command",
    "The probe command, after `--`: its exit status is the `status` input and its output the document",
);

/// `--rule <id>` on `record decide`: `check`'s narrowing, and REQUIRED, because a
/// decision with no rule to make it would be a silent pass (CLOUD-843).
pub(crate) const DECIDE_RULE: FlagDecl = FlagDecl {
    help: "The declared rule that decides over the record just written (repeatable, at least one)",
    required: true,
    ..CHECK_RULE
};

/// `<verb>` on `pr unsubscribed`: which of its three arms runs.
pub(crate) const UNSUBSCRIBED_VERB: FlagDecl =
    FlagDecl::positional("verb", "drop | record | check");

/// `--session-env <NAME>` on `pr unsubscribed`: the NAME of the variable, never
/// its value, on `[[mcp.source]]`'s discipline (non-negotiable rule 1).
pub(crate) const UNSUBSCRIBED_SESSION_ENV: FlagDecl = FlagDecl {
    required: true,
    ..FlagDecl::valued(
        "session_env",
        "session-env",
        "The name of the environment variable holding this host's session id; unset is no session",
    )
};

/// `--token-env <NAME>` on `pr unsubscribed`: the credential is named, never carried.
pub(crate) const UNSUBSCRIBED_TOKEN_ENV: FlagDecl = FlagDecl::valued(
    "token_env",
    "token-env",
    "The name of the environment variable holding the path of the credential file `drop` sends",
);

/// `--endpoint <URL>` on `pr unsubscribed`: the host's address, with `{session}`.
pub(crate) const UNSUBSCRIBED_ENDPOINT: FlagDecl = FlagDecl::valued(
    "endpoint",
    "endpoint",
    "The endpoint `drop` calls, with `{session}` where the session id goes",
);

/// `--tool <NAME>` on `pr unsubscribed`: the tool `drop` asks the endpoint to call.
pub(crate) const UNSUBSCRIBED_TOOL: FlagDecl =
    FlagDecl::valued("tool", "tool", "The tool `drop` asks the endpoint to call");

/// `--arguments <JSON>` on `pr unsubscribed`: the tool's argument shape is the
/// HOST's, so the consumer writes it (non-negotiable rule 1).
const UNSUBSCRIBED_ARGUMENTS: FlagDecl = FlagDecl::valued(
    "arguments",
    "arguments",
    "The tool's arguments `drop` sends: a JSON object whose strings may name {owner}, {repo}, {pr} and {session}",
);

/// `--family <NAME>` on `pr unsubscribed`: the family `check` records, and the
/// receipts' filename prefix.
pub(crate) const UNSUBSCRIBED_FAMILY: FlagDecl = FlagDecl {
    required: true,
    ..FlagDecl::valued(
        "family",
        "family",
        "The record family `check` writes, and the prefix of this session's receipts",
    )
};

/// `--rule <id>` on `pr unsubscribed`: the rule `check` decides with.
pub(crate) const UNSUBSCRIBED_RULE: FlagDecl = FlagDecl::valued(
    "rule",
    "rule",
    "The declared rule `check` decides with over the record it writes",
);

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
pub(crate) const ENFORCE_RULE: FlagDecl = FlagDecl {
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

/// `--half <tree|live>` on `enforce`: judge one half of the rows (step 13a).
///
/// The landing stage re-ran every row on every lap, so finished work was paid
/// for again. Splitting the rows by what their verdict is a function of lets
/// the tree half ride a `[[step]]` receipt keyed on the index while the live
/// half — refs, stores, the forge, the clock, processes — runs unreceipted.
/// `rules::Rule::half` is the classifier, and anything it cannot establish is
/// live. Absent, `enforce` judges every row exactly as before.
pub(crate) const ENFORCE_HALF: FlagDecl = FlagDecl::optional_enum(
    "half",
    "half",
    "Judge only the tree half (receipt-keyed on the index) or the live half of the rows",
    half_parser,
);

/// `--keyed-base <ref>` on `enforce`: a ref whose merge base the caller's
/// receipt keys (step 13a), repeatable. A `ratchet` row counting against one is
/// a function of the tree plus that key, so it joins the tree half; against
/// any other ref it stays live.
pub(crate) const ENFORCE_KEYED_BASE: FlagDecl = FlagDecl {
    id: "keyed_base",
    long: Some("keyed-base"),
    short: None,
    help: "A ref whose merge base the tree half's receipt keys, admitting ratchets against it (repeatable)",
    env: EnvDecl::None,
    global: false,
    positional: false,
    required: false,
    hidden: false,
    rung: Rung::None,
    value: ValueDecl::StrMany,
};

/// `--inputs-digest` on `enforce --half tree`: print one blake3 line over the
/// out-of-tree state the tree half reads, and judge nothing (step 13a).
///
/// The tree half's `[[step]]` receipt keys index entries and tool answers, and
/// the half still reads a store baseline, the admission store, the admission
/// blocks of `HEAD` and `HEAD^2`, the secret-identity key, `batten.local.toml`
/// and the settings' environment variables. Naming this verb as a `tools` line
/// is what puts those in the key, so a moved one is a miss. Read-only, and
/// refused without `--half tree`, the one half whose receipt it serves.
pub(crate) const ENFORCE_INPUTS_DIGEST: FlagDecl = FlagDecl::switch(
    "inputs_digest",
    "inputs-digest",
    "With --half tree: print a digest of the out-of-tree state that half reads, and judge nothing",
);

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
pub(crate) const CHECK_STAGED: FlagDecl = FlagDecl {
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
/// `adjudicate --event`: the host's event name, for a registration whose
/// payload names none (CLOUD-2700). The payload's own name wins when present.
pub(crate) const HOOK_EVENT: FlagDecl = FlagDecl {
    id: "event",
    long: Some("event"),
    short: None,
    help: "The host's event name, used only when the payload names none",
    env: EnvDecl::None,
    global: false,
    positional: false,
    required: false,
    hidden: false,
    rung: Rung::None,
    value: ValueDecl::Str,
};

pub(crate) const HOOK_INSTANT: FlagDecl = FlagDecl {
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
pub(crate) const TASK_NAME: FlagDecl =
    FlagDecl::positional("task", "The task's name, as its callers know it");

/// The process a record is keyed by.
///
/// Positional and required on every leaf, because the pid IS the record's
/// identity — the thing being written or read — the way `lint brief <path>` names
/// its file. A flag would read as a modifier on a verb with some other default
/// subject, and there deliberately is no default: guessing a pid is how a prober
/// ends up reporting on the asking process, which is the measured defect the
/// registry exists to replace.
pub(crate) const TASK_PID: FlagDecl =
    FlagDecl::positional("pid", "The process the record is keyed by");

/// What a task is doing at registration.
///
/// Optional, and defaulted in the verb rather than here: an empty phase renders
/// as `unknown`, which is a claim about the record, and a task that has only just
/// registered is `starting`, which is a fact about it.
pub(crate) const TASK_PHASE: FlagDecl =
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
pub(crate) const TASK_FIELD: FlagDecl = FlagDecl::positional("field", "The record field to print");

/// The task a singleton lock is keyed by.
///
/// Its own constant rather than [`TASK_NAME`]: there the name is a FIELD of a
/// record keyed by pid, here it IS the key, and a reader who conflates the two
/// expects one lock per process rather than one per task.
pub(crate) const SINGLETON_TASK: FlagDecl = FlagDecl::positional(
    "task",
    "The task's name, which is what the lock is keyed by",
);

/// `--recheck-ms <n>` on `singleton acquire`: the pause between the two
/// sightings a reclaim requires.
///
/// A flag rather than an environment variable, and present at all only so a test
/// can drive the reclaim case with a wide margin instead of racing the default.
/// Nothing in production sets it. Malformed is `Usage` rather than a fall back to
/// the default: this pause is the reclaim's whole safety margin against robbing a
/// live holder, so guessing it would decide a lock silently.
pub(crate) const SINGLETON_RECHECK: FlagDecl = FlagDecl {
    id: "recheck_ms",
    long: Some("recheck-ms"),
    short: None,
    help: "Milliseconds between the two sightings a reclaim requires",
    env: EnvDecl::None,
    global: false,
    positional: false,
    required: false,
    hidden: false,
    rung: Rung::None,
    value: ValueDecl::Str,
};

/// `task alive --program-root`: ACCEPTED AND UNREAD since CLOUD-1560. Liveness
/// compares the cmdline digest each registrant recorded, so no program root is
/// consulted; the flag stays so a manifest written for an older release keeps
/// parsing, and retires with `[task] program_root` (CLOUD-2463).
pub(crate) const TASK_PROGRAM_ROOT: FlagDecl = FlagDecl {
    id: "program_root",
    long: Some("program-root"),
    short: None,
    help: "Accepted and unread: liveness compares the cmdline each registrant recorded (CLOUD-1560)",
    env: EnvDecl::None,
    global: false,
    positional: false,
    required: false,
    hidden: false,
    rung: Rung::None,
    value: ValueDecl::Str,
};

/// `record tool --pick <name>=<token>` (CLOUD-1991): reduce `key=value`
/// measurement lines to `<name> <token>` in the writer.
///
/// ONE VALUE CARRYING BOTH KEYS rather than two flags, because the pair is one
/// decision — which field names a line and which one scores it — and two flags
/// could be half-given. Optional: absent, stdin is already record lines, which
/// is every caller this leaf had before it.
pub(crate) const TOOL_PICK: FlagDecl = FlagDecl {
    id: "pick",
    long: Some("pick"),
    short: None,
    help: "Reduce `key=value` lines: `<name-key>=<token-key>` names the field that labels a record line and the one that scores it",
    env: EnvDecl::None,
    global: false,
    positional: false,
    required: false,
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
pub(crate) const CHECK_SINCE: FlagDecl = FlagDecl {
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
pub(crate) const OVERRIDE_ADMISSION: FlagDecl = FlagDecl {
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
pub(crate) const OVERRIDE_RULE: FlagDecl = FlagDecl {
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
pub(crate) const OVERRIDE_VERDICT: FlagDecl = FlagDecl {
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
pub(crate) const LEASE_BRANCH: FlagDecl =
    FlagDecl::positional("branch", "The branch being asked about");

/// `<head>`: the commit `lease carries` judges.
///
/// **Positional and required, for [`LEASE_BRANCH`]'s reason.** The caller knows
/// which sha it means and the engine must not guess: on a `pull_request` event
/// the obvious guess is `GITHUB_SHA`, which is the MERGE commit and therefore
/// carries trunk's landing mechanism whenever the head did not touch it — so a
/// default would read every stale head as current, silently.
pub(crate) const LEASE_HEAD: FlagDecl =
    FlagDecl::positional("head", "The head commit being judged");

/// `<run>`: the run `lease guard` cancels on a stop.
///
/// Positional and required, for [`LEASE_HEAD`]'s reason: the engine must not
/// guess which run it is standing in, and a guard that cancelled the wrong one
/// would be worse than one that cancelled none.
pub(crate) const LEASE_RUN: FlagDecl = FlagDecl::positional("run", "The run to cancel on a stop");

/// `<reference>`: the remote reference a `land` sub-verb lands onto.
///
/// **OPTIONAL SINCE CLOUD-2188, AND STILL NEVER A GUESS.** It was required
/// because a default would have made the verb guess the trunk, and a wrong guess
/// replays onto the wrong base — a write, not a report. The required positional
/// did not stop the guess; it moved it into every consumer's task as a copied
/// `main`. Absent now, it is the DECLARED trunk — `must_land_on`, else the
/// remote's recorded default branch, both read rather than assumed — and with
/// neither the verb refuses with `worktree::NO_TRUNK` instead of picking one.
pub(crate) const LAND_REFERENCE: FlagDecl = FlagDecl::positional_optional(
    "reference",
    "The remote reference to land onto (default: the trunk — `must_land_on`, else the remote's default branch)",
);

/// `land lap --hold`: stop at the first final verify (CLOUD-2783).
///
/// The lap's only instrument that does not land: without it, measuring a lap
/// readied and fast-forwarded whatever it measured.
pub(crate) const LAND_HOLD: FlagDecl = FlagDecl::switch(
    "hold",
    "hold",
    "Stop after the first verify whose verdict is final, before the lease, push and ready",
);

/// `--resolve <path>`: a path whose conflict the caller merged in the worktree.
///
/// **Repeatable, and every conflicting path must be named** (CLOUD-1586).
/// `gitwrite`'s header refuses auto-resolution because it deletes the loop's one
/// human stop; this does not reinstate it. There is no `--ours`/`--theirs` — a
/// side-picking flag IS that strategy — and a partial naming refuses, because a
/// tree written for the paths nobody mentioned would carry the engine's own pick
/// arrived at by omission.
///
/// On `land replay` and never on `land lap`: a lap runs unattended, so any
/// resolution it could apply is one nobody looked at.
pub(crate) const LAND_RESOLVE: FlagDecl = FlagDecl {
    id: "resolve",
    long: Some("resolve"),
    short: None,
    help: "A path whose conflict is resolved in the worktree (repeatable)",
    env: EnvDecl::None,
    global: false,
    positional: false,
    required: false,
    hidden: false,
    rung: Rung::None,
    // `StrMany` for its own header's reason, and it is load-bearing here rather
    // than tidy: `Str` keeps only the LAST occurrence, so naming two conflicting
    // paths would silently drop the first — and a partial naming is exactly what
    // this verb refuses. The failure would be a refusal the caller cannot
    // explain, having named every path.
    value: ValueDecl::StrMany,
};

/// `--propose`: write a candidate for each conflicted path a shape covers
/// (CLOUD-1956).
///
/// **A candidate is never applied.** The replay still stops and moves nothing;
/// each candidate is written under the git dir for a person to read and pass back
/// as `--resolve <path>=<file>`, which stays the only act that puts a resolution
/// into a tree. On `land replay` and never on `land lap`, for [`LAND_RESOLVE`]'s
/// reason: nothing unattended should even be handed a merge to trust.
pub(crate) const LAND_PROPOSE: FlagDecl = FlagDecl {
    id: "propose",
    long: Some("propose"),
    short: None,
    help: "On a conflict, write a candidate merge for each path a known shape covers",
    env: EnvDecl::None,
    global: false,
    positional: false,
    required: false,
    hidden: false,
    rung: Rung::None,
    value: ValueDecl::Bool,
};

/// `<field>`: which advisory field `lease peek` prints.
///
/// A closed set, because the whole value of `peek` over reading the status prose
/// is that a caller can ACT on the answer: a field name that is merely echoed back
/// would make an unknown one print nothing and read as an unset field.
pub(crate) const LEASE_FIELD: FlagDecl = FlagDecl::positional(
    "field",
    "Which advisory field to print: branch, head or next",
);

/// `--subject <s>`: the gate's own canonical spelling of what it refused about.
pub(crate) const OVERRIDE_SUBJECT: FlagDecl = FlagDecl {
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

pub(crate) const CLASS: FlagDecl = FlagDecl {
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
pub(crate) const RECORD_ID: FlagDecl = FlagDecl {
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
pub(crate) const UNGATED: FlagDecl = FlagDecl {
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
pub(crate) const PRUNE: FlagDecl = FlagDecl {
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
/// `--check` on `wiring register` (CLOUD-2111): decide whether a registration
/// is owed, for the `[[startup]]` row that names the verb as its repair.
pub(crate) const REGISTER_CHECK: FlagDecl = FlagDecl {
    id: "check",
    long: Some("check"),
    short: None,
    help: "Exit non-zero if a registration is owed, and write nothing",
    env: EnvDecl::None,
    global: false,
    positional: false,
    required: false,
    hidden: false,
    rung: Rung::None,
    value: ValueDecl::Bool,
};

/// `--check` on `wiring gate` (CLOUD-2339): decide whether a link is owed.
pub(crate) const GATE_CHECK: FlagDecl = FlagDecl {
    id: "check",
    long: Some("check"),
    short: None,
    help: "Exit non-zero if a git hook link is owed, and write nothing",
    env: EnvDecl::None,
    global: false,
    positional: false,
    required: false,
    hidden: false,
    rung: Rung::None,
    value: ValueDecl::Bool,
};

/// `--all` on `wiring register` (CLOUD-2676): also write every harness's
/// committed surface under the repository, ungated by the disposable home.
pub(crate) const REGISTER_ALL: FlagDecl = FlagDecl {
    id: "all",
    long: Some("all"),
    short: None,
    help: "Also register batten on every harness's committed wiring file",
    env: EnvDecl::None,
    global: false,
    positional: false,
    required: false,
    hidden: false,
    rung: Rung::None,
    value: ValueDecl::Bool,
};

pub(crate) const CHECK: FlagDecl = FlagDecl {
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

pub(crate) const REPAIR: FlagDecl = FlagDecl {
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

pub(crate) const DRY_RUN: FlagDecl = FlagDecl {
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
pub(crate) const CAPTURE_ONLY: FlagDecl = FlagDecl {
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
pub(crate) const LINES: FlagDecl = FlagDecl {
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
pub(crate) const GREP: FlagDecl = FlagDecl {
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

/// `--field <pointer>` on `capture show`: one field of a stored JSON document
/// (CLOUD-2207).
///
/// A tracker response is stored as one line of JSON, so `--lines` and `--grep`
/// — line selectors — could only ever return the whole body: the pointer
/// `mcp call` prints led nowhere a reader could navigate, and the measured
/// response was a second, raw fetch of the same row. An RFC 6901 JSON Pointer
/// names the field; a string field is read as its own text, newlines restored,
/// and every other value as pretty-printed JSON, so the line selectors then
/// address the field rather than the document.
pub(crate) const FIELD: FlagDecl = FlagDecl {
    id: "field",
    long: Some("field"),
    short: None,
    help: "Read one field of a stored JSON document, named by an RFC 6901 JSON Pointer \
           (`/description`); --lines and --grep then select within it",
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
pub(crate) const RAW: FlagDecl = FlagDecl {
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
pub(crate) const BYTES: FlagDecl = FlagDecl {
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
pub(crate) const CALLS: FlagDecl = FlagDecl {
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

/// `state list --rule`: only findings of this rule (CLOUD-2175). The drain's
/// pointer for a rule whose locations it did not list, so the command returns
/// exactly the elided set rather than the whole store.
pub(crate) const STATE_RULE: FlagDecl = FlagDecl {
    id: "rule",
    long: Some("rule"),
    short: None,
    help: "Only findings of this rule",
    env: EnvDecl::None,
    global: false,
    positional: false,
    required: false,
    hidden: false,
    rung: Rung::None,
    value: ValueDecl::Str,
};

/// `state list --path`: only findings observed in this file (CLOUD-2175).
pub(crate) const STATE_PATH: FlagDecl = FlagDecl {
    id: "path",
    long: Some("path"),
    short: None,
    help: "Only findings observed in this file",
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
pub(crate) const STREAM: FlagDecl = FlagDecl {
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
pub(crate) const TOOL: FlagDecl = FlagDecl {
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
pub(crate) const KEY_AT: FlagDecl = FlagDecl {
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
/// `--merged-prs <file>` on `landed check`, and it is REQUIRED in effect
/// (CLOUD-186).
///
/// Not `required: true`, because a missing file and a missing flag are different
/// refusals and the verb says which. What makes it load-bearing is the
/// direction: absent is exit 2 rather than an empty set, since only 3% of this
/// repository's commits carry a closing keyword — fast-forward landing puts it
/// in the PR body — so deciding on commits alone reports a clean column it never
/// checked.
pub(crate) const MERGED_PRS: FlagDecl = FlagDecl {
    id: "merged_prs",
    long: Some("merged-prs"),
    short: None,
    help: "`<CLOUD-id><TAB><pr-number>` lines, one per closing key in a MERGED pull request",
    env: EnvDecl::None,
    global: false,
    positional: false,
    required: false,
    hidden: false,
    rung: Rung::None,
    value: ValueDecl::Str,
};

/// `--landed-by <file>` on `landed check` (CLOUD-903).
///
/// The caller's WORD, for rows the derived halves are structurally unable to
/// reach. Absent-is-empty rather than could-not-look, and the asymmetry with
/// `--merged-prs` is deliberate: absent evidence there silently halves a
/// disjunction, absent assertion here is the ordinary case and cannot
/// manufacture a false green. A row drained by it is REPORTED as asserted and
/// names its ref, so a reader can tell the caller's word from evidence.
pub(crate) const LANDED_BY: FlagDecl = FlagDecl {
    id: "landed_by",
    long: Some("landed-by"),
    short: None,
    help: "`<CLOUD-id><TAB><ref>` lines the caller asserts carry the work",
    env: EnvDecl::None,
    global: false,
    positional: false,
    required: false,
    hidden: false,
    rung: Rung::None,
    value: ValueDecl::Str,
};

/// `--claimed <file>` on `landed check` (CLOUD-186, repaired by CLOUD-1458).
///
/// The keys a commit reachable from the trunk CLOSES — claiming, never
/// merely mentioning. This is the first arm of the landedness disjunction, and
/// the caller supplies it rather than the engine reading it, for the reason
/// `mise-tasks/landed-check.sh` gives at its own call site: `claimed-keys` is
/// this repository's ONE authority on claim-versus-mention, and a second copy
/// of its `CLAIM_RE` is what CLOUD-378 was filed for.
///
/// **The arm shipped UNREACHABLE and this flag is the repair.** `Evidence`
/// declared the field, `landed()` and `asserted_only()` branched on it, and
/// four unit cases constructed it directly — so the predicate's own tier was
/// green over an arm the binary could not feed, a two-arm disjunction wearing a
/// three-arm header. `landed-check.sh` names the direction that costs: a
/// claim-only reading trades over-reporting for a SILENT UNDER-REPORT, which is
/// "strictly worse for a drain", and shipping without the arm is that same
/// error pointed the other way.
/// `--base <rev>` on `ci slow-needed` (CLOUD-398).
///
/// REQUIRED, because there is no safe default. A missing base is not "diff
/// against the parent" — it is a caller that has not said what the change is
/// relative to, and answering from a guess is how a tier gets skipped over a
/// comparison nobody made.
pub(crate) const BENCH_CHECK: FlagDecl = FlagDecl {
    id: "check",
    long: Some("check"),
    short: None,
    help: "Diff a fresh run against the committed table instead of writing it",
    env: EnvDecl::None,
    global: false,
    positional: false,
    required: false,
    hidden: false,
    rung: Rung::None,
    value: ValueDecl::Bool,
};

/// `forge intake --event <name>` (CLOUD-2690): the `X-GitHub-Event` name a
/// webhook body on stdin arrived under, because a body does not name itself.
pub(crate) const INTAKE_EVENT: FlagDecl = FlagDecl {
    id: "event",
    long: Some("event"),
    short: None,
    help: "The X-GitHub-Event name the webhook body on stdin arrived under",
    env: EnvDecl::None,
    global: false,
    positional: false,
    required: false,
    hidden: false,
    rung: Rung::None,
    value: ValueDecl::Str,
};

/// `forge intake --from wake` (CLOUD-2690): stdin is a harness
/// user-prompt-submit payload carrying a `<event source="github">` element.
pub(crate) const INTAKE_FROM: FlagDecl = FlagDecl {
    id: "from",
    long: Some("from"),
    short: None,
    help: "`wake`: stdin is a harness user-prompt-submit payload carrying the event",
    env: EnvDecl::None,
    global: false,
    positional: false,
    required: false,
    hidden: false,
    rung: Rung::None,
    value: ValueDecl::Str,
};

/// `forge poll --every <seconds>` (CLOUD-2693): loop, registered with `task`.
pub(crate) const POLL_EVERY: FlagDecl = FlagDecl {
    id: "every",
    long: Some("every"),
    short: None,
    help: "Poll every this many seconds, registered with `task` as forge-poll",
    env: EnvDecl::None,
    global: false,
    positional: false,
    required: false,
    hidden: false,
    rung: Rung::None,
    value: ValueDecl::Str,
};

pub(crate) const SLOW_BASE: FlagDecl = FlagDecl {
    id: "base",
    long: Some("base"),
    short: None,
    help: "The revision this checkout is diffed against",
    env: EnvDecl::None,
    global: false,
    positional: false,
    required: true,
    hidden: false,
    rung: Rung::None,
    value: ValueDecl::Str,
};

/// `test replay --structural` (CLOUD-2789): judge only what needs no build.
pub(crate) const REPLAY_STRUCTURAL: FlagDecl = FlagDecl {
    id: "structural",
    long: Some("structural"),
    short: None,
    help: "Judge only removed tests, without building: the seconds half the lap runs first",
    env: EnvDecl::None,
    global: false,
    positional: false,
    required: false,
    hidden: false,
    rung: Rung::None,
    value: ValueDecl::Bool,
};

/// `--head <rev>` on `ci slow-needed` (CLOUD-1991).
///
/// The diff is always taken against the CHECKOUT, which in a `pull_request` job
/// is the merge commit and elsewhere is `HEAD`. A caller naming a head asserts
/// the two carry one tree, and a head that does not is refused as a usage error
/// rather than silently answered about the checkout instead. This was the retired
/// task body's shell guard; it is the verb's own argument now.
pub(crate) const SLOW_HEAD: FlagDecl = FlagDecl {
    id: "head",
    long: Some("head"),
    short: None,
    help: "The revision whose tree the checkout must carry; refused when it does not",
    env: EnvDecl::None,
    global: false,
    positional: false,
    required: false,
    hidden: false,
    rung: Rung::None,
    value: ValueDecl::Str,
};

pub(crate) const CLAIMED: FlagDecl = FlagDecl {
    id: "claimed",
    long: Some("claimed"),
    short: None,
    help: "`<CLOUD-id>` lines a commit on the trunk (`must_land_on`, else the remote's default branch) closes, from `claimed-keys --closing-only`",
    env: EnvDecl::None,
    global: false,
    positional: false,
    required: false,
    hidden: false,
    rung: Rung::None,
    value: ValueDecl::Str,
};

/// `--declined <file>` on `landed check` (CLOUD-1127).
///
/// The keys a pull request body declined with `DO-NOT-CLOSE`. That marker is
/// honoured by `closing-key-check`, which is this repository's, and ignored by
/// whatever writes the board transition, which is not — so a row can be declined
/// and advanced by the same merge, and this is the evidence that says so.
pub(crate) const DECLINED: FlagDecl = FlagDecl {
    id: "declined",
    long: Some("declined"),
    short: None,
    help: "`<CLOUD-id>` lines a pull request body declined with DO-NOT-CLOSE",
    env: EnvDecl::None,
    global: false,
    positional: false,
    required: false,
    hidden: false,
    rung: Rung::None,
    value: ValueDecl::Str,
};

/// `--refs <file>` on `landed abandoned` (CLOUD-1513).
///
/// The remote's branch names, one per line. **Evidence rather than a spawn, and
/// that is what keeps the arm on the read-only allowlist**: `spec.rs` admits
/// `landed check` there precisely because it "starts no program", so resolving
/// this with a `git ls-remote` would take the arm off it.
///
/// Since CLOUD-843 the verb can also acquire the names itself, under `--gather`
/// — through the forge's REST listing and the vendored client, which is still
/// no program started, so the verb stays `read` the way `claim merged` (a forge
/// read by the same client) is. That listing is one forge's; a consumer whose
/// forge does not serve it gathers could-not-look on this arm and names the
/// branches here instead — `git ls-remote --heads` output reduced to names,
/// from whatever credential the caller holds. A file named here is never
/// replaced by a gathered reading.
///
/// Absent without `--gather` is an empty list, which is a legitimate reading: a
/// repository whose branches the caller did not gather cannot rescue any claim,
/// and the refusal for a gather that FAILED belongs to the caller that ran it.
pub(crate) const REFS: FlagDecl = FlagDecl {
    id: "refs",
    long: Some("refs"),
    short: None,
    help: "Branch names the remote carries, one per line",
    env: EnvDecl::None,
    global: false,
    positional: false,
    required: false,
    hidden: false,
    rung: Rung::None,
    value: ValueDecl::Str,
};

/// `--gather` on `landed abandoned` (CLOUD-843, retiring
/// `[tasks.in-progress-drain]`).
///
/// A SWITCH over the arms rather than a replacement for them: an arm the caller
/// names a file for is read from that file, and only an arm left unnamed is
/// acquired — the trunk's closing keys from the declared trunk's (`must_land_on`)
/// history in process, the merged pull requests and the remote's branches from
/// the forge through the vendored client, both from the one repository
/// `GH_REPO` / `LAND_LOCK_REMOTE` resolve. Off, every arm keeps its
/// caller-supplied contract unchanged. A gather that cannot finish is
/// could-not-look, never a thinner evidence set.
///
/// Still `read`: every acquisition is in process or through the vendored forge
/// client, so the verb starts no program — the property its place on the
/// read-only allowlist rests on.
pub(crate) const GATHER: FlagDecl = FlagDecl::switch(
    "gather",
    "gather",
    "Acquire each evidence arm no file was named for: the trunk's closing keys, merged pull requests, and the remote's branches",
);

/// `--instant <ISO-8601>` on `landed abandoned` (CLOUD-1513).
///
/// The instant the idle bound is measured against. **Supplied rather than read**,
/// which is the split `.claude/rules/policy-modules.md` states for every clock
/// here: the boundary owns it and the decision is handed the answer. Two
/// reasons, and both are load-bearing — house style §6 requires byte-stable
/// output, which a value differing per invocation cannot give; and without it
/// every fixture date drifts out of the bound as the calendar moves, so a suite
/// rots on a date nobody edited.
pub(crate) const INSTANT: FlagDecl = FlagDecl {
    id: "instant",
    long: Some("instant"),
    short: None,
    help: "The instant to measure the idle bound against, ISO-8601 (default: now)",
    env: EnvDecl::None,
    global: false,
    positional: false,
    required: false,
    hidden: false,
    rung: Rung::None,
    value: ValueDecl::Str,
};

/// `--max-idle-days <n>` on `landed abandoned` (CLOUD-1513).
///
/// How long a claim may sit untouched and still read as live. Declared rather
/// than fixed because the right number is a property of the fleet's cadence
/// rather than of the predicate, and the report echoes the value it used so a
/// reader is never left inferring which bound produced a finding.
pub(crate) const MAX_IDLE_DAYS: FlagDecl = FlagDecl {
    id: "max_idle_days",
    long: Some("max-idle-days"),
    short: None,
    help: "Days a claim may be idle before it reads as abandoned (default: 2)",
    env: EnvDecl::None,
    global: false,
    positional: false,
    required: false,
    hidden: false,
    rung: Rung::None,
    value: ValueDecl::Str,
};

pub(crate) const ISSUE: FlagDecl = FlagDecl {
    id: "issue",
    long: Some("issue"),
    short: None,
    help: "Read the issue payload from the capture store by key, where `mcp call ... get_issue` put it",
    env: EnvDecl::None,
    global: false,
    positional: false,
    required: false,
    hidden: false,
    rung: Rung::None,
    value: ValueDecl::Str,
};

/// Write the derived corpus to its committed path instead of to stdout.
///
/// **Off by default, which is the safer direction for a verb whose product is a
/// tracked file.** A caller who wants to SEE what would be recorded — a reviewer
/// diffing a proposed corpus against the committed one — must not have to dirty
/// the tree to do it, and `receipt clean` is one of the things that would then
/// refuse.
pub(crate) const SUITES_WRITE: FlagDecl = FlagDecl {
    id: "write",
    long: Some("write"),
    short: None,
    help: "Write the corpus to its committed path instead of printing it",
    env: EnvDecl::None,
    global: false,
    positional: false,
    required: false,
    hidden: false,
    rung: Rung::None,
    value: ValueDecl::Bool,
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
pub(crate) const REQUIRED_CHECKS: FlagDecl = FlagDecl {
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
pub(crate) const ABSENT_OK_CHECKS: FlagDecl = FlagDecl {
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
pub(crate) const ANSWERED_CONCLUSIONS: FlagDecl = FlagDecl {
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
///
/// A REF IS ACCEPTED AND RESOLVED, which keeps that property rather than bending
/// it (CLOUD-843): `--sha HEAD` is still the caller naming its subject, spelled
/// the way a caller with no shell to run `rev-parse` can spell it.
pub(crate) const WAIT_SHA: FlagDecl = FlagDecl {
    id: "sha",
    long: Some("sha"),
    short: None,
    help: "The commit whose check runs to read — a sha, or a ref this checkout resolves",
    env: EnvDecl::None,
    global: false,
    positional: false,
    required: true,
    hidden: false,
    rung: Rung::None,
    value: ValueDecl::Str,
};

/// `--sha` on `checks green`: read this commit's check runs from the forge
/// instead of taking a reading on stdin (CLOUD-843).
///
/// Optional, where `pr watch`'s is required, because absent keeps the verb's
/// original shape — a pure decision over a piped reading — byte for byte. Taken
/// literally rather than resolved, for [`WAIT_SHA`]'s reason: the caller knows
/// which commit it means, and resolving would also start a program the `read`
/// row promises this verb never starts.
pub(crate) const CHECKS_SHA: FlagDecl = FlagDecl {
    id: "sha",
    long: Some("sha"),
    short: None,
    help: "Read this commit's check runs from the forge instead of a reading on stdin",
    env: EnvDecl::None,
    global: false,
    positional: false,
    required: false,
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
pub(crate) const WAIT_REPO: FlagDecl = FlagDecl {
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
pub(crate) const WAIT_INTERVAL: FlagDecl = FlagDecl {
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
pub(crate) const WAIT_PROGRESS: FlagDecl = FlagDecl {
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
pub(crate) const WAIT_PROGRESS_ID: FlagDecl = FlagDecl {
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

pub(crate) const FANIN_CHECK: FlagDecl = FlagDecl {
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
pub(crate) const TAKEOVER: FlagDecl = FlagDecl {
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
pub(crate) const BYPASS_SEQUENCE: FlagDecl = FlagDecl {
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
pub(crate) const ADOPT: FlagDecl = FlagDecl {
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
/// The host's session identifier for the runtime observation (CLOUD-948).
///
/// OPTIONAL, and its absence is an answer rather than a usage error: a host that
/// cannot name a session cannot have a receipt written about one, and writing it
/// under a shared key would let two sessions answer for each other. The raw
/// token never reaches the disk — the record carries its digest.
pub(crate) const SESSION: FlagDecl = FlagDecl {
    id: "session",
    long: Some("session"),
    short: None,
    help: "The host's session identifier; without one no receipt is written",
    env: EnvDecl::None,
    global: false,
    positional: false,
    required: false,
    hidden: false,
    rung: Rung::None,
    value: ValueDecl::Str,
};

pub(crate) const ADOPT_FROM: FlagDecl = FlagDecl {
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

/// `--or <check>` on `receipt status` (CLOUD-843): another check whose receipt
/// answers the same question, any ONE valid receipt passing.
///
/// THE DISJUNCTION `verify` USED TO SPELL IN SHELL. A branch is claimed by a
/// refined issue, by an allowlisted bot, or by a licence carry (CLOUD-431,
/// CLOUD-693, CLOUD-1295) — three receipt kinds that attest three different
/// things, which is why they stay three rather than one widened kind. Each is
/// still judged by the one predicate, `receipt::branch_validity`, so the
/// staleness rule CLOUD-516 put on the first holds for all of them.
///
/// REPEATABLE AND ORDERED, for `ValueDecl::StrMany`'s reason: a second `--or`
/// silently replacing the first would drop a kind the caller named.
pub(crate) const RECEIPT_OR: FlagDecl = FlagDecl {
    value: ValueDecl::StrMany,
    ..FlagDecl::valued(
        "or",
        "or",
        "Another check whose receipt satisfies this one; any one valid receipt passes (repeatable)",
    )
};

/// `<step>` on the three `step` arms: the name a `[[step]]` row declares.
/// `--outputs` on `ci step`: append the command's `KEY=VALUE` lines to the
/// runner's output file.
pub(crate) const CI_STEP_OUTPUTS: FlagDecl = FlagDecl::switch(
    "outputs",
    "outputs",
    "Append the command's KEY=VALUE stdout lines to the runner's step-output file",
);

/// `--summary <title>` on `ci step`.
pub(crate) const CI_STEP_SUMMARY: FlagDecl = FlagDecl::valued(
    "summary",
    "summary",
    "Fence the tail of the command's output into the runner's run summary under this title",
);

/// `--save <path>` on `ci step`.
pub(crate) const CI_STEP_SAVE: FlagDecl = FlagDecl::valued(
    "save",
    "save",
    "Also write the command's stdout to this path, for a later step to read",
);

/// `--stdin <path>` on `ci step`.
pub(crate) const CI_STEP_STDIN: FlagDecl = FlagDecl::valued(
    "stdin",
    "stdin",
    "Feed this file to the command's standard input",
);

/// `--verdict <key>` on `ci step`.
pub(crate) const CI_STEP_VERDICT: FlagDecl = FlagDecl::valued(
    "verdict",
    "verdict",
    "The step-output key a mapped exit code is written under",
);

/// `--on <code>=<value>` on `ci step`, REPEATABLE AND ORDERED: each row maps
/// one exit code, and a mapped code exits 0.
pub(crate) const CI_STEP_ON: FlagDecl = FlagDecl {
    value: ValueDecl::StrMany,
    ..FlagDecl::valued(
        "on",
        "on",
        "Map an exit code to the verdict's value as <code>=<value>; a mapped code exits 0 (repeatable)",
    )
};

/// `--require-env <NAME>` on `ci step`, REPEATABLE: a variable that must be set
/// and non-empty before the command runs. Its value is never printed.
pub(crate) const CI_STEP_REQUIRE_ENV: FlagDecl = FlagDecl {
    value: ValueDecl::StrMany,
    ..FlagDecl::valued(
        "require_env",
        "require-env",
        "Refuse the step before running anything when this variable is unset or empty, naming it and never its value (repeatable)",
    )
};

/// `--capture <key>` on `ci step`.
pub(crate) const CI_STEP_CAPTURE: FlagDecl = FlagDecl::valued(
    "capture",
    "capture",
    "Write the first line of the command's stdout to the runner's step outputs under this key",
);

/// `--arg-env <NAME>` on `ci step`, REPEATABLE AND ORDERED: each appends one
/// variable's value to the command as a single argument.
pub(crate) const CI_STEP_ARG_ENV: FlagDecl = FlagDecl {
    value: ValueDecl::StrMany,
    ..FlagDecl::valued(
        "arg_env",
        "arg-env",
        "Append this variable's value to the command as one argument, in order; unset or empty is refused (repeatable)",
    )
};

/// The command on `ci step`, after the mandatory `--`.
pub(crate) const CI_STEP_COMMAND: FlagDecl = FlagDecl::trailing(
    "command",
    "The command, after `--`: its code is the verb's unless an --on row maps it",
);

pub(crate) const STEP_NAME: FlagDecl = FlagDecl::positional(
    "step",
    "The step's name, as the consumer's step table declares it",
);

/// `--arg <value>` on the three `step` arms (CLOUD-424's `--arg`, carried over).
///
/// REPEATABLE AND ORDERED, for `ValueDecl::StrMany`'s reason: each occurrence is
/// one more thing the step's verdict depends on beyond its input files — a target
/// triple, a base tree's id — and the key hashes them in the order written, so a
/// second `--arg` silently replacing the first would key two different runs alike.
pub(crate) const STEP_ARG: FlagDecl = FlagDecl {
    value: ValueDecl::StrMany,
    ..FlagDecl::valued(
        "arg",
        "arg",
        "A value the step's verdict depends on beyond its inputs, keyed in order (repeatable)",
    )
};

/// The group `step graph run` schedules, as the step table's `group` names it.
pub(crate) const STEP_GROUP: FlagDecl = FlagDecl::positional(
    "group",
    "The graph to run, as the step table's `group` field names it",
);

/// `--root <dir>` on `modules metrics` (CLOUD-2821).
pub(crate) const MODULES_ROOT: FlagDecl = FlagDecl {
    required: true,
    ..FlagDecl::valued(
        "root",
        "root",
        "The crate's source root, the directory holding lib.rs",
    )
};

/// `--record <path>` on `modules ratchet` (CLOUD-2821).
pub(crate) const MODULES_RECORD: FlagDecl = FlagDecl {
    required: true,
    ..FlagDecl::valued(
        "record",
        "record",
        "The record file, one `<root> cycle=<n> propagation=<bp> impls=<n> shims=<n>` line per root",
    )
};

/// `--check` on `modules ratchet` (CLOUD-2821).
pub(crate) const MODULES_CHECK: FlagDecl = FlagDecl::switch(
    "check",
    "check",
    "Never write the record: one looser than the tree is refused too",
);

/// `modules cut`'s source package directory (CLOUD-2812).
pub(crate) const MODULES_CUT_FROM: FlagDecl = FlagDecl::positional(
    "from",
    "The package directory to cut from, relative to the workspace root (crates/batten)",
);

/// `modules cut`'s new package name (CLOUD-2812).
pub(crate) const MODULES_CUT_NAME: FlagDecl = FlagDecl::positional(
    "name",
    "The new package's name; it lands beside the one cut from",
);

/// `modules cut`'s module set (CLOUD-2812).
pub(crate) const MODULES_CUT_SET: FlagDecl =
    FlagDecl::trailing("modules", "The crate-root modules that move, by name");

/// `--dry-run` on `modules cut`: print the plan, write nothing (CLOUD-2812).
pub(crate) const MODULES_DRY_RUN: FlagDecl = FlagDecl::switch(
    "dry_run",
    "dry-run",
    "Print each path the cut would write or remove, and write nothing",
);

pub(crate) const STEP_JOBS: FlagDecl = FlagDecl::valued(
    "jobs",
    "jobs",
    "Run at most this many of the group's rows at once (a positive integer; default: no bound)",
);

/// `--ref <ref>` on `step base` (CLOUD-2787): the revision whose merge base
/// with `HEAD` the base lines are read at.
pub(crate) const STEP_BASE_REF: FlagDecl = FlagDecl {
    required: true,
    ..FlagDecl::valued(
        "ref",
        "ref",
        "The ref whose merge base with HEAD the lines are read at",
    )
};

/// `--ref-env <VAR>` on `step base`: the variable that overrides `--ref`.
pub(crate) const STEP_BASE_REF_ENV: FlagDecl = FlagDecl::valued(
    "ref_env",
    "ref-env",
    "A variable whose value, when set and non-empty, replaces --ref",
);

/// The pathspecs `step base` prints a content id for, after the mandatory `--`.
pub(crate) const STEP_BASE_PATHS: FlagDecl = FlagDecl::trailing(
    "paths",
    "The paths, after `--`: one `base <path> <id>` line each, `absent` where missing",
);

/// `--exclude <NAME>` on `step env` (CLOUD-2786), repeatable: a variable a
/// pattern matches that is never keyed.
pub(crate) const STEP_ENV_EXCLUDE: FlagDecl = FlagDecl {
    value: ValueDecl::StrMany,
    ..FlagDecl::valued(
        "exclude",
        "exclude",
        "A variable a pattern matches that is never keyed, such as a per-run pid (repeatable)",
    )
};

/// The names and `PREFIX*` patterns `step env` keys, after the mandatory `--`.
pub(crate) const STEP_ENV_PATTERNS: FlagDecl = FlagDecl::trailing(
    "patterns",
    "The names or PREFIX* patterns, after `--`: an `env NAME=value` line per keyed variable, `env PATTERN none` where none matches",
);

/// The step's own command on `step run`, after the mandatory `--`.
pub(crate) const STEP_COMMAND: FlagDecl = FlagDecl::trailing(
    "command",
    "The step's command, after `--`: run only on a miss, recorded only when it exits 0",
);

/// `--names` on `sbom`: answer the asset names without scanning anything.
pub(crate) const SBOM_NAMES: FlagDecl = FlagDecl::switch(
    "names",
    "names",
    "Print the asset names as KEY=VALUE lines and exit, without scanning",
);

/// `--binary <path>` on `sbom`: inventory a built binary instead of the tree.
pub(crate) const SBOM_BINARY: FlagDecl = FlagDecl::valued(
    "binary",
    "binary",
    "Inventory this built binary from its own bytes instead of the tree",
);

/// `--target <triple>` on `sbom`: the triple a binary was built for.
///
/// It names the binary's asset through `dist`'s stem rule, so it is what
/// `--names` answers with when a binary's asset, not the tree's, is asked about.
pub(crate) const SBOM_TARGET: FlagDecl = FlagDecl::valued(
    "target",
    "target",
    "The target triple the binary was built for, which names its asset",
);

/// `--out-dir <dir>` on `sbom`.
pub(crate) const SBOM_OUT_DIR: FlagDecl = FlagDecl::valued(
    "out_dir",
    "out-dir",
    "Write the documents under this directory instead of the declared one",
);

/// `--record` on `sbom`: derive twice into scratch and record the reduction.
///
/// The producer half of the inventory gate (retiring `[tasks.record-sbom]`):
/// two derivations, because stability is one of the counts, and scratch rather
/// than the declared directory, because a producer that rewrote what it measures
/// could not measure it twice.
pub(crate) const SBOM_RECORD: FlagDecl = FlagDecl::switch(
    "record",
    "record",
    "Derive the tree's documents twice into scratch and record their counts under the declared tool row",
);

/// `--conformance` on `sbom`: derive into scratch and record the checker's exit
/// code per declared standard (retiring `[tasks.ntia-record]`).
pub(crate) const SBOM_CONFORMANCE: FlagDecl = FlagDecl::switch(
    "conformance",
    "conformance",
    "Derive the SPDX document into scratch and record the declared checker's exit code per standard",
);

/// `<target>` on `dist`: the triple to build.
pub(crate) const DIST_TARGET: FlagDecl = FlagDecl::positional(
    "target",
    "The target triple to build, which must already be installed",
);

/// `--stem` on `dist`: the asset's name, without building.
///
/// The naming contract has readers besides the build — an installer resolving
/// an asset, the binary SBOM naming its own — and a flag answering it is what
/// keeps them from re-spelling it.
pub(crate) const DIST_STEM: FlagDecl = FlagDecl::switch(
    "stem",
    "stem",
    "Print the target's asset stem and exit, without building",
);

/// `--build-tool <tool>` on `dist`.
pub(crate) const DIST_BUILD_TOOL: FlagDecl = FlagDecl::valued(
    "build_tool",
    "build-tool",
    "How to build for the target: cargo, cross, zigbuild or cargo-dist (default: $DIST_BUILD_TOOL, else cargo)",
);

/// `[tool]` on `mcp grant`: the tool name to resolve.
pub(crate) const MCP_TOOL: FlagDecl = FlagDecl::positional_optional(
    "tool",
    "The tool name to resolve, as `mcp__<server>__<tool>`; absent under --guard or --aliases",
);

/// `--guard` on `mcp grant`: decide the call a hook payload on stdin names.
pub(crate) const MCP_GUARD: FlagDecl = FlagDecl::switch(
    "guard",
    "guard",
    "Read a hook payload on stdin and refuse the call the committed settings deny",
);

/// `--aliases` on `mcp grant`: the portable alias each live server resolves to.
pub(crate) const MCP_ALIASES: FlagDecl = FlagDecl::switch(
    "aliases",
    "aliases",
    "List the portable alias each server in the injected config resolves to",
);

/// `--config <file>` on the MCP arms: the host-injected MCP config.
pub(crate) const MCP_CONFIG: FlagDecl = FlagDecl::valued(
    "config",
    "config",
    "The host-injected MCP config to resolve server names through",
);

/// `--settings <file>` on the MCP arms: the permission settings to judge.
pub(crate) const MCP_SETTINGS: FlagDecl = FlagDecl::valued(
    "settings",
    "settings",
    "The permission settings file to judge, instead of the declared one",
);

/// `--logs <dir>` on `mcp posture`: the host's MCP connection log tree.
pub(crate) const MCP_LOGS: FlagDecl = FlagDecl::valued(
    "logs",
    "logs",
    "The host's MCP connection log tree, instead of the one it keeps for this project",
);

/// `--spawns <file>` on `mcp posture`: the ledger `mcp spawn` appends to.
pub(crate) const MCP_SPAWNS: FlagDecl = FlagDecl::valued(
    "spawns",
    "spawns",
    "The spawn ledger `mcp spawn` appends to, instead of this clone's",
);

/// `--issue <key>` on `board check`, repeatable.
///
/// The board is many rows where `ready lint` judges one, so this is `ISSUE`'s
/// store read made repeatable rather than a second flag: absent, the payloads
/// arrive on stdin exactly as they always have.
pub(crate) const BOARD_ISSUE: FlagDecl = FlagDecl {
    value: ValueDecl::StrMany,
    ..FlagDecl::valued(
        "issue",
        "issue",
        "Read this issue's payload from the capture store rather than stdin (repeatable)",
    )
};

/// `--cites` on `board check` (CLOUD-826, retiring `mise-tasks/ready-cites-check.sh`).
///
/// A switch rather than a verb of its own: it is the same payload set read the
/// same way, asked a different question, and a second verb would be a second
/// place the set's reading could drift.
pub(crate) const BOARD_CITES: FlagDecl = FlagDecl::switch(
    "cites",
    "cites",
    "Judge each payload's Ready-block citations against the tree instead of the graph",
);

/// `--refs` on `board check` (CLOUD-809, retiring `mise-tasks/spec-ref-check.sh`).
pub(crate) const BOARD_REFS: FlagDecl = FlagDecl::switch(
    "refs",
    "refs",
    "Judge the tree's clause citations against the payloads instead of the graph",
);

/// `--ci-workflow <file>` on `record divergence`.
///
/// A flag rather than a literal: which workflow carries the graded CI runs is the
/// consumer's fact (rule 1), and a default would be a name out of one
/// repository's `.github`. Absent, the verb reads `$LAND_CI_WORKFLOW`, and it
/// refuses when neither names one.
pub(crate) const DIVERGENCE_CI: FlagDecl = FlagDecl::valued(
    "ci_workflow",
    "ci-workflow",
    "The workflow file whose runs are the graded CI runs (default: $LAND_CI_WORKFLOW)",
);

/// `--land-workflow <file>` on `record divergence`, for the same reason; absent,
/// the verb reads `$LAND_WORKFLOW`, the variable `land fast-forward` reads.
pub(crate) const DIVERGENCE_LAND: FlagDecl = FlagDecl::valued(
    "land_workflow",
    "land-workflow",
    "The workflow file whose runs are the landing bot's answers (default: $LAND_WORKFLOW)",
);

/// `--since <instant>` on `record divergence`: the window's start.
pub(crate) const DIVERGENCE_SINCE: FlagDecl = FlagDecl::valued(
    "since",
    "since",
    "The window's start, ISO-8601 (default: 24 hours before now)",
);

/// `[tag]` on `record attestation`: the release to judge.
pub(crate) const ATTESTATION_TAG: FlagDecl = FlagDecl::positional_optional(
    "tag",
    "The release tag to judge; absent is the latest release",
);

/// `--binary <name>` on `record attestation`: the file the verifier judges.
///
/// Required, and the consumer's: which executable a release attests is a fact
/// about that consumer, never a name the engine may carry (rule 1).
pub(crate) const ATTESTATION_BINARY: FlagDecl = FlagDecl {
    required: true,
    ..FlagDecl::valued(
        "binary",
        "binary",
        "The binary's file name inside each archive (a `.exe` suffix also matches)",
    )
};

/// `--verifier <program>` on `record attestation`.
pub(crate) const ATTESTATION_VERIFIER: FlagDecl = FlagDecl::valued(
    "verifier",
    "verifier",
    "The program that downloads the release and verifies each binary (default: gh)",
);

/// `--max-pages <n>` on `record divergence`: the walk's bound per workflow.
pub(crate) const DIVERGENCE_MAX_PAGES: FlagDecl = FlagDecl::valued(
    "max_pages",
    "max-pages",
    "Pages of runs to read per workflow before the window reads as truncated (default: 10)",
);

/// `--window <n>` on `record nonverdict`: how many recent failed runs to read.
pub(crate) const NONVERDICT_WINDOW: FlagDecl = FlagDecl::valued(
    "window",
    "window",
    "How many recent failed runs to read, 1 to 100 (default: 30)",
);

/// `--required-check <name>` on `record nonverdict`, repeatable: the roster a
/// failed job must be on to be counted, which is the consumer's fact. Absent,
/// the verb reads `$CI_REQUIRED_CHECKS`, comma-separated, the roster `land`
/// already reads, and refuses when neither names one.
pub(crate) const NONVERDICT_REQUIRED: FlagDecl = FlagDecl {
    value: ValueDecl::StrMany,
    ..FlagDecl::valued(
        "required_check",
        "required-check",
        "A required job, by exact name; only these are counted (repeatable; default: $CI_REQUIRED_CHECKS)",
    )
};

/// `--exclude-job <name>` on `record nonverdict`, repeatable: a job whose
/// failure its siblings manufacture, such as a fan-in, which is the consumer's
/// name to give. Absent, the verb reads `$CI_FANIN_CHECK`, the fan-in `land`
/// already reads.
pub(crate) const NONVERDICT_EXCLUDE: FlagDecl = FlagDecl {
    value: ValueDecl::StrMany,
    ..FlagDecl::valued(
        "exclude_job",
        "exclude-job",
        "A job never counted, such as a fan-in whose failure its siblings cause (repeatable; default: $CI_FANIN_CHECK)",
    )
};

/// `--verdict-step <prefix>` on `record nonverdict`, repeatable: how a job
/// renders a verdict is the consumer's fact. Absent, the verb reads
/// `$CI_VERDICT_STEPS`, comma-separated, and refuses when neither names one —
/// with no prefix every failure would read as a non-verdict.
pub(crate) const NONVERDICT_STEP: FlagDecl = FlagDecl {
    value: ValueDecl::StrMany,
    ..FlagDecl::valued(
        "verdict_step",
        "verdict-step",
        "A step-name prefix that marks a failed step as verdict-bearing (repeatable; default: $CI_VERDICT_STEPS)",
    )
};

/// `[tag]` on `release sums` and `record release`: the release to read.
///
/// Optional, and EMPTY reads as absent: a workflow passes the tag quoted, so the
/// argument always arrives, and "no tag" there means the latest release.
pub(crate) const RELEASE_TAG: FlagDecl = FlagDecl::positional_optional(
    "tag",
    "The release's tag; empty or absent is the latest release",
);

/// `--manifest <name>` on `release sums` and `record release`.
///
/// REQUIRED, and a flag rather than a literal: the manifest's file name is the
/// consumer's (rule 1), declared once in its own configuration and handed here.
pub(crate) const RELEASE_MANIFEST: FlagDecl = FlagDecl {
    required: true,
    ..FlagDecl::valued(
        "manifest",
        "manifest",
        "The checksum manifest's file name, as the release carries it",
    )
};

/// `release verify`'s tag (CLOUD-2033): required, because "the latest release"
/// is exactly what an installer must never resolve.
pub(crate) const VERIFY_TAG: FlagDecl = FlagDecl::positional("tag", "The release's tag");

/// `--draft` on `release verify`: verify a draft rather than a published release.
pub(crate) const VERIFY_DRAFT: FlagDecl = FlagDecl::switch(
    "draft",
    "draft",
    "Verify a draft, read through the assets API, rather than a published, immutable release",
);

/// `release path`'s head (CLOUD-2033 G2): the SHA graded, never a merge ref.
pub(crate) const PATH_SHA: FlagDecl = FlagDecl::positional("sha", "The head commit graded");

/// `--post` on `release path`: post the verdict as the `release-path` status.
pub(crate) const PATH_POST: FlagDecl = FlagDecl::switch(
    "post",
    "post",
    "Post the verdict as the release-path commit status on the graded head",
);

/// The tag `release discard`, `land-state` and `bump-unusable` act on.
pub(crate) const RELEASE_STATE_TAG: FlagDecl = FlagDecl::positional("tag", "The release's tag");

/// `--sha <sha>` on `release land-state`: the commit the build was dispatched with.
pub(crate) const LAND_STATE_SHA: FlagDecl = FlagDecl {
    required: true,
    ..FlagDecl::valued("sha", "sha", "The commit the build was dispatched with")
};

/// `--seal <workflow>` on `release path`: exit 1 under the pre-B2 seal
/// `final` runs, reading the settings from that guard workflow's last run.
pub(crate) const PATH_SEAL: FlagDecl = FlagDecl::valued(
    "seal",
    "seal",
    "Exit 1 when the verdict is failure and the head is not release-shaped or this release-guard workflow's last settings job is not green",
);

/// `--strict` on `release path`: the landers' refusal of a failure verdict.
pub(crate) const PATH_STRICT: FlagDecl =
    FlagDecl::switch("strict", "strict", "Exit 1 when the verdict is failure");

/// A required `--<long> <value>` flag with no env equivalent.
const fn required(id: &'static str, long: &'static str, help: &'static str) -> FlagDecl {
    FlagDecl {
        required: true,
        ..FlagDecl::valued(id, long, help)
    }
}

/// `--workflow <file>` on the release path's verbs: a workflow named by file,
/// which is the consumer's fact.
pub(crate) const RELEASE_WORKFLOW: FlagDecl = required(
    "workflow",
    "workflow",
    "The workflow's file name, as the forge's workflow API names it",
);

/// `--workflow <file>` on `release in-flight`, repeatable (CLOUD-2287): the
/// build workflow and the land workflow, each a run of which holds the freeze.
pub(crate) const IN_FLIGHT_WORKFLOW: FlagDecl = FlagDecl {
    required: true,
    value: ValueDecl::StrMany,
    ..FlagDecl::valued(
        "workflow",
        "workflow",
        "A release workflow's file name, as the forge's workflow API names it (repeatable)",
    )
};

/// `--branch <branch>` on `release bump-unusable`.
pub(crate) const RELEASE_BRANCH: FlagDecl = required(
    "branch",
    "branch",
    "The release branch the bump is committed onto",
);

/// `--land-workflow <file>` on `release cut`: where a baked head is landed.
pub(crate) const CUT_LAND_WORKFLOW: FlagDecl = FlagDecl::valued(
    "land_workflow",
    "land-workflow",
    "The land workflow a baked head of the open draft's target is dispatched to, instead of a new cut",
);

/// `--sha <sha>` on `release bake`: the release head the bake commits onto.
pub(crate) const BAKE_SHA: FlagDecl = FlagDecl::valued(
    "sha",
    "sha",
    "The release head the bake is committed onto; required unless --write-only",
);

/// `--branch <branch>` on `release bake`: the release branch moved to the bake.
pub(crate) const BAKE_BRANCH: FlagDecl = FlagDecl::valued(
    "branch",
    "branch",
    "The release branch moved to the bake commit; required unless --write-only",
);

/// `--write-only` on `release bake`: write the two files, commit nothing.
pub(crate) const BAKE_WRITE_ONLY: FlagDecl = FlagDecl::switch(
    "write_only",
    "write-only",
    "Write install.lock and install.sh to the working tree and commit nothing",
);

/// `--changelog <path>` on `release bump-unusable` and `release cut`.
pub(crate) const RELEASE_CHANGELOG: FlagDecl = required(
    "changelog",
    "changelog",
    "The changelog carrying the release's `## [X]` section",
);

/// `--at <rev>` on `release pin`.
pub(crate) const PIN_AT: FlagDecl = FlagDecl::valued(
    "at",
    "at",
    "Read the pin at this revision rather than the working tree",
);

/// `--last-run <workflow>` on `release settings`.
pub(crate) const SETTINGS_LAST_RUN: FlagDecl = FlagDecl::valued(
    "last_run",
    "last-run",
    "Answer from the settings job of this guard workflow's last completed run on the trunk",
);

/// `--out-dir <dir>` on `release sums`.
pub(crate) const RELEASE_OUT_DIR: FlagDecl = FlagDecl::valued(
    "out_dir",
    "out-dir",
    "Write the manifest under this directory (default: checksums)",
);

/// `--names` on `release sums`: answer the manifest's path and nothing else.
pub(crate) const RELEASE_NAMES: FlagDecl = FlagDecl::switch(
    "names",
    "names",
    "Print the manifest's path as sums=<path> and exit, with no tag, network or download",
);

/// `--tag <tag>` on `release backfill`, repeatable and ordered.
pub(crate) const BACKFILL_TAG: FlagDecl = FlagDecl {
    value: ValueDecl::StrMany,
    ..FlagDecl::valued(
        "tag",
        "tag",
        "A release tag to record (repeatable); absent, every tag the pattern selects, oldest first",
    )
};

/// `--workflow <file>` on `release backfill`: the consumer's workflow, required.
pub(crate) const BACKFILL_WORKFLOW: FlagDecl = FlagDecl {
    required: true,
    ..FlagDecl::valued(
        "workflow",
        "workflow",
        "The workflow file dispatched once per tag",
    )
};

/// `--ref <branch>` on `release backfill`: where the dispatched runs execute.
pub(crate) const BACKFILL_REF: FlagDecl = FlagDecl {
    required: true,
    ..FlagDecl::valued("ref", "ref", "The branch the dispatched runs execute on")
};

/// `--pattern <glob>` on `release backfill`: what a release tag is.
pub(crate) const BACKFILL_PATTERN: FlagDecl = FlagDecl {
    required: true,
    ..FlagDecl::valued(
        "pattern",
        "pattern",
        "The glob a release tag matches, as `git tag --list` matches it",
    )
};

/// `--dry-run` on `release backfill`.
pub(crate) const BACKFILL_DRY_RUN: FlagDecl = FlagDecl::switch(
    "dry_run",
    "dry-run",
    "Print the plan, oldest first, and dispatch nothing",
);

/// `--poll-interval <seconds>` on `release backfill`.
pub(crate) const BACKFILL_POLL_INTERVAL: FlagDecl = FlagDecl::valued(
    "poll_interval",
    "poll-interval",
    "Seconds between polls; the forge's own interval raises it (default: 5)",
);

/// `--max-polls <n>` on `release backfill`: a COUNT backstop, never a clock.
pub(crate) const BACKFILL_MAX_POLLS: FlagDecl = FlagDecl::valued(
    "max_polls",
    "max-polls",
    "Polls per tag before its run reads as never finishing (default: 240)",
);

/// `<kind>` on `record census note`.
pub(crate) const CENSUS_KIND: FlagDecl =
    FlagDecl::positional("kind", "h for a landing's beat, x for a deliberate stop");

/// `[reason]` on `record census note`: why a loop stopped, beside an `x`.
const CENSUS_REASON: FlagDecl = FlagDecl::positional_optional(
    "reason",
    "Why the loop stopped, one word, recorded beside an x",
);

/// `--once` on `record census report`: speak once per boot.
///
/// The verdict classifies the PREVIOUS boot, which is immutable history, so it
/// is true at every session start for the life of a container. Once the positive
/// reading has been read it is noise; this writes the mark that silences it, and
/// that write is why the arm is `write` rather than `read`.
pub(crate) const CENSUS_ONCE: FlagDecl = FlagDecl::switch(
    "once",
    "once",
    "Report once per boot: record that this boot's verdict was read, and stay silent after",
);

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
    // CLOUD-119's benchmark, ported out of `mise-tasks/token-bench.sh` and the
    // drift half of `mise-tasks/token-bench-check.sh` under CLOUD-1753.
    //
    // A NOUN THAT ONLY DISPATCHES, on `ci`'s reading: the noun decides nothing,
    // so it is `Unclassified` rather than `Read`.
    CommandDecl {
        path: "bench",
        id: "bench",
        about: "Measure what a capability costs an agent's context",
        data_channel: false,
        exits: EXITS_DISPATCHES,
        effect: Effect::Unclassified,
        flags: &[],
    },
    // `Unclassified`, and not optimistically `Write`: the arms it prices are the
    // CONSUMER's declared step sequences, so its reach is whatever they reach.
    // It writes the published table, and under `--check` it writes nothing and
    // compares — a gate that rewrote the tree it judges could not fail twice.
    CommandDecl {
        path: "bench tokens",
        id: "bench.tokens",
        about: "Measure the token economics of the Batten-wrapped path against the raw tool, from committed fixtures",
        data_channel: false,
        exits: EXITS_VERDICT,
        effect: Effect::Unclassified,
        flags: &[BENCH_CHECK],
    },
    CommandDecl {
        path: "check",
        id: "check",
        about: "Run the applicable read-only gates against the repository",
        data_channel: true,
        exits: EXITS_VERDICT,
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
        exits: EXITS_VERDICT,
        effect: Effect::Unclassified,
        flags: &[
            ENFORCE_RULE,
            ENFORCE_HALF,
            ENFORCE_KEYED_BASE,
            ENFORCE_INPUTS_DIGEST,
            JSON,
        ],
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
        // `EXITS_VERDICT`, because a lock refusal IS a verdict (review of #928).
        // `exec::hold` hands a held lock to `task::report_claim`, which returns
        // `ExitCode::Violation`, and the CLI census refuses any observed code
        // the row does not declare. The row said `EXITS_STANDARD`, which omits
        // 2 — so the one outcome `--lock` exists to produce was undeclared.
        exits: EXITS_VERDICT,
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
            LOCK,
            LOCK_PATH,
            LOCK_ATTEMPTS,
            LOCK_LABEL,
            EXEC_TRACKED,
            EXEC_EXCEPT,
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
        exits: EXITS_DISPATCHES,
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
        exits: EXITS_STANDARD,
        effect: Effect::Read,
        flags: &[
            FlagDecl::positional("handle", "The `<stream>:<digest>` handle to read"),
            LINES,
            GREP,
            FIELD,
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
        exits: EXITS_STANDARD,
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
        exits: EXITS_STANDARD,
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
        exits: EXITS_STANDARD,
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
        exits: EXITS_DISPATCHES,
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
    // ONE QUESTION IS NARROWED, AND ONLY IN POLICY (CLOUD-2289): whether a call
    // changes anything outside batten's own state. For a method whose verb only
    // reads it does not, so `read-only-is-preapproved.rego`'s `reads` admits
    // `mcp call <server> <read verb>` by the same `mcp_read_verb` regex that
    // admits the `mcp__*` tool form. This field, and `batten_effect`, still say
    // `Unclassified`.
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
        exits: EXITS_STANDARD,
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
    // The spawn ledger and the launch, ported off `mise-tasks/serena-mcp.sh`
    // under CLOUD-1753 (CLOUD-714 is the defect it exists for).
    //
    // WHAT THIS MUST NEVER BECOME is the whole of CLOUD-714 and it survives the
    // port structurally rather than by prose: not a retry, not a supervisor, not
    // a keepalive. It records and it EXECS, and after an exec there is no process
    // left that could restart anything. A shim that recovered from a failed
    // launch would hide the defect it was written to expose.
    //
    // `Unclassified` on `exec`'s own reading, and it is the honest one twice
    // over: the verb replaces this process with a command the CONSUMER named, so
    // its reach is whatever that command's is, and it writes a per-clone ledger
    // besides. An optimistic `read` here would put a process-replacing verb on
    // the derived allowlist.
    //
    // `data_channel` is FALSE and here it is load-bearing beyond `exec`'s reason:
    // STDOUT IS THE MCP TRANSPORT. One stray byte corrupts the JSON-RPC stream
    // and takes the server down looking exactly like the bug this records. So
    // Batten emits nothing on stdout at all, and the record it keeps is a file.
    // unreached: "mcp spawn" CLOUD-1753 the only caller is `.mcp.json`, whose JSON argv
    // spells the verb as separate array elements, which a text needle does not read
    // as a call. The release on PATH ships the verb (v0.0.188 answers its --help).
    CommandDecl {
        path: "mcp spawn",
        id: "mcp.spawn",
        about: "Record that a client actually spawned this server, then exec the launch line unchanged",
        data_channel: false,
        exits: EXITS_STANDARD,
        effect: Effect::Unclassified,
        flags: &[
            // Declared BEFORE the trailing argv, on `exec`'s note: a
            // `trailing_var_arg` swallows everything after the first free token.
            FlagDecl::positional(
                "server",
                "The server this launch is for, as the spawn ledger and `mcp-attach-check` name it",
            ),
            FlagDecl::trailing(
                "command",
                "The launch line, run verbatim — Batten execs it and does not supervise it",
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
        exits: EXITS_DISPATCHES,
        effect: Effect::Unclassified,
        flags: &[],
    },
    // The reclaim (CLOUD-766, CLOUD-1030), ported out of
    // `mise-tasks/target-prune.sh` under CLOUD-1059; since CLOUD-2198 one forced
    // run of the disk collector, with no floor.
    //
    // `destructive`, not `write`, and for `capture prune`'s reason one row up:
    // what it removes is recoverable only by re-running the build that produced
    // it — which is precisely the cost the retention policy exists to avoid
    // paying. So `-y` binds here too, and the primary caller is `verify`, a
    // program that must never be prompted into the void.
    CommandDecl {
        path: "target prune",
        id: "target.prune",
        about: "Collect superseded, then least recently used, build units until [prune] max_free_mb is free",
        data_channel: false,
        exits: EXITS_VERDICT,
        effect: Effect::Destructive,
        flags: &[DRY_RUN, PRUNE_ROOT],
    },
    // One rustup target made present (CLOUD-1753), retiring `target-ensure.sh`,
    // `doctor-check.sh` and `with-lock.sh` — three files that were one capability
    // split by the shell's limits rather than by the problem.
    //
    // UNDER `doctor` RATHER THAN `target`, and the noun is the decision. `target`
    // is *this repository's build tree* — what `prune` reclaims — where a rustup
    // target is a property of the TOOLCHAIN, which is what every other `doctor`
    // sub-verb already answers about. Filing it under `target` would put a verb
    // that installs a compiler component beside one that deletes build output.
    //
    // `write`, not `read`: it purges residue and runs `rustup target add`. It is
    // therefore absent from §5's agent allowlist BY CONSTRUCTION, which is that
    // derivation working rather than an omission — the allowlist is
    // `effect == read` and this reaches the network. Not `destructive` either, on
    // `target prune`'s own test: what it removes is a half-installed component
    // nothing can depend on, and re-running the verb restores it, so there is no
    // unrecoverable loss for `-y` to guard.
    CommandDecl {
        path: "doctor target",
        id: "doctor.target",
        about: "Make one rustup target installed, purging a half-installed one first, behind the toolchain's own lock",
        data_channel: false,
        exits: EXITS_STANDARD,
        effect: Effect::Write,
        flags: &[FlagDecl::positional(
            "target",
            "The target triple to install, as `rustup target list` spells it",
        )],
    },
    // Whether a diff can move the hk slow tier (CLOUD-398), ported out of
    // `mise-tasks/ci-slow-needed.sh` under CLOUD-1716.
    //
    // A NOUN THAT ONLY DISPATCHES, on `target`'s reading: the noun itself decides
    // nothing, so it is `Unclassified` rather than `Read` — a `read` noun over a
    // subtree leaks onto §5's derived allowlist for any consumer treating an
    // entry as a prefix.
    CommandDecl {
        path: "ci",
        id: "ci",
        about: "Answer what this repository's continuous integration needs of a change",
        data_channel: false,
        exits: EXITS_DISPATCHES,
        effect: Effect::Unclassified,
        flags: &[],
    },
    // `checks green`'s SHAPE, deliberately: the answer is yes or no, so `0` is
    // "the tier is needed" and `Violation` is "it is not". Could-not-look is
    // `Internal`, which is the reading an empty diff gets — a wrong base or a
    // shallow clone, never a clean diff.
    CommandDecl {
        path: "ci slow-needed",
        id: "ci.slow-needed",
        about: "Decide whether a diff can move the slow tier, so a diff that cannot does not pay for it",
        data_channel: false,
        exits: EXITS_VERDICT,
        effect: Effect::Read,
        flags: &[SLOW_BASE, SLOW_HEAD],
    },
    // WHICH suites a diff can move (CLOUD-886), ported out of
    // `mise-tasks/suite-select.sh` under CLOUD-1716.
    //
    // `Read` and `EXITS_STANDARD` rather than `ci slow-needed`'s verdict table,
    // because this ANSWERS rather than decides: the suite list is the payload, a
    // caller runs what it names, and there is no yes-or-no for an exit code to
    // carry. Could-not-look widens to every suite instead of refusing -- a
    // selector that cannot answer must never narrow, which is the asymmetry
    // `suites::select` is built around.
    CommandDecl {
        path: "ci suites",
        id: "ci.suites",
        about: "Name the bats suites a diff can move, or every suite where it cannot prove one inert",
        // **NO DATA CHANNEL, and the declaration was the defect rather than the
        // implementation.** This row said `true` while the verb offers no `-J`
        // and emits no document: it writes one suite PATH per line, which the
        // caller hands straight to bats. `cli::every_data_channel_verb_emits_one_pure_json_document`
        // and `cli::no_progress_reaches_stderr_when_it_is_not_a_terminal` both
        // caught it — the first because an empty answer printed nothing where a
        // document was promised, the second because `-J` is not a flag here at
        // all.
        //
        // Inventing a JSON shape to satisfy the declaration would be the wrong
        // repair: nothing consumes one, and `generate schema` carries this same
        // `false` for the same reason — its only output IS the artifact, with no
        // human rendering to switch away from.
        data_channel: false,
        exits: EXITS_STANDARD,
        effect: Effect::Read,
        flags: &[SLOW_BASE],
    },
    // The runner-file glue a workflow step used a shell for (CLOUD-843, Phase
    // 4): step outputs, the run summary, a verdict mapped to an output, a
    // capture. `step run`'s reading: it runs the command the caller names, so
    // it is `Unclassified`, and the child's verdict is the verb's.
    CommandDecl {
        path: "ci step",
        id: "ci.step",
        about: "Run one command and write its step outputs, run summary or mapped verdict to the runner's files",
        data_channel: false,
        exits: EXITS_VERDICT,
        effect: Effect::Unclassified,
        flags: &[
            CI_STEP_OUTPUTS,
            CI_STEP_SUMMARY,
            CI_STEP_SAVE,
            CI_STEP_STDIN,
            CI_STEP_VERDICT,
            CI_STEP_ON,
            CI_STEP_ARG_ENV,
            CI_STEP_CAPTURE,
            CI_STEP_REQUIRE_ENV,
            CI_STEP_COMMAND,
        ],
    },
    // CLOUD-65's install contract, ported out of `mise-tasks/install-check.sh`
    // under CLOUD-1716.
    //
    // A NOUN THAT ONLY DISPATCHES, on `ci`'s reading: the noun itself decides
    // nothing, so it is `Unclassified` rather than `Read` -- a `read` noun over
    // a subtree leaks onto the derived allowlist for any consumer treating an
    // entry as a prefix.
    CommandDecl {
        path: "release",
        id: "release",
        about: "Answer whether a release is installable as it says it is, hash its assets, and backfill its tracking",
        data_channel: false,
        exits: EXITS_DISPATCHES,
        effect: Effect::Unclassified,
        flags: &[],
    },
    // `Unclassified` RATHER THAN `Read`, and the reason is the interim: this
    // asks `install.sh` through the query flags it publishes, so it spawns, and
    // its reach is whatever that program's is. An optimistic `read` here would
    // put a process-spawning verb on the derived allowlist. `dist`'s naming is
    // asked in process now (`dist::archive_stem`); `install.sh` stays shell
    // because it runs before the engine exists, so this stays `Unclassified`.
    CommandDecl {
        path: "release install",
        id: "release.install",
        about: "Decide whether install.sh, the release matrix and the binstall manifest agree on every asset name, and that no binary is committed",
        data_channel: false,
        exits: EXITS_VERDICT,
        effect: Effect::Unclassified,
        flags: &[],
    },
    // A release's checksum manifest, retiring `[tasks.checksums]` (CLOUD-843).
    // `write`: it writes one file, and it reaches the network, which the derived
    // read-only allowlist must never advertise. A release it could not read, or
    // one with nothing to hash, is exit 3 with nothing written.
    CommandDecl {
        path: "release sums",
        id: "release.sums",
        about: "Hash a published release's own assets into a checksum manifest, never the manifest itself",
        data_channel: false,
        exits: EXITS_STANDARD,
        effect: Effect::Write,
        flags: &[
            RELEASE_TAG,
            RELEASE_MANIFEST,
            RELEASE_OUT_DIR,
            RELEASE_NAMES,
        ],
    },
    // G1 (CLOUD-2033): whether a release is fully and correctly published.
    // `write`, as `record release` is: it writes the release's record before it
    // grades it, and it reaches the network.
    CommandDecl {
        path: "release verify",
        id: "release.verify",
        about: "Exit 0 only if a release carries every asset, its checksums match, and it is published and immutable at its own tag",
        data_channel: false,
        exits: EXITS_STANDARD,
        effect: Effect::Write,
        flags: &[VERIFY_TAG, VERIFY_DRAFT],
    },
    // G2 (CLOUD-2033): the one predicate a write of `main` is graded by.
    // `write`: `--post` posts a commit status, and G1 under it writes a record.
    CommandDecl {
        path: "release path",
        id: "release.path",
        about: "Print whether a head may write main: its pin is inherited, or it changes only the release paths to a verified published release",
        data_channel: false,
        exits: EXITS_STANDARD,
        effect: Effect::Write,
        flags: &[PATH_SHA, PATH_POST, PATH_SEAL, PATH_STRICT],
    },
    // The release path's verbs (CLOUD-2033 P3, P4). Each is one tested branch
    // a workflow `case`s on.
    CommandDecl {
        path: "release discard",
        id: "release.discard",
        about: "Delete a draft release and its tag; do nothing for no release; refuse a published one",
        data_channel: false,
        exits: EXITS_STANDARD,
        effect: Effect::Write,
        flags: &[RELEASE_STATE_TAG],
    },
    CommandDecl {
        path: "release in-flight",
        id: "release.in_flight",
        about: "Exit 0 when no release is in flight, 1 naming the one that is",
        data_channel: false,
        exits: EXITS_STANDARD,
        effect: Effect::Read,
        flags: &[IN_FLIGHT_WORKFLOW],
    },
    CommandDecl {
        path: "release land-state",
        id: "release.land_state",
        about: "Print the land job's branch for a release: skip-to-f, resume-at-d, burned, draft-ok, draft-bad or absent",
        data_channel: false,
        exits: EXITS_STANDARD,
        effect: Effect::Read,
        flags: &[RELEASE_STATE_TAG, LAND_STATE_SHA],
    },
    CommandDecl {
        path: "release bump-unusable",
        id: "release.bump_unusable",
        about: "Move a burned or stray-tagged version to the next one in all four release paths, as one commit on the release branch",
        data_channel: false,
        exits: EXITS_STANDARD,
        effect: Effect::Write,
        flags: &[RELEASE_STATE_TAG, RELEASE_BRANCH, RELEASE_CHANGELOG],
    },
    CommandDecl {
        path: "release guard",
        id: "release.guard",
        about: "Exit 0 only when a build of the commit may upload into the release: a draft that targets it",
        data_channel: false,
        exits: EXITS_STANDARD,
        effect: Effect::Read,
        flags: &[RELEASE_STATE_TAG, LAND_STATE_SHA],
    },
    CommandDecl {
        path: "release cut",
        id: "release.cut",
        about: "Discard any draft of the version, draft it at the release head and dispatch its build",
        data_channel: false,
        exits: EXITS_STANDARD,
        effect: Effect::Write,
        flags: &[
            RELEASE_STATE_TAG,
            LAND_STATE_SHA,
            RELEASE_CHANGELOG,
            RELEASE_WORKFLOW,
            CUT_LAND_WORKFLOW,
        ],
    },
    // `write` (CLOUD-2287): `install.lock` and the `install.sh` rendered from
    // it, committed onto the release head through the forge so the branch move
    // fires CI — or, with `--write-only`, written to the working tree.
    CommandDecl {
        path: "release bake",
        id: "release.bake",
        about: "Bake a release's tag and archive digests into install.lock and install.sh, as one commit on its release head",
        data_channel: false,
        exits: EXITS_STANDARD,
        effect: Effect::Write,
        flags: &[RELEASE_STATE_TAG, BAKE_SHA, BAKE_BRANCH, BAKE_WRITE_ONLY],
    },
    CommandDecl {
        path: "release pin",
        id: "release.pin",
        about: "Print the release batten.toml pins, in the working tree or at a revision",
        data_channel: false,
        exits: EXITS_STANDARD,
        effect: Effect::Read,
        flags: &[PIN_AT],
    },
    // G4 (CLOUD-2033): `read` since `--probe`, the one write, went (CLOUD-2508).
    CommandDecl {
        path: "release settings",
        id: "release.settings",
        about: "Exit 0 only when the rulesets and release settings the release path rests on hold",
        data_channel: false,
        exits: EXITS_STANDARD,
        effect: Effect::Read,
        flags: &[SETTINGS_LAST_RUN],
    },
    // The release pipeline's backfill sweep, retiring `[tasks.release-backfill]`
    // (CLOUD-843). `unclassified` rather than `write`: every dispatch starts a
    // run of the consumer's own workflow, whose effect is whatever that
    // workflow does — `exec`'s reading, one host over.
    CommandDecl {
        path: "release backfill",
        id: "release.backfill",
        about: "Dispatch a backfill workflow once per release tag, oldest first, waiting on each run and stopping at the first that does not succeed",
        data_channel: false,
        exits: EXITS_STANDARD,
        effect: Effect::Unclassified,
        flags: &[
            BACKFILL_TAG,
            BACKFILL_WORKFLOW,
            BACKFILL_REF,
            BACKFILL_PATTERN,
            BACKFILL_DRY_RUN,
            BACKFILL_POLL_INTERVAL,
            BACKFILL_MAX_POLLS,
        ],
    },
    CommandDecl {
        path: "config",
        id: "config",
        about: "Inspect configuration",
        data_channel: false,
        exits: EXITS_DISPATCHES,
        effect: Effect::Read,
        flags: &[],
    },
    CommandDecl {
        path: "config show",
        id: "config.show",
        about: "Print the effective configuration",
        data_channel: true,
        exits: EXITS_STANDARD,
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
        exits: EXITS_STANDARD,
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
        exits: EXITS_VERDICT,
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
        exits: EXITS_VERDICT,
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
        exits: EXITS_DISPATCHES,
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
        exits: EXITS_VERDICT,
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
        exits: EXITS_STANDARD,
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
        exits: EXITS_DISPATCHES,
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
    // function of install recency. `rules/toolchain.md` states the rule
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
        exits: EXITS_STANDARD,
        effect: Effect::Read,
        flags: &[JSON],
    },
    // THE CONTAINER'S PROXY VALUES ARE A PROPERTY OF THE WORLD (CLOUD-1399), so
    // this sits beside `doctor mediator` for the same reason and not in the bare
    // report: `rules/toolchain.md`'s rule from `lock-check`'s post-mortem
    // — a property of the commit belongs in the gate, a property of the world
    // belongs to its own caller.
    //
    // IT READS THIS PROCESS'S OWN ENVIRONMENT, and that is the capability being
    // added rather than an implementation detail. A consumer's own check asking
    // the same question through its task runner reads a value that runner's env
    // block has already corrected — so it grades the repair and calls the
    // container fenced while the container's own value is unfenced.
    //
    // `read`, and structurally: it resolves two strings against a list. Nothing
    // is spawned, NOTHING IS DIALLED and no name is looked up — the reserved
    // `.invalid` probe never leaves the process — so it belongs on the
    // `filter(effect == read)` allowlist without qualification.
    CommandDecl {
        path: "doctor egress",
        id: "doctor.egress",
        about: "Diagnose whether the agent proxy would carry this container's requests",
        data_channel: true,
        exits: EXITS_STANDARD,
        effect: Effect::Read,
        flags: &[JSON],
    },
    // CLOUD-2292. Folds one journal family under the git dir and prints a count
    // per pointer: `read`, no spawn and no network.
    // unreached: "doctor gaps" CLOUD-2292 a reader runs it to see which reads plan mode
    // lacks; nothing in the tree should act on its list unasked.
    CommandDecl {
        path: "doctor gaps",
        id: "doctor.gaps",
        about: "Count the refusals a rule marks counted, by rule and subject, most-refused first",
        data_channel: false,
        exits: EXITS_STANDARD,
        effect: Effect::Read,
        flags: &[],
    },
    // WHETHER THE FORGE CREDENTIAL CARRIES THE CLAIMS THE TASKS NEED (CLOUD-843,
    // retiring `gh-preflight`). `read`: it issues GETs against the endpoints the
    // committed `[[forge.probe]]` rows name and never a write — a row declaring
    // a write claim is reported as declared and never called. `doctor *`'s exit
    // set, for its siblings' reason: a missing claim is a failed diagnosis, and a
    // diagnosis renders no policy verdict, so it cannot mint a `2`.
    CommandDecl {
        path: "doctor forge",
        id: "doctor.forge",
        about: "Diagnose whether the forge credential carries the claims this repository's tasks declare",
        data_channel: false,
        exits: EXITS_STANDARD,
        effect: Effect::Read,
        flags: &[],
    },
    // THE ONE SUB-VERB THAT IS ALSO A ROW IN THE BARE REPORT (CLOUD-1398), and
    // the asymmetry with the two rows above it is the decision rather than an
    // oversight. `doctor mediator` and `doctor egress` are outside the report
    // because they answer properties of the WORLD; whether this clone's commit
    // path runs the gate is a property of the CHECKOUT, the same class as
    // `git-repo`, so it is reported where a reader is already looking.
    //
    // It exists as a verb ANYWAY because a `[[startup]]` row decides on an exit
    // status and has no way to select one row out of a report. `check = ["batten",
    // "doctor"]` would fail the commit-gate row whenever an unrelated declared
    // program was unreachable — measured in this container, where `hk` resolves
    // only under `mise exec` — and then run a repair that installs git hooks,
    // which cannot fix that, reporting `repair-failed` over a gate that is
    // installed. One predicate answers both callers; this row is what lets the
    // narrow caller ask it.
    //
    // `read`, and structurally so: it resolves a directory and stats two files.
    // Nothing is executed — running a hook to see whether it works is what a
    // shell task can do behind a probe variable, and reaching user-supplied code
    // from the `filter(effect == read)` allowlist is CLOUD-170's actual invariant.
    //
    // `gate` RATHER THAN `commit-gate`, AND THE HYPHEN IS THE WHOLE REASON. A man
    // page is committed as the hyphen-joined command path — `batten-doctor-gate.1`
    // — and `surface.rs`'s own suite maps that filename back by replacing EVERY
    // hyphen with a space. So a sub-verb whose name contains one is not
    // round-trippable: `batten-doctor-commit-gate.1` reads back as the command
    // `doctor commit gate`, which renders nothing, and three cases in
    // `crates/batten/tests/it/surface.rs` go red at once. Measured here rather
    // than reasoned — no verb on this surface has ever carried an internal
    // hyphen, and this is why. Do not reintroduce one.
    // THE BARE REPORT'S `config` CHECK, ASKED ALONE, on `doctor gate`'s reason
    // below: a `[[startup]]` row decides on an exit status, and the one skew no
    // row could see — an installed engine older than the tree, dropping every
    // row whose key it does not know — exits `0` from `config show` by design.
    // unreached: "doctor config" CLOUD-1973 the only caller is the
    // `engine-resolves-every-row` `[[startup]]` row, and `batten.toml` is
    // deliberately not a `verb reach other` line source (its prose reads as callers).
    CommandDecl {
        path: "doctor config",
        id: "doctor.config",
        about: "Diagnose whether this build resolves every row of the config",
        data_channel: true,
        exits: EXITS_STANDARD,
        effect: Effect::Read,
        flags: &[JSON],
    },
    CommandDecl {
        path: "doctor gate",
        id: "doctor.gate",
        about: "Diagnose whether this checkout's commit path runs the gate",
        data_channel: true,
        // `doctor *`'s set, and for the same reason every sibling takes it: a
        // diagnosis reports what it found about the checkout and renders no
        // policy verdict, so it cannot mint a `2`.
        exits: EXITS_STANDARD,
        effect: Effect::Read,
        flags: &[JSON],
    },
    // WHETHER THE TOOLCHAIN THIS MANIFEST DECLARES ACTUALLY EXISTS (CLOUD-1683).
    //
    // Outside the bare report, on `doctor mediator`'s and `doctor egress`' reason
    // rather than `doctor gate`'s: whether a tool is installed on this machine is
    // a property of the WORLD. It exists as a verb for the narrow-caller reason
    // the row above records — `verify` needs to ask THIS question alone and stop
    // on its exit status, and bare `doctor` would fail it for an unrelated
    // unreachable program.
    //
    // `read`, and structurally so: it reads the manifest and asks the tool runner
    // what it has installed. Nothing user-supplied is executed and nothing is
    // written.
    //
    // THE MANIFEST ARRIVES AS AN OPERAND, which is non-negotiable rule 1 rather
    // than a taste in ergonomics. The path is a CONSUMER ARTIFACT, and
    // `document_facts.rs`'s `no_artifact_name_reaches_the_core` refuses that
    // literal anywhere in `crates/batten/src` outside a three-file allowlist this
    // module is not on. A default would put it here; requiring it keeps the
    // consumer's own fact in the consumer's own task body, where every other one
    // already lives.
    CommandDecl {
        path: "doctor toolchain",
        id: "doctor.toolchain",
        about: "Diagnose whether every tool the manifest declares is installed",
        data_channel: true,
        // `doctor *`'s set, and for the same reason every sibling takes it: a
        // diagnosis reports what it found and renders no policy verdict, so it
        // cannot mint a `2`.
        exits: EXITS_STANDARD,
        effect: Effect::Read,
        flags: &[MANIFEST, JSON],
    },
    CommandDecl {
        path: "doctor hooks",
        id: "doctor.hooks",
        about: "Diagnose whether batten is wired on every hook surface of every harness",
        // Per-harness detail is the whole reason this is a sub-verb rather than a
        // line in `doctor`'s summary, and `-J` is where that detail goes.
        data_channel: true,
        exits: EXITS_STANDARD,
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
        exits: EXITS_STANDARD,
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
        exits: EXITS_VERDICT,
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
        exits: EXITS_STANDARD,
        effect: Effect::Write,
        flags: &[PRUNE, DRY_RUN],
    },
    CommandDecl {
        path: "generate",
        id: "generate",
        about: "Emit artifacts derived from the command spec, on stdout",
        data_channel: false,
        exits: EXITS_DISPATCHES,
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
        exits: EXITS_STANDARD,
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
        exits: EXITS_STANDARD,
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
        exits: EXITS_STANDARD,
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
        exits: EXITS_STANDARD,
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
        exits: EXITS_STANDARD,
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
        exits: EXITS_DISPATCHES,
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
        exits: EXITS_STANDARD,
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
    // The absolute measurement (CLOUD-207), ported out of `mise-tasks/perf.sh`
    // under CLOUD-1753.
    //
    // `Unclassified` and NOT `Read`, for `perf pair`'s reason: it builds a
    // release binary and runs the benchmark runner over it, so its reach is
    // whatever those have. It emits one record per path on stdout, which is the
    // data channel `record tool perf-p95` reads.
    CommandDecl {
        path: "perf measure",
        id: "perf.measure",
        about: "Measure this binary's invocation cost on every path and print one record per path",
        // **NO DATA CHANNEL**, for `ci suites`' reason and stated in this row's
        // own `about`: it prints ONE RECORD PER PATH — `path=… p50=… p95=…
        // mean=… runs=…` — which `batten record tool perf-p95 --pick path=p95` reduces. That line
        // format IS the contract with the frozen caller, so a JSON rendering
        // would be a second output nothing reads, and declaring a channel the
        // verb does not implement is what the two `cli` surface cases caught.
        data_channel: false,
        exits: EXITS_STANDARD,
        effect: Effect::Unclassified,
        flags: &[],
    },
    // The trunk's invocation-cost series (CLOUD-172), ported out of
    // `mise-tasks/perf-record.sh` under CLOUD-1753.
    //
    // `Write`, and it is the only `perf` arm that is: it appends a git note.
    // `EXITS_VERDICT` because refusing off trunk is a VIOLATION rather than an
    // error — a branch's numbers are not the trunk's, and the caller is being
    // told its request was wrong rather than that the engine broke.
    CommandDecl {
        path: "perf record",
        id: "perf.record",
        about: "Append a measurement to the trunk's invocation-cost series, read as `perf measure` records on stdin",
        data_channel: false,
        exits: EXITS_VERDICT,
        effect: Effect::Write,
        flags: &[],
    },
    CommandDecl {
        path: "perf compare",
        id: "perf.compare",
        about: "Decide whether a paired measurement read on stdin regressed past the threshold",
        data_channel: false,
        exits: EXITS_VERDICT,
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
        exits: EXITS_VERDICT,
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
    // CLOUD-843: `hook-latency-drift.yml`'s inline measurement, as a verb. It
    // times the command `[perf.latency]` declares, so its effect is that
    // command's — unknown ahead of time, hence `unclassified` rather than a guess.
    CommandDecl {
        path: "perf latency",
        id: "perf.latency",
        about: "Time the command `[perf.latency]` declares and report a median that has drifted from its budget, in either direction",
        data_channel: false,
        exits: EXITS_VERDICT,
        effect: Effect::Unclassified,
        flags: &[],
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
        exits: EXITS_DISPATCHES,
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
        exits: EXITS_VERDICT,
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
    // cargo-mutants as a landing gate with no shell in the task body: the
    // change written as its `--in-diff`, `--jobs` sized from the measured machine
    // and the tree's declared per-job cost, `--shard` from `$MUTANT_SHARD`, and
    // its exit read onto §6. `write`: it spawns cargo, which builds and mutates
    // copies of the tree. Its streamed output is cargo-mutants', and the verdict
    // files it reads are cargo-mutants' own.
    CommandDecl {
        path: "mutate cargo",
        id: "mutate.cargo",
        about: "Run cargo-mutants over the change since $MUTANT_CHANGED_SINCE on as many jobs as this machine holds",
        data_channel: false,
        exits: EXITS_VERDICT,
        effect: Effect::Write,
        flags: &[],
    },
    CommandDecl {
        path: "mutate census",
        id: "mutate.census",
        about: "Report every gate in the tree that is neither mutation-enforced nor carrying a filed exemption",
        data_channel: false,
        exits: EXITS_VERDICT,
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
        exits: EXITS_DISPATCHES,
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
        exits: EXITS_VERDICT,
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
        exits: EXITS_VERDICT,
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
        exits: EXITS_VERDICT,
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
        exits: EXITS_STANDARD,
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
    // CLOUD-1718's shape (a). There are two exit-code contracts in this tree and
    // they are INVERSES: this binary reads `1` as usage and `2` as a violation,
    // and 82 shell programs read `1` as a violation and `2` as could-not-look.
    // A caller on the wrong side of that boundary does not get a worse message,
    // it gets the opposite verdict — a blind spot read as a finding, or a finding
    // read as a blind spot.
    //
    // The bug dies with each program that retires, so this verb is justified by
    // what does NOT retire: the workflow tree, which is permanently bash by
    // declaration; the installer, which is bash by construction; and CONSUMER
    // repositories, whose gates hit the identical inversion with no campaign to
    // save them. Each of those still needs the fold, and this is the one place it
    // is decided.
    //
    // `read` structurally and in the strongest sense available: it opens no file,
    // walks no tree and spawns nothing. It reads two integers off its own command
    // line and returns a code.
    CommandDecl {
        path: "verdict",
        id: "verdict",
        about: "Fold a run's findings and blind spots into this tool's exit code",
        data_channel: false,
        // `EXITS_VERDICT`, because folding findings into an exit code is the
        // whole verb (review of #928). It calls `ExitCode::combine`, which
        // returns `Violation` the moment `findings > 0`, and the CLI census
        // refuses any observed code the row does not declare. Measured on the
        // shipped binary: `--findings 1` exits 2 and `--unjudgeable 1` exits 3,
        // against a row declaring neither 2 nor a reason it could not.
        exits: EXITS_VERDICT,
        effect: Effect::Read,
        flags: &[VERDICT_FINDINGS, VERDICT_UNJUDGEABLE],
    },
    CommandDecl {
        path: "policy explain",
        id: "policy.explain",
        about: "Resolve a verdict token to its class definition and the routes out of it",
        data_channel: true,
        exits: EXITS_STANDARD,
        effect: Effect::Read,
        flags: &[VERDICT_TOKEN, JSON, EXPLAIN_HISTORY],
    },
    // The OTHER dereference, and the emitted line carries pointers to both
    // (CLOUD-1637). `explain` answers about the CLASS; this answers about the
    // ROW that raised it, and the two are different questions wherever a class
    // has more than one raiser — which is 66 of this config's 128 rows, since a
    // `shape` or `receipt` row declares no class and raises its kind's native
    // one.
    //
    // WHY IT HAD TO EXIST BEFORE THE LINE COULD POINT AT IT. CLOUD-1286 moved a
    // row's `reason` off the hot path on the stated ground that `batten policy
    // rule <id>` is where it went. It had not gone anywhere: the verb was never
    // built, so for every row whose class gloss is generic the specific remedy
    // was unreachable from the refusal. `call name refused`'s gloss says only
    // that the call matches a shape the config refuses; that a board row is read
    // through `batten mcp call Linear get_issue` is `no-raw-issue-read`'s own
    // `reason`. Non-negotiable rule 2 — a rule ships with its mechanism — is why
    // this lands in the same change as the line that names it.
    //
    // `read` structurally, and on the same terms as its sibling: the committed
    // authority is loaded and one field of a row it already holds is printed. No
    // spawn, no network, no tree walk.
    //
    // Its payload is the same DELIBERATE, STATED exception to pointer-only
    // output that `explain` records above, and for the same reason: the text is
    // the config author's own declaration, not content read out of a subject
    // file.
    CommandDecl {
        path: "policy rule",
        id: "policy.rule",
        about: "Resolve a rule id to the remedy its row declares",
        data_channel: true,
        effect: Effect::Read,
        // A LOOKUP, NOT A VERDICT. It resolves an id to the row's own remedy and
        // decides nothing about the tree, so it cannot mint a `2` — an id that
        // resolves to nothing is the caller's malformed invocation (`1`), and a
        // config it cannot read is could-not-look (`3`).
        exits: EXITS_STANDARD,
        flags: &[RULE_ID_ARG, JSON],
    },
    // CLOUD-2290. The `preset` noun dispatches, and its one verb WRITES: the
    // copies under `policy/<preset>/` and two edits to `batten.toml`. So the noun
    // states `write` rather than inheriting `read`, and neither row lands on the
    // derived read-only allowlist.
    CommandDecl {
        path: "preset",
        id: "preset",
        about: "Take a vendored preset's modules into this repository",
        data_channel: false,
        exits: EXITS_DISPATCHES,
        effect: Effect::Write,
        flags: &[],
    },
    // unreached: "preset eject" CLOUD-2290 a consumer runs it once, by hand, to take
    // a module out of the binary; no task, workflow or hook should ever eject on
    // its own, so nothing in this tree invokes it.
    CommandDecl {
        path: "preset eject",
        id: "preset.eject",
        about: "Copy a preset module and its call closure into policy/<preset>/ and load the copies instead",
        data_channel: false,
        exits: EXITS_STANDARD,
        effect: Effect::Write,
        flags: &[FlagDecl::positional(
            "target",
            "The module to eject, as <preset>/<module>, e.g. claude-code-cloud/plan-mode-refuses-writes",
        )],
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
        exits: EXITS_DISPATCHES,
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
        exits: EXITS_VERDICT,
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
        exits: EXITS_DISPATCHES,
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
    // The `landed` noun (CLOUD-186, CLOUD-1127), ported off
    // `mise-tasks/landed-check.sh` when `shell-retirement` made editing a shell
    // rule refusable.
    CommandDecl {
        path: "landed",
        id: "landed",
        about: "Whether a board column is honest about what git and the forge already did",
        data_channel: false,
        exits: EXITS_DISPATCHES,
        effect: Effect::Unclassified,
        flags: &[],
    },
    // The adopted gate runner's surface contract (CLOUD-947). Two verbs and two
    // effects, because the row specifies them separately: "the generator is a
    // `write` … the gate is `read`. Both are declared on the command surface —
    // the generator is not a read verb that happens to write."
    //
    // That is the one place this pair departs from the `generate` family above,
    // which emits on stdout and leaves the redirect to the caller. Here the
    // artifact is not the output: the generator runs a program three times and
    // replaces one committed file, and a caller redirecting a stream could not
    // tell a partial acquisition from a complete one.
    CommandDecl {
        path: "hk",
        id: "hk",
        about: "The adopted gate runner's surface contract",
        data_channel: false,
        exits: EXITS_DISPATCHES,
        // UNCLASSIFIED, for `claim`'s and `record`'s reason: the subtree carries
        // one `write` arm and one `read` arm, and a consumer treating an entry as
        // a prefix must not pick the generator up off the read-only allowlist
        // (CLOUD-90). The noun acts on nothing itself.
        effect: Effect::Unclassified,
        flags: &[],
    },
    CommandDecl {
        path: "hk contract",
        id: "hk.contract",
        about: "Regenerate the committed plan projection from the pinned runner",
        // The pointer it emits is one path; a JSON document of one field would
        // be a second shape for the same answer, and byte-stability is not a
        // claim a mutating verb can make about two consecutive runs.
        data_channel: false,
        exits: EXITS_VERDICT,
        effect: Effect::Write,
        flags: &[],
    },
    CommandDecl {
        path: "hk observe",
        id: "hk.observe",
        about: "Record what this session resolved of the runner, once per contract digest",
        // The pointer it emits is one state token; a JSON document of one field
        // would be a second shape for the same answer, and byte-stability is not
        // a claim a mutating verb can make about two consecutive runs.
        data_channel: false,
        exits: EXITS_STANDARD,
        // WRITE, declared rather than smuggled into a read verb: it records a
        // receipt. It is the only write — nothing about the tree, the contract or
        // the plan is modified.
        effect: Effect::Write,
        flags: &[SESSION],
    },
    CommandDecl {
        path: "hk drift",
        id: "hk.drift",
        about: "Whether the committed plan projection still matches the pinned runner",
        // NO DATA CHANNEL, for `landed`'s reason: a `-J` verb must emit its
        // document unconditionally, and this verb's could-not-look arms — an
        // absent runner, an empty plan, another pin — have no document to emit.
        // The answer is one pointer line per drifted step.
        data_channel: false,
        exits: EXITS_VERDICT,
        effect: Effect::Read,
        flags: &[],
    },
    // `read`, structurally: it reads a payload on stdin and three caller-supplied
    // files, and starts no program. The `claimed-keys` half its predecessor
    // spawned is supplied as `--merged-prs` evidence instead, which is what keeps
    // this on the read surface.
    //
    // POINTER-ONLY IS THE WHOLE OUTPUT (rule 4). A finding is an issue key, the
    // column it holds, the column it should hold, and a reason class — never a
    // line of any body. A PR body and an issue body both carry consumer detail,
    // and a sweep that echoed them would leak it through CI logs.
    // NO DATA CHANNEL, and that is a withdrawal rather than an omission. It was
    // declared `true` first, and `every_data_channel_verb_emits_one_pure_json_document`
    // refused it: the contract is that a data channel emits its document
    // UNCONDITIONALLY, "including when the answer is empty — JSON that is
    // sometimes absent is unparseable", and the census invokes each such verb
    // with its declared arguments and no stdin.
    //
    // This verb's payload IS stdin. The two honest ways to satisfy the contract
    // were to emit `{"findings": []}` on the could-not-look arm — which is the
    // false green this whole gate exists to refuse — or to grow a
    // `ready lint --issue` affordance resolving the board from the capture
    // store, which nothing has asked for. The program being retired emits no
    // JSON either, so the port is faithful without one.
    CommandDecl {
        path: "landed check",
        id: "landed.check",
        about: "Refuse a board column that contradicts main's history or a declined key",
        data_channel: false,
        exits: EXITS_VERDICT,
        effect: Effect::Read,
        flags: &[CLAIMED, MERGED_PRS, LANDED_BY, DECLINED],
    },
    // The other half of the same question, and it is a SEPARATE arm rather than
    // a flag on `check` because the two demand different keys of different
    // subsets: `check` needs `id` and `status` of every row, this needs three
    // more of a subset it has not identified until the narrowing has run.
    //
    // `kind:verb` without a new top-level noun. CLOUD-1182 measured 77 of 113
    // engine-source retirements landing a brand-new verb and named that the
    // scope creep; an arm under an existing noun costs the surface nothing.
    //
    // Read, and the `--refs` flag is what keeps it so — see that declaration.
    // No data channel, for the reason the sibling above states at length: the
    // payload IS stdin, so an unconditional document is unwritable.
    CommandDecl {
        path: "landed abandoned",
        id: "landed.abandoned",
        about: "Refuse an In Progress claim with no landing, no pull request, no branch and no recent touch",
        data_channel: false,
        exits: EXITS_VERDICT,
        effect: Effect::Read,
        flags: &[
            CLAIMED,
            MERGED_PRS,
            LANDED_BY,
            REFS,
            INSTANT,
            MAX_IDLE_DAYS,
            GATHER,
        ],
    },
    CommandDecl {
        path: "ready lint",
        id: "ready.lint",
        about: "Refuse an issue whose Ready block fails a checkable clause of the Definition of Ready",
        data_channel: true,
        exits: EXITS_VERDICT,
        effect: Effect::Read,
        flags: &[ISSUE, JSON],
    },
    // The `checks` noun (CLOUD-1143), ported off `mise-tasks/checks-green.sh`.
    CommandDecl {
        path: "checks",
        id: "checks",
        about: "Whether a commit's check runs answer the question a landing depends on",
        data_channel: false,
        exits: EXITS_DISPATCHES,
        effect: Effect::Unclassified,
        flags: &[],
    },
    // `read`, and structurally so: it decides over a reading and cannot start a
    // program. By default the reading is handed to it on stdin — the poller
    // already holds the body it got conditionally — which is the
    // agents-fetch-gates-decide split the board gates use, and what lets every
    // case run offline.
    //
    // `--sha` TAKES THE READING IN PROCESS (CLOUD-843), through the same
    // `pr_watch::read` `record forge --fetch` and `land` use: one GET, no
    // program started and nothing written, so the row stays `read`. It exists to
    // retire the `checks-green` task's `gh api` + `jq` acquisition, whose only
    // other job was re-deciding the engine's exit code off its stdout. Absent,
    // the verb is the stdin decider it always was.
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
        exits: EXITS_VERDICT,
        effect: Effect::Read,
        flags: &[
            REQUIRED_CHECKS,
            ABSENT_OK_CHECKS,
            ANSWERED_CONCLUSIONS,
            FANIN_CHECK,
            CHECKS_SHA,
            WAIT_REPO,
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
        exits: EXITS_DISPATCHES,
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
        exits: EXITS_STANDARD,
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
        exits: EXITS_STANDARD,
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
        exits: EXITS_STANDARD,
        effect: Effect::Write,
        flags: &[PR_NUMBER],
    },
    // `write`: it rewrites the pull request's body so the merge moves the row.
    CommandDecl {
        path: "pr link",
        id: "pr.link",
        about: "Write the closing key into a bot pull request's body, so its merge moves the row",
        data_channel: false,
        exits: EXITS_STANDARD,
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
        exits: EXITS_STANDARD,
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
        exits: EXITS_VERDICT,
        effect: Effect::Unclassified,
        flags: &[PR_NUMBER],
    },
    // CLOUD-518's gate and CLOUD-790's actor (CLOUD-843, retiring
    // `[tasks.pr-unsubscribed]`). ONE leaf with a verb positional rather than
    // three, because its callers name the three arms as one task with the arm
    // and the pull request appended. `write`: every arm writes — `drop` a
    // receipt after a network call, `record` a receipt, `check` a record — and
    // `EXITS_VERDICT` because `check` is the decision over what it recorded.
    CommandDecl {
        path: "pr unsubscribed",
        id: "pr.unsubscribed",
        about: "Drop this session's webhook subscription to a pull request, attest it, or record and decide the reading",
        data_channel: false,
        exits: EXITS_VERDICT,
        effect: Effect::Write,
        flags: &[
            UNSUBSCRIBED_VERB,
            PR_NUMBER,
            UNSUBSCRIBED_SESSION_ENV,
            UNSUBSCRIBED_TOKEN_ENV,
            UNSUBSCRIBED_ENDPOINT,
            UNSUBSCRIBED_TOOL,
            UNSUBSCRIBED_ARGUMENTS,
            UNSUBSCRIBED_FAMILY,
            UNSUBSCRIBED_RULE,
        ],
    },
    // The `task` noun (CLOUD-425), ported off `mise-tasks/task-registry.sh` and
    // `mise-tasks/alive.sh` under CLOUD-843. Both halves, because the registry is
    // one mechanism read from both ends.
    CommandDecl {
        path: "task",
        id: "task",
        about: "What long-running tasks are doing, recorded where it can be read without a log",
        data_channel: false,
        exits: EXITS_DISPATCHES,
        effect: Effect::Unclassified,
        flags: &[],
    },
    // `write`, all five of them, and declared rather than inferred: each edits a
    // record under the git dir. A row claiming `read` would put a writing verb on
    // the derived read-only allowlist.
    CommandDecl {
        path: "task register",
        id: "task.register",
        about: "Record that a task has started, under its pid",
        data_channel: false,
        exits: EXITS_VERDICT,
        effect: Effect::Write,
        flags: &[TASK_NAME, TASK_PID, TASK_PHASE],
    },
    CommandDecl {
        path: "task phase",
        id: "task.phase",
        about: "Record what a registered task is now doing",
        data_channel: false,
        exits: EXITS_VERDICT,
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
        id: "task.tick",
        about: "Record that a task's loop went round",
        data_channel: false,
        exits: EXITS_VERDICT,
        effect: Effect::Write,
        flags: &[TASK_PID, TASK_VALUE],
    },
    CommandDecl {
        path: "task sig",
        id: "task.sig",
        about: "Record that the world a task is watching moved",
        data_channel: false,
        exits: EXITS_VERDICT,
        effect: Effect::Write,
        flags: &[TASK_PID, TASK_VALUE],
    },
    CommandDecl {
        path: "task unregister",
        id: "task.unregister",
        about: "Drop a task's record, which its exit path does and a kill cannot",
        data_channel: false,
        exits: EXITS_VERDICT,
        effect: Effect::Write,
        flags: &[TASK_PID],
    },
    // `read`, structurally: one field out of one record, opening nothing else.
    CommandDecl {
        path: "task read",
        id: "task.read",
        about: "One field of one task's record, so a prober composes rather than parsing the layout",
        data_channel: false,
        exits: EXITS_STANDARD,
        effect: Effect::Read,
        flags: &[TASK_PID, TASK_FIELD],
    },
    // `read` since CLOUD-2372: `alive` reports a corpse and deletes nothing, so a
    // crash stays visible on every read until the next `land`'s reap forgets it.
    // It used to reap what it reported, which made it a write.
    CommandDecl {
        path: "task alive",
        id: "task.alive",
        about: "What tasks are running right now and what phase each is in — one call, no log reading",
        data_channel: false,
        exits: EXITS_VERDICT,
        effect: Effect::Read,
        flags: &[TASK_PROGRAM_ROOT, HOOK_INSTANT],
    },
    // The `singleton` noun (CLOUD-428), ported off `mise-tasks/singleton.sh`
    // under CLOUD-843. It lands BESIDE `task` rather than inside it because the
    // lock and the registry answer different questions — "may a second one of
    // these start" versus "what is running" — while sharing one owner in
    // `task.rs`, which is what removed the hand-rolled registry reader the shell
    // carried.
    CommandDecl {
        path: "singleton",
        id: "singleton",
        about: "Whether a second copy of a task may start in this clone",
        data_channel: false,
        exits: EXITS_DISPATCHES,
        effect: Effect::Unclassified,
        flags: &[],
    },
    // Both `write`, and `acquire`'s classification is the load-bearing one: it
    // READS to decide and WRITES the lock it hands out, so a row claiming `read`
    // would put a writing verb on the derived read-only allowlist.
    CommandDecl {
        path: "singleton acquire",
        id: "singleton.acquire",
        about: "Take a task's lock for a pid, or refuse naming the process that holds it",
        data_channel: false,
        exits: EXITS_VERDICT,
        effect: Effect::Write,
        flags: &[SINGLETON_TASK, TASK_PID, SINGLETON_RECHECK],
    },
    CommandDecl {
        path: "singleton release",
        id: "singleton.release",
        about: "Drop a task's lock, which its exit trap does and a kill cannot",
        data_channel: false,
        exits: EXITS_STANDARD,
        effect: Effect::Write,
        flags: &[SINGLETON_TASK],
    },
    // The `claim` noun (CLOUD-1121), ported off `mise-tasks/claim-check.sh` on the
    // same terms.
    CommandDecl {
        path: "claim",
        id: "claim",
        about: "Whether the issue you are about to pull is actually unclaimed",
        data_channel: false,
        exits: EXITS_DISPATCHES,
        effect: Effect::Unclassified,
        flags: &[],
    },
    // `write`, and declared rather than inferred: the pullable path MINTS a claim
    // receipt under the git dir, which is the whole reason this verb exists rather
    // than a pure read — the mediated claim gate needs a claimed branch to be
    // distinguishable from an unclaimed one. A row claiming `read` here would put
    // a writing verb on the derived read-only allowlist.
    // CLOUD-1711. `mise-tasks/claimed-keys.sh` retires onto this leaf, and
    // `merged-pr-keys.sh` with it — that program shells into this same answer once
    // per pull request body, so the two are a closed set.
    //
    // A LEAF under `claim` rather than a noun of its own (CLOUD-1546's 42
    // top-level rows). `read`, and honestly so: it mints nothing and writes
    // nothing — it derives which keys a branch claims and prints them.
    //
    // Pointer-only: the keys alone, uppercased and sorted, never the prose they
    // were extracted from (rule 4).
    // CLOUD-1752's forge-window group, and `merged-pr-keys.sh`'s successor. It
    // asked `claimed-keys` once per pull request body; this asks
    // `race::claimed_from(.., ClosingOnly)` the same way, so the two sides of
    // every landed-ness comparison still come out of one authority (CLOUD-338).
    //
    // AN EVIDENCE PRODUCER, not a gate: its stdout is DATA its caller consumes,
    // which is why a could-not-look here exits non-zero where `claim race` — which
    // answers a question — reports could-not-look on stdout at 0. A producer that
    // exits clean having produced nothing is indistinguishable from a repository
    // with no merged pull requests, and that is the exact state the program it
    // replaces refuses as impossible of a repository with a trunk.
    CommandDecl {
        path: "claim merged",
        id: "claim.merged",
        about: "The keys merged pull request bodies close, as `<key>\\t<number>` rows",
        // `data_channel` is exactly "declares `-J`", which
        // `every_data_emitting_verb_declares_the_json_flag` pins in both
        // directions — it is not the wider claim the header paragraph makes
        // about stdout being data rather than a verdict. Two-column rows are
        // this family's shape and `claim keys` beside it says the same, so the
        // answer is the line shape, not a second encoding of it.
        data_channel: false,
        exits: EXITS_STANDARD,
        effect: Effect::Read,
        flags: &[MERGED_LIMIT],
    },
    CommandDecl {
        path: "claim keys",
        id: "claim.keys",
        about: "The issue keys this branch CLAIMS, as distinct from the ones it merely mentions",
        data_channel: false,
        exits: EXITS_STANDARD,
        effect: Effect::Read,
        flags: &[
            CLAIM_BRANCH,
            CLAIM_TITLE,
            CLAIM_LOG,
            CLOSING_ONLY,
            REFS_FIRST_ONLY,
        ],
    },
    CommandDecl {
        path: "claim check",
        id: "claim.check",
        about: "Refuse a pull of an issue somebody is already on, and mint the receipt when it is free",
        data_channel: true,
        exits: EXITS_VERDICT,
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
        exits: EXITS_VERDICT,
        effect: Effect::Write,
        flags: &[],
    },
    // `read`, and it is the honest column rather than a convenience: this verb
    // mints nothing and writes nothing. It asks the forge which OTHER open pull
    // request already claims a key this branch claims, and prints the answer.
    // Its two siblings above are `write` because they mint a receipt; there is
    // no receipt here, so a row claiming `write` would put a pure read on the
    // wrong side of the derived allowlist.
    //
    // NO `-J`, for `claim bot`'s reason one row up: what this verb can say
    // depends on what the forge answers about the open pull requests, so the
    // `-J` census's byte-stability term would be a claim about the forge rather
    // than about this binary.
    CommandDecl {
        path: "claim race",
        id: "claim.race",
        about: "Refuse a claim a different open pull request already carries, judged by head SHA",
        data_channel: false,
        exits: EXITS_VERDICT,
        effect: Effect::Read,
        flags: &[],
    },
    CommandDecl {
        path: "claim carry",
        id: "claim.carry",
        about: "Attest that this branch only carries licence rows forward, and mint the receipt when it does",
        data_channel: true,
        exits: EXITS_VERDICT,
        effect: Effect::Write,
        flags: &[JSON],
    },
    CommandDecl {
        path: "semver",
        id: "semver",
        about: "Whether this branch's API delta is compatible with the bump it claims",
        data_channel: false,
        exits: EXITS_DISPATCHES,
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
        exits: EXITS_VERDICT,
        effect: Effect::Write,
        flags: &[SEMVER_BASELINE, SEMVER_RELEASE_TYPE, SEMVER_PACKAGE],
    },
    CommandDecl {
        path: "attribution",
        id: "attribution",
        about: "What produced commits may carry about the tooling that made them",
        data_channel: false,
        exits: EXITS_DISPATCHES,
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
        exits: EXITS_VERDICT,
        effect: Effect::Read,
        flags: &[JSON, RANGE, MESSAGE, ATTRIBUTION_HARNESS],
    },
    // Reads one tag object through git and compares its tagger against the
    // declared identity. Same `read` promise as `attribution check`: git's own
    // plumbing and nothing user-supplied.
    CommandDecl {
        path: "attribution tagger",
        id: "attribution.tagger",
        about: "Refuse a tag cut by an identity this repository is not accountable to",
        data_channel: true,
        exits: EXITS_VERDICT,
        effect: Effect::Read,
        flags: &[TAG, JSON],
    },
    // The one write this subject introduces, self-declared (§5). Repo-local only:
    // it writes `.git/config` in this checkout and never `--global`, which covers
    // a developer's own unrelated repositories.
    CommandDecl {
        path: "attribution identity",
        id: "attribution.identity",
        about: "Set this clone's repo-local git identity when it is unset or denied",
        data_channel: false,
        exits: EXITS_STANDARD,
        effect: Effect::Write,
        flags: &[],
    },
    // The SIGNATURE surface's write, `attribution identity`'s twin (CLOUD-669,
    // retiring `[tasks.signing-posture-repair]` under CLOUD-843). Repo-local
    // only, and only against a signer whose key cannot be verified or
    // reproduced: a verifiable signer is left signing, which is the end state
    // CLOUD-591 works toward. `write`, self-declared (§5) — it may write
    // `.git/config` in this checkout.
    CommandDecl {
        path: "attribution signing",
        id: "attribution.signing",
        about: "Switch signing off in this clone when its signer cannot be verified or reproduced",
        data_channel: false,
        exits: EXITS_STANDARD,
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
        exits: EXITS_DISPATCHES,
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
        exits: EXITS_VERDICT,
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
        exits: EXITS_DISPATCHES,
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
        exits: EXITS_STANDARD,
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
        exits: EXITS_VERDICT,
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
        exits: EXITS_DISPATCHES,
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
        exits: EXITS_VERDICT,
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
        exits: EXITS_STANDARD,
        effect: Effect::Write,
        flags: &[DRY_RUN],
    },
    // NOTE: `provision-exec` — the launcher entry point CLOUD-1455 added — is
    // DELIBERATELY ABSENT from this table, and the absence is the design rather
    // than an omission.
    //
    // It is not a verb a person or a config invokes; it is what the kernel
    // re-enters this binary as when it reads a provisioned tool's `#!` line, and
    // everything after it belongs to somebody else's program. So it is
    // intercepted in `main` BEFORE any parsing, and clap never sees it. A row
    // here would be a promise this table cannot keep: `every_leaf_verb_dispatches`
    // asks that a declared leaf reach a typed arm, and this one must not — a
    // clap-parsed launcher would claim the tool's own `--help`, `-v` and `--`.
    //
    // Its effect is unclassified in the only sense that matters: absent from this
    // table it can never reach §5's agent read-only allowlist, which is derived
    // from `effect == read`. `crate::provision::launched` is the authority, and
    // `tests/it/provision.rs` pins that the interception happens rather than
    // clap answering.
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
        exits: EXITS_STANDARD,
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
        path: "adjudicate",
        id: "hook",
        about: "Adjudicate a mediated tool call read from stdin (a deny is exit 2, the one contract)",
        // Excluded deliberately: `hook`'s stdout is already a harness-shaped
        // decision document that the host parses. A second JSON shape on the
        // same stream, selected by a flag the host does not pass, could only
        // ever be an ambiguity — and it would break the per-harness decision
        // channel CLOUD-40 pinned.
        data_channel: false,
        exits: EXITS_VERDICT,
        effect: Effect::Unclassified,
        flags: &[
            HOOK_INSTANT,
            HOOK_EVENT,
            FlagDecl::required_enum(
                "harness",
                "harness",
                "The harness whose payload to decode and whose decision channel to answer in",
                harness_parser,
            ),
            // CLOUD-2696: the policy input is otherwise invisible, so a module
            // that passes its own cases and decides differently live leaves its
            // author nothing to compare.
            FlagDecl::switch(
                "show_input",
                "show-input",
                "Store the exact policy input this call produced and print its pointer on stderr",
            ),
        ],
    },
    // The payload noun exists so the extractor is NOT `hook field` (CLOUD-479).
    // `attach` marks any path with children `subcommand_required`, because §2
    // says a noun performs no default action — so nesting under `hook` would
    // have turned the PreToolUse mediator itself into a noun that refuses to
    // adjudicate. Measured while writing this: `batten adjudicate --harness
    // claude-code` began answering `requires a subcommand`, which is policy
    // unenforced for every mediated call.
    CommandDecl {
        path: "payload",
        id: "payload",
        about: "Read a hook payload from stdin",
        data_channel: false,
        exits: EXITS_DISPATCHES,
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
        exits: EXITS_STANDARD,
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
        exits: EXITS_DISPATCHES,
        effect: Effect::Unclassified,
        flags: &[],
    },
    // The precondition, asked on its own — ported off `mise-tasks/tree-clean.sh`
    // under CLOUD-1753.
    //
    // ONE PREDICATE, TWO CALLERS, AND THAT IS NOT A SECOND AUTHORITY. `receipt
    // record` refuses a dirty tree itself, which is the load-bearing end: it is
    // the verb that writes the receipt, so it is the only place the question is
    // both askable and answerable at the moment it matters. This row is the CHEAP
    // end, and the retiring program's own caller shows why both are needed —
    // `verify:gated` asks it in `depends` so a dirty tree fails in seconds rather
    // than after the ~170s the gate set costs, and `depends` completes before the
    // body starts, so a tree dirtied MID-RUN is invisible to it. Both call
    // `receipt::tree_state`; neither re-derives it.
    //
    // `read` in §5's strong sense: it counts what `git status` reports and writes
    // nothing, which is what lets `verify` ask it without the ask itself becoming
    // a reason the answer changes.
    CommandDecl {
        path: "receipt clean",
        id: "receipt.clean",
        about: "Refuse when the working tree differs from HEAD, so a receipt keyed to HEAD would attest bytes no commit contains",
        data_channel: false,
        exits: EXITS_VERDICT,
        effect: Effect::Read,
        flags: &[],
    },
    // Creates state the caller can recreate by re-running the check.
    CommandDecl {
        path: "receipt record",
        id: "receipt.record",
        about: "Record that the named check concluded pass against the current HEAD",
        // Records state and reports nothing; there is no document to emit.
        data_channel: false,
        exits: EXITS_STANDARD,
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
        about: "Judge the named check's recorded receipt against HEAD and the trunk (`must_land_on`, else the remote's default branch)",
        data_channel: true,
        exits: EXITS_VERDICT,
        effect: Effect::Read,
        flags: &[
            FlagDecl::positional("check", "The check whose receipt is judged"),
            RECEIPT_OR,
            FlagDecl::defaulted_enum(
                "key",
                "key",
                "Which git fact the receipt is judged against: the exact commit, or the branch",
                receipt_key_parser,
                "head",
            ),
            // `--base` (CLOUD-2260): the ref a `delta` receipt's identity is
            // taken against, which the verb otherwise has no row to read. Named
            // by the caller rather than defaulted, and a base that disagrees with
            // the declaring row resolves another identity, which reads `missing`
            // — so a drift between the two refuses rather than passes.
            FlagDecl::valued(
                "base",
                "base",
                "The ref a `--key delta` receipt's change identity is taken against",
            ),
            JSON,
        ],
    },
    // NO POSITIONAL, and the absence is the verb's whole content: it asks about
    // the DECLARED SET rather than about a check the caller names. A `--check`
    // here would make it `status` with extra steps, and would restore exactly the
    // half-asked shape the predecessor existed to remove — one call, one green,
    // and a head reported verified on half its evidence.
    //
    // `read`, and it joins the derived read-only allowlist: it opens receipts and
    // resolves two refs, and writes nothing.
    CommandDecl {
        path: "receipt verified",
        id: "receipt.verified",
        about: "Is HEAD verified — every declared check's receipt valid against this commit?",
        data_channel: false,
        effect: Effect::Read,
        exits: EXITS_VERDICT,
        flags: &[],
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
        exits: EXITS_DISPATCHES,
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
        exits: EXITS_STANDARD,
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
        exits: EXITS_STANDARD,
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
        exits: EXITS_DISPATCHES,
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
        exits: EXITS_VERDICT,
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
        exits: EXITS_DISPATCHES,
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
        exits: EXITS_STANDARD,
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
        exits: EXITS_STANDARD,
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
        exits: EXITS_STANDARD,
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
        exits: EXITS_STANDARD,
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
        exits: EXITS_STANDARD,
        effect: Effect::Read,
        flags: &[STATE_RULE, STATE_PATH, JSON],
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
        exits: EXITS_DISPATCHES,
        effect: Effect::Unclassified,
        flags: &[],
    },
    // CLOUD-1180's first landable slice, and `record <object>`'s spelling for
    // `record <object>`'s reason. CLOUD-1180's original table said `agent
    // instructions`; its own 2026-08-30 amendment respells that to `show agent`
    // under CLOUD-1184's imperative `VERB OBJECT` grammar, and both CLOUD-1184
    // and CLOUD-1179 have landed. Adding the noun-first spelling today would be
    // one more row for CLOUD-1190 to invert.
    //
    // `read`, AND THE WHOLE POINT IS THAT THE VERB CARRIES THE BAND. CLOUD-1184's
    // grammar puts the effect on the verb, so `show` is the read band by
    // construction — which is what makes a `read` noun here safe where `record`,
    // `capture` and `receipt` all had to be `unclassified` over write-bearing
    // subtrees. `tests::every_leaf_under_show_is_read` is what keeps that true
    // rather than merely intended: without it, one write leaf added under `show`
    // would silently put a writer on the derived agent allowlist for any consumer
    // treating an entry as a prefix (CLOUD-170).
    //
    // The write half of CLOUD-1180 — `migrate agent`, from the recovered-exact
    // `agent migrate apply` — is deliberately NOT here. It belongs to a `migrate`
    // verb in the write band, and the row records that respelling as a DEPARTURE
    // from a recovered spelling rather than applying it quietly.
    CommandDecl {
        path: "show",
        id: "show",
        about: "Report what something is, without changing it",
        data_channel: false,
        exits: EXITS_DISPATCHES,
        effect: Effect::Read,
        flags: &[],
    },
    // CLOUD-19's directive, landed at last: an agent asks the engine what it may
    // do here instead of being told in prose that goes stale.
    //
    // NOT A SECOND COMMAND AUTHORITY, which is the directive's actual constraint.
    // Every field is derived from a model that already exists — the read-only
    // allowlist from `spec::read_only_allowlist`, the exit table from
    // `ExitCode::ALL`, the gates from the resolved config — so this row adds a
    // VIEW and no new source of truth. See `agent.rs`'s module doc.
    CommandDecl {
        path: "show agent",
        id: "show.agent",
        about: "What an agent may do in this repository: the read-only verbs, the exit contract, and the declared gates",
        data_channel: true,
        exits: EXITS_STANDARD,
        effect: Effect::Read,
        flags: &[JSON],
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
    // The per-suite cost corpus (CLOUD-352), ported off `mise-tasks/suite-bench.sh`
    // under CLOUD-1753.
    //
    // A LEAF UNDER `record` RATHER THAN A NOUN OF ITS OWN, and the noun already
    // means what this does: write down what happened. The two neighbours key
    // their records by tool and by forge; this one keys by suite, and the store
    // is a committed file because the READER is a person deciding whether the
    // file they are about to edit is expensive.
    //
    // IT RUNS NOTHING. The corpus is derived from the report `test:bats` leaves
    // behind — re-executing the suite to measure it would cost more than the
    // waste it reports and would be a second authority over a run that already
    // happened. So this reads one file and writes one file, and reaches
    // `policy/spawn-adapters.rego` not at all.
    //
    // `--write` rather than always writing: without it the corpus goes to stdout,
    // which is what lets a caller diff a proposed corpus against the committed
    // one without touching the tree.
    CommandDecl {
        path: "record suites",
        id: "record.suites",
        about: "Derive what each bats suite costs from the report the runner wrote, and record it where an author reads it",
        data_channel: false,
        exits: EXITS_STANDARD,
        effect: Effect::Write,
        flags: &[SUITES_WRITE],
    },
    CommandDecl {
        path: "record tool",
        id: "record.tool",
        about: "Record a declared tool row's verdict, read as `<name> <token>` lines on stdin",
        // Records state and reports nothing; there is no document to emit.
        data_channel: false,
        exits: EXITS_STANDARD,
        effect: Effect::Write,
        flags: &[
            FlagDecl::positional(
                "id",
                "The `[[rule.tools]]` id whose verdict is being recorded",
            ),
            TOOL_PICK,
        ],
    },
    // The sibling half, and what keeps this noun from being the thirteenth singleton
    // CLOUD-1184 counts. The two stores differ in their KEY and in nothing else
    // (CLOUD-1171), so they are two leaves over one concept rather than two nouns —
    // and building both is what wakes `forge-verdict-required` up.
    CommandDecl {
        path: "record forge",
        id: "record.forge",
        about: "Record the forge's check verdicts for one commit, read as `<check> <conclusion>` lines on stdin or with --fetch from the forge",
        data_channel: false,
        exits: EXITS_STANDARD,
        effect: Effect::Write,
        flags: &[
            FlagDecl::positional("ref", "The ref or sha the verdict was taken against"),
            FORGE_FETCH,
            FORGE_FANIN,
            FORGE_ANSWERED,
        ],
    },
    // CLOUD-843's validator door, retiring `[tasks.record-verdicts]`' two
    // validator arms. `record tool` records a verdict some OTHER program reduced;
    // this runs the row's own declared argv and records the exit code, so the
    // reduction is one integer and the reading of it is the consumer's module.
    //
    // `Effect::Unclassified`, stated rather than guessed (see `effect.rs`): it
    // runs a program the CONSUMER names, so what it does cannot be known from
    // this row — `exec`'s disposition, one leaf over. The spawn is `exec`'s own,
    // so this adds no site to the inventory.
    CommandDecl {
        path: "record validate",
        id: "record.validate",
        about: "Run a declared tool row's `run` argv and record its exit code under the row's key",
        data_channel: false,
        exits: EXITS_STANDARD,
        effect: Effect::Unclassified,
        flags: &[FlagDecl::positional(
            "id",
            "The `[[rule.tools]]` id whose argv runs and whose verdict is recorded",
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
    // CLOUD-1713's two doors. Three programs (841 lines) hand-rolled a durable
    // store under `.git/` because the engine's own two shapes — keyed put/hit and
    // append-and-fold — had no leaf. LEAVES UNDER `record` rather than new nouns:
    // CLOUD-1546 counts 42 top-level rows and CLOUD-1182 records nine ports
    // becoming nine nouns, and a store family is an object this verb records, not
    // a verb of its own.
    // CLOUD-1717's producer door. Nine programs in that wave are MEASUREMENTS
    // rather than gates: house-style §5 keeps the `gh` spawn outside the engine
    // and moves only the adjudication in, so each needs a producer writing a
    // record a module can read.
    //
    // THE POLICY STORE, WHICH IS NOT THE TWO BELOW. This writes through
    // `recorder::record_path`, the store `Fact::Records` projects onto
    // `input.tree.records.<family>`; `record keyed`/`record journal` write task
    // stores that only `record show`/`record fold` read back. Same noun, two
    // different readers, so they are different leaves rather than one leaf with
    // a mode flag.
    //
    // ONE LEAF FOR NINE PRODUCERS. Nine bespoke verbs would each be `record
    // plan` with its validation removed — the duplication this campaign deletes
    // rather than relocates.
    CommandDecl {
        path: "record named",
        id: "record.named",
        about: "Record one named family under this branch, read from stdin",
        data_channel: false,
        exits: EXITS_STANDARD,
        effect: Effect::Write,
        flags: &[FlagDecl::positional(
            "family",
            "The record family, which is the key a module reads it under",
        )],
    },
    // CLOUD-1717's READING door, and it is the other half of `record named`
    // rather than a second spelling of it. `record named` takes a verdict a
    // producer already computed; this takes the producer's RAW INPUT and applies
    // the reading itself, so the reading is Rust the engine tests rather than a
    // script beside the task.
    //
    // THE SPAWN STAYS OUTSIDE, which is what makes this admissible at all.
    // House-style §5 puts a producer's `cargo metadata` or `cargo test` in the
    // task; the document arrives on stdin and the engine never executes
    // anything. `spawn-adapters` and `spawn-widening` both refuse a new
    // `Command` site under `crates/batten/src/**` with no override route, and
    // they are right to: a reading that needed one would have the wrong shape.
    //
    // `Effect::Write`, never `Read`: the agent read-only allowlist is DERIVED
    // from `effect == read` (`spec.rs`), and this writes a record.
    CommandDecl {
        path: "record derive",
        id: "record.derive",
        about: "Derive one named family's record from its input and write it",
        data_channel: false,
        exits: EXITS_STANDARD,
        effect: Effect::Write,
        flags: &[
            FlagDecl::positional(
                "family",
                "The record family, which selects the reading and is the key a module reads it under",
            ),
            DERIVE_INPUT,
        ],
    },
    CommandDecl {
        path: "record keyed",
        id: "record.keyed",
        about: "Put one value into a keyed store family, read from stdin",
        data_channel: false,
        exits: EXITS_STANDARD,
        effect: Effect::Write,
        flags: &[
            FlagDecl::positional("family", "The store family the record belongs to"),
            FlagDecl::positional("key", "The key the record is filed under"),
        ],
    },
    CommandDecl {
        path: "record journal",
        id: "record.journal",
        about: "Append one record to an append-and-fold store family, read from stdin",
        data_channel: false,
        exits: EXITS_STANDARD,
        effect: Effect::Write,
        flags: &[FlagDecl::positional(
            "family",
            "The store family the record belongs to",
        )],
    },
    // The READ half of CLOUD-1713's two families, and they stay under `record`
    // on `capture show`'s precedent: `record` is a store NOUN and is already
    // `unclassified` because the subtree writes, so a read leaf under it neither
    // leaks onto the derived agent allowlist nor needs a noun of its own. The
    // producer/consumer split is still §2's answer to "how does a
    // read-classed surface obtain a record without gaining a write" — the producer
    // is a separate verb, exactly as `record tool` already is for
    // `validator-verdict-clean`.
    CommandDecl {
        path: "record show",
        id: "record.show",
        about: "Read one keyed record back: `hit` and the value, or `miss`",
        data_channel: false,
        exits: EXITS_STANDARD,
        effect: Effect::Read,
        flags: &[
            FlagDecl::positional("family", "The store family to read"),
            FlagDecl::positional("key", "The key to look under"),
        ],
    },
    CommandDecl {
        path: "record fold",
        id: "record.fold",
        about: "Fold a journal family: `nothing`, its records, or `unreadable <path>`",
        data_channel: false,
        exits: EXITS_STANDARD,
        effect: Effect::Read,
        flags: &[FlagDecl::positional("family", "The store family to fold")],
    },
    CommandDecl {
        path: "record plan",
        id: "record.plan",
        about: "Record this branch's plan, read as `<id> <status>` lines on stdin",
        data_channel: false,
        exits: EXITS_STANDARD,
        effect: Effect::Write,
        // CLOUD-2807: the lines merge into the store by id; replacing the
        // whole store is the explicit, named exception.
        flags: &[FlagDecl::switch(
            "replace",
            "replace",
            "Replace the whole plan instead of merging these entries into it by id",
        )],
    },
    // The same argument one layer over, and here the envelope route is not merely
    // per-harness — it is unreliable in the ordinary case. `issue file same`
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
        exits: EXITS_STANDARD,
        effect: Effect::Write,
        flags: &[],
    },
    // CLOUD-843's forge-read door: `record named` with the producer moved IN.
    // Eleven shell bodies each spelled a paginated `gh api`, a `jq` projection
    // and a date cut-off; the row declares all three and this walks, reduces and
    // writes the family the row names.
    //
    // `record query`, NOT `record forge`, and the collision is why: `record
    // forge <ref>` already records a commit's check verdicts from stdin, and a
    // leaf that took either a ref or a query id in one positional would decide
    // which store it writes by guessing what the argument names.
    //
    // `Effect::Write`, never `Read`: it writes a record, and it reaches the
    // network, which the derived read-only allowlist must never advertise.
    CommandDecl {
        path: "record query",
        id: "record.query",
        about: "Run a declared `[[forge.query]]` read and record its reduction as the family it names",
        data_channel: false,
        exits: EXITS_STANDARD,
        effect: Effect::Write,
        flags: &[
            FlagDecl::positional(
                "id",
                "The `[[forge.query]]` id, which is also the record family written",
            ),
            QUERY_INPUT,
        ],
    },
    // `record derive` with the producer moved IN (CLOUD-843, retiring
    // `[tasks.evaluator-io-record]`): it runs the command after `--` and derives
    // the family's reading from its exit status and output. `unclassified`, and
    // stated: it runs a program the caller chose, which is `exec`'s reading.
    CommandDecl {
        path: "record probe",
        id: "record.probe",
        about: "Run a probe command and record the family's reading of its exit status and output",
        data_channel: false,
        exits: EXITS_STANDARD,
        effect: Effect::Unclassified,
        flags: &[
            FlagDecl::positional(
                "family",
                "The record family, which selects the reading and is the key a module reads it under",
            ),
            DERIVE_INPUT,
            PROBE_COMMAND,
        ],
    },
    // Derive, write SILENTLY, then decide with the named rules (CLOUD-843,
    // retiring `[tasks.finding-sink-check]`). Silent because its caller is a
    // `stop` handler, whose stdout on a pass the host shows; `write` for the
    // record, `EXITS_VERDICT` for the decision.
    CommandDecl {
        path: "record decide",
        id: "record.decide",
        about: "Derive a family's reading, record it without echoing it, and decide over it with the named rules",
        data_channel: false,
        exits: EXITS_VERDICT,
        effect: Effect::Write,
        flags: &[
            FlagDecl::positional(
                "family",
                "The record family, which selects the reading and is the key a module reads it under",
            ),
            DERIVE_INPUT,
            DECIDE_RULE,
        ],
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
        exits: EXITS_DISPATCHES,
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
        exits: EXITS_STANDARD,
        // `Destructive` is the VERB's classification and stays so, even though
        // `--check` and `--dry-run` write nothing: §5 classifies a command by
        // what it may do, not by what a particular invocation chose. A reader
        // must not learn that a destructive verb is sometimes safe.
        effect: Effect::Destructive,
        flags: &[DRY_RUN, CHECK],
    },
    // BATTEN'S OWN REGISTRATION WHERE A SESSION ROOT LOADS IT (CLOUD-2111). A
    // host loads project wiring only from the directory a session is rooted at,
    // so a session over a parent of the repository loads none of it. This
    // writes the ROOT's project surface, never the user-level one, which would
    // double-fire in a session rooted at the repository (CLOUD-525).
    //
    // `write`, not `destructive`: it only ADDS batten's own registration, never
    // removes or rewrites anybody's, and writes only where the environment is
    // declared disposable — `reclaim`'s posture without `reclaim`'s subject.
    CommandDecl {
        path: "wiring register",
        id: "wiring.register",
        about: "Register batten on the session root when a session is rooted above this repository",
        data_channel: false,
        exits: EXITS_STANDARD,
        effect: Effect::Write,
        flags: &[REGISTER_CHECK, REGISTER_ALL],
    },
    // THE CLONE'S OWN COMMIT HOOKS (CLOUD-476), retiring the `mkdir -p` and two
    // `ln -sfn` that were `[tasks."session:git-hooks"]` (CLOUD-1991). Under
    // `wiring` because it is the same act one surface over — pointing a runner's
    // hook registration at what should run — and `doctor gate` is its diagnosis,
    // as `doctor hooks` is `reclaim`'s.
    //
    // `write`, not `destructive`: the subject is this clone's hooks directory,
    // not a file shared by every checkout on the box, and what it replaces is
    // the link it would write — a committed `[[startup]]` row names it as that
    // directory's repair, which is the authorisation `reclaim` has to ask `-y`
    // for. CLOUD-2339: with no operand every git hook links to the batten binary
    // itself, which dispatches on argv[0] through `[hook.git]`; a body operand
    // keeps CLOUD-1991's two-hook link until a consumer's pin reads that table.
    CommandDecl {
        path: "wiring gate",
        id: "wiring.gate",
        about: "Link every git hook in this clone to the running batten binary, or both commit hooks to a checked-in body",
        data_channel: false,
        exits: EXITS_STANDARD,
        effect: Effect::Write,
        flags: &[
            FlagDecl::positional_optional(
                "body",
                "A hook body to link both commit hooks to, relative to the repository root",
            ),
            GATE_CHECK,
        ],
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
        exits: EXITS_DISPATCHES,
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
    // unreached: "lease authorises" CLOUD-1338 `land lap` asks the lease in process; this arm is the hand-stepping surface;
    // nothing in the tree invokes it yet.
    CommandDecl {
        path: "lease authorises",
        id: "lease.authorises",
        about: "May this branch spend a matrix right now?",
        data_channel: false,
        exits: EXITS_VERDICT,
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
    // `read`, and the staleness half of the CI-side precondition (CLOUD-1148 §2).
    //
    // A GATE rather than a report, like `check` below: `0` the head carries
    // trunk's landing mechanism, `2` it does not, `3` the reading could not be
    // taken. **The caller fails OPEN on `3`**, which is this gate's whole
    // posture and the opposite of every other refusal here — a reading nobody
    // could take would cancel every job in the fleet, where waving one matrix
    // through costs one matrix.
    //
    // The predecessor asked this by grepping the head's own `mise-tasks/land.sh`
    // for `land-lock acquire`. That predicate dies with the retirement and dies
    // QUIETLY: the read fails, the script takes its own fail-open path, and every
    // stale head passes. The path set it asks about is `[lease] landing_paths`,
    // which a retirement edits rather than invalidates.
    // unreached: "lease carries" CLOUD-1338 `land lap` reads the carried lease in process, not through the CLI;
    // nothing in the tree invokes it yet.
    CommandDecl {
        path: "lease carries",
        id: "lease.carries",
        about: "Gate: this head carries the landing mechanism trunk has, so it can be serialised",
        data_channel: false,
        effect: Effect::Read,
        exits: EXITS_VERDICT,
        flags: &[LEASE_HEAD],
    },
    // `write`, and it is the ONLY reason this is not a read: on a stop it cancels
    // the run it is standing in. A composite of `carries` and `authorises` (both
    // `read`), because the cancel-and-wait is the subtlest failure mode in the
    // whole loop — a non-zero exit makes the run's conclusion `failure`, `final`
    // then fails its `needs:` under `!cancelled()`, and the lander re-drafts
    // every PR in the fleet. One authority for that, never sixteen copies in
    // workflow YAML.
    //
    // **IT NEVER EXITS NON-ZERO**, so it carries no verdict a caller reads: the
    // stop IS the cancellation. That is why the exit table's `2` never appears
    // here and why the step needs no `|| exit 0` to be safe — though the
    // workflow keeps one anyway, because a binary that will not RUN is a
    // different failure from one that ran and decided.
    CommandDecl {
        path: "lease guard",
        id: "lease.guard",
        about: "The runner's step-0 guard: may this branch spend a matrix right now?",
        data_channel: false,
        effect: Effect::Write,
        exits: EXITS_VERDICT,
        flags: &[LEASE_HEAD, LEASE_BRANCH, LEASE_RUN],
    },
    CommandDecl {
        path: "lease check",
        id: "lease.check",
        about: "Gate: the lease is free or a live, well-formed hold — never a wedge and never garbage",
        data_channel: false,
        exits: EXITS_VERDICT,
        effect: Effect::Read,
        flags: &[],
    },
    // `read`. Prose for a human, and `-J` for everyone else — which is what stops
    // a caller parsing the sentence and turning a message into an interface, where
    // the next edit to the wording would be a silent breakage.
    // unreached: "lease status" CLOUD-1338 an operator read of the lease; nothing in the tree invokes it;
    // nothing in the tree invokes it yet.
    CommandDecl {
        path: "lease status",
        id: "lease.status",
        about: "Report who holds the lease, for how much longer, and who is admitted behind them",
        data_channel: true,
        exits: EXITS_STANDARD,
        effect: Effect::Read,
        flags: &[JSON],
    },
    // `read`. ONE ADVISORY FIELD, ON STDOUT, FOR A CALLER THAT MEANS TO ACT ON IT
    // — the machine-readable half of `status` for the fields a waiter reads.
    // Silent and `0` when the lease is absent, released or expired: "no lease
    // names a head" is a legitimate reading a waiter handles by staying on trunk,
    // not an error it should report.
    // unreached: "lease peek" CLOUD-1338 an operator read of the lease; nothing in the tree invokes it;
    // nothing in the tree invokes it yet.
    CommandDecl {
        path: "lease peek",
        id: "lease.peek",
        about: "Print one advisory field of the held lease, or nothing",
        data_channel: false,
        exits: EXITS_STANDARD,
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
    // unreached: "lease held" CLOUD-1338 an operator read of the lease; nothing in the tree invokes it;
    // nothing in the tree invokes it yet.
    CommandDecl {
        path: "lease held",
        id: "lease.held",
        about: "Is this clone's lease still held, with a beat of margin to act on?",
        data_channel: false,
        exits: EXITS_VERDICT,
        effect: Effect::Read,
        flags: &[],
    },
    // `write`: a compare-and-swap over a remote ref.
    // unreached: "lease acquire" CLOUD-1338 `land lap` acquires in process; this arm is the hand-stepping surface;
    // nothing in the tree invokes it yet.
    CommandDecl {
        path: "lease acquire",
        id: "lease.acquire",
        about: "Take the lease, waiting out a live holder and reaping a dead one",
        data_channel: false,
        exits: EXITS_VERDICT,
        effect: Effect::Write,
        flags: &[LEASE_BRANCH],
    },
    // `write`. One-shot, as against `hold`'s loop.
    // unreached: "lease renew" CLOUD-1338 `land lap` renews in process; this arm is the hand-stepping surface;
    // nothing in the tree invokes it yet.
    CommandDecl {
        path: "lease renew",
        id: "lease.renew",
        about: "Extend this clone's lease by one term",
        data_channel: false,
        exits: EXITS_VERDICT,
        effect: Effect::Write,
        flags: &[],
    },
    // `write`. The heartbeat, which a caller backgrounds for the length of a hold
    // and kills from the same trap that releases.
    // unreached: "lease hold" CLOUD-1338 `land lap` holds in process; this arm is the hand-stepping surface;
    // nothing in the tree invokes it yet.
    CommandDecl {
        path: "lease hold",
        id: "lease.hold",
        about: "Renew this clone's lease every beat until it is lost or the hold ends",
        data_channel: false,
        exits: EXITS_VERDICT,
        effect: Effect::Write,
        flags: &[],
    },
    // `write` rather than `destructive`, and the distinction is the tombstone's:
    // a release CASes the expiry to a sentinel and deletes nothing, so there is no
    // ref to recover and nothing a `-y` would be protecting. Releasing a lease
    // this clone does not hold is not an error either — the trap that calls it
    // fires on every exit path, including ones that never acquired.
    // unreached: "lease release" CLOUD-1338 `land lap` releases in process; this arm is the hand-stepping surface;
    // nothing in the tree invokes it yet.
    CommandDecl {
        path: "lease release",
        id: "lease.release",
        about: "Hand the lease back, leaving a tombstone rather than deleting the ref",
        data_channel: false,
        exits: EXITS_STANDARD,
        effect: Effect::Write,
        flags: &[],
    },
    // `write`. The second matrix, and the only one: admitting one successor while
    // the holder is still merging is what overlaps the window in which the queue
    // would otherwise be cold.
    // unreached: "lease reserve" CLOUD-1338 `land lap`'s speculation reserves in process, not through the CLI;
    // nothing in the tree invokes it yet.
    CommandDecl {
        path: "lease reserve",
        id: "lease.reserve",
        about: "Take the one slot behind the current holder",
        data_channel: false,
        exits: EXITS_VERDICT,
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
        exits: EXITS_DISPATCHES,
        effect: Effect::Unclassified,
        flags: &[],
    },
    // `write`, and it is the widest write in the tree: the odb, a remote-tracking
    // ref, the WORKTREE, and the lap record. It is not `destructive` — a replay
    // that cannot complete refuses and moves nothing, so there is no half-applied
    // state for a `--dry-run` to protect against, and declaring one would offer a
    // rehearsal this verb cannot perform.
    // unreached: "land replay" CLOUD-1338 `land lap` drives replay in process; this
    // arm is the hand-stepping surface and nothing in the tree invokes it yet.
    CommandDecl {
        path: "land replay",
        id: "land.replay",
        about: "Advance the base and replay this branch onto it, recording the outcome",
        data_channel: false,
        exits: EXITS_VERDICT,
        effect: Effect::Write,
        flags: &[LAND_REFERENCE, LAND_RESOLVE, LAND_PROPOSE],
    },
    // `write`, and the write is the RECORD rather than the wait: asking two
    // questions is a read, and what this leaves behind is both arms' answers for
    // a module to decide over. It is `write` rather than `read` for that reason
    // alone, which is the effect model working — the allowlist is derived from
    // the declaration, so a verb that writes anywhere may not sit under `read`.
    // unreached: "land wait" CLOUD-1338 `land lap` drives the CI wait in process; this arm is the hand-stepping surface;
    // nothing in the tree invokes it yet.
    CommandDecl {
        path: "land wait",
        id: "land.wait",
        about: "Ask whether this head is green and whether its base still holds; the first answer decides",
        data_channel: false,
        exits: EXITS_VERDICT,
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
    // unreached: "land push" CLOUD-1338 `land lap` drives the push in process; this arm is the hand-stepping surface;
    // nothing in the tree invokes it yet.
    CommandDecl {
        path: "land push",
        id: "land.push",
        about: "Push this branch to its own ref, under receive-pack's compare-and-swap",
        data_channel: false,
        exits: EXITS_VERDICT,
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
    // unreached: "land verify" CLOUD-1338 `land lap` drives verify in process; this arm is the hand-stepping surface;
    // nothing in the tree invokes it yet.
    CommandDecl {
        path: "land verify",
        id: "land.verify",
        about: "Run the configured gate over this head and record what it answered",
        data_channel: false,
        exits: EXITS_VERDICT,
        effect: Effect::Write,
        flags: &[],
    },
    // `read`: it compares the working tree with HEAD and HEAD with the
    // remote-tracking refs, writes nothing, and always exits `0` — it is advice
    // on stderr, never a refusal, because verifying without landing is
    // legitimate (CLOUD-2707).
    CommandDecl {
        path: "land placed",
        id: "land.placed",
        about: "Advise a gate run on a committed, pushed head that land is next and reuses its receipt",
        data_channel: false,
        exits: EXITS_VERDICT,
        effect: Effect::Read,
        flags: &[],
    },
    // `write`, and the write is REMOTE — a comment on somebody else's pull
    // request — which puts it beside `land push` rather than beside the record
    // writers above. It is not `destructive`: a comment adds, and the merge it
    // asks for is the bot's act rather than this verb's.
    //
    // NO FLAGS, for `land verify`'s reason carried one step out. The pull request
    // is a fact about this branch the forge already holds, so it is RESOLVED; the
    // workflow whose runs carry the verdict is the consumer's, so it arrives from
    // the environment. A number on argv would let a lap ask one pull request to
    // land while every other step of the same lap is looking at another — which is
    // exactly the binding defect CLOUD-465 records for a reused branch.
    // unreached: "land fast-forward" CLOUD-1338 `land lap` asks for the fast-forward in process; this arm is the hand-stepping surface;
    // nothing in the tree invokes it yet.
    CommandDecl {
        path: "land fast-forward",
        id: "land.fast-forward",
        about: "Ask this head's pull request to fast-forward, and read the answer that request got",
        data_channel: false,
        effect: Effect::Write,
        exits: EXITS_VERDICT,
        flags: &[],
    },
    // THE UNION OF EVERY STEP'S EFFECT, which is `write` because the widest of
    // them is: the lap replays the working tree, pushes, and comments. It is not
    // `destructive` for the reason `land replay` is not — every write is one a
    // rebase or a re-push repeats, and nothing here removes history.
    //
    // IT TAKES THE REFERENCE AND NOTHING ELSE. Every other input the lap needs is
    // already resolved somewhere: the branch from HEAD, the remote from
    // `$LAND_LOCK_REMOTE`, the gate from `$LAND_VERIFY`, the workflow from
    // `$LAND_WORKFLOW`, the bound from `$LAND_MAX_LAPS`. Adding a flag for any of
    // them would put a second spelling on the surface beside the one the
    // individual sub-verbs already read, and the two would drift — which is
    // `land verify`'s argument, made once per input rather than once.
    CommandDecl {
        path: "land lap",
        id: "land.lap",
        about: "Drive the whole lap and lap again on any refusal a rebase would clear",
        data_channel: false,
        effect: Effect::Write,
        exits: EXITS_VERDICT,
        flags: &[LAND_REFERENCE, LAND_HOLD],
    },
    // `write`, for `land replay`'s first half: it fetches the reference into the
    // odb and moves its remote-tracking ref, which is the lap's own fetch reused
    // so the trunk has one reading. The ANSWER is a verdict — `2` for a head that
    // is not built on the current tip — and it leaves no record (CLOUD-1991).
    CommandDecl {
        path: "land linear",
        id: "land.linear",
        about: "Whether this head is built on the reference's current tip, so it can fast-forward",
        data_channel: false,
        effect: Effect::Write,
        exits: EXITS_VERDICT,
        flags: &[LAND_REFERENCE],
    },
    // --- CLOUD-843's foundation surface (the bash retirement) -----------------
    //
    // Every row below carries its FINAL arguments and its §5 effect. A row whose
    // package has not landed answers "unimplemented" at exit 3 — could-not-look,
    // never a pass — so a caller repointed early fails loudly rather than
    // succeeding at nothing. None declares a data channel except `census shell`:
    // a `-J` document must be emitted unconditionally, and a verb that cannot yet
    // answer has none to emit. The retiring programs these replace emit KEY=VALUE
    // lines or pointers, never JSON, so the surface loses nothing by it.
    //
    // The `step` noun (CLOUD-424's step cache, retiring `[tasks.step-receipt]`).
    // Unclassified for `capture`'s reason: no arm under it is `read`.
    CommandDecl {
        path: "step",
        id: "step",
        about: "Answer a step from its receipt when its exact inputs, arguments and tools already passed",
        data_channel: false,
        exits: EXITS_DISPATCHES,
        effect: Effect::Unclassified,
        flags: &[],
    },
    // `Unclassified`, not `read`: the key hashes each declared tool's own
    // `--version` answer, which means running a program the CONSUMER named, and
    // it writes the pending key a later `record` must match. `hit`/`miss` is an
    // answer in words at exit 0 (CLOUD-498) — a miss is not a failure.
    // unreached: "step check" CLOUD-843 a component `step run` composes; no caller checks without running yet.
    CommandDecl {
        path: "step check",
        id: "step.check",
        about: "Say hit or miss for a step's inputs, arguments and tools, and remember the key a record must match",
        data_channel: false,
        exits: EXITS_STANDARD,
        effect: Effect::Unclassified,
        flags: &[STEP_NAME, STEP_ARG],
    },
    // `EXITS_VERDICT`: refusing to record because the inputs moved while the step
    // ran is a statement about the tree — a receipt then would attest bytes the
    // run never judged — not about the invocation.
    // unreached: "step record" CLOUD-843 a component `step run` composes; no caller records apart from a run yet.
    CommandDecl {
        path: "step record",
        id: "step.record",
        about: "Record that a step passed, refusing when its inputs changed since the paired check",
        data_channel: false,
        exits: EXITS_VERDICT,
        effect: Effect::Unclassified,
        flags: &[STEP_NAME, STEP_ARG],
    },
    // The composition a caller otherwise writes in shell around the pair: check,
    // run on a miss, record on a zero. It runs the command the caller names, so it
    // is `exec`'s reading exactly, and the child's verdict is the verb's.
    CommandDecl {
        path: "step run",
        id: "step.run",
        about: "Run a step's command only when its receipt misses, and record the receipt when it passes",
        data_channel: false,
        exits: EXITS_VERDICT,
        effect: Effect::Unclassified,
        flags: &[STEP_NAME, STEP_ARG, STEP_COMMAND],
    },
    // The step graph (CLOUD-2785): the order and fan width a lap used to spell
    // as positions in a mise array, read from the step table's `group`,
    // `depends_on` and `run`. Unclassified for `step run`'s reason: every node
    // runs a command the consumer declared.
    CommandDecl {
        path: "step graph",
        id: "step.graph",
        about: "Schedule the step table's rows as a graph",
        data_channel: false,
        exits: EXITS_DISPATCHES,
        effect: Effect::Unclassified,
        flags: &[],
    },
    // `EXITS_VERDICT`: the worst node's code is the verb's, so a refusing step
    // is a violation and a node that could not run is internal.
    CommandDecl {
        path: "step graph run",
        id: "step.graph.run",
        about: "Run a group's rows, dependencies first and at most --jobs at once, and exit with the worst row's code",
        data_channel: false,
        exits: EXITS_VERDICT,
        effect: Effect::Unclassified,
        flags: &[STEP_GROUP, STEP_JOBS],
    },
    // `step cover` (CLOUD-2788): reads the roster from the environment, the
    // step table and the pass record, and writes nothing: `read`. Its refusal
    // is a statement about what this head proved, so its exits are a verdict's.
    CommandDecl {
        path: "step cover",
        id: "step.cover",
        about: "Say whether every required CI check passed at HEAD or is exempt, naming each that did not",
        data_channel: false,
        exits: EXITS_VERDICT,
        effect: Effect::Read,
        flags: &[],
    },
    // `step base` (CLOUD-2787): reads object ids at the merge base of HEAD and
    // a ref, and writes nothing: `read`. A ref that does not resolve is
    // could-not-look, never a verdict, so its exits are the standard set.
    // unreached: "step base" CLOUD-2787 a [[step]] tools line the step cache answers in-process; nothing spawns it.
    CommandDecl {
        path: "step base",
        id: "step.base",
        about: "Print one `base <path> <id>` line per path, read at the merge base of HEAD and a ref",
        data_channel: false,
        exits: EXITS_STANDARD,
        effect: Effect::Read,
        flags: &[STEP_BASE_REF, STEP_BASE_REF_ENV, STEP_BASE_PATHS],
    },
    // `step env` (CLOUD-2786): reads this process's environment and writes
    // nothing: `read`. A malformed declaration is usage, never a verdict, so
    // its exits are the standard set.
    // unreached: "step env" CLOUD-2786 a [[step]] tools line the step cache answers in-process; nothing spawns it.
    CommandDecl {
        path: "step env",
        id: "step.env",
        about: "Print the sorted `env` lines a declared environment keys, the step cache's answer to the tool line",
        data_channel: false,
        exits: EXITS_STANDARD,
        effect: Effect::Read,
        flags: &[STEP_ENV_EXCLUDE, STEP_ENV_PATTERNS],
    },
    // The module-graph noun (CLOUD-2789). `cycle` reads the crate's source and
    // writes nothing: `read`. Its refusal over `--max` is a statement about the
    // tree, so its exits are a verdict's.
    CommandDecl {
        path: "modules",
        id: "modules",
        about: "Measure the crate's module graph",
        data_channel: false,
        exits: EXITS_DISPATCHES,
        effect: Effect::Read,
        flags: &[],
    },
    // unreached: "modules metrics" CLOUD-2821 an operator runs it to read a crate's
    // module-graph record line; the ratchet calls the library, not the verb.
    CommandDecl {
        path: "modules metrics",
        id: "modules.metrics",
        about: "Print every module-graph metric of a source root as one record line",
        data_channel: false,
        exits: EXITS_VERDICT,
        effect: Effect::Read,
        flags: &[MODULES_ROOT],
    },
    // `write`: it rewrites the record when every root scores at least as well
    // and one scores better, so the record only tightens. `--check` writes nothing.
    CommandDecl {
        path: "modules ratchet",
        id: "modules.ratchet",
        about: "Refuse any module-graph metric worse than the committed record, and tighten the record on improvement",
        data_channel: false,
        exits: EXITS_VERDICT,
        effect: Effect::Write,
        flags: &[MODULES_RECORD, MODULES_CHECK],
    },
    // `write`: it moves files and rewrites paths and manifests in the working
    // tree. A cut that is not closed downward writes nothing and exits 2.
    // The `rust` preset's `crate reach unknown` remedy (CLOUD-2812).
    // unreached: "modules cut" CLOUD-2812 an operator runs it from the `rust`
    // preset's remedy route and the crate-split skill; nothing in-tree cuts a crate.
    CommandDecl {
        path: "modules cut",
        id: "modules.cut",
        about: "Move a closed set of crate-root modules into a new sibling package, respelling every path, no shim",
        data_channel: false,
        exits: EXITS_VERDICT,
        effect: Effect::Write,
        flags: &[
            MODULES_DRY_RUN,
            MODULES_CUT_FROM,
            MODULES_CUT_NAME,
            MODULES_CUT_SET,
        ],
    },
    // The SPDX and CycloneDX inventories (retiring `[tasks.sbom]` and
    // `sbom-binary-record`). `write`: it writes the documents and runs the
    // inventory tools the consumer pins, which reach the network to fetch pinned
    // sources — `doctor target`'s reading, not `exec`'s, because the programs are
    // declared tools rather than arbitrary code.
    CommandDecl {
        path: "sbom",
        id: "sbom",
        about: "Derive the SPDX and CycloneDX inventories of this tree, or of a built binary, under the names its release assets carry",
        data_channel: false,
        exits: EXITS_STANDARD,
        effect: Effect::Write,
        flags: &[
            SBOM_NAMES,
            SBOM_BINARY,
            SBOM_TARGET,
            SBOM_OUT_DIR,
            SBOM_RECORD,
            SBOM_CONFORMANCE,
        ],
    },
    // The release build and archive (retiring `mise-tasks/dist.sh`). Unclassified:
    // a build runs every dependency's build script, and a cross build runs a
    // container, so its reach is not this repository's to state.
    CommandDecl {
        path: "dist",
        id: "dist",
        about: "Build the release binary for a target and stage its archive, printing KEY=VALUE pointers to both",
        data_channel: false,
        exits: EXITS_STANDARD,
        effect: Effect::Unclassified,
        flags: &[DIST_TARGET, DIST_STEM, DIST_BUILD_TOOL],
    },
    // Whether the committed permissions grant a call the host exposed under
    // another name (retiring `connector-allow-resolve`). `read`: it resolves names
    // through two files and a payload and runs nothing. `EXITS_VERDICT` because
    // `--guard` refuses a denied call.
    CommandDecl {
        path: "mcp grant",
        id: "mcp.grant",
        about: "Apply the committed MCP permissions to whichever server name the host exposed this session",
        data_channel: false,
        exits: EXITS_VERDICT,
        effect: Effect::Read,
        flags: &[MCP_TOOL, MCP_GUARD, MCP_ALIASES, MCP_CONFIG, MCP_SETTINGS],
    },
    // Whether this session's MCP servers are granted and actually attached
    // (retiring `mcp-attach-check` and `mcp-allow-check --session`). `read`: it
    // reads the settings, the injected config, the host's connection logs and the
    // spawn ledger, and starts nothing.
    CommandDecl {
        path: "mcp posture",
        id: "mcp.posture",
        about: "Refuse an enabled MCP server this session did not attach, or a grant the connector would still prompt for",
        data_channel: false,
        exits: EXITS_VERDICT,
        effect: Effect::Read,
        flags: &[MCP_SETTINGS, MCP_CONFIG, MCP_LOGS, MCP_SPAWNS],
    },
    // The `board` noun. Unclassified for `claim`'s reason: its `check` arm
    // records a receipt, and a noun that claimed `read` would hand that writer
    // to any consumer treating an entry as a prefix.
    CommandDecl {
        path: "board",
        id: "board",
        about: "Whether the board's columns and graph tell the truth about the work",
        data_channel: false,
        exits: EXITS_DISPATCHES,
        effect: Effect::Unclassified,
        flags: &[],
    },
    // The board discipline and the ready frontier (retiring `graph-check`,
    // `ready-cites-check` and `spec-ref-check`, CLOUD-1221). `write`, and the
    // foundation's `read` was one fact short: a coherent graph MINTS one
    // `[board] move_receipt` per judged key under `$GIT_DIR/batten-receipts/`,
    // which is the file the move guard reads (CLOUD-512). `claim check` is
    // `write` for the same reason. Nothing is spawned.
    CommandDecl {
        path: "board check",
        id: "board.check",
        about: "Refuse a board whose columns, graph or citations lie, and print the ready frontier",
        data_channel: false,
        exits: EXITS_VERDICT,
        effect: Effect::Write,
        flags: &[BOARD_ISSUE, BOARD_CITES, BOARD_REFS],
    },
    // Every board gate over ONE payload set, reported as a set (CLOUD-825),
    // retiring `[tasks.board-sweep]` (CLOUD-843). UNCLASSIFIED, not `read`: it
    // runs the argv the consumer's `[board] sweep` rows declare, and what those
    // do is theirs. The spawn is `exec`'s placed adapter, so the inventory does
    // not grow. `EXITS_VERDICT`: a refusal is `Violation`, and a gate that could
    // not look — or abstained on this clone — is `Internal`.
    CommandDecl {
        path: "board sweep",
        id: "board.sweep",
        about: "Run every declared board gate over one payload set and report the set of refusals",
        data_channel: false,
        exits: EXITS_VERDICT,
        effect: Effect::Unclassified,
        flags: &[BOARD_ISSUE],
    },
    // How far the landing loop diverged from linear over a window (retiring
    // `land-divergence-record`). `write`: it reads the forge and records a family.
    // Could-not-look — no remote, or an unreadable CI run or landing list — is
    // exit 3 and removes the record; a window read in PART is recorded, counted
    // in `unreadable` for the module to decide over.
    CommandDecl {
        path: "record divergence",
        id: "record.divergence",
        about: "Record how far the landing loop diverged from linear over a window of runs",
        data_channel: false,
        exits: EXITS_STANDARD,
        effect: Effect::Write,
        flags: &[
            DIVERGENCE_CI,
            DIVERGENCE_LAND,
            DIVERGENCE_SINCE,
            DIVERGENCE_MAX_PAGES,
        ],
    },
    // Which recent required-check failures never reached a verdict (retiring
    // `nonverdict-record`). `write`, on `record divergence`'s terms: it reads the
    // forge and records a family, and could-not-look is exit 3.
    CommandDecl {
        path: "record nonverdict",
        id: "record.nonverdict",
        about: "Record which recent required-check failures never reached a verdict",
        data_channel: false,
        exits: EXITS_STANDARD,
        effect: Effect::Write,
        flags: &[
            NONVERDICT_WINDOW,
            NONVERDICT_REQUIRED,
            NONVERDICT_EXCLUDE,
            NONVERDICT_STEP,
        ],
    },
    // A release's attestation posture and each archive's verifier verdict
    // (retiring `[tasks.attestation-record]`). `write`: it reads the forge,
    // spawns the verifier and records a family. Could-not-look — no credential,
    // a posture neither 200 nor 404, a failed download or unpack — is exit 3
    // and removes any stale record.
    CommandDecl {
        path: "record attestation",
        id: "record.attestation",
        about: "Record a release's attestation posture and what the verifier says of each archive's binary",
        data_channel: false,
        exits: EXITS_STANDARD,
        effect: Effect::Write,
        flags: &[ATTESTATION_TAG, ATTESTATION_BINARY, ATTESTATION_VERIFIER],
    },
    // The reclaim census (retiring `[tasks.reclaim-census]`): whether active work
    // was live when a container was replaced. A noun, because its four arms have
    // four effects.
    CommandDecl {
        path: "record census",
        id: "record.census",
        about: "Record whether a landing was in flight when a container was replaced, and read the verdict back",
        data_channel: false,
        exits: EXITS_DISPATCHES,
        effect: Effect::Unclassified,
        flags: &[],
    },
    CommandDecl {
        path: "record census note",
        id: "record.census.note",
        about: "Append a landing's beat or its deliberate stop under this container's boot",
        data_channel: false,
        exits: EXITS_STANDARD,
        effect: Effect::Write,
        flags: &[CENSUS_KIND, CENSUS_REASON],
    },
    // unreached: "record census record-boot" CLOUD-843 `record census report --once` writes the boot mark itself.
    CommandDecl {
        path: "record census record-boot",
        id: "record.census.record-boot",
        about: "Record this container's boot, once",
        data_channel: false,
        exits: EXITS_STANDARD,
        effect: Effect::Write,
        flags: &[],
    },
    // unreached: "record census report" CLOUD-843 the only caller is the `session-census`
    // `[[hook.handler]]` argv in `batten.toml`, which is deliberately not a `verb reach other`
    // line source (its prose reads as callers).
    CommandDecl {
        path: "record census report",
        id: "record.census.report",
        about: "Say whether a landing was in flight when the previous container was replaced",
        data_channel: false,
        exits: EXITS_VERDICT,
        effect: Effect::Write,
        flags: &[CENSUS_ONCE],
    },
    // unreached: "record census tally" CLOUD-843 a human-read report with no scripted caller.
    CommandDecl {
        path: "record census tally",
        id: "record.census.tally",
        about: "Count every recorded replacement by what it interrupted",
        data_channel: false,
        exits: EXITS_STANDARD,
        effect: Effect::Read,
        flags: &[],
    },
    // What a published release carries and what its manifest says about it,
    // retiring `[tasks.release-assets-record]`'s reading half (CLOUD-843).
    // `write`: it records a family and reaches the network. Could-not-look is
    // exit 3 and removes any stale record.
    CommandDecl {
        path: "record release",
        id: "record.release",
        about: "Record a published release's assets, its checksum manifest's entries, and the entries whose bytes disagree",
        data_channel: false,
        exits: EXITS_STANDARD,
        effect: Effect::Write,
        flags: &[RELEASE_TAG, RELEASE_MANIFEST],
    },
    // The `census` noun. `read` because its whole subtree is, `commit`'s reading.
    CommandDecl {
        path: "census",
        id: "census",
        about: "Count what this repository declares it is retiring, as pointers",
        data_channel: false,
        exits: EXITS_DISPATCHES,
        effect: Effect::Read,
        flags: &[],
    },
    // Every home shell lives in, in code lines (CLOUD-843). `read`: it opens the
    // declared manifests and the tracked files and starts nothing. A REPORT, not a
    // gate — the ban is the gate — so it declares no violation code: a census that
    // refused would be a second authority over what the ban already decides.
    CommandDecl {
        path: "census shell",
        id: "census.shell",
        about: "Count every shell line in the declared manifests, workflows and shell files, as pointers",
        data_channel: true,
        exits: EXITS_STANDARD,
        effect: Effect::Read,
        flags: &[JSON],
    },
    // The committed derivations' WRITER (CLOUD-1991), retiring the redirects the
    // `completions`, `man`, `schema` and `render:cli` task bodies carried in
    // shell. UNCLASSIFIED noun for `hk`'s reason: it dispatches, and a noun on the
    // read-only allowlist would carry its writer with it for any consumer that
    // reads an entry as a prefix.
    // The `engine` noun (CLOUD-2061): this binary's identity against the pin a
    // config declares. UNCLASSIFIED for `artifacts`' reason — it dispatches to a
    // read and a write, and a noun on the allowlist reads as a prefix.
    CommandDecl {
        path: "engine",
        id: "engine",
        about: "Report and record which engine this binary is, against a config's pin",
        data_channel: false,
        exits: EXITS_DISPATCHES,
        effect: Effect::Unclassified,
        flags: &[],
    },
    // `read`: it lists the tracked engine inputs and hashes their bytes.
    // unreached: "engine digest" CLOUD-2063 the landing gates call it; until then it is the hand surface for writing a source pin
    CommandDecl {
        path: "engine digest",
        id: "engine.digest",
        about: "Print the source digest of this tree's tracked engine inputs, the value a source pin names",
        data_channel: false,
        exits: EXITS_STANDARD,
        effect: Effect::Read,
        flags: &[],
    },
    // `write`: one stamp file beside the running binary, through `durable`.
    CommandDecl {
        path: "engine stamp",
        id: "engine.stamp",
        about: "Record this tree's source digest beside the running binary, so a source pin can be checked",
        data_channel: false,
        exits: EXITS_STANDARD,
        effect: Effect::Write,
        flags: &[],
    },
    // `write`, twice (CLOUD-2287, CLOUD-2279): every batten declaration in the
    // config — the `engine` line, each batten provision row and
    // `min_batten_version` — moved forward to the release `main` pins and never
    // backward, then `engine install`'s write. A workflow literal it cannot
    // rewrite refuses the whole update. Not `destructive`: the pin only
    // advances, and the install swaps atomically.
    // unreached: "engine update" CLOUD-2279 an operator's verb: moving a consumer's pin is a change to its config no task or workflow may make unasked, and `engine outdated --notice` is what names it
    CommandDecl {
        path: "engine update",
        id: "engine.update",
        about: "Bring every batten declaration in this config forward to the latest release, then install it",
        data_channel: false,
        exits: EXITS_STANDARD,
        effect: Effect::Write,
        flags: &[],
    },
    // `write`: the one `engine` line of the committed config (CLOUD-2063), and
    // nothing else in it. `--check` writes nothing, which is how the hk step asks
    // before its fixer runs.
    CommandDecl {
        path: "engine pin",
        id: "engine.pin",
        about: "Set the config's engine pin, or refresh a declared source pin to this tree's digest",
        data_channel: false,
        exits: EXITS_STANDARD,
        effect: Effect::Write,
        flags: &[ENGINE_PIN_VALUE, ENGINE_PIN_CHECK],
    },
    // `write`, for the cache: a release pin's binary is fetched, verified and
    // kept under git's common directory, then run over this tree (CLOUD-2063).
    // The verdict is the gate's: a source pin never lands, and a release pin
    // must load this config and carry every verb the released lanes invoke.
    // `write`: the engine the pin names (CLOUD-2203, CLOUD-2287). The bootstrap's
    // download is placed in the first directory `PATH` finds; an installed
    // engine is swapped atomically over each copy whose bytes or stamp differ,
    // and a satisfied or absent pin writes nothing. It reads only the `engine`
    // line, never the config, so it runs outside any repository too.
    CommandDecl {
        path: "engine install",
        id: "engine.install",
        about: "Install the engine the batten.toml pin names, from its release or from this tree",
        data_channel: false,
        exits: EXITS_STANDARD,
        effect: Effect::Write,
        flags: &[],
    },
    // `write`, and only through its flags (CLOUD-2279): bare, it reads `main`'s
    // pin and changelog off the raw-file host and writes nothing. `--record`
    // writes one record line and `--notice` one stamp file under the
    // repository's state directory.
    CommandDecl {
        path: "engine outdated",
        id: "engine.outdated",
        about: "Compare the config's release pin with the latest published release",
        data_channel: false,
        exits: EXITS_STANDARD,
        effect: Effect::Write,
        flags: &[
            ENGINE_OUTDATED_NOTICE,
            ENGINE_OUTDATED_RECORD,
            ENGINE_OUTDATED_MAX_RELEASES,
            ENGINE_OUTDATED_MAX_DAYS,
        ],
    },
    CommandDecl {
        path: "engine gate",
        id: "engine.gate",
        about: "Refuse a source pin, or a release pin that cannot load this config or lacks a verb the released lanes call",
        data_channel: false,
        exits: EXITS_STANDARD,
        effect: Effect::Write,
        flags: &[ENGINE_LANE],
    },
    // `write`, for the materialised tree and the build cache it keeps under the
    // repository's state directory (CLOUD-2090). The verdict is the base tests'
    // own pass or fail; a changed expectation is admitted only by the asked
    // ledger.
    CommandDecl {
        path: "test",
        id: "test",
        about: "Judge this branch's tests against their base revision",
        data_channel: false,
        exits: EXITS_DISPATCHES,
        effect: Effect::Unclassified,
        flags: &[],
    },
    CommandDecl {
        path: "test replay",
        id: "test.replay",
        about: "Run each modified test's base form against HEAD; a changed expectation is admitted only by a recorded answer",
        data_channel: true,
        exits: EXITS_STANDARD,
        effect: Effect::Write,
        flags: &[JSON, SLOW_BASE, REPLAY_STRUCTURAL],
    },
    // CLOUD-2690. THE FORGE'S DOOR: one event payload on stdin, normalized by
    // `forge_event`, deduplicated by its seen ring, and dispatched through the
    // same `dispatch_envelope` a harness hook takes. No server (CLOUD-204).
    CommandDecl {
        path: "forge",
        id: "forge",
        about: "Take forge events into the hook surface",
        data_channel: false,
        exits: EXITS_DISPATCHES,
        effect: Effect::Unclassified,
        flags: &[],
    },
    // unreached: "forge intake" CLOUD-2702 its caller is `forge poll`, in process,
    // and this clone starts that from `[[forge.source]]` rows the pinned engine
    // cannot read yet; a consumer's own hook or task is the other caller.
    CommandDecl {
        path: "forge intake",
        id: "forge.intake",
        about: "Run one forge event payload from stdin through the handlers and rules a harness hook gets",
        data_channel: false,
        exits: EXITS_VERDICT,
        effect: Effect::Write,
        flags: &[INTAKE_EVENT, INTAKE_FROM],
    },
    // CLOUD-2693. Where events come from when nothing pushes them: the first
    // available `[[forge.source]]`, read once or every N seconds.
    // unreached: "forge poll" CLOUD-2702 this clone registers it as a task once
    // the engine pin names a release that reads `[[forge.source]]`.
    CommandDecl {
        path: "forge poll",
        id: "forge.poll",
        about: "Read forge events from the first available declared source and run each through intake",
        data_channel: false,
        exits: EXITS_VERDICT,
        effect: Effect::Write,
        flags: &[POLL_EVERY],
    },
    CommandDecl {
        path: "artifacts",
        id: "artifacts",
        about: "Write the committed derivations of the command surface",
        data_channel: false,
        exits: EXITS_DISPATCHES,
        effect: Effect::Unclassified,
        flags: &[],
    },
    // `write`, declared rather than smuggled into `generate`: `generate` stays
    // stdout-only, and this writes the same bytes it emits into the paths the
    // caller names. The pointer is one `<kind>=<path>` line per derivation.
    CommandDecl {
        path: "artifacts write",
        id: "artifacts.write",
        about: "Write completions, man pages, schemas or the CLI reference where the caller names",
        data_channel: false,
        exits: EXITS_STANDARD,
        effect: Effect::Write,
        flags: &[
            ARTIFACT_COMPLETIONS,
            ARTIFACT_MAN,
            ARTIFACT_SCHEMA,
            ARTIFACT_REFERENCE,
        ],
    },
];

/// `--tracked <pathspec>` on `exec` (CLOUD-1991): append every TRACKED path the
/// pathspec selects to the child's argv, and run nothing when none is selected.
///
/// The shell spelling it retires is `git ls-files -z <spec> | xargs -0 -r
/// <tool>`, carried by five lint and format task bodies so a formatter never
/// reaches a deliberately corrupt fixture a suite wrote under an ignored
/// directory. REPEATABLE, for [`ValueDecl::StrMany`]'s reason: a second spec
/// widens the selection rather than silently replacing the first.
pub(crate) const EXEC_TRACKED: FlagDecl = FlagDecl {
    id: "tracked",
    long: Some("tracked"),
    short: None,
    help: "Append the tracked paths this pathspec selects to the command; run nothing if none",
    env: EnvDecl::None,
    global: false,
    positional: false,
    required: false,
    hidden: false,
    rung: Rung::None,
    value: ValueDecl::StrMany,
};

/// `--except <glob>` on `exec` (CLOUD-1991): drop the `--tracked` paths a glob
/// matches — the `:!:` exclusions a magic pathspec would carry, which `--tracked`
/// refuses rather than reading as a literal.
pub(crate) const EXEC_EXCEPT: FlagDecl = FlagDecl {
    id: "except",
    long: Some("except"),
    short: None,
    help: "Drop the tracked paths this glob matches from what --tracked selected",
    env: EnvDecl::None,
    global: false,
    positional: false,
    required: false,
    hidden: false,
    rung: Rung::None,
    value: ValueDecl::StrMany,
};

/// `--completions <dir>` on `artifacts write` (CLOUD-1991).
pub(crate) const ARTIFACT_COMPLETIONS: FlagDecl = FlagDecl {
    id: "completions",
    long: Some("completions"),
    short: None,
    help: "Write the bash, zsh and fish completion scripts into this directory",
    env: EnvDecl::None,
    global: false,
    positional: false,
    required: false,
    hidden: false,
    rung: Rung::None,
    value: ValueDecl::Str,
};

/// `--man <dir>` on `artifacts write` (CLOUD-1991).
pub(crate) const ARTIFACT_MAN: FlagDecl = FlagDecl {
    id: "man",
    long: Some("man"),
    short: None,
    help: "Write one man page per command into this directory, removing stale pages",
    env: EnvDecl::None,
    global: false,
    positional: false,
    required: false,
    hidden: false,
    rung: Rung::None,
    value: ValueDecl::Str,
};

/// `--schema <dir>` on `artifacts write` (CLOUD-1991).
pub(crate) const ARTIFACT_SCHEMA: FlagDecl = FlagDecl {
    id: "schema",
    long: Some("schema"),
    short: None,
    help: "Write the config and policy-input JSON Schemas into this directory",
    env: EnvDecl::None,
    global: false,
    positional: false,
    required: false,
    hidden: false,
    rung: Rung::None,
    value: ValueDecl::Str,
};

/// `--reference <path>` on `artifacts write` (CLOUD-1991).
pub(crate) const ARTIFACT_REFERENCE: FlagDecl = FlagDecl {
    id: "reference",
    long: Some("reference"),
    short: None,
    help: "Write the markdown CLI reference to this file",
    env: EnvDecl::None,
    global: false,
    positional: false,
    required: false,
    hidden: false,
    rung: Rung::None,
    value: ValueDecl::Str,
};

pub(crate) fn half_parser() -> ValueParser {
    ValueParser::new(clap::builder::EnumValueParser::<Half>::new())
}

pub(crate) fn harness_parser() -> ValueParser {
    ValueParser::new(clap::builder::EnumValueParser::<crate::config_model::Harness>::new())
}

/// CLOUD-479's field allowlist, as a pointer to the derive rather than a list of
/// tokens copied here — the same discipline every other parser in this section
/// follows, so the accepted spelling can never drift from the type that
/// receives it.
pub(crate) fn hook_field_parser() -> ValueParser {
    ValueParser::new(clap::builder::EnumValueParser::<crate::config_model::Field>::new())
}

/// hk's format axis, as a pointer to the type rather than a list of tokens —
/// the discipline every parser here follows, so an accepted spelling cannot
/// drift from the enum that receives it.
pub(crate) fn exec_format_parser() -> ValueParser {
    ValueParser::new(clap::builder::EnumValueParser::<
        crate::config_model::OutputFormat,
    >::new())
}

/// mise's style axis, on the same terms.
pub(crate) fn exec_style_parser() -> ValueParser {
    ValueParser::new(clap::builder::EnumValueParser::<
        crate::config_model::OutputStyle,
    >::new())
}

pub(crate) fn spec_format_parser() -> ValueParser {
    ValueParser::new(clap::builder::EnumValueParser::<SpecFormat>::new())
}

pub(crate) fn schema_surface_parser() -> ValueParser {
    ValueParser::new(clap::builder::EnumValueParser::<SchemaSurface>::new())
}

/// Which git fact `receipt status` judges the receipt against, as a pointer to
/// the type the config already uses rather than a second list of tokens — so the
/// CLI and a `[[rule]]`'s `key` column cannot come to mean different things
/// (CLOUD-741).
pub(crate) fn receipt_key_parser() -> ValueParser {
    ValueParser::new(clap::builder::EnumValueParser::<
        crate::config_model::ReceiptKey,
    >::new())
}

pub(crate) fn shell_parser() -> ValueParser {
    ValueParser::new(clap::builder::EnumValueParser::<clap_complete::Shell>::new())
}

/// One half of a split `enforce` (step 13a): see [`Rule::half`].
///
/// The split exists so the landing stage keeps finished work. The tree half is
/// run under a `[[step]]` receipt keyed on the index, so an unchanged tree skips
/// it; the live half — everything that reads a ref, a store, the forge, the
/// clock or a process — runs every time, unreceipted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Half {
    /// Rows whose verdict is a function of the indexed tree alone.
    Tree,
    /// Every other row, and any row whose half cannot be established.
    Live,
}

impl Half {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Half::Tree => "tree",
            Half::Live => "live",
        }
    }
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

/// The surfaces a schema can describe (CLOUD-239, CLOUD-879).
///
/// Two config surfaces, two derivations. `batten.toml` is the committed
/// authority; `batten.local.toml` is the raise-only override, which accepts a
/// strict subset and refuses the rest. One schema describing both is what let a
/// validator green-light keys the loader drops.
///
/// **And two POLICY-INPUT surfaces, which is why this is no longer
/// `ConfigSurface`.** CLOUD-879 derives the documents a Rego module reads as
/// `input` — one per scope — from the fact model, and neither is a config
/// surface: naming them under the old type would have made the type's name a lie
/// about half its variants. Renaming is the smaller lie to fix, and the two
/// existing flag values are untouched.
///
/// A flag on the existing emitter rather than a second sub-verb: CLOUD-244
/// records that §2 and the landed surface already disagree about where schema
/// emission lives, and adding a verb would deepen that before it is settled.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
#[non_exhaustive]
pub enum SchemaSurface {
    /// The committed authority: `batten.toml`.
    Authority,
    /// The raise-only override layer: `batten.local.toml`.
    Override,
    /// The `input` document a `scope = "tree"` Rego module reads.
    PolicyInput,
    /// The `input` document a `scope = "mediated_call"` Rego module reads.
    PolicyCall,
}

/// How much Batten says on stderr, quietest first.
///
/// The derived [`Ord`] is the ladder: `Silent < Quiet < Normal < Verbose < Debug
/// < Trace`, which is what makes [`Verbosity::admits`] a comparison rather than
/// a table anyone maintains.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
#[non_exhaustive]
pub enum Verbosity {
    /// Say nothing but a verdict or a usage error.
    Silent,
    /// Suppress ordinary progress; keep warnings.
    Quiet,
    /// The default.
    Normal,
    /// Explain what is being checked.
    Verbose,
    /// Add resolution detail.
    Debug,
    /// Add everything.
    Trace,
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

impl FlagDecl {
    /// A positional argument the command requires.
    pub(crate) const fn positional(id: &'static str, help: &'static str) -> Self {
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
    pub(crate) const fn positional_optional(id: &'static str, help: &'static str) -> Self {
        FlagDecl {
            required: false,
            ..FlagDecl::positional(id, help)
        }
    }

    /// A required trailing variadic: every remaining token, verbatim.
    pub(crate) const fn trailing(id: &'static str, help: &'static str) -> Self {
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
    pub(crate) const fn required_enum(
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
    pub(crate) const fn optional_enum(
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
    pub(crate) const fn defaulted_enum(
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
    pub(crate) const fn ladder(
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
    pub(crate) const fn presentation(
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

impl FlagDecl {
    /// An optional `--long <value>` flag with no env equivalent.
    pub(crate) const fn valued(id: &'static str, long: &'static str, help: &'static str) -> Self {
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
            value: ValueDecl::Str,
        }
    }

    /// An optional boolean `--long` switch with no env equivalent.
    pub(crate) const fn switch(id: &'static str, long: &'static str, help: &'static str) -> Self {
        FlagDecl {
            value: ValueDecl::Bool,
            ..FlagDecl::valued(id, long, help)
        }
    }
}
