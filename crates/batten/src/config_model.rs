//! The config MODEL (CLOUD-2789): `Config`, the sections it is made of, and
//! the names every module reads it by.
//!
//! Split from `config`, which keeps the load, the parse cache and the
//! validators. A module that only reads the model depends on this, not on the
//! load that depends on every module whose section it validates, so the model
//! stops tying its readers into one cycle. `config` re-exports every name here.

use std::collections::BTreeMap;

use anyhow::Result;
use clap::ValueEnum;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::error::UsageError;
use crate::rules::Rule;

/// The config schema version this build understands. A file declaring any other
/// version is refused rather than partially interpreted.
pub const SUPPORTED_VERSION: u32 = 1;

/// The committed authority Batten reads: the repo `batten.toml` in the working
/// directory. No upward walk, no `conf.d` merge (§8).
pub const CONFIG_FILE: &str = "batten.toml";

/// Where the derived authority schema is published, repo-relative.
///
/// Named once because two readers need it and a second spelling is a second
/// authority: `schema-check` regenerates and diffs the committed file, and
/// `config deprecations` reads the copy at a release ref. `/`-separated, as git
/// addresses a blob.
pub const SCHEMA_PATH: &str = "schema/batten.schema.json";

/// How strictly Batten applies its gates — the ordered, policy-bearing key the
/// §8 raise-only rule is defined over.
///
/// The ordering **is** the policy semantics: `Permissive < Standard < Strict`,
/// so "tighten" is the computable predicate `candidate >= current` rather than a
/// judgement call. Derived `Ord` follows declaration order, which is why the
/// variants are declared weakest-first; [`tests::strictness_orders_weakest_first`]
/// pins that so a reordering cannot silently invert the clamp.
///
/// Resolution is this issue's deliverable (CLOUD-29); the verbs that *read* the
/// resolved value attach as they land (`--fail-on-warning` is CLOUD-49).
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Default,
    Deserialize,
    Serialize,
    ValueEnum,
    JsonSchema,
)]
#[serde(rename_all = "snake_case")]
#[clap(rename_all = "snake_case")]
#[non_exhaustive]
pub enum Strictness {
    /// Advisory: findings are reported without failing the run.
    Permissive,
    /// The default: a finding is a violation.
    #[default]
    Standard,
    /// Everything `Standard` fails on, plus anything advisory.
    Strict,
}

/// Who takes the last step to the landing target (CLOUD-2656).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum LandedBy {
    /// The agent lands its own work with `batten land`.
    #[default]
    Agent,
    /// A person merges what the agent pushed.
    Person,
}

/// A parsed, validated `batten.toml`.
///
/// `deny_unknown_fields` makes an unrecognised key a hard error (§8): the config
/// surface stays narrow and a typo can never silently disable a gate.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Rows this build could not resolve and dropped, so the rest of the file
    /// still decides (CLOUD-1428).
    ///
    /// Not a config key — `skip` keeps it out of both the deserializer and the
    /// derived schema, so an author cannot write it and the published surface
    /// does not grow. It is the loader's own reading about the file, carried on
    /// the value so every caller can report it rather than each re-deriving it.
    ///
    /// **Empty is the answer, not the default.** A reader that treats a
    /// non-empty list as advisory has reintroduced the defect one layer along:
    /// each entry is a gate that is OFF, and CLOUD-251's "never a silent pass"
    /// is what makes reporting it half the change.
    #[serde(skip)]
    pub unresolvable: Vec<Unresolvable>,
    /// The config schema version. Must equal [`SUPPORTED_VERSION`].
    pub version: u32,
    /// The minimum Batten version permitted to read this file (semver).
    /// Enforced at parse time by [`check_min_version`]: a binary below it is
    /// refused with a [`UsageError`] (→ exit `1`) rather than allowed to report
    /// green over rules it does not understand (CLOUD-33).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_batten_version: Option<String>,
    /// The exact engine this file needs: a release tag or a source digest
    /// (CLOUD-2061). Read from the raw text before the parse by
    /// [`crate::engine::check`]; authority-only, as `min_batten_version` is.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub engine: Option<Pin>,
    /// How strictly the gates apply. Absent means "this file does not speak to
    /// strictness", which is what lets [`crate::resolve`] attribute the
    /// effective value to the layer that actually set it. Policy-bearing, so an
    /// override may only raise it (§8).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub strictness: Option<Strictness>,
    /// Whether a `warn`-severity finding is promoted to a violation (CLOUD-49).
    /// Absent means "this file does not speak to the setting", which is what
    /// lets [`crate::resolve`] attribute the effective value to the layer that
    /// actually set it. Policy-bearing, so an override may only turn it *on*
    /// (§8): `false` over a committed `true` is refused, never applied.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fail_on_warning: Option<bool>,
    /// Whether `batten engine outdated --notice` may tell a session the pin is
    /// behind (CLOUD-2279). Absent is on; `false` silences it, as `CI` and
    /// `BATTEN_NO_UPDATE_NOTICE` do. Read raw by the notice, never through a
    /// load, so a config this engine cannot load still hears it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub update_notice: Option<bool>,
    /// The declarative rules run against the repository. Absent or empty means
    /// "no rules configured" and nothing is reported. Which of these a given
    /// verb admits is the §5 effect split: `check` runs only non-spawning kinds
    /// and refuses the rest, `enforce` runs all of them (CLOUD-170).
    ///
    /// Every rule pins its `severity` explicitly — the key is required, with no
    /// implicit fallback — and carries a separate `scope` key whose vocabulary
    /// never conflates with severity's (CLOUD-61). Both disciplines are
    /// enforced at parse time: omission or conflation is a usage error here,
    /// never a value quietly assumed.
    #[serde(default, rename = "rule", skip_serializing_if = "Vec::is_empty")]
    pub rules: Vec<Rule>,
    /// The paths policy applies to, as an **ordered include/exclude list**: a
    /// plain glob includes, a `!`-prefixed glob excludes, and an exclude beats
    /// an include (CLOUD-37). Absent or empty means the set is empty — nothing
    /// is in scope — not "everything", because a set that silently defaults to
    /// universal membership is the widening a policy engine must never do.
    ///
    /// Not to be confused with [`Rule::scope`] ([`crate::rules::RuleScope`]),
    /// which is a per-rule axis saying *where a rule looks*. The two share a
    /// token and nothing else; their vocabularies never cross, exactly as
    /// severity's three axes do not (see [`crate::severity`]).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub scope: Vec<String>,
    /// Paths whose modification is guarded. A plain include set — no `!`
    /// entries — evaluated independently of [`Config::scope`] and
    /// [`Config::unlanded`]. CLOUD-31's config-trust diff defends this set.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub protected: Vec<String>,
    /// The refinement gate's consumer-set thresholds (CLOUD-472). Absent means
    /// this file does not speak to them, which every reader takes as
    /// could-not-look rather than as a default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ready: Option<Ready>,
    /// The landing mechanism's own paths, for the CI-side staleness read
    /// (CLOUD-1148 §2).
    ///
    /// Absent is could-not-look and exempts everything, which matches the
    /// precondition's whole posture: it fails open at every unknown, because a
    /// reading it cannot take would stop every job in the fleet where waving one
    /// matrix through costs one matrix.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lease: Option<Lease>,
    /// Which receipts a head must carry to be called verified (CLOUD-1338).
    ///
    /// Absent REFUSES rather than exempting, which is the opposite direction to
    /// `[lease]` above and deliberately so: this is a gate about the tree in
    /// hand, where that one is an economy about somebody else's runner.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt: Option<Receipt>,
    /// This consumer's board column vocabulary. Absent means this file does not
    /// speak to it, which every reader takes as could-not-look rather than as a
    /// default — see [`Board`] for why a default would be the violation again.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub board: Option<crate::board::Board>,
    /// Accepted invocation-latency regressions (CLOUD-1163 unit 10). Absent
    /// means this file accepts none, which is the safe direction — an absent
    /// table cannot exempt a path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub perf: Option<Perf>,
    /// The mutation sweep's committed enforced set (CLOUD-2010). Absent means
    /// this file declares none, and `batten mutate` then reads only the
    /// raise-only `$MUTANT_GATES` — both empty is a usage error, never an empty
    /// sweep.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mutate: Option<Mutate>,
    /// Programs that only ever READ the operands they are given, so naming a
    /// [`Config::protected`] path is not a mutation (CLOUD-1141).
    ///
    /// # This list is safe to be incomplete, and `verbs` was not
    ///
    /// The verb table enumerates MUTATIONS, so a program missing from it wrote a
    /// protected file unrefused — measured, `python3 -c "open('batten.toml','w')"`
    /// and `perl -pi -e` were allowed where `echo >`, `sed -i` and `tee` were
    /// denied. An allowlist-by-omission whose omissions are holes.
    ///
    /// This list inverts that. A protected path named by a program in NEITHER
    /// table is refused, so the failure mode of forgetting an entry here is a
    /// visible false refusal somebody fixes in a minute — and the failure mode of
    /// forgetting a writer is no longer a silent hole. That direction is the
    /// whole point; a longer verb table would have closed two instances and left
    /// the shape.
    ///
    /// **A program in `verbs` is already known** and is never consulted here: the
    /// verb table encodes its argv grammar, so `git add batten.toml` stays
    /// allowed because `git`'s mutating rows did not match, not because `git` is
    /// listed below.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub protected_readers: Vec<String>,
    /// Paths whose work is not yet landed. A plain include set, evaluated
    /// independently of the other two: a path may be `unlanded` without being
    /// `protected`, and the sets must never be collapsed (CLOUD-37).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unlanded: Vec<String>,
    /// Which files make up the governing config surface the `config_epoch`
    /// hashes (CLOUD-32). Absent means the default: this file alone.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub epoch: Option<Epoch>,
    /// Which files carry the contract a running session read at start
    /// (CLOUD-461). Absent means the predicate is not used here, which
    /// [`crate::contract::surface`] reports as **could not look** rather than as
    /// "nothing moved".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contract: Option<Contract>,
    /// The mutating-verb table (CLOUD-36): which programs change the world, in
    /// the one §5 effect vocabulary. Consumer-specific by nature, so it lives
    /// here and never in the crate (non-negotiable rule 1); the type and its
    /// lookup are [`crate::verbs`].
    #[serde(default, rename = "verb", skip_serializing_if = "Vec::is_empty")]
    pub verbs: Vec<crate::verbs::MutatingVerb>,
    /// The named-regex table (CLOUD-885): every expression a policy module may
    /// apply, declared once and referenced by id.
    ///
    /// Consumer-specific by nature for exactly [`Config::verbs`]'s reason — a
    /// tracker-key expression is a consumer identifier, so it lives here and
    /// never in the crate (non-negotiable rule 1). A module reaches it at
    /// `data.batten.patterns["<id>"]`; writing one inline is refused at load,
    /// which is what prices a one-off pattern against a field access over an
    /// already-parsed document. The type and its validation are
    /// [`crate::pattern`].
    #[serde(default, rename = "pattern", skip_serializing_if = "Vec::is_empty")]
    pub patterns: Vec<crate::pattern::NamedPattern>,
    /// The declared-walk table (CLOUD-1866): every graph traversal a module may
    /// read the answer of, declared once and referenced by id.
    ///
    /// Consumer-specific for [`Config::patterns`]'s reason and more sharply:
    /// which frontmatter field carries an edge, and what a chain terminates at,
    /// are a consumer's vocabulary, so they live here and never in the crate
    /// (non-negotiable rule 1). A module reads the answer at
    /// `input.tree.traversals["<id>"]` and is handed a REDUCTION — a boolean, a
    /// count, or the node names along the chain — never the walk.
    ///
    /// **Declaring it is also what bounds it**: [`crate::graph`] cannot walk
    /// what no row asked for, so a `check`'s cost is a property of this table
    /// rather than of the tree's size. The type and its validation are
    /// [`crate::traversal`].
    #[serde(default, rename = "traversal", skip_serializing_if = "Vec::is_empty")]
    pub traversals: Vec<crate::traversal::DeclaredTraversal>,
    /// The declared-key-set table (CLOUD-2005): every set a `reference` rule may
    /// resolve a cited token against, declared once and referenced by id.
    ///
    /// Consumer-specific for [`Config::traversals`]'s reason: which file holds a
    /// register, which column is its key, which frontmatter node names it, are a
    /// consumer's vocabulary (non-negotiable rule 1). The type, the one GFM row
    /// grammar and the validation are [`crate::register`].
    #[serde(default, rename = "register", skip_serializing_if = "Vec::is_empty")]
    pub registers: Vec<crate::register::DeclaredRegister>,
    /// The refusal vocabulary (CLOUD-1050): every verdict a gate may reach for,
    /// its one-line gloss, its class definition and its closed route list.
    ///
    /// **The sole authority for BOTH emitters** — a Rego `violation` and a
    /// native `Refusal` name a token out of this one table, which is the
    /// reversal CLOUD-1050 records of its own first review: a policy-only
    /// registry beside a native authority is two vocabularies that disagree the
    /// first time either moves. A module reaches it at
    /// `data.batten.verdicts["<id>"]`; a token nothing declares is refused at
    /// load, and a declared token nothing emits is refused the other way, so the
    /// table and the emitters cannot drift. The type and its validation are
    /// [`crate::verdict`].
    #[serde(default, rename = "verdict", skip_serializing_if = "Vec::is_empty")]
    pub verdicts: Vec<crate::verdict::DeclaredVerdict>,
    /// The three positional word lists every class and route name is drawn from
    /// (CLOUD-1284), and the tokenizer pin they were measured under.
    ///
    /// A **dictionary rather than a per-class essay**: a name spends three words
    /// and each word's meaning is declared once, so the marginal class costs no
    /// new prose. `verdict::validate` holds every name to it, which is what makes
    /// the naming convention a gate rather than a habit.
    #[serde(default, skip_serializing_if = "crate::verdict::Vocabulary::is_empty")]
    pub vocabulary: crate::verdict::Vocabulary,
    /// The per-path-class redirect table (CLOUD-280): what to run instead,
    /// keyed by what is protected rather than by the verb reaching for it.
    ///
    /// Consulted before [`MutatingVerb::redirect`], which stays the fallback, so
    /// the behaviour CLOUD-96 shipped is the floor rather than a regression.
    /// Deliberately a sibling of [`Config::protected`] rather than a widening of
    /// it: that set keeps its element type, so [`crate::trust`]'s
    /// `protected[<entry>]` weakening keys are untouched.
    ///
    /// [`MutatingVerb::redirect`]: crate::verbs::MutatingVerb::redirect
    #[serde(default, rename = "redirect", skip_serializing_if = "Vec::is_empty")]
    pub redirects: Vec<Redirect>,
    /// The agent-sourced facts this repository declares (CLOUD-776): a name, and
    /// the command whose output answers it.
    ///
    /// The channel these open is the one that removes a choice rather than making
    /// it. A fact the engine cannot reach used to mean *the engine spawns* or *we
    /// implement less*; a declared fact means the gate denies with
    /// [`crate::refusal::Fix::Run`], the AGENT's own tool runs the command, and
    /// the harness hands the bytes back on the post-tool event. Batten executes
    /// nothing, so house-style §5's read promise is untouched.
    ///
    /// Consumer-specific by nature, which is why the rows live here and never in
    /// the crate (non-negotiable rule 1): `gh pr list --search …` names a forge, a
    /// query syntax and a workflow, and the engine knows only that a fact has a
    /// name and a command.
    #[serde(default, rename = "fact", skip_serializing_if = "Vec::is_empty")]
    pub facts: Vec<crate::facts::Declared>,
    /// Receipts minted from the tool result that earned them (CLOUD-1024).
    ///
    /// The complement of `[[fact]]` above, on the other selector: a fact is keyed
    /// to a COMMAND the agent ran, a mint to the TOOL whose result carries the
    /// evidence. Both are written by the boundary on the post-tool event, from
    /// bytes the harness hands back rather than text the agent re-typed, which is
    /// CLOUD-526's measured forgery surface.
    ///
    /// Consumer-specific by nature, and this table is where non-negotiable rule 1
    /// is paid: `get_issue`, `issue-read`, `id` and `updatedAt` name a tracker,
    /// its tools and its schema, and every one of them is DECLARED here rather
    /// than chosen by the engine.
    ///
    /// This paragraph used to assert that a scan of the crate for those names
    /// found none. It was false — they appear throughout `crates/batten/src`,
    /// including in prose explaining the rule — and nothing re-ran it, which is
    /// the class `assertion_gates.rs` now refuses. What rule 1 actually requires
    /// is that the engine not CHOOSE them, and that is what this table is for.
    #[serde(default, rename = "mint", skip_serializing_if = "Vec::is_empty")]
    pub mints: Vec<crate::mint::Declared>,
    /// Records written from the tool result that earned them (CLOUD-1051).
    ///
    /// The third selector on the post-tool event, and the one that can carry a
    /// value another gate decided. A `[[mint]]` renders a template over the
    /// payload; a `[[recorder]]` may additionally run a declared program and
    /// record its verdict, which is what a board write's refinement column IS.
    ///
    /// Consumer-owned for the same reason `[[mint]]` is, and more so: the column
    /// names, the verdict tokens and the programs are all a tracker's vocabulary,
    /// and every one of them is declared here rather than chosen by the engine.
    /// (The scan this paragraph used to report having run is gone with
    /// [`Config::mints`]' — same false claim, same reason.)
    #[serde(default, rename = "recorder", skip_serializing_if = "Vec::is_empty")]
    pub recorders: Vec<crate::recorder::Declared>,
    /// The verb-written record families this repository's producers fill
    /// (CLOUD-1810).
    ///
    /// The sibling of [`Self::recorders`] on the other side of one split: a
    /// `[[recorder]]` row is filled from a mediated tool call, and one of these
    /// is filled by a producer calling `batten record named <family>`. Both
    /// project into `input.tree.records`, and until this table existed only the
    /// first could — so a store a `mise` task wrote was invisible to every
    /// module, and the row reading it reported clean over a record that said
    /// otherwise.
    ///
    /// **Declared rather than swept**, which is what keeps could-not-look
    /// readable: an absent record under a declared family is "the producer did
    /// not run", where the same absence with nothing declared is not a reading at
    /// all. [`RecordDeclared`] carries the whole argument.
    ///
    /// Consumer-owned, like the two tables above it: which measurements a
    /// repository records, and what fills each, are facts about that repository
    /// and never about the engine (non-negotiable rule 1).
    #[serde(default, rename = "record", skip_serializing_if = "Vec::is_empty")]
    pub records: Vec<RecordDeclared>,
    /// The programs a `[[recorder]]` may run, by id.
    ///
    /// Named rather than inline so one program has one spelling, which is
    /// `[[pattern]]`'s rule one layer over — and so `validate` can refuse a
    /// recorder naming a program nothing declares instead of leaving a column
    /// that renders could-not-look forever.
    #[serde(
        default,
        rename = "program",
        skip_serializing_if = "BTreeMap::is_empty"
    )]
    pub programs: BTreeMap<String, crate::recorder::Program>,
    /// Output predicates over a wrapped command's captured streams (CLOUD-117):
    /// literals that, found in `batten exec`'s output, promote a lying exit `0`
    /// to a violation. Consumer-specific by nature — which warning means
    /// not-actually-done is a property of the tools a repository runs — so it
    /// lives here and never in the crate (non-negotiable rule 1). The type and
    /// the predicate are [`crate::outputs`].
    #[serde(
        default,
        rename = "exec_pattern",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub exec_patterns: Vec<OutputPattern>,
    /// Output predicates that classify a landing gate's REFUSAL as the
    /// environment's rather than this tree's (CLOUD-861).
    ///
    /// **A separate table from [`Config::exec_patterns`], because the two answer
    /// opposite questions from the same shape.** That one asks *is this green run
    /// lying* and promotes a `0`; this one asks *a run already failed, and what
    /// KIND of failure was it* and promotes nothing. One table serving both would
    /// have to decide per reader whether a hit means promote-this-success or
    /// explain-this-failure, and a row written for one reading would silently
    /// change the other's verdict.
    ///
    /// Consumer-specific for [`Config::exec_patterns`]'s reason and then some:
    /// the literal is a toolchain's wording, and the `reason` is the remedy —
    /// *which* reclaim task to run is this repository's vocabulary, so putting
    /// either in the crate is non-negotiable rule 1's plainest violation.
    /// `crates/batten/tests/it/document_facts.rs` is the gate that would catch it.
    ///
    /// The measured case: `target-prune` passed a lap with 6242MB against its
    /// 4096MB floor, the link step then consumed all of it, and the stop said
    /// *"Reproduce and fix locally"* over a tree with nothing wrong in it.
    #[serde(
        default,
        rename = "verify_environment_pattern",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub verify_environment_patterns: Vec<OutputPattern>,
    /// How `batten exec` owns what it dispatched (CLOUD-427). Absent means the
    /// defaults, and the default is today's behaviour: Batten makes no process
    /// group. Authority-only by omission from [`OverrideConfig`] — an uncommitted
    /// file may not decide that a dispatched tree changes shape, because an
    /// orchestrator two levels up is built against the shape the repository
    /// declared. The type and the predicate are [`crate::exec`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exec: Option<ExecConfig>,
    /// Where a harness keeps its MCP wiring, and what to hand back instead of a
    /// method's full response (CLOUD-1260). Absent means Batten dispatches
    /// nothing and reduces nothing.
    ///
    /// Consumer-owned for [`Config::mints`]' reason and more sharply: the server
    /// id, the method names, the field sets and the reduction chosen per method
    /// are all a tracker's vocabulary, and every one of them is declared here
    /// rather than chosen by the engine. (The scan this paragraph used to report
    /// having run is gone with [`Config::mints`]' — same false claim.) The crate knows
    /// only *dispatch a declared method; reduce by a declared projection*. The
    /// type, the transport and the reductions are [`crate::mcp`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mcp: Option<McpConfig>,
    /// The bound on RESPONSE captures (CLOUD-918). Absent means the engine
    /// defaults.
    ///
    /// **`exec` captures stay unbounded and unchanged**, so the consumer that has
    /// this behaviour today keeps it: `prune` remains the whole lifecycle there,
    /// and that store is bounded by how many *distinct* outputs a repository
    /// produces, because identical bytes are one record. A bound exists for
    /// responses because response capture changes the growth law — per call rather
    /// than per distinct output — and inheriting `exec`'s posture into that would
    /// be adopting a bound computed for a different denominator.
    ///
    /// The type and the eviction are [`crate::capture`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capture: Option<CaptureConfig>,
    /// The suppression markers to count (CLOUD-36). Which comment shape waves
    /// a rule through is a property of the repository being gated, never of
    /// Batten; the type and the counting are [`crate::markers`].
    #[serde(default, rename = "marker", skip_serializing_if = "Vec::is_empty")]
    pub markers: Vec<Marker>,
    /// The designed escape hatch (CLOUD-208): per-rule waivers, each carrying a
    /// required justification and a required expiry.
    ///
    /// A waiver suppresses findings of the rule it names, and **lapses on its own
    /// date** — which is what makes the suppression set stop growing
    /// monotonically without anyone having to look at it. Not a severity: the
    /// filter runs over findings before the verdict, and [`crate::severity`]'s
    /// three axes are untouched. The type and the predicate are
    /// [`crate::waiver`].
    #[serde(default, rename = "waiver", skip_serializing_if = "Vec::is_empty")]
    pub waivers: Vec<crate::waiver::Waiver>,
    /// Decisions deferred on a condition the tree can check (CLOUD-759).
    ///
    /// The condition lives here as DATA rather than as prose in a tracker body,
    /// which is the whole mechanism: a reversal condition written in an issue is
    /// re-read by a human or by nobody, and both measured instances were found by
    /// accident while looking for something else.
    #[serde(default, rename = "deferral", skip_serializing_if = "Vec::is_empty")]
    pub deferrals: Vec<crate::deferral::Deferral>,
    /// The thresholds this repository holds itself to (CLOUD-50). Today one:
    /// `[budget.instructions]`, the always-loaded instruction set and what it
    /// may cost. Absent means no budget is declared and none is enforced — a
    /// threshold nobody wrote down is not a threshold of zero. The type and the
    /// predicate are [`crate::budget`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub budget: Option<Budget>,
    /// What ONE emitted mediated refusal line may cost (CLOUD-1286). Absent
    /// means no ceiling is declared and none is enforced, on the same reading as
    /// `[budget]` above. The type and the predicate are [`crate::refusal`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refusal: Option<crate::refusal::Ceiling>,
    /// What ONE emission of the advisory channel may cost, across every producer
    /// (CLOUD-896). Absent means unenforced, on `[budget]`'s reading. The type
    /// and the predicate are [`crate::advisory`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub advisory: Option<Channel>,

    /// The post-tool outcome signatures this repository recognises (CLOUD-945).
    ///
    /// **Consumer config, and that is non-negotiable rule 1 rather than a
    /// preference**: which codes and which program-specific patterns count as a
    /// class is the repository's answer, and `crates/batten` holds the matcher
    /// only. An empty table recognises nothing, which is the honest default —
    /// an advisory channel that fires on a signature nobody declared is noise
    /// that nobody chose.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub outcome: Vec<crate::outcome::Signature>,
    /// What this repository's hooks may cost ONE SESSION (CLOUD-417). Absent
    /// means unenforced, on `[budget]`'s reading. The type and the predicate are
    /// [`crate::hookcost`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hook_output: Option<HookCeiling>,
    /// The ref work must land on (CLOUD-51) — the target `worktree status`
    /// judges at-risk work against. Consumer-specific by nature: which ref is
    /// the trunk is a property of the repository being gated, never of Batten
    /// (non-negotiable rule 1), so the core ships no default and an absent key
    /// means the gate has no target rather than a guessed one.
    ///
    /// Deliberately not [`Config::unlanded`], which is a path-membership set the
    /// rule engine evaluates over tree content. The two are orthogonal — one is
    /// VCS state, the other is which paths policy calls unlanded — and folding
    /// them together would give one key two meanings.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub must_land_on: Option<String>,
    /// Who takes the last step to the landing target (CLOUD-2656): the agent
    /// (`land`), or a person who merges what the agent pushed. Absent is
    /// `"agent"`, today's behaviour. A fact about the repository's process, so
    /// authority-only: neither value is a raise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub landed_by: Option<LandedBy>,
    /// Side effects this repository attaches to hook events (CLOUD-91), the
    /// house-style §9 extension surface: `[[hook.action]]` names an event and a
    /// command already on the operator's PATH, so repo-specific cleanup or
    /// keepalive is reconstructed here rather than carried by the engine
    /// (non-negotiable rule 1). Absent means the repository attaches nothing.
    /// The type, its validator and the spawn are [`crate::action`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hook: Option<crate::action::HookConfig>,
    /// What this repository's container must be, and how it is repaired
    /// (CLOUD-1324). Each `[[startup]]` row names a `check` deciding whether
    /// the environment is right and, optionally, the `repair` that makes it so.
    ///
    /// A REPO-COMMITTED RULE RATHER THAN AN ENGINE CONSTANT, which is the whole
    /// reason the table exists: which preconditions a container needs is a
    /// property of the project being gated, never of Batten (non-negotiable
    /// rule 1), and the alternative it replaced was a boolean per repair inside
    /// a table about hook events. Absent or empty means this repository states
    /// no preconditions.
    ///
    /// Harness-agnostic by construction: a row names a command and an exit code
    /// and knows nothing about which agent harness is running.
    ///
    /// DELIBERATELY NOT `[[provision]]`, which is CLOUD-90's binary manifest —
    /// a pinned version, a URL and a checksum for one fetched tool. That table
    /// answers *is this artifact the one we pinned*; this one answers *is this
    /// container the one we declared*, and folding them together would give one
    /// noun two subjects. The two are siblings rather than rivals: both are
    /// house-style §9's check/fix duality, which `provision status`/`provision
    /// apply` established here first and this table follows.
    ///
    /// The type, its validator and the spawn are [`crate::startup`].
    #[serde(default, rename = "startup", skip_serializing_if = "Vec::is_empty")]
    pub startup: Vec<crate::startup::Startup>,
    /// The optional LLM judge's payload-privacy boundary (CLOUD-135): what may
    /// cross into a model call. Absent means no judge is configured; present and
    /// empty means pointers and hashes only, which is also what every field
    /// defaults to. The type and the pure builder are [`crate::judge`].
    ///
    /// This table lands **before** the judge that reads it, deliberately: a
    /// boundary written after the code it bounds is a boundary that code has
    /// already crossed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub judge: Option<Judge>,
    /// The design-evidence audit's one bound (CLOUD-53): how large a single
    /// capture may be. Absent means the engine default — the corpus arrives on
    /// stdin and the predicates are the engine's, so a repository that declares
    /// nothing still gets the full gate. The type and the gates are
    /// [`crate::design`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub design: Option<Design>,
    /// The merge contract this repository commits to (CLOUD-54), **derived**
    /// from the host ruleset. Absent means the contract is not projected here;
    /// present, it is what `config lint --host-rules` compares against. The host
    /// is always the authority — this is a copy a gate polices, never a second
    /// place the fact is decided.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ci: Option<crate::ci::Ci>,
    /// Repository settings the host decides and this tree projects (CLOUD-380).
    ///
    /// `[ci]`'s sibling and held to the same rule: the host is the authority, and
    /// this is a copy `config lint --host-rules` polices. Where `[ci]` projects
    /// the BRANCH ruleset, this projects the repository object — the settings
    /// whose change weakens a control and today leaves no diff behind.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<crate::ci::Host>,
    /// What this project's build costs and what to keep of it (CLOUD-1030).
    /// Absent means the repository runs no prune and `batten target prune` has
    /// nothing to decide against — a different claim from a floor of zero, which
    /// is why this is an option rather than a default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prune: Option<Prune>,
    /// Where the task programs live and which crashed task Stop relaunches
    /// (CLOUD-2370). Absent means the watchdog is off, and `land`'s reap and
    /// `task alive` fall back to their transitional sources (the environment's
    /// `BATTEN_TASK_PROGRAM_ROOT`, the `--program-root` flag) or, without one,
    /// reap nothing and cannot look.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub task: Option<crate::task::TaskTable>,
    /// The append-only defect ledger (CLOUD-52): where it lives and what may be
    /// in it. Absent means this repository keeps no in-tree ledger and the gate
    /// is simply not active.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub defects: Option<Defects>,
    /// Pinned tools this repository provisions (CLOUD-90): version, URL,
    /// checksum, unpack behaviour, binary name. Consumer-specific by nature —
    /// which tools a repository needs is that repository's business, never
    /// Batten's (non-negotiable rule 1) — so the core carries the mechanism and
    /// this table carries the answer. The type and both halves of the
    /// check/fix pair are [`crate::provision`].
    #[serde(default, rename = "provision", skip_serializing_if = "Vec::is_empty")]
    pub provisions: Vec<crate::provision::Provision>,
    /// The completed-session transcript this repository points `check` at
    /// (CLOUD-95). Host-specific, never consumer-specific: which file a host
    /// writes its transcript to is a property of the harness, not of any one
    /// repository, so rule 1 holds. Absent means the repository does not use
    /// the capability — a different claim from a path that resolves to
    /// nothing, which is why `resolve` answers with three states and not two.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transcript: Option<crate::transcript::TranscriptConfig>,
    /// How the advisory drain paces itself (CLOUD-79): the coalescing window and
    /// the empty-poll give-up count.
    ///
    /// Absent means the defaults apply, which is **not** the reading every other
    /// optional table here takes. Those are consumer policy — a budget nobody
    /// declared is not a budget of zero — where this is engine pacing: the drain
    /// runs on the `hook` surface whether or not a repository has an opinion
    /// about how often, and an absent table means "no opinion", not "do not
    /// drain". The type and the state machine are [`crate::drain`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub drain: Option<DrainConfig>,

    /// What produced commits may carry about the tooling that made them
    /// (CLOUD-274), enforcing the attribution decision record (CLOUD-268).
    /// Absent means this repository declares no attribution policy and the gate
    /// is simply not active — not that everything is permitted, which is why an
    /// absent table is a usage error at the gate rather than a silent pass.
    ///
    /// Consumer-specific by nature, and the reason it lives here: the engine
    /// carries the matcher, this file carries the vendor literals. That extends
    /// non-negotiable rule 1 from consumers to vendors — a grep of `crates/` for
    /// the configured patterns returns nothing (verified-by: batten-check — the
    /// rule-1 `forbid` rows over `crates/**` in this repository's own
    /// `batten.toml`, which run on every gate invocation). The type and the
    /// predicate are [`crate::attribution`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attribution: Option<crate::attribution::Attribution>,
    /// How a session credential is PROVED usable before anything is stripped on
    /// the strength of it (CLOUD-1569).
    ///
    /// Consumer config because the forge is the consumer's, which is
    /// non-negotiable rule 1: the engine holds the mechanism — refuse a known-bad
    /// credential first, then test the real one — and the endpoint that
    /// mechanism speaks to is a fact about this repository, not about batten.
    ///
    /// Absent means the capability is not declared, which reads as
    /// could-not-look rather than as healthy: no removal is authorised.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential: Option<CredentialProbe>,
    /// Which forge this repository is hosted on, in the two places the engine
    /// otherwise assumed one (CLOUD-1622).
    ///
    /// **A SEPARATE TABLE FROM `[credential]` ABOVE, and that separation is
    /// measured rather than tidy.** `[credential] names` answers "which variables
    /// hold a credential WE hold", and its own doc is explicit that the forge's
    /// conventional names are deliberately excluded — a host may inject a
    /// substitutable placeholder under them, so probing those would measure the
    /// host's credential rather than ours. [`Forge::credential_names`] answers the
    /// opposite question: which variables hold a token to AUTHENTICATE WITH,
    /// host-injected job tokens emphatically included. Folding the two would have
    /// stopped every REST read using the CI-provided token — a live regression,
    /// and the reason the row's suggestion to reuse the existing key does not
    /// survive contact with what that key declares.
    ///
    /// Absent is could-not-look rather than a default. The engine's own
    /// spellings are gone rather than kept as a fallback, because a fallback is
    /// how the seam stayed invisible: it worked here, on this forge, and returned
    /// a safe-looking nothing everywhere else.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub forge: Option<crate::rest::Forge>,
    /// The commit-subject convention this repository holds itself to
    /// (CLOUD-701). Absent means no convention is declared and the gate is not
    /// active — which the gate reports as exit 1, never as a clean pass over
    /// commits it had no rule to judge.
    ///
    /// Consumer-specific by nature (non-negotiable rule 1): which type words a
    /// repository admits is that repository's business, so the core carries the
    /// matcher and this table carries the answer. It lives here rather than in
    /// the task runner's config because it is a rule about what a commit may be,
    /// not about how a tool is run. The type and the predicate are
    /// [`crate::commit`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commit: Option<Commit>,
    /// The bot lane this repository files rows for (CLOUD-1295). Absent means it
    /// runs none, and the `pr` verbs say so rather than filing against defaults —
    /// a lane assembled from engine literals would be a row asserting a bump
    /// nobody configured.
    ///
    /// Consumer-specific by nature, and the reason it lives here rather than in
    /// the crate: which repository, which bot logins and which manifests a lane
    /// owns are that repository's business (non-negotiable rule 1), so the core
    /// carries the matcher and this table carries the answers. The type and the
    /// predicates are [`crate::bot`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bot_lane: Option<BotLane>,
    /// How the base-ref authority behaves when the ref cannot be reached
    /// (CLOUD-720). Absent means the strict default: an unreachable ref refuses.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust: Option<Trust>,
    /// The launcher-provisioned scripts this host re-arms every spawn
    /// (CLOUD-1704), as the authority states them. Absent means this consumer
    /// declares none, which is every consumer without a launcher.
    ///
    /// Consumer-specific by nature, and that is the whole reason it is a table
    /// rather than a constant: a script path is somebody's launcher artifact,
    /// and non-negotiable rule 1 keeps those out of `crates/batten`. The core
    /// carries the mechanism and this table carries the paths. The type, its
    /// validator and the write are [`crate::wiring`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wiring: Option<Wiring>,
    /// The measurements this consumer declares over its own tree (CLOUD-843):
    /// where it writes shell, and which files must stay shell. Absent means the
    /// census has nothing declared to read, which `batten census shell` refuses
    /// rather than reporting a zero it never measured.
    ///
    /// Consumer-specific by nature, for `wiring`'s reason: a manifest path, a
    /// workflow glob and an exempt file are somebody's layout, and non-negotiable
    /// rule 1 keeps those out of `crates/batten`. The grammar of "is this line
    /// shell" is the engine's; where to look is this table's. The type and the
    /// reading are [`crate::census`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub census: Option<Census>,
    /// What `batten sbom` inventories and under which names (CLOUD-843).
    /// Absent means the verb has no subject to name, which it refuses rather
    /// than guessing one.
    ///
    /// Consumer-specific for `census`'s reason: the subject's name, where its
    /// documents land, which paths a scan skips and where its licence table
    /// lives are somebody's layout. The derivation is the engine's; the type and
    /// the reading are [`crate::sbom`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sbom: Option<SbomDeclared>,
    /// The step cache's table (CLOUD-424, CLOUD-843): each step a caller brackets
    /// with `batten step`, the pathspecs whose index entries key its receipt and
    /// the tool argvs whose answers do. Empty means no step is declared, so every
    /// `batten step` call is a miss that records nothing.
    ///
    /// Consumer-specific by nature, for `startup`'s reason: which steps a
    /// repository runs and what each reads are facts about that repository
    /// (non-negotiable rule 1). Read from the committed authority alone, never
    /// layered. The row and its validator are [`crate::step_table`]; the cache
    /// that reads the table back lives above this loader and is not named here.
    #[serde(default, rename = "step", skip_serializing_if = "Vec::is_empty")]
    pub steps: Vec<crate::step_table::Step>,
}

/// The `[perf]` table: accepted invocation-latency regressions (CLOUD-1163
/// unit 10, ported off `mise-tasks/perf-compare.sh`'s `EXEMPT` heredoc).
///
/// # Why the rows are config and the THRESHOLD is not
///
/// The threshold is a property of the EXPERIMENT — a null comparison of one
/// identical binary as both arms spread 0.966–1.102, and 1.30 clears that
/// measured maximum. It says nothing about any consumer, so it stays a constant
/// in [`crate::perf`] with its measurement beside it.
///
/// Each row here is the opposite: it names a path, a date and a REASON, and every
/// reason this consumer has written cites a tracker key. Non-negotiable rule 1
/// forbids a consumer identifier anywhere in `crates/batten`, so the table cannot
/// be a literal in the crate whatever its shape — which is what decides this,
/// rather than a preference for configurability.
///
/// # Why a table rather than a raised threshold
///
/// A raised threshold is a repo-wide answer to a one-branch question: it stops
/// the gate asking about every other path, and nothing records what it was raised
/// for. A row accepts ONE path at ONE ratio until ONE date, so the gate keeps
/// asking everything else at the ordinary threshold and the decision expires by
/// itself. That is `prebuilt-lint`'s waiver semantics (CLOUD-92), one gate over.
#[derive(Debug, Clone, Default, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Perf {
    /// The accepted regressions. Absent or empty means every path is judged at
    /// the ordinary threshold, which is the safe direction: an absent table
    /// cannot exempt anything.
    #[serde(default, rename = "exempt", skip_serializing_if = "Vec::is_empty")]
    pub exempt: Vec<PerfExempt>,
    /// The wall-clock budget `batten perf latency` holds a command to
    /// (CLOUD-843). Absent means the verb has nothing to time, which it refuses
    /// rather than reporting a measurement it never took.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latency: Option<PerfLatency>,
}

/// One command's wall-clock budget, in whole seconds.
///
/// CONSUMER DATA, for `[perf.exempt]`'s reason: which command a repository
/// times and what it may cost are that repository's facts, and non-negotiable
/// rule 1 keeps them out of `crates/batten`. The budget is a ceiling DERIVED
/// from measurement, never a target chosen in advance, and re-deriving it is a
/// deliberate commit the verb's drift report prompts.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PerfLatency {
    /// The command, as an argv. Its exit status is IGNORED: a red run still
    /// takes time, and this measures cost rather than correctness.
    pub command: Vec<String>,
    /// How many times to run it; the verdict reads the median.
    pub runs: u32,
    /// The budget, in whole seconds.
    pub budget_seconds: u64,
    /// Seconds over the budget a median may reach before it is drift, so a
    /// shared runner's noise does not cry wolf.
    pub slack_seconds: u64,
    /// A median under `budget_seconds / loose_factor` is drift too: the budget
    /// has stopped bounding anything.
    pub loose_factor: u64,
}

/// One accepted regression: a path, its raised ratio, an expiry and a reason.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PerfExempt {
    /// The measured path this accepts, matched exactly against a record's
    /// `path=` field.
    pub path: String,
    /// The ratio this path may reach. **It only ever RAISES the bar**: a branch
    /// already inside the ordinary threshold is judged by the ordinary
    /// threshold, so an accepted regression cannot become a licence to drift up
    /// to it.
    ///
    /// **Text rather than a float, and the reason is [`Config`]'s own derive.**
    /// `Config` is `Eq`, which no `f64` field can be, and the alternative was to
    /// drop `Eq` from the whole authority so that one row could hold a number —
    /// a change to every comparison in the crate to save one parse here. The
    /// value is validated as a positive finite number at load, so the parse
    /// below cannot be reached with anything else, and text is what the retired
    /// shell held it as anyway.
    pub ratio: String,
    /// The date this acceptance lapses, `YYYY-MM-DD`. A lapsed row stops
    /// exempting rather than quietly continuing.
    pub expires: String,
    /// Why this regression is accepted. Required and non-empty: an exemption
    /// nobody explained is indistinguishable from a threshold nobody defends.
    pub reason: String,
}

impl Perf {
    /// Prove every row well formed at LOAD, which is where the shell read them
    /// one at a time and could only refuse the row it happened to reach.
    ///
    /// # Errors
    ///
    /// A row with an empty path or reason, a non-positive ratio, or an expiry
    /// that is not `YYYY-MM-DD`; a `[perf.latency]` with no program to time, or
    /// a zero `runs` or `loose_factor`. Each is a table that would decide the wrong
    /// thing rather than fail, which is CLOUD-253's rule for every table here.
    pub fn validate(&self) -> Result<()> {
        if let Some(latency) = &self.latency {
            if latency
                .command
                .first()
                .is_none_or(|program| program.trim().is_empty())
            {
                return Err(UsageError::raise(
                    "[perf.latency]: `command` must name a program to time".to_owned(),
                ));
            }
            if latency.runs == 0 || latency.loose_factor == 0 {
                return Err(UsageError::raise(
                    "[perf.latency]: `runs` and `loose_factor` must be at least 1; a zero is a \
                     measurement that decides nothing"
                        .to_owned(),
                ));
            }
        }
        for (index, row) in self.exempt.iter().enumerate() {
            let at = format!("[[perf.exempt]] #{}", index + 1);
            if row.path.trim().is_empty() {
                return Err(UsageError::raise(format!("{at}: `path` is empty")));
            }
            if row.reason.trim().is_empty() {
                return Err(UsageError::raise(format!(
                    "{at} ({}): `reason` is empty. An exemption nobody explained is a \
                     threshold nobody defends.",
                    row.path
                )));
            }
            if !row
                .ratio
                .parse::<f64>()
                .is_ok_and(|ratio| ratio.is_finite() && ratio > 0.0)
            {
                return Err(UsageError::raise(format!(
                    "{at} ({}): `ratio` must be a positive number, not `{}`",
                    row.path, row.ratio
                )));
            }
            // Compared as fixed-width text against `YYYY-MM-DD`, which is what
            // the shell's `[[ "$expires" < "$TODAY" ]]` did and what keeps this
            // free of a date dependency. The shape check is what makes that
            // comparison meaningful: `2026-9-1` sorts before `2026-11-30` and
            // would lapse a row that has not.
            let shaped =
                row.expires.len() == 10
                    && row.expires.chars().enumerate().all(
                        |(position, character)| match position {
                            4 | 7 => character == '-',
                            _ => character.is_ascii_digit(),
                        },
                    );
            if !shaped {
                return Err(UsageError::raise(format!(
                    "{at} ({}): `expires` must be YYYY-MM-DD, not `{}`. It is compared as \
                     text, so a short field lapses a row that has not.",
                    row.path, row.expires
                )));
            }
        }
        Ok(())
    }
}

/// The landing lease's own configuration (CLOUD-1148 §2).
#[derive(
    Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
#[serde(deny_unknown_fields)]
pub struct Lease {
    /// The paths that CONSTITUTE the landing mechanism, so a head can be asked
    /// whether it carries what trunk has.
    ///
    /// # A PATH SET RATHER THAN A GREP STRING, and that is the whole point
    ///
    /// The predecessor asked this by grepping the head's `mise-tasks/land.sh`
    /// for `land-lock acquire`. Both halves of that die with the retirement: the
    /// file is deleted, so the read fails, so the script takes its own fail-open
    /// path and reports "not judging this head's age" — and every stale head
    /// passes, silently, which is worse than a wrong answer.
    ///
    /// A declared path set survives, because the thing that changes when the
    /// mechanism moves is WHICH PATHS, and that is config a retirement edits
    /// rather than a literal a retirement invalidates.
    ///
    /// Empty is could-not-look: nothing to compare means no verdict, never a
    /// clean one.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub landing_paths: Vec<String>,

    /// Branch-name prefixes that land WITHOUT taking the lease, so the runner-side
    /// precondition must not judge them.
    ///
    /// # THE POPULATION IS THE LANDER'S, NOT THE AUTHOR'S
    ///
    /// These are branches some other workflow fast-forwards on a `workflow_run`
    /// completion, so no agent ever holds the lease on their behalf and judging
    /// them would refuse the run the gate exists to let through. The predecessor
    /// spelled the same set as a `case` in shell, and its comment carries the
    /// economics: a cancelled run is `completed`, so those landers DO fire, find
    /// the checks not green, and stop; nothing retries. Cancelling here would not
    /// save a matrix, it would DEFER one and add a stall.
    ///
    /// **Not the bot-author set** (`[bot_lane] bots`), and the two must not be
    /// collapsed: that keys on a forge LOGIN and this keys on a branch NAME,
    /// because what decides the question is which workflow lands the branch. A
    /// human who names a branch with one of these prefixes gets the same
    /// treatment, correctly — the lander fires on the name.
    ///
    /// **Prefixes on the branch, never a substring anywhere in the ref**, which
    /// the predecessor's suite pinned as its own case: a `case` arm matching
    /// mid-ref would exempt a branch that merely mentions one.
    ///
    /// Empty means every branch is judged, which is the gate's default and the
    /// reason this is a short named list rather than a pattern.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fast_forward_branches: Vec<String>,
}

/// The `[mutate]` table: which gates `batten mutate` must show able to fail
/// (CLOUD-2010).
///
/// # Why a committed table, and why the variable only raises it
///
/// The enforced set was an environment variable that only this repository's own
/// task runner set, so every consumer's `mutate census` refused with
/// `MUTANT_GATES is unset` and a consumer's suite could be shown to pass but
/// never shown able to fail. House-style §8 is the shape: ONE committed
/// authority, plus raise-only overrides. `$MUTANT_GATES` still adds names; it
/// can never remove one this table declares.
///
/// The `#MUTANT` rows themselves stay beside the code (`mutate.rs`'s `ROW`):
/// this table names WHICH gates are enforced, never how one is mutated, so it
/// is not the second authority a manifest of mutations would be.
#[derive(Debug, Clone, Default, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Mutate {
    /// The enforced gates. Each entry is a gate name exactly as `$MUTANT_GATES`
    /// carries one, or — when it contains `*` — a glob over tracked paths,
    /// expanded sorted to the name each matched file already has as a subject
    /// (`X` for `policy/X.rego`, the task name for `mise-tasks/X.sh`) and to the
    /// file's own path only where no other arm names it. A glob matching
    /// nothing is kept as written, so the census reports it `names-no-subject`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub gates: Vec<String>,
    /// Narrows which tracked files the census's declaration arm reads, in
    /// [`Config::scope`]'s include/exclude grammar. Absent means every tracked
    /// file — the declaration arm is opt-in by the `#MUTANT` lines a file
    /// carries, so there is no population to bound by default.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub scope: Vec<String>,
    /// The `command` mutation runner's argv (CLOUD-2211): a TOML array, never
    /// word-split, run once with the changed sources it owns appended. Its exit
    /// is the contract: 0 caught, 2 survived, anything else could-not-look.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub command: Vec<String>,
}

/// The `[receipt]` table: which receipts a head must carry to be called verified.
#[derive(Debug, Clone, Default, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    /// The checks `receipt verified` requires a valid receipt for.
    ///
    /// # NON-NEGOTIABLE RULE 1, AND THE ARRAY THIS REPLACES
    ///
    /// `receipt.rs` carried `const VERIFIED_BY: [&str; 2] = ["verify",
    /// "linear-check"]` — two of THIS consumer's task names, compiled into the
    /// core, which is the rule's plainest shape. A different adopter's gates are
    /// not called those things, and nothing in the engine could tell them so.
    ///
    /// # UNDECLARED FALLS BACK, and this doc said it refused
    ///
    /// The hazard is real and unchanged: an empty set would make
    /// `receipt verified` pass over every head, since *nothing is unverified*
    /// when nothing is required — a gate that answers clean because it was never
    /// told what to ask. What closes it is a fallback rather than a refusal.
    /// [`crate::receipt::verified_by`] resolves an undeclared or empty table to
    /// [`crate::receipt::VERIFIED_BY`], and its own header records why the first
    /// draft's usage error could not stand: it refused over a fixture repository
    /// with no `batten.toml` and no interest in receipts, and that suite's
    /// subject survives, so the only way to land the refusal was to edit around
    /// a gate that was right.
    ///
    /// The fallback is strictly more general than the `const` it replaced and
    /// costs an adopter nothing — our names over their receipts resolve to
    /// `Missing`, so `verified` refuses loudly on their first run rather than
    /// passing quietly. A wrong answer that announces itself is the acceptable
    /// failure; a silent one is not.
    ///
    /// **Stated here because a field's doc is where a reader looks for what an
    /// absent key does** (review of #848), and this one asserted a refusal the
    /// code does not make — with `trust.rs`'s `VerifiedCheckRemoved` repeating
    /// it, which is how one false premise became two.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub verified_by: Vec<String>,
}

/// The `[ready]` table: the refinement gate's consumer-set thresholds.
///
/// # Why a value and not a `[[pattern]]` row (CLOUD-472)
///
/// The first draft of the prose-dialect ratchet spelled its threshold as a
/// regex over the exempt key range. That is wrong twice. The pattern registry
/// exists so that one CONCEPT has one spelling — arithmetic is not a concept,
/// and a range encoded in alternation is unreadable and unmovable. And it makes
/// the decision turn on key TEXT, which the tracker is known to rewrite: this
/// consumer already declares `ready-issue-mention-markup` because a bare key
/// comes back wrapped in `<issue …>` markup, so matching key text is matching
/// the one thing the round trip mangles.
#[derive(Debug, Clone, Default, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Ready {
    /// From which creation instant a Ready block must carry the fenced claims
    /// object rather than prose. An ISO-8601 UTC stamp, compared verbatim
    /// against the tracker's own `createdAt`.
    ///
    /// **A RATCHET: moving it later is the only direction that tightens.**
    /// Absent is could-not-look and exempts everything, so a consumer that has
    /// not opted in is never refused for a question it did not ask.
    ///
    /// **An instant rather than a key ordinal, and that is a portability
    /// decision.** An ordinal reaches no consumer literal — the trailing digits,
    /// no separator assumed — so it passes `no-tracker-key-in-core`. It still
    /// requires keys that are numeric AND monotonic with creation order, which
    /// three popular trackers give and a slug- or UUID-keyed one does not, and it
    /// would fail SILENTLY there rather than loudly. Every tracker stamps a
    /// creation time, so this assumes nothing about how a consumer spells a key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prose_dialect_required_from: Option<String>,
    /// The instant from which a row owes a dispatched PRESSURE TEST (CLOUD-472).
    ///
    /// A sibling of the field above rather than a reuse of it, and the
    /// separation is the point: these two ratchets convert different things and
    /// a consumer must be able to move one without moving the other. Folding
    /// them into one instant would mean the day you demand a structured claims
    /// object is also the day you demand an agent dispatch, and a repository
    /// that wants the first and cannot yet afford the second would have no way
    /// to say so.
    ///
    /// Read exactly as its sibling is — fixed-width ISO-8601 UTC compared
    /// lexically, absent is could-not-look, and moving it LATER is the only
    /// direction that tightens.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pressure_test_required_from: Option<String>,
    /// The instant from which a `feat` row owes its prior-art search
    /// (CLOUD-2296), read exactly as its two siblings are.
    ///
    /// A ratchet rather than a switch for their reason: a row groomed Ready
    /// before the claim existed is not made unready by its arrival, so the
    /// queue a fleet is draining stays pullable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prior_art_required_from: Option<String>,
}

/// The `[trust]` table: what `--config-from` may do when the ref is unreachable.
///
/// House style §4 requires the authority to degrade safely rather than fail
/// open, and CLOUD-31's decision record makes offline last-known-good mandatory.
/// This table is the operator's half of that: the engine will serve a pinned,
/// previously validated config **only** where an explicit committed key says it
/// may.
///
/// **Not sniffed from the environment, and that is the design.** Detecting CI
/// would make a safety property depend on a heuristic about the world. A CI
/// checkout simply never sets this key, so the honest answer to a missing base
/// ref there stays "fetch it, or refuse" — which is what CLOUD-236's workflow
/// step already implements.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Trust {
    /// May an unreachable base ref be answered from the last validated config?
    ///
    /// Defaults to `false`. Turning it on **lowers the bar**, so it is a
    /// weakening in its own right ([`crate::trust::WeakeningKind`]) and is
    /// reported by the same comparison every other weakening goes through — the
    /// escape hatch is policed by the mechanism it would open. For the same
    /// reason it lives in the committed authority only: no raise-only override
    /// layer may set it (§8).
    ///
    /// It never reaches a ref that *resolves*. "The ref is good and declares no
    /// `batten.toml`" refuses in every configuration, or a branch pointing
    /// `--config-from` at a config-less ref picks its own policy.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub offline_fallback: bool,
}

/// The `[epoch]` table: which files govern this repository.
///
/// Declared as **config** rather than compiled in, because which files govern a
/// repository is that repository's business: an agent settings file, a
/// contributor guide, a hook config — each meaningful in one repository and
/// meaningless in the next. The core therefore carries only the default (this
/// file), and every consumer's own list lives in that consumer's own config, so
/// a grep of `crates/batten` for any consumer's identifiers returns nothing
/// (non-negotiable rule 1; verified-by: batten-check — the rule-1 `forbid` rows over `crates/**` in this repository's own `batten.toml`, which run on every gate invocation).

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Epoch {
    /// Repo-relative paths whose bytes the epoch covers. Order is irrelevant —
    /// [`crate::epoch::tracked_paths`] sorts and deduplicates, so the value is a
    /// function of the set rather than of how it was written.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tracked: Vec<String>,
}

/// The `[contract]` table: which files a running session must re-read when they
/// move (CLOUD-461).
///
/// **A second table rather than a reuse of [`Epoch`], and the reason is
/// structural.** `[epoch] tracked` is literal repo-relative paths, read one file
/// each — right for a config epoch, which must be a function of a *stated* set
/// or the value moves because of what happens to exist beside it. A contract
/// surface is the opposite case: a rules directory and a task tree, where a
/// newly added file **is** the drift. Globs are the whole point here and would
/// be a defect there, so the two tables answer different questions rather than
/// one table answering both badly.
///
/// Declared as config for the reason [`Epoch`] gives: which files carry a
/// repository's contract is that repository's business, so a grep of
/// `crates/batten` for any consumer's identifiers returns nothing
/// (non-negotiable rule 1; verified-by: batten-check — the rule-1 `forbid` rows over `crates/**` in this repository's own `batten.toml`, which run on every gate invocation).

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Contract {
    /// Globs over repo-relative `/`-separated paths whose bytes a session is
    /// told about when they move. Order is irrelevant — the manifest is a
    /// sorted map, so the snapshot is a function of the set.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tracked: Vec<String>,
    /// The subset of `tracked` that is the **hook wiring**, so the notice can
    /// say the wiring moved without the core knowing any host's file layout
    /// (CLOUD-525).
    ///
    /// Literal paths, not globs: this names specific files a consumer has
    /// declared to be its wiring, and a glob here would let the notice claim the
    /// wiring moved because something merely near it did.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub wiring: Vec<String>,
}

/// One thing this build could not resolve, dropped so the rest of the file
/// loads.
///
/// Pointer-only by construction (non-negotiable rule 4): what travels is an
/// ADDRESS in the document — never a byte of it. The parse error quotes the
/// source line, and that quote is exactly what must not reach a report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unresolvable {
    /// The table the drop happened in: an array-of-tables section like `rule`,
    /// or a plain `[section]` like `capture`.
    pub section: String,
    /// What was dropped there.
    pub unit: Unit,
}

/// The GRANULARITY of one drop, which differs because the units do.
///
/// **This distinction is the type's whole reason to be an enum, and collapsing
/// it is what review caught.** Both arms once wrote into one `id: Option<String>`
/// field whose doc said "not the key" while the plain-section arm put the key
/// there — so a reader could not tell a row from a key, and
/// [`crate::lint`]'s positional filter had to trust that an index of `0` on a
/// key drop would never collide with row `0` of a same-named section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Unit {
    /// A whole `[[row]]`, because a row is ONE GATE: a key it cannot read could
    /// change what that gate enforces, so the honest move is to stop enforcing
    /// it and say so.
    Row {
        /// The row's declared `id`, when it has one. A row without one is still
        /// reported — by index — because a silent drop is the vacuous pass this
        /// whole change exists to refuse.
        id: Option<String>,
        /// The row's ordinal within its section IN THE SOURCE, which is what
        /// [`crate::lint`]'s located view filters on.
        index: usize,
    },
    /// One key of a plain `[section]`, because a settings table is not a gate:
    /// an unknown key there is a setting this build does not have, so the
    /// honest move is to run on the build's own default and say so. Dropping
    /// the whole table instead would switch off a feature the file plainly
    /// wants, which is worse than the disease.
    ///
    /// **The key's NAME travels, and that is rule 4 satisfied rather than
    /// bent.** A key name is the address of the setting that is off — the
    /// thing a reader has to look up — where the row arm's `id` is the address
    /// of the gate that is off. Neither is content: the VALUE stays behind, and
    /// it is the value that could carry a secret.
    Key(String),
}

// ---- `[drain]` (CLOUD-2789: moved from `drain`, which re-exports it) ----

/// The coalescing window, in milliseconds, when the config declares none.
///
/// A batch of tool calls lands in well under a second on every host surveyed, so
/// this is sized to span one comfortably while staying far below the interval at
/// which an agent would notice a finding arriving late. It is a **default, not a
/// constant**: the §7 obligation is that pacing comes from config, and this is
/// only what an absent `[drain]` table resolves to.
pub const DEFAULT_INTERVAL_MS: u64 = 2_000;

/// Consecutive empty drains before wakes stop paying for one, when the config
/// declares none.
pub const DEFAULT_EMPTY_POLL_GIVEUP: u32 = 3;

/// Distinct identities one rule may spend entries on in a single drain, when the
/// config declares none.
///
/// Ten because the cap is a **rule-health** threshold rather than a display
/// preference: a check that fires on more than ten distinct identities inside
/// one changed scope is telling the operator something about itself, and the
/// summary line is the honest way to say it in one line instead of eleven.
pub const DEFAULT_CARDINALITY_CAP: usize = 10;

/// The rendered payload's token ceiling, when the config declares none.
///
/// Sized to a payload an agent reads rather than skims — roughly forty pointer
/// lines — and small enough that the drain firing on every batch boundary of a
/// long session stays a rounding error against the context it is protecting.
pub const DEFAULT_TOKEN_BUDGET: usize = 1_024;

/// How many of a subject's evaluations the flap ratio is computed over, when the
/// config declares none (CLOUD-165).
///
/// Eight because the window has to be long enough that an ordinary raise-then-fix
/// — one transition — stays far under any useful threshold, and short enough that
/// an identity which has *stopped* oscillating is believed again within a few
/// evaluations. Nagios ships twenty-one state slots for a check evaluated on a
/// timer; a window counted in evaluation boundaries needs fewer, because every
/// entry in it is a real scan rather than a poll.
pub const DEFAULT_FLAP_WINDOW: usize = 8;

/// The flap threshold as state changes per hundred adjacent evaluations, when the
/// config declares none.
///
/// Fifty: half the transitions the window could possibly hold. A raise, a fix and
/// a regression inside eight evaluations scores well under it; a check alternating
/// on every scan scores one hundred. Nagios's defaults bracket the same region
/// from either side, and the integer spelling is what keeps the comparison behind
/// a suppression exact.
pub const DEFAULT_FLAP_PERCENT: u32 = 50;

/// How many times a **flapping** identity may be emitted inside its window,
/// before the drain stops repeating it.
///
/// Three, and the number matters less than what it bounds: an oscillation says
/// everything it has to say in the first couple of emissions, and the rest is the
/// flood this policy exists to stop. A steady identity is never capped by it, so
/// this is not a rate limit on the drain (see [`crate::emission::Assessment::decide`]).
pub const DEFAULT_EMIT_CAP: usize = 3;

/// The `[drain]` table: how often the advisory drain may wake, when it stops
/// asking, and how much it may say when it does.
///
/// Every key here bounds **the engine's own output**, which is why none of them
/// is layered raise-only by [`crate::resolve`]: "raise" has no meaning for an
/// interval — a longer one is quieter and a shorter one is louder — and a cap on
/// what Batten prints about itself is not a policy bar a local file could
/// weaken. The committed authority sets them, and a local file does not move
/// them.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DrainConfig {
    /// The coalescing window in milliseconds. Every wake inside it after a drain
    /// is masked.
    ///
    /// `0` disables coalescing: every wake drains. That is a legitimate setting
    /// — it is what a host that really does deliver one wake per batch would
    /// want — and not a disabled feature, which is why it is spelled as the
    /// bottom of the range rather than as an `enabled` flag.
    #[serde(default = "default_interval_ms")]
    pub interval_ms: u64,
    /// How many consecutive silent drains before wakes stop draining until the
    /// store moves.
    ///
    /// `0` means the give-up applies immediately once a drain says nothing, so a
    /// quiet session pays a format read per wake and nothing more.
    #[serde(default = "default_empty_poll_giveup")]
    pub empty_poll_giveup: u32,
    /// Distinct identities one rule may spend entries on in a single drain.
    ///
    /// A rule over it renders one `rule R: K+ findings` summary line instead,
    /// and never `K` entries. `0` caps every rule that surfaced anything, which
    /// is the honest bottom of the range — a drain of nothing but summary lines
    /// — rather than a disabled feature.
    #[serde(default = "default_cardinality_cap")]
    pub cardinality_cap: usize,
    /// The rendered payload's ceiling, in estimated tokens.
    ///
    /// Applied after the cap, over the payload as a whole. `0` means the drain
    /// says nothing at all, which is a legitimate setting for a host that reads
    /// findings some other way and not a disabled feature.
    #[serde(default = "default_token_budget")]
    pub token_budget: usize,
    /// How many of a subject's evaluations the flap ratio is computed over
    /// (CLOUD-165), counted in evaluation boundaries and never in wall-clock time.
    ///
    /// `0` and `1` both mean no window can hold a transition, so nothing is ever
    /// annotated flapping and nothing is ever flap-suppressed — the honest bottom
    /// of the range, and the setting a consumer uses to turn the policy off
    /// without a second key that could disagree with this one.
    #[serde(default = "default_flap_window")]
    pub flap_window: usize,
    /// The flap threshold, as state changes per hundred adjacent evaluations.
    ///
    /// `0` annotates every identity with two evaluations in its window, and `101`
    /// or above annotates none, both of which are the range's honest ends rather
    /// than special cases.
    #[serde(default = "default_flap_percent")]
    pub flap_percent: u32,
    /// How many times a flapping identity may be emitted inside its window.
    ///
    /// `0` withholds a flapping identity outright. A steady one is unaffected at
    /// any value, because the cap and the annotation are read as a conjunction.
    #[serde(default = "default_emit_cap")]
    pub emit_cap: usize,
}

fn default_interval_ms() -> u64 {
    DEFAULT_INTERVAL_MS
}

fn default_empty_poll_giveup() -> u32 {
    DEFAULT_EMPTY_POLL_GIVEUP
}

fn default_cardinality_cap() -> usize {
    DEFAULT_CARDINALITY_CAP
}

fn default_token_budget() -> usize {
    DEFAULT_TOKEN_BUDGET
}

fn default_flap_window() -> usize {
    DEFAULT_FLAP_WINDOW
}

fn default_flap_percent() -> u32 {
    DEFAULT_FLAP_PERCENT
}

fn default_emit_cap() -> usize {
    DEFAULT_EMIT_CAP
}

impl Default for DrainConfig {
    fn default() -> Self {
        DrainConfig {
            interval_ms: DEFAULT_INTERVAL_MS,
            empty_poll_giveup: DEFAULT_EMPTY_POLL_GIVEUP,
            cardinality_cap: DEFAULT_CARDINALITY_CAP,
            token_budget: DEFAULT_TOKEN_BUDGET,
            flap_window: DEFAULT_FLAP_WINDOW,
            flap_percent: DEFAULT_FLAP_PERCENT,
            emit_cap: DEFAULT_EMIT_CAP,
        }
    }
}

// ---- `design` (CLOUD-2789: moved from `design`, which re-exports it) ----

/// The `[design]` table: the one config key this gate reads.
///
/// Deliberately a single key. The corpus is stdin's, the predicates are the
/// engine's, and the only thing a repository gets to say is how large a single
/// capture may be before it is worth a second look.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Design {
    /// The per-capture byte ceiling. Absent means [`DEFAULT_MAX_CAPTURE_BYTES`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_capture_bytes: Option<usize>,
}

// ---- `defects` (CLOUD-2789: moved from `defects`, which re-exports it) ----

/// The `[defects]` table: where the ledger lives and what may be in it.
///
/// Both keys are consumer facts. The crate carries neither a path nor a class
/// token (non-negotiable rule 1) — a taxonomy is a description of one team's
/// failure modes, not an engine fact.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Defects {
    /// The repo-relative path of the one JSONL ledger.
    pub path: String,
    /// The allowed `class` tokens. A record outside this set is refused.
    pub classes: Vec<String>,
}

// ---- `engine` (CLOUD-2789: moved from `engine`, which re-exports it) ----

/// The engine a config needs: exactly one of a release tag or a source digest.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Pin {
    /// A published release, spelled as its tag (`v0.0.198`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub release: Option<String>,
    /// The digest `batten engine digest` prints for the source tree the engine
    /// must be built from (64 hex).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
}

// ---- `markers` (CLOUD-2789: moved from `markers`, which re-exports it) ----

/// One suppression marker declared in `batten.toml`.
///
/// The two fields are deliberately separate axes: `id` is the stable name a
/// count is reported under and may not change when the spelling does, while
/// `token` is the literal text scanned for. Collapsing them would make every
/// re-spelling of a marker look like a brand-new one whose count starts at
/// zero — the ratchet defeated by a rename.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Marker {
    /// The stable identifier counts are reported under.
    pub id: String,
    /// The literal text that marks a suppression. Matched as a substring, not a
    /// pattern: a marker is a fixed shape an author types, and admitting a
    /// regex here would make the count a function of an expression rather than
    /// of the tree.
    pub token: String,
    /// Which files this marker is looked for in, as a `/`-separated glob. Omit
    /// to scan the whole tree.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub glob: Option<String>,
}

// ---- `hookcost` (CLOUD-2789: moved from `hookcost`, which re-exports it) ----

/// The `[hook_output]` table: what this repository's hooks may cost one session.
///
/// **Absent means unenforced**, on `[budget]`'s reading — a threshold nobody
/// declared is not a threshold of zero — so a consumer that has not adopted the
/// table measures exactly as it did before and refuses nothing.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HookCeiling {
    /// The ceiling on estimated tokens of hook output across the whole session.
    /// The boundary is `<=`, matching `[budget]`, `[refusal]` and `[advisory]`
    /// so the four thresholds in this tree do not disagree about their own edge.
    pub max_tokens: usize,
    /// How many times one hook may emit byte-identical text in one session.
    ///
    /// **The floor is 1, not 0.** Saying a thing once is the report; saying it
    /// again is the copy. A ceiling of 0 would refuse the first emission, which
    /// is a hook switched off rather than a hook made quiet — and this row puts
    /// "removing any hook, or weakening what it detects" explicitly out of scope.
    pub max_repeats: usize,
}

// ---- `advisory` (CLOUD-2789: moved from `advisory`, which re-exports it) ----

/// The `[advisory]` table: what ONE emission of the whole channel may cost.
///
/// **The channel, not the producer**, which is the whole of this row. Absent
/// means unenforced, on `[budget]`'s reading — a threshold nobody declared is
/// not a threshold of zero — so a consumer that has not adopted it emits exactly
/// what it emitted before.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Channel {
    /// The ceiling on estimated tokens for one emission, across every producer.
    /// The boundary is `<=`, matching `[budget]` and `[refusal]` so the three
    /// thresholds in this tree do not disagree about their own edge.
    pub max_tokens: usize,
}

// ---- `bot` (CLOUD-2789: moved from `bot`, which re-exports it) ----

/// The `[bot_lane]` table: which proposals this repository will file a row for.
///
/// Absent means the repository runs no bot lane, and the verbs say so rather than
/// filing against defaults — a lane assembled from engine literals would be a row
/// asserting a bump nobody configured, which is the CLOUD-198 class with a new
/// author.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BotLane {
    /// The forge repository, `owner/name`, that the lane's pull requests live in.
    pub repo: String,
    /// The logins whose pull requests earn a row.
    ///
    /// A list rather than a pattern: a login is a literal the forge assigns, and
    /// a regex over it would admit a neighbour nobody meant to trust.
    pub bots: Vec<String>,
    /// The manifests this lane owns, as globs. A PR touching none of them is
    /// refused rather than given an invented row.
    pub owned_manifests: Vec<String>,
    /// The hidden marker that ties a mirror issue to the pull request it was
    /// filed for.
    ///
    /// A comment rather than a label or a title convention: it survives an edit,
    /// it is invisible rendered, and it is what makes `ensure` idempotent across
    /// the window where the row exists and the PR body does not yet name it.
    pub marker_prefix: String,
    /// What the tracker's own sync leaves on the issue once it has mirrored it.
    /// The key is read from a comment carrying this, never from the issue body —
    /// that body is this lane's own text, so a key named there would be one we
    /// wrote rather than one the tracker assigned.
    pub linkback_marker: String,
    /// The tracker's key prefix, which a key is this followed by digits.
    ///
    /// The consumer's vocabulary, exactly as the Ready grammar's `[[pattern]]`
    /// rows are: a tracker's key shape in `crates/batten` is non-negotiable rule
    /// 1's violation.
    pub key_prefix: String,
    /// The branch prefix a bot receipt may be keyed to. A branch outside it is
    /// refused onto the agent claim receipt, which attests something else.
    pub branch_prefix: String,
    /// The path of the file whose text is the derived row's body, with
    /// `{{...}}` placeholders substituted.
    ///
    /// A tracked file rather than a string in the config: the body is a page of
    /// consumer prose carrying a Ready block, and a page of markdown inside a
    /// TOML value is unreviewable. It is also what keeps `ready-lint`'s grammar
    /// and the text it judges in one place a human edits.
    pub body_template: String,
}

// ---- `commit` (CLOUD-2789: moved from `commit`, which re-exports it) ----

/// The `[commit]` table: what a commit subject must look like here.
///
/// Consumer-specific by nature (non-negotiable rule 1): the engine holds the
/// matcher, this table holds the answer. Which type words a repository admits,
/// and whether it requires a scope, are that repository's business.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Commit {
    /// The regular expression every non-merge commit's subject must match.
    ///
    /// Required when the table is present: a `[commit]` declaring no pattern is
    /// the half-change rule 2 refuses — it reads as though a convention is
    /// recorded when nothing is.
    pub subject_pattern: String,
    /// Whether every commit in a judged RANGE must name the tracker row it
    /// serves, and which commits are exempt (CLOUD-843).
    ///
    /// Absent is the reading every consumer had before: a range is judged for
    /// its subjects and nothing else. Present, `commit check <base>..<head>`
    /// refuses a commit whose message claims no row — see [`judge_claims`].
    #[serde(default)]
    pub claims: Option<Claims>,
}

/// The `[commit.claims]` table: every commit names the row it serves (CLOUD-843).
///
/// # The server-side half of a claim
///
/// A claim receipt lives in the clone's own git directory and never leaves it,
/// so no reviewer and no workflow can see it. What a server CAN see is whether
/// each commit names the issue it serves — the half of the claim that survives a
/// fresh checkout (CLOUD-431). This repository's `commit-lint` task asked that in
/// shell, one `claim keys` spawn per commit; the question is this table's now,
/// asked in process over the range `commit check` already walks.
///
/// "Names a row" is `claim keys`' own reading of the WHOLE message — a closing
/// keyword first, then the first key of each `Refs:` trailer — through the
/// consumer's `[[pattern]]` grammar, never a key shape spelled here (rule 1).
/// Claiming is stricter than mentioning: a commit citing a row as evidence has
/// not thereby become work on it (CLOUD-338/CLOUD-378).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Claims {
    /// The commits that owe no claim, each a property of the COMMIT rather than
    /// of its wording: which paths it touched, and who authored it.
    ///
    /// Empty by default. An exemption keyed to the file set cannot be claimed by
    /// a hand-written commit that merely borrows a release's subject, which is why
    /// the subject is not a column here.
    #[serde(default)]
    pub unclaimed: Vec<Unclaimed>,
}

// ---- `census` (CLOUD-2789: moved from `census`, which re-exports it) ----

/// The `[census]` table: the measurements a consumer declares over its own tree.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct Census {
    /// Where this repository writes shell, for `batten census shell`. Absent
    /// means the census has nothing declared to read, which the verb refuses
    /// rather than reporting a zero it did not measure.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shell: Option<ShellCensus>,
}

/// `[census.shell]`: the homes shell may live in, and the files that must stay
/// shell.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct ShellCensus {
    /// Manifests whose command strings are counted, one row per file.
    #[serde(default, rename = "manifest", skip_serializing_if = "Vec::is_empty")]
    pub manifests: Vec<Manifest>,
    /// Workflow files whose `run:` steps are counted, as globs over tracked paths.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub workflows: Vec<String>,
    /// Paths that must stay shell because nothing else can run where they do, as
    /// globs. Still measured, reported apart, and never totalled.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exempt: Vec<String>,
}

// ---- `budget` (CLOUD-2789: moved from `budget`, which re-exports it) ----

/// The `[budget]` table: **named** file sets and what each may cost.
///
/// A map, not a struct with a field per set. The set name is the *consumer's*
/// — `[budget.instructions]` is this repository's name for its always-loaded
/// context, and an engine type carrying that name would be a consumer-specific
/// identifier in `crates/batten` (non-negotiable rule 1). A second consumer
/// budgeting a different surface declares `[budget.<their-name>]` and needs no
/// engine change; before this it needed a new field.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(transparent)]
pub struct Budget(pub BTreeMap<String, BudgetSet>);

/// One `[budget.<name>]` table.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BudgetSet {
    /// The counted file set, as globs over repo-relative `/`-separated paths.
    /// Every entry must match at least one file — see the module docs. Defaulted
    /// because a set may count only `embedded` entries; the two being empty
    /// *together* is what `measure` refuses.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub files: Vec<String>,
    /// The ceiling on estimated tokens over the whole set. The boundary is
    /// `<=`: exactly at budget passes.
    pub max_tokens: usize,
    /// The optional ceiling on loaded lines, the second predicate the shell gate
    /// this replaces carried. Absent means unenforced — a threshold nobody
    /// declared is not a threshold of zero.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_lines: Option<usize>,
    /// The optional ceiling on ONE file's loaded bytes (CLOUD-1934).
    ///
    /// **A different question from `max_tokens`, not a finer one.** The total
    /// bounds what a set costs when all of it loads, which is the right question
    /// for an always-loaded surface. A file that is read ON DEMAND, one call at a
    /// time, costs nothing until it is read and then fails whole if it is larger
    /// than one read can return — so its ceiling is per file, and a set total can
    /// be comfortably under budget while every read of its largest member fails.
    ///
    /// Bytes rather than estimated tokens because the ceiling it stands for is
    /// MEASURED in bytes: the largest file a host returned whole. Absent means
    /// unenforced, and the boundary is `<=` like every other one here.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_bytes_per_file: Option<usize>,
    /// Always-loaded strings carried *inside* a config file rather than in a
    /// file of their own. Empty by default: a repository with no such surface
    /// declares nothing (CLOUD-298).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub embedded: Vec<EmbeddedDecl>,
}

// ---- `capture` (CLOUD-2789: moved from `capture`, which re-exports it) ----

/// The bound on response captures (CLOUD-918).
///
/// Enforced **at write time**, and the trigger is the write — never a clock,
/// never a schedule, never a background sweeper. That is
/// `rules/toolchain.md`'s split between a gate and a schedule, and
/// [`prune`]'s own doc already refuses a time-based sweeper on the same grounds.
#[derive(
    Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
#[serde(deny_unknown_fields)]
pub struct CaptureConfig {
    /// Total response-capture bytes the store may hold. Absent means the default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_bytes: Option<u64>,
    /// Response-capture records the store may hold. Absent means the default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_records: Option<u64>,
    /// The payload size at which a rendered response switches from carrying the
    /// bytes to carrying an address (CLOUD-1367).
    ///
    /// **An ECONOMIC threshold and nothing else.** A payload at or under it is
    /// cheaper to send than an address plus the round trip to resolve one; over
    /// it, the address wins. Absent means [`DEFAULT_INLINE_MAX_BYTES`].
    ///
    /// It is deliberately NOT a privacy or safety cap. Those refuse to emit
    /// content at all and are their own rows; this one only ever changes the
    /// REPRESENTATION, and both routes carry the same semantic result. Reusing
    /// one number for both would mean a measurement about token cost silently
    /// deciding what may leave the process.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inline_max_bytes: Option<u64>,
    /// The `o200k` token count over which ANY tool's result reaches the model as
    /// a pointer to its stored view rather than as its text (CLOUD-2223).
    /// Absent means [`DEFAULT_RESULT_MAX_TOKENS`].
    ///
    /// Tokens, because the window is spent in tokens: a byte or line count is a
    /// proxy that is 3-4x out on code and worse on dense text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result_max_tokens: Option<u64>,
}

// ---- `exec` (CLOUD-2789: moved from `exec`, which re-exports it) ----

/// The `[exec]` table: how `batten exec` owns what it dispatched.
///
/// One key today, and it is an opt-in rather than a tuning knob. `false` is not
/// a conservative default chosen for taste — it is the *only* value that leaves
/// the process topology byte-for-byte what it was, which is what an existing
/// consumer's orchestrator is already built against.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ExecConfig {
    /// Whether Batten may put a dispatched command in its own process group and
    /// take responsibility for tearing that group down.
    ///
    /// Declared rather than inferred, because the residual case is not
    /// observable: an orchestrator two levels up intending to `kill(-pgid)` looks
    /// exactly like one that is not. Even when this is `true`, Batten still
    /// declines whenever mise's own two rules say an ancestor is already
    /// managing — see [`GroupDecision`].
    #[serde(default)]
    pub manage_process_group: bool,
    /// Whether the child's bytes are copied onto Batten's own streams.
    ///
    /// `false` is the CLOUD-429 default and the whole point: the bytes are
    /// already stored, content-addressed and addressable, so printing them again
    /// charges the caller a second time for output the engine has. `--tee`
    /// restores the old behaviour verbatim.
    #[serde(default)]
    pub tee: bool,
    /// How Batten's own record is encoded (hk's axis).
    #[serde(default)]
    pub format: OutputFormat,
    /// How a teed child's bytes are presented, and whose output is suppressed
    /// (mise's axis).
    #[serde(default)]
    pub style: OutputStyle,
    /// How many of a `:::` bundle's commands run at once — mise's `--jobs`.
    ///
    /// `1` by default, which is stricter than mise's own default and chosen
    /// rather than inherited: a bundle's commands share one working tree, and
    /// widening concurrency a caller did not ask for is how two of them start
    /// writing the same file. Zero is read as one.
    #[serde(default = "one")]
    pub jobs: usize,
    /// Whether a bundle keeps going past a command that failed — mise's
    /// `--continue-on-error`.
    #[serde(default)]
    pub continue_on_error: bool,
    /// Echo the child's PROGRESS lines to stderr even when its bytes are not
    /// teed (#1276): `stage <step> ran|hit <s>` and the mutant sweep's per-row
    /// and schema lines ([`is_progress_line`]). A stored gate log is a pointer
    /// at its end (CLOUD-2223), so without this a lap that ran for an hour said
    /// nothing about which stage it was in. Never configuration: a caller's
    /// own choice, so it is skipped by serde and absent from the schema.
    #[serde(skip)]
    #[schemars(skip)]
    pub progress: ExecProgress,
}

/// hk's format axis, adopted rather than invented.
///
/// `hk/src/structured_output.rs` already spells these three for a tool that
/// reports on child processes, and a caller who knows hk must not have to learn
/// a second vocabulary to read Batten. The names are hk's; what they range over
/// is Batten's own record.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize, JsonSchema, clap::ValueEnum,
)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum OutputFormat {
    /// Pointer lines, one per fact.
    #[default]
    Human,
    /// One JSON document.
    Json,
    /// One JSON record per line.
    Jsonl,
}

/// mise's style axis, adopted rather than invented.
///
/// `mise/src/task/task_output.rs` spells these seven, and its `style_only()`
/// separates the stream *style* from the *suppression* of the tool's own
/// metadata — a distinction Batten needs and would otherwise have conflated into
/// one key. [`OutputStyle::style_only`] is that function, by that name.
///
/// **With one command in flight, `prefix`, `replacing` and `timed` render
/// alike.** They are still accepted, because adopting half a vocabulary is how a
/// caller learns that Batten's version of a name means something else; what
/// distinguishes them is a bundle of concurrent children, which is CLOUD-430's
/// subject and not this one's.
///
/// **`timed` emits no wall-clock field, and that is the byte-stability answer**
/// §6 demands rather than a limitation. A duration in Batten's own output would
/// make the same run print differently twice, and [`crate::capture`] already
/// refuses a timestamp for exactly that reason.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize, JsonSchema, clap::ValueEnum,
)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum OutputStyle {
    /// Each line carries the child's program name.
    Prefix,
    /// The child's bytes, verbatim and as they arrive.
    #[default]
    Interleave,
    /// Each stream whole, in a fixed order, after the child exits.
    KeepOrder,
    /// As [`OutputStyle::Prefix`]: redrawing in place needs a terminal Batten
    /// never assumes it has.
    Replacing,
    /// As [`OutputStyle::Prefix`], minus the clock — see the type's docs.
    Timed,
    /// Batten says nothing of its own; the child still speaks.
    Quiet,
    /// Nobody speaks.
    Silent,
}

/// Whether a stream that is not teed still echoes its progress lines
/// ([`ExecConfig::progress`]).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ExecProgress {
    /// Nothing but what the tee setting shows.
    #[default]
    Silent,
    /// Each [`is_progress_line`] reaches stderr as it arrives.
    Echo,
}

// ---- `mcp` (CLOUD-2789: moved from `mcp`, which re-exports it) ----

/// The `[mcp]` table: where the wiring lives, and what to return instead of a
/// payload.
#[derive(
    Debug, Clone, Default, PartialEq, Eq, serde::Deserialize, serde::Serialize, schemars::JsonSchema,
)]
#[serde(deny_unknown_fields)]
pub struct McpConfig {
    /// Where a harness keeps its MCP wiring, in precedence order.
    ///
    /// A LIST rather than one row because one repository is worked in from
    /// several harnesses, and each keeps its wiring somewhere else. The first row
    /// that resolves a server wins, so the order is a statement about which
    /// harness to believe when two are installed.
    #[serde(default, rename = "source", skip_serializing_if = "Vec::is_empty")]
    pub sources: Vec<McpSource>,
    /// What to return instead of a method's full response.
    ///
    /// A method with no row here is dispatched and returned whole.
    #[serde(default, rename = "result", skip_serializing_if = "Vec::is_empty")]
    pub results: Vec<ResultRow>,
    /// Server names whose committed permission rules apply under WHATEVER key the
    /// host exposes the server as this session (CLOUD-191, CLOUD-843).
    ///
    /// Each is a name some `[[mcp.source]]` row's `endpoint_contains` declares,
    /// because the endpoint is the only thing that identifies a renamed server:
    /// `mcp grant` finds the exposed key's endpoint, matches it to one of these
    /// names, and applies the committed `permissions` rules written for that name.
    /// `mcp posture` reads the same list for the grants a connector would still
    /// prompt for.
    ///
    /// **A LIST, and deliberately not every `endpoint_contains` name.** A name here
    /// turns a committed allow rule into a pre-approval under a key nobody
    /// committed. A server the host authorises at its own connector layer must not
    /// be translated, or the translation grants what the host did not — so the
    /// consumer states which servers its permission file governs, rather than the
    /// engine inferring it from a selector written for dispatch.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub permission_aliases: Vec<String>,
}

/// One `[[mcp.result]]` row: what to hand back instead of a method's response.
#[derive(
    Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize, schemars::JsonSchema,
)]
#[serde(deny_unknown_fields)]
pub struct ResultRow {
    /// The method this row reduces. The consumer's vocabulary, matched exactly.
    pub method: String,
    /// What to make of the response.
    pub reduce: Reduce,
    /// The fields kept, in the order they are written.
    ///
    /// Top-level keys of the payload the row's `node` reaches. A declared field
    /// the payload does not carry is ABSENT from the reduction rather than
    /// present and null: "the row does not have this" and "the reduction dropped
    /// it" are different answers.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fields: Vec<String>,
    /// Where the payload sits inside the JSON-RPC result, in [`Node::at`]'s
    /// spelling. An empty string is the result itself.
    ///
    /// Declared rather than known, because how a server frames a payload is the
    /// server's business and this crate holds no opinion about it.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub node: String,
    /// Whether the node's scalar text is itself a document to parse.
    ///
    /// A server that frames its payload as text carrying JSON is common and is
    /// not something the engine may assume: a row says so, and a row that says so
    /// wrongly gets could-not-look rather than a reduction over the wrong tree.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub embedded: bool,
}

/// One `[[mcp.source]]` row: a file that carries a server's transport, endpoint
/// and headers.
///
/// The shape is [`crate::facts::Rooted`]'s deliberately — same three-part bound,
/// same reason — with a `node` because a wiring file holds every server the
/// harness knows and the row has to say which subtree is the server map.
#[derive(
    Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize, schemars::JsonSchema,
)]
#[serde(deny_unknown_fields)]
pub struct McpSource {
    /// The key this source is named by in a report.
    ///
    /// The id and never the resolved path: a resolved path is a machine's home
    /// directory, and non-negotiable rule 4 keeps one out of every finding.
    pub id: String,
    /// The NAME of the environment variable holding the directory `path`
    /// resolves beneath, or absent for a path relative to the repository root.
    ///
    /// A name, never a value, and never a directory this crate knows. Unset or
    /// empty on this machine is could-not-look, never an absent file: "this host
    /// does not have that root" and "the file is not there" are different
    /// answers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root: Option<String>,
    /// A base this crate knows how to name without an operator's help.
    ///
    /// Mutually exclusive with `root`, and refused at load if both appear. Absent
    /// with `root` absent is the repository root, exactly as before.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base: Option<Base>,
    /// The path beneath that root.
    ///
    /// Relative and downward — an absolute path or a `..` component is refused at
    /// load, so a declaration cannot walk back out of the root it named.
    ///
    /// # `${VAR}` expands, and that is what makes a per-session file nameable
    ///
    /// A launcher that mints its wiring per session writes it under a name
    /// carrying the session id, so the FILENAME is not writable in advance even
    /// where the directory is. A row spells the id where it appears:
    ///
    /// ```text
    /// path = "mcp-config-${CLAUDE_CODE_REMOTE_SESSION_ID}.json"
    /// ```
    ///
    /// **Expansion is not a glob, and the difference is the whole reason this is
    /// allowed where a glob was declined (CLOUD-1251).** A glob's three fatal
    /// objections were that the match count is not one, that the engine would have
    /// to walk a filesystem, and that a row's id cannot be authored for a name
    /// that does not exist yet. Expansion has none of them: the result is exactly
    /// one path, the engine expands a variable rather than looking around, and the
    /// id is the row's own. `[[rule.external]]`'s discipline is unchanged — *the
    /// engine expands a variable; it does not scan*.
    ///
    /// Only `${NAME}` is a placeholder. A bare `$NAME` is a literal, because a
    /// path is allowed to contain a `$` and guessing where such a name ends is how
    /// one spelling becomes two.
    pub path: String,
    /// Where the server map sits inside the parsed document, in [`Node::at`]'s
    /// spelling. An empty string is the document itself.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub node: String,
    /// Server names this source resolves by ENDPOINT rather than by map key.
    ///
    /// Keyed by the name a caller types, valued by a substring the entry's
    /// endpoint must carry.
    ///
    /// **A launcher that mints its server key per registration episode leaves
    /// that key unwritable in advance** (CLOUD-1264). CLOUD-178 measured one
    /// connector exposed as three different tool prefixes across episodes;
    /// [`crate::rules::selects_tool_name`] absorbs that for a RULE, by matching a
    /// `__`-delimited segment. Dispatch has no such analogue — the key IS the
    /// name — so a row naming one episode's key resolves nothing in the next, and
    /// a remedy citing it is a command that cannot run. Measured 2026-09-02: the
    /// same connector was keyed `Linear` in one container and by a UUID in
    /// another, at the same address.
    ///
    /// The ADDRESS is what does not move, which is why the selector is over the
    /// endpoint and not over anything else the entry carries.
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub endpoint_contains: std::collections::BTreeMap<String, String>,
    /// The credential this source's servers authenticate with, if they need one.
    ///
    /// **Absent is the default and it is byte-identical to no credential at all**
    /// — a wiring file whose headers already authenticate needs nothing here, and
    /// adding this key must not change what such a source does.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential: Option<McpCredential>,
}

// ---- `judge` (CLOUD-2789: moved from `judge`, which re-exports it) ----

/// The `[judge]` table: what the judge may put in a model call.
///
/// Every field defaults to the refusing reading, so a `[judge]` table that
/// merely exists sends nothing but pointers and hashes.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Judge {
    /// The content classes admitted **raw** into a model call. Empty — the
    /// default — means pointer-only: no span bytes cross at all.
    ///
    /// A class named here is admitted and nothing else is. There is deliberately
    /// no "all" spelling: a config that wants both classes names both, so the
    /// diff that widens the boundary shows what it widened.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub raw: Vec<PayloadClass>,
    /// The ceiling on assembled payload bytes. Absent means
    /// [`DEFAULT_MAX_PAYLOAD_BYTES`].
    ///
    /// There is deliberately **no** key for what happens over the `protected`
    /// set: one protected member refuses the invocation, full stop. See the
    /// module docs for why that key was removed rather than defaulted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_payload_bytes: Option<usize>,
    /// The judge command, as a template. The first whitespace-separated token is
    /// a program on the operator's `PATH`, **executed directly and never through
    /// a shell** — so this is data a reviewer can read, not a script.
    ///
    /// Absent is legal on its own: a `[judge]` table predates the judge that
    /// reads it (CLOUD-135 landed first), and a repository that declared a
    /// boundary and no command must keep loading. It is a judge **row** that
    /// cannot resolve without one — see [`argv`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run: Option<String>,
    /// The model the operator's command should use, substituted into [`Judge::run`]
    /// at each `{{model}}` placeholder.
    ///
    /// **Opaque to the engine**: never parsed, never validated against a list,
    /// never used to decide anything. Batten has no opinion about which model a
    /// consumer judges with, and a build that shipped a roster would be stating
    /// one — plus going stale (non-negotiable rule 1: the fact is the consumer's).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
}

/// A class of content that could cross into a model call.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum PayloadClass {
    /// The bytes of one matched span.
    SpanText,
    /// The bytes of a whole file.
    FileText,
}

// ---- `wiring` (CLOUD-2789: moved from `wiring`, which re-exports it) ----

/// The `[wiring]` table: what this consumer's launcher re-arms every spawn.
#[derive(
    Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct Wiring {
    /// The declared scripts, in the order the config lists them.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub disarm: Vec<Disarm>,
}

/// One declared script to neutralise.
///
/// Both fields are the consumer's: this module names no script and no marker
/// (non-negotiable rule 1). A path here is a launcher's artifact name, which is
/// precisely what may not appear in `crates/batten`.
#[derive(
    Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct Disarm {
    /// The script, relative to the home directory.
    ///
    /// **Under `$HOME` and nowhere else**, enforced by [`Wiring::validate`] at
    /// load. A shim over a tracked path would be this repair mutating the tree it
    /// is supposed to be judging, and an absolute path is how that would be
    /// written — so the refusal is at parse time, where `config lint` names the
    /// key, rather than at the write, where it would already have happened.
    pub path: String,
    /// The comment the shim carries, and the whole of how a second pass knows
    /// its own work.
    ///
    /// Idempotence rides on this: a body containing the marker is left BYTE for
    /// byte, so running the verb twice writes once. Reading the file's length, or
    /// its mtime, or whether it merely looks short would each be a proxy that
    /// drifts; the marker is the consumer's own declared token and cannot.
    pub marker: String,
}

// ---- `prune` (CLOUD-2789: moved from `prune`, which re-exports it) ----

/// The `[prune]` table: the build tree, what to keep, and the collector's band.
///
/// CONSUMER CONFIG, NOT A CONST (non-negotiable rule 1): which directory a
/// project builds into and how much free space its builds need are facts about
/// THAT project.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Prune {
    /// The build directory, relative to the repository root.
    #[serde(default = "default_root")]
    pub root: String,
    /// Copies retained per stem. See the module header for why this is 2.
    ///
    /// The bound is in the SCHEMA as well as in [`Prune::validate`] (raised on
    /// #734): an editor validating against the published schema is the surface
    /// most consumers meet first.
    #[serde(default = "default_keep")]
    #[schemars(range(min = 1))]
    pub keep: usize,
    /// RETIRED (CLOUD-2198): the warm floor. Read and ignored, so a config
    /// written for the floor model still loads while its pin moves; the
    /// collector's band ([`Prune::min_free_mb`]) replaces it.
    #[serde(default, skip_serializing)]
    pub warm: Option<serde_json::Value>,
    /// RETIRED (CLOUD-2198): the cold floor. Read and ignored, as `warm`.
    #[serde(default, skip_serializing)]
    pub cold: Option<serde_json::Value>,
    /// RETIRED (CLOUD-2198): the escalation's regrowable roots. Read and
    /// ignored, as `warm`: the collector never drops a cache whole.
    #[serde(default, skip_serializing)]
    pub regrowable: Option<serde_json::Value>,
    /// Below this much free space, in MB, the disk collector runs (CLOUD-2197):
    /// on every mediated call, and throughout `land` and `mutate sweep`. Nix's
    /// `min-free`. Declared with [`Prune::max_free_mb`] or not at all; absent,
    /// the collector runs at [`DEFAULT_FREE_BAND`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_free_mb: Option<u64>,
    /// Once triggered, the collector frees space until this much is free, in
    /// MB, then stops. Nix's `max-free`; above [`Prune::min_free_mb`], so the
    /// pair is a hysteresis band rather than a threshold that re-fires at once.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_free_mb: Option<u64>,
}

pub fn default_root() -> String {
    String::from("target")
}

// ---- `sbom` (CLOUD-2789: moved from `sbom`, which re-exports it) ----

/// The `[sbom]` table (CLOUD-843).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(rename = "SbomDeclared")]
#[non_exhaustive]
pub struct SbomDeclared {
    /// The subject's name: the documents' source name, and the stem both the
    /// tree's documents and a binary's asset are named from.
    pub subject: String,
    /// Where the tree's two documents are written, relative to the repository
    /// root unless absolute.
    pub out_dir: String,
    /// Where a binary's asset is written, relative to the repository root unless
    /// absolute.
    pub binary_out_dir: String,
    /// Paths the tree scan skips, passed to the scanner verbatim.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exclude: Vec<String>,
    /// The pinned-actions licence table, repository-relative. Absent skips the
    /// actions pass; declared and unreadable is could-not-look.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actions: Option<String>,
    /// The `[[rule.tools]]` row `--record` keys its reduction under.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inventory: Option<String>,
    /// What `--conformance` runs and where it records.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conformance: Option<Conformance>,
}

/// The `[sbom.conformance]` table.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(rename = "SbomConformance")]
#[non_exhaustive]
pub struct Conformance {
    /// The record family the checker's answers are written under.
    pub record: String,
    /// The checker program, run as `<checker> <document> --comply <standard>
    /// --output json --output-file <report>`.
    pub checker: String,
    /// The standards asked, in order. Never empty.
    pub standards: Vec<String>,
}

// ---- `record` (CLOUD-2789: moved from `record`, which re-exports it) ----

/// One family a producer writes through [`run_named`], declared by the consumer
/// (CLOUD-1810).
///
/// # The gap this closes, and why neither existing surface could
///
/// [`run_named`] writes a branch-keyed store, and until this existed nothing
/// could read one. [`crate::rules`]' projection builds the set of families it
/// hands a module as the declared [`crate::recorder::Declared`] rows unioned with
/// [`VERB_WRITTEN`], and a caller-named family is in neither:
///
/// - [`VERB_WRITTEN`] is a fixed list because the ENGINE owns both halves of
///   those three stores. A consumer's family cannot join it without this crate
///   knowing a consumer's name, which non-negotiable rule 1 forbids outright.
/// - A `[[recorder]]` cannot express one either: [`crate::recorder::Declared`]
///   requires `tool`, because that table selects on a mediated tool call. A
///   family a `mise` task writes answers to no tool call at all.
///
/// So the store was written, the row was registered, the module read
/// `input.tree.records["<family>"]` — and the key was absent, every rule beneath
/// it undefined, and the gate green. Measured over `branch-age`: a record naming
/// a 36-day branch against a two-day threshold, `batten check` exit `0`. That is
/// CLOUD-1707's dead gate one surface over.
///
/// # Declared rather than swept, which is the whole design
///
/// The projection could have read whatever files happen to sit in the store
/// directory. It must not, for the reason [`crate::rules`] already gives about a
/// sibling fact: a family set cannot become an ambient sweep of whatever records
/// happen to be on disk, because then a leftover file from a retired producer
/// answers as a live measurement and nothing names what SHOULD be there.
///
/// A declaration is also what makes could-not-look readable. An absent record
/// under a DECLARED family is "the producer did not run"; the same absence under
/// no declaration is not a reading at all, and collapsing the two is the error in
/// the fact model this whole store exists to avoid.
///
/// # Config rather than a column on the rule that reads it
///
/// [`crate::rules`] settles this at its own call site: the fact is what THIS
/// repository's producers accumulated, so a per-rule declaration would be a
/// second place for the same answer to live. Two rules reading one family is
/// ordinary; two rules disagreeing about what writes it is not expressible.
#[derive(
    Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize, schemars::JsonSchema,
)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct RecordDeclared {
    /// The family name, which is also its file name under the store.
    ///
    /// Held to [`safe_component`]'s grammar at validation rather than at write
    /// time alone, so a family that could never be written is refused while its
    /// author is watching instead of on the first producer run.
    pub record: String,
    /// What writes it, as a runnable command.
    ///
    /// **Never executed, and that is not a gap.** House style §5 keeps the spawn
    /// outside `check`, so this is a pointer — the job `[[verdict.route]]`'s
    /// `target` already does. What it buys is that a declared family always says
    /// who fills it: a store with no producer is a row that can only ever read
    /// could-not-look, and the moment to catch that is at config load rather than
    /// after a green run nobody questions.
    pub writer: String,
}

// ---- `redirect` (CLOUD-2789: moved from `redirect`, which re-exports it) ----

/// One declared path class and the mutation sanctioned for it.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Redirect {
    /// The path class this redirect speaks for, in the engine's one glob
    /// dialect.
    ///
    /// Deliberately independent of `protected`: this table answers "what should
    /// they run instead", never "is this guarded". A glob here matching a path
    /// no `protected` entry covers simply never comes up, which is the harmless
    /// direction — the alternative, deriving protection from a redirect, is the
    /// set-collapsing CLOUD-37 exists to prevent.
    pub glob: String,
    /// The sanctioned mutation for that class — the "run this instead" a deny
    /// carries.
    pub mutation: String,
    /// The sanctioned READ for that class, and the whole of the read-side gate
    /// (CLOUD-1258).
    ///
    /// # Why a read is gated at all
    ///
    /// `no-tool-substitution` is `kind = "pipeline"` and decides over shell
    /// argv, so a structured-tool call is invisible to it; `protected` crossed
    /// with `[[verb]]` enumerates MUTATIONS, and CLOUD-442's port states "reads
    /// stay allowed". So a generic file read of a memory was gated by nothing,
    /// measured 2026-08-31 with the Serena server healthy and `read_memory`
    /// loadable. That is not a style preference: a path read couples the caller
    /// to the tree layout, and CLOUD-868 proposes moving that tree — `read_memory`
    /// survives the move and a hardcoded path does not, so every flat-path read
    /// is an unmigrated call site against it.
    ///
    /// # OPTIONAL, AND THE ABSENCE IS THE "SESSION DOES NOT OFFER IT" ARM
    ///
    /// The row demands that the gate allow where the tool is not available,
    /// because a redirect naming a tool the session does not carry is CLOUD-998's
    /// defect one layer over. The boundary cannot see whether an MCP server is
    /// healthy — that is not a fact any mediated payload carries — so the
    /// question is answered where it IS decidable: the consumer declares the
    /// read remedy, and a consumer without the tool declares none and is refused
    /// nothing. The remedy is therefore a string its own author wrote, which is
    /// the strongest available guarantee that it names something reachable.
    ///
    /// A row with no `read` key gates nothing on the read side and keeps its
    /// mutation half exactly as before.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub read: Option<String>,
    /// The MCP server whose tool `read` names (CLOUD-2229).
    ///
    /// Declared, the read is refused only where some `[[mcp.source]]` resolves
    /// this server, which is the question `batten mcp call` answers before it
    /// dispatches. Measured on #1132: in a cloud session no source resolved
    /// `serena`, so the refusal named a route the session could not take and
    /// every memory read was refused outright. Absent, `read` refuses as before.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub read_server: Option<String>,
}

// ---- `outputs` (CLOUD-2789: moved from `outputs`, which re-exports it) ----

/// One declared output predicate: a literal that must not appear.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OutputPattern {
    /// The stable identifier a match is reported under.
    ///
    /// Required, and it is what keeps the report pointer-only: a finding names
    /// `stream:line` plus this id, never the line that matched. Without an id the
    /// only way to say *which* pattern fired would be to echo the bytes.
    pub id: String,
    /// The case-sensitive literal that must not appear in the watched stream.
    pub pattern: String,
    /// Which stream to watch. Defaults to both.
    #[serde(default)]
    pub stream: Watched,
    /// What the caller should do about it.
    ///
    /// Required, unlike on a file rule. A file finding is a `path:line` a reader
    /// can open; a promoted exit code is all a caller gets back, so a refusal
    /// naming only its id would be un-actionable (CLOUD-122).
    pub reason: String,
}

/// Which captured stream a pattern is matched against.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum Watched {
    /// The child's standard output only.
    Stdout,
    /// The child's standard error only.
    Stderr,
    /// Both streams.
    ///
    /// The default, and deliberately the *widest* reading: a tool that moves a
    /// warning from one stream to the other between releases would otherwise
    /// silently stop being gated, and a pattern that quietly matches nothing is
    /// the failure this whole feature exists to prevent.
    #[default]
    Both,
}

// ---- `provision` (CLOUD-2789: moved from `provision`, which re-exports it) ----

/// How a credential is proved usable, declared by the consumer.
///
/// **One field, and the control credential is NOT one of them.** A caller does
/// not get to choose what "known bad" means: the engine sends a syntactically
/// plausible token that must be refused, because a consumer that could name it
/// could name one the route happens to accept and turn the control arm into a
/// rubber stamp.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CredentialProbe {
    /// The endpoint that answers 2xx for a good credential and refuses a bad
    /// one.
    ///
    /// It must be a route the fence sends DIRECT. Pointed at one an intercepting
    /// proxy carries, the control arm fails — the junk credential is accepted —
    /// and the engine reports could-not-look rather than pretending to a verdict
    /// it cannot reach.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub probe_url: Option<String>,
    /// The variables a session credential may arrive under, most specific first.
    ///
    /// **Declared here rather than listed in the engine, which is non-negotiable
    /// rule 1.** It was two GitHub-shaped literals in `crates/batten` for one
    /// commit, and a consumer on another forge — or on a host that injects under
    /// a third name — has neither: every candidate is then absent,
    /// [`credential_health`] answers [`Credential::Unusable`], and every removal
    /// is silently skipped forever. That failure is INVISIBLE, because skipping
    /// a removal is also the correct behaviour when a credential is genuinely
    /// bad, so the dead path and the working path look identical from outside.
    ///
    /// Which names belong here is a judgement only the consumer can make. A host
    /// may inject a substitutable placeholder under the forge's conventional
    /// names, so probing those would measure the host's credential rather than
    /// one we hold — the exact conflation this mechanism exists to undo, and the
    /// reason this list is deliberately not "every variable that looks like a
    /// token". Naming none is could-not-look, not health: it authorises nothing.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub names: Vec<String>,
}

/// The `jobs` default, as a function because `serde` needs one.
pub const fn one() -> usize {
    1
}

pub const fn default_keep() -> usize {
    2
}

/// One class of commit that owes no claim.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Unclaimed {
    /// The row's name, for a reader of the config — never printed per commit.
    pub id: String,
    /// A regular expression EVERY path the commit changed must match. A commit
    /// that changed nothing matches vacuously, as the retired shell's filter did.
    pub paths: String,
    /// When set, the commit's AUTHOR address — git's `%ae` — must match this too.
    ///
    /// The author rather than the committer, because a forge commits an App's work
    /// as itself and only the author half names which App wrote it.
    #[serde(default)]
    pub author: Option<String>,
}

/// One manifest whose command strings are counted.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct Manifest {
    /// The manifest's repo-relative path.
    pub path: String,
    /// The keys whose values are commands, as they are spelled before ` = `.
    pub keys: Vec<String>,
    /// The header prefix that opens one named unit — a task table, say. Every
    /// shell line between one such header and the next is that unit's. Absent,
    /// each shell line is reported on its own.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unit: Option<String>,
}

/// One `[[budget.<name>.embedded]]` entry: a string inside a config file that a
/// host loads on every session.
///
/// Both fields are the **consumer's**. A host that always injects a key from its
/// own config — Serena's project file, an editor's workspace settings — is a
/// property of the repository using that host, not of Batten, so naming either
/// one in `crates/batten` would be the consumer-specific identifier
/// non-negotiable rule 1 forbids. The engine knows only "parse this file, read
/// this key, count the string".
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EmbeddedDecl {
    /// The repo-relative, `/`-separated path of the config file to read. A
    /// literal path and never a glob: a key is read from one document, and a
    /// pattern would leave "which file's key" unanswered.
    pub path: String,
    /// The key whose string value is counted. Dotted for a nested key
    /// (`a.b.c`); the engine walks maps only, so a key under a sequence is a
    /// miss rather than a guess.
    pub key: String,
}

/// How a [`ResultRow`] turns a response into something rule 4 permits.
///
/// A closed set rather than an expression language, for
/// [`crate::facts::Reduction`]'s reason exactly: every member is bounded by
/// construction, so no row can declare a reduction that yields the payload back.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize, serde::Serialize, schemars::JsonSchema,
)]
#[serde(rename_all = "lowercase")]
pub enum Reduce {
    /// The declared fields, with their values passed through as the payload
    /// carries them.
    ///
    /// The read-side answer. What bounds it is the DECLARATION — a field nobody
    /// named never leaves the store — so a consumer choosing its own field set is
    /// choosing its own cost.
    Project,
    /// The declared fields, each held to a bounded SCALAR.
    ///
    /// The write-side answer (CLOUD-1122), and it differs from [`Reduce::Project`]
    /// in KIND rather than in degree: a field whose value runs past [`TOKEN_MAX`],
    /// or is a container rather than a scalar, is **absent** rather than
    /// truncated, because a prefix of somebody's issue body is still their issue
    /// body. So this arm structurally cannot echo a body however the row is
    /// written, where `project` leaves that to the declaration.
    ///
    /// # Why the bound is length and not [`crate::facts::Reduction::Token`]'s
    ///
    /// That reduction additionally refuses any value carrying whitespace, and it
    /// is right to: its product reaches the POLICY INPUT, where a module could
    /// lift a sentence into a `subjects` pointer, so "is this already a token"
    /// is the question worth asking. This arm's product reaches the CALLER, and
    /// the thing being kept out is a 15k-character description — which the length
    /// bound stops on its own.
    ///
    /// Copying the whitespace clause across was this row's own near-miss,
    /// measured before it shipped: `save_issue` answers `status = "In Progress"`,
    /// so the arm would have silently dropped the one field CLOUD-1122 names in
    /// its remedy — `{id, status, handle}` — while every test still passed. A
    /// bound borrowed from a surface with a different threat model is how a
    /// reduction quietly stops answering the question it was built for.
    Acknowledge,
    /// [`Reduce::Project`], applied to EVERY element of an array node.
    ///
    /// The list-side answer (CLOUD-1380). The other two arms do one flat
    /// field-pick against the node a row names, so a response whose payload is an
    /// array of objects is unreducible by either: naming the array as `node` makes
    /// every field lookup miss, and leaving `node` at the root keeps the array
    /// whole and reduces nothing. Measured before this arm existed, a
    /// `list_issues` call reported `undeclared` and **emitted 20,366 bytes against
    /// 17,313 stored** — more out than in, because an undeclared result is handed
    /// back re-serialised rather than reduced.
    ///
    /// `node` names the array and the declared `fields` are read from each
    /// element, so one row describes both halves and no second field vocabulary
    /// appears. The projected elements come back under the array's own key, which
    /// is what lets a consumer read the reduction by the path it reads the
    /// response by.
    ///
    /// # Its bound is a different KIND from the other two, stated rather than
    /// absorbed
    ///
    /// `project` and `acknowledge` are bounded by the DECLARATION alone: a field
    /// nobody named never leaves the store, so the reduction's size is fixed
    /// whatever the payload holds. This arm is bounded per element by the
    /// declaration and **in count by the page the caller asked for** — a function
    /// of the request rather than of the response. That is weaker than the other
    /// two, and it is the enum's contract met rather than dodged: no row can
    /// declare a reduction that yields the payload back, but a caller asking for a
    /// thousand rows does get a thousand projected rows.
    ///
    /// Which is why the scalar siblings are carried and containers are not:
    /// `hasNextPage` and `cursor` are what make the page size a thing the caller
    /// controls, so dropping them would leave paging unanswerable — the reduction
    /// would satisfy every size predicate by destroying the one mechanism that
    /// bounds it. A container sibling is refused for [`Reduce::Acknowledge`]'s
    /// reason exactly: a shape whose size the caller did not bound.
    Each,
}

/// A directory the crate can name on its own, for a source whose file does not
/// live under the repository or under a directory an operator exports.
///
/// A closed set of ONE, deliberately. Every member has to be a location the
/// platform itself defines, because the alternative is this crate learning a
/// harness's layout — non-negotiable rule 1's violation — and because a member
/// nobody can predict is a scan wearing an enum's clothes.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize, serde::Serialize, schemars::JsonSchema,
)]
#[serde(rename_all = "lowercase")]
pub enum Base {
    /// The OS temporary directory, as the platform defines it.
    ///
    /// **Named rather than spelled `/tmp`**, which is what keeps it portable and
    /// keeps a literal path out of a config. It is where a launcher that mints a
    /// per-session file puts it, and the one location an operator has no variable
    /// for — `TMPDIR` is unset on a great many hosts, so a row naming it as a
    /// `root` silently does not resolve there.
    Temp,
}

/// One `[mcp.source.credential]` table: WHICH credential a source spends, never
/// the credential (CLOUD-1261).
///
/// # The whole point is the indirection
///
/// `batten.toml` is committed, so a value here would be a secret in git. What a
/// row carries is a **name**: the name of an environment variable, or the name of
/// an environment variable whose value is a path. That is `[[rule.external]]`'s
/// root discipline applied to key material — *the engine expands a variable; it
/// does not scan* — and it is what lets a public config say "this server needs
/// the operator's token" without saying what the token is.
///
/// # Every resolved value is a [`Secret`], which has no route to a `String`
///
/// The negative half is the load-bearing one, so it is enforced by type rather
/// than by remembering to redact: [`Secret`] has no `Display`, its `Debug` prints
/// a fixed marker, and the only thing that consumes it is the header list handed
/// to the transport. A failure path cannot render it because there is no method
/// that would.
#[derive(
    Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize, schemars::JsonSchema,
)]
#[serde(deny_unknown_fields)]
pub struct McpCredential {
    /// The header the credential is sent in.
    ///
    /// Declared rather than assumed: `Authorization` is the common answer and the
    /// default, but a session-scoped endpoint may want its own name, and guessing
    /// one produces a 401 that says nothing about why.
    #[serde(default = "authorization")]
    pub header: String,
    /// The scheme prefixed to the value, space-separated. Empty sends the value
    /// alone, which is what a bare token header wants.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub scheme: String,
    /// The NAME of an environment variable holding the credential itself.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub env: Option<String>,
    /// The NAME of an environment variable holding the PATH of a file that holds
    /// the credential.
    ///
    /// The two-hop spelling is deliberate and it is the one a harness actually
    /// offers: a launcher that mints a per-session token writes it to a file and
    /// exports the path, so the path is not writable in advance while the variable
    /// name is.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file_from: Option<String>,
    /// The NAME of a key in the server's own wiring entry whose value is a
    /// command that prints the request headers as a JSON object.
    ///
    /// Claude Code's spelling is `headersHelper`: a local `~/.claude.json` entry
    /// for an HTTP server authenticates by running it (measured 2026-10-25, the
    /// GitHub server's helper prints `{"Authorization":"Bearer …"}` from `gh auth
    /// token`), and carries no static `headers` at all, so a row with neither
    /// `env` nor `file_from` dispatched unauthenticated and got a 401. The row
    /// names the KEY, never the command: the command lives in the wiring file
    /// the source names (the operator's own, for a home-rooted source; a
    /// repo-relative source trusts that file as much as this config), and only
    /// the `header` this row names is taken from what it prints. That value is
    /// usually finished (`Bearer …`), so `scheme` stays empty for such a helper.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub helper: Option<String>,
}

/// The default header a credential is sent in.
pub fn authorization() -> String {
    "Authorization".to_owned()
}
