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
use crate::preset_catalog::RuleScope;
use crate::preset_catalog::{Applicability, RouteKind};
use crate::severity::{AdvisoryTier, RuleSeverity};
use crate::sink::Sink;
use std::collections::BTreeSet;
use std::path::Path;

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
    /// Not to be confused with [`Rule::scope`] ([`crate::preset_catalog::RuleScope`]),
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
    pub verdicts: Vec<DeclaredVerdict>,
    /// The three positional word lists every class and route name is drawn from
    /// (CLOUD-1284), and the tokenizer pin they were measured under.
    ///
    /// A **dictionary rather than a per-class essay**: a name spends three words
    /// and each word's meaning is declared once, so the marginal class costs no
    /// new prose. `verdict::validate` holds every name to it, which is what makes
    /// the naming convention a gate rather than a habit.
    #[serde(default, skip_serializing_if = "Vocabulary::is_empty")]
    pub vocabulary: Vocabulary,
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
    pub mints: Vec<MintDeclared>,
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
    pub recorders: Vec<RecorderDeclared>,
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
    pub programs: BTreeMap<String, Program>,
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
    pub waivers: Vec<Waiver>,
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
    pub refusal: Option<Ceiling>,
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
    pub hook: Option<HookConfig>,
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
    pub startup: Vec<Startup>,
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
    pub provisions: Vec<Provision>,
    /// The completed-session transcript this repository points `check` at
    /// (CLOUD-95). Host-specific, never consumer-specific: which file a host
    /// writes its transcript to is a property of the harness, not of any one
    /// repository, so rule 1 holds. Absent means the repository does not use
    /// the capability — a different claim from a path that resolves to
    /// nothing, which is why `resolve` answers with three states and not two.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transcript: Option<TranscriptConfig>,
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
    pub attribution: Option<Attribution>,
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

impl Config {
    #[must_use]
    pub fn declaring_nothing() -> Self {
        Config {
            credential: None,
            forge: None,
            unresolvable: Vec::new(),
            records: Vec::new(),
            version: SUPPORTED_VERSION,
            deferrals: Vec::new(),
            host: None,
            min_batten_version: None,
            engine: None,
            // Declaring nothing declares no landing path set, which the reader
            // takes as could-not-look — the same direction every other absent
            // table here takes.
            lease: None,
            receipt: None,
            strictness: None,
            fail_on_warning: None,
            update_notice: None,
            rules: Vec::new(),
            patterns: Vec::new(),
            traversals: Vec::new(),
            registers: Vec::new(),
            verdicts: Vec::new(),
            vocabulary: crate::config_model::Vocabulary::default(),
            scope: Vec::new(),
            protected: Vec::new(),
            // Declaring nothing means declaring no threshold either, which the
            // reader takes as could-not-look and exempts everything — the same
            // direction every other field here grants.
            ready: None,
            board: None,
            // Declaring nothing accepts no regression, which is also the safe
            // reading: an authority that cannot be read must not exempt a path.
            perf: None,
            // Declaring nothing enforces no gate. `batten mutate` then reads the
            // environment alone and refuses when that is empty too, so an
            // unreadable authority cannot become a sweep over nothing.
            mutate: None,
            // No protected paths means the unknown-program clause has nothing to
            // guard, so an empty reader set costs nothing here and is the honest
            // value: a config declaring nothing declares no readers either.
            protected_readers: Vec::new(),
            unlanded: Vec::new(),
            contract: None,
            epoch: None,
            verbs: Vec::new(),
            redirects: Vec::new(),
            facts: Vec::new(),
            mints: Vec::new(),
            recorders: Vec::new(),
            programs: BTreeMap::new(),
            markers: Vec::new(),
            exec: None,
            mcp: None,
            capture: None,
            exec_patterns: Vec::new(),
            // No declared classifier means every gate refusal reads as being
            // about the tree, which is the advice that was always given and is
            // right in the common case — the safe direction for an authority
            // that could not be read.
            verify_environment_patterns: Vec::new(),
            waivers: Vec::new(),
            // An authority that declares no budget grants no exemption from one
            // either — there is simply no threshold, which is what `None` says.
            budget: None,
            refusal: None,
            advisory: None,
            outcome: Vec::new(),
            hook_output: None,
            must_land_on: None,
            landed_by: None,
            // An authority that cannot be read attaches no side effects. The
            // safe direction is unambiguous here: firing a command an
            // unreadable config might have declared is the one outcome nobody
            // could justify.
            hook: None,
            judge: None,
            // Declaring no ceiling is not declaring a ceiling of zero: the audit
            // falls back to the engine default, so an unreadable authority
            // withholds no gate here — it only fails to tighten one.
            design: None,
            ci: None,
            // No `[prune]` is no build tree named and no floor declared, which is
            // exactly what an unreadable authority grants: the verb reports that
            // nothing was asked for rather than inventing a number about somebody
            // else's target directory.
            prune: None,
            task: None,
            defects: None,
            provisions: Vec::new(),
            // Declaring no container preconditions is the ordinary case: a
            // project that states none has nothing for `batten startup` to
            // decide, which is a different thing from one whose checks all pass.
            startup: Vec::new(),
            // Declaring no transcript is the ordinary case, and it is not the
            // same as pointing at one that is missing: the first says the
            // capability was never claimed, the second that it was claimed and
            // is unavailable. Only the second is worth reporting.
            transcript: None,
            // Declaring no drain pacing is "no opinion", which resolves to the
            // engine's defaults — NOT "do not drain". The asymmetry with the
            // keys above is deliberate: those are policy this authority grants,
            // and an authority granting nothing must grant nothing, where this
            // is pacing for a surface that runs regardless. An authority that
            // cannot be read still has a drain; it simply has no view on how
            // often it speaks.
            drain: None,

            // An authority that declares no attribution policy grants no
            // exemption from one: there is simply nothing to judge by, and the
            // gate says so (exit 1) rather than passing over commits it never
            // read.
            attribution: None,
            // And no commit convention: absent is "no rule was declared", which
            // the gate answers 1 to rather than waving commits through.
            commit: None,
            bot_lane: None,
            // An authority that cannot be read grants no permission to answer
            // from a pin either. The default is the strict one, and an absent
            // authority must not be the way to reach the lenient one.
            trust: None,
            // An authority declaring no scripts disarms none. Absent is the
            // honest empty here rather than a conservative default with teeth:
            // the engine cannot know what a launcher on this host writes, and
            // guessing a path would be exactly the consumer identifier rule 1
            // keeps out.
            wiring: None,
            // An authority declaring no census declares nowhere shell lives; the
            // verb says so rather than counting a tree it was told nothing about.
            census: None,
            // No subject declared, so `batten sbom` has nothing to name.
            sbom: None,
            // An authority declaring no steps keys no receipt: every `batten step`
            // call is a miss that runs the step and records nothing, which is the
            // cache off rather than a cache answering for anything.
            steps: Vec::new(),
        }
    }
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
    /// Let a session with `BATTEN_STATE_REPO` set but no access to that
    /// repository proceed unattached (CLOUD-2939). Without it, a set variable
    /// means the session is meant to share the branch's receipts, so a session
    /// that cannot read the state repository is held until it is attached; with
    /// it, the session runs every step from its own receipts and says so. A
    /// developer without access is never blocked: this is their route.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub state_repo_optional: bool,
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

impl Unresolvable {
    #[must_use]
    pub fn line(&self) -> String {
        match &self.unit {
            Unit::Row { id: Some(id), .. } => format!("{} {id}", self.section),
            Unit::Row { id: None, index } => format!("{} #{index}", self.section),
            Unit::Key(key) => format!("{}.{key}", self.section),
        }
    }
    #[must_use]
    pub fn row_index(&self) -> Option<usize> {
        match self.unit {
            Unit::Row { index, .. } => Some(index),
            Unit::Key(_) => None,
        }
    }
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

impl Defects {
    /// Refuse a `[defects]` table naming no path.
    ///
    /// # Errors
    ///
    /// A usage error when `path` is empty or whitespace.
    pub fn validate(&self) -> Result<()> {
        if self.path.trim().is_empty() {
            return Err(UsageError::raise(
                "defects.path: names no file; a ledger with no path is not a ledger".to_owned(),
            ));
        }
        if self.classes.is_empty() {
            return Err(UsageError::raise(
                "defects.classes: declares no class; every record would be refused, which is a \
                 table that cannot be used rather than one that permits nothing"
                    .to_owned(),
            ));
        }
        let unique: BTreeSet<&String> = self.classes.iter().collect();
        if unique.len() != self.classes.len() {
            return Err(UsageError::raise(
                "defects.classes: contains a duplicate".to_owned(),
            ));
        }
        Ok(())
    }
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

impl Marker {
    pub(crate) fn selects(&self, path: &str) -> bool {
        self.glob
            .as_ref()
            .is_none_or(|glob| crate::selector::glob_match(glob, path))
    }
}

impl Marker {
    pub(crate) fn validate(&self) -> Result<()> {
        if self.id.is_empty() {
            return Err(UsageError::raise("marker: `id` must not be empty"));
        }
        if self.token.is_empty() {
            return Err(UsageError::raise(format!(
                "marker {}: `token` must not be empty; an empty token matches every line",
                self.id
            )));
        }
        if self.glob.as_deref() == Some("") {
            return Err(UsageError::raise(format!(
                "marker {}: `glob` must not be empty; omit the key to scan the whole tree",
                self.id
            )));
        }
        Ok(())
    }
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
    ///
    /// LEGACY (CLOUD-2628): a non-empty list with no `mode` reads as
    /// `mode = "migrate"` with these paths exempt, exactly as before the ban
    /// judged presence. Removing that reading is CLOUD-2745's.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exempt: Vec<String>,
    /// How the `shell-hygiene` ban judges this tree. Absent is presence: any
    /// shell no `generated` entry covers is refused. `migrate` judges growth
    /// only, while a repository ports what it has.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<ShellMode>,
    /// The only shell the presence ban admits: files a named generator writes
    /// and a named test holds, one row per glob.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub generated: Vec<Generated>,
    /// The only shell engine source may spawn (CLOUD-2770): one row per
    /// function whose string-literal argv runs a shell because an external
    /// format forces it. Held in both directions, whatever `mode` says.
    #[serde(default, rename = "spawn", skip_serializing_if = "Vec::is_empty")]
    pub spawns: Vec<Spawn>,
}

/// One `[[census.shell.spawn]]` row: an engine function that spawns a shell,
/// and the external contract that forces it to.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct Spawn {
    /// The source file, repo-relative.
    pub path: String,
    /// The function holding the spawn, by its name. Optional to the parser so
    /// that the census's validation is what refuses its absence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub function: Option<String>,
    /// The external format that makes the argv a shell command line, with a
    /// citation (a URL). Optional to the parser so that the census's
    /// validation is what refuses its absence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contract: Option<String>,
}

impl ShellCensus {
    /// The effective mode: migrating when `mode = "migrate"` is declared or a
    /// legacy `exempt` list is non-empty, presence otherwise. `exempt = []` is
    /// the same as absent, so it is presence.
    #[must_use]
    pub fn migrating(&self) -> bool {
        self.mode == Some(ShellMode::Migrate) || !self.exempt.is_empty()
    }
}

/// `[census.shell] mode`: the one knob between presence and growth.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum ShellMode {
    /// Presence is not judged; the growth arms refuse new shell and shell that
    /// grows, so the existing surface may only shrink.
    Migrate,
}

/// One `[[census.shell.generated]]` row: shell a generator writes and a test
/// holds.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct Generated {
    /// The generated files, as a glob over tracked paths (`*`, `?`, `**`).
    pub path: String,
    /// The command or function that writes them, as free text. Optional to the
    /// parser so that the census validation is what refuses its absence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub generator: Option<String>,
    /// The test that holds their bytes, as `<test file>::<test name>`. Optional
    /// to the parser so that the census validation is what refuses it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub check: Option<String>,
}

/// A `check` value split into its file and its test name, when it has the
/// `<test file>::<test name>` shape: both halves non-empty and free of
/// whitespace.
#[must_use]
pub fn check_parts(check: &str) -> Option<(&str, &str)> {
    let (file, name) = check.split_once("::")?;
    let bare = |part: &str| !part.is_empty() && !part.chars().any(char::is_whitespace);
    (bare(file) && bare(name)).then_some((file, name))
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

impl Budget {
    pub fn sets(&self) -> impl Iterator<Item = (&String, &BudgetSet)> {
        self.0.iter()
    }
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

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
    /// teed (#1276): `stage <step> ran|hit <s>`, a graph node's verdict
    /// `step graph: ok|red <group> <id> <exit> <secs> <pointer>` (CLOUD-2838),
    /// and the mutant sweep's per-row and schema lines ([`is_progress_line`]).
    /// A stored gate log is a pointer
    /// at its end (CLOUD-2223), so without this a lap that ran for an hour said
    /// nothing about which stage it was in. Never configuration: a caller's
    /// own choice, so it is skipped by serde and absent from the schema.
    #[serde(skip)]
    #[schemars(skip)]
    pub progress: ExecProgress,
}

impl ExecConfig {
    pub const DEFAULT: Self = Self {
        manage_process_group: false,
        tee: false,
        format: OutputFormat::Human,
        style: OutputStyle::Interleave,
        jobs: 1,
        continue_on_error: false,
        progress: ExecProgress::Silent,
    };
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

impl OutputStyle {
    pub(crate) fn style_only(self) -> Self {
        match self {
            OutputStyle::Quiet | OutputStyle::Silent => OutputStyle::Interleave,
            other => other,
        }
    }
    pub(crate) fn suppresses_batten(self) -> bool {
        matches!(self, OutputStyle::Quiet | OutputStyle::Silent)
    }
    pub(crate) fn suppresses_child(self) -> bool {
        matches!(self, OutputStyle::Silent)
    }
}

/// Whether a stream that is not teed still echoes its progress lines
/// ([`ExecConfig::progress`]).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ExecProgress {
    /// Nothing but what the tee setting shows.
    #[default]
    Silent,
    /// Each [`is_progress_line`] — a stage's line, a graph node's `step graph:`
    /// verdict, a mutant sweep's line — reaches stderr as it arrives.
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
    /// [`crate::facts::selects_tool_name`] absorbs that for a RULE, by matching a
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

impl PayloadClass {
    pub const ALL: &'static [PayloadClass] = &[PayloadClass::SpanText, PayloadClass::FileText];
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            PayloadClass::SpanText => "span_text",
            PayloadClass::FileText => "file_text",
        }
    }
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

impl Wiring {
    /// Refuse a malformed `[wiring]` table.
    ///
    /// # Errors
    ///
    /// The reason, when a `disarm` row is malformed.
    pub fn validate(&self) -> Result<(), String> {
        for row in &self.disarm {
            if row.path.is_empty() {
                return Err("[[wiring.disarm]]: `path` is empty, so it names no script".to_owned());
            }
            let path = Path::new(&row.path);
            // A root is the refusal, not absoluteness: on Windows `\x` has a root
            // and is still relative, yet it escapes `$HOME`, and every absolute
            // path has one too. A drive-relative `C:x` has neither and still
            // passes here (CLOUD-2472).
            if path.has_root() {
                return Err(format!(
                    "[[wiring.disarm]]: `path` {:?} is absolute — a declared script is relative to \
                     the home directory, because a shim over a tracked file would be a mutation of \
                     the tree",
                    row.path
                ));
            }
            if path
                .components()
                .any(|part| matches!(part, std::path::Component::ParentDir))
            {
                return Err(format!(
                    "[[wiring.disarm]]: `path` {:?} climbs out of the home directory with `..`",
                    row.path
                ));
            }
            // A blank marker matches every body, so the first pass would report
            // `shimmed` over a file it never touched — the false green this whole
            // module is built to refuse, one table over.
            if row.marker.trim().is_empty() {
                return Err(format!(
                    "[[wiring.disarm]]: `marker` for {:?} is blank, so no body could carry it",
                    row.path
                ));
            }
        }
        Ok(())
    }
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
    /// Compiler-cache directories, relative to the repository root, that a
    /// pass empties before it touches any cargo unit (CLOUD-2907): oldest file
    /// first, until the pass has freed what it needs or the caches are empty.
    /// A cache is an accelerator, never the authority, so a reclaimed entry is
    /// a miss the next build refills by compiling. No default: the core names
    /// no cache tool.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub caches: Vec<String>,
}

#[must_use]
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
/// hands a module as the declared [`RecorderDeclared`] rows unioned with
/// [`VERB_WRITTEN`], and a caller-named family is in neither:
///
/// - [`VERB_WRITTEN`] is a fixed list because the ENGINE owns both halves of
///   those three stores. A consumer's family cannot join it without this crate
///   knowing a consumer's name, which non-negotiable rule 1 forbids outright.
/// - A `[[recorder]]` cannot express one either: [`RecorderDeclared`]
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
#[must_use]
pub const fn one() -> usize {
    1
}

#[must_use]
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
    /// The carrier whose fields this manifest's commands are, by its id in
    /// `shell_logic::CARRIERS` (`mise-task` or `hk-step`, the two with a
    /// manifest reader). Exactly one of `carrier` and `keys` (CLOUD-2627).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub carrier: Option<String>,
    /// The keys whose values are commands, as they are spelled before ` = `,
    /// for a manifest no carrier describes. Exactly one of `carrier` and
    /// `keys`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub keys: Vec<String>,
    /// The header prefix that opens one named unit — a task table, say. Every
    /// shell line between one such header and the next is that unit's. Absent,
    /// each shell line is reported on its own.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unit: Option<String>,
}

/// The carriers a manifest row may name: the ones the census has a manifest
/// reader for. Every other `shell_logic::CARRIERS` row is cited data only.
pub(crate) const MANIFEST_CARRIERS: [&crate::shell_logic::Carrier; 2] =
    [&crate::shell_logic::MISE_TASK, &crate::shell_logic::HK_STEP];

impl Manifest {
    /// The carrier this row names, when it names one the census reads.
    #[must_use]
    pub fn carrier(&self) -> Option<&'static crate::shell_logic::Carrier> {
        manifest_carrier(self.carrier.as_deref()?)
    }

    /// The command fields: the carrier's, or the row's own `keys`.
    #[must_use]
    pub fn fields(&self) -> Vec<String> {
        match self.carrier() {
            Some(carrier) => carrier.fields.iter().map(|&f| f.to_owned()).collect(),
            None => self.keys.clone(),
        }
    }
}

/// A manifest-readable carrier by id.
pub(crate) fn manifest_carrier(id: &str) -> Option<&'static crate::shell_logic::Carrier> {
    MANIFEST_CARRIERS
        .iter()
        .copied()
        .find(|carrier| carrier.id == id)
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
#[must_use]
pub fn authorization() -> String {
    "Authorization".to_owned()
}

/// One reference-to-path rewrite for a [`CeilingUnit::TrackedArtifacts`] ceiling
/// (CLOUD-925).
///
/// Both fields are the **consumer's**. A shorthand a repository writes in its own
/// prompts to name its own files is a property of that repository, so naming
/// either half in `crates/batten` would be the consumer-specific identifier
/// non-negotiable rule 1 forbids — the same split
/// [`crate::config_model::EmbeddedDecl`] already makes for a config key it counts.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Rewrite {
    /// The reference shape, as a regular expression over one candidate token.
    /// Capture groups are available to `path`.
    pub reference: String,
    /// The repository-relative path the reference names, with `$1`-style
    /// references to `reference`'s capture groups.
    pub path: String,
}

/// What a [`Rule::max`] ceiling counts over its declared projection (CLOUD-925).
///
/// Two units rather than one, because `fanout-guard`'s two conjuncts measure the
/// same bytes and differ in the *subject* of the cap: the prompt's own size, and
/// how many tracked artifacts it names. A single unit would have forced one of
/// them into a second rule kind.
///
/// **The unit cannot be inferred from the projection**, which is why this is a
/// column rather than a derivation: one prompt has both a token count and a
/// manifest count, and a row has to say which one it is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum CeilingUnit {
    /// Estimated tokens over the projection, via [`crate::budget::estimate_tokens`].
    ///
    /// **The same estimator the file-set budget uses**, not a second one: CLOUD-925
    /// §1 requires one authority for what a ceiling is, so a per-call cap must not
    /// arrive with its own arithmetic. `free` — the bytes are already decoded.
    Tokens,
    /// How many **tracked** repository artifacts the projection names.
    ///
    /// The reading manifest: path-shaped tokens intersected with the tracked set,
    /// plus resolvable memory references. Tracked is the whole of it — a spawn
    /// naming a path this repository does not carry is naming nothing it can be
    /// made to read, so it does not count, and a URL or a branch name drops out
    /// by construction rather than by an allowlist somebody has to tune.
    ///
    /// **This unit is the one that acquires.** It needs the tracked set, which is
    /// a property of a checkout and not of the envelope, so it is resolved at the
    /// boundary and reaches [`crate::hook::adjudicate`] as a fact — never opened
    /// from inside the decision, which stays pure.
    TrackedArtifacts,
    /// How many attributes in a Rust file escape the lint [`Rule::pattern`]
    /// names: each `#[expect(..)]` or `#[allow(..)]` whose list carries it, read
    /// off the parsed syntax tree by [`crate::codemod::lint_escapes`] (#1276).
    ///
    /// **A RATCHET'S FILE MEASURE, never a call ceiling.** Counted over a glob
    /// against a base, it makes an inventory of escapes (a spawn census) a
    /// number that may only fall: whatever `main` carries is the baseline, so
    /// no site needs approving, and a branch that adds one has to retire one.
    LintEscapes,
}

/// An event a call raises, which the engine resolves on every route it knows
/// (CLOUD-2662). A row names the event, never the routes: `gh pr ready`, a
/// non-draft `gh pr create`, a reopen, the ready mutation through `gh api`, and
/// the forge connector's create and undraft all raise `pull-request-ready`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum CallEvent {
    /// A call that can leave a pull request open and not a draft.
    PullRequestReady,
}

/// The kind of predicate a [`Rule`] applies to its matched files.
///
/// Serialized as a lowercase `kind = "..."` token in `batten.toml`. Marked
/// `#[non_exhaustive]` because the engine is designed to grow kinds (the dynamic
/// `command` kind is CLOUD-89) without that being a breaking change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum RuleKind {
    /// A static banned shape, one line at a time. Every line of a matched file
    /// that carries the banned shape is a finding, unless `exclude` takes it
    /// back out. The check is inspection-only.
    ///
    /// The shape is either the literal `pattern` or the expression `regex` —
    /// exactly one, never both (CLOUD-283). The literal is the common case and
    /// the readable one; the expression is for a predicate that genuinely is a
    /// shape, such as a flag cluster judged by its letters.
    Forbid,
    /// A dynamic check: run the `check` template and treat its exit code as the
    /// predicate — `0` passes, non-zero is a violation. The sanctioned escape
    /// hatch for rules no static shape can express.
    ///
    /// The kind carries house style §9's **`check`/`fix` duality**: `check` is
    /// the inspection-only gate and the only side enforcement ever runs, `fix`
    /// is the optional mutating half. The duality is a contract with the config
    /// author that Batten cannot verify — an arbitrary command declared as a
    /// check may still write — so it governs how a rule is *authored* and never
    /// licenses the verb that runs it to claim `read`.
    ///
    /// It is an **exit-code predicate, not a judge** (CLOUD-93): the command's
    /// output is never parsed for meaning. Because it executes a process
    /// declared in `batten.toml`, it runs only on the non-`read` surface (§5,
    /// CLOUD-170).
    Command,
    /// A banned **command shape**: the mediated call `batten hook` is
    /// adjudicating matches `pattern` read as an effective program plus the
    /// adjacent words that must follow it.
    ///
    /// Distinct from [`RuleKind::Command`], which *runs* a declared command.
    /// This one runs nothing — it is a string match over a command line the
    /// host handed us, so it cannot spawn and stays on the read-safe surface.
    Shape,
    /// A **count that may only move one way** (CLOUD-55): the total occurrences
    /// of `pattern` across files matching `glob`, compared between a base rev
    /// and the working tree, must not move in the banned `direction`.
    ///
    /// The counted shape is `pattern` or `regex`, exactly one, as for
    /// [`RuleKind::Forbid`]. The expression is for a token one literal cannot
    /// spell: an attribute is counted wherever it is indented and in every form
    /// it takes, while a prose mention of it is not (CLOUD-2059).
    ///
    /// The kind exists because the property worth gating on a test suite is not
    /// immutability — tests are edited every day, so a protected path would
    /// block writing them — but *direction of change*. That is the same shape
    /// `trust.rs` already encodes for config: which way is weakening is a
    /// property of the key.
    ///
    /// Counted in **aggregate per rule**, never per file: a test moved between
    /// two files matching the glob changes nothing, so renames and
    /// consolidations that preserve the suite are clean with no rename tracking.
    /// The price is that the finding names counts rather than locations, and
    /// `git diff` answers *where*.
    Ratchet,
    /// A mediated call that requires a **verification receipt** to be valid
    /// before it is allowed (CLOUD-312, over CLOUD-203's receipt store).
    ///
    /// Distinct from [`RuleKind::Shape`], which refuses a command outright:
    /// this one refuses a command *whose precondition has not been proved*, and
    /// the same command is allowed the moment the receipt exists. The predicate
    /// is [`crate::receipt::validity`] — already total and fail-closed — so this
    /// kind adds a trigger and a refusal, never a second opinion about what a
    /// valid receipt is.
    ///
    /// The verdicts are resolved at the hook's boundary and handed to the
    /// adjudicator as data, because adjudication is contractually pure. That is
    /// the same split the bypass hatch already uses.
    Receipt,
    /// A mediated call whose **exit status is discarded by the structure it sits
    /// in** (CLOUD-443).
    ///
    /// Distinct from [`RuleKind::Shape`] by what it reads, not by severity. A
    /// shape row matches a program and its adjacent words; this one is about what
    /// SURROUNDS the command — what its status is handed to (a pipe), what
    /// replaces it (a following `;` or `||` element), and whether it was detached
    /// (`nohup`, a trailing `&`). Those are properties of the operators between
    /// segments, which the parser used to discard, so no amount of word matching
    /// could express them.
    ///
    /// Every shape it denies **fails green** — exit 0 with plausible output —
    /// which is why noticing them repeatedly did not stop them. `&&` is
    /// deliberately not among them: it short-circuits, so a failure still
    /// propagates and there is no false green to refuse.
    ///
    /// The row carries the two tables the predicate is defined over: which
    /// programs are verdict-bearing (`verdict`) and which stages substitute
    /// output for status (`filters`). Both are the consumer's — one repository's
    /// build command is another's irrelevance — so the crate names neither.
    Pipeline,
    /// A **model-validated** rule (CLOUD-56): hand the row's `criteria` and the
    /// admitted classes of its matched files to the command in `[judge].run`,
    /// and read that command's exit code.
    ///
    /// The kind exists for the predicates no static shape can express — "this
    /// test asserts behaviour, not a tautology" — and it is the one kind whose
    /// outcome is **advisory-only and structurally unable to block** (house
    /// style §0.3; the 2026-08-07 evidence base measured model judges at AUROC
    /// ≤0.65 on false-success detection, so a judge verdict may inform and never
    /// gate).
    ///
    /// "Structurally" is literal, and it is why this variant looks unfinished
    /// next to the others: a judge outcome **never becomes a [`Finding`]**.
    /// `run_rule` cannot produce one — the row is `allow`, which that walker
    /// already skips — so [`any_blocking`] and `--fail-on-warning` have nothing
    /// to see. Blocking is not forbidden here, it is unrepresentable.
    ///
    /// Distinct from [`RuleKind::Command`], which also runs something and reads
    /// an exit code: that one is an *exit-code predicate* whose command is a
    /// gate, and its findings deny. This one's command consults a model, and its
    /// findings advise. The gate/judge line (CLOUD-93) is exactly this pair.
    Judge,
    /// A **credential in the tree** (CLOUD-59): run the pinned secret scanner
    /// over the matched paths and turn each match into a pointer.
    ///
    /// The kind exists because [`RuleKind::Forbid`] bans literals named in
    /// advance, and a credential is the banned shape nobody can enumerate — so a
    /// committed secret passes every other gate this engine has. Detection is
    /// adopted prior art; what this kind owns is **containment**, in
    /// [`crate::secrets`].
    ///
    /// Distinct from [`RuleKind::Command`], which could run the same binary and
    /// could not express this: a command rule's contract is the exit code alone,
    /// with both child streams nulled, so it yields one batch verdict per glob —
    /// no per-secret `path:line`, no per-secret identity, and nothing to key.
    /// Reading the scanner's output is precisely what makes this kind different,
    /// and precisely what makes it dangerous: the scanner prints the byte it
    /// matched. Every span is opaque from the parse boundary onward
    /// ([`crate::identity::SecretSpan`]), and [`Finding`] has no field one could
    /// occupy, so pointer-only output is structural rather than a property of
    /// the renderer.
    Secrets,
    /// Address a node in a structured document and compare it to a literal
    /// (CLOUD-772).
    ///
    /// The kind that turns a parsed document into policy. It reads a file the
    /// `glob` selects, parses it as the declared `format`, walks to `node`, and
    /// reports when the value there is not `pattern`. What it never does is name
    /// an artifact: `format` and `node` are the consumer's, so a rule over a
    /// workflow file and a rule over a package manifest are the same code
    /// (non-negotiable rule 1).
    ///
    /// Three-valued (CLOUD-757), which is the whole reason it exists. A file
    /// that does not parse is **could not look** and is reported, never silently
    /// clean — an extraction that returns nothing reading as agreement is the
    /// live failure mode of every hand-rolled reader this replaces.
    Document,
    /// A **registered policy module** evaluated over the resolved fact set
    /// (CLOUD-647, CLOUD-689): the module contributes denials, and decides
    /// nothing else.
    ///
    /// The kind exists because the rule table is a flat loop — no row consumes
    /// another's verdict — so a predicate over *relationships* between facts is
    /// not expressible as a row at all. The layer this engine is absorbing shows
    /// what that costs: 57 of 126 tasks compose over a sibling's exit code, a
    /// three-state channel that forces every consumer to re-derive the
    /// producer's structure.
    ///
    /// **Admitted to [`RuleScope::MediatedCall`], which is the whole point**, and
    /// admitted on [`Authority::Supplied`] rather than by exception. A
    /// [`RuleKind::Command`] row spawns a process that can read any file and
    /// reach the network; a module evaluated over `Facts` sees the fields the
    /// boundary resolved and acquires nothing. The fact set *is* the bound, which
    /// is why it had to exist before this kind could (CLOUD-763).
    ///
    /// **Deny-only, and that is structural.** Only the module's `deny` set is
    /// read; there is no spelling for an allow that overrides a TOML deny. That
    /// preserves §8's raise-only invariant *and* removes the allow/deny
    /// contradiction class by construction, leaving nothing for a consumer to
    /// get wrong in the direction that weakens a gate.
    ///
    /// The module is **registered**, never discovered: `module` names it in the
    /// one committed authority. §8 forbids the upward directory walk and the
    /// `conf.d` merge — that is, implicit discovery — and naming each module in
    /// the authority is the opposite of both. Globbing a policy directory would
    /// be the thing §8 refuses.
    Policy,
    /// **Every cited token resolves to a key of a declared `[[register]]`**
    /// (CLOUD-2005): the predicate a consumer otherwise hand-writes per citation
    /// shape, measured at 94.6 s for one policy row whose joins rescanned every
    /// register row per row.
    ///
    /// The join is the engine's, in [`crate::register::resolve`]: a map probe per
    /// citation, never a rescan, so the cost is linear in citations plus keys.
    /// The row's [`Rule::cites`] names the register and the citer; the citer's
    /// paths come from the row's `glob` unless it cites another register.
    ///
    /// Deny-only and pointer-only: rule id, citer `path:line` or path, and the
    /// register id. A register that could not be built is could-not-look and is
    /// reported as such, never as an empty set.
    Reference,
    /// **One of the engine's compiled mediated-call gates, enabled and graded by
    /// a row** (CLOUD-2291): [`Rule::gate`] names which.
    ///
    /// The predicate is the engine's, never the row's — the row says only
    /// whether the gate runs and at what severity. The verdict strings are the
    /// gate's own and do not change, so every route, waiver and `policy explain`
    /// that names one keeps working; the row `id` is the rule id only.
    ///
    /// **A gate with no row runs at `deny`**, and only `severity = "allow"`
    /// switches one off. A config predating the kind keeps its gates, and no
    /// added row can lower a gate it does not name; a row grading one below
    /// `deny` is a weakening `config lint` reports, and only the committed
    /// authority may carry one.
    Native,
}

/// The published schema for [`Rule::preset`]: a string constrained to the
/// **embedded** preset names (CLOUD-836 §4).
///
/// Generated from [`preset_names`] rather than written out, so
/// the schema and the binary cannot disagree about what may be enabled. A
/// hand-maintained enum here would be a second authority over the same set, and
/// the failure mode is the quiet one: an editor accepting a name the loader then
/// refuses, or refusing one it accepts.
pub(crate) fn preset_name_schema(generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
    let _ = generator;
    let names: Vec<serde_json::Value> = preset_names()
        .into_iter()
        .map(|name| serde_json::Value::String(name.to_owned()))
        .collect();
    schemars::json_schema!({
        "type": ["string", "null"],
        "enum": names,
    })
}

// Declared through `token_enum!` (CLOUD-2442). `ALL`'s order is the order the
// mediated chain runs the gates.
token_enum! {
    serde
    /// The compiled gates a [`RuleKind::Native`] row may enable (CLOUD-2291).
    #[derive(
        Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize, JsonSchema,
    )]
    #[non_exhaustive]
    pub enum NativeGate by as_str {
        /// A `git reset` that would discard commits no ref holds (CLOUD-462).
        DestructiveReset => "destructive-reset",
        /// A second copy of a one-per-clone task (CLOUD-438).
        Singleton => "singleton",
        /// A config row changed by a context that has not read its history
        /// (CLOUD-2144).
        History => "history",
        /// A `&` job nothing in the same call waits on, where the harness has a
        /// supported background option instead (CLOUD-2667).
        Detach => "detach",
        /// A mediated `git commit` whose message subject breaks
        /// `[commit].subject_pattern` (CLOUD-2683).
        CommitSubject => "commit-subject",
        /// A call that reaches a repository other than its session's home
        /// (CLOUD-2672). Opt-in: armed only where the home declares a row.
        RepositoryReach => "repository-reach",
    }
}

/// One declarative rule from `batten.toml`'s `[[rule]]` array.
///
/// `deny_unknown_fields` keeps the surface narrow (§8): a mistyped key is a hard
/// error, never a silently ignored setting that disables a gate. The struct is
/// flat rather than an enum with `#[serde(flatten)]` precisely so this guarantee
/// holds — `flatten` silently defeats `deny_unknown_fields`.
/// `severity` is required by every kind but `judge`, which is refused it
/// (CLOUD-445). The field is an `Option` so a judge row can omit it, so the
/// derived `required` list cannot carry it — and a schema that merely dropped it
/// would stop flagging the missing key on the four kinds that must have one,
/// moving a check out of the editor with nothing taking its place.
///
/// This conditional puts it back, stated once here and derived into both
/// published schemas. It mirrors [`RuleKind::requires`] and
/// [`RuleKind::permits`]; `tests::the_schema_conditional_matches_the_column_census`
/// is what keeps the two from drifting.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(extend("allOf" = serde_json::json!([{
    "if": { "properties": { "kind": { "const": "judge" } }, "required": ["kind"] },
    "then": { "not": { "required": ["severity"] } },
    "else": { "required": ["severity"] }
}])))]
// `#[non_exhaustive]` for [`crate::facts::Fact`]'s reason, one layer over: every
// declared-read family adds a COLUMN here, so `constructible_struct_adds_field`
// made each one an API break. A downstream caller constructs a `Rule` through
// serde rather than a struct literal — which is what `deny_unknown_fields` and
// the schema are for — so this closes a break nobody was using.
#[non_exhaustive]
pub struct Rule {
    /// A stable identifier for the rule, surfaced in findings so a violation
    /// points back at the policy that produced it.
    pub id: String,
    /// Which predicate to apply to the matched files.
    pub kind: RuleKind,
    /// The glob selecting which files the rule inspects, matched against
    /// repo-relative paths (`/`-separated). `**` matches any run of path
    /// segments, `*` and `?` match within a single segment.
    ///
    /// Optional at the type level and required per-kind: a file kind cannot load
    /// without it, and [`RuleKind::Shape`] — which inspects no files — rejects it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub glob: Option<String>,
    /// What a match does: `deny` fails the run, `warn` reports without failing
    /// (until `--fail-on-warning` promotes it, CLOUD-49), `allow` switches the
    /// rule off (cargo-deny's model, CLOUD-61).
    ///
    /// **Required for every kind but one**, and required *per kind* rather than
    /// by the type (CLOUD-445). Every committed rule states what a match does
    /// explicitly, with no implicit fallback — omitting the key is a usage error
    /// (exit `1`), never a silently assumed level.
    ///
    /// The exception is [`RuleKind::Judge`], which is **refused** the column: a
    /// judge verdict is advisory and must not reach the exit contract by any
    /// path, so the axis it declares instead is [`Rule::tier`]. Both halves come
    /// free from the ordinary column census — `severity` is in
    /// [`RuleKind::requires`] for the other four kinds and absent from
    /// [`RuleKind::permits`] for this one — which is why this is an `Option`
    /// rather than a required field with a loader-side exception. A type that
    /// demanded the key would make a valid judge config undeserializable, and
    /// the derived JSON Schema would flag the one row that must not carry it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub severity: Option<RuleSeverity>,
    /// Which file domain the rule evaluates over. Independent of `severity` —
    /// scope says *where* the rule looks, severity says *what a match does* —
    /// and neither key's vocabulary parses as the other's. Defaults to
    /// [`RuleScope::Tree`], the pinned per-field default.
    #[serde(default)]
    pub scope: RuleScope,
    /// The literal shape this rule bans — one meaning, two domains.
    ///
    /// For [`RuleKind::Forbid`] it is a substring banned from matched *files*.
    /// For [`RuleKind::Shape`] it is a banned *command line*: the first word is
    /// the effective program (matched after wrapper look-through) and the rest
    /// are the adjacent non-flag words that must follow it, so
    /// `pattern = "gh pr merge"` reads exactly as a reviewer would say it aloud.
    /// Required by both kinds, rejected by [`RuleKind::Command`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pattern: Option<String>,
    /// The banned shape as a regular expression — [`RuleKind::Forbid`]'s
    /// **alternative** to `pattern`, never an addition to it (CLOUD-283), and the
    /// counted token's for [`RuleKind::Ratchet`] on the same terms (CLOUD-2059).
    ///
    /// A row carries exactly one of the two, and one carrying both is a load
    /// error rather than a precedence rule nobody can read. `pattern` stays the
    /// common case because a literal is the readable one (§9); this is the
    /// escape for a predicate that genuinely is a *shape* — a flag cluster
    /// judged by its letters, where `-qxF` must count as `-q` and an enumeration
    /// of spellings rots.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub regex: Option<String>,
    /// A regex that **un**-matches: a matched line carrying it is not a finding.
    ///
    /// [`RuleKind::Forbid`] only, and regex-only with no literal twin — an
    /// exclusion is inherently shape-based, and the measured one (a whole-line
    /// comment, `^[[:space:]]*#`) cannot be written as a literal at all.
    ///
    /// Comment-awareness lives here, in the consumer's config, rather than as a
    /// `skip_comments` flag in the engine: per-language comment syntax inside
    /// `crates/batten` would break non-negotiable rule 1, and it would also be
    /// wrong — `no-conflict-markers` must still fire inside a comment. What a
    /// comment looks like is a property of a repository, not of Batten.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exclude: Option<String>,
    /// A regex over the content a write would LAND, for a
    /// [`RuleKind::Shape`] row on the mediated path (CLOUD-758).
    ///
    /// **The first content-keyed predicate on this surface.** Every write-shaped
    /// gate before it was path-keyed — it could see which file was being touched
    /// and not what would end up in it, which is CLOUD-736's reported symptom:
    /// `git rm` on a workflow refused and a `Write` of one permitted.
    ///
    /// Regex-only with no literal twin, for [`Rule::exclude`]'s reason: a
    /// predicate over file content is inherently shape-based, and an enumeration
    /// of spellings rots.
    ///
    /// **Rule 4 is the load-bearing clause.** A row here DECIDES over the
    /// content and the refusal carries this rule's id and the path — never a
    /// matched byte. The content reaches the typed predicate and stops: it is
    /// projected into the policy input as a shape and a count, so no free-form
    /// consumer message can echo it.
    ///
    /// **The predicate runs over the whole prospective content**, so a bare `^`
    /// anchors to the start of the FILE rather than of a line. A per-line
    /// predicate wants `(?m)`, and the difference is not academic: without it a
    /// row catches a marker a write puts on the first byte and misses the same
    /// marker three lines in.
    ///
    /// A tool whose shape carries no content — a shell command, an MCP call —
    /// yields [`crate::facts::Look::CouldNotLook`], and a row here does not fire
    /// on it. That is *not* the same as matching an empty file, and collapsing
    /// the two would make the row fire on every call as though it had looked.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,
    /// The tool a `mediated_call` row is **about** — matched exactly, or as a
    /// `__`-delimited suffix (CLOUD-924).
    ///
    /// **The third way to key a mediated row**, beside [`Rule::pattern`] (a
    /// command line) and [`Rule::content`] (what a write would land), and the
    /// only one a *structured* call can satisfy. `adjudicate` returns `Allow`
    /// the moment `envelope.command` is empty, and an MCP call, a `Read` and a
    /// `Task` spawn all carry an empty command — so before this column the two
    /// connector guards had nothing to retire onto, which is CLOUD-312's rows 4
    /// and 5. It reads [`crate::hook::Envelope::raw_tool`], the host's own word,
    /// and never the normalized [`Event`] (CLOUD-779's split).
    ///
    /// # Why a suffix, and why not a bare one
    ///
    /// **The suffix half is not a convenience.** A host mints the prefix of an
    /// MCP tool name and rotates it: CLOUD-665 and CLOUD-684 are the same
    /// measured failure twice, a rule naming a server label the host never
    /// registers under, matching nothing, silently. A consumer that already
    /// keyed its own hook matchers on a trailing pattern did so for exactly that
    /// reason. An exact-only selector here would rebuild the defect those two
    /// rows closed.
    ///
    /// **A bare suffix over-matches, so the delimiter is load-bearing.**
    /// `tool = "Edit"` would select `NotebookEdit`, and `tool = "Read"` any tool
    /// whose name happens to end in those bytes — a row selecting a neighbouring
    /// tool nobody named is the widening direction a policy engine may never
    /// drift in. So a match is the whole name, or the whole final `__`-delimited
    /// segment of it, which is `board-payloads`' own rule (`endswith("__get_issue")`)
    /// and carries its reasoning: MCP names are `mcp__<server>__<tool>`, and the
    /// tool is the last segment. `save_issue` therefore selects
    /// `mcp__Linear__save_issue` and `mcp__cc451d34-…__save_issue` alike, and
    /// `Edit` selects `Edit` alone.
    ///
    /// Permitted on [`RuleKind::Shape`] and [`RuleKind::Receipt`] — the kinds a
    /// row can key on a tool with no command in hand. **Not** on
    /// [`RuleKind::Pipeline`], whose predicate is the operators *between* a
    /// command's segments: a structured call has none, so the column would load,
    /// match nothing, and read as coverage.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool: Option<String>,
    /// Narrow a `mediated_call` row to a call whose named projection is
    /// **absent** (CLOUD-987).
    ///
    /// A MODIFIER, not a selector: the row still selects on its own terms —
    /// `tool` for a structured call, `pattern` for a shell one — and this decides
    /// whether that selection refuses. The same shape [`Rule::requires_key`] and
    /// [`Rule::require_via`] already carry, and it is listed in `permits` rather
    /// than `requires` for the reason `require_via` gives: a modifier that
    /// narrowed by DEFAULT would silently change every row that never asked.
    ///
    /// **It exists because the absence is the predicate.** CLOUD-312's row 1
    /// gates *creating* a tracker row and must not gate *editing* one, and the
    /// two differ only in whether the call named an id. Its own header:
    /// *"Denying an update would demand a search before every edit to an issue,
    /// which is absurd and would get the guard switched off within a day."* A row
    /// that could not say "only when this is absent" would be that guard.
    ///
    /// Absent means the projection read `None` — which for
    /// [`Field`] collapses missing, null, empty and
    /// wrong-typed, exactly as every other reader of that allowlist sees it. One
    /// definition of absence, in the decoder, rather than a second one here.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub when_absent: Option<Field>,
    /// Which projection supplies the subject for a [`ReceiptKey::Named`] receipt
    /// (CLOUD-987).
    ///
    /// Required by that key and refused without it: a `named` receipt with no
    /// projection has no subject to file under, and a receipt keyed on nothing
    /// would read the same file for every call — which is
    /// [`ReceiptKey::Branch`] wearing a different name, and the exact collapse
    /// that variant's doc refuses.
    ///
    /// A [`Field`] rather than a free-form key, for the reason the
    /// allowlist exists: the subject of a receipt is about to become a path
    /// component under `$GIT_DIR`, so which values can reach it must be a closed
    /// set somebody enumerated.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_from: Option<Field>,
    /// Which ref a [`ReceiptKey::Delta`] receipt's identity is taken against
    /// (CLOUD-1547) — the read-side twin of [`MintDeclared::key_base`].
    ///
    /// Required by that key and refused without it, and refused ON any other:
    /// the identity is a diff and a diff needs two sides, so a `delta` row with
    /// no base has no subject, and a base on a `head` row is a column the engine
    /// would silently never read.
    ///
    /// A CONSUMER's ref name, so it lives on the row rather than as a constant in
    /// the crate (non-negotiable rule 1): which branch a repository lands on is
    /// that repository's business, and `must_land_on` already answers it for a
    /// different question rather than for this one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_base: Option<String>,
    /// Narrow [`Rule::when_present`] from *the key is there* to *the key holds
    /// THIS value* (CLOUD-312 row 3).
    ///
    /// **Presence was not enough, and row 3 is the measured case.** That guard
    /// gates one transition — a move to In Review — and its header prices the
    /// alternative in the same terms row 1's does: gating every column "would
    /// demand a graph-check before every edit, which is how a guard gets switched
    /// off within a day (CLOUD-199)." A row that could only ask whether the call
    /// named a state would fire on every edit that named any, so the guard stayed
    /// bash on a column boundary rather than on a missing projection.
    ///
    /// **The comparison is normalised, and the normalisation is generic rather
    /// than a consumer's.** Case is folded and spaces, underscores and hyphens are
    /// dropped from both sides, because a tracker's state parameter accepts a
    /// type, a name or an id, so a column's three spellings are one move. What is normalised is the SHAPE of a comparison; which value matters
    /// is the consumer's and lives in their `batten.toml` (non-negotiable rule 1).
    ///
    /// It qualifies `when_present` rather than standing alone: a value with no
    /// projection names nothing to read it out of, and that is a load error.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub when_value: Option<String>,
    /// The shape a value must have to be a receipt subject at all (CLOUD-312
    /// row 2).
    ///
    /// **A projection can legitimately carry a value that names no subject, and
    /// reading one as a missing receipt is a false positive rather than a
    /// finding.** Row 2 is the measured case: the tracker's `id` parameter takes
    /// an issue key OR a UUID, the receipt namespace is keyed by key, and
    /// resolving a UUID needs a credential no hook has. The retiring guard calls
    /// that a genuine cannot-look and ALLOWS, in its own words because denying
    /// "would refuse a legitimate update over a spelling the agent is entitled to
    /// use, which is the false-positive rate that gets a guard bypassed and then
    /// enforces nothing."
    ///
    /// Without this the engine would file the UUID as a subject, find no file and
    /// deny — strictly worse than the bash it replaced, on the call the bash was
    /// careful about.
    ///
    /// So a value the shape does not match resolves the subject to **absent**,
    /// which [`crate::receipt::verdicts`] already takes to could-not-look and
    /// therefore to allow. It narrows what counts as a subject; it never denies.
    ///
    /// The expression is the CONSUMER's, because what a tracker's identifiers look
    /// like is a consumer fact (non-negotiable rule 1) — the core knows only that
    /// a subject may be shape-constrained.
    ///
    /// Compiled at load by [`Rule::validate_receipt_columns`], so a bad expression
    /// is a config error rather than a per-call surprise. That sentence was here
    /// before the check was, which is the defect review caught on #680: an
    /// unparseable expression was discarded per call and the row it qualified went
    /// quietly dead. The direction matters — the failure ALLOWED — and a comment
    /// asserting an invariant nothing enforces is what stops the next reader
    /// looking for it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_shape: Option<String>,
    /// How old a receipt for this row may be, in seconds (CLOUD-988).
    ///
    /// **Existence was the whole verdict until this column, and for CLOUD-312's
    /// row 2 existence is the wrong question.** `issue-read-guard`'s predicate is
    /// CLOUD-508's bound — not *which* row was read but *how recently* — and a
    /// receipt that merely exists answers a read of unbounded age, which is the
    /// defect that issue names. So the row declares the bound and the engine
    /// compares.
    ///
    /// **THE CLOCK IS THE BOUNDARY'S, NEVER `adjudicate`'s.** The comparison
    /// happens where the receipt is already being read — [`crate::receipt`],
    /// called from the boundary — and reaches the decision as an ordinary
    /// [`crate::receipt::Validity`], exactly as staleness does. That is the
    /// waiver table's precedent: a waiver lapses on a date, and `today()` is
    /// handed in rather than taken inside, pinned by
    /// `adjudicate_reads_no_clock_even_now_that_a_waiver_can_lapse`. This column
    /// buys a fourth `Validity` and no clock in the core.
    ///
    /// Seconds rather than a duration string, because the output contract is
    /// byte-stable and a parsed duration is a second spelling of one number.
    /// Zero is refused: a receipt that is expired the instant it is written
    /// refuses every call and reads as a bound from the file.
    ///
    /// Absent means what it always meant — existence is the verdict — so no
    /// committed row changes meaning by this column arriving.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_age: Option<u64>,
    /// What one field of the receipt must say for this row to be satisfied
    /// (CLOUD-1100).
    ///
    /// **Existence and recency are both statements about the READ, and this is
    /// the first column that is a statement about what was read.** `max_age`
    /// bounds how old the receipt is; nothing until this asked what it recorded.
    /// A Todo promotion needs the second question: a row read seconds ago and
    /// found unready must be refused, and a receipt that merely exists cannot
    /// distinguish that from a row read seconds ago and found ready.
    ///
    /// **Three-valued, and it fails OPEN.** The field says the required value ->
    /// satisfied. The field says something else -> [`crate::receipt::Validity::
    /// Refuted`], a deny. The field is **absent** — a shorter receipt, a receipt
    /// minted by the hand-run task that predates the column, a renderer that
    /// could not judge and wrote the absent token — -> satisfied, because a
    /// verdict about the environment must never be spoken as a verdict about the
    /// subject. That direction is what lets the column be added to a live receipt
    /// family without invalidating a single receipt already on disk.
    ///
    /// Positional, because the receipt body is positional by construction and
    /// that is already this repository's convention for reading one — the
    /// censused readers take field 4 and field 5 of `issue-read` today.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requires_field: Option<FieldBound>,
    /// Narrow a `mediated_call` row to a call whose named projection is
    /// **present** (CLOUD-987).
    ///
    /// [`Rule::when_absent`]'s mirror, and the pair is what makes CLOUD-312's
    /// rows 1 and 3 different rules rather than one with a flag: row 1 gates the
    /// call that named NO id, row 3 gates the call that DID name a state. Same
    /// modifier shape, opposite polarity, and neither is the default.
    ///
    /// **It exists because "moved" is a fact about the arguments.**
    /// `board-move-guard` fires only when a call moves a row between columns, and
    /// a call that merely edits one names no `state`. Without this the row would
    /// gate every edit — the same over-fire `when_absent` prevents one key over,
    /// and the reason both directions had to land together.
    ///
    /// Present means the projection read `Some` — one definition of presence, in
    /// the decoder, shared with `when_absent` so the two cannot disagree about
    /// what `state: ""` means.
    ///
    /// A row may carry both, over different projections: row 3 wants *a state was
    /// named* and, in principle, *an id was named*. Carrying both over the SAME
    /// projection is refused at load, because it can never fire.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub when_present: Option<Field>,
    /// A branch-keyed marker whose PRESENCE is this row's firing condition
    /// (CLOUD-1390).
    ///
    /// **The third modifier polarity, and the one the other two cannot express.**
    /// [`Rule::when_absent`] and [`Rule::when_present`] condition on a projection
    /// of the CALL — what the harness handed over. This conditions on a fact about
    /// the BRANCH that an earlier turn left behind, which no field of this call
    /// carries.
    ///
    /// **It exists because a punt is the absence of an action.** A gate refuses
    /// actions, and at the moment a turn ends by offering work instead of doing it
    /// there is no action to refuse — CLOUD-97 and CLOUD-219 each ruled out making
    /// the turn's end a deny, because committing and pushing is what survives a
    /// container reclaim and that path must stay free. So the observation is made
    /// where the evidence is and the refusal lands where a refusal is allowed: the
    /// next mediated write. `ready-guard` and `claim read unread` are the same
    /// shape one surface over.
    ///
    /// **Presence, never validity**, and the distinction is what keeps this from
    /// being a second opinion about receipts. [`crate::receipt::validity`] decides
    /// whether a receipt PROVES something; this asks only whether a marker file
    /// exists. A marker is not a proof and carries no conclusion to be stale.
    ///
    /// **The spend is deletion, by the sweep that already runs.** A row named here
    /// must be one of [`BRANCH_KEYED_RECEIPTS`], so landing clears it
    /// and nothing else has to know how it is retired — which is also what stops
    /// this from becoming a state machine with its own lifecycle.
    ///
    /// Absent on every row that predates this column, which then behaves exactly
    /// as before: the modifiers are additive, and absent means "this row is about
    /// the selection alone".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub while_marker: Option<String>,
    /// Fire only while `HEAD` exists in this clone and on no remote-tracking ref
    /// (CLOUD-843).
    ///
    /// **The harm a punt row names, measured rather than proxied.** `turn mint
    /// ahead` refuses because work "committed nowhere but this container" dies
    /// with a reclaim, and its remedy says a push is what makes stopping safe —
    /// but nothing it selected on read a push. Its only lever was a `verify`
    /// receipt for `HEAD`, and on a tree that compiles only after edits that
    /// receipt cannot be earned without the writes the row refuses: a deadlock
    /// whose sole exit, a head-bound admission, every commit voids.
    ///
    /// Conjoined with the other modifiers, so a row carrying `while_marker` too
    /// fires while the marker exists AND `HEAD` is unpushed. Could-not-look
    /// selects the row, the direction `while_marker`'s own unreadable arms take:
    /// an unknown answer must not switch a refusal off.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub while_unpushed: bool,
    /// The envelope projection a [`Rule::max`] ceiling measures (CLOUD-925).
    ///
    /// A [`Field`], reusing the existing named allowlist rather than
    /// minting a second vocabulary for the same thing — and inheriting its safety
    /// argument, which is what makes this admissible at all: the allowlist can
    /// never name `Envelope::input` wholesale, so a ceiling can only ever be
    /// pointed at a projection somebody deliberately exposed.
    ///
    /// Required with `max` and `counts`, refused without them: a projection named
    /// with no cap measures something and decides nothing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub measures: Option<Field>,
    /// What the [`Rule::max`] ceiling counts over [`Rule::measures`] (CLOUD-925).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub counts: Option<CeilingUnit>,
    /// The per-CALL ceiling: the largest measurement that still passes
    /// (CLOUD-925).
    ///
    /// **A ceiling whose subject is one call, which `[budget.<name>]` structurally
    /// cannot express** — that table is a file set, `files` globs plus
    /// `max_tokens`, evaluated over the tree by `policy budget`. So the bound
    /// `fanout-guard` carries (count the prompt, count the reading manifest,
    /// refuse past a cap) had no spelling as a row, and CLOUD-312's row 6 read
    /// "config" with no mechanism behind it.
    ///
    /// **The boundary is `<=`: exactly at the cap passes.** Inherited from
    /// [`crate::budget::Report::over_budget`] rather than decided again, because
    /// CLOUD-925 §1 requires one authority for what a ceiling *is* — a second
    /// comparison semantics for the same word is how the two would drift, and
    /// which side of the boundary is inclusive is precisely the kind of detail
    /// that drifts silently.
    ///
    /// **A modifier, not a keying column.** The row still selects on its own
    /// terms — `tool` for a structured call (CLOUD-924), `pattern` for a shell
    /// one — and this decides whether that selection refuses. Same shape
    /// [`Rule::requires_key`] already carries, and for the same reason: the
    /// selection half is unchanged.
    ///
    /// Rule 4 holds structurally: a breach reports the measurement, the cap and
    /// the row id. Never a byte of what was measured — which is the argument
    /// [`Field::Prompt`] already carries for counting bytes it may
    /// not echo.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max: Option<usize>,
    /// How a reference in the measured projection resolves to a repository path,
    /// for a [`CeilingUnit::TrackedArtifacts`] ceiling (CLOUD-925).
    ///
    /// **The consumer's vocabulary, and non-negotiable rule 1 is why it is a
    /// column.** A repository that writes `mem:core` in a prompt to mean one of
    /// its own files knows that mapping; `crates/batten` must not. So the engine
    /// knows only the RELATIONSHIP — a token is rewritten, and the result is
    /// counted if the tree tracks it — and the shorthand itself is config.
    ///
    /// Each entry is a regular expression and a replacement, applied to a
    /// candidate token before the tracked-set lookup. A token no entry matches is
    /// looked up as written, so a plain path needs no rewrite at all and the
    /// column stays absent for every consumer that uses none.
    ///
    /// Compiled at load like `regex`, `exclude` and `content`: left to
    /// adjudication an unparseable expression is skipped on every call, which is
    /// a ceiling that reads as configured and counts less than it should — the
    /// permissive direction.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resolves: Vec<Rewrite>,
    /// An extra literal that must appear in the mediated command **as written**
    /// for a [`RuleKind::Shape`] rule to fire. Optional, that kind only.
    ///
    /// It exists for one real case rather than as a general escape hatch: a
    /// landing directive lives inside a quoted `--body`, so it is not one of the
    /// words the shape matches, and without this an ordinary `gh pr comment`
    /// would be denied alongside the one that carries the directive. Matched
    /// against the raw text of the same segment, quotes included.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contains: Option<String>,
    /// A literal whose presence **exempts** the command from a
    /// [`RuleKind::Shape`] row that would otherwise fire (CLOUD-1477's sibling).
    ///
    /// [`Rule::contains`]'s twin in the other polarity, and it exists for the
    /// same structural reason rather than as a general escape hatch: the operand
    /// matcher drops flags before comparing, so a row cannot distinguish two
    /// commands that differ only by a flag. `contains` is how a row DEMANDS one;
    /// this is how a row EXCLUDES one, and without it the only expressible
    /// predicate over a flag is "must be present".
    ///
    /// **The measured case is `git rebase`.** `patch run loose` bans a
    /// hand-driven landing lap — `git rebase origin/main` — by asking whether the
    /// line names `origin/main`. But `git rebase --onto origin/main <upstream>
    /// <branch>` names it too, and is not a lap at all: `--onto` moves a range
    /// somewhere else, which is a history edit the landing loop cannot perform,
    /// so the row refused an operation its own remedy does not offer and declared
    /// no route to it. A lap never spells itself with `--onto`, because a lap has
    /// no upstream to name.
    ///
    /// Matched against the raw text of the same line as `contains`, quotes
    /// included, and for the same reason: line one's text must not exempt line
    /// two's command.
    ///
    /// **The permissive direction is the one to fear here**, which is why it is
    /// `shape` only and a literal rather than a regex. A `contains` that is wrong
    /// makes a row fire less often than it reads; so does this — but this is the
    /// column whose whole job is to switch a deny off, so it stays the narrowest
    /// thing that can do the job and is named in the row's `reason` wherever it
    /// is used.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unless_contains: Option<String>,
    /// Narrow a [`RuleKind::Shape`] deny to a line whose argv carries a WORD
    /// matching this expression (CLOUD-2669), anchored as `^(?:…)$`.
    ///
    /// The words are this line's argv after the effective program, minus its
    /// redirections, unquoted by the segmenter: `-m "never use --no-verify"` is
    /// one word and holds no `--no-verify` word, where `contains` sees one. A
    /// regex rather than a literal so a bundled short flag (`-anm`) is
    /// expressible; anchoring is what keeps it a word test.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub word: Option<String>,
    /// The exempting polarity of [`Rule::word`]: a line whose argv carries a
    /// matching word does not fire. Line-scoped, like `unless_contains`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unless_word: Option<String>,
    /// Select a `shape` or `receipt` row by the event a call raises rather than
    /// by its spelling (CLOUD-2662). One selector of `pattern`, `content`,
    /// `tool` and `on` per row.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub on: Option<CallEvent>,
    /// Narrow a [`RuleKind::Shape`] deny to a call that reached its program
    /// **without** the named mediator (CLOUD-271).
    ///
    /// The row still selects on the command shape; this decides whether that
    /// selection refuses. Without it a row keyed on `cargo` denies every route
    /// to `cargo`, the sanctioned one included — because
    /// `hook::effective_program` looks *through* `mise exec` by design, so the
    /// mediated call resolves to the same program as the bare one. The
    /// objection here is not to the program but to the **toolchain selection**:
    /// a bare `cargo` compiles against whatever is ambient, and the pin is what
    /// makes a local green mean anything.
    ///
    /// So the mediator is read from the segment **as written**, which is the
    /// one place the two routes still differ, and a wrapper cannot launder it:
    /// `env RUSTFLAGS=-Awarnings cargo build` names no mediator and is refused,
    /// while `env FOO=1 mise exec -- cargo build` names one and is not.
    ///
    /// A closed set rather than a free string: an unrecognised mediator would
    /// be a row that never finds what it is looking for and therefore denies
    /// everything, which is the loud half of the same silence
    /// [`validate`] exists to refuse.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub require_via: Option<RequireVia>,
    /// Narrow a [`RuleKind::Shape`] deny to work that names **no** tracker key
    /// (CLOUD-446).
    ///
    /// A bare shape row means *this command is banned*. This modifier turns the
    /// same row into *this command is banned unless the work is keyed*: the row
    /// still selects on the command shape, and the expression decides whether
    /// that selection refuses. It is a modifier rather than a kind of its own
    /// precisely because the selection half is unchanged.
    ///
    /// The evidence is the mediated command itself plus, resolved at the
    /// boundary, the branch name and the commit subjects on
    /// `<base>..HEAD` — the same fixed VCS-query class [`RuleKind::Receipt`]
    /// already makes, which is why [`RuleKind::carries_ambient_authority`] stays `false`.
    /// Requires `base`, since the range has to be named by the consumer rather
    /// than by a trunk name baked into the crate.
    ///
    /// **The vocabulary is the consumer's.** `CLOUD-<n>` is this repository's
    /// tracker, not Batten's, so what a key looks like is an expression in
    /// `batten.toml` (non-negotiable rule 1). Compiled at load, like `regex` and
    /// `exclude`, so a bad one names its row rather than becoming a gate that
    /// silently allows.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requires_key: Option<String>,
    /// Why this rule refuses, and what to do instead — the deny's whole text.
    ///
    /// Required by [`RuleKind::Shape`], where the refusal is all a caller gets;
    /// optional elsewhere, where a `path:line` pointer plus the id already says
    /// where to look.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// An optional link to the policy this rule enforces, appended to the deny.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_url: Option<String>,
    /// The environment variable that suppresses **this row**, named in this
    /// row's own deny (CLOUD-437).
    ///
    /// Absent means no hatch: there is no general one to fall back to, so a row
    /// without this column is suppressed only by a waiver or an admission, both
    /// of which leave a record. A row declaring one is declaring that its bypass
    /// is a *separate decision* from every other row's.
    ///
    /// Why a per-row column rather than one global name: the bash guards this
    /// surface inherited each had their own hatch, so an operator could suppress
    /// `memory-guard` alone while `ready-guard` stayed live. One global name
    /// silently widens the blast radius of every bypass — invisibly, because the
    /// deny text cannot say what else it just switched off.
    ///
    /// It is an environment variable rather than a `batten.local.toml` key on
    /// purpose. A hatch LOWERS policy, and house-style §8's override channel is
    /// raise-only; an env var is a per-invocation decision, visible in the
    /// command that took it and gone when the process exits, where a config key
    /// would make the same lowering persistent and invisible.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bypass_env: Option<String>,
    /// The **inspection-only** command template a [`RuleKind::Command`] rule
    /// runs as its gate. Required by that kind, rejected by any other.
    ///
    /// Split on whitespace into `program` plus arguments and executed
    /// **directly — never through a shell**, so what runs is exactly what a
    /// reviewer reads (§9: rules "name a command already on the operator's
    /// PATH"). A bare [`FILES_PLACEHOLDER`] argument expands in place to the
    /// matched paths; omit it and the command self-discovers.
    ///
    /// Named for the half it is, not for the act of running: §9's duality has
    /// two commands, and a column called `run` could name either. Enforcement
    /// is always this one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub check: Option<String>,
    /// The **mutating** half of §9's duality: the command that repairs what
    /// `check` condemned. Optional, [`RuleKind::Command`] only.
    ///
    /// Parsed today and **executed by nothing**: serialised fix execution is an
    /// engine capability that does not exist yet. The key is reserved now
    /// rather than later because §2 declares no back-compatibility surface, so
    /// a config author who writes one is writing the final spelling.
    ///
    /// A row carrying it is refused by [`run_all`] rather than quietly ignored
    /// — a declared repair that silently never runs is the false green this
    /// engine exists to refuse.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fix: Option<String>,
    /// What this rule PRODUCES: the record the boundary writes after the rule has
    /// decided (CLOUD-851).
    ///
    /// The first column on this struct that is not an input selector. Every other
    /// path-shaped key — `glob`, `documents`, `pattern` — narrows what the rule
    /// READS; this one names what the run leaves behind, which is the notion the
    /// model had none of and which eleven bash writers need somewhere to land.
    ///
    /// **It does not make the rule impure and it does not make it spawn.** The
    /// rule stays [`crate::facts::Cost::Read`] and
    /// [`RuleKind::carries_ambient_authority`] is untouched: a declaration here
    /// yields a [`crate::sink::Requested`] value, and the boundary performs it.
    /// `the_two_axes_agree_about_every_kind` still holds, which is the assertion
    /// that a sink was added as a third axis rather than `Cost::Effect` quietly
    /// repurposed into meaning "mutates".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub produces: Option<Sink>,
    /// Path globs this rule's [`Rule::glob`] selects but must NOT judge
    /// (CLOUD-883).
    ///
    /// **`glob` could say "these files" and not "these files except those",** so
    /// a broad rule and a precise one could not compose over one tree: the broad
    /// one always double-reported what the narrow one owned. Measured on
    /// CLOUD-881, whose `forbid` row over `**` reports `Cargo.toml:225` — a
    /// legitimate dependency pin — because deciding that needs the TOML table the
    /// line sits in, which is a `policy` row's question and not a literal's.
    ///
    /// **Not [`Rule::exclude`], which is a regex over the matched LINE and never
    /// sees a path.** The two are confused often enough that this column is named
    /// for what it subtracts rather than for the globs it holds.
    ///
    /// # Narrowing is structural here
    ///
    /// Selection is a [`PathSet`]: `glob` is the only include and these are the
    /// excludes, so the selected set is a SUBSET of what `glob` alone selects, by
    /// construction. `PathSet`'s rule is that an exclude beats an include and the
    /// outcome does not depend on the order patterns were written in — which is
    /// what makes this safe where gitignore's last-match-wins is not. There, a
    /// later positive pattern re-includes, so a negation can WIDEN, and widening
    /// is the one direction a policy engine may never drift ([`Selector`]).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exclude_paths: Vec<String>,
    /// The retired spelling of [`Rule::check`], present only so the refusal can
    /// name its replacement.
    ///
    /// Carried as a field rather than left to `deny_unknown_fields` for the
    /// same reason [`crate::config::OverrideConfig::min_batten_version`] is:
    /// "unknown field `run`" reads as a typo, where this is a rename with one
    /// specific fix. Every deny points to it (CLOUD-122).
    ///
    /// Deliberately absent from [`Rule::columns`]: that census classifies the
    /// columns a kind may *carry*, and no kind carries this one — it is refused
    /// outright by [`Rule::validate`], ahead of any per-kind question.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run: Option<String>,
    /// Hash the matched span **verbatim** rather than collapsing its whitespace.
    ///
    /// For a rule whose subject *is* literal content, where a reformat genuinely
    /// changes the thing being flagged. The default collapses whitespace on the
    /// `git patch-id` model, so a formatter reflow does not re-mint an identity;
    /// a `verbatim` rule trades that for sensitivity to the bytes it is about.
    /// `Option<bool>` rather than `bool` so the column census can see presence
    /// (`Rule::columns`), which is what makes a `verbatim` on a kind that hashes
    /// no span a usage error instead of an ignored key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verbatim: Option<bool>,
    /// A per-rule identity discriminator: split one identity into several.
    ///
    /// **Split-only by construction, not by validation.** The default identity
    /// is hashed as a field of the override's preimage
    /// ([`crate::identity::override_fingerprint`]), so two spans with different
    /// default identities cannot collide under any discriminator — this can
    /// fragment a group and is mathematically unable to merge two. Changing it
    /// is a deliberate re-mint, not a rename.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity_key: Option<String>,
    /// Which way a [`RuleKind::Ratchet`] count may move. Required by that kind,
    /// rejected by every other.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub direction: Option<Direction>,
    /// The git rev a [`RuleKind::Ratchet`] counts against, and the one a
    /// `requires_key` shape row reads commit subjects since. Any rev git
    /// resolves; one it cannot is a usage error naming the rev for the ratchet,
    /// and "could not look" for the shape row — a tree gate owes an answer where
    /// a mediated call must not become un-runnable outside a checkout.
    ///
    /// One column for both because it is one question — *since where* — and a
    /// second spelling of it would be the trunk name written twice.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base: Option<String>,
    /// The header token a [`RuleKind::Ratchet`]'s files declare their SUBJECT
    /// with, turning the row into *a decrease is admitted when the subject
    /// died* (CLOUD-807).
    ///
    /// A bare ratchet means *this count may not fall*, and the only hatch for a
    /// legitimate reduction is a `[[waiver]]` — which expires, and which cannot
    /// say WHICH reductions are legitimate. This modifier says it. The value is
    /// the line prefix a matched file writes its subject after; everything to
    /// the end of that line is read as whitespace-separated paths.
    ///
    /// **The vocabulary is the consumer's** (non-negotiable rule 1). `#
    /// subject:` is one repository's comment syntax, not Batten's, so the token
    /// is config and this crate never names a specific repo's files. What the
    /// core knows is the RELATIONSHIP: a file declares paths, and those paths
    /// dying is what buys its own deletion.
    ///
    /// Declaring it has two consequences, and the second is what makes the
    /// first honest:
    ///
    /// 1. **Admission.** A decrease is admitted iff every file whose own count
    ///    fell declares a subject, and every path that subject names was a blob
    ///    at `base` and is absent from the working tree.
    /// 2. **Obligation.** EVERY matched file must carry a resolvable header —
    ///    not merely the ones a given change touches. Absent, empty, or naming
    ///    a path that no longer exists is a finding at the row's severity.
    ///
    /// Without (2) the admission rests on a header nobody checks, and a suite
    /// outliving its subject — the header rotted into a lie — reads exactly
    /// like one that never had a subject at all.
    ///
    /// **Headers are read from the BASE tree.** A retired file does not exist
    /// in the working tree, so base is the only place its subject can be read —
    /// and it is also the right place: a change cannot rewrite its own
    /// permission by editing the header in the same commit. The price is that
    /// widening a too-narrow header before a retirement takes a prior landed
    /// commit, which is the correct direction for the trade, since a header
    /// narrower than the truth is a hole and one wider than it is only friction.
    ///
    /// Requires `base`, like the ratchet's count itself: the admission is
    /// decidable from two trees and one of them has to be named.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retires_with: Option<String>,
    /// How a deletion proves it conserved logic, not merely files (CLOUD-908).
    ///
    /// [`Rule::retires_with`] buys a decrease with a dead subject; this obliges
    /// every named case inside that decrease to be claimed by exactly one arm in
    /// the head tree. See [`Conserves`] for the three arms and what each owes.
    ///
    /// Requires `retires_with`, and therefore `base`: it refines that column's
    /// admission rather than standing beside it, and a mapping with no admission
    /// to refine would decide nothing on a rule that never permits a decrease.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conserves: Option<Conserves>,
    /// How a change declares that a newly added file cannot migrate (CLOUD-929).
    ///
    /// [`Rule::retires_with`] admits a DECREASE with a subject that died; this
    /// admits an INCREASE with a reason the author writes down. Both let a
    /// ratchet permit the movement it exists to refuse, so both are the same
    /// shape — a line prefix, read for a declaration — and neither is a waiver:
    /// the permit lives in the rule rather than in a row that expires.
    ///
    /// **It is read from the WORKING tree, and that asymmetry is the whole
    /// design rather than an oversight.** `retires_with` reads the BASE tree
    /// because a retired file has no working copy, and because reading base is
    /// what stops a change rewriting its own permission in the commit that
    /// spends it. For an increase that inverts exactly: a new file is absent
    /// from base, so the working tree is the only place its marker can be read,
    /// and a change therefore *can* write its own permission.
    ///
    /// So this column is **structurally weaker than its sibling and must not be
    /// described as the same guarantee**. It is a declaration a reviewer reads in
    /// the diff, not a proof the engine verified against a tree the author could
    /// not edit. What it buys is still worth having: it converts a silent
    /// increase into a visible, attributed one, and it makes the author name the
    /// reason at the moment they incur it rather than in a retrospective.
    ///
    /// The engine checks only that a declaration is PRESENT and non-empty. Any
    /// convention about what it must say — an issue key, a bucket name — is the
    /// consumer's, because a tracker's vocabulary inside this crate is
    /// non-negotiable rule 1's violation.
    ///
    /// Requires `base` for its sibling's reason: the admission is decidable only
    /// against two trees, since "newly added" means "absent from base".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub admits_with: Option<String>,
    /// Judge a ratchet per matched file rather than on the sum (CLOUD-2663).
    ///
    /// Each path present at `base` is held to its OWN base count, so one file
    /// shrinking can no longer pay for another growing. A path absent at base is
    /// not judged: a per-file ceiling is that file's count at base, and a file
    /// the branch creates has none. A path deleted since base counts `0`.
    ///
    /// Refused with `retires_with` and `conserves`, which both buy an AGGREGATE
    /// decrease that a per-file row does not have.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub per_file: bool,
    /// How to parse the documents a [`RuleKind::Document`] row selects. Required
    /// by that kind, rejected by every other.
    ///
    /// **Declared, never inferred from the path.** An extension is a naming
    /// convention — a JSON5 file is conventionally `.json5` and legally
    /// anything — and this column is what decides which parser reads the bytes.
    /// Guessing wrong yields "could not look" on a file that is perfectly well
    /// formed, which blames the document for the engine's inference.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub format: Option<crate::facts::Format>,
    /// The dotted node path a [`RuleKind::Document`] row addresses — `a.b.0.c`,
    /// walking maps by key and lists by index. Required by that kind, rejected
    /// by every other.
    ///
    /// The path is the consumer's, like every other artifact-shaped value here:
    /// `crates/batten` knows how to walk a document and nothing about what any
    /// particular one contains (non-negotiable rule 1).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node: Option<String>,
    /// The name this rule publishes its derived value under, for another rule to
    /// read (CLOUD-773). [`RuleKind::Document`] only.
    ///
    /// **A value, not a verdict.** Composition already exists in the layer this
    /// engine is absorbing: 57 of 126 tasks invoke a sibling and branch on its
    /// exit code. That channel carries three states and nothing else, so a
    /// consumer that needs the producer's *structure* re-derives it — measured,
    /// `graph-check` spawns `ready-lint` and then re-spells the issue-key regex
    /// three times. The re-derivation is caused by values not crossing the
    /// boundary, which is what this column is for.
    ///
    /// Names are global to the config and unique: two rows deriving one name is
    /// refused at load, because "which one did I read" is not a question a
    /// reviewer should have to answer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub derives: Option<String>,
    /// What a [`RuleKind::Reference`] row cites and the register it resolves
    /// against (CLOUD-2005). Required by that kind, refused by every other.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cites: Option<crate::register::Cites>,
    /// The derived value this rule compares its node against — [`Rule::pattern`]'s
    /// **alternative**, never an addition to it. [`RuleKind::Document`] only.
    ///
    /// A row carries exactly one of the two, the shape `forbid`'s
    /// `pattern`/`regex` pair already uses (CLOUD-283): a row carrying both is a
    /// load error rather than a precedence rule nobody can read.
    ///
    /// Three checks run at load and never later (house-style §8, and CLOUD-647
    /// measured that the obvious candidate engine reports the third at
    /// *evaluation*, which on the mediated path is the worst possible time):
    /// the name must be derived by some row, the reference graph must be
    /// acyclic, and the derivation's [`RuleKind::fact_class`] must not make this
    /// rule more expensive or narrower than its own kind already is.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reads: Option<String>,
    /// Per-predicate severity, keyed by an id the module publishes (CLOUD-832).
    /// [`RuleKind::Policy`] only.
    ///
    /// **Why a row's single `severity` is not enough.** A bundle carries many
    /// predicates and this repository's own rules span `deny` and lower
    /// severities; one row cannot carry both, so without this key every
    /// predicate in a bundle inherits one verdict and the bundle is as strict as
    /// its strictest member or as lax as its laxest. That is the "severity
    /// flattens" half of CLOUD-832, and it is the half a waiver cannot stand in
    /// for — a waiver suppresses, it does not lower.
    ///
    /// Absent, and absent per key, means [`Rule::severity`] — the row's own
    /// value is the default for every predicate it registers, so the narrow case
    /// stays one line. A key naming an id no module publishes is refused at
    /// load by [`crate::policy::load`], which is the only place that sees both
    /// the row and the module's declared set; it would otherwise be a setting
    /// that parses and does nothing, which house style §8 refuses everywhere
    /// else.
    ///
    /// This does NOT widen §8's raise-only invariant, and the argument is worth
    /// stating rather than leaving to luck, because the key appears in the
    /// OVERRIDE schema too. Three refusals already standing close it:
    /// [`crate::config::OverrideConfig`] admits rules a local file *adds* and
    /// refuses a redefinition of a committed id, so there is no committed bar
    /// here to lower; [`crate::policy::load`] refuses two rows registering one
    /// module, so an override cannot re-register the same bundle at a lower
    /// severity; and it refuses two modules publishing one predicate id, so an
    /// override cannot smuggle a laxer copy of a predicate in beside the
    /// original. On top of that a module is deny-only by construction — there is
    /// no spelling for an allow — so a predicate's severity chooses how loudly it
    /// refuses, never whether some other gate stops refusing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub predicate_severity: Option<BTreeMap<String, RuleSeverity>>,
    /// The vendored preset this rule enables, by name (CLOUD-836).
    /// [`RuleKind::Policy`] only, and the third of the three mutually-exclusive
    /// sources — [`Rule::module`] is one file, [`Rule::bundle`] one folder, this
    /// one a bundle compiled into the binary.
    ///
    /// **A preset is not an authority; it is content the authority enables.**
    /// That is what keeps it clear of CLOUD-29's one-committed-authority rule,
    /// and why enabling one is explicit here rather than default-on: a consumer
    /// who enables nothing gets nothing, so this adds no implicit behaviour for
    /// §8 to have an opinion about.
    ///
    /// The valid names are [`preset_names`], derived from the
    /// embedded set — an unknown name is a config error at load (exit `1`),
    /// never a silent no-op, and the published schema's enum is generated from
    /// the same list so the two cannot disagree.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(schema_with = "preset_name_schema")]
    pub preset: Option<String>,
    /// The CI provider this repository runs, where the enabled preset reads one
    /// (CLOUD-1625).
    ///
    /// **A consumer fact, so it lives in the consumer's config** — which is
    /// non-negotiable rule 1 applied to the seam that broke it. The engine
    /// declares which provider's language a preset's modules read
    /// ([`crate::preset_catalog::Manifest::provider`]); this declares which one is in
    /// use here; and the two are compared at load. Neither guesses the other.
    ///
    /// Omitted is the ordinary case: six of the seven presets read no provider's
    /// language, so a row enabling one needs nothing here. A row enabling a
    /// preset that DOES read one, and naming no provider or a different one, is
    /// refused before compilation — because the alternative is the preset
    /// evaluating over an empty document set and reporting clean.
    ///
    /// ON THIS ROW rather than in `[ci]`: that table is "this repository's
    /// committed copy of the host's contract" (`crate::ci::Ci`), a mirror of the
    /// host's branch protection that `ci-drift` polices key by key, and a key
    /// with no host counterpart breaks the mirror. `[host]` is the host's repo
    /// settings and is no better a fit. One optional key beside the `preset` it
    /// qualifies keeps the configuration narrow, which is rule 6.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    /// Modules of the enabled preset this row does NOT compile, by name — the
    /// file stem, as `plan-mode-refuses-writes` (CLOUD-2290).
    ///
    /// The half of ejecting a module that the binary owns: a local copy declares
    /// the ids the vendored module did, and `claim_ids` refuses one id from two
    /// bundles, so the vendored module has to step aside for the copy to load.
    /// `batten preset eject` writes this key; it is ordinary config, so a
    /// consumer may write it by hand too.
    ///
    /// A name the preset does not ship is refused at load (exit `1`), never
    /// ignored: an `except` that excepts nothing would leave the vendored module
    /// running beside the copy that was meant to replace it.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub except: Vec<String>,
    /// The tool environments the enabled preset installs at startup, by name
    /// (CLOUD-2633). Only a preset declaring an install takes it.
    ///
    /// **A consumer fact, passed rather than discovered**: an agent environment
    /// is not a CI one is not a dev one, so the install loads the base
    /// configuration plus exactly these, never every environment file present.
    /// A `[[startup]]` row naming the same `preset` places the install in the
    /// startup sequence. `Some(empty)` is refused at load rather than read as
    /// "base only", and so is a name the repository configures nothing for.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub environments: Option<Vec<String>>,
    /// `NAME=VALUE` assignments the derived install runs under (CLOUD-2633) —
    /// how this repository's tool must install, such as from its lockfile.
    /// Requires `environments`; it may not set the preset's own selector, which
    /// `environments` owns.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub install_env: Vec<String>,
    /// Which compiled gate a [`RuleKind::Native`] row enables (CLOUD-2291).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gate: Option<NativeGate>,
    /// The bundle root this rule enables, as a repository-relative directory
    /// (CLOUD-833). [`RuleKind::Policy`] only, and the **alternative** to
    /// [`Rule::module`] rather than an addition to it.
    ///
    /// A row carries exactly one of the two, the shape `forbid`'s
    /// `pattern`/`regex` pair already uses (CLOUD-283): a row carrying both is a
    /// load error rather than a precedence rule nobody can read.
    ///
    /// **Why a folder does not reopen §8.** §8 forbids *implicit discovery* —
    /// the upward directory walk and the `conf.d` merge — because merging can
    /// weaken. Nothing here merges. The one committed authority names the root
    /// explicitly, and every module inside it is deny-only by construction, so
    /// enumerating them can only ADD refusals. §8's invariant is raise-only, and
    /// a set that cannot subtract satisfies it more strongly than the typed rule
    /// table does. Globbing for `*.rego` anywhere ELSE would be the thing §8
    /// refuses; naming this root is the opposite of it.
    ///
    /// The root joins the `protected` set for the same reason a named module
    /// does — see [`Rule::module`]. A folder must not be less protected than a
    /// file was.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bundle: Option<String>,
    /// The documents a tree-scoped policy row hands its bundle (CLOUD-833).
    /// [`RuleKind::Policy`] with [`RuleScope::Tree`] only.
    ///
    /// **Bounded by declaration, never by an ambient walk.** A bundle is handed
    /// exactly the documents its row names, the way [`crate::facts::Declared`]
    /// already works — which is what keeps house style §4's "cheap when
    /// irrelevant" true: a row whose declared inputs are unchanged does no work
    /// at all. A rule that walked the tree would pay for every file on every
    /// invocation and would make the `read` classification a lie by degrees.
    ///
    /// Each entry is a repository-relative path. The parsed result is
    /// `input.tree.documents[<path>]`, built by
    /// [`crate::rules::tree_document`] from `facts.rs`'s existing `Format`/`Node`
    /// substrate (CLOUD-772) — reused rather than re-implemented, so no second
    /// parser lands.
    ///
    /// A declared document the tree does not carry is
    /// [`crate::facts::Look::CouldNotLook`] and never an empty input: a module
    /// that could not see its subject has not established anything about it,
    /// which is CLOUD-251's vacuous pass in the place it would be least visible.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub documents: Vec<String>,
    /// The paths this rule needs before its body is worth running (CLOUD-125).
    ///
    /// The **declared input-precondition**: every entry must exist under the
    /// run's root, or the rule is [`NotObserved::RuleSkipped`] and the first
    /// missing path is reported as the unmet requirement. Absent — the default —
    /// means the rule is unconditional, which is what makes this additive: a row
    /// that declares none behaves exactly as it did before the column existed.
    ///
    /// **Not spelled `precondition`**, and that is not aesthetic. A
    /// `[[verdict.route]]` already carries a `precondition`, and that one is a
    /// human-answerable question an override is granted against
    /// ([`crate::admission`]) — a different thing entirely from a predicate the
    /// engine decides. One word for both would put two unrelated concepts under
    /// one name in the same config file. The `requires_` prefix is the family
    /// this actually belongs to, beside `requires_key` and `requires_field`.
    ///
    /// **Resolvable without a subprocess, by construction** — the whole line
    /// CLOUD-125 draws against the `command` kind. Existence of a declared path
    /// is a stat; a precondition that needed a program to answer would be a
    /// second, unbounded evaluation before the one the rule declares, and that
    /// is what the `command` kind is for, evaluated *inside* the check.
    ///
    /// Deliberately absent from [`Rule::columns`], with the git and document
    /// families and for their reason: this classifies as a declared READ rather
    /// than a per-kind capability, so it is permitted on every kind rather than
    /// listed in ten `permits()` arms that would then have to be kept in step.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub requires_path: Vec<String>,
    /// The documents a tree-scoped policy row hands its bundle, **selected by
    /// glob** (CLOUD-850).
    ///
    /// [`Rule::documents`]'s sibling and the reason it stopped being the only
    /// spelling. `documents` is literal-path only — the sole path handling was
    /// `root.join(path)`, no expansion — so `documents = ["mise-tasks/*"]` was
    /// read as a file with a `*` in its name, failed, landed in `missing`, and
    /// skipped the whole rule. Silently, green. A policy row was the one kind
    /// excluded from the glob machinery every other kind uses, and it is the kind
    /// the entire retirement campaign migrates onto: 27 of the 82 bash gates open
    /// more than five files.
    ///
    /// Resolved with [`Selector`] — `globset` with `literal_separator(true)` —
    /// against the run's one `ignore` walk, exactly as every glob-taking kind
    /// already does. No second matcher.
    ///
    /// **Additive, and `documents` is unchanged.** A row may declare either or
    /// both; the union is what its bundle is handed. Keeping the literal spelling
    /// working is what makes this not a breaking change, and it stays the right
    /// spelling for the ~55 gates that each open one to four named paths.
    ///
    /// A glob that matches nothing is a **stated** skip rather than a silent one,
    /// for the reason the whole row exists: a selector that selects nothing and a
    /// tree that satisfies the predicate are otherwise the same green.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sources: Vec<String>,
    /// The files a tree-scoped policy row hands its bundle as **lines**
    /// (CLOUD-846).
    ///
    /// [`Rule::documents`]'s unparsed sibling, and the ceiling it lifts was
    /// measured: of the 20 tree-scoped gates, 8 read structured config and 12
    /// read content no fact could carry — 4 markdown, 5 `.bats`/`.rs`/`.pkl`
    /// source, 3 no file literals at all. `Format::for_path` answers `None` for
    /// every one of those, so the path landed in `missing` and the row skipped.
    ///
    /// The value is `input.tree.lines[<path>]`, an array of strings. A path that
    /// cannot be read stays in `missing` — **could-not-look, never an empty
    /// array**, which is the distinction that keeps CLOUD-251's vacuous pass out:
    /// a file nobody could read and a file with no matching line are not the same
    /// answer.
    ///
    /// **Bounded by declaration, exactly as `documents` is.** A row reads the
    /// paths it names and no others.
    ///
    /// **Rule 4 is what picks this shape over raw text.** A module may SEE a
    /// line; a finding may not CARRY one. Lines are the widest shape that cannot
    /// put content into a finding by accident, and `tests/pointer_only.rs` holds
    /// that structurally rather than by review.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub lines: Vec<String>,
    /// The files a tree-scoped policy row hands its bundle as lines, **selected
    /// by glob** (CLOUD-864).
    ///
    /// [`Rule::lines`] is to this what [`Rule::documents`] is to
    /// [`Rule::sources`], and the pair landed asymmetric: CLOUD-850 gave the
    /// parsed half a glob and the unparsed half kept literal paths only. That
    /// leaves the fact model's widest surface reachable only by naming every
    /// path — and the gates that need LINES rather than a parsed document are
    /// precisely the ones reading many files, since `Format::for_path` answers
    /// `None` for source text.
    ///
    /// Measured need: the shebang rule this column was added for decides over
    /// **137** shell programs. Enumerating them is a list that goes stale the
    /// next time one is added, silently and green — the failure the declaration
    /// bound is supposed to prevent, reintroduced by the spelling.
    ///
    /// Same [`Selector`], same union semantics, same stated-skip on a glob that
    /// matches nothing. Additive: `lines` is unchanged and stays right for a row
    /// naming one or two paths.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub line_sources: Vec<String>,
    /// The Rust files this policy row reads as **call sites**, by literal path
    /// (CLOUD-914).
    ///
    /// [`Rule::lines`]' sibling one tier up: `lines` answers *does this token
    /// appear in this file*, and this answers *does it appear in command
    /// position*. A row wanting the second must say so, because parsing is
    /// strictly more expensive than splitting and nobody should pay it by
    /// accident.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub invocations: Vec<String>,
    /// The same, glob-selected (CLOUD-914).
    ///
    /// Ships WITH its literal column rather than arriving a row later, which is
    /// the asymmetry `line_sources` records having to fix: a gate over call
    /// sites is a gate over many files by construction, so the enumerated
    /// spelling would go stale the first time a module was added.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub invocation_sources: Vec<String>,
    /// The Rust files this policy row reads as a **`use` graph**, by literal path
    /// (CLOUD-762).
    ///
    /// Separate from [`Rule::invocations`] because the two answer different
    /// questions over the same parse — what a file CALLS versus what it REACHES —
    /// and a row wanting one should not pay to project the other.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub uses: Vec<String>,
    /// The same, glob-selected (CLOUD-762).
    ///
    /// A layering rule decides over every module by construction, so the glob is
    /// the spelling that matters and it ships with its literal column.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub use_sources: Vec<String>,
    /// The source files this policy row reads as **units**, glob-selected
    /// (CLOUD-1008): every function, comment and string in a Rust file, and every
    /// function and `:=` binding in a Rego module, as D4 nodes with counts.
    ///
    /// Glob-only, without a literal sibling column, deliberately: a gate over
    /// code units is a gate over every file of a language by construction, and
    /// house style §8 keeps configuration narrow. Only a row declaring it pays a
    /// parse; nothing is acquired for a row that does not.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unit_sources: Vec<String>,
    /// The git facts this policy row reads, **declared** (CLOUD-907).
    ///
    /// [`Rule::documents`]'s sibling for the family that is not a file, and the
    /// declaration is load-bearing twice over.
    ///
    /// **It is what keeps `Cost::Read` honest.** `bench/gates/RESULTS.md`
    /// re-derived the corpus and 22 gate tasks need a git fact the engine could
    /// not emit; every one of them names which. Resolving the family ambiently
    /// instead would make every run pay for every variant — and this tree has
    /// already measured that bill: CLOUD-851 took `check` from a p50 of 4.76ms to
    /// 10.01ms, 2.103x, by locating the git dir and reading HEAD unconditionally
    /// for a question no rule had asked.
    ///
    /// **And it is what makes the acquisition auditable.** A reader of
    /// `batten.toml` sees exactly which rows read the checkout's state, which is
    /// the same property `documents` gives for files.
    ///
    /// Refs and ranges are [`Rule::refs`] and [`Rule::ranges`] rather than
    /// entries here, because those two carry a parameter and these three do not.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub git: Vec<GitRead>,
    /// Whether this policy row reads the **resolved-symbol** fact (CLOUD-760).
    ///
    /// A bare flag rather than a path list, because the fact is one whole-crate
    /// value: a delegated analyser resolves names across the compilation, and
    /// asking it about one file would be asking a different, cheaper question
    /// that [`Rule::invocations`] already answers.
    ///
    /// **Declared rather than ambient, and here the reason is the cost class.**
    /// This is the first `Cost::Effect` fact — resolving it RUNS `cargo clippy`
    /// over the crate, which is seconds rather than the milliseconds every other
    /// fact costs. Every git fact is declared for a bill CLOUD-851 measured at
    /// 2.103x; this one would be far worse, and a run that paid it without being
    /// asked would make `check` unusable.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub symbols: bool,
    /// The vendored reviews this policy row reads, **declared** (CLOUD-472).
    ///
    /// Each becomes an entry of `input.tree.review` under its own `id`. Declared
    /// per row for `symbols`' reason and more so: this is the second
    /// `Cost::Effect` fact, and a MISS dispatches an agent — minutes and tokens,
    /// where clippy is seconds. The digest key makes that once per unique
    /// subject rather than once per lap, but a run that paid it unasked would
    /// still be the shape that gets a gate switched off.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub review: Vec<crate::facts::ReviewQuery>,
    /// The refs this policy row resolves, **declared** (CLOUD-907).
    ///
    /// Each becomes an entry of `input.tree["git-refs"]` carrying the commit it
    /// names and whether HEAD descends from it. A ref that does not resolve is
    /// **absent from that map**, never present with `ancestor_of_head: false`:
    /// `origin/main` missing in a shallow clone is not "the branch has not
    /// landed", and a gate reading it that way reports the wrong verdict with
    /// full confidence.
    ///
    /// Separate from [`Rule::ranges`] although git's own ref-name rules would
    /// make one column injective — `git check-ref-format` forbids `..` in a ref
    /// name, so an entry containing it could only be a range. Two columns
    /// anyway: the two ask different questions, they sit on different surfaces
    /// (a ref is bounded and a range is not), and CLOUD-883's lesson is that a
    /// column earns its name from what it does rather than from what it can be
    /// packed with.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub refs: Vec<String>,
    /// The commit ranges this policy row reads, **declared** (CLOUD-907).
    ///
    /// Spelled `<base>..<head>`, and each becomes an entry of
    /// `input.tree["git-ranges"]` carrying that range's commits as a sha and a
    /// subject each. A range whose endpoints do not resolve is **absent**, never
    /// an empty list — "nothing landed in this range" and "I could not read this
    /// range" are the two answers a migration gate most needs kept apart.
    ///
    /// Pointer-only at the boundary: a subject is git's `%s`, which is how the
    /// log itself points at a commit. A message body or a diff would put tracked
    /// content on the policy input, and rule 4 is decided at the acquisition
    /// rather than at the report.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ranges: Vec<String>,
    /// The commit ranges this policy row reads the IDENTITY FIELDS of,
    /// **declared** (CLOUD-1187).
    ///
    /// Each becomes an entry of `input.tree["commit-meta"]` carrying, per commit,
    /// its sha, author, committer and trailers — and **no message body and no
    /// diff**. That omission is structural rather than careful:
    /// [`crate::git::CommitMeta`] has no body field, so rule 4 is decided by the
    /// type and not by a projection remembering to drop something.
    ///
    /// **Its own column rather than a widening of [`Rule::ranges`]**, and the
    /// reason is cost. `ranges` reads a subject per commit; this peels a commit
    /// OBJECT per commit, and range length is unbounded per declaration —
    /// `origin/main..HEAD` is one declaration and an unknown number of commits.
    /// Folding the two would make every row that wants subjects pay for a peel it
    /// never asked for.
    ///
    /// A range whose endpoints do not resolve is **absent**, never an empty list,
    /// exactly as `ranges` is.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub commits: Vec<String>,
    /// The paths this policy row reads the STAGED bytes of, **declared**
    /// (CLOUD-1203).
    ///
    /// `git show :<path>` — the index, never the working tree. That distinction
    /// is the whole column: [`crate::facts::Fact::Tracked`] walks the checkout,
    /// so a gate judging THE COMMIT rather than the developer's working copy
    /// cannot use it and would pass over a staged-but-unsaved edit.
    ///
    /// Each becomes an entry of `input.tree.staged`, parsed by the path's own
    /// format. A path with no staged entry, one whose bytes are not UTF-8, and
    /// one this build cannot parse are each **absent** and named in `missing`
    /// with the cause — never present with an empty node.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub staged: Vec<String>,
    /// The history PATTERNS this policy row resolves, **declared** (CLOUD-1200).
    ///
    /// [`Rule::refs`] and [`Rule::ranges`] name what they want; these describe
    /// it, because the answer set is not knowable at declaration time — every tag
    /// matching a glob, the commit that deleted a path. Each row becomes an entry
    /// of `input.tree["git-history"]` under its own `id`.
    ///
    /// **The pattern is the bound.** A pattern no row names resolves nothing, so
    /// this is a projection of a declared set rather than a git shell — the same
    /// negative half every family here owes.
    ///
    /// A SHALLOW clone leaves the whole fact `null`: it cannot see the history a
    /// path query walks, and a truncated walk reported as a result is a gate
    /// deciding over history it could not see. A declared pattern that matched
    /// nothing is present with an empty list, which is a real answer.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub history: Vec<crate::facts::HistoryQuery>,
    /// The tag GLOBS this policy row lists, **declared** (CLOUD-843).
    ///
    /// Each becomes an entry of `input.tree["git-tags"]` under the glob as
    /// written, carrying every tag it matches — by `git tag --list`'s own match —
    /// with the commit each peels to and when it was cut. A glob matching nothing
    /// is present with an empty list, which is an answer; `null` is the
    /// references that could not be read.
    ///
    /// Not [`Rule::history`]'s tag query: that family nulls on a shallow clone,
    /// because a path query walks history, and a tag listing walks none.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    /// The config KEYS this policy row reads, **declared** (CLOUD-843).
    ///
    /// Each becomes an entry of `input.tree["git-config"]` carrying the value in
    /// force and the value each scope sets, with git's boolean reading of each.
    /// Resolved across every scope git consults, because the question a signing
    /// posture asks is a conflict BETWEEN scopes.
    ///
    /// **The declaration is the secrecy bound.** A config file can carry a
    /// credential; a key no row names is never read. A key git could not address
    /// (`section.name` at least) is refused at load.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub git_config: Vec<String>,
    /// The PATHSPECS this policy row reads the index under, **declared**
    /// (CLOUD-843).
    ///
    /// Each becomes an entry of `input.tree["git-index"]` under the spec as
    /// written, carrying the index entries it selects (path, mode, oid, stage),
    /// the selected tracked paths the working tree has diverged from, and the
    /// untracked paths beneath it. git's pathspec rules without magic; a
    /// `:`-magic spec is refused at load rather than read as a literal that
    /// selects nothing.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub index: Vec<String>,
    /// The refs this policy row reads the engine's own finding store for,
    /// **declared** (CLOUD-1203).
    ///
    /// Each becomes an entry of `input.tree.state` carrying that ref's pointer
    /// lines — a fingerprint, a rule id and a count each, and nothing a finding
    /// said. **Keyed by ref**, so a listing accumulated on another branch is
    /// simply not in the map: a finding observed elsewhere is not evidence about
    /// this checkout's work.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub state: Vec<String>,
    /// The commit SHAs this policy row reads the forge's verdict for,
    /// **declared** (CLOUD-1154).
    ///
    /// Each becomes an entry of `input.tree.forge` carrying that SHA's check
    /// verdicts as `name -> conclusion` tokens, read back from a record a
    /// producer wrote OUTSIDE the engine. **The engine opens no socket** — house
    /// style §5 forbids an HTTP client here — so the fetch is somebody else's and
    /// this is a keyed read off disk, which `evaluator-io-check` gates.
    ///
    /// **Keyed by SHA, which is the safety property.** A record taken against a
    /// different commit is not evidence about this one, so it does not answer.
    /// That is the difference between reading a verdict and inheriting a stale
    /// one.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub forge: Vec<String>,
    /// The third-party tool verdicts this policy row reads, **declared**
    /// (CLOUD-1171).
    ///
    /// Each row becomes an entry of `input.tree["tool-verdict"]` under its own
    /// `id`, carrying that tool's findings as `name -> pointer` tokens — read
    /// back from a record a producer wrote OUTSIDE the engine, because `check` is
    /// `read` and structurally cannot run a validator.
    ///
    /// **Keyed by (tool, pinned version, input digest), and the keying is the
    /// safety property.** A record from a differently-pinned tool, or one taken
    /// over bytes that have since changed, lives under a different name and is
    /// never opened. That is what makes a verdict stale by construction rather
    /// than by a comparison a module could forget.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tools: Vec<crate::facts::ToolQuery>,

    /// The adopted gate runner's EFFECTIVE plan, per declared surface
    /// (CLOUD-949).
    ///
    /// Each row becomes an entry of `input.tree.plan` under its own `id`,
    /// carrying what the runner said it would run — acquired from the runner
    /// itself, never re-derived from its config, because the runner owns its
    /// selector and a second derivation is a second authority on which files a
    /// step runs over.
    ///
    /// **Acquired fresh rather than read back, which is the difference from
    /// `tools`.** A verdict is a statement about bytes that have a digest; a plan
    /// is a statement about a WORKING TREE, whose dirty and index state move
    /// without HEAD. Keying a stored plan would mean comparing every binding
    /// field before trusting it, and a comparison a caller can forget is the
    /// staleness class this avoids by simply taking the plan now.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub plan: Vec<PlanQuery>,
    /// The already-minted receipt fields this policy row reads, **declared**
    /// (CLOUD-1310).
    ///
    /// Each row becomes an entry of `input.tree.minted` under its own `id`,
    /// carrying `subject -> value` tokens taken from receipts the MEDIATED
    /// boundary wrote. The engine fetches nothing: the credential existed in the
    /// session that read the subject, and what happens here is a line off disk.
    ///
    /// **Bounded by AGE, and that is why this is not [`Rule::captured`].** The
    /// capture store is keyed by content and carries no clock, so a question
    /// about a MUTABLE field answers from whichever read sorts first by digest —
    /// the state before the work. Here a reading older than the row declares is
    /// simply absent, which is [`Rule::tools`]' stale-by-construction property
    /// rather than the capture store's.
    ///
    /// **Absent is the ORDINARY answer.** The receipt store lives under the git
    /// directory and is never committed, so on a fresh clone and on every CI
    /// runner it is empty. A module over this column therefore refuses narrowly
    /// and abstains widely, and one that read absence as agreement would report
    /// clean everywhere it matters least.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub minted: Vec<crate::facts::MintedQuery>,
    /// The reductions this policy row reads out of the capture store,
    /// **declared** (CLOUD-1188).
    ///
    /// Each row becomes an entry of `input.tree.captured` under its own `id`,
    /// carrying the REDUCTION it asked for — a boolean, a count, or a bounded
    /// token — and never the response it came from. A row declares what to reduce
    /// and how, because handing a module a payload would put a tracker's prose on
    /// the policy input where any predicate could lift it into a pointer.
    ///
    /// **The store, never stdin**: a stdin-fed fact is dropped by the surface
    /// table before projection, is context re-sent every turn, and is invisible to
    /// the `batten step` key — three independent refusals, any one of which is
    /// enough.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub captured: Vec<crate::facts::CaptureQuery>,
    /// The task manifests this row reads, **declared** (CLOUD-856).
    ///
    /// Parsed ONCE at session start and recorded; the mediated call reads the
    /// record. `Fact::Document` stays unresolvable on that path because a
    /// document is unbounded there, and this is how the one predicate that
    /// genuinely needs a manifest gets it without putting a parse on the hot
    /// path.
    ///
    /// The manifest's own bytes key the record, so a manifest that moves
    /// invalidates it by construction.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tasks: Vec<crate::facts::TaskQuery>,
    /// The extractions this row reads over the session's own transcript,
    /// **declared** (CLOUD-1172).
    ///
    /// Each row becomes an entry of `input.facts.extracted` under its own `id`,
    /// carrying an INTEGER — the extractor set is closed and every member counts
    /// a typed event, so no span of session text can reach a module through this
    /// column. An extractor no row declares yields nothing.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub extract: Vec<crate::facts::ExtractQuery>,
    /// The landing targets this policy row asks about, **declared** (CLOUD-880).
    ///
    /// Each becomes an entry of `input.tree.landing` answering whether THIS
    /// checkout's work is on that target — **by patch identity**, because CLOUD-36
    /// decides merged-ness that way and a rebased landing is invisible to
    /// ancestry. That is the question [`Rule::refs`] deliberately does not answer:
    /// a ref resolves to a commit there, and reachability was refused precisely so
    /// this column could carry the honest test instead.
    ///
    /// A target that cannot be scanned is **absent**, never a negative. It is the
    /// same absence-versus-empty rule as `refs` and `ranges`, and here it is the
    /// most dangerous of the three to get wrong: `landed: false` fabricated from a
    /// failed scan reads as *this work is outstanding* and a gate acts on it.
    ///
    /// Declaration bounds the cost. A scan walks the head-side commits and
    /// computes a patch id per commit, so it is one scan per named target rather
    /// than an ambient sweep of the trunk — the same bound `refs` puts on ref
    /// resolution, and what makes `Cost::Read` an honest classification.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub landing: Vec<String>,
    /// The globs whose paths this policy row wants classified against
    /// [`Rule::base`] — added, edited or deleted (CLOUD-1059).
    ///
    /// **Requires `base`**, and the load refuses the column without it, because a
    /// delta with no rev to compare against is not a narrower question but an
    /// unanswerable one. That is [`Rule::retires_with`]'s rule, and this column
    /// shares the `base` it reads on purpose: two spellings of "what did this
    /// branch change" is the drift a single column exists to prevent.
    ///
    /// Declaration bounds WHICH paths are reported and deliberately does not bound
    /// what answering costs — a glob is a selection over the whole tree, so the
    /// walk happens either way. That is why [`crate::facts::BASE_DELTA`] is
    /// `Surface::Check` and never `Hook`.
    ///
    /// A base that does not resolve leaves the whole fact `None`, projected as
    /// `null`, never an empty delta: "this branch changed nothing" and "I could
    /// not read the base" are the two answers a migration gate must keep apart.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub delta_sources: Vec<String>,
    /// The files OUTSIDE the repository root this policy row may read,
    /// **declared** (CLOUD-1167).
    ///
    /// Each row becomes an entry of `input.tree.external` under its own `id`,
    /// carrying the parsed node of the file found at `path` beneath the directory
    /// the named `root` environment variable holds.
    ///
    /// **This column is the entire bound, and the negative half is the point.** A
    /// module reads the ids ITS OWN row declares and nothing else, so no module
    /// can read a path no row names — which is the difference between a fact and
    /// a filesystem scanner, and what keeps house style §5's read-only allowlist
    /// and non-negotiable rule 1 satisfied. The engine expands a variable; it
    /// does not know what any variable means, so a launcher's or a toolchain's
    /// directory layout stays in the consumer's config where rule 1 puts it.
    ///
    /// An id whose root variable is unset, whose file is absent or unreadable, or
    /// whose bytes the parser refused is **absent** from the map and named in
    /// `missing` with its cause — never present with an empty node. "This host
    /// has no such root" and "the file says nothing" are different answers, and a
    /// gate that confuses them reports green on every host that never had the
    /// root.
    ///
    /// Declared on the row rather than in a root table so
    /// [`crate::trust::weakenings`] compares it for free: every `Rule` column
    /// outside `RULE_NON_PREDICATE` is compared byte-for-byte, so a branch
    /// repointing a row at a different file is reported as a weakening. That move
    /// — choosing the evidence — is exactly the one that has to be visible.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub external: Vec<crate::facts::Rooted>,
    /// The registered policy module this rule evaluates, as a repository-relative
    /// path (CLOUD-647). [`RuleKind::Policy`] only.
    ///
    /// **Registration, never discovery.** §8 forbids the upward directory walk
    /// and the `conf.d` merge; naming the module here, in the one committed
    /// authority, is the opposite of both, and the list of registered modules is
    /// itself reviewable data. Globbing a policy directory would be the thing §8
    /// refuses, and is why this is a path per row rather than a directory key.
    ///
    /// The path is what a reader reviews and what `[epoch] tracked` should hash;
    /// the module's SOURCE never appears in any emitted document, because a
    /// rendered policy body is a payload and rule 4 admits only pointers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub module: Option<String>,
    /// Why this rule's findings have no fix — the stated answer, which is not
    /// the same as an absent one (CLOUD-81).
    ///
    /// A finding a caller can neither clear nor act on spends attention for
    /// nothing, so "there is no fix" must be *said*. The **alternative** to
    /// [`Rule::fix`], never an addition: a row carrying both is a load error
    /// rather than a precedence rule nobody can read.
    ///
    /// This is the only column CLOUD-81 adds. `fix` already exists — CLOUD-215
    /// reserved it as the `command` kind's repair side — and
    /// [`Rule::remediation`] reads it rather than declaring a second spelling of
    /// the same thing. Recording a repair on a finding is not *running* one, so
    /// this does not disturb `run_all`'s refusal of a rule that declares it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub no_fix_reason: Option<String>,
    /// Why a declared repair does NOT hand the call back to be re-issued
    /// (CLOUD-1639).
    ///
    /// Required on a row whose class declares
    /// [`Applicability::Silent`], and rejected on every other
    /// row — the same both-directions shape [`Rule::no_fix_reason`] has, and for
    /// a sharper reason. `retry` is the posture the field supports: pre-commit
    /// fails the run when a hook modifies files, Ruff makes the caller opt in,
    /// and the one measurement of silent server-side rewrite put it 22.3% down
    /// on utility. So proceeding without telling the caller to re-issue is the
    /// exception, and an exception with no stated reason is a default wearing
    /// one.
    ///
    /// It is NOT [`Rule::no_fix_reason`]'s sibling in meaning: that one says why
    /// a row declares no repair at all, this says why a repair that RAN does not
    /// owe a re-issue. A row can honestly carry both.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub no_retry_reason: Option<String>,
    /// The receipts a [`RuleKind::Receipt`] row requires, all of which must be
    /// valid before the matched call is allowed. Required by that kind,
    /// rejected by every other.
    ///
    /// A list rather than a single name because the predicate this ports is
    /// already a conjunction — readying a PR requires that the branch both
    /// verified and is linear on the trunk — and expressing it as two rows
    /// would let one be deleted while the other kept the gate looking whole.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checks: Option<Vec<String>>,
    /// The receipts a [`RuleKind::Receipt`] row accepts **any one** of. Required
    /// by that kind when [`Rule::checks`] is absent, rejected by every other.
    ///
    /// The disjunction beside the conjunction, rather than a spelling inside
    /// `checks`, because the two say different things and a row usually wants
    /// both: `checks` is what must ALL hold, `checks_any` is one alternative
    /// among equals. A row carrying both is read as the conjunction of the two —
    /// every name in `checks` valid, AND at least one name here valid — which is
    /// conjunctive normal form and so expresses anything either column alone
    /// could not.
    ///
    /// The measured occasion is CLOUD-1297. `verify`'s own body accepts a
    /// `claim`, a `bot` or a `carry` receipt and treats any one as enough, and
    /// the mediated gate could not follow it: `claim-needs-receipt` demanded
    /// `claim` alone, so a branch legitimately carrying a `bot.<branch>` receipt
    /// was denied on every write despite holding a valid attestation — a live
    /// false positive since CLOUD-693, which CLOUD-1295's third receipt kind
    /// inherited. Spelling it as a second `checks` row could not work: a second
    /// receipt row is a second AND, so it would have denied every ordinary write
    /// on every branch.
    ///
    /// An ALTERNATION LOWERS A BAR, which is why a consumer row adopting one
    /// owes `config-lint` a groomed `Weakens:` clause. That is the raise-only
    /// discipline of house-style §8 working, not an obstacle to it: the column
    /// makes a weakening expressible and therefore reviewable, where before it
    /// was expressible only as a false positive nobody could remove.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checks_any: Option<Vec<String>>,
    /// Which git fact a [`RuleKind::Receipt`] row's receipts are keyed to.
    ///
    /// Optional with a pinned default of [`ReceiptKey::Head`], the conservative
    /// one: a HEAD-keyed receipt expires on an amend or a rebase, so omitting
    /// the key can only make a gate stricter than intended, never weaker.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<ReceiptKey>,
    /// What makes a [`RuleKind::Receipt`] row fire — a command shape, or the fact
    /// that the call writes (CLOUD-444).
    ///
    /// Optional with a pinned default of [`ReceiptTrigger::Command`], which is
    /// what every row written before this column meant. The axis is orthogonal to
    /// `key`: a trigger says *when* the precondition is due, a key says *what
    /// invalidates* the proof of it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trigger: Option<ReceiptTrigger>,
    /// The programs whose exit status IS the answer, for a
    /// [`RuleKind::Pipeline`] row (CLOUD-443).
    ///
    /// Declared on the rule rather than as a config-root table because it is what
    /// this rule is *defined over*: a global table would be a second authority
    /// with no other consumer, and the set would outlive the row that reads it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verdict: Option<Vec<VerdictProgram>>,
    /// The pipeline stages that substitute output for status — pagers and
    /// filters alike, since each replaces the verdict with its own.
    ///
    /// A plain name list, not a `VerdictProgram`: a filter's identity is the
    /// program, and no subcommand makes `tail` more or less of one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filters: Option<Vec<String>>,
    /// The text utilities whose use **as a first stage over a repository path**
    /// stands in for a first-class tool, for a [`RuleKind::Pipeline`] row
    /// (CLOUD-864).
    ///
    /// The second predicate this kind carries, and it belongs here for the
    /// reason the kind exists: what separates a substitution from a legitimate
    /// filter is not the program but **what surrounds it**. `grep pat crates/`
    /// answers a question `Grep` answers better; `git ls-files | grep crates/`
    /// is a filter over another command's output and no tool replaces it. Same
    /// program, same operand, opposite verdicts — and only the position in the
    /// pipeline tells them apart, which is precisely what a `shape` row cannot
    /// see (`matching_shape_rows` iterates every segment with no index in scope,
    /// so it would refuse the filter too).
    ///
    /// A plain name list, like `filters` and for the same reason: a substitute's
    /// identity is the program.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub substitutes: Option<Vec<String>>,
    /// The script interpreters whose script FILE operand must resolve inside the
    /// repository, for a [`RuleKind::Pipeline`] row (CLOUD-2304).
    ///
    /// The third family, and `substitutes`' mirror: the same first-stage walk,
    /// the same pipe bound, the containment test pointed the other way. A
    /// script file carries its writes in its own body, where no edit guard
    /// reads them, so one outside the tree is refused and one the tree holds —
    /// reviewed code — runs. A plain name list, the consumer's fact: which
    /// programs run a file operand varies by repository.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interprets: Option<Vec<String>>,
    /// What a [`RuleKind::Judge`] row asks the model — the committed evaluation
    /// instruction handed to the judge command (CLOUD-56).
    ///
    /// **Committed, and that is the point.** The question a model is asked is
    /// policy: it belongs in the authority a reviewer reads and a diff shows,
    /// not in a prompt assembled at run time out of something else. It is also
    /// the one payload class that carries no egress question at all
    /// ([`crate::judge::RuleText`]) — it is the config author's own words, on
    /// their way back to them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub criteria: Option<String>,
    /// How fast a [`RuleKind::Judge`] finding must be answered
    /// ([`crate::severity::AdvisoryTier`], CLOUD-80). Absent means
    /// [`AdvisoryTier::Advisory`], the least-urgent rank.
    ///
    /// This is the axis a judge row declares **instead of** `severity`, and the
    /// substitution is the whole advisory bound: `severity` decides the exit
    /// contract, `tier` decides a response deadline. A judge row is refused the
    /// `severity` column outright, so the axis a model's opinion could ride into
    /// the exit code does not exist for this kind.
    ///
    /// A default rather than a required column, unlike `severity` on every other
    /// kind: an omitted deadline resolves to the weakest one, which withholds no
    /// gate because there is no gate here to withhold.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tier: Option<AdvisoryTier>,
}

/// Which git fact a receipt is keyed to, and therefore what invalidates it.
///
/// The distinction is not a tuning knob, it is what the receipt *attests*.
/// A `head` receipt claims something about those exact bytes, so an amend or a
/// rebase must expire it. A `branch` receipt claims a decision about the work,
/// which every commit on the branch continues to serve, so a SHA-keyed one
/// would demand a re-claim per commit — the false-positive rate that gets a
/// guard bypassed. Both spellings are carried from the shell layer that proved
/// them (`ready-guard` keys by SHA, `claim-check` by branch).
///
/// **`ValueEnum` because the CLI selects the same keying** (CLOUD-741). A
/// `receipt` rule is pinned to [`RuleScope::MediatedCall`], so `batten check`
/// can never evaluate one and `verify` cannot reach this predicate through the
/// engine — which left `verify` re-implementing it in shell, weakly enough that
/// CLOUD-516's own incident passed. `receipt status --key branch` is how the
/// tree surface reaches the one implementation instead, so config and CLI must
/// name the keying with the same tokens or the two surfaces disagree about what
/// they asked for. `clap`'s and serde's renames both land on `head`/`branch`;
/// the `clap(rename_all)` is stated rather than inferred so a future variant
/// cannot drift them apart.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, ValueEnum)]
#[serde(rename_all = "lowercase")]
#[clap(rename_all = "lowercase")]
#[derive(Default)]
pub enum ReceiptKey {
    /// Keyed to the exact commit; an amend, a rebase, or a moved trunk expires it.
    #[default]
    Head,
    /// Keyed to the branch; every commit on it continues to serve the claim.
    Branch,
    /// Keyed to a value the CALL names, read through [`Rule::key_from`]
    /// (CLOUD-987).
    ///
    /// **The subject is one row of somebody's board, not one checkout**, and that
    /// is the whole reason this variant exists. CLOUD-312's row 2 bounds how stale
    /// a read may be before a write is authorised, and `issue-read-check`'s header
    /// says why the key cannot be the branch: *"a branch legitimately updates
    /// several issues; a branch key would let a fresh read of one issue authorise
    /// a stale write to another."* So collapsing this to [`ReceiptKey::Branch`]
    /// is not a simplification — it is the defect that comment refuses, and
    /// CLOUD-508 is the incident.
    ///
    /// **The value becomes a filename, so it is refused rather than sanitised.**
    /// [`SinkKey`]'s doc already states the hazard for a config-spelled key; a
    /// PAYLOAD-supplied one is strictly worse, because the call is what a rule is
    /// judging. A value that is not a single safe path component — empty, or
    /// carrying a separator, or `.`/`..`, or absurdly long — resolves to
    /// could-not-look and **allows**, rather than being rewritten into something
    /// that would file under a subject the caller did not name. Rewriting could
    /// silently collide two subjects onto one receipt, which is the one outcome
    /// worse than not looking.
    Named,
    /// Keyed to the identity of the branch's whole CHANGE against
    /// [`Rule::key_base`] (CLOUD-1547) — the read side of [`MintKey::Delta`].
    ///
    /// **The fourth keying, and it exists because the other three price a review
    /// at the wrong rate.** [`ReceiptKey::Head`] expires on every commit AND on
    /// every rebase, so a landing loop that rebases per lap re-buys the receipt
    /// each lap for a change that did not move — the false-positive rate
    /// [`ReceiptKey::Branch`]'s own doc says gets a guard bypassed.
    /// [`ReceiptKey::Branch`] goes the other way and expires on nothing but a
    /// restart, so a branch reviewed once may then push anything. Neither is
    /// *these bytes, however they were replayed*.
    ///
    /// The subject is [`crate::git::branch_patch_id`] — a merge-base diff over
    /// COMMITTED bytes with line numbers excluded — so a rebase that changes no
    /// content resolves to the same name and the receipt still answers, while a
    /// single changed line files it under a name nothing looks up.
    ///
    /// **Read through the one identity the mint writes under, never re-derived.**
    /// A second notion of *the same change* is free to disagree with the first
    /// about exactly the rebase this keying turns on, which is the class
    /// `.claude/rules/policy-modules.md` records for `base-delta` and the reason
    /// `receipt::delta_subject` and `mint::render` resolve through the same
    /// function rather than through two readings of one rule.
    ///
    /// An identity that does not resolve — no `key_base`, an unresolvable base
    /// ref, or an EMPTY diff — is could-not-look, and a rule keyed on it answers
    /// [`crate::receipt::Validity::Missing`] rather than fabricating a subject. A branch that
    /// changed nothing has no identity, and minting one would let two empty
    /// changes compare equal.
    Delta,
}

/// One field of a receipt, and what it must say (CLOUD-1100).
///
/// A struct rather than two flat columns because the pair is meaningless split:
/// a position with no required value decides nothing, and a required value with
/// no position has nothing to read. Spelling them as one table makes the
/// half-declared form unwritable rather than merely refused.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FieldBound {
    /// Which whitespace-separated field of the receipt's first line, 1-indexed.
    ///
    /// 1-indexed rather than 0-indexed because every prose reader of these
    /// receipts already counts that way — `claim-check` reads "field 4" and
    /// `finding-sink-check` "field 5" — and a config that counted differently
    /// from the comments describing it is a second convention nobody asked for.
    pub at: usize,
    /// The value that satisfies the row. Any other value refutes it; an absent
    /// field is could-not-look and satisfies.
    pub is: String,
}

/// A git fact a rule declares reading, for the three variants that take no
/// parameter (CLOUD-907).
///
/// The parameterised two are [`Rule::refs`] and [`Rule::ranges`]. A closed enum
/// rather than a string, for [`SinkKey`]'s reason: a name the config could spell
/// arbitrarily is a question the engine would have to answer at runtime, and an
/// unknown variant here is a load error rather than a fact that silently
/// resolves to undefined — which is the shape a Rego predicate reads as "does
/// not hold".
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize, JsonSchema,
)]
#[serde(rename_all = "kebab-case")]
pub enum GitRead {
    /// [`crate::facts::Fact::GitHead`] — HEAD's commit, branch and detachedness.
    Head,
    /// [`crate::facts::Fact::GitStatus`] — how the working tree differs from
    /// HEAD. Tree surface only: it walks the checkout.
    Status,
    /// [`crate::facts::Fact::GitRemote`] — the configured remotes and HEAD's
    /// upstream. Read from `.git/config`; never over the network.
    Remote,
    /// [`crate::facts::Fact::GitWorktrees`] — the linked worktree registrations,
    /// and whether each one's directory is still there (CLOUD-1424). Tree surface
    /// only: it lists the registry and stats each entry.
    Worktrees,
}

/// How a deletion proves it conserved LOGIC and not merely files (CLOUD-908).
///
/// [`Rule::retires_with`] admits a decrease when the deleted file's declared
/// subject died. That conserves **files**: it asks *is the subject gone* and never
/// *did the cases move*, so a migration can delete a suite and land green with
/// nothing asserting what replaced it. Measured on the one retirement that has
/// happened — 22 named cases deleted, 18 successors, six identifiable from
/// nothing in the tree, and one whose behaviour changed deliberately with no
/// mark on it.
///
/// This column closes that. Every named case in a file whose count fell must be
/// claimed, in the HEAD tree, by **exactly one** arm. Three shipped with
/// CLOUD-908 and the two optional ones arrived with the classes they are for —
/// which is why the count is not restated in prose: it went stale the moment
/// `withdrawn` landed, and this table is the authority instead.
///
/// | arm | means | obliges |
/// | --- | --- | --- |
/// | `carried` | the same assertion, in a new home | a target that resolves; feeds the differential replay |
/// | `subsumed` | a general property elsewhere now covers it | a target that resolves |
/// | `changed` | it diverges deliberately | a target that resolves **and** a reason |
/// | `ported` | it moved, and the subject STAYED | a target that resolves **and** the surviving subject |
///
/// An unclaimed case, an arm naming a target this tree does not have, or one case
/// claimed twice, all refuse the deletion.
///
/// **Declared, never inferred.** The same argument [`Rule::retires_with`] makes
/// for `# subject:`: a name heuristic over case titles would be worse than
/// nothing, because titles are prose. The engine knows the RELATIONSHIP — a
/// deleted named thing is claimed by exactly one arm naming something that
/// exists — and every token spelling it is the consumer's (non-negotiable rule 1).
///
/// **The arms live on their targets, and the walk that finds them is bounded by
/// declaration.** `declared_in` is the glob the head tree is read over, never an
/// ambient sweep: the same posture the git facts take, and the reason a mapping
/// is greppable rather than filed in a second register nothing keeps current.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Conserves {
    /// The line prefix a named case is declared after, in the file being deleted.
    ///
    /// The name STARTS immediately after this token and ENDS at the next
    /// [`Conserves::close`], so a token ending in the opening delimiter — `@test
    /// "` — reads the quoted title and nothing else on the line.
    pub case: String,
    /// The delimiter a case name ends at, in a dying file and in an arm alike.
    ///
    /// One field for both, because they are one question: an arm has to spell the
    /// case it claims the same way the case spells itself, or the match is between
    /// two different vocabularies and the mapping decides nothing.
    pub close: String,
    /// The token an arm claiming *the same assertion, moved* is written after.
    pub carried: String,
    /// The token an arm claiming *a general property covers this now* is written
    /// after.
    pub subsumed: String,
    /// The token an arm claiming *this diverges, deliberately* is written after.
    /// Alone among the three it also owes a reason — the text after its target.
    pub changed: String,
    /// The token an arm claiming *nothing replaces this, the subject is gone* is
    /// written after (CLOUD-1080). Optional, so a row without it behaves exactly
    /// as it did before this column existed.
    ///
    /// **The other three all name a successor, and a WITHDRAWAL has none.** They
    /// describe a suite migrating into another mechanism; this describes a feature
    /// removed, where the honest mapping is that there is nothing to map. Without
    /// it the only ways past a withdrawal are a false `subsumed` — a ledger entry
    /// that lies to pass — or a `[[waiver]]`, which `config-lint` refuses as
    /// `waiver-added` unless the weakening was groomed onto the issue before the
    /// work. So the gate had no honest path, which is a defect rather than a
    /// verdict.
    ///
    /// **It is admissible ONLY where the dying file's declared subject is absent
    /// at head**, which is what keeps it strictly narrower than the waiver it
    /// replaces: it cannot excuse deleting cases whose subject is still standing,
    /// and that is the abuse a bare fourth verb would open. It owes a reason and
    /// names no target, for the same reason it exists — there is no successor to
    /// name, and a column demanding one would be the false `subsumed` again.
    pub withdrawn: Option<String>,
    /// The token an arm claiming *the case moved, and the subject STAYED* is
    /// written after (CLOUD-1268). Optional, like [`Conserves::withdrawn`].
    ///
    /// **The exact mirror of the fourth arm, and that symmetry is the design.**
    /// `withdrawn` is admissible only where the dying file's declared subject
    /// died; this one only where it LIVES. Between them the two answers to "what
    /// happened to the subject" both have a spelling, and neither can be written
    /// over the other's condition.
    ///
    /// **The class it exists for was measured and had no honest route.** Where a
    /// migration retires one LAYER, a suite may declare a subject that layer never
    /// contains — a manifest, a tool config, a launcher program, a source file.
    /// [`SubjectFacts::died`] is `.all()`, so it can never hold for such a suite,
    /// which is undeletable BY CONSTRUCTION and in silence. Measured in this
    /// engine's own consumer, that was a fifth of a serial test corpus, including
    /// the longest single suite in a lane whose makespan cannot fall below it.
    ///
    /// Which paths those are is the CONSUMER's fact and is not named here
    /// (non-negotiable rule 1): the engine knows only that a declared subject
    /// survived. Both other routes edit the dying suite in place, which a consumer
    /// gate over authored rules may refuse outright — so the spelling has to live
    /// in the ledger, which is here.
    ///
    /// **It obliges MORE than `carried`, never less.** A target the tree carries,
    /// exactly as the first three do — and additionally a `subject:` field naming
    /// a path the DYING FILE ITSELF DECLARED at base and the head tree still
    /// carries. That field is what clears the aggregate subject-alive term, by
    /// naming the survivor rather than by a `carried` row falsely claiming the
    /// case moved into it. The subject is read from the base header rather than
    /// taken from the author, which is the anti-fabrication term: a row cannot
    /// name a convenient survivor it invented.
    pub ported: Option<String>,
    /// The glob the head tree is read over to find arms.
    ///
    /// Required rather than defaulted to the rule's own `glob`: the successors of
    /// a retired suite are by definition NOT under the glob the suite was, so a
    /// default would look total and select nothing — a mapping that admits
    /// everything, which is the failure this column exists to end.
    pub declared_in: String,
}

/// One program family whose **exit status is the answer** (CLOUD-443).
///
/// Enumerable on purpose. "Is this command's status the thing the caller wants"
/// is not decidable in general, and an open predicate would be a judgement
/// (non-negotiable rule 3) — so the set is a closed list the consumer declares,
/// and the read-only member of each family is excluded by name, because a query's
/// output *is* its answer and piping it is ordinary composition.
///
/// The four optional columns are not four ideas: each is the shape one real
/// family needs, and no row may carry two that contradict.
///
/// | column | matches | the family it exists for |
/// | --- | --- | --- |
/// | `subcommands` | first non-flag word is one of these | a task runner's `run`, a VCS's mutating verbs |
/// | `nested` | second non-flag word is one of these | a forge CLI's `<noun> <verb>` |
/// | `except` | a first word exists and is NOT listed | a build tool with far more verdict subcommands than query ones |
/// | `any_argument` | a first word merely exists | a test runner, where a bare invocation prints usage and answers nothing |
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct VerdictProgram {
    /// The program name as it appears on a command line. Matched exactly, on the
    /// EFFECTIVE program — wrapper lookthrough is the hook parser's, not a second
    /// implementation here.
    pub program: String,
    /// The first non-flag words that make this program verdict-bearing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subcommands: Option<Vec<String>>,
    /// The second non-flag words, for a program that dispatches twice. Requires
    /// `subcommands`, since a nested word with nothing above it names no action.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nested: Option<Vec<String>>,
    /// The first non-flag words that are **queries** — everything else is a
    /// verdict. The inverse of `subcommands` and refused alongside it: a row
    /// cannot both allow-list and deny-list the same position.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub except: Option<Vec<String>>,
    /// Whether any first non-flag word at all makes this a verdict, for a program
    /// whose bare form answers nothing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub any_argument: Option<bool>,
}

impl VerdictProgram {
    pub(crate) fn matches(&self, program: &str, words: &[&str]) -> bool {
        if self.program != program {
            return false;
        }
        let first = words.first().copied();
        if let Some(allowed) = self.subcommands.as_deref() {
            let Some(first) = first else { return false };
            if !allowed.iter().any(|candidate| candidate == first) {
                return false;
            }
            let Some(nested) = self.nested.as_deref() else {
                return true;
            };
            return words
                .get(1)
                .is_some_and(|second| nested.iter().any(|candidate| candidate == second));
        }
        if let Some(queries) = self.except.as_deref() {
            return first.is_some_and(|first| !queries.iter().any(|query| query == first));
        }
        self.any_argument.unwrap_or_default() && first.is_some()
    }
}

impl VerdictProgram {
    pub(crate) fn validate(&self, rule: &str) -> anyhow::Result<()> {
        let refuse = |detail: &str| {
            Err(UsageError::raise(format!(
                "rule {rule}: verdict {}: {detail}",
                self.program
            )))
        };
        if self.program.trim().is_empty() || self.program.split_whitespace().count() != 1 {
            return Err(UsageError::raise(format!(
                "rule {rule}: a verdict entry names one program, not {:?}",
                self.program
            )));
        }
        for (name, list) in [
            ("subcommands", self.subcommands.as_deref()),
            ("nested", self.nested.as_deref()),
            ("except", self.except.as_deref()),
        ] {
            if list.is_some_and(<[String]>::is_empty) {
                return refuse(&format!("`{name}` is empty, so it narrows nothing"));
            }
        }
        if self.subcommands.is_some() && self.except.is_some() {
            return refuse("`subcommands` and `except` are opposite readings of the same position");
        }
        if self.nested.is_some() && self.subcommands.is_none() {
            return refuse(
                "`nested` needs `subcommands` — a second word with no first names nothing",
            );
        }
        let any = self.any_argument.unwrap_or_default();
        if any && (self.subcommands.is_some() || self.except.is_some()) {
            return refuse("`any_argument` already admits every word, so it cannot be narrowed");
        }
        if !any && self.subcommands.is_none() && self.except.is_none() {
            return refuse("declares no condition, so it never matches");
        }
        Ok(())
    }
}

/// The mediator a [`Rule::require_via`] row requires (CLOUD-271).
///
/// One variant, deliberately, and it is a variant rather than a string because
/// the set is the set of mediators the matcher knows how to look for. A free
/// string would let a typo load as a row that never finds its mediator and
/// therefore refuses every call — a gate that reads as narrow and denies wide.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum RequireVia {
    /// The pinned toolchain: the call reached its program through `mise`.
    ///
    /// `mise run <task>` and `mise exec -- <program>` both count. They are the
    /// same fact for this key — the program was selected by the pin rather than
    /// by `PATH` — and only the second reaches the program token at all, since
    /// `mise run` names a task and is judged as `mise` itself.
    Mise,
}

/// What makes a receipt row fire (CLOUD-444).
///
/// The two triggers answer different questions and neither subsumes the other. A
/// [`ReceiptTrigger::Command`] row says "before you run *this*, prove *that*" —
/// the precondition is due at one recognisable invocation, and the row names it
/// with a `pattern`. A [`ReceiptTrigger::Write`] row says the precondition is due
/// before the work is *touched at all*, which no command shape can express:
/// the claim gate fires on every write precisely because the edit it exists to
/// catch is the first one, whatever tool makes it.
///
/// A write-triggered row therefore carries no `pattern` and no `contains` — both
/// name a command line a write does not have — and its exclusions (git-ignored,
/// outside the repository, inside `.git`) are boundary facts rather than config,
/// because they are questions about a checkout and this table is not.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum ReceiptTrigger {
    /// Fires on a mediated command matching the row's `pattern`.
    #[default]
    Command,
    /// Fires on any mediated call that writes a judgeable path.
    Write,
}

/// Which way a ratcheted count may move.
///
/// Named for the *permitted* direction rather than the banned one, so a config
/// row reads as the promise it makes: `non_decreasing` says this count will not
/// fall.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum Direction {
    /// The count may rise or hold, never fall. The test-deletion guard.
    NonDecreasing,
    /// The count may fall or hold, never rise. The new-`#[ignore]` guard.
    NonIncreasing,
}

impl Direction {
    pub const ALL: &'static [Direction] = &[Direction::NonDecreasing, Direction::NonIncreasing];
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Direction::NonDecreasing => "non_decreasing",
            Direction::NonIncreasing => "non_increasing",
        }
    }
    #[must_use]
    pub fn violated(self, base: usize, working: usize) -> bool {
        match self {
            Direction::NonDecreasing => working < base,
            Direction::NonIncreasing => working > base,
        }
    }
}

/// The `[hook]` table: what this repository attaches to hook events.
///
/// A table rather than a bare `[[hook.action]]` array at the top level, so the
/// noun has somewhere to grow — and so the config surface reads the way the
/// house style names it (§9).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HookConfig {
    /// The declared actions, in declaration order. Order is the firing order:
    /// a reader should be able to predict it from the file without a rule.
    #[serde(default, rename = "action", skip_serializing_if = "Vec::is_empty")]
    pub actions: Vec<Action>,
    /// The declared handlers, in declaration order (CLOUD-898).
    ///
    /// Order is the running order, and it decides which of two refusals is
    /// reported — so a reader predicts it from the file rather than from a rule,
    /// exactly as `action`'s firing order is.
    ///
    /// A SECOND NOUN IN THE SAME TABLE, not a widening of the first. An action
    /// is a side effect that cannot change the answer; a handler participates in
    /// the decision. They share `[hook]` because they answer the same question —
    /// what does this repository attach to hook events — and stay separate
    /// because they make opposite promises about the answer.
    #[serde(default, rename = "handler", skip_serializing_if = "Vec::is_empty")]
    pub handlers: Vec<Handler>,
    /// Whether this repository declares its hook surfaces **exclusively**
    /// batten's: one `batten hook` registration per emitted event, and no other
    /// command registered natively beside it (CLOUD-893).
    ///
    /// **A DECLARATION, and that is what makes it expressible at all.** Whether a
    /// hook beside batten's is legitimate is a consumer's judgement — the reason
    /// [`crate::doctor::HarnessWiring::siblings`] gives for being a count and
    /// never a failure — so the engine may not decide it. What the engine CAN do
    /// is enforce what a consumer decided, and this is where that decision is
    /// written down. Naming the invariant in `crates/batten` while leaving the
    /// choice to the config is what keeps non-negotiable rule 1 intact.
    ///
    /// **Raise-only (house-style §8), which is the whole difference between this
    /// and a waiver.** Absent or `false` is today's behaviour, so no adopter
    /// inherits a verdict by upgrading; `true` can only ever ADD refusals. That
    /// is categorically unlike a declaration that suppresses one — a sibling
    /// table naming an issue that will retire each entry reads as diligence and
    /// functions as a permanent exemption, and it is what let this repository
    /// report green over ten non-batten registrations.
    ///
    /// It says nothing about handlers: a `[[hook.handler]]` runs BEHIND `batten
    /// hook` rather than beside it, so it is not a native registration and this
    /// flag never refuses one.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub exclusive: bool,
    /// The git hooks this repository runs, by githooks(5) name, each the argv
    /// batten passes git's own arguments and streams through to (CLOUD-2339).
    ///
    /// Every git hook links to the batten binary, which dispatches on argv[0];
    /// a name with no row exits 0. One table, no directory walk (rule 6).
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub git: std::collections::BTreeMap<String, Vec<String>>,
}

/// One declared side effect.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Action {
    /// The stable identifier a failure is reported under.
    ///
    /// Separate from the command for [`crate::config_model::Marker`]'s reason: the
    /// argv is free to change without the thing it is called in reports changing
    /// with it.
    pub id: String,
    /// The event this action fires on, as [`Event::as_str`] spells it.
    ///
    /// A **normalized** token, never a host's own word: an action declared once
    /// should fire on every host that offers the moment, and keying it on
    /// Claude's spelling would silently not fire on Gemini's.
    pub on: String,
    /// The command, as argv. Never a shell string.
    ///
    /// argv rather than a command line because there is then no quoting layer
    /// between what an operator wrote and what runs — no word splitting, no
    /// glob expansion, no `$(…)`. §9's rule is that an extension surface names
    /// a command already on the operator's PATH; this is that, with the
    /// arguments spelled out rather than parsed back out of a string.
    pub run: Vec<String>,
}

/// The `[attribution]` table: what produced commits may carry about the tooling.
///
/// Consumer-specific by nature (non-negotiable rule 1, extended from consumers to
/// vendors): the engine holds the matcher, this table holds the answer. A vendor
/// name is configuration here and never a literal in the crate.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Attribution {
    /// Patterns refused in the `author` and `committer` identity fields.
    ///
    /// Both fields, because the environment sets both and a repair reaching only
    /// `author` leaves the vendor identity on every commit's `committer` — absent
    /// from `git log`'s default format and fully public regardless.
    pub identity_deny: Vec<String>,
    /// Patterns refused in any trailer, matched against the whole `Key: value`
    /// line: a co-authorship form lives in the key, a session URL in the value.
    pub trailer_deny: Vec<String>,
    /// Patterns refused in the commit message body — attribution-as-advertising.
    pub body_deny: Vec<String>,
    /// The carve-out from [`Attribution::trailer_deny`]. Absent or empty exempts
    /// **nothing**, which is how a silent posture is expressed as data.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub trailer_allow: Vec<String>,
    /// Identities permitted to have cut a release tag (CLOUD-1794).
    ///
    /// AN ALLOW LIST, AND A SEPARATE ONE FROM [`Attribution::identity`], because
    /// the two answer different questions and measurably hold different values.
    /// `identity` is what `attribution identity` WRITES into a clone's git config
    /// — the identity commits must be authored by. A release tag is cut by
    /// whatever credential the release workflow holds, which renders as that
    /// account's identity and need not be the committing one. Measured on this
    /// repository: every tag from v0.0.155 to v0.0.162 was cut by an address that
    /// is not `identity`'s, and the history carries both as legitimate.
    ///
    /// Judging tags against `identity` therefore refuses every release, which is a
    /// worse outage than the one this gate exists to catch — and is exactly what
    /// the first draft did before it was run against real tags.
    ///
    /// A LIST rather than one value, because the accountable credential changes:
    /// migrating from a personal token to an org-owned App (CLOUD-94) changes the
    /// identity tags carry, and a transition where both are briefly valid should
    /// be expressible without leaving the gate off.
    ///
    /// DEFAULTED, AND THAT IS NOT THE SAME CLAIM AS "AN EMPTY LIST IS FINE"
    /// (CLOUD-1789). The first draft made this mandatory and conflated two
    /// questions: whether an empty list is a policy — it is not — and whether
    /// every consumer must answer this one, which it must not. `Attribution`
    /// carries `deny_unknown_fields`, so a required field here makes any config
    /// written before this key existed fail to parse, which is a breaking change
    /// to a table that governs commits rather than tags; it was caught by
    /// `trust::tests::shrinking_a_deny_list_or_widening_the_carve_out_is_a_weakening`,
    /// whose fixture is a `[attribution]` table with no reason to mention tags.
    ///
    /// ABSENT IS COULD-NOT-LOOK, NEVER CLEAN, which is where the "empty is not a
    /// policy" half survives: [`Attribution::judge_tagger`] refuses to decide over
    /// an empty list rather than passing every tag. So a consumer that does not
    /// govern tag identity is unaffected — it never calls the verb — and one that
    /// calls the verb without declaring the key gets a loud exit `1` instead of a
    /// false green. That is the asymmetry rather than a softening of it.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tag_identity_allow: Vec<String>,
    /// A committed accountable identity: still parsed, NEVER consulted
    /// (CLOUD-2659).
    ///
    /// Who answers for a commit is the person making it, and a name committed
    /// here reaches every clone, so `attribution identity` resolves the person at
    /// run time instead (git, the session owner, the forge user). Optional so a
    /// table without it loads; kept parseable so a consumer that still carries
    /// one does not break. A present table is still refused with a blank half.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity: Option<Identity>,
}

/// The identity a commit is accountable to.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Identity {
    /// `user.name`.
    pub name: String,
    /// `user.email`.
    pub email: String,
}

impl Identity {
    #[must_use]
    pub fn rendered(&self) -> String {
        format!("{} <{}>", self.name, self.email)
    }
}

/// **Serialized in `clap`'s spelling, not serde's default** (CLOUD-925). A
/// `[[rule]]` ceiling names a projection with `measures`, so this enum is now
/// config vocabulary as well as CLI vocabulary — and `kebab-case` is what
/// `ValueEnum` already renders, so `--field last-assistant-message` and
/// `measures = "last-assistant-message"` are one spelling. Taking serde's
/// `snake_case` default would have given the same variant two names, which is
/// the drift the shared type is here to prevent.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum, Deserialize, Serialize, JsonSchema,
)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum Field {
    /// The host's own event spelling, echoed back untouched.
    ///
    /// UNNORMALIZED on purpose, and the reason is now the ECHO rather than a gap
    /// in [`Event`].
    ///
    /// **The premise this cited is gone, re-read rather than amended a third
    /// time (CLOUD-777, 2026-08-21).** The comment argued from absence twice: it
    /// read *"knows neither `UserPromptSubmit` nor `PostToolBatch`"* until
    /// `PostToolBatch` landed (CLOUD-389), was corrected to cite
    /// `UserPromptSubmit` alone (CLOUD-817), and said in as many words that
    /// answering CLOUD-817 *yes* would remove the premise rather than amend it.
    /// It is answered yes: [`Event::UserPromptSubmit`] exists, so
    /// [`Event::normalize`] now knows every spelling a supported host emits and
    /// the absence argument has nothing left to stand on.
    ///
    /// What survives is a property of the CONSUMER rather than of the enum: a
    /// hook wired to more than one event echoes this value back into its own
    /// reply, and a host reads its own spelling there. `contract-drift` is the
    /// registered example. Normalizing here would hand it `session-start` where
    /// the host said `SessionStart`, so the field stays the host's token and
    /// [`Envelope::event`] stays the concept — the same split those two fields
    /// carry everywhere else.
    HookEventName,
    /// The host's session id.
    SessionId,
    /// The tool being mediated.
    ToolName,
    /// The command text, for shell-shaped tools.
    Command,
    /// The host's working directory.
    Cwd,
    /// Whether this is a re-entered `Stop` hook.
    StopHookActive,
    /// The assistant's last message.
    ///
    /// The one prose-bearing member, and it is here because `stop-guard`
    /// already receives exactly these bytes by exactly this route — it pipes
    /// them straight to `stop-posture-check`. Moving the read from `jq` to here
    /// changes which process parses the payload, not what flows where; rule 4
    /// governs what a CHECK reports, and this is a decoder, not a verdict.
    LastAssistantMessage,
    /// The path to the session transcript.
    TranscriptPath,
    /// The prompt a subagent spawn commits a fresh context window to.
    ///
    /// The second prose-bearing member, admitted on `LastAssistantMessage`'s
    /// argument rather than a new one: this is a DECODER, and rule 4 governs
    /// what a check reports. `fanout-guard` (CLOUD-287) reads these bytes to
    /// count them and emits only a count, a cap and repo paths — never a byte of
    /// the prompt.
    ///
    /// It is also the member that could not be served any other way. A spawn is
    /// not shell-shaped, so `Command` is empty for it, and the prompt lives in
    /// [`Envelope::input`] — which is exactly what this allowlist exists to keep
    /// a caller from addressing by path. Naming this one projection is the
    /// deliberate edit the type's own doc calls for.
    ///
    /// APPENDED, never inserted. `semver` reads a reordered variant as
    /// `enum_no_repr_variant_discriminant_changed` — a break — and this addition
    /// is patch-compatible only at the end. The order carries no meaning.
    Prompt,
    /// Whether the host was asked to run this call in the background.
    ///
    /// `"true"` or `"false"`, never the flag's own JSON spelling: the caller is
    /// a shell script comparing against a literal, and a decoder that echoed
    /// `True` or `1` for some host would move the per-harness normalization out
    /// of here and into every script.
    ///
    /// THE SECOND MEMBER READ OUT OF [`Envelope::input`], and the less exposed
    /// of the two. The allowlist's safety argument is that it can never name
    /// [`Envelope::input`] wholesale, because a tool input is among the likeliest
    /// places in this engine for a secret to appear (non-negotiable rule 4); a
    /// boolean projection of one named key cannot carry one. Absent reads as
    /// absent rather than as `false` — "the host did not say" and "the host said
    /// no" are the same decision for every caller today, but collapsing them
    /// here would make them inseparable for one that is not.
    ///
    /// CLOUD-613 named this as a fact the mediated envelope hides, which is why
    /// `run-shape-guard`'s surviving families could not be expressed as config
    /// rows. It is hidden no longer; growing this allowlist is the deliberate
    /// edit the type's own doc calls for, and CLOUD-821 is the caller that
    /// needed it.
    ///
    /// APPENDED, never inserted, for the reason stated on [`Field::Prompt`].
    RunInBackground,
    /// The `id` a structured call names its subject by (CLOUD-987).
    ///
    /// THE THIRD MEMBER READ OUT OF [`Envelope::input`], and it is what lets a
    /// row tell **creating** a thing from **annotating** one. CLOUD-312's rows 1
    /// and 3 both turn on it: a `save_issue` carrying no `id` opens a row, one
    /// carrying an `id` edits a row that already exists, and gating the second
    /// as though it were the first is the outcome `issue-search-guard`'s own
    /// header says *"would get the guard switched off within a day."*
    ///
    /// The allowlist's safety argument is unchanged and is the reason this is a
    /// MEMBER rather than a config-named key: it can never address
    /// [`Envelope::input`] wholesale, so a caller cannot point a rule at an
    /// arbitrary path in the likeliest place in the envelope for a secret. A key
    /// somebody enumerated here cannot carry one by accident.
    ///
    /// A non-string value reads as absent rather than as its debug rendering,
    /// [`Field::Prompt`]'s rule: a caller comparing identifiers must never be
    /// handed `{"a":1}` and told it is one.
    ///
    /// APPENDED, never inserted, for the reason stated on [`Field::Prompt`].
    InputId,
    /// The `state` a structured call moves its subject to (CLOUD-987).
    ///
    /// The fourth and last member read out of [`Envelope::input`], on
    /// [`Field::InputId`]'s argument. `board-move-guard` (CLOUD-312's row 3)
    /// fires only when a call MOVES something rather than merely editing it, so
    /// without this the row would gate every edit — the same over-fire
    /// [`Field::InputId`] exists to prevent one key over.
    ///
    /// APPENDED, never inserted, for the reason stated on [`Field::Prompt`].
    InputState,
    /// Whether a structured call sets its subject's `draft` flag (CLOUD-2260).
    ///
    /// `"true"` or `"false"`, [`Field::RunInBackground`]'s rendering and its
    /// safety argument: a boolean projection of one named key cannot carry a
    /// secret. It exists because readying a pull request is not only a shell
    /// command — a forge connector's update call setting `draft` to `false` fires
    /// the same `ready_for_review` and buys the same CI matrix, and a gate keyed on
    /// `gh pr ready` alone left that route open.
    ///
    /// APPENDED, never inserted, for the reason stated on [`Field::Prompt`].
    InputDraft,
}

/// What a mint's receipt is filed under.
///
/// The two keyings the censused receipts actually use, and a closed enum rather
/// than a free string for [`crate::sink::SinkKey`]'s reason: a key a config
/// could spell arbitrarily is a filename a config could point anywhere, and the
/// store lives under `$GIT_DIR`.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize, schemars::JsonSchema,
)]
#[serde(rename_all = "kebab-case")]
pub enum MintKey {
    /// Filed under a subject the RESULT names — one row of somebody's board.
    /// The subject comes from [`MintDeclared::key_from`].
    Named,
    /// Filed under the current branch, so every commit on it continues to serve
    /// the same record.
    Branch,
    /// Filed under the identity of the branch's whole CHANGE against
    /// [`MintDeclared::key_base`] (CLOUD-1484).
    ///
    /// **The third keying, and it exists because neither of the two above can
    /// key a receipt to the bytes a review actually read.** [`MintKey::Named`]
    /// takes its subject from the tool result, which knows nothing about the
    /// repository; [`MintKey::Branch`] takes a name that outlives every commit
    /// under it, which is the staleness defeat
    /// [`crate::receipt::branch_validity`] already had to be written to patch
    /// around (CLOUD-516).
    ///
    /// The identity is [`crate::git::branch_patch_id`], so it moves when the
    /// change moves and does NOT move when a rebase merely relocates it. Both
    /// halves are load-bearing: without the first a receipt would outlive the
    /// code it attests to, and without the second the landing loop would re-buy
    /// the attested work on every lap, which is the shape that gets a gate
    /// switched off rather than satisfied.
    Delta,
}

/// Whether a mint replaces its record or appends to it.
///
/// The distinction is the censused one and it is not cosmetic. A read receipt
/// answers *how old is the newest read*, so the freshest must overwrite the
/// stalest; a search receipt accumulates what the author has seen, so it appends.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize, schemars::JsonSchema,
)]
#[serde(rename_all = "kebab-case")]
pub enum MintMode {
    /// Truncate and write. The freshest answer is the only answer.
    Replace,
    /// Append a line. The record is a journal of what was seen.
    Append,
    /// Remove the record (CLOUD-2083). The call this row selects ENDS what a
    /// sibling row of the same name recorded: a marker minted when a pull request
    /// opened is gone once it is closed unmerged, where only the landed path used
    /// to sweep it. Nothing is written, so the body is rendered only to prove the
    /// row's `requires` held.
    Clear,
}

/// One receipt this repository mints from a tool result.
///
/// Every column is a consumer's string or a closed enum; nothing here names a
/// tracker, a tool or a field (non-negotiable rule 1).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MintDeclared {
    /// The receipt namespace — the same token a `receipt` rule's `checks` list
    /// names, so the file this writes is the file that rule reads.
    pub name: String,
    /// Which tool's result mints it, matched by [`crate::facts::selects_tool_name`].
    ///
    /// **A tool name, never a field shape.** A write response and a read payload
    /// are shape-identical across the fields either carries, so duck-typing lets
    /// the later, poorer payload win; and the match is on the whole name or its
    /// whole final `__`-delimited segment because a connector is exposed under
    /// more than one name over its lifetime (CLOUD-178).
    pub tool: String,
    /// What the record is filed under.
    pub key: MintKey,
    /// The path whose value is the subject, for [`MintKey::Named`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_from: Option<String>,
    /// The INPUT path whose value is the subject, for [`MintKey::Named`]
    /// (CLOUD-2294): the alternative to [`MintDeclared::key_from`], exactly one of
    /// which a `named` row declares.
    ///
    /// A dispatch names its subject in its ARGUMENTS — the row a skill was asked
    /// to groom — and answers with prose, so a result path has nothing to read.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_from_input: Option<String>,
    /// A pattern the subject must match, or the row mints nothing (CLOUD-2294).
    ///
    /// [`crate::config_check::receipt::safe_subject`] bounds a subject STRUCTURALLY and admits
    /// a space, so free-text arguments ("groom M2 to ready") would file under
    /// themselves. What a row key looks like is the consumer's fact (rule 1), so
    /// it is declared here, read exactly as a `receipt` rule's `key_shape` is:
    /// unanchored, so the author writes `^…$`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_shape: Option<String>,
    /// The base ref the change is measured against, for [`MintKey::Delta`].
    ///
    /// Declared rather than defaulted: which ref a branch is *a change against*
    /// is the consumer's fact, and an engine that assumed one would be naming a
    /// branch in a repo-agnostic core (non-negotiable rule 1).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_base: Option<String>,
    /// The path whose value must equal [`MintDeclared::selects`] for this row to
    /// mint at all (CLOUD-1484).
    ///
    /// # Why presence could not do this job
    ///
    /// [`MintDeclared::requires`] asserts a path is present and non-null, which is
    /// the right shape for a SUCCESS predicate and the wrong one for a
    /// SELECTION. A harness that dispatches every one of its skills, agents or
    /// commands through one tool name gives [`MintDeclared::tool`] nothing to
    /// discriminate on: the row would mint on every invocation of that tool and
    /// the receipt would attest that *something* ran. That is a false green in
    /// the one direction a dispatch gate exists to refuse, and no amount of
    /// `requires` reaches it, because the field is present either way — it just
    /// holds another value.
    ///
    /// **The shape is adopted, not invented.** [`crate::capture`] already
    /// resolves a stored response by `key_at`/`key` through [`scalar`], the same
    /// selector this uses, so a path spelled here means what it means there.
    ///
    /// Absent leaves the row judged exactly as it was before this column
    /// existed: [`MintDeclared::tool`] alone decides, which is every landed row's
    /// behaviour.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selects_at: Option<String>,
    /// The value [`MintDeclared::selects_at`] must hold. Compared for EQUALITY,
    /// never as a substring: a prefix match would let a longer name a consumer
    /// never declared mint under a shorter one's row.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selects: Option<String>,
    /// Paths that must be present and non-null in the result for anything to be
    /// written. **This is the success predicate** — see the module doc.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub requires: Vec<String>,
    /// A receipt that must already be on file UNDER THE SAME KEY for this row to
    /// mint at all (CLOUD-2261): the name of another declared writer row.
    ///
    /// # Why a dispatch could not attest a completion
    ///
    /// A host that answers a skill dispatch with `Launching skill: <name>` has
    /// said only that the ask happened. A receipt minted there attests the
    /// review was ASKED FOR over these bytes, and a gate reading it lets a change
    /// through that nobody finished reviewing. The completion is a DIFFERENT
    /// call — the one the skill ends with — and that call names no change and no
    /// skill, so on its own it would attest that *some* review finished over
    /// *something*.
    ///
    /// The two halves together are the attestation: the dispatch row selects
    /// which review over which change, and the completion row mints the receipt
    /// a gate reads only when that dispatch is on file under the identity the
    /// completion resolves now. A change committed between the two moves the key,
    /// so the earlier dispatch no longer answers and the completion mints nothing.
    ///
    /// Absent leaves the row judged exactly as before the column existed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub after: Option<String>,
    /// How `after` is met (CLOUD-2680): `spend` (the default) consumes the
    /// prerequisite, so one dispatch answers one completion; `require` only
    /// checks it is on file, so one bridge admits every dependent over the same
    /// change. Absent never serializes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub after_mode: Option<AfterMode>,
    /// Whether the record is replaced or appended.
    pub mode: MintMode,
    /// The record's bytes, as a template over the closed placeholder vocabulary
    /// [`Piece`] documents.
    pub body: String,
}

/// How a `[[mint]]` row's `after` prerequisite is met (CLOUD-2680).
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "lowercase")]
pub enum AfterMode {
    /// The prerequisite is consumed by the record it admits.
    #[default]
    Spend,
    /// The prerequisite is checked and left on file.
    Require,
}

/// Every vendored preset's name, in a stable order.
///
/// Derived from [`crate::preset_catalog::MANIFESTS`] so the binary and the published
/// schema cannot
/// disagree about what may be enabled — the same discipline `surface::SURFACE`
/// carries, and the reason an unknown name is a config error rather than a
/// silent no-op.
#[must_use]
pub fn preset_names() -> Vec<&'static str> {
    crate::preset_catalog::names()
}

/// Which resolver a [`Provision`] row is turned into a cached binary by
/// (CLOUD-970).
///
/// **One variant today, and that is the deliverable rather than a placeholder.**
/// The indirection is what makes a second resolver a row rather than a branch;
/// a real second backend is the row that proves it was worth having, and landing
/// one here would be two changes wearing one commit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
#[non_exhaustive]
pub enum Backend {
    /// Fetch a pinned URL, verify its SHA-256, unpack it, place the binary.
    ///
    /// The behaviour every committed row already has, named so it can be one of
    /// several rather than the only thing a row can mean.
    #[default]
    Native,
}

/// One provisioned tool.
///
/// The `oneOf` mirrors [`validate_artifact_spelling`]'s xor into the derived
/// schema, the same way [`crate::config_model::Rule`] mirrors its severity conditional:
/// an author editing `batten.toml` against the published schema gets the refusal
/// in their editor rather than on the next run. It is a **second expression of
/// one rule, never a second authority** — the loader's check is what decides, and
/// it is what the error message comes from.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(extend("oneOf" = serde_json::json!([
    { "required": ["url", "sha256"], "not": { "required": ["platforms"] } },
    { "required": ["platforms"], "not": { "anyOf": [
        { "required": ["url"] },
        { "required": ["sha256"] }
    ] } }
])))]
pub struct Provision {
    /// Which resolver turns this row into a cached binary (CLOUD-970).
    ///
    /// **The row names what it wants; a backend resolves it.** Every entry was
    /// implicitly one resolver — fetch a URL, verify a checksum, unpack, place a
    /// binary — and that shape is right but was not named, so a second one could
    /// not be added without a compatibility branch beside every read of `url`.
    /// mise's answer to the same problem is the backend (`ubi:`, `aqua:`,
    /// `cargo:`), and it is the pinned toolchain here, so this is adopting prior
    /// art rather than expanding the core.
    ///
    /// **Absent is [`Backend::Native`], which is what makes this additive.** Every
    /// committed row keeps its meaning and its bytes; `expand → migrate →
    /// contract` needs no migrate step when the expansion has a default that IS
    /// the old behaviour. An unknown backend is a load-time config error naming
    /// it — never a silent skip, which is the direction a row that resolved to
    /// nothing would fail in.
    ///
    /// Non-negotiable rule 1 draws the boundary: the backend VOCABULARY is
    /// generic and lives here, while which backend a consumer picks and what it
    /// resolves lives in that consumer's `batten.toml`.
    #[serde(default)]
    pub backend: Backend,
    /// The entry's name, unique within the manifest. Also the first cache path
    /// segment, so two tools never share a directory.
    pub name: String,
    /// The pinned version. Encoded in the cache path, so two pinned versions
    /// coexist and a version change is a cache miss rather than an overwrite.
    pub version: String,
    /// Where the artifact comes from, when one artifact serves every platform.
    /// `https://` or `file://` — see the module docs for why those two and no
    /// others.
    ///
    /// Mutually exclusive with [`Provision::platforms`]; see that field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// The SHA-256 of the artifact, lowercase hex. The whole equality test.
    ///
    /// Paired with [`Provision::url`], and refused without it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    /// Per-platform artifacts, keyed `<os>-<arch>` — `linux-x86_64`,
    /// `macos-aarch64`, `windows-x86_64`.
    ///
    /// **Exactly one of this and the `url`/`sha256` pair**, refused at load
    /// rather than at fetch. Two spellings exist because two genuinely different
    /// things get pinned: a platform-independent artifact (a script, a jar, a
    /// test fixture) has one URL and gains nothing from a table, while a
    /// compiled tool ships one artifact per target and cannot be expressed
    /// without one. Collapsing them would force every entry to name a platform
    /// it does not have, and the xor is the same shape `RuleKind::Forbid`'s
    /// `pattern`/`regex` predicate already uses.
    ///
    /// The key is `{os}-{arch}` read straight off [`std::env::consts`] rather
    /// than a Rust target triple. That is what the running binary can actually
    /// observe about itself; a triple would need a mapping table, and the arm
    /// that guesses `-gnu` versus `-musl` from `os = "linux"` is a guess that
    /// installs a binary the host cannot run. The granularity is the same one
    /// `mise.lock` uses, and it inherits the same limitation, stated rather than
    /// hidden: glibc and musl share the `linux` key.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub platforms: BTreeMap<String, Artifact>,
    /// What the artifact is, and therefore how to get the binary out of it.
    #[serde(default)]
    pub unpack: Unpack,
    /// Leading path components dropped from every archive entry, as `tar
    /// --strip-components` (CLOUD-2682). Requires [`Provision::bin`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub strip: Option<usize>,
    /// The binary's path inside the archive after `strip` (CLOUD-2682). Set,
    /// the whole archive is extracted to `<entry>/tree/` and the binary is
    /// `tree/<bin>`, beside the files it reads; unset, one file is matched by
    /// name, as before.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bin: Option<String>,
    /// The binary's name inside the artifact, and the name it is cached under.
    pub binary: String,
    /// A directory to ALSO place the binary in, so it reaches `PATH`.
    ///
    /// Absent for every entry batten invokes itself: the cache path is resolved
    /// in-process, so `ripsecrets` needs no `PATH` presence and putting it there
    /// would widen what a consumer's shell can reach for no gain.
    ///
    /// **It exists for the bootstrap case, which is the one entry the cache
    /// cannot serve** (CLOUD-1389). The container's Setup script is one line
    /// that installs batten, so batten is the first thing present and the task
    /// runner is not — and every gate in this repository is a `mise run`. A
    /// runner resolved only inside batten's own process is unreachable from the
    /// session handlers, the git hooks and the agent's own shell, all of which
    /// invoke it by bare name.
    ///
    /// `~` is expanded, and nothing else is: no `$VAR`, no `$(…)`, no glob. The
    /// same bound [`Startup::check`] states for argv, and for
    /// the same reason — an operator reads the declared path and that is the
    /// path. A relative value is refused at load rather than resolved against
    /// whatever directory the process happens to be in.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub link: Option<String>,
    /// Environment this tool needs in its OWN process before it will work.
    ///
    /// **This is not `[env]` one layer over, and the difference is the whole
    /// reason the key exists** (CLOUD-1455). A task runner applies its own `[env]`
    /// to what it SPAWNS; its own resolver — the HTTP client that fetches what it
    /// is being asked to install — reads the process environment it was started
    /// with, and nothing a manifest says can reach back and change that. Measured
    /// 2026-09-05, the same cold install of one pinned tool, the bypass declared
    /// two ways: through the runner's `[env]` the install 403s, and with the same
    /// two variables in the process environment it succeeds.
    ///
    /// So the environment has to be applied by whatever LAUNCHES the tool, which
    /// is what this field is read by — [`link_onto_path`] for everything that
    /// resolves the tool by bare name, and [`crate::rules::spawn_resolving`]'s
    /// pinned rung for batten's own spawns. Both, because a row that fixed only
    /// one would leave the other silently unfixed.
    ///
    /// Empty for every entry that needs nothing, which is the ordinary case: an
    /// entry declaring no rows is copied onto `PATH` exactly as before.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub env: Vec<ProvisionEnv>,
}

/// One variable a provisioned tool's launcher sets, and how its value is found.
///
/// **Both spellings are DERIVED rather than literal, and that is deliberate.** A
/// literal value would be wrong twice over here: the two things this exists to
/// carry are a proxy exemption list, which must be added to whatever the host
/// already exempts rather than replacing it, and a credential, which must never
/// be written into a tracked file at all. Neither is expressible as a constant,
/// so the row declares the RULE and the launcher resolves it against the
/// environment it finds.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(extend("oneOf" = serde_json::json!([
    { "required": ["prepend_list"], "not": { "required": ["from_first_set"] } },
    { "required": ["from_first_set"], "not": { "required": ["prepend_list"] } },
    { "required": ["unset"], "not": { "anyOf": [
        { "required": ["prepend_list"] },
        { "required": ["from_first_set"] },
        { "required": ["reject_prefix"] }
    ] } }
])))]
pub struct ProvisionEnv {
    /// The variable to set.
    pub name: String,
    /// Entries to add to the front of a comma-separated list, keeping whatever
    /// the host already had and adding nothing twice.
    ///
    /// Idempotent by construction: an entry already present is not added again,
    /// so a launcher that runs a launcher does not grow the value without bound.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub prepend_list: Vec<String>,
    /// Set from the first of these variables that is set and non-empty.
    ///
    /// A list rather than one name because the fallback is the point: the same
    /// tool wants a session credential where one exists and the runner's own
    /// where it does not, and a row naming one would be dead in whichever
    /// environment does not have it. **Nothing is written when none is set** —
    /// an empty credential is refused by some tools and accepted as anonymous by
    /// others, and inventing one is a claim this row cannot make.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub from_first_set: Vec<String>,
    /// Apply this row only where the host's trust bundle carries a certificate
    /// authority whose subject names this ORGANISATION.
    ///
    /// **This is what keeps a bypass from being applied to somebody's working
    /// proxy.** A row without it applies everywhere, which is right for a row
    /// that only ever adds a credential; it is wrong for one that routes traffic
    /// around a proxy, because a proxy is a legitimate part of most networks and
    /// the only one worth going around is one that refuses by policy what it was
    /// asked to carry.
    ///
    /// The condition is the CA rather than the proxy variables, and the
    /// difference is the whole reason the field is spelled this way. Every
    /// intercepting environment sets those variables, so keying on them would
    /// refuse to honour a real proxy the moment somebody configured one. Keying
    /// on the authority in the trust path names the specific interceptor and
    /// goes false the day those variables point at a CA the operator chose.
    ///
    /// Measured 2026-09-05 in this sandbox: the bundle those variables name
    /// carries five interception authorities, presenting three different common
    /// names across the direct and proxied paths, and the ORGANISATION is the
    /// only field common to all five — so a row matching a common name would
    /// silently miss whichever path the author did not test.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub when_trust_names: Option<String>,
    /// Treat a candidate whose value starts with this as if it were not set.
    ///
    /// **A FAST PATH, NEVER THE DECISION.** The authority on whether a
    /// credential is usable is [`Credential`], which is measured against the
    /// forge; this is a cheap syntactic hint that lets an obvious marker lose
    /// without spending a probe on it. A host that stops prefixing its
    /// placeholder tomorrow — which this one can, without warning — degrades to
    /// the measurement rather than to a wrong answer, because the probe is what
    /// actually decides (CLOUD-1569).
    ///
    /// **A placeholder is not a weak credential, it is a MARKER**, and the
    /// difference decides the verdict. This container injects `GITHUB_TOKEN`
    /// and `GH_TOKEN` carrying a literal `proxy-` prefix: proxied, the value
    /// never reaches GitHub because the proxy substitutes its own; fenced, it is
    /// sent verbatim and GitHub answers `Bad credentials`. So `from_first_set`
    /// alone cannot express the intent — the placeholder IS set and IS
    /// non-empty, so it wins the first-set race against nothing (CLOUD-1569).
    ///
    /// Applied to every candidate, including the row's own name where it appears
    /// in the list, which is what lets one row say "prefer a real credential,
    /// and if there is none, leave nothing behind rather than a marker".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reject_prefix: Option<String>,
    /// Remove the variable from the launched environment entirely.
    ///
    /// **Unset is not "set to empty", and only unset is honest here.** An empty
    /// `HTTPS_PROXY` is read by some clients as "no proxy" and by others as a
    /// malformed URL, and an empty credential is refused by some tools and taken
    /// as anonymous by others — so writing one is a claim this row cannot make.
    /// The distinction already exists one field up, where `from_first_set`
    /// resolving to nothing writes nothing.
    ///
    /// Pair it with `when_trust_names`: clearing a proxy variable is right in a
    /// container whose egress is intercepted by an authority the row names, and
    /// wrong on a machine whose proxy somebody configured deliberately.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub unset: bool,
}

/// One platform's artifact: where it comes from, and what it must hash to.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Artifact {
    /// Where the artifact comes from. `https://` or `file://`.
    pub url: String,
    /// The SHA-256 of the artifact, lowercase hex.
    pub sha256: String,
    /// This platform's archive format, when it is not the entry's.
    ///
    /// A tool commonly ships a tarball for every Unix target and a zip for
    /// Windows (uv, zizmor and actionlint all do), so one entry-wide
    /// [`Provision::unpack`] could not pin all five platforms. Absent means the
    /// entry's.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unpack: Option<Unpack>,
    /// This platform's [`Provision::strip`], when it is not the entry's.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub strip: Option<usize>,
    /// This platform's [`Provision::bin`], when it is not the entry's: Node's
    /// Linux tarball has `bin/node`, its Windows zip `node.exe` at the top.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bin: Option<String>,
}

/// How to get the binary out of the fetched artifact.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum Unpack {
    /// The artifact *is* the binary.
    #[default]
    None,
    /// A gzipped tarball; the entry whose file name is
    /// [`Provision::cached_name`] is extracted and everything else ignored.
    TarGz,
    /// A zip archive, read the same way as [`Unpack::TarGz`].
    Zip,
}

/// How a record is filed.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize, schemars::JsonSchema,
)]
#[serde(rename_all = "kebab-case")]
pub enum RecordKey {
    /// Filed under the current branch, so every commit on it continues to serve
    /// the same record.
    Branch,
}

/// One recorder this repository declares.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct RecorderDeclared {
    /// What this row is called. Unique across the table, and never the file — a
    /// record is written by SEVERAL rows (one per tool, and one per create/groom
    /// path), so keying uniqueness on the file would make the natural
    /// declaration unwritable.
    pub name: String,
    /// The record this row appends to — the file, and the file the rule that
    /// reads it names.
    ///
    /// Deliberately many-to-one. The censused record carries a line per board
    /// write whatever tool made it, so the rows that write it differ in their
    /// selector and their columns while naming one destination.
    pub record: String,
    /// Which tool's result records, matched by [`crate::facts::selects_tool_name`].
    ///
    /// A tool name, never a field shape, for [`crate::config_model::MintDeclared::tool`]'s
    /// measured reason: a connector is exposed under more than one name over its
    /// lifetime (CLOUD-178), and a write response and a read payload are
    /// shape-identical across the fields either carries.
    pub tool: String,
    /// What the record is filed under.
    pub key: RecordKey,
    /// Paths into the RESULT that must resolve for anything to be written.
    ///
    /// The success predicate, exactly as [`crate::mint::satisfied`] is: a result
    /// that does not carry these is a call that did not do the thing, and
    /// recording it would put a row in the journal for work nobody did.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub requires: Vec<String>,
    /// Paths into the INPUT that must NOT resolve for anything to be written.
    ///
    /// The censused use is telling a create from an update: an update carries an
    /// id the create cannot, so a recorder that only wants creates declares the
    /// id here rather than needing a negation operator in the expression
    /// language.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub refused_when_input: Vec<String>,
    /// Paths into the RESULT that must NOT resolve for anything to be written
    /// (CLOUD-2214).
    ///
    /// The censused use is a backgrounded runner call: its result carries
    /// `backgroundTaskId`, and its `stdout` is the host's placeholder rather than
    /// the command's output, so reading it records a measurement of nothing — a
    /// `closes 0` over a PR body nobody saw.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub refused_when_result: Vec<String>,
    /// Input paths whose value must MATCH a declared pattern, by pattern id.
    ///
    /// **The selector a tool name cannot express.** [`RecorderDeclared::tool`] narrows to
    /// a tool, which is enough while the tool's identity is the whole question —
    /// a board write is any `save_issue` at all. It is not enough for a general
    /// runner: every shell call arrives as one tool, so a row wanting *the
    /// command that fetched the pull request body* has a tool name that matches
    /// every command in the session and a result shape identical for all of them.
    ///
    /// The value is a `[[pattern]]` id rather than an inline regex, for the
    /// reason `rules/policy-modules.md` gives for a module: one concept,
    /// one spelling, refused at load rather than duplicated at leisure. An
    /// undeclared id fails the load and says which recorder named it.
    ///
    /// Reads the INPUT, never the result, and that is the safe direction here
    /// even though [`Value::Input`] is the forgeable half elsewhere: this decides
    /// only WHETHER to record, and the columns still take their values from what
    /// the far end returned. A caller who spoofs the command string buys a record
    /// of a call whose own result is what gets written down.
    ///
    /// A path that does not resolve to a scalar refuses the row, on the
    /// could-not-look rule the rest of this module keeps: a selector that cannot
    /// read its subject has not matched it.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub requires_input_matching: BTreeMap<String, String>,
    /// Write only when the record ALREADY carries a line whose column
    /// `column` equals this expression's value.
    ///
    /// **The narrow exception that keeps a remedy reachable.** A gate that
    /// refuses a subject recorded in a bad state has to tell the author how to
    /// clear it, and "fix the subject and re-run" only works if the fix is
    /// recorded too. But recording every later write would let a row this branch
    /// never filed be re-judged on its own say-so — so the exception is bounded
    /// to subjects this record already names, which is exactly the set this
    /// branch is answerable for.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requires_recorded: Option<Recorded>,
    /// The columns, in order, space-joined into one line.
    ///
    /// **Every column renders exactly one whitespace-free token.** A record a
    /// positional reader can parse cannot have a variable-width field before its
    /// last, and the shell recorder this replaces learned that the hard way — its
    /// fifth column swallowed the sixth until the join moved to write time. So
    /// [`render_column`] folds whitespace rather than trusting a template not to
    /// produce any.
    pub columns: Vec<Column>,
}

/// A precondition on what the record already holds.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct Recorded {
    /// Every column that must match, keyed by position from zero.
    ///
    /// **A map rather than one column, and the reason is measured.** The
    /// censused record carries a line per board write whatever KIND it was, so a
    /// precondition on the subject alone matches a comment line about that
    /// subject — and a comment is not this branch having filed the row. The
    /// retired shell anchored on the kind and the whole id field together; this
    /// is that anchor, generalised.
    pub matches: BTreeMap<usize, Value>,
}

/// One column of a record.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct Column {
    /// What this column is called. Never read by the engine — it is what makes
    /// the config legible and what a finding can point at.
    pub name: String,
    /// The expression whose value this column carries.
    pub value: Value,
    /// Remove, from this column's whitespace-separated tokens, every token the
    /// named expression yields.
    ///
    /// The censused use is *"the rows the stored body cites that the caller
    /// passed as no relation"* — a set difference between what a program emitted
    /// and what the input carried. Expressed as a column operation rather than a
    /// [`Value`] variant because it is about the rendered tokens, not about the
    /// JSON.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub minus: Option<Value>,
    /// Drop this token if it equals the value of the named expression.
    ///
    /// The row's own key is not an edge to anywhere; without this the censused
    /// column counts every row as citing itself.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub without: Option<Value>,
    /// Render as `<count><separator><joined>` rather than as the tokens alone.
    ///
    /// **A count and a pointer, never the payload** (non-negotiable rule 4). The
    /// separator is the consumer's because the reader of the record is the
    /// consumer's too.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub counted_with: Option<String>,
    /// Render `0` rather than [`ABSENT`] when the expression resolved and yielded
    /// no tokens.
    ///
    /// **Zero is a count; `-` is could-not-look.** Collapsing the two is the one
    /// mistake this record shape cannot afford, because a gate downstream passes
    /// on `-` by design and would then pass on a real measurement of nothing.
    #[serde(default)]
    pub zero_is_a_count: bool,
}

/// An expression over the tool envelope and the programs this repository owns.
///
/// **Closed, for [`crate::config_check::mint::Piece`]'s reason**: an unrecognised form is a
/// load error, never a value that silently renders as itself and writes a record
/// nobody can read.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub enum Value {
    /// A constant the consumer wrote. What a `kind` column is made of.
    Literal(String),
    /// The branch this record is being written on (CLOUD-1280).
    ///
    /// **The record is already branch-keyed and this exposes what the writer
    /// holds** — [`crate::lib`]'s `write_records` resolves the branch to choose
    /// the record's own path and, until this variant, never handed it to an
    /// expression. So a column could name what the LEASE says and nothing it
    /// could compare that against.
    ///
    /// The measured need is one row of a port rather than a general convenience.
    /// `land-lock status` grades the lease against the CLONE (`mine`), which is
    /// the question a developer's checkout asks; `authorises` grades it against
    /// the BRANCH and admits one case `status` cannot — the successor a rival
    /// reserved behind the holder (CLOUD-369). A predicate without this variant
    /// therefore refuses a reserved successor that the bash it replaces allows,
    /// which is a fail-CLOSED deviation and exactly the laundering CLOUD-1269
    /// forbids: *"a port that quietly makes it fail closed has laundered a
    /// stop-the-world into a gate."*
    ///
    /// **Could-not-look is a real answer here and is spelled `None`**: a detached
    /// HEAD has no branch, which is a state rather than an error, and rendering
    /// some placeholder would let a comparison against it succeed by accident.
    ///
    /// Names nothing (non-negotiable rule 1): it yields whatever ref the clone is
    /// standing on, so a consumer's trunk name never reaches the crate.
    Branch,
    /// The scalar at a dotted path into the tool RESULT.
    Result(String),
    /// The scalar at a dotted path into the tool INPUT.
    ///
    /// Separate from [`Value::Result`] rather than one path with a prefix,
    /// because the two differ in TRUST and the difference is the whole reason the
    /// censused recorder is unforgeable: the result is what the far end stored,
    /// the input is what the caller asked for. A consumer choosing between them
    /// is choosing whose word to take, and that choice should be spelled.
    Input(String),
    /// A JSON object built from named sub-expressions.
    Object(BTreeMap<String, Value>),
    /// Every string the named iterating INPUT paths yield, space-joined.
    ///
    /// [`Value::Wrap`]'s plain sibling, and both are needed rather than one
    /// being a special case of the other. `Wrap` builds the OBJECT shape a
    /// program reads on stdin; this builds the TOKEN list a column operation
    /// compares against. Using `Wrap` for a `minus` compares against
    /// `{"id":"X"}` and removes nothing — measured, and silently, because a set
    /// difference that subtracts nothing looks exactly like one with nothing to
    /// subtract.
    ///
    /// A list rather than one path because the censused use unions three
    /// relation directions, and a union spelled as three columns would be three
    /// columns nobody wanted.
    Inputs(Vec<String>),
    /// Each string an iterating INPUT path yields, wrapped as `{<key>: value}`.
    ///
    /// The shape a relation list takes in the payload the censused verdict
    /// program reads. Generic because the key is the consumer's.
    Wrap {
        /// The iterating input path, e.g. `blockedBy[]`.
        from: String,
        /// The object key each element is filed under.
        key: String,
    },
    /// The lines of another expression's value from a label matching `select`
    /// until the next label matching `label`.
    ///
    /// **Both patterns are `[[pattern]]` ids, never inline regexes**, which is the
    /// same load-time refusal `rules/policy-modules.md` records for a
    /// policy module and for the same measured reason: one concept, one spelling.
    /// The censused use narrows a body to one clause of a structured block, and
    /// that block's grammar already has exactly one definition elsewhere.
    Section {
        /// The expression whose text is narrowed.
        from: Box<Value>,
        /// The pattern id every label matches — what ENDS a span.
        label: String,
        /// The pattern id the wanted label matches — what STARTS the span.
        select: String,
    },
    /// What a declared program said about another expression's value.
    ///
    /// The id field is `run` rather than `program`, which is not cosmetic: this
    /// enum is externally tagged, so the variant's own key is already `program`
    /// and a field of the same name nests one inside the other for a reader.
    Program {
        /// The program id, resolved through the consumer's `[program]` table.
        run: String,
        /// The expression whose rendered value is handed to the program on stdin.
        stdin: Box<Value>,
        /// What to read back.
        read: Read,
    },
    /// What a **compiled** authority said about another expression's value
    /// (CLOUD-1100).
    ///
    /// [`Value::Program`]'s in-process twin, and deliberately its twin rather
    /// than its replacement: a `[program]` row names a path the CONSUMER owns, an
    /// authority names a predicate the CRATE owns. Switching a column from one to
    /// the other buys the same verdict without a spawn, which is what lets a
    /// grammar the crate already parses stop being resolved by executing a shell
    /// program on every board write.
    ///
    /// **[`Read`] is reused unchanged, and that is the whole compatibility
    /// story.** The authority answers in the spawned program's own status
    /// contract (see [`crate::ready::adjudicate`], which documents the inversion
    /// CLOUD-909 records), so a column switching `program` for `authority` keeps
    /// its `read` table byte-for-byte and keeps recording the same tokens.
    Authority {
        /// Which compiled authority decides.
        ask: Ask,
        /// The expression whose value the authority judges. Handed over as JSON
        /// rather than as text: nothing is being written to a pipe, so the
        /// serialize-and-reparse round trip a spawn needs would only be a second
        /// place for the shape to change.
        stdin: Box<Value>,
        /// What to read back.
        read: Read,
    },
}

/// A compiled authority a recorder column may ask.
///
/// **Closed, and a name rather than a path**, which is what keeps rule 1 intact:
/// this enum's one variant says *the Definition-of-Ready grammar* and nothing
/// here names a tracker, a tool or a board. [`crate::config_check::mint::Authority`] is its
/// twin on the template side and the two resolve the same names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub enum Ask {
    /// [`crate::ready`] — the Ready-block grammar over a tracker payload.
    Ready,
    /// [`crate::lease::Asked::Status`] — does the landing lease authorise this
    /// clone right now? Answers in the engine's exit table, so the consumer's
    /// `status` map reads `0` authorising / `2` held elsewhere and leaves `3`
    /// unmapped, which is where the lease's fail-open asymmetry lives.
    ///
    /// **Named for the practice rather than for a program** (non-negotiable rule
    /// 1): "a landing lease" is a word about trunk-based landing, where
    /// `land-lock` was one repository's file name.
    LeaseStatus,
    /// [`crate::lease::Asked::Successor`] — which branch the live holder
    /// admitted behind it, on stdout, or nothing where no reservation stands.
    LeaseSuccessor,
    /// [`crate::ready::named_paths`] — which tracked paths an issue body names.
    ///
    /// **Named for the question rather than for the retired program** (rule 1):
    /// "the paths this row names" is a statement about a tracker body, where
    /// `board-diff-overlap` was one repository's file name for a sensor that
    /// also had a second mode nothing reached.
    NamedPaths,
    /// The keys a text names in CLOSING form, one per line on stdout — the
    /// grammar's own [`crate::ready::Grammar::keys_closed_in`] (CLOUD-1717).
    ///
    /// **It replaces a spawn of the program whose `--list` mode was the only
    /// home of the closing-verb regex.** That program is retired, and a second
    /// copy of the verb set here would be one concept with two spellings; the
    /// grammar already owns it, including the disclaimer a regex never saw
    /// (`does not close CLOUD-1` names the key and closes nothing).
    ClosingKeys,
}

/// What a recorder reads back from a program it ran.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub enum Read {
    /// The exit status, mapped through a table the consumer wrote.
    ///
    /// **An unmapped status is [`ABSENT`], never a default verdict**, and the
    /// censused reason is exact: the program this replaces exits `0` for pass,
    /// `1` for a judgement and `2` for *could not judge*, so folding anything
    /// non-zero into the refusal would record a verdict about the ENVIRONMENT
    /// wearing the mask of a verdict about the subject.
    Status(BTreeMap<String, String>),
    /// Standard output, whole.
    Stdout,
    /// The remainder of the first stdout line carrying this prefix.
    ///
    /// **Absent is could-not-look; present-and-empty is the honest zero.** The
    /// censused producer emits its line BEFORE it branches on a verdict, so a
    /// missing line means it never got that far, and a present empty one means it
    /// looked and found nothing.
    StdoutLine(String),
}

/// One program a recorder may run.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct Program {
    /// The path, repo-relative. Resolved against the repository root rather than
    /// the cwd for [`crate::lib`]'s measured reason: a hook inherits the cwd of
    /// the tool call, which is not required to be inside this project.
    pub path: String,
    /// Arguments, before stdin is written.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub args: Vec<String>,
}

/// The `[refusal]` table: what one emitted mediated line may cost.
///
/// **Declared, never a literal in the crate** (non-negotiable rule 2, and the
/// same reasoning `[budget.instructions]` is built on): a ceiling written into
/// `crates/batten` is this repository's judgement compiled into every consumer's
/// engine, and a consumer whose harness renders differently could not move it
/// without a release. [`crate::config_model::BudgetSet`] is the landed shape this
/// copies — a ceiling and nothing else, absent meaning unenforced, because a
/// threshold nobody declared is not a threshold of zero.
///
/// The unit is **estimated tokens**, on `budget.rs`'s own bytes-per-token
/// convention rather than a tokenizer: this is a ceiling on a line, checked off
/// the hot path, and a real BPE pass here would be the dependency CLOUD-1284
/// deliberately kept to `[dev-dependencies]`.
///
/// It is not [`crate::verdict`]'s `GLOSS_MAX`, which stays. That bounds one
/// FIELD — the gloss `explain` prints — and this bounds the emitted LINE. Both
/// exist for the same reason and neither substitutes for the other: with the
/// gloss off the hot path, `GLOSS_MAX` is what stops it growing back into a
/// paragraph where nothing measures it.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Ceiling {
    /// The ceiling on estimated tokens for ONE emitted mediated refusal line.
    /// The boundary is `<=`: exactly at budget passes, matching
    /// [`crate::budget::Report::over_budget`] so the two thresholds in this tree
    /// do not disagree about their own edge.
    ///
    /// **Bounds the REPEAT arm** — the compact `<token> <pointers> <rule-id>`
    /// every firing after the first emits. The first sighting is a different
    /// quantity and has its own key below.
    pub max_tokens: usize,
    /// The ceiling on the FIRST sighting of a rule, which carries the class
    /// definition (CLOUD-1637).
    ///
    /// **A second key rather than a second meaning for the first**, because the
    /// two arms are different quantities: `max_tokens` prices prose a reader has
    /// already read, and this prices the one firing where they have not. Folding
    /// them would force a consumer to choose between bounding the repeat usefully
    /// and letting the definition arrive at all.
    ///
    /// Absent means unbounded, which is the answer every other budget in this
    /// tree gives an undeclared row: the ceiling is the consumer's statement
    /// about their own line, and inventing one here would be this crate deciding
    /// a consumer fact.
    ///
    /// What it bounds is the ROUTE LIST, never the line. Over budget, routes are
    /// dropped from the end and the gloss never is; when `<token> <pointers>
    /// <rule-id> — <gloss>; <first route>` is itself over, it is emitted anyway.
    /// See [`crate::hook::deny_text`] for why that irreducible case is a decision
    /// rather than an oversight.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first_sighting_max_tokens: Option<usize>,
}

/// One declared precondition, and optionally the fix for it.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Startup {
    /// The stable token a report names.
    ///
    /// Separate from the command for [`crate::config_model::Marker`]'s reason: the
    /// argv is free to change without the thing it is called in reports changing
    /// with it.
    pub id: String,
    /// What this row is about, in one line, for a reader of the config.
    ///
    /// Required rather than optional: a precondition nobody wrote the meaning of
    /// down is one the next reader cannot decide whether to keep — and since the
    /// report is pointer-only, this is the only place that meaning can live.
    pub gloss: String,
    /// The command deciding whether the environment is right, as argv.
    ///
    /// Exit `0` is provisioned; anything else is not. argv rather than a shell
    /// string for `[[hook.action]]`'s reason — there is then no quoting layer
    /// between what an operator wrote and what runs: no word splitting, no glob
    /// expansion, no `$(…)`.
    ///
    /// Omitted exactly when [`Startup::preset`] is set, which derives it.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub check: Vec<String>,
    /// The enabled preset whose install this row runs (CLOUD-2633), in place
    /// of a hand-written `check` and `repair`.
    ///
    /// The row's position is the consumer's — it runs once the rows above it
    /// have bootstrapped the tool — and its argv is derived from the preset's
    /// declared install and the enabling `[[rule]]`'s `environments` and
    /// `install_env`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(schema_with = "preset_name_schema")]
    pub preset: Option<String>,
    /// How the check's run becomes a verdict.
    ///
    /// Absent is [`Decided::ExitStatus`], which is the ordinary case and the one
    /// every row before CLOUD-1454 assumed.
    #[serde(default, skip_serializing_if = "Decided::is_default")]
    pub decided_by: Decided,
    /// The command that fixes it, as argv. Absent means diagnose-only.
    ///
    /// A row with no repair is not a lesser row: some preconditions genuinely
    /// cannot be fixed from inside the container, and a row saying so is more
    /// use than a repair that silently does nothing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repair: Option<Vec<String>>,
}

/// How a check's run is read as an answer.
///
/// **This exists because a program can be a perfectly good reporter and a
/// useless gate**, and a row declaring one as its check is dead rather than
/// wrong-looking (CLOUD-1454). Measured on the row this was added for:
/// `mise ls --current` prints `(missing)` beside a tool that is not installed
/// and exits `0`, so `toolchain-is-provisioned` reported `ok` over a container
/// with nothing installed — and because a `[[startup]]` row only repairs when
/// its check FAILS, the `mise install --yes` that would have fixed it never ran.
/// A dead gate and a provisioned container were byte-identical on the report.
///
/// The remedy stays inside the argv bound rather than growing a shell: the same
/// program has a spelling that says nothing when there is nothing to say
/// (`mise ls --current --missing`), so what the row needed was a way to declare
/// that SILENCE is the pass — not a pipeline, a `test`, or a wrapper task.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum Decided {
    /// Exit `0` is provisioned. The default, and what every row means unless it
    /// says otherwise.
    #[default]
    ExitStatus,
    /// Exit `0` **and** nothing written to stdout is provisioned.
    ///
    /// Rule 4 holds here in the TYPE rather than by care: what crosses back is a
    /// `bool` over the child's stdout, never a byte of it, so a check whose
    /// output names paths, versions or hosts still cannot put any of that in a
    /// report. That is the same bound [`Outcome`] already carries, one layer
    /// earlier.
    SilentExit,
}

impl Decided {
    /// Whether this is the value an absent key means, so the derived schema and
    /// the round-tripped config both stay quiet about the ordinary case.
    ///
    /// BESIDE ITS TYPE because serde's `skip_serializing_if` names it by path
    /// from this module's own attributes, where no extension trait's import
    /// reaches (CLOUD-2793).
    ///
    /// `&self` on a `Copy` type is the derive's signature, not a choice: serde's
    /// `skip_serializing_if` passes a reference. NO `trivially_copy_pass_by_ref`
    /// EXPECTATION: that lint honours `avoid-breaking-exported-api` and never
    /// fires on a `pub` fn, so an `#[expect]` here is unfulfilled, which is a
    /// hard error that failed every clippy run over this crate, the spawn census
    /// (`adapter place missing`, CLOUD-2816) among them.
    #[must_use]
    pub const fn is_default(&self) -> bool {
        matches!(self, Self::ExitStatus)
    }
}

/// Every declared row, with each `preset` row's argv derived from the preset's
/// install and its enabling rule's parameters (CLOUD-2633).
///
/// In declaration order, so the consumer decides where the install runs — after
/// the rows that bootstrap the tool, before the rows whose repairs need it.
/// Pure: whether a listed environment is configured is a question about the
/// tree, decided when the row runs
/// ([`crate::startup::ENVIRONMENT_UNCONFIGURED`]), so a tree lacking one still
/// resolves for every other verb. A preset row no rule parameterises is
/// refused at load, and passes through unchanged here.
///
/// BESIDE [`Startup`], NOT IN `startup`: `resolve` calls this, and `startup`
/// reaches `resolve`, so a call into `startup` closed a larger module cycle
/// (CLOUD-2789). This reads only the model and the preset catalog.
#[must_use]
pub fn derive_startup(rows: &[Startup], rules: &[Rule]) -> Vec<Startup> {
    rows.iter()
        .map(|row| {
            let Some((install, rule)) = row.preset.as_deref().and_then(|name| {
                install_of(name).zip(rules.iter().find(|rule| {
                    rule.preset.as_deref() == Some(name) && rule.environments.is_some()
                }))
            }) else {
                return row.clone();
            };
            let environments = rule.environments.as_deref().unwrap_or_default();
            let (check, repair) = install_argv(install, environments, &rule.install_env);
            Startup {
                check,
                repair: Some(repair),
                decided_by: Decided::SilentExit,
                ..row.clone()
            }
        })
        .collect()
}

/// The install the named preset declares, if any.
#[must_use]
pub fn install_of(name: &str) -> Option<&'static crate::preset_catalog::Install> {
    crate::preset_catalog::MANIFESTS
        .iter()
        .find(|manifest| manifest.name == name)
        .and_then(|manifest| manifest.install.as_ref())
}

/// The derived check and repair argv: one `env` prefix — the selector naming
/// exactly `environments`, then the consumer's `install_env` — before the
/// tool's own operands.
#[must_use]
pub fn install_argv(
    install: &crate::preset_catalog::Install,
    environments: &[String],
    install_env: &[String],
) -> (Vec<String>, Vec<String>) {
    let prefix = || {
        let mut argv = vec![
            String::from("env"),
            format!(
                "{}={}",
                install.selector,
                environments.join(install.separator)
            ),
        ];
        argv.extend(install_env.iter().cloned());
        argv.push(install.program.to_owned());
        argv
    };
    let tail = |operands: &[&str]| {
        let mut argv = prefix();
        argv.extend(operands.iter().map(|operand| (*operand).to_owned()));
        argv
    };
    (tail(install.check), tail(install.repair))
}

/// The configured transcript, as `batten.toml` declares it: where it is, and
/// whose dialect it is in.
///
/// **It used to say "a path, not a format selector", and that was the bug**
/// (CLOUD-1624). Which host wrote the file was left to the fixtures, so the
/// engine read every transcript through one host's grammar and reported the zero
/// events that produces on any other as a clean session. The dialect is a fact
/// about this consumer's setup, and non-negotiable rule 1 puts a consumer fact
/// in the consumer's own `batten.toml` rather than in the core.
///
/// Host-specific, never consumer-specific, so rule 1 holds in the other
/// direction too — no consumer's directory layout appears in the engine.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema, Default)]
#[serde(deny_unknown_fields)]
pub struct TranscriptConfig {
    /// Repo-relative path to the completed session transcript.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// Which host wrote it, selecting the record grammar to read it with
    /// (CLOUD-1624).
    ///
    /// **Omitted is could-not-look, never a default.** `cli.rs`'s attribution
    /// host is the precedent and states it: an unnamed host "declares nothing
    /// rather than borrowing a default's declarations". Defaulting here would
    /// read an unnamed host's transcript through one host's grammar and report
    /// the zero events that yields as a clean session — the exact false green
    /// this key exists to close. A consumer that declares a `path` and no
    /// `harness` gets [`Capability::Unnamed`] and every gate over the transcript
    /// abstains.
    ///
    /// The fourth fact about one host on this table, joining `path`,
    /// `memory_root` and the task store for the reason those three already give:
    /// splitting facts about a single host across tables is the widening rule 6
    /// forbids.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub harness: Option<Harness>,
    /// The host's memory-root prefix, for CLOUD-267's self-persistence match.
    ///
    /// Host-adapter data on the same table rather than a second authority: the
    /// transcript's format and the host's memory layout are two facts about one
    /// host, and splitting them across tables would be the widening rule 6
    /// forbids. Omitted, [`crate::selfwrite::DEFAULT_MEMORY_ROOT`] applies.
    ///
    /// A **prefix matched against targets the transcript recorded** — never a
    /// path this engine opens, stats, or globs, which is what keeps the rule
    /// inside the repo root.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory_root: Option<String>,
    /// Where this host keeps the session's own task store, with `{session}`
    /// standing in for the id the envelope carries (CLOUD-1376).
    ///
    /// ON THIS TABLE RATHER THAN A `[session]` ONE, and the reason is this
    /// table's own: the transcript's format and the host's memory layout are
    /// already "two facts about one host", and splitting them across tables
    /// would be the widening rule 6 forbids. A third fact about the same host
    /// joins them rather than opening a second authority over the same subject.
    ///
    /// A TEMPLATE, because the engine may not derive it. The store lives outside
    /// the repository root and its layout is the HOST's — deriving it from the
    /// transcript path would put a directory layout in the engine, which rule 1
    /// refuses. The consumer names the shape; the engine substitutes one field it
    /// was handed and opens what the substitution names.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tasks: Option<String>,
}

/// One way out of a refusal.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Route {
    /// The id a rendered refusal names, e.g. `task read first`.
    ///
    /// Stable and referenceable: an agent told `task read first` twice has
    /// been told the same thing twice, which a paraphrase cannot establish.
    pub id: String,
    /// Which kind of way out this is.
    pub kind: RouteKind,
    /// What it points at, read according to [`Route::kind`].
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub target: String,
    /// What the asker must be able to state. [`RouteKind::Override`] only, and
    /// required there.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub precondition: Option<String>,
}

/// One declared vocabulary word: the spelling, and what it means in a name.
///
/// The gloss is what makes dropping the per-class essay from the hot path safe
/// rather than merely cheap (CLOUD-1284). A class used to buy a new essay to
/// explain its own free-text name; a word buys one gloss that every name using
/// it reuses, so the *marginal* class costs no new prose at all.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct VocabularyWord {
    /// The spelling, as it appears in a name. One token under the declared pin.
    pub word: String,
    /// What this word contributes to a name that uses it.
    pub gloss: String,
}

/// The three positional lists a name is drawn from, and the pin they were
/// measured under (CLOUD-1284).
///
/// # Why the middle list is `action` and not `verb`
///
/// The grammar is `<subject> <action> <condition>` and the issue writes the
/// middle slot as "verb". The config key cannot be `verb`: `[[verb]]` is already
/// this config's table of mutating **shell** verbs, and two unrelated tables one
/// letter apart is the drift a reader pays for every time. The prose keeps the
/// grammatical word; the key states which table it belongs to.
///
/// # Why the pin is data and not a constant
///
/// The token counts are model-specific, and `bench/tokens/method.toml` already
/// sets this repository's discipline for a constant a published figure depends
/// on: state it with its source and the date it was read, so a reader checks the
/// arithmetic against the primary rather than trusting a program. The *ratio*
/// argument survives a different tokenizer — common English words are
/// single-merge in every modern BPE vocabulary — but the exact integer does not,
/// so the integer's provenance travels with it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Vocabulary {
    /// The encoding every word's token count was measured under.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tokenizer: Option<String>,
    /// Where that encoding is published.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tokenizer_source: Option<String>,
    /// When it was read.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tokenizer_retrieved: Option<String>,
    /// Slot 1: what the finding is about.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub subject: Vec<VocabularyWord>,
    /// Slot 2: what was done, or what relation is being judged.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub action: Vec<VocabularyWord>,
    /// Slot 3: the state that makes it a refusal.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub condition: Vec<VocabularyWord>,
}

// DEMOTED BESIDE THE TYPE (CLOUD-2803, Lakos). These read only the three
// slots, so they belong to the type's own layer. As `verdict::VocabularyExt`
// they made every caller import from `verdict`, and the edge
// `config_model -> verdict` alone held 13 modules in the largest cycle.
impl Vocabulary {
    /// The list for one slot, by position: 0 subject, 1 action, else condition.
    #[must_use]
    pub fn slot(&self, position: usize) -> &[VocabularyWord] {
        match position {
            0 => &self.subject,
            1 => &self.action,
            _ => &self.condition,
        }
    }

    /// Whether this vocabulary declares anything at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.subject.is_empty() && self.action.is_empty() && self.condition.is_empty()
    }

    /// Every declared word, with the slot it was declared in.
    pub fn words(&self) -> impl Iterator<Item = (usize, &VocabularyWord)> {
        [&self.subject, &self.action, &self.condition]
            .into_iter()
            .enumerate()
            .flat_map(|(slot, words)| words.iter().map(move |word| (slot, word)))
    }
}

/// One declared refusal class.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DeclaredVerdict {
    /// The token, e.g. `task name undefined`.
    pub id: String,
    /// What the boundary may DO about this class, beyond naming it (CLOUD-1639).
    ///
    /// Absent is [`Applicability::Advice`], which is every class's behaviour
    /// today and the reason the column defaults rather than being required: a
    /// refusal that names a remedy the agent follows itself is the shape 200 of
    /// this tree's classes already have, and making them all restate it would be
    /// a column that carries no information 99% of the time.
    #[serde(default, skip_serializing_if = "Applicability::is_default")]
    pub applicability: Applicability,
    /// One line, the hot path's whole payload, and a first sighting's `what`.
    pub gloss: String,
    /// How to deal with a refusal of this class, delivered once per context
    /// window beside the gloss (CLOUD-2143). See [`crate::doc`].
    #[serde(default, skip_serializing_if = "crate::doc::Doc::is_empty")]
    pub doc: crate::doc::Doc,
    /// What the class means, at length. `batten policy explain`'s payload, and
    /// the **deliberate exception** to pointer-only output (house style §6):
    /// `explain` is local documentation rather than a finding, and carrying the
    /// text the hot path no longer does is its entire purpose.
    pub class: String,
    /// The ways out, in the order a reader should consider them.
    #[serde(default, rename = "route", skip_serializing_if = "Vec::is_empty")]
    pub routes: Vec<Route>,
    /// The token that replaced this one, for a class that has been retired.
    ///
    /// A **tombstone**: the entry stays so a historical token is still
    /// explainable, which git history cannot do at runtime. A tombstone is
    /// exempt from the emitted-somewhere half of registry equality, because the
    /// whole point is that nothing emits it any more.
    ///
    /// One of **two** retirement arms — see [`DeclaredVerdict::withdrawn`] for
    /// the other, and why naming both is refused.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub successor: Option<String>,
    /// Why this class was **withdrawn**, for one that was not replaced at all
    /// (CLOUD-1114).
    ///
    /// The second retirement arm, and it exists because the first cannot express
    /// this case. A class can be withdrawn rather than replaced — the thing it
    /// refused should no longer be refused by anything — so there is no successor
    /// and naming one would be a false claim about where the class went. Before
    /// this arm the only ways past were to invent a successor that does not hold
    /// the predicate, or to delete the row and lose the ability to explain a
    /// historical token, which is the whole thing a tombstone exists for.
    ///
    /// **It owes a reason and names no target**, exactly as
    /// [`crate::config_model::Conserves::withdrawn`] does one registry over (CLOUD-1080,
    /// the precedent for this arm's shape): a column demanding a target here
    /// would be the invented successor again. An empty reason is refused, so the
    /// arm cannot be spent as a bare "gone".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub withdrawn: Option<String>,
}

/// One declared waiver: which rule, why, until when, and optionally where.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Waiver {
    /// The [`crate::config_model::Rule::id`] this waiver suppresses findings of.
    pub rule: String,
    /// Why the finding is being waived. Required, and required to be non-empty:
    /// an unjustified waiver is the undesigned hatch this table replaces, and a
    /// reason nobody had to write is one nobody can review.
    pub reason: String,
    /// The last day this waiver applies, `YYYY-MM-DD`. Required — see the module
    /// docs on why a waiver with no expiry is the rot rather than a convenience.
    pub expires: String,
    /// A glob narrowing the waiver to some of the rule's findings.
    ///
    /// Absent means the whole rule, which is the widest a waiver can be and
    /// therefore the one that must be typed deliberately rather than reached by
    /// omitting a field nobody noticed. Matched with
    /// [`crate::selector::glob_match`], so a waiver's path vocabulary is the one the
    /// rules use and not a second dialect.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
}

/// The harness adapters `batten hook` can speak. Each owns the decode of its
/// host's payload into an [`Envelope`] and the encode of a [`Decision`] into
/// what that host consumes; the core between them is harness-blind.
/// **THREE SPELLINGS OF ONE NAME, held together rather than trusted to agree.**
/// `clap::ValueEnum` spells `--harness`, serde spells `[transcript] harness` in
/// `batten.toml` (CLOUD-1624), and [`Harness::as_str`] spells it for a matrix
/// that builds no command. `kebab-case` is what makes the serde spelling the
/// same token as the other two, and
/// `tests::every_harness_token_matches_its_serde_spelling` is what keeps it that
/// way — the same guard `every_harness_token_matches_its_clap_spelling` already
/// provides for the flag.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    clap::ValueEnum,
    serde::Serialize,
    serde::Deserialize,
    schemars::JsonSchema,
)]
#[serde(rename_all = "kebab-case")]
pub enum Harness {
    /// Claude Code's `PreToolUse` payload; a deny is returned as the
    /// `hookSpecificOutput.permissionDecision` JSON object on stdout with exit
    /// `0` — the channel the production shell guards already use.
    ClaudeCode,
    /// Cursor. Two payload families under one host: a generic `preToolUse` that
    /// looks like Claude's, and specialized events (`beforeShellExecution`,
    /// `beforeReadFile`, `beforeMCPExecution`) that carry the operand at top
    /// level and **no** `tool_name` at all. Session is `conversation_id`.
    Cursor,
    /// GitHub Copilot CLI, registered in its **`PascalCase`** dialect — which
    /// yields `hook_event_name` natively. The camelCase dialect omits the event
    /// name entirely, so Batten does not speak it.
    CopilotCli,
    /// Gemini CLI. Claude-identical payload fields, different event names
    /// (`BeforeTool` rather than `PreToolUse`).
    GeminiCli,
    /// Codex CLI, whose wire format is a near-verbatim clone of Claude Code's —
    /// its own repo says so. No payload shim is needed; the adapter exists so
    /// the host is nameable and its fixture is pinned against drift.
    CodexCli,
    /// The neutral core contract: envelope in, decision as exit code out —
    /// `0` allow, `2` deny (reason on stderr), for any host whose only decision
    /// channel is an exit status. Both codes are the §7 table's, unmodified.
    ExitCode,
}

/// One declared handler.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Handler {
    /// The stable identifier a verdict, a violation and a timing are reported
    /// under.
    ///
    /// Separate from the command for [`crate::config_model::Action`]'s reason: the
    /// argv is free to change without the thing it is called in reports changing
    /// with it. Here it carries a second load — it is the key a per-handler
    /// timing series is recorded against, so a renamed handler starts a new
    /// series rather than silently continuing another's.
    pub id: String,
    /// The event this handler runs on, as [`Event::as_str`] spells it.
    ///
    /// A **normalized** token, never a host's own word — `action`'s rule for
    /// `action`'s reason: a handler declared once should run on every host that
    /// offers the moment, and keying it on one host's spelling would silently
    /// not run on another's.
    pub on: String,
    /// The command, as argv. Never a shell string.
    ///
    /// argv rather than a command line so there is no quoting layer between what
    /// an operator wrote and what runs: no word splitting, no glob expansion, no
    /// command substitution.
    pub run: Vec<String>,
    /// How long this handler may run, in milliseconds.
    ///
    /// Absent means [`DEFAULT_TIMEOUT`]. There is deliberately no spelling for
    /// "no timeout": the bound is the property the door exists to provide, and a
    /// surface letting a handler opt out of it would return every registration
    /// to the state this replaces.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_ms: Option<u64>,
    /// Which tool names this handler runs for, as a regular expression over the
    /// raw name (CLOUD-312 row 5).
    ///
    /// **Absent means every call at the event**, which is what [`selects`] did for
    /// every row before this column existed — so no landed row changes behaviour by
    /// its arrival.
    ///
    /// # Why a handler needs one at all
    ///
    /// [`selects`] narrows by EVENT, which is the whole narrowing `pre-tool` was
    /// admitted on. That is enough for `user-prompt-submit`, which fires once a
    /// turn. It is not enough for `pre-tool`, which fires on every tool call:
    /// measured 2026-08-25 while retiring `connector-allow-guard`, an unnarrowed
    /// `pre-tool` handler cost **19.6ms p50 on a `Bash` call and 19.9ms on a
    /// `Read`** — calls it has nothing to say about — against a `wired` path whose
    /// whole p50 is 21ms. The guard it replaced was registered under a host matcher
    /// and never saw those calls, so the door would have been a regression dressed
    /// as a consolidation.
    ///
    /// # A regex here, where a rule row gets `tool`
    ///
    /// [`crate::config_model::Rule::tool`] is a SUFFIX selector, deliberately: a rule
    /// naming a literal server is the CLOUD-178 trap, where a host rotates the
    /// exposed name and the row silently matches nothing. This column is a regex
    /// instead, because the predicate a dispatched program needs is not always a
    /// suffix — `connector-allow-guard` decides `mcp__<any server>__<any verb>`,
    /// which is a PREFIX and which no suffix selector can say.
    ///
    /// **The trap is refused rather than trusted.** A matcher naming a literal
    /// server segment is exactly what CLOUD-178 measured going inert, so
    /// [`Handler::validate`] rejects one — `^mcp__` is admitted and
    /// `^mcp__Linear__` is not. That keeps the freedom this column needs without
    /// re-opening the defect the sibling column's shape exists to prevent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub matcher: Option<String>,
    /// Which COMMANDS this handler runs for, as a regular expression over the
    /// mediated call's command string (CLOUD-1650).
    ///
    /// **Absent means every call [`Handler::matcher`] already selected**, so no
    /// landed row changes behaviour by this column's arrival — the same promise
    /// `matcher` itself made when it was added.
    ///
    /// # Why the sibling column cannot express this
    ///
    /// [`Handler::matcher`] is a regex over the TOOL NAME. That is the whole of
    /// what it can say, and for a shell tool the tool name is `Bash` on every
    /// call the agent makes — so a handler that wants *some* shell commands and
    /// not others has, without this, exactly two options: fire on all of them, or
    /// on none. Firing on all of them is not a neutral default. Measured
    /// 2026-08-25 on the sibling column's own row, an unnarrowed `pre-tool`
    /// handler cost 19.6ms p50 on a `Bash` call against a `wired` path whose
    /// whole p50 is 21ms — so "narrow by tool name only" prices a handler about a
    /// dozen commands as if it were about every one.
    ///
    /// # It names a SHAPE, never a program's own vocabulary
    ///
    /// The engine holds the matcher and the consumer's `batten.toml` holds the
    /// expression, which is `protected`'s split and non-negotiable rule 1's: a
    /// list of git subcommands in `crates/batten` would be one consumer's
    /// vocabulary shipped to every adopter. What is generic here is "select on
    /// what the call is going to RUN, not on what the host called the tool".
    ///
    /// # A command that cannot be read does NOT select
    ///
    /// The opposite reading from [`Handler::selects_tool`]'s unparseable-matcher
    /// arm, and the asymmetry is deliberate. There, running is the safe direction
    /// because the row was validated at load and reaching the fallback means a
    /// caller skipped validation. Here, could-not-look means the ENVELOPE carried
    /// no command — every non-command tool call in the session — and selecting on
    /// those would fire the handler on every `Read` and every `Edit`, which is the
    /// unnarrowed cost this column exists to avoid. A row declaring this column
    /// has said its subject is a command; an envelope with no command is not its
    /// subject.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command_matcher: Option<String>,
    /// Whether this handler's subject is the TREE, so a call writing outside the
    /// repository does not select it (CLOUD-2390).
    ///
    /// Measured: `filed-row-settled` refuses every Edit and Write while a filed
    /// row is unsettled, and its remedy is a board write. In plan mode the board
    /// write is refused, so the host's plan file — outside the repository, and
    /// the one file plan mode exists to write — could not be written either.
    ///
    /// **A boolean, not a path expression**: the boundary already makes a
    /// written path repo-relative exactly when it lies inside the repository
    /// (`hook::relativise_writes`), so a ROOTED path IS a path outside it, and
    /// no row has to spell a host's directory layout. Rooted, not absolute: on
    /// Windows `/root/x.md` has a root but no drive, so `is_absolute` reads it
    /// as inside, and only the Windows leg says so. A call that writes no path
    /// is selected — nothing was written outside. `false` is every landed row.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub tree_only: bool,
    /// The issue that owns retiring this handler (CLOUD-984).
    ///
    /// **A handler is an antipattern with a ratchet, never a destination.** The
    /// door makes a dispatched program safe — a bound, central fail-open, a
    /// stated output shape — and none of that makes it *policy*. A predicate
    /// living behind a spawn is one the committed authority cannot be read to
    /// discover, so every handler is a debt somebody owes, and this column is
    /// where the creditor is named.
    ///
    /// Absent is not refused at load, deliberately — see
    /// [`Handler::transitional_defect`] for why the enforcement is tree-scoped.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,
    /// The date past which this handler is overdue, `YYYY-MM-DD`.
    ///
    /// Not an expiry that switches the handler OFF: a dispatched program that
    /// silently stopped running is the fail-open this whole surface exists to
    /// close. It is a date past which the DIAGNOSIS says so, which is the only
    /// form of pressure that cannot itself become an outage.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires: Option<String>,
    /// Whether this handler's advisory is a **pre-approval** rather than a note.
    ///
    /// CLOUD-191's channel, and the reason it is a column rather than a new exit
    /// code: §7's table is `0/1/2/3` with no per-kind exception, and
    /// [`Outcome::Advise`] already occupies exit `0` with output. A third meaning
    /// distinguished by the *shape* of stdout is exactly what [`impersonates_host`]
    /// refuses, so the capability is DECLARED here and the channel stays the exit
    /// code the handler already has. A row without this behaves exactly as it does
    /// today, and no new vocabulary enters the stream.
    ///
    /// **What it buys.** `connector-allow-guard` reads the session's injected MCP
    /// config to learn which of a server's two names — readable or UUID — is live
    /// this session, and applies the committed verdict to the live spelling. Its
    /// allow arm has to reach the host as `permissionDecision: "allow"` or the
    /// operator is prompted for a grant they already wrote down.
    ///
    /// **What it cannot buy.** A pre-approval only ever upgrades a decision that
    /// was already an allow; the boundary enforces that rather than trusting it, so
    /// no handler can spend a refusal the engine's own rows reached. And it is
    /// refused at load on any event whose host does not honour one, because a
    /// declared grant that lands nowhere is indistinguishable from this handler
    /// never having run.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub preapproves: bool,
}

/// One declared plan query: which surface to ask about, and what a module needs
/// to decide over the answer.
///
/// **`required` and `prohibited_profiles` are CONSUMER facts** and live in the
/// row rather than in this crate (non-negotiable rule 1). They are projected
/// alongside the acquired plan so the module compares two halves of one document
/// rather than reaching for a second source — the same shape a `[[rule.tools]]`
/// row's `id` gives its module.
#[derive(
    Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct PlanQuery {
    /// The key this plan is projected under in `input.tree.plan`.
    pub id: String,
    /// Which surface to ask about: a hook name the contract also covers.
    pub hook: String,
    /// The steps this consumer requires the plan to include.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required: Vec<String>,
    /// Profiles whose presence makes the plan unusable for this consumer.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub prohibited_profiles: Vec<String>,
    /// Profiles to ask the runner about, each passed as `--profile <p>`
    /// (CLOUD-843).
    ///
    /// **The runner's own grammar, including its negation** (`!slow`), so a
    /// consumer can ask what the gate plans with a tier switched OFF — the only
    /// reading that shows which steps declare that tier, since a step excluded
    /// for a missing profile is by construction a step that declared it. The
    /// answer stays hk's: this passes the words and parses nothing.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub profile: Vec<String>,
}

/// The lifecycle events the core normalizes, whatever a host spells them.
///
/// A vocabulary enum with a `const ALL`, the shape [`Harness`],
/// [`crate::capture::Stream`] and [`crate::config_model::RuleKind`] already use, so
/// anything ranging over events is derived rather than re-typed — the golden
/// census in `tests/cli.rs` reads this, which is what stops a new variant from
/// landing with no fixture.
///
/// The set is what the dependent surfaces consume, not everything a host emits:
/// which events a given host offers is the capability table's business
/// (CLOUD-45), and per-host spellings beyond the converged ones below are the
/// shims' (CLOUD-44).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Event {
    /// Before a tool runs — the only point at which a deny still prevents
    /// anything, and so the only event policy adjudicates.
    PreTool,
    /// After a tool ran. A deny here would refuse something that already
    /// happened, which no host honours and none of them offer.
    PostTool,
    /// End of turn: the reconciliation point the stop gate uses (CLOUD-85).
    Stop,
    /// Start of a session.
    SessionStart,
    /// A task was marked complete. **Claude-only** across the surveyed hosts,
    /// and the one Claude-exclusive capability that is load-bearing here: exit 2
    /// prevents the completion, which is the literal machine form of Batten's
    /// thesis about completion signals. A policy keyed on it degrades to the
    /// Stop family elsewhere (see [`Capabilities::degrade`]).
    TaskCompleted,
    /// A settings file is being edited mid-session. Claude-only; a
    /// self-protection surface no other surveyed host offers.
    ConfigChange,
    /// The host named an event this build does not normalize. Distinct from an
    /// absent one: absent means nobody said, this means somebody said something
    /// we do not know, and the two must not collapse.
    Unrecognized,
    // DECLARED AFTER the catch-all on purpose, which reads oddly and is the
    // cheaper of two honest options. This enum is field-less and carries no
    // `repr`, so a consumer may write `Event::Unrecognized as u8` and inserting
    // ahead of it shifts that value — `cargo semver-checks` calls it
    // `enum_no_repr_variant_discriminant_changed`. Appending keeps the change
    // patch-compatible instead of putting a break in the changelog for a
    // discriminant nothing observes. Reading order lives in `Event::ALL`, which
    // is what every census and the wiring emitter iterate, so nothing but this
    // declaration is affected.
    /// Every tool call in a batch has resolved, before the next model request
    /// (CLOUD-389). **Claude-only** across the surveyed hosts.
    ///
    /// The batch boundary [`crate::drain`] wants and, until this variant existed,
    /// inferred with a coalescing window on every host including the one that
    /// emits it. The window is not replaced — four of five surveyed hosts offer
    /// no batch event, and CLOUD-79 puts the once-per-batch guarantee in the mask
    /// rather than in any event — so this is the exact path where one exists and
    /// the window is the fallback it was designed as. A policy keyed on it
    /// degrades to [`Event::PostTool`] elsewhere (see [`Capabilities::degrade`]).
    ///
    /// No deny channel, and that is structural rather than a choice: a boundary
    /// between batches is not a decision point, and [`adjudicate`] allows every
    /// non-pre-tool event before any rule is consulted.
    PostToolBatch,
    /// A turn's prompt has been submitted, before the model sees it.
    /// **Claude-only** across the surveyed hosts.
    ///
    /// Appended for the reason [`Event::PostToolBatch`] above it was: this enum
    /// carries no `repr`, so inserting ahead of an existing variant shifts a
    /// discriminant a consumer may have cast, which `cargo semver-checks` reports
    /// as `enum_no_repr_variant_discriminant_changed`. Reading order is
    /// [`Event::ALL`]'s, which is what every census and the wiring emitter
    /// iterate.
    ///
    /// **It carries a deny channel, and that is measured rather than assumed**
    /// (CLOUD-777, 2026-08-21). This repository's own wiring was the evidence:
    /// two bash guards registered here reached `exit 2` on five paths between
    /// them and emitted no advisory shape — deny-issuing gates on this surface,
    /// honoured by the host. So this is **not** one of the stated no-ops beside
    /// it: [`adjudicated`]'s arm says the channel is real and that no rule kind
    /// selects for it yet, which is a gap with an owner rather than a decision
    /// that there is nothing to decide.
    ///
    /// **The evidence moved rather than expired** (CLOUD-898). One of those two
    /// guards is now a `[[hook.handler]]` dispatched by `batten hook` instead of
    /// registered beside it, so the count above is history. The conclusion is
    /// unchanged and is now demonstrated by the door itself: a handler exiting
    /// `2` at this event produces the host's own deny document, asserted in
    /// `tests/cli.rs`. What DID change is the advisory half — this host offers no
    /// `additionalContext` field here, so a handler's advice at this event
    /// degrades to the operator's stream. Deny reaches the model; advice does
    /// not.
    UserPromptSubmit,
    // CLOUD-2581: the rest of Claude Code's 33 hook events (measured on
    // 2.1.319), appended for the discriminant reason above. All but the
    // worktree pair carry no verdict and pass through until a rule needs one.
    /// A tool call failed. Claude Code (CLOUD-2581).
    PostToolFailure,
    /// The host showed the user a notification. Claude Code (CLOUD-2581).
    Notification,
    /// A submitted prompt was expanded (a slash command or mention). Claude Code (CLOUD-2581).
    UserPromptExpansion,
    /// A session ended. Claude Code (CLOUD-2581).
    SessionEnd,
    /// A turn ended on an error rather than a stop. Claude Code (CLOUD-2581).
    StopFailure,
    /// A subagent started. Claude Code (CLOUD-2581).
    SubagentStart,
    /// A subagent finished. Claude Code (CLOUD-2581).
    SubagentStop,
    /// Before the context is compacted. Claude Code (CLOUD-2581).
    PreCompact,
    /// After the context was compacted. Claude Code (CLOUD-2581).
    PostCompact,
    /// Before the session's model changes. Claude Code (CLOUD-2581).
    PreModelSwitch,
    /// After the session's model changed. Claude Code (CLOUD-2581).
    PostModelSwitch,
    /// The host is about to ask the user for a permission. Claude Code (CLOUD-2581).
    PermissionRequest,
    /// A permission was denied. Claude Code (CLOUD-2581).
    PermissionDenied,
    /// The host's setup phase. Claude Code (CLOUD-2581).
    Setup,
    /// A teammate agent went idle. Claude Code (CLOUD-2581).
    TeammateIdle,
    /// A task was created. Claude Code (CLOUD-2581).
    TaskCreated,
    /// An MCP server asked the user for input. Claude Code (CLOUD-2581).
    Elicitation,
    /// The user answered an elicitation. Claude Code (CLOUD-2581).
    ElicitationResult,
    /// The host asks for a linked worktree; stdout answers with its path. Claude Code (CLOUD-2581).
    WorktreeCreate,
    /// The host asks for a linked worktree to be removed. Claude Code (CLOUD-2581).
    WorktreeRemove,
    /// An instructions file was loaded. Claude Code (CLOUD-2581).
    InstructionsLoaded,
    /// The session's working directory changed. Claude Code (CLOUD-2581).
    CwdChanged,
    /// A watched file changed. Claude Code (CLOUD-2581).
    FileChanged,
    /// A directory was added to the session. Claude Code (CLOUD-2581).
    DirectoryAdded,
    /// The host displayed a message. Claude Code (CLOUD-2581).
    MessageDisplay,
    /// The host is about to send a model request. Codex `PreModelRequest`,
    /// Gemini `BeforeModel` (CLOUD-2700).
    ModelRequest,
    /// A model response arrived. Codex `PostModelRequest`, Gemini `AfterModel`
    /// (CLOUD-2700).
    ModelResponse,
    /// The host is about to choose which tools the model is offered. Gemini
    /// `BeforeToolSelection` (CLOUD-2700).
    ToolSelection,
    /// The agent finished a response. Cursor `afterAgentResponse` (CLOUD-2700).
    AgentResponse,
    /// The agent finished a thinking block. Cursor `afterAgentThought`
    /// (CLOUD-2700).
    AgentThought,
    /// The user interrupted the agent. Codex `Interrupt` (CLOUD-2700).
    Interrupt,
    /// The host reported an error. Copilot `ErrorOccurred` (CLOUD-2700).
    ErrorOccurred,
    /// A workspace was opened. Cursor `workspaceOpen` (CLOUD-2700).
    WorkspaceOpen,
    /// Tab completion is about to read a file. Cursor `beforeTabFileRead`
    /// (CLOUD-2700). Not a tool call: the payload carries no tool.
    TabFileRead,
    /// Tab completion edited a file. Cursor `afterTabFileEdit` (CLOUD-2700).
    TabFileEdit,
    /// A forge event: one of GitHub's webhook events, normalized by
    /// [`crate::forge_event`] (CLOUD-2689). No host emits it, so no wiring
    /// registers it; `forge intake` is its door. Its verdict is a finding about
    /// something that already happened, as on `post-tool`.
    Forge,
    /// A child session this one dispatched reached an end (CLOUD-2826):
    /// `session.done`, `session.dead` or `session.unstarted`, from
    /// `batten session watch`. A harness-provider lifecycle source
    /// (CLOUD-1728's taxonomy) no host emits, so, like [`Event::Forge`], no
    /// wiring registers it. Appended for the discriminant reason above.
    ChildSession,
}

/// What batten does about one name in a [`HookSource`]'s vocabulary.
///
/// Named `HookDisposition`, never bare `Disposition`:
/// `findings::Disposition` and `selfwrite::Disposition` are public already.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HookDisposition {
    /// Batten is registered for it; `check` is the declared verb that checks the
    /// registration on a live checkout.
    Registered {
        /// A `surface::SURFACE` path.
        check: &'static str,
    },
    /// Deliberately not registered; `reason` is a stable kebab id.
    Unsupported {
        /// Why, as a kebab id rather than prose.
        reason: &'static str,
    },
}

#[rustfmt::skip]
pub(crate) const BY_GATE: HookDisposition = HookDisposition::Registered { check: "doctor gate" };

/// Whether `name` is a githooks(5) hook name, one of [`GIT_HOOKS`] (CLOUD-2339).
#[must_use]
pub fn is_git_hook(name: &str) -> bool {
    GIT_HOOKS.iter().any(|(hook, _)| *hook == name)
}

/// githooks(5) for git 2.43, one row per name, alphabetical.
///
/// **A SNAPSHOT**: a hook a later git adds is not caught automatically. The
/// registered rows must equal `doctor::COMMIT_HOOKS`, which stays the runtime
/// authority for which git hooks batten links.
///
/// `pre-push` IS REGISTERED, no longer `adjudicated-elsewhere`: the push was
/// left to the mediated call and `land`, and a commit `git revert` made through
/// the sequencer (no `commit-msg`) reached `verify` with a non-conventional
/// subject. The push is the last local point every commit passes.
///
/// Every reason is a stable id: `after-the-fact` refuses nothing that has not
/// already happened (the [`Event::PostTool`] argument), `server-side` runs on a
/// remote, and `no-predicate` is a hook nothing here has a rule for yet.
/// `pre-merge-commit` stays `no-predicate`: fast-forward landing makes no merge
/// commits. Registering a further hook is per-source work, not this table's.
pub const GIT_HOOKS: &[(&str, HookDisposition)] = &[
    ("applypatch-msg", unsupported("no-predicate")),
    ("commit-msg", BY_GATE),
    ("fsmonitor-watchman", unsupported("not-a-gate")),
    ("p4-changelist", unsupported("no-predicate")),
    ("p4-post-changelist", unsupported("after-the-fact")),
    ("p4-pre-submit", unsupported("no-predicate")),
    ("p4-prepare-changelist", unsupported("no-predicate")),
    ("post-applypatch", unsupported("after-the-fact")),
    ("post-checkout", unsupported("after-the-fact")),
    ("post-commit", unsupported("after-the-fact")),
    ("post-index-change", unsupported("after-the-fact")),
    ("post-merge", unsupported("after-the-fact")),
    ("post-receive", unsupported("server-side")),
    ("post-rewrite", unsupported("after-the-fact")),
    ("post-update", unsupported("server-side")),
    ("pre-applypatch", unsupported("no-predicate")),
    ("pre-auto-gc", unsupported("no-predicate")),
    ("pre-commit", BY_GATE),
    ("pre-merge-commit", unsupported("no-predicate")),
    ("pre-push", BY_GATE),
    ("pre-rebase", unsupported("no-predicate")),
    ("pre-receive", unsupported("server-side")),
    ("prepare-commit-msg", unsupported("no-predicate")),
    ("proc-receive", unsupported("server-side")),
    ("push-to-checkout", unsupported("server-side")),
    ("reference-transaction", unsupported("no-predicate")),
    ("sendemail-validate", unsupported("no-predicate")),
    ("update", unsupported("server-side")),
];

/// Fold a value for [`Rule::when_value`]'s comparison.
///
/// Case-insensitive, and the three separators a tracker's state parameter treats
/// as noise are dropped. Deliberately NOT a general slug: nothing else is
/// stripped, so a value that differs by any other character still differs.
pub(crate) fn comparable(value: &str) -> String {
    value
        .chars()
        .filter(|ch| !matches!(ch, ' ' | '_' | '-'))
        .flat_map(char::to_lowercase)
        .collect()
}

/// Is `token` a shell assignment, `NAME=VALUE` or the append `NAME+=VALUE`?
///
/// THE APPEND IS AN ASSIGNMENT TOO (CLOUD-2840): `TOUCHED+=(a b)` in a sourced
/// script was read as a program named `TOUCHED+=(a`, and the install gate held
/// the call on it.
pub(crate) fn is_env_assignment(token: &str) -> bool {
    let Some((name, _)) = token.split_once('=') else {
        return false;
    };
    let name = name.strip_suffix('+').unwrap_or(name);
    let mut chars = name.chars();
    matches!(chars.next(), Some(c) if c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// The record this module writes, and the one `record::VERB_WRITTEN` names so a
/// module can read it back.
pub const LAP_RECORD: &str = "lap";

/// The receipt families keyed by BRANCH NAME rather than by sha.
///
/// **A sha-keyed receipt dies with its sha and needs no sweep; these do not.**
/// Each of these records something about a branch's whole filing history, so the
/// next piece of work to reuse the name would be judged against rows that belong
/// to the last one (CLOUD-774).
///
/// `filed-here-nudged` and `filed-set-nudged` are no longer written: the Stop
/// ladder stopped withholding its pointers (CLOUD-2078). They stay listed so a
/// clone that ran an older engine still has its leftovers swept when the branch
/// lands, rather than keeping them forever.
/// `unlanded-nudged` was missing once (CLOUD-1390). `unlanded_pointer` writes
/// `unlanded-nudged.<slug>` under this same directory, keyed by the completion
/// finding's own fingerprint, and `turn mint ahead` reads it as its
/// `while_marker`: the claim was told.
///
/// **What a missed family costs is a marker that outlives the work it was
/// about.** Left behind, the next piece of work to reuse the name inherits it,
/// and is judged as though it had already been told what the last one was.
///
/// **`pub(crate)` because a `while_marker` row is validated against it**
/// (CLOUD-1390). A marker that landing does not sweep is a refusal with no spend:
/// the row fires, the work lands, the file survives, and the next branch to reuse
/// the name is denied for a punt it did not commit. `Rule::validate_marker`
/// refuses that row at load rather than letting the pair drift, which is the same
/// discipline this list's own header records having needed twice already.
pub(crate) const BRANCH_KEYED_RECEIPTS: &[&str] = &[
    "board-writes",
    "filed-here-nudged",
    "filed-set-nudged",
    "unlanded-nudged",
    "unlanded-spoken",
    // The Stop's step for this claim (CLOUD-2655): land, or deepen the clone.
    "unlanded-step",
    // The Stop refusal's bound and its dispatch excuse (CLOUD-2441): left behind,
    // a reused branch name would inherit a spent refusal or a free Stop.
    "unlanded-refused",
    "land-dispatched",
    // `pr-open`, minted from `create_pull_request`'s own result: this branch has an
    // unlanded pull request, so opening a second one is the bundle split
    // AGENTS.md's "one PR all of it" refuses. Landing sweeps it here, which is what
    // lets the NEXT branch open its one PR.
    "pr-open",
];

pub(crate) const fn unsupported(reason: &'static str) -> HookDisposition {
    HookDisposition::Unsupported { reason }
}
