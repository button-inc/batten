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
    pub engine: Option<crate::engine::Pin>,
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
    pub redirects: Vec<crate::redirect::Redirect>,
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
    /// all. [`crate::record::Declared`] carries the whole argument.
    ///
    /// Consumer-owned, like the two tables above it: which measurements a
    /// repository records, and what fills each, are facts about that repository
    /// and never about the engine (non-negotiable rule 1).
    #[serde(default, rename = "record", skip_serializing_if = "Vec::is_empty")]
    pub records: Vec<crate::record::Declared>,
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
    pub exec_patterns: Vec<crate::outputs::OutputPattern>,
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
    pub verify_environment_patterns: Vec<crate::outputs::OutputPattern>,
    /// How `batten exec` owns what it dispatched (CLOUD-427). Absent means the
    /// defaults, and the default is today's behaviour: Batten makes no process
    /// group. Authority-only by omission from [`OverrideConfig`] — an uncommitted
    /// file may not decide that a dispatched tree changes shape, because an
    /// orchestrator two levels up is built against the shape the repository
    /// declared. The type and the predicate are [`crate::exec`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exec: Option<crate::exec::ExecConfig>,
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
    pub mcp: Option<crate::mcp::McpConfig>,
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
    pub capture: Option<crate::capture::CaptureConfig>,
    /// The suppression markers to count (CLOUD-36). Which comment shape waves
    /// a rule through is a property of the repository being gated, never of
    /// Batten; the type and the counting are [`crate::markers`].
    #[serde(default, rename = "marker", skip_serializing_if = "Vec::is_empty")]
    pub markers: Vec<crate::markers::Marker>,
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
    pub budget: Option<crate::budget::Budget>,
    /// What ONE emitted mediated refusal line may cost (CLOUD-1286). Absent
    /// means no ceiling is declared and none is enforced, on the same reading as
    /// `[budget]` above. The type and the predicate are [`crate::refusal`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refusal: Option<crate::refusal::Ceiling>,
    /// What ONE emission of the advisory channel may cost, across every producer
    /// (CLOUD-896). Absent means unenforced, on `[budget]`'s reading. The type
    /// and the predicate are [`crate::advisory`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub advisory: Option<crate::advisory::Channel>,

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
    pub hook_output: Option<crate::hookcost::Ceiling>,
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
    pub judge: Option<crate::judge::Judge>,
    /// The design-evidence audit's one bound (CLOUD-53): how large a single
    /// capture may be. Absent means the engine default — the corpus arrives on
    /// stdin and the predicates are the engine's, so a repository that declares
    /// nothing still gets the full gate. The type and the gates are
    /// [`crate::design`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub design: Option<crate::design::Design>,
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
    pub prune: Option<crate::prune::Prune>,
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
    pub defects: Option<crate::defects::Defects>,
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
    pub drain: Option<crate::drain::DrainConfig>,

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
    pub credential: Option<crate::provision::CredentialProbe>,
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
    pub commit: Option<crate::commit::Commit>,
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
    pub bot_lane: Option<crate::bot::BotLane>,
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
    pub wiring: Option<crate::wiring::Wiring>,
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
    pub census: Option<crate::census::Census>,
    /// What `batten sbom` inventories and under which names (CLOUD-843).
    /// Absent means the verb has no subject to name, which it refuses rather
    /// than guessing one.
    ///
    /// Consumer-specific for `census`'s reason: the subject's name, where its
    /// documents land, which paths a scan skips and where its licence table
    /// lives are somebody's layout. The derivation is the engine's; the type and
    /// the reading are [`crate::sbom`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sbom: Option<crate::sbom::Declared>,
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
