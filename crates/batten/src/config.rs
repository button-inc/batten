//! The `batten.toml` loader (house-style §8).
//!
//! Configuration is **one committed authority** — the repo `batten.toml` — plus
//! raise-only overrides (env, flags, a git-ignored `batten.local.toml`). This
//! module loads and validates *one file*; [`crate::resolve`] layers the files
//! and the overrides in the §8 precedence order and applies the raise-only
//! clamp (the standalone config-lint predicate over that clamp is CLOUD-87).
//!
//! The surface is deliberately narrow (non-negotiable rule 6): the config is a
//! typed struct with **no unknown keys** — a typo is an error, not a silently
//! ignored setting — and a required schema `version` so an incompatible file
//! fails loudly rather than being half-understood.
//!
//! ## Absence is the default layer; invalidity is still a refusal (CLOUD-70)
//!
//! A repository with **no** `batten.toml` resolves to [`defaults`] — §8's layer
//! 0, the one [`crate::resolve::Source::Default`] already models — rather than
//! failing, so `check` works out of the box and `init` is opt-in.
//!
//! That is emphatically **not** a widening of where configuration may come from
//! (non-negotiable rule 6): there is still one committed authority, still no
//! upward walk and no `conf.d` merge. Nothing new is *discovered*; a compiled-in
//! value is used when nothing was written. The two cases stay sharply apart —
//! **absence selects the defaults, invalidity never does.** A `batten.toml` that
//! is present and malformed, carries an unknown key, or declares an unsupported
//! `version` is refused exactly as before.
//!
//! [`load`] keeps the strict reading, and [`load_authority`] carries the
//! defaulting one, because absence means different things to different callers:
//! [`crate::trust`]'s comparand needs "this authority grants nothing" (deleting
//! the file is the *maximal weakening*, CLOUD-243) and [`crate::doctor`] needs to
//! report `config-missing`. Only the §8 resolution chain wants defaults.

use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::Path;

use anyhow::Result;
use clap::ValueEnum;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::error::UsageError;
use crate::rules::Rule;
use crate::{outputs, waiver};

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

/// A parsed, validated `batten.toml`.
///
/// `deny_unknown_fields` makes an unrecognised key a hard error (§8): the config
/// surface stays narrow and a typo can never silently disable a gate.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// The config schema version. Must equal [`SUPPORTED_VERSION`].
    pub version: u32,
    /// The minimum Batten version permitted to read this file (semver).
    /// Enforced at parse time by [`check_min_version`]: a binary below it is
    /// refused with a [`UsageError`] (→ exit `1`) rather than allowed to report
    /// green over rules it does not understand (CLOUD-33).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_batten_version: Option<String>,
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
    /// its tools and its schema, so a grep of `crates/batten` for any of them
    /// returns nothing and every one of them lives here.
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
    /// so a grep of `crates/batten` for any of them returns nothing and every one
    /// of them lives here.
    #[serde(default, rename = "recorder", skip_serializing_if = "Vec::is_empty")]
    pub recorders: Vec<crate::recorder::Declared>,
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
    /// How `batten exec` owns what it dispatched (CLOUD-427). Absent means the
    /// defaults, and the default is today's behaviour: Batten makes no process
    /// group. Authority-only by omission from [`OverrideConfig`] — an uncommitted
    /// file may not decide that a dispatched tree changes shape, because an
    /// orchestrator two levels up is built against the shape the repository
    /// declared. The type and the predicate are [`crate::exec`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exec: Option<crate::exec::ExecConfig>,
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
    /// The thresholds this repository holds itself to (CLOUD-50). Today one:
    /// `[budget.instructions]`, the always-loaded instruction set and what it
    /// may cost. Absent means no budget is declared and none is enforced — a
    /// threshold nobody wrote down is not a threshold of zero. The type and the
    /// predicate are [`crate::budget`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub budget: Option<crate::budget::Budget>,
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
    /// Side effects this repository attaches to hook events (CLOUD-91), the
    /// house-style §9 extension surface: `[[hook.action]]` names an event and a
    /// command already on the operator's PATH, so repo-specific cleanup or
    /// keepalive is reconstructed here rather than carried by the engine
    /// (non-negotiable rule 1). Absent means the repository attaches nothing.
    /// The type, its validator and the spawn are [`crate::action`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hook: Option<crate::action::HookConfig>,
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
    /// What this project's build costs and what to keep of it (CLOUD-1030).
    /// Absent means the repository runs no prune and `batten target prune` has
    /// nothing to decide against — a different claim from a floor of zero, which
    /// is why this is an option rather than a default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prune: Option<crate::prune::Prune>,
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
    /// the configured patterns returns nothing. The type and the predicate are
    /// [`crate::attribution`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attribution: Option<crate::attribution::Attribution>,
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
    /// How the base-ref authority behaves when the ref cannot be reached
    /// (CLOUD-720). Absent means the strict default: an unreachable ref refuses.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust: Option<Trust>,
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
/// (non-negotiable rule 1).
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
/// (non-negotiable rule 1).
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

/// Parse and validate a `batten.toml` from `text`, attributing errors to
/// `source` (a path or label) in their messages.
///
/// # Errors
///
/// Returns a [`UsageError`] (→ exit `1`) for a malformed file, an unknown key,
/// or an unsupported [`Config::version`]. These are bad *input*, not internal
/// failures.
pub fn parse(text: &str, source: &str) -> Result<Config> {
    let config = parse_ungated(text, source)?;
    check_min_version(&config, source)?;
    Ok(config)
}

/// The other direction of [`parse`]: a [`Config`] back to TOML text.
///
/// **Exists so the round trip has one spelling** (CLOUD-341). The loader's
/// contract is that it either produces a valid [`Config`] or a [`UsageError`],
/// *and never a silently-wrong value* — and that last clause is only decidable by
/// re-emitting an accepted config and reading it back. Both drivers of that
/// property (the seeded one beside this loader, and the unbounded fuzz target)
/// need the emit half, and neither should reach for the TOML crate itself: a
/// second spelling of "how this config is written down" is a second authority
/// over the same bytes, and it is the half most likely to drift under a parser
/// bump — which is the very shift the property exists to catch.
///
/// # Errors
///
/// Raises a [`UsageError`] (→ exit `1`) for a config the emitter cannot write.
/// That is a **disagreement between the two halves of the config surface**
/// rather than bad input, and it is surfaced rather than tolerated: every value
/// in a `Config` reached it through [`parse`], so a shape only one half can
/// express is a finding.
pub fn emit(config: &Config) -> Result<String> {
    toml::to_string(config)
        .map_err(|err| UsageError::raise(format!("cannot re-emit the resolved config: {err}")))
}

/// The migration window applied to one config's text, ahead of the typed parse.
///
/// **Two jobs, and they are the two halves §2 names.** A key inside its window is
/// STRIPPED so `deny_unknown_fields` does not refuse it — the whole point of the
/// window is that the old spelling still loads — and its pointer is returned for
/// the caller to report. A key past expiry is REFUSED here rather than stripped,
/// because the window closing is the deprecation grammar's one hard edge; letting
/// it fall through to `deny_unknown_fields` would report it as an unknown key,
/// which is a different diagnostic with a different remedy and is the collapse
/// §7(c) exists to catch.
///
/// A key that was never ours is left alone entirely, to be refused as unknown by
/// the typed parse. This function narrows nothing and widens nothing: it only
/// moves keys the table already names.
///
/// # Errors
///
/// Raises a [`UsageError`] (→ exit `1`) when `text` is not TOML, or when a key
/// past its expiry is present.
pub fn apply_window(
    text: &str,
    source: &str,
    table: &[Deprecation],
    today: &str,
) -> Result<(String, Vec<String>)> {
    let mut parsed: toml::Table = toml::from_str(text)
        .map_err(|err| UsageError::raise(format!("invalid config {source}: {err}")))?;
    let mut reported = Vec::new();
    // Sorted, because the report is compared byte-for-byte under §6 and a TOML
    // table's iteration order is not the author's file order.
    let mut present: Vec<String> = parsed.keys().cloned().collect();
    present.sort();
    for key in present {
        match deprecation_of(table, &key, today) {
            Some(standing @ Standing::Expired { .. }) => {
                return Err(UsageError::raise(format!(
                    "invalid config {source}: {}",
                    deprecation_line(&standing)
                )));
            }
            Some(standing @ Standing::Migrating { .. }) => {
                parsed.remove(&key);
                reported.push(deprecation_line(&standing));
            }
            None => {}
        }
    }
    let text = toml::to_string(&parsed)
        .map_err(|err| UsageError::raise(format!("invalid config {source}: {err}")))?;
    Ok((text, reported))
}

/// One key's migration window: what replaces it, when the window closes, and the
/// row that owns the move (CLOUD-360).
///
/// **`expand -> migrate -> contract`, and this type is the MIDDLE stage.** Expand
/// is adding the replacement key beside the old one; migrate is this window,
/// where the old key still parses and says so; contract is removal, at which
/// point the key moves to [`RETIRED_KEYS`] and is tolerated only in a base ref.
/// The two tables are one authority read at two stages of a key's life, never two
/// places a deprecation is recorded — a key in both is a contradiction and
/// `no_key_is_both_deprecated_and_retired` refuses it.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Deprecation {
    /// The top-level key, as it appears in `batten.toml`.
    pub key: &'static str,
    /// The key that replaces it, or `None` when the capability is going away
    /// with no successor — a distinction a consumer needs and which an empty
    /// string would hide.
    pub replacement: Option<&'static str>,
    /// The day the window closes, `YYYY-MM-DD`. On and after it the key is
    /// REFUSED rather than reported.
    pub expires: &'static str,
    /// The `CLOUD-*` row that owns the migration, so a consumer reading the
    /// finding can find out why.
    pub issue: &'static str,
}

/// Keys this engine still accepts and is migrating away from.
///
/// **Empty is the honest state today and is not a disabled gate.** The predicate
/// over it is exercised by [`deprecation_of`]'s own cases, which supply a table
/// rather than reading this one — the shipped table records real migrations, and
/// inventing a fake row so a fixture has something to find would put a key in the
/// published schema that no consumer should ever write. What an empty table must
/// NOT do is make the schema-removal gate vacuous, and it does not:
/// `no_key_leaves_the_schema_unannounced` reads both tables, so an empty one
/// makes every removal a finding rather than none (CLOUD-251).
pub const DEPRECATED_KEYS: &[Deprecation] = &[];

/// How a key stands against the deprecation table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Standing {
    /// Inside its window: parses, and reports.
    Migrating {
        /// The window this key is inside.
        deprecation: Deprecation,
    },
    /// Past its expiry: refused.
    Expired {
        /// The window that closed.
        deprecation: Deprecation,
    },
}

/// Where a key stands, given a table and the day it is being judged on.
///
/// **The table and the date are ARGUMENTS, not reads.** That is what makes this
/// decidable in a test without a fake row in the shipped table and without a
/// clock: a window is a comparison between two dates, and a predicate that read
/// the wall clock would answer differently tomorrow for the same commit — which
/// is the property a gate must not have.
///
/// `today` and `expires` are both `YYYY-MM-DD`, so a lexical comparison IS a
/// chronological one and no date library is bought for it. A malformed `expires`
/// sorts as some string and would silently change the verdict, which is why
/// `every_declared_expiry_is_a_date` refuses one at the table rather than here.
#[must_use]
pub fn deprecation_of(table: &[Deprecation], key: &str, today: &str) -> Option<Standing> {
    let found = table.iter().find(|row| row.key == key)?.clone();
    if today >= found.expires {
        Some(Standing::Expired { deprecation: found })
    } else {
        Some(Standing::Migrating { deprecation: found })
    }
}

/// The pointer-only diagnostic for one standing (non-negotiable rule 4).
///
/// Key, replacement, expiry and owning row — never the VALUE configured at the
/// key, which is the consumer's content and is exactly what a diagnostic quoting
/// the line would leak.
#[must_use]
pub fn deprecation_line(standing: &Standing) -> String {
    let (verdict, row) = match standing {
        Standing::Migrating { deprecation } => ("deprecated", deprecation),
        Standing::Expired { deprecation } => ("expired", deprecation),
    };
    let replacement = row.replacement.unwrap_or("none");
    format!(
        "{} {verdict} replacement={replacement} expires={} ({})",
        row.key, row.expires, row.issue
    )
}

/// The top-level keys a derived JSON Schema declares.
///
/// **Top-level only, stated rather than implied.** Both deprecation tables key on
/// a top-level `batten.toml` key — `RETIRED_KEYS` names `worktree`, not
/// `worktree.pileup` — so the removal gate compares the surface those tables can
/// actually annotate. A field disappearing from inside a `$defs` type is a real
/// change this does not see, and claiming otherwise would be the wider promise
/// CLOUD-251 calls a vacuous pass.
///
/// # Errors
///
/// Raises a [`UsageError`] (→ exit `1`) when `text` is not a JSON object carrying
/// a `properties` map — a schema this cannot read is not a schema with no keys.
pub fn schema_keys(text: &str, source: &str) -> Result<std::collections::BTreeSet<String>> {
    let parsed: serde_json::Value = serde_json::from_str(text)
        .map_err(|err| UsageError::raise(format!("unreadable schema {source}: {err}")))?;
    let properties = parsed
        .get("properties")
        .and_then(serde_json::Value::as_object);
    let Some(properties) = properties else {
        return Err(UsageError::raise(format!(
            "unreadable schema {source}: no `properties` map, so its key set cannot be compared"
        )));
    };
    Ok(properties.keys().cloned().collect())
}

/// Keys the released schema declared that this one does not, and which neither
/// table announces (CLOUD-360 §2).
///
/// **The gate the row exists for.** A key vanishing from the published schema is
/// a silent break for every consumer whose `batten.toml` still carries it: their
/// config stops loading with an unknown-key error naming no successor. The
/// grammar's promise is that removal is always preceded by a window, and this is
/// the predicate that holds it.
///
/// Either table satisfies it, because they are consecutive stages of one life: a
/// key mid-window is in [`DEPRECATED_KEYS`] and one already contracted is in
/// [`RETIRED_KEYS`], and both mean the removal was announced.
///
/// An EMPTY deprecation table therefore makes this stricter, never weaker —
/// every removal is unannounced until somebody writes the row. That is the
/// direction CLOUD-251 asks for: the gate with nothing declared refuses rather
/// than passing quietly.
#[must_use]
pub fn removals_unannounced(
    released: &std::collections::BTreeSet<String>,
    current: &std::collections::BTreeSet<String>,
    deprecated: &[Deprecation],
    retired: &[(&str, &str)],
) -> Vec<String> {
    released
        .iter()
        .filter(|key| !current.contains(*key))
        .filter(|key| !deprecated.iter().any(|row| row.key == key.as_str()))
        .filter(|key| !retired.iter().any(|(name, _)| name == key))
        .cloned()
        .collect()
}

/// Keys a **past** engine accepted and this one has retired, with the issue that
/// retired each.
///
/// `deny_unknown_fields` is total on [`Config`], which is right for the working
/// tree and wrong for a config read out of a git ref: the base was written under
/// whatever engine landed it, so a key this build has since retired makes the
/// whole file unparseable and [`parse_base`]'s caller reports "could not look"
/// about a file nobody can fix. That is not a hypothetical — it is what retiring
/// a key COSTS, measured on CLOUD-780: the change that removes `[worktree]`
/// cannot land, because `config lint` judges it against an `origin/main` that
/// still declares it, and no edit to either side resolves that.
///
/// A hand-kept census rather than a blanket leniency, and the difference is the
/// point: an unknown key that was never a Batten key is still refused in a base
/// ref exactly as in the working tree, so this buys the one case it names and
/// nothing else. A row may be dropped once no supported base can carry it.
///
/// Retirement is also why nothing is lost by ignoring these: the key names no
/// policy this build can read, so a comparison that cannot see it is not missing
/// a verdict it could otherwise have reached.
pub const RETIRED_KEYS: &[(&str, &str)] = &[(
    "worktree",
    "CLOUD-780: the pileup predicate and `worktree reclaim` retired with the git \
     primitives they rested on",
)];

/// Parse a `batten.toml` read from a **git ref**, tolerating the keys
/// [`RETIRED_KEYS`] names and nothing else.
///
/// [`trust::load_base`] is the one funnel every out-of-band config load passes
/// through ([`crate::lint`], [`crate::epoch`], [`crate::resolve`]'s
/// `--config-from`), so this is where the version skew between a ref and this
/// build is answered — once, rather than per caller.
///
/// The stripped table is re-serialized and handed to [`parse`], so there is one
/// validation path rather than two that could disagree. The accepted cost, and
/// the only one: a schema error in a base config is attributed to `source`
/// without its original line span, because the span belongs to bytes that no
/// longer exist. A caller reading such an error is looking at a ref, not at a
/// file they are editing.
///
/// # Errors
///
/// As [`parse`], plus a [`UsageError`] (→ exit `1`) when `text` is not TOML at
/// all.
///
/// [`trust::load_base`]: crate::trust::load_base
pub fn parse_base(text: &str, source: &str) -> Result<Config> {
    let mut table: toml::Table = toml::from_str(text)
        .map_err(|err| UsageError::raise(format!("invalid config {source}: {err}")))?;
    // Nothing is reported when a key is dropped: the report this feeds is a
    // comparison of two policies, and "the base declared a key this build no
    // longer has" is a fact about the build rather than about either policy.
    for (key, _why) in RETIRED_KEYS {
        table.remove(*key);
    }
    let text = toml::to_string(&table)
        .map_err(|err| UsageError::raise(format!("invalid config {source}: {err}")))?;
    parse(&text, source)
}

/// The override surface: exactly what `batten.local.toml` may carry.
///
/// A **second type**, not a second reading of [`Config`], and that is the whole
/// point (CLOUD-239). The subset used to exist only as `local.*` reads inside
/// [`crate::resolve`] — invisible to a validator, so the published schema
/// vouched for keys the loader silently dropped and for one it refused outright.
/// With the surface written as a type, the schema derives from it and the two
/// cannot disagree.
///
/// `deny_unknown_fields` is what makes the refusal total and free: every
/// authority-only key (`epoch`, `marker`, `verb`, `budget`, `must_land_on`,
/// `judge`, `ci`, `defects`, `provision`, `transcript`, `design`) becomes a hard
/// parse error here rather than a silently discarded tightening. A hand-maintained
/// refusal list would be a second authority, and would drift the moment a field
/// is added to [`Config`]. `hook` is
/// authority-only for a sharper one (CLOUD-91): an action *runs a command*, and
/// there is no reading of §8's raise-only rule under which an uncommitted file
/// adding one is a tightening.
///
/// Every key here is **raise-only**; [`crate::resolve`] holds that invariant,
/// and the per-field docs say which direction "raise" means.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OverrideConfig {
    /// The schema version, required exactly as the authority requires it.
    pub version: u32,
    /// Present only so the refusal can name it.
    ///
    /// Carried as a field rather than left to `deny_unknown_fields` because
    /// "authority-only, an override may not restate it" tells the author what
    /// they did wrong, where "unknown field" would suggest a typo.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_batten_version: Option<String>,
    /// Raised, never lowered: a committed `strict` cannot be relaxed here.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub strictness: Option<Strictness>,
    /// Raised, never lowered: a committed `true` cannot be turned off here.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fail_on_warning: Option<bool>,
    /// Rules this file **adds**. Redefining a committed id is refused.
    #[serde(default, rename = "rule", skip_serializing_if = "Vec::is_empty")]
    pub rules: Vec<Rule>,
    /// Scope narrowing, and **excludes only** — a plain include is refused.
    ///
    /// Includes union, so a local include could only ever *widen* the set,
    /// which is exactly what §8's raise-only clause forbids. Excludes are purely
    /// subtractive, so appending them to the authority's ordered list is
    /// provably narrowing and needs no reasoning about entry order.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub scope: Vec<String>,
    /// Protected paths this file **adds** — §8's "add protected paths" verbatim.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub protected: Vec<String>,
    /// Unlanded paths this file **adds**; an include-only set, like `protected`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unlanded: Vec<String>,
    /// `exec` output predicates this file **adds**. A duplicate id is refused.
    #[serde(
        default,
        rename = "exec_pattern",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub exec_patterns: Vec<outputs::OutputPattern>,
    /// Redirects this file **adds**. A duplicate glob is refused.
    ///
    /// Needs no raise-only clamp, and that is a decision rather than an
    /// oversight: a redirect changes what a refusal *says*, never whether it
    /// fires, so there is no bar here to lower. Refusing a redefinition is
    /// coherence with the other append-only tables.
    #[serde(default, rename = "redirect", skip_serializing_if = "Vec::is_empty")]
    pub redirects: Vec<crate::redirect::Redirect>,
    /// Waivers this file adds, for rules the authority does not declare. A
    /// waiver over a committed rule lowers that bar and is refused.
    #[serde(default, rename = "waiver", skip_serializing_if = "Vec::is_empty")]
    pub waivers: Vec<waiver::Waiver>,
}

/// Parse an *override* layer, without the [`Config::min_batten_version`] gate.
///
/// `min_batten_version` is an **authority-only** key: [`crate::resolve`] refuses
/// a `batten.local.toml` that sets it at all. Gating on it here would fire
/// first and replace that refusal — telling an author their binary is too old
/// when the real problem is that they set the key in a file that may not carry
/// it. The more specific message is the useful one, so the override layer parses
/// ungated and lets the authority-only check speak.
///
/// # Errors
///
/// Returns a [`UsageError`] (→ exit `1`) for a malformed file, an unsupported
/// `version`, a table that fails its own validator, or **any key outside the
/// override surface** — including one that is perfectly valid in the file it was
/// copied from, which is the case this type exists to catch.
pub fn parse_override(text: &str, source: &str) -> Result<OverrideConfig> {
    let config: OverrideConfig = toml::from_str(text)
        .map_err(|err| UsageError::raise(format!("invalid config {source}: {err}")))?;
    if config.version != SUPPORTED_VERSION {
        return Err(UsageError::raise(format!(
            "unsupported config version {} in {source}; this build supports version {SUPPORTED_VERSION}",
            config.version
        )));
    }
    // The same validators the authority runs, over the same tables. An override
    // row is a policy row: one that loads here and gates nothing is the defect
    // CLOUD-242 named, and it does not become acceptable for being uncommitted.
    crate::rules::validate_in(&config.rules, text, source)?;
    crate::outputs::validate(&config.exec_patterns)?;
    crate::waiver::validate(&config.waivers)?;
    Ok(config)
}

/// The override surface's JSON schema, derived from [`OverrideConfig`].
///
/// A second artifact rather than a second reading of the first: `.taplo.toml`
/// binds `batten.local.toml` to this one, so an editor and `taplo lint` agree
/// with the loader about which keys that file may carry.
///
/// # Errors
///
/// Returns an error when the schema cannot be serialized.
pub fn override_schema() -> Result<String> {
    Ok(serde_json::to_string_pretty(&schemars::schema_for!(
        OverrideConfig
    ))?)
}

/// The shared body: deserialize and check the schema `version`.
fn parse_ungated(text: &str, source: &str) -> Result<Config> {
    let config: Config = toml::from_str(text)
        .map_err(|err| UsageError::raise(format!("invalid config {source}: {err}")))?;
    if config.version != SUPPORTED_VERSION {
        return Err(UsageError::raise(format!(
            "unsupported config version {} in {source}; this build supports version {SUPPORTED_VERSION}",
            config.version
        )));
    }
    // The verb table is validated here, at load, because nothing else validates
    // it anywhere: `verbs::validate` had no caller outside its own tests, so a
    // `[[verb]]` row that is inert — `effect = "read"` in a table named for
    // mutation, matching nothing while reading as covered — loaded clean, as did
    // a verb declared twice. A refusal with no call site is prose (non-negotiable
    // rule 2), and this one was asserted present by a doc comment, a merged PR
    // body and a passing test that reached past `parse` to call the validator by
    // hand (CLOUD-242).
    //
    // In `parse_ungated` rather than `parse` so an override layer is held to it
    // too: `batten.local.toml` may add verb rows, and a raise-only override that
    // adds an inert one has still written something that cannot mean anything.
    crate::verbs::validate(&config.verbs)?;
    // The named-regex table, at parse for the identical reason (CLOUD-885): a
    // malformed expression is a config fault, and refusing it here means
    // `config lint` and `doctor` catch it rather than a mediated call
    // discovering it at adjudication, which is the worst time and the wrong exit
    // class (house style §8).
    crate::pattern::validate(&config.patterns)?;
    // The refusal vocabulary, at parse for the identical reason (CLOUD-1050).
    // Every clause is a property of the TABLE — a token's prefix, a gloss that
    // is one line, a route list that is not an override alone, a tombstone chain
    // that terminates — so it is knowable without a tree and belongs where a
    // config fault is reported. Registry EQUALITY against what the modules
    // actually emit needs the compiled bundles and lives in `policy::load`.
    crate::verdict::validate(&config.verdicts)?;
    crate::redirect::validate(&config.redirects)?;
    // And the marker table, for the identical reason in the identical shape
    // (CLOUD-253). Both tables arrived in one commit; CLOUD-242 wired one of
    // them up and nobody checked the sibling, so an empty `token` — which
    // matches every line of every file — still loaded clean. The completeness
    // test below is what stops the next table arriving orphaned the same way.
    crate::markers::validate(&config.markers)?;
    // And the action table, where "validated only by the runner" would be worst
    // of all: an action is a command, and a row that loads clean but names no
    // event is a side effect the operator believes is attached and which fires
    // at no moment. Refused at load, so the failure lands on the config rather
    // than as silence at the event.
    if let Some(hook) = &config.hook {
        crate::action::validate(&hook.actions)?;
        crate::handler::validate(&hook.handlers)?;
    }
    // And the rule table, which used to be validated only by the runner that
    // happened to evaluate it (CLOUD-48). That was defensible while the tree
    // engine was the only runner; `batten hook` is now a second one, and a
    // malformed `mediated_call` row validated only by `check` is a policy row
    // that loads, matches nothing at the mediation channel, and reads as
    // coverage. `run_rule` still calls `Rule::validate` as defence in depth.
    crate::rules::validate_in(&config.rules, text, source)?;
    crate::outputs::validate(&config.exec_patterns)?;
    // And the waiver table, where the stakes are inverted from every other row
    // here: a malformed rule fails to gate, but a malformed *waiver* is a hatch
    // whose expiry nobody could read. Refusing at load is what makes "every
    // waiver carries an expiry" true of the resolved config rather than aspirational.
    crate::waiver::validate(&config.waivers)?;
    crate::facts::validate(&config.facts)?;
    // The cross-table half (CLOUD-859), which needs both lists and so cannot live
    // in either one's own validator: a `named` receipt row over an agent-sourced
    // check is a gate no record can satisfy.
    crate::facts::validate_keying(&config.facts, &config.rules)?;
    crate::mint::validate(&config.mints)?;
    // AFTER the pattern table is validated, because a recorder's `section` names
    // a pattern id and the refusal for a missing one is only honest once the ids
    // are known to be well-formed themselves.
    crate::recorder::validate(
        &config.recorders,
        &config.programs,
        &config
            .patterns
            .iter()
            .map(|pattern| pattern.id.clone())
            .collect(),
    )?;
    // `[budget]` is a table rather than a list, so the census below (which scans
    // `Vec<T>` fields) does not reach it — but the failure it guards against is
    // the same one: a table that parses and gates nothing. A `[budget]` header
    // with no `[budget.instructions]` under it is refused here (CLOUD-50).
    crate::budget::validate(config.budget.as_ref())?;
    // Validated at parse, like `[[verb]]` and `[[marker]]`: CLOUD-242's lesson
    // is that a table nothing validates is coverage that means nothing.
    if let Some(ci) = &config.ci {
        ci.validate()?;
    }
    if let Some(defects) = &config.defects {
        defects.validate()?;
    }
    // Same reason, sharpened by what this table's values ARE: two floors, each
    // asserting it equals a measured worst lap times a stated factor. That
    // arithmetic is checkable and nothing else checks it, so a floor that
    // disagrees with its own recorded basis would otherwise reach the disk
    // decision looking exactly like a measured one (CLOUD-1030).
    if let Some(prune) = &config.prune {
        prune.validate()?;
    }
    // Same reason, plus one specific to this table: every one of its values is a
    // regular expression, and an uncompilable pattern is a rule that silently
    // matches nothing. Refused here, where the error names the key, rather than
    // at the gate, where it would look like a clean commit.
    if let Some(attribution) = &config.attribution {
        attribution.validate()?;
    }
    // Same reason, and the same specific one: `subject_pattern` is a regular
    // expression, so an uncompilable value is a convention that matches nothing
    // and passes every commit silently.
    if let Some(commit) = &config.commit {
        commit.validate()?;
    }
    // `[transcript]` is a table too, so the census does not reach it either; the
    // guarded failure is a `path` key present and blank, which would resolve to
    // the repository root and read as an unparseable transcript (CLOUD-95).
    crate::transcript::validate(config.transcript.as_ref())?;
    // A pin that can never match, a name that owns a cache path twice, an empty
    // required field: each is refused here rather than at fetch time, where the
    // failure would blame the artifact for a typo in this file.
    crate::provision::validate(&config.provisions)?;
    Ok(config)
}

/// The version of the running binary, as `Cargo.toml` declares it.
///
/// Read from the compiled-in package version rather than re-typed, so the gate
/// compares against the build that is actually running.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Refuse a config this build is too old to honour (CLOUD-33).
///
/// `min_batten_version` is the config author's statement of the oldest binary
/// that understands the file. A binary below it cannot honour the policy the
/// file describes — and a gate that runs anyway is worse than one that refuses,
/// because it reports green over rules it silently did not understand.
///
/// This is [`UsageError`] (→ exit `1`), the same class as an unreadable or
/// unsupported-version config: bad *input* for this binary, never a
/// [`crate::ExitCode::Violation`]. A violation is a verdict about the
/// repository; refusing to run is a statement about the invocation, and
/// conflating them would have a harness read "this binary is too old" as
/// "policy denied this call" (§7).
///
/// Equal-or-newer runs. An unparseable version on either side is refused rather
/// than skipped, because "cannot compare" is not "compatible".
fn check_min_version(config: &Config, source: &str) -> Result<()> {
    let Some(required) = config.min_batten_version.as_deref() else {
        return Ok(()); // The file does not speak to a minimum: nothing to gate.
    };
    let required = semver::Version::parse(required).map_err(|err| {
        UsageError::raise(format!(
            "invalid min_batten_version {required:?} in {source}: {err}"
        ))
    })?;
    let running = semver::Version::parse(VERSION)
        .map_err(|err| UsageError::raise(format!("invalid build version {VERSION:?}: {err}")))?;
    if running < required {
        return Err(UsageError::raise(format!(
            "{source} requires batten {required} or newer; this build is {VERSION}"
        )));
    }
    Ok(())
}

/// The JSON Schema for `batten.toml`, derived from [`Config`].
///
/// Derived, never hand-authored (CLOUD-33, `DoR` §1): the schema is generated
/// from the very types `parse` deserializes into, so it cannot describe a
/// config this binary would refuse — nor miss a key it accepts.
///
/// Emitted as byte-stable pretty JSON (§6): `schemars` orders properties
/// deterministically, so identical input yields identical bytes and the drift
/// gate never fails at random.
///
/// # Errors
///
/// Returns an error only if serialization itself fails, which for this
/// data-only tree does not occur in practice.
pub fn schema() -> Result<String> {
    Ok(serde_json::to_string_pretty(&schemars::schema_for!(
        Config
    ))?)
}

impl Config {
    /// A config that declares no policy at all.
    ///
    /// Deliberately not a [`Default`] impl. `version` has exactly one accepted
    /// value ([`SUPPORTED_VERSION`]), so a derived default would produce a
    /// `Config` carrying `0` that no loader would accept — a value that looks
    /// like a config and is not one. Written as a literal rather than parsed from
    /// a string constant so it needs no fallible path and no `expect`, and so
    /// that a field added to [`Config`] fails to compile here until someone
    /// decides what "declares nothing" means for it.
    ///
    /// Used where an **absent or unreadable** authority still has to be compared
    /// against a trusted one (CLOUD-243): granting nothing is exactly what an
    /// authority that cannot be read grants, so this is the honest comparand —
    /// every key the trusted side declares then reports as removed.
    #[must_use]
    pub fn declaring_nothing() -> Self {
        Config {
            version: SUPPORTED_VERSION,
            min_batten_version: None,
            strictness: None,
            fail_on_warning: None,
            rules: Vec::new(),
            patterns: Vec::new(),
            verdicts: Vec::new(),
            scope: Vec::new(),
            protected: Vec::new(),
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
            capture: None,
            exec_patterns: Vec::new(),
            waivers: Vec::new(),
            // An authority that declares no budget grants no exemption from one
            // either — there is simply no threshold, which is what `None` says.
            budget: None,
            must_land_on: None,
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
            defects: None,
            provisions: Vec::new(),
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
            // An authority that cannot be read grants no permission to answer
            // from a pin either. The default is the strict one, and an absent
            // authority must not be the way to reach the lenient one.
            trust: None,
        }
    }
}

/// Whether the committed authority was there to read (CLOUD-70).
///
/// A named type rather than a `bool` because it travels: [`crate::resolve`]
/// carries it into attribution, where "the authority was absent" is what makes
/// every emitted key read `default` rather than `repo-config`. A bare boolean at
/// that call site would say nothing about which way `true` points.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Authority {
    /// A `batten.toml` was found and parsed.
    Present,
    /// No `batten.toml` exists, so [`defaults`] is the whole configuration.
    Absent,
}

/// The one stderr line an unconfigured run emits (§6: stderr is messaging).
///
/// It names the consequence and the fix, not just the fact — the shape
/// [`crate::transcript::ABSENT_NOTICE`] uses. "There is no `batten.toml`" is a
/// filesystem observation; "the built-in defaults are what just gated your tree,
/// and here is how to state your own" is what a reader has to act on.
///
/// Exactly one line, and only on stderr: stdout stays the findings channel and
/// must be byte-identical to a run whose committed authority states the same
/// effective config, which is also why no `-J` field pairs with this.
///
/// The file name is written out rather than interpolated from [`CONFIG_FILE`],
/// because a `const` cannot format one; `tests::the_defaults_note_names_the_config_file`
/// is what keeps the two from drifting.
pub const DEFAULTS_NOTE: &str =
    "no batten.toml; running on built-in defaults — `batten init` writes one to edit";

/// The compiled-in default layer: §8's layer 0, as a whole [`Config`].
///
/// Stated **once**, and only where the existing layer 0 does not already state
/// it. `strictness` and `fail_on_warning` are deliberately left `None` here:
/// [`crate::resolve`] supplies their layer-0 values and attributes them to
/// [`crate::resolve::Source::Default`], so restating them here would be a second
/// defaults table that could disagree with the first.
///
/// What this *does* add is the default rule set. An unconfigured `check` that
/// evaluated nothing would exit `0` over every repository on earth — a pass that
/// means "no rule looked", which is precisely the false green this engine exists
/// to refuse. So the defaults ship one repo-agnostic gate (see [`default_rules`])
/// and the zero-config run answers on findings.
///
/// The defaults are the **whole** configuration or none of it. They are not
/// merged into a `batten.toml` that declares no rules: an authority that states
/// its policy has stated it, and folding a rule in underneath would widen a
/// committed policy from the engine — the direction §8 never permits.
///
/// Built from [`Config::declaring_nothing`] rather than beside it, so the delta
/// is the only thing written here and a field added to [`Config`] still fails to
/// compile at the one site that has to decide what it means.
#[must_use]
pub fn defaults() -> Config {
    Config {
        rules: default_rules(),
        ..Config::declaring_nothing()
    }
}

/// The rules a repository gets when it has declared none.
///
/// **One rule, and it has to earn its place twice over**: it must be meaningful
/// in *every* repository (non-negotiable rule 1 — no consumer-specific
/// identifier can appear here), and its finding must be one no project would
/// defend. An unresolved merge conflict is the one shape that qualifies: it is
/// syntactically broken in every language, nobody commits one on purpose, and
/// the pattern is a literal git itself writes.
///
/// A function rather than a `const` because [`Rule`] carries owned `String`s.
/// Written as a literal rather than parsed from an embedded TOML blob: this path
/// cannot fail, so it needs no `expect` (which the workspace lints forbid), and
/// a column added to [`Rule`] fails to compile here rather than being silently
/// absent. [`tests::the_default_rules_pass_the_validator`] holds it to the same
/// validator every committed rule passes.
fn default_rules() -> Vec<Rule> {
    vec![Rule {
        id: "no-conflict-markers".to_owned(),
        kind: crate::rules::RuleKind::Forbid,
        // Every path, unlike the starter's `**/*/*`. That narrower glob exists
        // to keep the rule off the `batten.toml` that declares it — a `forbid`
        // pattern is a literal, so it appears in its own config — and this layer
        // has no config file to trip over.
        glob: Some("**/*".to_owned()),
        severity: Some(crate::severity::RuleSeverity::Deny),
        scope: crate::rules::RuleScope::Tree,
        pattern: Some("<<<<<<< ".to_owned()),
        regex: None,
        exclude: None,
        content: None,
        tool: None,
        measures: None,
        counts: None,
        max: None,
        resolves: Vec::new(),
        when_absent: None,
        when_present: None,
        when_value: None,
        key_from: None,
        key_shape: None,
        max_age: None,
        requires_field: None,
        contains: None,
        require_via: None,
        requires_key: None,
        reason: None,
        policy_url: None,
        bypass_env: None,
        check: None,
        fix: None,
        produces: None,
        exclude_paths: Vec::new(),
        git: Vec::new(),
        refs: Vec::new(),
        ranges: Vec::new(),
        commits: Vec::new(),
        staged: Vec::new(),
        state: Vec::new(),
        landing: Vec::new(),
        symbols: false,
        delta_sources: Vec::new(),
        run: None,
        verbatim: None,
        identity_key: None,
        direction: None,
        base: None,
        retires_with: None,
        conserves: None,
        admits_with: None,
        format: None,
        node: None,
        derives: None,
        reads: None,
        module: None,
        bundle: None,
        preset: None,
        documents: Vec::new(),
        sources: Vec::new(),
        lines: Vec::new(),
        line_sources: Vec::new(),
        invocations: Vec::new(),
        invocation_sources: Vec::new(),
        uses: Vec::new(),
        use_sources: Vec::new(),
        external: Vec::new(),
        predicate_severity: None,
        no_fix_reason: None,
        checks: None,
        key: None,
        trigger: None,
        verdict: None,
        filters: None,
        substitutes: None,
        criteria: None,
        tier: None,
    }]
}

/// Load and validate the `batten.toml` at `path`.
///
/// # Errors
///
/// Returns a [`UsageError`] (→ exit `1`) when the file is missing, malformed,
/// carries an unknown key, or declares an unsupported version. A non-`NotFound`
/// I/O failure propagates as an internal error (→ exit `3`).
pub fn load(path: &Path) -> Result<Config> {
    parse(&read(path)?, &path.display().to_string())
}

/// Load the committed authority at `path`, or the compiled-in [`defaults`] when
/// there is none (CLOUD-70).
///
/// The **only** difference from [`load`] is what a missing file means, and the
/// asymmetry is the whole point: absence selects the default layer, invalidity
/// never does. A present file that does not parse, carries an unknown key,
/// declares an unsupported `version`, or demands a newer binary is refused
/// exactly as [`load`] refuses it, and a non-`NotFound` I/O failure still
/// propagates as an internal error (→ exit `3`) — "I could not look" must never
/// resolve to "there was nothing to see".
///
/// [`load`] keeps the strict reading for the callers whose question is different:
/// `doctor` reports a missing authority as a finding, and `trust` compares an
/// unreadable one against [`Config::declaring_nothing`] because deleting the file
/// is the maximal weakening (CLOUD-243) — both would be silently answered wrong
/// by a loader that handed them defaults.
///
/// # Errors
///
/// As [`load`], minus the missing-file case.
pub fn load_authority(path: &Path) -> Result<(Config, Authority)> {
    match fs::read_to_string(path) {
        Ok(text) => Ok((
            parse(&text, &path.display().to_string())?,
            Authority::Present,
        )),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok((defaults(), Authority::Absent)),
        Err(err) => Err(err.into()),
    }
}

/// Load an *override* layer, without the [`Config::min_batten_version`] gate.
///
/// See [`parse_override`] for why the override layer is ungated.
///
/// # Errors
///
/// As [`load`], minus the version gate.
pub fn load_override(path: &Path) -> Result<OverrideConfig> {
    parse_override(&read(path)?, &path.display().to_string())
}

/// Read a config file, mapping a missing file to a [`UsageError`] and any other
/// I/O failure to an internal error (→ exit `3`).
fn read(path: &Path) -> Result<String> {
    match fs::read_to_string(path) {
        Ok(text) => Ok(text),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Err(UsageError::raise(format!(
            "no config found at {}",
            path.display()
        ))),
        Err(err) => Err(err.into()),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {

    use super::*;
    use crate::error::UsageError;

    /// Tables whose entries are proven well formed at load, and the call in
    /// [`parse_ungated`] that does it. Deleting a call fails the test below.
    const VALIDATED_AT_LOAD: &[(&str, &str)] = &[
        ("verbs", "crate::verbs::validate("),
        ("patterns", "crate::pattern::validate("),
        ("verdicts", "crate::verdict::validate("),
        ("redirects", "crate::redirect::validate("),
        ("markers", "crate::markers::validate("),
        // The LOCATED form (CLOUD-773): the loaders hold the config text, so a
        // composition refusal points at a line rather than only at a rule id.
        // `rules::validate_in` runs `rules::validate` first — one implementation,
        // an optional locator — so naming it here is naming the whole check.
        ("rules", "crate::rules::validate_in("),
        ("exec_patterns", "crate::outputs::validate("),
        ("provisions", "crate::provision::validate("),
        ("waivers", "crate::waiver::validate("),
        ("facts", "crate::facts::validate("),
        ("mints", "crate::mint::validate("),
        ("recorders", "crate::recorder::validate("),
    ];

    /// Tables proven well formed somewhere else, each with the reason. Listing
    /// an exemption is the point: a reader sees the justification rather than
    /// an absence, which is what an orphaned validator looks like.
    const VALIDATED_BY_ITS_RUNNER: &[(&str, &str)] = &[];

    #[test]
    fn every_typed_config_table_has_a_validation_call_site() {
        // The class behind CLOUD-242 and CLOUD-253: a validator whose only
        // caller is its own tests refuses nothing, while a doc comment, a PR
        // body and a passing test all say it does. Both tables shipped in one
        // commit; the first fix wired up one of them, and nothing here noticed
        // the other for a day. One reviewed list per destiny plus this
        // completeness check is the idiom `effect.rs` and `RuleKind::ALL`
        // already use — a new table must be classified or this fails.
        //
        // A `Vec<String>` field is a glob list with no typed entry to validate,
        // so it is exempt by its element type rather than by a third hand-kept
        // list that could itself go stale.
        let source = include_str!("config.rs");
        let struct_body = {
            let start = source
                .find("pub struct Config {")
                .expect("Config is declared here");
            let rest = &source[start..];
            &rest[..rest.find("\n}").expect("the struct closes")]
        };
        let parse_body = {
            let start = source
                .find("fn parse_ungated")
                .expect("the shared parse body is declared here");
            let rest = &source[start..];
            &rest[..rest.find("\n}").expect("the function closes")]
        };

        let mut seen = Vec::new();
        for line in struct_body.lines() {
            let Some(rest) = line.trim().strip_prefix("pub ") else {
                continue;
            };
            let Some((field, element)) = rest.split_once(": Vec<") else {
                continue;
            };
            if element.starts_with("String") {
                continue;
            }
            seen.push(field);

            let at_load = VALIDATED_AT_LOAD.iter().find(|(name, _)| *name == field);
            let by_runner = VALIDATED_BY_ITS_RUNNER
                .iter()
                .any(|(name, _)| *name == field);
            assert!(
                at_load.is_some() != by_runner,
                "config table `{field}` is in neither list (or both). Say where its entries \
                 are proven well formed: at load, or by the runner that evaluates them. A \
                 table nothing validates is a refusal that cannot fire (CLOUD-253)."
            );
            if let Some((_, call)) = at_load {
                assert!(
                    parse_body.contains(call),
                    "config table `{field}` is listed as validated at load, but \
                     `parse_ungated` does not call `{call}`."
                );
            }
        }

        assert!(
            !seen.is_empty(),
            "the struct scan must actually find tables"
        );
        for (name, _) in VALIDATED_AT_LOAD.iter().chain(VALIDATED_BY_ITS_RUNNER) {
            assert!(
                seen.contains(name),
                "`{name}` is listed but is no longer a Config table; drop the stale entry."
            );
        }
    }

    fn is_usage_error(err: &anyhow::Error) -> bool {
        err.downcast_ref::<UsageError>().is_some()
    }

    #[test]
    fn minimal_config_parses() {
        let config = parse("version = 1\n", "test").unwrap();
        assert_eq!(config.version, 1);
        assert_eq!(config.min_batten_version, None);
    }

    #[test]
    fn optional_fields_round_trip() {
        let config = parse("version = 1\nmin_batten_version = \"0.0.0\"\n", "test").unwrap();
        assert_eq!(config.min_batten_version.as_deref(), Some("0.0.0"));
    }

    #[test]
    fn strictness_orders_weakest_first() {
        // The raise-only clamp is `candidate >= current` over this ordering, so
        // an accidental reordering of the variants would invert "tighten" into
        // "weaken" without any other test noticing.
        assert!(Strictness::Permissive < Strictness::Standard);
        assert!(Strictness::Standard < Strictness::Strict);
        assert_eq!(Strictness::default(), Strictness::Standard);
    }

    #[test]
    fn strictness_round_trips_through_toml() {
        let config = parse("version = 1\nstrictness = \"strict\"\n", "test").unwrap();
        assert_eq!(config.strictness, Some(Strictness::Strict));
    }

    #[test]
    fn unknown_strictness_value_is_a_usage_error() {
        let err = parse("version = 1\nstrictness = \"whatever\"\n", "test").unwrap_err();
        assert!(is_usage_error(&err));
    }

    #[test]
    fn fail_on_warning_round_trips_through_toml() {
        // The config surface of the one promotion setting (CLOUD-49). Absent is
        // distinct from `false`: only the former lets a later layer claim the key.
        let config = parse("version = 1\nfail_on_warning = true\n", "test").unwrap();
        assert_eq!(config.fail_on_warning, Some(true));
        let off = parse("version = 1\nfail_on_warning = false\n", "test").unwrap();
        assert_eq!(off.fail_on_warning, Some(false));
        assert_eq!(
            parse("version = 1\n", "test").unwrap().fail_on_warning,
            None
        );
    }

    #[test]
    fn a_non_boolean_fail_on_warning_is_a_usage_error() {
        // The key's vocabulary is TOML's own boolean literals; a string that
        // merely looks like one is bad input, not a value to coerce. This is the
        // same typing discipline `version = "1"` is held to above.
        for value in ["\"true\"", "1", "\"yes\""] {
            let err =
                parse(&format!("version = 1\nfail_on_warning = {value}\n"), "test").unwrap_err();
            assert!(
                is_usage_error(&err),
                "fail_on_warning = {value} must be refused"
            );
        }
    }

    #[test]
    fn unknown_key_is_a_usage_error() {
        let err = parse("version = 1\nbogus = true\n", "test").unwrap_err();
        assert!(is_usage_error(&err), "unknown key must be a usage error");
    }

    #[test]
    fn a_retired_key_is_tolerated_in_a_base_ref_and_refused_in_the_working_tree() {
        // The asymmetry IS the mechanism (CLOUD-780). A ref carries the config
        // the engine of its day accepted; the working tree is judged by this
        // one. Collapsing the two in either direction breaks something: refusing
        // the base makes retiring a key unlandable, and tolerating the working
        // tree makes a retired key silently inert in the file an author edits.
        let text = "version = 1\n[worktree]\npileup_threshold = 3\n";

        let base = parse_base(text, "origin/main:batten.toml")
            .expect("a base carrying a retired key is still comparable");
        assert_eq!(base.version, SUPPORTED_VERSION);

        let err = parse(text, "batten.toml").unwrap_err();
        assert!(
            is_usage_error(&err),
            "the working tree gets no such tolerance"
        );
    }

    #[test]
    fn a_base_ref_gets_no_tolerance_for_a_key_that_was_never_ours() {
        // The census is what keeps this from being blanket leniency: only the
        // keys `RETIRED_KEYS` names are dropped, so a typo in a base ref is the
        // usage error it has always been.
        let err = parse_base("version = 1\nbogus = true\n", "origin/main:batten.toml").unwrap_err();
        assert!(is_usage_error(&err));
    }

    /// A table row for the window cases. The shipped `DEPRECATED_KEYS` is empty
    /// and should be — inventing a row so a test has something to find would put
    /// a key in the published schema no consumer should write — so the predicate
    /// takes its table as an argument and these supply one.
    fn window(expires: &'static str) -> Vec<Deprecation> {
        vec![Deprecation {
            key: "old_table",
            replacement: Some("new_table"),
            expires,
            issue: "CLOUD-360",
        }]
    }

    #[test]
    fn a_key_inside_its_window_parses_and_is_reported() {
        let table = window("2099-01-01");
        let (stripped, reported) = apply_window(
            "version = 1\n[old_table]\nvalue = 1\n",
            "batten.toml",
            &table,
            "2026-08-25",
        )
        .expect("an in-window key loads");
        assert_eq!(
            reported,
            vec![
                "old_table deprecated replacement=new_table expires=2099-01-01 (CLOUD-360)"
                    .to_owned()
            ],
            "the finding is pointer-only: key, replacement, expiry, owning row"
        );
        assert!(
            !reported.iter().any(|line| line.contains("value")),
            "a configured VALUE must never reach the diagnostic (rule 4)"
        );
        // And the stripped text is what the typed parse then accepts.
        parse(&stripped, "batten.toml").expect("the stripped config is valid");
    }

    #[test]
    fn a_key_past_its_expiry_is_refused_rather_than_reported() {
        let table = window("2026-01-01");
        let err = apply_window(
            "version = 1\n[old_table]\nvalue = 1\n",
            "batten.toml",
            &table,
            "2026-08-25",
        )
        .expect_err("an expired key is refused");
        assert!(
            is_usage_error(&err),
            "an expired key is exit 1, not a panic"
        );
        assert!(
            format!("{err}").contains("old_table expired"),
            "the refusal names the expired key: {err}"
        );
    }

    /// The boundary, stated rather than left to a reader: the window closes ON
    /// the expiry date, so `today == expires` is expired.
    #[test]
    fn the_window_closes_on_its_expiry_day_not_after_it() {
        let table = window("2026-08-25");
        assert!(
            matches!(
                deprecation_of(&table, "old_table", "2026-08-25"),
                Some(Standing::Expired { .. })
            ),
            "the expiry day is outside the window"
        );
        assert!(
            matches!(
                deprecation_of(&table, "old_table", "2026-08-24"),
                Some(Standing::Migrating { .. })
            ),
            "the day before it is inside"
        );
    }

    /// §7(c): the two refusals must stay TELLABLE APART. If a deprecated key and
    /// an unknown key produced the same diagnostic, the window would be
    /// invisible to the consumer it exists for.
    #[test]
    fn an_unknown_key_is_refused_differently_from_a_deprecated_one() {
        let table = window("2026-01-01");
        let expired = apply_window(
            "version = 1\n[old_table]\nvalue = 1\n",
            "batten.toml",
            &table,
            "2026-08-25",
        )
        .expect_err("expired");
        // A key the table never named is left for the typed parse, which refuses
        // it as unknown.
        let (passed, reported) = apply_window(
            "version = 1\n[never_ours]\nvalue = 1\n",
            "batten.toml",
            &table,
            "2026-08-25",
        )
        .expect("an unfamiliar key is not this predicate's to refuse");
        assert!(
            reported.is_empty(),
            "nothing to report about a key we never had"
        );
        let unknown = parse(&passed, "batten.toml").expect_err("unknown keys stay errors");

        let (expired, unknown) = (format!("{expired}"), format!("{unknown}"));
        assert!(
            expired.contains("expired"),
            "the expired diagnostic says so: {expired}"
        );
        assert!(
            !unknown.contains("expired"),
            "an unknown key must not borrow the deprecation vocabulary: {unknown}"
        );
        assert_ne!(expired, unknown, "the two refusals are distinguishable");
    }

    /// The two tables are one authority read at two stages. A key in both is a
    /// contradiction: it cannot be simultaneously still-accepted and already-gone.
    #[test]
    fn a_key_leaving_the_schema_unannounced_is_a_finding() {
        let released = schema_keys(
            r#"{"properties":{"version":{},"gone":{},"kept":{}}}"#,
            "released",
        )
        .expect("the released schema reads");
        let current =
            schema_keys(r#"{"properties":{"version":{},"kept":{}}}"#, "current").expect("current");

        // Nothing announces it: a finding.
        assert_eq!(
            removals_unannounced(&released, &current, &[], &[]),
            vec!["gone".to_owned()],
            "an empty table makes every removal a finding, never none"
        );

        // Mid-window announces it.
        let window = window("2099-01-01");
        let mut mid = window.clone();
        mid[0] = Deprecation {
            key: "gone",
            replacement: Some("kept"),
            expires: "2099-01-01",
            issue: "CLOUD-360",
        };
        assert!(
            removals_unannounced(&released, &current, &mid, &[]).is_empty(),
            "a key inside its window is announced"
        );

        // And so does the contracted stage, because the two tables are one
        // authority read at consecutive points of a key's life.
        assert!(
            removals_unannounced(&released, &current, &[], &[("gone", "CLOUD-360")]).is_empty(),
            "a retired key was announced when its window ran"
        );
    }

    #[test]
    fn a_key_that_is_merely_added_is_not_a_removal() {
        let released = schema_keys(r#"{"properties":{"version":{}}}"#, "released").expect("rel");
        let current =
            schema_keys(r#"{"properties":{"version":{},"brand_new":{}}}"#, "current").expect("cur");
        assert!(
            removals_unannounced(&released, &current, &[], &[]).is_empty(),
            "the grammar governs removals; adding a key needs no window"
        );
    }

    /// A schema this cannot read is COULD NOT LOOK, never "declared no keys" —
    /// the latter would report every key as removed, or, read the other way
    /// round, would wave a real removal through (CLOUD-251).
    #[test]
    fn an_unreadable_schema_is_refused_rather_than_read_as_empty() {
        assert!(is_usage_error(
            &schema_keys("not json at all", "released").expect_err("refused")
        ));
        assert!(is_usage_error(
            &schema_keys(r#"{"title":"no properties here"}"#, "released").expect_err("refused")
        ));
    }

    #[test]
    fn no_key_is_both_deprecated_and_retired() {
        for row in DEPRECATED_KEYS {
            assert!(
                !RETIRED_KEYS.iter().any(|(key, _)| *key == row.key),
                "{} is in both tables; migrating and retired are consecutive \
                 stages, never concurrent ones",
                row.key
            );
        }
    }

    /// A malformed expiry would sort as some string and silently decide a window,
    /// so the shape is refused at the table rather than at the comparison.
    #[test]
    fn every_declared_expiry_is_a_date_and_names_its_row() {
        for row in DEPRECATED_KEYS {
            let parts: Vec<&str> = row.expires.split('-').collect();
            assert!(
                parts.len() == 3
                    && parts[0].len() == 4
                    && parts[1].len() == 2
                    && parts[2].len() == 2
                    && row.expires.chars().all(|c| c.is_ascii_digit() || c == '-'),
                "{}: expiry {:?} is not YYYY-MM-DD, so the lexical comparison that \
                 decides its window is not a chronological one",
                row.key,
                row.expires
            );
            assert!(
                row.issue.starts_with("CLOUD-"),
                "{}: a migration names the row that owns it",
                row.key
            );
        }
    }

    #[test]
    fn every_retired_key_names_the_issue_that_retired_it() {
        // A row nobody can date is a row nobody can drop, and dropping them once
        // no supported base carries the key is how this list stays short.
        for (key, why) in RETIRED_KEYS {
            assert!(!key.is_empty(), "a retired key needs a name");
            assert!(
                why.contains("CLOUD-"),
                "{key}: a retirement names the issue that decided it, got {why:?}"
            );
        }
    }

    #[test]
    fn unsupported_version_is_a_usage_error() {
        let err = parse("version = 2\n", "test").unwrap_err();
        assert!(is_usage_error(&err));
        assert!(err.to_string().contains("unsupported config version 2"));
    }

    #[test]
    fn missing_version_is_a_usage_error() {
        let err = parse("min_batten_version = \"0.0.0\"\n", "test").unwrap_err();
        assert!(is_usage_error(&err));
    }

    #[test]
    fn malformed_toml_is_a_usage_error() {
        // A syntactic parse failure is bad input (→ exit 1), not an internal error.
        let err = parse("version = = 1\n", "test").unwrap_err();
        assert!(is_usage_error(&err), "malformed TOML must be a usage error");
    }

    #[test]
    fn wrong_value_type_is_a_usage_error() {
        // `version` is a u32; a string must be refused rather than coerced. This
        // pins the parser's typing behaviour — the surface a `toml` bump is most
        // likely to shift silently (see auto-bot-land.yml).
        let err = parse("version = \"1\"\n", "test").unwrap_err();
        assert!(is_usage_error(&err), "type mismatch must be a usage error");
    }

    #[test]
    fn duplicate_key_is_a_usage_error() {
        // TOML forbids a key defined twice; ensure that stays a hard error and is
        // not last-wins-silently coerced by a future parser.
        let err = parse("version = 1\nversion = 1\n", "test").unwrap_err();
        assert!(is_usage_error(&err), "duplicate key must be a usage error");
    }

    #[test]
    fn error_message_attributes_the_source() {
        // Parse errors must name their source so a consumer can locate the file.
        let err = parse("version = = 1\n", "some/path/batten.toml").unwrap_err();
        assert!(
            err.to_string().contains("some/path/batten.toml"),
            "parse error must attribute its source, got: {err}"
        );
    }

    // --- CLOUD-341: the seeded property, beside the loader it measures --------
    //
    // The four cases above pin the behaviours somebody thought of. A consumer's
    // `batten.toml` can use TOML constructs none of them exercises, so a parser
    // semantics shift there still escapes a green auto-land — the `toml` crate's
    // `+spec-1.1.0` line is the live example. This sweep is the half that does
    // not depend on having thought of the construct.
    //
    // **Deterministic and bounded, which is what licenses it on the landing
    // path.** The generator is a fixed xorshift over a fixed fragment pool, so
    // the corpus is a pure function of the seed range and a failure names a seed
    // a reader can re-run. The UNBOUNDED half is `fuzz/fuzz_targets/config_parse.rs`,
    // driven by libFuzzer on a schedule (`mise run fuzz`), and it shares this
    // property's body through `fuzz/properties.rs` rather than restating it.

    /// The seed range the sweep covers.
    ///
    /// A count rather than a duration: a wall-clock budget would make the corpus
    /// depend on how loaded the machine is, which is the non-determinism this
    /// tier exists not to have.
    const SEEDS: u64 = 512;

    /// A fixed xorshift64\*, so the corpus is a pure function of the seed.
    ///
    /// Hand-rolled rather than a generator crate: this needs a reproducible
    /// stream and nothing else, and a dependency whose algorithm may change
    /// between versions would make an old seed stop naming its own input.
    struct Seeded(u64);

    impl Seeded {
        fn new(seed: u64) -> Self {
            // Never zero: xorshift has a fixed point there and would emit one
            // document forever, which is a sweep that looks busy and is not.
            Seeded(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1)
        }

        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }

        fn pick<'a, T>(&mut self, from: &'a [T]) -> &'a T {
            let index = usize::try_from(self.next() % from.len() as u64).unwrap_or(0);
            &from[index]
        }
    }

    /// TOML fragments, deliberately spanning constructs the hand-written cases
    /// never reach: dotted keys, inline tables, arrays of tables, literal and
    /// multi-line strings, integer spellings, datetimes, unicode keys, a BOM,
    /// CRLF, and outright junk.
    ///
    /// Mixed valid and invalid on purpose. A pool of only-valid fragments proves
    /// the accepting direction and says nothing about the refusing one, and a
    /// pool of only-invalid ones can never reach the round-trip clause at all.
    const FRAGMENTS: &[&str] = &[
        "version = 1\n",
        "version = 1_0\n",
        "version = 0x1\n",
        "version = +1\n",
        "version = \"1\"\n",
        "version = 1.0\n",
        "min_batten_version = \"0.0.1\"\n",
        "min_batten_version = '0.0.1'\n",
        "min_batten_version = \"\"\"0.0.1\"\"\"\n",
        "min_batten_version = 1979-05-27\n",
        "strictness = \"strict\"\n",
        "strictness = \"STRICT\"\n",
        "fail_on_warning = true\n",
        "fail_on_warning = \"true\"\n",
        "protected = [\"a/**\"]\n",
        "protected = [\"a/**\", ]\n",
        "protected = []\n",
        "protected = \"a/**\"\n",
        "scope = [\"!vendor/**\"]\n",
        "unlanded = [\"wip/**\"]\n",
        "[epoch]\ntracked = [\"batten.toml\"]\n",
        "epoch = { tracked = [\"batten.toml\"] }\n",
        "epoch.tracked = [\"batten.toml\"]\n",
        "[[rule]]\nid = \"no-todo\"\nkind = \"forbid\"\nglob = \"**/*.rs\"\npattern = \"TODO\"\nseverity = \"deny\"\n",
        "[[rule]]\nid = \"no-todo\"\nkind = \"forbid\"\n",
        "[[rule]]\n",
        "must_land_on = \"origin/main\"\n",
        "# a comment that decides nothing\n",
        "\n",
        "\r\n",
        "\u{feff}",
        "\"ünïcode\" = 1\n",
        "not_a_key = true\n",
        "= 1\n",
        "version = = 1\n",
        "[unclosed\n",
        "\"\"\"\n",
    ];

    /// One seeded document.
    fn document(seed: u64) -> String {
        let mut rng = Seeded::new(seed);
        let lines = 1 + rng.next() % 6;
        let mut text = String::new();
        for _ in 0..lines {
            text.push_str(rng.pick(FRAGMENTS));
        }
        text
    }

    /// The round-trip clause, over one accepted config.
    ///
    /// Separated so the discriminator below can state that this — and only this
    /// — is what a silently-wrong value fails.
    fn round_trips(config: &Config) -> bool {
        let Ok(emitted) = emit(config) else {
            return false;
        };
        parse(&emitted, "round-trip").is_ok_and(|reread| &reread == config)
    }

    #[test]
    fn arbitrary_toml_reaches_one_of_exactly_two_outcomes() {
        // §2: a valid `Config`, or a usage error — never a panic (which would
        // abort this test rather than be caught, and that IS the assertion), and
        // never an internal error, which would be exit `3` for a malformed file
        // that is bad input rather than a broken engine.
        let mut accepted = 0_usize;
        let mut refused = 0_usize;
        for seed in 0..SEEDS {
            let text = document(seed);
            match parse(&text, "seeded") {
                Ok(config) => {
                    accepted += 1;
                    assert!(
                        round_trips(&config),
                        "seed {seed}: the loader accepted a value it does not read back"
                    );
                }
                Err(err) => {
                    refused += 1;
                    assert!(
                        is_usage_error(&err),
                        "seed {seed}: a rejected config is exit 1, never a policy verdict or an \
                         internal error"
                    );
                }
            }
        }
        // Both directions, or the sweep proves nothing: a corpus every input of
        // which is refused never reaches the round-trip clause, and one every
        // input of which is accepted never exercises the refusal.
        assert!(accepted > 0, "no seeded document was accepted");
        assert!(refused > 0, "no seeded document was refused");
    }

    #[test]
    fn the_seeded_sweep_is_deterministic_across_invocations() {
        // What licenses this on the landing path at all. A property that drew a
        // different corpus per run would fail on somebody else's machine for a
        // reason they cannot reproduce, which is the flake this tier is split to
        // avoid — the unbounded search is where nondeterminism is allowed, and
        // it gates nothing.
        let sweep = || -> Vec<(String, bool)> {
            (0..SEEDS)
                .map(|seed| {
                    let text = document(seed);
                    let verdict = parse(&text, "seeded").is_ok();
                    (text, verdict)
                })
                .collect()
        };
        assert_eq!(sweep(), sweep(), "the seeded corpus is not reproducible");
    }

    #[test]
    fn the_round_trip_clause_is_what_catches_a_silently_wrong_value() {
        // CLOUD-418, at its sharpest: the property IS the deliverable here, so
        // it has to be shown able to fail. This stands in for a mutated loader
        // that ACCEPTS a wrong value — the residual a flat auto-land cannot see,
        // and the one a `toml` bump is most likely to introduce by coercing a
        // value, dropping a table, or last-wins-merging a duplicate.
        let honest = parse("version = 1\nstrictness = \"strict\"\n", "test").unwrap();
        assert!(round_trips(&honest), "an honest parse round-trips");

        // The same input read by a loader that quietly coerced one field. Note
        // what does NOT catch it: it is a valid `Config`, so the two-outcome
        // clause is satisfied, it never panics, and every other property in
        // `fuzz/properties.rs` — determinism, the clamp's totality, sortedness —
        // holds over it exactly as it does over the honest one.
        let mut coerced = honest.clone();
        coerced.strictness = Some(Strictness::Permissive);
        assert!(
            parse(&emit(&coerced).unwrap(), "test").is_ok(),
            "the wrong value is still a valid config, which is what makes it silent"
        );
        assert_ne!(
            coerced, honest,
            "the mutation must be observable at all, or this case proves nothing"
        );

        // And what does catch it: reading the accepted value back and comparing.
        // `round_trips` is a fixed point of an honest loader, so the way to fail
        // it is for the value the loader reports to differ from the value its
        // own emitted bytes parse to.
        let reread = parse(&emit(&honest).unwrap(), "test").unwrap();
        assert_ne!(
            reread, coerced,
            "the round-trip comparison cannot distinguish the coerced value from the honest one"
        );
    }

    #[test]
    fn missing_file_is_a_usage_error() {
        // `load` keeps the strict reading. CLOUD-70 defaults the *authority*
        // loader, not this one: `doctor` reports a missing config as a finding
        // and `trust` compares an unreadable one against `declaring_nothing`,
        // and a `load` that answered with defaults would silently break both.
        let err = load(Path::new("does/not/exist/batten.toml")).unwrap_err();
        assert!(is_usage_error(&err));
    }

    #[test]
    fn a_missing_authority_loads_the_defaults() {
        // CLOUD-70's whole change, at the loader: absence selects layer 0.
        let (config, present) = load_authority(Path::new("does/not/exist/batten.toml")).unwrap();
        assert_eq!(present, Authority::Absent);
        assert_eq!(config, defaults());
        assert_eq!(config.version, SUPPORTED_VERSION);
    }

    #[test]
    fn a_present_authority_is_parsed_and_reported_present() {
        let dir = std::env::temp_dir().join("batten-config-authority-present");
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join(CONFIG_FILE);
        fs::write(&path, "version = 1\nstrictness = \"strict\"\n").unwrap();
        let (config, present) = load_authority(&path).unwrap();
        assert_eq!(present, Authority::Present);
        assert_eq!(config.strictness, Some(Strictness::Strict));
    }

    #[test]
    fn a_present_but_invalid_authority_is_still_a_usage_error() {
        // The asymmetry CLOUD-70 rests on: absence selects the defaults,
        // invalidity never does. Each of these three would be a *silent policy
        // downgrade* if it defaulted — the operator wrote a file, and answering
        // with the engine's own rules would report green over rules they wrote.
        let dir = std::env::temp_dir().join("batten-config-authority-invalid");
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join(CONFIG_FILE);
        for text in [
            "version = = 1\n",                                 // malformed
            "version = 1\nbogus = 1\n",                        // unknown key
            "version = 2\n",                                   // unsupported version
            "version = 1\nmin_batten_version = \"999.0.0\"\n", // too old a build
        ] {
            fs::write(&path, text).unwrap();
            let err = load_authority(&path).unwrap_err();
            assert!(
                is_usage_error(&err),
                "{text:?} must be refused, not defaulted"
            );
        }
    }

    #[test]
    fn the_defaults_declare_a_live_rule() {
        // An unconfigured `check` that evaluated nothing would exit 0 over every
        // repository on earth — the "did it even run" pass this engine exists to
        // refuse. The obligation is the same one `init::tests` puts on the
        // starter, over the other artifact a fresh consumer can arrive through.
        let config = defaults();
        assert!(
            !config.rules.is_empty(),
            "the default layer ships no rule: a zero-config `check` would gate nothing"
        );
    }

    #[test]
    fn the_default_rules_pass_the_validator() {
        // Held to the validator every committed rule passes, so a hand-written
        // literal cannot ship a shape the loader would refuse from a file.
        crate::rules::validate(&defaults().rules).expect("the default rules validate");
    }

    #[test]
    fn the_defaults_are_evaluable_by_the_read_only_surface() {
        // `check` refuses a spawning kind outright, so a default rule carrying
        // one would make the zero-config run exit 1 — the one exit CLOUD-70 says
        // a missing authority must never produce.
        for rule in &defaults().rules {
            assert!(
                !rule.kind.carries_ambient_authority(),
                "default rule {} spawns, so `batten check` would refuse the whole run",
                rule.id
            );
            assert_eq!(
                rule.scope,
                crate::rules::RuleScope::Tree,
                "a default rule no tree scan evaluates would gate nothing"
            );
        }
    }

    #[test]
    fn the_defaults_leave_the_layer_zero_keys_unset() {
        // `strictness` and `fail_on_warning` have their layer-0 values in
        // `resolve`, and stating them again here would be a second defaults
        // table — two answers to one question, free to drift.
        let config = defaults();
        assert_eq!(config.strictness, None);
        assert_eq!(config.fail_on_warning, None);
    }

    #[test]
    fn the_defaults_carry_no_consumer_identifier() {
        // Non-negotiable rule 1, at the one place a compiled-in policy could
        // break it: every default rule must be meaningful in any repository, so
        // it names no path a particular project happens to have.
        for rule in &defaults().rules {
            assert_eq!(rule.glob.as_deref(), Some("**/*"));
        }
    }

    #[test]
    fn the_defaults_note_names_the_config_file() {
        // The note spells the file name out because a `const` cannot format one;
        // this is what keeps the literal and `CONFIG_FILE` from drifting.
        assert!(DEFAULTS_NOTE.contains(CONFIG_FILE));
        assert!(
            !DEFAULTS_NOTE.contains('\n'),
            "the defaults note is exactly one line"
        );
    }

    #[test]
    fn the_committed_example_loads() {
        // The shipped batten.example.toml must actually load (DoD: it round-trips).
        let example = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../batten.example.toml");
        let config = load(&example).expect("batten.example.toml loads");
        assert_eq!(config.version, SUPPORTED_VERSION);
    }

    #[test]
    fn the_shipped_starter_loads() {
        // The same obligation for the template `batten init` writes, which is the
        // artifact a consumer actually receives — the example above is a document
        // a reader copies by hand, and the two are gated separately until the
        // retirement lands (CLOUD-206's follow-up).
        let config = parse(crate::init::STARTER, CONFIG_FILE).expect("the starter loads");
        assert_eq!(config.version, SUPPORTED_VERSION);
    }

    /// A well-formed rule table with the given `severity` and `scope` lines
    /// spliced in, for the explicit-defaults and conflation cases below.
    fn rule_config(severity_line: &str, scope_line: &str) -> String {
        format!(
            "version = 1\n\n[[rule]]\nid = \"r\"\nkind = \"forbid\"\nglob = \"**\"\n\
             pattern = \"x\"\n{severity_line}{scope_line}"
        )
    }

    #[test]
    fn a_rule_with_explicit_severity_and_scope_parses() {
        let config = parse(
            &rule_config("severity = \"warn\"\n", "scope = \"tree\"\n"),
            "test",
        )
        .unwrap();
        assert_eq!(config.rules.len(), 1);
        assert_eq!(
            config.rules[0].severity(),
            crate::severity::RuleSeverity::Warn
        );
        assert_eq!(config.rules[0].scope, crate::rules::RuleScope::Tree);
    }

    #[test]
    fn a_rule_omitting_severity_is_a_usage_error() {
        // The explicit-defaults discipline (CLOUD-61): a committed rule states
        // its severity or the file does not parse. No implicit fallback exists
        // for the parser to fall into.
        let err = parse(&rule_config("", "scope = \"tree\"\n"), "test").unwrap_err();
        assert!(is_usage_error(&err));
        assert!(
            err.to_string().contains("severity"),
            "the refusal must name the missing key, got: {err}"
        );
    }

    #[test]
    fn a_severity_token_in_the_scope_key_is_a_usage_error() {
        // Scope ≠ severity: the two keys' vocabularies never cross, so writing
        // one axis's value into the other key is bad input, not a lenient read.
        for token in ["deny", "warn", "allow"] {
            let err = parse(
                &rule_config("severity = \"deny\"\n", &format!("scope = \"{token}\"\n")),
                "test",
            )
            .unwrap_err();
            assert!(is_usage_error(&err), "scope = \"{token}\" must be refused");
        }
    }

    #[test]
    fn a_scope_token_in_the_severity_key_is_a_usage_error() {
        let err = parse(&rule_config("severity = \"tree\"\n", ""), "test").unwrap_err();
        assert!(is_usage_error(&err), "severity = \"tree\" must be refused");
    }
}
