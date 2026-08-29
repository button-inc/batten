//! Config resolution: one committed authority plus raise-only overrides (§8).
//!
//! The repo `batten.toml` is the single committed **authority**. Env vars,
//! command-line flags, and a git-ignored [`LOCAL_CONFIG_FILE`] are **overrides**.
//! There is no upward directory walk and no `conf.d` merge — the local file is a
//! single amends-style override, never a merged tree.
//!
//! Two properties are load-bearing:
//!
//! * **Precedence is declared as data.** [`SETTINGS`] states, per key, its env
//!   var and its flag; the resolver *reads that table* rather than hard-coding
//!   the names, so the layering is inspectable
//!   instead of being resolution logic buried in the binary. Order is
//!   `flag > env > local file > repo config > default` — exactly the [`Source`]
//!   declaration order.
//! * **Overrides are raise-only.** For a policy-bearing key an override may only
//!   *tighten*, never weaken: raising [`Strictness`] is accepted, lowering it is
//!   a [`UsageError`] (→ exit `1`), and the local file may only *add* rules —
//!   redefining a committed rule is refused, so the worst an uncommitted file can
//!   do is make a gate stricter — which is what keeps config the trust boundary
//!   even with a local override present.
//!
//!   That monotonicity is the *same shape* §5 states for effects, but this layer
//!   owns it outright rather than inheriting it: §5's `max_effect` — per-flag
//!   effect annotations and a monotone maximum over them — is **specified, not
//!   implemented**. [`crate::effect::Effect`] is declared per command and
//!   carries no ordering, so there is nothing here to take a maximum of; the
//!   implementation rides CLOUD-27's spec work (CLOUD-217 (22)). Read the
//!   raise-only rule above as load-bearing on its own, not as a corollary of
//!   something already in the tree.
//!
//! `batten config show` prints the resolved config **with its sources**, so
//! which layer won a key is an answer the tool gives rather than one a reader
//! has to reconstruct — and, since CLOUD-373, **which other layers spoke** too.
//! Naming only the winner leaves a key resolving to `env` reading identically
//! whether the committed authority also set it or said nothing at all: a repo
//! being overridden in a shell, and a repo that never had an opinion. Telling
//! those apart used to mean re-running the binary with layers removed, which is
//! the diagnostic this verb exists to spare a reader. The fold already knows
//! every contributor, so [`Contributors`] keeps them rather than discarding
//! them on the way out.
//!
//! **Which layer won is not the same question as what that layer read**
//! (CLOUD-332). [`Source`] answers the first, and its `Ord` *is* §8's precedence,
//! so it cannot also carry the second without the ladder acquiring a rank nobody
//! specified. [`Origin`] is that second axis: a **class** — `committed`,
//! `base-ref`, `uncommitted`, `ambient`, `ingested`, `builtin` — carried on every
//! [`Contributor`] beside its layer. Two things fall out of it that could not be
//! asked before. A base-ref reading stops being indistinguishable from a
//! working-tree one (CLOUD-722), which is what lets a consumer *require* the
//! trusted reading from the type instead of re-inspecting whether a flag was
//! passed. And [`authority_violations`] becomes decidable: an ingested reading
//! that is the effective authority for a key a committed source also sets is a
//! refusal, read off the retained contributor set rather than inferred from the
//! winner — which the winner alone cannot answer.
//!
//! **A repository with no authority at all resolves to layer 0** (CLOUD-70):
//! [`config::defaults`] becomes the whole configuration and every key attributes
//! to [`Source::Default`]. That adds no place configuration may come from — the
//! chain is still one committed file plus raise-only overrides, with no upward
//! walk — it only stops the chain from refusing when the first layer above the
//! default is missing. `--config-from` is the one exception and stays strict;
//! [`authority`] says why.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use anyhow::Result;
use clap::ValueEnum;
use serde::{Serialize, Serializer};

use crate::config::{self, Strictness};
use crate::error::UsageError;
use crate::rules::Rule;

/// The git-ignored local override file, read from the same directory as the
/// committed authority. Optional: absent simply means "no local override".
pub const LOCAL_CONFIG_FILE: &str = "batten.local.toml";

/// A config layer, declared **weakest-first**: the derived `Ord` is the §8
/// precedence order `flag > env > local file > repo config > default`, so the
/// winning source for a key is the greatest layer that set it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Source {
    /// The compiled-in default, used when no layer speaks to the key.
    Default,
    /// The committed authority, the repo `batten.toml`.
    RepoConfig,
    /// The git-ignored [`LOCAL_CONFIG_FILE`].
    LocalFile,
    /// A `BATTEN_`-prefixed environment variable.
    Env,
    /// A command-line flag.
    Flag,
}

impl Source {
    /// The stable lowercase token used in machine output (§6).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Source::Default => "default",
            Source::RepoConfig => "repo-config",
            Source::LocalFile => "local-file",
            Source::Env => "env",
            Source::Flag => "flag",
        }
    }
}

impl Serialize for Source {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

/// Where a layer's bytes came from, as a **class** — never a path and never a
/// revspec (CLOUD-332).
///
/// Orthogonal to [`Source`], which is why it is a second type rather than two
/// more variants of the first. `Source` answers *which layer won* and its derived
/// `Ord` **is** §8's precedence order; this answers *what kind of thing that layer
/// read*, which `--config-from` changes without moving anything in the ladder. A
/// sixth `Source` variant would have to be ordered somewhere in a chain whose
/// order is the specification, and there is no honest place to put it.
///
/// `#[non_exhaustive]` from birth, exactly as [`crate::trust::Provenance`] is:
/// CLOUD-128's ingesting adapters and CLOUD-720's pin token are then additive
/// forever, which is the break `Source` — public, exhaustive, and named in every
/// `config show` document — cannot take.
///
/// **Declaration order is load-bearing in exactly one place, and it is not
/// precedence.** [`Contributor`] sorts on its layer first, so this ordering only
/// ever breaks a tie *within* one layer, and [`Origin::Ingested`] is declared last
/// so that it wins such a tie. When an adapter eventually seats an ingested value
/// at the same [`Source`] a committed file also set, the ingested contributor is
/// therefore the greatest — which is what lets [`authority_violations`] *see* it.
/// Ordered low, that predicate could never fire and the gate would be vacuous
/// while reading as coverage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[non_exhaustive]
pub enum Origin {
    /// The compiled-in default: no source at all, so nothing was read.
    Builtin,
    /// A file this repository commits, read from the working tree.
    Committed,
    /// The committed authority read **out of band**, from a git ref rather than
    /// the working tree (CLOUD-722). Still the committed authority — see
    /// [`Origin::is_committed`] — read somewhere a branch cannot edit.
    BaseRef,
    /// A git-ignored file on this machine: [`LOCAL_CONFIG_FILE`].
    Uncommitted,
    /// The process environment or the command line.
    Ambient,
    /// Content an adapter imported from outside this repository.
    ///
    /// **No adapter produces this token in this tree.** The class is minted here
    /// because [`authority_violations`] is the boundary CLOUD-332 exists to make
    /// checkable, and a boundary with no class on the far side of it decides
    /// nothing. CLOUD-128 is the producer, and it lands additively because this
    /// enum is `#[non_exhaustive]`.
    Ingested,
}

impl Origin {
    /// The stable lowercase token used in machine output (§6).
    ///
    /// A **class**, never a machine-local path or a raw revspec: a path is both
    /// payload and non-portable, so it would fail non-negotiable rule 4 and §6's
    /// byte-stability at once.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Origin::Builtin => "builtin",
            Origin::Committed => "committed",
            Origin::BaseRef => "base-ref",
            Origin::Uncommitted => "uncommitted",
            Origin::Ambient => "ambient",
            Origin::Ingested => "ingested",
        }
    }

    /// The class a layer reads from when nothing redirects it.
    ///
    /// [`Source::RepoConfig`] is the one layer this can be wrong for, and
    /// `--config-from` is the one thing that makes it wrong; [`authority_origin`]
    /// is where that override is applied, once per resolve.
    #[must_use]
    pub const fn of(layer: Source) -> Self {
        match layer {
            Source::Default => Origin::Builtin,
            Source::RepoConfig => Origin::Committed,
            Source::LocalFile => Origin::Uncommitted,
            Source::Env | Source::Flag => Origin::Ambient,
        }
    }

    /// Whether this reading is one the repository commits — the half
    /// [`authority_violations`] turns on, stated once so no caller re-derives it.
    ///
    /// [`Origin::BaseRef`] answers `true` deliberately: a base-ref reading **is**
    /// the committed authority, read elsewhere. Answering `false` would make
    /// CLOUD-722's token trip CLOUD-332's gate, which is two rows disagreeing
    /// about one fact.
    #[must_use]
    pub const fn is_committed(self) -> bool {
        matches!(self, Origin::Committed | Origin::BaseRef)
    }
}

impl Serialize for Origin {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

/// One layer that set a key, paired with the class it read from.
///
/// `layer` is declared **first**, so the derived `Ord` puts [`Source`]'s ordering
/// — which is §8's precedence — ahead of the class. Provenance is a tiebreak
/// within one layer and never a re-ranking of the ladder.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[non_exhaustive]
pub struct Contributor {
    /// The §8 layer that set the key.
    pub layer: Source,
    /// The class of thing that layer read.
    pub provenance: Origin,
}

impl Contributor {
    /// A contributor pairing one layer with one class.
    #[must_use]
    pub const fn new(layer: Source, provenance: Origin) -> Self {
        Contributor { layer, provenance }
    }
}

/// Every layer that **set** one key, weakest-first (CLOUD-373).
///
/// The winner is the greatest member, so "who won" and "was this key contested"
/// are two readings of one value rather than two values that can disagree.
/// [`Source`]'s derived `Ord` *is* §8's precedence order, which is what makes a
/// `BTreeSet` sufficient on its own: the declared weakest-first emission order
/// and the winner both fall out of that one ordering, so no artifact of the
/// order the resolver happened to visit the layers in can reach the emitted
/// document (§6). There is no second map and no parallel provenance structure
/// to keep in step.
///
/// [`Source::Default`] is deliberately **not** a member. It is the name for "no
/// layer spoke", not a layer that speaks: a key reading `[default, repo-config]`
/// would report a contest against a value nobody wrote, and "a key exactly one
/// layer set reports exactly one contributor" would then be false of every
/// authority key. An empty set is that case, and both [`Contributors::winner`]
/// and [`Contributors::layers`] answer `default` for it — as
/// [`Contributors::provenance`] answers [`Origin::Builtin`], the exact mirror.
///
/// **The members are [`Contributor`] pairs rather than bare [`Source`]s
/// (CLOUD-332), and a set rather than a map keyed by layer.** That is forced by
/// the predicate: an ingested contributor and a committed one must be able to
/// coexist on one key, and since [`Source`] gains no variant for ingestion the
/// ingested reading sits at an *existing* layer — which a map keyed by layer
/// cannot hold both of. Retaining both is exactly what makes
/// [`authority_violations`] decidable instead of an inference from the winner.
/// The inner field stays private, so this is invisible to the public API.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Contributors(BTreeSet<Contributor>);

impl Contributors {
    /// The set for a key no layer set, which the compiled-in default answers.
    #[must_use]
    pub const fn unset() -> Self {
        Contributors(BTreeSet::new())
    }

    /// The set for a key `layer` set, reading from that layer's own class.
    #[must_use]
    pub fn set_by(layer: Source) -> Self {
        Contributors::set_by_origin(layer, Origin::of(layer))
    }

    /// The set for a key `layer` set, reading from `provenance`.
    ///
    /// The spelling the authority layer needs: `repo-config` reads `committed`
    /// from the working tree and `base-ref` under `--config-from`, and nothing
    /// else about the layer changes.
    #[must_use]
    pub fn set_by_origin(layer: Source, provenance: Origin) -> Self {
        Contributors(BTreeSet::from([Contributor::new(layer, provenance)]))
    }

    /// Record that `layer` also set the key, reading from that layer's own class.
    ///
    /// Idempotent, so a layer that merely *restates* a lower layer's value —
    /// accepted by the raise-only clamp and re-attributed to the higher layer —
    /// appears once rather than once per pass over it.
    pub fn also(&mut self, layer: Source) {
        self.also_from(layer, Origin::of(layer));
    }

    /// Record that `layer` also set the key, reading from `provenance`.
    pub fn also_from(&mut self, layer: Source, provenance: Origin) {
        self.0.insert(Contributor::new(layer, provenance));
    }

    /// The layer that won: the greatest that set the key, or [`Source::Default`]
    /// when none did.
    #[must_use]
    pub fn winner(&self) -> Source {
        self.greatest().map_or(Source::Default, |c| c.layer)
    }

    /// The class the **winning** contributor read from, or [`Origin::Builtin`]
    /// when no layer set the key.
    #[must_use]
    pub fn provenance(&self) -> Origin {
        self.greatest().map_or(Origin::Builtin, |c| c.provenance)
    }

    /// Whether any contributor read from a class the repository commits.
    ///
    /// The half [`authority_violations`] pairs with [`Contributors::provenance`];
    /// stated here so no caller re-derives what "committed" means.
    #[must_use]
    pub fn committed(&self) -> bool {
        self.0.iter().any(|c| c.provenance.is_committed())
    }

    /// Every layer that set the key, weakest-first — `[default]` when none did.
    ///
    /// Never empty, and always ends with [`Contributors::winner`], so a reader
    /// can take the last element as the answer §8 owes them without a special
    /// case for the uncontested key.
    #[must_use]
    pub fn layers(&self) -> Vec<Source> {
        self.contributors().into_iter().map(|c| c.layer).collect()
    }

    /// Every contributor, weakest-first, each paired with the class it read.
    ///
    /// Never empty, for [`Contributors::layers`]'s reason and with the same
    /// shape: the unset key reports the one pair `(default, builtin)`.
    #[must_use]
    pub fn contributors(&self) -> Vec<Contributor> {
        if self.0.is_empty() {
            return vec![Contributor::new(Source::Default, Origin::Builtin)];
        }
        self.0.iter().copied().collect()
    }

    /// The greatest contributor, or `None` for a key no layer set.
    fn greatest(&self) -> Option<Contributor> {
        self.0.iter().next_back().copied()
    }
}

/// One key's layering, declared as data (§8) rather than implied by code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct SettingSpec {
    /// The `batten.toml` key, and the name used in the emitted `sources` map.
    pub key: &'static str,
    /// The environment variable that overrides it, if any.
    pub env: Option<&'static str>,
    /// The command-line flag that overrides it, if any.
    pub long_flag: Option<&'static str>,
}

/// The declared layering for every overridable key.
///
/// The resolver reads the env var and flag names *from here*, so this table is
/// the definition rather than documentation of one.
///
/// Every key here is policy-bearing and so subject to the raise-only clamp;
/// there is deliberately no per-key "is this policy-bearing" flag, because a
/// flag no code path reads is the declared-but-unenforced drift a policy engine
/// exists to prevent. A key that layers by plain precedence reintroduces the
/// distinction in the change that first needs it — together with the branch
/// that consults it.
pub const SETTINGS: &[SettingSpec] = &[
    SettingSpec {
        key: "strictness",
        env: Some("BATTEN_STRICTNESS"),
        long_flag: Some("--strictness"),
    },
    SettingSpec {
        // The one promotion setting (CLOUD-49), exposed three ways that resolve
        // to a single value. Every consumer reads the resolved value; no verb
        // re-declares a promotion knob of its own, and `batten exec` is
        // deliberately not a consumer at all (CLOUD-117).
        key: "fail_on_warning",
        env: Some("BATTEN_FAIL_ON_WARNING"),
        long_flag: Some("--fail-on-warning"),
    },
    SettingSpec {
        // Rules layer additively: the local file may add a rule, never redefine
        // or remove a committed one. There is no env or flag surface — a policy
        // predicate belongs in a reviewable file, not an ambient variable.
        key: "rule",
        env: None,
        long_flag: None,
    },
];

/// Look up a setting's declaration by key, or `None` for a key [`SETTINGS`]
/// does not declare.
///
/// Absence is a value rather than a panic (CLOUD-300). The alternative was an
/// `expect` exempted from the no-panic lint by a doc comment citing a test that
/// pinned "every key reaching here is declared" — and that test did not exist,
/// so the exemption rested on a mechanism nobody had built. Both callers have a
/// "this layer does not speak to the key" answer already, so handing them one
/// more way to reach it costs nothing and leaves nothing needing a pin.
fn setting(key: &str) -> Option<&'static SettingSpec> {
    SETTINGS.iter().find(|spec| spec.key == key)
}

/// The flag layer: values supplied on the command line, highest precedence.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Overrides {
    /// `--strictness`, when passed.
    pub strictness: Option<Strictness>,
    /// `--fail-on-warning`, when passed. A bare boolean flag has no "off" form,
    /// so this layer is raise-only by construction: `true` raises, absent says
    /// nothing and lets a lower layer keep the key.
    pub fail_on_warning: bool,
    /// `--config-from <ref>`, when passed. Not a *value* override like the two
    /// above: it selects **where the committed authority is read from** (a git
    /// ref instead of the working tree), leaving the §8 precedence chain
    /// untouched — env, flag and local-file overrides still stack on top under
    /// the same raise-only clamp (CLOUD-31).
    pub config_from: Option<String>,
}

/// The effective configuration, plus the layer that won each key.
///
/// Serialized flat so `config show` reads as the config it is, with `sources`
/// alongside (§8: "prints the effective config with sources"). Field order is
/// fixed and the map is sorted, so the output is byte-stable (§6).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Resolved {
    /// Whether a committed authority existed at all (CLOUD-70).
    ///
    /// Skipped by serde, exactly as [`Resolved::sources`] is, and for the same
    /// reason: the emitted document is the *config*, and this is a fact about
    /// where the config came from. `config show` already says it in the language
    /// it has — every key attributed to `default` — so a key here would be a
    /// second, redundant spelling that `check`'s stdout would then have to carry.
    #[serde(skip_serializing)]
    pub authority: config::Authority,
    /// The schema version of the committed authority.
    pub version: u32,
    /// The minimum Batten version the authority permits (enforcement: CLOUD-33).
    ///
    /// Emitted even when absent — as `null`, attributed to `default`. Skipping
    /// it would make the document's key set depend on the config's content, and
    /// "every emitted key carries a source" would then be satisfied by a
    /// document that simply stopped emitting the keys it could not attribute
    /// (CLOUD-30).
    pub min_batten_version: Option<String>,
    /// The effective strictness, after the raise-only clamp.
    pub strictness: Strictness,
    /// Whether a `warn`-severity finding is promoted to a violation, after the
    /// raise-only clamp (CLOUD-49). The checks/advisory pipeline reads this
    /// resolved value; it is the only promotion setting there is.
    pub fail_on_warning: bool,
    /// The effective rule set: the committed rules plus any the local file adds.
    #[serde(rename = "rule")]
    pub rules: Vec<Rule>,
    /// The scope path set: the authority's list, plus any `!` excludes the
    /// local file added. Raise-only — see [`merge_local_scope`] for why a local
    /// include is refused rather than appended.
    pub scope: Vec<String>,
    /// The protected path set: the authority's paths, plus any the local file
    /// **added**. §8's "add protected paths" verbatim; adding to an include-only
    /// set can only guard more.
    pub protected: Vec<String>,
    /// The unlanded path set, layered exactly as [`Resolved::protected`] is.
    pub unlanded: Vec<String>,
    /// The governing config surface hashed into `config epoch` (CLOUD-32).
    pub epoch: Option<config::Epoch>,
    /// The contract surface a running session is told about when it moves
    /// (CLOUD-461). Authority-only, like [`Resolved::epoch`]: what a session
    /// must re-read is the committed authority's claim, and a local file that
    /// could narrow it would be a way to switch the reminder off quietly.
    pub contract: Option<config::Contract>,
    /// The mutating-verb table, consumer data the authority supplies.
    #[serde(rename = "verb")]
    pub verbs: Vec<crate::verbs::MutatingVerb>,
    /// The named-regex table (CLOUD-885), consumer data the authority supplies —
    /// carried for [`Resolved::verbs`]'s reason and layered the same way.
    #[serde(rename = "pattern")]
    pub patterns: Vec<crate::pattern::NamedPattern>,
    /// The refusal vocabulary (CLOUD-1050), consumer data the authority
    /// supplies — carried for [`Resolved::patterns`]'s reason and layered the
    /// same way.
    ///
    /// **Authority only, no local layer.** A `batten.local.toml` that could add
    /// a class could give a refusal words the committed policy never chose,
    /// which is a weakening dressed as an addition: the token stays the same and
    /// what it MEANS changes. House style §8 admits raise-only overrides, and
    /// redefining a refusal is not one.
    #[serde(rename = "verdict")]
    pub verdicts: Vec<crate::verdict::DeclaredVerdict>,
    /// The per-path-class redirect table (CLOUD-280), authority rows plus any a
    /// local file **added**. Local rows append after committed ones, and the
    /// lookup takes the first match, so an uncommitted file can add a class the
    /// authority never named and can never change what a committed row says.
    #[serde(rename = "redirect")]
    pub redirects: Vec<crate::redirect::Redirect>,
    /// The agent-sourced facts the authority declares (CLOUD-776).
    ///
    /// **Authority-only**, and that is a security property rather than a
    /// consistency one — the same reason `[[hook.action]]` is. The declared
    /// command is what a deny tells the agent to run AND what the stored record
    /// is verified against, so a `batten.local.toml` able to add a row could
    /// point a gate at a command whose output it chooses, and the gate would
    /// accept it as a fact.
    #[serde(rename = "fact")]
    pub facts: Vec<crate::facts::Declared>,
    /// The receipts the authority mints from a tool result (CLOUD-1024).
    ///
    /// **Authority-only, on a stronger form of the reason `facts` above is.** A
    /// declared fact lets a local file point a gate at output it chooses; a
    /// declared mint lets one WRITE the receipt a gate honours, choosing the
    /// name, the subject and the bytes. That is not evidence pointed at the wrong
    /// place, it is evidence manufactured, so the local layer cannot reach this
    /// table at all — it is carried straight from the authority rather than
    /// through [`Tables`], which is what makes the restriction structural rather
    /// than a rule someone has to remember.
    #[serde(rename = "mint")]
    pub mints: Vec<crate::mint::Declared>,
    /// The records the authority writes from a tool result (CLOUD-1051).
    ///
    /// **Authority-only, on the strongest form of the reason `mints` above is.**
    /// A declared mint lets a local file manufacture the evidence a gate honours.
    /// A declared recorder does that AND chooses which program supplies a
    /// column's value — so a local layer able to reach this table could hand a
    /// gate a verdict of its own choosing while every rule, pattern and severity
    /// stayed exactly as the authority wrote them. Carried straight from the
    /// authority rather than through [`Tables`], so the restriction is structural
    /// rather than a rule someone has to remember.
    #[serde(rename = "recorder")]
    pub recorders: Vec<crate::recorder::Declared>,
    /// The programs a recorder may run, authority-only for the same reason and
    /// separately, because the indirection is the sharper half: repointing an id
    /// here changes what every column reading it records while the recorder rows
    /// stay byte-identical.
    #[serde(rename = "program")]
    pub programs: std::collections::BTreeMap<String, crate::recorder::Program>,
    /// The suppression-marker table, consumer data the authority supplies.
    #[serde(rename = "marker")]
    pub markers: Vec<crate::markers::Marker>,
    /// The `exec` output predicates (CLOUD-117), authority rows plus any a local
    /// file **added**. Raise-only by construction: a local file can only append,
    /// and a row reusing a committed id is refused rather than merged.
    #[serde(rename = "exec_pattern")]
    pub exec_patterns: Vec<crate::outputs::OutputPattern>,
    /// The waiver table (CLOUD-208), authority rows plus any a local file
    /// **added for a rule the authority does not declare**. A local waiver over a
    /// committed rule is refused rather than merged — see [`merge_local_waivers`].
    #[serde(rename = "waiver")]
    pub waivers: Vec<crate::waiver::Waiver>,
    /// How `batten exec` owns what it dispatched (CLOUD-427), as the authority
    /// states it. Not layered: an uncommitted file may not change the shape of a
    /// process tree an orchestrator two levels up is built against.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exec: Option<crate::exec::ExecConfig>,
    /// The declared thresholds (CLOUD-50), as the authority states them. Not
    /// layered: a budget is a bar this repository sets for itself, and there is
    /// no raise-only reading of "tighten a threshold" that a local file could
    /// be trusted with — lowering it is the weakening, and `trust.rs` compares
    /// the committed bytes for that.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub budget: Option<crate::budget::Budget>,
    /// The ref work must land on (CLOUD-51), as the authority states it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub must_land_on: Option<String>,
    /// The hook actions (CLOUD-91), as the authority states it. Not layered,
    /// and the one key where that is a security property rather than a
    /// consistency one: an action is a command, so a local file able to add one
    /// could run anything under the agent's own hook.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hook: Option<crate::action::HookConfig>,
    /// The judge payload boundary (CLOUD-135), as the authority states it. Not
    /// layered: every field is refusing by default and widening it is the
    /// weakening, so there is no raise-only reading a local file could be
    /// trusted with — `trust.rs` compares the committed bytes instead.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub judge: Option<crate::judge::Judge>,
    /// The design-evidence audit's per-capture ceiling (CLOUD-53), as the
    /// authority states it. Not layered: for a budget, smaller is stricter, so a
    /// local file could only ever *raise* the ceiling through the ordinary
    /// raise-only reading — which is the weakening. [`crate::design::
    /// effective_cap`] is the tighten-only clamp waiting for a layer that
    /// tightens; until one exists the authority's value stands alone.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub design: Option<crate::design::Design>,
    /// The derived merge contract (CLOUD-54), as the authority states it. Not
    /// layered: a local file cannot change what the host requires, and a copy
    /// that disagreed with the committed one would be a third answer to a
    /// question that already has one authority.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ci: Option<crate::ci::Ci>,
    /// The build tree and its two disk floors (CLOUD-1030), as the authority
    /// states it. Not layered, and for the direction the raise-only reading gets
    /// wrong here: a floor is a MINIMUM, so the local-file layer's ordinary
    /// "larger is stricter" instinct is inverted — a local file lowering the
    /// floor would weaken exactly the refusal this table exists to make. The
    /// numbers are measurements of this repository's own build, carrying the date
    /// they were taken, so there is one place to re-measure and no second answer.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prune: Option<crate::prune::Prune>,
    /// The defect ledger's declaration (CLOUD-52), as the authority states it.
    /// Not layered: where the ledger lives and what may be in it is a property
    /// of the repository, and a local file that could redirect it would be able
    /// to point the append-only gate at a different file than the one committed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub defects: Option<crate::defects::Defects>,
    /// The provisioning manifest (CLOUD-90), as the authority states it.
    #[serde(rename = "provision", skip_serializing_if = "Vec::is_empty")]
    pub provisions: Vec<crate::provision::Provision>,
    /// The transcript the optional `check` input reads (CLOUD-95), as the
    /// authority states it. Not layered: pointing the capability at a different
    /// file changes which evidence the run judges, and there is no raise-only
    /// reading of that — a local file redirecting it would be choosing the
    /// evidence, which is the weakening `trust.rs` compares committed bytes for.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transcript: Option<crate::transcript::TranscriptConfig>,
    /// The advisory drain's pacing (CLOUD-79), as the authority states it. Not
    /// layered, and for a reason unlike its neighbours': theirs is that lowering
    /// a bar is the weakening, where **an interval has no direction at all** — a
    /// longer window is quieter and a shorter one is louder, and neither is a
    /// weakening of anything the raise-only clamp could measure. A key with no
    /// monotone reading does not belong in a monotone layer.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub drain: Option<crate::drain::DrainConfig>,
    /// The attribution policy (CLOUD-274), as the authority states it. Not
    /// layered, for the same reason `transcript` is not: every value in it is a
    /// deny pattern or the identity commits are accountable to, and a local file
    /// editing either would be *loosening* the policy — the exact weakening
    /// `trust.rs` compares committed bytes for. There is no raise-only reading of
    /// "match fewer things".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attribution: Option<crate::attribution::Attribution>,
    /// The commit-subject convention (CLOUD-701), as the authority states it.
    /// Not layered, for the reason the neighbours above are not: the value is the
    /// predicate itself, and a local file editing it would be *loosening* the
    /// convention — there is no raise-only reading of "match more things".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub commit: Option<crate::commit::Commit>,
    /// Which layers set each **emitted** key.
    ///
    /// Keyed by the serialized key name, and total over the document rather
    /// than over [`SETTINGS`]: `SETTINGS` declares which layers *may* override a
    /// key, which is a strictly smaller set than the keys this struct prints.
    /// Pinning attribution to the overridable subset is what made the printed
    /// "effective config" structurally partial (CLOUD-30).
    ///
    /// Every contributor, not only the winner (CLOUD-373) — the layering is an
    /// ordered fold that already knows them all, and a key whose committed value
    /// was overridden is a different situation from one no committed file ever
    /// spoke to. [`Contributors`] carries both readings.
    ///
    /// Skipped by serde so the document is exactly the config keys; the pairing
    /// happens in [`Resolved::attributed`].
    #[serde(skip_serializing)]
    pub sources: BTreeMap<&'static str, Contributors>,
    /// The base-ref authority this run was judged by, and where it came from
    /// (CLOUD-720). `None` when no `--config-from` was named.
    ///
    /// Carried so the two things that follow the load — the weakening delta and
    /// the pin the run mints on reaching a verdict — use the *same* config this
    /// resolve took its policy from. Loading it twice would let a degraded
    /// resolve be followed by a refusing delta, which is one run reaching two
    /// answers about one ref.
    ///
    /// Skipped by serde for [`Resolved::authority`]'s reason: the emitted
    /// document is the config, and this is a fact about where the config came
    /// from.
    #[serde(skip_serializing)]
    pub base: Option<crate::trust::Loaded>,
}

/// One emitted key: its value, the layer that won it, and every layer that set
/// it.
///
/// Field order is the emitted order, and it is fixed here rather than sorted,
/// so the document's bytes are a function of the config alone (§6).
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Attributed {
    /// The effective value, exactly as the key serializes.
    pub value: serde_json::Value,
    /// The layer token that set it — never a filesystem path or a raw env
    /// value, both of which would break byte-stability across machines and leak
    /// a home directory.
    ///
    /// **A bare [`Source`] token, and it stays one.** Folding the class into this
    /// string (`repo-config@base-ref`) would put two facts in one field and break
    /// every consumer that reads it, for a distinction [`Attributed::provenance`]
    /// already carries beside it.
    pub source: Source,
    /// The class the winning layer read from (CLOUD-332) — a source class, never
    /// a machine-local path.
    pub provenance: Origin,
    /// Every layer that set the key, weakest-first, **including** the winner —
    /// so [`Attributed::source`] is always this list's last element's layer, and
    /// [`Attributed::provenance`] its class.
    ///
    /// All three are read off one [`Contributors`] set, so they cannot
    /// disagree; keeping `source` beside them is what leaves §8's "which layer
    /// won" answerable without a reader having to know that the last element is
    /// the greatest one (CLOUD-373).
    pub contributors: Vec<Contributor>,
}

impl Resolved {
    /// The class the committed authority was read as (CLOUD-722).
    ///
    /// Derived from [`Resolved::base`] — the loaded base-ref authority — and
    /// **never** from whether `--config-from` was passed. That is the whole point
    /// of the row: a consumer requiring the trusted reading asks the type, rather
    /// than re-inspecting override plumbing and re-deriving what the load already
    /// decided.
    #[must_use]
    pub fn authority_origin(&self) -> Origin {
        authority_origin(self.base.as_ref())
    }

    /// The effective configuration as
    /// `{key: {value, source, provenance, contributors}}`, sorted.
    ///
    /// Derived from this struct's own serialization rather than composed by
    /// hand, so the emitted key set is the struct's and cannot drift from it —
    /// which is also what makes "every emitted key carries a source" a checkable
    /// property instead of a promise.
    ///
    /// # Errors
    ///
    /// Propagates a serialization failure.
    pub fn attributed(&self) -> anyhow::Result<BTreeMap<String, Attributed>> {
        let document = serde_json::to_value(self)?;
        let serde_json::Value::Object(fields) = document else {
            anyhow::bail!("the resolved configuration did not serialize as an object");
        };
        fields
            .into_iter()
            .map(|(key, value)| {
                let contributors = self.sources.get(key.as_str()).ok_or_else(|| {
                    // Unreachable in a build that passes
                    // `tests::every_emitted_key_carries_a_source`; stated as an
                    // error rather than a panic because an unattributed key is
                    // exactly the defect this change removes.
                    anyhow::anyhow!("emitted key {key} carries no source")
                })?;
                Ok((
                    key,
                    Attributed {
                        value,
                        source: contributors.winner(),
                        provenance: contributors.provenance(),
                        contributors: contributors.contributors(),
                    },
                ))
            })
            .collect()
    }
}

/// The class the committed authority was read as, from the base-ref load's own
/// outcome (CLOUD-722).
///
/// One function, called by both [`resolve_with_env`] — which stamps it onto every
/// `repo-config` contributor — and [`Resolved::authority_origin`], so the per-key
/// attribution and the accessor cannot disagree about one reading.
///
/// **A pin resolves to [`Origin::BaseRef`] too**, on the reason
/// [`authority`] already gives: a pin is a previously validated instance of the
/// same one authority, not a third place configuration may live. Telling the two
/// apart is CLOUD-720's, and it stays free because [`Origin`] is
/// `#[non_exhaustive]`.
fn authority_origin(base: Option<&crate::trust::Loaded>) -> Origin {
    match base {
        None => Origin::Committed,
        Some(_) => Origin::BaseRef,
    }
}

/// A key whose effective value came from an **ingested** reading while a
/// committed contributor also set it (CLOUD-332).
///
/// Pointer-only: the key and the class that won it, never the value. A value is
/// the payload non-negotiable rule 4 keeps out of a finding, and a config value
/// is exactly the kind of payload that carries a secret.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct AuthorityViolation {
    /// The emitted key, as [`Resolved`] serializes it.
    pub key: String,
    /// The class that won the key.
    pub effective: Origin,
}

/// Every key an ingested reading is the effective authority for, sorted.
///
/// **Decidable because contributors are retained per key.** The committed and the
/// ingested contributor coexist in one [`Contributors`] set, so the question is a
/// read of that set rather than an attempt to infer where a value came from by
/// looking at the winner alone — which cannot be done, since the winner is one
/// value and says nothing about who else spoke.
///
/// Two cases that are deliberately **not** violations, and they are why this is a
/// boundary rather than a ban:
///
/// * a committed reading winning over an ingested contributor — that is the
///   boundary holding;
/// * an ingested reading winning where nothing committed spoke — that is
///   ingestion doing its job on a repository that authored no answer.
///
/// No adapter produces [`Origin::Ingested`] in this tree, so this returns empty
/// for every configuration reachable today; CLOUD-128 is the producer. The
/// predicate ships with it rather than after it, because a boundary rule landing
/// alongside its own first violator is a rule nobody can test in isolation.
#[must_use]
pub fn authority_violations(
    sources: &BTreeMap<&'static str, Contributors>,
) -> Vec<AuthorityViolation> {
    sources
        .iter()
        .filter(|(_, contributors)| {
            contributors.provenance() == Origin::Ingested && contributors.committed()
        })
        .map(|(key, contributors)| AuthorityViolation {
            key: (*key).to_owned(),
            effective: contributors.provenance(),
        })
        .collect()
}

/// The refusal [`authority_violations`] earns, or `None` when the boundary holds.
///
/// A function rather than a block inside [`resolve_with_env`], because the
/// producer of an ingested reading does not exist yet (CLOUD-128) and a refusal
/// no test can reach is a refusal nobody has read. This is the exact value the
/// resolver returns, so a test over it covers the real path minus the layer that
/// cannot be built.
///
/// A [`Denial`] and never a [`UsageError`]: the raise-only clamp in
/// [`Layered::raise`] refuses an **invocation**, which is exit `1`, where this
/// refuses what the **repository** resolved to — the statement exit `2` is for.
///
/// [`Denial`]: crate::error::Denial
#[must_use]
pub fn authority_refusal(violations: &[AuthorityViolation]) -> Option<anyhow::Error> {
    let first = violations.first()?;
    Some(crate::error::Denial::raise(format!(
        "{}: an {} reading is the effective authority for {} key(s) a committed source also sets; \
         an ingested value may only tighten a committed one, never replace it (§8)",
        first.key,
        first.effective.as_str(),
        violations.len(),
    )))
}

/// A value paired with every layer that set it, so a later layer can name both
/// sides of a rejected weakening — and so the document can name every layer
/// that spoke, not only the one that won (CLOUD-373).
///
/// The winning layer is [`Contributors::winner`] rather than a field of its own:
/// the layers are applied weakest-first, so the greatest contributor *is* the
/// winner, and storing it twice would be two spellings of one fact.
#[derive(Debug, Clone)]
struct Layered<T> {
    value: T,
    contributors: Contributors,
}

impl<T: Ord + Copy> Layered<T> {
    /// Apply a candidate from a higher layer under the raise-only clamp.
    ///
    /// Tightening (or restating) is accepted and the layer is recorded as a
    /// contributor; weakening is refused, naming the key, both layers, and both
    /// values so the operator can see exactly which file to fix. The refusal
    /// returns before any mutation, so a rejected override leaves neither the
    /// value nor the attribution touched.
    ///
    /// Generic over the key's type because the clamp *is* the ordering: every
    /// policy-bearing key resolves to a value where "tighten" means `candidate >=
    /// current`, whether that ordering is [`Strictness`]'s three ranks or
    /// `false < true`. One implementation means a second key cannot acquire a
    /// subtly different notion of weakening — `render` supplies the key's own
    /// token vocabulary for the message, and nothing else varies.
    fn raise(
        &mut self,
        candidate: T,
        source: Source,
        origin: &str,
        key: &str,
        render: fn(T) -> String,
    ) -> Result<()> {
        if candidate < self.value {
            return Err(UsageError::raise(format!(
                "{key}: {origin} would weaken policy ({} → {}); overrides may only tighten, \
                 never weaken a gate (§8)",
                render(self.value),
                render(candidate),
            )));
        }
        self.value = candidate;
        self.contributors.also(source);
        Ok(())
    }
}

/// The lowercase token a [`Strictness`] is written as in config, env, and flags.
///
/// Read off the `ValueEnum` derive rather than re-tabulated, so the flag, the
/// env var, the TOML key, and this message can never name a variant differently.
fn token(strictness: Strictness) -> String {
    strictness
        .to_possible_value()
        .map_or_else(|| "unknown".to_owned(), |v| v.get_name().to_owned())
}

/// The env layer for one key: its variable name and the value that variable
/// carries, or `None` when this layer does not speak to the key.
///
/// An **empty** variable is "not set", not a bad value: `FOO= cmd`, and a CI
/// that exports every knob unconditionally, both produce one. Filtering that
/// here rather than in each key's parser is what keeps empty→default (§10) a
/// single rule instead of one every new setting has to remember.
///
/// A key [`SETTINGS`] does not declare joins a key declaring no env var: this
/// layer does not speak to it, which is the answer the `?` chain already gives.
fn env_layer(key: &str, env: &dyn Fn(&str) -> Option<String>) -> Option<(&'static str, String)> {
    let name = setting(key)?.env?;
    let raw = env(name)?;
    let trimmed = raw.trim();
    (!trimmed.is_empty()).then(|| (name, trimmed.to_owned()))
}

/// The flag that overrides one key, falling back to `default` for a key the
/// table declares no flag for — or does not declare at all, which reaches the
/// same fallback rather than a distinct one.
fn flag_name(key: &str, default: &'static str) -> &'static str {
    setting(key)
        .and_then(|spec| spec.long_flag)
        .unwrap_or(default)
}

/// The token a boolean key is written as in config, env, and messages.
///
/// TOML's own boolean literals, so the `batten.toml` key, the env var, and a
/// refusal message all speak one vocabulary. Nothing else parses: widening the
/// accepted set later stays backward-compatible, narrowing it would not.
fn bool_token(value: bool) -> String {
    if value { "true" } else { "false" }.to_owned()
}

/// Parse a boolean from an override's textual value, accepting exactly the
/// tokens [`bool_token`] emits.
fn parse_bool(raw: &str, origin: &str, key: &str) -> Result<bool> {
    match raw {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => Err(UsageError::raise(format!(
            "{key}: {origin} has unknown value {raw:?}; expected one of {}, {}",
            bool_token(false),
            bool_token(true),
        ))),
    }
}

/// Parse a [`Strictness`] from an override's textual value, via the same
/// `ValueEnum` mapping `clap` uses for the flag.
fn parse_strictness(raw: &str, origin: &str) -> Result<Strictness> {
    Strictness::from_str(raw, false).map_err(|_| {
        let expected: Vec<String> = Strictness::value_variants()
            .iter()
            .copied()
            .map(token)
            .collect();
        UsageError::raise(format!(
            "strictness: {origin} has unknown value {raw:?}; expected one of {}",
            expected.join(", ")
        ))
    })
}

/// Resolve the effective config for the repository rooted at `dir`, reading the
/// process environment for the env layer.
///
/// # Errors
///
/// Returns a [`UsageError`] (→ exit `1`) when the committed authority is
/// missing or invalid, when the local file is invalid, or when any override
/// would weaken a policy-bearing key.
pub fn resolve(dir: &Path, overrides: &Overrides) -> Result<Resolved> {
    resolve_with_env(dir, overrides, &|name| std::env::var(name).ok())
}

/// Load the committed authority — layer 1 of the §8 chain.
///
/// **Optional in the working tree, required from a ref.** A missing working-tree
/// `batten.toml` resolves to [`config::defaults`], layer 0 (CLOUD-70): there is
/// still no upward walk to fall back on — the answer comes from the binary, not
/// from somewhere else on disk — so this is zero-config onboarding and not a
/// second place configuration may live.
///
/// Under `--config-from`, it is read from a git ref rather than the working
/// tree — same layer, same precedence, different source. That is the whole trust
/// mechanism: policy loads out of band of the change under review, so a branch
/// cannot relax the rules it is judged by (CLOUD-31). **That path stays strict**,
/// and the asymmetry is deliberate: a caller naming a ref asked to be judged by
/// what that ref declares, so answering with the engine's defaults would let a
/// branch that deletes `batten.toml` pick its own policy — the exact weakening
/// the flag exists to prevent.
fn authority(
    dir: &Path,
    config_from: Option<&str>,
) -> Result<(
    config::Config,
    config::Authority,
    Option<crate::trust::Loaded>,
)> {
    let Some(reference) = config_from else {
        let (config, present) = config::load_authority(&dir.join(config::CONFIG_FILE))?;
        return Ok((config, present, None));
    };
    // §4's lifecycle, and the one place in the engine that takes it: an
    // unreachable REFERENCE may be answered from the last validated config,
    // where a ref that resolves and declares none may not. `trust::load` is
    // where that asymmetry lives; here it is only consumed.
    //
    // `Permitted` is the CALL SITE's answer, not the policy's — `trust::load`
    // still requires a pin that verifies and a pinned config whose own
    // `[trust] offline_fallback` is on, so passing it here widens nothing.
    match crate::trust::load(dir, reference, crate::trust::OfflineFallback::Permitted)? {
        // `Authority::Present` either way, and a pin does not weaken that: it is
        // a previously validated instance of the same one authority, so every
        // key it declares is attributed to `Source::RepoConfig` exactly as a ref
        // read would be. The provenance travels beside the config rather than in
        // the precedence ladder, whose `Ord` IS §8's order.
        crate::trust::Load::Loaded(loaded) => Ok((
            loaded.config.clone(),
            config::Authority::Present,
            Some(*loaded),
        )),
        crate::trust::Load::RefUnreachable { reference } => Err(UsageError::raise(format!(
            "cannot resolve {reference} in this repository"
        ))),
        crate::trust::Load::AbsentAtRef { reference } => Err(UsageError::raise(format!(
            "{} is absent at {reference}",
            config::CONFIG_FILE
        ))),
    }
}

/// [`resolve`], with the env layer supplied by `env` so it is testable without
/// mutating the process environment.
///
/// # Errors
///
/// As [`resolve`].
pub fn resolve_with_env(
    dir: &Path,
    overrides: &Overrides,
    env: &dyn Fn(&str) -> Option<String>,
) -> Result<Resolved> {
    let (repo, present, base) = authority(dir, overrides.config_from.as_deref())?;
    // Resolved ONCE, from the load's own outcome rather than from the flag, and
    // stamped onto every `repo-config` contributor below (CLOUD-722). The layers
    // above the authority keep `Origin::of` — a base-ref reading says where the
    // AUTHORITY came from and nothing about the shell that ran the command.
    let origin = authority_origin(base.as_ref());

    // Layer 0 — the compiled-in default, overwritten by anything above it. It
    // contributes NOTHING: `Contributors::unset` is "no layer spoke", which is
    // what `default` names, so the authority below replaces the set rather than
    // adding to it.
    let mut strictness = Layered {
        value: Strictness::default(),
        contributors: Contributors::unset(),
    };
    if let Some(value) = repo.strictness {
        // The authority sets the floor; nothing below it can weaken it, so this
        // is an assignment rather than a clamped raise.
        strictness = Layered {
            value,
            contributors: Contributors::set_by_origin(Source::RepoConfig, origin),
        };
    }

    // The promotion setting layers by the identical chain and the identical
    // clamp; `false < true` is the ordering "tighten" is defined over.
    let mut fail_on_warning = Layered {
        value: false,
        contributors: Contributors::unset(),
    };
    if let Some(value) = repo.fail_on_warning {
        fail_on_warning = Layered {
            value,
            contributors: Contributors::set_by_origin(Source::RepoConfig, origin),
        };
    }

    let mut tables = Tables {
        // Presence, not emptiness: the default layer now carries a rule of its
        // own (CLOUD-70), so "the table is non-empty" no longer implies a
        // committed file said so.
        rules_source: declared_by(present, !repo.rules.is_empty(), origin),
        rules: repo.rules.clone(),
        exec_patterns: repo.exec_patterns.clone(),
        redirects: repo.redirects.clone(),
        facts: repo.facts.clone(),
        waivers: repo.waivers.clone(),
    };

    // The three policy-bearing path sets (CLOUD-37), seeded from the authority
    // and narrowable by the local layer below (CLOUD-239).
    let mut paths = Paths::from_authority(&repo, present, origin);

    // Layer 2 — the git-ignored local file. Optional, and raise-only.
    let local_path = dir.join(LOCAL_CONFIG_FILE);
    if local_path.exists() {
        // Ungated: `min_batten_version` is authority-only, and the refusal in
        // `apply_local` names that specifically. Gating here would replace it
        // with "this build is too old" — true of the value, useless about the
        // mistake (CLOUD-33).
        //
        // `OverrideConfig` IS the override surface (CLOUD-239), so a key this
        // layer cannot honour never reaches here: `deny_unknown_fields` refused
        // it at parse. What used to be a silently dropped tightening — a local
        // `protected` that looked applied and wasn't — is now either applied or
        // a load error, with no third outcome.
        let local = config::load_override(&local_path)?;
        apply_local(
            local,
            &repo,
            &mut strictness,
            &mut fail_on_warning,
            &mut tables,
            &mut paths,
        )?;
    }

    // Layer 3 — the environment. An *empty* variable is "not set", not a bad
    // value: `FOO= cmd`, and a CI that exports every knob unconditionally, both
    // produce one. Distinguishing empty→default from present-but-invalid is the
    // house style's stated position (§10), and the alternative is worse — a
    // harmless empty export would fail every invocation.
    if let Some((name, raw)) = env_layer("strictness", env) {
        let value = parse_strictness(&raw, name)?;
        strictness.raise(value, Source::Env, name, "strictness", token)?;
    }
    if let Some((name, raw)) = env_layer("fail_on_warning", env) {
        let value = parse_bool(&raw, name, "fail_on_warning")?;
        fail_on_warning.raise(value, Source::Env, name, "fail_on_warning", bool_token)?;
    }

    // Layer 4 — the command line, highest precedence and still raise-only: a
    // flag may tighten a gate for one run, never disable one for it.
    if let Some(value) = overrides.strictness {
        let flag = flag_name("strictness", "--strictness");
        strictness.raise(value, Source::Flag, flag, "strictness", token)?;
    }
    if overrides.fail_on_warning {
        // Only the raising direction exists here: a bare boolean flag cannot
        // express "off", so the clamp has nothing to refuse. Routed through
        // `raise` anyway so the attribution to `flag` follows the same path as
        // every other layer rather than a bespoke assignment.
        let flag = flag_name("fail_on_warning", "--fail-on-warning");
        fail_on_warning.raise(true, Source::Flag, flag, "fail_on_warning", bool_token)?;
    }

    let resolved = assemble(
        &repo,
        present,
        strictness,
        fail_on_warning,
        tables,
        paths,
        base,
    );

    // CLOUD-332's boundary, decided HERE rather than in `config show`: the
    // resolver is the one authority, and a reader that decided this itself would
    // be the second resolution path §1 exists to make unrepresentable. A `Denial`
    // and not a `UsageError` — the raise-only clamp above refuses an *invocation*
    // (exit `1`), where this refuses what the *repository* resolved to, which is
    // what exit `2` means.
    if let Some(refusal) = authority_refusal(&authority_violations(&resolved.sources)) {
        return Err(refusal);
    }
    Ok(resolved)
}

/// Which layers a key that only the authority can set came from.
///
/// One function for the whole document, so the two halves of the answer cannot
/// drift apart: a key is `repo-config` when a committed authority exists **and**
/// declares it, and `default` otherwise. Absence of the authority collapses the
/// first half, which is what makes every key on an unconfigured repository read
/// `default` (CLOUD-70) without that being written out per key.
///
/// The `default` half is [`Contributors::unset`] rather than a set containing
/// `Source::Default`, for the reason [`Contributors`] gives: a key nobody set
/// has no contributors, and `default` is what that is called.
///
/// `origin` is the class the authority was read as — [`Origin::Committed`] from
/// the working tree, [`Origin::BaseRef`] under `--config-from` (CLOUD-722).
/// Threading it here rather than per key is what makes every authority-only key
/// carry the reading's class without ~30 call sites each deciding it.
fn declared_by(present: config::Authority, declared: bool, origin: Origin) -> Contributors {
    match present {
        config::Authority::Present if declared => {
            Contributors::set_by_origin(Source::RepoConfig, origin)
        }
        _ => Contributors::unset(),
    }
}

/// The append-only tables, carried as one value through the layering.
///
/// One parameter rather than four, so [`apply_local`] and [`assemble`] both stay
/// inside the argument budget. Each table is merged by its own rule — see the
/// `merge_local_*` helpers and the rule loop — and none may have a committed row
/// redefined by the local layer.
struct Tables {
    rules: Vec<Rule>,
    rules_source: Contributors,
    exec_patterns: Vec<crate::outputs::OutputPattern>,
    redirects: Vec<crate::redirect::Redirect>,
    facts: Vec<crate::facts::Declared>,
    waivers: Vec<crate::waiver::Waiver>,
}

/// Apply the git-ignored local file over the authority's values, raise-only.
///
/// Extracted from [`resolve_with_env`] because that function is the §8
/// precedence chain and has to read as one: five layers in sequence, each a few
/// lines. Inlining a per-key merge for every layered table is what pushed it
/// past the line limit, and the chain is the thing a reader comes here for.
///
/// # Errors
///
/// Returns a [`UsageError`] (→ exit `1`) when the local file restates
/// `min_batten_version`, lowers a clamped value, redefines a committed row, or
/// writes a `scope` entry that would widen rather than narrow.
fn apply_local(
    local: config::OverrideConfig,
    repo: &config::Config,
    strictness: &mut Layered<Strictness>,
    fail_on_warning: &mut Layered<bool>,
    tables: &mut Tables,
    paths: &mut Paths,
) -> Result<()> {
    if local.min_batten_version.is_some() {
        return Err(UsageError::raise(format!(
            "{LOCAL_CONFIG_FILE}: `min_batten_version` is set by the committed authority ({}) \
             only; an override may not restate it",
            config::CONFIG_FILE,
        )));
    }
    if let Some(value) = local.strictness {
        strictness.raise(
            value,
            Source::LocalFile,
            LOCAL_CONFIG_FILE,
            "strictness",
            token,
        )?;
    }
    if let Some(value) = local.fail_on_warning {
        // The raise-only clause §8 names directly: a committed `on` cannot be
        // turned off by an uncommitted file.
        fail_on_warning.raise(
            value,
            Source::LocalFile,
            LOCAL_CONFIG_FILE,
            "fail_on_warning",
            bool_token,
        )?;
    }
    for rule in local.rules {
        if tables.rules.iter().any(|committed| committed.id == rule.id) {
            // Redefining a committed rule could weaken it (a narrower glob, a
            // pattern that no longer matches) and Batten cannot tell tightening
            // from weakening across arbitrary predicates — so the conservative
            // reading refuses rather than guesses.
            return Err(UsageError::raise(format!(
                "rule {}: {LOCAL_CONFIG_FILE} may not redefine a rule from {}; an override may \
                 only add rules, never weaken a committed gate (§8)",
                rule.id,
                config::CONFIG_FILE,
            )));
        }
        tables.rules.push(rule);
        // `also`, not an assignment: the committed authority still declared the
        // rules it declared, and a table both layers contributed to is exactly
        // the contest CLOUD-373 makes legible. Idempotent, so a local file
        // adding several rules records its layer once.
        tables.rules_source.also(Source::LocalFile);
    }
    merge_local_patterns(&mut tables.exec_patterns, local.exec_patterns)?;
    merge_local_redirects(&mut tables.redirects, local.redirects)?;
    merge_local_waivers(&mut tables.waivers, local.waivers, &repo.rules)?;
    // §8's three policy-bearing path sets, raise-only. Before CLOUD-239 these
    // were parsed and discarded: an author who wrote `protected` here got no
    // complaint from the editor, none from `taplo lint`, none from `batten
    // check` — and no effect. A tightening lost without a word is worse than one
    // refused, because the operator's intent vanishes.
    if merge_local_scope(&mut paths.scope, local.scope)? {
        paths.scope_source.also(Source::LocalFile);
    }
    if !local.protected.is_empty() {
        // Union: "add protected paths" is §8's own wording, and adding to an
        // include-only set can only guard more paths.
        paths.protected.extend(local.protected);
        paths.protected_source.also(Source::LocalFile);
    }
    if !local.unlanded.is_empty() {
        paths.unlanded.extend(local.unlanded);
        paths.unlanded_source.also(Source::LocalFile);
    }
    Ok(())
}

/// The three policy-bearing path sets after layering, with their attribution.
///
/// Grouped so [`assemble`] takes one parameter rather than six. Nothing here
/// derives one set from another — a path's membership in `scope`, `protected`
/// and `unlanded` are three separate answers (CLOUD-37).
struct Paths {
    scope: Vec<String>,
    protected: Vec<String>,
    unlanded: Vec<String>,
    scope_source: Contributors,
    protected_source: Contributors,
    unlanded_source: Contributors,
}

impl Paths {
    /// Seed all three from the committed authority, before any layering.
    ///
    /// Attribution follows the same present-means-`repo-config` rule every
    /// authority key gets, so a set the local layer never touches reads exactly
    /// as it did before these keys became layerable.
    fn from_authority(repo: &config::Config, present: config::Authority, origin: Origin) -> Self {
        let authority_set = |declared: bool| declared_by(present, declared, origin);
        Paths {
            scope_source: authority_set(!repo.scope.is_empty()),
            protected_source: authority_set(!repo.protected.is_empty()),
            unlanded_source: authority_set(!repo.unlanded.is_empty()),
            scope: repo.scope.clone(),
            protected: repo.protected.clone(),
            unlanded: repo.unlanded.clone(),
        }
    }
}

/// Narrow the committed scope with a local file's excludes.
///
/// Returns whether anything was narrowed, so the caller can attribute the key.
///
/// **Excludes only, and a plain include is refused.** `scope` is one ordered
/// include/exclude list whose includes *union*: appending an include can only
/// add paths, so a local include is either a widening — exactly what §8's
/// raise-only clause forbids — or a no-op that reads as policy. Excludes are
/// purely subtractive, so appending them is provably narrowing whatever the
/// authority declared, with no reasoning about entry order required.
///
/// This is deliberately narrower than §8's "narrow scope" read at its widest: an
/// author cannot express "restrict to `src/**`" in one entry, only "exclude what
/// I do not want". The trade is soundness — there is no local `scope` this
/// function accepts that can enlarge the set.
///
/// # Errors
///
/// Returns a [`UsageError`] (→ exit `1`) for a local entry that is not a `!`
/// exclude, naming the entry.
fn merge_local_scope(scope: &mut Vec<String>, local: Vec<String>) -> Result<bool> {
    if local.is_empty() {
        return Ok(false);
    }
    for entry in &local {
        if !entry.starts_with('!') {
            return Err(UsageError::raise(format!(
                "scope: `{entry}` — {LOCAL_CONFIG_FILE} may only NARROW scope, so every entry must \
                 be a `!` exclude; an include would widen the set an override may not widen (§8)",
            )));
        }
    }
    scope.extend(local);
    Ok(true)
}

/// Append a local file's output predicates to the committed ones.
///
/// The same reading local *rules* get, and for the same reason: a local file may
/// ADD a pattern — tightening, one more way for a wrapped command to be caught
/// lying — but may not redefine a committed one, since a narrowed stream or an
/// altered literal is a weakening Batten cannot distinguish from a fix.
///
/// Extracted rather than inlined because `resolve_with_env` is the §8 chain and
/// reads as one; a second per-table merge loop in its body is the thing that
/// pushed it past the line limit.
///
/// # Errors
///
/// Returns a [`UsageError`] when a local pattern reuses a committed id.
fn merge_local_patterns(
    committed: &mut Vec<crate::outputs::OutputPattern>,
    local: Vec<crate::outputs::OutputPattern>,
) -> Result<()> {
    for pattern in local {
        if committed.iter().any(|row| row.id == pattern.id) {
            return Err(UsageError::raise(format!(
                "exec_pattern {}: {LOCAL_CONFIG_FILE} may not redefine a pattern from {}; an \
                 override may only add patterns, never weaken a committed gate (§8)",
                pattern.id,
                config::CONFIG_FILE,
            )));
        }
        committed.push(pattern);
    }
    Ok(())
}

/// Add a local file's redirects to the committed ones, refusing a redefinition.
///
/// The same append-only shape [`merge_local_patterns`] uses, keyed on `glob`,
/// and for coherence rather than for safety: a redirect is **not
/// policy-bearing** — it changes what a refusal says, never whether it fires —
/// so §8's raise-only clamp has no bar here to protect. What refusing a
/// redefinition buys is that a committed remedy cannot be quietly reworded by an
/// uncommitted file, which is a claim about provenance, not about strictness.
///
/// Appending is what makes that hold: [`crate::redirect::resolve`] takes the
/// **first** matching row, so a local row can only ever answer for a class the
/// authority left unclaimed.
fn merge_local_redirects(
    committed: &mut Vec<crate::redirect::Redirect>,
    local: Vec<crate::redirect::Redirect>,
) -> Result<()> {
    for entry in local {
        if committed.iter().any(|row| row.glob == entry.glob) {
            return Err(UsageError::raise(format!(
                "redirect {}: {LOCAL_CONFIG_FILE} may not redefine a redirect from {}; an \
                 override may only add path classes the authority does not claim (§8)",
                entry.glob,
                config::CONFIG_FILE,
            )));
        }
        committed.push(entry);
    }
    Ok(())
}

/// Add a local file's waivers to the committed ones, refusing any that touch a
/// committed rule.
///
/// This is the one place where the local layer *lowers* a bar rather than raising
/// one, so the clamp has to be strict. [`Layered::raise`] cannot express it — it
/// is bounded `T: Ord + Copy` and a waiver has no ordering — so this copies the
/// blunter rule local *rules* already get, on the same stated ground: Batten
/// cannot tell tightening from weakening across arbitrary predicates, and a
/// waiver over a committed gate is the case where guessing wrong switches that
/// gate off from an uncommitted file.
///
/// A waiver for a rule the authority does not declare is accepted, because it
/// suppresses nothing the committed policy asserts. That is what lets a local
/// file waive a rule it also added, without a second mechanism.
///
/// # Errors
///
/// Returns a [`UsageError`] when a local waiver names a committed rule, or when
/// two waivers end up sharing an identity.
fn merge_local_waivers(
    committed: &mut Vec<crate::waiver::Waiver>,
    local: Vec<crate::waiver::Waiver>,
    rules: &[Rule],
) -> Result<()> {
    for waiver in local {
        if rules.iter().any(|rule| rule.id == waiver.rule) {
            return Err(UsageError::raise(format!(
                "waiver {}: {LOCAL_CONFIG_FILE} may not waive a rule declared in {}; a waiver \
                 lowers the bar, so the durable tier is the committed authority alone (§8)",
                waiver.rule,
                config::CONFIG_FILE,
            )));
        }
        committed.push(waiver);
    }
    // Re-validate the merged table: two layers can each be well formed and still
    // duplicate an identity between them, and a duplicate that only exists after
    // layering would otherwise never be refused.
    crate::waiver::validate(committed)
}

/// Build the resolved configuration from the authority plus the layered values.
///
/// Split out so the layering above reads as the §8 chain it is, rather than
/// ending in a field-by-field copy of every key the authority carries.
fn assemble(
    repo: &config::Config,
    present: config::Authority,
    strictness: Layered<Strictness>,
    fail_on_warning: Layered<bool>,
    tables: Tables,
    paths: Paths,
    base: Option<crate::trust::Loaded>,
) -> Resolved {
    // Re-read from `base` rather than taken as a parameter: `authority_origin` is
    // a pure function of the load's outcome, and this function is already at the
    // argument budget. One function means the two readings cannot disagree.
    let origin = authority_origin(base.as_ref());
    // Sources read off before the lists move, so every layered value is moved
    // into the document rather than cloned beside it.
    let sources = attribution(
        repo,
        present,
        strictness.contributors,
        fail_on_warning.contributors,
        tables.rules_source,
        &paths,
        origin,
    );
    Resolved {
        authority: present,
        version: repo.version,
        min_batten_version: repo.min_batten_version.clone(),
        strictness: strictness.value,
        fail_on_warning: fail_on_warning.value,
        rules: tables.rules,
        scope: paths.scope,
        protected: paths.protected,
        unlanded: paths.unlanded,
        epoch: repo.epoch.clone(),
        contract: repo.contract.clone(),
        verbs: repo.verbs.clone(),
        patterns: repo.patterns.clone(),
        verdicts: repo.verdicts.clone(),
        redirects: tables.redirects,
        facts: tables.facts,
        // Straight from the authority, never through `tables`: see the field's
        // own note for why the local layer may not reach this one.
        mints: repo.mints.clone(),
        recorders: repo.recorders.clone(),
        programs: repo.programs.clone(),
        markers: repo.markers.clone(),
        exec: repo.exec,
        exec_patterns: tables.exec_patterns,
        waivers: tables.waivers,
        budget: repo.budget.clone(),
        must_land_on: repo.must_land_on.clone(),
        hook: repo.hook.clone(),
        transcript: repo.transcript.clone(),
        attribution: repo.attribution.clone(),
        commit: repo.commit.clone(),
        judge: repo.judge.clone(),
        design: repo.design.clone(),
        ci: repo.ci.clone(),
        prune: repo.prune.clone(),
        defects: repo.defects.clone(),
        provisions: repo.provisions.clone(),
        drain: repo.drain.clone(),
        sources,
        base,
    }
}

/// Which layers set each emitted key.
///
/// Every key the authority *can* set but no layer may override is attributed the
/// same way — present in the committed file means `repo-config`, absent means
/// `default` — so the two cannot drift apart by being written out per key. Such
/// a key can never be contested: there is exactly one layer able to speak to it,
/// which is why `declared_by` answers with a set of at most one.
fn attribution(
    repo: &config::Config,
    present: config::Authority,
    strictness: Contributors,
    fail_on_warning: Contributors,
    rules: Contributors,
    paths: &Paths,
    origin: Origin,
) -> BTreeMap<&'static str, Contributors> {
    let authority_set = |declared: bool| declared_by(present, declared, origin);
    BTreeMap::from([
        // `version` comes from the authority whenever there is one: the key is
        // required within the file. With no file it is the defaults' own
        // `SUPPORTED_VERSION`, which is layer 0 like everything else on an
        // unconfigured repository (CLOUD-70).
        ("version", authority_set(true)),
        (
            "min_batten_version",
            authority_set(repo.min_batten_version.is_some()),
        ),
        ("strictness", strictness),
        ("fail_on_warning", fail_on_warning),
        ("rule", rules),
        // Layered since CLOUD-239: these three carry the local file's source
        // when it narrowed them, so `config show` names the layer that did —
        // and since CLOUD-373 the authority's beside it, since narrowing a
        // committed set is the contest a reader most needs to see.
        ("scope", paths.scope_source.clone()),
        ("protected", paths.protected_source.clone()),
        ("unlanded", paths.unlanded_source.clone()),
        ("epoch", authority_set(repo.epoch.is_some())),
        ("contract", authority_set(repo.contract.is_some())),
        ("verb", authority_set(!repo.verbs.is_empty())),
        ("pattern", authority_set(!repo.patterns.is_empty())),
        // Authority-only, like `fact` below and for a related reason (CLOUD-1050):
        // a local row here would not point a gate at chosen output, it would
        // supply the WORDS a committed gate refuses in — the token stays the same
        // and what it means changes, which is a weakening dressed as an addition.
        ("verdict", authority_set(!repo.verdicts.is_empty())),
        ("marker", authority_set(!repo.markers.is_empty())),
        (
            "exec_pattern",
            authority_set(!repo.exec_patterns.is_empty()),
        ),
        ("exec", authority_set(repo.exec.is_some())),
        ("redirect", authority_set(!repo.redirects.is_empty())),
        // Authority-only, like `hook.action` and for the same security reason: a
        // declared command is what a deny asks the agent to run AND what the
        // record is verified against, so a local file able to add a row could
        // point a gate at output it chooses (CLOUD-776).
        ("fact", authority_set(!repo.facts.is_empty())),
        // Authority-only for a stronger form of `fact`'s reason: a local row
        // here would not point a gate at chosen output, it would write the
        // receipt the gate honours (CLOUD-1024).
        ("mint", authority_set(!repo.mints.is_empty())),
        // Authority-only for the STRONGEST form of that reason: a recorder row
        // writes what a gate reads AND names the program whose verdict a column
        // carries, so a local row here could hand a gate an answer of its own
        // choosing while every rule and severity stayed as the authority wrote
        // them (CLOUD-1051).
        ("recorder", authority_set(!repo.recorders.is_empty())),
        // Separately, because the indirection is the sharper half: repointing an
        // id here changes what every column reading it records while the recorder
        // rows stay byte-identical.
        ("program", authority_set(!repo.programs.is_empty())),
        ("waiver", authority_set(!repo.waivers.is_empty())),
        ("budget", authority_set(repo.budget.is_some())),
        ("must_land_on", authority_set(repo.must_land_on.is_some())),
        ("hook", authority_set(repo.hook.is_some())),
        ("transcript", authority_set(repo.transcript.is_some())),
        ("attribution", authority_set(repo.attribution.is_some())),
        ("commit", authority_set(repo.commit.is_some())),
        ("judge", authority_set(repo.judge.is_some())),
        ("design", authority_set(repo.design.is_some())),
        ("ci", authority_set(repo.ci.is_some())),
        ("prune", authority_set(repo.prune.is_some())),
        ("defects", authority_set(repo.defects.is_some())),
        ("provision", authority_set(!repo.provisions.is_empty())),
        ("drain", authority_set(repo.drain.is_some())),
    ])
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::fs;

    use super::*;

    /// Write a repo (and optionally a local override) into a fresh temp dir.
    fn repo(name: &str, repo_toml: &str, local_toml: Option<&str>) -> std::path::PathBuf {
        // `CARGO_TARGET_TMPDIR` exists only for integration tests, so a unit
        // test takes its scratch space from the system temp dir instead.
        let dir = std::env::temp_dir().join("batten-resolve-tests").join(name);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join(config::CONFIG_FILE), repo_toml).unwrap();
        let local = dir.join(LOCAL_CONFIG_FILE);
        match local_toml {
            Some(contents) => fs::write(&local, contents).unwrap(),
            // A leftover file from a prior run would silently change the case.
            None => {
                let _ = fs::remove_file(&local);
            }
        }
        dir
    }

    fn no_env(_: &str) -> Option<String> {
        None
    }

    /// A committed authority declaring one redirect class.
    const REDIRECT_AUTHORITY: &str = "version = 1\nprotected = [\"guarded/**\"]\n\n[[redirect]]\nglob = \"guarded/**\"\nmutation = \"use the surface that owns it\"\n";

    #[test]
    fn a_local_file_may_add_a_redirect_class_the_authority_does_not_claim() {
        // The permitted direction, and the reason it needs no clamp: a redirect
        // changes what a refusal SAYS, never whether it fires, so an added class
        // lowers no bar. A session gating a scratch tree can name its own remedy
        // without touching committed policy.
        let dir = repo(
            "redirect-local-add",
            REDIRECT_AUTHORITY,
            Some(
                "version = 1\n\n[[redirect]]\nglob = \"vendor/**\"\nmutation = \"re-run the generator\"\n",
            ),
        );
        let resolved = resolve_with_env(&dir, &Overrides::default(), &no_env).unwrap();
        assert_eq!(resolved.redirects.len(), 2);
        // Appended AFTER the committed rows, which is what makes first-match-wins
        // safe: a local row can only ever answer for a class the authority left
        // unclaimed.
        assert_eq!(resolved.redirects[0].glob, "guarded/**");
        assert_eq!(resolved.redirects[1].glob, "vendor/**");
        assert_eq!(
            crate::redirect::resolve(&resolved.redirects, "guarded/thing"),
            Some("use the surface that owns it"),
            "the committed remedy still answers for its own class"
        );
    }

    #[test]
    fn a_local_file_may_not_redefine_a_committed_redirect() {
        // Not a strictness clamp — there is no bar here to lower — but a
        // provenance one: a committed remedy must not be quietly reworded by an
        // uncommitted file, the same refusal every other append-only table gives.
        let dir = repo(
            "redirect-local-redefine",
            REDIRECT_AUTHORITY,
            Some(
                "version = 1\n\n[[redirect]]\nglob = \"guarded/**\"\nmutation = \"do whatever\"\n",
            ),
        );
        let err = resolve_with_env(&dir, &Overrides::default(), &no_env).unwrap_err();
        assert!(is_usage_error(&err), "got: {err}");
        assert!(
            err.to_string().contains("guarded/**"),
            "the refusal names the class: {err}"
        );
    }

    #[test]
    fn an_authority_declaring_no_redirect_resolves_an_empty_table() {
        // Absent is not empty-and-wrong: a repository that names no path class
        // simply falls through to the verb's own redirect, which is CLOUD-96's
        // behaviour and the floor this table sits on top of.
        let dir = repo("redirect-absent", "version = 1\n", None);
        let resolved = resolve_with_env(&dir, &Overrides::default(), &no_env).unwrap();
        assert!(resolved.redirects.is_empty());
    }

    fn is_usage_error(err: &anyhow::Error) -> bool {
        err.downcast_ref::<UsageError>().is_some()
    }

    #[test]
    fn source_order_is_the_declared_precedence() {
        // §8: flag > env > local file > repo config > default.
        assert!(Source::Default < Source::RepoConfig);
        assert!(Source::RepoConfig < Source::LocalFile);
        assert!(Source::LocalFile < Source::Env);
        assert!(Source::Env < Source::Flag);
    }

    #[test]
    fn every_emitted_key_carries_a_source() {
        // The identity this replaces was `sources.len() == SETTINGS.len()`,
        // which pinned attribution to the OVERRIDABLE subset — so every key the
        // document emitted outside `SETTINGS` (`version`, `min_batten_version`,
        // the path sets, the consumer tables) printed with no source at all, and
        // the hole widened with every `batten.toml` key that landed (CLOUD-30).
        //
        // The property now is total over the emitted document: `attributed()`
        // errors on an unattributed key, so this asserts it succeeds and that
        // the key set is the struct's own serialization.
        let dir = repo("emitted-keys", "version = 1\n", None);
        let resolved = resolve_with_env(&dir, &Overrides::default(), &no_env).unwrap();
        let document = resolved
            .attributed()
            .expect("every emitted key is attributed");

        let serialized = serde_json::to_value(&resolved).unwrap();
        let serde_json::Value::Object(fields) = serialized else {
            panic!("the resolved configuration serializes as an object");
        };
        assert_eq!(
            document.keys().cloned().collect::<Vec<_>>(),
            fields.keys().cloned().collect::<Vec<_>>(),
            "the attributed document must cover exactly the serialized keys"
        );

        // `SETTINGS` keeps its own, narrower job: declaring which layers may
        // override a key. Every key it names must still be emitted.
        for spec in SETTINGS {
            assert!(
                document.contains_key(spec.key),
                "SETTINGS declares {} but the document does not emit it",
                spec.key
            );
        }
    }

    #[test]
    fn a_key_no_layer_set_reads_default_and_an_authority_key_reads_repo_config() {
        let dir = repo(
            "attribution-layers",
            "version = 1\nprotected = [\"a\"]\n",
            None,
        );
        let resolved = resolve_with_env(&dir, &Overrides::default(), &no_env).unwrap();
        let document = resolved.attributed().unwrap();
        assert_eq!(document["protected"].source, Source::RepoConfig);
        assert_eq!(document["unlanded"].source, Source::Default);
        assert_eq!(document["version"].source, Source::RepoConfig);
    }

    #[test]
    fn a_contested_key_names_every_layer_that_set_it() {
        // CLOUD-373's whole point: `strictness` here resolves to `local-file`
        // either way, so the winner alone cannot tell a committed policy being
        // overridden from a repository that never had an opinion. The
        // contributor list is what separates them.
        let contested = repo(
            "contributors-contested",
            "version = 1\nstrictness = \"standard\"\n",
            Some("version = 1\nstrictness = \"strict\"\n"),
        );
        let document = resolve_with_env(&contested, &Overrides::default(), &no_env)
            .unwrap()
            .attributed()
            .unwrap();
        assert_eq!(
            document["strictness"].contributors,
            vec![
                Contributor::new(Source::RepoConfig, Origin::Committed),
                Contributor::new(Source::LocalFile, Origin::Uncommitted),
            ],
            "both layers set the key, weakest-first, each naming what it read"
        );
        assert_eq!(document["strictness"].source, Source::LocalFile);
        assert_eq!(document["strictness"].provenance, Origin::Uncommitted);

        // The same winner, reached with nothing underneath it. Identical
        // `source`, different `contributors` — which is the defect closed.
        let uncontested = repo(
            "contributors-uncontested",
            "version = 1\n",
            Some("version = 1\nstrictness = \"strict\"\n"),
        );
        let document = resolve_with_env(&uncontested, &Overrides::default(), &no_env)
            .unwrap()
            .attributed()
            .unwrap();
        assert_eq!(document["strictness"].source, Source::LocalFile);
        assert_eq!(
            document["strictness"].contributors,
            vec![Contributor::new(Source::LocalFile, Origin::Uncommitted)],
            "a key exactly one layer set reports exactly one contributor"
        );
    }

    #[test]
    fn a_key_no_layer_set_reports_the_default_alone() {
        // `default` is what "nobody spoke" is called, not a layer that spoke, so
        // it appears alone or not at all. A `[default, repo-config]` reading
        // would report a contest against a value nobody wrote — and would make
        // "exactly one layer means exactly one contributor" false of every
        // authority key in the document.
        let dir = repo(
            "contributors-default",
            "version = 1\nprotected = [\"a\"]\n",
            None,
        );
        let document = resolve_with_env(&dir, &Overrides::default(), &no_env)
            .unwrap()
            .attributed()
            .unwrap();
        assert_eq!(
            document["unlanded"].contributors,
            vec![Contributor::new(Source::Default, Origin::Builtin)],
            "`default` pairs with `builtin`: nobody spoke, so nothing was read"
        );
        assert_eq!(
            document["protected"].contributors,
            vec![Contributor::new(Source::RepoConfig, Origin::Committed)]
        );
        for (key, attributed) in &document {
            assert!(
                attributed.contributors.len() == 1
                    || !attributed
                        .contributors
                        .iter()
                        .any(|c| c.layer == Source::Default),
                "{key} reports `default` beside another layer: {:?}",
                attributed.contributors
            );
        }
    }

    #[test]
    fn contributors_are_emitted_in_declaration_order_and_end_with_the_winner() {
        // §6: the order is `Source`'s DECLARATION order, never the order the
        // resolver happened to fold the layers in — and a layer that merely
        // restates the value below it is recorded once, not once per pass.
        let dir = repo(
            "contributors-declaration-order",
            "version = 1\nstrictness = \"standard\"\n",
            None,
        );
        let document = resolve_with_env(
            &dir,
            &Overrides {
                strictness: Some(Strictness::Strict),
                ..Overrides::default()
            },
            &|name| (name == "BATTEN_STRICTNESS").then(|| "standard".to_owned()),
        )
        .unwrap()
        .attributed()
        .unwrap();
        assert_eq!(
            document["strictness"].contributors,
            vec![
                Contributor::new(Source::RepoConfig, Origin::Committed),
                Contributor::new(Source::Env, Origin::Ambient),
                Contributor::new(Source::Flag, Origin::Ambient),
            ],
            "the env layer restated the committed value and still counts once"
        );

        // Over the whole document, and stated as the two properties the emitted
        // shape rests on rather than as one fixture's answer.
        for (key, attributed) in &document {
            let mut sorted = attributed.contributors.clone();
            sorted.sort_unstable();
            sorted.dedup();
            assert_eq!(
                *attributed.contributors, sorted,
                "{key}'s contributors are not in declared weakest-first order"
            );
            assert_eq!(
                attributed.contributors.last().map(|c| c.layer),
                Some(attributed.source),
                "{key}'s winner is not its greatest contributor"
            );
            assert_eq!(
                attributed.contributors.last().map(|c| c.provenance),
                Some(attributed.provenance),
                "{key}'s provenance is not the greatest contributor's"
            );
        }
    }

    #[test]
    fn default_wins_when_no_layer_speaks() {
        let dir = repo("resolve-default", "version = 1\n", None);
        let resolved = resolve_with_env(&dir, &Overrides::default(), &no_env).unwrap();
        assert_eq!(resolved.strictness, Strictness::Standard);
        assert_eq!(resolved.sources["strictness"].winner(), Source::Default);
    }

    #[test]
    fn repo_config_beats_default() {
        let dir = repo(
            "resolve-repo",
            "version = 1\nstrictness = \"permissive\"\n",
            None,
        );
        let resolved = resolve_with_env(&dir, &Overrides::default(), &no_env).unwrap();
        assert_eq!(resolved.strictness, Strictness::Permissive);
        assert_eq!(resolved.sources["strictness"].winner(), Source::RepoConfig);
    }

    #[test]
    fn local_file_may_tighten() {
        let dir = repo(
            "resolve-local-tighten",
            "version = 1\nstrictness = \"standard\"\n",
            Some("version = 1\nstrictness = \"strict\"\n"),
        );
        let resolved = resolve_with_env(&dir, &Overrides::default(), &no_env).unwrap();
        assert_eq!(resolved.strictness, Strictness::Strict);
        assert_eq!(resolved.sources["strictness"].winner(), Source::LocalFile);
    }

    #[test]
    fn local_file_may_not_weaken() {
        // The load-bearing clamp: an uncommitted file cannot lower a gate.
        let dir = repo(
            "resolve-local-weaken",
            "version = 1\nstrictness = \"strict\"\n",
            Some("version = 1\nstrictness = \"permissive\"\n"),
        );
        let err = resolve_with_env(&dir, &Overrides::default(), &no_env).unwrap_err();
        assert!(is_usage_error(&err));
        assert!(
            err.to_string().contains("may only tighten"),
            "the refusal must say why, got: {err}"
        );
    }

    #[test]
    fn local_file_may_add_a_rule() {
        let dir = repo(
            "resolve-local-add-rule",
            "version = 1\n\n[[rule]]\nid = \"a\"\nkind = \"forbid\"\nglob = \"**\"\npattern = \"x\"\nseverity = \"deny\"\n",
            Some(
                "version = 1\n\n[[rule]]\nid = \"b\"\nkind = \"forbid\"\nglob = \"**\"\npattern = \"y\"\nseverity = \"deny\"\n",
            ),
        );
        let resolved = resolve_with_env(&dir, &Overrides::default(), &no_env).unwrap();
        let ids: Vec<&str> = resolved.rules.iter().map(|r| r.id.as_str()).collect();
        assert_eq!(ids, vec!["a", "b"], "an added rule tightens policy");
        assert_eq!(resolved.sources["rule"].winner(), Source::LocalFile);
    }

    #[test]
    fn local_file_may_not_redefine_a_committed_rule() {
        let dir = repo(
            "resolve-local-redefine",
            "version = 1\n\n[[rule]]\nid = \"a\"\nkind = \"forbid\"\nglob = \"**\"\npattern = \"x\"\nseverity = \"deny\"\n",
            Some(
                "version = 1\n\n[[rule]]\nid = \"a\"\nkind = \"forbid\"\nglob = \"nothing/**\"\npattern = \"x\"\nseverity = \"deny\"\n",
            ),
        );
        let err = resolve_with_env(&dir, &Overrides::default(), &no_env).unwrap_err();
        assert!(is_usage_error(&err));
        assert!(err.to_string().contains("may not redefine"), "got: {err}");
    }

    /// `batten.toml` text declaring rule `a`, plus whatever else the case needs.
    fn with_rule_a(extra: &str) -> String {
        format!(
            "version = 1\n\n[[rule]]\nid = \"a\"\nkind = \"forbid\"\nglob = \"**\"\n\
             pattern = \"x\"\nseverity = \"deny\"\n{extra}"
        )
    }

    fn waiver_row(rule: &str) -> String {
        format!("\n[[waiver]]\nrule = \"{rule}\"\nreason = \"tracked\"\nexpires = \"2099-01-01\"\n")
    }

    #[test]
    fn a_local_waiver_over_a_committed_rule_is_refused() {
        // The one direction where the local layer would LOWER the bar, so the
        // clamp is a flat refusal: `Layered::raise` needs `Ord` and a waiver has
        // none, so there is no "clamp to the tighter one" to fall back on.
        let dir = repo(
            "resolve-local-waiver-committed",
            &with_rule_a(""),
            Some(&format!("version = 1\n{}", waiver_row("a"))),
        );
        let err = resolve_with_env(&dir, &Overrides::default(), &no_env).unwrap_err();
        assert!(is_usage_error(&err));
        assert!(err.to_string().contains("may not waive"), "got: {err}");
    }

    #[test]
    fn a_local_file_may_add_a_waiver_for_an_undeclared_rule() {
        // It suppresses nothing the committed policy asserts, so refusing it would
        // buy no safety and would stop a local file waiving a rule it also added.
        let dir = repo(
            "resolve-local-waiver-unknown",
            &with_rule_a(""),
            Some(&format!("version = 1\n{}", waiver_row("elsewhere"))),
        );
        let resolved = resolve_with_env(&dir, &Overrides::default(), &no_env).unwrap();
        let rules: Vec<&str> = resolved.waivers.iter().map(|w| w.rule.as_str()).collect();
        assert_eq!(rules, vec!["elsewhere"]);
    }

    #[test]
    fn a_committed_waiver_resolves_and_is_attributed_to_the_authority() {
        let dir = repo(
            "resolve-committed-waiver",
            &with_rule_a(&waiver_row("a")),
            None,
        );
        let resolved = resolve_with_env(&dir, &Overrides::default(), &no_env).unwrap();
        assert_eq!(resolved.waivers.len(), 1);
        assert_eq!(resolved.sources["waiver"].winner(), Source::RepoConfig);
    }

    #[test]
    fn a_layered_duplicate_waiver_is_refused_even_though_each_layer_is_clean() {
        // Both files are individually well formed; the duplicate exists only after
        // merging, which is the one case a per-file validator cannot see.
        let dir = repo(
            "resolve-layered-duplicate-waiver",
            &with_rule_a(&waiver_row("elsewhere")),
            Some(&format!("version = 1\n{}", waiver_row("elsewhere"))),
        );
        let err = resolve_with_env(&dir, &Overrides::default(), &no_env).unwrap_err();
        assert!(is_usage_error(&err));
        assert!(err.to_string().contains("declared twice"), "got: {err}");
    }

    #[test]
    fn env_beats_the_local_file_and_is_raise_only() {
        let dir = repo(
            "resolve-env",
            "version = 1\nstrictness = \"permissive\"\n",
            Some("version = 1\nstrictness = \"standard\"\n"),
        );
        let strict = resolve_with_env(&dir, &Overrides::default(), &|name| {
            (name == "BATTEN_STRICTNESS").then(|| "strict".to_owned())
        })
        .unwrap();
        assert_eq!(strict.strictness, Strictness::Strict);
        assert_eq!(strict.sources["strictness"].winner(), Source::Env);

        // …and it still cannot go below the local file's floor.
        let err = resolve_with_env(&dir, &Overrides::default(), &|name| {
            (name == "BATTEN_STRICTNESS").then(|| "permissive".to_owned())
        })
        .unwrap_err();
        assert!(is_usage_error(&err));
    }

    #[test]
    fn an_undeclared_key_has_no_env_layer_and_falls_back_to_the_declared_default() {
        // CLOUD-300. `setting()` used to `expect` its key into existence, under
        // an `#[allow(clippy::expect_used)]` whose `# Panics` comment cited a
        // test that was never written. The panic was unreachable only by
        // coincidence of today's call sites, so this pins the property the
        // citation claimed — from the other end, over the two functions that
        // actually call it, now that absence is a value rather than a panic.
        //
        // The env closure answers EVERY name, so a `None` here can only come
        // from the table lookup; an unset variable cannot produce it.
        assert!(
            env_layer("not_a_declared_key", &|_| Some("loud".to_owned())).is_none(),
            "a key SETTINGS does not declare has no env layer"
        );
        assert_eq!(
            flag_name("not_a_declared_key", "--fallback"),
            "--fallback",
            "an undeclared key falls back exactly as a declared key with no flag does"
        );

        // The declared keys still resolve, so this cannot pass by `setting()`
        // answering `None` to everything.
        assert_eq!(
            env_layer("strictness", &|_| Some("strict".to_owned())),
            Some(("BATTEN_STRICTNESS", "strict".to_owned()))
        );
        assert_eq!(flag_name("strictness", "--fallback"), "--strictness");
        assert!(
            env_layer("rule", &|_| Some("loud".to_owned())).is_none(),
            "a declared key with no env var has no env layer either"
        );
    }

    #[test]
    fn an_empty_env_var_means_unset_not_invalid() {
        // `BATTEN_STRICTNESS= batten check` and a CI that exports every knob
        // unconditionally both produce an empty value. It must fall through to
        // the layer below, not fail the run (§10: empty → default).
        let dir = repo(
            "resolve-env-empty",
            "version = 1\nstrictness = \"strict\"\n",
            None,
        );
        for raw in ["", "   "] {
            let resolved = resolve_with_env(&dir, &Overrides::default(), &|name| {
                (name == "BATTEN_STRICTNESS").then(|| raw.to_owned())
            })
            .expect("an empty env var is not a bad value");
            assert_eq!(resolved.strictness, Strictness::Strict);
            assert_eq!(
                resolved.sources["strictness"].winner(),
                Source::RepoConfig,
                "an empty override must not claim the key"
            );
        }
    }

    #[test]
    fn the_local_file_may_not_restate_an_authority_only_key() {
        // The override layer honours strictness and rules; anything else it
        // parses must be refused, never parsed and dropped. A silently ignored
        // `min_batten_version` would read as applied while doing nothing.
        let dir = repo(
            "resolve-local-authority-key",
            "version = 1\nmin_batten_version = \"0.0.0\"\n",
            Some("version = 1\nmin_batten_version = \"9.9.9\"\n"),
        );
        let err = resolve_with_env(&dir, &Overrides::default(), &no_env).unwrap_err();
        assert!(is_usage_error(&err));
        assert!(
            err.to_string().contains("min_batten_version"),
            "the refusal must name the key, got: {err}"
        );
    }

    #[test]
    fn unknown_env_value_is_a_usage_error() {
        let dir = repo("resolve-env-bad", "version = 1\n", None);
        let err = resolve_with_env(&dir, &Overrides::default(), &|name| {
            (name == "BATTEN_STRICTNESS").then(|| "loose".to_owned())
        })
        .unwrap_err();
        assert!(is_usage_error(&err));
    }

    #[test]
    fn flag_beats_env_and_is_raise_only() {
        let dir = repo("resolve-flag", "version = 1\n", None);
        let env = |name: &str| (name == "BATTEN_STRICTNESS").then(|| "standard".to_owned());
        let resolved = resolve_with_env(
            &dir,
            &Overrides {
                strictness: Some(Strictness::Strict),
                ..Overrides::default()
            },
            &env,
        )
        .unwrap();
        assert_eq!(resolved.strictness, Strictness::Strict);
        assert_eq!(resolved.sources["strictness"].winner(), Source::Flag);

        let err = resolve_with_env(
            &dir,
            &Overrides {
                strictness: Some(Strictness::Permissive),
                ..Overrides::default()
            },
            &env,
        )
        .unwrap_err();
        assert!(is_usage_error(&err), "a flag may not weaken a gate either");
    }

    #[test]
    fn fail_on_warning_layers_through_the_whole_chain() {
        // The one setting, resolved once, reachable from every layer §8 declares
        // — and attributed to the layer that actually set it.
        let off = repo("fow-default", "version = 1\n", None);
        let resolved = resolve_with_env(&off, &Overrides::default(), &no_env).unwrap();
        assert!(!resolved.fail_on_warning, "unset means off");
        assert_eq!(
            resolved.sources["fail_on_warning"].winner(),
            Source::Default
        );

        let committed = repo("fow-repo", "version = 1\nfail_on_warning = true\n", None);
        let resolved = resolve_with_env(&committed, &Overrides::default(), &no_env).unwrap();
        assert!(resolved.fail_on_warning);
        assert_eq!(
            resolved.sources["fail_on_warning"].winner(),
            Source::RepoConfig
        );

        let local = repo(
            "fow-local",
            "version = 1\n",
            Some("version = 1\nfail_on_warning = true\n"),
        );
        let resolved = resolve_with_env(&local, &Overrides::default(), &no_env).unwrap();
        assert!(resolved.fail_on_warning);
        assert_eq!(
            resolved.sources["fail_on_warning"].winner(),
            Source::LocalFile
        );

        let resolved = resolve_with_env(&off, &Overrides::default(), &|name| {
            (name == "BATTEN_FAIL_ON_WARNING").then(|| "true".to_owned())
        })
        .unwrap();
        assert!(resolved.fail_on_warning);
        assert_eq!(resolved.sources["fail_on_warning"].winner(), Source::Env);

        let resolved = resolve_with_env(
            &off,
            &Overrides {
                fail_on_warning: true,
                ..Overrides::default()
            },
            &no_env,
        )
        .unwrap();
        assert!(resolved.fail_on_warning);
        assert_eq!(resolved.sources["fail_on_warning"].winner(), Source::Flag);
    }

    #[test]
    fn a_committed_fail_on_warning_may_not_be_turned_off() {
        // The raise-only clause, over every layer that can express "off". The
        // flag cannot: `--fail-on-warning` has no negative form, which is why it
        // is absent from this list rather than missing from it.
        let dir = repo(
            "fow-weaken-local",
            "version = 1\nfail_on_warning = true\n",
            Some("version = 1\nfail_on_warning = false\n"),
        );
        let err = resolve_with_env(&dir, &Overrides::default(), &no_env).unwrap_err();
        assert!(is_usage_error(&err));
        assert!(
            err.to_string().contains("fail_on_warning")
                && err.to_string().contains("may only tighten"),
            "the refusal must name the key and say why, got: {err}"
        );

        let committed = repo(
            "fow-weaken-env",
            "version = 1\nfail_on_warning = true\n",
            None,
        );
        let err = resolve_with_env(&committed, &Overrides::default(), &|name| {
            (name == "BATTEN_FAIL_ON_WARNING").then(|| "false".to_owned())
        })
        .unwrap_err();
        assert!(is_usage_error(&err), "env may not turn a committed on off");

        // Restating the committed value is not a weakening: it is accepted and
        // re-attributed, exactly as a restated `strictness` is.
        let resolved = resolve_with_env(&committed, &Overrides::default(), &|name| {
            (name == "BATTEN_FAIL_ON_WARNING").then(|| "true".to_owned())
        })
        .unwrap();
        assert_eq!(resolved.sources["fail_on_warning"].winner(), Source::Env);
    }

    #[test]
    fn turning_fail_on_warning_off_below_an_unset_authority_is_allowed() {
        // `false` is the default, so a lower-precedence `false` weakens nothing.
        // Only a *committed on* creates a floor — this is what keeps the clamp a
        // policy rule rather than a blanket ban on writing the key.
        let dir = repo(
            "fow-off-is-not-weakening",
            "version = 1\n",
            Some("version = 1\nfail_on_warning = false\n"),
        );
        let resolved = resolve_with_env(&dir, &Overrides::default(), &no_env).unwrap();
        assert!(!resolved.fail_on_warning);
        assert_eq!(
            resolved.sources["fail_on_warning"].winner(),
            Source::LocalFile
        );
    }

    #[test]
    fn an_empty_fail_on_warning_env_var_means_unset_not_invalid() {
        // Same §10 position as strictness: an unconditional CI export of every
        // knob must not fail the run, and must not claim the key either.
        let dir = repo(
            "fow-env-empty",
            "version = 1\nfail_on_warning = true\n",
            None,
        );
        for raw in ["", "   "] {
            let resolved = resolve_with_env(&dir, &Overrides::default(), &|name| {
                (name == "BATTEN_FAIL_ON_WARNING").then(|| raw.to_owned())
            })
            .expect("an empty env var is not a bad value");
            assert!(resolved.fail_on_warning);
            assert_eq!(
                resolved.sources["fail_on_warning"].winner(),
                Source::RepoConfig
            );
        }
    }

    #[test]
    fn an_unparseable_fail_on_warning_env_value_is_a_usage_error() {
        // Present-but-invalid is refused, never coerced — a `=1` that silently
        // read as `true` would be a gate whose state nobody can predict.
        let dir = repo("fow-env-bad", "version = 1\n", None);
        for raw in ["1", "0", "yes", "TRUE", "on"] {
            let err = resolve_with_env(&dir, &Overrides::default(), &|name| {
                (name == "BATTEN_FAIL_ON_WARNING").then(|| raw.to_owned())
            })
            .unwrap_err();
            assert!(is_usage_error(&err), "{raw:?} must be refused");
            // Weakest-first, the same order `strictness` lists its variants in.
            assert!(
                err.to_string().contains("false, true"),
                "the refusal must name the accepted tokens, got: {err}"
            );
        }
    }

    #[test]
    fn there_is_no_upward_walk() {
        // §8: no directory walk, and CLOUD-70 does not weaken it — it is the
        // property most at risk from "zero-config", so this case is sharper now
        // than when it only had to observe an error. The child resolves to the
        // DEFAULTS; the parent's `strictness = "strict"` must not reach it.
        let parent = repo(
            "resolve-no-walk",
            "version = 1\nstrictness = \"strict\"\n",
            None,
        );
        let child = parent.join("child");
        fs::create_dir_all(&child).unwrap();
        let resolved = resolve_with_env(&child, &Overrides::default(), &no_env).unwrap();
        assert_eq!(resolved.authority, config::Authority::Absent);
        assert_eq!(
            resolved.strictness,
            Strictness::Standard,
            "the parent's config must not be found by walking up"
        );
        assert_eq!(resolved.sources["strictness"].winner(), Source::Default);
    }

    #[test]
    fn an_unconfigured_repository_resolves_to_the_default_layer() {
        // CLOUD-70: absence of the authority IS layer 0, never an error.
        let dir = repo("resolve-zero-config", "version = 1\n", None);
        fs::remove_file(dir.join(config::CONFIG_FILE)).unwrap();
        let resolved = resolve_with_env(&dir, &Overrides::default(), &no_env).unwrap();
        assert_eq!(resolved.authority, config::Authority::Absent);
        assert_eq!(resolved.version, config::SUPPORTED_VERSION);
        assert_eq!(resolved.strictness, Strictness::Standard);
        assert!(!resolved.fail_on_warning);
    }

    #[test]
    fn every_key_of_an_unconfigured_repository_is_attributed_to_default() {
        // The §5 obligation `config show` answers: with no committed file there
        // is no key any layer above the default could have set, and `version` —
        // which used to be hard-coded `repo-config` because the file was
        // required — is the one this would most easily get wrong.
        let dir = repo("resolve-zero-config-sources", "version = 1\n", None);
        fs::remove_file(dir.join(config::CONFIG_FILE)).unwrap();
        let resolved = resolve_with_env(&dir, &Overrides::default(), &no_env).unwrap();
        let document = resolved
            .attributed()
            .expect("every emitted key is attributed");
        for (key, attributed) in &document {
            assert_eq!(
                attributed.source,
                Source::Default,
                "{key} is attributed to {:?} on an unconfigured repository",
                attributed.source
            );
        }
        assert!(document.contains_key("version"), "the scan must find keys");
    }

    #[test]
    fn the_default_rule_survives_resolution() {
        // The defaults are only worth having if they reach the runner: a rule
        // that loads and is dropped by the layering gates nothing.
        let dir = repo("resolve-zero-config-rules", "version = 1\n", None);
        fs::remove_file(dir.join(config::CONFIG_FILE)).unwrap();
        let resolved = resolve_with_env(&dir, &Overrides::default(), &no_env).unwrap();
        assert_eq!(resolved.rules, config::defaults().rules);
        assert!(!resolved.rules.is_empty());
        assert_eq!(resolved.sources["rule"].winner(), Source::Default);
    }

    #[test]
    fn a_committed_authority_declaring_no_rules_gets_no_default_rule() {
        // The defaults are the WHOLE configuration or none of it. Merging one in
        // underneath a committed file would widen a policy its author wrote, and
        // §8 has no layer that may do that.
        let dir = repo("resolve-authority-no-rules", "version = 1\n", None);
        let resolved = resolve_with_env(&dir, &Overrides::default(), &no_env).unwrap();
        assert_eq!(resolved.authority, config::Authority::Present);
        assert!(resolved.rules.is_empty());
        assert_eq!(resolved.sources["version"].winner(), Source::RepoConfig);
    }

    #[test]
    fn a_local_override_still_layers_over_an_absent_authority() {
        // The chain does not lose its upper layers when its first layer is
        // missing — and it stays raise-only, which is what keeps an uncommitted
        // file from being able to weaken the defaults it now sits on.
        let dir = repo(
            "resolve-zero-config-local",
            "version = 1\n",
            Some("version = 1\nstrictness = \"strict\"\n"),
        );
        fs::remove_file(dir.join(config::CONFIG_FILE)).unwrap();
        let resolved = resolve_with_env(&dir, &Overrides::default(), &no_env).unwrap();
        assert_eq!(resolved.strictness, Strictness::Strict);
        assert_eq!(resolved.sources["strictness"].winner(), Source::LocalFile);

        // …and the clamp still refuses a local file that redefines a default
        // rule, exactly as it refuses one redefining a committed rule.
        let redefining = repo(
            "resolve-zero-config-local-redefine",
            "version = 1\n",
            Some(
                "version = 1\n\n[[rule]]\nid = \"no-conflict-markers\"\nkind = \"forbid\"\n\
                 glob = \"nothing/**\"\npattern = \"x\"\nseverity = \"deny\"\n",
            ),
        );
        fs::remove_file(redefining.join(config::CONFIG_FILE)).unwrap();
        let err = resolve_with_env(&redefining, &Overrides::default(), &no_env).unwrap_err();
        assert!(is_usage_error(&err));
        assert!(err.to_string().contains("may not redefine"), "got: {err}");
    }

    #[test]
    fn a_present_but_invalid_authority_still_refuses() {
        // Absence selects the defaults; invalidity never does. A config that
        // silently resolved to the engine's own rules would report green over
        // the rules its author actually wrote.
        for text in [
            "version = = 1\n",
            "version = 1\nbogus = true\n",
            "version = 9\n",
        ] {
            let dir = repo("resolve-zero-config-invalid", text, None);
            let err = resolve_with_env(&dir, &Overrides::default(), &no_env).unwrap_err();
            assert!(is_usage_error(&err), "{text:?} must be refused");
        }
    }

    #[test]
    fn zero_config_resolution_is_byte_stable() {
        // §6, over the layer CLOUD-70 adds: the defaults are a compiled-in
        // constant, so two runs must not differ.
        let dir = repo("resolve-zero-config-stable", "version = 1\n", None);
        fs::remove_file(dir.join(config::CONFIG_FILE)).unwrap();
        let first = resolve_with_env(&dir, &Overrides::default(), &no_env).unwrap();
        let second = resolve_with_env(&dir, &Overrides::default(), &no_env).unwrap();
        assert_eq!(
            serde_json::to_string(&first).unwrap(),
            serde_json::to_string(&second).unwrap()
        );
    }

    #[test]
    fn an_invalid_local_file_is_a_usage_error() {
        // The override file is held to the same narrow surface as the authority.
        let dir = repo(
            "resolve-local-invalid",
            "version = 1\n",
            Some("version = 1\nbogus = true\n"),
        );
        let err = resolve_with_env(&dir, &Overrides::default(), &no_env).unwrap_err();
        assert!(is_usage_error(&err));
    }

    #[test]
    fn resolution_is_byte_stable() {
        // §6: the same input yields the same bytes, sources map included.
        let dir = repo("resolve-stable", "version = 1\n", None);
        let first = resolve_with_env(&dir, &Overrides::default(), &no_env).unwrap();
        let second = resolve_with_env(&dir, &Overrides::default(), &no_env).unwrap();
        assert_eq!(
            serde_json::to_string(&first).unwrap(),
            serde_json::to_string(&second).unwrap()
        );
    }
}
