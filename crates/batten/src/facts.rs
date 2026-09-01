//! The fact model (CLOUD-757): what a fact costs, and where it may be resolved.
//!
//! Batten already runs resolve-at-the-boundary, evaluate-purely.
//! [`crate::hook::adjudicate`] is contractually pure — no I/O, no environment,
//! no clock — and every environmental answer it needs arrives as data the
//! boundary looked up first. What did not exist until this module is a *stated*
//! classification of those answers, so a new one could land unclassified and the
//! promise that `batten hook` builds no runtime (CLOUD-745 item 5, CLOUD-747
//! constraint 3) stayed an intention rather than a type.
//!
//! # Two axes, and why this is a product rather than a fifth rung
//!
//! The obvious model is one ladder — `free`, `read`, `effect`, `stateful` — with
//! the mediated path allowed some prefix of it. That model cannot express the
//! case that forced this issue. **Forge state** (a pull request's mergeability, a
//! check run's conclusion) is bounded, cacheable and one API call: `read` by
//! price. It is still barred from the mediated path, because reaching it means
//! building an HTTP client, and the bound there is the **no-runtime assertion**
//! rather than the price. A ladder has to lie about one of the two.
//!
//! So there are two independent axes:
//!
//! * [`Cost`] — what resolving this *spends*: `free` / `read` / `effect` /
//!   `stateful`.
//! * [`Surface`] — the **narrowest** surface on which it may be resolved:
//!   `hook` / `check` / `verify-only`.
//!
//! | cost \ narrowest surface | hook | check | verify-only |
//! | -- | -- | -- | -- |
//! | free      | yes | yes | yes |
//! | read      | yes | yes | forge facts live here |
//! | effect    | no  | yes | yes |
//! | stateful  | no  | no  | yes |
//!
//! Independence is the whole content of the table: `read` appears in three
//! columns, so knowing the price tells you nothing about the surface, and that
//! is exactly the pair — `read` × `verify-only` — a one-axis model collapses.
//!
//! # Composition takes the meet on **both** axes
//!
//! [`Class::meet`] is what a derived fact is classified by (CLOUD-773): at most
//! as cheap as its **most expensive** input, and at most as wide as its
//! **narrowest** input. A `read`-class rule therefore cannot silently inherit an
//! `effect`-class dependency, and a hook-surface rule cannot silently inherit a
//! verify-only one. Meeting on one axis and inheriting the other would be the
//! same lie the ladder tells, one composition step later.
//!
//! Neither axis derives [`Ord`], deliberately. An ordering invites `a > b` and a
//! bare `max`, which reads as arithmetic over two things that are not numbers;
//! the ordering each axis does have is spelled out in its own exhaustive match,
//! where a new variant stops the crate compiling instead of sorting itself into
//! a silently wrong position.
//!
//! # Stated per fact, never inferred
//!
//! [`crate::rules::RuleKind::carries_ambient_authority`] is the shipped model and this
//! copies it wholesale: every match over an axis is exhaustive with **no
//! wildcard arm**, [`Cost::ALL`] / [`Surface::ALL`] / [`Fact::ALL`] keep the
//! partitions total, and each fact's classification is a `const` written beside
//! the fact rather than derived from its name or its type. A wildcard arm is
//! what would let a new fact default to "cheap and hook-safe", which is the one
//! direction the mistake is expensive in.
//!
//! # Three-valued by default
//!
//! [`Look`] states once what `receipts` has carried since it shipped: a fact
//! distinguishes *is*, *is not*, and **could not look**. `None` in
//! [`crate::hook::ReceiptFacts`] and [`crate::hook::KeyFacts`] is exactly
//! [`Look::CouldNotLook`], and it allows — outside a checkout, on a detached
//! HEAD, or against a base that does not resolve, a gate that cannot look must
//! never become a gate that blocks everything. Naming the third value keeps that
//! posture deliberate rather than an accident of `Option`.
//!
//! # The tree-surface boundary, named while still empty
//!
//! `check` and `enforce` have no `Facts` analogue: `rules::run_rule`
//! reads the file list and dispatches. [`Surface::Check`] is the name that
//! boundary carries. It was named while still EMPTY — stated before anything
//! sat on it, which is what stopped the first fact to land there being
//! classified by whoever happened to write it.
//!
//! **It is not empty, and this paragraph said it was for a day** (CLOUD-849).
//! It read *"every fact classified today sits at [`Surface::Hook`] — which is
//! itself the finding."* [`Fact::Document`] has not since CLOUD-772, and
//! [`DOCUMENT`]'s own doc says so in the opposite words — *"the first fact whose
//! narrowest surface is NOT the hook."* Two claims about one table, a few
//! hundred lines apart, disagreeing: CLOUD-589's class, in the header every
//! reader of this module starts from.
//!
//! The narrower claim is the one that still holds: everything `adjudicate`
//! consumes is hook-resolvable, and the second axis exists for the facts the
//! mediated path must not be made to pay for.

/// What resolving a fact spends.
///
/// The narrow question — the price — with no claim about *where* it may be
/// paid. [`Surface`] answers that, and the two are independent.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Cost {
    /// Already in hand, merely unread: the envelope's own fields, the process's
    /// own environment block. Nothing is spawned, opened, or waited on.
    Free,
    /// A bounded query — one file, one git plumbing call, one clock reading.
    /// Bounded is the operative word: a `check` may hold it.
    Read,
    /// Resolving it runs a program, which is what house-style §5 splits on.
    Effect,
    /// Resolving it needs something warm and outliving the call (CLOUD-671).
    Stateful,
}

impl Cost {
    /// Every cost the model knows, so the partitions above are total.
    ///
    /// A new variant must be added here or `tests/facts.rs`'s
    /// `all_covers_every_cost` fails
    /// — the same guard `RuleKind::ALL` gives `carries_ambient_authority`.
    pub const ALL: &'static [Cost] = &[Cost::Free, Cost::Read, Cost::Effect, Cost::Stateful];

    /// The stable lowercase token (§6).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Cost::Free => "free",
            Cost::Read => "read",
            Cost::Effect => "effect",
            Cost::Stateful => "stateful",
        }
    }

    /// The meet: the **more expensive** of the two.
    ///
    /// Written as an exhaustive match over the pair rather than a comparison, so
    /// adding a rung is a deliberate act at every site that already decided one
    /// — the alternative sorts the new variant into whatever position its
    /// declaration order implies, silently.
    #[must_use]
    pub const fn meet(self, other: Cost) -> Cost {
        match (self, other) {
            (Cost::Free, Cost::Free) => Cost::Free,
            (Cost::Free | Cost::Read, Cost::Read) | (Cost::Read, Cost::Free) => Cost::Read,
            (Cost::Free | Cost::Read | Cost::Effect, Cost::Effect)
            | (Cost::Effect, Cost::Free | Cost::Read) => Cost::Effect,
            (Cost::Free | Cost::Read | Cost::Effect | Cost::Stateful, Cost::Stateful)
            | (Cost::Stateful, Cost::Free | Cost::Read | Cost::Effect) => Cost::Stateful,
        }
    }
}

/// The narrowest surface on which a fact may be resolved.
///
/// Narrowest, not "where it happens to be resolved today": [`Surface::Hook`]
/// means the mediated path may resolve it, and therefore so may every wider
/// surface. [`Surface::VerifyOnly`] is the most restricted value, not the least.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Surface {
    /// Resolvable on the mediated call itself, under CLOUD-689's 100ms budget
    /// and CLOUD-747's no-runtime assertion — and therefore anywhere.
    Hook,
    /// Resolvable by the tree verbs. The boundary this names does not exist yet
    /// (`rules::run_rule` dispatches straight off the file list); naming it is
    /// what keeps the first fact that needs it from inventing its own.
    Check,
    /// Resolvable only where a runtime, a network client or a warm process is
    /// admissible. Forge state lives here at [`Cost::Read`] — bounded, cheap,
    /// and still barred from the hook, which is the pair the second axis exists
    /// to express.
    VerifyOnly,
}

impl Surface {
    /// Every surface the model knows, so the partitions above are total.
    pub const ALL: &'static [Surface] = &[Surface::Hook, Surface::Check, Surface::VerifyOnly];

    /// The stable lowercase token (§6).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Surface::Hook => "hook",
            Surface::Check => "check",
            Surface::VerifyOnly => "verify-only",
        }
    }

    /// The meet: the **narrower** of the two.
    ///
    /// A derived fact is resolvable only where every input is, so composition
    /// moves towards [`Surface::VerifyOnly`] and never away from it.
    #[must_use]
    pub const fn meet(self, other: Surface) -> Surface {
        match (self, other) {
            (Surface::Hook, Surface::Hook) => Surface::Hook,
            (Surface::Hook | Surface::Check, Surface::Check) | (Surface::Check, Surface::Hook) => {
                Surface::Check
            }
            (Surface::Hook | Surface::Check | Surface::VerifyOnly, Surface::VerifyOnly)
            | (Surface::VerifyOnly, Surface::Hook | Surface::Check) => Surface::VerifyOnly,
        }
    }

    /// Whether a fact narrowed to `self` may be resolved while running `on`.
    #[must_use]
    pub const fn admits(self, on: Surface) -> bool {
        match (self, on) {
            (Surface::Hook, Surface::Hook | Surface::Check | Surface::VerifyOnly)
            | (Surface::Check, Surface::Check | Surface::VerifyOnly)
            | (Surface::VerifyOnly, Surface::VerifyOnly) => true,
            (Surface::Check | Surface::VerifyOnly, Surface::Hook)
            | (Surface::VerifyOnly, Surface::Check) => false,
        }
    }
}

/// One fact's classification: a point in the [`Cost`] × [`Surface`] product.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Class {
    /// What resolving it spends.
    pub cost: Cost,
    /// The narrowest surface it may be resolved on.
    pub surface: Surface,
}

impl Class {
    /// Both axes, always. There is no constructor taking one.
    #[must_use]
    pub const fn new(cost: Cost, surface: Surface) -> Class {
        Class { cost, surface }
    }

    /// The meet on **both** axes — the classification of a fact derived from
    /// `self` and `other` (CLOUD-773).
    ///
    /// Meeting one axis and carrying the other through is the defect this
    /// method's existence prevents: it is how a `read`-class rule acquires an
    /// `effect`-class dependency while still reporting itself cheap.
    #[must_use]
    pub const fn meet(self, other: Class) -> Class {
        Class::new(self.cost.meet(other.cost), self.surface.meet(other.surface))
    }

    /// Whether this fact may be resolved while running `on`.
    #[must_use]
    pub const fn resolvable_on(self, on: Surface) -> bool {
        self.surface.admits(on)
    }
}

/// A fact's three-valued answer: *is*, *is not*, and **could not look**.
///
/// The generalisation of the `receipts` contract, which has carried it since it
/// shipped: `None` in [`crate::hook::ReceiptFacts`] is not "looked and found
/// nothing", it is "the question could not be asked", and it **allows**. Keeping
/// the two apart is what makes the fail-open posture a decision rather than a
/// side effect of reaching for `Option`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Look<T> {
    /// Looked, and the fact holds — carrying whatever the boundary read.
    Is(T),
    /// Looked, and the fact does not hold.
    IsNot,
    /// The question could not be asked: no checkout, no base ref, no store.
    CouldNotLook,
}

impl<T> Look<T> {
    /// The stable lowercase token for the arm (§6), never the value.
    ///
    /// Pointer-only by construction (rule 4): a fact's *content* can be a path,
    /// a rev or a secret-adjacent string, and this reports which of the three
    /// answers came back and nothing else.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Look::Is(_) => "is",
            Look::IsNot => "is-not",
            Look::CouldNotLook => "could-not-look",
        }
    }

    /// Whether the boundary failed to reach the question at all.
    #[must_use]
    pub const fn could_not_look(&self) -> bool {
        match self {
            Look::CouldNotLook => true,
            Look::Is(_) | Look::IsNot => false,
        }
    }
}

/// What a rule PRODUCES — the third axis, and the one [`Cost`] structurally
/// cannot carry (CLOUD-851).
///
/// # Why a separate axis rather than a `Cost` arm
///
/// `Cost` describes what resolving a fact SPENDS, and it has no arm meaning
/// "mutates". [`Cost::Effect`] is the near miss and it cannot be repurposed:
/// `rules::tests::the_two_axes_agree_about_every_kind` welds
/// `Cost::Effect | Cost::Stateful` to `RuleKind::carries_ambient_authority()`
/// over every kind x scope pairing, so a kind classified `Effect` that does not
/// spawn goes red there. That test is right and stays. A sink is not a spawn.
///
/// # Three kinds, because the census found three
///
/// Eleven bash writers, sorted by what READS the thing written. That is the
/// distinction that matters — not the file format, and not where it lives:
///
/// * nothing reads it back ([`Production::Journal`]),
/// * a later run reads it back AS A FACT ([`Production::Baseline`]), which is the
///   genuine ratchet and the only kind that makes a decision depend on a
///   previous one,
/// * only its own presence is read ([`Production::Marker`]).
///
/// # The write is the boundary's, always
///
/// A rule declaring a sink stays [`Cost::Read`] on the resolution axis, because
/// it does not perform the write: the decision REQUESTS an effect and the
/// boundary performs it, on [`crate::refusal::Fix::Run`]'s existing shape. That
/// is what keeps `hook::adjudicate` pure with three of the four writing hook
/// bodies on the mediated path.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    serde::Deserialize,
    serde::Serialize,
    schemars::JsonSchema,
)]
#[serde(rename_all = "kebab-case")]
pub enum Production {
    /// An append-only audit trail. Nothing reads it back as a decision input, so
    /// it can never change a verdict — which is exactly why it is the safe kind.
    Journal,
    /// A keyed baseline a LATER run reads back as a fact. The genuine ratchet:
    /// `issue-read.<key>`, `claim.<branch>`, `batten-contract/<session-id>`.
    Baseline,
    /// "Have I already said this." Only presence is read, never content, so the
    /// record is empty by construction and rule 4 holds without a digest.
    Marker,
}

impl Production {
    /// Every production kind the model knows, so a partition over it is total.
    pub const ALL: &'static [Production] = &[
        Production::Journal,
        Production::Baseline,
        Production::Marker,
    ];

    /// The stable lowercase token (§6) — the spelling a `batten.toml` writes.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Production::Journal => "journal",
            Production::Baseline => "baseline",
            Production::Marker => "marker",
        }
    }

    /// Whether a later run reads this kind back, and therefore whether it may
    /// reach the tree surface's input at all.
    ///
    /// **This is the predicate `sink::store` filters on, and for one turn it was
    /// declared and called by nothing.** A journal was loaded into
    /// `input.tree.produced` beside the baselines, so a module could decide on a
    /// digest from a record this module's own doc calls "an audit trail nothing
    /// reads back as a decision input". The statement and the behaviour
    /// disagreed, and the statement was the one with no mechanism — which is
    /// non-negotiable rule 2's failure exactly: a rule without a runnable gate is
    /// half a change, and a predicate with no call site is prose.
    ///
    /// A MARKER READS BACK, and the first version said otherwise. Its content is
    /// empty by construction, but its PRESENCE is the whole fact — "have I
    /// already said this" is answered by the record existing. Excluding it would
    /// have deleted the idempotence kind's only signal while looking like a
    /// tightening.
    #[must_use]
    #[expect(
        clippy::match_same_arms,
        reason = "the two `true` arms are true for DIFFERENT reasons — a baseline's content is the fact, a marker's existence is — and collapsing them would delete the distinction that decides whether an empty record means anything"
    )]
    pub const fn reads_back(self) -> bool {
        match self {
            // The content is the fact.
            Production::Baseline => true,
            // The EXISTENCE is the fact; the content is empty.
            Production::Marker => true,
            // Write-only. Nothing may decide on it, which is what makes it the
            // safe kind rather than merely the cheap one.
            Production::Journal => false,
        }
    }
}

/// The facts `lib.rs`'s `Facts` bundle carries to [`crate::hook::adjudicate`] today.
///
/// One variant per field of that bundle, so "what does this call cost, and where
/// may it be paid" is answerable without reading five modules.
///
/// **DELIBERATELY NOT `#[non_exhaustive]`, and that was tried and reverted.**
/// Adding a variant to a closed enum is an API break, so the obvious move when
/// ten families landed at once was to open it. It cannot be done: `tests/facts.rs`
/// is a separate crate, so `non_exhaustive` forces its census match to carry a
/// wildcard — and that match's whole value is that it has none, because a new
/// fact then fails to COMPILE until somebody states its class. Opening the enum
/// buys downstream compatibility by deleting the gate that makes the model honest
/// (CLOUD-757), which is the wrong trade. The break is declared instead.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Fact {
    /// The `BATTEN_HOOK_BYPASS` hatch (CLOUD-610).
    Bypass,
    /// The receipt verdicts a `requires_receipt` row is judged against.
    Receipts,
    /// The tracker-key evidence a `requires_key` row is judged against.
    Keys,
    /// The end-of-turn facts, default on every event but `Stop`.
    Stop,
    /// The rules a live waiver suppresses today, with each claimed expiry.
    Waived,
    /// A structured document, parsed once and addressed by node path (CLOUD-772).
    Document,
    /// The repository-relative paths the working-tree walk yields — see
    /// [`TRACKED`] for the walk and its bound.
    ///
    /// **Not the git index, despite the token.** The walk honours `.gitignore`,
    /// so an unignored file the index does not carry IS here and an ignored one
    /// is not. `tracked` is the spelling `policy.rs`'s own example established
    /// and consumer modules are written against; stating the difference beside
    /// the variant is cheaper than a rename that would break them, and leaving
    /// it unstated is how a module author writes a predicate about the index and
    /// gets an answer about the checkout.
    Tracked,
    /// A declared file's lines, unparsed.
    Lines,
    /// A **declared** file that lives OUTSIDE the repository root, parsed
    /// (CLOUD-1167).
    ///
    /// **Not a filesystem scanner, and the bound is stated here rather than
    /// trusted to the name** — [`Fact::Tracked`]'s doc is the precedent, and this
    /// variant needs it for a stronger reason: a reader who assumes it reads
    /// `$HOME` freely has assumed a scanner. What it reads is an `[[external]]`
    /// row's `path`, resolved beneath the directory ONE named environment
    /// variable holds. The engine knows how to expand a variable and nothing
    /// else; which variable, and which path beneath it, are the consumer's facts
    /// in the consumer's config, which is what keeps non-negotiable rule 1
    /// satisfied. **A path no row declares is unreadable by any module** — that
    /// negative half is the whole safety property.
    External,
    /// What a command the AGENT ran said, read off the post-tool result buffer
    /// (CLOUD-776).
    AgentSourced,
    /// What a write is about to put on disk, before it happens (CLOUD-758).
    Prospective,
    /// What EARLIER runs produced, keyed (CLOUD-851) — the read half of
    /// [`Production::Baseline`] and of [`Production::Marker`]'s presence test.
    Produced,
    /// Where HEAD is: its commit, the branch it is on, and whether it is
    /// detached (CLOUD-907).
    GitHead,
    /// What the working tree looks like against the index: dirty, staged,
    /// untracked (CLOUD-907).
    GitStatus,
    /// What this checkout is connected to: its remotes and HEAD's upstream
    /// (CLOUD-907).
    GitRemote,
    /// A **declared** ref, resolved — and whether HEAD descends from it
    /// (CLOUD-907).
    GitRef,
    /// A **declared** commit range, as the commits in it (CLOUD-907).
    GitRange,
    /// A **declared** commit range, as each commit's IDENTITY fields — author,
    /// committer and trailers, and no message body (CLOUD-1187).
    ///
    /// **The body's absence is structural, not a habit.** `git::CommitMeta` has
    /// no such field, so a module cannot read one and a later projection cannot
    /// leak one by forgetting to drop it. Non-negotiable rule 4 refuses tracked
    /// content at the boundary rather than at the report, and a message body is
    /// exactly that: prose the author wrote. An identity string and a
    /// `Key: value` trailer are not, which is why these three are admissible and
    /// `%B` is not.
    CommitMeta,
    /// Whether this branch's work is on each **declared** target, by patch
    /// identity (CLOUD-880) — the landing question `Fact::GitRef` leaves open.
    Landing,
    /// A **declared** PATTERN's matching commits — every tag matching a glob, or
    /// the commits that added or deleted a path (CLOUD-1200).
    ///
    /// **The half [`Fact::GitRef`] and [`Fact::GitRange`] structurally cannot
    /// reach.** Those resolve what a rule NAMES; this resolves what it
    /// DESCRIBES, because the answer set is not knowable at declaration time.
    /// What stays declared is the pattern, so a pattern no row names resolves
    /// nothing — the difference between a fact and a git shell.
    ///
    /// Widens WHICH commits are visible, never WHAT one carries: the per-entry
    /// shape is a sha, a subject and (for a tag glob) the tag name.
    GitHistory,
    /// A **declared** path's STAGED bytes, parsed — `git show :<path>`, which
    /// [`Fact::Tracked`] explicitly is not (CLOUD-1203).
    ///
    /// **The index, not the checkout, and the difference is the whole variant.**
    /// `Tracked` walks the working tree; `GitStatus` names the paths that differ
    /// and counts them. Neither can answer what a path SAYS at the point it was
    /// staged, which is the question a gate judging the COMMIT rather than the
    /// developer's working copy has to ask. A successor reading the worktree
    /// instead passes over a staged-but-unsaved edit — a silent wrong answer.
    ///
    /// `Tracked` is deliberately NOT widened to mean this: that would change
    /// every existing consumer's answer without any of them asking.
    Staged,
    /// The forge's verdict for a **declared** SHA, read back from a record a
    /// producer wrote OUTSIDE the engine (CLOUD-1154).
    ///
    /// **The engine opens no socket, and that is the whole shape.** House style
    /// §5 forbids an HTTP client here and the ~100ms mediated budget forbids it
    /// twice over, so the fetch happens once somewhere else — a workflow step, an
    /// agent call — and writes a keyed record this reads. That is
    /// [`AGENT_SOURCED`]'s own argument moved from the hook surface to the tree
    /// one: the same answer that is `verify-only` when the ENGINE would fetch it
    /// is not when something else already did. `evaluator-io-check` stays the
    /// gate on it.
    ///
    /// **Keyed by SHA, and the keying is the safety property.** A record taken
    /// against a different commit is not evidence about this one, so it does not
    /// answer — which is the difference between reading a verdict and inheriting
    /// a stale one.
    Forge,
    /// A **third-party tool's** verdict, read back from a record keyed to the
    /// tool, the version it was pinned at, and the digest of what it read
    /// (CLOUD-1171).
    ///
    /// **[`Fact::Forge`]'s mechanism with a different key, and that is the whole
    /// row.** The producer runs the tool once, outside — a `mise` task, a CI step
    /// — and writes a keyed record; the engine reads it back and spawns nothing.
    /// `check` is `read` and structurally incapable of running a validator, which
    /// is why ~five governed programs that adjudicate one had no successor.
    ///
    /// **The key is a TRIPLE, and each component refuses a different lie.** The
    /// TOOL and its PINNED VERSION, because one validator's answer at v1.1 is not
    /// its answer at v1.2 — CLOUD-646's shape, closed for this path. The INPUT
    /// DIGEST, because a verdict over bytes that have since changed is a verdict
    /// about a file nobody is asking about. A record whose key differs in any
    /// component lives under a different name and does not answer.
    ///
    /// **Deliberately not a benchmark record.** CLOUD-1171's own correction
    /// withdraws that half: `batten perf` already ships and already spawns, so a
    /// measurement was never blocked on a record family. A benchmark key would
    /// also owe a machine identity and a declared null spread, which is a
    /// different design and not this one.
    ToolVerdict,
    /// A **declared** reduction over a response the agent already captured
    /// (CLOUD-1188).
    ///
    /// **The reduction is part of the fact, and that is the whole design.** Ten
    /// board gates are pure predicates that exist as CLI verbs only because they
    /// have nowhere to read from — they take a payload on stdin. A fact carrying
    /// whole payloads would put a tracker's prose on the policy input where any
    /// module can lift it into a `subjects` pointer, so non-negotiable rule 4
    /// would be violated by construction rather than by carelessness. So a row
    /// declares WHAT to reduce and HOW — present, count, or a bounded token — and
    /// the projection carries the answer, never the text it came from.
    ///
    /// **The store, never stdin, and three independent reasons say so.** A
    /// stdin-fed fact declared `Surface::Check` is dropped by
    /// [`Surface::admits`] before projection, so the module silently sees
    /// nothing. A payload on stdin is a payload something read, which is context
    /// re-sent every turn. And the step-receipt key does not include stdin, so
    /// two runs over different payloads on one tree hit one receipt and skip.
    ///
    /// [`crate::capture::list`] is sorted by handle rather than by time, so this
    /// is a pure function of the store's bytes — which is what `Surface::Check`
    /// requires and what stdin could never offer.
    Captured,
    /// The task runner's own argv, read back from a receipt minted OUTSIDE the
    /// mediated call (CLOUD-856).
    ///
    /// **The `Document` arm stays `None`, and this is why it can.** A module
    /// asking *is this argv a weaker form of a task's own* needs the manifest's
    /// task bodies, and parsing a document of unbounded size on every mediated
    /// call would spend the whole invocation budget. So the parse happens once,
    /// at session start where a read of that size is admissible, and the call
    /// reads one small keyed record.
    ///
    /// **Staleness is structural.** The record's key is recomputed at read time
    /// from the manifest as it stands, so a record about a manifest that has
    /// since moved does not answer — could-not-look, never a task table to be
    /// trusted a little.
    ///
    /// `Read` × `Hook` is the honest pair: a file read the mediated path may
    /// make, on the surface it is made from. The EFFECT — asking the runner
    /// anything — is [`PINNED`]'s, already landed, and this does not repeat it.
    Tasks,
    /// The result of a **declared extractor** over the session's own transcript
    /// (CLOUD-1172).
    ///
    /// **Not the transcript, and the distinction is the whole row.** A transcript
    /// is the richest source of secrets the engine can be pointed at — every
    /// command, every file body, every prompt — so a fact carrying its bytes
    /// would be the most direct violation of non-negotiable rule 4 available,
    /// worse than the commit body [`COMMIT_META`] declines to carry, because a
    /// body is authored and a transcript is captured.
    ///
    /// **What reaches a module is a COUNT, and the type is the guarantee.** The
    /// extractor set is closed and every member resolves to an integer over
    /// [`crate::transcript`]'s TYPED events — a tool call's name, a result's
    /// `is_error` flag, a hook run's exit code — never over prose. No span of
    /// session text can reach the policy input by construction rather than by
    /// this projection remembering to drop one.
    ///
    /// **Could-not-look is the COMMON case here** (CLOUD-388: transcripts die
    /// with their container), and it has four distinguishable spellings —
    /// unconfigured, absent, unreadable, and *the extractor ran and matched
    /// nothing*. A gate that confused the first three with the fourth would
    /// report "nothing was stranded" on every host that has no transcript at all.
    Extracted,
    /// The engine's own finding store, as the pointer lines a **declared** ref
    /// accumulated (CLOUD-1203).
    ///
    /// **Not a [`Fact::Produced`] reading under another name**, which the row
    /// required be asked before a variant was added. `Produced` reads a SINK the
    /// consumer declared, keyed by the record's own name; this reads the store
    /// the engine mints for itself, keyed by the REF a finding was observed on.
    /// Different writer, different key, different lifetime — one variant cannot
    /// answer both without a key that means two things.
    State,
    /// What a **declared** Rust source file's call sites invoke, and with what
    /// literal arguments — the token's syntactic POSITION, which no line
    /// predicate can see (CLOUD-914).
    Invocations,
    /// Which module a **declared** Rust source file reaches, resolved through the
    /// crate root's own re-export table (CLOUD-762).
    Uses,
    /// Where the crate uses a type a delegated analyser resolved by NAME, rather
    /// than by spelling (CLOUD-760). The first `Cost::Effect` fact.
    Symbols,
    /// How the **declared** globs' paths differ from a **declared** base rev:
    /// added, edited, deleted (CLOUD-1059).
    BaseDelta,
    /// The lines a **declared** `[[recorder]]` accumulated on this branch
    /// (CLOUD-1051).
    Records,
    /// The programs the project's pin puts on `PATH` (CLOUD-1028).
    ///
    /// **Read here, effect elsewhere, and the split is deliberate.** Asking the
    /// pin runs a program, which the model bars from the mediated path — so what
    /// this fact resolves on a call is the RECORD [`crate::pinned::refresh`]
    /// wrote, keyed to the manifest and lockfile that decide the answer. The
    /// same shape [`Fact::Stop`] takes: the price counted here is the price of
    /// the reading, not of the thing being read.
    Pinned,
}

/// [`Fact::Bypass`] — the hatch is an environment variable, and the kernel
/// handed the process its environment block at `exec`. Reading it spawns
/// nothing, opens nothing and waits on nothing, which is the whole content of
/// [`Cost::Free`].
pub const BYPASS: Class = Class::new(Cost::Free, Surface::Hook);

/// [`Fact::Receipts`] — a file and two git refs (`hook.rs`'s receipt read).
/// Bounded plumbing, which is exactly what a `read`-classified verb may hold,
/// and it is resolved on the mediated path today.
pub const RECEIPTS: Class = Class::new(Cost::Read, Surface::Hook);

/// [`Fact::Keys`] — a bounded `git log` against a base ref. Same shape as
/// [`RECEIPTS`] and the same classification; the `None` both carry is
/// [`Look::CouldNotLook`].
pub const KEYS: Class = Class::new(Cost::Read, Surface::Hook);

/// [`Fact::Stop`] — the at-risk report and the undischarged denials, read from
/// the store on disk. A bounded read, on the mediated path.
pub const STOP: Class = Class::new(Cost::Read, Surface::Hook);

/// [`Fact::Waived`] — the waiver rows rode in with the already-loaded policy, so
/// the one thing actually resolved here is the date, through `waiver::today`.
/// A clock reading is bounded and is not free: it is the single boundary read
/// that keeps *same commit + same date → same bytes* true.
pub const WAIVED: Class = Class::new(Cost::Read, Surface::Hook);

/// [`Fact::Document`] — a local file read and a parse, and the first fact whose
/// narrowest surface is NOT the hook (CLOUD-772). It is `read` by price, exactly
/// like [`RECEIPTS`], and still barred from the mediated path: parsing an
/// arbitrary document is unbounded in the input's size where a git ref read is
/// not, and CLOUD-689's 100ms budget is per mediated call. The two axes moving
/// independently here is the model earning its second axis on a landed fact
/// rather than on the forge facts that motivated it.
pub const DOCUMENT: Class = Class::new(Cost::Read, Surface::Check);

/// [`Fact::Tracked`] — the repository-relative paths the checkout carries
/// (CLOUD-845).
///
/// `read` x `check`, and it sits beside [`DOCUMENT`] on both axes for the same
/// reason: it is a walk of the working tree, unbounded in the size of the
/// repository where a git ref read is not, and CLOUD-689's 100ms budget is per
/// mediated call. A `check` may hold it because `check` is bounded by the
/// repository it is pointed at and says so.
///
/// **It is paths, never content.** That is what keeps it a different fact from
/// [`DOCUMENT`] rather than a cheaper mode of it, and it is what a whole class of
/// gates actually needs — `no-docs-tree`-shaped predicates over *which files
/// exist*. Rule 4 is structural here: there is no byte of any file to leak,
/// because none is read.
pub const TRACKED: Class = Class::new(Cost::Read, Surface::Check);

/// [`Fact::Lines`] — a declared file's lines, unparsed (CLOUD-846).
///
/// `read` x `check`, beside [`DOCUMENT`] and [`TRACKED`], and **Tree/Check only
/// is stated here rather than inherited**: reading a file of unbounded size is
/// unbounded in the input exactly as parsing one is, and CLOUD-689's 100ms
/// budget is per mediated call. This must never be repointed at
/// [`Surface::Hook`] to serve a hook body that wants to read a file.
///
/// **Why lines and not raw text, and why not matches.** Measured, 12 of the 20
/// tree-scoped gates read content no fact could carry — markdown, `.bats`, Rust
/// source — so the ceiling was not four formats' worth of parsing but the
/// absence of any unstructured fact at all. Of the three shapes:
///
/// * **raw text** is the widest and the worst for rule 4: a policy body holding
///   a file's contents is one `msg` away from a payload in a finding, which is
///   why [`crate::policy::Module`] deliberately holds no `source`;
/// * **matches** — the engine applies a declared pattern — is narrowest, and it
///   moves the predicate half back OUT of Rego, which is what the retirement
///   exists to stop;
/// * **lines** is the widest shape that cannot put content into a finding by
///   accident. A module can decide *line 42 matched* and report the path and the
///   number; the content stays on the engine's side of the boundary.
///
/// **Not a fifth parser.** The four markdown gates read tables and headings out
/// of prose; under a lines fact they are line predicates like the rest. A
/// markdown AST would be a parser per prose convention.
pub const LINES: Class = Class::new(Cost::Read, Surface::Check);

/// [`Fact::External`] — a declared file outside the repository root, parsed
/// (CLOUD-1167).
///
/// `read` x `check`, sitting beside [`DOCUMENT`] on both axes and for its
/// reasons: it opens a file and parses it, which is unbounded in the input's
/// size where a git ref read is not, and CLOUD-689's 100ms budget is per
/// mediated call. **Never repoint this at [`Surface::Hook`]** — a hook body that
/// wants to read a launcher's configuration file is precisely the shape the
/// budget exists to refuse.
///
/// # Why this is a projection and not a scanner
///
/// Nine governed programs exist to compare against a file the repository does
/// not contain — a harness's wiring, a toolchain's data directory, a launcher's
/// cache — so each has a successor that cannot see its own subject. The
/// admissible answer to that is **not** "let a module read any path". House
/// style §5's read-only allowlist and non-negotiable rule 1 both refuse a
/// filesystem scanner, and an unbounded `$HOME` read would make this crate know
/// a consumer's directory layout.
///
/// So the bound is three-part and every part is load-time:
///
/// * the set is **declared** — one `[[external]]` row per readable file, and a
///   path no row names resolves nothing for any module;
/// * the root is **one environment variable**, named by the row. The engine
///   expands a variable; it does not know what any particular variable means,
///   which is the line non-negotiable rule 1 draws. A row naming a variable this
///   machine does not set is [`Look::CouldNotLook`], never an absent file;
/// * the path is **relative and downward** — absolute paths and `..` components
///   are refused when the config loads, so a declaration cannot walk back out of
///   the root it named.
///
/// # Content in, pointers out
///
/// The parsed node reaches a module exactly as [`DOCUMENT`]'s does, because a
/// predicate that cannot see the file cannot decide anything about it. What rule
/// 4 governs is the way OUT: a finding over this family carries the declared id
/// and never a byte of the file, which matters more here than anywhere else in
/// the model — these paths hold a consumer's permissions, connector rosters and
/// credentials. The could-not-look channel carries the **id** for the same
/// reason, where every other family carries a path: a resolved absolute path is
/// a machine's home directory, and putting one on the policy input would leak
/// the layout this bound exists to keep out.
pub const EXTERNAL: Class = Class::new(Cost::Read, Surface::Check);

/// [`Fact::Invocations`] — a declared Rust file's call sites, parsed (CLOUD-914).
///
/// `read` x `check`, for [`LINES`]' reasons exactly: parsing a file of unbounded
/// size is unbounded in the input, and CLOUD-689's 100ms budget is per mediated
/// call. Never repoint this at [`Surface::Hook`].
///
/// **What it adds over [`LINES`], stated as the thing a line predicate cannot
/// do.** `lines` answers *does this token appear in this file*; this answers
/// *does this token appear IN COMMAND POSITION*. The tree measures the
/// difference rather than arguing it: five of `git.rs`'s seven source-scan
/// gates assemble their needles by concatenation — `["merge", "-base"].concat()`
/// — for one stated reason, that *"this assertion's own source is not a match
/// for the gate it states"*. The two gates that do NOT obfuscate are exactly the
/// two that never read their own module's source. A substring gate must hide its
/// own literals precisely when its corpus includes itself, and that is the
/// defect this fact retires.
///
/// **Only arguments, never receivers, and that is what makes the discriminator
/// work.** A literal in a call's argument list is an invocation argument; a
/// literal in an array initialiser, a `let` binding, or the receiver of a method
/// call is not. So an `.arg(..)` carrying a banned token is reported and a
/// needle array holding the same token is not — same bytes, same file, opposite
/// verdicts, which is the test this fact lives or dies on. Comments never arrive
/// at all: the parser discards them before this sees a token.
///
/// **This paragraph could not spell its own example, and that is the finding.**
/// It first read `.arg("merge" + "-base")` with the token written plainly, and
/// `git::tests::no_ancestry_decides_merged_ness` went red on `facts.rs` —
/// against PROSE IN A DOC COMMENT, at no call site at all. The guard is behaving
/// exactly as designed; the substring tier simply cannot tell a comment from a
/// call. So the sentence above describes its example instead of writing it, for
/// the same reason five of `git.rs`'s seven gates assemble their needles by
/// concatenation. Measured while documenting the fact that retires the
/// workaround — which is the strongest evidence this row could have asked for,
/// and it arrived unprompted.
///
/// **Rust only, and deliberately.** CLOUD-310 rejected the tree-sitter route on
/// a corpus of 46 extensionless shell programs, and both of its defects are
/// artefacts of that corpus — file discovery, and the bash grammar's fit to
/// `.bats`. Neither reaches `crates/**/*.rs`. What survives its rejection and
/// binds here is the parse-coverage obligation: a file the parser cannot read is
/// [`Look::CouldNotLook`], never an empty node set.
pub const INVOCATIONS: Class = Class::new(Cost::Read, Surface::Check);

/// [`Fact::Uses`] — a declared Rust file's `use` edges, resolved (CLOUD-762).
///
/// `read` x `check`, and the classification is a MEASUREMENT rather than a
/// judgement. CLOUD-762's reversal condition says a bounded, nameable error count
/// puts this tier here and an unbounded one sends it to `Cost::Effect` behind a
/// delegated analyser. Over `crates/batten/src/**` the count is **four**, in two
/// classes, both re-exports — `crates/batten/tests/it/use_graph.rs` asserts it, so
/// the number cannot rot into prose.
///
/// **What a line predicate gets wrong, and in both directions.** `trust.rs` and
/// `output.rs` reach `error` through a name the root re-exports, so a layering
/// gate reading lines is silently green on an edge it exists to judge;
/// `policy.rs` and `sink.rs` read as internal where the root's own private import
/// makes them external, so the same gate invents an edge. Aliases and glob
/// imports move no top-level edge in this tree at all.
///
/// **Cheap AND correct, which the reversal condition did not anticipate.** The
/// re-export table is itself syntax: resolving all four sites needs the crate
/// root's `use` and `pub use` items and nothing else — no name resolution, no
/// analyser, no `Cost::Effect`. Never repoint this at [`Surface::Hook`]; a
/// whole-tree graph is not a per-call question and the 100ms budget is per call.
pub const USES: Class = Class::new(Cost::Read, Surface::Check);

/// [`Fact::AgentSourced`] — a small record under the git dir, written by the
/// boundary from bytes the harness already handed it (CLOUD-776).
///
/// **This is the row that makes the second axis pay for itself.** The table above
/// says forge facts are `read` × `verify-only`: bounded and cacheable by price,
/// and barred from the mediated path because reaching them means building an
/// HTTP client. That bound is about the ENGINE resolving them. An agent-sourced
/// fact is not the engine resolving anything — the agent ran the command, the
/// harness delivered the bytes, and Batten reads a file. So the same underlying
/// answer that is `verify-only` when the engine would fetch it is `hook` when the
/// agent sources it, and the price is a file read either way.
///
/// That is not a loophole in the table; it is the table being about *who
/// resolves* rather than *what is known*, which is what having two axes was for.
pub const AGENT_SOURCED: Class = Class::new(Cost::Read, Surface::Hook);

/// [`Fact::Prospective`] — the content a `Write` or an `Edit` would land
/// (CLOUD-758).
///
/// **`read`, and CLOUD-758's Ready block says `free`.** The correction is worth
/// stating rather than quietly applying, because the issue's whole argument is
/// that this is the cheapest fact in the system and the argument is *nearly*
/// right.
///
/// A `Write` genuinely is free: `tool_input.content` was deserialized before
/// [`crate::hook::adjudicate`] was called, and reading it spawns nothing and
/// opens nothing. But the acceptance also demands *the computed post-edit
/// content of an* `Edit`, and computing that means reading the file off disk —
/// the envelope carries `old_string` and `new_string`, never the surrounding
/// bytes. One bounded file read is exactly [`Cost::Read`], on the same standard
/// that makes [`WAIVED`] `read` for a clock reading.
///
/// So the class is the **meet** of the two acquisition paths, which is what
/// [`Class::meet`] says a composed fact is: at most as cheap as its most
/// expensive input. Classifying it `free` on the strength of the cheaper arm is
/// the ladder-shaped lie this module exists to refuse, one fact down.
///
/// [`Surface::Hook`] is unaffected and is the load-bearing half: the read is
/// bounded, narrowed to calls a rule has already selected for, and needs no
/// runtime — so it sits where [`RECEIPTS`] sits rather than where [`DOCUMENT`]
/// does. Parsing an arbitrary document is unbounded in the input's size; reading
/// the one file a call names is not.
pub const PROSPECTIVE: Class = Class::new(Cost::Read, Surface::Hook);

/// [`Fact::Produced`] — the keyed records earlier runs asked the boundary to
/// write (CLOUD-851).
///
/// `read` x `check`, and both halves are stated rather than inherited.
///
/// `read`, because acquiring it is a bounded file read per declared key, the same
/// price as [`RECEIPTS`] — and emphatically NOT the price of the write, which the
/// rule never performs. A rule declaring a sink still costs a read; the boundary
/// pays for the production separately and after the decision.
///
/// [`Surface::Check`] rather than [`Surface::Hook`], beside [`DOCUMENT`] and
/// [`TRACKED`], because a tree run reads the store for every key its rules
/// declare and that count is unbounded in the ruleset where a single named record
/// is not — [`AGENT_SOURCED`]'s one file is the contrast, and CLOUD-689's 100ms
/// budget is per mediated call. The censused writers this exists for are gate
/// tasks, which is the tree surface; the four hook bodies among them want a
/// hook-resolvable read of one named key, which is a narrower fact than this one
/// and is not this row's to invent.
pub const PRODUCED: Class = Class::new(Cost::Read, Surface::Check);

// The five git facts (CLOUD-907). They are five rather than one BECAUSE THE
// COSTS DIFFER, which is the whole content of CLOUD-757's cost x surface model:
// a single `Fact::Git` would have to take the widest arm of the five, and the
// widest is an unbounded worktree read that would then be legal on a 100ms
// mediated call.
//
// The split is also what the measurement asked for. `bench/gates/RESULTS.md`
// re-derived the corpus by command-position invocation: of the 52 git-bucket
// gate tasks, 30 read git only to locate the repository or to list tracked
// files -- both already resolved -- and the 22 that remain divide 15 head, 11
// log, 4 remote, 2 status, 1 ancestry. A collapsed fact would price the 15
// cheapest reads at the cost of the two most expensive.
//
// EVERY ONE OF THEM IS ACQUIRED ONLY WHEN A RULE DECLARES IT. That is not an
// optimisation, it is what keeps `Cost::Read` honest -- and it is a lesson this
// tree has already paid for once: locating the git dir and reading HEAD
// unconditionally cost `check` a measured p50 of 4.76ms -> 10.01ms (2.103x) in
// CLOUD-851, for a question no rule in the set had asked.

/// [`Fact::GitHead`] — the commit HEAD names, the branch it is on, and whether
/// it is detached.
///
/// `read`: one ref read, and the ref file is open-and-parse with no walk behind
/// it. This is the cheapest of the five and the most asked for, and it is
/// bounded in the same sense [`RECEIPTS`] is — the work does not grow with the
/// repository.
///
/// An empty repository has no HEAD commit, and a detached HEAD has no branch.
/// Both are [`Look::CouldNotLook`] rather than an empty string: Rego reads an
/// undefined path as "does not hold", so a gate asking "is the branch protected"
/// would pass on a detached HEAD if the two collapsed.
///
/// **`Surface::Check` DESPITE THE COST, and the reason is the one this row is
/// named for.** `Surface` names the narrowest surface a fact MAY be resolved on,
/// and by cost this belongs at [`Surface::Hook`] — one ref read, cheaper than
/// [`RECEIPTS`]. It was written that way first, and that draft put `git-head`
/// into `policy-call.schema.json` while the mediated boundary resolved it for
/// nobody: a key `opa check -s` types green and the engine never fills, which is
/// CLOUD-845's defect arriving through the schema built to prevent it. The
/// census is why the gap is not worth closing speculatively — of the 22 gate
/// tasks owing a git fact, every one is a `Gate`-described program `batten
/// check` runs and none is a mediated call. The day a `scope = "mediated_call"`
/// row declares one, this moves to `Hook` together with the narrowing that makes
/// it true, and the wildcard-free matches over [`Fact::ALL`] are what force that
/// edit to be deliberate.
pub const GIT_HEAD: Class = Class::new(Cost::Read, Surface::Check);

/// [`Fact::GitStatus`] — dirty, staged and untracked paths.
///
/// `read` x **`check`**, and the surface is the decision this const exists to
/// record. `status` walks the working tree, so its cost grows with the
/// checkout — the same unboundedness that puts [`DOCUMENT`] and [`TRACKED`] on
/// the tree surface. CLOUD-689's 100ms budget is per mediated call, and a
/// worktree walk inside one is how a `read` classification becomes a lie by
/// degrees.
pub const GIT_STATUS: Class = Class::new(Cost::Read, Surface::Check);

/// [`Fact::GitRemote`] — the configured remotes and HEAD's upstream.
///
/// `read`: config file plus one ref. **No network, ever.** A remote's
/// URL is a line of `.git/config`; asking the remote what it holds would be
/// `Cost::Effect` and a different fact, which this one deliberately is not.
/// A checkout with no remote is [`Look::CouldNotLook`], never an empty list —
/// "there is no remote" and "I could not read the config" are different answers
/// and only one of them should silence a gate.
///
/// `Surface::Check` rather than `Surface::Hook` for [`GIT_HEAD`]'s reason, which
/// is about what the boundary resolves rather than about what this costs.
pub const GIT_REMOTE: Class = Class::new(Cost::Read, Surface::Check);

/// [`Fact::GitRef`] — each **declared** ref, resolved to the commit it names.
///
/// `read`, and DECLARATION is what makes that classification true. The
/// cost is one ref resolution per declared name, so it is bounded by the ruleset
/// rather than by the repository. An ambient sweep of `refs/` would be the same
/// fact at a different price, which is exactly the drift `documents` is bounded
/// against.
///
/// A ref that does not resolve is [`Look::CouldNotLook`], carried as absence
/// from the map. `origin/main` missing in a shallow or freshly-cloned checkout
/// is not an answer about that ref, and a gate reading a fabricated one would
/// report a verdict with full confidence.
///
/// **THE COMMIT, AND NOT WHETHER HEAD DESCENDS FROM IT.** The first version
/// carried the reachability answer beside the sha and
/// `no_ancestry_decides_merged_ness` refused it: CLOUD-36 decides merged-ness by
/// PATCH IDENTITY, because a rebased landing is invisible to ancestry. The
/// landing question has an answer already — `git::landing` — and CLOUD-880 is
/// the row that makes it a fact family.
///
/// `Surface::Check` rather than `Surface::Hook` for [`GIT_HEAD`]'s reason.
pub const GIT_REF: Class = Class::new(Cost::Read, Surface::Check);

/// [`Fact::GitRange`] — the commits in each **declared** range.
///
/// `read` x **`check`**. Declared, like [`GIT_REF`], but declaration does not
/// bound it: `origin/main..HEAD` is one declaration and an unknown number of
/// commits, so the surface is the tree's the way [`DOCUMENT`]'s is. The
/// declaration bounds WHICH ranges are read, never how much each costs.
///
/// Pointer-only at the boundary (non-negotiable rule 4): a commit is its sha and
/// its subject, and a subject is what the log renders as a pointer to the
/// commit. No message body, no diff, no line of a tracked file.
/// [`Fact::CommitMeta`] — a declared range's commits, as their identity fields
/// (CLOUD-1187).
///
/// `read` x `check`, beside [`GIT_RANGE`], and the classification is the same
/// claim one level down: the engine ALREADY computes these three fields in
/// `git::commit_record`, in process via `gix` under `open::Options::isolated`,
/// so there is no spawn and no cost-class change. What was missing was a
/// projection.
///
/// **Cost, stated rather than borrowed.** Range length is unbounded per
/// declaration — `origin/main..HEAD` is one declaration and an unknown number of
/// commits — and this peels an object per commit where [`GIT_RANGE`] reads a
/// subject, so it multiplies an already-unbounded term by more than a constant.
/// The ~5.4 µs-per-document figure in `.claude/rules/rust.md` was measured over
/// `documents` and does NOT cover this arm; measure it rather than quote it.
/// That cost is why the declaration is its own column rather than riding
/// `ranges`: a row wanting subjects must not be made to pay for it.
pub const COMMIT_META: Class = Class::new(Cost::Read, Surface::Check);

pub const GIT_RANGE: Class = Class::new(Cost::Read, Surface::Check);

/// [`Fact::Landing`] — whether this branch's work is on each **declared** target,
/// by patch identity (CLOUD-880).
///
/// **The fact [`GIT_REF`] deliberately does not carry.** That row's own header
/// says so: it dropped the reachability answer because `no_ancestry_decides_
/// merged_ness` refused it, since CLOUD-36 decides merged-ness by PATCH IDENTITY
/// and a rebased landing is invisible to ancestry. `git::landing` has computed
/// that answer since CLOUD-36; what it lacked was a way for a rule to ask.
///
/// `read`, and DECLARATION is what makes that honest, exactly as it does for
/// [`GIT_REF`]. A run whose rules name no landing target resolves nothing, and
/// the cost is one scan per declared target rather than a sweep of the trunk.
///
/// **The cost is real and the surface says so.** A scan walks the head-side
/// commits and computes a patch id per commit, so this is `Surface::Check` and
/// never `Hook` — not because the boundary declines to resolve it, but because a
/// per-commit `git patch-id` inside a ~100ms mediated call is not a budget it
/// fits. [`GIT_RANGE`] is classified on the same reading.
///
/// **Could-not-look is a distinct answer, and here it is the one that matters
/// most.** An unresolvable target, an empty repository, or a scan that failed are
/// absence from the map — never "nothing is landed". Rego reads an undefined path
/// as *does not hold*, so a fabricated negative would report unlanded work with
/// full confidence, which is the direction that lets a gate pass on ignorance.
/// [`Fact::Staged`] — a declared path's staged bytes (CLOUD-1203).
///
/// `read` x `check`, beside [`DOCUMENT`] and for its reasons: it reads a blob of
/// unbounded size, and CLOUD-689's 100ms budget is per mediated call.
///
/// **Bounded by declaration, like every other read in the family.** A path no
/// row names is not staged-read, so this is a projection rather than an index
/// dump — and the index is exactly as large as the tree.
/// [`Fact::GitHistory`] — a declared pattern's matching commits (CLOUD-1200).
///
/// `read` x `check`, beside [`GIT_RANGE`], and in process via `gix` under the
/// same isolated open — no spawn, no cost-class change.
///
/// **Cost, stated rather than borrowed.** A tag glob over a long history is
/// unbounded per declaration, the same shape [`GIT_RANGE`]'s own comment records,
/// and a path query WALKS that history comparing two trees per commit. The
/// ~5.4 µs-per-document figure in `.claude/rules/rust.md` was measured over
/// `documents` and does not cover this arm; measure it rather than quote it.
///
/// A shallow clone resolves the whole family as could-not-look rather than a
/// partial answer, which is why this can be `Cost::Read` honestly: the expensive
/// case is the one it refuses to half-answer.
pub const GIT_HISTORY: Class = Class::new(Cost::Read, Surface::Check);

pub const STAGED: Class = Class::new(Cost::Read, Surface::Check);

/// [`Fact::Forge`] — the forge's verdict for a declared SHA (CLOUD-1154).
///
/// `read` x `check`, beside [`PRODUCED`] and [`RECORDS`]: it reads a record off
/// disk that something else wrote. **Not `verify-only`**, and that is the axis
/// earning itself — forge state is `read` x `verify-only` when the engine would
/// FETCH it, and this fact is what a producer already fetched, so the surface
/// moves while the price does not.
///
/// The bound is the declaration: a SHA no row names resolves nothing, so this
/// cannot become an ambient sweep of whatever records happen to be on disk.
pub const FORGE: Class = Class::new(Cost::Read, Surface::Check);

/// [`Fact::ToolVerdict`] — a third-party tool's verdict, per declared key
/// (CLOUD-1171).
///
/// `read` x `check`, and it is [`FORGE`]'s argument a second time: the SPAWN is
/// the producer's, outside the engine, so what remains here is a record off disk
/// and a digest of the bytes it was taken over. Classifying it [`Cost::Effect`]
/// would name a cost this fact does not pay and would put a validator inside
/// `check`, which house style §5 makes structurally impossible.
///
/// The bound is the declaration: a tool no row names resolves nothing.
pub const TOOL_VERDICT: Class = Class::new(Cost::Read, Surface::Check);

/// [`Fact::Captured`] — a declared reduction over a captured response
/// (CLOUD-1188).
///
/// `read` x `check`, beside [`PRODUCED`] and [`RECORDS`]: a listing off disk that
/// something else populated. **Not `verify-only`**, and that is [`FORGE`]'s
/// argument once more — the same answer is `verify-only` when the ENGINE would
/// fetch it and is not when the agent already did, because the table is about who
/// resolves rather than about what is known.
///
/// The bound is the declaration AND the reduction: a key no row names resolves
/// nothing, and what a named key yields is a token rather than a payload.
pub const CAPTURED: Class = Class::new(Cost::Read, Surface::Check);

/// [`Fact::Tasks`] — the task runner's argv, from a receipt (CLOUD-856).
///
/// `read` x `hook`, and both halves are the row's answer rather than a default.
/// `Read` because the mediated path opens ONE small record: the manifest parse it
/// replaces is where the unbounded cost lived, and that has moved to session
/// start. `Hook` because the consumer is a mediated-call guard — and `Hook` is the
/// NARROWEST surface a fact may be resolved on, so the tree surface may resolve it
/// too if a gate ever wants it.
///
/// Deliberately NOT [`Cost::Effect`]: asking the runner is an effect and is
/// [`PINNED`]'s, already landed under the same store. Classifying this one
/// `Effect` would claim a cost it does not pay and put a spawn on the hot path.
pub const TASKS: Class = Class::new(Cost::Read, Surface::Hook);

/// [`Fact::Extracted`] — a declared extractor's result over the session's own
/// transcript (CLOUD-1172).
///
/// `read` x `hook`. `Read` because it opens one path the HOST handed over and
/// parses it; `Hook` because the transcript is a property of the session, and the
/// session is what the mediated surface is inside. A tree-scoped run has no
/// session to ask about, which is why this is the narrower surface rather than
/// the wider one.
pub const EXTRACTED: Class = Class::new(Cost::Read, Surface::Hook);

/// [`Fact::State`] — the engine's own finding store, per declared ref
/// (CLOUD-1203).
///
/// `read` x `check`, matching [`PRODUCED`] and [`RECORDS`], which are already
/// out-of-tree keyed reads on the check surface. It is a listing off disk: no
/// spawn, no network, and nothing a `check` is not already allowed to do.
///
/// **Keyed by ref, and that is the safety property.** A finding observed on
/// another branch is not evidence about this one, so a listing keyed elsewhere
/// simply is not in the map — the same shape `git-refs` uses, where a ref that
/// does not resolve is absent rather than present with a null.
pub const STATE: Class = Class::new(Cost::Read, Surface::Check);

pub const LANDING: Class = Class::new(Cost::Read, Surface::Check);

/// [`Fact::Symbols`] — **the first occupant of [`Cost::Effect`]**, and the
/// reserved variant stops being empty for a stated reason.
///
/// `effect` x `check`, and each half is a decision rather than an inference.
///
/// **`Cost::Effect` because resolving it RUNS A PROGRAM**, which is the whole
/// content of that variant and the only thing it claims. Every other fact in this
/// table is `Free` or `Read`; this one spawns `cargo clippy` and waits for it.
/// Naming that honestly is the point — a fact that spawned while classified
/// `Read` would make the cost axis decorative.
///
/// **`Surface::Check`, and `Surface::Hook` is REFUSED.** `run_static` already
/// refuses a spawning kind outright, and a fact resolvable on the mediated path
/// would weaken that promise from a structural guarantee into a convention.
/// `resolvable_on` is what enforces it, and `tests/facts.rs`'s exhaustive match
/// is what keeps the refusal from being merely intended.
///
/// **`check` RESOLVES IT DIRECTLY rather than consuming a receipt, and that is
/// the §5 decision CLOUD-760 left open.** The receipt route was the tempting one
/// — `verify` already writes SHA-keyed receipts that `hook` reads — and it is
/// refused here for a reason that is about honesty rather than machinery: a
/// receipt-backed fact is a claim about a tree some EARLIER run saw, and `check`
/// consuming one would report a census of a tree that is not the one in front of
/// it. The cost axis exists precisely so an expensive fact can be declared
/// expensive instead of being made to look cheap. A caller that cannot afford it
/// does not ask for it; that is what `Class` is for.
///
/// The amortisation argument survives and is not this row's: a receipt-backed
/// SECOND class of the same fact is buildable later, and would be a different
/// `Class` rather than a quiet reinterpretation of this one.
pub const SYMBOLS: Class = Class::new(Cost::Effect, Surface::Check);
/// [`Fact::BaseDelta`] — how the **declared** globs' paths differ from a
/// **declared** base rev (CLOUD-1059).
///
/// `read` x **`check`**, for [`GIT_RANGE`]'s reason and one of its own. Declared
/// on both axes — which globs and which base — but neither declaration bounds the
/// cost: a glob is a selection over the whole tree, and answering it walks the
/// base tree once and the working tree once. That is a `check`-surface walk, not
/// something a ~100ms mediated call absorbs.
///
/// Pointer-only at the boundary (non-negotiable rule 4): three lists of
/// repo-relative paths. Never a hunk, never a line, never the content that
/// changed — the same bound [`GIT_STATUS`] holds, and for the same reason, since
/// a migration gate needs to know WHICH files moved and never what they say.
pub const BASE_DELTA: Class = Class::new(Cost::Read, Surface::Check);

/// [`Fact::Records`] — the lines a declared recorder accumulated (CLOUD-1051).
///
/// `read` x **`check`**, and the second axis is the interesting one because the
/// obvious reading is wrong. The record is ONE branch-keyed file, so by price
/// this is [`RECEIPTS`]'s equal and the hook could hold it. It sits on `check`
/// anyway, because the consumer decides at LANDING: the gate reading it asks
/// whether a row this branch filed names code this branch has open, and that
/// question needs the branch's whole diff beside it — a fact that is already
/// `check`-only for its own unbounded-walk reason. Projecting the record onto a
/// surface where its counterpart cannot follow would put half a predicate within
/// reach and leave the gate unwritable.
///
/// Pointer-only holds by construction rather than by care: a recorder's columns
/// are already whitespace-free tokens, and every one of them is a count, an id or
/// a tracked path — never a line of the body that produced it.
pub const RECORDS: Class = Class::new(Cost::Read, Surface::Check);

/// [`Fact::Pinned`] — one file read under `$GIT_DIR`, keyed to the manifest and
/// the lockfile.
///
/// **`Read`, not `Effect`, and the reason is which act this classifies.**
/// Resolving the set from the pin spawns, and an `Effect` fact may not sit on
/// the hook — so the spawn happens once, off this surface, and what a mediated
/// call performs is the read of what it wrote. Classifying the read by the price
/// of its producer would bar the fact from the only surface that has a consumer,
/// and would say something false about what a call costs.
pub const PINNED: Class = Class::new(Cost::Read, Surface::Hook);

impl Fact {
    /// Every fact the boundary resolves today, so [`Fact::class`] is total.
    pub const ALL: &'static [Fact] = &[
        Fact::Bypass,
        Fact::Receipts,
        Fact::Keys,
        Fact::Stop,
        Fact::Waived,
        Fact::Document,
        Fact::Tracked,
        Fact::Lines,
        Fact::External,
        Fact::AgentSourced,
        Fact::Prospective,
        Fact::Produced,
        Fact::GitHead,
        Fact::GitStatus,
        Fact::GitRemote,
        Fact::GitRef,
        Fact::GitRange,
        Fact::CommitMeta,
        Fact::Landing,
        Fact::GitHistory,
        Fact::Staged,
        Fact::State,
        Fact::Forge,
        Fact::ToolVerdict,
        Fact::Captured,
        Fact::Tasks,
        Fact::Extracted,
        Fact::Invocations,
        Fact::Uses,
        Fact::Symbols,
        Fact::BaseDelta,
        Fact::Records,
        Fact::Pinned,
    ];

    /// The stable lowercase token (§6) — the field name in `lib.rs`'s `Facts`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Fact::Bypass => "bypass",
            Fact::Receipts => "receipts",
            Fact::Keys => "keys",
            Fact::Stop => "stop",
            Fact::Waived => "waived",
            Fact::Document => "document",
            Fact::Tracked => "tracked",
            Fact::Lines => "lines",
            Fact::External => "external",
            Fact::AgentSourced => "agent-sourced",
            Fact::Prospective => "prospective",
            Fact::Produced => "produced",
            Fact::GitHead => "git-head",
            Fact::GitStatus => "git-status",
            Fact::GitRemote => "git-remote",
            Fact::GitRef => "git-refs",
            Fact::GitRange => "git-ranges",
            Fact::CommitMeta => "commit-meta",
            Fact::Landing => "landing",
            Fact::GitHistory => "git-history",
            Fact::Staged => "staged",
            Fact::State => "state",
            Fact::Forge => "forge",
            Fact::ToolVerdict => "tool-verdict",
            Fact::Captured => "captured",
            Fact::Tasks => "tasks",
            Fact::Extracted => "extracted",
            Fact::Invocations => "invocations",
            Fact::Uses => "uses",
            Fact::Symbols => "symbols",
            Fact::BaseDelta => "base-delta",
            Fact::Records => "records",
            Fact::Pinned => "pinned-programs",
        }
    }

    /// This fact's classification — the stated `const` beside it, returned
    /// rather than recomputed.
    ///
    /// The indirection is the point: the classification is written next to the
    /// fact it describes, and this match is the only thing that could disagree
    /// with it. `tests/facts.rs`'s `every_fact_returns_its_stated_const` closes that gap,
    /// and the exhaustive match with no wildcard arm closes the other one — a
    /// new variant fails to compile rather than defaulting to cheap.
    #[must_use]
    pub const fn class(self) -> Class {
        match self {
            Fact::Bypass => BYPASS,
            Fact::Receipts => RECEIPTS,
            Fact::Keys => KEYS,
            Fact::Stop => STOP,
            Fact::Waived => WAIVED,
            Fact::Document => DOCUMENT,
            Fact::Tracked => TRACKED,
            Fact::Lines => LINES,
            Fact::External => EXTERNAL,
            Fact::AgentSourced => AGENT_SOURCED,
            Fact::Prospective => PROSPECTIVE,
            Fact::Produced => PRODUCED,
            Fact::GitHead => GIT_HEAD,
            Fact::GitStatus => GIT_STATUS,
            Fact::GitRemote => GIT_REMOTE,
            Fact::GitRef => GIT_REF,
            Fact::GitRange => GIT_RANGE,
            Fact::CommitMeta => COMMIT_META,
            Fact::Landing => LANDING,
            Fact::GitHistory => GIT_HISTORY,
            Fact::Staged => STAGED,
            Fact::State => STATE,
            Fact::Forge => FORGE,
            Fact::ToolVerdict => TOOL_VERDICT,
            Fact::Captured => CAPTURED,
            Fact::Tasks => TASKS,
            Fact::Extracted => EXTRACTED,
            Fact::Invocations => INVOCATIONS,
            Fact::Uses => USES,
            Fact::Symbols => SYMBOLS,
            Fact::BaseDelta => BASE_DELTA,
            Fact::Records => RECORDS,
            Fact::Pinned => PINNED,
        }
    }

    /// The key this fact is projected under in the **tree** input document, or
    /// `None` for a fact the tree surface does not carry (CLOUD-845).
    ///
    /// **Why this is not [`Fact::as_str`].** The mediated document keys straight
    /// off `as_str`, and the tree document would too if it were being designed
    /// now — but `input.tree.documents` shipped in CLOUD-833 and consumer modules
    /// are written against it. Renaming a shipped input key to save an accessor
    /// would break every module the retirement campaign is about to write, so the
    /// spelling is stated instead.
    ///
    /// **Stated beside the fact, exactly like [`Fact::class`].** The point of the
    /// indirection is that the vocabulary lives in one place and the projection
    /// reads it: `rules::tree_document` iterates [`Fact::ALL`] and asks this,
    /// rather than hand-writing keys that then drift from the model. That drift
    /// is precisely CLOUD-845 — `input.tree.tracked` was documented, never built,
    /// and nothing could tell, because no table said what the tree emits.
    ///
    /// Exhaustive with no wildcard arm, so a new fact must decide here whether
    /// the tree carries it rather than defaulting to absent — and absent is the
    /// shape a Rego predicate reads as silently undefined.
    #[must_use]
    pub const fn tree_key(self) -> Option<&'static str> {
        match self {
            Fact::Document => Some("documents"),
            Fact::Tracked => Some("tracked"),
            Fact::Lines => Some("lines"),
            // CLOUD-1167. Tree-only, like the three above and for their
            // reason: opening and parsing a file is a `check`-surface cost.
            // The key is the DECLARED ID rather than a path, which is what
            // keeps a machine's home directory off the policy input.
            Fact::External => Some("external"),
            Fact::Produced => Some("produced"),
            // The five git facts (CLOUD-907). All five reach the tree surface,
            // and three of them are `Surface::Hook` — which is not a
            // contradiction but the axis working as documented: `Hook` is the
            // NARROWEST surface a fact may be resolved on, so every wider one
            // may resolve it too. The consumers this row exists for are the 22
            // gate tasks the census leaves owing a fact, and a gate is the tree
            // surface.
            Fact::GitHead => Some("git-head"),
            Fact::GitStatus => Some("git-status"),
            Fact::GitRemote => Some("git-remote"),
            Fact::GitRef => Some("git-refs"),
            Fact::GitRange => Some("git-ranges"),
            // CLOUD-1187. Tree-only like the rest of the family, and for a
            // sharper reason: it peels a commit object per commit in the range.
            Fact::CommitMeta => Some("commit-meta"),
            // The landing family (CLOUD-880). A gate is the tree surface, and
            // every consumer this row exists for -- the tasks that today read a
            // sibling's exit code to learn whether work landed -- is one.
            Fact::Landing => Some("landing"),
            // CLOUD-1203. Tree-only: reading the index is a `check`-surface
            // cost, and the store is a listing a mediated call has no occasion
            // to want.
            // CLOUD-1200. Tree-only: a history walk is a `check`-surface cost.
            Fact::GitHistory => Some("git-history"),
            Fact::Staged => Some("staged"),
            Fact::State => Some("state"),
            // CLOUD-1154. Tree-only: a mediated call has no SHA to ask about
            // and no budget to read a record set.
            Fact::Forge => Some("forge"),
            // CLOUD-1171. Tree-only for `forge`'s reason and one more: the
            // digest half opens the declared input, which is a `check`-surface
            // cost and not a mediated call's.
            Fact::ToolVerdict => Some("tool-verdict"),
            // CLOUD-1188. Tree-only: reducing a response means reading and
            // parsing every capture the store holds until a declared key
            // matches, which is a `check`-surface cost. The consumers are board
            // gates, and a gate is the tree surface by construction.
            Fact::Captured => Some("captured"),
            // Tree-only by construction (CLOUD-914): a call site is a property
            // of committed source, and the mediated path has no budget to parse
            // one.
            Fact::Invocations => Some("invocations"),
            Fact::Uses => Some("uses"),
            // The resolved-symbol tier (CLOUD-760). Tree surface like the two
            // above, and `Cost::Effect` where they are `Read` — the cost axis is
            // independent of the surface one, which is exactly what makes the
            // pair expressive rather than redundant.
            Fact::Symbols => Some("symbols"),
            // Tree-only for the same reason (CLOUD-1059): the answer is a walk
            // of the base tree and a walk of the working tree, which is a
            // `check`-surface cost and not a mediated call's.
            Fact::BaseDelta => Some("base-delta"),
            Fact::Records => Some("records"),
            // Hook-surface facts. The tree engine resolves none of them, and
            // naming them here as `None` is what lets the correspondence test
            // assert the emitted key set in BOTH directions rather than only
            // checking that what is emitted is legal.
            // `Prospective` is here for a sharper reason than the rest, and it
            // is worth stating rather than folding in: the others are hook-only
            // because the tree engine has no occasion to resolve them, where
            // this one is hook-only because THE QUESTION DOES NOT EXIST on the
            // tree surface. A tree scan reads what a file contains; a
            // prospective fact is what a file would contain if a call it has not
            // made yet were allowed. Naming it `Some(..)` would invite a Rego
            // predicate to ask the tree what a write is about to do, which is a
            // question with no answer rather than an answer of none.
            Fact::Bypass
            | Fact::Receipts
            | Fact::Keys
            | Fact::Stop
            | Fact::Waived
            | Fact::AgentSourced
            // Hook-only for CLOUD-856's own reason rather than by default: the
            // record exists so the MEDIATED call need not parse a document, and
            // a tree-scoped gate that wants the task table can declare the
            // document directly and pay for it there.
            | Fact::Tasks
            // Hook-only, and structurally so (CLOUD-1172): the subject is THIS
            // session's transcript, which the host hands to the boundary. A tree
            // run has no session to ask about, so the question does not exist
            // there rather than being one the tree declines to answer.
            | Fact::Extracted
            | Fact::Prospective
            // Hook-surface too, and deliberately not offered to the tree: the
            // question it answers is about a COMMAND — was this program reached
            // through the pin — and a tree walk has no command to ask it of. A
            // gate wanting the same set asks the pin directly, which it may,
            // being an `Effect` surface (CLOUD-1028).
            | Fact::Pinned => None,
        }
    }

    /// The JSON Schema fragment this fact is projected as, on whichever surface
    /// carries it (CLOUD-879).
    ///
    /// **Stated beside the fact, for [`Fact::class`]'s reason and one more.**
    /// The two schemas in `schema/` were hand-written, and a hand-written schema
    /// beside a derived projection is the drift CLOUD-845 is: `input.tree.tracked`
    /// was documented and never emitted, and nothing could tell. Deriving the
    /// document from this makes a fact that gains a surface gain a schema entry in
    /// the same edit, and `opa check -s` then refuses a module reading a key the
    /// engine never emits — the build-time half CLOUD-876 bought.
    ///
    /// **Shape, never content.** A fragment constrains the container and says what
    /// the fact is; it deliberately does not constrain what a consumer's document
    /// holds inside it. Typing somebody else's TOML is not this schema's job, and
    /// a fragment that tried would refuse valid consumer config at build time.
    ///
    /// Exhaustive with no wildcard arm, like the two matches above: a new fact
    /// decides its schema here or fails to compile.
    #[must_use]
    pub fn schema_fragment(self) -> serde_json::Value {
        match self {
            Fact::Document => serde_json::json!({
                "type": "object",
                "description": "Fact::Document. Path -> the parsed node. Contents are arbitrary consumer TOML/YAML/JSON, so values are deliberately unconstrained; the schema's job here is the key set one level up, not the shape of somebody else's config.",
                "additionalProperties": true,
            }),
            Fact::Tracked => serde_json::json!({
                "type": "array",
                "description": "Fact::Tracked. Repository-relative paths the working-tree walk yields -- paths, never content.",
                "items": {"type": "string"},
            }),
            Fact::Lines => serde_json::json!({
                "type": "object",
                "description": "Fact::Lines. Path -> the file's lines, unparsed (CLOUD-846).",
                "additionalProperties": {"type": "array", "items": {"type": "string"}},
            }),
            Fact::External => Self::external_schema_fragment(),
            Fact::Invocations => serde_json::json!({
                "type": "object",
                "description": "Fact::Invocations (CLOUD-914). Path -> the call sites in that Rust file, each `program` (the callee as written), `arguments` (the string literals it PASSES -- never its receiver) and `line`. A path absent from this map is could-not-look: the parser could not read it. A path present with an empty list is a file that parsed and calls nothing. Rego reads an undefined path as `does not hold`, so those two must never collapse.",
                "additionalProperties": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "program": {"type": "string"},
                            "arguments": {"type": "array", "items": {"type": "string"}},
                            "line": {"type": "integer"},
                        },
                        "additionalProperties": false,
                    },
                },
            }),
            Fact::Staged
            | Fact::State
            | Fact::Forge
            | Fact::ToolVerdict
            | Fact::Captured
            | Fact::Produced
            | Fact::Records => Self::keyed_read_schema_fragment(self),
            Fact::Symbols => Self::symbols_schema_fragment(),
            Fact::Uses => serde_json::json!({
                "type": "object",
                "description": "Fact::Uses (CLOUD-762). Path -> that file's `use` edges. `to` is the module or crate reached AFTER resolution through the crate root's re-export table; `item` the imported leaf name; `origin` one of internal/external/root-item/local; `via_root` whether resolution supplied `to` rather than the text, which is the flag that marks an edge a line predicate reads wrongly. An edge still `root-item` is one the root's table could not name, and is could-not-look at the edge level rather than an edge onto nothing. A path absent from this map could not be parsed; a path present with an empty array imports nothing.",
                "additionalProperties": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "to": {"type": "string"},
                            "item": {"type": "string"},
                            "origin": {"type": "string"},
                            "via-root": {"type": "boolean"},
                            "line": {"type": "integer"},
                        },
                        "additionalProperties": false,
                    },
                },
            }),
            Fact::Bypass => serde_json::json!({
                "type": "boolean",
                "description": "Fact::Bypass -- the BATTEN_HOOK_BYPASS hatch (CLOUD-610). The one fact whose shape is certain enough to constrain.",
            }),
            // The description-only family delegates, for the same reason and
            // along the same kind of seam as the git family below: every one of
            // these constrains nothing but its own prose, so a match arm each
            // buys no readability that one table does not.
            Fact::Receipts
            | Fact::Keys
            | Fact::Stop
            | Fact::Waived
            | Fact::AgentSourced
            | Fact::Prospective
            | Fact::Tasks
            | Fact::Extracted => Self::described_schema_fragment(self),
            Fact::Pinned => Self::pinned_schema_fragment(),
            // The git and landing families delegate (CLOUD-880). Extracted
            // because this function hit its own 100-line ceiling when `Landing`
            // arrived, and the ceiling is right: a match arm per fact is readable
            // and a match arm per fact for twenty facts is not. Split along the
            // seam that already exists rather than by line count.
            Fact::BaseDelta => serde_json::json!({
                "type": ["object", "null"],
                "description": "Fact::BaseDelta (CLOUD-1059). How the declared globs' paths differ from the declared base rev: `added` present now and not at base, `edited` present in both with different content, `deleted` present at base and not now. Repo-relative paths only -- never a hunk and never a line, non-negotiable rule 4. NULL when the base rev does not resolve, never an empty delta: `this branch changed nothing` and `I could not read the base` are the two answers a migration gate must keep apart, and a fabricated empty set passes the gate on ignorance.",
                "properties": {
                    "added": {"type": "array", "items": {"type": "string"}},
                    "edited": {"type": "array", "items": {"type": "string"}},
                    "deleted": {"type": "array", "items": {"type": "string"}},
                    // CLOUD-1051. A subset of the three above: the paths whose
                    // non-comment remainder moved. Serialized as `code-changed`
                    // rather than `code_changed` because every other key in this
                    // document is hyphenated.
                    "code-changed": {"type": "array", "items": {"type": "string"}},
                    // CLOUD-1051. When the base rev was committed, strict
                    // ISO-8601 UTC and fixed width, so a consumer orders it
                    // lexicographically rather than parsing a date. `null` when
                    // the rev resolves to no commit — the path lists are still
                    // answered, because they were computable and this was not.
                    "base-date": {"type": ["string", "null"]},
                    // CLOUD-1051. What each EDITED path said at the base rev, so
                    // a predicate can ask what an edit REMOVED — the one question
                    // `input.tree.lines` cannot answer, because it is the head
                    // side. Bounded to `edited`: an added path has no base side
                    // and a deleted one has no head side. A path absent here is
                    // could-not-look, never a measured nothing.
                    "base-lines": {
                        "type": "object",
                        "additionalProperties": {"type": "array", "items": {"type": "string"}},
                    },
                },
                "additionalProperties": false,
            }),
            Fact::GitHead
            | Fact::GitStatus
            | Fact::GitRemote
            | Fact::GitRef
            | Fact::GitRange
            | Fact::CommitMeta
            | Fact::GitHistory
            | Fact::Landing => Self::git_schema_fragment(self),
        }
    }

    /// The schema fragment for the `Cost::Effect` fact (CLOUD-760).
    ///
    /// Split out for [`Fact::git_schema_fragment`]'s reason — it is what pushed
    /// [`Fact::schema_fragment`] past the line ceiling — but on a different seam,
    /// and the seam is the one that matters here: **this is the only fragment
    /// that has to describe a producer as well as a shape.** The `provenance`
    /// half is not decoration. A fact whose value depends on which analyser at
    /// which version resolved it is not byte-stable under §6 unless the document
    /// says which one that was, so the tool, its version and the pinned
    /// invocation travel inside the fact rather than beside it.
    ///
    /// `sites` is pointer-only, per non-negotiable rule 4: a path, a line and the
    /// lint that fired. The analyser's message, and the source line it quoted,
    /// are content and stay out of the policy input.
    fn symbols_schema_fragment() -> serde_json::Value {
        serde_json::json!({
            // NULLABLE, like the git family and for its reason: the projection
            // emits `null` for both did-not-look answers, and a schema typing
            // this as a bare object refuses the module that handles them. Caught
            // by `opa check -s` -- which is the whole argument for deriving the
            // schema from the fact rather than writing it beside it.
            "type": ["object", "null"],
            "description": "Fact::Symbols (CLOUD-760). The first Cost::Effect fact: where a delegated analyser resolved a named type, by NAME rather than by spelling. `provenance` records which tool at which version produced it, because a fact whose meaning depends on an unrecorded tool version is not canonical. `sites` is pointer-only -- a path, a line and the lint that fired, never the diagnostic's message or the source it quoted.",
            "properties": {
                "provenance": {
                    "type": "object",
                    "properties": {
                        "tool": {"type": "string"},
                        "version": {"type": "string"},
                        "invocation": {"type": "array", "items": {"type": "string"}},
                    },
                    "additionalProperties": false,
                },
                "sites": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "path": {"type": "string"},
                            "line": {"type": "integer"},
                            "lint": {"type": "string"},
                        },
                        "additionalProperties": false,
                    },
                },
            },
            "additionalProperties": false,
        })
    }

    /// The schema fragment for the facts that constrain nothing but their own
    /// prose (CLOUD-1051 split this out; CLOUD-880 set the precedent).
    ///
    /// **The seam is a property of the fragment, not of the fact.** Every arm
    /// here carries `description` and no `type`, deliberately: these are the
    /// facts whose shape is not certain enough to constrain, and saying so once
    /// is the statement. A fact that grows a constrained shape leaves this
    /// function for an arm of its own, which is the edit rather than a comment.
    ///
    /// Unreachable for every other fact, and stated the way
    /// [`Fact::git_schema_fragment`] states it: no `debug_assert`, exhaustive
    /// arms, and a misrouted fact gets its own fragment rather than a panic.
    fn described_schema_fragment(self) -> serde_json::Value {
        match self {
            Fact::Receipts => serde_json::json!({
                "description": "Fact::Receipts -- check -> verdict token, or null for could-not-look.",
            }),
            Fact::Keys => serde_json::json!({
                "description": "Fact::Keys -- the tracker-key evidence, or null for could-not-look.",
            }),
            Fact::Stop => serde_json::json!({
                "description": "Fact::Stop -- the end-of-turn facts.",
            }),
            Fact::Waived => serde_json::json!({
                "description": "Fact::Waived -- the rules a live waiver suppresses, with each claimed expiry.",
            }),
            Fact::AgentSourced => serde_json::json!({
                "description": "Fact::AgentSourced -- what a command the AGENT ran said (CLOUD-776), or null.",
            }),
            Fact::Prospective => serde_json::json!({
                "description": "Fact::Prospective -- the SHAPE of what a write would land (CLOUD-758): look, bytes, lines. Never the content, which is where rule 4 is decided rather than promised.",
            }),
            Fact::Extracted => serde_json::json!({
                "type": ["object", "null"],
                "description": "Fact::Extracted (CLOUD-1172). Declared extractor id -> its result, which is an INTEGER and can be nothing else: the extractor set is closed and every member counts TYPED events -- a tool call, a result the host flagged as an error, a hook run's exit code -- never prose. No span of session text can reach this document by construction. NULL for could-not-look, which is the COMMON case here rather than the edge one (CLOUD-388: transcripts die with their container): no transcript on the envelope, a host that keeps none, and one that would not parse are all null, and all three are DIFFERENT from an extractor that ran and counted zero. A gate that confused them reports `nothing was stranded` on every host that never had a transcript. An id no row declared is ABSENT from the map: an undeclared extractor yields nothing, which is what makes this a projection of a declared set rather than a reader of sessions.",
                "additionalProperties": {"type": "integer"},
            }),
            Fact::Tasks => serde_json::json!({
                "description": "Fact::Tasks (CLOUD-856). Task NAME -> its normalised argv as a word list, or null where the task exists and is not a single command -- a pipeline, a sequence, a multi-line body. Those two are different answers and a name ABSENT from the map is a third: the task is not defined. Read from a receipt minted OUTSIDE the mediated call, at session start, so this path parses no manifest, invokes no runner, probes no binary and walks no tree. The receipt's key is recomputed from the manifest as it stands, so a record about a manifest that has since moved does not answer -- null for the whole fact, never a task table trusted a little. Also null for an unwritten record, a schema this build does not read, and one past the size cap; a guard comparing against an empty table would permit every substitution it exists to refuse.",
            }),
            // Not this family: `schema_fragment` constrains this one itself,
            // because its shape is certain. Named here rather than dropped for
            // the reason the tail arm states — a wildcard would let a later fact
            // classify itself instead of failing to compile.
            Fact::Pinned => serde_json::json!({
                "description": "unrouted fact -- schema_fragment does not delegate this one",
            }),
            // NOT THIS FAMILY, AND NAMED RATHER THAN WILDCARDED, for the reason
            // `git_schema_fragment`'s tail states: `no_axis_match_carries_a_wildcard_arm`
            // refuses a `_ =>`, and a wildcard would let a fact added later
            // classify itself here instead of failing to compile.
            Fact::Bypass
            | Fact::Document
            | Fact::Tracked
            | Fact::Lines
            | Fact::External
            | Fact::Invocations
            | Fact::Uses
            | Fact::Produced
            | Fact::Symbols
            | Fact::BaseDelta
            | Fact::Records
            | Fact::GitHead
            | Fact::GitStatus
            | Fact::GitRemote
            | Fact::GitRef
            | Fact::GitRange
            | Fact::CommitMeta
            | Fact::GitHistory
            | Fact::Landing
            | Fact::Staged
            | Fact::State
            | Fact::Forge
            | Fact::ToolVerdict
            | Fact::Captured => serde_json::json!({
                "description": "unrouted fact -- schema_fragment delegated a fact described_schema_fragment does not own",
            }),
        }
    }

    /// The schema fragment for the pinned-program fact (CLOUD-1028).
    ///
    /// Its own function for `git_schema_fragment`'s reason rather than a new one:
    /// `schema_fragment` hit its 100-line ceiling again when this arrived, and
    /// the ceiling is right — an arm per fact is readable, and a function that
    /// grows one every time the model does is not.
    ///
    /// CONSTRAINED, unlike the described-only family, because this shape IS
    /// certain: a sorted array of program names, or `null`. Stating it buys the
    /// build-time half CLOUD-876 wants — `opa check -s` then refuses a module
    /// that iterates the fact without reading the null, which is exactly the
    /// could-not-look arm a predicate over it must not skip.
    fn pinned_schema_fragment() -> serde_json::Value {
        serde_json::json!({
            "type": ["array", "null"],
            "items": {"type": "string"},
            "description": "Fact::Pinned (CLOUD-1028) -- the program NAMES the project's pin puts on PATH, sorted, or null for could-not-look. Names only: what a program is for, and every byte it would print, is somebody else's fact.",
        })
    }

    /// The schema fragment for the out-of-root family (CLOUD-1167).
    ///
    /// Its own function for [`Fact::pinned_schema_fragment`]'s reason:
    /// [`Fact::schema_fragment`] hit its 100-line ceiling again when this
    /// arrived, and the ceiling is right — an arm per fact is readable, and a
    /// function that grows one every time the model does is not.
    ///
    /// It does NOT join the description-only family, because the CONTAINER's
    /// shape is certain even though a consumer's document is not: this is an
    /// object keyed by declared id, and stating that is what makes `opa check -s`
    /// refuse a module that indexes it as an array. What stays unconstrained is
    /// the value, for [`Fact::schema_fragment`]'s stated reason — typing somebody
    /// else's configuration file is not this schema's job.
    fn external_schema_fragment() -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "description": "Fact::External (CLOUD-1167). DECLARED ID -> the parsed node of a file outside the repository root. Keyed by the declaring row's id and NEVER by the resolved path, because a resolved path is a machine's home directory and rule 4 keeps one off this document. An id ABSENT from this map could not be looked at -- its root environment variable is unset, the file is missing, unreadable, or the parser refused it -- and `missing` names the id with the cause. Absent is never an empty node: a module handed one would decide over a file it never saw. A path no row declares is unreadable by any module, which is what makes this a projection of a declared set rather than a filesystem scan.",
            "additionalProperties": true,
        })
    }

    /// The schema fragment for the two KEYED READS outside the working tree
    /// (CLOUD-1203).
    ///
    /// Their own function for [`Fact::pinned_schema_fragment`]'s reason:
    /// [`Fact::schema_fragment`] hit its 100-line ceiling again, and the ceiling
    /// is right — an arm per fact is readable, and a function that grows one
    /// every time the model does is not.
    ///
    /// The seam is real rather than arbitrary. Both read something the working
    /// tree does not carry — the index, and the engine's own store — and both are
    /// NULLABLE for the same pair of could-not-look conditions: nobody declared
    /// one, and the thing could not be opened. A schema typing either as a bare
    /// object would refuse the module that handles them, which `opa check -s`
    /// catches and which is the whole argument for deriving these from the fact.
    fn keyed_read_schema_fragment(self) -> serde_json::Value {
        match self {
            Fact::Forge => serde_json::json!({
                "type": ["object", "null"],
                "description": "Fact::Forge (CLOUD-1154). Declared SHA -> the forge's check verdicts for it, as `name -> conclusion` TOKENS. Read back from a record a producer wrote OUTSIDE the engine: the engine opens no socket, which `evaluator-io-check` gates. KEYED BY SHA -- a record taken against a different commit is not evidence about this one, so it is simply not in the map; that keying is the safety property and the difference between reading a verdict and inheriting a stale one. Tokens only -- a check's name and its conclusion, never a check-run body or an annotation. NULL when no row declared a SHA and when no record store is readable; a declared SHA with no record is ABSENT from the map, and a declared SHA whose record holds no checks is present with an EMPTY object. Those three are different answers and a gate that confuses them reports green on a commit nothing ever judged.",
                "additionalProperties": {
                    "type": "object",
                    "additionalProperties": {"type": "string"},
                },
            }),
            Fact::ToolVerdict => serde_json::json!({
                "type": ["object", "null"],
                "description": "Fact::ToolVerdict (CLOUD-1171). Declared id -> a third-party tool's verdict for it, as `finding name -> pointer` TOKENS. Read back from a record a producer wrote OUTSIDE the engine, because `check` is read-only and structurally cannot run a validator. KEYED BY (tool, pinned version, input digest) -- a record from a differently-pinned tool, or one taken over bytes that have since changed, lives under a different name and does not answer; that keying is the safety property and closes CLOUD-646's shape for this path. Pointers only -- a finding id and a `path:line`, never a tool's report. NULL when no row declared a tool and when no record store is readable; a declared id whose key has no record is ABSENT from the map, and one whose record holds no findings is present with an EMPTY object. Those three are different answers and a gate that confuses them reports clean over a validator that never ran.",
                "additionalProperties": {
                    "type": "object",
                    "additionalProperties": {"type": "string"},
                },
            }),
            Fact::Captured => serde_json::json!({
                "type": ["object", "null"],
                "description": "Fact::Captured (CLOUD-1188). Declared id -> the REDUCTION that row asked for over a response the agent already captured: a boolean for `present`, an integer for `count`, a bounded whitespace-free string for `token`. THE REDUCTION IS PART OF THE FACT rather than the consumer's discipline -- a payload on this document could be lifted into a `subjects` pointer by any module, so non-negotiable rule 4 is decided here. A `token` reduction over a value that is not a bounded token is REFUSED and the id is absent, which is what makes `tokens, not prose` structural. Resolved from the capture store and NEVER from stdin: the store is sorted by handle, so two runs over unchanged bytes agree, which is what `Surface::Check` requires. NULL when no row declared a reduction and when no store is readable; a declared id no capture answers is ABSENT from the map, never a false negative.",
                "additionalProperties": {"type": ["boolean", "integer", "string"]},
            }),
            Fact::Records => serde_json::json!({
                "type": "object",
                "description": "Fact::Records (CLOUD-1051). RECORD name -> the lines accumulated in it on this branch, in write order. Keyed by the record rather than by the recorder row because several rows may write one record. Each line is the recorder's own whitespace-free columns; the projection adds nothing and reads nothing out of them. A record ABSENT from this map could not be read; the collapse into an empty list is what this keeps open.",
                "additionalProperties": {
                    "type": "array",
                    "items": {"type": "string"},
                },
            }),
            Fact::Produced => serde_json::json!({
                "type": "object",
                "description": "Fact::Produced. Sink key -> the record an earlier run's boundary wrote: a digest and a count for a baseline, the empty string for a marker. Never content -- non-negotiable rule 4 holds at the sink harder than at a report (CLOUD-851).",
                "additionalProperties": {"type": "string"},
            }),
            Fact::Staged => serde_json::json!({
                "type": ["object", "null"],
                "description": "Fact::Staged (CLOUD-1203). Declared path -> its STAGED content, parsed by the path's format -- `git show :<path>`, which `tracked` explicitly is NOT: that fact walks the WORKING TREE. A path with no staged entry, one whose bytes are not UTF-8, and one whose format this build cannot parse are each ABSENT from this map rather than present with an empty node, and `missing` names the path with the cause. NULL when no row declared a staged read, so a module can tell `nobody asked` from `nothing is staged`.",
                "additionalProperties": true,
            }),
            Fact::State => serde_json::json!({
                "type": ["object", "null"],
                "description": "Fact::State (CLOUD-1203). Declared ref -> the finding pointer lines the engine's own store accumulated on it, in `findings::pointer_lines`' own spelling: `<fingerprint> <rule> <ref> <count>`. The SAME shape `input.tree.records` carries, and the same reason -- these are the lines `unlanded-check` already reads, so a successor reads what the program read rather than a re-derivation that could disagree. KEYED BY REF: a finding observed on another branch is not evidence about this one, so a listing keyed elsewhere is simply not in the map. Pointers only -- a fingerprint, a rule id and a number, never a finding's message or the line it pointed at. NULL when no row declared a state read, or when no store is bound to this checkout: `nobody asked` and `nothing was ever recorded` are both could-not-look, and neither is an empty listing.",
                "additionalProperties": {"type": "array", "items": {"type": "string"}},
            }),
            // NOT THIS FAMILY, AND NAMED RATHER THAN WILDCARDED, for
            // `git_schema_fragment`'s tail's reason: a `_ =>` is refused by
            // `no_axis_match_carries_a_wildcard_arm`, and a wildcard would let a
            // fact added later classify itself here instead of failing to
            // compile.
            Fact::Bypass
            | Fact::Receipts
            | Fact::Keys
            | Fact::Stop
            | Fact::Waived
            | Fact::Document
            | Fact::Tracked
            | Fact::Lines
            | Fact::External
            | Fact::AgentSourced
            | Fact::Prospective
            | Fact::Invocations
            | Fact::Uses
            | Fact::Symbols
            | Fact::BaseDelta
            | Fact::Pinned
            | Fact::GitHead
            | Fact::GitStatus
            | Fact::GitRemote
            | Fact::GitRef
            | Fact::GitRange
            | Fact::CommitMeta
            | Fact::GitHistory
            | Fact::Tasks
            | Fact::Extracted
            | Fact::Landing => serde_json::json!({
                "description": "unrouted fact -- schema_fragment delegated a fact keyed_read_schema_fragment does not own",
            }),
        }
    }

    /// The schema fragment for the commit-metadata family (CLOUD-1187).
    ///
    /// Its own function rather than a `git_schema_fragment` arm, for that
    /// function's own reason one iteration later: it hit the line ceiling when
    /// this family arrived. The seam is the one the model already has — the git
    /// family answers questions about the repository's SHAPE, and this one about
    /// a commit's identity fields.
    fn commit_meta_schema_fragment() -> serde_json::Value {
        serde_json::json!({
                "type": ["object", "null"],
                "description": "Fact::CommitMeta (CLOUD-1187). Declared range -> each commit's IDENTITY fields: `commit` the sha, `author` and `committer` as `Name <email>`, `trailers` as whole `Key: value` lines. THERE IS NO MESSAGE BODY AND NO DIFF, and none can be added by accident -- `git::CommitMeta` has no such field, so non-negotiable rule 4 is decided by the type rather than by this projection remembering to drop something. A range whose endpoints do not resolve is ABSENT rather than an empty list, matching `git-ranges`: `no commits in this range` and `I could not look` are the two answers a history gate must keep apart. Declared separately from `git-ranges` because this peels an object per commit, and a row wanting subjects must not pay for that.",
                "additionalProperties": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "commit": {"type": "string"},
                            "author": {"type": "string"},
                            "committer": {"type": "string"},
                            "trailers": {"type": "array", "items": {"type": "string"}},
                        },
                        "additionalProperties": false,
                    },
                },
        })
    }

    /// The schema fragment for the undeclarable-history family (CLOUD-1200).
    ///
    /// Its own function for [`Fact::commit_meta_schema_fragment`]'s reason one
    /// iteration later: [`Fact::git_schema_fragment`] hit the line ceiling again
    /// when this arrived. The seam is real — the git family answers what a
    /// NAMED ref or range holds, and this one answers what a PATTERN matches,
    /// which is the distinction the whole variant exists for.
    fn history_schema_fragment() -> serde_json::Value {
        serde_json::json!({
                "type": ["object", "null"],
                "description": "Fact::GitHistory (CLOUD-1200). Declared query id -> the commits its PATTERN matched: every tag matching a glob, or the commits that added or deleted a path. This is the half `git-refs` and `git-ranges` cannot reach -- they resolve what a rule NAMES, and here the answer set is not knowable at declaration time. Each entry is a sha, a subject, and the tag name for a tag query: a history fact widens WHICH commits are visible, never WHAT one carries, so there is no body and no hunk. NULL when no row declared a pattern AND when the repository is SHALLOW -- a shallow clone cannot see the history a path query walks, and a truncated walk reported as a result is a gate deciding over history it could not see. A declared pattern that matched nothing is present with an EMPTY list, which is a real answer and not could-not-look.",
                "additionalProperties": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "commit": {"type": "string"},
                            "subject": {"type": "string"},
                            "tag": {"type": "string"},
                        },
                        "additionalProperties": false,
                    },
                },
        })
    }

    /// The schema fragment for the git and landing families (CLOUD-880).
    ///
    /// Split out of [`Fact::schema_fragment`] when `Landing` pushed it past the
    /// line ceiling. The seam is the one the model already has — these six are the
    /// facts that answer questions about the repository's history rather than about
    /// its files — so this is a boundary rather than an arbitrary cut.
    ///
    /// **Every other fact is unreachable here and says so.** A `debug_assert`
    /// would be a runtime claim about a compile-time property; instead the arms
    /// are exhaustive and the non-family facts return their own fragment, so a new
    /// fact routed here by mistake gets a wrong answer no test would pass rather
    /// than a panic in the field.
    fn git_schema_fragment(self) -> serde_json::Value {
        match self {
            Fact::GitHead => serde_json::json!({
                "type": ["object", "null"],
                "description": "Fact::GitHead (CLOUD-907). `commit` is HEAD's sha, `branch` the branch it is on, `detached` whether it is on one at all. `commit` is null in an empty repository and `branch` is null on a detached HEAD -- could-not-look, never an empty string, because Rego reads an undefined path as `does not hold`.",
                "properties": {
                    "commit": {"type": ["string", "null"]},
                    "branch": {"type": ["string", "null"]},
                    "detached": {"type": "boolean"},
                },
                "additionalProperties": false,
            }),
            Fact::GitStatus => serde_json::json!({
                "type": ["object", "null"],
                "description": "Fact::GitStatus (CLOUD-907). Repository-relative paths the working tree differs from HEAD on, plus a count of uncommitted entries. Paths, never a diff hunk and never a line -- non-negotiable rule 4.",
                "properties": {
                    "changed": {"type": "array", "items": {"type": "string"}},
                    "uncommitted": {"type": "integer"},
                },
                "additionalProperties": false,
            }),
            Fact::GitRemote => serde_json::json!({
                "type": ["object", "null"],
                "description": "Fact::GitRemote (CLOUD-907). `remotes` is name -> URL as `.git/config` holds it and `upstream` is HEAD's tracking ref, null when it has none. Read from disk: asking a remote what it holds would be Cost::Effect and a different fact.",
                "properties": {
                    "remotes": {"type": "object", "additionalProperties": {"type": "string"}},
                    "upstream": {"type": ["string", "null"]},
                },
                "additionalProperties": false,
            }),
            Fact::GitRef => serde_json::json!({
                "type": ["object", "null"],
                "description": "Fact::GitRef (CLOUD-907). Declared ref -> the commit it names. A ref that does not resolve is ABSENT from this map rather than present with a null: `origin/main` missing in a shallow clone is not an answer about that ref. Reachability is deliberately not here -- CLOUD-36 decides merged-ness by patch identity, because a rebased landing is invisible to ancestry.",
                "additionalProperties": {"type": "string"},
            }),
            Fact::Landing => serde_json::json!({
                "type": ["object", "null"],
                "description": "Fact::Landing (CLOUD-880). Declared target -> whether this branch's work is on it, BY PATCH IDENTITY. `verdict` is the answer, `landed` whether there is no unlanded content, and `unlanded` the head-side commits with no proof on the target -- shas only. A target that does not resolve is ABSENT from this map rather than present with a negative: `nothing landed` and `I could not look` are the two answers a landing gate must never confuse, because the second read as the first passes a gate on ignorance. Ancestry is deliberately not the test -- CLOUD-36 decides merged-ness by patch identity, since a rebased landing is invisible to ancestry.",
                "additionalProperties": {
                    "type": "object",
                    "properties": {
                        "verdict": {"type": "string"},
                        "landed": {"type": "boolean"},
                        "unlanded": {"type": "array", "items": {"type": "string"}},
                    },
                    "additionalProperties": false,
                },
            }),
            Fact::CommitMeta => Self::commit_meta_schema_fragment(),
            Fact::GitHistory => Self::history_schema_fragment(),
            Fact::GitRange => serde_json::json!({
                "type": ["object", "null"],
                "description": "Fact::GitRange (CLOUD-907). Declared range -> the commits in it, each a sha and a subject. A range whose endpoints do not resolve is ABSENT rather than an empty list -- `no commits landed` and `I could not look` are the two answers this map must keep apart. Subject only: a message body or a diff would put tracked content on the input.",
                "additionalProperties": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "commit": {"type": "string"},
                            "subject": {"type": "string"},
                        },
                        "additionalProperties": false,
                    },
                },
            }),
            // NOT THIS FAMILY, AND NAMED RATHER THAN WILDCARDED. A `_ =>` here is
            // refused by `no_axis_match_carries_a_wildcard_arm`, and the rule is
            // right: exhaustiveness is a totality guarantee only while no arm is a
            // wildcard, so a fact added later would classify itself instead of
            // failing to compile. These are unreachable by construction —
            // `schema_fragment` delegates six variants and only those — and
            // spelling them out is what makes a seventh a compile error in both
            // functions rather than a silent default in one.
            Fact::Bypass
            | Fact::Receipts
            | Fact::Keys
            | Fact::Stop
            | Fact::Waived
            | Fact::Document
            | Fact::Tracked
            | Fact::Lines
            | Fact::External
            | Fact::AgentSourced
            | Fact::Prospective
            | Fact::Produced
            | Fact::Invocations
            | Fact::Uses
            | Fact::Symbols
            | Fact::BaseDelta
            | Fact::Records
            | Fact::Staged
            | Fact::State
            | Fact::Forge
            | Fact::ToolVerdict
            | Fact::Captured
            | Fact::Tasks
            | Fact::Extracted
            | Fact::Pinned => serde_json::json!({
                "description": "unrouted fact -- schema_fragment delegated a fact git_schema_fragment does not own",
            }),
        }
    }
}

/// The document formats the engine can parse — the **format** half of a document
/// fact (CLOUD-772).
///
/// # Formats, never artifacts
///
/// Non-negotiable rule 1 decides this shape. A `parse the toolchain manifest`
/// fact would name a consumer's toolchain choice inside `crates/batten`; the
/// core knows only *formats*, and which paths carry which format is the
/// consumer's `batten.toml`. That is why the variants below are TOML and YAML
/// rather than any file name, and why
/// `tests/document_facts.rs`'s `no_artifact_name_reaches_the_core` is a gate on
/// it rather than a convention anyone has to remember.
///
/// # PKL is declarable and deliberately unparseable
///
/// It has no maintained Rust parser, and adopting one on speculation is the
/// scope expansion this repository refuses. So it is a **variant** rather than
/// an omission: a consumer that declares a PKL path gets [`Look::CouldNotLook`],
/// exhaustively matched, instead of a fact that silently does not exist. An
/// absent variant would answer the same declaration with "no rows", and the only
/// way to find that out is that the rule never fires — which is the vacuous pass
/// the whole issue is filed against.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    Hash,
    serde::Serialize,
    serde::Deserialize,
    schemars::JsonSchema,
)]
#[serde(rename_all = "lowercase")]
pub enum Format {
    /// TOML.
    Toml,
    /// YAML — one document per stream; a multi-document stream reads its first.
    Yaml,
    /// JSON.
    Json,
    /// JSON5: JSON with comments, trailing commas and unquoted keys.
    Json5,
    /// PKL. Declarable, never parsed — see the type's own note.
    Pkl,
}

impl Format {
    /// Every format the engine knows, so the partitions below are total.
    pub const ALL: &'static [Format] = &[
        Format::Toml,
        Format::Yaml,
        Format::Json,
        Format::Json5,
        Format::Pkl,
    ];

    /// The stable lowercase token used in config and machine output (§6).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Format::Toml => "toml",
            Format::Yaml => "yaml",
            Format::Json => "json",
            Format::Json5 => "json5",
            Format::Pkl => "pkl",
        }
    }

    /// Whether this crate carries a parser for the format.
    ///
    /// Stated per variant rather than inferred from whether [`Format::read`]
    /// happens to return a value, so adding a format is a deliberate act at both
    /// sites and a declared-but-unparseable one cannot be mistaken for a bug.
    #[must_use]
    pub const fn parseable(self) -> bool {
        match self {
            Format::Toml | Format::Yaml | Format::Json | Format::Json5 => true,
            Format::Pkl => false,
        }
    }

    /// The format a path's extension names, when it names one this crate parses.
    ///
    /// **Extension-based, and only where the row did not say.** A
    /// [`crate::rules::RuleKind::Document`] row states its `format` explicitly,
    /// and that stays the authority there — the column exists because a file
    /// named `.json` that is really JSON5 would parse-fail and report
    /// "could not look" forever, blaming the file for the guess. A tree-scoped
    /// `policy` row declares a LIST of documents rather than one, so a per-path
    /// column would mean a parallel list nobody could keep aligned; the
    /// extension is the honest default there, and a path whose extension names
    /// nothing is [`Look::CouldNotLook`] rather than a guess.
    ///
    /// `Pkl` is deliberately absent: it is declarable and unparseable
    /// ([`Format::parseable`]), so returning it here would promise a read that
    /// cannot happen.
    #[must_use]
    pub fn for_path(path: &str) -> Option<Format> {
        let extension = path.rsplit_once('.').map(|(_, ext)| ext)?;
        // Searched over `ALL` rather than matched on the extension string, and
        // that inversion is what keeps the axis total: a match on the extension
        // needs a wildcard (there are infinitely many strings), and a wildcard
        // is precisely what `no_axis_match_carries_a_wildcard_arm` refuses —
        // a format added later would classify itself instead of failing to
        // compile. Asking each variant which extensions it owns puts the
        // decision back on the enum, where the compiler can insist on it.
        Format::ALL
            .iter()
            .copied()
            .find(|format| format.extensions().contains(&extension))
    }

    /// The filename extensions this format owns, without the dot.
    ///
    /// Beside the variant rather than in a lookup table, for
    /// [`Format::parseable`]'s reason: adding a format has to be a deliberate
    /// act at every site that classifies one, and a table somewhere else is a
    /// second authority that goes stale silently.
    ///
    /// `Pkl` owns none deliberately — it is declarable and unparseable, so
    /// claiming `.pkl` here would promise a read that cannot happen and turn
    /// every `.pkl` in a declared list from an honest could-not-look into a
    /// parse failure blamed on the file.
    #[must_use]
    pub const fn extensions(self) -> &'static [&'static str] {
        match self {
            Format::Toml => &["toml"],
            Format::Yaml => &["yaml", "yml"],
            Format::Json => &["json"],
            Format::Json5 => &["json5"],
            Format::Pkl => &[],
        }
    }

    /// Parse `text` as this format.
    ///
    /// Three-valued by construction (CLOUD-757): a document that parses is
    /// [`Look::Is`], and **anything else is [`Look::CouldNotLook`]** — a syntax
    /// error, an empty YAML stream, a format this crate cannot parse. It is
    /// never [`Look::IsNot`], because a file failing to parse says nothing at
    /// all about what it contains. That distinction is the whole point: the
    /// hand-rolled readers this replaces default an empty extraction to
    /// agreement, so a file they cannot read passes every gate over it.
    #[must_use]
    pub fn read(self, text: &str) -> Look<Node> {
        match self {
            Format::Toml => match toml::from_str::<toml::Value>(text) {
                Ok(value) => Look::Is(Node::from_toml(&value)),
                Err(_) => Look::CouldNotLook,
            },
            Format::Yaml => match yaml_rust2::YamlLoader::load_from_str(text) {
                // The first document of the stream, and only it. A multi-document
                // stream addressed as one would need a document index in every
                // node path, which no consumer here has; taking the first is the
                // narrow answer rather than a silent merge of several.
                Ok(documents) => match documents.first() {
                    Some(document) => Look::Is(Node::from_yaml(document)),
                    None => Look::CouldNotLook,
                },
                Err(_) => Look::CouldNotLook,
            },
            Format::Json => match serde_json::from_str::<serde_json::Value>(text) {
                Ok(value) => Look::Is(Node::from_json(&value)),
                Err(_) => Look::CouldNotLook,
            },
            Format::Json5 => match json5::from_str::<serde_json::Value>(text) {
                Ok(value) => Look::Is(Node::from_json(&value)),
                Err(_) => Look::CouldNotLook,
            },
            // Declared, and honestly unanswerable. See the type's own note.
            Format::Pkl => Look::CouldNotLook,
        }
    }
}

/// A parsed document, canonicalised into one shape whatever it was written in.
///
/// # One tree, four syntaxes
///
/// The point of a document fact is that a node path means the same thing in
/// TOML and in JSON5, so every format lands here rather than each rule learning
/// four libraries' value types. That is also what makes a rule portable across
/// an artifact that changes format.
///
/// # Byte-stability is structural, not careful (§6)
///
/// [`Node::Map`] is a [`BTreeMap`], so iteration order is the keys' order and
/// never the file's — two runs over identical bytes produce identical output,
/// key ordering included, without any call site having to sort. And a number is
/// carried as its **source text** rather than as `f64`: re-formatting a parsed
/// float is the classic place a value stops round-tripping, and a version pin is
/// exactly the kind of number that must survive as written.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Node {
    /// An explicit null.
    Null,
    /// A boolean.
    Bool(bool),
    /// A number, carried verbatim as the source wrote it.
    Number(String),
    /// A string, or any scalar the format does not distinguish further.
    Text(String),
    /// An ordered sequence.
    List(Vec<Node>),
    /// A mapping, keyed in sort order.
    Map(std::collections::BTreeMap<String, Node>),
}

impl Node {
    /// This node as JSON, for an evaluator that takes an input document.
    ///
    /// The canonical tree is the authority and this is a **projection of it**,
    /// which is what keeps CLOUD-772's "one canonical tree" true with a second
    /// consumer attached: TOML, YAML, JSON and JSON5 all arrive here as the same
    /// shape, so a policy module written against one format decides identically
    /// over another. A second parser aimed at the evaluator would have
    /// reintroduced exactly the per-consumer re-derivation the fact model exists
    /// to stop.
    ///
    /// [`Node::Number`] carries its source spelling verbatim, so it is emitted
    /// as a JSON number when it round-trips and as a string when it does not —
    /// a TOML datetime or an oversized integer keeps its bytes rather than being
    /// silently reshaped into something the source did not say.
    #[must_use]
    pub fn to_json(&self) -> serde_json::Value {
        match self {
            Node::Null => serde_json::Value::Null,
            Node::Bool(flag) => serde_json::Value::Bool(*flag),
            Node::Number(text) => text.parse::<serde_json::Number>().map_or_else(
                |_| serde_json::Value::String(text.clone()),
                serde_json::Value::Number,
            ),
            Node::Text(text) => serde_json::Value::String(text.clone()),
            Node::List(items) => {
                serde_json::Value::Array(items.iter().map(Node::to_json).collect())
            }
            Node::Map(map) => serde_json::Value::Object(
                map.iter()
                    .map(|(key, item)| (key.clone(), item.to_json()))
                    .collect(),
            ),
        }
    }

    fn from_toml(value: &toml::Value) -> Node {
        match value {
            toml::Value::String(text) => Node::Text(text.clone()),
            toml::Value::Integer(number) => Node::Number(number.to_string()),
            toml::Value::Float(number) => Node::Number(number.to_string()),
            toml::Value::Boolean(flag) => Node::Bool(*flag),
            // A datetime is a scalar with one canonical spelling, which is what
            // `Text` means here — not a string the author typed.
            toml::Value::Datetime(stamp) => Node::Text(stamp.to_string()),
            toml::Value::Array(items) => Node::List(items.iter().map(Node::from_toml).collect()),
            toml::Value::Table(table) => Node::Map(
                table
                    .iter()
                    .map(|(key, item)| (key.clone(), Node::from_toml(item)))
                    .collect(),
            ),
        }
    }

    fn from_json(value: &serde_json::Value) -> Node {
        match value {
            serde_json::Value::Null => Node::Null,
            serde_json::Value::Bool(flag) => Node::Bool(*flag),
            serde_json::Value::Number(number) => Node::Number(number.to_string()),
            serde_json::Value::String(text) => Node::Text(text.clone()),
            serde_json::Value::Array(items) => {
                Node::List(items.iter().map(Node::from_json).collect())
            }
            serde_json::Value::Object(map) => Node::Map(
                map.iter()
                    .map(|(key, item)| (key.clone(), Node::from_json(item)))
                    .collect(),
            ),
        }
    }

    fn from_yaml(value: &yaml_rust2::Yaml) -> Node {
        match value {
            yaml_rust2::Yaml::Real(number) => Node::Number(number.clone()),
            yaml_rust2::Yaml::Integer(number) => Node::Number(number.to_string()),
            yaml_rust2::Yaml::String(text) => Node::Text(text.clone()),
            yaml_rust2::Yaml::Boolean(flag) => Node::Bool(*flag),
            yaml_rust2::Yaml::Array(items) => {
                Node::List(items.iter().map(Node::from_yaml).collect())
            }
            yaml_rust2::Yaml::Hash(hash) => Node::Map(
                hash.iter()
                    .filter_map(|(key, item)| {
                        // A non-scalar key addresses nothing a node path can
                        // spell, so it is dropped rather than stringified into a
                        // key a consumer could never write. YAML permits them;
                        // no artifact in scope uses one.
                        Node::from_yaml(key)
                            .scalar()
                            .map(|key| (key, Node::from_yaml(item)))
                    })
                    .collect(),
            ),
            // An alias resolves to a node this loader does not hand us, and a
            // bad value is the parser saying it could not read one. Both are
            // absences rather than nulls, and `Null` is the honest carrier: the
            // node exists in the file and holds nothing this fact can address.
            yaml_rust2::Yaml::Alias(_) | yaml_rust2::Yaml::BadValue | yaml_rust2::Yaml::Null => {
                Node::Null
            }
        }
    }

    /// The node at a dotted path, three-valued.
    ///
    /// `a.b.0.c` walks maps by key and lists by index. A path that does not
    /// resolve is [`Look::IsNot`] — **looked, and it is not there** — which is
    /// the distinction from a document that could not be parsed at all. The two
    /// collapsing into one another is the failure mode of every hand-rolled
    /// reader this replaces.
    #[must_use]
    pub fn at(&self, path: &str) -> Look<&Node> {
        let mut here = self;
        for segment in path.split('.').filter(|segment| !segment.is_empty()) {
            let next = match here {
                Node::Map(map) => map.get(segment),
                Node::List(items) => segment.parse::<usize>().ok().and_then(|at| items.get(at)),
                Node::Null | Node::Bool(_) | Node::Number(_) | Node::Text(_) => None,
            };
            match next {
                Some(node) => here = node,
                None => return Look::IsNot,
            }
        }
        Look::Is(here)
    }

    /// This node's scalar text, or `None` where it is a container.
    ///
    /// One spelling per kind, so a comparison in `batten.toml` reads the same
    /// whatever format the document was written in.
    #[must_use]
    pub fn scalar(&self) -> Option<String> {
        match self {
            Node::Text(text) | Node::Number(text) => Some(text.clone()),
            Node::Bool(true) => Some("true".to_owned()),
            Node::Bool(false) => Some("false".to_owned()),
            Node::Null | Node::List(_) | Node::Map(_) => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Undeclarable git history (CLOUD-1200)
// ---------------------------------------------------------------------------
/// One `[[rule.history]]` row: a PATTERN whose matching set the engine resolves
/// (CLOUD-1200).
///
/// **The half `Fact::GitRef` and `Fact::GitRange` structurally cannot reach.**
/// Those resolve what a rule NAMES — a ref, a `base..head` range — and thirteen
/// governed programs need history the declaration cannot name in advance: every
/// tag matching a pattern, the commit that deleted a path. The answer set is not
/// knowable at declaration time, which is exactly why a literal cannot express
/// it.
///
/// **What stays declared is the PATTERN, and that is the whole safety property.**
/// A pattern no row names resolves nothing, so this is a projection of a declared
/// set rather than a git shell. Widening WHICH commits are visible is admissible;
/// widening what a commit CARRIES is not, and the per-entry shape stays a sha and
/// a subject for that reason.
#[derive(
    Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize, schemars::JsonSchema,
)]
#[serde(deny_unknown_fields)]
pub struct HistoryQuery {
    /// The key this query's matching set is projected under.
    pub id: String,
    /// A tag glob — every tag whose name matches, with the commit it names.
    ///
    /// Exactly one of `tags` and `path` is required; [`HistoryQuery::shape`] is
    /// what refuses a row carrying both or neither, at load.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tags: Option<String>,
    /// A path whose add/delete history is wanted — *when did this appear or
    /// vanish*, which no snapshot fact answers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// Which transition on `path` to report: `"A"` for added, `"D"` for deleted.
    ///
    /// Required with `path` and refused without it. Defaulting it would make a
    /// row that forgot it silently mean one of the two, and which one is not
    /// guessable from the path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filter: Option<String>,
}

/// Which of the two shapes a [`HistoryQuery`] row is.
///
/// A closed enum rather than three optional fields read ad hoc, so the
/// exactly-one-of obligation is decided once, at load, rather than by every
/// reader remembering it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HistoryShape {
    /// Every tag matching the glob.
    Tags,
    /// The commits that ADDED the path.
    PathAdded,
    /// The commits that DELETED the path.
    PathDeleted,
}

impl HistoryQuery {
    /// The row's shape, or `None` when it declares neither or both.
    ///
    /// `None` is a CONFIG FAULT the loader refuses, never a could-not-look: no
    /// state of the repository makes a row declaring both a tag glob and a path
    /// answerable, so reporting it as a failed look would present a permanent
    /// authoring error as a transient one — the choice
    /// [`crate::rules::NotAcquired::UnknownFormat`] already makes.
    #[must_use]
    pub fn shape(&self) -> Option<HistoryShape> {
        // WRITTEN AS GUARDS RATHER THAN AS A TUPLE MATCH, and the reason is a
        // gate rather than taste: `tests/facts.rs`'s
        // `no_axis_match_carries_a_wildcard_arm` scans this file for `_ =>`, and
        // the three-way tuple this used to match on cannot be spelled
        // exhaustively without one. The scan is blunt on purpose — a wildcard
        // introduced anywhere in this module is a fact that could later classify
        // itself instead of failing to compile — so the shape that satisfies it
        // is the shape to write, not an exemption to argue for.
        if self.tags.is_some() {
            // Both is a config fault, and so is a filter with no path to apply
            // it to.
            if self.path.is_some() || self.filter.is_some() {
                return None;
            }
            return Some(HistoryShape::Tags);
        }
        // A filter with no path to apply it to is a config fault too, and the
        // `?` is the whole of that arm.
        self.path.as_ref()?;
        match self.filter.as_deref() {
            Some("A") => Some(HistoryShape::PathAdded),
            Some("D") => Some(HistoryShape::PathDeleted),
            // A path with no filter, or one naming a transition this does not
            // resolve. Neither is could-not-look: no state of the repository
            // makes either answerable, so the loader refuses the row.
            Some(_) | None => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Out-of-root files (CLOUD-1167)
// ---------------------------------------------------------------------------
/// One `[[rule.external]]` row: a file outside the repository root that a
/// tree-scoped module may read (CLOUD-1167).
///
/// **The declaration IS the bound.** A module reads the ids its own row names
/// and nothing else, so a path no row declares is unreadable — which is the
/// difference between this fact and a filesystem scanner, and the whole of the
/// safety property CLOUD-1167 owes.
///
/// Declared on the ROW rather than in a root table, deliberately: `Rule`'s
/// columns are already compared byte-for-byte by
/// [`crate::trust::weakenings`] unless `RULE_NON_PREDICATE` exempts them, so a
/// branch that repoints an existing row at a different file is reported as a
/// weakening with no new machinery. Repointing the evidence is exactly the move
/// that has to be visible.
#[derive(
    Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize, schemars::JsonSchema,
)]
#[serde(deny_unknown_fields)]
pub struct Rooted {
    /// The key this file is projected under in `input.tree.external`.
    ///
    /// The id and never the resolved path, because a resolved path is a
    /// machine's home directory and non-negotiable rule 4 keeps one off the
    /// policy input.
    pub id: String,
    /// The NAME of the environment variable holding the directory to resolve
    /// `path` beneath.
    ///
    /// A name, never a value, and never a directory this crate knows: the engine
    /// expands whatever variable a row names and has no opinion about which
    /// variables exist or what any of them means. That is where non-negotiable
    /// rule 1 is paid — a launcher's, a toolchain's or a cache's layout is the
    /// consumer's fact, in the consumer's config.
    ///
    /// Unset or empty on this machine is [`Look::CouldNotLook`], never an absent
    /// file: "this host does not have that root" and "the file is not there" are
    /// different answers and a gate that confuses them reports green on every
    /// host that never had the root.
    pub root: String,
    /// The path beneath that root.
    ///
    /// Relative and downward — [`Rooted::escapes`] refuses an absolute path or
    /// any `..` component when the config loads, so a declaration cannot walk
    /// back out of the root it named.
    pub path: String,
}

impl Rooted {
    /// Whether `path` would leave the root it is resolved beneath.
    ///
    /// Refused at LOAD rather than at resolution, which is the same choice
    /// [`crate::rules::NotAcquired::UnknownFormat`] makes and for its reason: no
    /// state of the filesystem makes `../../etc/shadow` an admissible
    /// declaration, so reporting it as could-not-look would present a permanent
    /// authoring error as a transient one.
    ///
    /// A Windows-style root prefix counts as absolute too, so the refusal does
    /// not depend on which platform parses the config.
    #[must_use]
    pub fn escapes(&self) -> bool {
        let path = std::path::Path::new(&self.path);
        path.components().any(|component| {
            matches!(
                component,
                std::path::Component::ParentDir
                    | std::path::Component::RootDir
                    | std::path::Component::Prefix(_)
            )
        })
    }
}

// ---------------------------------------------------------------------------
// Transcript extractors (CLOUD-1172)
// ---------------------------------------------------------------------------
/// One `[[rule.extract]]` row: a named extraction over the session's own
/// transcript (CLOUD-1172).
///
/// **A declaration of WHAT TO COUNT, never of what to read.** The row cannot ask
/// for a span, a match, or a line, because [`Extraction`] has no member that
/// yields one — which is how rule 4 is decided here rather than trusted to every
/// consumer.
#[derive(
    Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize, schemars::JsonSchema,
)]
#[serde(deny_unknown_fields)]
pub struct ExtractQuery {
    /// The key this result is projected under in `input.facts.extracted`.
    pub id: String,
    /// Which typed event to count.
    pub count: Extraction,
}

/// The closed set of extractions a row may declare.
///
/// **Closed, and every member returns an integer.** An open expression language,
/// or a member yielding a match, would put the session's own text within reach of
/// a module — and a transcript holds every command, every file body and every
/// prompt this session touched. The set is small on purpose: each member is a
/// field [`crate::transcript`] already types, so none of them reads prose even
/// internally.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize, serde::Serialize, schemars::JsonSchema,
)]
#[serde(rename_all = "kebab-case")]
pub enum Extraction {
    /// Turn boundaries.
    Turns,
    /// Tool calls the session made.
    ToolCalls,
    /// Tool results the HOST flagged as errors — its own boolean, never a
    /// substring match on a message.
    ToolErrors,
    /// Hook runs the session recorded.
    HookDecisions,
    /// Hook runs that DENIED, by the §7 verdict exit code rather than by prose.
    HookDenials,
}

impl Extraction {
    /// This extraction's answer over a parsed stream's typed counts.
    ///
    /// Exhaustive with no wildcard arm, like every other axis match in this
    /// module: a member added later decides here or fails to compile, rather
    /// than defaulting to a count of something else.
    #[must_use]
    pub const fn of(self, counts: &crate::transcript::Counts) -> usize {
        match self {
            Extraction::Turns => counts.turns,
            Extraction::ToolCalls => counts.tool_calls,
            Extraction::ToolErrors => counts.tool_errors,
            Extraction::HookDecisions => counts.hook_decisions,
            Extraction::HookDenials => counts.hook_denials,
        }
    }
}

// ---------------------------------------------------------------------------
// Task manifests (CLOUD-856)
// ---------------------------------------------------------------------------
/// One `[[rule.tasks]]` row: a manifest whose task table the engine reads ONCE,
/// outside the mediated call (CLOUD-856).
///
/// **A declaration rather than a per-call read, and that is the row's whole
/// answer.** `Fact::Document` stays unresolvable on the mediated path because a
/// document is unbounded there; naming the manifest here moves the parse to
/// session start, where a read of that size is admissible, and leaves the call
/// reading one small keyed record.
///
/// Which file carries a task table, and under which node, is the consumer's fact
/// — non-negotiable rule 1 — so the engine learns both from this row and knows
/// nothing about either.
#[derive(
    Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize, schemars::JsonSchema,
)]
#[serde(deny_unknown_fields)]
pub struct TaskQuery {
    /// The repository-relative manifest to parse.
    ///
    /// Its bytes also key the receipt, so a manifest that changes invalidates the
    /// record by construction rather than by anyone remembering to.
    pub manifest: String,
    /// The node path the task table lives under, in [`Node::at`]'s spelling.
    pub node: String,
}

// ---------------------------------------------------------------------------
// Reductions over captured responses (CLOUD-1188)
// ---------------------------------------------------------------------------
/// One `[[rule.captured]]` row: what to reduce out of an already-captured
/// response, and how (CLOUD-1188).
///
/// **The row declares a reduction, not a read.** That asymmetry with every other
/// declared-read family here is the point: the others name a subject and the
/// module decides what to make of it, and this one cannot, because the subject is
/// a tracker payload and handing a module one would put its prose on the policy
/// input. Rule 4 is therefore decided by the declaration's shape rather than by
/// every consumer remembering it.
#[derive(
    Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize, schemars::JsonSchema,
)]
#[serde(deny_unknown_fields)]
pub struct CaptureQuery {
    /// The key this reduction is projected under in `input.tree.captured`.
    pub id: String,
    /// The token that selects which captured response answers.
    ///
    /// An opaque string the consumer supplies. The engine knows nothing about
    /// what it names — it matches captures containing it and reduces the first in
    /// handle order, which is where non-negotiable rule 1 is paid: a tracker's
    /// key vocabulary is the consumer's fact and never this crate's.
    pub key: String,
    /// The node path inside the selected response, in [`Node::at`]'s spelling.
    pub node: String,
    /// What to make of the node the path reaches.
    pub reduce: Reduction,
}

/// How a [`CaptureQuery`] turns a node into something rule 4 permits.
///
/// A closed set rather than an open expression language, deliberately: every
/// member is bounded by construction, so no row can declare a reduction that
/// yields prose. An `extract` or `matches` arm would reopen exactly that.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize, serde::Serialize, schemars::JsonSchema,
)]
#[serde(rename_all = "lowercase")]
pub enum Reduction {
    /// Whether the node exists at all — a boolean.
    Present,
    /// How many members the node has: a list's length, a map's size, `1` for a
    /// scalar. Never a length in characters, which would be a measurement of
    /// prose.
    Count,
    /// The node's scalar text, **iff** it is already a bounded token.
    ///
    /// A value carrying whitespace, or longer than [`TOKEN_MAX`], is REFUSED and
    /// the id is absent — never truncated, because a truncated payload is still a
    /// payload and a prefix of somebody's issue body is exactly what rule 4 is
    /// about.
    Token,
}

/// The longest a `token` reduction may be.
///
/// A bound rather than a guideline: `Reduction::Token`'s whole claim is that what
/// reaches the policy input is a token, and a claim with no number behind it is
/// the prose ban restated rather than enforced. Sized for a status name, a key,
/// or an identifier — comfortably past every one of those and far short of a
/// sentence.
pub const TOKEN_MAX: usize = 64;

impl Reduction {
    /// Apply this reduction to the node a path reached, or `None` where the
    /// answer would not be one rule 4 permits.
    ///
    /// [`Look::CouldNotLook`] and [`Look::IsNot`] both mean the path did not
    /// reach a node, and both answer `false` for [`Reduction::Present`] and `0`
    /// for [`Reduction::Count`] — because "the node is not there" IS the answer
    /// those two reductions were asked for. `Token` is different and returns
    /// `None`: there is no token to carry, and inventing an empty string would
    /// let a predicate comparing against `""` succeed over a node nobody read.
    #[must_use]
    pub fn apply(self, found: &Look<&Node>) -> Option<serde_json::Value> {
        let node = match found {
            Look::Is(node) => Some(*node),
            Look::IsNot | Look::CouldNotLook => None,
        };
        match self {
            Reduction::Present => Some(serde_json::json!(node.is_some())),
            Reduction::Count => Some(serde_json::json!(match node {
                Some(Node::List(items)) => items.len(),
                Some(Node::Map(entries)) => entries.len(),
                Some(_) => 1,
                None => 0,
            })),
            Reduction::Token => {
                let text = node?.scalar()?;
                // REFUSED RATHER THAN TRUNCATED. A prefix of a payload is still a
                // payload, and this is the one line that makes "tokens, not
                // prose" a property of the projection instead of a hope about
                // consumers.
                if text.is_empty()
                    || text.len() > TOKEN_MAX
                    || text.chars().any(char::is_whitespace)
                {
                    return None;
                }
                Some(serde_json::json!(text))
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Third-party tool verdicts (CLOUD-1171)
// ---------------------------------------------------------------------------
/// One `[[rule.tools]]` row: a third-party tool's verdict the engine reads back
/// from a keyed record (CLOUD-1171).
///
/// **Every field is a component of the KEY, and each refuses a different lie.**
/// A record is found only under the exact triple, so a validator pinned
/// elsewhere, or one whose answer predates a change to what it read, is not a
/// record about this repository's current state — it lives under a different
/// name and simply does not answer. That negative half is the family's safety
/// property, in the same place [`Rooted`]'s is: the declaration.
///
/// The engine knows nothing about which tools exist or what any of them checks.
/// It composes a key and reads a file, which is where non-negotiable rule 1 is
/// paid — the tool's name, its pin and its subject are the consumer's facts, in
/// the consumer's `batten.toml`.
#[derive(
    Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize, schemars::JsonSchema,
)]
#[serde(deny_unknown_fields)]
pub struct ToolQuery {
    /// The key this verdict is projected under in `input.tree["tool-verdict"]`.
    ///
    /// The declared id rather than the composed key, because a composed key
    /// carries a digest that changes every time the input does — a module
    /// written against one would have to be edited whenever the file it judges
    /// is edited.
    pub id: String,
    /// The tool's name, as the producer wrote it into the record's key.
    pub tool: String,
    /// The version the tool was PINNED at when it ran.
    ///
    /// A component of the key rather than a field inside the record, and that is
    /// deliberate: a version compared after the read is a comparison a module can
    /// forget to make, where a version in the key means a mismatched record is
    /// never found at all.
    pub version: String,
    /// The repository-relative path whose bytes the verdict was taken over.
    ///
    /// Its digest is the third component of the key, so a verdict goes stale by
    /// construction the moment the file changes — the anti-staleness half, and
    /// the one a `status: clean` marker alone could never provide.
    ///
    /// Unreadable, or outside the tree, is [`Look::CouldNotLook`]: the id is
    /// absent from the map, never present with an empty verdict.
    pub input: String,
}

impl ToolQuery {
    /// Whether any key component carries a character that would make the
    /// composed key ambiguous or reach outside the record directory.
    ///
    /// Refused at LOAD, for [`Rooted::escapes`]' reason: no state of the
    /// filesystem makes `../../x` or a name carrying the field separator an
    /// admissible declaration, so reporting it as could-not-look would present a
    /// permanent authoring error as a transient one.
    #[must_use]
    pub fn malformed(&self) -> bool {
        [self.tool.as_str(), self.version.as_str()]
            .iter()
            .any(|part| {
                part.is_empty()
                    || part.contains(KEY_SEPARATOR)
                    || part.contains('/')
                    || part.contains('\\')
            })
    }
}

/// What joins a [`ToolQuery`]'s components into one record name.
///
/// Stated once here rather than spelled at both the composing and the validating
/// site, which is the two-authorities shape `.claude/rules/policy-modules.md`
/// records for patterns, one layer down.
pub const KEY_SEPARATOR: char = '@';

// ---------------------------------------------------------------------------
// Agent-sourced facts (CLOUD-776)
// ---------------------------------------------------------------------------

/// One recorded agent-sourced fact, as it sits under the git dir.
///
/// # The channel, and why it is not a spawn
///
/// A gate that needs a fact it does not hold denies with
/// [`crate::refusal::Fix::Run`]; the agent runs that command with its own
/// binary, its own flags and its own PATH; the harness hands the result buffer
/// back as [`crate::hook::Envelope::result`]; the boundary records what it said
/// and the retry decides. **Batten executes nothing**, so house-style §5's read
/// promise is untouched — reading a buffer somebody else produced is not running
/// a program, and that is why [`AGENT_SOURCED`] can sit on `Surface::Hook` while
/// the same answer fetched by the engine could not.
///
/// It is also the cheap variant of a pattern this repository already uses.
/// "Agents fetch, gates decide" normally makes the MODEL transport the payload,
/// and CLOUD-526 priced that exactly: ~15 KB of **output** tokens per
/// `issue-read` receipt, an asymmetry that produced seven forged receipts in one
/// measured session. A tool buffer is different in kind — the model does not
/// re-type it, so there is no transcription to be unfaithful and no cost
/// proportional to the artifact.
///
/// # The shape is `issue-read-check`'s, borrowed rather than invented
///
/// **What was seen, and when it was seen**; the reader bounds the age. That is
/// already this repository's answer to a fact that goes stale with no
/// compare-and-swap available, and it is a recency bound rather than a freshness
/// proof — the same limitation, stated the same way.
///
/// # Rule 4, structural rather than careful
///
/// A command's stdout can carry anything, which makes a result buffer the
/// likeliest thing in the envelope to hold a secret. **No byte of it reaches THIS
/// record.** [`rows_in`] reduces the buffer to a COUNT at the boundary and the
/// count is what reaches disk, so a deny message, a `-J` document and everything
/// under the state root are payload-free by construction rather than by care at
/// each emission site.
///
/// The scope is this path, and stating it wider was true once and is not now
/// (CLOUD-917, which superseded the no-storage rule with the capture contract;
/// CLOUD-918/919 landed the store). Responses ARE persisted, deliberately — by
/// `capture`, under its own contract, which [`decode_response`] is the one
/// authority on and which `batten capture show <handle> --raw` hands back
/// verbatim. That is the route a payload the model must not re-type travels, and
/// the paragraph above is exactly why it is a separate store with a separate
/// contract rather than a field of a receipt.
///
/// [`decode_response`]: crate::capture::decode_response
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sourced {
    /// The command that actually ran, verbatim, so the gate can check it against
    /// what it asked for.
    pub command: String,
    /// When the agent ran it, RFC3339. Provenance beside the answer; no predicate
    /// here reads a clock (the caller supplies one, `waiver::today`'s idiom).
    pub seen_at: String,
    /// How many rows the buffer carried. **A count, never the payload.**
    pub rows: usize,
}

impl Sourced {
    /// Render the record as its on-disk lines.
    ///
    /// One `key value` pair per line, the shape every other receipt in
    /// `$GIT_DIR/batten-receipts/` uses, so a human reading that directory does
    /// not meet a second format.
    #[must_use]
    pub fn render(&self) -> String {
        format!(
            "command {}\nseen-at {}\nrows {}\n",
            self.command, self.seen_at, self.rows
        )
    }

    /// Parse a record back, or `None` if it is not one.
    ///
    /// Unreadable and unparseable both answer `None`, which [`sourced`] turns
    /// into [`Look::CouldNotLook`] — fail closed to *could not look*, never to a
    /// fact. A half-written record is exactly the case that must not read as "ran
    /// and there are none".
    #[must_use]
    pub fn parse(text: &str) -> Option<Sourced> {
        // An if/else chain rather than a `match` with a `_ =>` arm, and that is
        // this module's own gate rather than a style choice: `tests/facts.rs`
        // scans this file for wildcard arms, because `_ => Cost::Free` compiles
        // happily and classifies every future fact as cheap. The scan is
        // file-wide and blunt on purpose, so a match over STRING keys — which
        // cannot be exhaustive — is written without the token instead of the gate
        // being taught an exception it would then have to be trusted about.
        let (mut command, mut seen_at, mut rows) = (None, None, None);
        for line in text.lines() {
            let (key, value) = line.split_once(' ')?;
            if key == "command" {
                command = Some(value.to_owned());
            } else if key == "seen-at" {
                seen_at = Some(value.to_owned());
            } else if key == "rows" {
                rows = Some(value.parse().ok()?);
            }
        }
        Some(Sourced {
            command: command?,
            seen_at: seen_at?,
            rows: rows?,
        })
    }
}

/// Where one agent-sourced fact's record lives, beside the other receipts.
///
/// **Keyed on the SUBJECT the declaring row's `key` resolves to, never on the
/// name alone** (CLOUD-859). The name-only form shipped with this channel and its
/// own doc argued for it: a `claimed-key` answer is a statement about one issue
/// row at one moment, so keying it to a branch would make the same answer
/// unavailable to the next branch that needs it. That reasoning is right for a
/// fact about an *issue* and wrong for a fact about a *head*, and hard-coding it
/// made the difference inexpressible — a `receipt` row could declare
/// `key = "head"`, `rules::validate` would hold it to one keying per check, and
/// the record would file under the name regardless. Measured: a record minted
/// clear on one head still satisfied its check on the next commit, so the gate
/// bound once per branch.
///
/// So the reading that doc defends is now spelled `key = "branch"` rather than
/// built in, and both readings are expressible. The subject is HEAD's SHA under
/// [`crate::rules::ReceiptKey::Head`], the branch name under
/// [`crate::rules::ReceiptKey::Branch`], and the call's own value under
/// [`crate::rules::ReceiptKey::Named`] — the same three subjects
/// `receipt::verdicts` already resolves for the receipt store, resolved once at
/// the boundary because `adjudicate` may not look.
///
/// Both components are `/`-substituted: a branch name legitimately carries
/// separators and a filename may not. The spelling matches
/// `receipt::branch_receipt_name`'s for the same reason it does there — two
/// spellings of one filename are two things to drift.
#[must_use]
pub fn sourced_path(git_dir: &std::path::Path, name: &str, subject: &str) -> std::path::PathBuf {
    git_dir.join("batten-receipts").join(format!(
        "fact.{}.{}",
        name.replace('/', "-"),
        subject.replace('/', "-")
    ))
}

/// What a recorded answer means, given the command the gate asked for.
///
/// A pure function of the record and the request — no clock, no filesystem —
/// which is what lets the whole contract be tested without a world.
///
/// **Two different failures share [`Look::CouldNotLook`], and that is the point.**
/// No record means the agent never ran it. A record naming a different command
/// means something ran and it was not what was asked for. Neither is a fact, and
/// both call for the same remedy — run *the* command — so they answer the same
/// arm rather than tempting a caller to treat one of them as evidence.
///
/// The command comparison is byte equality, deliberately. The agent picks WHICH
/// command runs; it does not author what the output says. Any normalisation is a
/// gap between what was asked and what is accepted, and a fact keyed to a
/// `Fix::Run` nobody verifies is CLOUD-526's forgery gradient on a new surface.
#[must_use]
pub fn sourced(record: Option<&Sourced>, asked_for: &str) -> Look<usize> {
    match record {
        Some(record) if record.command == asked_for => Look::Is(record.rows),
        Some(_) | None => Look::CouldNotLook,
    }
}

/// Reduce a tool result buffer to a row count by **normalising it to an array**,
/// or [`Look::CouldNotLook`] where no count can honestly be given.
///
/// # Why normalise rather than refuse (CLOUD-992)
///
/// This function used to read exactly two shapes — a bare row array and the
/// content-block envelope — and answer could-not-look for everything else. The
/// reasoning was sound and is preserved below: **answering `0` for a buffer this
/// build cannot read would be a guessed envelope becoming a silent fact.**
///
/// What was wrong is that refusing is not the only way to avoid that, and it made
/// the channel **unusable from any shell tool**. Measured on real Bash responses:
/// every one is raw text, so the first match arm rejected it. The channel's first
/// intended consumer declares a `gh` command, so it would have seen could-not-look
/// on every call — a gate refusing every `gh pr ready`, unsatisfiable by running
/// the very command its deny prints.
///
/// The alternative considered and rejected was making each declared command
/// project an array (`gh … --jq '[…]'`). That puts the obligation on every future
/// fact row, fails as could-not-look rather than loudly when forgotten, and is
/// invisible in the rule that consumes it.
///
/// # The table
///
/// | buffer | rows |
/// | -- | -- |
/// | JSON array that is not wholly content blocks | its length — an empty one is a genuine zero |
/// | content-block envelope (EVERY item a content block) | the sum over its blocks, each normalised by the rules below — could-not-look if ANY block says nothing |
/// | a shell tool's envelope object (`{stdout, stderr}`) | its stream text, normalised by the rules below — the buffer is a MEMBER, never the object |
/// | any other JSON object, or any non-string scalar | `1` — one element, wrapped |
/// | text that parses as a JSON array | that array's length |
/// | text that parses as any other JSON value | `1` |
/// | text that is not JSON at all | `1` — one opaque row |
/// | text that is empty or whitespace | could-not-look — see below |
/// | [`serde_json::Value::Null`] | could-not-look — an absent buffer is not a reading |
///
/// **The invariant that must not regress: no unread shape is ever reported as
/// `0`.** Wrapping preserves it exactly as refusing did — an opaque buffer counts
/// as one row, never none — so a `rows == 0` predicate stays fail-closed.
///
/// **The empty buffer is the one place the three-valued reading survives, and it
/// earns it.** A command that failed and printed nothing is indistinguishable
/// from one that legitimately found nothing, so `0` and `1` are both guesses:
/// `0` would let an unreviewed head through, `1` would deny a gate forever. Only
/// could-not-look states what is actually known.
///
/// A tool whose output cannot be parsed as JSON wants an **adapter** rather than
/// this fallback — the one-opaque-row reading keeps a gate fail-closed in the
/// meantime and is inventoried as debt (CLOUD-993), not left as the design.
///
/// No byte of the buffer is returned (rule 4). The count is the whole answer.
#[must_use]
pub fn rows_in(result: &serde_json::Value) -> Look<usize> {
    match result {
        // An absent buffer is not a reading. Distinct from an empty one, which
        // at least says a tool answered.
        serde_json::Value::Null => Look::CouldNotLook,
        serde_json::Value::Array(items) => {
            // ENVELOPE SEMANTICS DEMAND THE WHOLE ARRAY, NOT A MEMBER OF IT. A
            // row array may legitimately contain a row that happens to be
            // text-shaped, and treating that array as an envelope reads the one
            // block and DROPS every other row: `[{"type":"text","text":"[]"},
            // {"id":1}]` answered `Is(0)` for two rows, breaking the fail-closed
            // invariant this function exists to hold. So an array is an envelope
            // only when every item is a content block; anything else is a bare
            // row array and counts its items.
            //
            // An EMPTY array lands here too and is a genuine zero — a shape we
            // read that carried nothing, not a shape we failed to read.
            if items.is_empty() || !items.iter().all(is_text_block) {
                return Look::Is(items.len());
            }
            // The content-block envelope an MCP tool returns. Each block's text
            // goes through the same normalisation a bare text buffer does, so the
            // two entry points cannot disagree about one string.
            // NO BLOCK IS SKIPPED, and that is the whole of this loop's contract.
            // `is_text_block` guarantees a string `text`, so nothing can be
            // silently filtered out here — a `filter_map` over the field would
            // drop a block it could not read and then report the SUM OF THE REST
            // as the buffer's count, which is how a partly-unreadable envelope
            // came back `Is(0)`.
            //
            // And one unreadable block condemns the whole envelope. A block
            // saying nothing contributes no knowable count, so folding it in as
            // `0` would be a guess presented as a reading; could-not-look is the
            // only honest answer for the buffer as a whole. That is also what
            // keeps the single-empty-block envelope could-not-look, as it has
            // always been.
            let mut rows = 0;
            for block in items {
                let Some(text) = block.get("text").and_then(serde_json::Value::as_str) else {
                    return Look::CouldNotLook;
                };
                let Some(count) = rows_in_text(text) else {
                    return Look::CouldNotLook;
                };
                rows += count;
            }
            Look::Is(rows)
        }
        serde_json::Value::String(text) => rows_in_text(text).map_or(Look::CouldNotLook, Look::Is),
        // A SHELL TOOL'S BUFFER IS A MEMBER OF THIS OBJECT, NEVER THE OBJECT.
        // This is the arm the whole capability turned on and the one a shape
        // table could not see: Claude Code hands a Bash call's response back as
        // `{stdout, stderr, …}`, so counting the object gives `1` for every
        // shell command ever declared — measured, `printf '[1,2,3]'` recorded
        // `rows 1`. Normalising buffers was necessary and not sufficient,
        // because the buffer never arrived as one.
        //
        // `capture::decode_response` is the ONE authority on that shape. It
        // already reads `stdout` then `stderr` in a declared order, already
        // says so against the measured corpus, and is already the reader the
        // capture store trusts. A second copy of the field list here is the
        // "two copies drifted" failure this repository keeps recording — so
        // this defers to it rather than restating it.
        serde_json::Value::Object(_) => match crate::capture::decode_response(result) {
            // A shell envelope: count what the tool actually printed.
            Ok(decoded) if decoded.blocks > 0 => match std::str::from_utf8(&decoded.bytes) {
                Ok(text) => rows_in_text(text).map_or(Look::CouldNotLook, Look::Is),
                // Bytes that are not text are a shape this build did not read,
                // never a buffer that carried nothing.
                Err(_) => Look::CouldNotLook,
            },
            // An object carrying no readable stream member is not an envelope at
            // all — it is a single JSON row, which is one element wrapped.
            Ok(_) | Err(_) => Look::Is(1),
        },
        // A single number or boolean is one element. Wrapping it is what makes
        // the count obvious rather than making the caller project.
        serde_json::Value::Number(_) | serde_json::Value::Bool(_) => Look::Is(1),
    }
}

/// How many rows one text buffer carries, by the table on [`rows_in`], or
/// `None` when it says nothing at all.
///
/// Split out because the bare-string arm and every text block inside a
/// content-block envelope must answer identically — a second copy of this rule
/// is how the two entry points come to disagree about the same string.
///
/// `Option<usize>` rather than [`Look<usize>`]: a count has only two outcomes
/// here, and `Look`'s third — [`Look::IsNot`] — is not one of them. Returning
/// `Look` would put an arm on every caller that no input can reach, and a
/// wildcard over it is exactly how a future third outcome would be silently
/// folded into "nothing to add".
fn rows_in_text(text: &str) -> Option<usize> {
    if text.trim().is_empty() {
        // Nothing was said. Neither `0` nor `1` is knowable here; see the doc.
        return None;
    }
    match serde_json::from_str::<serde_json::Value>(text) {
        Ok(serde_json::Value::Array(inner)) => Some(inner.len()),
        // Any other JSON value is one element; prose that does not parse is one
        // opaque row. Both are "we saw something", which is what matters.
        Ok(_) | Err(_) => Some(1),
    }
}

/// How many rows a buffer carries GIVEN what its command promised (CLOUD-993).
///
/// The shape-declaring counterpart to [`rows_in`], and the difference between
/// them is the whole of this change: `rows_in` infers a shape from the bytes,
/// this one CHECKS the bytes against a shape somebody stated. A mismatch is
/// [`Look::CouldNotLook`] — never a count — so a command that quietly stops
/// emitting what it declares fails loudly instead of reporting a plausible `1`
/// forever and silently making a `rows == 0` predicate unsatisfiable.
///
/// The envelope question is [`rows_in`]'s and is not repeated here: where the
/// buffer LIVES (a bare string, a content-block array, a shell tool's
/// `{stdout, stderr}` object) is orthogonal to what SHAPE it promised, and
/// `decode_response` is the one authority on the first. So this decodes through
/// the same path and then judges the text.
///
/// # Rule 4
///
/// A mismatch verdict carries no byte of the buffer. The caller renders the
/// fact's NAME and the shape it DECLARED — both already in hand from config —
/// because a buffer that failed to parse is the likeliest thing in the envelope
/// to be holding a secret, and quoting it in a deny is how that would escape.
#[must_use]
pub fn rows_declared(result: &serde_json::Value, returns: Returns) -> Look<usize> {
    // WHICH CONTRACT, NAMED VARIANT BY VARIANT. No wildcard on either axis:
    // `tests/facts.rs`'s `no_axis_match_carries_a_wildcard_arm` refuses one, and
    // its reasoning is exactly this function's risk — a `_` arm would classify a
    // future `Returns` variant silently, and the direction it would classify it
    // in is "satisfied", which is the expensive one.
    //
    // The decode comes FIRST, because could-not-look is the answer under every
    // declaration: an envelope this build cannot read, and a buffer that said
    // nothing at all, are facts about the reading rather than about the shape.
    // Shared rather than repeated per arm, which is also what keeps `Opaque`
    // three-valued instead of collapsing an empty buffer into a row.
    let Some(text) = buffer_text(result) else {
        return Look::CouldNotLook;
    };
    if text.trim().is_empty() {
        return Look::CouldNotLook;
    }
    let demands_array = match returns {
        Returns::JsonArray => true,
        Returns::Json => false,
        // `Opaque` DISCLAIMS THE SHAPE, so counting elements would be an
        // inference the declaration explicitly refused to make — the guess this
        // whole field exists to end. It read as `rows_in` at first, on the
        // reasoning that a contract promising nothing has nothing to check; that
        // is backwards. `rows_in` parses `"[1,2]"` as TWO rows, which is a claim
        // about a shape nobody declared, and it left one of three variants
        // defeating the change's own thesis. A command that promises nothing and
        // answered gives exactly one opaque answer.
        //
        // Nothing is lost by it: a consumer that wants the length has
        // `json-array`, and one that wants a single JSON value has `json`. There
        // is no coherent third want — "count the elements but do not promise
        // there are elements" is the inference, spelled as a declaration.
        Returns::Opaque => return Look::Is(1),
    };
    let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&text) else {
        // Prose under a JSON contract. THE case this function exists for: the
        // interim reading counted this as one opaque row, which is
        // indistinguishable from the tool honestly finding one thing.
        return Look::CouldNotLook;
    };
    // One axis now — the JSON shape — with every variant named, for the reason
    // the `demands_array` match above names every contract.
    match parsed {
        // An array satisfies both JSON contracts, and its length is the count.
        serde_json::Value::Array(rows) => Look::Is(rows.len()),
        // Every other JSON shape. Under `json-array` it is a mismatch: a JSON
        // OBJECT here is the raw `gh api graphql` shape, which counts as `1`
        // under the inferring reader and looks entirely fine, so declaring the
        // array is what turns a missing `--jq '[…]'` projection into a refusal.
        // Under `json` the same value is legitimate and counts as one element.
        serde_json::Value::Object(_)
        | serde_json::Value::String(_)
        | serde_json::Value::Number(_)
        | serde_json::Value::Bool(_)
        | serde_json::Value::Null => {
            if demands_array {
                Look::CouldNotLook
            } else {
                Look::Is(1)
            }
        }
    }
}

/// The buffer's text, wherever the envelope keeps it (CLOUD-993).
///
/// Extracted so [`rows_declared`] can judge a shape without re-deriving where
/// the bytes live. The three shapes are [`rows_in`]'s and stay its authority; a
/// content-block envelope concatenates its blocks, which is the same summing
/// `rows_in` does one level up.
fn buffer_text(result: &serde_json::Value) -> Option<String> {
    match result {
        serde_json::Value::String(text) => Some(text.clone()),
        serde_json::Value::Object(_) => crate::capture::decode_response(result)
            .ok()
            .filter(|decoded| decoded.blocks > 0)
            .and_then(|decoded| String::from_utf8(decoded.bytes).ok()),
        serde_json::Value::Array(items) if items.iter().all(is_text_block) => {
            let mut joined = String::new();
            for block in items {
                joined.push_str(block.get("text").and_then(serde_json::Value::as_str)?);
            }
            Some(joined)
        }
        // A bare row array carries rows, not text: there is no string to check a
        // declared shape against, and `rows_in` already counts it correctly.
        // Answering `None` sends that to could-not-look, which is honest — the
        // declaration said the COMMAND emits an array, and an already-decomposed
        // array is not something this path can attribute to it.
        serde_json::Value::Array(_)
        | serde_json::Value::Null
        | serde_json::Value::Number(_)
        | serde_json::Value::Bool(_) => None,
    }
}

/// Whether one array item is a content block this build can read in full.
///
/// **A STRING `text` IS PART OF THE SHAPE, not a detail the reader checks
/// later.** Keying only on `type` admitted `{"type":"text","text":7}` as a
/// block, and the envelope loop then had to cope with a block it could not
/// read — which it did by skipping it, so
/// `[{"type":"text","text":"[]"},{"type":"text","text":7}]` answered `Is(0)`
/// for a buffer half of which was never read.
///
/// Requiring the string here fixes it in the one place that decides, and it
/// decides in the more useful direction: a malformed block is not a content
/// block, so its array is not an envelope at all and counts as ordinary rows.
/// Two rows is what that buffer carries, and saying so beats refusing it.
fn is_text_block(value: &serde_json::Value) -> bool {
    value.get("type").and_then(serde_json::Value::as_str) == Some("text")
        && value.get("text").is_some_and(serde_json::Value::is_string)
}

/// The JSON a tool actually returned, unwrapped from the envelope it arrived in
/// (CLOUD-1024).
///
/// **The envelope is the shape, and a reader that skips this sees nothing.**
/// [`rows_in`] one function up already knows that an MCP tool answers with a
/// content-block array whose `text` carries the real payload; a caller that wants
/// the payload's FIELDS rather than a count needs the same knowledge, and a
/// second copy of it is the drift this shares the [`is_text_block`] predicate to
/// avoid.
///
/// Measured, and only against the live host: a mint reading `result.get("id")`
/// passed every fixture — a test hands the engine a bare object — and matched
/// nothing at all in production, because the connector wraps every response.
/// That is the same class as the capture subsystem's own decode, which is why
/// the capture store kept working while the field reader saw an array with no
/// members it recognised.
///
/// `None` where no JSON can honestly be recovered. Distinct from a payload that
/// parses to `null`, which is a reading of nothing rather than a failure to read
/// — the three-valued discipline [`Look`] states for the count.
#[must_use]
pub fn payload_in(result: &serde_json::Value) -> Option<serde_json::Value> {
    match result {
        // An envelope only when EVERY item is a content block, which is
        // `rows_in`'s rule and for its reason: a row array may legitimately hold
        // a text-shaped row, and reading that as an envelope would drop every
        // other row.
        serde_json::Value::Array(items) if !items.is_empty() && items.iter().all(is_text_block) => {
            let joined: String = items
                .iter()
                .filter_map(|item| item.get("text").and_then(serde_json::Value::as_str))
                .collect();
            serde_json::from_str(&joined).ok()
        }
        // The other envelope the survey records: the blocks under a `content`
        // member rather than at the top level.
        serde_json::Value::Object(members) => {
            // An `if let` rather than a `match`, because the wildcard arm the
            // other spelling needs is refused by `no_axis_match_carries_a_
            // wildcard_arm` — a text scan over this module, which cannot tell an
            // `Option` match from an axis one and is right not to try.
            if let Some(inner @ serde_json::Value::Array(_)) = members.get("content") {
                payload_in(inner)
            } else {
                // An ordinary object IS the payload. The common case, and the one
                // every fixture exercises.
                Some(result.clone())
            }
        }
        // A tool that answered with a JSON string still answered.
        serde_json::Value::String(text) => serde_json::from_str(text).ok(),
        serde_json::Value::Null => None,
        // A bare array that is NOT an envelope, and the two scalars. Each is a
        // real answer carrying no members, so it is returned rather than refused
        // — a caller's required projection is what decides it says nothing, and
        // deciding that here would be a second place the same question is asked.
        //
        // Spelled out rather than left to a wildcard: `no_axis_match_carries_a_
        // wildcard_arm` refuses one, so a value variant added later fails to
        // compile instead of classifying itself (CLOUD-757).
        serde_json::Value::Array(_) | serde_json::Value::Bool(_) | serde_json::Value::Number(_) => {
            Some(result.clone())
        }
    }
}

/// One agent-sourced fact a consumer declares: its name, and the command whose
/// output answers it.
///
/// # Why the command is CONFIG rather than a crate constant
///
/// Non-negotiable rule 1. `gh pr list --search …` names a forge, a query syntax
/// and a workflow — all of them a consumer's facts, none of them the engine's.
/// The core knows that an agent-sourced fact has a name and a command; which
/// command answers which question is `batten.toml`'s.
///
/// # One value, read twice, which is the point
///
/// The same string is the command the deny asks the agent to run AND the command
/// the record is checked against. That is deliberate and is the lesson of the two
/// issues this one follows: CLOUD-779 and CLOUD-601 were both a harness-level
/// declaration kept in step BY HAND with the reachability it implied, and both
/// drifted. A fix text and a verification target that could disagree would be the
/// same defect a third time, on a surface where the disagreement is a forged
/// fact rather than a silent allow.
#[derive(
    Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
#[serde(deny_unknown_fields)]
pub struct Declared {
    /// The fact's name — the token a `receipt` row's `checks` list refers to,
    /// and the key its record is stored under.
    pub name: String,
    /// The command whose output answers it, verbatim.
    ///
    /// Read twice, and the same bytes both times: it is what the deny tells the
    /// agent to run, and what the stored record is compared against.
    ///
    /// **Optional since CLOUD-690, and exactly one of this or [`Declared::tool`]
    /// is required** — refused at load by [`validate`], never defaulted, because a
    /// row answering to neither selects nothing and a row answering to both has
    /// two forgery controls that can disagree.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    /// The tool whose RESULT answers it, matched by
    /// [`crate::rules::selects_tool_name`] (CLOUD-690).
    ///
    /// The alternative to `command`, and it exists because a command's transport
    /// can be unavailable where the same data reaches a tool. Measured: the
    /// declared `gh api graphql` behind CLOUD-859's review gate is refused by a
    /// proxy that serves the same review threads through an MCP tool, so the gate
    /// was unsatisfiable and running the command its own deny printed returned
    /// 403.
    ///
    /// **The forgery control changes shape rather than disappearing.** A `command`
    /// row is protected by byte-equality against what the agent ran; a `tool` row
    /// is protected by the selector, because the agent does not choose which tool
    /// a host reports. It is the same control `[[mint]]` relies on, through the
    /// same function, so there is no second matcher to drift.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool: Option<String>,
    /// A path to the array whose MATCHING elements are counted (CLOUD-690).
    ///
    /// Without it the whole result is reduced by [`rows_declared`], which is the
    /// pre-CLOUD-690 behaviour and stays the default. With it, the count is over
    /// the elements of that array which satisfy [`Declared::matching`] — the
    /// capability CLOUD-690 records, and the one neither `[[mint]]`'s `requires`
    /// (presence, not absence) nor `rows_in` (every element, unfiltered) can
    /// express.
    ///
    /// It does not retire [`Declared::returns`]: `opaque` beside it is refused at
    /// load, and `json-array` still requires the buffer itself to be an array
    /// before the path is walked. A column this reading ignored would be the
    /// accepted-and-unread defect one layer down.
    ///
    /// A path that is absent, or present and not an array, is **could-not-look**
    /// rather than zero matches. That is this row's own inherited constraint —
    /// CLOUD-310 defect 1, a scanner that found nothing and exited 0 — and the
    /// distinction `rows_in` already draws one function up.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub counts: Option<String>,
    /// The predicate each counted element must satisfy: path to literal,
    /// **equality only, `ANDed`** (CLOUD-690).
    ///
    /// Spelled `where` in config and `matching` in Rust, because `where` is a
    /// keyword. Empty means every element of `counts` matches, which is a genuine
    /// reading — *how many elements are there* — and not a missing predicate.
    ///
    /// **Deliberately not a query language.** No operators, no negation, no
    /// field-to-field comparison, no nesting beyond a path. Each of those is a
    /// step toward the `conf.d` merge house style §8 refuses, and the measured
    /// consumer needs none of them; the one thing it does need and cannot have —
    /// comparing a review's author to the PR's — is named on CLOUD-690 as
    /// CLOUD-859's to solve rather than quietly admitted here.
    #[serde(
        default,
        rename = "where",
        skip_serializing_if = "std::collections::BTreeMap::is_empty"
    )]
    pub matching: std::collections::BTreeMap<String, Literal>,
    /// Conditions beside the collection, each holding one adding to the count
    /// (CLOUD-690, restoring what CLOUD-859's projection carried).
    ///
    /// **The shape `counts`/`where` structurally cannot reach.** Those two speak
    /// about elements OF an array; this speaks about a scalar sitting next to it,
    /// evaluated against the whole payload. The measured instance is a page cap:
    /// `pageInfo.hasNextPage` is `true` beside a `review_threads` array that is
    /// therefore incomplete, and an unresolved thread outside that page would
    /// leave the count at zero — a false green in the one direction the gate
    /// exists to prevent.
    ///
    /// **Nothing else can express it, which is why it is a column rather than
    /// config.** A second `[[fact]]` cannot: a `counts` path resolving to a bool
    /// answers could-not-look, so a row asserting `hasNextPage == false` would
    /// deny forever instead of passing when the page is complete. A Rego module
    /// cannot either: `input.call` carries the tool's NAME and never its
    /// arguments, so no predicate can even require a full page be asked for.
    ///
    /// Same vocabulary as [`Declared::matching`] deliberately — the same
    /// `Literal`, the same path grammar, equality only — so this adds a place a
    /// predicate may be evaluated and not a second predicate language.
    ///
    /// Rule 4 holds identically: a clause NAMES a path, and what is found there
    /// is compared and discarded. The count is the whole output.
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub blocking: std::collections::BTreeMap<String, Literal>,
    /// Which INVOCATIONS of the declared tool answer this row, read over the
    /// call's own input object (CLOUD-690).
    ///
    /// **The selector names a tool; this names the call.** One tool serves several
    /// methods, and the method is an ARGUMENT rather than part of the name the
    /// host attributes the result to — so `tool` alone cannot tell one method's
    /// result from another's, and [`Declared::counts`] can only discriminate them
    /// when their payloads happen to differ in shape. Measured, that happened not
    /// to hold: `pull_request_read`'s `get_reviews` and `get_files` both answer
    /// with a bare top-level array, so a row counting `.` over the tool recorded
    /// a non-zero count from a FILE listing and satisfied a check that asks
    /// whether a review exists. Shape is a proxy for the method; this is the
    /// method.
    ///
    /// **It only ever narrows.** A row carrying no clause records from every call
    /// the selector matches, which is the behaviour every row had before this
    /// column; a clause means FEWER calls mint a record, so a check naming the row
    /// denies at least as often. There is no spelling here that lets one more
    /// call satisfy a gate.
    ///
    /// Refused beside `command` at load: a command row's forgery control is
    /// byte-equality over the whole command line, so the arguments are already in
    /// what is compared and a second, weaker predicate over the same bytes could
    /// only disagree with it.
    ///
    /// Same vocabulary as [`Declared::matching`] and [`Declared::blocking`] — the
    /// same `Literal`, the same path grammar, equality only — so this adds a third
    /// place a predicate is evaluated and not a third predicate language. Rule 4
    /// holds identically: a clause NAMES a path, and what is found there is
    /// compared and discarded.
    #[serde(
        default,
        rename = "when",
        skip_serializing_if = "std::collections::BTreeMap::is_empty"
    )]
    pub called_with: std::collections::BTreeMap<String, Literal>,
    /// What the command promises to return (CLOUD-993).
    ///
    /// **Required, with no default**, and that is the whole point. Before this
    /// field, `rows_in` inferred the shape from the bytes on every call, and the
    /// inference was wrong three times in two days — each time producing a
    /// plausible NUMBER rather than an error, which is the worst available
    /// failure. A default would put the inference straight back: the row would
    /// stop stating a contract and start inheriting one.
    ///
    /// The migration cost is zero because this repository declares no `[[fact]]`
    /// rows yet, which is exactly why the field arrives required now rather than
    /// optional-then-tightened.
    pub returns: Returns,
}

/// How many elements of the declared collection satisfy the declared predicate
/// (CLOUD-690).
///
/// This is the capability CLOUD-690 records, and the reason it is needed rather
/// than convenient: [`rows_in`] counts EVERY element of a result, so a gate whose
/// question is *how many are still unresolved* reads a head with all its threads
/// answered as still blocking. The count is not inconvenient there, it is wrong.
///
/// # Could-not-look, never zero
///
/// An absent path, a path whose value is not an array, and an unreadable envelope
/// all answer [`Look::CouldNotLook`]. Zero is reserved for *the array was there
/// and nothing in it matched*, which is the only reading that means the gate may
/// pass. CLOUD-310 defect 1 — a scanner that found nothing and exited `0`, a
/// permanent silent green — is this row's own inherited constraint, and this is
/// where it is honoured.
///
/// # Rule 4
///
/// The return is a count. No matched element, and no value read at a `where`
/// path, is returned, stored or rendered anywhere — which is what lets a
/// consumer's `where` name a value without that value becoming a payload the
/// engine carries.
#[must_use]
pub fn counted(result: &serde_json::Value, declared: &Declared) -> Look<usize> {
    let Some(path) = declared.counts.as_deref() else {
        // No collection declared: the pre-CLOUD-690 reading, unchanged, which is
        // Acceptance's "a row declaring neither column behaves exactly as before".
        return rows_declared(result, declared.returns);
    };
    // The SAME normalisation every other reader on this path uses. A shell tool's
    // buffer is a member of its envelope (CLOUD-859's measurement) and an MCP
    // tool's is a content-block array, so the payload has to be lifted out before
    // a path means anything — and doing that here rather than reimplementing it
    // is why a `tool`-selected row and a `command`-selected one see one shape.
    let Some(payload) = payload_in(result) else {
        return Look::CouldNotLook;
    };
    // The declared shape decides before the path does, so `returns` is a contract
    // on this path too and not a column the counting reading quietly steps over.
    // `opaque` cannot reach here — `validate` refuses it beside `counts` — and
    // `json` promises only that the buffer is JSON, which `payload_in` has
    // already established.
    if declared.returns == Returns::JsonArray && !payload.is_array() {
        return Look::CouldNotLook;
    }
    // `.` IS THE PAYLOAD ITSELF, and it needs a spelling because two obvious ones
    // do not work: the empty string is refused by `validate` (an empty `counts` is
    // a row that names no collection), and `[]` iterates, so it selects N values
    // where the slice pattern below requires one array. A tool answering with a
    // bare top-level array — `pull_request_read`'s `get_reviews` is the measured
    // one — is otherwise uncountable.
    let selected = if path == "." {
        vec![&payload]
    } else {
        let Some(selected) = crate::mint::select(&payload, path) else {
            return Look::CouldNotLook;
        };
        selected
    };
    // Exactly one array. A path selecting several values is a path the consumer
    // wrote expecting one collection, and summing them would answer a question
    // nobody asked.
    let [collection] = selected.as_slice() else {
        return Look::CouldNotLook;
    };
    let Some(elements) = collection.as_array() else {
        return Look::CouldNotLook;
    };
    let matched = elements
        .iter()
        .filter(|element| matches_every_clause(element, &declared.matching))
        .count();
    // EACH BLOCKING CONDITION IS ONE MORE, which is the arithmetic the `--jq`
    // projection this replaces did by emitting an extra element. Added rather than
    // short-circuiting to a refusal, because the consumer's predicate is a count
    // and a caller that wants "any blocking condition" already spells it `> 0`.
    let beside = declared
        .blocking
        .iter()
        .filter(|(path, wanted)| holds_over(&payload, path, wanted))
        .count();
    Look::Is(matched + beside)
}

/// Whether one condition beside the counted collection holds over the payload.
///
/// The element-scoped twin is [`matches_every_clause`], and the two share
/// [`Literal::matches`] so a `where` clause and a `blocking` clause can never
/// disagree about what equality means. Written without a `match` for that
/// function's reason: `tests/facts.rs` scans this module for wildcard arms.
///
/// **An unresolvable path does not hold**, which is the same direction the
/// element twin takes and the safe one here: a mistyped `blocking` path adds
/// nothing rather than refusing every call, so the failure is a gate that is no
/// stronger than before rather than one nobody can clear.
fn holds_over(payload: &serde_json::Value, path: &str, wanted: &Literal) -> bool {
    let Some(found) = crate::mint::select(payload, path) else {
        return false;
    };
    let [only] = found.as_slice() else {
        return false;
    };
    wanted.matches(only)
}

/// Whether one element of a counted collection satisfies every declared clause.
///
/// Extracted from [`counted`] and written WITHOUT a `match`, which is this
/// module's own gate rather than a style choice: `tests/facts.rs` scans this file
/// for wildcard arms, because `_ => Cost::Free` compiles happily and classifies
/// every future fact as cheap. A slice pattern cannot be exhaustive, so the
/// alternative here would be teaching that scan an exception it would then have to
/// be trusted about.
///
/// **A clause whose path does not resolve in THIS element is not a match, and that
/// is not could-not-look.** The collection was readable; this element simply does
/// not satisfy the predicate. Reading a missing key as unknowable would let one
/// odd element take the whole count to could-not-look, which is a verdict about
/// the array drawn from a fact about one of its members.
fn matches_every_clause(
    element: &serde_json::Value,
    clauses: &std::collections::BTreeMap<String, Literal>,
) -> bool {
    clauses.iter().all(|(path, wanted)| {
        let Some(found) = crate::mint::select(element, path) else {
            return false;
        };
        // Exactly one value, for `counted`'s reason one level up: a clause path
        // selecting several is a path the consumer wrote expecting one leaf.
        let [only] = found.as_slice() else {
            return false;
        };
        wanted.matches(only)
    })
}

impl Declared {
    /// What answers this fact — the declared command, or the declared tool.
    ///
    /// **One spelling, because it is stored and compared** (CLOUD-690).
    /// [`Sourced::command`] holds this value and [`sourced`] compares against it,
    /// so a row's two possible selectors must collapse to one string here or the
    /// writer and the reader disagree about what a satisfied record looks like.
    /// [`validate`] refuses a row with neither, so the fallback is unreachable
    /// through a loaded config and exists only to keep this total.
    #[must_use]
    pub fn answered_by(&self) -> &str {
        // EXHAUSTIVE, with no tuple wildcard: `tests/facts.rs` scans this file for
        // `_ =>`, `_ if` and `, _)` alike, because an axis match that classifies a
        // future variant silently is the one mistake here that is expensive in a
        // predictable direction. A 2-tuple of options has four arms, so totality
        // costs nothing and the compiler keeps giving it.
        match (self.command.as_deref(), self.tool.as_deref()) {
            (Some(command), None) => command,
            // Refused at load by `validate`, so unreachable through a config; the
            // command wins here rather than panicking, because a policy assembled
            // in-process should not be able to abort a hook.
            (Some(command), Some(_ignored_tool)) => command,
            (None, Some(tool)) => tool,
            (None, None) => "",
        }
    }

    /// Whether this row is answered by a call the host attributed to `raw_tool`
    /// running `command` (CLOUD-690).
    ///
    /// The two selectors, and their two different forgery controls: a `command`
    /// row is byte-equality against what the agent ran, because the agent chooses
    /// the command; a `tool` row is [`crate::rules::selects_tool_name`], because
    /// the agent does not choose what the host calls the tool it just ran.
    #[must_use]
    pub fn answered_here(&self, raw_tool: &str, command: &str) -> bool {
        match (self.command.as_deref(), self.tool.as_deref()) {
            (Some(declared), None) => declared == command,
            // As `answered_by`: refused at load, and the command's byte-equality is
            // the stricter of the two controls, so it is the one that decides.
            (Some(declared), Some(_ignored_tool)) => declared == command,
            (None, Some(selector)) => crate::rules::selects_tool_name(selector, raw_tool),
            (None, None) => false,
        }
    }

    /// Whether this row's [`Declared::called_with`] clauses hold over the call's
    /// own input object (CLOUD-690).
    ///
    /// The second half of selection, asked beside [`Declared::answered_here`]:
    /// that one decides which TOOL answers the row, this one decides which of its
    /// invocations. An empty clause set is `true`, so a row that names no call
    /// keeps the pre-column behaviour exactly.
    ///
    /// **An unresolvable path does not select**, which is the opposite direction
    /// from [`holds_over`]'s and deliberately so: there, a mistyped path adds
    /// nothing to a count and leaves a gate no weaker than before; here, reading a
    /// missing `method` as a match would put back the very over-selection this
    /// column exists to remove. Both directions are the one that cannot turn a
    /// typo into a satisfied gate.
    #[must_use]
    pub fn selected_by(&self, input: &serde_json::Value) -> bool {
        matches_every_clause(input, &self.called_with)
    }
}

/// One scalar a [`Declared::matching`] entry compares against.
///
/// **A closed set of three, not `serde_json::Value`.** An arbitrary value would
/// admit an object or an array on the right-hand side of an equality, which is
/// either a nested predicate nobody specified or a deep comparison whose cost is
/// unbounded — and both are the query language CLOUD-690's refinement exists to
/// keep out. Three scalars are what a tool result's leaves actually are.
#[derive(
    Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
#[serde(untagged)]
pub enum Literal {
    /// A boolean, which is the measured consumer's case (`isResolved = false`).
    Bool(bool),
    /// An integer. Floats are deliberately absent: equality over them is a trap,
    /// and no surveyed tool result keys a decision on one.
    Integer(i64),
    /// A string.
    Text(String),
}

impl Literal {
    /// Whether `found` is this literal.
    ///
    /// Typed rather than stringly: comparing `"false"` to `false` would make a
    /// config that looks right decide wrong, and a tool result's booleans are
    /// booleans.
    #[must_use]
    fn matches(&self, found: &serde_json::Value) -> bool {
        match self {
            Literal::Bool(wanted) => found.as_bool() == Some(*wanted),
            Literal::Integer(wanted) => found.as_i64() == Some(*wanted),
            Literal::Text(wanted) => found.as_str() == Some(wanted.as_str()),
        }
    }
}

/// What a declared command promises its output looks like (CLOUD-993).
///
/// **Three values, deliberately, and the smallness is a design constraint rather
/// than a starting point.** A vocabulary that grows a variant per tool is the
/// inference problem again with more syntax — the reader would be back to asking
/// which of fifteen shapes arrived. These three are the distinctions a COUNT can
/// actually rest on: a sequence whose length means something, a single value, and
/// nothing promised at all.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "kebab-case")]
pub enum Returns {
    /// The decoded buffer parses as a JSON array; `rows` is its length.
    ///
    /// An empty array is a GENUINE ZERO — the reading a review gate rests on,
    /// where `rows == 0` has to mean "the command looked and found none" rather
    /// than "nobody looked". Anything that is not an array is a mismatch and
    /// answers could-not-look, which is what catches a command that quietly
    /// stopped emitting JSON.
    JsonArray,
    /// The decoded buffer parses as any JSON value; an array counts its length,
    /// anything else counts as one element.
    ///
    /// For a command whose output is honestly JSON but not honestly a sequence.
    /// Distinct from [`Returns::JsonArray`] so the two cannot collapse: a raw
    /// `gh api graphql` object is legitimate here and a mismatch there.
    Json,
    /// No shape is promised: anything non-empty is one opaque row.
    ///
    /// The escape hatch, and it has to be SAID. That is the difference between a
    /// considered choice and a silent fallback — a command routed through a
    /// wrapper that annotates its own output cannot carry a JSON contract, and
    /// declaring `opaque` records that rather than discovering it per call.
    ///
    /// **It is not an escape back to inference, and the distinction is the one
    /// this whole enum exists for.** A buffer that happens to look like a JSON
    /// array still counts as ONE here, because the row disclaimed the shape and
    /// counting its elements would be a claim about a contract nobody made. It
    /// first read as [`rows_in`] on the reasoning that a promise of nothing has
    /// nothing to check; that is backwards, and it left one of three variants
    /// defeating the field's own purpose. A consumer wanting the length declares
    /// [`Returns::JsonArray`].
    Opaque,
}

/// Refuse a malformed `[[fact]]` table (CLOUD-776).
///
/// Three ways a row can be wrong, and each would make a gate that cannot fire —
/// CLOUD-253's shape, which is why a table nothing validates is itself refused:
///
/// * an **empty name** has no `checks` token to be referred to by, so no rule
///   could ever select it;
/// * an **empty command** would tell the agent to run nothing and then verify a
///   record against nothing, which no record can satisfy;
/// * a **duplicate name** is two answers to one question, and the lookup takes
///   the first — so the second row is silently dead config.
///
/// # What this function deliberately does NOT check
///
/// `returns` (CLOUD-993). It is a required non-`Option` field on a
/// `deny_unknown_fields` struct, so serde refuses an absent one and the enum
/// refuses a value outside the three — both BEFORE this function is handed a
/// `Declared` at all. Adding a check here would be unreachable code asserting a
/// property the type already guarantees, which is the shape that reads as
/// coverage and is not. The load-time refusal is tested against the real config
/// path rather than against this function.
///
/// # Errors
///
/// Returns a [`crate::error::UsageError`] (→ exit `1`) naming the offending row.
/// Pointer-only: the fact's NAME, never its command, which is a consumer's
/// argv and may carry anything.
pub fn validate(facts: &[Declared]) -> anyhow::Result<()> {
    let mut seen: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();
    for fact in facts {
        if fact.name.trim().is_empty() {
            return Err(crate::error::UsageError::raise(
                "a `[[fact]]` row declares an empty `name`, so no `checks` entry could refer to it",
            ));
        }
        validate_one(fact)?;
        if !seen.insert(fact.name.as_str()) {
            return Err(crate::error::UsageError::raise(format!(
                "`[[fact]]` `{}` is declared twice; the lookup takes the first, so the second \
                 row is config that can never fire",
                fact.name
            )));
        }
    }
    Ok(())
}

/// The conjuncts that decide ONE `[[fact]]` row, extracted from [`validate`].
///
/// Split when the workspace's function-length lint asked for it, and along the
/// seam the loop already drew: [`validate`] owns what is true of the SET — a name
/// declared twice is two answers to one question — and this owns what is true of
/// a row on its own. Every refusal here is pointer-only (rule 4): the row's NAME,
/// never its command, which is a consumer's argv and may carry anything.
///
/// # Errors
///
/// Returns a [`crate::error::UsageError`] (-> exit `1`) naming the offending row.
fn validate_one(fact: &Declared) -> anyhow::Result<()> {
    // EXACTLY ONE SELECTOR (CLOUD-690). Neither means the row answers to
    // nothing and can never be satisfied; both means two forgery controls —
    // byte-equality on the command, the selector on the tool — that can
    // disagree about whether the same call answered the fact. Refused at load
    // rather than resolved by precedence, because a precedence rule here is a
    // rule about rules.
    match (fact.command.as_deref(), fact.tool.as_deref()) {
        (Some(command), None) if command.trim().is_empty() => {
            return Err(crate::error::UsageError::raise(format!(
                "`[[fact]]` `{}` declares an empty `command`: the deny would ask the agent \
                 to run nothing, and no record could satisfy it",
                fact.name
            )));
        }
        (None, Some(tool)) if tool.trim().is_empty() => {
            return Err(crate::error::UsageError::raise(format!(
                "`[[fact]]` `{}` declares an empty `tool`, which selects every call and \
                 therefore none",
                fact.name
            )));
        }
        (None, None) => {
            return Err(crate::error::UsageError::raise(format!(
                "`[[fact]]` `{}` declares neither `command` nor `tool`, so nothing can ever \
                 answer it and the checks naming it deny forever",
                fact.name
            )));
        }
        (Some(_), Some(_)) => {
            return Err(crate::error::UsageError::raise(format!(
                "`[[fact]]` `{}` declares both `command` and `tool`; they are alternatives, \
                 and a row carrying both has two forgery controls that can disagree about \
                 whether a call answered it",
                fact.name
            )));
        }
        (Some(_), None) | (None, Some(_)) => {}
    }
    // A predicate over no collection is a column that reads as configured and
    // filters nothing — `counted` would fall through to the whole-result
    // reading and the `where` would silently never be consulted. That is the
    // accepted-and-unread defect this channel has now shipped twice
    // (CLOUD-993, CLOUD-859), so it is a load error.
    if !fact.matching.is_empty() && fact.counts.is_none() {
        return Err(crate::error::UsageError::raise(format!(
            "`[[fact]]` `{}` declares `where` and no `counts`: the predicate has no \
             collection to filter, so it would be read by nothing",
            fact.name
        )));
    }
    if fact
        .counts
        .as_ref()
        .is_some_and(|path| path.trim().is_empty())
    {
        return Err(crate::error::UsageError::raise(format!(
            "`[[fact]]` `{}` declares an empty `counts` path",
            fact.name
        )));
    }
    // `blocking` takes `where`'s refusal for `where`'s reason: without a
    // collection there is no count for a condition to add to, so `counted`
    // would fall through to the whole-result reading and the clauses would be
    // read by nothing.
    if !fact.blocking.is_empty() && fact.counts.is_none() {
        return Err(crate::error::UsageError::raise(format!(
            "`[[fact]]` `{}` declares `blocking` and no `counts`: there is no count for a \
             condition beside the collection to add to, so the clauses would be read by \
             nothing",
            fact.name
        )));
    }
    // `returns` STAYS READ ON THE COUNTING PATH, and this is the conjunct that
    // makes that true rather than nominal. `opaque` disclaims the buffer's
    // shape; a `counts` path is a claim that the buffer is a JSON document
    // with that key in it. A row carrying both states two contradictory
    // contracts and the second one silently wins, which is the
    // accepted-and-unread defect this channel has shipped twice already
    // (CLOUD-993, CLOUD-859). The other two values are both legitimate here
    // and `counted` enforces each of them against the payload.
    if fact.counts.is_some() && fact.returns == Returns::Opaque {
        return Err(crate::error::UsageError::raise(format!(
            "`[[fact]]` `{}` declares `counts` and `returns = \"opaque\"`: the path is a \
             claim about a shape the row disclaims, so one of the two would decide and the \
             other would be read by nothing",
            fact.name
        )));
    }
    // THE OTHER `returns`/`counts` CONTRADICTION, and it is mutually
    // unsatisfiable rather than merely contradictory. `json-array` requires the
    // PAYLOAD ITSELF to be the array, and `crate::mint::select` resolves a
    // named segment with `Value::get`, which answers `None` on an array — so
    // the pair reaches `Look::CouldNotLook` on every payload there can ever be,
    // and a check naming the row denies forever with no read that clears it.
    // `.` is exempt because it is the spelling for the payload itself and is
    // the only path that means anything over a bare array.
    //
    // Refused at load rather than left to a permanent could-not-look for the
    // reason the whole channel is built on: a gate nobody can satisfy is
    // CLOUD-859's measured failure, and it presented as a deny naming a remedy
    // that could not clear it.
    if fact.returns == Returns::JsonArray
        && fact
            .counts
            .as_deref()
            .is_some_and(|path| path.trim() != ".")
    {
        return Err(crate::error::UsageError::raise(format!(
            "`[[fact]]` `{}` declares `returns = \"json-array\"` and a named `counts` path: \
             the shape requires the payload to BE the array and the path requires a member \
             of an object, so no payload can satisfy both and the row could never look",
            fact.name
        )));
    }
    // `when` SELECTS AMONG A TOOL'S CALLS, and a `command` row has nothing for
    // it to select among: the whole command line is compared byte for byte, so
    // the arguments are already inside the forgery control and a second,
    // weaker predicate over the same bytes could only disagree with it.
    // Refused rather than ignored, because a clause accepted and unread is this
    // channel's own repeated defect (CLOUD-993, CLOUD-859).
    if !fact.called_with.is_empty() && fact.command.is_some() {
        return Err(crate::error::UsageError::raise(format!(
            "`[[fact]]` `{}` declares `when` beside `command`: a command row is matched by \
             byte-equality over the whole command line, so its arguments are already \
             compared and the clauses would be read by nothing",
            fact.name
        )));
    }
    Ok(())
}

/// Refuse a keying an agent-sourced record cannot be filed under (CLOUD-859).
///
/// `key` became load-bearing on this path when the record started honouring it,
/// and exactly one of the three values is unreachable here. **The two halves run
/// on different envelopes**: the record is WRITTEN on the post-tool event of the
/// fact's own command — a shell call carrying a command line and nothing else —
/// and READ on the mediated call the receipt row selects. A `head` or `branch`
/// subject is a fact about the checkout and resolves identically at both moments;
/// a `named` subject is projected out of the reading call's own arguments, which
/// the writing call does not have.
///
/// So a `named` agent-sourced check would deny with a `Fix::Run`, the agent would
/// run the command it names, and no record would be filed — a gate nobody can
/// satisfy by doing what it asks. That is the failure this whole row exists to
/// end, so it is refused at load rather than shipped as a column that reads as
/// configured and files nothing.
///
/// # Errors
///
/// Returns a [`crate::error::UsageError`] (→ exit `1`) naming the fact and the
/// row. Pointer-only: two ids, never a command.
pub fn validate_keying(facts: &[Declared], rules: &[crate::rules::Rule]) -> anyhow::Result<()> {
    for rule in rules {
        if rule.kind != crate::rules::RuleKind::Receipt
            || rule.receipt_key() != crate::rules::ReceiptKey::Named
        {
            continue;
        }
        for check in rule.checks.iter().flatten() {
            if facts.iter().any(|fact| &fact.name == check) {
                return Err(crate::error::UsageError::raise(format!(
                    "rule {}: `key = \"named\"` over the agent-sourced fact `{check}` — a named \
                     subject is projected from the call this row SELECTS, and the record is \
                     written on the post-tool event of the fact's own command, which carries no \
                     such subject. No record could ever be filed, so the check would deny \
                     forever and running the command it names would not satisfy it. Key it \
                     `head` or `branch`.",
                    rule.id
                )));
            }
        }
    }
    Ok(())
}
