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
    /// Whether this branch's work is on each **declared** target, by patch
    /// identity (CLOUD-880) — the landing question `Fact::GitRef` leaves open.
    Landing,
    /// What a **declared** Rust source file's call sites invoke, and with what
    /// literal arguments — the token's syntactic POSITION, which no line
    /// predicate can see (CLOUD-914).
    Invocations,
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
pub const LANDING: Class = Class::new(Cost::Read, Surface::Check);

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
        Fact::AgentSourced,
        Fact::Prospective,
        Fact::Produced,
        Fact::GitHead,
        Fact::GitStatus,
        Fact::GitRemote,
        Fact::GitRef,
        Fact::GitRange,
        Fact::Landing,
        Fact::Invocations,
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
            Fact::AgentSourced => "agent-sourced",
            Fact::Prospective => "prospective",
            Fact::Produced => "produced",
            Fact::GitHead => "git-head",
            Fact::GitStatus => "git-status",
            Fact::GitRemote => "git-remote",
            Fact::GitRef => "git-refs",
            Fact::GitRange => "git-ranges",
            Fact::Landing => "landing",
            Fact::Invocations => "invocations",
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
            Fact::AgentSourced => AGENT_SOURCED,
            Fact::Prospective => PROSPECTIVE,
            Fact::Produced => PRODUCED,
            Fact::GitHead => GIT_HEAD,
            Fact::GitStatus => GIT_STATUS,
            Fact::GitRemote => GIT_REMOTE,
            Fact::GitRef => GIT_REF,
            Fact::GitRange => GIT_RANGE,
            Fact::Landing => LANDING,
            Fact::Invocations => INVOCATIONS,
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
            // The landing family (CLOUD-880). A gate is the tree surface, and
            // every consumer this row exists for -- the tasks that today read a
            // sibling's exit code to learn whether work landed -- is one.
            Fact::Landing => Some("landing"),
            // Tree-only by construction (CLOUD-914): a call site is a property
            // of committed source, and the mediated path has no budget to parse
            // one.
            Fact::Invocations => Some("invocations"),
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
            | Fact::Prospective => None,
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
            Fact::Bypass => serde_json::json!({
                "type": "boolean",
                "description": "Fact::Bypass -- the BATTEN_HOOK_BYPASS hatch (CLOUD-610). The one fact whose shape is certain enough to constrain.",
            }),
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
            Fact::Produced => serde_json::json!({
                "type": "object",
                "description": "Fact::Produced. Sink key -> the record an earlier run's boundary wrote: a digest and a count for a baseline, the empty string for a marker. Never content -- non-negotiable rule 4 holds at the sink harder than at a report (CLOUD-851).",
                "additionalProperties": {"type": "string"},
            }),
            Fact::Prospective => serde_json::json!({
                "description": "Fact::Prospective -- the SHAPE of what a write would land (CLOUD-758): look, bytes, lines. Never the content, which is where rule 4 is decided rather than promised.",
            }),
            // The git and landing families delegate (CLOUD-880). Extracted
            // because this function hit its own 100-line ceiling when `Landing`
            // arrived, and the ceiling is right: a match arm per fact is readable
            // and a match arm per fact for twenty facts is not. Split along the
            // seam that already exists rather than by line count.
            Fact::GitHead
            | Fact::GitStatus
            | Fact::GitRemote
            | Fact::GitRef
            | Fact::GitRange
            | Fact::Landing => Self::git_schema_fragment(self),
        }
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
            | Fact::AgentSourced
            | Fact::Prospective
            | Fact::Produced
            | Fact::Invocations => serde_json::json!({
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
/// likeliest thing in the envelope to hold a secret. **No byte of it is stored.**
/// [`rows_in`] reduces the buffer to a COUNT at the boundary and the count is
/// what reaches disk, so a deny message, a `-J` document and everything under
/// the state root are payload-free by construction rather than by care at each
/// emission site.
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
/// Keyed on the FACT's own natural key rather than on a branch or a SHA: a
/// claimed-key answer is a statement about one issue row at one moment, and
/// keying it to a branch would make the same answer unavailable to the next
/// branch that needs it and stale-by-construction on this one.
#[must_use]
pub fn sourced_path(git_dir: &std::path::Path, name: &str) -> std::path::PathBuf {
    git_dir
        .join("batten-receipts")
        .join(format!("fact.{}", name.replace('/', "-")))
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
    pub command: String,
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
        if fact.command.trim().is_empty() {
            return Err(crate::error::UsageError::raise(format!(
                "`[[fact]]` `{}` declares an empty `command`: the deny would ask the agent to \
                 run nothing, and no record could satisfy it",
                fact.name
            )));
        }
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
