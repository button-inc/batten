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
//! [`crate::rules::RuleKind::spawns_processes`] is the shipped model and this
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
//! boundary will carry when it arrives, and every fact classified today sits at
//! [`Surface::Hook`] — which is itself the finding. Everything `adjudicate`
//! consumes is hook-resolvable; the second axis exists for facts that are not
//! landed yet, and stating it before they land is what stops the first one being
//! classified by whoever happens to write it.

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
    /// — the same guard `RuleKind::ALL` gives `spawns_processes`.
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

impl Fact {
    /// Every fact the boundary resolves today, so [`Fact::class`] is total.
    pub const ALL: &'static [Fact] = &[
        Fact::Bypass,
        Fact::Receipts,
        Fact::Keys,
        Fact::Stop,
        Fact::Waived,
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
        }
    }
}
