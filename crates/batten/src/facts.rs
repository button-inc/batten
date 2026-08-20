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
    /// What a command the AGENT ran said, read off the post-tool result buffer
    /// (CLOUD-776).
    AgentSourced,
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

impl Fact {
    /// Every fact the boundary resolves today, so [`Fact::class`] is total.
    pub const ALL: &'static [Fact] = &[
        Fact::Bypass,
        Fact::Receipts,
        Fact::Keys,
        Fact::Stop,
        Fact::Waived,
        Fact::Document,
        Fact::AgentSourced,
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
            Fact::AgentSourced => "agent-sourced",
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
            Fact::AgentSourced => AGENT_SOURCED,
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

/// Reduce a tool result buffer to a row count, or [`Look::CouldNotLook`] if its
/// shape is not one this build recognises.
///
/// The buffer's shape is per-tool and only partly surveyed: an MCP tool returns a
/// content-block array (measured — `tests/board-write-record.bats`), and a shell
/// tool returns something this repository has not measured. **Answering `0` for a
/// shape this build cannot read would be a guessed envelope becoming a silent
/// fact**, which is the failure the capability table exists to prevent, so an
/// unrecognised shape is could-not-look instead.
///
/// Two shapes are read, both with evidence in this tree: a **bare row array**,
/// and the **content-block envelope**, whose text blocks are counted where they
/// parse as JSON arrays — the same `fromjson?` posture `board-write-record` takes
/// over the same bytes, so a block that is not JSON is skipped rather than
/// aborting the read.
///
/// No byte of the buffer is returned (rule 4). The count is the whole answer.
#[must_use]
pub fn rows_in(result: &serde_json::Value) -> Look<usize> {
    let serde_json::Value::Array(items) = result else {
        return Look::CouldNotLook;
    };
    let blocks: Vec<&serde_json::Value> = items.iter().filter(|item| is_text_block(item)).collect();
    if blocks.is_empty() {
        // A bare array of rows. An EMPTY array reaches here too and is a genuine
        // zero — it is a shape we read that carried nothing, not a shape we
        // failed to read.
        return Look::Is(items.len());
    }
    let mut rows = 0;
    let mut parsed_any = false;
    for text in blocks
        .iter()
        .filter_map(|block| block.get("text").and_then(serde_json::Value::as_str))
    {
        if let Ok(serde_json::Value::Array(inner)) = serde_json::from_str::<serde_json::Value>(text)
        {
            rows += inner.len();
            parsed_any = true;
        }
    }
    // Nothing parsed is NOT "zero rows": it is a shape this build did not
    // understand, which is could not look.
    if parsed_any {
        Look::Is(rows)
    } else {
        Look::CouldNotLook
    }
}

fn is_text_block(value: &serde_json::Value) -> bool {
    value.get("type").and_then(serde_json::Value::as_str) == Some("text")
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
