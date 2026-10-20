//! The Definition-of-Ready grammar, as a predicate over a tracker payload
//! (CLOUD-179, ported from `mise-tasks/ready-lint.sh` by CLOUD-1121).
//!
//! The gate document opens by asserting that "Every clause is a computable
//! check, not a judgement" — this is the half that makes that true. Ready was
//! adjudicated by a human reading prose, which left the refinement gate
//! feedforward-only, the exact shape non-negotiable rule 2 calls half a change.
//!
//! It matters most where agents groom. This repo lands by fast-forward on green
//! CI, so nothing human sits between "the agent believes it is done" and "it is
//! on main", and CI cannot fail a correct implementation of the wrong thing. The
//! Ready block is the only place a specification error is catchable at all.
//!
//! **What this does not do, deliberately:** it never asserts that all eight
//! clauses are present. The gate document is explicit that "An issue's own body
//! carries only its *specializations* of these clauses, not a restatement of
//! them", and CLOUD-33 — the corpus's most thoroughly refined issue — omits §4
//! entirely and is correctly Ready. So: validate the clauses that ARE present,
//! and say nothing about absence. It also does not judge whether the block
//! describes the *right* work; that is not computable, and a gate pretending
//! otherwise would be a judge (CLOUD-93).
//!
//! ## Why this is Rust and not Rego
//!
//! The predicate reads a tracker PAYLOAD, which is not tree state: a Rego module
//! reads `input.tree.*`, and there is no issue-payload fact for it to read.
//! `policy/shell-retirement.rego` accepts `crates/batten/src/*.rs` as a policy
//! surface for exactly this reason — a port is not obliged to become a module
//! when the module surface cannot express the input.
//!
//! ## Pointer-only, and here it is load-bearing (rule 4)
//!
//! Every finding is a line number and a rule id, never the matched prose. Issue
//! bodies carry customer detail, and a lint that echoed them would leak through
//! CI logs. [`Finding`] has no field a body can occupy, so that is structural
//! rather than a habit each call site keeps.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use regex::Regex;

use crate::Result;
use crate::error::UsageError;

/// A pointer at something wrong with the block: a line and a rule id.
///
/// **No field can carry a byte of the body** — that is what makes rule 4
/// structural here rather than editorial.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    /// The description-relative line, 1-indexed. `0` is "the body as a whole",
    /// which is what `no-ready-block` reports against.
    pub line: usize,
    /// The rule id, plus its parenthesised detail where the rule carries one.
    /// Detail is an id or a token, never prose from the issue.
    pub rule: String,
}

/// What the lint decided, and everything a caller needs to render it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Report {
    /// The violations, in the order the clauses are checked.
    pub findings: Vec<Finding>,
    /// The derived facts, for the data channel. Byte-stable and pointer-only:
    /// issue keys and one bump token, never a line of any block.
    pub emissions: Vec<String>,
    /// How many citations could not be cross-checked because the payload
    /// carries no `relations` key.
    pub unjudgeable: usize,
    /// Where to point when reporting that gap — the first citation that hit it.
    pub unjudged_line: usize,
}

/// The parsed payload this predicate decides over.
///
/// **Absent and present-but-empty are two different answers** (CLOUD-679), and
/// for the shell program's whole life they were one empty string.
/// `[.relations.blockedBy[]?.id]` yields `[]` for both, so a caller who fetched
/// without `includeRelations` got every §8 and deferral citation reported as
/// `blocker-cited-without-relation` — the gate accusing a correctly-refined
/// issue of citing a phantom blocker, and implying a remedy (add the relation)
/// for a relation that already exists.
///
/// Measured 2026-08-19, same bodies, only the key differing: CLOUD-326 produced
/// four violations with the key stripped and exit 0 with it injected, and its
/// `blockedBy` and both `relatedTo` edges were on the tracker throughout. So
/// presence is read once, and it is `has`, never a count.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Payload {
    /// The issue key, or `?` when the payload carries none.
    pub id: String,
    /// The issue body.
    pub description: String,
    /// Whether the payload carried a `relations` key at all.
    pub relations_present: bool,
    /// When the tracker says the row was created, verbatim, or `None` where the
    /// payload carried none. Never parsed into a date type: it is compared
    /// against another fixed-width ISO-8601 UTC stamp, so lexical order is
    /// chronological order and a parser would only add a way to disagree.
    pub created_at: Option<String>,
    /// The `blockedBy` edges, for the §8 cross-check.
    pub blocked_by: Vec<String>,
    /// Every edge in any direction, for the deferral cross-check. A deferral is
    /// not necessarily a blocker — often the receiving issue is `relatedTo` —
    /// and demanding `blockedBy` would push authors to declare false
    /// dependencies to pass a lint.
    pub all_relations: Vec<String>,
}

impl Payload {
    /// Parse one `get_issue` response.
    ///
    /// # Errors
    ///
    /// [`UsageError`] when the value carries no `.description` — exit 1's
    /// "could not read the input", distinct from a failing block, so a caller
    /// piping the wrong thing never looks like an unrefined issue.
    pub fn parse(value: &serde_json::Value) -> Result<Self> {
        let description = value
            .get("description")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                UsageError::raise(
                    "ready: not a get_issue payload with a .description field".to_owned(),
                )
            })?
            .to_owned();
        let relations = value.get("relations");
        let relations_present = relations.is_some_and(|r| !r.is_null());
        let blocked_by = relations
            .and_then(|r| r.get("blockedBy"))
            .and_then(serde_json::Value::as_array)
            .map(|edges| ids_of(edges))
            .unwrap_or_default();
        let all_relations = relations
            .and_then(serde_json::Value::as_object)
            .map(|map| {
                map.values()
                    .flat_map(|value| match value {
                        serde_json::Value::Array(edges) => ids_of(edges),
                        other => other
                            .get("id")
                            .and_then(serde_json::Value::as_str)
                            .map(|id| vec![id.to_owned()])
                            .unwrap_or_default(),
                    })
                    .collect()
            })
            .unwrap_or_default();
        Ok(Self {
            id: value
                .get("id")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("?")
                .to_owned(),
            created_at: value
                .get("createdAt")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned),
            description,
            relations_present,
            blocked_by,
            all_relations,
        })
    }
}

/// Every `id` in a relation array.
fn ids_of(edges: &[serde_json::Value]) -> Vec<String> {
    edges
        .iter()
        .filter_map(|edge| edge.get("id").and_then(serde_json::Value::as_str))
        .map(str::to_owned)
        .collect()
}

// --- the grammar, resolved from the consumer's `[[pattern]]` table -----------
//
// THE WHOLE GRAMMAR IS THE CONSUMER'S, AND NONE OF IT IS SPELLED HERE. Which
// headings open a Ready block, how a clause is labelled, what a commit type looks
// like, what an issue key looks like — every one of those names something only
// the gated repository has, and non-negotiable rule 1 keeps a consumer identifier
// out of this crate. This module holds the PREDICATE; `batten.toml` holds the
// vocabulary it decides over.
//
// MEASURED, BECAUSE IT LANDED THE OTHER WAY FIRST (CLOUD-1100). CLOUD-1121 ported
// this predicate out of a shell program and carried 18 tokens in with it as
// `const`s, the tracker key among them. Every gate passed: the agnosticism rows are
// four `forbid` literals and none of them is a tracker key, so rule 1 had a
// mechanism for four strings and none for the class. The duplication arrived with
// it — `clause-label` was a `[[pattern]]` row AND a `const` here, byte-identical
// but for a case flag this module had added.
//
// `no-tracker-key-in-core` is the mechanism that would have refused it.

/// Every token the predicate reads, compiled once.
///
/// What a row emits when it releases nothing but still lands a commit
/// (CLOUD-1092).
///
/// Distinct from `none`, which means *lands nothing at all*, and distinct from a
/// bump token, which names a release this row does not cut. Whitespace-free like
/// every other emission, so a consumer reads it with one split.
///
/// **Its value is load-bearing only in that it is not `none`.** The consumer that
/// motivated the split tests the token for equality with `none`, so any other
/// spelling stops the exemption firing; this one is named for what it asserts so
/// a reader of the stdout does not have to infer it.
const NO_RELEASE: &str = "no-release";

/// The fenced claims object inside a Ready block (CLOUD-453).
///
/// **A fence rather than a clause label, because a label is prose and prose is
/// what this replaces.** ```` ```json ```` is unambiguous inside a markdown body
/// and the tracker renders it as one, so what the author sees and what the
/// parser reads are the same span.
///
/// `(?s)` so the body may span lines; the closing fence is what ends it, never a
/// blank line, because an object is legitimately paragraph-shaped.
const CLAIMS_FENCE: &str = r"(?s)```json[[:space:]]*\n(.*?)\n?```";

/// The exit codes a `gate.exits` claim may name — the crate's one table, and no
/// per-verb exception (house style §6-§7).
const CONTRACT_EXITS: [u64; 4] = [0, 1, 2, 3];

/// The commit types the arrow table knows.
///
/// Conventional Commits' set, and it is enumerated here because the derivation
/// needs a closed one: see [`check_claimed_type`] for why a default arm alone
/// turns a typo into a claim.
const CONVENTIONAL_TYPES: [&str; 11] = [
    "feat", "fix", "docs", "style", "refactor", "perf", "test", "build", "ci", "chore", "revert",
];

/// The keys a claims object must carry, in the order they are reported.
///
/// **Required rather than validated-if-present, and that inversion is the whole
/// row.** The prose path validates the clauses that ARE there and says nothing
/// about absence — deliberately, since the gate document forbids restating all
/// eight — so a missing mechanism and a mechanism the parser failed to find
/// reach the same verdict: clean. CLOUD-420 sat in the ready queue with a §2
/// saying its central design decision was still to be made, and no gate could
/// see it, because the sentence was well-formed prose in a well-formed block.
///
/// A key cannot be well-formed prose. That is the entire mechanism.
const REQUIRED_CLAIMS: [&str; 5] = [
    "source_of_truth",
    "gate",
    "commit_type",
    "blockers",
    "tests",
];

/// **Resolution is loud, never lenient.** A missing row is could-not-look — the
/// same posture `input.tree.missing` takes — because a grammar token that
/// silently resolved to nothing would make the clause it anchors report clean
/// over every body. That is the shape a dead gate and a clean tree share, and it
/// is the one failure this whole module exists to avoid.
#[derive(Debug)]
pub struct Grammar {
    opener: Regex,
    parent_opener: Regex,
    legacy_opener: Regex,
    clause_label: Regex,
    open_questions: Regex,
    legacy_clause_notation: Regex,
    /// From which creation instant a Ready block must carry the claims object
    /// rather than prose (CLOUD-472). `None` is could-not-look and exempts
    /// everything.
    ///
    /// # Two wrong shapes preceded this, and the second is the instructive one
    ///
    /// It was first a `[[pattern]]` row spelling the exempt range as a regex over
    /// the key. That is wrong twice: the registry gives one CONCEPT one spelling
    /// and arithmetic is not a concept, and it decides on key TEXT, which this
    /// consumer already declares `ready-issue-mention-markup` for because the
    /// tracker rewrites a bare key into `<issue …>` markup on the round trip.
    ///
    /// It was then a key ORDINAL — the trailing digits, no separator assumed, so
    /// no consumer literal reached the crate. That passes
    /// `no-tracker-key-in-core` and is still a consumer assumption smuggled in:
    /// it requires keys that are numeric AND monotonic with creation order. Three
    /// popular trackers satisfy that and a slug- or UUID-keyed one does not — and
    /// it would fail SILENTLY there, resolving `None` and never ratcheting, which
    /// is the dead-gate shape this module exists to avoid.
    ///
    /// **A creation instant assumes nothing.** Every tracker stamps one, the
    /// payload already carries it, and `policy/filed-here.rego`'s
    /// `predates_the_branch` already compares tracker timestamps this way with
    /// the reasoning written out: both sides are fixed-width ISO-8601 UTC, so
    /// lexical order IS chronological order. Moving it later is the only
    /// direction that tightens, which makes it a ratchet rather than a switch.
    prose_dialect_required_from: Option<String>,
    /// The instant from which a row owes a dispatched pressure test
    /// (CLOUD-472), read exactly as the field above is.
    pressure_test_required_from: Option<String>,
    /// The instant from which a `feat` row owes its prior-art search
    /// (CLOUD-2296), read exactly as the two fields above are.
    prior_art_required_from: Option<String>,
    /// The reviews a refinement block owes, as the consumer declared them.
    ///
    /// Carried here rather than re-read from config because `lint` is a pure
    /// function of (grammar, payload, root) and must stay one: a second config
    /// load inside it would be a second authority over which reviews are owed,
    /// and the two could disagree for a caller that resolved with overrides.
    pressure_test_reviews: Vec<crate::facts::ReviewQuery>,
    bump_label: Regex,
    commit_type: Regex,
    bump_token: Regex,
    break_denial: Regex,
    break_qualified: Regex,
    gate_intro: Regex,
    gate_intro_line: Regex,
    deny_severity: Regex,
    replay_named: Regex,
    replay_count: Regex,
    defer_verb: Regex,
    key: Regex,
    closing_verb: Regex,
    /// A negator sitting on the closing verb, which unmakes the claim.
    closing_negation: Regex,
    mention_markup: Regex,
}

/// The `[[pattern]]` ids this predicate reads.
///
/// Named as one list so a consumer can be told what to declare, and so
/// `tests::every_declared_id_resolves` can assert the crate and the config agree
/// without a second spelling of the set.
pub const REQUIRED_PATTERNS: &[&str] = &[
    "ready-opener",
    "ready-parent-opener",
    "ready-legacy-opener",
    // NOT `ready-clause-label`: the §1 span already declares `clause-label`, and a
    // Ready block has exactly one definition of where a clause begins. One
    // concept, one row, however many readers.
    "clause-label",
    "ready-open-questions",
    "ready-legacy-clause-notation",
    "ready-bump-label",
    "ready-commit-type",
    "ready-bump-token",
    "ready-break-denial",
    "ready-break-qualified",
    "ready-gate-intro",
    "ready-gate-intro-line",
    "ready-deny-severity",
    "ready-replay-named",
    "ready-replay-count",
    "ready-defer-verb",
    "ready-issue-key",
    "ready-closing-verb",
    "ready-issue-mention-markup",
];

impl Grammar {
    /// Resolve every token from the declared table.
    ///
    /// # Errors
    ///
    /// [`UsageError`] naming the first id the table does not declare, or the
    /// first whose expression will not compile. Both are config faults at exit
    /// `1` — a statement about the invocation rather than about any issue.
    pub fn resolve(patterns: &[crate::pattern::NamedPattern]) -> Result<Self> {
        Self::assemble(&|id| {
            let Some(row) = patterns.iter().find(|row| row.id == id) else {
                return Err(Self::undeclared(id));
            };
            Regex::new(&row.regex).map_err(|_| {
                UsageError::raise(format!(
                    "ready: the `[[pattern]]` row `{id}` does not compile as a regular expression"
                ))
            })
        })
    }

    /// The same grammar, from a table the caller has already compiled.
    ///
    /// The mediated path's entry point: `batten hook` compiles the `[[pattern]]`
    /// table once per call for every other reader, so a `[[recorder]]` column or
    /// a `[[mint]]` piece that asks this authority takes the matchers already in
    /// hand rather than compiling twenty-three of them a second time.
    ///
    /// # Errors
    ///
    /// [`UsageError`] naming the first id the table does not carry — the same
    /// refusal [`Grammar::resolve`] raises, because it is the same gap.
    pub fn from_compiled(patterns: &std::collections::BTreeMap<String, Regex>) -> Result<Self> {
        Self::assemble(&|id| {
            patterns
                .get(id)
                .cloned()
                .ok_or_else(|| Self::undeclared(id))
        })
    }

    /// Apply the consumer's prose-dialect threshold (CLOUD-472).
    ///
    /// Separate from [`Self::assemble`] because it is not a `[[pattern]]` and
    /// must not become one: the registry holds concepts with one spelling, and a
    /// number is neither. Absent on [`Self::from_compiled`]'s path by design —
    /// the recorder resolves a grammar to answer an `{authority:…}` column and
    /// has no consumer config in hand, so it gets could-not-look rather than a
    /// threshold guessed from somewhere else.
    #[must_use]
    pub fn with_prose_threshold(mut self, from: Option<String>) -> Self {
        self.prose_dialect_required_from = from;
        self
    }

    /// The cutover from which a row owes a dispatched pressure test.
    ///
    /// Absent on [`Self::from_compiled`]'s path for `with_prose_threshold`'s
    /// reason: the recorder resolves a grammar to answer an `{authority:…}`
    /// column and holds no consumer config, so it gets could-not-look rather
    /// than a threshold guessed from somewhere else.
    #[must_use]
    pub fn with_pressure_test_threshold(mut self, from: Option<String>) -> Self {
        self.pressure_test_required_from = from;
        self
    }

    /// The cutover from which a `feat` row owes its prior-art search
    /// (CLOUD-2296). Absent on [`Self::from_compiled`]'s path for the reason
    /// the two thresholds above give.
    #[must_use]
    pub fn with_prior_art_threshold(mut self, from: Option<String>) -> Self {
        self.prior_art_required_from = from;
        self
    }

    /// The declared reviews whose subject is a refinement body.
    ///
    /// Filtered by the CALLER rather than here: which subject kinds exist is
    /// `review`'s vocabulary, and a grammar that knew the token would be a
    /// second place to change when a kind is added.
    #[must_use]
    pub fn with_pressure_test_reviews(mut self, rows: Vec<crate::facts::ReviewQuery>) -> Self {
        self.pressure_test_reviews = rows;
        self
    }

    /// A row the consumer's table does not declare.
    ///
    /// **Could-not-look, and it says so** — a clause whose anchor has no
    /// definition was never judged, which is not the same as judged clean, and
    /// that distinction is the whole reason resolution is loud.
    fn undeclared(id: &str) -> anyhow::Error {
        UsageError::raise(format!(
            "ready: this repository declares no `[[pattern]]` row `{id}`, so the Ready \
             grammar has no definition for it — the clause it anchors could not be \
             judged at all, which is not the same as judging it clean"
        ))
    }

    /// Every field, from one lookup — so the two entry points above cannot drift
    /// into resolving different token sets.
    fn assemble(find: &dyn Fn(&str) -> Result<Regex>) -> Result<Self> {
        Ok(Self {
            opener: find("ready-opener")?,
            parent_opener: find("ready-parent-opener")?,
            legacy_opener: find("ready-legacy-opener")?,
            clause_label: find("clause-label")?,
            open_questions: find("ready-open-questions")?,
            legacy_clause_notation: find("ready-legacy-clause-notation")?,
            bump_label: find("ready-bump-label")?,
            commit_type: find("ready-commit-type")?,
            bump_token: find("ready-bump-token")?,
            break_denial: find("ready-break-denial")?,
            break_qualified: find("ready-break-qualified")?,
            gate_intro: find("ready-gate-intro")?,
            gate_intro_line: find("ready-gate-intro-line")?,
            deny_severity: find("ready-deny-severity")?,
            replay_named: find("ready-replay-named")?,
            replay_count: find("ready-replay-count")?,
            defer_verb: find("ready-defer-verb")?,
            prose_dialect_required_from: None,
            pressure_test_required_from: None,
            prior_art_required_from: None,
            pressure_test_reviews: Vec::new(),
            key: find("ready-issue-key")?,
            closing_verb: find("ready-closing-verb")?,
            closing_negation: find("ready-closing-negation")?,
            mention_markup: find("ready-issue-mention-markup")?,
        })
    }

    /// The grammar this repository itself declares, for a unit test that needs
    /// one.
    ///
    /// **It reads the committed table rather than a fixture**, and that is the
    /// point rather than convenience: a fixture would let a required id fall out
    /// of `batten.toml` while every test that needs a grammar kept passing, which
    /// is the class this module's own resolution is loud about. Every caller of
    /// this therefore asserts, as a side effect, that the committed table still
    /// declares the whole of [`REQUIRED_PATTERNS`].
    #[cfg(test)]
    pub(crate) fn committed() -> Self {
        match Self::resolve(&committed_patterns()) {
            Ok(grammar) => grammar,
            Err(err) => panic!("the committed [[pattern]] table must declare the grammar: {err}"),
        }
    }

    /// The tracker's mention markup stripped, so the stored and rendered forms
    /// become one case.
    ///
    /// A pattern written against the RENDERED form never matches the stored one,
    /// and an exemption tested only on plain-text fixtures is dead code in
    /// production.
    fn strip_mentions(&self, text: &str) -> String {
        self.mention_markup.replace_all(text, "").into_owned()
    }
}

/// The committed `[[pattern]]` rows, read the way [`Grammar::committed`] reads
/// them — for a test whose gate reads rows beyond the grammar's own.
///
/// Read once per process: a case that asks for the rows and then for the
/// grammar built from them pays one parse of the committed file, not two.
#[cfg(test)]
pub(crate) fn committed_patterns() -> Vec<crate::pattern::NamedPattern> {
    static ROWS: std::sync::LazyLock<Vec<crate::pattern::NamedPattern>> =
        std::sync::LazyLock::new(read_committed_patterns);
    ROWS.clone()
}

#[cfg(test)]
fn read_committed_patterns() -> Vec<crate::pattern::NamedPattern> {
    let text = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../batten.toml"))
        .unwrap_or_default();
    match crate::facts::Format::Toml.read(&text) {
        crate::facts::Look::Is(crate::facts::Node::Map(map)) => match map.get("pattern") {
            Some(crate::facts::Node::List(items)) => items
                .iter()
                .filter_map(|item| {
                    let crate::facts::Node::Map(row) = item else {
                        return None;
                    };
                    let text_of = |key: &str| match row.get(key) {
                        Some(crate::facts::Node::Text(value)) => Some(value.clone()),
                        _ => None,
                    };
                    Some(crate::pattern::NamedPattern {
                        id: text_of("id")?,
                        regex: text_of("regex")?,
                    })
                })
                .collect(),
            _ => Vec::new(),
        },
        _ => Vec::new(),
    }
}

/// The grammar's rows, lent to the sibling gates over the same bodies
/// (CLOUD-1221).
///
/// `batten board check` judges a SET of payloads — the columns they sit in, the
/// graph between them, and the citations each body makes against the tree — and
/// every one of those questions opens a Ready block, finds a clause label or
/// names an issue key exactly as this module does. Lending the compiled rows
/// rather than resolving them a second time is what keeps one definition of each:
/// the three shell programs that asked these questions before carried their own
/// copies, and `spec-ref-check` said so in its header as a cost.
impl Grammar {
    /// The opener row: where a Ready block begins.
    #[must_use]
    pub fn opener(&self) -> &Regex {
        &self.opener
    }

    /// The clause-label row: where a clause begins.
    #[must_use]
    pub fn clause_label(&self) -> &Regex {
        &self.clause_label
    }

    /// The issue-key row, as written, for a caller composing it into a wider
    /// expression — a status claim is a key followed by a column word.
    #[must_use]
    pub fn key_expression(&self) -> &str {
        self.key.as_str()
    }

    /// The tracker's mention markup stripped, so the stored and rendered forms of
    /// a body are one case for a sibling scan too.
    #[must_use]
    pub fn without_mentions(&self, text: &str) -> String {
        self.strip_mentions(text)
    }
}

/// Compile an expression this module owns.
///
/// **Only the two that are not consumer vocabulary reach this** — the
/// Conventional Commits footer and the scope-stripping expression. Neither is an
/// identifier, and neither would mean anything different in another repository,
/// so neither is a `[[pattern]]` row. Every token that names something only the
/// gated repository has is in [`Grammar`].
///
/// The workspace forbids `unwrap`/`expect` on reachable paths, so a failure falls
/// back to an expression matching nothing rather than panicking; both literals are
/// pinned by `tests::the_inline_expressions_compile`.
/// The Conventional Commits breaking-change footer.
const BREAKING_FOOTER: &str = r"BREAKING CHANGE:";

/// A scope suffix on a commit type, stripped before the type is read.
const SCOPE_SUFFIX: &str = r"[(][^)]*[)]";

fn compiled(pattern: &str) -> Regex {
    Regex::new(pattern).unwrap_or_else(|_| {
        #[expect(
            clippy::unwrap_used,
            reason = "`$^` is a literal that cannot fail to compile; it is the \
                      matches-nothing fallback for a pattern that did"
        )]
        Regex::new(r"$^").unwrap()
    })
}

/// THE ONE DEFINITION OF AN ISSUE KEY (CLOUD-1142).
///
/// # Why the grammar is here and the vocabulary is not
///
/// CLOUD-761 measured twenty independent derivations of the key pattern across
/// nine spellings, diverged on three axes, with a shipped defect behind them: a
/// body writing the lowercase form is accepted by one gate and invisible to two
/// others. This is the definition those sites are meant to converge on.
///
/// **The token itself is never written here.** It is the consumer's, read from
/// the `[[pattern]]` registry as [`Grammar::key`], and `no-tracker-key-in-core`
/// refuses a derivation of it anywhere under `crates/**` — the mechanism that
/// exists because CLOUD-1121 carried the literal in as a `const` and passed every
/// gate. So this module owns the three AXES and the consumer owns the TOKEN, and
/// the split is what keeps one definition compatible with rule 1.
///
/// # The three axes, decided by CLOUD-761 and built here
///
/// **Case: sensitive.** Nothing here folds case. The consumer's row carries no
/// `(?i)`, so the lowercase spelling is not a key and is refused rather than
/// normalised — normalising up is precisely what produced the shipped defect.
///
/// **Boundary: the surrounding bytes, checked rather than composed.** The stated
/// form is `(^|[^0-9A-Za-z-])…([^0-9]|$)`, and this does not build it as a
/// regex — `regex` has no lookahead, so a trailing class would CONSUME the byte
/// after a match and make two adjacent keys unfindable. Reading the bytes on
/// either side of a match answers the same question, and it means the crate
/// composes no key expression at all: there is nothing here for a twenty-first
/// derivation to be a copy OF.
///
/// **Project prefix: mandatory.** Inherited from the consumer's row rather than
/// asserted here. The four shell `case` globs this replaces accept `AB-1`, `Z-9`
/// and `A-1foo` because a glob cannot anchor; [`Grammar::key_of`] anchors by
/// requiring the match to span the whole input, which no glob can express.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct IssueKey(String);

impl IssueKey {
    /// The key as the consumer wrote it.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The trailing number, for the numeric ordering [`Grammar::keys_in`] keeps.
    fn number(&self) -> u64 {
        self.0
            .rsplit('-')
            .next()
            .and_then(|n| n.parse::<u64>().ok())
            .unwrap_or(0)
    }
}

impl std::fmt::Display for IssueKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Is the byte before a match a boundary — i.e. NOT one a key could continue
/// through?
///
/// `-` is in the class deliberately, and that is the axis `\b` cannot express: a
/// word boundary treats `-` as a separator, so `\b` would find a key inside a
/// longer hyphenated token. Two landed sites disagreed on exactly this while both
/// looking correct.
fn opens_a_key(text: &str, at: usize) -> bool {
    text[..at]
        .chars()
        .next_back()
        .is_none_or(|c| !c.is_ascii_alphanumeric() && c != '-')
}

/// Is the byte after a match a boundary?
///
/// Digits only, per the decided form. A letter may follow — `CLOUD-1x` contains
/// the key `CLOUD-1` — which is why [`Grammar::key_of`] asks a different
/// question than this one rather than reusing it.
fn closes_a_key(text: &str, at: usize) -> bool {
    text[at..]
        .chars()
        .next()
        .is_none_or(|c| !c.is_ascii_digit())
}

// THE DECLARED MUTATION (CLOUD-761), beside the reader it applies to.
//
// `engine-ready` resolves this file, so `mise run mutant` APPLIES the row rather
// than only binding it. The obligation itself is bound in
// `crates/batten/tests/it/issue_key.rs`, because `obligations-bound`'s
// `line_sources` covers `crates/batten/tests/**` and not this directory — the
// same split a `.rego` module already has, where `#MUTANT-SUITE` names a suite
// somewhere else entirely. The row is spelled identically in both places, so a
// reader comparing them sees one claim rather than two.
//
// It loosens the CASE axis at the one place the grammar compiles a consumer
// expression, which is what makes it discriminate: `key_of` and `keys_in`
// compose no key expression of their own, so there is nothing else here for a
// mutation to reach.
//MUTANT-SUITE crates/batten/tests/it/issue_key.rs
//MUTANT case-insensitive-key-accepted|s@^            Regex::new(&row.regex)@            Regex::new(\&format!("(?i){}", row.regex))@|the_committed_reader_refuses_the_lowercase_spelling
impl Grammar {
    /// Is this WHOLE string a key? The four shell `case` globs' question.
    ///
    /// Anchored by construction: the match must begin at 0 and end at the input's
    /// length, so `CLOUD-1x` is not a key even though it contains one. A glob
    /// cannot say this, which is why those sites accept `AB-1` and `A-1foo`
    /// today.
    #[must_use]
    pub fn key_of(&self, text: &str) -> Option<IssueKey> {
        let found = self.key.find(text)?;
        (found.start() == 0 && found.end() == text.len())
            .then(|| IssueKey(found.as_str().to_owned()))
    }

    /// The issue keys in a span, deduped and ordered NUMERICALLY.
    ///
    /// Numeric and not a bare sort, for `graph-check`'s reason: `CLOUD-10` sorts
    /// before `CLOUD-9` lexically, so a caller diffing two runs could not tell an
    /// ordering change from a content one.
    ///
    /// The boundary check is what stops a key being found inside a longer token.
    /// A greedy match already prevents the reverse case the two landed sites
    /// commented on — `CLOUD-17` is not returned for `CLOUD-179`, because the
    /// match IS `CLOUD-179` — so a caller asking "does this text carry key K"
    /// compares against this set rather than searching again. That is the third
    /// derivation this definition removes rather than adds.
    #[must_use]
    pub fn keys_in(&self, text: &str) -> Vec<IssueKey> {
        let found: BTreeSet<&str> = self
            .key
            .find_iter(text)
            .filter(|m| opens_a_key(text, m.start()) && closes_a_key(text, m.end()))
            .map(|m| m.as_str())
            .collect();
        let mut keys: Vec<IssueKey> = found.into_iter().map(|k| IssueKey(k.to_owned())).collect();
        keys.sort_by_key(IssueKey::number);
        keys
    }

    /// Does `prefix` end in a closing verb that is NOT negated?
    ///
    /// **Two rows rather than one cleverer row, because Rust's regex has no
    /// lookbehind** (CLOUD-1752). `ready-closing-verb` is anchored at the end so
    /// it decides the text immediately before a key — which is precisely why it
    /// reads `does not close CLOUD-1` as a claim: the prefix ends in `close` and
    /// the negation is one word further back, outside an end-anchored pattern's
    /// reach.
    ///
    /// So the verb is LOCATED rather than merely detected, and the text before it
    /// is asked the second question. Measured over 713 merged pull requests, six
    /// rows read as closed by bodies that say in so many words that they do not
    /// close them.
    fn closes_rather_than_disclaims(&self, prefix: &str) -> bool {
        let Some(verb) = self.closing_verb.find(prefix) else {
            return false;
        };
        // `find` yields the leftmost match, and the pattern's own leading
        // `(^|[^0-9A-Za-z-])` may eat the separator before the verb — so the
        // negation is asked about everything up to where the match began.
        !self.closing_negation.is_match(&prefix[..verb.start()])
    }

    /// The keys a span names in CLOSING form — the ones a merge will move.
    ///
    /// **Naming a key and closing one are different facts, and conflating them is
    /// the defect this narrows** (CLOUD-674): a body citing a row as evidence is
    /// not claiming it, and `claimed-keys` already learned that distinction the
    /// expensive way. So this is [`Self::keys_in`] filtered by what precedes each
    /// match rather than a second search — the same one definition of a key, asked
    /// a narrower question.
    ///
    /// The verb set is the forge's rather than this repository's, and it lives in
    /// the pattern registry for the reason every other token does: one concept,
    /// one spelling. Anchored at the END, so it decides the text immediately
    /// before the key and nothing further back.
    #[must_use]
    pub fn keys_closed_in(&self, text: &str) -> Vec<IssueKey> {
        let found: BTreeSet<&str> = self
            .key
            .find_iter(text)
            .filter(|m| opens_a_key(text, m.start()) && closes_a_key(text, m.end()))
            .filter(|m| self.closes_rather_than_disclaims(&text[..m.start()]))
            .map(|m| m.as_str())
            .collect();
        let mut keys: Vec<IssueKey> = found.into_iter().map(|k| IssueKey(k.to_owned())).collect();
        keys.sort_by_key(IssueKey::number);
        keys
    }
}

/// The key strings in a span, for the callers inside this module that still want
/// them as text.
fn keys_in(grammar: &Grammar, text: &str) -> Vec<String> {
    grammar
        .keys_in(text)
        .into_iter()
        .map(|k| k.as_str().to_owned())
        .collect()
}

/// One emitted derived fact: a label and its key set.
///
/// A line present with no keys is the honest empty set; an ABSENT line is "this
/// run never got here", which is a different answer — CLOUD-251's split applied
/// to a producer rather than to a verdict.
///
/// **THE SEPARATOR IS NOT TRIMMED, and the trim was a real defect rather than a
/// cosmetic one** (CLOUD-1100). The port carried the case above — a present line
/// with no keys — and changed its BYTES, emitting `cites-body` where the program
/// it replaced emitted `cites-body `. To a human reader those are the same line.
/// To the one mechanical consumer they are opposite answers:
/// `read = { stdout-line = "cites-body " }` strips that exact prefix, so a
/// trimmed line does not match, the column records the absent token, and *this
/// row cites nothing* becomes *could not look* — which is the very distinction
/// `zero-is-a-count` exists on that column to preserve. Found by running this
/// authority and `mise-tasks/ready-lint.sh` over one corpus
/// (`crates/batten/tests/it/authority_replay.rs`), which is what a replay is for and
/// what neither producer's own suite could see.
fn emit_keys(grammar: &Grammar, label: &str, text: &str) -> String {
    format!("{label} {}", keys_in(grammar, text).join(" "))
}

/// The 1-indexed line of the first match, or `None`.
fn first_line(pattern: &Regex, lines: &[&str]) -> Option<usize> {
    lines
        .iter()
        .position(|line| pattern.is_match(line))
        .map(|n| n + 1)
}

/// The workspace version, which decides which `SemVer` arrows fire.
///
/// A property of this tree, not of the world — no network, no registry lookup —
/// which is what keeps this a gate on the commit rather than a currency check.
/// The range ends at the next table header, so a `version` key under
/// `[workspace.dependencies]` is never read as the crate's.
///
/// # Errors
///
/// [`UsageError`] when it cannot be read: a gate that cannot establish its own
/// regime must not guess, because guessing either way manufactures a violation
/// or launders one.
pub fn workspace_version(root: &Path) -> Result<String> {
    let manifest = std::fs::read_to_string(root.join("Cargo.toml")).map_err(|_| {
        UsageError::raise(format!(
            "ready: cannot read the workspace version from {}/Cargo.toml — §6 needs it to know \
             which SemVer arrows fire",
            root.display()
        ))
    })?;
    let mut in_package = false;
    for line in manifest.lines() {
        if line.starts_with('[') {
            if in_package {
                break;
            }
            in_package = line.trim() == "[workspace.package]";
            continue;
        }
        if in_package
            && let Some(rest) = line.strip_prefix("version = \"")
            && let Some(version) = rest.split('"').next()
        {
            return Ok(version.to_owned());
        }
    }
    Err(UsageError::raise(format!(
        "ready: cannot read the workspace version from {}/Cargo.toml — §6 needs it to know which \
         SemVer arrows fire",
        root.display()
    )))
}

// CLOUD-806's two arms, carried off the retired `mise-tasks/ready-lint.sh`
// (CLOUD-1221). The first drops the body emission, so a consumer reading the
// derived fact silently gets nothing and cannot tell that from an empty body. The
// second takes it back on the `no-ready-block` refusal, which is where it was
// first written: the fact then exists for refined rows only, and an unrefined
// row's stray citation — the likeliest kind — becomes invisible.
//MUTANT emission-dropped|s@^    report.emissions.push(emit_keys($@    std::mem::drop(emit_keys(@|the_bodys_cited_keys_are_emitted_before_any_verdict
//MUTANT emission-after-the-verdict|s@^            rule: "no-ready-block".to_owned(),$@            rule: { report.emissions.clear(); "no-ready-block".to_owned() },@|the_bodys_cited_keys_are_emitted_before_any_verdict
/// Lint one payload against the checkable Ready clauses.
///
/// **The order of the checks is the order of the report**, and it is the shell
/// program's order preserved: opener, clause floor, open questions, notation,
/// §6, §7, §8, deferrals. A caller diffing two runs reads a stable sequence.
///
/// # Errors
///
/// [`UsageError`] when a §6 clause is present and the workspace version cannot
/// be read — the one input this predicate needs that the payload does not carry.
pub fn lint(grammar: &Grammar, payload: &Payload, root: &Path) -> Result<Report> {
    let mut report = Report::default();
    let lines: Vec<&str> = payload.description.lines().collect();

    // THE DERIVED FACT, PART ONE (CLOUD-806), EMITTED BEFORE THE FIRST VERDICT.
    // Its position is the whole of its correctness: it is a property of the
    // BODY, not of the Ready block. An unrefined row still cites rows, and the
    // tracker still mints an edge per citation from it — so emitting it after
    // the `no-ready-block` refusal would make the fact unavailable for exactly
    // the rows most likely to carry a stray citation, and a consumer would read
    // that absence as "could not look" over a body read perfectly well.
    report.emissions.push(emit_keys(
        grammar,
        "cites-body",
        &grammar.strip_mentions(&payload.description),
    ));

    let Some(ready_start) = first_line(&grammar.opener, &lines) else {
        report.findings.push(Finding {
            line: 0,
            rule: "no-ready-block".to_owned(),
        });
        return Ok(report);
    };

    // The opener line, read once: it decides both the notation report and the
    // parent exemption on the clause floor.
    let opener = lines.get(ready_start - 1).copied().unwrap_or_default();
    if grammar.legacy_opener.is_match(opener) {
        report.findings.push(Finding {
            line: ready_start,
            rule: "non-canonical-ready-opener (use `**Refinement — Ready`)".to_owned(),
        });
    }

    let block_lines: Vec<&str> = lines[ready_start - 1..].to_vec();
    let block = block_lines.join("\n");
    // A block-relative match, reported as a description-relative line. Falls
    // back to the opener, which is what the shell's `line_of` does: a pointer
    // that names the block is still a pointer, where naming line 0 would read as
    // "the body as a whole" and mean something else.
    let line_of = |pattern: &Regex| -> usize {
        first_line(pattern, &block_lines).map_or(ready_start, |n| ready_start + n - 1)
    };

    // --- the clause floor -----------------------------------------------------
    //
    // CLOUD-299. Validating only the clauses PRESENT is deliberate and stays,
    // but "only what is present" needs a floor, or a block with NOTHING present
    // is indistinguishable from a refined one. Measured on CLOUD-59: its body
    // opened `**Refinement from the identity decision (CLOUD-123) …**`, carrying
    // no clause at all — the opener matched, zero clauses were found, zero were
    // checked, and it exited 0 with no §1, §3, §6 or §7 anywhere. It sat in the
    // ready queue on that pass.
    //
    // A parent is exempt BY OPENER, never by count: the gate document tells an
    // epic to link the document rather than copy the lists, so a clause-free
    // parent block is the prescribed shape. Keying the exemption on the count
    // would have exempted every empty leaf too.
    let clause = &grammar.clause_label;
    let clauses = block_lines.iter().filter(|l| clause.is_match(l)).count();
    if clauses == 0 && !grammar.parent_opener.is_match(opener) {
        report.findings.push(Finding {
            line: ready_start,
            rule: "ready-block-without-clauses".to_owned(),
        });
    }

    // A LABEL WHOSE EMPHASIS IS GONE IS STILL A CLAUSE (CLOUD-1330). The
    // `clause-label` row reads the plain bullet closing `(§N).` as one, so the
    // tracker's normaliser — which strips the emphasis on every later save — no
    // longer costs the author a re-bold per save. The arm that stood here
    // (`clause-label-not-anchored`, CLOUD-1082) reported the stripped label
    // instead of reading it, and was a treadmill by construction; the row's own
    // comment in `batten.toml` carries the measurement and the anchor's bound.

    if grammar.open_questions.is_match(&block) {
        report.findings.push(Finding {
            line: line_of(&grammar.open_questions),
            rule: "open-questions-block-ready".to_owned(),
        });
    }

    if grammar.legacy_clause_notation.is_match(&block) {
        report.findings.push(Finding {
            line: line_of(&grammar.legacy_clause_notation),
            rule: "non-canonical-clause-notation (use §N)".to_owned(),
        });
    }

    // THE CHECKABLE HALF, IF THE BLOCK CARRIES ONE (CLOUD-453). An object is
    // authoritative for what it carries, so §6 and §8 are skipped when one is
    // present rather than run alongside it: two readings of one claim can
    // disagree, and a row that disagrees with itself is the shape no reviewer
    // can adjudicate.
    let structured = check_claims(grammar, payload, root, &block, ready_start, &mut report)?;

    // THE DIALECT, AS A FACT. Named so a caller can find the blocks still to
    // convert without re-reading any body — and it is the sensor the ratchet
    // below reads, rather than a second derivation of the same question.
    report.emissions.push(format!(
        "dialect {}",
        if structured { "json" } else { "prose" }
    ));

    // THE PROSE DIALECT IS A LEGACY, NOT AN ALTERNATIVE (CLOUD-472).
    //
    // This clause used to say a prose-only block "still PASSES — every issue
    // Ready today stays Ready, which is what lets the corpus converge
    // deliberately instead of in one sweep". The first half is still true below
    // the threshold. The second half was left to intent, **and intent did not
    // converge it**: measured 2026-09-01 over the 50-row Todo queue, the object
    // was used by nothing, and CLOUD-1306 — filed that day — carried a §7 naming
    // three obligations in prose, none of them joinable to anything. A sensor
    // with no ratchet on it reports a defect forever.
    //
    // WHY THE OBJECT IS THE THING BEING DEMANDED, rather than a new grammar:
    // `REQUIRED_CLAIMS` already forces `tests`, and `check_claimed_tests`
    // already forces `file` AND `mutation` on every entry — CLOUD-418's
    // obligation as a field, where an entry that cannot name the mutation which
    // would kill it cannot be written. That mechanism landed and was simply
    // unreachable, because `check_claims` returns `false` on an absent fence and
    // the caller falls back here.
    //
    // A RATCHET RATHER THAN A FLIP, and the cost is why. `graph-check` enforces
    // `Todo ⇒ ready-lint exits 0`, so refusing every prose block at once takes
    // the board's whole ready frontier dark in one step — CLOUD-858's measured
    // shape, where three rows did exactly that.
    //
    // Past the declared cutover, read as [`owed_from`] reads every ratchet here.
    if !structured && owed_from(grammar.prose_dialect_required_from.as_deref(), payload) {
        report.findings.push(Finding {
            line: ready_start,
            rule: "claims-object-absent".to_owned(),
        });
    }

    // THE PRESSURE TEST, CONFIRMED RATHER THAN JUDGED (CLOUD-472).
    //
    // Every other clause here reads the block and infers quality from its SHAPE,
    // which is what an author optimises against once the gate exists — the
    // measured failure that opened this row, where every clause was present and
    // none had been pressure-tested. This asks a different question that shape
    // cannot answer: has a PARTICULAR vendored prompt run over these exact bytes?
    // It is a comparison of two digests, so no model verdict reaches the exit
    // code (rule 3), and it cannot be satisfied by better prose because the prose
    // is the input to the hash.
    //
    // THE BODY IS THE TRACKER'S, which is the forgery control that makes this
    // worth anything: `payload.description` is what the tracker RETURNED, the
    // same source the recorder's `verdict` authority column reads. A digest over
    // a self-assembled payload would certify whatever the caller typed —
    // measured green three times against text in a local file, once under an id
    // no row carried.
    //
    // COULD-NOT-LOOK PASSES, THREE WAYS OVER, and each is a different absence:
    // no declared cutover (the consumer has not asked for this), a payload with
    // no creation instant (unplaceable against one), and no runner installed (an
    // environment that cannot be asked). `review::for_body` returns
    // `CouldNotLook` for the third, so the only refusal left is a review that
    // was asked for and did not answer.
    if owed_from(grammar.pressure_test_required_from.as_deref(), payload) {
        for row in &grammar.pressure_test_reviews {
            if matches!(
                crate::review::for_body(root, row, &payload.description),
                crate::facts::Look::IsNot
            ) {
                report.findings.push(Finding {
                    line: ready_start,
                    rule: format!("pressure-test-undispatched ({})", row.id),
                });
            }
        }
    }

    if !structured {
        check_bump(grammar, root, &block_lines, &line_of, &mut report)?;
    }
    check_replay(grammar, &block, &line_of, &mut report);
    if !structured {
        emit_prose_blockers(grammar, payload, &mut report);
    }
    check_deferrals(grammar, payload, &mut report);

    Ok(report)
}

// Carried off the retired `mise-tasks/ready-lint.sh` (CLOUD-1221). The first
// restores the whole-line read of the break marker, so a clause DENYING a break
// is read as declaring one again — the CLOUD-852 defect; its discriminating case
// is a `no bump` type, since a releasable one collapses to the same answer either
// way. The second drops the unqualified-denial refusal, which is the whole
// failure CLOUD-842 reversed: the five landed rows were silent, not warned.
//MUTANT break-read-off-the-whole-line|s@^    let breaking = type_token.contains('!')@    let breaking = bump_line.contains('!')@|the_break_marker_is_read_off_the_type_token_and_never_off_the_line
//MUTANT break-claim-refusal-dropped|s@^    if grammar.break_denial.is_match(bump_line) .*{$@    if false {@|a_negative_break_claim_must_name_the_surface_it_denies_about
//MUTANT type-read-after-answer|s@^        .find(\x7cm\x7c m.start() < answer_at)$@        .next()@|a_type_named_after_a_none_answer_does_not_make_the_row_land_a_commit
/// §6: the commit type and the bump must agree, and a break denial must name a
/// surface.
fn check_bump(
    grammar: &Grammar,
    root: &Path,
    block_lines: &[&str],
    line_of: &dyn Fn(&Regex) -> usize,
    report: &mut Report,
) -> Result<()> {
    let label = &grammar.bump_label;
    let Some(bump_line) = block_lines.iter().find(|l| label.is_match(l)) else {
        return Ok(());
    };
    // Read lazily, INSIDE the clause: an issue with no §6 needs no version, and
    // demanding one would break linting a payload from outside a checkout.
    let version = workspace_version(root)?;

    // THE TYPE IS WHAT PRECEDES THE ANSWER (CLOUD-2128). A type token after the
    // bump token is the row's prose about it: CLOUD-1055 and CLOUD-368 answer
    // `none` and then explain a correction "from `docs`", and reading that later
    // token made a row that lands nothing read as one landing a `docs` commit.
    let answer_at = grammar
        .bump_token
        .find(bump_line)
        .map_or(bump_line.len(), |m| m.start());
    let type_token = grammar
        .commit_type
        .find_iter(bump_line)
        .find(|m| m.start() < answer_at)
        .map(|m| m.as_str().to_owned())
        .unwrap_or_default();
    let scope = compiled(SCOPE_SUFFIX);
    let commit_type = scope
        .replace_all(&type_token, "")
        .replace(['`', '!'], "")
        .to_lowercase();
    let breaking = type_token.contains('!') || compiled(BREAKING_FOOTER).is_match(bump_line);

    if grammar.break_denial.is_match(bump_line) && !grammar.break_qualified.is_match(bump_line) {
        report.findings.push(Finding {
            line: line_of(&grammar.bump_label),
            rule: "unqualified-break-claim (say which surface: `consumer` or `library` — `mise \
                   run semver` decides the library half)"
                .to_owned(),
        });
    }

    // "none" is a valid explicit answer — a tracker-only or repo-config change
    // lands no commit at all, and demanding a type there would force a lie.
    let mut declared = grammar
        .bump_token
        .find(bump_line)
        .map(|m| m.as_str().to_lowercase())
        .unwrap_or_default();
    if declared == "none" {
        "no bump".clone_into(&mut declared);
    }

    // THE DERIVED FACT (CLOUD-735), emitted INSIDE the §6 clause and not before
    // it: unlike `cites-body`, whose span is the whole body, this fact does not
    // exist for a row carrying no §6 — and a row with no clause must read as
    // "did not say", never as "said none". A consumer that sees no `bump` line
    // at all is looking at exactly that.
    //
    // TWO QUESTIONS, TWO TOKENS (CLOUD-1092). This fact used to answer *what does
    // the row release* while its one consumer read it as *does the row land a
    // commit*, and for every non-releasing type those are different answers. §6's
    // arrow table maps anything but `feat`/`fix` to `no bump` — deliberately, and
    // the collapse arm below refuses to fold it into `patch` because release-plz
    // produces no bump there at any version — so a `test`-typed row MUST declare
    // `no bump`, emitted `none`, and was then refused at In Review as
    // `declares-no-commit-with-pr` for landing the commit it exists to land.
    //
    // Measured on the board: CLOUD-106 (`test` -> no bump) was refused, while
    // CLOUD-421 passed only because "no version bump" misses the token
    // alternation and emits `-`. The row stating its bump most clearly was the
    // one refused — CLOUD-228's inversion, one fact downstream.
    //
    // So `none` is now reserved for the row that declares it lands NOTHING: no
    // bump AND no commit type, which is the dispatch-record shape CLOUD-735
    // exempts and the only shape that can never acquire a PR. A row naming a
    // non-releasing TYPE releases nothing and still lands a commit, and says so
    // with its own token.
    //
    // **The consumer is not touched, and that is the point rather than a
    // shortcut.** `graph-check.sh` keys its exemption on the literal `none`; it
    // is a governed shell rule that cannot retire, so `shell edit refused`
    // refuses any edit to it with one route and no override. Changing which rows
    // the producer spends that token on fixes the contradiction with the consumer
    // byte-unchanged — which also makes its unedited suite the evidence that the
    // repair reached it.
    let emitted = match (declared.as_str(), commit_type.is_empty()) {
        ("", _) => "-",
        ("no bump", true) => "none",
        ("no bump", false) => NO_RELEASE,
        (other, _) => other,
    };
    report.emissions.push(format!("bump {emitted}"));

    let mut expected = match commit_type.as_str() {
        "feat" => "minor",
        "fix" => "patch",
        "" => "",
        _ => "no bump",
    }
    .to_owned();
    if breaking {
        "major".clone_into(&mut expected);
    }

    // Below 0.1.0 every release-worthy type collapses to a patch: Cargo gives
    // 0.0.x no compatibility guarantee, so release-plz bumps the patch whatever
    // the type says, and an issue promising otherwise states something the tool
    // will not do. "no bump" does NOT collapse — a `ci`/`chore`-only change
    // releases nothing at any version, so folding it into patch would demand a
    // bump the tool never produces, the same error in the other direction.
    let mut why = String::new();
    if version.starts_with("0.0.") && !expected.is_empty() && expected != "no bump" {
        "patch".clone_into(&mut expected);
        " below 0.1.0".clone_into(&mut why);
    }

    if commit_type.is_empty() {
        // An explicit no-commit declaration needs no type; silence does.
        if declared != "no bump" {
            report.findings.push(Finding {
                line: line_of(&grammar.bump_label),
                rule: "commit-type-missing".to_owned(),
            });
        }
    } else if !declared.is_empty() && declared != expected {
        report.findings.push(Finding {
            line: line_of(&grammar.bump_label),
            rule: format!("bump-disagrees-with-type ({commit_type} implies {expected}{why})"),
        });
    }
    Ok(())
}

// Carried off the retired `mise-tasks/ready-lint.sh` (CLOUD-1221): the mutation
// drops the deny conjunct, so every gate-introducing block is demanded a replay —
// including the `warn` ones the clause deliberately leaves alone.
//MUTANT replay-demanded-of-a-warn-gate|s@^    if !grammar.gate_intro.is_match(block) .. !grammar.deny_severity.is_match(block) {$@    if !grammar.gate_intro.is_match(block) {@|a_deny_gate_owes_a_replay_and_a_warn_gate_does_not
/// §7: a new deny gate reports its firing rate before its severity is chosen.
///
/// CLOUD-751. Showing a gate CAN fail on a fixture (CLOUD-418) is a different
/// and weaker claim than knowing how often it fires on real history. The
/// conjunction is what keeps this off the rest of the corpus: it fires only on a
/// block that BOTH introduces a gate AND declares `deny`. A `warn` that fires
/// often is noise a reader can weigh, where a `deny` that fires often stops the
/// fleet — which is why the obligation attaches to `deny` alone.
///
/// Presence and shape only, never whether the number is good: judging an
/// acceptable false-positive rate is a model verdict and rule 3 forbids it. The
/// author reports; the reader decides.
fn check_replay(
    grammar: &Grammar,
    block: &str,
    line_of: &dyn Fn(&Regex) -> usize,
    report: &mut Report,
) {
    if !grammar.gate_intro.is_match(block) || !grammar.deny_severity.is_match(block) {
        return;
    }
    if grammar.replay_named.is_match(block) && grammar.replay_count.is_match(block) {
        return;
    }
    report.findings.push(Finding {
        line: line_of(&grammar.gate_intro_line),
        rule: "deny-without-replay (a deny gate reports its firing rate first: replay the \
               predicate over `git rev-list <trunk>` and record commits examined, times \
               fired, and how many were false positives)"
            .to_owned(),
    });
}

/// The fenced claims object, validated (CLOUD-453).
///
/// Returns whether an object was found, so the caller knows which dialect the
/// block is written in and whether the prose path still owns §6 and §8.
///
/// **When an object is present the prose is not read for what it carries.** That
/// is the one-authority-per-fact rule applied inside a single body: two readings
/// of one claim can disagree, and the row that disagrees with itself is exactly
/// the shape a reviewer cannot adjudicate. §7's table says the object wins and
/// the prose goes unread, so this returns `true` and the caller skips those two
/// checks rather than running both and reconciling.
///
/// **The bump is DERIVED, never declared.** The object carries `commit_type` and
/// the arrow table computes what it releases, so the class CLOUD-228 and
/// CLOUD-1092 both lived in — a declaration disagreeing with the table it is
/// checked against — is not expressible here at all. That is the difference
/// between checking a claim and removing the chance to make a wrong one.
//MUTANT empty-tests-admitted-beyond-docs|s@declared == "docs"@!declared.is_empty()@|a_refactor_row_still_owes_its_tests
fn check_claims(
    grammar: &Grammar,
    payload: &Payload,
    root: &Path,
    block: &str,
    block_line: usize,
    report: &mut Report,
) -> Result<bool> {
    let Some(found) = compiled(CLAIMS_FENCE).captures(block) else {
        return Ok(false);
    };
    let Some(source) = found.get(1) else {
        return Ok(false);
    };
    // A fence that is not an object is a violation rather than an absent one:
    // the author reached for the mechanism and mis-typed it, and reading that as
    // "no object here" would silently drop them back onto the prose path.
    let Ok(claims) = serde_json::from_str::<serde_json::Value>(source.as_str()) else {
        report.findings.push(Finding {
            line: block_line,
            rule: "claims-object-unparseable".to_owned(),
        });
        return Ok(true);
    };

    // A `docs` OR COMMITLESS ROW MAY DECLARE NO TESTS (CLOUD-1938), and only
    // those. A change to prose alone has no behaviour a mutation could kill —
    // measured on CLOUD-1931, two memory files and one sentence, where the memory
    // graph's own gate is `#MUTANT-EXEMPT` — and `none` lands nothing at all, so
    // demanding an entry bought a fabricated one or `--bypass-sequence`, and
    // neither is a claim. Narrow on purpose: `refactor`, `perf`, `test` and the
    // other non-releasing types change code, so an empty list there is still an
    // omission, and so is `docs!`, which claims a breaking change. Read the way
    // `check_claimed_type` reads the field: trimmed, case-insensitive. The row
    // still has to name its `gate`.
    let declared = claims
        .get("commit_type")
        .and_then(serde_json::Value::as_str)
        .map(|declared| declared.trim().to_ascii_lowercase());
    let prose_only = declared
        .as_deref()
        .is_some_and(|declared| declared == "docs" || declared == "none");
    // A `feat` OWES ITS PRIOR-ART SEARCH (CLOUD-2296): `feat!` included, read off
    // the typed field, never the prose (rule 3), and only from the declared
    // cutover on — the pressure test's ratchet, so a row groomed Ready before
    // the claim existed stays Ready. Entry shape is [`check_claimed_prior_art`]'s.
    let owes_prior_art = declared
        .as_deref()
        .is_some_and(|declared| declared.trim_end_matches('!') == "feat")
        && owed_from(grammar.prior_art_required_from.as_deref(), payload);
    for key in REQUIRED_CLAIMS
        .into_iter()
        .chain(owes_prior_art.then_some("prior_art"))
    {
        // PRESENT AND NON-EMPTY, because an empty string, array or object is an
        // omission wearing a declaration's shape. `blockers: []` is the one
        // deliberate exception and is handled below — a row with no blockers
        // must be able to SAY so, which is the absence this row exists to make
        // writable. `tests: []` joins it for a `docs` row alone, above.
        let present = match claims.get(key) {
            None | Some(serde_json::Value::Null) => false,
            Some(serde_json::Value::String(text)) => !text.trim().is_empty(),
            Some(serde_json::Value::Array(items)) => {
                key == "blockers" || (key == "tests" && prose_only) || !items.is_empty()
            }
            Some(serde_json::Value::Object(fields)) => !fields.is_empty(),
            Some(_) => true,
        };
        if !present {
            report.findings.push(Finding {
                line: block_line,
                rule: format!("claim-missing ({key})"),
            });
        }
    }

    // THE OBLIGATION SET, EMITTED BEFORE ANY VERDICT (CLOUD-472).
    //
    // Position is correctness, exactly as it is for `cites-body`: a recorder
    // reads this line to carry the declared obligations into the tree, where a
    // `verify`-time rule can ask whether each one is bound to a case. Emitting
    // it after a refusal would make the set unavailable for precisely the rows
    // most likely to carry a broken one, and a consumer would read that absence
    // as could-not-look over a block that was read perfectly well.
    //
    // `<file>:<slug>` per entry, space separated. An EMPTY line is the honest
    // zero — the object was read and declares no obligations — while no line at
    // all is a prose block, or a payload this verb never got through, which
    // `Read::StdoutLine` keeps apart by construction.
    report.emissions.push(format!(
        "obligations {}",
        claims
            .get("tests")
            .and_then(serde_json::Value::as_array)
            .map(|tests| tests
                .iter()
                .filter_map(|entry| {
                    let file = entry.get("file").and_then(serde_json::Value::as_str)?;
                    let mutation = entry.get("mutation").and_then(serde_json::Value::as_str)?;
                    Some(format!("{file}:{mutation}"))
                })
                .collect::<Vec<_>>()
                .join(" "))
            .unwrap_or_default()
    ));

    check_claimed_gate(&claims, block_line, report);
    check_claimed_type(&claims, root, block_line, report)?;
    check_claimed_blockers(grammar, payload, &claims, block_line, report);
    check_claimed_tests(&claims, block_line, report);
    check_claimed_prior_art(&claims, block_line, report);
    Ok(true)
}

/// `prior_art` — the search a `feat` row owes before it builds (CLOUD-2296).
///
/// AGENTS.md's "adopt prior art; don't expand the core" was prose with no gate:
/// four engine mechanisms were built in one session before any search, each with
/// an existing tool that did the job. A typed list is what makes the search
/// writable as a claim and its absence visible.
///
/// Its PRESENCE on a `feat` is the required-claims loop's to decide, where every
/// other required key is: a `fix` repairs what exists, and a `feat` is the row
/// that adds. This holds each entry to its shape, on any row that carries one.
///
/// What is decided is the SHAPE — a tool, where it lives, adopt or reject, and a
/// reason for a rejection. Whether the reason is any good is a judgement, and no
/// gate here makes one.
fn check_claimed_prior_art(claims: &serde_json::Value, line: usize, report: &mut Report) {
    let entries = match claims.get("prior_art") {
        None | Some(serde_json::Value::Null) => return,
        Some(serde_json::Value::Array(entries)) => entries,
        // A STRING OR AN OBJECT IS NOT A SEARCH: it passes presence and would
        // otherwise skip every check below.
        Some(_) => {
            report.findings.push(Finding {
                line,
                rule: "prior-art-entry-incomplete".to_owned(),
            });
            return;
        }
    };
    for entry in entries {
        // Read the way `commit_type` is: trimmed, case-insensitive.
        let verdict = entry
            .get("verdict")
            .and_then(serde_json::Value::as_str)
            .map(|verdict| verdict.trim().to_ascii_lowercase());
        if !filled(entry, "tool")
            || !filled(entry, "url")
            || !matches!(verdict.as_deref(), Some("adopt" | "reject"))
        {
            report.findings.push(Finding {
                line,
                rule: "prior-art-entry-incomplete".to_owned(),
            });
        } else if verdict.as_deref() == Some("reject") && !filled(entry, "reason") {
            report.findings.push(Finding {
                line,
                rule: "prior-art-rejection-unreasoned".to_owned(),
            });
        }
    }
}

/// Whether a row created at `payload`'s instant is past the `from` cutover, so
/// the ratchet that cutover declares applies to it.
///
/// COULD-NOT-LOOK PASSES, TWICE OVER, and both are the same posture. A consumer
/// that declares no cutover has not asked for the ratchet, and a payload carrying
/// no creation instant cannot be placed against one — so each leaves the row
/// judged exactly as it was before the clause existed. Reading either as "past
/// the cutover" would turn a verdict about the environment into a verdict about
/// the row.
///
/// Both sides are fixed-width ISO-8601 UTC as the tracker stamps them, so a
/// lexical comparison IS a chronological one — the same reading, and the same
/// reasoning, as `policy/filed-here.rego`'s `predates_the_branch`.
fn owed_from(from: Option<&str>, payload: &Payload) -> bool {
    from.zip(payload.created_at.as_deref())
        .is_some_and(|(from, created)| created >= from)
}

/// Whether `entry[key]` is a string with something in it — the one reading of
/// "filled" every claims list holds an entry's fields to.
fn filled(entry: &serde_json::Value, key: &str) -> bool {
    entry
        .get(key)
        .and_then(serde_json::Value::as_str)
        .is_some_and(|text| !text.trim().is_empty())
}

/// `gate` — a task NAMED, and exits inside the one contract.
///
/// # Why the task is not resolved here, and where that question does live
///
/// CLOUD-453's §3 asks for `gate.task` "resolving to a real `mise` task". It does
/// not resolve here, and the reason is non-negotiable rule 1 rather than an
/// omission: resolving it means opening the consumer's task manifest, which
/// means this module naming that manifest — and `document_facts.rs`'s
/// `no_artifact_name_reaches_the_core` refuses exactly that. It caught the first
/// draft of this function doing it. Its residue list is a **shrink-only**
/// ratchet, so adding a row for a live mechanism would be widening a gate rather
/// than satisfying it.
///
/// The question is not dropped, it is somewhere better: `batten.toml`'s
/// `command-task-defined` row already decides whether a named task exists, over
/// the consumer's own declaration of where tasks live, and raises
/// `task name undefined` with `task read first`. Re-deriving it here would be a
/// second authority over one fact with only the newer one deciding — CLOUD-351's
/// class — on top of the rule 1 violation.
///
/// So what this checks is that a task is NAMED. That is the half that makes the
/// mechanism unwritable as prose, which is the row's actual point: a field wants
/// a command, and a sentence does not fit in it.
fn check_claimed_gate(claims: &serde_json::Value, line: usize, report: &mut Report) {
    let Some(gate) = claims.get("gate") else {
        return;
    };
    if !filled(gate, "task") {
        report.findings.push(Finding {
            line,
            rule: "gate-task-unnamed".to_owned(),
        });
    }
    if let Some(exits) = gate.get("exits").and_then(serde_json::Value::as_array) {
        for exit in exits {
            let outside = exit
                .as_u64()
                .is_none_or(|code| !CONTRACT_EXITS.contains(&code));
            if outside {
                report.findings.push(Finding {
                    line,
                    rule: "gate-exit-outside-contract".to_owned(),
                });
            }
        }
    }
}

/// `commit_type` — a type the arrow table knows, with the bump derived from it.
fn check_claimed_type(
    claims: &serde_json::Value,
    root: &Path,
    line: usize,
    report: &mut Report,
) -> Result<()> {
    let Some(declared) = claims
        .get("commit_type")
        .and_then(serde_json::Value::as_str)
    else {
        return Ok(());
    };
    let commit_type = declared.trim().to_lowercase();
    // `none` is the commitless declaration, and it carries the same meaning here
    // as the prose clause's: this row lands nothing, so there is no type and no
    // release. CLOUD-735's exemption reads the emitted token, not this field.
    if commit_type == "none" {
        report.emissions.push("bump none".to_owned());
        return Ok(());
    }
    let breaking = commit_type.ends_with('!');
    let bare = commit_type.trim_end_matches('!');
    // A TYPE THE ARROW TABLE KNOWS, and this is the hole the derivation would
    // otherwise open. With the bump computed rather than declared, an unknown
    // type has no wrong answer to disagree with — `fixx` would simply fall
    // through the default arm and read as "releases nothing", which is a typo
    // silently becoming a claim. The prose path could not have this defect
    // because it compared two things; this one has to name the set.
    if !CONVENTIONAL_TYPES.contains(&bare) {
        report.findings.push(Finding {
            line,
            rule: format!("commit-type-unknown ({bare})"),
        });
        return Ok(());
    }
    let mut bump = match bare {
        "feat" => "minor",
        "fix" => "patch",
        _ => NO_RELEASE,
    };
    if breaking {
        bump = "major";
    }
    // The 0.0.x collapse, and it is read from the tree rather than assumed:
    // Cargo gives 0.0.x no compatibility guarantee, so release-plz bumps the
    // patch whatever the type says. `NO_RELEASE` does not collapse, for the
    // reason the prose path's arm gives — folding it into patch would demand a
    // bump the tool never produces.
    let version = workspace_version(root)?;
    if version.starts_with("0.0.") && bump != NO_RELEASE {
        bump = "patch";
    }
    report.emissions.push(format!("bump {bump}"));
    Ok(())
}

/// `blockers` — the §8 cross-check, over a list instead of over a sentence.
///
/// The same predicate the prose path applies, reached without a claim scan: a
/// list needs no anchor, no span and no sentence boundary, so every defect
/// CLOUD-1113 and its neighbours record is unreachable from here by
/// construction. That is the argument for the object, in one clause.
fn check_claimed_blockers(
    grammar: &Grammar,
    payload: &Payload,
    claims: &serde_json::Value,
    line: usize,
    report: &mut Report,
) {
    let Some(blockers) = claims.get("blockers").and_then(serde_json::Value::as_array) else {
        return;
    };
    let cited: Vec<String> = blockers
        .iter()
        .filter_map(|value| value.as_str().map(str::to_owned))
        .collect();
    report
        .emissions
        .push(emit_keys(grammar, "cites-blockers", &cited.join(" ")));
    for key in cited {
        if !payload.relations_present {
            report.unjudgeable += 1;
            if report.unjudged_line == 0 {
                report.unjudged_line = line;
            }
            continue;
        }
        if !payload.blocked_by.iter().any(|edge| edge == &key) {
            report.findings.push(Finding {
                line,
                rule: format!("blocker-cited-without-relation ({key})"),
            });
        }
    }
}

/// `tests` — every entry names a file and the mutation that would kill it.
///
/// CLOUD-418's obligation as a field. A `§7` paragraph can promise a test and
/// name no way to tell a discriminating one from coverage; an entry missing
/// `mutation` cannot.
fn check_claimed_tests(claims: &serde_json::Value, line: usize, report: &mut Report) {
    let Some(tests) = claims.get("tests").and_then(serde_json::Value::as_array) else {
        return;
    };
    for entry in tests {
        for key in ["file", "mutation"] {
            if !filled(entry, key) {
                report.findings.push(Finding {
                    line,
                    rule: format!("test-claim-incomplete ({key})"),
                });
            }
        }
        // `mutation` NAMES A DECLARED `#MUTANT` SLUG (CLOUD-472). The field
        // landed under CLOUD-418 as prose describing the mutation that would
        // kill the case — which is a better claim than nothing and is still not
        // joinable to anything. A slug is: `batten mutate` resolves it, applies
        // the expression, runs the named case, and a SURVIVOR is the finding. So
        // "pressure tested" stops being an assertion and becomes an exit code.
        //
        // SHAPE HERE, RESOLUTION AT `verify`. At refinement time the case does
        // not exist yet — refusing an unresolvable slug here is the false-failure
        // trap this row's own §3 names — so this checks only that the field is a
        // TOKEN rather than a sentence. A slug carries no whitespace, which is
        // the whole discriminator and is what `mutate`'s own three-field row
        // format already requires of it.
        let prose = entry
            .get("mutation")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|text| text.split_whitespace().count() > 1);
        if prose {
            report.findings.push(Finding {
                line,
                rule: "test-claim-mutation-not-a-slug".to_owned(),
            });
        }
    }
}

/// §8 on a prose block: the board's edges, never the block's sentence (CLOUD-1771).
///
/// A `blockedBy` relation is live on both sides of the ref, so a §8 sentence
/// restating it is a copy that goes stale while the edge stays true: measured on
/// CLOUD-1306, whose sentence named a blocker Done for a day and deferred an
/// Urgent row. This used to parse that sentence and hold its keys to the edges,
/// which kept the copy load-bearing. It now reads nothing from the block, and
/// `cites-blockers` names the edges themselves.
///
/// EMITTED WITH OR WITHOUT A RELATIONS KEY, as the empty set where there is none:
/// that is the line the retired program was recorded emitting for a block with
/// no §8 span (`authority_replay.rs`'s `RECORDED`), and a consumer branching on
/// its presence keeps the answer it had. The claims object's `blockers` key is a
/// key rather than prose, and [`check_claimed_blockers`] still holds it to the
/// edges.
//MUTANT prose-blockers-from-the-sentence|s@^        \&payload.blocked_by.join(" "),$@        \&payload.description,@|a_section_eight_sentence_is_never_read_as_a_claim
fn emit_prose_blockers(grammar: &Grammar, payload: &Payload, report: &mut Report) {
    report.emissions.push(emit_keys(
        grammar,
        "cites-blockers",
        &payload.blocked_by.join(" "),
    ));
}

/// Deferral claims linked, not asserted (CLOUD-197).
///
/// The same predicate as §8, applied to the other direction of dependency. A
/// block claiming an obligation is *someone else's* is asserting a hand-off the
/// board does not know about unless a relation records it. Prose alone lets an
/// obligation be declared somebody else's problem and then belong to nobody.
///
/// Unlike §8 this is checked over the WHOLE description: a deferral is most
/// often written in Done, in an Open questions list, or in an out-of-scope
/// note — exactly the places an obligation goes to die.
fn check_deferrals(grammar: &Grammar, payload: &Payload, report: &mut Report) {
    let plain = grammar.strip_mentions(&payload.description);
    let plain_lines: Vec<&str> = plain.lines().collect();
    let hit = compiled(&format!(
        r"({})[^.]{{0,40}}?{}",
        grammar.defer_verb.as_str(),
        grammar.key.as_str()
    ));
    for (index, line) in plain_lines.iter().enumerate() {
        if !hit.is_match(line) {
            continue;
        }
        // The id must FOLLOW the verb, not merely share a line: "CLOUD-9 blocks
        // this, deferred to CLOUD-10" defers only CLOUD-10.
        let mut cited: Vec<String> = Vec::new();
        for span in hit.find_iter(line) {
            cited.extend(keys_in(grammar, span.as_str()));
        }
        cited.sort_unstable();
        cited.dedup();
        for key in cited {
            // An issue may not defer to itself; that is a wording slip.
            if key == payload.id {
                continue;
            }
            if !payload.relations_present {
                report.unjudgeable += 1;
                if report.unjudged_line == 0 {
                    report.unjudged_line = index + 1;
                }
                continue;
            }
            if !payload.all_relations.iter().any(|edge| edge == &key) {
                report.findings.push(Finding {
                    line: index + 1,
                    rule: format!("deferral-cited-without-relation ({key})"),
                });
            }
        }
    }
}

/// The token a satisfied block renders as, wherever a renderer asks this
/// authority for a value.
pub const VERDICT_READY: &str = "ready";

/// The token a block carrying at least one finding renders as.
pub const VERDICT_UNREADY: &str = "unready";

/// What this authority says about one raw tracker payload, **in the spawned
/// program's own contract** rather than in this crate's (CLOUD-1100).
///
/// # Why the codes are inverted here, deliberately
///
/// CLOUD-909 records the trap: `mise-tasks/ready-lint.sh` spells `0` pass, `1`
/// violation, `2` could-not-look, and batten's own `0/1/2/3` table spells `2` for
/// the policy verdict and `1` for a usage error. This function answers in the
/// SHELL program's codes, because its callers are the `[[recorder]]` columns
/// whose `read = { status = { "0" = "ready", "1" = "unready" } }` tables were
/// written against that program. Answering in batten's contract would silently
/// re-map every one of those tables — a wrong verdict wearing a right verdict's
/// shape, which reads as data rather than as a gap.
///
/// `None` is **could not look**, and it is not the same answer as `Some((2, _))`:
/// the first is a payload this authority could not read at all, the second is a
/// block it read and could not fully cross-check. Both render as the absent
/// token downstream — `2` because no consumer's status table maps it — so the
/// distinction costs a caller nothing and keeps the two causes distinguishable
/// here.
///
/// stdout is the emissions, in [`lint`]'s order and one per line, which is what
/// `read = { stdout-line = "cites-body " }` reads. They go out **before** any
/// verdict for CLOUD-806's reason: they are properties of the BODY, not of the
/// block, so an unrefined row must still emit them.
/// `grammar` is the CALLER's, resolved once at the boundary from the consumer's
/// `[[pattern]]` rows. This authority carries no vocabulary of its own — the
/// openers, the clause notation and the relation names are the consumer's facts
/// and live in `batten.toml`, which is what keeps non-negotiable rule 1 true of
/// this module. A consumer whose table cannot build one has no grammar, and its
/// caller answers could-not-look rather than passing a payload nothing judged.
#[must_use]
pub fn adjudicate(
    grammar: &Grammar,
    payload: &serde_json::Value,
    root: &Path,
) -> Option<(i32, String)> {
    let parsed = Payload::parse(payload).ok()?;
    let report = lint(grammar, &parsed, root).ok()?;
    let mut out = String::new();
    for emission in &report.emissions {
        out.push_str(emission);
        out.push('\n');
    }
    // The order is the rule (CLOUD-679): a judgeable violation outranks a gap,
    // because the block is wrong regardless of what could not be seen.
    let status = match (report.findings.is_empty(), report.unjudgeable > 0) {
        (false, _) => 1,
        (true, true) => 2,
        (true, false) => 0,
    };
    Some((status, out))
}

/// The tracked paths an issue body NAMES (CLOUD-774), ported off
/// `mise-tasks/board-diff-overlap.sh --named` under CLOUD-1716.
///
/// # POINTER-ONLY IS STRUCTURAL HERE, not careful
///
/// Only paths this repository TRACKS can reach the output, so a body's prose, a
/// customer name or a pasted credential cannot (non-negotiable rule 4). That is
/// a property of the resolution rather than of a scrubbing step somebody has to
/// remember.
///
/// # BASENAMES RESOLVE, AND AN AMBIGUOUS ONE RESOLVES TO NOTHING
///
/// Bodies here write `git.rs:107`, not `crates/batten/src/git.rs`. Measured on
/// the three rows the retired program was built from, exact path matching found
/// ZERO and basename resolution found all three — so exact matching would ship a
/// sensor blind to its own corpus. Where several tracked paths share a basename
/// it resolves to NONE of them: guessing which file was meant is a wrong answer
/// wearing a right one's shape.
///
/// # It decides nothing, and that is what keeps it out of rule 3
///
/// One fact: which tracked paths the body names. It scores no prose, compares no
/// semantics and infers no intent. `filed-here` is the gate; this is the sensor
/// it reads.
///
/// `None` is could-not-look — an unreadable payload, or a tree whose index will
/// not open. An empty answer is the honest zero and renders as `0`.
#[must_use]
pub fn named_paths(payload: &serde_json::Value, root: &Path) -> Option<(i32, String)> {
    let body = body_text(payload)?;
    let tracked = crate::git::tracked_paths(root).ok()?;
    if tracked.is_empty() {
        return None;
    }

    // One basename to every tracked path carrying it, so ambiguity is a count
    // rather than a second scan.
    let mut by_base: BTreeMap<&str, Vec<&String>> = BTreeMap::new();
    for path in &tracked {
        by_base
            .entry(path.rsplit('/').next().unwrap_or(path.as_str()))
            .or_default()
            .push(path);
    }

    let mut named: BTreeSet<String> = BTreeSet::new();
    for token in tokens_in(&body, &by_base) {
        let token = token.trim_end_matches(['.', ',', ';', ':']);
        if tracked.contains(token) {
            named.insert(token.to_owned());
            continue;
        }
        let base = token.rsplit('/').next().unwrap_or(token);
        // Exactly one candidate resolves. Several is ambiguous and resolves to
        // none: 28 of 530 tracked basenames are ambiguous in this tree.
        if let Some([only]) = by_base.get(base).map(Vec::as_slice) {
            named.insert((*only).clone());
        }
    }

    let mut out = String::new();
    if named.is_empty() {
        out.push_str("0\n");
    } else {
        out.push_str(&named.len().to_string());
        for path in &named {
            out.push(' ');
            out.push_str(path);
        }
        out.push('\n');
    }
    Some((0, out))
}

/// THREE SHAPES, because bodies here use all three.
///
/// A dotted path or filename; a backticked `mise-tasks/<task>`; and a bare
/// backticked task name, tried as itself AND with `.sh`. The second form of the
/// third shape is the load-bearing one: a task is INVOKED as `mise run land` and
/// written up as `land`, while the file it resolves to is `land.sh`. Prose does
/// not carry the extension and should not have to.
fn tokens_in(body: &str, by_base: &BTreeMap<&str, Vec<&String>>) -> BTreeSet<String> {
    let mut found: BTreeSet<String> = BTreeSet::new();
    for word in body.split(|ch: char| ch.is_whitespace() || ch == '`') {
        let word = word.trim_matches(['(', ')', '[', ']', '*', '"', '\'']);
        if word.is_empty() {
            continue;
        }
        // A dotted path or filename: something before a `.` and an extension
        // after it, which is the shape the retired program's first pattern read.
        if let Some((stem, extension)) = word.rsplit_once('.')
            && !stem.is_empty()
            && !extension.is_empty()
            && extension.chars().all(|ch| ch.is_ascii_alphanumeric())
        {
            found.insert(word.to_owned());
        }
        if word.starts_with("mise-tasks/") {
            found.insert(word.to_owned());
        }
        // The bare backticked task name, tried as itself AND with `.sh`. The
        // second form is the load-bearing one: a task is INVOKED as `mise run
        // land` and written up as `land`, while the file it resolves to is
        // `land.sh`. Both are admitted only where they RESOLVE, which is what
        // stops an ordinary English word in backticks entering the token set.
        for candidate in [word.to_owned(), format!("{word}.sh")] {
            if by_base.contains_key(candidate.as_str()) {
                found.insert(candidate);
            }
        }
    }
    found
}

/// The body text out of a tracker payload, whatever shape the result carries.
fn body_text(payload: &serde_json::Value) -> Option<String> {
    if let Some(text) = payload.as_str() {
        return Some(text.to_owned());
    }
    for key in ["description", "body"] {
        if let Some(text) = payload.get(key).and_then(serde_json::Value::as_str) {
            return Some(text.to_owned());
        }
    }
    None
}

/// This authority's verdict as the token a template renders.
///
/// `-` for could-not-look on both of its causes, which is the direction that
/// makes a thin payload read LOUDER downstream rather than quieter (CLOUD-691).
#[must_use]
pub fn verdict_token(
    grammar: &Grammar,
    payload: &serde_json::Value,
    root: &Path,
) -> Option<&'static str> {
    match adjudicate(grammar, payload, root) {
        Some((0, _)) => Some(VERDICT_READY),
        Some((1, _)) => Some(VERDICT_UNREADY),
        _ => None,
    }
}

// CLOUD-1142's fixed example set, driven against the grammar this repository
// COMMITS rather than a fixture — `Grammar::committed`'s own reason: a fixture
// would let the registry row change while every case here kept passing, which is
// the drift one definition exists to remove.
//
// The examples are the row's, written down there rather than left to the
// implementer, and each one is a site that behaves differently today.
#[cfg(test)]
mod issue_key_tests {
    use super::Grammar;

    /// The consumer's own key, spelled from parts so this file carries no
    /// derivation of the token — `no-tracker-key-in-core` refuses one anywhere
    /// under `crates/**`, and a test is not exempt from the rule it is testing.
    pub(super) fn key(n: u32) -> String {
        format!("{}-{n}", "CL".to_owned() + "OUD")
    }

    #[test]
    fn the_consumers_own_key_is_a_key() {
        // The positive arm first: without it every refusal below is satisfied by
        // a definition that refuses everything.
        let grammar = Grammar::committed();
        let subject = key(757);
        assert_eq!(
            grammar.key_of(&subject).map(|k| k.as_str().to_owned()),
            Some(subject.clone()),
            "the committed vocabulary's own key must parse"
        );
    }

    #[test]
    fn the_lowercase_spelling_is_not_a_key() {
        // CASE: SENSITIVE. The shipped defect CLOUD-761 measured — one gate
        // accepts this spelling and two others cannot find it. Refused rather
        // than normalised, because normalising up produced the disagreement.
        let grammar = Grammar::committed();
        assert_eq!(grammar.key_of(&key(757).to_lowercase()), None);
    }

    #[test]
    fn a_glob_shaped_near_miss_is_not_a_key() {
        // PROJECT PREFIX: MANDATORY. All three are accepted today by the four
        // shell `case` globs, which test `[A-Z]*-[0-9]*` and cannot anchor.
        let grammar = Grammar::committed();
        for subject in ["AB-1", "Z-9", "A-1foo"] {
            assert_eq!(grammar.key_of(subject), None, "{subject} is not a key");
        }
    }

    #[test]
    fn a_key_with_a_trailing_letter_is_not_a_key_but_contains_one() {
        // The glob `<PREFIX>-[0-9]*` accepts this for the same reason. The whole
        // string must BE the key, and here the match stops short of the input's
        // end — which is also why this asks a different question from `keys_in`,
        // where the same string legitimately CONTAINS a key.
        let grammar = Grammar::committed();
        let subject = format!("{}x", key(1));
        assert_eq!(grammar.key_of(&subject), None);
        assert_eq!(grammar.keys_in(&subject).len(), 1);
    }

    #[test]
    fn a_shorter_key_is_not_found_inside_a_longer_one() {
        // BOUNDARY. The case two landed sites commented on by name. A greedy
        // match takes the whole number, so the short key never appears — and a
        // caller asking "does this carry key K" compares against this set rather
        // than searching again, which is the derivation this removes.
        let grammar = Grammar::committed();
        let found = grammar.keys_in(&key(179));
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].as_str(), key(179));
        assert!(!found.iter().any(|k| k.as_str() == key(17)));
    }

    #[test]
    fn a_key_glued_to_a_leading_token_is_not_found() {
        // The other half of the boundary, and the half `\b` gets wrong: a word
        // boundary treats `-` as a separator, so it would find a key inside a
        // longer hyphenated token.
        let grammar = Grammar::committed();
        for prefix in ["X", "9", "SUB-"] {
            let subject = format!("{prefix}{}", key(757));
            assert!(
                grammar.keys_in(&subject).is_empty(),
                "{subject} carries no key of its own"
            );
        }
    }

    #[test]
    fn ordinary_prose_yields_its_keys_in_numeric_order() {
        // The allow that keeps the boundary honest: the separators a body
        // actually uses must still open a key, or the definition refuses most
        // real text and gets replaced by a twenty-first copy.
        let grammar = Grammar::committed();
        let text = format!("Refs: {}, {} and ({}).", key(10), key(9), key(1142));
        let found: Vec<String> = grammar
            .keys_in(&text)
            .into_iter()
            .map(|k| k.as_str().to_owned())
            .collect();
        assert_eq!(
            found,
            vec![key(9), key(10), key(1142)],
            "numeric, not lexical"
        );
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod lint_tests {
    use super::{
        Grammar, Payload, Report, adjudicate, body_text, filled, lint, named_paths, owed_from,
        tokens_in, verdict_token, workspace_version,
    };
    use serde_json::{Value, json};
    use std::collections::BTreeMap;
    use std::path::{Path, PathBuf};

    use super::issue_key_tests::key;

    /// A tree whose workspace version is `version`, which is all §6 reads of it.
    fn versioned(name: &str, version: &str) -> PathBuf {
        let dir = crate::scratch::scratch(name);
        std::fs::write(
            dir.join("Cargo.toml"),
            format!(
                "[workspace]\nmembers = []\n\n[workspace.package]\nversion = \"{version}\"\n\n\
                 [workspace.dependencies]\nversion = \"9.9.9\"\n"
            ),
        )
        .expect("the manifest");
        dir
    }

    fn payload(body: &str, relations: Option<Value>) -> Payload {
        let mut value =
            json!({"id": key(1), "description": body, "createdAt": "2026-10-01T00:00:00.000Z"});
        if let Some(relations) = relations {
            value["relations"] = relations;
        }
        Payload::parse(&value).expect("a payload")
    }

    fn linted(grammar: &Grammar, body: &str, relations: Option<Value>, root: &Path) -> Report {
        lint(grammar, &payload(body, relations), root).expect("linted")
    }

    fn rules(report: &Report) -> Vec<String> {
        report
            .findings
            .iter()
            .map(|f| format!("{}:{}", f.line, f.rule))
            .collect()
    }

    fn emitted<'a>(report: &'a Report, label: &str) -> Option<&'a str> {
        report
            .emissions
            .iter()
            .find_map(|line| line.strip_prefix(label)?.strip_prefix(' '))
    }

    const OPENER: &str = "**Refinement — Ready (a summary)**";
    const SOURCE: &str = "* **Source of truth (§1).** One artifact.";

    fn prose(bump: &str) -> String {
        format!("{OPENER}\n{SOURCE}\n* **Commit / bump (§6).** {bump}\n")
    }

    #[test]
    fn a_relations_key_is_present_unless_null_and_every_edge_is_read() {
        let parsed = payload(
            "x",
            Some(
                json!({"blockedBy": [{"id": "A-1"}], "related": [{"id": "A-2"}], "parent": {"id": "A-3"}}),
            ),
        );
        assert!(parsed.relations_present);
        assert_eq!(parsed.blocked_by, ["A-1"]);
        let mut all = parsed.all_relations.clone();
        all.sort();
        assert_eq!(all, ["A-1", "A-2", "A-3"]);
        assert!(!payload("x", Some(Value::Null)).relations_present);
        assert!(!payload("x", None).relations_present);
    }

    #[test]
    fn the_grammar_lends_its_key_and_strips_mention_markup() {
        let grammar = Grammar::committed();
        let expression = regex::Regex::new(grammar.key_expression()).expect("compiles");
        assert!(expression.is_match(&key(5)));
        assert!(!expression.is_match("no key here"));
        assert_eq!(
            grammar.without_mentions("a <issue id=\"7\">b</issue> c"),
            "a b c"
        );
        let found = grammar.keys_in(&key(5));
        assert_eq!(
            found.iter().map(ToString::to_string).collect::<Vec<_>>(),
            [key(5)]
        );
    }

    #[test]
    fn only_an_undisclaimed_closing_verb_before_a_free_standing_key_closes_it() {
        let grammar = Grammar::committed();
        let closed = |text: &str| -> Vec<String> {
            grammar
                .keys_closed_in(text)
                .iter()
                .map(ToString::to_string)
                .collect()
        };
        assert_eq!(closed(&format!("Closes {}", key(5))), [key(5)]);
        assert!(closed(&format!("does not close {}", key(6))).is_empty());
        assert!(closed(&format!("see {}", key(7))).is_empty());
        assert!(closed(&format!("closes{}", key(8))).is_empty());
    }

    #[test]
    fn the_workspace_version_is_read_from_the_package_table_alone() {
        let root = versioned("ready-version", "1.2.3");
        assert_eq!(workspace_version(&root).expect("read"), "1.2.3");
    }

    #[test]
    fn the_body_cites_its_keys_before_any_verdict() {
        let grammar = Grammar::committed();
        let report = linted(&grammar, &format!("see {}", key(5)), None, Path::new("."));
        assert_eq!(
            report.emissions.first().map(String::as_str),
            Some(&*format!("cites-body {}", key(5)))
        );
        assert_eq!(rules(&report), ["0:no-ready-block"]);
    }

    #[test]
    fn a_finding_points_at_its_line_in_the_description() {
        let grammar = Grammar::committed();
        let root = Path::new(".");
        let report = linted(&grammar, &format!("intro\n\n{OPENER}\n"), None, root);
        assert_eq!(rules(&report), ["3:ready-block-without-clauses"]);
        let report = linted(
            &grammar,
            &format!("intro\n{OPENER}\n{SOURCE}\nOpen questions blocking Ready: one.\n"),
            None,
            root,
        );
        assert_eq!(rules(&report), ["4:open-questions-block-ready"]);
        let report = linted(
            &grammar,
            &format!("**Definition of Ready**\n{SOURCE}\n"),
            None,
            root,
        );
        assert!(
            rules(&report)
                .contains(&"1:non-canonical-ready-opener (use `**Refinement — Ready`)".to_owned()),
            "{:?}",
            rules(&report)
        );
    }

    #[test]
    fn the_clause_floor_spares_a_parent_and_a_block_with_a_clause() {
        let grammar = Grammar::committed();
        let root = Path::new(".");
        assert_eq!(
            rules(&linted(&grammar, &format!("{OPENER}\n"), None, root)),
            ["1:ready-block-without-clauses"]
        );
        assert!(
            rules(&linted(
                &grammar,
                &format!("{OPENER}\n{SOURCE}\n"),
                None,
                root
            ))
            .is_empty()
        );
        assert!(
            rules(&linted(
                &grammar,
                "## Refinement gate\nsee the document\n",
                None,
                root
            ))
            .is_empty()
        );
    }

    #[test]
    fn a_prose_block_owes_the_object_past_the_cutover_and_reads_its_own_clauses() {
        let mut grammar = Grammar::committed();
        let root = versioned("ready-prose-dialect", "1.2.0");
        let edges = Some(json!({"blockedBy": [{"id": key(3)}]}));
        let report = linted(&grammar, &prose("`fix` → patch"), edges.clone(), &root);
        assert!(rules(&report).is_empty(), "{:?}", rules(&report));
        assert_eq!(emitted(&report, "dialect"), Some("prose"));
        assert_eq!(emitted(&report, "bump"), Some("patch"));
        assert_eq!(emitted(&report, "cites-blockers"), Some(&*key(3)));
        grammar.prose_dialect_required_from = Some("2026-09-01T00:00:00.000Z".to_owned());
        let report = linted(&grammar, &prose("`fix` → patch"), edges, &root);
        assert_eq!(rules(&report), ["1:claims-object-absent"]);
        let report = linted(&grammar, &claims(&json!(complete())), None, &root);
        assert!(
            !rules(&report)
                .iter()
                .any(|r| r.ends_with("claims-object-absent"))
        );
    }

    fn bump_rules(grammar: &Grammar, root: &Path, bump: &str) -> (Vec<String>, Option<String>) {
        let report = linted(grammar, &prose(bump), None, root);
        (rules(&report), emitted(&report, "bump").map(str::to_owned))
    }

    #[test]
    fn the_declared_bump_agrees_with_the_type_on_a_released_line() {
        let grammar = Grammar::committed();
        let root = versioned("ready-bump-one", "1.2.0");
        let clean = |bump: &str| {
            let (found, _) = bump_rules(&grammar, &root, bump);
            assert!(found.is_empty(), "{bump}: {found:?}");
        };
        clean("`feat` → minor");
        clean("`fix` → patch");
        clean("`feat!` → major");
        clean("`ci` → no bump");
        clean("`fix` — the arrow table decides");
        let (found, emitted) = bump_rules(&grammar, &root, "`feat` → patch");
        assert_eq!(found, ["3:bump-disagrees-with-type (feat implies minor)"]);
        assert_eq!(emitted.as_deref(), Some("patch"));
        let (found, _) = bump_rules(&grammar, &root, "`fix` → minor");
        assert_eq!(found, ["3:bump-disagrees-with-type (fix implies patch)"]);
        let (found, emitted) = bump_rules(&grammar, &root, "**none**");
        assert!(found.is_empty(), "{found:?}");
        assert_eq!(emitted.as_deref(), Some("none"));
        let (found, emitted) = bump_rules(&grammar, &root, "nothing said");
        assert_eq!(found, ["3:commit-type-missing"]);
        assert_eq!(emitted.as_deref(), Some("-"));
        let (found, _) = bump_rules(&grammar, &root, "minor, and the type is `feat`");
        assert_eq!(found, ["3:commit-type-missing"]);
    }

    #[test]
    fn below_one_tenth_a_releasing_type_collapses_to_a_patch() {
        let grammar = Grammar::committed();
        let root = versioned("ready-bump-zero", "0.0.5");
        let (found, _) = bump_rules(&grammar, &root, "`feat` → patch");
        assert!(found.is_empty(), "{found:?}");
        let (found, _) = bump_rules(&grammar, &root, "`ci` → no bump");
        assert!(found.is_empty(), "{found:?}");
    }

    #[test]
    fn a_break_denial_must_name_its_surface() {
        let grammar = Grammar::committed();
        let root = versioned("ready-break", "1.2.0");
        let rule = "3:unqualified-break-claim (say which surface: `consumer` or `library` — `mise \
                    run semver` decides the library half)";
        assert_eq!(
            bump_rules(&grammar, &root, "`fix` → patch, not breaking").0,
            [rule]
        );
        assert!(
            bump_rules(
                &grammar,
                &root,
                "`fix` → patch, not breaking for the consumer"
            )
            .0
            .is_empty()
        );
    }

    #[test]
    fn a_deny_gate_owes_its_replay_and_nothing_else_does() {
        let grammar = Grammar::committed();
        let root = Path::new(".");
        let gate = "* **Gate (§3).** `mise-tasks/thing-check.sh`, severity = deny.";
        let found = rules(&linted(
            &grammar,
            &format!("{OPENER}\n{SOURCE}\n{gate}\n"),
            None,
            root,
        ));
        assert_eq!(found.len(), 1, "{found:?}");
        assert!(found[0].starts_with("3:deny-without-replay"), "{found:?}");
        let uncounted = format!("{OPENER}\n{SOURCE}\n{gate}\nA replay is planned.\n");
        assert_eq!(rules(&linted(&grammar, &uncounted, None, root)).len(), 1);
        let replayed = format!("{OPENER}\n{SOURCE}\n{gate}\nReplay: 40 commits, fired 2 times.\n");
        assert!(rules(&linted(&grammar, &replayed, None, root)).is_empty());
        let warn = "* **Gate (§3).** `mise-tasks/thing-check.sh`, severity = warn.";
        assert!(
            rules(&linted(
                &grammar,
                &format!("{OPENER}\n{SOURCE}\n{warn}\n"),
                None,
                root
            ))
            .is_empty()
        );
        let deny = "* **Severity (§3).** **deny**.";
        assert!(
            rules(&linted(
                &grammar,
                &format!("{OPENER}\n{SOURCE}\n{deny}\n"),
                None,
                root
            ))
            .is_empty()
        );
    }

    fn complete() -> serde_json::Map<String, Value> {
        let Value::Object(map) = json!({
            "source_of_truth": "the row",
            "gate": {"task": "verify", "exits": [0, 2]},
            "commit_type": "fix",
            "blockers": [],
            "tests": [{"file": "a.rs", "mutation": "slug"}],
        }) else {
            unreachable!()
        };
        map
    }

    fn claims(object: &Value) -> String {
        format!("{OPENER}\n{SOURCE}\n\n```json\n{object}\n```\n")
    }

    fn claimed(
        grammar: &Grammar,
        root: &Path,
        edit: impl FnOnce(&mut serde_json::Map<String, Value>),
    ) -> Report {
        let mut object = complete();
        edit(&mut object);
        linted(
            grammar,
            &claims(&Value::Object(object)),
            Some(json!({})),
            root,
        )
    }

    #[test]
    fn a_complete_object_passes_and_derives_its_bump() {
        let grammar = Grammar::committed();
        let root = versioned("ready-claims-complete", "1.2.0");
        let report = claimed(&grammar, &root, |_| {});
        assert!(rules(&report).is_empty(), "{:?}", rules(&report));
        assert_eq!(emitted(&report, "dialect"), Some("json"));
        assert_eq!(emitted(&report, "bump"), Some("patch"));
        assert_eq!(emitted(&report, "obligations"), Some("a.rs:slug"));
        let unparseable = linted(
            &grammar,
            &format!("{OPENER}\n{SOURCE}\n```json\n{{nope\n```\n"),
            None,
            &root,
        );
        assert_eq!(rules(&unparseable), ["1:claims-object-unparseable"]);
    }

    #[test]
    fn a_required_claim_must_be_present_and_non_empty() {
        let grammar = Grammar::committed();
        let root = versioned("ready-claims-required", "1.2.0");
        let missing =
            |edit: fn(&mut serde_json::Map<String, Value>)| rules(&claimed(&grammar, &root, edit));
        assert_eq!(
            missing(|o| {
                o.insert("source_of_truth".into(), json!(" "));
            }),
            ["1:claim-missing (source_of_truth)"]
        );
        assert_eq!(
            missing(|o| {
                o.insert("gate".into(), json!({}));
            }),
            ["1:claim-missing (gate)", "1:gate-task-unnamed"]
        );
        assert_eq!(
            missing(|o| {
                o.insert("tests".into(), json!([]));
            }),
            ["1:claim-missing (tests)"]
        );
        assert!(
            missing(|o| {
                o.insert("commit_type".into(), json!("docs"));
                o.insert("tests".into(), json!([]));
            })
            .is_empty()
        );
        assert!(
            missing(|o| {
                o.insert("commit_type".into(), json!("none"));
                o.insert("tests".into(), json!([]));
            })
            .is_empty()
        );
        assert_eq!(
            missing(|o| {
                o.insert("commit_type".into(), json!("docs"));
                o.insert("source_of_truth".into(), json!([]));
            }),
            ["1:claim-missing (source_of_truth)"]
        );
    }

    #[test]
    fn a_feat_owes_its_prior_art_from_the_cutover_and_each_entry_its_shape() {
        let mut grammar = Grammar::committed();
        let root = versioned("ready-prior-art", "1.2.0");
        let feat = |o: &mut serde_json::Map<String, Value>| {
            o.insert("commit_type".into(), json!("feat"));
        };
        assert!(rules(&claimed(&grammar, &root, feat)).is_empty());
        grammar.prior_art_required_from = Some("2026-09-01T00:00:00.000Z".to_owned());
        assert_eq!(
            rules(&claimed(&grammar, &root, feat)),
            ["1:claim-missing (prior_art)"]
        );
        assert!(
            rules(&claimed(&grammar, &root, |_| {})).is_empty(),
            "a fix owes none"
        );
        let entry = |entry: Value| {
            rules(&claimed(&grammar, &root, |o| {
                o.insert("prior_art".into(), json!([entry]));
            }))
        };
        assert!(entry(json!({"tool": "t", "url": "u", "verdict": "adopt"})).is_empty());
        assert!(
            entry(json!({"tool": "t", "url": "u", "verdict": " Reject ", "reason": "r"}))
                .is_empty()
        );
        let incomplete = ["1:prior-art-entry-incomplete"];
        assert_eq!(entry(json!({"url": "u", "verdict": "adopt"})), incomplete);
        assert_eq!(entry(json!({"tool": "t", "verdict": "adopt"})), incomplete);
        assert_eq!(
            entry(json!({"tool": "t", "url": "u", "verdict": "maybe"})),
            incomplete
        );
        assert_eq!(
            entry(json!({"tool": "t", "url": "u", "verdict": "reject"})),
            ["1:prior-art-rejection-unreasoned"]
        );
        let shapeless = rules(&claimed(&grammar, &root, |o| {
            o.insert("prior_art".into(), json!("searched"));
        }));
        assert_eq!(shapeless, incomplete);
    }

    #[test]
    fn a_cutover_applies_from_its_instant_and_could_not_look_passes() {
        let at = |created: &str| {
            let mut value = json!({"description": ""});
            value["createdAt"] = json!(created);
            Payload::parse(&value).expect("a payload")
        };
        let from = Some("2026-09-01T00:00:00.000Z");
        assert!(owed_from(from, &at("2026-09-01T00:00:00.000Z")));
        assert!(owed_from(from, &at("2026-10-01T00:00:00.000Z")));
        assert!(!owed_from(from, &at("2026-08-01T00:00:00.000Z")));
        assert!(!owed_from(None, &at("2026-10-01T00:00:00.000Z")));
        assert!(filled(&json!({"k": "x"}), "k"));
        assert!(!filled(&json!({"k": " "}), "k"));
        assert!(!filled(&json!({}), "k"));
    }

    #[test]
    fn a_gate_names_its_task_and_exits_inside_the_contract() {
        let grammar = Grammar::committed();
        let root = versioned("ready-claimed-gate", "1.2.0");
        let found = rules(&claimed(&grammar, &root, |o| {
            o.insert("gate".into(), json!({"exits": [7]}));
        }));
        assert_eq!(
            found,
            ["1:gate-task-unnamed", "1:gate-exit-outside-contract"]
        );
    }

    #[test]
    fn a_claimed_type_derives_its_bump_from_the_arrow_table() {
        let grammar = Grammar::committed();
        let derived = |root: &Path, commit_type: &str| {
            let report = claimed(&grammar, root, |o| {
                o.insert("commit_type".into(), json!(commit_type));
            });
            (rules(&report), emitted(&report, "bump").map(str::to_owned))
        };
        let released = versioned("ready-claimed-type-one", "1.2.0");
        assert_eq!(derived(&released, "feat").1.as_deref(), Some("minor"));
        assert_eq!(derived(&released, "Fix").1.as_deref(), Some("patch"));
        assert_eq!(derived(&released, "feat!").1.as_deref(), Some("major"));
        assert_eq!(derived(&released, "docs").1.as_deref(), Some("no-release"));
        assert_eq!(derived(&released, "none").1.as_deref(), Some("none"));
        assert_eq!(derived(&released, "none").0, Vec::<String>::new());
        assert_eq!(
            derived(&released, "fixx").0,
            ["1:commit-type-unknown (fixx)"]
        );
        let early = versioned("ready-claimed-type-zero", "0.0.5");
        assert_eq!(derived(&early, "feat").1.as_deref(), Some("patch"));
        assert_eq!(derived(&early, "docs").1.as_deref(), Some("no-release"));
    }

    #[test]
    fn a_claimed_blocker_is_held_to_the_edges_or_counted_unjudgeable() {
        let grammar = Grammar::committed();
        let root = versioned("ready-claimed-blockers", "1.2.0");
        let mut object = complete();
        object.insert("blockers".into(), json!([key(2)]));
        let body = claims(&Value::Object(object));
        let unread = linted(&grammar, &body, None, &root);
        assert_eq!((unread.unjudgeable, unread.unjudged_line), (1, 1));
        assert_eq!(emitted(&unread, "cites-blockers"), Some(&*key(2)));
        let unlinked = linted(&grammar, &body, Some(json!({})), &root);
        assert_eq!(
            rules(&unlinked),
            [format!("1:blocker-cited-without-relation ({})", key(2))]
        );
        assert_eq!(unlinked.unjudgeable, 0);
        let linked = linted(
            &grammar,
            &body,
            Some(json!({"blockedBy": [{"id": key(2)}]})),
            &root,
        );
        assert!(rules(&linked).is_empty(), "{:?}", rules(&linked));
    }

    #[test]
    fn a_test_claim_names_its_file_and_a_mutation_slug() {
        let grammar = Grammar::committed();
        let root = versioned("ready-claimed-tests", "1.2.0");
        let tests = |entry: Value| {
            rules(&claimed(&grammar, &root, |o| {
                o.insert("tests".into(), json!([entry]));
            }))
        };
        assert_eq!(
            tests(json!({"file": "a.rs"})),
            ["1:test-claim-incomplete (mutation)"]
        );
        assert_eq!(
            tests(json!({"file": "a.rs", "mutation": "two words"})),
            ["1:test-claim-mutation-not-a-slug"]
        );
    }

    #[test]
    fn a_deferral_is_held_to_the_relations_and_never_to_the_row_itself() {
        let grammar = Grammar::committed();
        let root = Path::new(".");
        let body = format!(
            "{OPENER}\n{SOURCE}\nThe rest is deferred to {}.\nAnd {} is now mine.\n",
            key(2),
            key(1)
        );
        let unread = linted(&grammar, &body, None, root);
        assert_eq!((unread.unjudgeable, unread.unjudged_line), (1, 3));
        let unlinked = linted(&grammar, &body, Some(json!({})), root);
        assert_eq!(
            rules(&unlinked),
            [format!("3:deferral-cited-without-relation ({})", key(2))]
        );
        let linked = linted(
            &grammar,
            &body,
            Some(json!({"relatedTo": [{"id": key(2)}]})),
            root,
        );
        assert!(rules(&linked).is_empty(), "{:?}", rules(&linked));
    }

    #[test]
    fn the_adjudication_answers_in_the_shell_programs_codes() {
        let grammar = Grammar::committed();
        let root = Path::new(".");
        let value = |body: &str, relations: Option<Value>| {
            let mut value = json!({"id": key(1), "description": body});
            if let Some(relations) = relations {
                value["relations"] = relations;
            }
            value
        };
        let ready = value(&format!("{OPENER}\n{SOURCE}\n"), Some(json!({})));
        let (status, out) = adjudicate(&grammar, &ready, root).expect("judged");
        assert_eq!(status, 0);
        assert_eq!(out, "cites-body \ndialect prose\ncites-blockers \n");
        assert_eq!(verdict_token(&grammar, &ready, root), Some("ready"));
        let unready = value("no block", None);
        assert_eq!(
            adjudicate(&grammar, &unready, root).map(|(s, _)| s),
            Some(1)
        );
        assert_eq!(verdict_token(&grammar, &unready, root), Some("unready"));
        let partial = value(
            &format!("{OPENER}\n{SOURCE}\nDeferred to {}.\n", key(2)),
            None,
        );
        assert_eq!(
            adjudicate(&grammar, &partial, root).map(|(s, _)| s),
            Some(2)
        );
        assert_eq!(verdict_token(&grammar, &partial, root), None);
    }

    #[test]
    fn a_body_names_the_tracked_paths_it_resolves_to_unambiguously() {
        let dir = crate::scratch::scratch("ready-named-paths");
        crate::gitwrite::init_on_main(&dir).expect("a repository");
        let paths = ["src/a.rs", "mise-tasks/land.sh", "x/dup.md", "y/dup.md"];
        for path in paths {
            let full = dir.join(path);
            std::fs::create_dir_all(full.parent().expect("a parent")).expect("a directory");
            std::fs::write(full, "").expect("a file");
        }
        let owned: Vec<String> = paths.iter().map(|p| (*p).to_owned()).collect();
        crate::gitwrite::commit_paths(&dir, &owned, "chore: seed").expect("a commit");
        let body = json!({"description": "see a.rs and `land` and dup.md (twice)."});
        assert_eq!(
            named_paths(&body, &dir),
            Some((0, "2 mise-tasks/land.sh src/a.rs\n".to_owned()))
        );
        assert_eq!(
            named_paths(&json!({"description": "nothing"}), &dir),
            Some((0, "0\n".to_owned()))
        );
    }

    #[test]
    fn a_token_is_a_dotted_word_split_on_whitespace_and_backticks() {
        let by_base: BTreeMap<&str, Vec<&String>> = BTreeMap::new();
        let found: Vec<String> = tokens_in("`a.rs` x.toml .rs b. `c.d`", &by_base)
            .into_iter()
            .collect();
        assert_eq!(found, ["a.rs", "c.d", "x.toml"]);
    }

    #[test]
    fn the_body_is_read_off_any_shape_the_result_carries() {
        assert_eq!(body_text(&json!("raw")).as_deref(), Some("raw"));
        assert_eq!(body_text(&json!({"body": "b"})).as_deref(), Some("b"));
        assert_eq!(
            body_text(&json!({"description": "d", "body": "b"})).as_deref(),
            Some("d")
        );
        assert_eq!(body_text(&json!({})), None);
    }
}
