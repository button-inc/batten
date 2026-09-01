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

use std::collections::BTreeSet;
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
    unanchored_clause: Regex,
    open_questions: Regex,
    legacy_clause_notation: Regex,
    /// The keys still allowed to write a Ready block as prose (CLOUD-472).
    ///
    /// **A THRESHOLD, NOT A SWITCH.** Issue keys are minted in order, so a key
    /// pattern IS a creation-order cutover — and it is one the consumer can read
    /// and move, in the consumer's own key space, with none of the timezone,
    /// format or clock-skew hazard a date literal carries.
    prose_dialect_exempt: Regex,
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
    blockers_label: Regex,
    blockedby_claim: Regex,
    blocks_tail: Regex,
    relatedto_tail: Regex,
    defer_verb: Regex,
    key: Regex,
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
    "ready-unanchored-clause",
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
    "ready-blockers-label",
    "ready-blockedby-claim",
    "ready-blocks-tail",
    "ready-relatedto-tail",
    "ready-defer-verb",
    "ready-issue-key",
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
            unanchored_clause: find("ready-unanchored-clause")?,
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
            blockers_label: find("ready-blockers-label")?,
            blockedby_claim: find("ready-blockedby-claim")?,
            blocks_tail: find("ready-blocks-tail")?,
            relatedto_tail: find("ready-relatedto-tail")?,
            defer_verb: find("ready-defer-verb")?,
            prose_dialect_exempt: find("ready-prose-dialect-exempt")?,
            key: find("ready-issue-key")?,
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
        let text =
            std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../batten.toml"))
                .unwrap_or_default();
        let rows: Vec<crate::pattern::NamedPattern> = match crate::facts::Format::Toml.read(&text) {
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
        };
        match Self::resolve(&rows) {
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

/// The issue keys in a span, deduped and ordered NUMERICALLY.
///
/// Numeric and not a bare sort, for `graph-check`'s reason: `CLOUD-10` sorts
/// before `CLOUD-9` lexically, so a caller diffing two runs could not tell an
/// ordering change from a content one.
fn keys_in(grammar: &Grammar, text: &str) -> Vec<String> {
    let found: BTreeSet<&str> = grammar.key.find_iter(text).map(|m| m.as_str()).collect();
    let mut keys: Vec<String> = found.into_iter().map(str::to_owned).collect();
    keys.sort_by_key(|k| {
        k.rsplit('-')
            .next()
            .and_then(|n| n.parse::<u64>().ok())
            .unwrap_or(0)
    });
    keys
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

    // A LABEL WHOSE EMPHASIS IS GONE IS A CLAUSE THIS GATE COULD NOT ANCHOR, and
    // saying so is the whole of this arm (CLOUD-1082).
    //
    // The floor above fires only at ZERO clauses, so a block that lost SOME of
    // its labels still has clauses and passes — while the ones it lost have
    // vanished from every reader, including the `[[recorder]]`'s `sec1` column
    // and therefore `filed-here`'s `cites_only` exemption. Measured: every label
    // plain is `ready-block-without-clauses`; one label bolded and the rest
    // plain is a clean pass. Partial loss is exactly what the tracker's
    // normaliser produces, because it only degrades what it already touched.
    //
    // REPORTED, NEVER ACCEPTED. Reading the plain label AS a clause would be the
    // looser anchor CLOUD-290 was filed about. This says the line looks like a
    // clause and could not be read as one, which costs the author one re-bold
    // and costs the grammar nothing.
    for (offset, line) in block_lines.iter().enumerate() {
        if grammar.unanchored_clause.is_match(line) {
            report.findings.push(Finding {
                line: ready_start + offset,
                rule: "clause-label-not-anchored".to_owned(),
            });
        }
    }

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
    // COULD-NOT-LOOK PASSES, and it is the id that decides. A payload carrying
    // no readable key cannot be placed against the threshold at all, so it is
    // judged exactly as it was before this clause existed. Reading "no key" as
    // "past the cutover" would turn a verdict about the payload into a verdict
    // about the row.
    if !structured
        && grammar.key.is_match(&payload.id)
        && !grammar.prose_dialect_exempt.is_match(&payload.id)
    {
        report.findings.push(Finding {
            line: ready_start,
            rule: "claims-object-absent".to_owned(),
        });
    }

    if !structured {
        check_bump(grammar, root, &block_lines, &line_of, &mut report)?;
    }
    check_replay(grammar, &block, &line_of, &mut report);
    if !structured {
        check_blockers(grammar, payload, &block_lines, &line_of, &mut report);
    }
    check_deferrals(grammar, payload, &mut report);

    Ok(report)
}

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

    let type_token = grammar
        .commit_type
        .find(bump_line)
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
               predicate over `git rev-list origin/main` and record commits examined, times \
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

    for key in REQUIRED_CLAIMS {
        // PRESENT AND NON-EMPTY, because an empty string, array or object is an
        // omission wearing a declaration's shape. `blockers: []` is the one
        // deliberate exception and is handled below — a row with no blockers
        // must be able to SAY so, which is the absence this row exists to make
        // writable.
        let filled = match claims.get(key) {
            None | Some(serde_json::Value::Null) => false,
            Some(serde_json::Value::String(text)) => !text.trim().is_empty(),
            Some(serde_json::Value::Array(items)) => key == "blockers" || !items.is_empty(),
            Some(serde_json::Value::Object(fields)) => !fields.is_empty(),
            Some(_) => true,
        };
        if !filled {
            report.findings.push(Finding {
                line: block_line,
                rule: format!("claim-missing ({key})"),
            });
        }
    }

    check_claimed_gate(&claims, block_line, report);
    check_claimed_type(&claims, root, block_line, report)?;
    check_claimed_blockers(grammar, payload, &claims, block_line, report);
    check_claimed_tests(&claims, block_line, report);
    Ok(true)
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
    let named = gate
        .get("task")
        .and_then(serde_json::Value::as_str)
        .is_some_and(|task| !task.trim().is_empty());
    if !named {
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
            let filled = entry
                .get(key)
                .and_then(serde_json::Value::as_str)
                .is_some_and(|text| !text.trim().is_empty());
            if !filled {
                report.findings.push(Finding {
                    line,
                    rule: format!("test-claim-incomplete ({key})"),
                });
            }
        }
    }
}

/// §8: blockers linked, not assumed.
///
/// The highest-value rule here, and the only one prose cannot fake. A block
/// CLAIMING a blocker while carrying no such relation is asserting a dependency
/// the board does not know about — exactly the failure the clause names.
///
/// What opens a claim is the consumer's `ready-blockedby-claim` row, which
/// carries the corpus's spellings of one concept — the tracker's own token and
/// the English phrase alike. Naming a spelling here too would be a second
/// authority on it (CLOUD-1113), and after CLOUD-1146 the vocabulary is not this
/// crate's to name at all.
///
/// **Claims, not mentions.** A well-formed §8 bullet also cross-references the
/// other relation directions, and flagging those would punish precision. So only
/// ids in the span after the first claim opener are claims, and the span ends at
/// a `blocks`/`relatedTo` token or the sentence's end. Widening WHICH spellings
/// open a claim leaves every one of those span rules untouched, which is what
/// keeps a §8 bullet that cross-references a sibling from becoming a claim.
fn check_blockers(
    grammar: &Grammar,
    payload: &Payload,
    block_lines: &[&str],
    line_of: &dyn Fn(&Regex) -> usize,
    report: &mut Report,
) {
    let label = &grammar.blockers_label;
    let Some(start) = first_line(label, block_lines) else {
        // No §8 span at all, so no keys are emitted for it. An absent line is
        // "this run never got far enough to know", per set.
        report
            .emissions
            .push(emit_keys(grammar, "cites-blockers", ""));
        return;
    };

    // The claim is not always ON the label line. The corpus's usual dialect is a
    // single-line bullet, but a `### Blockers (§8)` heading with the claim in
    // the paragraph below is equally legitimate markdown, and reading only the
    // label line made every such issue pass VACUOUSLY. So: the label line plus
    // the first paragraph after it, stopping at the next heading or the blank
    // line that ends it. Bounded on purpose — a greedier span would swallow
    // later sections and flag ids that assert nothing about blocking.
    let mut span: Vec<&str> = Vec::new();
    let mut seen_body = false;
    for (offset, line) in block_lines[start - 1..].iter().enumerate() {
        if offset == 0 {
            span.push(line);
            continue;
        }
        if line.starts_with('#') {
            break;
        }
        if line.trim().is_empty() {
            if seen_body {
                break;
            }
            continue;
        }
        seen_body = true;
        span.push(line);
    }
    let text = grammar.strip_mentions(&span.join("\n"));

    let claim = grammar
        .blockedby_claim
        .find(&text)
        .map(|m| m.as_str().to_owned())
        .unwrap_or_default();
    // A claim is one sentence: the §8 bullet legitimately carries trailing
    // cross-references that assert nothing about blocking.
    let claim = claim.split(". ").next().unwrap_or_default().to_owned();
    let claim = grammar.blocks_tail.replace(&claim, "");
    let claim = grammar.relatedto_tail.replace(&claim, "");

    report
        .emissions
        .push(emit_keys(grammar, "cites-blockers", &span.join("\n")));

    for cited in keys_in(grammar, &claim) {
        // THE SCAN STILL RUNS, THE CROSS-CHECK DOES NOT (CLOUD-679). Finding the
        // citation is what makes "the missing key is the SOLE reason" computable
        // at all: a payload with no key and nothing cited lost nothing and must
        // stay clean, because CLOUD-526 declares that a caller may project
        // everything but `.description` away.
        if !payload.relations_present {
            report.unjudgeable += 1;
            if report.unjudged_line == 0 {
                report.unjudged_line = line_of(&grammar.blockers_label);
            }
            continue;
        }
        if !payload.blocked_by.iter().any(|edge| edge == &cited) {
            report.findings.push(Finding {
                line: line_of(&grammar.blockers_label),
                rule: format!("blocker-cited-without-relation ({cited})"),
            });
        }
    }
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
