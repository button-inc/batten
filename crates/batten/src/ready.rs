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

// --- the grammar, as declared patterns ---------------------------------------
//
// Each of these is the ONE authority for the token it names. `.claude/rules/`
// points here rather than restating them, so a copy cannot drift from the
// parser — the discipline the shell program established and this port keeps.

/// Two openers, because a parent and a leaf carry different things.
///
/// A leaf opens `**Refinement — Ready (…)**` and states its own
/// specializations. A parent opens `## Refinement gate` and points at the gate
/// for its children — the gate document's own vocabulary for an epic. Matching
/// only the leaf form reported `no-ready-block` on every correctly-refined epic
/// on the board, which is the worst kind of false negative: it would have pushed
/// authors to rename a heading the spec prescribes purely to satisfy a lint.
/// Measured on CLOUD-7.
///
/// A fourth opener, `**Definition of ready**`, is recognised only to be REPORTED
/// (CLOUD-299) — the dialect four issues actually use. Leaving it unrecognised
/// made the anchor wrong in both directions at once: those bodies reported
/// `no-ready-block`, right for three of them but reached by accident.
const READY_OPENERS: &str =
    r"(?i)^\*\*Refinement|^#{2,3} +Refinement|^#{2,3} +Ready|^\*\*Definition of [Rr]eady";

/// The parent dialect, needed twice: to locate a block, and to exempt it from
/// the clause floor.
const PARENT_OPENER: &str = r"(?i)^#{2,3} +Refinement gate";

/// The non-canonical opener, recognised only to converge the corpus.
const LEGACY_OPENER: &str = r"(?i)^\*\*Definition of [Rr]eady";

/// What counts as a clause, and why it is not a bare `(§N)`.
///
/// The §N namespace is overloaded: Ready blocks legitimately cite house-style
/// sections in prose ("pointer-only per §6"), so counting any `(§N)` would let a
/// cross-reference satisfy the floor — a vacuous pass in a narrower form. The
/// anchor is the label+tag pair in both corpus dialects: a bolded label at line
/// start, or a heading carrying the tag. The heading arm is load-bearing, not
/// defensive — bodies whose ONLY clause is a `### Blockers (§8)` heading are on
/// the board.
const CLAUSE_LABEL: &str = r"(?i)^[[:space:]]*([*-][[:space:]]*)?\*\*[^*]*\((§|clause )[0-9]+\)|^#{2,6}[[:space:]]+[^#]*\((§|clause )[0-9]+\)";

/// The questions-are-artifacts protocol: an agent that hits a real ambiguity
/// writes it onto the issue and moves on, and the issue stays out of the ready
/// queue. That only holds if the marker is a gate — otherwise a question can be
/// written and the issue promoted anyway, which is the silent-rot case.
const OPEN_QUESTIONS: &str = r"(?i)open questions? blocking ready|\(incomplete —";

/// The older `(clause N)` dialect, recognised only to be reported. Accepting
/// both silently is what lets drift accumulate.
const LEGACY_CLAUSE_NOTATION: &str = r"(?i)\(clause [0-9]+\)";

/// The §6 clause label. Anchored on the LABEL + tag pair, never on a bare
/// `(§6)`: the §N namespace is overloaded, and only a line carrying the
/// "Commit / bump (§6)" label is the clause.
const BUMP_LABEL: &str = r"(?i)Commit / bump \((§|clause )6\)";

/// The commit type as a WHOLE code span, never a prefix (CLOUD-290).
///
/// The closing backtick used to be optional, so the pattern matched a prefix of
/// any longer span and any backticked token beginning with a type word was read
/// as the declared type. Measured on two lines differing only in the bump text:
/// a line reading "`ci-local-parity`; `feat` -> patch until 0.1.0" — an honest
/// declaration — was refused as "ci implies no bump", while a line whose type
/// was really `ci` passed while reading the type as `test`. The defect was loud
/// exactly when the author was right and silent exactly when it did no damage,
/// which is why it survived: it is discoverable only by experiment.
///
/// The optional `(scope)` arm is not decoration: `fix(gate)` is a legitimate
/// Conventional Commit declaration, and without it the tightened anchor would
/// turn a verdict this gate reaches today into `commit-type-missing`.
const TYPE_TOKEN: &str = r"(?i)`(build|chore|ci|docs|feat|fix|perf|refactor|revert|style|test)([(][a-z0-9._-]+[)])?!?`!?";

/// The corpus's ways of DENYING a break.
///
/// **The `!` is read off the TYPE TOKEN, never off the line** (CLOUD-852). This
/// was a count of `!|BREAKING CHANGE` over the whole clause, which has no
/// polarity: the corpus's own way of denying a break is to write "Not `!`", and
/// that spelling made the gate read `expected = "major"`. Five rows on the board
/// use it. It went unnoticed because below 0.1.0 a false `major` collapses to
/// `patch`, which is where `feat` and `fix` already collapse — so for every
/// releasable type the wrong reason produced the right answer.
const BREAK_DENIAL: &str =
    r"(?i)not[[:space:]]+`?!`?|not[[:space:]]+breaking|non-?breaking|no[[:space:]]+break[a-z]*";

/// The denial, qualified by the surface it denies about (CLOUD-842).
///
/// `batten` is BOTH a binary and a library, so "breaking" names two different
/// objects and §6 has one word for them: the CONSUMER surface (`batten.toml`
/// rows, exit codes, output shape) and the LIBRARY surface (the `pub` Rust API,
/// which `mise run semver` measures). Five rows of the CLOUD-839 bundle declared
/// "not `!`" reasoning correctly about the first and never checking the second;
/// the change landed as `feat(policy)!`.
///
/// **The qualifier must attach to the denial, not merely share the line.**
/// CLOUD-832's clause reads "Not `!`: the string `deny` path is preserved, so no
/// consumer shape breaks" — the word `consumer` is forty characters downstream,
/// part of the reasoning rather than the scope of the denial. A bare "does
/// `consumer` appear anywhere" test passes the one row this clause exists to
/// refuse.
///
/// The connective set is an alternation rather than a bracket expression: an em
/// dash is multibyte, and a bracket expression would match one of its own bytes.
const BREAK_QUALIFIED: &str = r"(?i)(not[[:space:]]+`?!`?|not[[:space:]]+breaking|non-?breaking|no[[:space:]]+break[a-z]*)[[:space:]]*(-|—|,|:)?[[:space:]]*(for|to|on|in|of)?[[:space:]]*(the[[:space:]]+)?(consumer|library)";

/// A block that INTRODUCES a gate: a fenced `[[rule]]` declaration, or a
/// `mise-tasks/<name>-check` path. The extension is OPTIONAL and both spellings
/// must match — a gate is written up as `mise-tasks/x-check` and the file is
/// `mise-tasks/x-check.sh` (CLOUD-865), so anchoring on `-check` at the closing
/// backtick silently stopped recognising a gate introduction the day the tree
/// grew extensions.
const GATE_INTRO: &str =
    r"(?s)```[^`]*\[\[rule\]\]|`mise-tasks/[a-z0-9][a-z0-9._-]*-check(\.sh|\.bash)?`";

/// The same anchor, narrowed to something that matches WITHIN one line, so the
/// pointer names the right place.
const GATE_INTRO_LINE: &str = r"\[\[rule\]\]|`mise-tasks/[a-z0-9][a-z0-9._-]*-check(\.sh|\.bash)?`";

/// A severity ASSIGNMENT or a bolded declaration, never the bare word: this
/// rule's own id is `deny-without-replay`, so a bare-word predicate self-trips
/// on the block that introduces the rule.
const DENY_SEVERITY: &str = r"(?i)severity[[:space:]]*=[[:space:]]*.?deny|\*\*deny\*\*";

/// What counts as a replay: a line naming one, plus a firing count somewhere in
/// the block. Block-wide rather than one-line, because a replay is reported as a
/// fenced measurement whose prose header names it and whose body carries the
/// numbers — measured on CLOUD-752 and CLOUD-753, neither of which puts both
/// halves on one line.
const REPLAY_NAMED: &str = r"(?i)replay";

/// The count half of a replay.
const REPLAY_COUNT: &str =
    r"(?i)[0-9][^.]{0,40}fir(e|ed|ing)|fir(e|ed|ing)[^.]{0,40}[0-9]|would-fire";

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

/// The §8 clause label.
const BLOCKERS_LABEL: &str = r"(?i)Blockers \((§|clause )8\)";

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

/// What opens a blocker CLAIM, and the whole of what does (CLOUD-1113).
///
/// **A named constant rather than an inline literal, because the corpus writes
/// one concept three ways and the anchor knew one of them.** It was
/// `(?i)blockedBy` — case-insensitive and space-SENSITIVE — so the code-span and
/// bare camel-case forms matched and `blocked by`, ordinary English for the same
/// assertion, did not. A claim the anchor cannot parse does not fail: the id loop
/// never runs and the clause passes **vacuously**, which is precisely the failure
/// §8 exists to catch, arriving through §8's own anchor.
///
/// Measured twice while grooming (2026-08-28). CLOUD-438 wrote "blocked by
/// CLOUD-435 phase 2" against `blockedBy: []` and exited 0 — and the claim was
/// not merely unchecked but FALSE, the blocker having been Done for some time
/// while the row sat in Backlog behind it. CLOUD-1089 wrote "blocked by CLOUD-1008,
/// which is itself blocked by CLOUD-1009" while carrying only the first relation;
/// the second id would have been reported had the anchor matched.
///
/// **The tracker teaches the spelling the gate could not read**, which is why
/// this is likelier than it looks: the convention is a code span, and the UI
/// displays the relation as "Blocked by", so an author writing prose rather than
/// copying the convention reaches for exactly the form that was invisible.
///
/// `[[:space:]]*` rather than a literal space covers all three at once — no
/// separator, one space, a newline where the phrase wraps — and the leading
/// backtick needs no clause of its own, since the match may start inside a code
/// span and take the rest.
///
/// **Deliberately not wider.** "depends on", "needs", "waits for" are
/// intent-bearing phrases that assert no board relation, and reading them as
/// claims is CLOUD-454's question rather than this one: that row is the OPPOSITE
/// direction — a relation the body never claims — and needs its own argument.
const BLOCKER_CLAIM: &str = r"(?i)blocked[[:space:]]*by";

/// A hand-off verb, for the deferral scan.
///
/// Claims, not mentions — the discipline §8 establishes. "The same failure shape
/// as CLOUD-195" is a comparison, "split out of CLOUD-177" is provenance, "see
/// CLOUD-33" is a cross-reference; none hands anything off, and flagging them
/// would punish the cross-referencing that makes issues readable. So a claim is
/// a hand-off VERB immediately followed by an id, nothing looser.
const DEFER_VERB: &str = r"(?i)(deferred?|deferring|defers) (it |that |this )?to|owned by|belongs to|left to|handed off to|handled by|tracked (separately )?(in|by|under)|moved? to|is now|remains";

/// An issue key.
const KEY: &str = r"CLOUD-[0-9]+";

/// Linear serialises a mention as `<issue …>CLOUD-N</issue>`, so the markup is
/// stripped and the stored and rendered forms become one case. A pattern written
/// against the rendered form never matches the stored one, and an exemption
/// tested only on plain-text fixtures is dead code in production.
fn strip_mentions(text: &str) -> String {
    let markup = compiled(r"</?issue[^>]*>");
    markup.replace_all(text, "").into_owned()
}

/// Compile a pattern declared in this module.
///
/// Every pattern here is a `const` in this file, so a failure is a bug in this
/// module rather than anything a caller can cause — but the workspace forbids
/// `unwrap`/`expect` on reachable paths, so the fallback is a regex that matches
/// nothing rather than a panic. A pattern that failed to compile then reports no
/// findings for its own clause, which is the fail-open direction and is caught
/// by `tests::every_declared_pattern_compiles` rather than at runtime.
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
fn keys_in(text: &str) -> Vec<String> {
    let key = compiled(KEY);
    let found: BTreeSet<&str> = key.find_iter(text).map(|m| m.as_str()).collect();
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
/// (`crates/batten/tests/authority_replay.rs`), which is what a replay is for and
/// what neither producer's own suite could see.
fn emit_keys(label: &str, text: &str) -> String {
    format!("{label} {}", keys_in(text).join(" "))
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
pub fn lint(payload: &Payload, root: &Path) -> Result<Report> {
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
        "cites-body",
        &strip_mentions(&payload.description),
    ));

    let Some(ready_start) = first_line(&compiled(READY_OPENERS), &lines) else {
        report.findings.push(Finding {
            line: 0,
            rule: "no-ready-block".to_owned(),
        });
        return Ok(report);
    };

    // The opener line, read once: it decides both the notation report and the
    // parent exemption on the clause floor.
    let opener = lines.get(ready_start - 1).copied().unwrap_or_default();
    if compiled(LEGACY_OPENER).is_match(opener) {
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
    let line_of = |pattern: &str| -> usize {
        first_line(&compiled(pattern), &block_lines).map_or(ready_start, |n| ready_start + n - 1)
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
    let clause = compiled(CLAUSE_LABEL);
    let clauses = block_lines.iter().filter(|l| clause.is_match(l)).count();
    if clauses == 0 && !compiled(PARENT_OPENER).is_match(opener) {
        report.findings.push(Finding {
            line: ready_start,
            rule: "ready-block-without-clauses".to_owned(),
        });
    }

    if compiled(OPEN_QUESTIONS).is_match(&block) {
        report.findings.push(Finding {
            line: line_of(OPEN_QUESTIONS),
            rule: "open-questions-block-ready".to_owned(),
        });
    }

    if compiled(LEGACY_CLAUSE_NOTATION).is_match(&block) {
        report.findings.push(Finding {
            line: line_of(LEGACY_CLAUSE_NOTATION),
            rule: "non-canonical-clause-notation (use §N)".to_owned(),
        });
    }

    // THE CHECKABLE HALF, IF THE BLOCK CARRIES ONE (CLOUD-453). An object is
    // authoritative for what it carries, so §6 and §8 are skipped when one is
    // present rather than run alongside it: two readings of one claim can
    // disagree, and a row that disagrees with itself is the shape no reviewer
    // can adjudicate.
    let structured = check_claims(payload, root, &block, ready_start, &mut report)?;

    // THE DIALECT, AS A FACT RATHER THAN A VERDICT. A prose-only block still
    // PASSES — every issue Ready today stays Ready, which is what lets the
    // corpus converge deliberately instead of in one sweep — and is named, so a
    // caller can find the ones still to convert without re-reading any body.
    // Reporting it as a finding would refuse ~40 refined rows for being written
    // before the mechanism existed, which is the recognise-to-report bargain
    // this gate already runs twice.
    report.emissions.push(format!(
        "dialect {}",
        if structured { "json" } else { "prose" }
    ));

    if !structured {
        check_bump(root, &block_lines, &line_of, &mut report)?;
    }
    check_replay(&block, &line_of, &mut report);
    if !structured {
        check_blockers(payload, &block_lines, &line_of, &mut report);
    }
    check_deferrals(payload, &mut report);

    Ok(report)
}

/// §6: the commit type and the bump must agree, and a break denial must name a
/// surface.
fn check_bump(
    root: &Path,
    block_lines: &[&str],
    line_of: &dyn Fn(&str) -> usize,
    report: &mut Report,
) -> Result<()> {
    let label = compiled(BUMP_LABEL);
    let Some(bump_line) = block_lines.iter().find(|l| label.is_match(l)) else {
        return Ok(());
    };
    // Read lazily, INSIDE the clause: an issue with no §6 needs no version, and
    // demanding one would break linting a payload from outside a checkout.
    let version = workspace_version(root)?;

    let type_token = compiled(TYPE_TOKEN)
        .find(bump_line)
        .map(|m| m.as_str().to_owned())
        .unwrap_or_default();
    let scope = compiled(r"[(][^)]*[)]");
    let commit_type = scope
        .replace_all(&type_token, "")
        .replace(['`', '!'], "")
        .to_lowercase();
    let breaking = type_token.contains('!') || compiled(r"BREAKING CHANGE:").is_match(bump_line);

    if compiled(BREAK_DENIAL).is_match(bump_line) && !compiled(BREAK_QUALIFIED).is_match(bump_line)
    {
        report.findings.push(Finding {
            line: line_of(BUMP_LABEL),
            rule: "unqualified-break-claim (say which surface: `consumer` or `library` — `mise \
                   run semver` decides the library half)"
                .to_owned(),
        });
    }

    // "none" is a valid explicit answer — a tracker-only or repo-config change
    // lands no commit at all, and demanding a type there would force a lie.
    let mut declared = compiled(r"(?i)major|minor|patch|no bump|none")
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
    // is a governed shell rule that cannot retire, so `V-SHELL-RULE-EDITED`
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
                line: line_of(BUMP_LABEL),
                rule: "commit-type-missing".to_owned(),
            });
        }
    } else if !declared.is_empty() && declared != expected {
        report.findings.push(Finding {
            line: line_of(BUMP_LABEL),
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
fn check_replay(block: &str, line_of: &dyn Fn(&str) -> usize, report: &mut Report) {
    if !compiled(GATE_INTRO).is_match(block) || !compiled(DENY_SEVERITY).is_match(block) {
        return;
    }
    if compiled(REPLAY_NAMED).is_match(block) && compiled(REPLAY_COUNT).is_match(block) {
        return;
    }
    report.findings.push(Finding {
        line: line_of(GATE_INTRO_LINE),
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
    check_claimed_blockers(payload, &claims, block_line, report);
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
/// `V-TASK-UNDEFINED` with `R-DEFINE-THE-TASK`. Re-deriving it here would be a
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
        .push(emit_keys("cites-blockers", &cited.join(" ")));
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
/// What opens a claim is [`BLOCKER_CLAIM`], which carries the corpus's three
/// spellings of one concept; naming the spelling here too would be a second
/// authority on it (CLOUD-1113).
///
/// **Claims, not mentions.** A well-formed §8 bullet also cross-references the
/// other relation directions, and flagging those would punish precision. So only
/// ids in the span after the first claim opener are claims, and the span ends at
/// a `blocks`/`relatedTo` token or the sentence's end. Widening WHICH spellings
/// open a claim leaves every one of those span rules untouched, which is what
/// keeps a §8 bullet that cross-references a sibling from becoming a claim.
fn check_blockers(
    payload: &Payload,
    block_lines: &[&str],
    line_of: &dyn Fn(&str) -> usize,
    report: &mut Report,
) {
    let label = compiled(BLOCKERS_LABEL);
    let Some(start) = first_line(&label, block_lines) else {
        // No §8 span at all, so no keys are emitted for it. An absent line is
        // "this run never got far enough to know", per set.
        report.emissions.push(emit_keys("cites-blockers", ""));
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
    let text = strip_mentions(&span.join("\n"));

    let claim = compiled(&format!(r"{BLOCKER_CLAIM}[\s\S]*"))
        .find(&text)
        .map(|m| m.as_str().to_owned())
        .unwrap_or_default();
    // A claim is one sentence: the §8 bullet legitimately carries trailing
    // cross-references that assert nothing about blocking.
    let claim = claim.split(". ").next().unwrap_or_default().to_owned();
    let claim = compiled(r"(?i)`?blocks`?[^A-Za-z][\s\S]*").replace(&claim, "");
    let claim = compiled(r"(?i)`?relatedTo`?[\s\S]*").replace(&claim, "");

    report
        .emissions
        .push(emit_keys("cites-blockers", &span.join("\n")));

    for cited in keys_in(&claim) {
        // THE SCAN STILL RUNS, THE CROSS-CHECK DOES NOT (CLOUD-679). Finding the
        // citation is what makes "the missing key is the SOLE reason" computable
        // at all: a payload with no key and nothing cited lost nothing and must
        // stay clean, because CLOUD-526 declares that a caller may project
        // everything but `.description` away.
        if !payload.relations_present {
            report.unjudgeable += 1;
            if report.unjudged_line == 0 {
                report.unjudged_line = line_of(BLOCKERS_LABEL);
            }
            continue;
        }
        if !payload.blocked_by.iter().any(|edge| edge == &cited) {
            report.findings.push(Finding {
                line: line_of(BLOCKERS_LABEL),
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
fn check_deferrals(payload: &Payload, report: &mut Report) {
    let plain = strip_mentions(&payload.description);
    let plain_lines: Vec<&str> = plain.lines().collect();
    let hit = compiled(&format!(r"({DEFER_VERB})[^.]{{0,40}}?{KEY}"));
    for (index, line) in plain_lines.iter().enumerate() {
        if !hit.is_match(line) {
            continue;
        }
        // The id must FOLLOW the verb, not merely share a line: "CLOUD-9 blocks
        // this, deferred to CLOUD-10" defers only CLOUD-10.
        let mut cited: Vec<String> = Vec::new();
        for span in hit.find_iter(line) {
            cited.extend(keys_in(span.as_str()));
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
#[must_use]
pub fn adjudicate(payload: &serde_json::Value, root: &Path) -> Option<(i32, String)> {
    let parsed = Payload::parse(payload).ok()?;
    let report = lint(&parsed, root).ok()?;
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
pub fn verdict_token(payload: &serde_json::Value, root: &Path) -> Option<&'static str> {
    match adjudicate(payload, root) {
        Some((0, _)) => Some(VERDICT_READY),
        Some((1, _)) => Some(VERDICT_UNREADY),
        _ => None,
    }
}
