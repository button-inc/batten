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

/// The §8 clause label.
const BLOCKERS_LABEL: &str = r"(?i)Blockers \((§|clause )8\)";

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
fn emit_keys(label: &str, text: &str) -> String {
    format!("{label} {}", keys_in(text).join(" "))
        .trim_end()
        .to_owned()
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

    check_bump(root, &block_lines, &line_of, &mut report)?;
    check_replay(&block, &line_of, &mut report);
    check_blockers(payload, &block_lines, &line_of, &mut report);
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
    let emitted = match declared.as_str() {
        "" => "-",
        "no bump" => "none",
        other => other,
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

/// §8: blockers linked, not assumed.
///
/// The highest-value rule here, and the only one prose cannot fake. A block
/// CLAIMING blockedBy CLOUD-N while carrying no such relation is asserting a
/// dependency the board does not know about — exactly the failure the clause
/// names.
///
/// **Claims, not mentions.** A well-formed §8 bullet also cross-references the
/// other relation directions, and flagging those would punish precision. So only
/// ids in the span after the first `blockedBy` token are claims, and the span
/// ends at a `blocks`/`relatedTo` token or the sentence's end.
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

    let claim = compiled(r"(?i)blockedBy[\s\S]*")
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
