# Worked surveys: the latent-comment-gate bibliography, and PALM

Two prior-art surveys and what transferred from each. The method is
`mem:prior-art-and-issue-hygiene`; the structural-matcher, static-analysis,
phrase-matching and logic-engine surveys are `mem:research/worked-surveys`.

## A worked survey: the latent-comment-gate bibliography and the linters that already shipped it (CLOUD-1089)

Two passes over one design: an audit of the 25 citations an issue was filed with,
and a broadening pass over deployed tooling. Evidence and per-candidate verdicts
are in the Batten project document; only what transfers is here. The headline is
the one this file keeps re-learning from a new direction — **the closest prior art
to a policy predicate is usually a shipped linter, not a paper** — and the second
pass found the reference implementation of the exact rule under design, with its
scars, in about the time the first pass spent checking DOIs.

**Seed a citation audit with cases you already know are wrong, and say so in the
brief.** Two were planted here: an issue calling a paper's "comment entailment
from code" by an invented name, and a method name used as if it were a paper
title. The auditor reproduced both independently and was told to declare it if it
had not. That declaration is what makes the other 23 verdicts worth reading —
without it, a clean report is indistinguishable from an insensitive instrument,
which is the standing rule about absences applied to a literature pass.

**The Takes that were wrong were the OBVIOUS readings of their titles, and that
is the tell.** Two of 25 stated the opposite of their source. A co-evolution study
was cited for "documentation lags code"; its significant finding is that comments
and code grow at about the same rate. A comment-update study was cited for
"inconsistent updates cause bugs"; its finding is that deviation from a file's
_own historical practice_ predicts defects. Both wrong Takes are what you would
guess from the title alone, and both were sitting under correct DOIs. **A
bibliography assembled by paraphrasing titles resolves perfectly and says false
things** — the anchor being live is not evidence about the claim, which is
CLOUD-794's mode 2 in a corpus nobody thought of as citations.

**A bibliography that follows one field's citation graph misses the adjacent
field entirely, and the adjacent field is usually nearer.** 25 citations of
comment-quality research, and the deterministic comment-to-specification line
(@tComment, Toradocu, Jdoctor, C2S) was absent — the one body of work that
actually translates comments into checkable specifications, and the nearest thing
to the "conservative deterministic entailment" the design wanted. One of them
shares an author with a paper the issue _did_ cite. Citation-following is
depth-first and the useful neighbours are usually one hop sideways; ask what
field would have had to solve this for a different reason.

### What the shipped linters had that the papers did not

**One tool was the reference implementation, and its exclusions were all scars.**
Clippy's `duplicated_attributes` decides "the same identifier twice in one
container" — the design's predicate, one domain over — in about 75 lines: a fresh
map per syntactic item, a canonical key, both spans reported, and **no
machine-applicable fix**. Three exclusions, each a paid-for lesson: a duplicate
produced by macro expansion is not the author's duplicate; the **prose-bearing key
is exempt**, because two annotations legitimately carrying the same human
rationale are not a duplicate; and a class it cannot decide is **declined by
name** in a standing comment rather than guessed at. Its issue #12537 is the
fourth: a canonical key that flattened boolean structure collided two positions
that were _not interchangeable_, and the fix was to stop feeding that evidence in
at all rather than to write a cleverer key.

**"We need a parser" was two claims with different prices, and the design had
bought the expensive one for both.** Measured across five tools: confirming a
token is _in a comment_ rather than in a string is a lexer question and every one
of them decides it at token level; what needs a parser is only the **container**,
and only if the container is "everything attached to one declaration" rather than
"one comment". The design had not chosen between those containers, and the choice
is what decides whether the parser is needed. **Split a stated prerequisite into
the questions it actually contains before accepting a blocker built on it** — the
edge survived here, narrowed from "comment recognition" to "scope resolution",
which is a different and smaller thing to wait for.

**Compare before resolving.** Measured on Ruff: an identifier it has been
explicitly configured _not_ to resolve still reports as duplicated. Duplication is
decidable from the token alone, so folding it inside the resolve step loses the
most likely real case — a typo repeated by copy-paste, which is how duplicates are
born. Six tools gave six different answers to "what happens when the identifier
does not resolve", and the worst (mypy's) makes an unknown id byte-indistinguishable
from a stale one, so the remedy the tool prints is the opposite of the one the
author needs. **When one predicate can be decided on weaker evidence than its
neighbours, decide it there, and pin the decoupling with a test whose subject is
unresolvable.**

**Two shipped auto-fixes destroy author prose, and both are years old and known.**
Ruff still deletes a trailing explanation after a suppression code because a
lexical delimiter, not a semantic one, was what shipped; ESLint's unused-directive
fix, composed with another fixer in the same pass, removes a directive that the
same run then makes necessary — reproduced on current versions, closed as
intended. The transferable rule: **a redundancy verdict is only sound over a
frozen object.** Compute it against the tree as committed, and never run its fix
in the same pass as another mutation.

### Two defects of ours the survey found, which is the usual yield

Both are filed. `no-tool-substitution` resolves a bare relative path against the
repository root instead of the call's working directory, so the same file gets
opposite verdicts by relative and absolute spelling — and its verdict prose
asserts the path is tracked, which nothing checks. **A verdict token exists so a
reader can look the class up; one whose prose states an unchecked fact about its
subject is believed, which is worse than a class with no name.**

The second is the one worth carrying. `ready-cites-check` had CLOUD-920's
three-valued answer — resolves, refused, prospective — on its **path** arm only,
while CLOUD-920's own measurement had been taken entirely on the **test** arm:
three refusals, every one a §7 naming the suite its row existed to write. So the
fix reached the arm the evidence did not come from, and the arm it did come from
kept the behaviour the evidence condemned. **The cause was that the decision was
inline in whichever loop needed it first**, so extending it meant copying the
grammar and the cheap move was not to. Both `#MUTANT` rows were inline too, and a
mutation over an inline copy can only ever kill the arm it was written against —
so the census reported coverage over an unguarded arm. Repaired here by making the
decision one function and repointing the mutations at it. **When a fix lands in
one arm of a symmetric gate, check the mutation's reach before believing the
census: a mutation that names a line can only prove the line it names.**

### Measure your own corpus before you brief a survey — the brief is the deliverable

This is the entry to read if only one is read, and it is a correction of the entry
that stood here first. That version was titled "the survey falsified the programme's
own objective" and it was wrong in the way that matters most: **the survey refuted a
goal nobody held.**

The programme's objective is _conditional semantic delta_ — retain only canonical
non-code facts the reader needs, once per applicable context. I briefed six families
as "minimise inline comment tokens consumed as LLM context," which is a raw-length
rule, and the owning issue says in as many words: do not collapse this into a generic
`no comments` or raw-length rule. Two families then refuted the collapsed version and
I recorded that as a finding about the programme.

**Read against the actual objective, both results invert.** The ablation studies
removed comments _wholesale_, which is a raw-length intervention that says nothing
about delta; and in the one place removal helped, the removed material was **synthetic
padding** — prose with zero semantic delta, i.e. evidence _for_ the delta framing.
curl's ~100% SPDX tag coverage with **99.8% prose retention** is not evidence against
a canonical id; it is the measured demonstration that **an id pays only when the prose
it replaces is actually deleted**, which is the argument _for_ a compact-replacement
obligation. The saving was a property of the deletion, and the design that claimed it
for the identifier was the thing at fault.

The one claim that survives intact is the layer error, and it is now the _reason_ for
the framing rather than an objection to it: **an objective phrased over a downstream
consumer's token budget is not a property of the tree, so it cannot be gated.** Delta
is a tree property. Budget is not. That is why the objective is stated as delta.

**What the corpus said, and it should have been measured first** (this repository,
2026-08-28, 24,189 comment blocks; 17,537 of them substantive):

- **54% of repository bytes are comment or prose**, and only **4.1% of that mass sits
  in a grammar anything can parse** — `#MISE description=`, `#MUTANT`, `// carried:`,
  `# METADATA`, `#[expect(reason=)]`. There was already a comment grammar here. It was
  simply tiny, and extending it beats inventing one.
- Recurring fact types: rejected-alternative 25.9%, provenance 24.8%, constraint
  24.4%, owner 8.5%, hazard 7.0%, cross-reference 5.1%, measurement 3.9%, banner 2.8%,
  falsified-by 2.3%, authority 1.4%.
- **Provenance is an attachment to a fact, not the payload.** Of provenance-bearing
  blocks, 52.7% also match a checkable fact type by regex; hand-inspecting a random
  sample of 12 from the rest found only 2–3 genuinely retirable. Prose that merely
  narrates history and carries nothing else is **~2–3% of blocks**, not the 35% the
  line-level count implied. So the density win is **canonicalisation, not deletion**,
  and a design that strips the issue key and the date deletes the evidence behind the
  fact — which is this repository's core discipline.

**The generalisable rules, and the first is the expensive one:**

1. **A survey inherits its brief's framing and cannot escape it.** Six agents ran
   competently against the wrong question and returned a confident wrong answer.
   Nobody checks the objective; that is the parent's job, before spending anything.
2. **Measure your own corpus first.** It is local, it is free, and it is the only
   instrument that answers "what would the mechanism have to express here." It also
   produced a fact type — `falsified-by`, a "Fails by:" recipe, ~406 occurrences —
   that no amount of literature would have suggested, because it is our own
   discipline written in prose.
3. **A line-level count of a paragraph-level phenomenon is a different measurement,
   not a rougher one.** The same corpus read by line said 9.7% history and read by
   block said 35%; hand-sampling said ~3%. Each step changed the conclusion.
4. **When an objective looks falsified, check what actually depended on it.** Here
   nothing did — the narrow rule was already a pure redundancy predicate over
   identifier identity — which is the tell that the objective was never the one being
   tested.

### An identity and a clause are different objects — check which one your rule is about

This entry replaces one that said the opposite, and the way it was wrong is the
transferable part. It read: JML conjoins repeated `requires`, ACSL does the same,
Doxygen joins adjacent `\invariant`, SARIF permits one rule id twice — _"four
independent designs, one answer: a repeated annotation composes and is never an
error"_ — and concluded that our duplicate-refusal inverts the unanimous convention
of its field and therefore needs an unusually well-defended premise.

**The four were answering a different question.** A JML `requires` is a **clause**,
and a conjunction of clauses is meaningful, so repetition composes. A Sphinx label,
a Doxygen `\anchor`, an SPDX id, a `@latent` id are **identities in a namespace**, and
two definitions of one identity are a contradiction. Once the objects are separated
the apparent unanimity dissolves, and so does the need to apologise for the rule.
The Doxygen citation was also conflating both halves of one tool: a repeated `\ref`
composes, a repeated `\anchor`/`\section` **definition** warns.

Measured across the redone survey, shipped grammars answer the identity question three
ways, and the distribution is the finding:

- **Diagnose it** — Sphinx (`duplicate label X, other instance in …`, exit 1 under
  `-W`; `-n` is not required, it governs domain cross-references), Doxygen `\anchor`.
- **Silently shadow it, first wins** — rustdoc link labels, JEP 413 `{@snippet}`
  region ids, icontract. **This is the majority**, and it is the worst of the three:
  a duplicate silently changes which target a reader resolves to, with no diagnostic
  anywhere.
- **Compose it** — the clause grammars, which are not answering this question.

So the argument for refusing a duplicate identity is not "we disagree with the field"
but **"the common behaviour is a hazard class"** — and that is a much stronger thing
to put in a verdict registry's `class` prose, because it is checkable and it tells a
reader what goes wrong rather than asking them to accept a preference.

Two more from the same family, both still standing: **the decidable predicates over a
prose annotation are exactly the structural ones** — presence, absence, position,
adjacency, uniqueness, well-formedness, registry membership. Truth is not on the list,
and the redone survey put a number on the ceiling: across every shipped mechanism
measured, the most any of them forces is **one token** (Go `revive`'s `exported` rule,
which requires the comment's first word to be the symbol name and reads nothing after
it). A `# Errors` section that is present but empty passes clippy; `/// .` satisfies
`missing_docs`; `"""."""` satisfies pydocstyle and interrogate. And **a prose-bearing
key must be exempt from any duplicate predicate**: clippy exempts `sym::reason` for
exactly this, and without that exemption a dedup fix deletes the only copy of
knowledge nothing else holds.

### A proxy that is wrong in both directions is not a lossy proxy

A unit correction, not a refutation of anything — it says which unit to count, and
the programme's own audit row already counts that unit. Every shipped
line counter reports `comments = 3` for three lines of bare `//` (3 real tokens)
and `comments = 3` for three lines of dense prose (164 real tokens) — a 54.7x
spread on the quantity actually being conserved — while reporting `comments = 0`
for four trailing comments carrying 49 tokens. **No calibration constant fixes
that, because the spread is a property of the content rather than of the
language.** Before adopting a metric as a stand-in for the one you want, measure
the two extremes; if the error is unbounded in both directions the metric is not
approximating your quantity at all, and a threshold set on it is a threshold set
on noise. The route that works is to count the **span**, not the line — a comment
is a node with byte offsets, and every failure in that family disappears the moment
the unit cannot be shared with code.

### Method notes, cheap and repeatable

- **A brief that omits half the object gets half an audit.** The citation brief
  handed over the citation strings without the "Take" each was paired with, so
  the auditor could only report what each paper _licenses_ and flagged the gap
  rather than guessing. That was the right report and a defective brief; the two
  reversals above were then found by hand against it. Hand over the claim, not
  just the reference.
- **Consensus is installed at the org level and can be off for a session.** When
  it is, a literature pass runs on plain search and is correspondingly weaker at
  exactly the "what else exists" question. Check before planning around it.
- **The tracker's `save_issue` was refused under the connector's UUID-form
  registration and allowed under its readable alias, in one session, minutes
  apart.** The injected config showed `always_ask` on that one tool for the UUID
  entry. `mem:connector-allowlist-recovery` records the flip as bidirectional and
  unexplained; this adds that the _permission policy_, not just the tool name,
  differs between the two registrations — so re-resolving the tool name after a
  reconnect is not merely cosmetic, it can be the difference between a write
  landing and not.

## PALM (ASE 2025), and the citation defect the survey found on the way

Surveyed 2026-08-20 from a preprint on LLM-generated Rust unit tests, prompted
under compiler feedback against MIR-derived path constraints. Four threads; three
corroborate decisions already made here and **nothing was adopted from them**. The
fourth found a live defect, and the useful part of this entry is which candidates
the adoption test threw out.

**What was load-bearing in the paper, and it is house-style §5 from outside.** The
model is bounded by a computable artifact and adjudicated by a non-model oracle —
rustc's exit code, then coverage instrumentation — looping until the oracle
passes. Where it has no oracle, whether an assertion _means_ anything, it makes no
claim at all, and its own threats-to-validity concede bug detection was out of
scope. **The paper's weakest claim sits exactly where its oracle stops**, which is
the transferable shape: an agent loop is worth what its non-model oracle is worth.

**Corroborated, not adopted.** 72.30% average coverage against 70.94% for
human-written tests, with 80 generated tests merged into open-source crates on
that basis. That is this repo's threat model with numbers in it: coverage parity
is reachable by a generator optimising compilation and coverage while asserting
nothing about behaviour. It argues for keeping `[tasks.coverage]` a report and
never a gate (CLOUD-111), and it is evidence on CLOUD-357 (`assertions-not-gutted`
counts tokens) and CLOUD-480. The one gap nobody owned — CLOUD-418 excluded
`crates/` from mutation proof — is now CLOUD-810.

**Also corroborated: an acceptance count taken once and never re-measured.** The
paper never checks whether the 80 merged tests still exist or still pass. This
repo already splits merged from released (`landed-check`, `done-check`,
CLOUD-192); the residue — nothing re-measures a claim after it lands — is
CLOUD-633's shape.

**Declined outright, and the reason is scope rather than merit.** The paper put 91
machine-generated PRs into repos it does not own and says nothing about disclosing
that; the precedent for how that ends is the UMN hypocrite-commits withdrawal,
where the contributions were mass-reverted and the org banned, and rust-lang
adopted an LLM policy on 2026-08-05 requiring disclosure and requiring tests.
`attribution.rs` already models the two public surfaces as data. An
_upstream-contribution_ posture — rules for contributing into a repo you do not
own — is outside the scope reminder. Recorded so the next survey does not
re-derive it.

### The thread that found something, and it was not the thread it looked like

The URL handed over was `arxiv.org/html/2506.09002v1`. v1 is superseded: the
title changed, and the headline moved from 75.77% line coverage to 72.30%, with
nothing at the v1 URL saying so. A stable pointer to a claim that moved — which
generalises to **a coordinate into an authority the citer cannot see**, and
`rules-drift` had already settled the shape for those: a claim that is PRESENT AND
WRONG fails; an absent one stays free. Only the scope stopped at the repo boundary.

Measured at `4183bc4`: 1,106 `§N` references in tracked files, pointing at **four**
different things — 83 `house-style §N`, 49 `CLOUD-<n> §N` (20 distinct pairs, 17
issues), 18 DoR/DoD clause refs qualified only by wording, 2 naming the attribution
decision record. `ready-lint` already pays for that overload twice, anchoring on a
label+tag pair because "the §N namespace is overloaded".

CLOUD-420 was cited three times at a `§4` it does not have; the content meant is
under its §3. CLOUD-809 is the gate, `mise-tasks/spec-ref-check.sh`.

Note the shape of that sentence: it names the key and the clause **apart**,
because the gate cannot tell a citation from a description of one, and prose that
documents a bad citation by reproducing it becomes an unfixable finding. The gate
excludes only its own file and suite; everything else — this memory included —
says it the long way.

### Two candidates the adoption test threw out, which is why this entry exists

- **A `house-style §N` existence predicate.** All 83 resolve. The issue first cited
  CLOUD-244 and CLOUD-368 as instances and **neither is one**: CLOUD-244 is §2
  disagreeing with the landed `SURFACE` (§2 exists, it said something wrong),
  CLOUD-368 is §10 contradicting §0.3 (both exist). Content drift, not an absent
  anchor. Citing them was CLOUD-794's mode 2 — _the anchor resolves but the fact
  lives elsewhere_ — committed inside the issue filed to fix mode 2. Rule 1 holds:
  no local failure, no adoption, **not even a cheap one**, and cheap was exactly
  the argument that nearly carried it.
- **A bare-`§N` ratchet**, the count non-increasing against `origin/main`. 1,020
  name no target, but most are locally unambiguous, so the number is not a defect
  count. Ratcheting it is `assertions-not-gutted` counting `assert` tokens — the
  very anti-pattern the survey had just finished writing up. **A survey can import
  the flaw it came to name**; the tell was that the metric was easy to compute and
  nobody had said what a true positive looked like.

The general form, since both rejections share it: **before shipping a count, say
what a true positive is.** Neither candidate could, and the one predicate that
survived names its own witness.
