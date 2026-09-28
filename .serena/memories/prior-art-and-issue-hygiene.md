# Mining prior art, and where the output goes

Read when: surveying another project's practice, adopting a tool or pattern from
outside, or writing a `CLOUD-*` issue that came out of such a survey.

## Mine it, don't mirror it

External projects are a source of **ideas, standards, architectures, rules,
axioms, formulas** — never of authority. "They do it" is not a reason. The
question is always: what problem does this solve, does _this_ repo have that
problem, and what is the version of the solution that fits our constraints?

The adoption test, in order:

1. **Name our failure.** Which observed problem here does it fix? No local
   failure, no adoption — not even a cheap one.
2. **Extract the principle, discard the packaging.** The value is usually a rule
   ("lock a binary artifact, vendor a source tree"), not the specific tool.
3. **Re-derive against our constraints.** Repo-agnostic core, gates as computable
   predicates, one authority per fact, output-is-a-pointer, no `docs/` tree. A
   practice that violates one of these is not adopted with an exception; it is
   re-solved.
4. **Ship it with its gate.** An adopted practice with no runnable check is prose.

The posture, in the maintainer's words: **proudly found elsewhere**. Building our own
is the choice that has to be justified. Adopting is not.

## How to survey "what is idiomatic" without anchoring

Measured on the 2026-09-27 lifecycle-scripting run (CLOUD-982). The first plan was
rejected twice before this one held:

1. It anchored on the one tool the requester had named.
2. It then swapped in the planner's own favourite tools, found by recall.

- **The corpus is chosen by computable criteria, never by name.**
  - Registry rankings: crates.io recent-downloads plus the category tops. For tools,
    GitHub topics plus dependents.
  - Then maintenance filters: pushed in the last 90 days, a release in the last 6
    months, at least 3 authors, CI present, MSRV set, current edition.
  - Stratify, and record the query so the corpus can be re-run.
- **Tally what emerges, not a checklist.** Collect raw facts (trees, manifests, CI
  `run:` lines) and group them afterwards. Report anything at 25% or more of a
  stratum. Call something _idiomatic_ only at 60% or more, and state the frequency
  and stratum.
- **Refute before ranking.** A separate pass re-clones a sample to check the
  citations, and hunts for counter-evidence. It found that 30/39 repos keeping
  scripts fell to 23/39 when you require two or more.
- **Reconcile with Linear before recommending.** The census's 2026-08-22 landing
  review had already rejected merge queues on values. The new survey ranked a merge
  queue fifth, and that would have silently contradicted the earlier verdict.
- **Folklore that did not survive:** "Rust projects don't use bash" (30/39 keep
  scripts, rust-lang leading), "xtask is idiomatic" (6/39), "CI is what you run
  locally" (2/39 have one command). The real idiom is _no logic in shell_, not
  _no shell_.

Where a survey's _reasoning_ lives: this file, or the memory for the subsystem it
touched. Not in the issue, not in the code, not in a commit message.

## The corpus a prose literal is measured over

No literal over prose ships until it is measured over a real corpus, counting
firings **and** true positives among them. One corpus that method needs does not
exist yet, and the gap is measured rather than argued: **session transcripts do
not accumulate on their own.** They are written inside the session's own ephemeral container and
destroyed with it. `/root/.claude/projects/` held exactly one `.jsonl` on
2026-08-11, and one again on 2026-08-17 — a different container six days later —
and both times it was the session doing the measuring. Every session starts at
N=1, its own, and ends at N=0.

That measurement stands. **The rule first written from it did not**, and the
correction is the useful part of this entry.

The rule said: a predicate over assistant prose may not derive its literals from
a mined session-transcript corpus, so an admissible literal must be _witnessed_
or measured over a durable artifact. It read as though the constraint were
physical. It was not — it was a policy choice about what may leave the container,
asserted inside an issue body, and the owner lifted it on 2026-08-17. Raw session
transcripts may be collected to a **private** durable store. The corpus is being
built rather than ruled out, and `mise run transcript-corpus-check` changes from
a monument to a progress reading: it reports whether the corpus has accumulated
yet.

Reading prose **in session** was never affected either way: `stop-posture-check`
reads the turn's final message and `finding-sink-check` reads the live transcript
at the Stop boundary. Neither needs another session's transcript to run.

### Two ways this got argued wrong, both worth keeping

The verdict that refused collection was reached by two moves that look like
reasoning and are not. Neither is specific to transcripts.

**Impossibility asserted from an enumeration.** The refusal ran: a derived
per-turn payload is either a phrase-hit vector (presupposes the phrase, so it
cannot discover one) or a token/n-gram inventory (reconstructs the prose), _and
there is no third shape_. There are third shapes. A hashed n-gram sketch
presupposes no phrase, since any candidate is queried against it afterwards — it
is answerable on invertibility instead, natural-language trigrams being an
enumerable space. Differentially private counts are answerable on utility, the
counts here being sparse enough that noise at any useful epsilon is the same
order as the signal. An argument that says "no other shape exists" collapses the
moment someone produces one; an argument that prices the shapes it found survives
a fourth being proposed. Write the second kind.

**A null result from a circular measurement.** The shipped literal set was run
over the durable artifacts, returned almost nothing, and that was read as
evidence against adopting a _discovery_ method. But the corpus was searched for
hand-authored strings, which can only match themselves — and hand-authoring the
strings is the defect the discovery method exists to fix. A method proposed to
replace enumeration cannot be evaluated by asking whether the enumeration already
covers the ground. The same shape appears as "no witnessed miss needs it": the
witnessed misses are exactly what the current matcher was able to surface.

The general form, since both instances cost a verdict: **an absence supports
"this sample cannot answer the question" far more often than "the question has no
answer"**, and the slide between them is tempting precisely because a null result
is cheap to obtain. Before writing "cannot", check whether the measurement's own
construction guaranteed the zero — if it did, the finding is about the
measurement.

One residue that is real either way: nothing re-measures a literal **already
shipped**, which is CLOUD-633.

### The durable artifacts, measured, and what they are good for

Measured 2026-08-17 (CLOUD-624). The shipped hedged-flag set plus two candidate
expansions, over every durable artifact this repo has:

| artifact              | volume | firings | true |
| --------------------- | ------ | ------- | ---- |
| 60 merged PR bodies   | 223 KB | 0       | 0    |
| 100 issue/PR comments | 262 KB | 0       | 0    |
| 400 commit messages   | 615 KB | 7       | 0    |

All seven are non-instances: three are a commit message naming a pattern it is
fixing, four are commits quoting the literals as data.

Read narrowly, that is a fact about **register**: this repo's PR bodies and
commit messages are terse, in the style its own issue hygiene prescribes, so the
phrasing that shows up in chat barely appears in them. It is a reason the corpus
this work needs is a **transcript** corpus, not a verdict about the method — see
the two wrong moves above for how it was briefly read as one.

Two things that follow and are worth keeping:

- Zero firings over a corpus containing almost none of the phrasing is an
  **uninformative sample**, never a clean bill. Do not cite it as evidence that a
  literal expansion is safe.
- The durable artifacts are still the right corpus for predicates over **their
  own** register — `deferral-check` was measured over 60 PR bodies precisely
  because a PR body is what it reads. Match the corpus to the artifact the
  predicate consumes, rather than to whichever corpus is easiest to fetch.

## The attribution rule

Once adopted, the practice is ours and is justified on our terms. **Do not leave
third-party names, project names, or "as X does" scattered in issues, code
comments, commit messages, or PR bodies.** Comments state the rule and the
evidence that produced it, in this repo's terms:

> **Bad** — `# bats via submodule, the same shape jdx's repos use`
>
> **Good** — `# A tool pin would be the obvious choice and is the wrong one: the`
> `# published package is a source archive, and those are not byte-stable, so`
> `# mise lock records a checksum a later download legitimately fails (CI hit`
> `# exactly that). Lock a binary artifact, vendor a source tree.`

The good version survives the third party disappearing, changing their mind, or
being wrong. The bad version is an appeal to authority that a reader cannot
evaluate. Exception: a URL identifying a _tool we depend on_ (`mise.jdx.dev`, an
`amends` package URL) is a coordinate, not an appeal — those stay.

## Issue hygiene

A `CLOUD-*` issue states the point of the issue and nothing else. The reader is
whoever picks it up cold, and they need the problem, the mechanism, what blocks
it, and the predicates.

**Belongs in an issue:** the problem in this repo's terms; the mechanism as
commands and gates; concrete blockers; the Ready predicate; the Done predicate;
decisions the work forces and who must make them.

**Never belongs in an issue:**

- Process narrative — "found while surveying", "deferred deliberately",
  "worth doing rather than just tidy", "resolve before starting".
- Where the idea came from, or who does it elsewhere.
- Agent-directed instructions or meta-commentary. Agent instructions go in
  AGENTS.md (must bind every turn) or a memory (read on trigger). An issue is
  read by whoever works the issue, not by every agent in every session.
- Session artifacts: PR numbers as provenance, what a previous branch did,
  apologies, hedging, running commentary on the writing.

Same discipline for PR bodies: what changed, why it mattered _here_, what a
reviewer should look at. Not how the work unfolded.

### The tracker eats markdown tables on save

A table in an issue body does not round-trip. `save_issue` normalises it and
strips the leading characters of every cell — measured on CLOUD-75, where
`CLOUD-240` became `OUD-240`, `203` became `3`, `212` became `2`, `257` became
`7`, a lone `2` emptied, and the `| --- |` separator was rewritten in the same
pass. It is silent: no error, exit 0, visible only by reading the save response
back.

It lands worst where it is least visible. A Ready block is the one artifact a
successor trusts without re-deriving, and that run published four wrong latency
measurements into one. **Use a list** — lists round-trip byte-exact.

The hazard is the tracker's, not markdown's: a table in a memory or in
`AGENTS.md` is a file on disk and is safe (this page carries several).

### The same save reflows paragraphs, so emphasis must not cross a line break

A hard-wrapped paragraph is rejoined into one line on save. Where an emphasis run
opened on one wrapped line and closed on the next, the delimiters land adjacent to
the join and are re-emitted — leaving a literal `****` in the rendered body.
Measured on CLOUD-807, 2026-08-20: four sites in one filing, e.g. a bold run
around a code span became `**no** ` + a code span + `**, no****` / `****per-suite
scope**`. Silent, exit 0, and visible only by reading the save response back —
the same failure mode as the table above, and `ready-lint` cannot see it either,
because the block is still structurally valid.

Two rules, both cheap: **keep an emphasis run on one line**, and **keep code spans
outside it**. A bold run that wraps a code span gets split even on one line —
`**a `x` b**` comes back as `**a** `x` **b**`, which renders correctly but is not
what was written. Repairing it costs a fresh `issue-read` receipt per attempt,
since the row's revision moves on every save.

## Sorting rule

Five destinations, no overlap:

| Knowledge                                    | Goes to              |
| -------------------------------------------- | -------------------- |
| Must bind every turn, every agent            | AGENTS.md            |
| Needed only at a trigger, by whoever hits it | a Serena memory      |
| A unit of work with Ready/Done predicates    | a `CLOUD-*` issue    |
| Derived from code, for a consumer to read    | generated at publish |
| What this reader needs, in this moment only  | the chat message     |

If a paragraph does not answer "who reads this, and when", it has no destination
and should not be written.

**Chat is the only destination that stores nothing.** It dies with the session,
so nothing durable may terminate there. This rule governed written artifacts for
a long time while chat was treated as a free channel, and the result was that
every finding got written twice — once to its durable home, once as a chat
paragraph restating it. The second copy has no reader and costs the user
attention on every message.

The tell is hedged flag-framing: "one thing I'd flag rather than leave implied",
"worth noting", "the honest read is". Each is self-indicting. If the content is a
finding, its home is an issue or a memory and the sentence is a duplicate; if it
has no home, it should not exist. A durable record and a chat summary of that
record are not two audiences — they are one fact and one echo.

AGENTS.md carries the per-sentence test, since it must bind every turn. What
belongs here is the reason it kept failing: the previous version enumerated banned
constructions instead of stating the predicate, so each new phrasing escaped.
**An enumeration cannot close an open class** — the same defect that let a `tail`
rule scoped to two tasks miss every other task (`mem:toolchain-and-hooks`). When a
behavioural rule is written, state the predicate; a list of instances is a
worked example, never the rule.

It recurred, which is the part worth recording. AGENTS.md carried this insight in
its output-posture paragraph and, three paragraphs earlier, a closed list of "four
disguises a punt wears". A fifth shape — offering an action the same file already
pre-authorizes — was not among the four, so the list read as inapplicable and the
punt went through. **A fix applied to one paragraph is not applied to the
document**: when a predicate replaces a list, sweep every list in the file stating
the same kind of rule, or the next instance escapes through the one you left.

Two more from that incident. **An exception must say what it obliges instead** —
"out of scope" licensed not fixing and terminated there, so a real defect was
reported into chat, which stores nothing; an exception that ends the action
without naming a destination routes the finding to the only channel left. And
**the same substitution recurs one layer up**: `gh-guard` correctly refused a
hand-typed `/fast-forward` and named `mise run land`, then was satisfied by `mise
run land` wrapped in a bespoke retry loop invented on the spot. Re-deciding how
the workflow is _shaped_ crosses no tool boundary, so no guard can see it.

No gate is available for this one: a `PreToolUse` hook sees tool calls, not
assistant prose, and no exit code attaches to a sentence. Every other guard here
works because what it judges crosses a tool boundary. Recorded rather than
implied, so nobody re-derives it: CLOUD-200.

### A sixth shape, measured 2026-08-21: the blocker asserted but never tested

AGENTS.md's predicate says "a block reported as a decision (a block is a bug)".
That wording assumes the block is **real** — the reader's remedy is to go fix it.
The shape that escaped is one layer earlier: a blocker **asserted without being
tested**, so the deferral reads as principled and there is nothing for anyone to
check. Two in one session, both wrong, both one command from being settled:

| asserted blocker                                                                 | why it was false                                                                                                  | cost of testing it                   |
| -------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------- | ------------------------------------ |
| "measuring whether CodeRabbit reviews drafts needs a fresh draft PR" (CLOUD-847) | three PRs that session were opened as drafts and readied later; the experiment was already in their event history | one `list_workflow_runs` call        |
| "the `land.bats` hang is a race" (CLOUD-848)                                     | inferred from a single green suite run; never reproduced                                                          | a bounded loop, free local execution |

**A real block and an assumed one are indistinguishable in prose, and that is the
defect.** Both come out as one confident sentence, so the punt predicate cannot
discriminate them by reading. What discriminates is whether a command was run. So
the obligation attaches to the assertion rather than to the deferral: **naming a
blocker obliges the check that establishes it**, in the same turn, or the blocker
is a guess and must be written as one.

This is the same failure as the "worked survey" entries above, seen from the other
end. Those record the adoption test being run and throwing candidates out; this
records a candidate explanation being adopted because nobody ran the test on it.
The `#[expect]` discipline in `mem:core`'s spawn census is the shape that works:
an annotation that goes stale is red in both directions. A prose blocker goes
stale silently.

No gate reaches this either, for the reason above — the assertion is prose. But
the tell is cheap and specific: a sentence containing "needs", "requires",
"cannot be done without" or "is a race" **about this session's own next action**,
with no tool call behind it in the same turn.

**Generated output is not written by anyone and is not committed.** CI derives it
from the code and publishes it; nothing lands in the tree. Two things follow.
`no-docs-tree` is not an obstacle to documentation — it fails on _tracked_
`docs/` paths, so generated output never trips it. And a generated artifact needs
no drift gate: one produced from the binary at publish time is current by
construction, and "regenerate + `git diff --exit-code`" only exists to protect a
_committed_ copy from going stale. Committing generated output creates the
problem the drift gate then solves. The exception is an artifact a consumer must
resolve independently — a published JSON schema — which is committed _and_ gated,
because the copy they fetch has to match the code.

## Portability constrains where instructions live

Instructions live in vendor-neutral files: `AGENTS.md` (with `CLAUDE.md` a
symlink to it) and the checked-in Serena memories, all plain markdown any agent
can read. Do **not** move instructions into a vendor-specific mechanism —
`.claude/rules/`, or any other single-tool rule format — even when it offers a
capability the neutral files lack, such as path-scoped loading. Buying a context
saving with a lock-in is the wrong trade here: the repo is read by more than one
agent, and an instruction only one of them can see is an instruction the others
will violate.

## Which survey tools actually reach the evidence (CLOUD-381)

Measured on the rules-engine defaults census. Both findings cost a wasted call
to discover, and neither is inferable from the tool descriptions.

- **Scholar Gateway is Wiley-only — near-useless for software engineering.**
  Two on-topic articles across 24 passages over two queries; the rest was
  intrusion detection, genome browsers, and Cray provisioning, matched on the
  words "rule set". **Consensus is the one to reach for** (Semantic Scholar +
  Scopus + ArXiv): the same two themes returned Vassallo, Tómasdóttir, Hu,
  Liargkovas and Ueda on the first try. Consensus rate-limits at ~2 concurrent
  calls — batch two, not three.
- **GitHub reaction counts are out of reach for outside repos.** API access is
  scoped to `button-inc/batten`, and `add_repo` on a survey target is declined
  by the permission classifier, so `search_issues` sorted by reactions — the
  obvious reception signal — is unavailable for every repo being surveyed. A
  shallow `git clone` of the target still works, so Track A (read the source)
  is unaffected; only the issue-reaction channel is closed. Substitute
  countable signals that are reachable: HN item points/comments, named figures
  in write-ups, and issue/PR numbers via plain fetch.

The transferable rule: **a survey's evidence plan must name signals the
environment can actually produce.** An unreachable signal silently becomes an
unattested claim, which is exactly what the grading exists to catch.

## Worked surveys — read one before running a survey of the same shape

Each is the reference instance of a judgement, kept for its reasoning rather
than its verdict:

- `mem:research/worked-surveys` — structural matchers (CLOUD-310: run the
  candidate over the real tree and count both directions), the static-analysis
  and agent-hook field (CLOUD-311/312/314: license per layer and per file, bus
  factor from the log, canaries), token-normalized phrase matching (CLOUD-624:
  rejected for undecidability, with a re-open predicate), and a logic engine as
  a substrate (CLOUD-623: displacement vs capability, and classifying by input
  shape before dividing).
- `mem:research/latent-comment-gate` — the latent-comment-gate bibliography
  (CLOUD-1089: the nearest prior art is a shipped linter; measure your own corpus
  before briefing), and PALM (a stable pointer to a claim that moved; say what a
  true positive is before shipping a count).
