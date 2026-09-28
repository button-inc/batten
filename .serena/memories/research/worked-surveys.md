# Worked surveys: structural matchers, static analysis, phrase matching, logic engines

Four prior-art surveys and the transferable judgement each produced. The method
they instantiate — mine, don't mirror; re-derive against our constraints; where
the output goes — is `mem:prior-art-and-issue-hygiene`. The latent-comment-gate
bibliography and PALM are `mem:research/latent-comment-gate`.

## A worked survey: the structural-matcher field (CLOUD-310)

The reference instance of step 3, "re-derive against our constraints". The tool
was excellent and the verdict was still mostly reject, because the deciding
facts were properties of _this_ tree and none of them appear in anyone's
documentation:

- **All 46 `mise-tasks/*` are extensionless.** Language dispatch by file
  extension therefore sees none of them, the directory walk reports
  `scannedFileCount=0`, and the process exits `0`. A gate over this repo's own
  gates would have been a permanent silent green — the exact false green the
  engine exists to kill, arriving as an adoption.
- **A grammar that _almost_ fits fails silently.** `.bats` is not bash. The
  parse dropped ~11% of `run` invocations across the suite while emitting zero
  error nodes, and it erred in both directions at once.

The transferable rule: **run the candidate over the real tree and count, in both
directions, before writing the verdict.** A tool evaluated on its own examples
evaluates its examples. Two numbers settle an adoption argument that prose
cannot — how many of the incumbent's findings it eliminates, and how many real
ones it loses.

Second finding, and the one that survives the tool being rejected: of a literal
rule's findings on this tree, the false positives were overwhelmingly
**whole-line comments** — 27 of 40 for one gate, 8 of 40 for another, closing
the second gate exactly. The expensive capability, knowing a string from a
`case` pattern, bought only the remaining 13. When a matcher upgrade is
proposed, price the cheap discriminator first; it usually carries most of the
measured gap.

**A compile-time rule compiler does not remove the interpreter — it adds a
second one.** A candidate whose selling point was "rules compiled into the
binary, not interpreted" shipped both: the same rule grammar existed twice, once
as macro-expanded token generation and once as a 729-line runtime evaluator,
hand-synced, and under two different licenses. The reason is structural rather
than sloppy — a compile-time expansion cannot read a rule a consumer supplies at
run time, so the moment user-supplied rules are wanted the interpreter comes
back, and here it came back as a separate program on the other side of a license
boundary. Price that duplicate whenever a candidate offers the compiled form as
the cheap one: it is the cost the design hides, and it is where the two halves
drift.

Where the residue goes: an approximation reported as coverage is worse than the
literal it replaced, so the change that lands the cheap half must _name_ the
lines it still cannot reach and file them with a re-open predicate. CLOUD-310's
is stated as one — the upstream crate declares a stable API **and** its MSRV is
at or below our pin. "Revisit later" is not a predicate and reopens nothing.

## A worked survey: the static-analysis and agent-hook field (CLOUD-311/312/314)

Kept because the survey's _reasoning_ has no other home, and because four of its
five candidates were **rejected** — the rejections are what future surveys need,
since each names a mechanism this repo already shipped. Evidence and sources live
in the project doc; only the transferable judgement is here.

**Separate a tool's engine from its rules before asking whether to adopt it.**
The engines surveyed (Semgrep, and the Opengrep fork) are LGPL-2.1 — dependable
as a subprocess, since nothing links. The maintained rule corpus is not: it
permits "internal business purposes" only and forbids making the rules available
as a service, which excludes shipping them with anything open-sourceable. The
agent plugin has _no license at all_, which grants nothing and makes it
readable-but-not-vendorable. One product, three licenses, three different
answers. **Ask the question per layer, never per vendor** — the licensing FAQ
page said "LGPL-2.1" and would have been read as clearance for all three.

**And per FILE, once copying is on the table.** The rule above asks per layer
because a product's layers can carry different licenses; this asks one level
finer, because a single crate's _files_ can too. A candidate's library crate
declared `MPL-2.0` in its manifest and three of its ten sources carried no
per-file notice at all — including the largest, which was the file worth copying
— under a repository whose only license text was AGPL. What makes it worth
stating separately is which disposition it reaches: a **dependency** is governed
by the published package metadata and is untouched by this, so the gap bites
only where the plan is to copy files out. A manifest field is a claim about the
crate; a per-file notice is the claim a copied file carries with it, and only
the second travels.

**A survey's most useful output can be an argument for a rule we already have.**
That plugin's fleet-rollout documentation ships managed settings with
`autoUpdate` against a git repo — no version pin, no checksum, no attestation —
deployed so users cannot override them, executing a stripped 16 MB binary on
every agent tool call. That is `no-source-built-tool` and the locked-url +
per-platform-checksum discipline argued from the opposite direction by someone
with every incentive to find a cheaper way. Record that; it is worth more than
another adoption.

**"They have a knob we lack" is usually a channel we already factor.** Their
four-mode finding vocabulary looked like a rank we were missing; the fourth mode
turned out to describe _where a finding is displayed_, which our report level and
exit contract already separate. But their _precedence_ rule — highest mode wins
when a rule appears in several policies — is max-severity resolution, i.e.
independent confirmation that raise-only is the stable resolution for layered
policy. **A rejected candidate can still yield evidence for a decision already
made**, and that evidence is worth more than the feature would have been.

**Measure a project's bus factor from the commit log, not from stars or commit
count.** A capture brief described a candidate as popular, busy and active, and
cited a star count and a total commit count for it. The log said 850 of those
898 commits — 94.7% — came from one address, the next contributor had 8, and the
default branch had been quiet for two months. Both headline numbers move _with_
the concentration rather than against it, so neither can detect it; `git log
--format=%ae | sort | uniq -c | sort -rn` can, in one command. This is a
`depend-on` question specifically: adopting the design costs nothing when the
author stops, and taking the crate does.

**Measure the wrapped tool; never infer its contract from its docs.** Measured,
not read: it exits 0 with findings by default (a false green unless `--error`);
`--error` alone _still_ exits 0 on a file it could not parse (only `--strict`
surfaces it, and a silently-skipped file is the exact false green we exist to
kill); its JSON is not byte-stable and the flag documented to fix that does not;
an absolute config path leaks into rule identifiers; and its auto-config mode
refuses to run with telemetry disabled. Every one of those would have been missed
by reading. **The gating question was not behaviour but distribution shape** — it
publishes no standalone binary, so there is nothing to pin, which disqualified it
on our own toolchain rules before any of the above mattered.

**A tool-side privacy behaviour is not a mechanism.** Its logged-out output
happens to redact matched bytes, which looked like it satisfied
output-is-a-pointer. It is a _licensing_ gate, reversible in any release, and it
does not cover the other output format at all. The durable answer was already
ours: a `command` rule discards the child's streams, so the payload cannot reach
our output whatever the tool prints. **When a constraint appears to be satisfied
by someone else's configuration, check whether one of our surfaces satisfies it
structurally** — that is the version that cannot be revoked.

**The adoption test's step 1 is load-bearing and it is where this survey ended.**
Nothing was adopted for Button to _run_, because no security failure in these
repositories was ever named. Their threat model is injected or insecure code
patterns; ours is honest agent or human error — wrong entity, wrong time, wrong
completion signal. A tool can be excellent, licensed cleanly, and pinnable, and
still fail at "which observed problem here does it fix". The revisit trigger is
recorded in the doc rather than left implicit, because "no" without a trigger
becomes "no" forever by default.

**A survey that classifies a corpus needs canaries, and a canary is a regression
test — not a plausibility check.** Seed the run with cases whose answer is already
known _because getting them wrong is a mistake you actually made_, and fail the run
when one misclassifies. Two rounds of this survey proved it. Round one screened
20k repositories by name, then matched policy files by filename, and produced
errors in both directions: two `deny.toml` files that are cargo-deny's, a
`conftest.py` that is pytest's, and real policy missed because only the root was
listed. Round two was built to make those unrepresentable — and the canaries caught
it reproducing the same blind spot in a new costume, fetching only paths guessed in
advance, so two root-level policy files were "absent" again. **Absence of evidence
is a claim about your instrument before it is a claim about the world**, and the
canary is what tells the two apart. The corollary for the classifier itself: a name
may decide what gets _read_; only the text decides what a thing _is_.

The one adoption was a _defect_ their design exposed in ours: a fingerprint whose
preimage includes matched values is an offline-guessable commitment to a matched
credential, so for a secret-class finding the primary key carries the payload the
finding exists to avoid printing — rule 4 violated by the key rather than by the
output line, and the key is the more durable of the two. **The best thing a
survey finds is often not their feature but our bug.**

## A worked survey: token-normalized phrase matching (CLOUD-624)

The reference instance of a survey whose candidate **survived every objection
raised against it and was rejected anyway** — for undecidability, not on the
merits. Rejecting a good idea because the question cannot be answered yet is a
distinct verdict from rejecting a bad one, and it has to be written down
differently: with a re-open predicate, and with the withdrawn objections
preserved so nobody re-litigates them.

**The two arguments that were wrong, which is the durable part.**

- _"`tokenizers` is BPE, so the category is learned."_ Wrong. Deterministic
  segmentation, lemmatization and finite-state morphology estimate nothing;
  naming one crate does not make the category learned. A token pattern over
  named classes is **more** explainable than a regex alternation — `these tokens
matched this rule` is inspectable, and the edges of a hand-tuned alternation
  are not — which is the direction the gates-decide rule points, not away from it.
- _"No witnessed miss needs it."_ Wrong on the facts. Two are witnessed, each
  citing a real turn on its own issue: `one thing to flag …` silent where `one
thing I would flag …` fires (CLOUD-487), and `worth naming` silent until
  CLOUD-387 landed one verb set across both openers. Neither was found by
  enumeration — each was found by noticing a **sibling string** fired, which is
  the defect, not the evidence against it.

**What actually decided it: a measurement that cannot be run here.** Recall
against a witnessed miss is not evidence about a matcher — a pattern authored
against known strings hits them by construction, the same circularity that makes
a hand-authored literal set the defect in the first place. What decides a
widening is the **false-positive class it opens**, and that needs negatives in
the register the predicate reads. This repo's durable artifacts are the wrong
register (the 2026-08-17 run in `mem:prior-art-and-issue-hygiene`), and
`transcript-corpus-check` answers `independent=1 min=2` where the 1 is the
asking session itself.

**The generalizable rule, and it is what tonight taught:**

> **When a blocker is rescoped into a first-class capability, the dependent stops
> being blocked and becomes a consumer.** It should close with a re-open
> predicate rather than wait, because it no longer has any claim on the
> capability's schedule or scope.

A `blockedBy` edge asserts that the blocker's completion is owed to the
dependent. Once the blocker is scoped on its own terms — CLOUD-671 says in as
many words that it "is not a means of unblocking CLOUD-624" — that assertion is
false, and leaving the edge up is the board lying about who owes whom. The
dependent's honest move is to decide now on what it can decide, and to name what
would change the answer.

**A re-open predicate is a command and an exit code, and half of one is stated
as half.** CLOUD-624's floor is "more assistant turns than the largest
measurement any shipped prose literal already rests on" — the 113-turn
transcript behind `finding-sink-check`'s table, so a new verdict cannot rest on
thinner evidence than the gates it means to improve. `transcript-corpus-check`
counts **independent sessions**, not turns, so the session half is runnable
today and the turn half is an obligation on the successor. Saying so beats
inventing a turn-counting gate to make the sentence look complete.

**One line of scar tissue from the same chain:** do not specify a mechanism over
an API you have not read. A redaction design named `ripsecrets` byte spans and
`SecretSpan` substitution; neither exists — the scanner emits matched text with
no offsets, and the type has no route back to `&str` by design.

## A worked survey: a logic engine as a predicate substrate (CLOUD-623)

The reference instance of a **substrate** question — "should a different engine
evaluate what we already decide" — and of reaching for the wrong instrument.
Scryer Prolog was the candidate. The rejection holds, on supply-chain grounds
alone; the argument that carried most of the weight was **circular**, and that
correction is the durable part of this entry.

**Separate the displacement question from the capability question. They take
different instruments, and one of them cannot be counted.**

- _Displacement_ — "would this replace code we have?" — is answered by counting
  the code it would replace. Valid; CLOUD-310 is the worked case.
- _Capability_ — "would this let us express what we currently cannot?" — **can
  never be answered that way.** Counting current uses of a primitive the system
  has no way to express returns zero by construction. That zero is the constraint
  measuring itself.

CLOUD-623 applied the displacement instrument to a capability question. It
measured a flat `for rule in rules` loop, no fixpoint, no rule consuming
another's verdict, under 60 relational lines across the board gates — and read
that as evidence relational reasoning was not wanted here. It is evidence of
nothing but the engine forbidding it. **The corrective was already written** —
_absence of evidence is a claim about your instrument before it is a claim about
the world_, in the canary entry above — and the section that violated it was
written after it anyway. Another recurrence of _a fix applied to one paragraph is
not applied to the document_.

**Two sessions reached this rule independently in one week, and that is the
strongest thing about it.** The corpus entry in `mem:prior-art-and-issue-hygiene`
states the same rule from the other direction — a discovery method cannot be
evaluated by asking whether the enumeration it would replace already covers the
ground, and _an absence supports "this sample cannot answer the question" far
more often than "the question has no answer"_. That was reached on a
prose-literal corpus; this one on a rule engine's missing primitive. Same error,
unrelated tickets, neither author having read the other. Treat the two as one
rule with two worked instances rather than two rules: the corpus entry owns the
general form, and this entry owns the displacement/capability split that tells
you _which_ instrument the question wanted.

**The instrument for a capability question is demand, and demand is countable.**
Not usage — the _workarounds usage was forced into_: invariants asserted in prose
because nothing can decide them, one predicate split across artifacts that must
be hand-kept in step, bespoke pairwise checkers, filed capability gaps, and
defects whose root cause is a missing cross-entity check. Measured here after the
verdict, and not marginal: **29 prose-asserted cross-row invariants**; **seven
`mise-tasks` whose entire purpose is asserting two artifacts agree** (`ci-drift`,
`ci-local-parity`, `contract-drift`, `hook-latency-drift`, `mise-pin-agreement`,
`rules-drift`, `timeout-drift`); **nine independently re-derived copies of one
issue-key regex**, already diverged in case-sensitivity; and `validate`
(`rules.rs:1445`) carrying exactly **two** cross-row checks beside a comment
conceding a third class it "cannot see". Three of these are shipped defects
rather than risk: two parallel config views drifted until `config lint` refused
valid configs; two restated constants drifted, one by 4x; and a `batten.toml`
comment still names a task file the tree no longer has.

**The cheapest tell is the author working around the gap in their own words.**
_`forbid` cannot express "agrees with"._ _Two rows would let one be deleted while
the gate still looked whole._ _The per-row `validate` cannot see the collision._
When the codebase already argues for a capability in its comments, a usage count
saying otherwise is measuring the wrong thing — and those comments are a grep
away, which makes this instrument practical rather than aspirational.

**A heterogeneous count is not a denominator. Classify by INPUT SHAPE before
dividing by it.** The demand count above is a tally of one symptom, not of one
problem, and the instant it was used to ask "would moving these to an engine
help?" it had to be split — because the classes have different answers and the
aggregate has none. The split that decided it: invariants whose hard part is
**extraction** (two files must agree, but one side's value has to be parsed out
of markdown, bash, pkl or yaml) are unreachable by any engine that decides over
structured facts — it replaces a two-line comparison and leaves everything
expensive, then adds materialization. Invariants over **already-typed data** (the
parsed rule table) are the reachable class. Invariants over **Rust source** are
tests and always were. And duplication of one literal in nine places wants **one
authority**, not reasoning — the engine is simply the wrong tool, and reaching
for it there is how a good instrument gets discredited.

So the sequence is: count the symptom, then classify by what the decision would
have to read, then divide only within a class. Skipping the middle step produces
a number that looks like evidence for every option at once. This is the same
error as the displacement/capability one, one level up — there the instrument was
wrong for the question, here the population is wrong for the instrument — and the
standing lesson applies: a fix applied to one paragraph is not applied to the
document.

**A re-open predicate can be unsatisfiable by construction, which is a permanent
"no" wearing an escape hatch.** CLOUD-623's was "re-open when the in-tree
relational core exceeds 200 code lines" — a threshold the rejection itself
guarantees can never be crossed, since nothing can write relational code. Check a
re-open predicate against the world the rejection creates, not the world that
proposed it. The repaired form counts demand, which _does_ move: prose-asserted
cross-row invariants, drift-checker tasks, and defects of that class.

**The expensive half of a gate here is turning prose into facts, and no
substrate improves it.** `ready-lint` is ~95 code lines of markdown-dialect regex
feeding ~23 lines of predicate; `claim-race-check` is ~6 lines of predicate
inside ~50 of fetching. This one survives, with its scope stated: it prices a
candidate offering a better _decision_ step, and says nothing about one offering
a decision we cannot currently make at all.

**Delegating to an exact tool already installed beats hosting an engine — for
the predicates that tool actually decides.** Cycle detection over one graph is
`tsort`; ancestry is `git merge-base --is-ancestor`; the released split is `git
log --not --tags`. Each is decidable, pinned and free. The over-reach to avoid is
concluding that because three delegations hold, a fourth predicate has one:
`tsort` decides a graph handed to it and nothing assembles the rule set into a
graph to hand over.

**A `read` classification is a structural promise, so no embedded evaluator of
config-supplied code can sit behind one.** house-style §5 derives the agent
allowlist from `effect == read` and requires a `read` verb to be _incapable_ of
reaching user-supplied code rather than trusted not to. A clause database
supplied by config **is** user-supplied code, so every logic-backed rule would
land in `enforce` — off the mediation path, which is where the value was supposed
to be. This is the test for any proposal that embeds an interpreter, it
generalises past whichever one is on offer, and it is decided before performance
or licensing. The measured bound alongside it: the `hook` path
carries a p95 budget `perf-assert` owns, and pays it on every mediated tool call.

**The layer that decides a dependency question is the resolved closure, and it is
the one layer nobody documents.** Asking per layer rather than per vendor is
already the rule above; this sharpens where the layers are. Resolved against this
workspace: the engine's own license is BSD-3-Clause and its MSRV is 1.85, both
clean — and its closure adds **211 packages to our 183** at default features, or
**104** with `default-features = false`, four of which are MPL-2.0 and therefore
outside `deny.toml`'s permissive allow-list. Those four survive the minimal
build: they arrive through an HTML scraper the engine does not feature-gate, as
does a dynamic-library loader. **A feature flag narrows a blast radius, never a
closure** — the crate page is not the artifact, and the only honest read is
`cargo metadata` against a throwaway manifest.

**A substrate question and an authoring-surface question are different questions,
and the narrowness rule answers only the second.** Non-negotiable rule 6 rejected
a general-purpose policy language as the surface a consumer _writes_. An engine
behind an unchanged typed rule table adds no config surface at all, so rule 6
does not reach it — and saying so is what made the rest of the verdict
falsifiable instead of foregone. **Concede the objection that does not apply**; it
is how the ones that do apply get believed.

**Rule 4 governs what is EMITTED, not what is computed** — and CLOUD-623 got
this wrong in the strict direction. Its verdict read "a derivation trace is a
payload" as disqualifying any engine whose value involves one. It does not: an
engine may derive freely so long as what reaches stdout is a pointer, and a
conflict diagnostic naming two rule sites is already pointer-shaped. **Ask what
the surface emits, never what the engine computes to get there** — the strict
reading refuses tools on a constraint they do not violate, which is the same
error as adopting one on a constraint it only appears to satisfy.

**Price the distribution shape first; it is cheap and it decides more candidates
than behaviour does.** The sidecar shape lost on our own toolchain rules before
any of the above mattered — no registry entry to resolve, `lock-complete`
requiring `linux-x64`, `linux-arm64` and `macos-arm64`, and the remaining install
route a source build `no-source-built-tool` denies by literal match. That is the
third candidate disqualified on exactly this, after the two recorded in
`mise.toml`.

**"The general seam already ships" is only an answer if the seam reaches the
thing being asked for.** CLOUD-623 answered "where would we integrate X" with the
`command` rule kind, the universal extension surface (house-style §9) — correct
for _running_ an external checker, and **irrelevant to anything cross-row**: a
`command` row is invoked per row and sees one row's world, so no arrangement of
them decides a property of the set. Check the seam against the shape of the ask
before offering it; a general surface at the wrong altitude reads as a complete
answer and is not one.

**A rejection needs a re-open predicate, and the predicate needs checking against
the world the rejection creates** — see the unsatisfiable-by-construction trap
above. CLOUD-623's surviving half is the registry entry that lets
`lock-complete` exit 0 for the required platforms; its second half was replaced,
because the original counted a thing the rejection guaranteed would stay at zero.

Findings from running it, none inferable and each cheap to repeat — deliberately
uncounted, because the list keeps growing and a numeral in front of it is one
more hand-maintained thing to drift:

- **Before calling a red check a base-branch failure, confirm the failing code
  is on the base.** Measured the hard way: a branch's `windows` job failed on
  three tests its own one-file diff could not touch, so the failure was reported
  — on the PR and on the owning issue — as inherited from `main`. It was not.
  The branch had picked up **eight commits from another bundle** through the
  landing loop's rebase, and the Windows test job existed **only there**:
  `git show origin/main:.github/workflows/ci.yml | grep -c windows` returned 1
  against the branch's 9. One diff of the implicated file between `origin/main`
  and `HEAD` settles it, and costs nothing. **A clean diff is not a clean
  branch** — a long-lived branch through a rebase loop can be carrying work
  nobody attributed to it, and "it fails on `main` too" is the most comfortable
  wrong answer available precisely when your own change looks innocent. The
  second cost is larger than the misdiagnosis: landing it would have shipped a
  `feat` change and a CI workflow as a side effect of a docs commit, so **check
  the commit list, not just the diff, before landing anything that has lapped.**
- **A measurement pointed at the wrong tree reports success.** The first
  dependency probe resolved this workspace instead of the throwaway manifest — a
  directory override outranked the `cd` — and exited 0 with a plausible package
  count. It was caught only because two runs that must have differed came back
  byte-identical. **Build the discriminator in**: run the variant whose answer is
  required to differ, and read equal outputs as an instrument fault before a
  finding. This is the canary rule applied to a measurement rather than a corpus.
- **A probe built with the ambient toolchain is not a measurement of a pinned
  repo** — the same rule one layer up, where the instrument is the compiler
  rather than the tree. A candidate engine's probe ran clean, and its detection
  behaviour went onto the issue as evidence; rebuilt through the pinned
  toolchain it **did not compile at all**, because the crate's own source uses a
  method in a `const fn` that the pin predates. The container's ambient compiler
  was nine minor versions ahead and nothing in the probe's output named it.
  **A probe lives outside the workspace, so the local verify gate never sees
  it** — the usual backstop for building against the wrong compiler does not
  exist here, and the wrong answer lands as a durable verdict on the tracker,
  where nothing re-runs it. Say in the record which toolchain produced the
  numbers. Two corollaries, each separately load-bearing: an MSRV gate that
  reads _declared_ floors from package metadata cannot see a dependency that
  declares none, so only a build finds the floor; and narrowing a feature set
  narrows the dependency closure but never reaches a crate's own source, so
  "minimal features fixes the floor" is a hypothesis to test, not a conclusion.
- **Mechanizing an invariant retires no prose, so counting comment lines as a
  saving overstates the case for adopting a tool.** A survey priced 13
  hand-maintained cross-row invariants at ~117 comment lines and read that as
  the cost a mechanism would remove. Translating two of them measured what those
  lines are: **rationale** — why two rows rather than one, why a conjunction is
  packed into one row — which survives any mechanism, so nothing was retired in
  either direction. What a check buys is a claim moving from **undecided to
  decided**, which is worth more than a line count and is not one. **Price a
  candidate on the capability only it has**: the marginal cost of a general tool
  and of a bespoke check converge, and the general tool starts behind by
  whatever materializing its facts costs — measured at 38 lines the in-process
  route did not pay at all, because it already held the parsed rows.
- **`claim-check`'s receipt is branch-keyed (`claim.<branch>`), so branch first,
  then claim** — the loop as usually written states the two in the other order,
  and the refusal it produces reads as a missing claim rather than a misplaced
  one. What was actually _observed_ is worse than misplacement and is stated as
  measured rather than inferred: run on `main`, the task reported `pullable` and
  exit 0 and wrote **no receipt on any key**, `claim.main` included. So the
  ordering rule is the safe practice; the defect underneath it is CLOUD-377,
  which had recorded this only for a detached HEAD and now carries the attached
  case too. **A gate's exit code that does not depend on whether it produced the
  artifact its own downstream gate requires** is the shape to watch for; this one
  swallows the write with `2>/dev/null || true`.
- The survey's own bug, per the standing pattern: the counting exposed
  `graph-check`'s joins as unindexed — a whole-payload reparse per node lookup
  called from three loops, a linear rescan of the edge list per node, and a
  `ready-lint` fork per Todo id. An indexing defect, fixable in place, filed as
  CLOUD-634. The substrate was never what made it slow.
- **The reviewer who overturned this was right on method, and the method is what
  transferred.** The objection was one sentence — an absence you cannot express
  is not an absence you can measure — and it invalidated the load-bearing count
  without touching a fact in it. **A verdict whose evidence is a count is refuted
  by attacking the denominator, not the arithmetic**, so state what the count
  would look like if the hypothesis were false _before_ running it. Here it would
  have looked identical, which is the definition of a measurement that decides
  nothing. Nothing gates this: a `PreToolUse` hook sees tool calls, not a
  reasoning step, the same limit CLOUD-200 records. Written down so the next
  survey inherits the question rather than the error.
