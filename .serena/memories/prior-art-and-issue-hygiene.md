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

Where a survey's _reasoning_ lives: this file, or the memory for the subsystem it
touched. Not in the issue, not in the code, not in a commit message.

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
