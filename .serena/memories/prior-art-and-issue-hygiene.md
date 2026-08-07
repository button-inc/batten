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
