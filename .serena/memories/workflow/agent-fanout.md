# Fan-out: one planner, N implementers, the board as the only coordinator

Read when: running more than one agent session against this repo at once, or
deciding whether to. The gates this protocol leans on are `mise run ready-lint`
and `mise run graph-check` (CLOUD-179, CLOUD-175); the board model is
`mem:workflow/board-states`.

## Shape

One **planner** session keeps the ready queue full; N **implementer** sessions
drain it, each in its own sandboxed environment with its own clone. No agent
talks to another agent, and there is no dispatcher: the planner never assigns
work, it only makes work _claimable_. Coordination is entirely board state.

- **Claiming is a single write**: Todo → In Progress + assign yourself in the
  same `save_issue` call, then read back; if the assignee isn't you, you lost
  the race — write **nothing** (nulling the winner's assignee would clobber the
  claim) and take the next frontier issue.
- **The frontier is computed, never guessed**: pipe the active columns'
  `get_issue(includeRelations: true)` payloads to `mise run graph-check`. Every
  session computing it independently gets the same answer; that shared
  determinism is what replaces a dispatcher.
- **Ready-block edits go through anchored `patch` ops only** — a whole-
  description overwrite is last-write-wins and discards Linear's concurrency
  protection.

## The brief is gated, not described

A fan-out is only as good as what travels in the brief, and the facts that do not
inherit — which identifiers, which scope, what binds inside it, what has already
been read, and the deterministic check to run — used to live here as prose. They
now live as data in `brief::SCHEMA`, gated by **`batten lint brief <path>`** (or
stdin), exit `2` on a missing section and on a `check` section carrying no
runnable command (CLOUD-84). Lint the brief before dispatching it; this file does
not restate the set, because a requirement stated twice drifts.

## The planner's ladder

1. Re-check issues whose open questions were answered — a human answer is the
   highest-value work available.
2. Ready depth low? Groom the next Backlog issue until `ready-lint` exits 0,
   then promote. Groom-first, not build-first: a fleet that only grooms when
   starved is one cycle too late.
3. Otherwise reconcile: re-derive the graph from what landed; propose (never
   silently apply) edge corrections.

## Questions are artifacts, not blocking states

A genuine ambiguity is written onto the issue (`**Open questions blocking
Ready:**` — `ready-lint` refuses to promote past it), and the agent moves to
the next issue. **The issue blocks; the loop does not.** Ration questions: ask
only when the answer changes the acceptance criteria; otherwise state the
assumption in the block and flag it. If every issue accumulates a question,
say so loudly — the human is the bottleneck and silence hides it.

## Caps, and what actually bounds N

Build WIP cap: **2**, enforced at claim time, re-checked after claiming (on an
overshoot the holder of the lexically-highest id yields). Past ~2–3
implementers the binding constraint is **land contention**, not compute: every
land forces siblings to rebase and re-run `verify`, so N ≈ time-between-lands ÷
verify-duration. **A rising re-verify rate is NOT the stop signal** — an
earlier version of this file said it was, and that optimises against the wrong
cost. `land` laps unattended: a fast-forward refusal rebases and re-verifies
with no model turn, so a moved base costs CPU and wall-clock, both of which are
free here, and zero tokens. Re-verifying is the loop working.

What actually costs is narrower, and each has its own control:

| Cost                                  | Control                                                    |
| ------------------------------------- | ---------------------------------------------------------- |
| a rebase **conflict** (needs a human) | file-domain partitioning of bundles                        |
| **CI minutes** on a run `main` voids  | draft until plausibly next; `main-watch` cancels in flight |
| **tokens**                            | bundles, and `land` lapping without returning to the model |

So the objective is pace of landed work per token, not collision avoidance.
Coordination between sessions is impossible by construction — there is no
dispatcher and no lock — so collisions are designed for rather than prevented,
in the CSMA/CD sense: detect, back off, retry, keep the medium saturated. The
target state is that **every time a merge lands, at least one sibling is already
rebased, verified and ready to go in behind it**.

Shortening `verify` still helps, but as latency to that ready state, not as
headroom for more sessions. There is deliberately no
cap on In Review: in a fast-forward trunk nothing queues there.

**Measured 2026-08-11, and the model held.** Over three hours `main` took 25
commits — mean gap **487s** — against a `verify` of **~170s**, so N ≈ **2.9**
with the cap at 2: at the ceiling. The symptom at that point is not a stall but
a cost: a lap is `verify` + CI + the fast-forward wait, roughly 5–7 minutes
against an 8.1-minute mean gap, so each lap is near a coin flip and PRs landed
in 8, 3, 4 and 2 laps. Nothing is broken when this happens — `main-watch`
already polls conditionally (a 304 is free), and a `main` that moves mid-CI
cancels the doomed run through `concurrency: cancel-in-progress`, which is the
cheap direction. **5 of those 25 commits were release-plz `chore: release`**, so
each landed change was producing about two commits on `main`; CLOUD-319's
debounce targets exactly that amplifier. The lever remains the one stated above:
shorten `verify`, do not add sessions.

**Re-measured three hours later, and the model no longer held — a lap now LOSES
by arithmetic, not by coin flip.** Over `main`'s ten commits to 21:09Z the mean
gap was **436s**, down from 487s, while a full lap is `verify` (~200s) + CI
(~5–6 min) + the fast-forward wait — call it 8–10 minutes against a 7.3-minute
gap. CLOUD-122 lost **16 consecutive laps** across two `mise run land`
invocations, every one of them green on CI. Nothing was broken and no change was
at fault; the loop simply cannot converge while the gap is under a lap.

Two distinct lap-loss shapes showed up, and only one is the documented one:

- **main moved before CI finished** (3 of 16) — the void-the-verdict case
  `ci-wait`/`main-watch` race for on purpose. Cheap, cancels early.
- **CI green, `/fast-forward` posted, the bot then SILENT while main moved**
  (5 of 16, and the majority of the laps that got that far). `land` infers a
  refusal from main moving rather than from the bot answering, so this reads in
  the log as a refusal that never happened. The bot is not rejecting the
  fast-forward; it is slower than `main`.

**A third shape, measured on CLOUD-206 the same evening: the bot ANSWERS, with a 403.** Across two more `land` invocations (16 further laps, every one green on
CI) lap 7 of the second carried a real refusal body — `API rate limit exceeded
for user ID 597920`, the _bot's_ credential, not the session's, whose own
`rate_limit` read 4900/5000 remaining at the time. So "the bot was silent" and
"the bot is slower than `main`" do not cover the space: under sustained fleet
landing the fast-forward bot can exhaust its own hourly budget, and then no
amount of lapping can win because the refusal is unconditional until its reset.
Distinguishing them costs nothing — the refusal body is already in `land`'s log —
and it matters because the two have opposite responses: slowness argues for
shortening the lap, a 403 argues for waiting out the reset.

That second shape is what makes the ceiling bite sooner than the N ≈ 2.9 model
predicts: the model prices a lap at verify + CI, and the bot's silence is a third
term nobody measured. Raising `LAND_MAX_LAPS` (the task's own documented bound)
buys more attempts within one invocation but does not change the per-lap odds —
it spends CI minutes against a losing bet.

**Then the bot was measured, and it is not the term. Superseded 2026-08-11
22:01Z (CLOUD-399).** Over `fast-forward.yml`'s full available history — **400
runs, 21:31→22:01Z**, 248 executed, 152 skipped by the `author_association` gate
— the bot answered **every** attempt: dispatch lag 0s, answer time median
**12s**, **max 23s**. It is never slow. And it is not silent: **243 of the 248
concluded `failure`**, the failing step being `sequoia-pgp/fast-forward` itself —
real "not a fast-forward" refusals against a branch that had gone behind.

So "the bot is not rejecting the fast-forward; it is slower than `main`" above is
**wrong**. The reading it came from is explained by a second defect (CLOUD-409):
`land` picks its refusal verdict out of an unfiltered 20-run window, which at 13
runs/minute is ~90s of history containing every PR's refusals — so a lap cannot
reliably tell its own verdict from a stranger's, and the log stops being evidence.

The measured shape is a **thundering herd**: 248 landing attempts in 30 minutes
producing **5 merges**, a ~2% per-attempt success rate. That falsifies — rather
than merely argues with — "in a fast-forward trunk nothing queues there" above.
The queue already exists; it is implemented as 243 discarded CI matrices per half
hour instead of as a lease, which is the expensive way to have one. Shortening the
lap is still worth doing and is no longer sufficient: at 2% per attempt, halving
`L` does not converge. CLOUD-393 builds the lease; **the lever is now: serialise
the landing, shorten the lap, quiet `main` — never add sessions.**

One term that measurement prices too high, from a second branch lapping the same
window (CLOUD-68): **the lap gets cheaper as it goes.** Cargo caches warm across
laps, so `verify` fell from ~240s on lap 1 to **86s** by lap 8 — a lap of ~10
minutes becoming ~7.5 against the same 7.3-minute gap. So the odds a re-invoked
`land` faces are not the odds its first lap faced, and re-invoking it as written
is not the same bet as raising `LAND_MAX_LAPS`. Neither is a substitute for the
lever; both beat engineering around the loop.

**What the backstop is asking when it stops you.** `still not linear after 8
laps; main is moving faster than a lap takes. Look before lapping again` — the
thing to look at is whether the laps lost for a REASON (rebase conflict, red CI,
failed `verify`) or purely because `main` moved. Only the second is contention,
and only the second is safe to re-run unchanged; the first is a defect the loop
is correctly refusing to paper over. Measured again on CLOUD-282, which spent a
full 8 laps to the backstop with every `verify` green and CI green three separate
times, then lost the next invocation to a genuine rebase conflict — two different
answers to that question, one invocation apart.

A land that stops on the backstop is **re-run, not re-engineered**: wrapping it
in bespoke retry or pre-check logic is forbidden (AGENTS.md), and re-invoking
`mise run land` after confirming the laps lost only to movement is the sanctioned
move.

## Planners fan out freely; implementers do not

The cap above is a **build** cap, and reading it as a cap on sessions is the
mistake worth naming. A planning-only session writes no code, takes no lock,
claims no issue and never rebases — it reads, decides, and posts a plan to the
issue. Nothing it does is on the contended path, so N planners cost only tokens.
Landing is what contends. Fan out planning; drain the plans at 2.

Dispatched as `/plan-fleet` (`.claude/commands/plan-fleet.md`), which owns the
procedure; this section owns why it is shaped that way.

**Dispatch bundles, not single tickets.** A session handed one ticket stops when
it lands, and its container plus its warm context are thrown away. A session
handed an ordered chain in one file domain keeps going, and — the part that
matters for the cap above — amortises several commits over one rebase cost
instead of paying that cost per ticket. Bundling is what raises the ceiling;
adding sessions is not.

Order within a bundle by real dependency: the ticket whose gate the next one
needs goes first, and the ticket that _replaces_ what an earlier one fixed goes
last (CLOUD-328 then CLOUD-214 is the worked example — fix the walker's contract
and pin it with assertions, then let the replacement land against those
assertions). Each child plans **one ticket at a time**: a later ticket's shape
depends on what the earlier one landed, so planning the chain up front is
planning against a tree that does not exist.

The dispatcher does not need perfect dependency knowledge. Every child runs
`claim-check` per ticket and skips what is not pullable, so a mis-sequenced
bundle degrades to a skip rather than a collision.

Three things about the harness that the procedure encodes because they are
invisible until they bite:

- **A child's final chat message is never read by the parent.** Under plan mode
  this costs nothing — the plan goes to the approval UI and the work goes to
  commits and PRs, all durable. It matters only for a child that produces a
  conclusion and no artifact: a research or decision ticket must be told to
  write to the issue, or its output dies with the session. Do NOT reflexively
  tell an implementing child to post its plan as a Linear comment; plan mode
  already has a destination, and a duplicate copy on the issue is a second
  authority that goes stale the moment the plan changes under review.
- `permission_mode: "plan"` **is the right default, and is already this
  environment's.** Measured 2026-08-11: children dispatched without it came up
  `PERMISSION_MODE_PLAN` anyway and parked at "Waiting on permission:
  ExitPlanMode". That park is the feature — the child plans, a human approves,
  and it works on from there. It is only a defect for work nobody intends to
  approve, which then stalls forever. Pass it explicitly so the intent is legible.
- **Reasoning effort is not a `create_session` parameter.** Children inherit the
  dispatcher's, so dispatch from a session at the effort you want them to run at.
- **In-process subagents are the wrong tool here, for a reason unrelated to
  caps.** They share the parent's single working tree, and there is no channel
  for one to put a question to the human — the parent must relay it after the
  subagent has already stopped. Sibling sessions get their own container, their
  own clone, and their own thread to ask in.

The partition is by **file domain**, not by topic, and it is only real if it
reads open PRs' file lists rather than their titles. Two issues that read as
unrelated but both edit `mise-tasks/land` are one issue for dispatch purposes.

## A fan-out that drafts rather than lands

The section above is right that a non-landing session is off the contended path
and "costs only tokens". **This is what those tokens cost**, because the reading
that kills a fleet is "only tokens" → "free".

Every bound in the caps section is a bound on **landing**. An agent that
researches, reviews, or drafts never lands, so land contention derives nothing
about it — and the silence that leaves is an absence of a _derivation_, not an
absence of a _constraint_. Eight drafting agents were launched into that silence.

The binding constraint for this shape is **per-agent fixed cost**, which is paid
once per agent and therefore multiplies with N. Measured 2026-08-11: the one
agent in that fleet which completed anything spent **63,848 tokens** to fetch a
single issue and run one lint. That is the **floor for near-zero work**, not an
average — budget from it, not from what the work "should" cost. Each prompt
named eight artifacts as required reading, so the fixed cost was paid eight
times over before any agent did anything.

Three rules follow, and none of them is derived from land contention:

- **Digest, don't cite.** Context shared across the fan-out is computed **once**
  and passed as one artifact. A prompt that names N documents as required
  reading multiplies the read cost by the fleet size to deliver identical bytes
  to every member. The reading list is the anti-pattern; the digest is the fix.
- **Checkpoint at the unit's own gate.** Each unit is written to its **durable
  home** — the tracker, a memory, a PR — the moment it passes, never batched
  behind siblings. Scratch dies with the container and no consumer reads it, so
  work that ends the session in a scratch file was never done. This is the same
  property `mem:workflow/board-states` makes of the board: the durable write IS
  the delivery.
- **Pilot one, then widen.** Carry a single unit end to end, _through its
  durable write_, before spending the shape on the rest. A recipe unproven on
  one unit must not be spent on fifty-one — and "unproven" means the write has
  not been observed, not that the prompt looks right.

**What is gated here, stated plainly so nothing is assumed:** none of the three.
They are reference material with no exit code behind them, because the predicate
they need is a measurement of a session's actual spend, which is out of tree —
the capability gap CLOUD-95 registers. The cap of 2 above IS enforced, at claim
time; these are not. Read that as a reason to hold them deliberately, not as a
reason to discount them: the cost they bound was paid in full before it was
written down.

## What each implementer does

The existing contract: claim → build → draft PR → `mise run verify` → `mise run
linear-check` → `mise run land` (backgrounded) → In Review + attach the PR (the attachment is what makes `graph-check`'s
In-Review predicate true). **`land` is the only readier** — a hand `gh pr ready`
spent before its push buys only draft-era skips (CLOUD-247), and the ready must
be the event that fires CI on the SHA that lands. Blocked mid-build? Same question protocol: write it
on the issue, move the issue back to Backlog, release, take the next one.
