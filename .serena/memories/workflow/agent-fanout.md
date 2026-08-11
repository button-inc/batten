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

## What each implementer does

The existing contract, unchanged: claim → build → draft PR → `mise run verify`
→ `mise run linear-check` → `gh pr ready` → `mise run land` (backgrounded) →
In Review + attach the PR (the attachment is what makes `graph-check`'s
In-Review predicate true). Blocked mid-build? Same question protocol: write it
on the issue, move the issue back to Backlog, release, take the next one.
