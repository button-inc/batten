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
verify-duration. A rising re-verify rate is the stop signal, and shortening
`verify` buys more parallelism than adding sessions. There is deliberately no
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

## What each implementer does

The existing contract, unchanged: claim → build → draft PR → `mise run verify`
→ `mise run linear-check` → `gh pr ready` → `mise run land` (backgrounded) →
In Review + attach the PR (the attachment is what makes `graph-check`'s
In-Review predicate true). Blocked mid-build? Same question protocol: write it
on the issue, move the issue back to Backlog, release, take the next one.
