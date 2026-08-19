---
description: Dispatch sibling sessions over the ready queue in bundles, each planning then landing its own chain
---

Dispatch a fleet of sibling sessions over the ready queue. Each gets a **bundle**
— an ordered chain of tickets in one file domain — which it plans and lands one
ticket at a time.

`$ARGUMENTS` may name tickets or bundles. If empty, compute the frontier
yourself as described in step 1.

The model this implements is `mem:workflow/agent-fanout`. Read it before
deviating; this file is the procedure, not the reasoning.

## 1. Compute the frontier, do not guess it

- Pull the `Todo` column, and `In Progress` for what is already claimed.
- A ticket is dispatchable only if `blockedBy` is empty **or** every blocker has
  landed. Do not infer readiness from the column alone — a blocker added after
  promotion still holds.
- Pipe the active columns' payloads to `mise run graph-check` rather than
  eyeballing the graph.
- You do **not** need perfect global knowledge before dispatching. Each child
  runs `mise run claim-check` per ticket and skips what is not pullable, so a
  mis-sequenced bundle degrades to a skip rather than a collision. Push the
  dependency check down to the gate; that is what it is for.

## 2. Subtract what is already spoken for

Three independent sources, all necessary:

- `list_sessions` with `mine: true` — a **non-archived** session whose title or
  branch names a ticket intends it. Archived sessions do not.
- Open PRs, and their **file lists**
  (`git diff --name-only origin/main...origin/<head>`), not their titles.
- `In Progress` assignees on the board.

## 3. Bundle by file domain, and order within the bundle

Group tickets into chains where **one session owns one file domain end to end**.
Two tickets that read as unrelated but both edit `mise-tasks/land` belong in the
same bundle, sequenced — never in two, racing.

Order within a bundle by real dependency, cheapest-enabling-first: the ticket
that makes the next one's gate exist goes first; the ticket that replaces what
an earlier one fixed goes last. Say in the prompt _why_ the order is what it is,
so the child does not silently reorder it.

Name the domain explicitly in each prompt as files the session **owns**, plus
the neighbouring files it must **not** touch because a sibling holds them. Where
a domain collides with an open PR, say so and tell the child to expect a rebase
rather than engineer around one.

Report what you held back and why. A silently dropped ticket reads as "the queue
was empty" when it was not.

## 3b. Choose the bundle's PR shape, and say which in the prompt

Two shapes are sanctioned. The per-ticket loop below is the default; **one PR
for the whole bundle** is the other, and it is practised here rather than
hypothetical — PR #385 landed CLOUD-494 → 493 → 492 as one PR, three commits,
one land, and the dependency-automation bundle (CLOUD-593 → 655 → 657 → 658 → 661) is the second instance. Until CLOUD-661 neither this file nor
`mem:workflow/agent-fanout` admitted the second shape existed, so every time it
was chosen it read as a child going off-script and the next dispatch re-derived
the reasoning from nothing.

**The criterion, so the choice is not taste.** CI matrices scale with readied
heads: one PR is one matrix, N PRs are N.

- **One PR per bundle** when the bundle is a single unit of build work — its
  tickets share a file domain, each one's gate or config is what the next one
  extends, and none of them is worth landing without the others. `agent-fanout`
  already argues this for the rebase cost ("amortises several commits over one
  rebase cost instead of paying that cost per ticket"); the matrix is the same
  argument one step further, and CLOUD-596 measured what a readied head costs
  here.
- **One PR per ticket** when the tickets are independently useful — each is
  worth landing alone, and holding one back behind another's failure buys
  nothing.

**Three costs of the one-PR shape, none of them a reason not to choose it and
all of them things a child must be told:**

1. **The board reports N units of work for one contender.** `graph-check` counts
   issues In Progress, so a five-ticket bundle reads WIP 5 against a cap of 6.
   Nothing in tree binds a ceiling to that count, so it is a reporting artifact
   rather than a refusal — CLOUD-502 measured it, and is Canceled, so a reader
   who meets the artifact finds no explanation unless it is here.
2. **The branch must be KEYLESS, and nothing checks that it is.**
   `closing-key-check` passes on the first closing key it finds (CLOUD-527), and
   `mem:workflow/board-states` measured branch-name precedence beating the PR
   body — a branch naming one issue moved that issue and left the others
   untouched. So name the branch for the domain (`claude/<domain>-bundle`), close
   every key in the body, and check the board after the merge.
3. **One failure holds the batch.** CLOUD-344's finding about grouped Dependabot
   PRs applies unchanged: a red on any commit holds the whole set.

## 4. One `create_session` per bundle

Call the Claude Code Remote `create_session` tool with
`source_url: https://github.com/button-inc/batten`, `model: claude-opus-5`,
tags `["batten-bundle", "ready-queue-<YYYY-MM-DD>"]`,
and a title of the form `BUNDLE <domain> — CLOUD-<a> → CLOUD-<b>`.

**Whether to pass `permission_mode: "plan"` is a property of the DISPATCH, not
of the bundle.** Pass it when a human is standing by to approve in the web UI;
omit it when the dispatch is fire-and-forget. The same bundle takes opposite
answers depending on which is true, so the choice is made per dispatch and not
once per ticket.

It is **not** a default, and **not** this environment's: `create_session`
inherits the caller's mode, and dispatchers here run `auto`, so omitting it
yields `PERMISSION_MODE_AUTO`. Unattended, plan mode is not a free extra gate —
one child parked 91 minutes on `AskUserQuestion` for no commit, branch or PR.
Attended it is the cheapest review point there is: the five CLOUD-607 bundles
dispatched in plan mode with the owner approving all reached `review_ready`.
Reasoning in `mem:workflow/agent-fanout`; measurements on CLOUD-672.

Reasoning effort is **not** a `create_session` parameter; children inherit the
dispatching session's. Dispatch from a session at the effort you want.

Each prompt is standalone — the child starts from nothing — and carries:

1. **The bundle, in order**, with one line per ticket on what it is and why it
   sits where it does.
2. **The file domain**: what this session owns, and what it must not touch.
3. **What to read**: `AGENTS.md` first — naming it as the standing authorization
   to carry work to landed without asking, because a child that has not read it
   will stop after the edits and wait. Then `mem:workflow/agent-fanout`,
   `mem:workflow/board-states`, the `.claude/rules/` file matching the surface,
   and any house-style section that governs the surface it touches.
4. **The per-ticket loop**, verbatim in shape: `claim-check` → claim → plan
   **this ticket only** — waiting for approval only if this was a plan-mode
   dispatch, since an unattended child told to wait never proceeds (CLOUD-672)
   → build, `verify`, `linear-check`,
   draft PR, `land` backgrounded → next ticket. For a bundle dispatched under
   the one-PR shape (step 3b), the loop is `claim-check` → claim → plan **this
   ticket only** → build → commit → next ticket, with the draft PR, `verify`,
   `linear-check` and `land` run once, after the last commit — and the three
   costs above stated in the prompt, since a child that has not been told about
   the keyless branch will name the branch for one ticket and strand the rest.
5. **The instruction not to plan ahead.** A later ticket's shape depends on what
   the earlier one lands; planning the whole bundle up front is planning against
   a tree that does not exist.
6. **The instruction to keep going.** Do not stop after one ticket and do not
   stop to report progress — the board and the PRs are the report. A blocked
   ticket is written on the issue, moved to Backlog, and skipped, not a reason to
   halt the chain.

## 5. Verify, then report

`get_session` on at least one child until it reaches `RUNNING` with a
`task_summary`. `PENDING` only means the container is provisioning.

Then report the fleet: bundle, domain, tickets. Do not idle waiting — the
sessions outlive the turn.

## What bounds the fleet

**Not the re-verify rate.** `land` laps unattended — a fast-forward refusal
rebases and re-verifies with no model turn — so a moved base spends CPU and
wall-clock, both free here, and zero tokens. Re-verifying is the loop working,
and throttling the fleet to avoid it optimises against a cost that does not
exist.

Three costs are real, and each has its own control:

| Cost                                  | Control                                             |
| ------------------------------------- | --------------------------------------------------- |
| a rebase **conflict** (needs a human) | file-domain partitioning — step 3                   |
| **CI minutes** on a run `main` voids  | the `land-lock` lease — `mem:workflow/landing-loop` |
| **CI minutes** per readied head       | the bundle's PR shape — step 3b                     |
| **tokens**                            | bundles, and `land` lapping without a model turn    |

So the objective is pace of landed work per token, not collision avoidance.
There is exactly one coordination primitive — `land-lock`, a CAS lease on
`refs/heads/batten-land-lock` that `land` acquires before the ready/push pair,
so the draft→ready transition that spends the CI bill happens inside the hold.
It decides **who goes first and nothing more**: bounded to the holder plus one
admitted successor, regardless of how many sessions are dispatched. Everything
else stays CSMA/CD — detect, back off, retry, keep the medium saturated.

Do not build a second admission authority on top of it, and do not "repair" it
back to an unlocked loop: `mem:workflow/landing-loop` is the one place its
semantics live, and it records which of its shapes read as breakage from an old
clone. What the lease does not yet do — keep the queue warm across a merge,
stop a loser starving — is CLOUD-369's residue, not a gap to fill here.

`mem:workflow/agent-fanout` carries the fan-out measurement.
