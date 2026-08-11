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

## 4. One `create_session` per bundle

Call the Claude Code Remote `create_session` tool with
`source_url: https://github.com/button-inc/batten`, `model: claude-opus-5`,
`permission_mode: "plan"`, tags `["batten-bundle", "ready-queue-<YYYY-MM-DD>"]`,
and a title of the form `BUNDLE <domain> — CLOUD-<a> → CLOUD-<b>`.

**Plan mode is correct here and is also this environment's default.** The child
plans, a human approves in the web UI, and it then works on. Its one failure
mode is a child nobody intends to approve — that stalls indefinitely, so only
omit it when dispatching genuinely fire-and-forget work.

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
   **this ticket only** and wait for approval → build, `verify`, `linear-check`,
   draft PR, `land` backgrounded → next ticket.
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

Planning fans out freely: a planner writes no code and takes no lock. **Landing
contends** — every land forces siblings to rebase and re-run `verify`, so the
ceiling is roughly time-between-lands ÷ verify-duration, and the honest signal
that you are past it is a rising re-verify rate, not a stall. Bundles raise that
ceiling by amortising several commits per session over one rebase cost; adding
sessions does not. `mem:workflow/agent-fanout` carries the measurement and the
current cap.
