---
description: Dispatch one planning-only sibling session per ready issue, partitioned by file domain
---

Dispatch a fleet of planning-only sibling sessions over the ready queue.

`$ARGUMENTS` may name the issues (`CLOUD-333 CLOUD-224 …`). If it is empty,
compute the frontier yourself as described in step 1.

The model this implements — the caps, the measurement behind them, and why
planners and implementers scale differently — is `mem:workflow/agent-fanout`.
Read it before deviating; this file is the procedure, not the reasoning.

## 1. Compute the frontier, do not guess it

- Pull the `Todo` column, and `In Progress` for what is already claimed.
- An issue is dispatchable only if `blockedBy` is empty **or** every blocker has
  landed. Fetch `get_issue(includeRelations: true)` — do not infer readiness from
  the column alone, since a blocker added after promotion still holds.
- Pipe the active columns' payloads to `mise run graph-check` rather than
  eyeballing the graph. Every session computing it independently gets the same
  answer, and that shared determinism is what replaces a dispatcher.

## 2. Subtract what is already spoken for

Three independent sources, all of them necessary:

- `list_sessions` with `mine: true` — a **non-archived** session whose title or
  branch names an issue intends it. Archived sessions do not.
- Open PRs, and their **file lists**
  (`git diff --name-only origin/main...origin/<head>`), not just their titles.
  This is what makes the partition in step 3 real rather than nominal.
- `In Progress` assignees on the board.

## 3. Partition by file domain, not by topic

Two issues that read as unrelated but both edit `mise-tasks/land` are one issue
for dispatch purposes. Group by the files each plan will touch, and give each
session a domain no sibling holds. Where a domain collides with an **open PR**,
either hold the issue back or state the collision in that child's prompt, so its
implementer expects a rebase instead of engineering around one.

Report what you held back and why. A silently dropped issue reads as "the queue
was empty" when it was not.

## 4. One `create_session` per issue

Call the Claude Code Remote `create_session` tool with
`source_url: https://github.com/button-inc/batten`, tags
`["batten-planner", "ready-queue-<YYYY-MM-DD>"]`, and a title of the form
`PLAN CLOUD-<n> — <short handle>`.

Do **not** pass `permission_mode: "plan"`. It blocks on an approval prompt in the
web UI that nobody is watching, and the child stalls indefinitely.

Each prompt is standalone — the child starts from nothing — and carries, in order:

1. **The refusal, first and explicit.** Planning only: do not implement, commit,
   push, run `land`, or claim the issue. Leave it in `Todo`, unassigned.
2. **What to read**: `AGENTS.md`, then `mem:workflow/agent-fanout`,
   `mem:workflow/board-states`, plus the `.claude/rules/` file matching the
   surface and any memory its toolchain touches.
3. **What the plan must name**: exact files; the mechanism as a command and an
   exit code over an object it decides; the test obligation and where it lives;
   commit type and bump; and anything in the Ready block the current tree
   contradicts.
4. **The question protocol**: a genuine ambiguity goes onto the issue under
   `**Open questions blocking Ready:**` via an **anchored patch op**, never a
   whole-description overwrite. Ration them — state an assumption and flag it
   where you can, and ask only when the answer changes acceptance. The issue
   blocks; the loop does not.
5. **Where the output goes**: a comment on the Linear issue. Say plainly that the
   child's final chat message is not read, because it is not — the parent never
   sees it, so a plan left only there dies with the session.
6. **The issue's own substance**, carried over rather than referenced: the
   measurement, the Ready block's specializations, the rejected alternatives, and
   any decision the issue deliberately leaves to the implementer. A prompt that
   says "read CLOUD-n and plan it" spends the child's first ten minutes
   rediscovering what the dispatcher already had loaded.

## 5. Verify, then report

Call `get_session` on at least one child until it reaches `RUNNING` with a
`task_summary`. `PENDING` only means the container is still provisioning, and is
not evidence the fleet works.

Then report the fleet: issue, domain, session title. Do not idle waiting on
plans — the sessions outlive the turn, and their plans land on the issues whether
or not anyone is watching.

## What this command is not

It does not dispatch implementers. Build WIP is capped at **2**, and past ~2–3
the binding constraint is land contention rather than compute — the caps section
of `mem:workflow/agent-fanout` carries the measurement. Planning fans out freely
because planners write no code and take no locks; landing does not.
