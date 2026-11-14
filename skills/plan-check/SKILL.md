---
name: plan-check
description: Checks an implementation plan before the first edit of a claimed row — its shape, every claim it makes about the tree, the two questions no command decides, and an isolated, report-only cold read whose verdict the author never writes — then has the plan corrected until that read says it is executable. Use as soon as a plan has been written, when asked to "check the plan", and before the first edit of any claimed row.
---

# Checking a plan before the first edit

A plan is checked by something that did not write it. The evidence is blunt: a
model critiquing its own plan does not help and can make it worse, while a sound
external check does help. So the rungs a command can decide are a command's, and
the rest goes to a reader who has only the plan, the row and the repository.

A plan is criteria and steps, never code. Detail written into a plan cascades
when it is wrong, so keep it at the level of acceptance items and the steps
that serve them.

## The ladder: run it per plan, cheapest rung first

Copy this checklist and tick it. A plan that fails a rung is fixed before the
next, costlier rung is spent on it.

```
Plan for CLOUD-N:
- [ ] P0 shape: seven parts, in order, none empty; steps recorded
- [ ] P1 verify: every claim about the tree resolved by its instrument
- [ ] P2 pressure-test: the two questions answered in writing
- [ ] P3 validate: isolated cold read, every finding fixed or answered, read again
- [ ] verdict pasted into Validation as plain text
```

## P0: shape

The plan has seven headed parts, in this order, and none is empty:

1. **Goal**: the row's acceptance items, one per line, each with an id: `A1`,
   `A2`, and so on.
2. **Steps**: each with an id (`S1`, `S2`, …), the files it touches, and the
   item ids it serves. Record every step as an entry in the engine's plan store
   with `batten record plan`, which reads `<id> <status>` lines on stdin. That
   store is the one the landing gate reads, so a step that is not recorded is a
   step nothing holds to its end.
3. **First failing test**: by file and case name.
4. **Commands**: in the order they prove the change.
5. **Out of scope**.
6. **Unknown**: what you do not know yet, and how you will find out.
7. **Validation**: where the validator's reply goes. It is the last part.

Two forms are taught because the plan's lint enforces them:

- **A trivial change** records an empty plan and writes the single line `none`
  under Goal and under Steps.
- **A later ticket on the same branch** extends the same plan: the earlier items
  and steps stay, and the whole list is recorded again under the new claim, each
  entry with its current status. A record that drops an earlier ticket's steps
  is a plan the landing gate cannot hold.

This rung and the coverage half of the next are decided by a command, not by
you. Do not spend judgement on what a command can decide; fix what it reports.

## P1: verify

Every claim the plan makes about the tree is resolved with the instrument
`rules/scanning.md` names for its class:

- each path and symbol: read it;
- each number: reproduce it with a command, and write the command down;
- each "already exists": look it up.

A claim the plan copied from the row is checked too. The row is evidence, not
proof: rows groomed in this repository have been measured carrying a symbol
that does something else, a number done by hand, and a mechanism that could not
work as written. When the tree and the row disagree, the tree wins: fix the
plan, and write what you found on the row.

## P2: pressure-test

Two questions no command can decide. Answer each in writing, in the plan:

- **Which named test would pass without the change?** A test that passes either
  way proves nothing. Name the assertion that fails today.
- **Which step cannot run in the stated order because it needs a later one?**
  Reorder until none does.

Whether every item has a step and every step an item is a matching of ids, so
it is the lint's, not yours.

## P3: validate

Spawn one isolated, report-only subagent with the brief in
`references/plan-validator-brief.md`. Write the plan and the row to scratch
files first and hand it the paths.

It is told to be the engineer who must execute the plan with nothing else, and
to look for what would stop it. It is not asked whether the plan is good: an
evaluator asked for approval gives it.

Its reply has a fixed shape (the brief has it) and ends with one literal line:

- `VERDICT: executable-as-written`, or
- `VERDICT: needs-fixes`.

A GOAL the validator restates differently from yours is a defect in the plan:
the plan says something other than what you meant. Rewrite it.

## Correct, then say

1. Fix every finding in the plan with evidence, or answer it in the plan.
2. Run the validator again on the corrected plan. You never write the verdict.
3. Paste the validator's reply into Validation **as plain text, not inside a
   code fence**: the lint does not read fenced lines. Validation is read only
   for the verdict line, so the reply's quoted pointers and headings are fine
   there.
4. If the second read still says `needs-fixes`, stop planning this ticket:
   write the open findings on the issue and move it to Backlog, as the dispatch
   procedure says for a blocked ticket.

End by stating the verdict and the count of findings fixed.

The plan's lint, which decides P0 and coverage and writes the receipt that lifts
the hold on edits, is not yet available in this repository; until it is, the
validator's verdict in Validation is the whole of the check.
