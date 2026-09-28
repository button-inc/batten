---
name: groom
description: Grooms a tracker row toward Ready by forcing the judgement a Ready linter cannot make — every pointer re-read against the tree, every number reproduced, the mechanism decided, the tests shown to discriminate — then validates it with an isolated, report-only cold read before promotion. Use whenever asked to groom, refine, ready, promote or pressure-test a row or a milestone ("groom M2 to ready", "get CLOUD-N ready", "is this row ready?"), and before moving any row into Todo.
---

# Grooming a row to Ready

A Ready linter answers "is the block well-formed". It never answers "is the row
true". Every defect this repository has measured in a groomed row was
**well-formed and false**: a symbol that does not exist, a store census never
taken, a count with no command, a mechanism deferred behind a gate name, a test
file picked off a glob, a blocker that was never a blocker. So the linter's
exit 0 is where grooming starts, never where it ends.

The deliverable of a grooming session is the **board**. A grooming session
never claims, readies or lands (CLOUD-1568).

## The ladder — run it per row, cheapest rung first

Copy this checklist and tick it per row. A row that fails a rung is fixed
before the next, costlier rung is spent on it.

```
Row CLOUD-N:
- [ ] L0 floor: `batten ready lint --issue CLOUD-N` findings fixed
- [ ] L1 claims: every pointer, number and board claim resolved (below)
- [ ] L1 decision: mechanism decided, tests discriminate, prose agrees with §7
- [ ] L2 cold read: isolated validator report, every finding fixed or answered
- [ ] promote, or leave in Backlog with the open question written on the row
```

### L0 — the floor

Read the row through the verb (`batten mcp call Linear get_issue '{"id":"CLOUD-N"}'`),
then run `batten ready lint --issue CLOUD-N` and fix what it reports. Its exit 0
means "no known shape defect". Never report it as "ready".

### L1 — resolve every claim, in this session

List every claim the row makes, then resolve each with the instrument
`rules/scanning.md` names for its class. Do not reason from memory; a claim you
did not look up is unresolved.

1. **Pointers.** Every path, `path::symbol`, rule id, task name, `input.*` key,
   test name. Does it exist at `origin/main`, and does it do what the row says?
   A symbol that exists but does something else is a false premise.
2. **Contents and live behaviour.** A claim about what a store, a session or a
   queue CONTAINS is answered by counting it, not by reading the writer
   (CLOUD-1523: correct in code, zero live instances).
3. **Numbers.** Every figure names the command or fixture that reproduces it.
   Re-run it. A number you cannot reproduce is removed or re-measured
   (CLOUD-1522's 19,348 was a double count).
4. **Board claims.** Blockers, "decided on", "duplicate of", a status. Search
   the board before trusting any of them (`rules/scanning.md` row four). Look
   for a refutation that exists elsewhere and was never written to this row.

Then the decision checks, which are about the row against itself:

5. **Decided, not deferred.** "Needs a mechanism", "to be designed", "a gate
   will decide" beside a well-formed block is a deferral wearing a status
   (CLOUD-1567). If the evidence in hand decides it, decide it in the row. If it
   genuinely does not, write the open question and leave the row in Backlog.
6. **Tests that discriminate.** Each `tests[]` entry names a real or clearly
   new file, a case that fails without the change and passes with it, and a
   `MUTANT <slug>|` row that `batten mutate` can reach or an honest statement
   that it cannot (CLOUD-1526 clause 8). A file picked because it exists is the
   defect `rules/scanning.md` measured, not a test obligation.
7. **Prescription vs acceptance.** Does doing exactly what the row prescribes
   satisfy the row's own §2 and §7? Where they disagree, the acceptance is the
   spec (`mem:workflow/board-states`).

Fix everything you can evidence, directly in the row: Backlog and Todo bodies
are specs, and correcting them in place is what grooming is.

### L2 — the isolated cold read

The implementer will start from nothing but the row, AGENTS.md and the repo.
Reproduce that: spawn one read-only `Explore` subagent per row, with the brief
in `skills/groom/references/validator-brief.md` and the row body written to a
scratch file it can Read. Rows are independent, so validators for several rows
run in parallel.

- The validator is **report-only**. It never writes a file or the tracker. The
  grooming session applies every fix itself, one row at a time.
- Its value is that it did not write the row. Measured on CLOUD-1968: a fresh
  isolated read caught every seeded defect with or without this skill, while
  the recorded failures were all main sessions linting rows they had just
  written. The isolation is the lever; do not skip it because L1 looked clean.
  Models also under-ask unless pushed to, which is why the brief demands
  its questions.
- Every finding is either fixed in the row with evidence, or answered in the
  row. A divergence between its restated goal and yours is a defect in the row.
- Post its report on the row as a comment, with the fixes it caused.

Measured cost: about 81k tokens and 5 minutes per row. Spend it only on rows
that passed L1.

### Promote, or do not

Promote to Todo only when L0 is clean, every L1 claim is resolved, and the L2
findings are closed. A row with an open question stays in Backlog with the
question written on it, ranked by what it changes. Ask only when the answer
changes the acceptance.

## What to report

Report per row, as a count and a pointer, never as "groomed" or "ready" alone:

- rows promoted, and for each the L2 findings that were fixed;
- rows left in Backlog, and the open question that holds each;
- premises refuted, with the row and the evidence.

## References

- `skills/groom/references/validator-brief.md`: the L2 brief and reply shape.
- `skills/groom/references/defect-classes.md`: the measured classes, one line each,
  with the row that measured it.
- The evidence behind all of this is the Linear document "Grooming evidence
  dossier — what a groom must force that a linter cannot", on CLOUD-1526.
