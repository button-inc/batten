# Ready gate vs. Todo column vs. In-flight view

Do NOT confuse these three. "Ready" in the Definition of Ready & Done is NOT a
Linear workflow status.

1. **Ready block** — *text inside the issue*. The Definition-of-Ready content
   authored during refinement: "the mechanism is specified as a computable
   predicate." It is a property of the issue body, not a column. Likewise the
   Done gate ("landed on `main` by fast-forward, CI-confirmed green") is a
   predicate, and the `Done` column is where issues land once it is met.

2. **Todo column** — the *ready queue*. Holds issues whose Ready block has
   passed, waiting to be pulled. Button Cloud (CLOUD) team states:
   Backlog → Todo → In Progress → In Review → Done (+ Canceled/Duplicate).
   There is deliberately no status literally named "Ready"; Todo is it.

3. **"In flight" view** — the shared signal that a story was pulled. Filter:
   `Project is Batten` AND `Status is any of {In Progress, In Review}`. Pulling a
   story = Todo → In Progress; it then appears here for everyone. This is
   correctly configured — do not propose "fixes" to it.

## The trap (an earlier agent fell in twice)
- Wrong: reading "Ready" as a missing workflow status because it parallels
  "Done" → concluding pulls are "not observable."
- Wrong: then "fixing" CLAUDE.md to map Ready → the Todo column. That conflates
  issue *content* (the Ready block) with a *column* and would inject confusion.
- CLAUDE.md's wording is correct as-is. Do not reword the gate descriptions to
  name columns.

Pulling a story IS observable: it leaves Todo and surfaces in the In-flight
view on transition to In Progress. The process is sound; do not break it.
