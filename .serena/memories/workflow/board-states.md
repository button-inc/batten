# Linear board states — the observability surface

Read when: starting/finishing work on a `CLOUD-*` issue, or reasoning about how
others know what's in flight. The crisp rule lives in AGENTS.md ("The board");
this memory is the model, the mapping, and the trap.

## The rule

Move the issue as you move the work. The **transition is the notification** —
there is no separate "tell people." Button Cloud (CLOUD) team states:

| State           | Meaning                                               | You move it here when                                                                                                         |
| --------------- | ----------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------- |
| Backlog         | not yet Ready                                         | —                                                                                                                             |
| **Todo**        | the **ready queue**                                   | the Definition-of-Ready predicate is validated (the issue's **Ready block** is satisfied). Issues here are available to pull. |
| **In Progress** | checked out, being worked                             | you start work — assign yourself in the same move.                                                                            |
| **In Review**   | landed to trunk, under post-merge review, pre-release | the change is on `main`.                                                                                                      |
| Done            | released                                              | the change ships.                                                                                                             |

## Two things that trip agents up

1. **"Ready" is not a status.** It is the **Ready block** — text inside the issue
   authored during refinement, "the mechanism specified as a computable
   predicate." `Todo` is the _column_ that holds issues whose Ready block passed.
   Do not add a `Ready` status; do not reword AGENTS.md to map "Ready" → a column.
   Symmetric with Done: the Done _gate_ ("landed on `main` by fast-forward, CI
   green") is a predicate; the `Done` _column_ is where issues land once it holds.

2. **In Review means already merged — this is trunk-based.** Per
   https://trunkbaseddevelopment.com/ we review _after_ merge, before release, to
   avoid large divergence on `main`. Unreviewed code paths are kept out of
   released behavior by **feature flags**, never by withholding the merge. So a
   story reaching In Review has already landed to trunk; review gates the
   _release_, not the _merge_.

## How "pulled" becomes observable

The **In flight** view (`Project is Batten` AND `Status is any of {In Progress,
In Review}`) surfaces every pulled/landed story to everyone. It is correctly
configured — do not "fix" its filter. A story is invisible only if you started
work without moving Todo → In Progress; the fix is the discipline above, not the
view.

## Gate gap (honesty per non-negotiable rule 2)

This discipline is currently prose (feedforward), because the transitions are
Linear-side and Batten does not yet gate them. The computable version —
`In Progress ⇒ assignee != null`, `In Review ⇒ a landed PR exists` — is a Batten
roadmap predicate. Until it ships, hold the discipline manually.
