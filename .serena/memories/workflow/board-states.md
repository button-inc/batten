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

## The gate (was: gate gap)

The computable version of this discipline ships as `mise run graph-check`
(CLOUD-175): pipe the active columns' `get_issue(includeRelations: true)`
payloads and it enforces `In Progress ⇒ assignee != null` and `In Review ⇒ at
least one linked GitHub PR attachment` (the checkable approximation of "a
landed PR exists" — commit containment belongs to the In Review → Done release
transition), plus acyclic and non-dangling `blockedBy`, emitting the ready
frontier and WIP count as a by-product. What remains manual is only the
_fetch_: no tracker credential exists, so an agent pipes the board in; the
verdict is the gate's alone. Attach every landed PR to its issue — the
attachment is what makes the In Review predicate true.

## The board moves itself — supply the key, don't perform the transition

The tracker's GitHub integration performs the state transitions from the issue
identifier appearing in a branch name, PR title, or commit message. Measured
here: a commit carrying `Refs: CLOUD-178` moved that issue Todo -> In Progress,
set its assignee, and attached the PR, with no write call from the session.

So an agent hand-moving the board is doing work that is already automated, and
doing it the fragile way. A state change is a tracker write, and a write can be
denied mid-session when the connector re-registers under a name no allow rule
matches (CLOUD-178) — which is exactly how a session lost the ability to update
the board for three landed PRs. An identifier in a commit travels in git, where
nothing can deny it.

`mise run issue-guard` is what guarantees the key exists: it denies `gh pr
create` and `gh pr ready` unless a `CLOUD-<n>` appears in the branch, a commit,
or the command.

Two things this does NOT cover, both observed rather than assumed:

- **The merge-side transition did not fire.** #100 merged and CLOUD-178 stayed
  In Progress; its state history shows only the one transition. Landing still
  needs checking, and In Review / Done may need configuring on the integration
  side before that half can be trusted.
- **Prefer the tracker's own branch name.** Each issue exposes a `gitBranchName`
  (`<user>/cloud-178-<slug>`); a branch named that way carries the key from the
  first push, before any commit message does.
