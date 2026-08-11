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
| Done            | released                                              | the change ships **and** `graph-check` accepts the issue — see the sweep ordering below.                                      |

## The In Review → Done sweep is a CONJUNCTION, and the order is fixed

Two gates, and neither alone is the transition (CLOUD-309):

- `graph-check` — "is this issue honestly labelled": In Review ⇒ a linked GitHub
  PR attachment. It runs **first**.
- `released <tag>` — "did this tag ship it": a ref in the tag's commit range, or a
  supplied commit the range contains (CLOUD-260).

`mise run released` now composes them: pipe the In Review closure and it runs
`graph-check` by path, reports any issue that gate names as `REFUSED (<rule>)`,
and exits 1. **Pipe `attachments`** — the key is what decides `in-review-no-pr`,
and a payload assembled without it cannot answer the question at all, so an In
Review issue missing the key is exit 2 ("could not look"), not a verdict.

Why the order exists: `released` resolves refs from commit _messages_, so an issue
a commit merely CITES reads as shipped. CLOUD-228 and CLOUD-231 were In Review
with `attachments: []`, bulk-flipped out of Todo eight seconds apart with nothing
ever landed, and `released` named both movable at `v0.0.29`. CLOUD-257's hold
marker cannot catch that shape — an author who never worked the issue has no
reason to add one. So there are two refusals now, covering opposite halves:
`HELD` is the issue that _says_ it is not done, `REFUSED` is the issue that never
started.

`dangling-blocker` is deliberately not a refusal: a sweep pipes the In Review
closure by design, so an edge leaving it is the expected input shape, not a board
lying.

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
identifier appearing in a branch name, PR title, or commit message — with no
write call from the session.

**But it is publish-side only, and an earlier version of this entry got that
wrong.** It claimed a commit carrying `Refs: CLOUD-178` moved that issue Todo ->
In Progress. Re-measured 2026-08-08 (CLOUD-230): a commit carrying `Refs:
CLOUD-37`, pushed at 04:33:18, moved nothing. The issue went In Progress at
04:35:08 — eight seconds after `gh pr create`, ~105 seconds after that push —
and was Done at 04:38:27. **The PR event is the trigger, not the keyed commit.**

So the automation issues a _receipt_ for work already written. It cannot reserve
anything, because at pull time nothing has been pushed and no key can travel.
**The pull-time claim is yours to make by hand** — move Todo -> In Progress and
assign yourself _before_ writing code. That is not the redundant hand-move
warned about below; the redundant one is the publish-side move the integration
already performs.

What it cost when nobody did: CLOUD-49 went In Progress at 04:29:34 and a second
session started writing it ~6 minutes later, having read the issue at startup
while it was still Todo and never re-read it. Both implementations were
complete; one was discarded. `mise run claim-check` is that re-read, with an
exit code (`not-todo` / `assigned` / `has-pr`), and `issue-guard` now refuses
`gh pr create` when another open PR already claims the key — the earliest
computable moment, since no artifact exists at pull time for a hook to inspect.

For the transitions the automation _does_ perform, an agent hand-moving the
board is doing work that is already automated, and doing it the fragile way. A state change is a tracker write, and a write can be
denied mid-session when the connector re-registers under a name no allow rule
matches (CLOUD-178) — which is exactly how a session lost the ability to update
the board for three landed PRs. An identifier in a commit travels in git, where
nothing can deny it.

`mise run issue-guard` is what guarantees the key exists: it denies `gh pr
create` and `gh pr ready` unless a `CLOUD-<n>` appears in the branch, a commit,
or the command.

### This applies to transitions ONLY — never to issue content

The caution above is about **state**: a column change, automated by the
integration and fragile to perform by hand. It says nothing about **content** —
acceptance criteria, a Ready block, a measurement, a recorded decision, a
deferred obligation. Nothing automates content, the Definition of Ready makes
authoring it the agent's job, and writing it is part of doing the work rather
than a permission-bearing act.

Conflating the two is a live failure mode, not a hypothetical: an agent read
"don't perform the transition" as "tracker writes need permission", stopped short
of an edit its own issue required, and asked (CLOUD-197). **Write content
freely; let the key move the state.**

The caution about transitions also has limits. When the automation demonstrably
has not fired — the merge side does not today — performing the move by hand is
correct, not a violation. The rule is that the board must be true, and an
automation that did not run is not an excuse for a board that is wrong.

Two things this does NOT cover, both observed rather than assumed:

- **The merge-side transition fires now, and it lands on Done — not In Review.**
  The older reading here (from #100 / CLOUD-178, where it did not fire at all)
  is superseded. Measured on CLOUD-61: merging #129 moved In Progress → Done,
  and merging #131 did it again from In Progress. **It is not keyword-gated** —
  an earlier version of this entry blamed `Closes CLOUD-<n>`, and #131 falsified
  that: its body said only "Follow-up to #129 (CLOUD-61)" with a `Refs:` trailer
  and the issue still completed on merge. Opening a PR drives the other
  direction: In Review → In Progress, measured two minutes after a hand-move.
  So **hand-moving to In Review does not stick** — the next PR event overwrites
  it, and re-doing the move is a fight with an automation that will win.

  What to do instead: let the automation land the issue on Done, then check
  whether Done is _truthful_ — the [dor-dod] gate is "released", and that is a
  computable question, not a judgement. `git tag --contains <sha>` (or `mise run
released`) answers it. On CLOUD-61 the answer made Done correct: cbe5228
  shipped in v0.0.19. Only a Done whose commit is in **no** tag is a board that
  is lying, and that is the case worth a hand-move.

- **Prefer the tracker's own branch name.** Each issue exposes a `gitBranchName`
  (`<user>/cloud-178-<slug>`); a branch named that way carries the key from the
  first push, before any commit message does.

- **The branch name is not one key source among three — it BEATS the others.**
  Re-measured 2026-08-09 (CLOUD-270). A branch named `claude/groom-cloud-35-*`
  carried a commit trailed `Refs: CLOUD-270` and a PR body naming CLOUD-270. On
  merge the integration moved **CLOUD-35** and left CLOUD-270 untouched, and
  attached the PR to CLOUD-35 as well. So "branch name, PR title, or commit
  message" reads as a precedence order, not a union: keying the commit and the
  body does NOT redirect the automation off a branch name that names something
  else. Rename the branch, or expect to hand-correct.

- **It does not guard on the source column, so it can resurrect a dead issue.**
  CLOUD-35 was **Canceled** when that merge landed, and the automation moved it
  to Done — a closed-out issue silently reappearing as completed work it never
  did. The earlier model here ("In Progress → Done") described the column it was
  observed leaving, not a precondition it checks.

- **Landing is not Done for a `ci` commit, and the automation cannot know that.**
  Done means released ([dor-dod]). A `ci`-typed commit releases nothing at any
  version, so its SHA is in no tag and Done would be a lie the moment the
  automation writes it; **In Review** is the truthful column until some later
  release sweeps the commit up. `git tag --contains <sha>` is the check, and an
  empty answer is the hand-move case this file already names.
