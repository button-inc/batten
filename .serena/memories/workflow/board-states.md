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
| **In Review**   | landed to trunk, under post-merge review, pre-release | the change is on `main` — the merge writes it **iff the PR body closes the key** (CLOUD-192).                                 |
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
payloads and it enforces `In Progress ⇒ assignee != null`, `In Review ⇒ at
least one linked GitHub PR attachment` (the checkable approximation of "a
landed PR exists" — commit containment belongs to the In Review → Done release
transition) and `Todo ⇒ ready-lint exits 0` (`todo-not-ready`, CLOUD-375 — the
ready queue is a column claim of the same kind, and an unready issue sitting in
it was a `board coherent` verdict until that landed), plus acyclic and
non-dangling `blockedBy`, emitting the ready
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

- **The merge-side transition fires, and it now lands on In Review.** Two
  readings here are superseded, in order, and the sequence is the useful part.
  First it did not fire at all (#100 / CLOUD-178). Then it fired and **overshot
  to Done** — measured on CLOUD-61, and again on CLOUD-499, whose history reads
  `Todo → In Progress → Done` with Done set at merge time while `main` stood 50
  commits past `v0.0.62`. **It is not keyword-gated**: an earlier version blamed
  `Closes CLOUD-<n>`, and #131 falsified that — a `Refs:` trailer completed the
  issue just the same.

  CLOUD-192 changed the setting — the integration's **merged** event now maps to
  In Review rather than Done — and then measured what that setting alone buys.
  **The answer is nothing, unless the PR CLOSES its issue.** A controlled pair on
  one issue, same repo, same branch name, same fast-forward landing, one
  variable:

  | PR   | body says          | merged     | In Review at    |
  | ---- | ------------------ | ---------- | --------------- |
  | #398 | `Refs: CLOUD-192`  | `06:27:05` | never           |
  | #400 | `Closes CLOUD-192` | `06:59:39` | `06:59:41` (2s) |

  So Linear's **closing vs contributing** split is what decides it: a
  contributing PR links and attaches and drives no status. Three other
  explanations were ruled out by measurement rather than argument — the key
  travelled (the attachment resolved to the issue), the setting persisted (the
  page was re-read _after_ the merge), and GitHub reports `MERGED` with
  `mergedAt`, so a fast-forward landing is not invisible.

  **This also retires the `#131` counter-example** that stood here — a
  `Refs:`-only PR completing on merge does not reproduce, and it was measured
  against the old `Done` mapping.

  **Write `Closes <key>` in the PR body**, and `closing-key-check` refuses a body
  that names its issue without it. Every PR here named its issue and none closed
  it, because `issue-guard` requires the key and nothing required the form — the
  convention was satisfied and the outcome still wrong. Use `DO-NOT-CLOSE` when a
  PR deliberately does not complete its issue, which under trunk-based
  development is the several-PRs-per-issue case (CLOUD-186); closing on the first
  landing is CLOUD-468's defect.

  So the path is `In Progress → In Review → Done`: the first leg is the merge's,
  once the body closes the key, and **the last leg is yours.** Done has exactly
  one source, a release, and nothing automates that leg
  either — the integration triggers on PR events, and "a tag now contains this
  commit" is not one, so no setting reaches it. `released <tag>` names what a
  release promoted (the `release-plz` run summary prints it); `done-check`
  refuses a Done that shipped in nothing.

- **`done-check` is the gate on that last leg** (CLOUD-192). Pipe the Done
  closure and it refuses any Done that no `v*` tag reaches: `CLOUD-N Done -> In
Review`, exit 1. It is `landed-check`'s terminal twin — both name In Review
  from opposite sides, one for a board behind git, one for a board ahead of the
  release — and it composes with `released` running the other way.

  **It only ever refutes a Done, never confirms one**, and the asymmetry is
  deliberate: refs are resolved from commit messages, so a ref inside a tag is
  weak evidence (a commit can cite or defer), while a ref nowhere near a tag is
  conclusive. Two things it therefore stays quiet about — an issue whose work
  half-landed and half-shipped (CLOUD-468's question), and a Done no commit
  names at all, which it reports as `unlanded` and does not fail on.

  Both preconditions are exit 2, and they fail in opposite directions: no
  `origin/main` makes every Done look unlanded (false green), no tags makes
  every Done look unreleased (false red). A default CI checkout fetches no tags,
  so the second is the ordinary way to meet it — a board that looks entirely
  broken there has not been judged, it has failed to be looked at.

- **Prefer the tracker's own branch name.** Each issue exposes a `gitBranchName`
  (`<user>/cloud-178-<slug>`); a branch named that way carries the key from the
  first push, before any commit message does.

- **A branch naming a DIFFERENT issue beats the other key sources.**
  Re-measured 2026-08-09 (CLOUD-270). A branch named `claude/groom-cloud-35-*`
  carried a commit trailed `Refs: CLOUD-270` and a PR body naming CLOUD-270. On
  merge the integration moved **CLOUD-35** and left CLOUD-270 untouched, and
  attached the PR to CLOUD-35 as well. So "branch name, PR title, or commit
  message" reads as a precedence order, not a union: keying the commit and the
  body does NOT redirect the automation off a branch name that names something
  else. Rename the branch, or expect to hand-correct.

  **Scope it to what was measured: a branch naming a different key. A branch
  naming NO key is not that case** — precedence has nothing to rank, so the
  commit trailer carries it and the automation lands on the right issue.
  `issue-guard` already accepts the key in the branch, a commit, **or** the
  command, so the mechanism never required the branch to carry it.

  This is worth stating because the unconditional wording cost a session a
  blocking question (CLOUD-509): its harness pinned it to a keyless branch,
  which this entry appeared to forbid, and it stopped to ask about a conflict
  that did not exist. A rule generalised past its measurement reads as a
  prohibition, and the reader cannot tell which part was observed. When a
  measured precedence is written down, write the condition it was measured
  under.

- **It does not guard on the source column, so it can resurrect a dead issue.**
  CLOUD-35 was **Canceled** when that merge landed, and the automation moved it
  to Done — a closed-out issue silently reappearing as completed work it never
  did. The earlier model here ("In Progress → Done") described the column it was
  observed leaving, not a precondition it checks.

- **Landing is not Done for a commit that cuts no release, and the automation
  cannot know that.** Done means released ([dor-dod]). A commit that bumps no
  version is in no tag, so Done would be a lie the moment anything writes it;
  **In Review** is the truthful column until some later release sweeps the
  commit up — which is why the merged event maps there and stops. `done-check`
  is the check, over the whole board rather than one sha at a time; `git tag
--contains <sha>` answers the single case by hand.

  **The commit TYPE is not the predictor — the PATH is.** An earlier version of
  this entry said "a `ci`-typed commit releases nothing", which reads as though
  `fix`/`feat` always release. They do not: release-plz versions the _package_,
  so a commit touching nothing under `crates/` leaves it "already up to date"
  whatever its type. Measured on `3fc2785` (`fix(released)`, zero crate files):
  release-plz ran green and cut no release. Four earlier task-layer `fix`
  commits — `6796f61`, `6ec6c4c`, `508fcad`, `fb00a57` — behaved identically and
  all reached a tag only by being swept into `v0.0.37`. Since the whole
  `mise-tasks/` layer sits outside the crate, this is the ordinary case for gate
  work, not an edge one.

  **And a crate-touching commit no longer tags promptly either (CLOUD-319).**
  The release PR used to land the instant its CI went green, so every such commit
  shipped its own tag within minutes. `auto-release-land` now gates that automated
  `/fast-forward` on `mise run release-due`: the PR lands once `main` has been
  quiet for 30 minutes (`RELEASE_QUIET_MINUTES`) or the last release is 24h old
  (`RELEASE_MAX_WAIT_HOURS`), whichever comes first, and a half-hourly cron is
  what asks. So **In Review is the truthful column for longer**, by design — a
  batch is accumulating in the open release PR, and one tag sweeps all of it.
  Nothing about the sweep changes; what changes is that "landed, not yet tagged"
  is the ordinary state for up to a day rather than a few minutes. A maintainer
  commenting `/fast-forward` on the release PR still lands it immediately.
