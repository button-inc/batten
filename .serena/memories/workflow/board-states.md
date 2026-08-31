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

### The two gates are still not enough, and the third leg is a READ, not a re-run

Both gates above answer questions about the _board_ and the _commit graph_. Neither
asks whether the work the row demanded exists. `released`'s own header says so:
**shipping a ref is necessary for Done, not sufficient** — refs resolve from commit
MESSAGES, so a commit can cite, document or defer an issue without implementing it.

So a promotion is a four-part conjunction:

1. `released "$TAG" </dev/null` — a tag's range names the ref
2. `graph-check` — the board labels the row honestly
3. **acceptance-read against the released tree** — every Acceptance clause resolves
   to a mechanism that actually exists
4. **MUTANT-directive presence** where the row declares one

**A per-row suite re-run is NOT one of them**, and the reason is measured rather than
argued. `policy.rs` claimed `no_evaluator_feature_admits_io` at `1a5ab50`
(2026-08-21T03:30); the test first existed at `6b33388`, 6h45m later:

```
v0.0.97  claim=yes  test=no
v0.0.98  claim=yes  test=no
v0.0.99  claim=yes  test=yes
```

**Two releases shipped the crate's central security claim citing a test that did not
exist**, with the suite green throughout. A re-run reports green and says nothing; a
grep for the named test catches it in one second. That is the same class as
CLOUD-807's original false Done — `retires_with` absent, the waiver intact, 0 of 141
`# subject:` headers, marked Done. **The defect this sweep exists to prevent is the
one only an acceptance-read catches**, because you cannot run a test nobody wrote.

The re-run's one unique catch — a test that exists and fails — is covered by **one**
suite run at HEAD for the whole sweep. The suite is shared; N per-row runs are the
same evidence N times.

Two bounds, so this is not read as complete. A green suite does not establish that a
test discriminates (CLOUD-418's class — leg 4 is the partial answer). And a suite
verdict is a property of the whole tree **including base you did not author**:
measured 2026-08-22, `tests/land.bats:1310` failed inside a full parallel `verify` on
a speculatively linearized tree and passed in isolation on the same content
(CLOUD-466). That is why the HEAD run is a sweep-level check and never per-row
evidence.

A row whose acceptance does not fully resolve **stays In Review with the shortfall
recorded on it.** Promoting it anyway is the exact defect above, reproduced by hand.

### When a row's prose prescribes a repair, its own Acceptance overrules the prose

An acceptance-read is usually run against the tree. Run it against the row's **own
prescriptive prose** too, because the two can disagree and the prose is the half
that gets followed.

Measured 2026-08-22 on CLOUD-858. Its diagnosis section prescribed, for CLOUD-134,
_"converging the dialect is what would make that visible"_ — convert a retired Ready
dialect to the canonical one so `ready-lint` can read it. Executed literally that
produces a block which PASSES the gate. But CLOUD-134's own Decision section says
_"Gate on a named first consumer being concrete"_, and no consumer is named — so the
passing block would have certified an unmet precondition. CLOUD-858's own last
acceptance bullet forbids exactly that: _"a row that genuinely has open questions
leaves the ready queue rather than acquiring a Ready block that papers over them."_

The prescription and the acceptance were in the same body, four paragraphs apart,
and only one of them was wrong. The repair that satisfies both is to converge the
dialect **and** leave the queue — a Ready block that declares the open question,
in Backlog.

Why this recurs rather than being one author's slip: a diagnosis is written while
reading the defect, and an Acceptance while imagining the finished state. Nothing
compares them, and `ready-lint` cannot — it decides a block's clauses against each
other, never a body's prose against its own acceptance. So the check is manual and
cheap: **before executing a prescription a row hands you, read that row's Acceptance
and ask whether the prescribed result satisfies it.** Where they conflict, the
Acceptance is the specification and the prescription is a note.

The tell that you are in this case: the prescription names a mechanical edit
("converge", "rename", "add the label") and the Acceptance names a property
("does not paper over", "no scope moves"). A mechanical edit can always be
performed; whether it produces the property is the question the edit does not ask.

## Three things that trip agents up

0. **A row's STATE decides whether its body is a spec or a record — so it decides
   whether you fix the row or file a new one.** This follows from the table above,
   and nothing here used to say it.

   | state                   | the body is                                                         | a wrong design is fixed by                                                 |
   | ----------------------- | ------------------------------------------------------------------- | -------------------------------------------------------------------------- |
   | Backlog, **Todo**       | a **spec** — nothing has been built from it                         | **editing the row in place.** Correct it fully; that is what grooming is   |
   | In Progress             | a spec somebody is executing                                        | editing, but tell the assignee — they may already have built from it       |
   | **In Review**, **Done** | a **record** — the code is on `main` (In Review) or released (Done) | **a NEW row**, with a superseded reference on the old one. Never a rewrite |

   The cut is **landed-ness, not readership.** In Review means already merged (item
   2 below), so its body describes shipped behaviour: rewriting it makes the record
   disagree with the code, and the disagreement is invisible. A Todo row has shipped
   nothing, so its body is still the only statement of intent, and editing it is the
   whole point of the ready queue.

   **The failure mode is treating a Todo row as untouchable.** Measured on CLOUD-1152
   (Urgent, Todo, unclaimed, 2026-08-30): a session found its central premise false,
   declined to correct it, and planned a spin-off row plus a supersede note —
   inventing a second authority over a design nothing had built yet, and leaving the
   ready queue holding the wrong spec. It reached for that shape twice before the
   rule was stated. The opposite error is the more familiar one and is already
   covered by the CLOUD-994 class: quietly rewriting a shipped row so the record
   matches whatever got built.

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
exit code (`not-todo` / `assigned` / `has-pr`), and `claim-race-check` refuses
`verify` when another open PR already claims the key. That is later than the `gh
pr create` the retired `issue-guard` fired on, and later still than pull time,
which is what this wanted: the predicate needs a network call, and no rule kind
can make one on a mediated call (CLOUD-446). `verify` is the earliest surface
that still sits on every path to a published PR.

**`claim-check` runs BEFORE the board move, not after — and the order is not
interchangeable.** It refuses `not-todo`, so once the issue is In Progress it
refuses the very claim you just made, and it cannot tell your own move from a
competitor's: every agent authenticates as the same tracker user, which is why
`assigned` deliberately does not say "assigned to someone else". Measured
2026-08-19 on CLOUD-697 — the board was moved first, `claim-check` then answered
`not-todo (in In Progress)`, and the receipt `verify` demands could only be
minted with `BATTEN_CLAIM_TAKEOVER=1`, which records the refusal it overrode.
That is the right escape once you are in the hole (reverting the column to fake
a clean transition history would be worse), but the hole is avoidable: pipe the
Todo payload, get the receipt, then write the state. Sequence: `claim-check` →
board move → code.

**And it happened anyway, one hatch further along — measured 2026-08-19 on
CLOUD-430.** A session claimed over a `claim-check` refusal whose only rule was
`assigned`, built the whole ticket, and found on its first rebase that another
session had landed the same mechanism 31 minutes later (`03d4fa6`, PR #519). Full
duplicate, discarded unpushed. The override was argued from three facts, all
true: `Todo` with no In Progress in the state history, no attached PR, and no
remote branch or open PR on GitHub naming the key.

**Every one of those is a statement about what a competitor has PUBLISHED, and
during the window a claim exists to cover, a competitor has published nothing** —
the one here was ~30 minutes from its first push. So the three signals that look
like evidence of an empty field are blind precisely when it matters, and
`assigned` was the only rule that could see anything. Read with the paragraph
above: its ambiguity is a reason to treat the row as **occupied**, not a reason
to discount it. A board-hygiene story ("some rows just carry the owner's name")
fits the noise reading and the true one equally well, which makes it an argument
for whichever answer you already wanted.

**So `BATTEN_CLAIM_TAKEOVER` is for a branch, not for a doubt.** Above it is the
right escape from a board already moved; its other sanctioned case is the
resumed branch in a fresh container, whose receipt is stranded under a `.git/`
that no longer exists. Where there is no branch to resume and no move to undo, a
takeover is the refusal being reasoned around. The cost is one session's build
plus whatever the duplicate wrote elsewhere from its own vantage point (here: a
wrong diagnosis posted on CLOUD-412, corrected after the fact).

For the transitions the automation _does_ perform, an agent hand-moving the
board is doing work that is already automated, and doing it the fragile way. A state change is a tracker write, and a write can be
denied mid-session when the connector re-registers under a name no allow rule
matches (CLOUD-178) — which is exactly how a session lost the ability to update
the board for three landed PRs. An identifier in a commit travels in git, where
nothing can deny it.

The **engine** is what guarantees the key exists (CLOUD-446): `batten.toml`'s
`pr-names-an-issue` and `ready-names-an-issue` rows deny `gh pr create` and `gh
pr ready` unless a `CLOUD-<n>` appears in the branch, a commit on
`origin/main..HEAD`, or the command itself. Any one of the three allows, and a
call the hook cannot read a checkout for allows too. What no longer counts is a
key that appears ONLY in a PR body typed by hand — the port dropped the `gh pr
view` read, because a network call cannot fit the mediated path's latency
budget. The duplicate-claim half is `claim-race-check`, a `tree`-scoped
`command` row (`claim-not-raced`) that `batten check` runs under `verify`; it
refuses a key already claimed by a different open PR, and `mise-tasks/issue-guard.sh`
is deleted.

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
  it, because the key rule requires the key and nothing required the form — the
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

- **A ROW THAT LANDS NO COMMIT DECLARES SO IN §6, AND THAT IS WHAT LETS IT LEAVE
  In Progress** (CLOUD-735). Both gates out of that column key on artifacts a
  commitless row can never produce: `graph-check` wants an In Review row to carry
  a linked PR, and `done-check` refuses a Done no `v*` tag reaches. A dispatch
  record's deliverable is a `create_session` per bundle and a board state, so it
  opens no PR and lands no commit — it can be pulled and never put down. Three sat
  In Progress with their campaigns finished (CLOUD-607, 632, 703), each
  indistinguishable on the board from work somebody abandoned, which is the
  false-signal class the column discipline exists to catch.

  The declaration is the one §6 already carries. `ready-lint` accepts `none` as an
  explicit answer — a tracker-only change lands no commit, and demanding a type
  there would force a lie — so **`**Commit / bump (§6).\*\* **none**`is what makes a
row exempt from`in-review-no-pr`.** No new vocabulary, no fourth authority:
`ready-lint`emits what it parsed and`graph-check` reads that fact, because the
  §6 grammar is subtle enough (CLOUD-290's whole-code-span anchoring, found by
  experiment) that a second reading of it would drift.

  **The exemption is a declaration, never a default, and it costs something to
  claim.** A row declaring `none` that carries a PR anyway is refused as
  `declares-no-commit-with-pr` — otherwise `none` becomes the cheapest way past
  the gate for any row at all, which is the roster cheat CLOUD-607 names one layer
  over. A row that says nothing about §6 is judged exactly as before.

  **What this does NOT decide is whether the campaign finished.** The exemption
  reads one clause of one body; it makes no claim about the bundles a dispatch
  record dispatched. `graph-check` reads `blockedBy` and a record's bundles are
  `relatedTo`, which is not a dependency edge — so "every bundle landed" is not
  computable there without inventing a fourth reading of what a campaign is. Check
  the bundles by hand before moving such a row, as CLOUD-735's acceptance asks.

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
  The key gate already accepts the key in the branch, a commit, **or** the
  command, so the mechanism never required the branch to carry it.

  This is worth stating because the unconditional wording cost a session a
  blocking question (CLOUD-509): its harness pinned it to a keyless branch,
  which this entry appeared to forbid, and it stopped to ask about a conflict
  that did not exist. A rule generalised past its measurement reads as a
  prohibition, and the reader cannot tell which part was observed. When a
  measured precedence is written down, write the condition it was measured
  under.

  **And the condition turns out to be the one that decides it: `Closes` BEATS
  the branch name, while `Refs:` does not.** Measured 2026-08-21 on CLOUD-860.
  Branch `claude/groom-cloud-847-tfh0or` — naming a different, already-In-Review
  row — carried PR #635 whose body read `Closes CLOUD-860`. On merge the
  integration moved **CLOUD-860** to In Review and attached #635 to it, two
  seconds after the merge. The branch name lost.

  Read against CLOUD-270 above, whose PR body merely NAMED its issue, the two
  measurements agree on one rule rather than conflicting: this is CLOUD-192's
  closing-versus-contributing split outranking the branch, not a precedence
  order among equals. A CLOSING key redirects the automation; a contributing
  mention does not, and a branch name outranks the mention alone.

  So the practical guidance narrows rather than reverses. A branch naming
  another key is safe **iff** the body closes the key you mean; without a
  closing key it still lands on the branch's issue. A session that predicted a
  hand-correction here from the older wording wrote the prediction twice before
  the board falsified it.

- **"The branch name lost" was measured on one row and read as a contest. It is
  not one: EVERY key a PR carries moves, and every one collects the
  attachment.** The entry above is right that a `Closes` key is what redirects
  _completion_; it is wrong to conclude the branch's own row sat still. Both
  rows moved, on both events, on both PRs — re-read from the board 2026-08-22,
  from the same two PRs the entry above cites.

  | event             | PR (branch names CLOUD-847) | body                              | CLOUD-847                | CLOUD-860                    |
  | ----------------- | --------------------------- | --------------------------------- | ------------------------ | ---------------------------- |
  | opened `22:22:19` | #635                        | `Closes CLOUD-860`                | → In Progress `22:22:22` | (claimed by hand `22:21:49`) |
  | merged `23:24:33` | #635                        | "                                 | → In Review `23:24:35`   | → In Review `23:24:35`       |
  | opened `23:26:18` | #639                        | `DO-NOT-CLOSE`, `Refs: CLOUD-860` | → In Progress `23:26:21` | → In Progress `23:26:21`     |
  | merged `00:27:23` | #639                        | "                                 | → In Review `00:27:26`   | → In Review `00:27:26`       |

  Three things follow, and the third is the one that costs something.

  **Attachment is a UNION, not a winner.** #635 and #639 are each attached to
  both rows. So the starvation shape CLOUD-847's arm I predicted — a row ending
  In Review with no PR attached while an unrelated row hoards PRs it did not
  produce, which is exactly what `graph-check`'s `in-review-no-pr` refuses —
  **does not reproduce.** Do not re-derive that fear from the precedence entry
  above; it is about state, and attachment does not behave like state.

  **`DO-NOT-CLOSE` stops `closing-key-check`, not the board.** #639 declared it,
  closed nothing, and still moved two rows twice. It is an exemption from the
  body convention, never a hold on the automation — a PR deliberately not
  completing its row should expect the row to move anyway, and check.

  **A PR opening drags a linked row BACKWARDS.** #639 knocked CLOUD-860 out of
  In Review, where #635 had just landed it, back to In Progress — a row losing
  ground to a PR that was not its work. `landed-check` names a board behind git
  and is the gate that catches this; the fix is a hand-move forward, and the
  avoidance is not to mention a settled row in a body that is about to open a PR.

  What this does NOT overturn is the completion half. `Refs:` still does not
  _close_ (#398 vs #400 above stands, and no row here reached Done). The
  unresolved tension is narrower than it looks: #398's `Refs:`-only body moved
  nothing at all, while #639's moved two rows to In Review. The discriminating
  variable is untested — likeliest that #398 predates the merged→In Review
  mapping's effect on merely-linked rows. Whoever next needs it should measure a
  `Refs:`-only PR against a row in Todo, and write the condition down.

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
  quiet for `RELEASE_QUIET_MINUTES` or the last release is older than
  `RELEASE_MAX_WAIT_HOURS`, whichever comes first, and a cron is what asks.
  `mise-tasks/release-due.sh` owns both windows; read them there rather than here
  (CLOUD-770). So **In Review is the truthful column for longer**, by design — a
  batch is accumulating in the open release PR, and one tag sweeps all of it.
  Nothing about the sweep changes; what changes is that "landed, not yet tagged"
  is the ordinary state for up to a day rather than a few minutes. A maintainer
  commenting `/fast-forward` on the release PR still lands it immediately.
