# Fan-out: one planner, N implementers, the board as the only coordinator

Read when: running more than one agent session against this repo at once, or
deciding whether to. The gates this protocol leans on are `mise run ready-lint`
and `mise run graph-check` (CLOUD-179, CLOUD-175); the board model is
`mem:workflow/board-states`.

## READ FIRST: you cannot open the sessions. `create_session` is blocked upstream.

**Every parameter this memory documents for `create_session` — permission mode,
effort, title, tags — is accurate and unusable, because the call itself is
refused.** It returns `MCP tool call requires approval`, in every session, with
no human to approve it. Do not probe it "to see if it works now". Do not add an
allow rule. Do not send anyone to a settings screen.

Why, sourced rather than re-derived
([#76264](https://github.com/anthropics/claude-code/issues/76264),
[#61044](https://github.com/anthropics/claude-code/issues/61044),
[#61097](https://github.com/anthropics/claude-code/issues/61097); full detail and
the recognisable tell in `mem:connector-allowlist-recovery`'s STOP section): the
session-management tools carry a **mandatory-approval flag** — _"requires
explicit approval regardless of permission mode"_ — and all three escapes are
documented as tested and failing (`bypassPermissions`, an explicit
`permissions.allow` entry for the exact tool name, and a `PreToolUse` hook
returning allow). A second upstream defect has the CCR proxy refusing
server-side, before the permission layer is reached.

**The governing principle, and the reason this keeps recurring:** the refusal is
the REMOTE's behaviour, and **we can only change our harness.** Every attempt so
far has tried to change the remote's mind — a grant, a translation, a
bypass — and every one of them is a documented dead end. Design around it
instead.

**So the fleet is dispatched BY HAND**, and that is settled rather than a
workaround to re-litigate: `CLOUD-731`, `CLOUD-784`, `CLOUD-839` are the
precedents. **What an agent produces is the prompts, not the sessions.**

**Write them BOTH places, and this is not a style point — getting it wrong
withholds the deliverable.** The board is where they must persist, because chat
dies with the container. **Chat is where they must appear, because that is the
only surface the human can paste from.** A prompt that exists only in a Linear
row is not delivered: the human would have to go open the row, find it, and copy
it out of rendered markdown. Measured 2026-08-21 — an earlier version of this
paragraph said "never into chat", and the session followed it, wrote the prompts
to the row, told the user they were dispatch-ready, and delivered nothing the
user could use. They asked for them in chat four separate times.

So: **fenced code blocks in the reply, one per bundle, complete and
self-contained**, and the same text appended to the dispatch row. Do not
summarise the prompt in chat and point at the row for the full text; the
paste has to be the thing in front of them.

**Two consequences of hand dispatch that bite, both measured:**

- `get_session` is blocked too, so a child's `permission_mode` cannot be read
  back after it starts. CLOUD-728 measured the cost: five bundles came up
  `default` instead of the intended mode and ran to landed unsupervised. Whoever
  opens the sessions confirms the mode in the UI; no agent can confirm it for
  them.
- The mode is **not inherited** from the pasting session in the way the
  parameter docs below imply. Read that section for what the values do, not for
  what a dispatcher can rely on.

Re-open this only from a changelog entry or a reply on those upstream issues.

## Shape

One **planner** session keeps the ready queue full; N **implementer** sessions
drain it, each in its own sandboxed environment with its own clone. No agent
talks to another agent, and there is no dispatcher: the planner never assigns
work, it only makes work _claimable_. Coordination is entirely board state.

- **Claiming is a single write**: Todo → In Progress + assign yourself in the
  same `save_issue` call, then read back; if the assignee isn't you, you lost
  the race — write **nothing** (nulling the winner's assignee would clobber the
  claim) and take the next frontier issue.
- **The frontier is computed, never guessed**: pipe the active columns'
  `get_issue(includeRelations: true)` payloads to `mise run graph-check`. Every
  session computing it independently gets the same answer; that shared
  determinism is what replaces a dispatcher.
- **Ready-block edits go through anchored `patch` ops only** — a whole-
  description overwrite is last-write-wins and discards Linear's concurrency
  protection.

## The brief is gated, not described

A fan-out is only as good as what travels in the brief, and the facts that do not
inherit — which identifiers, which scope, what binds inside it, what has already
been read, and the deterministic check to run — used to live here as prose. They
now live as data in `brief::SCHEMA`, gated by **`batten lint brief <path>`** (or
stdin), exit `2` on a missing section and on a `check` section carrying no
runnable command (CLOUD-84). Lint the brief before dispatching it; this file does
not restate the set, because a requirement stated twice drifts.

## The planner's ladder

1. Re-check issues whose open questions were answered — a human answer is the
   highest-value work available.
2. Ready depth low? Groom the next Backlog issue until `ready-lint` exits 0,
   then promote. Groom-first, not build-first: a fleet that only grooms when
   starved is one cycle too late.
3. Otherwise reconcile: re-derive the graph from what landed; propose (never
   silently apply) edge corrections.

## Questions are artifacts, not blocking states

A genuine ambiguity is written onto the issue (`**Open questions blocking
Ready:**` — `ready-lint` refuses to promote past it), and the agent moves to
the next issue. **The issue blocks; the loop does not.** Ration questions: ask
only when the answer changes the acceptance criteria; otherwise state the
assumption in the block and flag it. If every issue accumulates a question,
say so loudly — the human is the bottleneck and silence hides it.

## Caps, and what actually bounds N

Build WIP cap: **6**, enforced at claim time, re-checked after claiming (on an
overshoot the holder of the lexically-highest id yields).

**Set to 6 by the owner, 2026-08-14, superseding the 2 this file carried.** That
2 was never an owner decision — it was written here alongside the land-contention
model below and then read back by every later session (and by CLOUD-607) as though
it were one, which is how a number nobody approved becomes a standing constraint.
The measurement below is unaffected and is NOT the cap: N ≈ 2.9 prices _land
contention_, and the lever that measurement argues for is still "serialise the
landing, shorten the lap, quiet `main`". The cap is a separate, owner-set bound on
how many implementers may hold a claim at once, and the two must not be conflated
again — if the arithmetic below argues for a different number, that is an argument
to bring to the owner, not a licence to edit this one.

Past the cap the binding constraint is **land contention**, not compute: every
land forces siblings to rebase and re-run `verify`, so N ≈ time-between-lands ÷
verify-duration. **A rising re-verify rate is NOT the stop signal** — an
earlier version of this file said it was, and that optimises against the wrong
cost. `land` laps unattended: a fast-forward refusal rebases and re-verifies
with no model turn, so a moved base costs CPU and wall-clock, both of which are
free here, and zero tokens. Re-verifying is the loop working.

What actually costs is narrower, and each has its own control:

| Cost                                  | Control                                                    |
| ------------------------------------- | ---------------------------------------------------------- |
| a rebase **conflict** (needs a human) | file-domain partitioning of bundles                        |
| **CI minutes** on a run `main` voids  | draft until plausibly next; `main-watch` cancels in flight |
| **tokens**                            | bundles, and `land` lapping without returning to the model |

So the objective is pace of landed work per token, not collision avoidance.
Coordination between sessions is impossible by construction — there is no
dispatcher and no lock — so collisions are designed for rather than prevented,
in the CSMA/CD sense: detect, back off, retry, keep the medium saturated. The
target state is that **every time a merge lands, at least one sibling is already
rebased, verified and ready to go in behind it**.

Shortening `verify` still helps, but as latency to that ready state, not as
headroom for more sessions. There is deliberately no
cap on In Review: in a fast-forward trunk nothing queues there.

**Measured 2026-08-11, and the model held.** Over three hours `main` took 25
commits — mean gap **487s** — against a `verify` of **~170s**, so N ≈ **2.9**
with the cap at 2: at the ceiling. The symptom at that point is not a stall but
a cost: a lap is `verify` + CI + the fast-forward wait, roughly 5–7 minutes
against an 8.1-minute mean gap, so each lap is near a coin flip and PRs landed
in 8, 3, 4 and 2 laps. Nothing is broken when this happens — `main-watch`
already polls conditionally (a 304 is free), and a `main` that moves mid-CI
cancels the doomed run through `concurrency: cancel-in-progress`, which is the
cheap direction. **5 of those 25 commits were release-plz `chore: release`**, so
each landed change was producing about two commits on `main`; CLOUD-319's
debounce targets exactly that amplifier. The lever remains the one stated above:
shorten `verify`, do not add sessions.

**Re-measured three hours later, and the model no longer held — a lap now LOSES
by arithmetic, not by coin flip.** Over `main`'s ten commits to 21:09Z the mean
gap was **436s**, down from 487s, while a full lap is `verify` (~200s) + CI
(~5–6 min) + the fast-forward wait — call it 8–10 minutes against a 7.3-minute
gap. CLOUD-122 lost **16 consecutive laps** across two `mise run land`
invocations, every one of them green on CI. Nothing was broken and no change was
at fault; the loop simply cannot converge while the gap is under a lap.

Two distinct lap-loss shapes showed up, and only one is the documented one:

- **main moved before CI finished** (3 of 16) — the void-the-verdict case
  `ci-wait`/`main-watch` race for on purpose. Cheap, cancels early.
- **CI green, `/fast-forward` posted, the bot then SILENT while main moved**
  (5 of 16, and the majority of the laps that got that far). `land` infers a
  refusal from main moving rather than from the bot answering, so this reads in
  the log as a refusal that never happened. The bot is not rejecting the
  fast-forward; it is slower than `main`.

**A third shape, measured on CLOUD-206 the same evening: the bot ANSWERS, with a 403.** Across two more `land` invocations (16 further laps, every one green on
CI) lap 7 of the second carried a real refusal body — `API rate limit exceeded
for user ID 597920`, the _bot's_ credential, not the session's, whose own
`rate_limit` read 4900/5000 remaining at the time. So "the bot was silent" and
"the bot is slower than `main`" do not cover the space: under sustained fleet
landing the fast-forward bot can exhaust its own hourly budget, and then no
amount of lapping can win because the refusal is unconditional until its reset.
Distinguishing them costs nothing — the refusal body is already in `land`'s log —
and it matters because the two have opposite responses: slowness argues for
shortening the lap, a 403 argues for waiting out the reset.

That second shape is what makes the ceiling bite sooner than the N ≈ 2.9 model
predicts: the model prices a lap at verify + CI, and the bot's silence is a third
term nobody measured. Raising `LAND_MAX_LAPS` (the task's own documented bound)
buys more attempts within one invocation but does not change the per-lap odds —
it spends CI minutes against a losing bet.

**Then the bot was measured, and it is not the term. Superseded 2026-08-11
22:01Z (CLOUD-399).** Over `fast-forward.yml`'s full available history — **400
runs, 21:31→22:01Z**, 248 executed, 152 skipped by the `author_association` gate
— the bot answered **every** attempt: dispatch lag 0s, answer time median
**12s**, **max 23s**. It is never slow. And it is not silent: **243 of the 248
concluded `failure`**, the failing step being `sequoia-pgp/fast-forward` itself —
real "not a fast-forward" refusals against a branch that had gone behind.

So "the bot is not rejecting the fast-forward; it is slower than `main`" above is
**wrong**. The reading it came from is explained by a second defect (CLOUD-409):
`land` picks its refusal verdict out of an unfiltered 20-run window, which at 13
runs/minute is ~90s of history containing every PR's refusals — so a lap cannot
reliably tell its own verdict from a stranger's, and the log stops being evidence.

The measured shape is a **thundering herd**: 248 landing attempts in 30 minutes
producing **5 merges**, a ~2% per-attempt success rate. That falsifies — rather
than merely argues with — "in a fast-forward trunk nothing queues there" above.
The queue already exists; it is implemented as 243 discarded CI matrices per half
hour instead of as a lease, which is the expensive way to have one. Shortening the
lap is still worth doing and is no longer sufficient: at 2% per attempt, halving
`L` does not converge. CLOUD-393 builds the lease; **the lever is now: serialise
the landing, shorten the lap, quiet `main` — never add sessions.**

One term that measurement prices too high, from a second branch lapping the same
window (CLOUD-68): **the lap gets cheaper as it goes.** Cargo caches warm across
laps, so `verify` fell from ~240s on lap 1 to **86s** by lap 8 — a lap of ~10
minutes becoming ~7.5 against the same 7.3-minute gap. So the odds a re-invoked
`land` faces are not the odds its first lap faced, and re-invoking it as written
is not the same bet as raising `LAND_MAX_LAPS`. Neither is a substitute for the
lever; both beat engineering around the loop.

**What the backstop is asking when it stops you.** `still not linear after 8
laps; main is moving faster than a lap takes. Look before lapping again` — the
thing to look at is whether the laps lost for a REASON (rebase conflict, red CI,
failed `verify`) or purely because `main` moved. Only the second is contention,
and only the second is safe to re-run unchanged; the first is a defect the loop
is correctly refusing to paper over. Measured again on CLOUD-282, which spent a
full 8 laps to the backstop with every `verify` green and CI green three separate
times, then lost the next invocation to a genuine rebase conflict — two different
answers to that question, one invocation apart.

A land that stops on the backstop is **re-run, not re-engineered**: wrapping it
in bespoke retry or pre-check logic is forbidden (AGENTS.md), and re-invoking
`mise run land` after confirming the laps lost only to movement is the sanctioned
move.

## Planners fan out freely; implementers do not

The cap above is a **build** cap, and reading it as a cap on sessions is the
mistake worth naming. A planning-only session writes no code, takes no lock,
claims no issue and never rebases — it reads, decides, and posts a plan to the
issue. Nothing it does is on the contended path, so N planners cost only tokens.
Landing is what contends. Fan out planning; drain the plans at 2.

Dispatched as `/plan-fleet` (`.claude/commands/plan-fleet.md`), which owns the
procedure; this section owns why it is shaped that way.

**Dispatch bundles, not single tickets.** A session handed one ticket stops when
it lands, and its container plus its warm context are thrown away. A session
handed an ordered chain in one file domain keeps going, and — the part that
matters for the cap above — amortises several commits over one rebase cost
instead of paying that cost per ticket. Bundling is what raises the ceiling;
adding sessions is not.

Order within a bundle by real dependency: the ticket whose gate the next one
needs goes first, and the ticket that _replaces_ what an earlier one fixed goes
last (CLOUD-328 then CLOUD-214 is the worked example — fix the walker's contract
and pin it with assertions, then let the replacement land against those
assertions). Each child plans **one ticket at a time**: a later ticket's shape
depends on what the earlier one landed, so planning the chain up front is
planning against a tree that does not exist.

The dispatcher does not need perfect dependency knowledge. Every child runs
`claim-check` per ticket and skips what is not pullable, so a mis-sequenced
bundle degrades to a skip rather than a collision.

**A bundle's PR shape is a second choice, and the procedure owns it**
(CLOUD-661): `.claude/commands/plan-fleet.md` step 3b, "Choose the bundle's PR
shape". The amortisation argument above is what it extends — from the rebase
cost to the CI matrix — so it is not restated here.

Three things about the harness that the procedure encodes because they are
invisible until they bite:

- **A child's final chat message is never read by the parent.** Under plan mode
  this costs nothing — the plan goes to the approval UI and the work goes to
  commits and PRs, all durable. It matters only for a child that produces a
  conclusion and no artifact: a research or decision ticket must be told to
  write to the issue, or its output dies with the session. Do NOT reflexively
  tell an implementing child to post its plan as a Linear comment; plan mode
  already has a destination, and a duplicate copy on the issue is a second
  authority that goes stale the moment the plan changes under review.
- `permission_mode: "plan"` **is the right default, and is already this
  environment's.** Measured 2026-08-11: children dispatched without it came up
  `PERMISSION_MODE_PLAN` anyway and parked at "Waiting on permission:
  ExitPlanMode". That park is the feature — the child plans, a human approves,
  and it works on from there. It is only a defect for work nobody intends to
  approve, which then stalls forever. Pass it explicitly so the intent is legible.

  **Both halves are false. Superseded 2026-08-18 (CLOUD-672).** The 2026-08-11
  reading was taken from a dispatcher already in plan mode, so it measured one
  case and recorded it as an environment property. The "only a defect for work
  nobody intends to approve" bound is the normal case, not the edge: one child
  parked **91 minutes** on `AskUserQuestion` — not `ExitPlanMode` — for zero
  commits, branches or PRs, and the same ticket re-dispatched without the
  parameter reached a draft PR. Plan mode does not add one gate at the end; it
  raises the child's propensity to hand control back at all.

  **The criterion is a property of the DISPATCH, not the ticket, and for an
  interactively-driven fan-out it resolves to `plan`.** Someone steering a
  campaign is standing by by construction, and the approval prompt is the
  cheapest review point there is — before any tokens are spent building, where a
  review of the finished branch is after. Plan mode was _correct_ for the five
  CLOUD-607 BUNDLE children on 2026-08-14, all of which reached `review_ready`
  with the owner approving in the web UI. `default`/`auto` is for a dispatch
  nobody is watching, and "the dispatcher would rather not wait" is not that.

  **CLOUD-672's own replacement claim was false too, and it is the one to stop
  re-typing: the mode is NOT inherited.** Measured 2026-08-19, one account, one
  environment, over CLOUD-703's six bundles — dispatcher `auto` + omitted came up
  `default`; dispatcher `plan` + `auto` was **refused at the call** ("requires the
  parent session to be in auto mode"); dispatcher `plan` + `default` came up
  `plan`. No single rule fits all three: omission does not inherit, and a value
  below the caller's is not honoured either. The reachable set is bounded by the
  dispatcher's mode at the moment of the call, which drifts as plan mode is
  entered and left. So name the parameter, **read the child's mode back**, and
  dispatch from the mode you want the children to run in. The cost of omitting
  it: five wave-1 bundles came up `default` and ran to landed without their plans
  ever reaching the owner supervising the campaign (CLOUD-728).

  **Unmeasured, so do not lean on "works on from there":** one child declined a
  write at end-of-session citing plan mode, hours after its plan was approved.
  Whether the mode persists past approval or was re-entered is not established.

- **Reasoning effort is not a `create_session` parameter.** Children inherit the
  dispatcher's, so dispatch from a session at the effort you want them to run at.
- **In-process subagents are the wrong tool here, for a reason unrelated to
  caps.** They share the parent's single working tree, and there is no channel
  for one to put a question to the human — the parent must relay it after the
  subagent has already stopped. Sibling sessions get their own container, their
  own clone, and their own thread to ask in.

The partition is by **file domain**, not by topic, and it is only real if it
reads open PRs' file lists rather than their titles. Two issues that read as
unrelated but both edit `mise-tasks/land` are one issue for dispatch purposes.

## A fan-out that drafts rather than lands

The section above is right that a non-landing session is off the contended path
and "costs only tokens". **This is what those tokens cost**, because the reading
that kills a fleet is "only tokens" → "free".

Every bound in the caps section is a bound on **landing**. An agent that
researches, reviews, or drafts never lands, so land contention derives nothing
about it — and the silence that leaves is an absence of a _derivation_, not an
absence of a _constraint_. Eight drafting agents were launched into that silence.

The binding constraint for this shape is **per-agent fixed cost**, which is paid
once per agent and therefore multiplies with N. Measured 2026-08-11: the one
agent in that fleet which completed anything spent **63,848 tokens** to fetch a
single issue and run one lint. That is the **floor for near-zero work**, not an
average — budget from it, not from what the work "should" cost. Each prompt
named eight artifacts as required reading, so the fixed cost was paid eight
times over before any agent did anything.

Three rules follow, and none of them is derived from land contention:

- **Digest, don't cite.** Context shared across the fan-out is computed **once**
  and passed as one artifact. A prompt that names N documents as required
  reading multiplies the read cost by the fleet size to deliver identical bytes
  to every member. The reading list is the anti-pattern; the digest is the fix.
- **Checkpoint at the unit's own gate.** Each unit is written to its **durable
  home** — the tracker, a memory, a PR — the moment it passes, never batched
  behind siblings. Scratch dies with the container and no consumer reads it, so
  work that ends the session in a scratch file was never done. This is the same
  property `mem:workflow/board-states` makes of the board: the durable write IS
  the delivery.
- **Pilot one, then widen.** Carry a single unit end to end, _through its
  durable write_, before spending the shape on the rest. A recipe unproven on
  one unit must not be spent on fifty-one — and "unproven" means the write has
  not been observed, not that the prompt looks right.

**What is gated here, stated plainly so nothing is assumed:** none of the three.
They are reference material with no exit code behind them, because the predicate
they need is a measurement of a session's actual spend, which is out of tree —
the capability gap CLOUD-95 registers. The cap of 2 above IS enforced, at claim
time; these are not. Read that as a reason to hold them deliberately, not as a
reason to discount them: the cost they bound was paid in full before it was
written down.

## What each implementer does

The existing contract: claim → build → draft PR → `mise run verify` → `mise run
linear-check` → `mise run land` (backgrounded) → In Review + attach the PR (the attachment is what makes `graph-check`'s
In-Review predicate true). **`land` is the only readier** — a hand `gh pr ready`
spent before its push buys only draft-era skips (CLOUD-247), and the ready must
be the event that fires CI on the SHA that lands. Blocked mid-build? Same question protocol: write it
on the issue, move the issue back to Backlog, release, take the next one.

## What the DISPATCHER still owns: the Done leg, which no implementer can reach

The contract above ends at **In Review, and that is correct** — it is the terminal
state an implementer _can_ reach. Done means released, and neither half of a
fan-out can perform that move:

- **The implementer cannot.** The tag postdates its merge by a release cycle.
  Measured 2026-08-22: bundle A landed 01:38, `v0.0.103` was cut 02:44.
- **CI cannot.** `release-plz.yml`'s promotion step is read-only _by design_ and
  says so in its own comment — _"Performing the move needs a Linear token that
  does not exist yet; printing the list needs nothing."_ It prints what WOULD
  move into the run summary. Nothing reads that summary.

So a fan-out that lands N rows leaves N rows In Review **by construction**. The
dispatch record must schedule the post-release pass, because no other actor in
the system can.

**Measured on CLOUD-839 (2026-08-22).** Five bundles, sixteen rows, no scheduled
sweep: 16 of 17 spine rows sat In Review across three releases, and a board-wide
census found **46** In Review rows that a `v*` tag had already shipped. The
dispatch prompt told each agent to _"carry the lifecycle to landed-and-verified"_
— which IS In Review. Every agent hit the target exactly. **The defect was the
brief's, not the fleet's**, and it is the same shape as CLOUD-825: a mechanism
that decides nothing because it has no invoker.

So a dispatch brief states the terminal state explicitly (**In Review + the PR
attached**) and names who runs the Done pass afterwards. Saying "to Done" in a
brief is worse than saying nothing: it asks for a transition the agent is
structurally unable to make.

### Running the pass

`mise run released "$TAG" </dev/null` for the refs a tag shipped, where `TAG` is the
shipped tag — spelling the placeholder in angle brackets makes it a redirect and the line
dies with a shell syntax error before `mise` is ever reached. Then pipe the In
Review closure back through it (`get_issue` payloads carrying `attachments`,
`description` and `relations` — `board-payloads` recovers them byte-perfect from
the transcript) for the conjunction with `graph-check`; then `done-check` to
confirm no Done outran its release. Shipping a ref is **necessary, not
sufficient** — read each row's own Acceptance against the released tree before
promoting it. CLOUD-807 was once Done with none of its acceptance met, and a
bulk flip reproduces that defect once per row.

**Redirect stdin.** `released` chooses its payload source with `[ -t 0 ]`, which
is false for a task-runner or backgrounded call whether or not anything was
piped — so a bare invocation falls through to `cat` and blocks on a stdin nobody
closes. Measured 2026-08-22: hung ~15 minutes before it was killed. `</dev/null`
is what selects the refs-only form.
