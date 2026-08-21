---
paths:
  - "mise.toml"
  - "mise-tasks/*"
  - "hk.pkl"
  - "tests/*.bats"
  - ".github/workflows/*.yml"
---

# Toolchain, gate, and the lifecycle tasks

These load when you touch the workshop; deeper detail is in
`mem:toolchain-and-hooks`.

**Use mise for everything** — tools via `[tools]`, env via `[env]`, commands as
`[tasks]` run with `mise run`; never a bare `cargo`/`export`/one-off install, so
CI, hk, and your shell run byte-identical commands. Per clone: `mise install`,
`git submodule update --init` (bats, in `tests/bats`), and the git hooks — which
`.claude/hooks/session-start.sh` now performs and `doctor` asserts (CLOUD-476),
so none of the three is left to a human remembering a prose list. Not `hk
install`: its generated hook calls `hk` bare, which does not resolve where
mise's shims are off PATH, so the installed body is `.claude/hooks/git-hook` —
which also refuses to re-enter a gate that is already running, the recursion
that hung a commit when `doctor` first tried to execute a hook from inside the
gate.

## The lifecycle tasks

`mise run linear-check` (is HEAD fast-forwardable? — it fetches with an explicit
`+refs/heads/main:refs/remotes/origin/main` refspec and deepens a shallow clone
first, because a single-branch clone's configured refspec covers only its own
branch and `git fetch origin main` would silently update nothing), `ci-wait` (block until every
check-run is terminal), `land` (drive the branch to merged; it runs `verify`,
`verified` and `ci-wait` per lap, so a red PR cannot be landed). Background
`ci-wait` and `land`.

**Landing is a loop, and `land` drives the whole loop.** `main` advances
constantly, so the fast-forward bot refuses the moment your branch stops being a
direct descendant. That refusal is the design working: each lap rebases onto a
little more landed work, so conflicts arrive one small resolvable increment at a
time, and batching them is how a branch diverges until it cannot land at all. A
lap is fetch → rebase → `verify` → `verified` → push → `ci-wait` →
`/fast-forward` → read the answer, and a refusal starts the next lap by itself.
Every lap re-verifies and re-waits because a rebase mints a new SHA and the
receipts keyed to the old one are gone. Expect several; a lap costs one CI run
and that is the price of the design, not waste. **The only stop is a rebase that
conflicts** — the one step needing a decision, and exactly the step frequent laps
keep small. `LAND_MAX_LAPS` (2) is a runaway backstop on the lap COUNT, never a
wall clock on a wait; the `verify`/`verified`/`ci-wait` calls are per-lap in the
body rather than `#MISE depends`, because a dependency runs once and a loop needs
them every time round.

**A lap's wait is a race, and the economies are gated.** CI minutes are metered;
this sandbox is not. So the wait runs `ci-wait` ("is this SHA green") alongside
`main-watch` ("is this SHA still landable"), and whichever answers first decides
— the moment `main` advances, the run in flight is already waste, and the push
the next lap makes cancels it through the workflows' `concurrency:
cancel-in-progress`, which is why nothing calls `gh run cancel`. `main-watch`
polls conditionally like `ci-wait`, so a quiet `main` costs no rate limit; that
is what makes a second poller affordable at all. A lap whose HEAD still carries a
`verify` receipt re-proves nothing, and a **red run re-drafts the PR** — CI skips
drafts, so that is the only thing that stops the next push buying another run
while you fix it locally; the next lap readies it again. `mise run
ci-local-parity` (in the hk `gate`) holds the properties that make CI a
confirmation rather than a discovery: no job runs on a draft, every
`pull_request` workflow supersedes its own runs, no job starts before the
landing lease authorises its branch (CLOUD-420), and every task CI runs is one
`verify` runs. The task's own header is the list; a count restated here is what
went stale twice. `zizmor.yml` broke the first two for its whole life, so a draft
that touched a workflow still spent a runner and re-drafting did not close the
tap (CLOUD-240).

**The expensive steps answer from per-step receipts (CLOUD-424).** The cargo
chain, `test:bats`, `deny`, `zizmor`, `msrv`, `cross-check`, `darwin-link` and
`batten-check` route through `mise run step-receipt`: a content-addressed
receipt under `.git/batten-receipts/`, keyed by the step's input files (index
blob ids), its task body read from `mise tasks info`, its tools' live
`--version` output, and any argument. Same inputs, same command, same toolchain
⇒ same verdict, so a hit skips the step — which is what makes a rebase-only lap
cheap. This is not test-impact selection: nothing is inferred, and any key that
cannot be computed runs the step (fail closed). Under CI the cache neither hits
nor records — CI confirms independently. Spec table and rationale in
`mise-tasks/step-receipt`; decision table in `tests/step-receipt.bats`. Wrap a
step only when its cost dwarfs the ~0.3s a check/record pair costs.

Two defects got it here (CLOUD-235, then CLOUD-238), and the second is the
instructive one. First the refusal was invisible — the predicate's history is in
the task's own header. Second, restoring the signal and still _exiting_ on a
refusal was only half the design: with every refusal arriving out-of-band and a
linear-looking 5-step contract, an agent inferred landing was "a race I keep
losing" and began batching rebase→verify→push→land into one command to close the
window — optimising _against_ the design, since batching removes no refusal and
only makes each lap bigger. **A loop a caller has to notice is a loop a caller
will eventually mis-model**, so the task laps itself and the inference has
nowhere to start. `tests/land.bats` covers every way a lap can end, with a count
assertion, so an unexercised path cannot go dead again.

The board gates follow the agents-fetch-gates-decide pattern — each is a pure
function of stdin (`get_issue` payloads piped in by the caller, since no tracker
credential exists), so live runs need board data but their bats suites run
unconditionally in the gate. `mise-tasks/` is the authoritative list; don't
restate a count here, which is how "three `PreToolUse` hooks" went stale. `mise run ready-lint` validates an issue's Ready
block: only the clauses _present_ (restating all eight is forbidden by the DoR
doc), and it holds §8 to `blockedBy` _claims_ against the real relations. Every
token it anchors on — which openers name a block, which line is the `(§6)`
clause rather than a house-style cross-reference, which code span is the commit
type — is defined once, in `mise-tasks/ready-lint`'s comments beside the pattern
that implements it. Read it there; a restatement here is a copy that drifts, and
CLOUD-290 was an author rediscovering the real grammar by experiment. `mise run
claim-check` is the pull-time half: pipe the payload for the issue you mean to
pull and it exits non-zero on `not-todo`, `assigned`, or `has-pr` (a PR already
attached — someone published before the column moved). The automation will not
claim for you; it fires on the PR event, which is the end of the work. `mise run
graph-check` enforces the board discipline (`In Progress ⇒ assignee`,
`In Review ⇒ a linked PR attachment`, `Todo ⇒ ready-lint exits 0` — the queue is
a column claim like the other two, CLOUD-375 — acyclic and non-dangling
`blockedBy`) and
emits the ready frontier + WIP count on stdout — the same command gates and
schedules, so every session computes the same frontier. Fan-out protocol:
`mem:workflow/agent-fanout`.

**`ci-wait` decides terminality over a named required set, never over "any graded
run"** (CLOUD-327). `$CI_REQUIRED_CHECKS` in `mise.toml [env]` names the checks
that carry a verdict about this repository, and `land`'s `graded_runs` reads the
same value, so the two cannot drift. **An external analyzer stays out of that
roster and is gated inside `final` instead** (CLOUD-441): `mise run sonar-gate`
judges the one check-run by name, in CI and in `verify`. It is not a job, so
`needs:` cannot reach it and `ci-local-parity` would reject its name; it is not
draft-gated either, so `graded_runs` counting it would read a draft-era skip set
as answered. Absent is a pass there for the `zizmor` reason; exit 3 passes in
`verify` (an unpushed HEAD has no verdict) and fails in CI after a bounded retry. **Each name is judged by its LATEST run**
(CLOUD-436): a SHA accumulates a check-run per event, so a PR created as a draft
carries its `opened`-event skip set forever, and judging the union let that
residue veto a verdict that already existed — an unbounded poll over a green
head, and once over a completed red. `started_at` orders them, the run `id`
breaks a same-second tie, and a reading that carries neither answers as the
union did. Both readers share the rule for the same reason they share the
roster. Green means at least one required check
graded, none skipped, none pending; a required check that skipped is not an
answer and the poll continues, while an unrelated check gets neither a vote nor a
veto. `skipped` is still not a bad conclusion — it is the draft's economy, and
refusing it everywhere is the CLOUD-247 stall — what changed is where it is read.
Absent is not skipped: `zizmor` is path-filtered and produces no run at all on a
PR touching no workflow, so requiring every name to be present would hang.
The list is hand-maintained until CLOUD-54's derived `[ci].required_checks`
lands, and `ci-local-parity` is the sensor on it: a `pull_request` job missing
from the set, or a name matching no job, fails the gate.

`ci-wait` polls conditionally: each request carries the previous ETag as
`If-None-Match`, and a 304 costs nothing against the rate limit (measured: three
consecutive 304s left `X-RateLimit-Used` unchanged). That is what pays for the
1s interval — an unconditional poll had to stay slow to stay affordable, so the
news arrived late. The sleep is not what sets the pace: the round trip is ~470ms
(~260ms network, ~130ms `gh` startup), so the real cycle is ~1.5s.
`X-Poll-Interval` is honoured as a floor if the endpoint ever sends one; it does
not today. Never pipe these into a pager or a filter, and never put anything after
them in a `;`/`||` list: each discards the verdict AND the exit status
(`mem:toolchain-and-hooks`, "A Bash call is a supervised process"). Run the
command alone in the call and read the log in a separate one.

**A rebase or fetch that touches the instruction surface is a re-read trigger.**
Hooks and instruction files are session-start snapshots: the harness loads the
wiring once and the agent reads `AGENTS.md`, `.claude/rules/*` and the task layer
once, so a contract that lands mid-session binds nothing until it is re-read —
re-read the files named before the next lifecycle step, and self-enforce the rule
of any hook `.claude/settings.json` added, since that wiring cannot reload
(CLOUD-187). `contract-drift` is the feedforward half.

That's a rule, so it ships with mechanisms — the hooks wired in
`.claude/settings.json` (the settings file is the authoritative list; don't
restate its count here), each failing open on anything it can't parse. Most are
`PreToolUse`; the ones that are not name their event below, and the settings
file is what says how many that is:

**`PreToolUse` is now ONE entry — the engine** (`.claude/hooks/batten-hook.sh`
→ `batten hook --harness claude-code`), reading the `mediated_call` rows of
`batten.toml` and nothing else (CLOUD-312). Six `mise run` launches per Bash
call cost a measured 1.247 s serial / 605 ms concurrent to do milliseconds of
policy, ~93% of it task-runner startup (CLOUD-435).

**What that leaves unenforced, so you self-enforce it rather than assume
coverage.** The engine carries the `gh` lifecycle, the protected-path gate over
both shell verbs and write tools, and `ready-guard`'s receipt predicate. It also carries the whole
of `memory-guard`, whose last five write shapes — a destination-only copy, an
in-place stream edit, and a version-control move or remove — became expressible
as `[[verb]]` qualifiers in CLOUD-442, so that guard is **deleted** rather than
still runnable, and `run-shape-guard`'s three verdict-discarding shapes
(CLOUD-443), leaving that guard only the two families named below. It carries
`issue-guard`'s **naming** half as of CLOUD-446 — a `requires_key` modifier on
the two `gh pr create`/`ready` shape rows — and structurally cannot carry its
duplicate-claim half, which needs `gh pr list` plus a `gh pr view` per
competitor; that became the `tree`-scoped `claim-not-raced` row instead, so
`issue-guard` is **deleted** rather than still runnable. It does **not** carry
`contract-drift` — a linked capability gap on
CLOUD-312 — and that guard still runs by hand (`mise run contract-drift`,
payload on stdin). The bullets below describe every
guard's predicate; which of them a hook actually fires is the settings file's
answer, not this list's.

**A missing binary fails open, loudly.** `session-start.sh` builds it
(`mise run build:release`); if that did not run, the launcher emits an
`::error::` line every call and a `systemMessage` once per session. Silence
means it is mediating.

- `gh-guard` denies `gh pr merge`, `gh pr checks`, `gh run watch` and a
  hand-typed `/fast-forward` comment, naming the task to use instead. Decision
  table in `mise-tasks/gh-guard-check`, gated by `mise run test:bats`. Reads
  (`gh pr view`/`list`/`create`, `gh pr ready`, `gh api`, `gh run view`) are not
  blocked. Bypass: `BATTEN_GH_GUARD_BYPASS=1`.
- **`memory-guard` is retired** (CLOUD-442), and what it denied is now the
  engine's protected-path gate: `.serena/memories/**` in `protected` crossed with
  the `[[verb]]` table, which covers the Write/Edit tools and a command's
  write-shaped segments alike — redirects, `tee`, `mv`/`cp`/`rm`, an in-place
  stream edit, a version-control move or remove. Reads stay allowed, and the
  Serena tool to use instead travels as each row's `redirect`, so a move still
  names `rename_memory` — the only route that rewrites `mem:` referrers. The
  table in `batten.toml` is the one authority; the corpus that used to live in
  `tests/memory-guard.bats` is `crates/batten/tests/mediated_verbs.rs`. There is
  no `BATTEN_MEMORY_GUARD_BYPASS`: a mediated deny takes the engine's own hatch.
- `policy-budget` gates AGENTS.md plus anything always-loaded against a token
  budget — what every agent pays every turn. It is `batten policy budget`, not a
  shell task: the counted set and both thresholds are `[budget.instructions]` in
  `batten.toml`. An entry matching no file is exit 1, never a quiet pass.
- **`issue-guard`'s naming half is the engine's** (CLOUD-446), as the
  `pr-names-an-issue` and `ready-names-an-issue` rows in `batten.toml`: a
  `shape` row carrying `requires_key`, which narrows the deny from _this command
  is banned_ to _this command is banned unless the work is keyed_. The
  expression and the `base` it reads commits since are the consumer's, because a
  tracker's vocabulary in `crates/batten` is non-negotiable rule 1's violation;
  `(?i)` is load-bearing, since the tracker's own branch names are lower case.
  Three evidence sources, any one of which allows — the command, the branch, the
  commit subjects on `origin/main..HEAD` — and all three resolve at the boundary
  because `adjudicate` is pure. `None` is "could not look" and allows, matching
  the bash guard's `|| exit 0`. The one source the port drops is `gh pr view`:
  a PR body typed by hand and never echoed into the branch or a commit is no
  longer evidence, because a network round trip cannot fit the invocation budget
  `perf-assert` enforces.
  The other half is the row below, and `issue-guard` is **deleted**.
- **`claim-race-check` is the duplicate-claim half** (CLOUD-446), and it is a
  `tree`-scoped `command` row — `claim-not-raced` — run by `batten check` under
  `verify`, never on a mediated call. Since CLOUD-230 the predicate refuses a key
  already **claimed** by a different open PR, because CLOUD-49 was implemented
  twice in one cycle and one side, already written and verified, was thrown away.
  Claiming, never merely naming: both sides of the comparison go through
  `claimed-keys`, which is the one authority on the distinction — the
  competitor's branch, title and `Refs:` trailers are self-declarations, its body
  counts only through a closing keyword. Applying the narrowing to one side and
  not the other made a PR citing the key as evidence read as racing it
  (CLOUD-378). GitHub is the source, not the tracker, and every failure to reach
  it — no `gh`, no network, an unparseable answer, no resolvable claim — allows.
  **It cannot live on the mediated call**: `RuleKind::scopes` pairs every
  spawning kind with `RuleScope::Tree` alone, pinned by
  `rules::tests::no_mediated_call_kind_spawns_a_process`, and a round trip on
  every tool call is disqualifying against that same budget besides. The cost of
  the move, stated rather than absorbed: it catches the race at `verify` where
  the guard caught it at `gh pr create`. Both are later than pull time, which is
  what CLOUD-230 wanted and which no candidate restores. `glob` names the check's
  own file so the trigger and the mechanism are one object, which is also what
  keeps it out of every fixture (CLOUD-614). Bypass:
  `BATTEN_CLAIM_RACE_BYPASS=1`, when a second PR against one issue is deliberate.
  What neither half gates is whether outstanding items reach the issue: nothing
  in the **tree** carries that, and the compensating control is that a durable
  home always exists by then — `deferral-check` reads the PR body for the rest
  (CLOUD-323).
- `deferral-check` is the finish-side half of that pair (CLOUD-323): `land`
  pipes the PR body in before readying, and a paragraph containing `judgement
call` with no `CLOUD-*` key **in that same paragraph** stops the lap. Two open
  decisions had landed on `main` with a PR paragraph as their only record, and
  the board showed a clean Done. Paragraph-local is the whole design — measured
  over 60 merged PRs, "a deferral phrase and no key in the BODY" fires on zero,
  because the key rule already forces a key onto every one (`issue-guard`
  when that was measured; the engine's `pr-names-an-issue` since CLOUD-446). `worth checking`
  (2 firings, both review prompts) and `deliberate` (16) were measured and
  dropped; one shape survived, firing once, correctly.
- `filed-here-check` is that stop's sibling, and the second half of CLOUD-514:
  `deferral-check` prices a decision left with no home, this prices a home opened
  instead of a fix. `board-write-record` (a `PostToolUse` body) records every row
  this branch put on the board — kind, id, the tracker's `updatedAt`, the
  `ready-lint` verdict over the body the **tracker returned**, and the diff
  overlap — and `land` calls this beside `deferral-check`, refusing when a row
  this branch CREATED was stored `unready`. Three states rather than two: `ready` passes, `unready` refuses, and
  `-` — the recorder could not lint — passes, because reading "not answered" as
  "refused" turns a verdict about the environment into one about the row.
  Comments are recorded and never gated: a comment on the row that already owns a
  finding is the honest common case, and pricing it pushes the pressure toward
  silence, which is the failure `finding-sink-check` exists to catch.
  **A second refusal prices PROXIMITY** (`filed-over-own-diff`, CLOUD-514 phase
  3), because the first prices only refinement and a Ready block is prose —
  measured, four rows filed in three and a half minutes and every one recorded
  `ready`, so the toll certified the punts instead of reversing them. The
  recorder's fifth column is `board-diff-overlap`: the tracked paths the row's
  body names intersected with `origin/main...HEAD`, basenames resolved (exact
  matching found none of the three real rows) and an ambiguous one resolving to
  nothing. Non-zero stops the lap, and the load-bearing difference is that there
  is **no prose remedy** — fix it here, comment on the row that owns it, file it
  after landing from a clean tree, or `BATTEN_FILED_HERE_OVERLAP=1`, which
  records which rows it overrode. It prices filing against **the diff** and
  claims nothing wider: a punt about code the branch never touched is invisible
  to it. The verdict is unforgeable by the author for the reason the receipt pattern usually is not —
  `ready-lint` over a payload the caller assembles was measured green three times
  against text in a local file, once under an id no row carried. Fails open on an
  absent record, and a branch predating the recorder can never have one: the store
  lives under `$GIT_DIR`, is never committed, and dies with the container — which
  is also why no fleet-wide firing rate is measurable. Bypass:
  `BATTEN_FILED_HERE_BYPASS=1`. **`--checklist` is a third mode over the same
  parse** (CLOUD-97): it enumerates EVERY row this branch filed, marks the ones
  whose named paths intersect the diff, and asks the agent to affirm each is
  independent work rather than a punt. A sibling of `--advisory`, never a
  widening of it — that predicate is measured and mutation-gated, and retuning a
  gate by editing the question it answers is not a refactor. Both nudge modes
  print pointers on **stderr**, because this file's stdout carries its own
  summary lines and a stdout capture reads "no board writes recorded" as a
  checklist of one row.
- `unlanded-check` is the end-of-turn half nobody had (CLOUD-97), and it decides
  NOTHING: `completion.unlanded` — a completion marker in the session transcript
  with no patch-id-equivalent commit on the landing target — is the engine's
  verdict, minted by `batten state record`, and this reads the store and points
  at it. A bash re-derivation would answer by ancestry where the engine answers
  by patch identity, and a rebased-then-landed branch is clean to one and dirty
  to the other. It reads the PLAIN `batten state list` rather than `-J` because a
  by-path hook does not get mise's env and so has no pinned `jq`; the engine
  already emits `<fingerprint> <rule> <ref> <count>`, which the shell can read.
  Fail-closed on the observation — `skipped`/`errored` is not a finding — and
  fail-open on everything else, since it runs inside a Stop hook. Once per HEAD
  sha: the finding holds while the work is unlanded, so an unsuppressed rule
  repeats one pointer every turn until nobody reads it, and a new commit is a new
  answer to the question. Bypass: `BATTEN_UNLANDED_CHECK_BYPASS=1`, which the
  `state record` call in `stop-guard` rides too — a caller who switched the rule
  off should not still pay a tree walk per turn for an answer nobody reads.
- **`stop-guard` ends every turn with a question now.** It ran four rules and
  then exited silently, and silence is the common case — so the most valuable
  thing it could say was the thing it never said. Each rule fires only on a shape
  somebody enumerated and measured recall is the weak half of all of them; the
  bare `done?` has no recall problem, and `finding-sink-check`'s header already
  records it surfacing nine real findings in one session while carrying no
  information at all. It is last and mutually exclusive with the rest: a turn
  already handed a pointer has been asked something more specific. The cost is
  one model round trip on a turn that would otherwise have ended, bounded to one
  per turn by `stop_hook_active`; the registration went from ~28ms to
  ~330-440ms, nearly all of it the `state record` call the fourth rule rests on.
- **`claim-guard` is retired** (CLOUD-444); the pull-time half of the pair the
  key rule finishes (CLOUD-272) is now the `claim-needs-receipt` row in
  `batten.toml` — a `receipt` rule with `trigger = "write"` and `key = "branch"`.
  It denies a write whose target is **inside the repo and not git-ignored** when
  the current branch carries no claim receipt. `claim-check` still mints that
  receipt on its pullable path, under `.git/batten-receipts/`, and the engine
  reads the same file: keyed by **branch**, not by SHA like `ready-guard`'s,
  because a claim attests to a decision about an _issue_ that every commit on the
  branch continues to serve, and a SHA-keyed one would demand a re-claim per
  commit. The naive form ("refuse unless a `CLOUD-<n>` is In Progress") is not
  computable in a hook at all: no tracker credential exists there, which is why
  `claim-check` is a pure function of piped stdin. Scratch work is excluded
  structurally rather than by tuning — git-ignored, out-of-repo and `.git` paths
  are never judged, and a detached HEAD has no branch to key on — while an
  untracked-but-not-ignored file **is**, since opening a new feature file is the
  first edit this catches. There is no `BATTEN_CLAIM_GUARD_BYPASS`: a mediated
  deny takes the engine's own hatch.
- **The three verdict-discarding shapes are the engine's** (CLOUD-443), as
  `batten.toml`'s `verdict-not-discarded` row — `kind = "pipeline"`. They are
  piping a verdict-bearing command into a pager or filter, following it with `;`
  or `||` in the same list, and detaching it with `nohup`/`&`. The
  verdict-bearing list is data on the row — `mise run`, `git push`/`fetch`/
  `rebase`, mutating `gh pr`, `cargo` minus its query subcommands, and `bats`
  given a suite (CLOUD-473: `mise run test:bats` was covered by the `mise` row
  while `mise exec -- bats` and a path-invoked `tests/bats/bin/bats` ran the same
  gates unguarded) — because the predecessor was scoped to the literal string
  `mise run` and an agent complying with it exactly kept making the identical
  error on the next command (CLOUD-199, measured on `git push`, `cargo clippy`
  and `cargo test`). `&&` is deliberately allowed: it short-circuits, so a
  failure still propagates and there is no false green to stop. The deny states
  the principle — read the status from the harness — rather than naming one
  command, since complying with the narrower wording is how the second instance
  happened.
- `run-shape-guard` is what remains after that move, and it is **two families the
  engine cannot express**. A **foreground `sleep`** throws away the SESSION
  rather than a verdict: the harness kills the call at ~2 minutes, so a poll
  meant to be patient fails instead — measured at exit 143 and 144 over a hung
  commit, after which the container was reclaimed with the work uncommitted.
  `run_in_background` on the call is a fact about the call rather than the
  command string, and it is what admits the recommended `until <test>; do sleep
1; done`. It admits only that: a **backgrounded `sleep` with no `until`/`while`
  around it** is a timer, not a wait — it exits on the clock rather than on the
  thing it is waiting for, and duplicates the completion notification that
  already fires (CLOUD-821, measured at 490 such calls in one session against 2
  that changed a decision). Registered by path on `PreToolUse`/`Bash`, which it
  had never been until that issue. A **`git commit` that cannot obtain a
  message** spends the whole gate first, because `githooks(5)` runs `pre-commit`
  before git asks for one; its predicate is over heredoc binding. Retiring both
  into the engine is CLOUD-613. Bypass: `BATTEN_RUN_SHAPE_BYPASS=1`.
- `fanout-guard` is the one entry on `Task` (CLOUD-287): a subagent spawn was the
  only unmediated call in the wiring, and the workflow contract's "a subagent
  spawn above all" had no mechanism behind it. Two conjuncts over the spawn
  prompt, both pure functions of the envelope — the deduped artifacts it names,
  and its own size. The manifest is the term worth capping: fleet width is the
  multiplier, but the reading list inside each prompt is the multiplicand and it
  dominates. A named artifact counts only if it is TRACKED, so `origin/main` and
  a URL drop out by construction rather than by an allowlist somebody has to
  tune. It reads the payload through `payload-field`, never `jq`, because it is
  registered by path (`hook-pin-check`), and it is blind by construction to what
  an agent reads on its own initiative. Bypass: `BATTEN_FANOUT_GUARD_BYPASS=1`.
- `contract-drift` is not `PreToolUse`, and it cannot
  be: that event's model-facing channel is exit 2, which _blocks_ the call, and
  CLOUD-97 and CLOUD-219 each ruled a deny out independently. So it runs on
  `SessionStart`, seeding the snapshot before any tool does, since an autonomous
  session's first batch is routinely fetch+rebase and a snapshot written after it
  would record the drift as the baseline. The per-batch entry it was designed for
  **stays absent**, and CLOUD-461 is why: `batten hook` has no advisory channel,
  so there is nowhere for a once-per-batch reminder to land. Until then a
  contract that changes mid-session is announced at the next session start and
  not before — which is precisely what the re-read rule above exists to cover.
  It hashes the tracked surface (`AGENTS.md`, `.claude/rules`,
  `.claude/settings.json`, `hk.pkl`, `mise-tasks`) in one `git hash-object` pass,
  keyed per **session** so a session that started after a change
  is not nudged about one it already has. Silence is the default; a change-set is
  reported once, because reporting overwrites the snapshot. Pointer-only — paths
  and a count, never a byte of the file, asserted in `tests/contract-drift.bats`,
  because a reminder carrying the new text is a mirror and a mirror is cleared by
  reading the hook instead of the file. Bypass:
  `BATTEN_CONTRACT_DRIFT_BYPASS=1`.
- `ready-guard` denies `gh pr ready` unless `verify` and `linear-check` have both
  passed against this exact HEAD. Each writes a receipt under
  `.git/batten-receipts/` keyed to the commit it validated, and linear-check's
  records the `origin/main` it was linear against — so an amend, a rebase, or a
  `main` that moved all invalidate it instead of silently still counting.
  Readying is the single event that starts CI, so this is the one precondition
  whose cost is paid in CI minutes when it is skipped. Bypass:
  `BATTEN_READY_GUARD_BYPASS=1`.

**`ExitPlanMode` and `AskUserQuestion` are ungated, and that is a decision rather
than a gap** (CLOUD-515). `plan-hold` gated them for one day: a deny until a
backgrounded sleeper occupied the container, on the premise that occupancy defers
the reclaim that destroys a human's typed approval. The premise was measured twice
and failed twice (CLOUD-491), its own sensor never returned a single reading, and
the cost — a refused call plus a four-hour sleeper on every path to a person — was
paid unconditionally. Removed until one `plan-hold-check spanned` = `0` reading
exists; the code is a `git revert` away. **The problem is still real** — CLOUD-451
is open, and an idle handoff turn still risks the reclaim. What is gone is one
unvalidated remedy for it.

`mise run landed-check` is a board gate on the same stdin pattern: an
issue In Progress whose ref appears on `main` has landed, and landed is In
Review. It exists because the tracker's open-side automation fires on "a commit
mentions this issue", which is not "work began" — a commit can continue,
document, cite or defer. It only ever moves forward into In Progress, so it
dragged an issue back out of In Review and left two others stranded (CLOUD-186).

`mise run spec-ref-check` is the same pattern aimed at the tree rather than the
board: it refuses a `CLOUD-<n> §N` citation in a tracked file when the piped issue
declares no clause `N`. Enumerate what to fetch with
`git grep -hoE "CLOUD-[0-9]+'?s? §[0-9]+"` and pipe those `get_issue` payloads.
It **refutes and never confirms**, which is load-bearing rather than stylistic: a
Ready block may legitimately omit a clause — CLOUD-45 has no §4, CLOUD-80 no §3 or
§5 — so a sparse set is not a defect and a citation of a missing one is. Sub-numbers
resolve to their parent. An issue cited but absent from the payload is exit `2`,
never a silent pass. The transcription hazard CLOUD-469 records runs the OPPOSITE
way here than in `graph-check`: a shortened body carries fewer clause labels, so it
manufactures findings rather than hiding them — which is why a projected
`list_issues` is not a valid input, its descriptions being truncated.

`batten attribution` enforces the attribution decision record (CLOUD-268) over
produced commits (CLOUD-274): no vendor identity in `author`/`committer`, no
co-authorship-form model identity, no vendor session URL, no marketing formula.
Two seams, and neither adds a task name to a workflow — `mise run
commit-attribution` is a `depends` of `commit-lint`, so it rides the
`BASE_SHA`/`HEAD_SHA` contract `verify` and CI's commit-lint job already share
(a second workflow entry would oblige `verify` to run it too, per
`ci-local-parity`); `mise run commit-attribution-msg` runs from hk's `commit-msg`
hook and refuses before the commit exists. Findings are pointers (`<sha8>
author`, `<sha8> trailer:<key>`) and never the matched text, because everything
it reads is content someone wanted suppressed. The policy is `[attribution]` in
`batten.toml` — patterns, the carve-out, and the accountable identity — never a
literal in the crate, and `tests/commit-attribution.bats` asserts both the
wiring and that no configured pattern matches anything under `crates/`. **The
emptiness of `trailer_allow` is this repo's posture**, not an unfinished config:
silent-with-records, so every disclosure trailer is refused. `mise run
attribution-identity` is the one write (`batten attribution identity`,
self-declared per house style §5): repo-local only, it repairs an unset or denied
identity, leaves a contributor's compliant one alone, and runs from
`session-start.sh` so a clone is compliant before it writes a line.

`mise run gh-preflight` answers "does this token carry the claims our tasks
need?" by probing the read endpoints and reporting each 403's
`X-Accepted-GitHub-Permissions`; write claims are declared, never exercised. Run
it in a fresh environment before concluding a task is broken — an under-scoped
token otherwise surfaces as an unrelated 403 in whichever task runs first.

## Invocation latency: the number, the series, and the regression gate

`perf` measures batten's own invocation cost (hyperfine over a release build:
`noop`, `check`, `hook`) and `perf-assert` holds it to the ceiling README
publishes — an ABSOLUTE budget rather than a ratchet, taken from clig's
response-time floor. The number itself lives in `perf-assert`'s `BUDGETS` table,
which is also what the README clause holds the published column against; do not
restate it here (CLOUD-770). `perf-pair` asks the other
question: it builds this branch's binary AND its merge base's, measures them back
to back on one machine, and `perf-compare` decides the RATIO. `perf-gate`
composes those two and is the one name `verify` calls. Do not confuse this with
`hook-latency-drift`, which measures the hk gate's own pre-commit tier (CLOUD-509)
rather than the binary's startup.

**Wall clock, paired — instruction counts are not available.** CLOUD-172
specified callgrind with wall clock as a fallback. `mise registry valgrind`
reports "tool not found in registry", so it cannot be pinned, and
`no-source-built-tool` forbids compiling one; the fallback is the only branch.
What rescues wall clock is not a better clock but a better experiment — machine
noise is common-mode across a pair measured seconds apart, so it divides out.
Hence a ratio, never an absolute, and `perf-record` stamps `metric=wall-clock`
into every series entry so a later instruction-count series can never be diffed
against this one and read as a step change. The threshold is derived, not chosen:
a null comparison (identical binary as both arms, n=30) spread 0.966–1.102, and
`perf-compare`'s 1.30 clears that measured maximum. Re-measure with `mise run
perf-pair --null`; a bats case fails if the constant is tightened below the
recorded floor.

**In `verify` AND as a CI job, and the second is not redundant.** `verify` is
where it catches a regression earliest: `ready-guard` refuses `gh pr ready`
without a verify receipt for this exact HEAD, so the branch stops before it can
spend a matrix. But `verify` is what an author runs, not a check — `[tasks.ci]`
is `depends = ["hooks", "deny"]`, so for its whole life `perf-gate` ran on no
runner at all, and CLOUD-172's "a PR that regresses fails a check that names the
regressed measurement" was unmet. The `perf` job in `ci.yml` is that check, in
`final`'s `needs:` and in `CI_REQUIRED_CHECKS`. Both placements cost the common
change nothing: `perf-gate` exits clean without building when the diff against
the merge base touches no crate source, manifest or lockfile, because a binary
that cannot have changed cannot have got slower.

**The series records on a clock, not on a push to `main`.** A per-commit series
implies a push-to-`main` workflow, which AGENTS.md forbids — and the reason holds
rather than merely applying: `main` advances only by fast-forward to a SHA CI
already judged, so a push trigger buys a runner per merge for a measurement a
clock can take. `perf.yml` records daily from `main` into `refs/notes/perf`.
The cost is resolution, affordable because the series is not the attribution
mechanism — `perf-gate` catches a regression at the commit that caused it.
`perf-record` refuses to run off the trunk, because a series mixing a branch's
numbers with the trunk's cannot be read at all. (That decision belongs in
AGENTS.md beside the rule it honours; AGENTS.md is at its budgeted line ceiling,
so it lives here with the rest of the workshop detail.)

## The gate

`mise-tasks/` scripts are real programs: `shfmt`, `shellcheck` and `test:bats`
run in the same hk gate as the Rust steps. `mise run test` aggregates
`test:cargo` + `test:bats`. Every config format is formatted and validated there
too — `taplo` (TOML), `pkl` + `pkl format` (`hk.pkl`, so a malformed gate fails
at check time rather than when a hook tries to run), `prettier` (Markdown, with
`CHANGELOG.md` in `.prettierignore` because release-plz owns it), `actionlint`
(workflows). Don't hand-format any of them; run `mise run fmt`.

The task layer mirrors that reach rather than stopping at Rust: `mise run lint`
fans out to `lint:clippy`, `lint:fmt`, `lint:toml` and `lint:actions` via
`depends`, so each tool is runnable alone and `lint` means the whole tree.
`mise run fix` is its symmetric partner — `clippy --fix`, then the derived
artifacts (`completions`, `man`, `schema`), then every formatter — in that order and
sequentially, because those stages contend on the cargo target-dir lock and
rewrite each other's bytes. `fmt` remains the formatters-only subset.

Two commands are single-definition on purpose: hk's `cargo-fmt` and
`cargo-clippy` steps override the builtin command with `mise run lint:fmt` and
`mise run lint:clippy`, so the hook and the task can never disagree about what
passes. The step SELECTORS still come from upstream — `actionlint` already globs
`.github/workflows/*.y{,a}ml`, `taplo` and `taplo_format` already glob
`**/*.toml`, all three `check_first` — so re-declaring those here would be a
second authority for a selector upstream already tests.

`lint:toml` feeds taplo `git ls-files '*.toml'` rather than letting it walk the
tree: `target/` holds deliberately corrupt TOML fixtures the suite writes, and a
gate that fails on its own test data gets switched off.

The pre-commit hook runs the gate and commit-msg validates the subject. Run
`mise run ci` locally rather than discovering a failure at commit time.

## Task bodies do not run under `set -e` — fail closed by hand

A `shell = "bash -c"` body in `mise.toml` runs every line regardless of the
previous line's exit status (verified: a body of `false` followed by an `echo`
prints the echo and exits 0). So in a **gate**, any command whose failure would
change the verdict must be guarded explicitly — otherwise the gate reports on
state it never refreshed, which is a silent false green and worse than no gate.

Two instances of this had already landed. `linear-check`'s `git fetch` fed the
`origin/main` ref every later line reads, so a failed fetch left it comparing a
stale main to itself, passing, and writing a receipt `ready-guard` then honours
— `gh pr ready` allowed on a branch that was not rebased. `lock-check` ran
`mise lock` unguarded, so a failed lock left a clean diff and the gate claiming
"complete and current" about a file it never regenerated.

`lock-check` had a second, deeper defect that guarding could not reach, and it
is the one to learn from: **a gate whose verdict comes from a remote API and a
write is not testing the commit.** It fetched every tool's release metadata and
rewrote the tracked lockfile, so it answered "did upstream change since this
commit" — failing a branch for drift it did not cause, and leaving the rewrite
in the tree for the next `git add -A`. Worse, regenerate-and-diff detects drift
_only_: `mise lock` never removes or repairs an existing entry, so a stably
wrong lockfile passes forever. One did — a `cargo-zigbuild` platform key with a
checksum and no url, the exact partial entry the gate's own comment cited as its
motivation. Its stated premise ("CI installs with `mise install --locked`") was
false too; no workflow passes `--locked`.

Split accordingly: `mise run lock-complete` is the pure gate (committed bytes
only, no network, no write, `tests/lock-complete.bats`), and currency runs on a
schedule in `.github/workflows/lock-currency.yml`. When writing a gate, ask
which of the two it is — a property of the commit belongs in the gate, a
property of the world belongs on a clock.

A third instance was the caller, not a script: `verify`'s own body called
`linear-check` and `commit-lint` unguarded, so a `main` that moved under the
branch left it running commit-lint against a stale `BASE_SHA`, writing the
receipt `ready-guard` honours, and printing `fast-forward-green` — `gh pr ready`
allowed, and CI minutes spent, on work that failed its own pre-flight. Guarded
now, with `tests/task-fail-closed.bats` asserting the body carries no bare `mise
run` call and reaches its receipt write only past the guards.

The rule: **a gate step that cannot run must exit non-zero and leave no
receipt.** Prefer `if ! cmd; then echo "::error:: …" >&2; exit 1; fi` over a
bare call. A task complex enough to need several of those belongs in
`mise-tasks/` as a file task with `set -euo pipefail` and a bats suite — which
is why `linear-check` lives there, gated by `tests/linear-check.bats`.
