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
`In Review ⇒ a linked PR attachment`, acyclic and non-dangling `blockedBy`) and
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
both shell verbs and write tools, and `ready-guard`'s receipt predicate. It does
**not** yet carry `run-shape-guard`, `issue-guard`, `claim-guard`,
`memory-guard`'s `cp`/`sed -i`/`git mv`/`git rm` shapes, or `contract-drift` —
each is a linked capability gap on CLOUD-312, and each guard still runs by hand
(`mise run <guard>`, payload on stdin). The bullets below describe every
guard's predicate; which of them a hook actually fires is the settings file's
answer, not this list's.

**A missing binary fails open, loudly.** `session-start.sh` builds it
(`mise run build:release`); if that did not run, the launcher emits an
`::error::` line every call and a `systemMessage` once per session. Silence
means it is mediating.

**One `PreToolUse` entry is not the engine**, and it names its reason:
`plan-hold-guard` on `ExitPlanMode|AskUserQuestion` (CLOUD-451). The predicate is
"a named background process is live", which no rule kind expresses — a linked
capability gap, like the others above — and CLOUD-435's cost argument does not
reach it: those two tools fire at most once per turn, the frequency class of the
`Stop` and `UserPromptSubmit` entries it kept, so no Bash call pays for it. It is
invoked by path for the same reason the launcher is.

- `gh-guard` denies `gh pr merge`, `gh pr checks`, `gh run watch` and a
  hand-typed `/fast-forward` comment, naming the task to use instead. Decision
  table in `mise-tasks/gh-guard-check`, gated by `mise run test:bats`. Reads
  (`gh pr view`/`list`/`create`, `gh pr ready`, `gh api`, `gh run view`) are not
  blocked. Bypass: `BATTEN_GH_GUARD_BYPASS=1`.
- `memory-guard` denies a write to `.serena/memories/`; they go through the
  Serena tools, which enforce the size ceiling and rewrite `mem:` references on
  rename. It is wired to **both** matchers, because matching the tool wrapper
  rather than the effective action is what let a Bash heredoc write memories
  while the guard was installed (CLOUD-185): the Write/Edit branch judges
  `file_path`, the Bash branch judges a command's write-shaped segments —
  redirects, `tee`, `sed -i`, `mv`/`cp`/`rm`, `git mv`/`git rm`. Reads stay
  allowed, and a `mv` inside the tree names `rename_memory` specifically, since
  that is the only route that rewrites referrers. Decision table in
  `mise-tasks/memory-guard-check` — the guarded path is written once there, so
  the two branches cannot disagree — gated by `mise run test:bats`. Bypass:
  `BATTEN_MEMORY_GUARD_BYPASS=1`.
- `policy-budget` gates AGENTS.md plus anything always-loaded against a token
  budget — what every agent pays every turn. It is `batten policy budget`, not a
  shell task: the counted set and both thresholds are `[budget.instructions]` in
  `batten.toml`. An entry matching no file is exit 1, never a quiet pass.
- `issue-guard` denies `gh pr create` and `gh pr ready` unless the work names a
  `CLOUD-<n>` issue — in the branch, in a commit on it, or in the command — and,
  since CLOUD-230, unless that issue is unclaimed: a different **open** PR
  **claiming** the key is refused, because CLOUD-49 was implemented twice in one
  cycle and one side was thrown away. Claiming, never merely naming — both sides
  of that comparison go through `claimed-keys`, which is what the key is checked
  against; the competitor's branch, title and `Refs:` trailers are
  self-declarations, its body counts only through a closing keyword. Applying
  the narrowing to one side and not the other made a PR citing the key as
  evidence read as racing it (CLOUD-378). GitHub is the source for that lookup,
  not the tracker, and it fails open when `gh` is absent or failing. It is the _earliest_ computable moment, not an early one:
  no artifact exists at pull time for a hook to inspect, so opening the draft PR
  before the work is what makes the refusal cheap. The
  board rule was prose, and prose is feedforward only: a session followed every
  gated discipline and skipped every ungated one, landing three PRs with no
  issue moved and an existing issue (carrying measurements that contradicted the
  fix) never read. You cannot name an issue you have not looked up, so the gate
  that blocks landing is what forces the search. It does NOT gate whether
  outstanding items reach the issue: nothing in the **tree** carries that, and
  its compensating control is that a durable home always exists by then.
  **Half of that is now gated after all** — the claim used to read "not
  computable over any artifact the repo can see", and the PR body is an artifact
  `gh` can see. `deferral-check` reads it (CLOUD-323). Bypass:
  `BATTEN_ISSUE_GUARD_BYPASS=1`, for a PR that genuinely precedes its issue.
- `deferral-check` is the finish-side half of that pair (CLOUD-323): `land`
  pipes the PR body in before readying, and a paragraph containing `judgement
call` with no `CLOUD-*` key **in that same paragraph** stops the lap. Two open
  decisions had landed on `main` with a PR paragraph as their only record, and
  the board showed a clean Done. Paragraph-local is the whole design — measured
  over 60 merged PRs, "a deferral phrase and no key in the BODY" fires on zero,
  because `issue-guard` already forces a key onto every one. `worth checking`
  (2 firings, both review prompts) and `deliberate` (16) were measured and
  dropped; one shape survived, firing once, correctly.
- `claim-guard` is the pull-time half of the pair `issue-guard` finishes
  (CLOUD-272): it denies a Write/Edit whose target is **inside the repo and not
  git-ignored** when the current branch carries no claim receipt. `claim-check`
  mints that receipt on its pullable path, under `.git/batten-receipts/`, keyed
  by **branch** — not by SHA like `ready-guard`'s, because a claim attests to a
  decision about an _issue_ that every commit on the branch continues to serve,
  and a SHA-keyed one would demand a re-claim per commit. The naive form
  ("refuse unless a `CLOUD-<n>` is In Progress") is not computable in a hook at
  all: no tracker credential exists there, which is why `claim-check` is a pure
  function of piped stdin. Scratch work is excluded structurally rather than by
  tuning — git-ignored and out-of-repo paths are never judged — while an
  untracked-but-not-ignored file **is**, since opening a new feature file is the
  first edit this catches. Bypass: `BATTEN_CLAIM_GUARD_BYPASS=1`.
- `run-shape-guard` denies three ways of throwing away a **verdict-bearing**
  command's exit status: piping it into a pager or filter, following it with `;`
  or `||` in the same list, and detaching it with `nohup`/`&`. A fourth shape
  throws away the SESSION rather than a verdict, and needs no verdict-bearing
  command to do it: a **foreground `sleep`**, which the harness kills at ~2
  minutes, so a poll meant to be patient fails instead — measured at exit 143
  and 144 over a hung commit, after which the container was reclaimed with the
  work uncommitted. `run_in_background` on the call is what tells that apart
  from the recommended `until <test>; do sleep 1; done`, which is allowed. The
  verdict-bearing list is written once as data in the task — `mise run`,
  `git push`/`fetch`/`rebase`, mutating `gh pr`, `cargo` minus its query
  subcommands, and `bats` given a suite (CLOUD-473: `mise run test:bats` was
  covered by the `mise` row while `mise exec -- bats` and a path-invoked
  `tests/bats/bin/bats` ran the same gates unguarded) — because the guard was
  scoped to the literal string `mise run`
  and an agent complying with it exactly kept making the identical error on the
  next command (CLOUD-199, measured on `git push`, `cargo clippy` and
  `cargo test`). `&&` is deliberately allowed: it short-circuits, so a failure
  still propagates and there is no false green to stop. The deny message states
  the principle — read the status from the harness — rather than naming one
  command, since complying with the narrower wording is how the second instance
  happened. Bypass: `BATTEN_RUN_SHAPE_BYPASS=1`.
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
- `plan-hold-guard` denies `ExitPlanMode` and `AskUserQuestion` while no
  background hold is live, because handing control to a human is the one turn
  end that is correctly idle — and an idle container is reclaimed, destroying
  whatever the human had already typed into the approval box (CLOUD-451). The
  remedy the deny names is `mise run plan-hold`, launched with
  `run_in_background`: a sleeper that prints nothing until it is released, so it
  costs no tokens while someone reads. Two events release it, because a human
  can answer in two ways: `plan-hold-release` on `UserPromptSubmit` for a typed
  reply, and `plan-hold-release-tool` on `PostToolUse` over the same two tools
  the guard gates, because answering `AskUserQuestion` or approving
  `ExitPlanMode` produces a **tool result and not a prompt** — so the prompt path
  could never see the case the mechanism exists for (CLOUD-485). Either way the
  sentinel is removed and the hold **exits** rather than being killed; that exit
  is the wake-up. Only the answer releases: a turn merely ending must leave the
  hold standing, or the reclaim comes back through the fix. The tool path runs no
  classifier — provenance is structural there, where a prompt's is not. The predicate is a sentinel naming a
  pid that still answers `kill -0`, in `mise-tasks/plan-hold-check`, which is
  where the hold directory is spelled; a corpse is reaped on sight, the way
  `alive` treats a dead `batten-tasks` entry. **The hold also grades itself**
  (CLOUD-491): it records each poll and, separately, an intentional exit, so
  `session-start` can say whether a hold was live when the last container
  replacement happened — the question CLOUD-451's acceptance is written in and
  nothing could previously answer. The record is structural rather than
  timestamped because the last ~3 minutes of writes before a replacement were
  measured not to survive; that measurement, and why an `x` is never written from
  the exit trap, are in `plan-hold-check`'s own header. Bypass:
  `BATTEN_PLAN_HOLD_BYPASS=1`, for deliberately ending a turn idle.

`mise run landed-check` is a board gate on the same stdin pattern: an
issue In Progress whose ref appears on `main` has landed, and landed is In
Review. It exists because the tracker's open-side automation fires on "a commit
mentions this issue", which is not "work began" — a commit can continue,
document, cite or defer. It only ever moves forward into In Progress, so it
dragged an issue back out of In Review and left two others stranded (CLOUD-186).

`mise run gh-preflight` answers "does this token carry the claims our tasks
need?" by probing the read endpoints and reporting each 403's
`X-Accepted-GitHub-Permissions`; write claims are declared, never exercised. Run
it in a fresh environment before concluding a task is broken — an under-scoped
token otherwise surfaces as an unrelated 403 in whichever task runs first.

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
artifacts (`completions`, `schema`), then every formatter — in that order and
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
