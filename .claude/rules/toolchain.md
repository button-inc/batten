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
`git submodule update --init` (bats, in `tests/bats`), `hk install`.

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
keep small. `LAND_MAX_LAPS` (8) is a runaway backstop on the lap COUNT, never a
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
ci-local-parity` (in the hk `gate`) holds the three properties that make CI a
confirmation rather than a discovery: no job runs on a draft, every
`pull_request` workflow supersedes its own runs, and every task CI runs is one
`verify` runs. `zizmor.yml` broke the first two for its whole life, so a draft
that touched a workflow still spent a runner and re-drafting did not close the
tap (CLOUD-240).

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
doc), anchored on label+tag pairs like `Commit / bump (§6)` because bare `(§N)`
collides with house-style section references, holding §8 to `blockedBy` _claims_
(one sentence, mention markup stripped) against the real relations. `mise run
claim-check` is the pull-time half: pipe the payload for the issue you mean to
pull and it exits non-zero on `not-todo`, `assigned`, or `has-pr` (a PR already
attached — someone published before the column moved). The automation will not
claim for you; it fires on the PR event, which is the end of the work. `mise run
graph-check` enforces the board discipline (`In Progress ⇒ assignee`,
`In Review ⇒ a linked PR attachment`, acyclic and non-dangling `blockedBy`) and
emits the ready frontier + WIP count on stdout — the same command gates and
schedules, so every session computes the same frontier. Fan-out protocol:
`mem:workflow/agent-fanout`.

`ci-wait` polls conditionally: each request carries the previous ETag as
`If-None-Match`, and a 304 costs nothing against the rate limit (measured: three
consecutive 304s left `X-RateLimit-Used` unchanged). That is what pays for the
1s interval — an unconditional poll had to stay slow to stay affordable, so the
news arrived late. The sleep is not what sets the pace: the round trip is ~470ms
(~260ms network, ~130ms `gh` startup), so the real cycle is ~1.5s.
`X-Poll-Interval` is honoured as a floor if the endpoint ever sends one; it does
not today. Never pipe these into a pager: it discards the verdict AND the exit status
(`mem:toolchain-and-hooks`, "A Bash call is a supervised process").

That's a rule, so it ships with mechanisms — the `PreToolUse` hooks wired in
`.claude/settings.json` (the settings file is the authoritative list; don't
restate its count here), each failing open on anything it can't parse:

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
  naming the key (title, body, or branch) is refused, because CLOUD-49 was
  implemented twice in one cycle and one side was thrown away. GitHub is the
  source for that lookup, not the tracker, and it fails open when `gh` is
  absent or failing. It is the _earliest_ computable moment, not an early one:
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
- `ready-guard` denies `gh pr ready` unless `verify` and `linear-check` have both
  passed against this exact HEAD. Each writes a receipt under
  `.git/batten-receipts/` keyed to the commit it validated, and linear-check's
  records the `origin/main` it was linear against — so an amend, a rebase, or a
  `main` that moved all invalidate it instead of silently still counting.
  Readying is the single event that starts CI, so this is the one precondition
  whose cost is paid in CI minutes when it is skipped. Bypass:
  `BATTEN_READY_GUARD_BYPASS=1`.

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
