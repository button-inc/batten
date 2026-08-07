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
check-run is terminal), `land` (comment `/fast-forward`, block until merged or
refused; depends on `ci-wait`, so a red PR cannot be landed). Background
`ci-wait` and `land`.

Two board gates follow the agents-fetch-gates-decide pattern — each is a pure
function of stdin (`get_issue` payloads piped in by the caller, since no tracker
credential exists), so live runs need board data but their bats suites run
unconditionally in the gate. `mise run ready-lint` validates an issue's Ready
block: only the clauses _present_ (restating all eight is forbidden by the DoR
doc), anchored on label+tag pairs like `Commit / bump (§6)` because bare `(§N)`
collides with house-style section references, holding §8 to `blockedBy` _claims_
(one sentence, mention markup stripped) against the real relations. `mise run
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
not today. Never log these tasks through `tail`: it discards the end of the run, which
is the part carrying the verdict.

That's a rule, so it ships with mechanisms — three `PreToolUse` hooks wired in
`.claude/settings.json`, each failing open on anything it can't parse:

- `gh-guard` denies `gh pr merge`, `gh pr checks`, `gh run watch` and a
  hand-typed `/fast-forward` comment, naming the task to use instead. Decision
  table in `mise-tasks/gh-guard-check`, gated by `mise run test:bats`. Reads
  (`gh pr view`/`list`/`create`, `gh pr ready`, `gh api`, `gh run view`) are not
  blocked. Bypass: `BATTEN_GH_GUARD_BYPASS=1`.
- `memory-guard` denies a direct Write/Edit to `.serena/memories/`; they go
  through the Serena tools, which enforce the size ceiling and rewrite `mem:`
  references on rename. Bypass: `BATTEN_MEMORY_GUARD_BYPASS=1`.
- `context-budget` gates AGENTS.md plus anything always-loaded against a token
  budget — what every agent pays every turn.
- `ready-guard` denies `gh pr ready` unless `verify` and `linear-check` have both
  passed against this exact HEAD. Each writes a receipt under
  `.git/batten-receipts/` keyed to the commit it validated, and linear-check's
  records the `origin/main` it was linear against — so an amend, a rebase, or a
  `main` that moved all invalidate it instead of silently still counting.
  Readying is the single event that starts CI, so this is the one precondition
  whose cost is paid in CI minutes when it is skipped. Bypass:
  `BATTEN_READY_GUARD_BYPASS=1`.

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
