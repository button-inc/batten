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

`mise run linear-check` (is HEAD fast-forwardable?), `ci-wait` (block until every
check-run is terminal), `land` (comment `/fast-forward`, block until merged or
refused; depends on `ci-wait`, so a red PR cannot be landed). Background
`ci-wait` and `land`.

`ci-wait` polls conditionally: each request carries the previous ETag as
`If-None-Match`, and a 304 costs nothing against the rate limit (measured: three
consecutive 304s left `X-RateLimit-Used` unchanged). That is what pays for the
5s interval — an unconditional poll had to stay slow to stay affordable, so the
news arrived late. `X-Poll-Interval` is honoured as a floor when the server sends
one. Never log these tasks through `tail`: it discards the end of the run, which
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
