# AGENTS.md

Guidance for AI coding agents (and humans who like checklists) working in the
Batten repository. Batten is a repo-agnostic **policy engine** that keeps *"done"*
aligned with landed-and-verified work. Dogfooding is the point: Batten is its own
consumer #1, so hold this codebase to the discipline Batten exists to enforce.

## Setup

The toolchain is pinned with [`mise`](https://mise.jdx.dev) and git hooks run
through [`hk`](https://hk.jdx.dev). Run once per clone:

```bash
mise install     # provision the pinned Rust toolchain and hk
hk install       # install the git hooks into .git/hooks
```

**Use [mise](https://mise.jdx.dev) for everything it is reasonably designed for
in this repo — always.** That means: install and pin every dev tool through
`[tools]` (never a one-off `brew`/`cargo install` or a system binary), read and
set env vars through `[env]` (never ad-hoc `export`s), and run every repeatable
command as a `[tasks]` task invoked with `mise run` (never a bare `cargo …` or a
duplicated shell snippet in CI or a hook). If you reach for a tool, a variable,
or a scripted command, define it in `mise.toml` first and call it through mise.
CI, `hk`, and your shell then execute byte-identical commands.

Everything — tools, env vars, and tasks — is defined in `mise.toml`. Use the
tasks rather than raw cargo so local, hook, and CI runs are identical:

```bash
mise run test          # workspace test suite
mise run lint          # clippy, warnings denied
mise run fmt           # format
mise run ci            # fmt-check + lint + test + deny (what CI runs)
mise run cross-check   # type-check other targets from Linux
mise tasks             # list them all
```

## Serena (semantic code tools)

The repo ships a project-scoped [Serena](https://github.com/oraios/serena) MCP
server so agents get LSP-backed *semantic* code navigation and edits (find
symbol / references, rename, symbol-level edits) instead of grep-and-splice. You
do not need to know Serena to benefit from it — it is wired up in `.mcp.json` and
starts automatically. The only prerequisite is the pinned toolchain:

```bash
mise install   # provides `uv`/`uvx`, which .mcp.json uses to launch Serena
```

`.mcp.json` runs `uvx --from serena-agent==<pinned> serena start-mcp-server
--context claude-code --project .`. The `--project .` matters: Serena keys
projects by **path** and activates the current working directory, so the main
checkout and every worktree under `.claude/worktrees/` are independent projects
with their own symbol cache.

**Worktree collisions are configured away**, so you don't have to think about
them:

- `.serena/project.yml` is checked in (shared, working config: Rust language
  server, gitignore-aware indexing). Its `ignored_paths` excludes
  `.claude/worktrees/**` — without that, the main checkout, which physically
  contains every worktree, would index N+1 copies of the tree and cross-link
  their symbols. This is *the* worktree failure mode; it is handled here.
- `.serena/cache/` (the per-machine symbol index) and `.serena/project.local.yml`
  (local overrides) are git-ignored via `.serena/.gitignore`. Each checkout
  builds its own cache; nothing machine-specific is committed.
- `.claude/worktrees/` is git-ignored, so worktree copies are never committed.

If a worktree ever misbehaves (stale index), delete its `.serena/cache/` and let
Serena rebuild. Do not commit `.serena/cache/` or point two worktrees at one
cache.

## Branching model — trunk-based development

This repo follows [trunk-based development](https://trunkbaseddevelopment.com/).
`main` is the single long-lived branch and is always releasable. Work happens on
**short-lived** branches that are opened, reviewed, and landed within a day or
two — not long-running feature branches that drift and rot. Keep changes small
and integrate frequently; land by fast-forward so `main` is a linear sequence of
tested commits (see [Commits and pull requests](#commits-and-pull-requests)).
Batten exists to make "done" mean *landed and verified* rather than merely
pushed, so its own history holds to that.

## CI is expensive; your local execution is free

Every CI run costs real minutes. **Your own execution costs nothing.** So the
default is always: verify everything locally, exhaustively, *before* CI ever
runs. CI is a final confirmation of what you already proved locally — never a
remote place to discover failures you could have caught for free.

This only works because **CI runs the exact same `mise` tasks you run locally**.
`mise run ci` (fmt-check + lint + test + deny), `mise run cross-check`, and
`mise run commit-lint` are literally what the workflows invoke. If CI ever runs a
command that isn't a `mise` task you can run locally, that is a bug — fix it so
they match.

**The workflow contract (all of it is enforced or it has failed):**

1. **PRs start as drafts.** Open every PR with `gh pr create --draft`. **CI does
   not run on draft PRs** — drafts are where you iterate and verify locally at
   zero CI cost.
2. **Before marking a draft ready, run `mise run verify` and get it green.** That
   task mirrors CI *and* asserts your branch is **fast-forward-green**: rebased
   onto the current `origin/main`, with `ci` + `cross` + `commit-lint` all
   passing. "Green but stale" is not green — rebase first.
3. **Only then `gh pr ready`.** Marking ready is the single event that triggers
   CI. Because you already ran the identical tasks locally against an up-to-date
   base, this run should pass on the first try. A red CI run on a freshly-readied
   PR means step 2 was skipped.
4. **Land by fast-forward** (`/fast-forward` comment). Never the merge button.
5. **Never re-run CI on an already-tested SHA.** Fast-forward means `main` takes
   the PR's exact commits, which already passed CI, so nothing re-runs on `main`.
   Do not add push-to-`main` CI triggers.

If a PR is not rebased on the latest green `main`, if `mise run verify` was not
green locally first, or if CI ran a command you couldn't run locally, the process
has failed — stop and fix the process, not just the symptom.

## Non-negotiable project rules

1. **The core stays repo-agnostic.** No consumer-specific identifiers — no
   account numbers, client names, or entity paths — anywhere in `crates/batten`.
   A grep of the source for a specific consumer's names must return zero hits.
   Consumer facts live in that consumer's own `batten.toml`.
2. **Rules ship with their mechanism.** A new rule without a runnable gate (a
   check with an exit code) is only half a change. A prose rule is feedforward
   only; a log without a gate is sensor only.
3. **Gates are computable predicates, not model judgements.** An enforcement gate
   resolves to a command and an exit code, never a classification.
4. **Machine-readable output is byte-stable and pointer-only.** The same input
   produces identical bytes. Checks over sensitive content return a count,
   pointer, or boolean — never the sensitive content itself.
5. **Respect the exit-code contract** (`crates/batten/src/exit.rs`): `0` success,
   `1` policy violation, `2` usage error, `70` internal error. The `hook`
   subcommand deliberately inverts part of this so exit `2` *denies* a mediated
   tool call — that inversion lives with the hook layer only.
6. **Configuration stays narrow:** a two-layer model — the repo `batten.toml`
   plus env and flag overrides. No upward directory walk, no `conf.d` merge.

## Editing conventions

- Keep `main` thin; put logic in the library (`lib.rs` and its modules) so it is
  testable. The binary only parses args, calls `run`, and maps the result to a
  process exit status.
- Library code is held to the workspace lints: no `unwrap`/`expect`/`panic` on
  reachable paths, no stray `print*!` (the binary boundary is the one sanctioned
  place to write to stderr), `unsafe` is forbidden.
- Every behavioral change ships with a test. Prefer end-to-end tests over the
  compiled binary (see `crates/batten/tests/cli.rs`) for anything a consumer
  depends on — exit codes, output shape, flag handling.

## Before you commit

The `hk` pre-commit hook runs `mise run fmt/lint/test`; the commit-msg hook runs
`mise run commit-msg`. Run `mise run ci` locally rather than discovering a
failure at commit time.

## Commits and pull requests

- **Every commit** follows
  [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/):
  `type(scope): summary`, e.g. `feat(cli): add check subcommand`. Allowed types:
  `build, chore, ci, docs, feat, fix, perf, refactor, revert, style, test`. This
  is enforced per-commit (not just the PR title) because PRs land by
  **fast-forward** — each commit lands on `main` with its **original SHA**,
  unchanged, and drives semver.
- **Landing a PR:** comment `/fast-forward` on it. GitHub's merge button is
  disabled/blocked on purpose — "Rebase and merge" rewrites every commit under a
  new SHA and throws away the objects CI tested. `main` only advances to a commit
  whose exact SHA already passed `ci`, `cross`, and `commit-lint`. Keep your
  branch fast-forwardable (rebase it on `main` locally before it lands).
- **Semver and the changelog are automated.** `release-plz` reads the commits
  since the last release and bumps the version + `CHANGELOG.md` in a release PR
  (`feat` → minor, `fix` → patch, `!`/`BREAKING CHANGE` → major). Do **not**
  hand-edit the version or changelog.
- Keep PRs small and focused; rebase on `main` before opening.
- Reference the relevant issue (the `CLOUD-*` board) in the PR description.

## Where things are

```
crates/batten/
  src/main.rs   thin binary: parse → run → exit status
  src/lib.rs    library entry (`run`), module tree
  src/cli.rs    clap command surface (empty tree at scaffold stage)
  src/exit.rs   the exit-code contract
  tests/cli.rs  end-to-end tests over the compiled binary
batten.toml     Batten's own policy config (consumer #1)
.mcp.json       project-scoped MCP servers (Serena semantic code tools)
.serena/        Serena project config (project.yml tracked; cache/ ignored)
mise.toml       pinned toolchain (Rust, hk, uv)
hk.pkl          git hooks (fmt, clippy, test, conventional commits)
deny.toml       cargo-deny policy (licenses, advisories, sources)
```

## Scope reminder

Batten is a policy engine — **not** a general-purpose hook runner, file-shape
linter, secret scanner, AST linter, or reference monitor. Its threat model is
honest agent or human error: acting on the wrong entity, at the wrong time, or
with the wrong completion signal. Do not expand the core past that; adopt strong
prior art (alint, Probity, cargo-deny, rulesync) rather than rebuilding it, and
build only the pieces with no suitable open-source equivalent.
