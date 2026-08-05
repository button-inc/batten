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
mise.toml       pinned toolchain (Rust, hk)
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
