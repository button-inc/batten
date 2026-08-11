# Contributing to Batten

Thanks for your interest in Batten. This document covers the mechanics; the
project's direction lives on its issue board.

## Ground rules

- Batten's core is **repo-agnostic**. No consumer-specific identifiers, account
  numbers, or entity names belong in the library or CLI — those live in a
  consumer's own `batten.toml`.
- **Rules ship with their mechanism.** A new rule without a gate (a runnable
  check with an exit code) is only half a change.
- **Gates decide, they do not estimate.** A predicate that only approximates its
  own question — a model judgement, or a match over open-ended content — may
  advise; it never blocks.
- Machine-readable output must be **byte-stable** and pointer-only for sensitive
  checks — never emit the sensitive content itself.

## Setup

The toolchain is pinned with [`mise`](https://mise.jdx.dev) (see `mise.toml`),
and git hooks run through [`hk`](https://hk.jdx.dev) (see `hk.pkl`). Once:

```bash
mise install     # provision the pinned Rust toolchain and hk
git submodule update --init  # tests/bats — the shell test runner
hk install        # install the git hooks into .git/hooks
```

## Development

`mise.toml` is the single source of truth for tools, env, and tasks:

```bash
mise run test    # workspace tests
mise run lint    # every linter: clippy, rustfmt, taplo, actionlint
mise run fmt     # run every formatter over the tree
mise run fix     # fmt + clippy's autofixes + regenerate derived artifacts
mise run ci      # everything CI runs (the hk gate + deny)
mise tasks       # list them all
```

`lint` fans out to `lint:clippy`, `lint:fmt`, `lint:toml` and `lint:actions`;
run any one on its own to narrow a failure. `fix` is `lint`'s symmetric
partner — where `lint` reports, `fix` repairs — and is the one command to reach
for when the tree has drifted.

The `hk` pre-commit hook runs the same tasks, and the commit-msg hook enforces
Conventional Commits. CI runs on Linux only; cross-platform coverage splits in
two: `mise run cross-check` type-checks the Windows target, and `mise run
darwin-link` really links the macOS targets (zig, no macOS runner needed).
Please run `mise run ci` locally before opening a PR.

## Commits and pull requests

- **Every commit** follows
  [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/), e.g.
  `feat(cli): add check subcommand` or `fix: correct exit code for usage errors`.
  PRs land by **fast-forward** (comment `/fast-forward`), so each commit reaches
  `main` with its original SHA and feeds semver. GitHub's merge button is
  intentionally disabled — it would rewrite SHAs and discard what CI tested.
- **Versioning and `CHANGELOG.md` are automated by `release-plz`** — don't edit
  them by hand.
- **Open PRs as drafts** (`gh pr create --draft`). CI does not run on drafts —
  iterate and verify locally at no CI cost.
- **Run `mise run verify` and get it green before `gh pr ready`.** It runs the
  exact tasks CI runs and checks your branch is rebased on the latest `main`
  (fast-forward-green). Marking ready is what triggers CI, and it should pass
  first try.
- Keep PRs small and focused.
- Every behavioral change ships with a test.
- Reference the relevant issue in the PR description.

## Licensing of contributions

By contributing, you agree that your contributions will be licensed under the
[Apache-2.0](LICENSE-APACHE) license, matching the project.

## License compatibility of adopted tools

Batten adopts rather than rebuilds where strong prior art exists. Track the
license of each adopted or vendored tool here so the project stays
open-sourceable:

| Tool       | Role                                     | License           | Compatible with Apache-2.0 |
| ---------- | ---------------------------------------- | ----------------- | -------------------------- |
| alint      | file-shape, merge-marker, naming rules   | Apache-2.0        | ✅                         |
| Probity    | red-green-refactor discipline, LLM judge | MIT               | ✅                         |
| cargo-deny | dependency severity model                | Apache-2.0 OR MIT | ✅                         |
| ripsecrets | secret pointer adapter                   | MIT               | ✅                         |
| rulesync   | harness-to-hook-file mapping             | MIT               | ✅                         |

Confirm each _to confirm_ entry before that tool is adopted in a shipped
release. `mise run license-table-check` is that confirmation as a predicate: it
fails while any row is unresolved, so the precondition cannot be skipped by
forgetting it.

A verdict is read from the upstream **license file**, never from a registry facet,
a search result, or a project's own summary of itself. One surveyed project
carried three different licenses across its engine, its rule corpus, and its
plugin, and the summary page named only the first — so the question is asked per
artifact, and the row records what the file said.
