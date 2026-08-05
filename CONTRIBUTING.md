# Contributing to Batten

Thanks for your interest in Batten. This document covers the mechanics; the
project's direction lives on its issue board.

## Ground rules

- Batten's core is **repo-agnostic**. No consumer-specific identifiers, account
  numbers, or entity names belong in the library or CLI — those live in a
  consumer's own `batten.toml`.
- **Rules ship with their mechanism.** A new rule without a gate (a runnable
  check with an exit code) is only half a change.
- **Gates are computable predicates, not model judgements.**
- Machine-readable output must be **byte-stable** and pointer-only for sensitive
  checks — never emit the sensitive content itself.

## Setup

The toolchain is pinned with [`mise`](https://mise.jdx.dev) (see `mise.toml`),
and git hooks run through [`hk`](https://hk.jdx.dev) (see `hk.pkl`). Once:

```bash
mise install     # provision the pinned Rust toolchain and hk
hk install        # install the git hooks into .git/hooks
```

## Development

```bash
mise exec -- cargo fmt --all
mise exec -- cargo clippy --all-targets --all-features
mise exec -- cargo test --workspace
```

The `hk` pre-commit hook runs format, Clippy (warnings denied), and the test
suite; the commit-msg hook enforces Conventional Commits. CI runs the same on
Linux and macOS, plus `cargo-deny`. Please run the hooks locally before opening
a PR.

## Commits and pull requests

- Commit messages follow
  [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/), e.g.
  `feat(cli): add check subcommand` or `fix: correct exit code for usage errors`.
- Keep PRs small and focused; rebase on `main` before opening.
- Every behavioral change ships with a test.
- Reference the relevant issue in the PR description.

## Licensing of contributions

By contributing, you agree that your contributions will be dual licensed under
the [Apache-2.0](LICENSE-APACHE) and [MIT](LICENSE-MIT) licenses, matching the
project.

## License compatibility of adopted tools

Batten adopts rather than rebuilds where strong prior art exists. Track the
license of each adopted or vendored tool here so the project stays
open-sourceable:

| Tool | Role | License | Compatible with MIT/Apache-2.0 |
| ---- | ---- | ------- | ------------------------------ |
| alint | file-shape, merge-marker, naming rules | _to confirm_ | _to confirm_ |
| Probity | red-green-refactor discipline, LLM judge | _to confirm_ | _to confirm_ |
| cargo-deny | dependency severity model | Apache-2.0 OR MIT | ✅ |
| ripsecrets | secret pointer adapter | MIT | ✅ |
| rulesync | harness-to-hook-file mapping | _to confirm_ | _to confirm_ |

Confirm each _to confirm_ entry before that tool is adopted in a shipped
release.
