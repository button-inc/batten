---
paths:
  - "CHANGELOG.md"
  - "release-plz.toml"
  - "Cargo.toml"
---

# Commits, releases, and PR shape

The commit rules bind every commit and are summarised in AGENTS.md; this is the
detail, loaded when you touch release configuration.

- **Every commit** follows [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/):
  `type(scope): summary` (e.g. `feat(cli): add check subcommand`). Types: `build,
chore, ci, docs, feat, fix, perf, refactor, revert, style, test`. Enforced
  per-commit, not just on the PR title, because PRs land by fast-forward — each
  commit reaches `main` with its **original SHA** and drives semver.
- **Land by commenting `/fast-forward`** (`mise run land`). The merge button is
  blocked on purpose: "Rebase and merge" rewrites every commit under a new SHA
  and discards the objects CI tested. `main` only advances to a commit whose
  exact SHA already passed `ci`, `cross`, `commit-lint`.
- **Semver + changelog are automated.** `release-plz` reads commits since the
  last release and bumps version + `CHANGELOG.md` (`feat`→minor, `fix`→patch,
  `!`/`BREAKING CHANGE`→major). Do **not** hand-edit version or changelog.
- Keep PRs small and focused; rebase on `main` before opening. Reference the
  relevant `CLOUD-*` issue — scope lookups to the **Batten** project, since the
  board spans others.
