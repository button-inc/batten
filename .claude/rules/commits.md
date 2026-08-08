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
- **Below `0.1.0` those arrows do not fire — every release is a patch.** Cargo's
  SemVer gives `0.0.x` no compatibility guarantee, so release-plz bumps the
  patch whatever the type says. Measured: the `feat!` that reversed the exit
  contract (CLOUD-226), BREAKING CHANGE footer and all, released as **v0.0.23**
  and is marked `[**breaking**]` in the changelog at a patch version. Keep
  writing the honest type — the changelog marker and the history depend on it,
  and the arrows start firing at `0.1.0` — but do not promise a bump in an
  issue's Ready block that the tool will not produce.
- Keep PRs small and focused; rebase on `main` before opening. Reference the
  relevant `CLOUD-*` issue — scope lookups to the **Batten** project, since the
  board spans others.
