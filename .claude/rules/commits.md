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
  exact SHA already passed `final` — the single fan-in job every other leg
  reports through, which is what branch protection requires so that adding a job
  never needs a ruleset change. That indirection is also what let an EXTERNAL
  check start blocking a merge with no ruleset edit at all: `final` cannot
  `needs:` an app-posted check-run, so it reads the analyzer's verdict by name
  through `mise run sonar-gate` (CLOUD-441). The host still requires exactly
  `final`; what `final` means got wider. Which legs feed it is `ci.yml`'s business, and
  which check-runs carry a verdict for `ci-wait` is `CI_REQUIRED_CHECKS`'s; the
  host ruleset is the one authority for what blocks a merge, and `mise run
ci-drift` polices `batten.toml`'s `[ci]` projection of it against the live
  rules. There is deliberately no third copy in the tree — one was there, naming
  a set that predated `final`, read by nothing and gated by nothing (CLOUD-350).
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
- Rebase on `main` before opening. Reference the relevant `CLOUD-*` issue —
  scope lookups to the **Batten** project, since the board spans others.
- **A PR is bounded by what the work coherently needs, and a fix you can make is
  part of that work rather than a follow-up row.** This bullet used to open
  _"Keep PRs small and focused"_, and that clause is deleted rather than softened
  because it was read exactly as it looks: as licence to stop at a diff size and
  file the rest. AGENTS.md already settles this — _"a punt is any deferral you
  could have closed... Can do it, do it; can't, file it"_ — and a style note
  sitting one directory away must not read as an exception to it. Where the two
  seem to disagree, the anti-punt directive wins, and the disagreement is a bug
  in this file.

  Measured on CLOUD-1295 (2026-09-01), which is why the clause is gone rather
  than qualified. Retiring `bot-issue` surfaced three rows — CLOUD-1297,
  CLOUD-1299, CLOUD-1301. Two were closeable with the change in hand and the
  third became closeable mid-session when `main` deleted the governed suite that
  had blocked it. All three were filed instead, and this bullet was cited as the
  reason. The real reason was that the PR was nearly landed after four rebases;
  the citation was a route to the same outcome with less of the rule applied,
  which is the laundering AGENTS.md's override section names.

  **Feedforward only, and deliberately so — no gate is implied.** Non-negotiable
  rule 2 asks a new rule to ship a mechanism; this is the REMOVAL of a licence,
  and the directive it was overriding already exists and already binds. A reader
  who wants the mechanism should look at what actually catches this — `land`'s
  own refusal to ready an unfinished branch, and `deferral-check`, which holds a
  deferral to naming the row that owns it. Neither can decide whether a deferral
  was closeable, because that is a judgement and non-negotiable rule 3 forbids a
  gate resolving to one.

- **The FIRST key of a `Refs:` trailer is the row the commit SERVED; the rest are
  citations.** So `Refs: CLOUD-658, CLOUD-593, CLOUD-105` says this commit did
  CLOUD-658's work and cites the other two as evidence, prior measurement or
  superseded reasoning. Order is therefore load-bearing rather than cosmetic, and
  a citation must never be spelled first.

  This was practised and undocumented until CLOUD-674, which is a problem because
  a predicate now reads it: `closing-key-check` derives the set of rows a branch
  served from these first keys and refuses a PR body that closes only some of
  them. Before that, a bundle PR carrying eight rows and closing three stranded
  five — they never reached In Review, their work was on `main`, and the gate's
  passing line announced that the board would move. A gate enforcing an unwritten
  convention is one the next author breaks without warning, so the convention
  lives here, next to nothing else that restates it.

  `claimed-keys --refs-first-only` is the one authority on the extraction; do not
  re-derive the trailer scan, or the speculation boundary it carries is lost and a
  speculatively linearized branch gets a sibling's rows demanded of it.

## Commit identity: which authority wins, and why the question keeps returning

AGENTS.md rule 8 is the binding line; this is the detail behind it (CLOUD-605).

A **user-level** stop hook — outside this repository and outside every gate —
reports that commits will show as Unverified and prescribes reconfiguring the
committer to a vendor no-reply identity, then `--amend --reset-author`. Complying
produces a commit `[attribution] identity_deny` refuses, so a session that obeys
cannot commit again without bypassing this repository's own gate. CLOUD-274 built
that gate from a measurement here — 39 of the first 50 `main` commits carried an
environment-injected vendor identity — and its recorded position is that
accountability attaches to the human or service identity that directs, reviews
and adopts a change, never to a model identity.

**Three facts that decide it, all measured rather than argued:**

- **Its predicate is an OR and is unsatisfiable here.** It fires when the
  committer email is not the vendor one **or** the commit carries no `gpgsig`.
  Commits here are SSH-signed, so the signature term is already satisfied and the
  email term alone carries the refusal. The only value it accepts is the one
  `identity_deny` forbids: not a tuning problem, two contradictory policies.
- **Deleting it does not survive.** It is registered in the launcher's own
  settings, re-provisioned mid-session, and Claude Code _merges_ hooks across
  settings files — so a lower-precedence file can add a hook and never remove
  one. Turning it off is an owner action on the environment configuration that
  generates those settings, outside this repository.
- **The signature half is a different issue.** GitHub answers `verified: false,
reason: unknown_key` — the key is unpublished, not absent. That is CLOUD-591's,
  and resetting the author signs nothing, so obeying trades a tracked gap for a
  policy violation and leaves the tracked gap open.

**So: refuse it, and do not re-derive this.** `mise run attribution-identity`
writes the accountable identity repo-locally, and local beats global, which is
why every commit here is attributed correctly and the gate has never failed.
`no-denied-identity-prescribed` is the standing half — a `forbid` row refusing
any tracked Markdown that prescribes the denied identity, so the hook's remedy
cannot be copied into this tree and become a second authority. A repo-level stop
hook answering in the same channel was considered and **rejected on noise**: by
policy the committer is never the vendor identity, so it would fire on every
correctly-attributed commit forever, which is the compliance-reassurance shape
AGENTS.md's output posture forbids.
