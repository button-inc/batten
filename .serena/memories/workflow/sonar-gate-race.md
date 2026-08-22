# Sonar has been red for everyone, and `final` normally never finds out

Measured 2026-08-22 on PR #638, with `mise exec -- gh`.

## The finding

`sonar-gate` runs inside the `final` job and reads the `SonarCloud Code Analysis`
check-run **by name**. Absent is a pass, deliberately (`mise-tasks/sonar-gate.sh`
states the reason: an analyzer that declines to grade a PR produces no run at
all, and failing on that would wedge every PR it has no opinion about).

**`final` normally completes before Sonar has even started.** Three consecutive
merged PRs, from the check-runs API:

| PR   | `final` completed | Sonar STARTED    | `final` |
| ---- | ----------------- | ---------------- | ------- |
| #648 | 04:56:37Z         | 04:57:06Z (+29s) | success |
| #647 | 04:46:24Z         | 04:46:52Z (+28s) | success |
| #646 | 04:14:51Z         | 04:15:16Z (+25s) | success |

Every one of those landed with **Sonar `failure`** on its head and `final`
green, because the gate read _absent_. The verdict a PR gets from this gate is
therefore a function of how long its own CI takes, not of what the analyzer
found. That is not a gate; it is a coin toss with a bias.

## What it is hiding

`main` itself fails Sonar — **C Security Rating on New Code** — on roughly every
other trunk commit. Nothing surfaces it: AGENTS.md forbids push-to-`main`
workflows, so no run on `main` reads that verdict, and on PRs the race above
swallows it.

PR #638 was the first branch slow enough (a 300+ file diff plus the `perf` job)
for Sonar to answer before `final` ran. It reported **D Security Rating on New
Code** and blocked the landing. Nothing about that PR made Sonar red; it made
Sonar _audible_.

## Before you "fix" a Sonar failure on your branch

1. Check `main` first:
   `gh api repos/<owner>/<repo>/commits/<main-sha>/check-runs --jq '.check_runs[] | select(.name=="SonarCloud Code Analysis") | .conclusion'`
   If trunk is red, the failure is not yours — AGENTS.md's "red on the base
   branch too" exemption applies, and the remedy is an issue, not a patch.
2. Compare `final`'s `completed_at` against Sonar's `started_at` on a recently
   merged PR. If `final` finished first, that PR did not pass the gate — it
   outran it.

## Reading the findings at all

The dashboard is auth-walled (a private project answers `{"errors":[{"msg":
"Project doesn't exist"}]}` to an unauthenticated caller — a denial wearing a
404, so an empty `api/issues/search` result there is NOT a zero). No
`SONAR_TOKEN` exists in the container or in CI, since the SonarCloud GitHub App
does automatic analysis and needs none.

What DOES work is the check-run's **annotations** sub-resource, which the GitHub
MCP `get_check_run` tool does not expose:

    mise exec -- gh api repos/<owner>/<repo>/check-runs/<id>/annotations --paginate

**Capped at 50 by GitHub, and Sonar truncates to it silently.** Prove truncation
by arithmetic rather than trusting the list: on #638 one run showed 50
annotations of which 42 were one rule; fixing that rule left **50 again**, not 8.
So ≥92 issues existed and the list is a window, not an inventory. A
security-rated issue can sit entirely outside it — every one of the 50 visible on
#638 was a maintainability rule while the failing condition was Security.

Unioning annotations across every SHA on the PR does not fix this: only pushed
heads are analysed, and each posts the same truncated window.

## The two issues this deserves

Neither is a branch's job to fix in passing:

- **The race.** A gate whose verdict depends on which job finishes first is not
  a verdict. Either `final` waits for the analyzer (bounded, with absent still a
  pass after the wait) or the analyzer stops being read there at all. Today the
  bounded retry in `ci.yml` only re-runs `sonar-gate` when it answers exit 3
  (pending) — it never fires, because absent (pass) is returned first.
- **The standing red.** Trunk sits at C Security Rating with nobody watching.
  Whatever that is, it predates any branch reading this memory.

Related: `mem:workflow/landing-loop` for the rest of the landing sequence, and
`mem:github-access` before concluding an API is unreachable.
