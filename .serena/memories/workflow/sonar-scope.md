# SonarCloud: two analyses, one check-run name

Read when: reading, trusting, or changing `sonar-gate`; a Sonar verdict looks
wrong on a SHA; or someone claims the analyzer's findings cannot be read.
Measured 2026-08-22 (CLOUD-897, CLOUD-528).

## The one fact everything else follows from

SonarCloud posts **two different analyses under the identical check-run name**
`SonarCloud Code Analysis`. Only `details_url` tells them apart:

| scope            | `details_url` ends | when it posts                                |
| ---------------- | ------------------ | -------------------------------------------- |
| the pull request | `…&pullRequest=N`  | seconds after a push to the PR branch        |
| the branch       | `…&branch=main`    | seconds after the merge, on `main`'s new tip |

**Fast-forward puts both on one SHA.** `main`'s tip is byte-identical to the PR
head it landed, so a landed commit accumulates the PR verdict and then main's.
`sonar-gate` matches by NAME only and takes the latest run, so on any landed
SHA it reports **main's** verdict as that commit's:

```
$ SHA=<any landed sha> REPO=button-inc/batten mise run sonar-gate
failure  SonarCloud Code Analysis   → exit 1
```

That is trunk's standing `C` (CLOUD-528), not the commit's. Any `verify` over a
HEAD that has already landed hits it.

## There is no race with `final`

A PR-scoped analysis starts within ~0–20s of the push and finishes inside 30s,
including on a 338-file diff. `final` runs after the whole matrix, minutes
later. CLOUD-897 was filed on a table of "analyzer started 25s AFTER `final`
finished" — every one of those rows was the **branch** analysis posting after
the merge. Do not re-derive the race; the timestamps look exactly like one.

## The analyzer does not grade the head that lands

Across the last 14 merged PRs (#631–#650), **every merged head carried exactly
one sonar run and it was `branch=main`** — not one carried a PR-scoped analysis.
Intermediate SHAs on the same branches were graded in under 30s each. #638 is
the clean demonstration: `c3da83c` and `c757a33` each graded within 20s, and its
merged head `5c510fa` — head for 18 minutes, `final` green — was never graded.

So absent-is-a-pass (CLOUD-441's deliberate choice, and correct) fires on the
one SHA that matters. Scoping the gate is necessary and not sufficient.

## Reading the findings — what works and what lies

- The dashboard API answers an unauthenticated caller
  `{"errors":[{"msg":"Project doesn't exist"}]}` — **a denial wearing a 404**.
  An empty `api/issues/search` from there is not a zero.
- Check-run **annotations** are reachable and the GitHub MCP `get_check_run`
  tool does not expose them:
  `gh api repos/button-inc/batten/check-runs/<id>/annotations --paginate`
- Annotations are **capped at 50 and truncated silently**. Provable by
  arithmetic: one run showed 50 of which 42 were a single rule; clearing that
  rule left **50 again**, not 8 — so ≥92 existed. A security-rated issue can sit
  wholly outside the window, which is what happened.
- A **branch** analysis carries `annotations_count: 0`, so that route cannot
  reach `main`'s verdict at all. It is PR-only, and truncated even there.

There is no `SONAR_TOKEN` and no Sonar step in any workflow — analysis arrives
through the SonarCloud GitHub App's automatic analysis, which is why none of it
is under this repository's control or observation.

## The probe

```
gh api "repos/button-inc/batten/commits/$SHA/check-runs?per_page=100" \
  --jq '.check_runs[]|select(.name|test("Sonar"))|"\(.started_at) \(.conclusion) \(.details_url)"'
```

Always read `details_url`. A conclusion without it is not a verdict about
anything in particular.
