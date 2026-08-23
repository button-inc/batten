#!/usr/bin/env bash
#MISE description="Gate: the committed [ci] table still matches the host ruleset (CLOUD-54)"
#
# The merge contract has one authority — the host — and `batten.toml`'s `[ci]`
# is a projection of it. A projection nothing checks is a second authority
# waiting to happen: it drifts the moment somebody edits the ruleset in the
# GitHub UI, and every reader downstream keeps believing the stale copy.
#
# The split is the repo's standing one: **agents fetch, gates decide**
# (`graph-check`, `ready-lint`, `claim-check`). This task does the fetching
# because it is the one place a credential is expected; `batten config lint
# --host-rules -` is a pure, offline comparison over whatever arrives on stdin.
# That is what keeps the *gate* runnable with no token, byte-stable, and unable
# to fail because a network call did.
#
# Fetch failure is exit 1, not 0: a drift check that could not look has not
# found agreement, and reporting green there is the false-green shape this
# engine exists to catch.
# A gate listed in $MUTANT_GATES with no row here fails `mise run mutant`.
#MUTANT could-not-look-is-a-pass|s/^\texit 1$/\texit 0/|could not look is exit 1, never a green verdict

set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

branch="${CI_DRIFT_BRANCH:-main}"
repo="$(gh repo view --json nameWithOwner --jq .nameWithOwner)"

if ! payload="$(gh api "repos/$repo/rules/branches/$branch")"; then
	echo "::error:: ci-drift: could not read the ruleset for $repo@$branch; a check that could not look has not found agreement" >&2
	exit 1
fi

printf '%s' "$payload" | cargo run --quiet -p batten -- config lint --host-rules -
