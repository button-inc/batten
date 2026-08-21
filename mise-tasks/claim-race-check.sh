#!/usr/bin/env bash
#MISE description="Gate: no other OPEN pull request already claims this branch's issue — the duplicate-claim half of the retired issue-guard"
#
# CLOUD-446, half two. `issue-guard` was two predicates wearing one name. The
# naming half — does the work name a tracker key at all — became the engine's in
# the same issue, as a `requires_key` modifier on a shape row. This is what was
# left, and it is here rather than in the engine for a structural reason, not a
# scheduling one:
#
#   `batten hook` is barred from running a configured command on a mediated
#   call. `RuleKind::scopes` pairs every spawning kind with `RuleScope::Tree`
#   alone, pinned by `rules::tests::no_mediated_call_kind_spawns_a_process`, and
#   that invariant is worth more than this predicate. It is also the right call
#   on latency: the hook runs on every mediated tool call and this needs a
#   network round trip, which is disqualifying against the published <=100ms
#   budget.
#
# So the predicate moved to the tree surface, where spawning is already
# permitted, and reaches it as a `command` row (`claim-not-raced` in
# `batten.toml`) that `batten check` runs under `verify`.
#
# WHAT THAT COSTS, stated because it is a real reduction rather than a port.
# `issue-guard` fired at `gh pr create`; this fires at `verify`. Both are later
# than pull time, which is what CLOUD-230 actually wanted and which no candidate
# restores — the hook cannot make the call under any of them. Of the options
# this was the earliest that still sits on every path to a published PR, since
# `verify` runs before every ready and `land` is the only readier.
#
# THE PREDICATE. A branch claims an issue; if a DIFFERENT open PR also claims
# that issue, two agents are on one piece of work. Measured on 2026-08-08:
# CLOUD-49 was implemented twice in one cycle and one implementation — already
# written and verified — was thrown away. The board carried the claim from
# 04:29:34; the second session had read the issue while it was still Todo and
# never re-read it.
#
# CLAIMS, NEVER MENTIONS, and on BOTH sides of the comparison. A body cites
# related issues, prior measurements and superseded work as evidence; that is
# not a claim. `mise-tasks/claimed-keys.sh` is the single authority on the
# distinction and both sides go through it — applying the narrowing to one side
# only made a PR *citing* a key read as *racing* it (CLOUD-378). Measured there:
# PR #306 named CLOUD-133 in one row of an evidence table and refused
# CLOUD-133's own PR.
#
# FAILS OPEN ON EVERYTHING it cannot establish: no `gh`, no network, a timeout,
# an unparseable response, no resolvable claim, outside a checkout. A gate that
# cannot reach GitHub must never become the reason a branch cannot be verified,
# and unlike the hook this one sits in `verify` where a false red costs the whole
# pre-flight.
#
# POINTER-ONLY (non-negotiable rule 4): the refusal names the key and the
# competing PR NUMBER and branch. It never echoes a title, a body, or a commit
# message — everything it reads is prose someone else wrote.
#
# Exit 0 clean, 1 raced. The `command` rule kind turns any non-zero into a
# finding at the row's own severity, so there is no third code to invent here.
set -euo pipefail

[ -n "${BATTEN_CLAIM_RACE_BYPASS:-}" ] && exit 0

here="$(dirname "$0")"

# Outside a checkout there is no branch to derive a claim from, so there is
# nothing to judge — the same reading `claimed-keys` itself takes.
git rev-parse --git-dir >/dev/null 2>&1 || {
	echo "claim-race-check: not a git repository — nothing to judge"
	exit 0
}

command -v gh >/dev/null 2>&1 || {
	echo "claim-race-check: gh is not available — could not look, which is not a verdict"
	exit 0
}

# This branch's own PR, if it has one. Read once and used twice: as evidence of
# what this branch claims (a body carrying `Closes CLOUD-<n>` overrides the
# branch name, which is the escape hatch for a branch whose name no longer
# reflects the work), and to exclude ourselves from the competitor list.
mine=$(gh pr view --json number,body 2>/dev/null || true)
self=$(jq -r '.number // empty' <<<"$mine" 2>/dev/null || true)
mine_body=$(jq -r '.body // ""' <<<"$mine" 2>/dev/null || true)

# The keys THIS branch claims. `claimed-keys` reads the branch and the local log
# for itself; the PR body is the one source it cannot see, so it goes on stdin.
claimed=$("$here/claimed-keys.sh" <<<"$mine_body" 2>/dev/null || true)
[ -n "$claimed" ] || {
	echo "claim-race-check: this branch claims no issue — nothing to race"
	exit 0
}

raced=0
while read -r key; do
	[ -n "$key" ] || continue
	# `--search` covers title and body; the unfiltered list covers a PR whose
	# only mention of the key is its branch name — which is how the CLOUD-49
	# duplicate would have presented, since that branch named no issue at all.
	found=$(
		{
			gh pr list --state open --search "$key" --json number,headRefName \
				--jq '.[] | "\(.number) \(.headRefName)"' 2>/dev/null || true
			gh pr list --state open --json number,headRefName \
				--jq '.[] | "\(.number) \(.headRefName)"' 2>/dev/null || true
		} | sort -u
	)
	[ -n "$found" ] || continue

	while read -r number head; do
		[ -n "$number" ] || continue
		# Our own PR is not a competitor — otherwise every verify on a branch
		# that has published would refuse itself.
		[ "$number" = "$self" ] && continue
		# The competitor is asked the SAME question through the SAME authority
		# (CLOUD-378). Every source is passed explicitly because none is local:
		# the head branch and the title are the PR's self-declaration, its commit
		# messages carry the `Refs:` trailer, and the body is stdin — evidence
		# that counts only through a closing keyword.
		theirs=$(
			"$here/claimed-keys.sh" \
				--branch "$head" \
				--title "$(gh pr view "$number" --json title --jq '.title' 2>/dev/null || true)" \
				--log "$(gh pr view "$number" --json commits \
					--jq '.commits | map(.messageHeadline + "\n" + .messageBody) | join("\n")' 2>/dev/null || true)" \
				<<<"$(gh pr view "$number" --json body --jq '.body' 2>/dev/null || true)" 2>/dev/null || true
		)
		# Exact line match: `claimed-keys` emits one uppercased key per line and
		# `$key` came from the same program, so no substring rule is needed and
		# CLOUD-4 cannot match CLOUD-49.
		if grep -qxF "$key" <<<"$theirs"; then
			echo "::error:: claim-race-check: $key is already claimed by open PR #$number (branch $head)" >&2
			raced=$((raced + 1))
		fi
	done <<<"$found"
done <<<"$claimed"

if [ "$raced" -gt 0 ]; then
	echo "::error:: claim-race-check: $raced claim(s) raced. Two agents on one issue is work that gets thrown away — it has happened here, and the discarded side was already written and verified. Take the frontier from \`mise run graph-check\` rather than a snapshot read at session start; if the competing PR is stale, say so on the issue and close it rather than racing it. BATTEN_CLAIM_RACE_BYPASS=1 when a second PR against one issue is deliberate." >&2
	exit 1
fi

echo "claim-race-check: no open PR races this branch's claim"
