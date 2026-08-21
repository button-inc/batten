#!/usr/bin/env bash
#MISE description="Gate: an issue may become Done only if none of its own pull requests is still open (reads get_issue payloads on stdin)"
#
# CLOUD-468. **A merged PR is a completion signal for a DIFF. The board reads it
# as one for an ISSUE.** Those coincide only when the issue has exactly one PR,
# and nothing checked that they do.
#
# NAMED `done-pr-check`, NOT `done-check`, and the issue's Mechanism clause says
# `done-check` — corrected here because that name landed first for a DIFFERENT
# predicate (CLOUD-192: no release tag contains a Done issue's commits) and is
# already wired into `release-plz.yml`. Merging the two was considered and
# refused: that caller pipes Done rows with no `.pulls`, which this gate reads as
# "could not look" and answers 2 by design — the clause that keeps an unread PR
# from being the cheapest route to Done. Folding them together would turn a green
# release path red for a reason that has nothing to do with releases. Two
# questions about the same transition, two gates, one caller may run both.
#
# Measured on the board itself, 2026-08-12. CLOUD-420 carries FOUR pull requests
# — #362, #363, #366, #368 — and #368 was open and draft. Its `stateHistory`:
#
#     Todo -> In Progress   06:33
#     In Progress -> Done   07:17     <- premature
#     Done -> In Progress   07:52     <- reversed by hand, 35 minutes later
#
# The reversal is the evidence: the inference was made, acted on, and undone by a
# human. It was then made independently a second time, in a session reading the
# same board — two occurrences of one mechanizable error inside six hours. Two of
# CLOUD-420's own acceptance clauses were still unmet at the moment it read Done,
# and both lived in the PR nobody had noticed was open.
#
# This is the threat model rather than a novel class: honest error about a
# COMPLETION SIGNAL. Non-negotiable 2 — a rule without a runnable gate is half a
# change — so here is the gate.
#
# **Not the same question as its neighbours.** CLOUD-192 is about WHEN the
# automation fires (merge rather than release); this is about whether the
# transition is licensed AT ALL given the issue's own attachments — an issue with
# an open PR is not Done on any schedule. `graph-check` answers the ready
# frontier and the `In Review => linked PR` rule, which is the entry to review,
# not the exit from it. `landed-check` answers "this ref is on main, so it is at
# least In Review". None of them can see a second PR still in flight.
#
# **What it decides, and what it refuses to guess.** Arithmetic only: N attached
# pull requests, k of them open => not Done. It does NOT judge whether the merged
# ones did the work, which is not computable and would make this a judge rather
# than a gate (CLOUD-93, non-negotiable 3).
#
# **Interface: agents fetch, gates decide.** No tracker credential exists in this
# task, so the caller pipes what it already has — `get_issue` payloads, each
# carrying the PR states it fetched for that issue's attachments under `pulls`.
# Same normalisation `claim-check` and `graph-check` perform, so all three
# compose in one pipeline, and nothing here can hang, rate-limit, or behave
# differently in the sandbox than in CI.
#
# Exit 0 Done is licensed / 1 refused / 2 unreadable stdin.
#
# Declared mutations (CLOUD-418), one per clause the suite must be able to lose.
# The host anchor is here because widening the filter to `pull/[0-9]+` SURVIVED
# every other row when this was first written — the number capture requires a
# leading slash, so it rejects `how-to-pull/123` on its own, and only a
# same-shaped URL on another forge tells the two apart.
#MUTANT draft-not-open|s/^\t\tif \[ "\$(jq -r '\.draft \/\/ false' <<<"\$pull")" = true \]; then$/\t\tif false; then/|DRAFT pull request refuses
#MUTANT open-state-ignored|s/^\t\tif \[ "\$(jq -r '\.state \/\/ ""' <<<"\$pull")" = open \]; then$/\t\tif false; then/|OPEN pull request refuses
#MUTANT no-pr-licensed|s/^\tif \[ -z "\$numbers" \]; then$/\tif false; then/|no pull request at all is refused
#MUTANT absent-state-licensed|s/^\t\tif \[ -z "\$pull" \]; then$/\t\tif false; then/|COULD NOT LOOK
#MUTANT filter-host-unanchored|s@github\\\\\.com/\.+/pull/@pull/@|another host is not a PR
set -euo pipefail

# Accept either a JSON array or a concatenated stream of payload objects, the
# same normalisation `claim-check` performs.
if ! issues=$(jq -sc 'if length == 1 and (.[0] | type == "array") then .[0] else . end' 2>/dev/null) ||
	[ "$(jq 'length' <<<"$issues")" = 0 ] ||
	! jq -e 'all(.[]; has("id"))' <<<"$issues" >/dev/null 2>&1; then
	echo "::error:: stdin is not a set of get_issue payloads (need id per issue)" >&2
	exit 2
fi

blocked=0
# Pointer-only per non-negotiable rule 4: the issue id, the rule id, and the PR
# NUMBER. Never a PR title, never an issue body — a refusal that quoted either
# would be the payload-reading this repository forbids everywhere else.
report() {
	echo "$1 $2" >&2
	blocked=$((blocked + 1))
}

while read -r id; do
	[ -n "$id" ] || continue
	payload=$(jq -c --arg id "$id" '.[] | select(.id == $id)' <<<"$issues")

	# An attachment whose URL is a GitHub pull request. The filter is
	# `claim-check`'s, character for character, so the two agree by construction
	# on what counts as a PR rather than by two authors agreeing today. Matched
	# on the URL shape rather than the title, which is free text a human wrote.
	numbers=$(jq -r '[.attachments // [] | .[] | .url
	                  | select(test("github\\.com/.+/pull/[0-9]+"))
	                  | capture("/pull/(?<n>[0-9]+)").n] | unique | .[]' <<<"$payload")

	# No pull request at all. `graph-check` already requires one to enter In
	# Review, so Done cannot need less — and an issue that reached Done with
	# nothing linked is the case where this gate has least evidence, not most.
	if [ -z "$numbers" ]; then
		report "$id" "no-pr"
		continue
	fi

	while read -r n; do
		[ -n "$n" ] || continue
		pull=$(jq -c --argjson n "$n" '(.pulls // []) | .[] | select(.number == $n)' <<<"$payload")
		# The caller fetched the issue but not this PR's state. That is "could
		# not look", which is exit 2 and never a licence: the whole defect is a
		# Done granted over a PR nobody checked, so an absent state must not be
		# the path of least resistance to the same outcome.
		if [ -z "$pull" ]; then
			echo "::error:: done-pr-check: $id names PR #$n and stdin carries no state for it. Fetch it and pipe it under .pulls — a Done over an unread PR is the defect this gate exists to refuse." >&2
			exit 2
		fi

		# A DRAFT is open, and it is the sharper case: it is invisible in most
		# PR listings, which is exactly how #368 went unnoticed while its issue
		# was marked Done. Named separately so the refusal says which it is.
		if [ "$(jq -r '.draft // false' <<<"$pull")" = true ]; then
			report "$id" "open-pr (#$n, draft)"
			continue
		fi
		if [ "$(jq -r '.state // ""' <<<"$pull")" = open ]; then
			report "$id" "open-pr (#$n)"
		fi
		# Closed-and-unmerged is deliberately NOT a refusal. An abandoned or
		# superseded PR is a DECIDED outcome, not work in flight, and refusing
		# on it would block Done forever with no action that could clear it —
		# which is the shape of a gate that gets bypassed rather than satisfied.
		# The defect this gate names is an OPEN PR, and only that.
	done <<<"$numbers"
done <<<"$(jq -r '.[].id' <<<"$issues")"

if [ "$blocked" -ne 0 ]; then
	echo "::error:: done-pr-check: not Done — an issue still has a pull request open. A merged PR completes a diff, not an issue; an issue is done when every PR it carries has landed." >&2
	exit 1
fi
