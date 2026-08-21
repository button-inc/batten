#!/usr/bin/env bash
#MISE description="Emit the issue keys each MERGED pull request closed, as `<CLOUD-id><TAB><pr-number>` — the evidence landed-check decides on (CLOUD-814)"
#
# CLOUD-814. CLOUD-804 made landedness a disjunction and moved half of it to the
# caller: `landed-check --merged-prs <file>`, refusing with exit 2 when the file
# is absent rather than reporting a column it never checked. That refusal is
# right — at 3% commit-keyword coverage a commits-only reading answers "clean"
# almost always — but NOTHING PRODUCED THE FILE. Measured on `cdc6644`, the only
# two references in the repository were both consumers, and the only thing that
# had ever built one was an ad-hoc script under /tmp that dies with its
# container. So `mise run in-progress-drain` was unrunnable in a fresh clone:
# non-negotiable rule 2 inverted, the gate runnable and its input feedforward.
#
# THIS DECIDES NOTHING, which is what lets it hold a credential. The board-payload
# gates — `landed-check`, `graph-check`, `done-check`, `released`, `done-pr-check`,
# `board-move-guard` — are uniformly gh-free, and that is the agents-fetch-gates-
# decide split rather than an accident. This is the FETCH side: it gathers
# evidence and emits it, `landed-check` remains the one authority on landedness,
# and `claimed-keys` remains the one authority on what a closing keyword is. The
# same split `branch-age-check` draws when it reads the remote's refs.
#
# WHY IT ASKS `claimed-keys` PER PULL REQUEST rather than grepping the bodies
# itself: a second copy of CLAIM_RE is a second authority, and CLOUD-378 was
# filed for applying `claimed-keys` to one side of a comparison and not the
# other. Per-PR invocation is also what keys each answer to its number. It passes
# `--closing-only` (CLOUD-804) because the branch-name and `Refs:` fallbacks
# answer "what does this branch claim", which would readmit the citation this
# whole chain exists to refuse.
#
# TRUNCATION IS THE CORRECTNESS RISK, NOT A DETAIL, and it is measured rather
# than anticipated. `gh pr list --state merged --limit 400` returned exactly 400
# and cut the range at #161, hiding #170, #337 and #339, which then had to be
# checked one at a time by hand. This repository has 554 merged pull requests.
#
# The direction matters: a truncated evidence file is an UNDER-report, so a row
# whose work landed reads as live work and the drain stops naming it — silently,
# which is the property that makes it worse than an over-report. So the limit is
# explicit and the count is CHECKED AGAINST IT: a result equal to the limit means
# capped, and capped is "could not look", never a short answer. That is the
# general form of the issue's "pages to exhaustion", and it keeps working when
# the repository outgrows whatever number is written here.
#
# An empty result is also could-not-look, copying `branch-age-check`'s reading
# that a remote reporting no branches at all cannot be true of a repository with
# a trunk. An empty evidence file would silently disarm half the disjunction.
#
# Injectable, so the suite runs offline with no `gh` and no network:
#   MERGED_PR_KEYS_SOURCE  file of the JSON `gh pr list --json number,body` returns
#   MERGED_PR_KEYS_LIMIT   the fetch limit, so a case can drive the cap cheaply
#
# Exit 0 with rows / 2 could-not-look. There is no exit 1: this reports evidence
# and decides no verdict, so it has no "violation" to report.
#
# The mutations target the two conjuncts a caller cannot see for itself.
#MUTANT merged-pr-keys-ignores-truncation|s@^if \[ "\$count" -ge "\$limit" \]; then@if false; then@|a reading at the fetch limit is refused as truncated, not returned short
#MUTANT merged-pr-keys-accepts-empty|s@^if \[ "\$count" -eq 0 \]; then@if false; then@|an empty forge answer is could-not-look, never an empty evidence file
set -euo pipefail

cannot_look() {
	echo "::error:: merged-pr-keys: $1" >&2
	exit 2
}

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
limit="${MERGED_PR_KEYS_LIMIT:-5000}"
case "$limit" in
'' | *[!0-9]*) cannot_look "MERGED_PR_KEYS_LIMIT is not a number ('$limit')" ;;
esac

# --- the reading --------------------------------------------------------------
if [ -n "${MERGED_PR_KEYS_SOURCE:-}" ]; then
	raw=$(cat "$MERGED_PR_KEYS_SOURCE" 2>/dev/null) ||
		cannot_look "cannot read MERGED_PR_KEYS_SOURCE ($MERGED_PR_KEYS_SOURCE)"
else
	command -v gh >/dev/null 2>&1 || cannot_look "\`gh\` is not on PATH, so merged pull requests cannot be read. Set MERGED_PR_KEYS_SOURCE to a saved \`gh pr list --json number,body\` payload instead."
	raw=$(gh pr list --state merged --limit "$limit" --json number,body 2>/dev/null) ||
		cannot_look "cannot list merged pull requests — is \`gh\` authenticated?"
fi

jq -e 'type == "array"' <<<"$raw" >/dev/null 2>&1 ||
	cannot_look "the merged-pull-request reading is not a JSON array"

count=$(jq 'length' <<<"$raw")

# A result AT the limit is indistinguishable from one truncated by it, and the
# truncated reading is the dangerous one. Refuse rather than answer short.
if [ "$count" -ge "$limit" ]; then
	cannot_look "the forge returned $count pull request(s), which is the fetch limit — the answer is truncated and a truncated evidence file makes landed work read as live. Raise MERGED_PR_KEYS_LIMIT above $limit and run again."
fi

if [ "$count" -eq 0 ]; then
	cannot_look "the forge reports no merged pull requests at all, which cannot be true of a repository with a trunk. That is a reachability problem, not an empty answer."
fi

# --- the extraction, delegated ------------------------------------------------
#
# One `claimed-keys` call per pull request, with the body on stdin: argv cannot
# carry a body of arbitrary size (`landed-check` met `Argument list too long` at
# 1.27 MB), and stdin is the channel `claimed-keys` documents for exactly the
# evidence a caller holds and it cannot read for itself.
rows=""
while IFS= read -r idx; do
	number=$(jq -r ".[$idx].number" <<<"$raw")
	case "$number" in
	'' | null | *[!0-9]*) cannot_look "a pull request in the reading carries no usable number" ;;
	esac
	body=$(jq -r ".[$idx].body // \"\"" <<<"$raw")
	keys=$(printf '%s' "$body" | "$here/claimed-keys.sh" --closing-only --branch "" --title "" --log "" 2>/dev/null) ||
		cannot_look "claimed-keys could not judge the body of #$number"
	[ -n "$keys" ] || continue
	while IFS= read -r key; do
		[ -n "$key" ] || continue
		rows+="$key	$number"$'\n'
	done <<<"$keys"
done < <(jq -r 'keys_unsorted[]' <<<"$raw")

# Sorted and de-duplicated, so two runs over the same forge are byte-identical.
# Keys and numbers only — never a title or a body, which is where the keyword
# lives and which rule 4 keeps out of a report.
[ -n "$rows" ] && printf '%s' "$rows" | sort -u
exit 0
