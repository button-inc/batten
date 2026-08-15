#!/usr/bin/env bats
# CLOUD-508. The half that records how fresh a read of an issue was.
#
# Split from `issue-read-guard.bats` for the reason `claim-check` is split from
# the claim gate: `mutant` derives a suite from the gate's own name, so a decision
# and its adapter each need their own file to be coverable at all.
#
# Every test runs inside a throwaway `git init`, because the subject IS the git
# dir — the receipt is stored under `$GIT_DIR`, and a suite running in this
# repo's checkout would mint receipts that authorise a real session's writes.

setup() {
	CHECK="$BATS_TEST_DIRNAME/../mise-tasks/issue-read-check"
	REPO="$BATS_TEST_TMPDIR/repo"
	mkdir -p "$REPO"
	git -C "$REPO" init --quiet
	# Per fixture, never inherited: a CI runner carries no global identity, so a
	# bare `git commit` here fails only there.
	git -C "$REPO" config user.email t@example.com
	git -C "$REPO" config user.name t
	git -C "$REPO" commit -q --allow-empty -m init
	cd "$REPO" || return 1
	RECEIPTS="$REPO/.git/batten-receipts"
}

payload() {
	jq -nc --arg id "${1:-CLOUD-1}" --arg u "${2:-2026-08-13T04:00:00.000Z}" \
		'{id: $id, updatedAt: $u, status: "Todo"}'
}

@test "a get_issue payload mints a receipt keyed by the issue" {
	# Piped directly, never through `bash -c "$(payload) | …"`: that embeds the
	# JSON into a shell string, which reinterprets its braces and quotes before
	# the gate sees them. `issue-search-guard.bats` records the same trap costing
	# it nine of fifteen rows.
	run bash -c "'$CHECK'" <<<"$(payload)"
	[ "$status" -eq 0 ]
	[ -f "$RECEIPTS/issue-read.CLOUD-1" ]
	[[ "$output" == *"CLOUD-1"* ]]
}

# The receipt must carry WHEN, not only THAT. Existence alone is the gate this
# replaces — the claim gate's shape — and it cannot express a bound.
@test "the receipt records the revision seen and the time it was seen" {
	payload CLOUD-7 "2026-08-13T03:00:00.000Z" | "$CHECK" >/dev/null
	local line
	line=$(cat "$RECEIPTS/issue-read.CLOUD-7")
	[[ "$line" == "CLOUD-7 2026-08-13T03:00:00.000Z "* ]]
	# Field 3 is an epoch the guard subtracts from `now`; a non-numeric one makes
	# the guard fail open, so its shape is part of the contract between them.
	local stamp
	stamp=$(awk '{print $3}' <<<"$line")
	[[ "$stamp" =~ ^[0-9]+$ ]]
}

# Field 4 is the BODY BASELINE `claim-check` compares against (CLOUD-597,
# CLOUD-615). The contract between the two files is that it moves when the body
# moves and holds still when anything else about the row changes — which is the
# whole reason it exists, since `updatedAt` cannot tell those apart.
@test "the receipt records a body hash that tracks the body and nothing else" {
	local with_body
	with_body() { # with_body <key> <updatedAt> <description>
		jq -nc --arg id "$1" --arg u "$2" --arg d "$3" \
			'{id: $id, updatedAt: $u, status: "Todo", description: $d}'
	}
	field4() { awk 'NR==1{print $4}' "$RECEIPTS/issue-read.$1"; }

	with_body CLOUD-597 "2026-08-13T03:00:00.000Z" "the body" | "$CHECK" >/dev/null
	local first
	first=$(field4 CLOUD-597)
	[[ "$first" =~ ^[0-9a-f]{40}$ ]]

	# The CLOUD-597 shape: the row was touched, the body was not.
	with_body CLOUD-597 "2026-08-14T09:99:00.000Z" "the body" | "$CHECK" >/dev/null
	[ "$(field4 CLOUD-597)" = "$first" ]

	# And the shape the rule must still catch: the body itself changed.
	with_body CLOUD-597 "2026-08-13T03:00:00.000Z" "the body, refined" | "$CHECK" >/dev/null
	[ "$(field4 CLOUD-597)" != "$first" ]
}

@test "a payload with no description still mints, so the baseline is never a lie" {
	# An absent body hashes the empty string rather than being omitted: a missing
	# field would send `claim-check` down its fallback path silently.
	payload CLOUD-3 | "$CHECK" >/dev/null
	[[ "$(awk 'NR==1{print $4}' "$RECEIPTS/issue-read.CLOUD-3")" =~ ^[0-9a-f]{40}$ ]]
}

# Pointer-only, non-negotiable 4. A receipt is read by a human debugging a
# refusal, and an issue body can carry anything.
@test "the receipt carries no title and no body" {
	jq -nc '{id: "CLOUD-2", updatedAt: "2026-08-13T04:00:00.000Z", title: "a secret name", description: "a secret body"}' | "$CHECK" >/dev/null
	run cat "$RECEIPTS/issue-read.CLOUD-2"
	[[ "$output" != *"secret"* ]]
}

# A FRESH READ MUST OVERWRITE A STALE ONE. `issue-search-check` appends, because
# its receipt accumulates what the author has seen; this one answers "how old is
# the newest read", and an append would leave the guard parsing whichever line
# came first — the stalest.
@test "a second read replaces the first rather than appending" {
	payload CLOUD-3 | "$CHECK" >/dev/null
	payload CLOUD-3 | "$CHECK" >/dev/null
	run wc -l <"$RECEIPTS/issue-read.CLOUD-3"
	[ "${output// /}" = 1 ]
}

@test "reads of different issues do not authorise each other" {
	payload CLOUD-4 | "$CHECK" >/dev/null
	[ -f "$RECEIPTS/issue-read.CLOUD-4" ]
	[ ! -f "$RECEIPTS/issue-read.CLOUD-5" ]
}

@test "a payload missing updatedAt still mints, recording the absence" {
	jq -nc '{id: "CLOUD-6", status: "Todo"}' | "$CHECK" >/dev/null
	run cat "$RECEIPTS/issue-read.CLOUD-6"
	[[ "$output" == "CLOUD-6 - "* ]]
}

@test "a single-element array is accepted, so a list payload of one composes" {
	run bash -c "jq -nc '[{id: \"CLOUD-8\", updatedAt: \"x\"}]' | '$CHECK'"
	[ "$status" -eq 0 ]
	[ -f "$RECEIPTS/issue-read.CLOUD-8" ]
}

# Exit 2 is "I could not read the input", distinct from exit 1 "this is not a
# usable read" — a caller piping the wrong thing must not look like one who
# skipped the step. Same split as `claim-check` and `issue-search-check`.
@test "stdin that is not a get_issue payload is exit 2, not a silent mint" {
	local bad
	for bad in 'not json' '{}' '{"title":"no id"}' '[]'; do
		run bash -c "printf '%s' '$bad' | '$CHECK'"
		[ "$status" -eq 2 ]
	done
	run bash -c "ls '$RECEIPTS' 2>/dev/null"
	[ -z "$output" ]
}

# The receipt namespace is issue KEYS. A payload naming the row some other way
# cannot be filed against one, and inventing a name would mint a receipt the
# guard can never match — a hole rather than a refusal.
@test "an id that is not an issue key is refused rather than filed under a made-up name" {
	run bash -c "jq -nc '{id: \"7f3a-not-a-key\", updatedAt: \"x\"}' | '$CHECK'"
	[ "$status" -eq 1 ]
	run bash -c "ls '$RECEIPTS' 2>/dev/null"
	[ -z "$output" ]
}
