#!/usr/bin/env bats
# CLOUD-508. The guard that demands the read receipt be RECENT.
#
# The rows below are written so that a gate testing mere existence — which is
# what the claim receipt and `issue-search-guard` do, correctly, for their own
# questions — fails exactly one of them. That row is the incident.

setup() {
	CHECK="$BATS_TEST_DIRNAME/../mise-tasks/issue-read-check"
	GUARD="$BATS_TEST_DIRNAME/../mise-tasks/issue-read-guard"
	REPO="$BATS_TEST_TMPDIR/repo"
	mkdir -p "$REPO"
	git -C "$REPO" init --quiet
	git -C "$REPO" config user.email t@example.com
	git -C "$REPO" config user.name t
	git -C "$REPO" commit -q --allow-empty -m init
	cd "$REPO" || return 1
	RECEIPTS="$REPO/.git/batten-receipts"
}

# The payload goes through a FILE, and the helper prints its path — embedding
# JSON into a `bash -c` string lets the shell reinterpret its braces before the
# guard sees it, which is documented in `issue-search-guard.bats` as having
# failed nine of fifteen rows there.
update() {
	jq -nc --arg t "${2:-mcp__Linear__save_issue}" --arg id "${1:-CLOUD-1}" \
		'{tool_name: $t, tool_input: {id: $id, description: "groomed"}}' \
		>"$BATS_TEST_TMPDIR/payload.json"
	printf '%s\n' "$BATS_TEST_TMPDIR/payload.json"
}
create() {
	jq -nc --arg t "${1:-mcp__Linear__save_issue}" '{tool_name: $t, tool_input: {title: "a finding"}}' \
		>"$BATS_TEST_TMPDIR/payload.json"
	printf '%s\n' "$BATS_TEST_TMPDIR/payload.json"
}
# Mint a receipt and then backdate its stamp. Arithmetic on the recorded epoch,
# never a `sleep`: a wall-clock wait would make the suite grade the scheduler,
# which is the CLOUD-448 defect in `land-lock.bats`.
read_at_age() {
	local key="$1" age="$2" now
	jq -nc --arg id "$key" '{id: $id, updatedAt: "2026-08-13T04:00:00.000Z"}' | "$CHECK" >/dev/null
	now=$(date -u +%s)
	printf '%s 2026-08-13T04:00:00.000Z %s\n' "$key" "$((now - age))" >"$RECEIPTS/issue-read.$key"
}

@test "an update with no receipt is denied, and the denial names the fix" {
	run bash -c "'$GUARD' < $(update)"
	[ "$status" -eq 0 ]
	[[ "$output" == *'"permissionDecision": "deny"'* ]]
	[[ "$output" == *"mise run issue-read-check"* ]]
}

@test "an update from a fresh read is allowed" {
	read_at_age CLOUD-1 5
	run bash -c "'$GUARD' < $(update)"
	[ "$status" -eq 0 ]
	[ -z "$output" ]
}

# THE INCIDENT. A receipt exists — an existence gate passes this — and the read
# behind it is 51 minutes old, which is exactly the CLOUD-504 groom.
@test "an update from a read older than the bound is denied" {
	read_at_age CLOUD-1 3060
	run bash -c "'$GUARD' < $(update)"
	[ "$status" -eq 0 ]
	[[ "$output" == *'"permissionDecision": "deny"'* ]]
	# The age is the guard's own `date` minus the fixture's stamp, and a second
	# can tick between the two — so the exact integer is a race, measured as
	# `3061s old` against an asserted `3060s old`. What this case is about is that
	# the denial names an age PAST THE BOUND, which is what a reader acts on, so
	# assert that relation rather than an equality the clock can break.
	[[ "$output" =~ ([0-9]+)s\ old,\ past\ the\ 300s\ bound ]]
	[ "${BASH_REMATCH[1]}" -ge 3060 ]
}

@test "the bound is configurable, and honoured in both directions" {
	read_at_age CLOUD-1 600
	BATTEN_ISSUE_READ_MAX_AGE=900 run bash -c "'$GUARD' < $(update)"
	[ -z "$output" ]
	BATTEN_ISSUE_READ_MAX_AGE=300 run bash -c "'$GUARD' < $(update)"
	[[ "$output" == *'"permissionDecision": "deny"'* ]]
}

# A fresh read of one row must not authorise a stale write to another. This is
# why the receipt is keyed by ISSUE where `claim-check`'s is keyed by branch.
@test "a fresh read of one issue does not authorise an update to a different one" {
	read_at_age CLOUD-1 5
	run bash -c "'$GUARD' < $(update CLOUD-2)"
	[ "$status" -eq 0 ]
	[[ "$output" == *'"permissionDecision": "deny"'* ]]
}

# CLOUD-505's arm, untouched. Creating is `issue-search-guard`'s question.
@test "creating an issue is never gated here, receipt or not" {
	run bash -c "'$GUARD' < $(create)"
	[ "$status" -eq 0 ]
	[ -z "$output" ]
}

# THE ROW THAT FAILS UNDER A PREFIX-ANCHORED MATCHER. CLOUD-178 measured the same
# connector exposed under three names depending on the registration episode.
@test "all three live connector spellings are gated identically" {
	local tool
	for tool in mcp__Linear__save_issue mcp__claude_ai_Linear__save_issue mcp__4db58e41-0000-0000-0000-000000000000__save_issue; do
		run bash -c "'$GUARD' < $(update CLOUD-1 "$tool")"
		[ "$status" -eq 0 ]
		[[ "$output" == *'"permissionDecision": "deny"'* ]]
	done
}

@test "a tool that does not save an issue is never gated" {
	local tool
	for tool in mcp__Linear__save_comment mcp__Linear__list_issues Bash Write; do
		run bash -c "'$GUARD' < $(update CLOUD-1 "$tool")"
		[ "$status" -eq 0 ]
		[ -z "$output" ]
	done
}

# A UUID is a spelling the `id` parameter accepts, and a hook has no tracker
# credential to resolve it to a key. That is a genuine cannot-look, so it allows
# — denying would refuse legitimate updates over a spelling the agent is entitled
# to use, which is the false-positive rate that gets a guard bypassed.
@test "an id that is not an issue key fails open rather than denying" {
	run bash -c "'$GUARD' < $(update 7f3a1b2c-0000-4000-8000-000000000000)"
	[ "$status" -eq 0 ]
	[ -z "$output" ]
}

@test "an unreadable or nameless payload fails open" {
	local bad
	for bad in 'not json' '{}' '{"tool_name":""}' ''; do
		printf '%s' "$bad" >"$BATS_TEST_TMPDIR/bad.json"
		run bash -c "'$GUARD' < '$BATS_TEST_TMPDIR/bad.json'"
		[ "$status" -eq 0 ]
		[ -z "$output" ]
	done
}

# A half-written receipt is a cannot-look, not authorisation and not a verdict —
# the distinction `alive` draws between a corpse and a free lock.
@test "a malformed receipt fails open rather than denying" {
	mkdir -p "$RECEIPTS"
	printf 'CLOUD-1 x not-a-number\n' >"$RECEIPTS/issue-read.CLOUD-1"
	run bash -c "'$GUARD' < $(update)"
	[ "$status" -eq 0 ]
	[ -z "$output" ]
}

# A receipt from the future is a clock that moved, not a fresh read. It must not
# mint an unbounded licence, and it is not a defect in the write either.
@test "a receipt stamped in the future fails open rather than authorising" {
	read_at_age CLOUD-1 -3600
	run bash -c "'$GUARD' < $(update)"
	[ "$status" -eq 0 ]
	[ -z "$output" ]
}

@test "the bypass is honoured" {
	BATTEN_ISSUE_READ_BYPASS=1 run bash -c "'$GUARD' < $(update)"
	[ "$status" -eq 0 ]
	[ -z "$output" ]
}

# Pointer-only, non-negotiable 4: the refusal names the key and the age, never a
# line of whatever the agent was about to write.
@test "the denial carries no payload content" {
	run bash -c "'$GUARD' < $(update)"
	[[ "$output" != *"groomed"* ]]
}
