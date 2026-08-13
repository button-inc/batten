#!/usr/bin/env bats
# CLOUD-512. The guard that demands a move to In Review be ADJUDICATED.
#
# The rows are written so that a gate testing mere receipt EXISTENCE — which is
# what `claim-guard` and `issue-search-guard` do, correctly, for their own
# questions — fails the wrong-id row and the stale row. Those two are the
# incident: the CLOUD-480 sweep would have satisfied an existence gate, because
# the same session had run `graph-check` over a different closure minutes earlier.
#
# Every test runs inside a throwaway `git init`, because the subject IS the git
# dir: a suite running in this repo's checkout would mint or read receipts that
# authorise a real session's board writes.

setup() {
	GUARD="$BATS_TEST_DIRNAME/../mise-tasks/board-move-guard"
	CHECK="$BATS_TEST_DIRNAME/../mise-tasks/graph-check"
	REPO="$BATS_TEST_TMPDIR/repo"
	mkdir -p "$REPO"
	git -C "$REPO" init --quiet
	# Per fixture, never inherited: a CI runner carries no global identity, so a
	# bare `git commit` here fails only there.
	git -C "$REPO" config user.email t@example.com
	git -C "$REPO" config user.name t
	git -C "$REPO" commit -q --allow-empty -m init
	cd "$REPO" || return 1
	RECEIPT="$REPO/.git/batten-receipts/board-move"
	mkdir -p "$REPO/.git/batten-receipts"
}

# The payload goes through a FILE, and the helper prints its path — embedding
# JSON into a `bash -c` string lets the shell reinterpret its braces before the
# guard sees it, which `issue-search-guard.bats` records as having failed nine of
# its fifteen rows.
move() {
	# `${2-…}`, not `${2:-…}`: the stateless row passes an explicit empty string,
	# and the colon form substitutes the default over it — which silently sent a
	# move where the case meant to send none.
	jq -nc --arg t "${3:-mcp__Linear__save_issue}" --arg id "${1:-CLOUD-1}" --arg s "${2-In Review}" \
		'{tool_name: $t, tool_input: ({id: $id, description: "groomed"} + (if $s == "" then {} else {state: $s} end))}' \
		>"$BATS_TEST_TMPDIR/payload.json"
	printf '%s\n' "$BATS_TEST_TMPDIR/payload.json"
}
create() {
	jq -nc '{tool_name: "mcp__Linear__save_issue", tool_input: {title: "a finding", state: "In Review"}}' \
		>"$BATS_TEST_TMPDIR/payload.json"
	printf '%s\n' "$BATS_TEST_TMPDIR/payload.json"
}
# Arithmetic on the recorded epoch, never a `sleep`: a wall-clock wait would make
# the suite grade the scheduler, which is the CLOUD-448 defect in land-lock.bats.
adjudicated() {
	local age="$1"
	shift
	printf '%s %s\n' "$(($(date -u +%s) - age))" "$*" >>"$RECEIPT"
}

@test "a move to In Review with no adjudication is denied, and the denial names graph-check" {
	run bash -c "'$GUARD' < $(move)"
	[ "$status" -eq 0 ]
	[[ "$output" == *'"permissionDecision": "deny"'* ]]
	[[ "$output" == *"graph-check"* ]]
}

@test "a move covered by a fresh adjudication is allowed" {
	adjudicated 5 CLOUD-1 CLOUD-2
	run bash -c "'$GUARD' < $(move)"
	[ "$status" -eq 0 ]
	[ -z "$output" ]
}

# THE INCIDENT, half one. A receipt exists — an existence gate passes this — and
# it judged a different closure. That is the sweep that put CLOUD-480 In Review.
@test "an adjudication that judged OTHER issues does not authorise this one" {
	adjudicated 5 CLOUD-2 CLOUD-3
	run bash -c "'$GUARD' < $(move CLOUD-1)"
	[[ "$output" == *'"permissionDecision": "deny"'* ]]
}

# THE INCIDENT, half two. One adjudication must not authorise every later sweep
# in the clone; "for this turn" is not computable, so age is the bound.
@test "an adjudication older than the bound is denied, and the bound is configurable" {
	adjudicated 5000 CLOUD-1
	run bash -c "'$GUARD' < $(move)"
	[[ "$output" == *'"permissionDecision": "deny"'* ]]
	run bash -c "BATTEN_BOARD_MOVE_MAX_AGE=99999 '$GUARD' < $(move)"
	[ -z "$output" ]
}

# The two tests are ONE grep over whole lines rather than a max over the file: a
# stale line naming this issue and a fresh line naming others must not combine.
@test "a stale line naming this issue plus a fresh line naming others is not an authorisation" {
	adjudicated 5000 CLOUD-1
	adjudicated 5 CLOUD-2 CLOUD-3
	run bash -c "'$GUARD' < $(move CLOUD-1)"
	[[ "$output" == *'"permissionDecision": "deny"'* ]]
}

# A word boundary, or CLOUD-48 rides in on a receipt that judged CLOUD-480.
@test "an id is matched whole, so a prefix does not authorise a longer key" {
	adjudicated 5 CLOUD-480
	run bash -c "'$GUARD' < $(move CLOUD-48)"
	[[ "$output" == *'"permissionDecision": "deny"'* ]]
}

@test "every other column is somebody else's question and is never gated here" {
	local col
	for col in Todo "In Progress" Done Backlog Canceled Duplicate; do
		run bash -c "'$GUARD' < $(move CLOUD-1 "$col")"
		[ "$status" -eq 0 ]
		[ -z "$output" ]
	done
}

@test "a save_issue that sets no state at all is not a move" {
	run bash -c "'$GUARD' < $(move CLOUD-1 '')"
	[ -z "$output" ]
}

@test "the column is read case- and space-insensitively" {
	local spelling
	for spelling in "in review" "IN REVIEW" "inReview" "in_review"; do
		run bash -c "'$GUARD' < $(move CLOUD-1 "$spelling")"
		[[ "$output" == *'"permissionDecision": "deny"'* ]]
	done
}

# Creating is `issue-search-guard`'s arm, and a create cannot be a move.
@test "creating an issue is never gated here, even with a state" {
	run bash -c "'$GUARD' < $(create)"
	[ "$status" -eq 0 ]
	[ -z "$output" ]
}

# CLOUD-178 measured the same connector exposed under three names in one session.
@test "all three live connector spellings are gated identically" {
	local tool
	for tool in mcp__Linear__save_issue mcp__claude_ai_Linear__save_issue mcp__4db58e41-0000-0000-0000-000000000000__save_issue; do
		run bash -c "'$GUARD' < $(move CLOUD-1 'In Review' "$tool")"
		[[ "$output" == *'"permissionDecision": "deny"'* ]]
	done
}

@test "a tool that does not save an issue is never gated" {
	local tool
	for tool in mcp__Linear__save_comment mcp__Linear__list_issues Bash Write; do
		run bash -c "'$GUARD' < $(move CLOUD-1 'In Review' "$tool")"
		[ -z "$output" ]
	done
}

# A UUID is a spelling `id` accepts, and a hook has no credential to resolve it to
# a key. A genuine cannot-look, so it allows: denying would refuse a legitimate
# move over a spelling the agent is entitled to use.
@test "an id that is not an issue key fails open rather than denying" {
	run bash -c "'$GUARD' < $(move 7f3a1b2c-0000-4000-8000-000000000000)"
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

@test "a malformed receipt line is not an authorisation" {
	printf 'not-a-number CLOUD-1\n' >"$RECEIPT"
	run bash -c "'$GUARD' < $(move CLOUD-1)"
	[[ "$output" == *'"permissionDecision": "deny"'* ]]
}

# A receipt from the future is a clock that moved, not a fresh adjudication. It
# must not mint an unbounded licence, and it is not a defect in the write either.
@test "a receipt stamped in the future fails open rather than authorising" {
	adjudicated -3600 CLOUD-1
	run bash -c "'$GUARD' < $(move CLOUD-1)"
	[ -z "$output" ]
}

@test "the bypass is honoured" {
	run bash -c "BATTEN_BOARD_MOVE_BYPASS=1 '$GUARD' < $(move)"
	[ -z "$output" ]
}

# Pointer-only, non-negotiable 4: the refusal names the key and how to adjudicate,
# never a line of whatever the agent was about to write.
@test "the denial carries no payload content" {
	run bash -c "'$GUARD' < $(move)"
	[[ "$output" != *"groomed"* ]]
}

# THE COMPOSITION, and the anti-vacuity partner for the whole file: the receipt
# the guard demands is the one `graph-check` actually mints, and a board it
# REFUSES mints nothing. Without this the two halves could disagree for ever.
@test "graph-check mints the receipt this guard reads, and only on a coherent board" {
	jq -nc '{id:"CLOUD-1", status:"Done", attachments:[], relations:{blockedBy:[]},
	         description:"**Refinement — Ready (t)**\n\n* **Source of truth (§1).** One artifact."}' >board.json
	run bash -c "'$CHECK' <board.json"
	[ "$status" -eq 0 ]
	run bash -c "'$GUARD' < $(move CLOUD-1)"
	[ -z "$output" ]

	# A board signalling falsely — In Review with no PR — must authorise nothing.
	rm -f "$RECEIPT"
	jq -nc '{id:"CLOUD-2", status:"In Review", attachments:[], relations:{blockedBy:[]},
	         description:"**Refinement — Ready (t)**\n\n* **Source of truth (§1).** One artifact."}' >bad.json
	run bash -c "'$CHECK' <bad.json"
	[ "$status" -eq 1 ]
	run bash -c "'$GUARD' < $(move CLOUD-2)"
	[[ "$output" == *'"permissionDecision": "deny"'* ]]
}
