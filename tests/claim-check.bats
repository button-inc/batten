#!/usr/bin/env bats
# The pull-time half of the board discipline (CLOUD-230).
#
# `issue-guard` proves an issue was looked up *at some point*; it fires on `gh pr
# create`, which is the end of the work. This is the check that belongs at the
# start, and the failure it encodes is measured: CLOUD-49 went In Progress at
# 04:29:34 and a second session started writing it about six minutes later,
# throwing the result away. The board carried the claim the whole time.
#
# Every case is a crafted payload, because the whole point of the
# agents-fetch-gates-decide contract is that the verdict is a pure function of
# stdin — no tracker credential, no network, nothing to stub.

setup() {
	CHECK="$BATS_TEST_DIRNAME/../mise-tasks/claim-check"
}

# A get_issue payload with the fields this gate reads.
payload() {
	jq -nc \
		--arg id "${1:-CLOUD-1}" \
		--arg status "${2:-Todo}" \
		--arg assignee "${3:-}" \
		--arg pr "${4:-}" \
		'{
      id: $id,
      status: $status,
      assignee: (if $assignee == "" then null else $assignee end),
      attachments: (if $pr == "" then [] else [{url: $pr}] end)
    }'
}

@test "a Todo issue with nobody on it is pullable" {
	run bash -c "$(declare -f payload); payload CLOUD-230 Todo | $CHECK"
	[ "$status" -eq 0 ]
	[[ "$output" == *"pullable"* ]]
}

@test "the pullable message says to claim it, because the automation will not" {
	# The whole diagnosis in one line: the transition fires on the PR event, so
	# an agent that waits for it has already done the work.
	run bash -c "$(declare -f payload); payload CLOUD-230 Todo | $CHECK"
	[[ "$output" == *"before you write code"* ]]
	[[ "$output" == *"PR event"* ]]
}

@test "an issue already In Progress is not pullable" {
	run bash -c "$(declare -f payload); payload CLOUD-49 'In Progress' a@b | $CHECK"
	[ "$status" -eq 1 ]
	[[ "$output" == *"CLOUD-49 not-todo (in In Progress)"* ]]
}

@test "In Review and Done are not pullable either" {
	for state in "In Review" Done; do
		run bash -c "$(declare -f payload); payload CLOUD-49 '$state' | $CHECK"
		[ "$status" -eq 1 ]
		[[ "$output" == *"not-todo"* ]]
	done
}

@test "a Todo issue someone has already assigned is flagged" {
	run bash -c "$(declare -f payload); payload CLOUD-49 Todo a@b | $CHECK"
	[ "$status" -eq 1 ]
	[[ "$output" == *"CLOUD-49 assigned"* ]]
}

@test "a Todo issue with a PR already attached is flagged, with the PR number" {
	# The case the column alone misses: someone published before the board moved.
	run bash -c "$(declare -f payload); payload CLOUD-49 Todo '' https://github.com/button-inc/batten/pull/145 | $CHECK"
	[ "$status" -eq 1 ]
	[[ "$output" == *"CLOUD-49 has-pr (145)"* ]]
}

@test "a non-PR attachment is not a claim" {
	# Issues carry design docs and links; only a pull request means published work.
	run bash -c "$(declare -f payload); payload CLOUD-230 Todo '' https://linear.app/buttoninc/document/x | $CHECK"
	[ "$status" -eq 0 ]
}

@test "output is pointer-only — the issue id and the rule, never a body" {
	run bash -c "$(declare -f payload); payload CLOUD-49 'In Progress' | $CHECK"
	[[ "$output" != *"description"* ]]
	[[ "$output" != *"Why"* ]]
}

@test "a set of issues is judged as a set, and one bad apple blocks" {
	run bash -c "$(declare -f payload); { payload CLOUD-230 Todo; payload CLOUD-49 'In Progress'; } | $CHECK"
	[ "$status" -eq 1 ]
	[[ "$output" == *"CLOUD-49 not-todo"* ]]
	[[ "$output" != *"CLOUD-230 not-todo"* ]]
}

@test "a JSON array is accepted as well as a stream, matching graph-check" {
	run bash -c "$(declare -f payload); payload CLOUD-230 Todo | jq -s '.' | $CHECK"
	[ "$status" -eq 0 ]
}

@test "unreadable stdin is exit 2, distinct from a failing check" {
	run bash -c "printf 'not json' | $CHECK"
	[ "$status" -eq 2 ]
	[[ "$output" == *"not a set of get_issue payloads"* ]]
}

@test "empty stdin is exit 2, not a silent pass" {
	# A gate that reports pullable over nothing is the false green this repo
	# keeps re-meeting: an empty pipe must never read as permission.
	run bash -c "printf '' | $CHECK"
	[ "$status" -eq 2 ]
}

@test "a payload missing status is unreadable rather than assumed Todo" {
	run bash -c "echo '{\"id\":\"CLOUD-1\"}' | $CHECK"
	[ "$status" -eq 2 ]
}

# --- the claim receipt (CLOUD-272) ------------------------------------------
#
# `claim-check` was a pure read: it answered "is this pullable" and left no
# trace, so nothing downstream could tell a claimed branch from an unclaimed
# one. The receipt is that answer made durable, and `claim-guard` is its only
# reader.

setup_repo() {
	REPO="$BATS_TEST_TMPDIR/claimed"
	mkdir -p "$REPO"
	git -C "$REPO" init -q -b work
	git -C "$REPO" config user.email t@example.com
	git -C "$REPO" config user.name t
	git -C "$REPO" commit -q --allow-empty -m seed
	RECEIPT="$REPO/$(git -C "$REPO" rev-parse --git-dir)/batten-receipts/claim.work"
}

@test "the pullable path mints a receipt for the current branch" {
	setup_repo
	run bash -c "$(declare -f payload); payload CLOUD-272 Todo | (cd '$REPO' && $CHECK)"
	[ "$status" -eq 0 ]
	[ -f "$RECEIPT" ]
	# It records WHICH issue was cleared, so the trace is auditable rather than
	# a bare flag.
	[[ "$(cat "$RECEIPT")" == *"CLOUD-272"* ]]
}

@test "a NOT-pullable issue mints nothing — the receipt is the claim, not the attempt" {
	for state in "In Progress" "In Review" Done; do
		setup_repo
		run bash -c "$(declare -f payload); payload CLOUD-49 '$state' | (cd '$REPO' && $CHECK)"
		[ "$status" -eq 1 ]
		[ ! -f "$RECEIPT" ]
	done
	setup_repo
	run bash -c "$(declare -f payload); payload CLOUD-49 Todo a@b | (cd '$REPO' && $CHECK)"
	[ "$status" -eq 1 ]
	[ ! -f "$RECEIPT" ]
	setup_repo
	run bash -c "$(declare -f payload); payload CLOUD-49 Todo '' https://github.com/o/r/pull/7 | (cd '$REPO' && $CHECK)"
	[ "$status" -eq 1 ]
	[ ! -f "$RECEIPT" ]
}

@test "unreadable stdin mints nothing either" {
	setup_repo
	run bash -c "printf 'not json' | (cd '$REPO' && $CHECK)"
	[ "$status" -eq 2 ]
	[ ! -f "$RECEIPT" ]
}

@test "outside a checkout the verdict still stands — the receipt is a side effect" {
	# The gate's answer must not depend on being in a repo: `graph-check` and
	# this compose in one pipeline, and a caller inspecting the board from
	# anywhere still deserves the verdict.
	run bash -c "$(declare -f payload); payload CLOUD-272 Todo | (cd '$BATS_TEST_TMPDIR' && $CHECK)"
	[ "$status" -eq 0 ]
	[[ "$output" == *"pullable"* ]]
}
