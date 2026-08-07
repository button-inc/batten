#!/usr/bin/env bats
# The gate that ships with "verify and linear-check before readying".
#
# Readying starts CI, so the cost of a missed step is paid in CI minutes and a
# red run on a fresh PR. The receipts make the precondition checkable instead of
# remembered.

setup() {
	GUARD="$BATS_TEST_DIRNAME/../mise-tasks/ready-guard"
	cd "$BATS_TEST_DIRNAME/.." || return 1
	RECEIPTS="$(git rev-parse --git-dir)/batten-receipts"
	HEAD_SHA="$(git rev-parse HEAD)"
	MAIN_SHA="$(git rev-parse origin/main)"
	# Stash any real receipts so the suite neither reads nor destroys them.
	SAVED="$BATS_TEST_TMPDIR/saved"
	[ -d "$RECEIPTS" ] && cp -r "$RECEIPTS" "$SAVED"
	rm -rf "$RECEIPTS"
}

teardown() {
	rm -rf "$RECEIPTS"
	[ -d "$SAVED" ] && cp -r "$SAVED" "$RECEIPTS"
	return 0
}

ready() { printf '{"tool_input":{"command":"%s"}}' "${1:-gh pr ready 42}" | "$GUARD"; }

both_receipts() {
	mkdir -p "$RECEIPTS"
	date -u +%FT%TZ >"$RECEIPTS/verify.$HEAD_SHA"
	printf '%s' "${1:-$MAIN_SHA}" >"$RECEIPTS/linear-check.$HEAD_SHA"
}

@test "denies ready with no receipts at all" {
	run ready
	[[ "$output" == *'"permissionDecision": "deny"'* ]]
	[[ "$output" == *"verify receipt"* ]]
}

@test "denies ready when verify passed but linear-check did not" {
	mkdir -p "$RECEIPTS"
	date -u +%FT%TZ >"$RECEIPTS/verify.$HEAD_SHA"
	run ready
	[[ "$output" == *"linear-check receipt"* ]]
}

@test "denies ready when the receipts belong to a different commit" {
	# An amend or a rebase produces a new HEAD, so the old receipts must not count.
	mkdir -p "$RECEIPTS"
	date -u +%FT%TZ >"$RECEIPTS/verify.deadbeef"
	printf '%s' "$MAIN_SHA" >"$RECEIPTS/linear-check.deadbeef"
	run ready
	[[ "$output" == *"deny"* ]]
}

@test "denies ready when main moved after linear-check ran" {
	both_receipts "0000000000000000000000000000000000000000"
	run ready
	[[ "$output" == *"origin/main"* ]]
	[[ "$output" == *"Rebase"* ]]
}

@test "allows ready when both receipts match this HEAD and this main" {
	both_receipts
	run ready
	[ -z "$output" ]
}

@test "ignores commands that are not gh pr ready" {
	for c in 'gh pr view 42' 'gh pr create --draft' 'git commit -m "gh pr ready"' 'echo hi'; do
		run ready "$c"
		[ -z "$output" ]
	done
}

@test "honours the bypass" {
	run bash -c "printf '%s' '{\"tool_input\":{\"command\":\"gh pr ready 42\"}}' | BATTEN_READY_GUARD_BYPASS=1 '$GUARD'"
	[ -z "$output" ]
}
