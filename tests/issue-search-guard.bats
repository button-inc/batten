#!/usr/bin/env bats
# CLOUD-505. The guard that demands the search receipt.
#
# Split from `issue-search-check.bats` for the reason the claim gate is split from
# `claim-check`: `mutant` derives a suite from the gate's own name, so a decision
# and its adapter each need their own file to be coverable at all.
#
# Every test runs inside a throwaway `git init`, because the subject IS the git
# dir: the receipt is keyed to the branch and stored under `$GIT_DIR`, so a suite
# running in this repo's checkout would mint receipts that satisfy the guard for
# a real session.

setup() {
	CHECK="$BATS_TEST_DIRNAME/../mise-tasks/issue-search-check"
	GUARD="$BATS_TEST_DIRNAME/../mise-tasks/issue-search-guard"
	REPO="$BATS_TEST_TMPDIR/repo"
	mkdir -p "$REPO"
	git -C "$REPO" init --quiet
	# Per fixture, never inherited — a CI runner carries no global identity, so
	# a bare `git commit` here fails only there. See `issue-search-check.bats`.
	git -C "$REPO" config user.email t@example.com
	git -C "$REPO" config user.name t
	git -C "$REPO" commit -q --allow-empty -m init
	cd "$REPO" || return 1
}

# The payload goes through a FILE, and the helper prints its path. Embedding the
# JSON into a `bash -c` string instead lets the shell reinterpret its braces and
# quotes before the guard ever sees it — which is how the first version of this
# suite failed nine of fifteen rows on a payload the guard handles correctly.
create() {
	jq -nc --arg t "${1:-mcp__Linear__save_issue}" '{tool_name: $t, tool_input: {title: "a finding"}}' \
		>"$BATS_TEST_TMPDIR/payload.json"
	printf '%s\n' "$BATS_TEST_TMPDIR/payload.json"
}
update() {
	jq -nc --arg t "${1:-mcp__Linear__save_issue}" '{tool_name: $t, tool_input: {id: "CLOUD-1", title: "a finding"}}' \
		>"$BATS_TEST_TMPDIR/payload.json"
	printf '%s\n' "$BATS_TEST_TMPDIR/payload.json"
}

@test "creating an issue with no receipt is denied, and the denial names the fix" {
	run bash -c "'$GUARD' < $(create)"
	[ "$status" -eq 0 ]
	[[ "$output" == *'"permissionDecision": "deny"'* ]]
	[[ "$output" == *"mise run issue-search-check"* ]]
	# Pointer-only: never a guess about what this duplicates, because the gate
	# does not know and guessing would be the model verdict rule 3 refuses.
	[[ "$output" != *"duplicate of"* ]]
}

@test "creating an issue with a receipt is allowed" {
	jq -nc '[]' | "$CHECK" >/dev/null
	run bash -c "'$GUARD' < $(create)"
	[ "$status" -eq 0 ]
	[ -z "$output" ]
}

# An update must never be refused, or every edit to an issue needs a search
# first. The discriminator is `finding-sink-check`'s, already proven here.
@test "updating an existing issue is never gated, receipt or not" {
	run bash -c "'$GUARD' < $(update)"
	[ "$status" -eq 0 ]
	[ -z "$output" ]
}

# THE ROW THAT FAILS UNDER A PREFIX-ANCHORED MATCHER. CLOUD-178 measured the same
# connector exposed under three names depending on the registration episode, and
# a rule naming one matches none of the others — silently.
@test "all three live connector spellings are gated identically" {
	local tool
	for tool in mcp__Linear__save_issue mcp__claude_ai_Linear__save_issue mcp__4db58e41-0000-0000-0000-000000000000__save_issue; do
		run bash -c "'$GUARD' < $(create "$tool")"
		[ "$status" -eq 0 ]
		[[ "$output" == *'"permissionDecision": "deny"'* ]]
	done
}

@test "a tool that does not create an issue is never gated" {
	local tool
	for tool in mcp__Linear__save_comment mcp__Linear__list_issues Bash Write mcp__serena__write_memory; do
		run bash -c "'$GUARD' < $(create "$tool")"
		[ "$status" -eq 0 ]
		[ -z "$output" ]
	done
}

@test "an unreadable or nameless payload fails open" {
	local payload
	for payload in 'not json' '{}' '{"tool_name":""}' ''; do
		run bash -c "printf '%s' $(printf '%q' "$payload") | '$GUARD'"
		[ "$status" -eq 0 ]
		[ -z "$output" ]
	done
}

@test "the bypass is honoured" {
	run bash -c "BATTEN_ISSUE_SEARCH_BYPASS=1 '$GUARD' < $(create)"
	[ "$status" -eq 0 ]
	[ -z "$output" ]
}

@test "outside a git repository the guard fails open rather than blocking every filing" {
	cd "$BATS_TEST_TMPDIR" || return 1
	run bash -c "env GIT_CEILING_DIRECTORIES='$BATS_TEST_TMPDIR' '$GUARD' < $(create)"
	[ "$status" -eq 0 ]
	[ -z "$output" ]
}

# THE REGRESSION CASE: this incident. CLOUD-504 was filed over CLOUD-499, which
# two searches return in seconds. With no receipt the create is refused; once the
# search that would have surfaced CLOUD-499 is recorded, it proceeds.
@test "the CLOUD-504 over CLOUD-499 filing is refused, and allowed after the search" {
	run bash -c "'$GUARD' < $(create)"
	[[ "$output" == *'"permissionDecision": "deny"'* ]]
	run bash -c "jq -nc '[{id:\"CLOUD-499\"}]' | '$CHECK'"
	[ "$status" -eq 0 ]
	run bash -c "'$GUARD' < $(create)"
	[ -z "$output" ]
}

@test "the emitted denial is the hook shape, and it parses" {
	run bash -c "'$GUARD' < $(create) | jq -r '.hookSpecificOutput.hookEventName'"
	[ "$output" = "PreToolUse" ]
}
