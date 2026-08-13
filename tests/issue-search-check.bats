#!/usr/bin/env bats
# CLOUD-505. The search receipt. The guard that demands it is
# `tests/issue-search-guard.bats` — `mutant` derives a suite from the gate's own
# name, so the decision and its adapter each need their own file.
#
# Every test runs inside a throwaway `git init`, because the subject IS the git
# dir: the receipt is keyed to the branch and stored under `$GIT_DIR`, so a suite
# running in this repo's checkout would mint receipts that satisfy the guard for
# a real session.

setup() {
	CHECK="$BATS_TEST_DIRNAME/../mise-tasks/issue-search-check"
	REPO="$BATS_TEST_TMPDIR/repo"
	mkdir -p "$REPO"
	git -C "$REPO" init --quiet
	# The identity is set PER FIXTURE, never inherited. A CI runner carries no
	# global one, so a bare `git commit` here is `fatal: empty ident name` — and
	# it fails only there, which is the verify/CI mismatch `land` refuses to
	# land through. Every other fixture suite here spells it the same way.
	git -C "$REPO" config user.email t@example.com
	git -C "$REPO" config user.name t
	git -C "$REPO" commit -q --allow-empty -m init
	cd "$REPO" || return 1
}

receipt() {
	local branch
	branch=$(git symbolic-ref --quiet --short HEAD)
	printf '%s\n' "$(git rev-parse --git-dir)/batten-receipts/issue-search.${branch//\//-}"
}

@test "a list_issues payload mints a receipt naming the ids that were seen" {
	run bash -c "jq -nc '[{id:\"CLOUD-499\"},{id:\"CLOUD-503\"}]' | '$CHECK'"
	[ "$status" -eq 0 ]
	[[ "$output" == *"2 issue(s) seen"* ]]
	[ -f "$(receipt)" ]
	grep -q 'CLOUD-499 CLOUD-503' "$(receipt)"
}

# THE LOAD-BEARING CASE, not an edge one. The commonest honest outcome of
# searching before filing something genuinely new is zero hits. Refusing it would
# make the gate punish the exact behaviour it exists to produce, and would teach
# the bypass within a day.
@test "a search that returned nothing is still a search" {
	run bash -c "jq -nc '[]' | '$CHECK'"
	[ "$status" -eq 0 ]
	[[ "$output" == *"0 issue(s) seen"* ]]
	[ -f "$(receipt)" ]
}

@test "the {issues: [...]} envelope is accepted as well as a bare array" {
	run bash -c "jq -nc '{issues:[{id:\"CLOUD-1\"}]}' | '$CHECK'"
	[ "$status" -eq 0 ]
	[ -f "$(receipt)" ]
}

@test "a payload that is not a search cannot look, and mints nothing" {
	local bad
	for bad in 'not json' '{"prompt":"hi"}' '[{"title":"no id"}]' '42'; do
		run bash -c "printf '%s' $(printf '%q' "$bad") | '$CHECK'"
		[ "$status" -eq 2 ]
		[ ! -f "$(receipt)" ]
	done
}

@test "a detached HEAD cannot look rather than minting an unkeyed receipt" {
	git checkout -q --detach
	run bash -c "jq -nc '[]' | '$CHECK'"
	[ "$status" -eq 2 ]
}
