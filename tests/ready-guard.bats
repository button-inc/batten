#!/usr/bin/env bats
# The gate that ships with "verify and linear-check before readying".
#
# Readying starts CI, so a missed step is paid for in CI minutes and a red run on
# a fresh PR. The receipts make the precondition checkable instead of remembered.
#
# Every case runs in a scratch repository built here, never in the working
# clone. The first version read the clone's own HEAD and `origin/main`, which
# passed locally and failed in CI. The cause is single-branch cloning, not
# shallowness or sparseness: `git clone --depth 1` has no `origin/main`, while
# `--depth 1 --no-single-branch` does, because the configured fetch refspec
# covers only the cloned branch. An environment-dependent test proves nothing
# about the guard.

setup() {
	GUARD="$BATS_TEST_DIRNAME/../mise-tasks/ready-guard"
	REPO="$BATS_TEST_TMPDIR/repo"
	mkdir -p "$REPO"
	cd "$REPO" || return 1

	git init -q .
	git config user.email t@example.com
	git config user.name t
	git commit -q --allow-empty -m "base"
	MAIN_SHA="$(git rev-parse HEAD)"
	git update-ref refs/remotes/origin/main "$MAIN_SHA"
	git commit -q --allow-empty -m "work"
	HEAD_SHA="$(git rev-parse HEAD)"
	RECEIPTS="$REPO/.git/batten-receipts"
}

ready() { printf '{"tool_input":{"command":"%s"}}' "${1:-gh pr ready 42}" | "$GUARD"; }

receipts() {
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
	# An amend or a rebase produces a new HEAD, so old receipts must not carry over.
	mkdir -p "$RECEIPTS"
	date -u +%FT%TZ >"$RECEIPTS/verify.$MAIN_SHA"
	printf '%s' "$MAIN_SHA" >"$RECEIPTS/linear-check.$MAIN_SHA"
	run ready
	[[ "$output" == *"deny"* ]]
}

@test "denies ready when main moved after linear-check ran" {
	receipts "0000000000000000000000000000000000000000"
	run ready
	[[ "$output" == *"origin/main"* ]]
	[[ "$output" == *"Rebase"* ]]
}

@test "allows ready when both receipts match this HEAD and this main" {
	receipts
	run ready
	[ -z "$output" ]
}

@test "fails open where there is no origin/main ref" {
	# A single-branch checkout has no such ref. The guard is a local pre-flight,
	# so it must not deny in an environment it cannot evaluate — `linear-check`
	# is what resolves main there, and it is one of the things being demanded.
	receipts
	git update-ref -d refs/remotes/origin/main
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
