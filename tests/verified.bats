#!/usr/bin/env bats
# The verdict as an artifact keyed to the commit, rather than a remembered exit
# code. The receipt already existed and nothing read it; every consumer read the
# exit status, which an ordinary pipe destroys.
#
# The inversion this suite exists for: a FAILING verify whose exit code has been
# swallowed must still leave the repo unverified. Shape recognition
# (`run-shape-guard`) denies the idioms seen so far; this holds regardless of
# idiom, because no exit code is consulted at all.

setup() {
	GATE="$BATS_TEST_DIRNAME/../mise-tasks/verified"
	REPO="$BATS_TEST_TMPDIR/repo-$BATS_TEST_NUMBER"
	git init -q "$REPO"
	cd "$REPO" || return 1
	git config user.email t@t
	git config user.name t
	git commit -q --allow-empty -m "chore: init"
	git branch -f main
	git update-ref refs/remotes/origin/main main
	git commit -q --allow-empty -m "feat: work"
	HEAD_SHA=$(git rev-parse HEAD)
	MAIN_SHA=$(git rev-parse origin/main)
	RECEIPTS="$(git rev-parse --git-dir)/batten-receipts"
	mkdir -p "$RECEIPTS"
}

# Stand in for a passing verify + linear-check against the current origin/main.
receipts_for() {
	date -u +%FT%TZ >"$RECEIPTS/verify.$1"
	printf '%s' "$MAIN_SHA" >"$RECEIPTS/linear-check.$1"
}

@test "a commit with both current receipts is verified" {
	receipts_for "$HEAD_SHA"
	run "$GATE"
	[ "$status" -eq 0 ]
	[[ "$output" == *"verified:"* ]]
}

@test "THE INVERSION: a failed verify whose exit code was swallowed leaves HEAD unverified" {
	# `mise run verify | tail` exits 0 while verify failed and wrote no receipt.
	# The swallowed status is unavailable to this gate by construction.
	run "$GATE"
	[ "$status" -eq 1 ]
	[[ "$output" == *"NOT verified"* ]]
	[[ "$output" == *"swallowed by a pipe"* ]]
}

@test "the failure names what to run, not merely that it refused" {
	run "$GATE"
	[[ "$output" == *"mise run verify"* ]]
	[[ "$output" == *"never through a pipe"* ]]
}

@test "a verify receipt alone is not enough — linear-check is a separate claim" {
	date -u +%FT%TZ >"$RECEIPTS/verify.$HEAD_SHA"
	run "$GATE"
	[ "$status" -eq 1 ]
	[[ "$output" == *"linear-check receipt"* ]]
}

@test "an amend invalidates the receipt, because it produces a new HEAD" {
	receipts_for "$HEAD_SHA"
	git commit -q --amend --allow-empty -m "feat: work, reworded"
	run "$GATE"
	[ "$status" -eq 1 ]
}

@test "a main that moved under the branch invalidates the receipt" {
	receipts_for "$HEAD_SHA"
	git checkout -q main
	git commit -q --allow-empty -m "chore: someone else landed"
	git update-ref refs/remotes/origin/main main
	git checkout -q -
	run "$GATE"
	[ "$status" -eq 1 ]
	[[ "$output" == *"is now"* ]]
}

@test "a receipt for a different commit does not vouch for this one" {
	receipts_for "$MAIN_SHA"
	run "$GATE"
	[ "$status" -eq 1 ]
}

@test "output is a pointer — it names predicates and shas, never run contents" {
	printf 'secret build output\n' >"$RECEIPTS/verify.$HEAD_SHA"
	run "$GATE"
	[[ "$output" != *"secret build output"* ]]
}

@test "an unresolvable origin/main exits 2 — a checkout problem, not a verdict" {
	receipts_for "$HEAD_SHA"
	git update-ref -d refs/remotes/origin/main
	run "$GATE"
	[ "$status" -eq 2 ]
	[[ "$output" == *"checkout problem"* ]]
}

@test "outside a git repository it exits 2 rather than claiming unverified" {
	cd "$BATS_TEST_TMPDIR" || return 1
	run "$GATE"
	[ "$status" -eq 2 ]
}
