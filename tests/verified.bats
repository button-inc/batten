#!/usr/bin/env bats
# subject: mise-tasks/verified
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
	# The developer's global git config must not reach a fixture repo
	# (CLOUD-282). `init.defaultBranch=main` is the leak this suite tripped on —
	# git refuses `branch -f` on the CHECKED-OUT branch, so a machine configured
	# the modern way failed every test in the file at setup, while CI passed only
	# because the runner's git still defaults to `master`. `commit.gpgsign` is
	# the same shape. crates/batten/tests/common/mod.rs:184-185 already does this.
	export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null
	# `-b work`, so the checked-out branch is NAMED rather than inherited. The
	# `main` created below is a second branch marking the trunk while HEAD stays
	# on the feature branch — that topology is what these cases exercise — and
	# the force-create this replaces could only ever build it by accident: it
	# works while git's default is `master`, and git REFUSES to force the branch
	# that is currently checked out, so the same line failed outright the moment
	# a developer's default was the trunk's own name. Naming the branch makes the
	# topology explicit instead of inheriting it, and `main` is then a fresh name
	# needing no force at all. `no-branch-f-main` in batten.toml keeps the old
	# form out; the literal is not spelled here, because that row is a substring
	# rule over this directory and would fire on its own explanation.
	git init -q -b work "$REPO"
	cd "$REPO" || return 1
	git config user.email t@t
	git config user.name t
	git commit -q --allow-empty -m "chore: init"
	git branch main
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
