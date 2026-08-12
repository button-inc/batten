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
	# A SLASHED branch, because every branch in this repository has one
	# (`claude/…`, `wenzowski/…`) and a scratch repo's default branch is the one
	# shape that does not. Keying a receipt on the raw name makes `lease.claude/x`
	# a path through a directory that never exists, so nothing is written and the
	# guard refuses everything while looking like it works. The fixture is the
	# real shape now; `receipts()` writes through the same transform the task does.
	git checkout -q -b claude/scratch-work
	BRANCH="$(git rev-parse --abbrev-ref HEAD)"
}

ready() { printf '{"tool_input":{"command":"%s"}}' "${1:-gh pr ready 42}" | "$GUARD"; }

receipts() {
	mkdir -p "$RECEIPTS"
	date -u +%FT%TZ >"$RECEIPTS/verify.$HEAD_SHA"
	printf '%s' "${1:-$MAIN_SHA}" >"$RECEIPTS/linear-check.$HEAD_SHA"
	# The landing lease (CLOUD-420 §4). Written by `land-lock`'s `swap` — its only
	# writer, so acquire, renew, the heartbeat's steal path and release all reach
	# it — and refreshed on every beat, which is why a live one is the default here
	# and a case that wants it absent or lapsed has to say so.
	lease "${2:-$(($(date +%s) + 120))}"
}

# Empty argument removes it; anything else is the expiry instant it carries.
lease() {
	mkdir -p "$RECEIPTS"
	local key="lease.${BRANCH//\//-}"
	if [ -z "${1:-}" ]; then
		rm -f "$RECEIPTS/$key"
	else
		printf '%s' "$1" >"$RECEIPTS/$key"
	fi
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

# --- wrappers: the effective program is judged, not the wrapper ---------------

@test "denies a wrapped ready with no receipts" {
	run ready 'mise exec -- gh pr ready 42'
	[[ "$output" == *'"permissionDecision": "deny"'* ]]
}

@test "allows a wrapped ready when both receipts match" {
	receipts
	run ready 'mise exec -- gh pr ready 42'
	[[ "$output" != *deny* ]]
}

@test "gh pr ready --undo is the inverse action and is never gated" {
	# `--undo` converts a PR back to draft, which stops CI rather than starting
	# it, so a verify receipt is beside the point. The guard denied it because
	# flags are stripped before the verb is matched — and that blocked the one
	# call that can only save CI minutes, including the one `land` makes when it
	# bails so the retry push is free.
	run ready 'gh pr ready 167 --undo'
	[[ "$output" != *'"deny"'* ]]
}

@test "a plain gh pr ready is still gated" {
	run ready 'gh pr ready 167'
	[[ "$output" == *'"deny"'* ]]
}

# ---------------------------------------------------------------------------
# The landing lease, CLOUD-420's free half. The runner's precondition catches the
# same mistake, but only after a matrix has been dispatched and cancelled; this
# costs nothing and happens before the event that starts CI.

@test "denies ready when this clone does not hold the landing lease" {
	# THE CASE THIS EXISTS FOR. Four concurrent matrices ran on 2026-08-12 while
	# three sessions handed the lease around correctly — every one of them was a
	# push to a PR that was already ready, which is the state a hand-ready leaves
	# behind permanently.
	receipts
	lease ""
	run ready
	[[ "$output" == *'"permissionDecision": "deny"'* ]]
	[[ "$output" == *"landing lease"* ]]
}

@test "the lease refusal names the task to run, not merely the refusal" {
	receipts
	lease ""
	run ready
	[[ "$output" == *"mise run land"* ]]
}

@test "a LAPSED lease is refused, and the refusal says how long ago" {
	# The receipt is refreshed by the heartbeat, so a lapsed one does not mean
	# "you never had it" — it means the `land` that was holding it is gone, and
	# another branch may already have taken it.
	receipts
	lease "$(($(date +%s) - 30))"
	run ready
	[[ "$output" == *'"permissionDecision": "deny"'* ]]
	[[ "$output" == *"lapsed 3"* ]]
}

@test "a live lease allows the ready" {
	receipts
	run ready
	[ -z "$output" ]
}

@test "FAIL OPEN: an unparseable lease receipt allows rather than guessing" {
	# Same posture as every other unknown in this file. The runner's precondition
	# is the backstop and it is the one that costs money, so this half never has
	# to guess.
	receipts
	lease "not-a-timestamp"
	run ready
	[ -z "$output" ]
}

@test "FAIL OPEN: a detached HEAD has no branch to key a lease by" {
	receipts
	git checkout -q --detach
	run ready
	[ -z "$output" ]
}

@test "the lease is keyed by BRANCH, so another branch's lease does not vouch for this one" {
	# Keyed by branch rather than by sha, like `claim-check`'s and unlike
	# `verify`'s: a lease is a decision about which branch may land, which every
	# commit on it continues to serve. That is exactly why it must not be readable
	# from a different branch.
	receipts
	lease ""
	mkdir -p "$RECEIPTS"
	printf '%s' "$(($(date +%s) + 120))" >"$RECEIPTS/lease.some-other-branch"
	run ready
	[[ "$output" == *'"permissionDecision": "deny"'* ]]
}
