#!/usr/bin/env bats
# The guard that puts a gate between DISCOVERING work and EDITING files for it
# (CLOUD-272).
#
# The board discipline had two halves and only one was gated: `issue-guard`
# fires at `gh pr create`, which is the end of the work. Measured on CLOUD-270 —
# a defect was found, implemented, gated, committed and pushed before any issue
# existed, and every guard stayed green because the first one in the path fires
# at publish time. `ready-lint` then failed that issue's Ready block on
# `bump-disagrees-with-type`, a specification error a pre-implementation run
# would have caught for free and no amount of green CI could ever surface.
#
# The predicate is a pure function of the filesystem: a claim receipt exists for
# this branch, or it does not. `claim-check` mints it; that is the board read
# already having happened, left as a local durable trace.

setup() {
	GUARD="$BATS_TEST_DIRNAME/../mise-tasks/claim-guard"
	CHECK="$BATS_TEST_DIRNAME/../mise-tasks/claim-check"
	REPO="$BATS_TEST_TMPDIR/repo"
	mkdir -p "$REPO"
	git -C "$REPO" init -q -b work
	git -C "$REPO" config user.email t@example.com
	git -C "$REPO" config user.name t
	printf 'ignored/\n*.log\n' >"$REPO/.gitignore"
	mkdir -p "$REPO/ignored"
	printf 'x\n' >"$REPO/tracked.md"
	git -C "$REPO" add -A
	git -C "$REPO" commit -qm "seed"
}

# Drive the guard the way the harness does, from inside the repo.
guard() {
	jq -nc --arg p "$1" '{tool_input: {file_path: $p}}' |
		(cd "$REPO" && "$GUARD")
}

denied() {
	[[ "$1" == *'"deny"'* ]]
}

# Mint a receipt the way `claim-check` does on its pullable path.
mint() {
	local dir
	dir=$(git -C "$REPO" rev-parse --git-dir)
	mkdir -p "$REPO/$dir/batten-receipts"
	printf '%s\n' "${1:-CLOUD-272}" >"$REPO/$dir/batten-receipts/claim.work"
}

# --- the refusal ------------------------------------------------------------

@test "THE GAP: an edit inside the repo with no claim receipt is denied" {
	run guard "$REPO/tracked.md"
	denied "$output"
}

@test "the refusal names the escape rather than only refusing" {
	# A refusal with no route is what gets bypassed, and a bypassed guard
	# enforces nothing.
	run guard "$REPO/tracked.md"
	[[ "$output" == *"claim-check"* ]]
	[[ "$output" == *"In Progress"* ]]
}

@test "an untracked-but-not-ignored file is judged too" {
	# Opening a NEW feature file is the first edit this issue exists to catch;
	# exempting untracked paths would leave the hole open in its commonest form.
	run guard "$REPO/brand-new-feature.rs"
	denied "$output"
}

@test "a relative path is resolved against the repo, not left unjudged" {
	run bash -c "jq -nc '{tool_input:{file_path:\"tracked.md\"}}' | (cd '$REPO' && '$GUARD')"
	denied "$output"
}

# --- the escape, and what is never judged -----------------------------------

@test "with a receipt for this branch the same edit is allowed" {
	mint CLOUD-272
	run guard "$REPO/tracked.md"
	! denied "$output"
}

@test "a receipt for a DIFFERENT branch does not vouch for this one" {
	local dir
	dir=$(git -C "$REPO" rev-parse --git-dir)
	mkdir -p "$REPO/$dir/batten-receipts"
	printf 'CLOUD-1\n' >"$REPO/$dir/batten-receipts/claim.some-other-branch"
	run guard "$REPO/tracked.md"
	denied "$output"
}

@test "the receipt survives a commit, unlike a verify receipt" {
	# Keyed by BRANCH, not by SHA, and the difference is the design: a claim
	# attests to a decision about an issue, which every commit on the branch
	# continues to serve. A SHA-keyed claim would expire on the first commit and
	# demand a re-claim per commit — the false-positive rate that gets a guard
	# bypassed.
	mint CLOUD-272
	printf 'more\n' >>"$REPO/tracked.md"
	git -C "$REPO" commit -qam "second"
	run guard "$REPO/tracked.md"
	! denied "$output"
}

@test "a git-ignored path is never judged — that is the scratch-work half" {
	run guard "$REPO/ignored/scratch.md"
	! denied "$output"
	run guard "$REPO/notes.log"
	! denied "$output"
}

@test "a path outside the repository is never judged" {
	run guard "/tmp/scratch-notes.md"
	! denied "$output"
	run guard "$BATS_TEST_TMPDIR/elsewhere.md"
	! denied "$output"
}

# --- failure posture --------------------------------------------------------

@test "outside a checkout it fails open rather than denying every edit" {
	mkdir -p "$BATS_TEST_TMPDIR/bare"
	run bash -c "jq -nc '{tool_input:{file_path:\"$BATS_TEST_TMPDIR/bare/x.md\"}}' | (cd '$BATS_TEST_TMPDIR/bare' && '$GUARD')"
	! denied "$output"
	[ "$status" -eq 0 ]
}

@test "a detached HEAD fails open — there is no branch to key a claim on" {
	git -C "$REPO" checkout -q --detach
	run guard "$REPO/tracked.md"
	! denied "$output"
}

@test "the bypass is honoured, for a deliberate take-over of a stale claim" {
	run bash -c "jq -nc '{tool_input:{file_path:\"$REPO/tracked.md\"}}' | (cd '$REPO' && BATTEN_CLAIM_GUARD_BYPASS=1 '$GUARD')"
	! denied "$output"
}

@test "unparseable input fails open" {
	run bash -c "printf 'not json' | (cd '$REPO' && '$GUARD')"
	! denied "$output"
	[ "$status" -eq 0 ]
}

@test "an event carrying no file_path is nothing to judge" {
	run bash -c "jq -nc '{tool_input:{}}' | (cd '$REPO' && '$GUARD')"
	! denied "$output"
}
