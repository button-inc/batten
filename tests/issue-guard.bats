#!/usr/bin/env bats
# The mechanism for the board rule, which was prose and therefore skipped.
#
# The failure it encodes: three PRs landed in one session with no issue moved,
# no issue created, and an existing CLOUD issue — carrying measurements that
# contradicted the fix — never read. Every OTHER discipline in that session was
# followed, and every one of those has a gate on a call the agent cannot avoid.
#
# Every case runs in a throwaway repo, never in this one. The first draft ran in
# the real checkout and passed; the commit that added this guard put `Refs:
# CLOUD-178` in its own message, the guard then correctly allowed, and every
# deny case flipped red. A guard whose verdict reads live git state must be
# tested against git state the test controls.

setup() {
	GUARD="$BATS_TEST_DIRNAME/../mise-tasks/issue-guard"
	# A repo with no issue reference anywhere: not in the branch, not in history.
	REPO="$BATS_TEST_TMPDIR/repo-$BATS_TEST_NUMBER"
	git init -q "$REPO"
	cd "$REPO" || return 1
	git config user.email t@t
	git config user.name t
	git commit -q --allow-empty -m "chore: init"
	git branch -f main
	git update-ref refs/remotes/origin/main main
	git checkout -q -b plain-branch
}

# Feed a PreToolUse payload the way Claude Code does.
guard() {
	jq -nc --arg c "$1" '{tool_input: {command: $c}}' | "$GUARD"
}

denied() {
	[[ "$1" == *'"deny"'* ]]
}

@test "gh pr create with no issue anywhere is denied" {
	run guard 'gh pr create --draft --title x'
	denied "$output"
}

@test "the denial says what to do, not merely that it refused" {
	run guard 'gh pr create'
	[[ "$output" == *"Search the board"* ]]
	[[ "$output" == *"BATTEN_ISSUE_GUARD_BYPASS"* ]]
}

@test "gh pr ready is gated too — readying is what starts CI" {
	run guard 'gh pr ready 99'
	denied "$output"
}

@test "the wrapper form is judged, not the wrapper — mise exec is the sandbox's only form" {
	run guard 'mise exec -- gh pr create --draft'
	denied "$output"
}

@test "an issue named in the command body is enough" {
	run guard 'gh pr create --body Fixes CLOUD-178'
	! denied "$output"
}

@test "a branch naming the issue satisfies the guard without touching the command" {
	# The convention Linear's own gitBranchName produces.
	git checkout -q -b wenzowski/cloud-178-connector-names
	run guard 'gh pr create --draft'
	! denied "$output"
}

@test "a commit trailer naming the issue satisfies it, on a branch that does not" {
	git commit -q --allow-empty -m "fix: a thing

Refs: CLOUD-178"
	run guard 'gh pr create --draft'
	! denied "$output"
}

@test "an issue on main but not on this branch does not count" {
	# The reference has to be in work this branch adds, or the guard would pass
	# on any repo whose history has ever mentioned an issue.
	git checkout -q main
	git commit -q --allow-empty -m "chore: mentions CLOUD-999"
	git update-ref refs/remotes/origin/main main
	git checkout -q plain-branch
	run guard 'gh pr create --draft'
	denied "$output"
}

@test "an unrelated gh call is none of this guard's business" {
	run guard 'gh pr view 99 --json state'
	! denied "$output"
}

@test "a non-gh command is not touched" {
	run guard 'git push -u origin HEAD'
	! denied "$output"
}

@test "a commit message merely mentioning the command is not the command" {
	run guard 'git commit -m "explain gh pr create in the docs"'
	! denied "$output"
}

@test "the bypass is honoured, because a PR sometimes precedes its issue" {
	BATTEN_ISSUE_GUARD_BYPASS=1 run guard 'gh pr create'
	! denied "$output"
}

@test "unparseable input fails open rather than blocking every command" {
	run bash -c "printf 'not json' | $GUARD"
	! denied "$output"
	[ "$status" -eq 0 ]
}

@test "an empty command fails open" {
	run bash -c "jq -nc '{tool_input:{}}' | $GUARD"
	! denied "$output"
}

@test "outside a git repo it fails open rather than blocking every PR" {
	cd "$BATS_TEST_TMPDIR" || return 1
	run guard 'gh pr create --draft'
	! denied "$output"
}
