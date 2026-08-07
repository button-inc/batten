#!/usr/bin/env bats
# The mechanism for the board rule, which was prose and therefore skipped.
#
# The failure it encodes: three PRs landed in one session with no issue moved,
# no issue created, and an existing CLOUD issue — carrying measurements that
# contradicted the fix — never read. Every OTHER discipline in that session was
# followed, and every one of those has a gate on a call the agent cannot avoid.

setup() {
	GUARD="$BATS_TEST_DIRNAME/../mise-tasks/issue-guard"
	cd "$BATS_TEST_DIRNAME/.." || return 1
}

# Feed a PreToolUse payload the way Claude Code does.
payload() {
	jq -nc --arg c "$1" '{tool_input: {command: $c}}'
}

denied() {
	[[ "$1" == *'"deny"'* ]]
}

@test "gh pr create with no issue anywhere is denied" {
	run bash -c "payload() { jq -nc --arg c \"\$1\" '{tool_input:{command:\$c}}'; }; payload 'gh pr create --draft --title x' | $GUARD"
	denied "$output"
}

@test "the denial says what to do, not merely that it refused" {
	run bash -c "jq -nc '{tool_input:{command:\"gh pr create\"}}' | $GUARD"
	[[ "$output" == *"Search the board"* ]]
	[[ "$output" == *"BATTEN_ISSUE_GUARD_BYPASS"* ]]
}

@test "an issue named in the command body is enough" {
	run bash -c "jq -nc '{tool_input:{command:\"gh pr create --body Fixes CLOUD-178\"}}' | $GUARD"
	! denied "$output"
}

@test "gh pr ready is gated too — readying is what starts CI" {
	run bash -c "jq -nc '{tool_input:{command:\"gh pr ready 99\"}}' | $GUARD"
	denied "$output"
}

@test "the wrapper form is judged, not the wrapper — mise exec is the sandbox's only form" {
	run bash -c "jq -nc '{tool_input:{command:\"mise exec -- gh pr create --draft\"}}' | $GUARD"
	denied "$output"
}

@test "an unrelated gh call is none of this guard's business" {
	run bash -c "jq -nc '{tool_input:{command:\"gh pr view 99 --json state\"}}' | $GUARD"
	! denied "$output"
}

@test "a non-gh command is not touched" {
	run bash -c "jq -nc '{tool_input:{command:\"git push -u origin HEAD\"}}' | $GUARD"
	! denied "$output"
}

@test "a commit message merely mentioning the command is not the command" {
	run bash -c "jq -nc '{tool_input:{command:\"git commit -m \\\"explain gh pr create in the docs\\\"\"}}' | $GUARD"
	! denied "$output"
}

@test "the bypass is honoured, because a PR sometimes precedes its issue" {
	run bash -c "BATTEN_ISSUE_GUARD_BYPASS=1 jq -nc '{tool_input:{command:\"gh pr create\"}}' | BATTEN_ISSUE_GUARD_BYPASS=1 $GUARD"
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

@test "a branch naming the issue satisfies the guard without touching the command" {
	# The convention Linear's own gitBranchName produces:
	# wenzowski/cloud-178-claudeai-connector-tools-flip...
	local repo="$BATS_TEST_TMPDIR/repo"
	git init -q "$repo"
	cd "$repo" || return 1
	git config user.email t@t
	git config user.name t
	git commit -q --allow-empty -m init
	git checkout -q -b wenzowski/cloud-178-connector-names
	run bash -c "jq -nc '{tool_input:{command:\"gh pr create --draft\"}}' | $GUARD"
	! denied "$output"
}

@test "a commit trailer naming the issue satisfies it, on a branch that does not" {
	local repo="$BATS_TEST_TMPDIR/repo2"
	git init -q "$repo"
	cd "$repo" || return 1
	git config user.email t@t
	git config user.name t
	git commit -q --allow-empty -m init
	git branch -f main
	git update-ref refs/remotes/origin/main main
	git checkout -q -b some-branch-with-no-number
	git commit -q --allow-empty -m "fix: a thing

Refs: CLOUD-178"
	run bash -c "jq -nc '{tool_input:{command:\"gh pr create --draft\"}}' | $GUARD"
	! denied "$output"
}

@test "a branch and history with no issue at all is still denied inside a repo" {
	local repo="$BATS_TEST_TMPDIR/repo3"
	git init -q "$repo"
	cd "$repo" || return 1
	git config user.email t@t
	git config user.name t
	git commit -q --allow-empty -m init
	git branch -f main
	git update-ref refs/remotes/origin/main main
	git checkout -q -b plain-branch
	git commit -q --allow-empty -m "fix: no reference here"
	run bash -c "jq -nc '{tool_input:{command:\"gh pr create --draft\"}}' | $GUARD"
	denied "$output"
}
