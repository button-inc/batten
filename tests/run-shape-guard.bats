#!/usr/bin/env bats
# The two shapes the engine cannot express, and what is NOT here is the point.
#
# This suite used to cover five predicates. The three that discard a verdict — a
# pager or filter pipe, a trailing list element, `nohup`/`&` — moved into
# `batten hook` with CLOUD-443, and their corpus moved with them to
# `crates/batten/tests/pipeline_shapes.rs`. Leaving copies here would be two
# suites asserting one predicate, which is how the two come to disagree.
#
# What remains is a foreground `sleep`, whose predicate is over the CALL's
# `run_in_background` rather than over the command string, and a `git commit`
# that can never obtain a message, whose predicate is over heredoc binding.

setup() {
	GUARD="$BATS_TEST_DIRNAME/../mise-tasks/run-shape-guard"
	cd "$BATS_TEST_DIRNAME/.." || return 1
}

guard() {
	jq -nc --arg c "$1" '{tool_input: {command: $c}}' | "$GUARD"
}

denied() {
	[[ "$1" == *'"deny"'* ]]
}

# --- foreground-sleep ---------------------------------------------------------
#
# The fourth shape, and the one that destroys the session rather than a verdict.
# Measured 2026-08-12: a session polled a hung `git commit` with `sleep 90`,
# `sleep 100` and `sleep 180` in the foreground; the harness kills a foreground
# call at ~2 minutes, so the last two failed at exit 143 and 144, and the
# container was reclaimed with the fix uncommitted. AGENTS.md had forbidden this
# in prose for as long as it had forbidden the other three, and nothing enforced
# it — this guard named `sleep` only inside a comment's example.

bg_guard() { # the same call, marked run_in_background
	jq -nc --arg c "$1" '{tool_input: {command: $c, run_in_background: true}}' | "$GUARD"
}

@test "THE MEASURED SHAPE: a sleep in the middle of a compound is denied" {
	run guard 'cd /home/user/batten; sleep 90; git log --oneline -1'
	denied "$output"
	[[ "$output" == *"foreground"* ]]
}

@test "a leading sleep is denied too" {
	run guard 'sleep 45; echo done'
	denied "$output"
}

@test "a SHORT sleep is the same shape spending less" {
	# The predicate is the call's shape, not the duration: 2 seconds still waits
	# inside the call, and it is what the measured session reached for next.
	run guard 'pkill -f hk; sleep 2; git status --short'
	denied "$output"
}

@test "the denial names the remedy: background the wait, act on the exit" {
	run guard 'sleep 60'
	[[ "$output" == *"run_in_background"* ]]
	[[ "$output" == *"exit"* ]]
}

@test "a wrapper does not hide it" {
	run guard 'timeout 300 sleep 120'
	denied "$output"
}

@test "a BACKGROUND sleep is allowed — it is the recommended wait" {
	# `until <test>; do sleep 1; done` backgrounded is the documented form for
	# waiting on a condition, so denying it would be a pure false positive, and
	# a guard with false positives gets bypassed.
	run bg_guard 'until [ -f /tmp/done ]; do sleep 1; done'
	[[ "$output" != *'"deny"'* ]]
}

@test "a sleep written INSIDE a quoted span or a heredoc is not a call" {
	# A commit message or a task body describing the shape is prose, not the
	# shape — the same scrubbing the other three rules depend on.
	run guard 'git commit -m "never use a foreground sleep 90 to poll"'
	[[ "$output" != *'"deny"'* ]]
	run guard "$(printf 'cat > t.bats <<%s\nrun sleep 5\n%s\n' BATS BATS)"
	[[ "$output" != *'"deny"'* ]]
}

@test "a bare command with no sleep and no verdict is still none of this guard's business" {
	run guard 'ls -la'
	[[ "$output" != *'"deny"'* ]]
}

# --- unsatisfiable-commit (CLOUD-488) ----------------------------------------
#
# `git commit` is not verdict-bearing, so these rows also pin that the rule runs
# BEFORE the `last_verdict` early exit — a bare `git commit` reaches it at all.

@test "THE MEASURED SHAPE: the heredoc binds to a later element, so git gets nothing" {
	# `git add -A && git commit -F - … && mise run land … <<EOF` — the opener is
	# in the command string and absent from the element that needed it. ~4
	# minutes of gate on a commit git was always going to refuse.
	run guard "$(printf 'git add -A && git commit -F - >log 2>&1 && mise run land >l2 2>&1 <<%s\nmsg\n%s\n' "'EOF'" EOF)"
	denied "$output"
}

@test "a bare -F - with no redirect anywhere is denied" {
	run guard 'git commit -F -'
	denied "$output"
	run guard 'git commit --file=- >log'
	denied "$output"
}

@test "a git commit naming no message source at all is denied" {
	# Opens $EDITOR in a non-interactive call and blocks there — after the whole
	# gate has already run.
	run guard 'git commit'
	denied "$output"
	run guard 'git commit -a'
	denied "$output"
}

@test "the denial names -F <path>, which is the form that cannot rebind" {
	# A message that only says "this is wrong" reproduces the error: the author
	# writes another heredoc. The remedy has to be the heredoc-free form.
	run guard 'git commit -F -'
	[[ "$output" == *'-F <path>'* ]]
	[[ "$output" == *"pre-commit"* ]]
}

@test "every form that CAN obtain a message stays allowed" {
	local c
	for c in 'git commit -F /tmp/msg.txt' \
		'git commit -m "a message"' \
		'git commit -am "a message"' \
		'git commit --amend --no-edit' \
		'git commit --fixup HEAD' \
		'git commit -C HEAD@{1}'; do
		run guard "$c"
		[[ "$output" != *'"deny"'* ]]
	done
}

@test "a heredoc that genuinely binds to this element is a message source" {
	# The whole point of judging per element: the same `-F -` is correct here.
	run guard "$(printf 'git commit -F - <<%s\nmsg\n%s\n' "'EOF'" EOF)"
	[[ "$output" != *'"deny"'* ]]
}

@test "a file or a here-string redirected into it is a message source too" {
	run guard 'git commit -F - < /tmp/msg.txt'
	[[ "$output" != *'"deny"'* ]]
	run guard 'git commit -F - <<< "$msg"'
	[[ "$output" != *'"deny"'* ]]
}

@test "a git commit written INSIDE a quoted span or a heredoc is not a call" {
	# Same scrubbing every other rule depends on — and this file's own commit
	# message is the most likely place to write the shape down.
	run guard 'echo "git commit -F - hangs the gate"'
	[[ "$output" != *'"deny"'* ]]
	run guard "$(printf 'cat > t.bats <<%s\nrun git commit -F -\n%s\n' BATS BATS)"
	[[ "$output" != *'"deny"'* ]]
}
