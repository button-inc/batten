#!/usr/bin/env bats
# subject: mise-tasks/run-shape-guard.sh
# Neutralising text that *describes* the shapes rather than performing them.
#
# Every case here is one the guard denied while it was being written. A guard
# over command text has to distinguish a command from prose about a command, and
# the places that prose actually appears are commit messages, issue bodies and
# documentation heredocs — precisely where these shapes get written down.

setup() {
	GUARD="$BATS_TEST_DIRNAME/../mise-tasks/run-shape-guard.sh"
	cd "$BATS_TEST_DIRNAME/.." || return 1
}

guard() {
	jq -nc --arg c "$1" '{tool_input: {command: $c}}' | "$GUARD"
}

# THE VERDICT IS THE EXIT STATUS NOW, not a document this guard wrote. It is
# dispatched by `batten hook` as a `[[hook.handler]]` row (CLOUD-312 row 4),
# where §7's table is the contract: `2` refuses with its reason on stderr, `0`
# allows, and a host decision document on stdout is `Violation::ImpersonatedHost`
# — reported and never forwarded. `tests/run-shape-guard.bats` carries the same
# pair and the same reason.
#
# `$status` is the global bats `run` sets, so this reads the status of the call
# the case just made; the argument is kept so every call site stays as it was.
denied() {
	[ "$status" -eq 2 ]
}

@test "a multi-line commit message quoting the shapes is not the shapes" {
	# sed is line-based, so a quoted span opened on line 1 and closed on line 20
	# left every line between it exposed. This is the commonest possible shape:
	# a commit message explaining the very rule being added.
	run guard 'git commit -q -m "feat: guard the run shapes

  piped-verdict   mise run verify 2>&1 | tail -6 exits with tail status
  orphaned-run    nohup mise run land >log 2>&1 & returns at once

Both fail green."'
	! denied "$output"
}

@test "a single-line quoted mention is still not the shape" {
	run guard 'git commit -m "explain why mise run verify | tail hides the status"'
	! denied "$output"
}

@test "a heredoc body naming the shapes is documentation" {
	# `&&`, not `;`: since CLOUD-199 a verdict-bearing command followed by `;`
	# is denied for the trailing list, which would pass this test for the wrong
	# reason. `&&` keeps a verdict-bearing command in the string — so the guard
	# is genuinely engaged — while leaving the heredoc prose as the only thing
	# that could trip it.
	run guard 'mise run fmt && python3 - <<PY
text = "detaching with nohup / & loses the wake-up"
PY'
	! denied "$output"
}

@test "a here-string does not open a skip that swallows the rest" {
	# `<<<` is a here-STRING. Treating it as a heredoc opener would skip every
	# following line, silently disabling the guard for the rest of the command.
	#
	# Probed with a foreground `sleep` since CLOUD-443: the shape this used to
	# probe with — a detached `mise run` — belongs to the engine now, but the
	# SCRUBBING is still this guard's and is what the case is about.
	run guard 'grep -q x <<<"$v"; sleep 90'
	denied "$output"
}

@test "a real shape after a closed heredoc is still caught" {
	run guard 'python3 - <<PY
print("a sleep described here")
PY
sleep 120'
	denied "$output"
}

@test "a real shape after a closed quoted span is still caught" {
	run guard 'git commit -m "a message

spanning lines"; sleep 30'
	denied "$output"
}
