#MUTANT-SUITE crates/batten/tests/it/preapprove.rs
#MUTANT background-unchecked|s@^\tinput.call\["run-in-background"\] == true$@\ttrue@|a_foreground_call_is_not_rewritten
#MUTANT timeout-overwritten|s@^\tobject.get(input.call, "timeout", null) == null$@\ttrue@|an_explicit_timeout_is_left_alone
# A backgrounded call that names no timeout runs with the host's maximum
# (CLOUD-2157).
#
# THE MEASURED FAILURE, 2026-10-08. The background rows require
# `run_in_background` on every slow call, and Claude Code gives a backgrounded
# call that names no `timeout` 1,800,000 ms. A mutant sweep run that way was
# killed at 30 minutes, its verdict lost and the sweep spent again. The rows
# forced the slow path and said nothing about the one key that bounds it.
#
# A REWRITE, NOT A REFUSAL: the call is right and its input is incomplete, so
# refusing it would cost a turn to add a number the preset already knows. Both
# numbers are this host's, which is why they live here and never in the core.
#
# RIDES THE GRANT. The engine reads `rewrite` only for a call some module
# pre-approved, because the host applies a rewritten input only beside a
# permission decision. A call nothing grants runs as written.
package batten.claude_code_cloud.background_timeout

import rego.v1

rules contains "timer pin missing"

# Claude Code's ceiling for a backgrounded call, in milliseconds.
maximum := 7200000

rewrite contains {"rule": "timer pin missing", "key": "timeout", "value": maximum} if {
	input.call.event == "pre-tool"
	input.call.tool == "Bash"
	input.call["run-in-background"] == true
	object.get(input.call, "timeout", null) == null
}

call(background, timeout) := {"call": {
	"event": "pre-tool", "tool": "Bash", "permission-mode": "auto",
	"command": "mise run mutant",
	"run-in-background": background, "timeout": timeout,
}}

test_a_backgrounded_call_without_a_timeout_takes_the_maximum if {
	{"rule": "timer pin missing", "key": "timeout", "value": 7200000} in rewrite with input as call(true, null)
}

test_an_explicit_timeout_is_kept if {
	count(rewrite) == 0 with input as call(true, 600000)
}

test_a_foreground_call_is_left_alone if {
	count(rewrite) == 0 with input as call(false, null)
}

# A compound line is one call with one timeout, so it is rewritten the same way:
# the predicate reads the call, never a segment (CLOUD-857).
test_a_compound_backgrounded_line_takes_the_maximum if {
	{"rule": "timer pin missing", "key": "timeout", "value": 7200000} in rewrite with input as {"call": {
		"event": "pre-tool", "tool": "Bash", "permission-mode": "auto",
		"command": "cd /x && mise run mutant",
		"segments": [{"words": ["cd", "/x"]}, {"words": ["mise", "run", "mutant"]}],
		"run-in-background": true, "timeout": null,
	}}
}

test_an_unstated_background_is_left_alone if {
	count(rewrite) == 0 with input as call(null, null)
}
