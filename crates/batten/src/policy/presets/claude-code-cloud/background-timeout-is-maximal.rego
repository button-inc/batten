#MUTANT-SUITE crates/batten/tests/it/preapprove.rs
#MUTANT background-unchecked|s@^\tinput.call\["run-in-background"\] == true$@\ttrue@|a_foreground_call_is_not_rewritten
#MUTANT timeout-overwritten|s@^\tobject.get(input.call, "timeout", null) == null$@\ttrue@|an_explicit_timeout_is_left_alone
#MUTANT background-max-ignored|s@^\tis_number(ceiling)$@\tfalse@|a_raised_host_maximum_is_the_pinned_timeout
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
# refusing it would cost a turn to add a number the preset already knows. The
# numbers are this host's, so none lives in the harness-blind core: the ceiling
# arrives as `background-max`, computed by Claude Code's own decode adapter
# (`hook::background_max`), and the two-hour floor below is the host's documented
# maximum for an input that carries none.
#
# RIDES THE GRANT. The engine reads `rewrite` only for a call some module
# pre-approved, because the host applies a rewritten input only beside a
# permission decision. A call nothing grants runs as written.
package batten.claude_code_cloud.background_timeout

import rego.v1

rules contains "timer pin missing"

# THE HOST'S CEILING, AS THE HOST COMPUTES IT (CLOUD-2365). Not a constant: a
# raised `BASH_MAX_TIMEOUT_MS` lifts it, and a pin of the old two hours stopped a
# landing the host would have let run for a week. The host's adapter mirrors its
# arithmetic and hands the answer over as `background-max`; the two-hour floor
# below is for a host that reports none (`null`) or an input without the key.
# A FUNCTION, never a rule:
# a module-level value over `input` can answer a live call with what a `test_`
# computed (`read-only-is-preapproved.rego` measured it), and a function has no
# value to keep between two inputs.
maximum(call) := ceiling if {
	ceiling := object.get(call, "background-max", null)
	is_number(ceiling)
} else := 7200000

rewrite contains {"rule": "timer pin missing", "key": "timeout", "value": maximum(input.call)} if {
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

reporting(ceiling) := {"call": object.union(call(true, null).call, {"background-max": ceiling})}

test_the_host_maximum_is_pinned_when_present if {
	{"rule": "timer pin missing", "key": "timeout", "value": 604800000} in rewrite with input as reporting(604800000)
}

test_a_host_reporting_no_maximum_takes_two_hours if {
	{"rule": "timer pin missing", "key": "timeout", "value": 7200000} in rewrite with input as reporting(null)
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
