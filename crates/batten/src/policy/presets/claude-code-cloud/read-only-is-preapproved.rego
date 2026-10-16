#MUTANT-SUITE crates/batten/tests/it/preapprove.rs
#MUTANT admission-session-preapproved|s@^\tinput.call.admission == "read"$@\tinput.call.admission != "none"@|exit_plan_mode_is_admitted_in_plan_mode_and_never_preapproved
# A call that only reads is never put to the operator (CLOUD-1949).
#
# The host halts on a permission prompt, and a halted session is the failure the
# owner ruled out: "allowed calls must be allowed 100% of the time". A read
# cannot change what any gate decides next, so asking about one buys nothing and
# costs the turn. The engine asks this module only after every deny in the tree
# has had its say, so a read some other rule refuses stays refused (`compose` in
# `lib.rs`, deny first).
#
# WHICH CALLS ARE READS IS NOT DECIDED HERE (CLOUD-2398). It is `hook::admission`,
# projected as `input.call.admission`, the one definition plan mode, the
# unloadable-config floor and the session setup gate also read. This module used
# to carry its own tool, program, git-verb and MCP-verb lists while the floor
# carried another, and the two had already drifted apart.
#
# ONLY `"read"` IS GRANTED. `"session"` — `ExitPlanMode`, `AskUserQuestion`, the
# todo list — mutates nothing in the tree, but `ExitPlanMode`'s prompt IS the
# operator approving a plan, and granting it would skip that approval.
#
# The ERROR DIRECTION is "not proven read-only": `null` is left to the host,
# which prompts — never granted.
package batten.claude_code_cloud

import rego.v1

rules contains "call read now"

preapprove contains "call read now" if {
	input.call.event == "pre-tool"
	read_only(input.call)
}

# A FUNCTION, NEVER A RULE — measured rather than preferred. A module-level
# helper RULE's value computed under one test's `with input as` answered the live
# call too, so `Read` came back not read-only while the same document, handed to
# a test, was. A function has no value to keep between two inputs, because the
# input is its argument.
read_only(call) if {
	call.admission == "read"
}

test_a_read_is_preapproved if {
	"call read now" in preapprove with input as {"call": {"event": "pre-tool", "tool": "Read", "admission": "read"}}
}

test_a_session_call_is_not if {
	count(preapprove) == 0 with input as {"call": {"event": "pre-tool", "tool": "ExitPlanMode", "admission": "session"}}
}

test_an_unproven_call_is_not if {
	count(preapprove) == 0 with input as {"call": {"event": "pre-tool", "tool": "Edit", "admission": null}}
}

test_a_call_with_no_admission_key_is_not if {
	count(preapprove) == 0 with input as {"call": {"event": "pre-tool", "tool": "Read"}}
}
