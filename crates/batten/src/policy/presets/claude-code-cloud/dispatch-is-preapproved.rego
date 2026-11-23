#MUTANT-SUITE crates/batten/tests/it/preapprove.rs
#MUTANT dispatch-uncleared|s@^\tinput.facts\["dispatch-cleared"\] == true$@\ttrue@|a_dispatch_without_approval_is_not_preapproved
#MUTANT dispatch-auto-only|s@^\tinput.call\["permission-mode"\] != "plan"$@\tinput.call["permission-mode"] == "auto"@|a_cleared_dispatch_in_default_mode_is_granted_by_its_rule
# A dispatch the owner already approved is not put to them twice (CLOUD-1978).
#
# The owner's ruling: dispatch prompts are drafted, linted, and approved as a
# bundle through the host's question tool; once a prompt carries both receipts,
# starting or steering a sibling session with exactly that prompt is granted. A
# rejection mints nothing, so the host keeps asking — the dispatch waits, it is
# not refused.
#
# EVERY FACT HERE IS ONE THE ENGINE OWNS. `dispatch-cleared` is resolved at the
# boundary from the receipt store, keyed by the digest of the call's own prompt,
# so a prompt edited after approval reads `false` and grants nothing. The method
# is matched after the last `__`, so the server alias decides nothing.
#
# EVERY MODE BUT PLAN, BY RULING (2026-11-23, CLOUD-2768). It was auto mode
# only, and children booted in `default` put each `send_message` to the owner as
# a prompt. Plan mode is read-only: there the call is refused by `plan write
# refused`, and a dispatch is no read. Pre-tool only: at the permission events
# no fact is resolved, so `dispatch-cleared` reads null, and the mode grant
# already answers the call outside plan.
package batten.claude_code_cloud

import rego.v1

rules contains "call open now"

preapprove contains "call open now" if {
	input.call.event == "pre-tool"
	dispatch_method(input.call.tool)
	input.call["permission-mode"] != "plan"
	input.facts["dispatch-cleared"] == true
}

dispatch_method(tool) if regex.match(`^mcp__[^_].*__(create_session|send_message)$`, tool)

test_a_cleared_dispatch_is_granted_in_auto if {
	"call open now" in preapprove with input as {
		"call": {"event": "pre-tool", "tool": "mcp__Claude_Code_Remote__create_session", "permission-mode": "auto"},
		"facts": {"dispatch-cleared": true},
	}
}

test_an_uncleared_dispatch_is_not if {
	count(preapprove) == 0 with input as {
		"call": {"event": "pre-tool", "tool": "mcp__Claude_Code_Remote__create_session", "permission-mode": "auto"},
		"facts": {"dispatch-cleared": false},
	}
}

test_could_not_look_grants_nothing if {
	count(preapprove) == 0 with input as {
		"call": {"event": "pre-tool", "tool": "mcp__Claude_Code_Remote__send_message", "permission-mode": "auto"},
		"facts": {"dispatch-cleared": null},
	}
}

test_a_cleared_dispatch_is_granted_in_default if {
	"call open now" in preapprove with input as {
		"call": {"event": "pre-tool", "tool": "mcp__Claude_Code_Remote__create_session", "permission-mode": "default"},
		"facts": {"dispatch-cleared": true},
	}
}

test_plan_mode_is_not if {
	count(preapprove) == 0 with input as {
		"call": {"event": "pre-tool", "tool": "mcp__Claude_Code_Remote__create_session", "permission-mode": "plan"},
		"facts": {"dispatch-cleared": true},
	}
}

# A shell line that merely NAMES the method is not the method: the grant keys on
# the tool, so a compound command carrying the word is judged by the shell
# modules and granted nothing here.
test_a_shell_line_naming_the_method_is_not if {
	count(preapprove) == 0 with input as {
		"call": {"event": "pre-tool", "tool": "Bash", "permission-mode": "auto", "command": "echo create_session && true"},
		"facts": {"dispatch-cleared": true},
	}
}

test_another_method_is_not if {
	count(preapprove) == 0 with input as {
		"call": {"event": "pre-tool", "tool": "mcp__Claude_Code_Remote__archive_session", "permission-mode": "auto"},
		"facts": {"dispatch-cleared": true},
	}
}
