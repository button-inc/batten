#MUTANT-SUITE crates/batten/tests/it/preapprove.rs
#MUTANT subagent-mode-unchecked|s@^\tinput.call\["permission-mode"\] == "auto"$@\ttrue@|an_implementer_subagent_is_not_preapproved_in_default_mode
# In auto mode a subagent or a workflow is never put to the operator (CLOUD-2026).
#
# The owner's ruling, 2026-09-29: in auto mode subagents and workflows never
# prompt, implementers included; only sibling-session dispatch is gated, by
# receipt (`dispatch-is-preapproved`). A subagent works in this one checkout and
# every tool call it makes passes through the same hook, so each of its writes
# meets every deny in the tree on its own; the spawn itself decides nothing a
# gate could refuse later.
#
# COMPOSED AFTER EVERY DENY, as every grant here is: a worktree spawn is refused
# by `spawn place wrong` and stays refused.
#
# AUTO MODE ONLY. Plan mode keeps its own posture: a read-only subagent is
# granted by `call read now`, and any other spawn is refused by `plan write
# refused`.
package batten.claude_code_cloud

import rego.v1

rules contains "agent open now"

preapprove contains "agent open now" if {
	input.call.event == "pre-tool"
	subagent_tool(input.call.tool)
	input.call["permission-mode"] == "auto"
}

subagent_tool(tool) if tool in {"Agent", "Task", "Workflow"}

test_an_implementer_is_granted_in_auto if {
	"agent open now" in preapprove with input as {"call": {
		"event": "pre-tool", "tool": "Agent", "permission-mode": "auto",
		"arguments": {"subagent_type": "general-purpose", "prompt": "port x"},
	}}
}

test_a_workflow_is_granted_in_auto if {
	"agent open now" in preapprove with input as {"call": {
		"event": "pre-tool", "tool": "Workflow", "permission-mode": "auto",
		"arguments": {"script": "export const meta = {}"},
	}}
}

test_plan_mode_grants_nothing_here if {
	count(preapprove) == 0 with input as {"call": {
		"event": "pre-tool", "tool": "Agent", "permission-mode": "plan",
		"arguments": {"subagent_type": "general-purpose", "prompt": "port x"},
	}}
}

test_default_mode_grants_nothing_here if {
	count(preapprove) == 0 with input as {"call": {
		"event": "pre-tool", "tool": "Workflow", "permission-mode": "default",
		"arguments": {},
	}}
}

# A shell line naming the tool is not the tool: a compound command carrying the
# word is judged by the shell modules and granted nothing here.
test_a_shell_line_naming_the_tool_is_not if {
	count(preapprove) == 0 with input as {"call": {
		"event": "pre-tool", "tool": "Bash", "permission-mode": "auto",
		"command": "echo Agent && true",
	}}
}
