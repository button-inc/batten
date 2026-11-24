# A `create_trigger` is admitted only when its own prompt names an open child
# session (CLOUD-2889).
#
# The `send_later` arm's ruling and reasoning, over the other timer tool
# (`policy/timer-mint.rego` carries them in full): a Routine naming a session
# this session created and has not archived — `input.facts.minted["children-open"]`
# — is a wait on that child; one naming none, a PR heartbeat above all, is
# refused, listing the open ids. Null, absent and empty all refuse.
#
# ITS OWN MODULE FOR ITS OWN REMEDY: a module's finding id resolves to the row
# that binds the module, so this id gets its row's `reason` back rather than
# `commit read missing`'s absent one.
#MUTANT-SUITE crates/batten/tests/it/child_wait.rs
#MUTANT trigger-children-unread|s@^\tnot names_open_child(input.call.arguments.prompt)$@\ttrue@|create_trigger_naming_an_open_child_is_admitted
#MUTANT trigger-unrefused|s@^\tcalls("create_trigger")$@\tfalse@|create_trigger_naming_no_open_child_is_refused
#MUTANT trigger-spelling-unread|s@^\tendswith(input.call.tool, concat("", \["__", name\]))$@\tfalse@|create_trigger_naming_no_open_child_is_refused
#MUTANT trigger-children-match-unread|s@^\tcontains(text, id)$@\tfalse@|create_trigger_naming_an_open_child_is_admitted
#MUTANT trigger-children-unlisted|s@^\t"subjects": child_subjects,$@\t"subjects": [],@|create_trigger_naming_no_open_child_is_refused

# METADATA
# description: |
#   Bound to the MEDIATED-CALL surface: `input.call.arguments` is the tool's own
#   input, `input.facts.minted` the open-child receipts.
#   THIS BLOCK IS YAML AND MUST STAY THE LAST COMMENT BLOCK BEFORE `package`.
# schemas:
#   - input: schema["policy-call.schema"]
package batten.event_mint

import rego.v1

rules contains "event mint refused"

violation contains {
	"rule": "event mint refused",
	"verdict": "call name refused",
	"subjects": child_subjects,
} if {
	calls("create_trigger")
	not names_open_child(input.call.arguments.prompt)
}

calls(name) if {
	input.call.tool == name
}

calls(name) if {
	endswith(input.call.tool, concat("", ["__", name]))
}

open_children contains id if {
	some id, _ in input.facts.minted["children-open"]
}

names_open_child(text) if {
	is_string(text)
	some id in open_children
	contains(text, id)
}

child_subjects := [{"artifact": id} | some id in sort(open_children)]

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

child := "session_01ChildAbc"

open_child := {"minted": {"children-open": {"session_01ChildAbc": "open"}}}

trigger_call(tool, arguments) := {"call": {
	"command": "",
	"tool": tool,
	"arguments": arguments,
	"run-in-background": null,
	"segments": [],
}}

test_create_trigger_naming_an_open_child_is_admitted if {
	count(violation) == 0 with input as object.union(
		trigger_call("create_trigger", {"prompt": concat(" ", ["poll", child])}),
		{"facts": open_child},
	)
}

test_create_trigger_naming_no_open_child_is_refused if {
	some v in violation with input as object.union(
		trigger_call("mcp__x__create_trigger", {"prompt": "babysit PR #1282"}),
		{"facts": open_child},
	)
	v.rule == "event mint refused"
	v.subjects == [{"artifact": child}]
}

# The arm keys on the TOOL, never on a command's text: a shell line naming the
# verb inside a compound command is not the call.
test_a_shell_line_naming_the_verb_is_not_the_call if {
	count(violation) == 0 with input as {
		"call": {
			"tool": "Bash",
			"command": "cd /tmp && echo create_trigger",
			"run-in-background": false,
			"segments": [],
		},
		"facts": open_child,
	}
}

test_create_trigger_with_no_store_is_refused if {
	some v in violation with input as object.union(
		trigger_call("create_trigger", {"prompt": concat(" ", ["poll", child])}),
		{"facts": {"minted": null}},
	)
	v.rule == "event mint refused"
}
