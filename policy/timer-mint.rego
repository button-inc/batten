# A `send_later` is admitted only when its own message names an open child
# session (CLOUD-2889).
#
# The owner's ruling (2026-11-24): a dispatcher watching its children may wait,
# and a session babysitting a PR may not. The two are the same call with
# different payloads, so the question is what the timer names. A timer naming a
# session this session created and has not archived — a `child-open` receipt
# under a day old, projected as `input.facts.minted["children-open"]` — is a wait
# on that child. Anything else, a PR heartbeat above all, names none of them and
# is refused by construction, listing the open ids so the caller can bind its
# timer to one.
#
# NULL, ABSENT AND EMPTY ALL REFUSE. On a fresh clone or a CI runner the store is
# empty, the fact is null, `open_children` is empty, and `names_open_child` is
# undefined, so `not` holds and the call is refused exactly as the shape row did.
#
# ITS OWN MODULE, NOT AN ARM OF `run-shape.rego`, FOR THE REMEDY. A module's
# finding id resolves to the row that binds the module (`owning_row`), and that
# row's `reason` is both the deny line's `Do:` and what `batten policy rule`
# prints. As an arm of `run-shape.rego` this id resolved to `commit read
# missing`, which declares no remedy, so the refusal lost the one it had.
#MUTANT-SUITE crates/batten/tests/it/child_wait.rs
#MUTANT send-later-children-unread|s@^\tnot names_open_child(input.call.arguments.message)$@\ttrue@|send_later_naming_an_open_child_is_admitted_under_every_spelling
#MUTANT send-later-unrefused|s@^\tcalls("send_later")$@\tfalse@|send_later_naming_no_open_child_is_refused
#MUTANT send-later-spelling-unread|s@^\tendswith(input.call.tool, concat("", \["__", name\]))$@\tfalse@|send_later_naming_no_open_child_is_refused
#MUTANT send-later-children-match-unread|s@^\tcontains(text, id)$@\tfalse@|send_later_naming_an_open_child_is_admitted_under_every_spelling
#MUTANT send-later-children-unlisted|s@^\t"subjects": child_subjects,$@\t"subjects": [],@|send_later_naming_no_open_child_is_refused

# METADATA
# description: |
#   Bound to the MEDIATED-CALL surface: `input.call.arguments` is the tool's own
#   input, `input.facts.minted` the open-child receipts.
#   THIS BLOCK IS YAML AND MUST STAY THE LAST COMMENT BLOCK BEFORE `package`.
# schemas:
#   - input: schema["policy-call.schema"]
package batten.timer_mint

import rego.v1

rules contains "timer mint refused"

violation contains {
	"rule": "timer mint refused",
	"verdict": "call name refused",
	"subjects": child_subjects,
} if {
	calls("send_later")
	not names_open_child(input.call.arguments.message)
}

# The host's spelling of a tool, bare or behind a connector prefix, matched as
# `facts::selects_tool_name` matches a shape row's `tool`.
calls(name) if {
	input.call.tool == name
}

calls(name) if {
	endswith(input.call.tool, concat("", ["__", name]))
}

# Every open child of this session, by session id.
open_children contains id if {
	some id, _ in input.facts.minted["children-open"]
}

# Whether a timer's own text names one of them.
names_open_child(text) if {
	is_string(text)
	some id in open_children
	contains(text, id)
}

child_subjects := [{"artifact": id} | some id in sort(open_children)]

# ---------------------------------------------------------------------------
# Tests. Every case carries a `command`: the engine emits the empty string for
# a call that is not a shell, never null.
# ---------------------------------------------------------------------------

child := "session_01ChildAbc"

open_child := {"minted": {"children-open": {"session_01ChildAbc": "open"}}}

timer_call(tool, arguments) := {"call": {
	"command": "",
	"tool": tool,
	"arguments": arguments,
	"run-in-background": null,
	"segments": [],
}}

test_send_later_naming_an_open_child_is_admitted if {
	count(violation) == 0 with input as object.union(
		timer_call("mcp__Claude_Code_Remote__send_later", {"message": concat(" ", ["check", child])}),
		{"facts": open_child},
	)
}

test_send_later_naming_no_open_child_is_refused if {
	some v in violation with input as object.union(
		timer_call("send_later", {"message": "check CI on PR #1282"}),
		{"facts": open_child},
	)
	v.rule == "timer mint refused"
	v.subjects == [{"artifact": child}]
}

# NULL IS COULD-NOT-LOOK, AND IT REFUSES: a fresh clone has no receipt store.
test_send_later_with_no_store_is_refused if {
	some v in violation with input as object.union(
		timer_call("send_later", {"message": concat(" ", ["check", child])}),
		{"facts": {"minted": null}},
	)
	v.rule == "timer mint refused"
}

# The arm keys on the TOOL, never on a command's text: a shell line naming the
# verb inside a compound command is not the call.
test_a_shell_line_naming_the_verb_is_not_the_call if {
	count(violation) == 0 with input as {
		"call": {
			"tool": "Bash",
			"command": "cd /tmp && echo send_later",
			"run-in-background": false,
			"segments": [],
		},
		"facts": open_child,
	}
}

# A tool that merely ENDS in the name, with no `__` before it, is another tool.
test_a_tool_ending_in_the_name_is_not_the_timer if {
	count(violation) == 0 with input as object.union(
		timer_call("not_send_later", {"message": "x"}),
		{"facts": open_child},
	)
}
