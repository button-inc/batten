# A forge webhook subscription, refused outright, naming the open children
# (CLOUD-312 row 4, CLOUD-2889).
#
# `subscribe_pr_activity` is never a wait on a child: a webhook's silence is not
# success, and `mise run land` is the landing loop. So this arm admits nothing,
# whatever the call names. What CLOUD-2889 adds is the subjects: the refusal
# lists every open child session (`children-open`, a `child-open` receipt under a
# day old, projected as `input.facts.minted["children-open"]`), so a dispatcher
# refused here is pointed at the ids a `send_later` or `create_trigger` may name
# instead, as the `timer mint refused` and `event mint refused` arms point it.
#
# IT WAS A `kind = "shape"` ROW, AND IT IS A MODULE ONLY BECAUSE A ROW CANNOT
# READ `minted`. The id and the `call name refused` class are unchanged, so an
# admission written against either still binds, and the row's own `reason` is
# still the remedy `batten policy rule 'review watch refused'` prints.
#
# THE SPELLING IS `facts::selects_tool_name`'s: the bare name, or any name
# ending in `__` and the bare name. `unsubscribe_pr_activity` ends with
# `subscribe_pr_activity` but not with `__subscribe_pr_activity`, so it is
# another tool here exactly as it was to the shape row.
#MUTANT-SUITE crates/batten/tests/it/connector_verbs.rs
#MUTANT watch-unrefused|s@^\tcalls("subscribe_pr_activity")$@\tfalse@|every_spelling_of_a_decided_verb_is_refused
#MUTANT watch-connector-spelling-unread|s@^\tendswith(input.call.tool, concat("", \["__", name\]))$@\tfalse@|every_spelling_of_a_decided_verb_is_refused
#MUTANT-SUITE crates/batten/tests/it/child_wait.rs
#MUTANT watch-children-unlisted|s@^\t"subjects": child_subjects,$@\t"subjects": [],@|subscribe_pr_activity_stays_refused_with_a_child_open

# METADATA
# description: |
#   Bound to the MEDIATED-CALL surface: `input.call.tool` is the host's spelling
#   of the tool, `input.facts.minted` the open-child receipts.
#   THIS BLOCK IS YAML AND MUST STAY THE LAST COMMENT BLOCK BEFORE `package`.
# schemas:
#   - input: schema["policy-call.schema"]
package batten.review_watch

import rego.v1

rules contains "review watch refused"

violation contains {
	"rule": "review watch refused",
	"verdict": "call name refused",
	"subjects": child_subjects,
} if {
	calls("subscribe_pr_activity")
}

calls(name) if {
	input.call.tool == name
}

calls(name) if {
	endswith(input.call.tool, concat("", ["__", name]))
}

# Every open child of this session, by session id. Null, absent and empty all
# list none.
open_children contains id if {
	some id, _ in input.facts.minted["children-open"]
}

child_subjects := [{"artifact": id} | some id in sort(open_children)]

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

child := "session_01ChildAbc"

open_child := {"minted": {"children-open": {"session_01ChildAbc": "open"}}}

watch_call(tool) := {"call": {
	"command": "",
	"tool": tool,
	"arguments": {"owner": "o", "repo": "r", "pullNumber": 1},
	"run-in-background": null,
	"segments": [],
}}

test_review_watch_refused_lists_the_open_children if {
	some v in violation with input as object.union(
		watch_call("mcp__Claude_Code_Remote__subscribe_pr_activity"),
		{"facts": open_child},
	)
	v.rule == "review watch refused"
	v.verdict == "call name refused"
	v.subjects == [{"artifact": child}]
}

# NULL IS COULD-NOT-LOOK: the call is refused all the same, naming nobody.
test_review_watch_refused_with_no_store_names_nobody if {
	some v in violation with input as object.union(
		watch_call("subscribe_pr_activity"),
		{"facts": {"minted": null}},
	)
	v.rule == "review watch refused"
	v.subjects == []
}

test_unsubscribe_is_another_tool if {
	count(violation) == 0 with input as object.union(
		watch_call("mcp__Claude_Code_Remote__unsubscribe_pr_activity"),
		{"facts": open_child},
	)
}

# The arm keys on the TOOL, never on a command's text: a shell line naming the
# verb inside a compound command is not the call.
test_a_shell_line_naming_the_verb_is_not_the_call if {
	count(violation) == 0 with input as {
		"call": {
			"tool": "Bash",
			"command": "cd /tmp && echo subscribe_pr_activity",
			"run-in-background": false,
			"segments": [],
		},
		"facts": open_child,
	}
}

test_a_suffixed_name_is_another_tool if {
	count(violation) == 0 with input as object.union(
		watch_call("mcp__x__subscribe_pr_activity_v2"),
		{"facts": open_child},
	)
}
