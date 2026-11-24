# An archive is held while the child may still be working (CLOUD-2900).
#
# `archive_session` releases a child's container, and with it every background
# run still open there and every commit not yet pushed. Measured on the #1276
# fleet: a dispatcher read 45 minutes of silence as a dead machine and archived
# three children whose cargo-mutants runs were still going. A backgrounded run
# prints nothing until it exits, by design, so silence is not death.
#
# SO THE ARCHIVE WAITS ON A READ, NEVER ON A GUESS. `session watch` pairs every
# launch in the child's whole transcript with its notification and mints the
# answer as `child-state.<session id>`: `<now> <state> <open ids or ->`. The
# `[[rule.minted]]` rows project field 1 as `children-state` and field 2 as
# `children-tasks`, each under a day old. The archive is admitted only when the
# newest read of THAT child says `done`. A message to the child clears the read,
# since it can start a turn the read never saw.
#
# COULD-NOT-LOOK REFUSES. No read, a stale one, a cleared one, a store that could
# not be listed (`input.facts.minted` null) or a call naming no child: none of
# them is a `done` read, so none admits.
#
# A REFUSAL NAMES EACH OPEN TASK, or the child when none is open (rule 4).
#MUTANT-SUITE crates/batten/tests/it/archive_held.rs
#MUTANT archive-read-unchecked|s@^\tnot settled$@\tfalse@|an_archive_with_no_read_of_the_child_is_refused
#MUTANT archive-tasks-unnamed|s@^\tnamed := held$@\tnamed := [{"artifact": child}]@|an_archive_whose_last_read_names_open_tasks_is_refused_naming_each
#MUTANT archive-always-held|s@^\tstate == "done"$@\tfalse@|an_archive_after_a_done_read_is_admitted

# METADATA
# description: |
#   Bound to the MEDIATED-CALL surface: `input.call.arguments` is the tool's own
#   input, and `input.facts.minted` the declared `[[rule.minted]]` fields.
#   THIS BLOCK IS YAML AND MUST STAY THE LAST COMMENT BLOCK BEFORE `package`.
# schemas:
#   - input: schema["policy-call.schema"]
package batten.archive_held

import rego.v1

rules contains "task watch pending"

# Bare, or behind any connector prefix: the host's own name for the session
# server rotates between `Claude_Code_Remote` and `claude-code-remote`.
archiving if input.call.tool == "archive_session"

archiving if endswith(input.call.tool, "__archive_session")

# The child the call archives, or "" when the call names none.
child := id if {
	id := input.call.arguments.session_id
	is_string(id)
} else := ""

# The newest complete read of this child says `done`.
settled if {
	state := input.facts.minted["children-state"][child]
	state == "done"
}

# The tasks that read left open: comma-separated, `-` when none.
open_tasks contains task if {
	some task in split(input.facts.minted["children-tasks"][child], ",")
	not task in {"", "-"}
}

held := [{"artifact": task} | some task in sort(open_tasks)] if {
	count(open_tasks) > 0
} else := [{"artifact": child}] if {
	child != ""
} else := [{"artifact": input.call.tool}]

violation contains {
	"rule": "task watch pending",
	"verdict": "task watch pending",
	"subjects": named,
} if {
	archiving
	not settled
	named := held
}

# --- the module's own tier ----------------------------------------------------

c := "session_01ChildAbc"

archive(tool, minted) := {
	"call": {
		"command": "",
		"tool": tool,
		"arguments": {"session_id": c},
		"run-in-background": null,
	},
	"facts": {"minted": minted},
}

read(state, open) := {
	"children-state": {c: state},
	"children-tasks": {c: open},
}

spellings := ["archive_session", "mcp__Claude_Code_Remote__archive_session", "mcp__claude-code-remote__archive_session"]

refused_naming_the_child(tool, minted) if {
	some v in violation with input as archive(tool, minted)
	v.rule == "task watch pending"
	v.subjects == [{"artifact": c}]
}

test_no_read_is_refused_naming_the_child if {
	every tool in spellings {
		refused_naming_the_child(tool, {})
	}
}

# The gate keys on the structured tool, never on text: a shell line that only
# names it is some other gate's call.
test_a_shell_line_naming_the_tool_is_not_this_gates if {
	count(violation) == 0 with input as {
		"call": {"command": "cd /tmp && echo archive_session", "tool": "Bash", "arguments": {"session_id": c}, "run-in-background": null},
		"facts": {"minted": {}},
	}
}

test_an_unlisted_store_is_refused if {
	some _ in violation with input as archive("archive_session", null)
}

test_a_waiting_read_names_each_open_task if {
	some v in violation with input as archive("archive_session", read("waiting", "bwkc5djrv,bgqosjroi"))
	v.subjects == [{"artifact": "bgqosjroi"}, {"artifact": "bwkc5djrv"}]
}

test_a_dead_read_with_nothing_open_names_the_child if {
	some v in violation with input as archive("archive_session", read("dead", "-"))
	v.subjects == [{"artifact": c}]
}

test_a_done_read_admits if {
	every tool in spellings {
		count(violation) == 0 with input as archive(tool, read("done", "-"))
	}
}

test_another_childs_done_read_does_not_admit if {
	some _ in violation with input as archive("archive_session", {
		"children-state": {"session_01Other": "done"},
		"children-tasks": {"session_01Other": "-"},
	})
}

test_a_call_naming_no_child_is_refused if {
	some v in violation with input as {
		"call": {"command": "", "tool": "archive_session", "arguments": {}, "run-in-background": null},
		"facts": {"minted": read("done", "-")},
	}
	v.subjects == [{"artifact": "archive_session"}]
}

test_another_tool_is_not_held if {
	count(violation) == 0 with input as {
		"call": {"command": "", "tool": "get_session", "arguments": {"session_id": c}, "run-in-background": null},
		"facts": {"minted": {}},
	}
}
