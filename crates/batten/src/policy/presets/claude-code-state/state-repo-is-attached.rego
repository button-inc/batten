#MUTANT-SUITE crates/batten/tests/it/state_repo_gate.rs
#MUTANT state-hold-open|s@^\tstate.state == "unattached"$@\tfalse@|an_unattached_state_repo_holds_a_write_and_names_the_attach
#MUTANT attach-held|s@^attach_call(tool) if regex.match(.*@attach_call(tool) if false@|the_attach_and_the_reads_are_admitted_while_held
#
# CLOUD-2939. A session whose `BATTEN_STATE_REPO` names a repository it cannot
# read carries no receipt: every lap's pull and publish answers 401/403/404,
# and the lap recomputes what another container already proved. The host
# attaches a repository to a session with one call (`add_repo`, push access),
# so the engine probes, and this module holds the session until it is made.
#
# THE ENGINE DECIDES ACCESS; THIS DECIDES WHAT TO SAY. `input.facts["state-repo"]`
# is null unless the variable is set, no opt-out is declared, and a ref
# discovery answered 401, 403 or 404; then it names the status and the
# repository. A `200` lifts it on the next call with no command, and could-not-
# look holds nothing.
#
# ADMITTED WHILE HELD: a read, the host's notification read, an MCP method the
# engine-default library reads as read-only (the channels instructions arrive
# on, CLOUD-2840 r6), and the attach itself.

# METADATA
# description: |
#   Hold every call but a read and the attach while the session cannot read its
#   state repository. Bound to the MEDIATED-CALL surface. THIS BLOCK IS YAML AND
#   MUST STAY THE LAST COMMENT BLOCK BEFORE `package`.
# schemas:
#   - input: schema["policy-call.schema"]
package batten.claude_code_state

import rego.v1

rules contains "lease carry blocked"

state := input.facts["state-repo"]

unattached if {
	is_object(state)
	state.state == "unattached"
}

attach_call(tool) if regex.match(`^mcp__[^_].*__add_repo$`, tool)

admitted if input.call.operation == "read"

admitted if input.call.tool == "ReadNotifications"

admitted if attach_call(input.call.tool)

admitted if {
	input.call.operation == "mcp"
	data.batten.library.read_only(input.call)
}

violation contains {
	"rule": "lease carry blocked",
	"verdict": "lease carry blocked",
	"subjects": [
		{"artifact": sprintf("%s %v", [state.repository, state.status])},
		{"artifact": "add_repo access=push"},
	],
} if {
	unattached
	not admitted
}

# --- the load-time tier ------------------------------------------------------

held := {"state": "unattached", "status": 404, "repository": "acme/state"}

test_a_write_is_held_and_names_the_attach if {
	some v in violation with input as {"facts": {"state-repo": held}, "call": {"operation": "write", "tool": "Edit"}}
	{"artifact": "acme/state 404"} in v.subjects
	{"artifact": "add_repo access=push"} in v.subjects
}

test_a_read_and_the_attach_are_admitted if {
	count(violation) == 0 with input as {"facts": {"state-repo": held}, "call": {"operation": "read", "tool": "Read"}}
	count(violation) == 0 with input as {"facts": {"state-repo": held}, "call": {"operation": "other", "tool": "ReadNotifications"}}
	count(violation) == 0 with input as {"facts": {"state-repo": held}, "call": {"operation": "mcp", "tool": "mcp__claude-code-remote__add_repo"}}
}

test_a_lookalike_attach_is_held if {
	count(violation) == 1 with input as {"facts": {"state-repo": held}, "call": {"operation": "mcp", "tool": "mcp__x__add_repo_v2"}}
}

test_no_fact_holds_nothing if {
	count(violation) == 0 with input as {"facts": {"state-repo": null}, "call": {"operation": "write", "tool": "Edit"}}
}
