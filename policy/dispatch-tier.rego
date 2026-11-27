# A session this repository dispatches runs the model and effort its owner set,
# and a call that names another, or names none, is refused (CLOUD-2949).
#
# Owner ruling, 2026-11-27: the dispatching session runs the larger model; every
# session it opens is Opus at low effort. Nothing read either argument, and the
# host's default is the wrong one: a `create_session` that omits `model`
# inherits the dispatcher's, and one that omits `effort` takes the host's.
#
# SO ABSENCE IS A FINDING. Both arguments are required, each judged on its own,
# and the refusal names which one (`model`, `effort`), never its value (rule 4).
#
# THE VALUES ARE THIS CONSUMER'S, which is why this is a module here and not a
# preset: which model family and which effort a dispatch may name is a fact
# about this repository's owner, not about dispatching.
#
# ONLY THE CALL THAT OPENS A SESSION. `send_message` carries neither argument:
# a session's model is fixed when it is opened.
#MUTANT-SUITE crates/batten/tests/it/dispatch_tier.rs
#MUTANT model-unread|s@^\tnot allowed_model$@\tfalse@|a_dispatch_on_another_model_or_none_is_refused
#MUTANT effort-unread|s@^\tnot allowed_effort$@\tfalse@|a_dispatch_at_another_effort_or_none_is_refused
#MUTANT family-prefix-dropped|s@^\tstartswith(model, "claude-opus-")$@\tfalse@|an_opus_dispatch_at_low_effort_is_not_refused
#MUTANT every-call-judged|s@^\tendswith(input.call.tool, "__create_session")$@\ttrue@|a_call_that_opens_no_session_is_not_judged

# METADATA
# description: |
#   Bound to the MEDIATED-CALL surface: `input.call.arguments` is the tool's own
#   input, its `model` and `effort` for `create_session`.
#   THIS BLOCK IS YAML AND MUST STAY THE LAST COMMENT BLOCK BEFORE `package`.
# schemas:
#   - input: schema["policy-call.schema"]
package batten.dispatch_tier

import rego.v1

rules contains "call open wrong"

# The call that opens a sibling session, under whatever name the host gave the
# session connector.
opens if {
	input.call.event == "pre-tool"
	startswith(input.call.tool, "mcp__")
	endswith(input.call.tool, "__create_session")
}

model := object.get(input.call.arguments, "model", "")

effort := object.get(input.call.arguments, "effort", "")

# The family alias, or an exact id in the family.
allowed_model if model == "opus"

allowed_model if {
	startswith(model, "claude-opus-")
}

allowed_effort if effort == "low"

violation contains {
	"rule": "call open wrong",
	"verdict": "call open wrong",
	"subjects": [{"artifact": "model"}],
} if {
	opens
	not allowed_model
}

violation contains {
	"rule": "call open wrong",
	"verdict": "call open wrong",
	"subjects": [{"artifact": "effort"}],
} if {
	opens
	not allowed_effort
}

open(arguments) := {"call": {
	"event": "pre-tool",
	"tool": "mcp__x__create_session",
	"arguments": arguments,
}}

test_an_opus_dispatch_at_low_effort_raises_nothing if {
	count(violation) == 0 with input as open({"model": "opus", "effort": "low"})
	count(violation) == 0 with input as open({"model": "claude-opus-5-5", "effort": "low"})
}

test_another_model_is_refused_by_name if {
	found := violation with input as open({"model": "claude-fable-5-2", "effort": "low"})
	found == {{"rule": "call open wrong", "verdict": "call open wrong", "subjects": [{"artifact": "model"}]}}
}

test_no_model_is_refused if {
	some found in violation with input as open({"effort": "low"})
	found.subjects == [{"artifact": "model"}]
}

test_another_effort_is_refused_by_name if {
	found := violation with input as open({"model": "opus", "effort": "medium"})
	found == {{"rule": "call open wrong", "verdict": "call open wrong", "subjects": [{"artifact": "effort"}]}}
}

test_no_effort_is_refused if {
	some found in violation with input as open({"model": "opus"})
	found.subjects == [{"artifact": "effort"}]
}

test_a_call_that_opens_no_session_raises_nothing if {
	count(violation) == 0 with input as {"call": {
		"event": "pre-tool",
		"tool": "mcp__x__send_message",
		"arguments": {"message": "m"},
	}}
	count(violation) == 0 with input as {"call": {"event": "pre-tool", "tool": "Bash", "arguments": {}}}
}

# A compound shell line is a call too, and it opens nothing (the case
# `module-tested-bare-only` asks every mediated module for).
test_a_compound_shell_call_raises_nothing if {
	count(violation) == 0 with input as {"call": {
		"event": "pre-tool",
		"tool": "Bash",
		"arguments": {"command": "cd /tmp && echo create_session"},
	}}
}
