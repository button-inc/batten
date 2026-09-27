# The operator spoke and the session kept working without answering.
#
# MEASURED 2026-09-27: four operator messages sent mid-turn were answered with
# tool calls only, across several turns, and the operator saw a session that
# ignored them. AGENTS.md's output posture made it prose; this makes it a gate.
#
# THE PREDICATE IS A COUNT OVER TYPED EVENTS. `unanswered-human-calls` is the
# number of tool calls since the operator's last message (a user turn, or the
# host's `queued_command` attachment marked `humanTurn`) with no assistant text
# between them. No span of what anyone said reaches this module (rule 4).
#
# IT SHIPS AT `deny`, AND UNLIKE ITS SIBLING THAT IS SAFE. `turn run loose`
# ships at `warn` because a `mediated_call` deny refuses every later call and
# only a tool call could clear it. Here the discharge is TEXT: one sentence to
# the operator zeroes the count, and text is never a mediated call, so this can
# refuse a call but can never wedge a session. It cannot loop either: it acts
# only at PreToolUse and never at Stop, so it forces no continuation.
#
# ONE CALL OF SLACK. The call being adjudicated is itself counted, so a count of
# 1 is "the first action after the message, with nothing said". That is the
# refusal: answer first, then act.
#MUTANT-SUITE crates/batten/tests/it/answer_operator.rs
#MUTANT operator-may-be-ignored|s@^	input.facts.extracted\["unanswered-human-calls"\] >= 1$@	false@|a_mid_turn_message_answered_by_tools_alone_is_refused

# METADATA
# description: |
#   Bound to the MEDIATED CALL: this row is `scope = "mediated_call"`, so it
#   reads `input.call` and `input.facts` and never the tree document.
#   THIS BLOCK IS YAML AND MUST STAY THE LAST COMMENT BLOCK BEFORE `package`.
# schemas:
#   - input: schema["policy-call.schema"]
package batten.answer_the_operator

import rego.v1

rules contains "turn answer missing"

violation contains {
	"rule": "turn answer missing",
	"verdict": "turn answer missing",
	"subjects": [{"count": input.facts.extracted["unanswered-human-calls"]}],
} if {
	is_object(input.facts.extracted)
	input.facts.extracted["unanswered-human-calls"] >= 1
}

session(extracted) := {"call": {"command": "", "run-in-background": null}, "facts": {"extracted": extracted}}

test_a_tool_call_after_an_unanswered_message_is_refused if {
	some v in violation with input as session({"unanswered-human-calls": 1})
	v.verdict == "turn answer missing"
}

test_the_finding_carries_a_count_and_nothing_else if {
	some v in violation with input as session({"unanswered-human-calls": 4})
	v.subjects == [{"count": 4}]
}

# ANSWERED IS CLEAN: text after the message zeroes the count.
test_an_answered_message_is_clean if {
	count(violation) == 0 with input as session({"unanswered-human-calls": 0})
}

test_no_transcript_is_not_a_finding if {
	count(violation) == 0 with input as session(null)
}

test_a_host_that_records_no_turns_answers_could_not_look if {
	count(violation) == 0 with input as session({"tool-calls": 200})
}

test_a_compound_command_reaches_the_same_verdict if {
	some v in violation with input as {
		"call": {"command": "cd /tmp && mise run land", "run-in-background": null},
		"facts": {"extracted": {"unanswered-human-calls": 2}},
	}
	v.verdict == "turn answer missing"
}
