#MUTANT-SUITE crates/batten/tests/it/extracted_facts.rs
#MUTANT first-plan-every-plan|s@^\tinput.facts.extracted\["plan-exits"\] <= 1$@\tinput.facts.extracted["plan-exits"] >= 1@|a_second_plan_exit_is_admitted
#MUTANT first-plan-any-tool|s@^\tinput.call.tool == "ExitPlanMode"$@\ttrue@|plan_exits_counts_only_exit_plan_mode_calls
# A session's first plan is refused once, with the operator's own correction
# (CLOUD-2383).
#
# Measured, the sentence an operator typed back at almost every first plan:
# "verify, pressure test, validate; present corrected plan". A first plan is
# built from reports nobody re-read against the tree, and what corrects it is a
# pass that re-reads with tools, so the refusal asks for that pass instead of the
# operator typing it.
#
# ONCE, BY COUNT. `plan-exits` counts presentations in the session transcript,
# the in-flight call included, and a refused call stays recorded: the first
# presentation reads 1, the retry 2. `<= 1` rather than `== 1` so a host that
# had not yet written the in-flight call fires twice at worst, never forever.
#
# AN UNREAD COUNT ADMITS. Undefined — no transcript, an unsurveyed host, a row
# that declares no extract — never refuses; this module asks for a pass, it does
# not guess one is owed.
package batten.claude_code_cloud

import rego.v1

rules contains "plan check first"

violation contains {
	"rule": "plan check first",
	"verdict": "plan check first",
} if {
	input.call.event == "pre-tool"
	input.call.tool == "ExitPlanMode"
	input.facts.extracted["plan-exits"] <= 1
}

test_the_first_presentation_is_refused if {
	some v in violation with input as {
		"call": {"event": "pre-tool", "permission-mode": "plan", "tool": "ExitPlanMode"},
		"facts": {"extracted": {"plan-exits": 1}},
	}
	v.rule == "plan check first"
}

test_a_second_presentation_is_not if {
	not "plan check first" in {v.rule | some v in violation} with input as {
		"call": {"event": "pre-tool", "permission-mode": "plan", "tool": "ExitPlanMode"},
		"facts": {"extracted": {"plan-exits": 2}},
	}
}

test_an_unread_count_is_not if {
	not "plan check first" in {v.rule | some v in violation} with input as {"call": {"event": "pre-tool", "permission-mode": "plan", "tool": "ExitPlanMode"}}
}

# A compound shell line in plan mode, with the count at its refusing value, is
# still not a presentation: only the plan-exit tool is this module's subject,
# whatever the command carries (CLOUD-857's compound shape).
test_a_compound_shell_line_is_not if {
	not "plan check first" in {v.rule | some v in violation} with input as {
		"call": {
			"event": "pre-tool", "permission-mode": "plan", "tool": "Bash",
			"command": "git status && git log -1",
			"segments": [{"words": ["git", "status"], "terminator": "&&"}, {"words": ["git", "log", "-1"]}],
		},
		"facts": {"extracted": {"plan-exits": 1}},
	}
}

test_another_tool_is_not if {
	not "plan check first" in {v.rule | some v in violation} with input as {
		"call": {"event": "pre-tool", "permission-mode": "plan", "tool": "Read"},
		"facts": {"extracted": {"plan-exits": 1}},
	}
}
