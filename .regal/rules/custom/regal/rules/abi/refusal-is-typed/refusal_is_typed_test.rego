package custom.regal.rules.abi["refusal-is-typed_test"]

import data.custom.regal.rules.abi["refusal-is-typed"] as rule

# THE POSITIVE ARM IS THE ONE THAT MAKES THIS A TEST OF THE RULE. A suite that
# only asserted `count(r) > 0` over a `msg`-bearing module passes unchanged if
# the predicate is hard-wired to fire — which is the failure the sibling rule's
# own comments record hitting twice, in both directions. So the conforming
# module is asserted silent at every arm.

typed := `package batten.example

violation contains {
	"rule": "a-gate",
	"verdict": "a class probe",
	"subjects": [{"path": "a.rs"}],
} if {
	input.call.operation == "write"
}`

carries_msg := `package batten.example

violation contains {
	"rule": "a-gate",
	"msg": "prose no mechanism can check",
} if {
	input.call.operation == "write"
}`

composed_verdict := `package batten.example

violation contains {
	"rule": "a-gate",
	"verdict": sprintf("V-%s", ["A-CLASS"]),
} if {
	input.call.operation == "write"
}`

# A module's own test may construct the old shape to compare against — including
# one pinning a token being retired — so the prefix is exempt.
msg_inside_a_test := `package batten.example

test_something if {
	expected := {"rule": "a-gate", "msg": "the old shape"}
	expected.rule == "a-gate"
}`

# The discriminating negative: `msg` as a VALUE rather than a key. A rule that
# scanned for the literal anywhere would report this, and the literal is a
# perfectly ordinary string.
msg_as_a_value := `package batten.example

violation contains {
	"rule": "a-gate",
	"verdict": "a class probe",
	"subjects": [{"artifact": "msg"}],
} if {
	input.call.operation == "write"
}`

module(name, text) := object.union(
	regal.parse_module(name, text),
	{"regal": {"file": {"name": name}}},
)

test_a_typed_refusal_is_not_reported if {
	r := rule.report with input as module("typed.rego", typed)
	count(r) == 0
}

test_the_retired_key_is_reported if {
	r := rule.report with input as module("msg.rego", carries_msg)
	count(r) == 1
}

test_a_composed_verdict_is_reported if {
	r := rule.report with input as module("composed.rego", composed_verdict)
	count(r) == 1
}

test_a_test_rule_may_still_construct_the_old_shape if {
	r := rule.report with input as module("test.rego", msg_inside_a_test)
	count(r) == 0
}

test_the_literal_msg_as_a_value_is_not_a_key if {
	r := rule.report with input as module("value.rego", msg_as_a_value)
	count(r) == 0
}
