# The IO-free evaluator test is shown able to FAIL (CLOUD-831, CLOUD-418, ported
# off `mise-tasks/evaluator-io-check.sh` under CLOUD-1717).
#
# WHAT IT DEFENDS. `no_evaluator_feature_admits_io` asserts a policy module
# cannot reach `http.send`. Under the shipped feature set that is true, so the
# test is green — and A GREEN TEST PROVES NOTHING ABOUT WHETHER IT CAN
# DISCRIMINATE. If regorus silently stopped registering the builtin, or the
# fixture stopped compiling, or the assertion were reworded into a tautology, the
# test would stay green over an evaluator that had lost the property entirely.
#
# So the producer builds the same test with `probe-evaluator-io` on — which turns
# `regorus/http` on and nothing else — and this module REQUIRES IT TO HAVE
# FAILED. A probe build that passed is the finding.
#
# THE PROBE FEATURE COSTS THE CLOSURE NOTHING, which is what makes running it
# affordable and what stops it weakening the gate it defends. `regorus`'s `http`
# feature is `[]` — a bare feature gating only the builtin's registration — so
# `Cargo.lock` is byte-identical with it on or off, and
# `policy/evaluator-closure.rego`'s walk cannot see it.
#
# THREE STATES, AND THE THIRD IS THE ONE A GATE WRITTEN TO THE OBVIOUS SHAPE GETS
# WRONG. `cargo test` exits non-zero for a compile error, an unresolved feature,
# an absent toolchain and a panic in another test — every one of which would read
# as "the probe falsified the assertion" and hand this gate a pass it did not
# earn. Worse, it is a pass that gets MORE likely as the crate breaks, so the
# gate would be loudest exactly when it was lying. So the producer reads the
# harness's own `failures:` listing rather than the exit code, and records which
# of the three happened; this module refuses two of them and is silent on one.
#
# POINTER-ONLY (rule 4): the test name and the verdict, never the probe build's
# output. That log carries module bodies and paths, and the record never holds a
# byte of it.
#
#MUTANT-SUITE crates/batten/tests/it/evaluator_io_probe.rs
#MUTANT io-probe-not-inverted|s@^\t"probe passed" in lines$@\tfalse@|a_probe_build_in_which_the_test_passes_is_the_finding_not_a_pass
#MUTANT io-probe-trusts-the-exit-code|s@^\t"probe unread" in lines$@\tfalse@|a_probe_build_that_failed_to_compile_is_could_not_look_not_the_pass

# METADATA
# description: |
#   Bound to the TREE surface: `scope = "tree"`, so it reads the tree document
#   and never the mediated `{call, facts}` shape.
#   THE BRACKETS ARE NOT STYLE: the schema file carries a hyphen, so the dotted
#   form is a parse error reported as `invalid schema reference`.
#   THIS BLOCK IS YAML AND MUST STAY THE LAST COMMENT BLOCK BEFORE `package`.
# schemas:
#   - input: schema["policy-input.schema"]
package batten.evaluator_io_probe

import rego.v1

rules contains "test cover never"

# The record, or nothing. An absent record is "the producer did not run" and is
# silence; it must not be spelled the same way as a probe that ran.
lines := input.tree.records["evaluator-io-probe"]

# THE INVERSION IS THE GATE. A probe build that SUCCEEDED means the test stayed
# green with `http` on — so it discriminates nothing and is coverage theatre,
# which is the exact shape CLOUD-418 exists to refuse.
violation contains {
	"rule": "test cover never",
	"verdict": "test judge never",
	"subjects": [{"path": "crates/batten/tests/policy_modules.rs"}, {"artifact": "no_evaluator_feature_admits_io"}],
} if {
	"probe passed" in lines
}

# A NON-ZERO EXIT IS NOT YET THE ANSWER. The producer says so explicitly rather
# than leaving the module to infer it from an absent `probe failed`, because
# inferring would make "the producer never ran" and "the build broke" one state.
violation contains {
	"rule": "test cover never",
	"verdict": "test run unread",
	"subjects": [{"path": "crates/batten/tests/policy_modules.rs"}, {"artifact": "no_evaluator_feature_admits_io"}],
} if {
	"probe unread" in lines
}

# --- cases -------------------------------------------------------------------

test_a_probe_build_in_which_the_test_passes_is_the_finding_not_a_pass if {
	found := violation with input as {"tree": {"records": {"evaluator-io-probe": ["probe passed"]}}}
	count(found) == 1
}

test_a_probe_build_in_which_the_test_fails_is_the_pass if {
	found := violation with input as {"tree": {"records": {"evaluator-io-probe": ["probe failed"]}}}
	count(found) == 0
}

test_a_probe_build_that_failed_to_compile_is_could_not_look_not_the_pass if {
	found := violation with input as {"tree": {"records": {"evaluator-io-probe": ["probe unread"]}}}
	count(found) == 1
}

# The two refusals are distinct classes: one says the test is theatre, the other
# says nothing was learned. A case counting findings cannot tell them apart.
test_the_two_refusals_are_separate_classes if {
	passed := violation with input as {"tree": {"records": {"evaluator-io-probe": ["probe passed"]}}}
	unread := violation with input as {"tree": {"records": {"evaluator-io-probe": ["probe unread"]}}}
	{entry.verdict | some entry in passed} == {"test judge never"}
	{entry.verdict | some entry in unread} == {"test run unread"}
}

test_an_absent_record_says_nothing_rather_than_refusing if {
	found := violation with input as {"tree": {"records": {}}}
	count(found) == 0
}
