# The adopted gate runner's effective plan, adjudicated (CLOUD-949).
#
# WHAT THIS ROW EXISTS TO STOP: a policy-required step the runner silently
# excluded reading as satisfied. Two approximations were available and both fail
# that way -- parsing the runner's config re-implements a selector it owns, and
# encoding selector behaviour here makes the engine a second authority on which
# files a step runs over. Either produces a verdict about a plan that was never
# the plan.
#
# So this module reads a FACT the boundary acquired from the runner itself, at
# `input.tree.plan`, and compares it against the consumer's own row, carried in
# the same document as `required` and `prohibitedProfiles`. Nothing here parses
# the runner's config and nothing re-derives a selection.
#
# A FAILED ACQUISITION IS A REACQUIRE, NOT A PASS. A declared id the boundary
# could not take carries a `null` value rather than vanishing, and
# `plan-unacquired` fires on it. Without that arm the whole gate is satisfied by
# a runner nobody could reach -- the vacuity CLOUD-251 names, and the one a
# module that only iterated the plans it got would reproduce exactly.
#
# THE ROW'S REQUIRED LIST IS THE CONSUMER'S. It arrives inside the fact rather
# than as a literal here, so non-negotiable rule 1 holds structurally: this
# module names no step, no hook and no profile of anybody's.
#
# WHY `reasonKind` AND NOT PROSE (rule 4). A step excluded for a missing profile
# and one excluded by a glob miss are different findings with different remedies,
# and the kind is the only field that separates them. The runner's own sentence
# about it is not carried, is not stored, and is not emitted.
#
# THIS ROW CARRIED `#MUTANT-EXEMPT` AND THE RATIONALE UNDER IT WAS THE OTHER
# MARKER'S (CLOUD-1267). The sentence said the tier that drives the fact cannot
# be reddened by a mutation of this module -- which is true, and is precisely the
# `#MUTANT-OWNER` criterion rather than an exemption's. An exemption SUPPRESSES
# the finding; an owner declaration leaves the survivor red and names the row
# that owes the missing tier, changing no exit code. Spelling one as the other is
# the laundering the runner exists to refuse, and it was written on this branch.
#
#MUTANT-SUITE crates/batten/tests/it/hk_plan.rs
#MUTANT-OWNER CLOUD-845|the tier this module names drives `input.tree.plan` and never installs the module, so no case in it can turn red under a mutation of the predicate
#MUTANT plan-unacquired-silenced|s@^\tnot acquired\[id\]$@\tfalse@|the_boundary_acquires_a_plan_the_module_can_read

# METADATA
# description: |
#   Bound to the TREE surface: this row is `scope = "tree"`, so it reads the tree
#   document and never the mediated `{call, facts}` shape.
#   THE BRACKETS ARE NOT STYLE: the schema file carries a hyphen, so the dotted
#   form is a parse error reported as `invalid schema reference` rather than as a
#   missing bind, and an unbound module type checks as `Any`.
#   THIS BLOCK IS YAML AND MUST STAY THE LAST COMMENT BLOCK BEFORE `package`:
#   OPA parses the whole contiguous block that starts the annotation, so prose
#   placed after it reaches the YAML parser and the module fails to load.
# schemas:
#   - input: schema["policy-input.schema"]
package batten.hk_plan_required

import rego.v1

rules contains "plan-required-step"

rules contains "plan-prohibited-profile"

rules contains "plan-unacquired"

# Every declared row, as the engine emitted it: an id maps to the plan it took,
# or to `null` where it could not take one. `input.tree.plan` is itself `null`
# when no row declared a plan, which is right -- a repository that declares none
# owes none.
#
# THE `null` VALUE IS WHY THE DECLARED SET SURVIVES A FAILURE. A map that dropped
# the id would make `plan-unacquired` unwritable: the id nobody could acquire is
# exactly the id the refusal has to name.
declared := plan if {
	plan := input.tree.plan
	is_object(plan)
}

declared := {} if not is_object(input.tree.plan)

# The subset that was actually taken.
acquired[id] := plan if {
	some id, plan in declared
	is_object(plan)
}

# `plan-unacquired`: A DECLARED PLAN THE BOUNDARY COULD NOT TAKE.
#
# The reacquire arm. A plan nobody could read and a plan with nothing wrong are
# otherwise identical on the decision surface, which is the whole reason this
# fires rather than passing.
violation contains {
	"rule": "plan-unacquired",
	"verdict": "plan read missing",
	"subjects": [{"artifact": id}],
} if {
	some id, _ in declared
	not acquired[id]
}

# `plan-required-step`: A STEP THE CONSUMER REQUIRES THAT THE PLAN WILL NOT RUN.
#
# Missing and not-included are one finding with two causes, and the subject
# carries which: an absent step has no reason kind, and an excluded one carries
# the runner's own kind token.
violation contains {
	"rule": "plan-required-step",
	"verdict": "step run missing",
	"subjects": [{"artifact": id}, {"count": count(missing_in(id))}],
} if {
	some id, _ in acquired
	count(missing_in(id)) > 0
}

# A required step the plan does not include: either absent from it entirely, or
# present with a status that is not inclusion.
missing_in(id) := names if {
	plan := acquired[id]
	names := {name |
		some name in plan.required
		not included(plan, name)
	}
}

included(plan, name) if {
	some step in plan.steps
	step.name == name
	step.status == "included"
}

# `plan-prohibited-profile`: THE PLAN RESOLVED UNDER A PROFILE THE ROW REFUSES.
#
# A separate class from the one above because the remedy is different: a required
# step missing is a change to the gate, where a prohibited profile is a change to
# how the gate was invoked.
violation contains {
	"rule": "plan-prohibited-profile",
	"verdict": "plan run refused",
	"subjects": [{"artifact": id}],
} if {
	some id, plan in acquired
	some profile in plan.profiles
	profile in plan.prohibitedProfiles
}

deny contains finding if some finding in violation

test_a_required_step_the_plan_includes_is_clean if {
	count(violation) == 0 with input as {"tree": {"plan": {"gate": {
		"hook": "check",
		"profiles": [],
		"prohibitedProfiles": [],
		"required": ["one"],
		"steps": [{"name": "one", "status": "included", "reasonKind": "filter_match"}],
	}}}}
}

test_a_required_step_the_plan_excludes_is_refused if {
	some finding in violation with input as {"tree": {"plan": {"gate": {
		"hook": "check",
		"profiles": [],
		"prohibitedProfiles": [],
		"required": ["one"],
		"steps": [{"name": "one", "status": "skipped", "reasonKind": "profile_exclude"}],
	}}}}

	finding.rule == "plan-required-step"
}

test_a_required_step_the_plan_never_names_is_refused if {
	some finding in violation with input as {"tree": {"plan": {"gate": {
		"hook": "check",
		"profiles": [],
		"prohibitedProfiles": [],
		"required": ["absent"],
		"steps": [{"name": "one", "status": "included", "reasonKind": "filter_match"}],
	}}}}

	finding.rule == "plan-required-step"
}

test_a_declared_plan_that_could_not_be_acquired_is_refused if {
	some finding in violation with input as {"tree": {"plan": {"gate": null}}}

	finding.rule == "plan-unacquired"
}

test_a_prohibited_profile_is_refused if {
	some finding in violation with input as {"tree": {"plan": {"gate": {
		"hook": "check",
		"profiles": ["slow"],
		"prohibitedProfiles": ["slow"],
		"required": [],
		"steps": [{"name": "one", "status": "included", "reasonKind": "filter_match"}],
	}}}}

	finding.rule == "plan-prohibited-profile"
}

test_a_repository_declaring_no_plan_owes_none if {
	count(violation) == 0 with input as {"tree": {"plan": null}}
}
