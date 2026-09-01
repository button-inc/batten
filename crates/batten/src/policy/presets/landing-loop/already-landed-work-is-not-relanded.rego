# METADATA
# description: |
#   Work the target already carries is not landed again.
#
#   A landing attempt over a branch whose changes are already on the target buys
#   nothing and spends the metered tier to buy it: the matrix runs, the fleet's
#   landing lease is held against everyone else while it does, and the merge is a
#   no-op or a conflict. The loop that drives landing lives outside the engine;
#   this is the question it should have asked before it started.
#
#   THE ANSWER IS PATCH IDENTITY, NEVER REACHABILITY, and that is not this
#   module's choice — it is the only landing answer the engine will produce. A
#   rebased, squash-merged or cherry-picked branch leaves the same change on the
#   target under a different SHA with no ancestry path back, so every reachability
#   test reports "not landed" about work that landed. On a fast-forward trunk that
#   is the ORDINARY way work lands, which makes that false negative the common
#   case rather than the exotic one.
#
#   TWO TRAPS SIT IN THE SHAPE OF THIS FACT, AND THIS MODULE FELL INTO THE SECOND
#   BEFORE ITS OWN SUITE CAUGHT IT.
#
#   `landed` IS NOT `count(unlanded) == 0`, AND CONFLATING THEM IS THE REWRITE
#   THIS MODULE IS MOST LIKELY TO SUFFER. A squash-landed branch reaches its
#   verdict through the CUMULATIVE diff, so every per-commit proof is absent and
#   `unlanded` is non-empty while `landed` is true. A module reading the array
#   would report a squash-landed branch as outstanding work — the exact false
#   negative patch identity exists to prevent. Read the boolean the engine
#   computed.
#
#   AND `landed` IS NOT `verdict == "landed"` EITHER. The boolean is also true for
#   `nothing_to_land`, which is what a checkout sitting on the trunk with no
#   distinct work answers — so a module reading the boolean refuses every clean
#   tree. This one did, and every fixture in this repository's suite built from
#   the committed config reported it before the narrowing below.
#
#   WHAT THIS DELIBERATELY DOES NOT REFUSE. `not_landed_within_window` is an
#   UNPROVEN absence rather than a negative: the scan walks a bounded window, and
#   whether that window was truncated is not projected, so a module cannot tell a
#   proven "no" from "I stopped looking". Refusing it would be a verdict about how
#   far the engine looked wearing the clothes of a verdict about the branch.
#   `partially_landed` is a real mixed answer and somebody's judgement, not this
#   predicate's.
#
#   THREE ANSWERS AND THE MODULE READS ALL THREE. `null` is could-not-look —
#   nobody declared a target, or git could not be run at all. A declared target
#   ABSENT from the map could not be scanned: it does not resolve, the repository
#   is empty, or the two histories share no merge base. Only a target PRESENT
#   whose verdict is `landed` is refused. The absent case is the dangerous one,
#   because a fabricated negative there reads as *this work is outstanding* with
#   full confidence.
#
#   Names no branch, no remote and no task: the target is whatever string the
#   consumer's own row declared, so this stays true of the practice rather than of
#   one repository (non-negotiable rule 1).
#
#   THE BRACKETS ARE NOT STYLE: the schema file carries a hyphen, so the dotted
#   form is a parse error reported as `invalid schema reference`.
#   THIS BLOCK IS YAML AND MUST STAY THE LAST COMMENT BLOCK BEFORE `package`.
# schemas:
#   - input: schema["policy-input.schema"]
package batten.landing_loop

import rego.v1

rules contains "already-landed-work-is-not-relanded"

# Every declared target that already carries this branch's work.
#
# GUARDED on `is_object`, and the guard is load-bearing rather than defensive: the
# key is `null` when no row declared a target, and `some .. in null` is a hard
# evaluation FAULT in Rego, which takes the whole bundle down rather than missing
# quietly.
#
# `verdict == "landed"` RATHER THAN THE `landed` BOOLEAN, and the difference is a
# defect this module had first. The boolean is true for `nothing_to_land` as well
# — a branch with no distinct work at all, which is the ORDINARY state of a
# checkout sitting on the trunk. Refusing that refuses a STATE rather than an
# attempt, and the state is normal: measured, it fired on every fixture in this
# repository's own suite that builds a tree from the committed config.
#
# `landed` is the answer to "is there outstanding work", which a landing loop
# wants; this predicate asks the narrower question the refusal can act on — this
# branch HAS work and the target already carries it. A branch with nothing to
# land has no duplicate to warn about.
relanded contains target if {
	is_object(input.tree.landing)
	some target, answer in input.tree.landing
	answer.verdict == "landed"
}

# Pointer-only (non-negotiable rule 4): the target is the string the consumer's
# own row declared, and naming it is what makes the refusal diagnosable when
# several targets are declared. Never a commit, never the unlanded list.
violation contains {
	"rule": "already-landed-work-is-not-relanded",
	"verdict": "patch ship twice",
	"subjects": [{"artifact": target}],
} if {
	some target in relanded
}

# --- the load-time tier ------------------------------------------------------
#
# These pin the PREDICATE. They cannot pin that the ENGINE scans the target and
# computes patch identity — a `with input as` case fabricates the very shape the
# engine may be unable to produce, and here it would fabricate the SCAN the whole
# family turns on. `crates/batten/tests/it/policy_presets.rs` is the tier that
# runs this the way a consumer gets it, with the empty vocabulary.

answered(answer) := {"tree": {"landing": {"origin/main": answer}}}

test_work_already_on_the_target_is_refused if {
	some v in violation with input as answered({"verdict": "landed", "landed": true, "unlanded": []})
	v.verdict == "patch ship twice"
}

# THE SQUASH SHAPE, and the case that discriminates this module from one written
# over `unlanded`. The verdict is reached through the cumulative diff, so every
# per-commit proof is absent and the array is non-empty — a module reading the
# array calls this branch outstanding, which is the false negative patch identity
# exists to prevent.
test_a_squash_landed_branch_is_refused_though_unlanded_is_not_empty if {
	some v in violation with input as answered({
		"verdict": "landed",
		"landed": true,
		"unlanded": ["1111111", "2222222"],
	})
	v.rule == "already-landed-work-is-not-relanded"
}

# NOTHING TO LAND IS NOT A DUPLICATE, and this case is the one that keeps the
# predicate about an attempt rather than about a state. A checkout sitting on the
# trunk with no distinct work answers `nothing_to_land` with `landed` TRUE — so a
# module reading the boolean refuses every clean tree. Measured: it fired on every
# fixture in this repository's own suite built from the committed config.
test_a_branch_with_nothing_to_land_is_clean if {
	count(violation) == 0 with input as answered({
		"verdict": "nothing_to_land",
		"landed": true,
		"unlanded": [],
	})
}

# THE ANTI-VACUITY MIRROR. Without it every case above is satisfied by a module
# that refuses unconditionally, which is not a gate (CLOUD-418).
test_outstanding_work_is_clean if {
	count(violation) == 0 with input as answered({
		"verdict": "partially_landed",
		"landed": false,
		"unlanded": ["1111111"],
	})
}

# AN UNPROVEN ABSENCE IS NOT A NEGATIVE. The scan is windowed and the module
# cannot see whether it was truncated, so this must not be read as landed — and
# this case is what holds that line.
test_an_unproven_absence_is_not_refused if {
	count(violation) == 0 with input as answered({
		"verdict": "not_landed_within_window",
		"landed": false,
		"unlanded": ["1111111"],
	})
}

# A DECLARED TARGET THAT COULD NOT BE SCANNED is absent from the map entirely —
# it does not resolve, the repository is empty, or there is no merge base. There
# is nothing to refuse, and fabricating a negative here is the direction that
# reports outstanding work with full confidence.
test_a_target_that_could_not_be_scanned_is_not_refused if {
	count(violation) == 0 with input as {"tree": {"landing": {}}}
}

# COULD-NOT-LOOK, and without the `is_object` guard this case does not merely
# fail — it faults, taking the whole bundle with it.
test_could_not_look_does_not_fault if {
	count(violation) == 0 with input as {"tree": {"landing": null}}
}
