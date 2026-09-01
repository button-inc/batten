# METADATA
# description: |
#   A commit the forge has already judged is not judged again.
#
#   Landing is a loop, and every lap that re-runs a matrix over a commit the
#   forge already graded buys an answer that is already recorded. The verdict
#   does not change — the commit did not change — so the run is spend with no
#   information in it. Measured on one consumer's landing bot: 400 runs over one
#   half hour, 248 of them executed, against 5 merges.
#
#   THE POLLING AND THE LOOP STAY OUTSIDE. Only the decision is here: given the
#   verdicts recorded for a declared commit, has it been judged? Whoever is
#   driving the loop decides what to do about it, and this module needs no clock
#   to answer.
#
#   WHAT COUNTS AS JUDGED IS THE GENERIC HALF, AND IT IS NOT "IS IT GREEN".
#   Which check carries a verdict about a given repository is that repository's
#   fact and may not travel inside a preset (non-negotiable rule 1) — so this
#   asks whether the forge recorded ANYTHING for the commit, never whether what
#   it recorded passed. A consumer wanting the green question writes it as its
#   own module over the same fact, and the two do not report one practice twice.
#
#   THREE ANSWERS AND THE MODULE READS ALL THREE, on `input.tree.forge`'s own
#   contract. `null` is could-not-look — nobody declared a commit, or no store is
#   readable. A declared commit ABSENT from the map has no record: nothing has
#   judged it, which is the state a first run is supposed to be in. A commit
#   PRESENT carrying verdicts has been judged, and that is the only state this
#   refuses. Reading either of the first two as a judgement would refuse a commit
#   nothing ever looked at.
#
#   THE BRACKETS ARE NOT STYLE: the schema file carries a hyphen, so the dotted
#   form is a parse error reported as `invalid schema reference`.
#   THIS BLOCK IS YAML AND MUST STAY THE LAST COMMENT BLOCK BEFORE `package`.
# schemas:
#   - input: schema["policy-input.schema"]
package batten.landing_loop

import rego.v1

rules contains "graded-head-is-not-regraded"

# The compiled tier is the one that runs this the way a consumer gets it, with
# the empty vocabulary — the doc above says so, and CLOUD-1267 makes it the
# DECLARED suite rather than a `tests/<gate>.bats` no preset may have.
#
# The mutation raises the judged threshold past anything a fixture supplies, so
# a commit the forge recorded a verdict for stops being refused. It is aimed at
# the case's FIRST half deliberately: the second asserts silence, which survives
# a predicate that has stopped firing.
#MUTANT-SUITE crates/batten/tests/it/policy_presets.rs
#MUTANT judged-threshold-unreachable|s@count(checks) > 0@count(checks) > 999@|the_landing_loop_preset_refuses_a_regrade_and_is_green_by_turns

# Every declared commit the forge has recorded a verdict for.
#
# GUARDED on `is_object`, and the guard is load-bearing rather than defensive:
# the key is `null` when no row declared a commit, and `some .. in null` is a
# hard evaluation FAULT in Rego, which takes the whole bundle down rather than
# missing quietly.
#
# `count(checks) > 0` is what separates JUDGED from LOOKED AT AND SILENT. A
# commit present with an empty object was judged and the forge reported nothing,
# which is not a verdict to conserve — re-running it is the honest move, so it is
# deliberately not refused here.
graded contains sha if {
	is_object(input.tree.forge)
	some sha, checks in input.tree.forge
	is_object(checks)
	count(checks) > 0
}

# Pointer-only (non-negotiable rule 4): the commit is an identifier the caller
# already holds, and naming it is what makes a stopped lap diagnosable rather
# than mysterious. Never a check body, never a fetched payload.
violation contains {
	"rule": "graded-head-is-not-regraded",
	"verdict": "head grade twice",
	"subjects": [{"artifact": sha}],
} if {
	some sha in graded
}

# --- the load-time tier ------------------------------------------------------
#
# These pin the PREDICATE. They cannot pin that the ENGINE builds a record keyed
# to the commit the caller meant — a `with input as` case fabricates the very
# shape the engine may be unable to produce, and here it would fabricate the
# KEYING this family turns on. `crates/batten/tests/policy_presets.rs` is the
# tier that runs this the way a consumer gets it, with the empty vocabulary.

recorded(checks) := {"tree": {"forge": {"1111111": checks}}}

test_a_judged_commit_is_refused if {
	some v in violation with input as recorded({"final": "success"})
	v.verdict == "head grade twice"
}

# A red verdict is still a verdict, and re-running it is still spend. The
# practice is about re-grading, never about which way the grade went.
test_a_red_commit_is_refused_too if {
	some v in violation with input as recorded({"final": "failure"})
	v.rule == "graded-head-is-not-regraded"
}

# THE ANTI-VACUITY MIRROR. Without it the two cases above are satisfied by a
# module that refuses everything, which is not a gate (CLOUD-418).
test_an_ungraded_commit_is_clean if {
	count(violation) == 0 with input as {"tree": {"forge": {}}}
}

# JUDGED AND SILENT is not judged. The forge looked and recorded nothing, so
# there is no answer to conserve and a fresh run is the right move.
test_a_commit_judged_with_no_verdicts_is_clean if {
	count(violation) == 0 with input as recorded({})
}

# COULD-NOT-LOOK, and without the `is_object` guard this case does not merely
# fail — it faults, taking the whole bundle with it.
test_could_not_look_does_not_fault if {
	count(violation) == 0 with input as {"tree": {"forge": null}}
}
