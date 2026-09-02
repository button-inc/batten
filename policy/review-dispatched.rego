# METADATA
# description: |
#   A declared review ran over these bytes, or the branch does not land
#   (CLOUD-472).
#
#   THIS REFUSES ABSENCE, AND ABSENCE IS ALL IT MAY REFUSE. A declared id missing
#   from `input.tree.review` was never dispatched — the prompt has not been shown
#   to run over this subject — and that is a comparison of two digests, which is
#   a thing a gate may decide. What the agent CONCLUDED is not, and refusing on
#   it would be a model verdict wearing an exit code (non-negotiable rule 3). The
#   fact is shaped so that cannot be written: `findings` are `{path, line,
#   clause}` pointers with no field prose could occupy.
#
#   THE OPPOSITE ARM FROM `forge-verdict-required`, DELIBERATELY. That module
#   refuses only a PRESENT-and-red verdict and reads absence as could-not-look,
#   because the forge is a third party that may legitimately not have judged yet.
#   A review this branch was supposed to dispatch and did not is the branch's own
#   conduct, so here absence is the finding and a present record is clean whatever
#   it points at. Reading one module's posture as the family's is how a gate ends
#   up refusing the wrong arm.
#
#   THREE ANSWERS AND THE MODULE READS ALL THREE. `null` is could-not-look —
#   no row declared a review, or no store is readable. A declared id ABSENT from
#   the map has no record. An id PRESENT with an empty `findings` array ran and
#   pointed at nothing, which is clean and must stay clean: a gate that refused it
#   would price finding nothing, and the cheapest way past such a gate is an agent
#   that invents a finding.
#
#   WHY THE CHEAPER TIERS DO NOT SUBSTITUTE. `ready-lint` gates the SHAPE of a
#   refinement block, and shape is what an author optimises against once the gate
#   exists — the measured failure that opened CLOUD-472, where every clause was
#   present and none had been pressure-tested. `obligations-bound` binds a §7
#   entry to a killer mutation, but only at implementation time; at refinement
#   there is no code and no `#MUTANT` row to reach. A hash comparison is what
#   better-shaped prose cannot satisfy, because the prose is the input to the
#   hash.
#
#   THE BRACKETS ARE NOT STYLE: the schema file carries a hyphen, so the dotted
#   form is a parse error reported as `invalid schema reference`.
#   THIS BLOCK IS YAML AND MUST STAY THE LAST COMMENT BLOCK BEFORE `package`.
# schemas:
#   - input: schema["policy-input.schema"]
package batten.review_dispatched

import rego.v1

rules contains "review-dispatched"

# The reviews this repository declares it will not land without.
#
# The ids are the CONSUMER's, named here rather than derived from the fact: the
# fact carries what was dispatched, and a module that refused only over what it
# found could never refuse an absence — the one thing it exists to refuse. This
# is the same shape as `forge-verdict-required`'s `required := "final"`, and the
# same reason: the engine supplies what happened, the module decides what must.
required contains "ready-pressure-test"

# Whether the engine could look at the review store at all.
#
# GUARDED on `is_object`: the key is `null` when nobody declared a review or no
# store is readable, and reaching into `null` is a hard evaluation FAULT in Rego
# rather than a silent miss — the failure `forge-verdict-required`'s own comment
# records.
looked if {
	is_object(input.tree.review)
}

# The branch's own diff, as the engine resolved it — the same reading
# `plan-complete` and `filed-here` take, and `null` when the base does not
# resolve, so `changed` stays empty and every arm goes quiet rather than
# fabricating a verdict.
delta := input.tree["base-delta"]

changed contains path if {
	some path in delta.added
}

changed contains path if {
	some path in delta.edited
}

changed contains path if {
	some path in delta.deleted
}

# Every declared review with no record for the current subject.
#
# GATED ON THE ROW'S OWN DELTA, and without it this gate is unusable rather than
# merely noisy. The row declares `delta_sources` over the subject it reviews, so a
# non-empty delta means the thing to be reviewed CHANGED on this branch — which is
# when a review is owed. Ungated, the refusal fires on every checkout that has
# never dispatched, which is every fixture and every fresh clone: measured here,
# four `cli.rs` cases that only wanted to exercise other rules went red at once.
# That is the shape that gets a gate switched off, and `plan-complete` carries the
# identical narrowing for the identical reason.
#
# The digests stay the ENGINE's business: a record keyed to another prompt, or to
# bytes that have since changed, lives under a different name and never reaches
# the map. So "absent from the map" already means "not dispatched over what is
# here now", and a module re-deriving that would be a second authority over a key
# the engine composes.
undispatched contains id if {
	looked
	count(changed) > 0
	some id in required
	not input.tree.review[id]
}

violation contains {
	"rule": "review-dispatched",
	"verdict": "prompt run never",
	"subjects": [{"artifact": id}],
} if {
	some id in undispatched
}

# --- the load-time tier ------------------------------------------------------
#
# These pin the PREDICATE. They cannot pin that the ENGINE builds
# `input.tree.review` from a record the dispatch wrote — a `with input as` case
# fabricates the very shape the engine may be unable to produce, and here it
# would fabricate the KEYING the whole fact turns on.
# `crates/batten/tests/it/review_dispatched.rs` is that tier.

touched := {"added": ["AGENTS.md"], "edited": [], "deleted": [], "code-changed": []}

dispatched(findings) := {"tree": {
	"base-delta": touched,
	"review": {"ready-pressure-test": {
		"provenance": {"tool": "stub", "version": "0", "invocation": [], "prompt": "p"},
		"subject": {"kind": "document", "digest": "d"},
		"findings": findings,
	}},
}}

test_a_dispatched_review_is_clean if {
	count(violation) == 0 with input as dispatched([])
}

# A REVIEW THAT POINTED AT SOMETHING IS STILL A REVIEW THAT RAN. Refusing here
# would price finding something, and the cheapest way past that gate is an agent
# that reports nothing — which is the incentive this module must not create.
test_a_review_with_findings_is_still_clean if {
	count(violation) == 0 with input as dispatched([{"path": "a.md", "line": 1, "clause": "§7"}])
}

test_an_undispatched_review_is_refused if {
	some v in violation with input as {"tree": {"base-delta": touched, "review": {}}}
	v.verdict == "prompt run never"
}

# THE REFUSAL NAMES WHICH REVIEW, so a reader is not left to work out which of
# several declared ids is missing.
test_the_refusal_names_the_review if {
	ids := {v.subjects[0].artifact | some v in violation} with input as {"tree": {"base-delta": touched, "review": {}}}
	ids == {"ready-pressure-test"}
}

# A RECORD UNDER ANOTHER ID DOES NOT ANSWER. The map is keyed by the declared id,
# so a review of something else is not this one having run.
test_another_reviews_record_does_not_answer if {
	some v in violation with input as {"tree": {"base-delta": touched, "review": {"other": {"findings": []}}}}
	v.verdict == "prompt run never"
}

# COULD-NOT-LOOK, and without the `is_object` guard this case does not merely
# fail — it faults, taking the whole bundle with it.
test_could_not_look_does_not_fault if {
	count(violation) == 0 with input as {"tree": {"base-delta": touched, "review": null}}
}

# A BRANCH THAT DID NOT TOUCH THE SUBJECT OWES NO REVIEW. Without this the gate
# refuses every checkout that has never dispatched — every fixture and every
# fresh clone — which is the shape that gets a gate switched off rather than
# satisfied.
test_an_untouched_subject_is_not_refused if {
	count(violation) == 0 with input as {"tree": {
		"base-delta": {"added": [], "edited": [], "deleted": [], "code-changed": []},
		"review": {},
	}}
}

#MUTANT-SUITE crates/batten/tests/it/review_dispatched.rs
#MUTANT absence-unread|s@^\tnot input.tree.review\[id\]$@\tfalse@|an_absent_record_is_refused_over_the_engines_own_projection
#MUTANT could-not-look-refused|s@^\tlooked$@\ttrue@|a_missing_runner_is_could_not_look_and_never_a_refusal
#MUTANT untouched-subject-priced|s@^\tcount(changed) > 0$@\ttrue@|a_branch_that_did_not_touch_the_subject_owes_no_review
