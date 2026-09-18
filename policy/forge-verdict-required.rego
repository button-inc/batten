# METADATA
# description: |
#   The successor shape for the forge-reading half of CLOUD-1154's ~22, and the
#   demonstration that row owes.
#
#   `checks-green` asks one question: over a NAMED required set, is this sha
#   green? It could not migrate, because a tree-scoped module asking about a
#   check-run read undefined — Rego takes undefined as *does not hold*, so the
#   module was a dead gate, byte-identical to a clean tree on the decision
#   surface. `input.tree.forge` is the channel that was missing.
#
#   THE POLLING STAYS OUTSIDE. Per CLOUD-1177 only the DECISION moves into the
#   engine; `ci-wait`, `main-watch` and `abandon-matrix` keep their loop. This
#   module is the decision half and nothing else, which is why it needs no clock.
#
#   THE REQUIRED SET IS THIS CONSUMER'S. Which check names carry a verdict about
#   this repository is `mise.toml`'s `$CI_REQUIRED_CHECKS`, and non-negotiable
#   rule 1 keeps that out of `crates/batten`. The engine supplies "the verdicts
#   recorded for this sha"; the module decides what must be among them.
#
#   THREE ANSWERS, AND THE MODULE READS ALL THREE. `null` is could-not-look —
#   nobody declared a sha, or no store is readable. A declared sha ABSENT from
#   the map has no record: nothing has judged that commit. A sha PRESENT with an
#   empty object was judged and the forge said nothing. This module refuses only
#   the third, because the first two are not verdicts and a gate that treated
#   them as one would report on a commit nothing looked at.
#
#   THE BRACKETS ARE NOT STYLE: the schema file carries a hyphen, so the dotted
#   form is a parse error reported as `invalid schema reference`.
#   THIS BLOCK IS YAML AND MUST STAY THE LAST COMMENT BLOCK BEFORE `package`.
# schemas:
#   - input: schema["policy-input.schema"]
package batten.forge_verdict

import rego.v1

rules contains "forge check red"

# The check that carries this repository's verdict.
#
# One name rather than a set, deliberately: `final` is the fan-in every other
# required job feeds, and CLOUD-900 records what naming the leaves instead buys —
# every failure becomes manufacturable by omitting a job.
required := "final"

# Every declared sha whose record exists and does not carry a passing `final`.
#
# GUARDED on `is_object`: the key is `null` when nobody declared a sha, and
# `some .. in null` is a hard evaluation FAULT in Rego rather than a silent miss.
refused contains sha if {
	is_object(input.tree.forge)
	some sha, checks in input.tree.forge

	# PRESENT AND JUDGED, which is the only state this refuses. A sha with no
	# record is absent from the map entirely and never reaches here.
	#
	# `not passed(..)` RATHER THAN `!= "success"`, and the difference is a real
	# defect this file had first: Rego reads a MISSING key as undefined, and
	# `undefined != "success"` does not hold — so a record whose fan-in never
	# reported read as clean. That is precisely CLOUD-900's false pass, where
	# every failure becomes manufacturable by omitting a job. Negating a helper
	# is what makes absent and wrong the same refusal.
	not passed(checks)

	# AND THE FORGE ACTUALLY ANSWERED (CLOUD-1831). `passed` alone read "the forge
	# declined to run" as "the forge said no", which wedges a branch with no exit:
	# a draft's checks are stamped `skipped`, `record-verdicts` writes that record,
	# this row refuses it, `verify` exits 2 — and readying the pull request, the
	# only thing that would make `final` report anything else, is downstream of the
	# `land` that `verify` just stopped. Measured 2026-09-17 on #973, and again on
	# #974 where it cost four laps.
	not declined(checks)
}

# The fan-in reported, and it passed. Anything else — reported and failed, or
# never reported at all — is not this.
passed(checks) if {
	checks[required] == "success"
}

# The fan-in DECLINED to answer rather than answering no.
#
# STATED AS THE NON-ANSWER SET AND NEGATED, which is forced rather than stylistic.
# The obvious spelling is the complement — require `checks[required]` to be one of
# `CI_ANSWERED_CONCLUSIONS` — and it silently reintroduces CLOUD-900's false pass:
# a record that OMITS `final` leaves `checks[required]` undefined, so an
# is-an-answer test does not hold either, and the omission stops being refused.
# Negating the non-answer keeps absent and wrong the same refusal, exactly as
# `not passed(..)` above does.
#
# THE COMPLEMENT LIVES IN `mise.toml` as `CI_ANSWERED_CONCLUSIONS`, which
# `checks-green` and `ci-wait` read (CLOUD-363 fixed this same word in those two).
# The two spellings are complements rather than copies — this one cannot be
# written as the answered set for the reason above — so `mise.toml`'s own comment
# points here, and a change to either owes a look at the other. Three readers of
# one word is how this recurred.
declined(checks) if {
	checks[required] in non_answers
}

# `skipped` is a draft's stamp and `cancelled` is a superseded run's; neither is
# a judgement about the commit.
non_answers := {"skipped", "cancelled"}

violation contains {
	"rule": "forge check red",
	"verdict": "forge check red",
	"subjects": [{"count": count(refused)}],
} if {
	count(refused) > 0
}

# --- the load-time tier ------------------------------------------------------
#
# These pin the PREDICATE. They cannot pin that the ENGINE reads a record keyed
# to the right sha — a `with input as` case fabricates the very shape the engine
# may be unable to produce, and here it would fabricate the KEYING the family
# turns on. `crates/batten/tests/forge_facts.rs` is that tier, and its
# `a_record_keyed_to_another_sha_does_not_answer` case is the discriminating one.

recorded(checks) := {"tree": {"forge": {"1111111": checks}}}

test_a_green_record_is_clean if {
	count(violation) == 0 with input as recorded({"final": "success"})
}

test_a_failed_record_is_refused if {
	some v in violation with input as recorded({"final": "failure"})
	v.verdict == "forge check red"
}

# A judged commit whose fan-in never reported is not green, and reading it as
# green is exactly the false pass CLOUD-900 records.
test_a_record_missing_the_fan_in_is_refused if {
	some v in violation with input as recorded({"lint": "success"})
	v.verdict == "forge check red"
}

# NOTHING HAS JUDGED THIS COMMIT is not a verdict. The sha is absent from the
# map, so there is nothing to refuse — the distinction the fact keeps.
test_a_sha_with_no_record_is_not_refused if {
	count(violation) == 0 with input as {"tree": {"forge": {}}}
}

# COULD-NOT-LOOK, and without the `is_object` guard this case does not merely
# fail — it faults, taking the whole bundle with it.
test_could_not_look_does_not_fault if {
	count(violation) == 0 with input as {"tree": {"forge": null}}
}

# THE FORGE DECLINED TO RUN (CLOUD-1831). A draft's checks are stamped `skipped`,
# and a skip is the absence of an answer rather than an answer of no. Refusing it
# wedges the branch: readying the pull request is the only thing that makes
# `final` report anything else, and it is downstream of the `land` this refusal
# stops.
test_a_skipped_fan_in_is_not_refused if {
	count(violation) == 0 with input as recorded({"final": "skipped"})
}

# `cancelled` is the same class, one cause over: a run superseded before it could
# answer. CLOUD-363 fixed this same word for `ci-wait` and `checks-green`.
test_a_cancelled_fan_in_is_not_refused if {
	count(violation) == 0 with input as recorded({"final": "cancelled"})
}

# THE PAIR THAT KEEPS THE FIX FROM BECOMING CLOUD-900's FALSE PASS, and it is the
# load-bearing half. A non-answer is admitted only where the fan-in SAID so — a
# record that omits `final` entirely is still refused (the case above), and a
# leaf skipping while the fan-in genuinely failed is still refused here. Without
# this, "distinguish a non-answer" collapses into "admit anything that is not
# success", which is the predicate this module was written to avoid.
test_a_failed_fan_in_beside_a_skipped_leaf_is_still_refused if {
	some v in violation with input as recorded({"final": "failure", "windows": "skipped"})
	v.verdict == "forge check red"
}

#MUTANT-SUITE crates/batten/tests/it/forge_facts.rs
# THE CLOUD-845 OWNER NOTE IS WITHDRAWN, because its premise stopped being true
# (CLOUD-1831). It read "the tier this module names drives `input.tree.forge` and
# never installs the module, so no case in it can turn red under a mutation of
# the predicate" — correct while every case there drove `probe.rego`. The suite
# now installs THIS module from the tree in `real_fixture`, so a mutation of the
# predicate is observable and the exemption would be a stale claim about the
# world rather than a declared gap.
#MUTANT refusal-unread|s@^\tcount(refused) > 0$@\tfalse@|a_failed_fan_in_beside_a_skipped_leaf_is_still_refused
# CLOUD-1831's two, and they are a PAIR that cannot shadow each other — which is
# the whole reason the row names two. The first reinstates the wedge: drop the
# declined conjunct and a skipped fan-in is refused again. The second reinstates
# CLOUD-900's false pass from the other side: widen `non_answers` to admit every
# non-success conclusion and a genuine `failure` stops being refused. A fix that
# survived both would be one that admitted everything.
#MUTANT skipped-fan-in-refused|s@^\tnot declined(checks)$@\ttrue@|a_skipped_fan_in_is_not_refused
#MUTANT missing-fan-in-admitted|s@^\tchecks\[required\] in non_answers$@\tchecks[required] != "success"@|a_failed_fan_in_beside_a_skipped_leaf_is_still_refused
