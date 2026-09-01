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

rules contains "forge-verdict-required"

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
}

# The fan-in reported, and it passed. Anything else — reported and failed, or
# never reported at all — is not this.
passed(checks) if {
	checks[required] == "success"
}

violation contains {
	"rule": "forge-verdict-required",
	"verdict": "V-FORGE-VERDICT-NOT-GREEN",
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
	v.verdict == "V-FORGE-VERDICT-NOT-GREEN"
}

# A judged commit whose fan-in never reported is not green, and reading it as
# green is exactly the false pass CLOUD-900 records.
test_a_record_missing_the_fan_in_is_refused if {
	some v in violation with input as recorded({"lint": "success"})
	v.verdict == "V-FORGE-VERDICT-NOT-GREEN"
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

#MUTANT-SUITE crates/batten/tests/forge_facts.rs
#MUTANT-OWNER CLOUD-845|the tier this module names drives `input.tree.forge` and never installs the module, so no case in it can turn red under a mutation of the predicate
#MUTANT refusal-unread|s@^\tcount(refused) > 0$@\tfalse@|a_declared_sha_reads_its_own_record
