# METADATA
# description: |
#   The successor shape for the board-gate family, and the demonstration
#   CLOUD-1188 owes.
#
#   `claim-race-check`, `done-check`, `graph-check` and six siblings are PURE
#   PREDICATES that exist as CLI verbs only because they have nowhere to read
#   from — `.claude/rules/toolchain.md` names them as "a pure function of stdin".
#   None could migrate: a tree-scoped module asking about an issue's state read
#   undefined, and Rego takes undefined as *does not hold*. `input.tree.captured`
#   is the channel that was missing, and it is the difference between the
#   retirement campaign adding ~25 commands and adding none.
#
#   THE STORE HAS NO CLOCK, AND THAT BOUNDS WHAT A MODULE MAY ASK IT. Captures
#   are keyed by CONTENT and carry no timestamp — deliberately, because that is
#   what makes a reduction byte-stable — so a key read twice is two records and
#   `reduce` answers from the first in HANDLE order, which is digest order and
#   says nothing about time. A predicate over a MUTABLE field is therefore
#   unsound here: it can report a state that was true when somebody read it and
#   is not now.
#
#   This module asked exactly that in its first draft — "is the row pulled" — and
#   `batten check` over this repository's own store refused, correctly, from a
#   payload captured before the row was claimed. The fact was right and the
#   question was wrong. So the predicate moved to one the store CAN answer: a
#   property that does not change under a later read.
#
#   THE PREDICATE IS THIS CONSUMER'S. That a tracked row belongs to a project is
#   this tracker's vocabulary, and non-negotiable rule 1 keeps it out of
#   `crates/batten`. The engine supplies "the reduction this row declared"; this
#   module decides what an admissible answer looks like.
#
#   THE FACT CARRIES A TOKEN, NOT A PAYLOAD, AND THAT IS STRUCTURAL. The row
#   declares the reduction — `present`, `count`, or a bounded whitespace-free
#   `token` — so an issue body cannot reach this document even if a module asked
#   for one. A `token` over prose is REFUSED rather than truncated, which leaves
#   the id absent; that is why the guard below is `is_object` and then a
#   membership test, never a comparison against a value assumed present.
#
#   THREE ANSWERS, AND THE MODULE READS ALL THREE. `null` is could-not-look —
#   nobody declared a reduction, or no capture store is readable. A declared id
#   ABSENT from the map is a key nothing captured, or a reduction that refused.
#   An id PRESENT carries a real answer. This refuses only the third, because a
#   board gate reporting green over a store nobody filled is the vacuous pass in
#   its purest form.
#
#   THIS IS NOT THE CLAIM AUTOMATION. `claim-check` decides what is PULLABLE from
#   a payload the caller supplies; this decides whether a row the config names is
#   in a state work may proceed under, from bytes the agent already captured. The
#   polling and the fetching stay outside, exactly as CLOUD-1154's forge half
#   does.
#
#   THIS BLOCK IS YAML AND MUST STAY THE LAST COMMENT BLOCK BEFORE `package`.
# schemas:
#   - input: schema["policy-input.schema"]
package batten.claim_before_code

import rego.v1

rules contains "claim-before-code"

# Every declared id whose captured payload carries no project.
#
# A row nobody filed is a row no board state can be read about, which is why this
# is the sound question here: filing does not un-happen under a later read, so the
# answer does not depend on WHICH capture the store hands back.
#
# GUARDED on `is_object`: the key is `null` when nobody declared a reduction, and
# `some .. in null` is a hard evaluation FAULT in Rego rather than a silent miss.
refused contains id if {
	is_object(input.tree.captured)
	some id, filed in input.tree.captured

	# PRESENT AND ANSWERED `false`, which is the only state this refuses: a
	# capture exists for the key and it carries no project. An id nothing
	# captured is absent from the map entirely and never reaches here, which is
	# the could-not-look arm and not a verdict.
	filed == false
}

violation contains {
	"rule": "claim-before-code",
	"verdict": "V-CLAIM-BEFORE-CODE",
	"subjects": [{"count": count(refused)}],
} if {
	count(refused) > 0
}

# --- the load-time tier ------------------------------------------------------
#
# These pin the PREDICATE. They cannot pin that the ENGINE reduces the capture
# store at all — a `with input as` case fabricates the very shape the engine may
# be unable to produce (CLOUD-845, CLOUD-857), and here it would fabricate the
# reduction the whole family turns on.
# `crates/batten/tests/captured_facts.rs` is that tier, and its
# `no_payload_prose_reaches_the_policy_input` and
# `two_runs_over_an_unchanged_store_agree` cases are the discriminating ones.

reduced(filed) := {"tree": {"captured": {"this-row": filed}}}

test_a_filed_row_is_clean if {
	count(violation) == 0 with input as reduced(true)
}

test_an_unfiled_row_is_refused if {
	some v in violation with input as reduced(false)
	v.verdict == "V-CLAIM-BEFORE-CODE"
}

# NOTHING WAS CAPTURED about this key is not a verdict. The id is absent from the
# map, so there is nothing to refuse — the distinction the fact keeps, and the one
# a board gate reading a store nobody filled would destroy.
test_an_id_with_no_capture_is_not_refused if {
	count(violation) == 0 with input as {"tree": {"captured": {}}}
}

# A reduction of another KIND is not this predicate's answer. A `count` or a
# `token` under some other id must not be read as an unfiled row.
test_another_reduction_is_not_this_answer if {
	count(violation) == 0 with input as {"tree": {"captured": {"other-row": 3}}}
}

# COULD-NOT-LOOK, and without the `is_object` guard this case does not merely
# fail — it faults, taking the whole bundle with it.
test_could_not_look_does_not_fault if {
	count(violation) == 0 with input as {"tree": {"captured": null}}
}

#MUTANT-SUITE crates/batten/tests/it/captured_facts.rs
#MUTANT-OWNER CLOUD-845|the tier this module names drives `input.tree.captured` and never installs the module, so no case in it can turn red under a mutation of the predicate
#MUTANT refusal-unread|s@^\tcount(refused) > 0$@\tfalse@|a_declared_reduction_reaches_the_module
