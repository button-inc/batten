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
#   THE PREDICATE IS THIS CONSUMER'S. Which states exist, and which of them means
#   "pulled", is this tracker's vocabulary — AGENTS.md's board section spells it
#   `In Progress` — and non-negotiable rule 1 keeps that out of `crates/batten`.
#   The engine supplies "the token this row's declared reduction produced"; this
#   module decides which tokens are admissible.
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

# The state token that means a row has been pulled.
#
# One token rather than a set: AGENTS.md's board section names exactly one state
# as "pulled", and enumerating the others would make a state added later read as
# admissible by omission.
pulled := "started"

# Every declared id whose reduction produced a state that is not `pulled`.
#
# GUARDED on `is_object`: the key is `null` when nobody declared a reduction, and
# `some .. in null` is a hard evaluation FAULT in Rego rather than a silent miss.
refused contains id if {
	is_object(input.tree.captured)
	some id, state in input.tree.captured

	# PRESENT AND ANSWERED, which is the only state this refuses. An id whose
	# key nothing captured — or whose `token` reduction refused prose — is
	# absent from the map entirely and never reaches here.
	is_string(state)
	state != pulled
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

reduced(state) := {"tree": {"captured": {"this-row": state}}}

test_a_pulled_row_is_clean if {
	count(violation) == 0 with input as reduced("started")
}

test_an_unpulled_row_is_refused if {
	some v in violation with input as reduced("unstarted")
	v.verdict == "V-CLAIM-BEFORE-CODE"
}

# NOTHING WAS CAPTURED about this key is not a verdict. The id is absent from the
# map, so there is nothing to refuse — the distinction the fact keeps, and the one
# a board gate reading a store nobody filled would destroy.
test_an_id_with_no_capture_is_not_refused if {
	count(violation) == 0 with input as {"tree": {"captured": {}}}
}

# A reduction that REFUSED — a `token` over prose — leaves the id absent for the
# same reason, and must not be read as a state.
test_a_refused_reduction_is_not_a_state if {
	count(violation) == 0 with input as {"tree": {"captured": {"other-row": true}}}
}

# COULD-NOT-LOOK, and without the `is_object` guard this case does not merely
# fail — it faults, taking the whole bundle with it.
test_could_not_look_does_not_fault if {
	count(violation) == 0 with input as {"tree": {"captured": null}}
}

#MUTANT-EXEMPT CLOUD-931|no `tests/claim-before-code.bats` exists and none may be added: `mutant` resolves a gate's suite as `tests/$gate.bats`, and `V-SHELL-RULE-ADDED` refuses adding one, so there is no named case a mutation could turn red. The load-time tier is this file's own `test_` rules and the engine tier is `crates/batten/tests/captured_facts.rs`, neither of which is what the mutation runner drives
