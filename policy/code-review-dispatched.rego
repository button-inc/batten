# METADATA
# description: |
#   The branch's own change carries a code-review receipt, or it does not land
#   (CLOUD-1484).
#
#   THIS REFUSES ABSENCE, AND ABSENCE IS ALL IT MAY REFUSE. A patch identity with
#   no receipt under it means the declared review has not been shown to run over
#   this change — a comparison of two digests, which is a thing a gate may decide.
#   What the reviewer CONCLUDED is not, and refusing on it would be a model
#   verdict wearing an exit code (non-negotiable rule 3). Nothing the agent wrote
#   reaches this module: the receipt's fields are a commit id and an instant, and
#   there is no channel here a finding's prose could travel down.
#
#   THE DISPATCH IS THE AGENT'S AND THE RECEIPT IS THE BOUNDARY'S, which is the
#   whole difference from `review-dispatched` beside it. That module's engine
#   SPAWNS a reviewer, which is what put a runner, a probe and a prompt channel
#   into a repo-agnostic core. Here Batten refuses, the refusal names what the
#   agent owes, the agent dispatches its own review with its own harness, and
#   `[[mint]]` writes the receipt from the tool result the boundary already sees.
#   Nothing about that harness is expressible in this module or in the crate.
#
#   WHY THIS IS NOT THE SHAPE CLOUD-1265 REFUTED. `tool-verdict`'s
#   producer-writes-outside store went measured dead — `validator-verdict-clean`
#   reads a record nothing ever writes — because a person had to remember to run
#   the producer, and `review.rs` cites exactly that as its reason to spawn. The
#   hook is what does not transfer: nobody has to remember, because the boundary
#   sees the call it is already mediating. A reader who takes CLOUD-1265 as
#   refuting this design is reading past that difference.
#
#   THREE ANSWERS AND THE MODULE READS ALL THREE. `input.tree.minted` is `null`
#   when no row declared a receipt or no store is readable — could-not-look, and
#   silence is the honest answer on a fresh clone, which is every CI runner until
#   CLOUD-877 gives the receipt a portable form. A declared id PRESENT with the
#   current patch identity absent from it is the finding. Present WITH it is
#   clean, whatever the review said.
#
#   THE CLEAN-TREE CONDITION IS NOT HERE, AND THAT IS A DECISION. A receipt is
#   keyed to COMMITTED bytes, so it must not be minted while the tree is dirty —
#   but that belongs at the write, where `mint_receipts` refuses, rather than as a
#   second opinion here about whether the tree is clean. `tree-clean` already owns
#   that question for the landing path. A conjunct here would either duplicate it
#   or, read the other way round, make a dirty tree silence this gate.
#
#   THE BRACKETS ARE NOT STYLE: the schema file carries a hyphen, so the dotted
#   form is a parse error reported as `invalid schema reference`.
#   THIS BLOCK IS YAML AND MUST STAY THE LAST COMMENT BLOCK BEFORE `package`.
# schemas:
#   - input: schema["policy-input.schema"]
package batten.code_review_dispatched

import rego.v1

rules contains "code-review-dispatched"

# The receipts this repository declares it will not land code without.
#
# The id is the CONSUMER's, named here rather than derived from the fact, for
# `review-dispatched`'s reason one module over: a rule that refused only over what
# it FOUND could never refuse an absence, which is the one thing this exists to
# refuse.
required contains "code-review"

# Whether the engine could look at the receipt store at all.
#
# GUARDED on `is_object`: the key is `null` when nobody declared a receipt or no
# store is readable, and reaching into `null` is a hard evaluation FAULT in Rego
# rather than a silent miss.
looked if {
	is_object(input.tree.minted)
}

delta := input.tree["base-delta"]

# The identity of the change this branch is asking to land.
#
# A MERGE-BASE diff over COMMITTED bytes, which is what makes it survive the
# landing loop: `land` rebases every lap, and an identity that moved with the
# rebase would re-buy the review each time — minutes and tokens per lap, which is
# the shape that gets a gate switched off rather than satisfied.
#
# Absent — a base that does not resolve, or an EMPTY diff — leaves every arm below
# quiet. A branch that changed nothing has no identity, and reading that as
# `unreviewed` would refuse a checkout with nothing to review.
subject := delta["patch-id"]

# Whether a review is owed at all.
#
# GATED ON CODE, not on any change. `code-changed` is the subset whose non-comment
# remainder moved, so a prose-only branch owes nothing — and neither does a fresh
# clone or a fixture, which is the narrowing `review-dispatched` had to add after
# four `cli.rs` cases went red at once for wanting to exercise other rules.
owed if {
	count(delta["code-changed"]) > 0
}

# Every declared receipt with nothing filed under this change.
#
# The keying stays the ENGINE's business: a receipt taken over other bytes lives
# under a different subject and never matches, so `absent from the map` already
# means `not reviewed as this now stands`. A module re-deriving that would be the
# second authority over an identity `git::branch_patch_id` already owns.
unattested contains id if {
	looked
	owed
	is_string(subject)
	some id in required
	not input.tree.minted[id][subject]
}

violation contains {
	"rule": "code-review-dispatched",
	"verdict": "patch read never",
	"subjects": [{"artifact": id}],
} if {
	some id in unattested
}

# --- the load-time tier ------------------------------------------------------
#
# These pin the PREDICATE. They cannot pin that the ENGINE keys a receipt by the
# branch's patch identity, or that a rebase leaves that identity alone — a
# `with input as` case fabricates the very keying the whole gate turns on.
# `crates/batten/tests/it/code_review_dispatched.rs` is that tier.

changed := {
	"added": [],
	"edited": ["crates/batten/src/lib.rs"],
	"deleted": [],
	"code-changed": ["crates/batten/src/lib.rs"],
	"patch-id": "abc",
}

attested(subjects) := {"tree": {
	"base-delta": changed,
	"minted": {"code-review": subjects},
}}

test_a_receipt_under_this_change_is_clean if {
	count(violation) == 0 with input as attested({"abc": "cafe 1700000000"})
}

test_no_receipt_at_all_is_refused if {
	some v in violation with input as attested({})
	v.verdict == "patch read never"
}

# A RECEIPT OVER OTHER BYTES DOES NOT ANSWER. This is the anti-staleness half and
# the reason the key is a digest rather than a marker: push a commit and the old
# record lives under a name nothing looks up.
test_a_receipt_over_another_change_does_not_answer if {
	some v in violation with input as attested({"zzz": "cafe 1700000000"})
	v.verdict == "patch read never"
}

# THE REFUSAL NAMES WHICH RECEIPT, so a reader is not left working out which of
# several declared ids is missing.
test_the_refusal_names_the_receipt if {
	ids := {v.subjects[0].artifact | some v in violation} with input as attested({})
	ids == {"code-review"}
}

# A RECORD UNDER ANOTHER ID IS NOT THIS ONE HAVING RUN.
test_another_receipts_record_does_not_answer if {
	some v in violation with input as {"tree": {
		"base-delta": changed,
		"minted": {"other": {"abc": "cafe 1700000000"}},
	}}
	v.verdict == "patch read never"
}

# COULD-NOT-LOOK, and without the `is_object` guard this case does not merely
# fail — it faults, taking the whole bundle with it.
test_could_not_look_does_not_fault if {
	count(violation) == 0 with input as {"tree": {"base-delta": changed, "minted": null}}
}

# A PROSE-ONLY BRANCH OWES NO CODE REVIEW. Without this the gate refuses every
# checkout that has never dispatched, which is every fixture and every fresh
# clone.
test_a_prose_only_branch_is_not_refused if {
	count(violation) == 0 with input as attested_over({
		"added": [],
		"edited": ["AGENTS.md"],
		"deleted": [],
		"code-changed": [],
		"patch-id": "abc",
	})
}

# AN EMPTY DIFF HAS NO IDENTITY, and refusing over one would be a verdict about a
# branch with nothing to review.
test_a_change_with_no_identity_is_not_refused if {
	count(violation) == 0 with input as attested_over({
		"added": [],
		"edited": ["crates/batten/src/lib.rs"],
		"deleted": [],
		"code-changed": ["crates/batten/src/lib.rs"],
		"patch-id": null,
	})
}

attested_over(d) := {"tree": {"base-delta": d, "minted": {"code-review": {}}}}

#MUTANT-SUITE crates/batten/tests/it/code_review_dispatched.rs
#MUTANT absent-receipt-unread|s@^\tnot input.tree.minted\[id\]\[subject\]$@\tfalse@|an_absent_receipt_is_refused_over_the_engines_own_projection
#MUTANT no-identity-priced|s@^\tis_string(subject)$@\ttrue@|a_change_with_no_identity_owes_no_review
#MUTANT prose-only-priced|s@^\towed$@\ttrue@|a_prose_only_branch_owes_no_code_review
