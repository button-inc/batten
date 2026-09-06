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
#   THREE ANSWERS AND THE MODULE READS ALL THREE, AND THE ARM IS PER-ID.
#   `input.tree.minted` is `null` when no row declared a receipt, and a declared id
#   is ABSENT from the map when the engine could not LIST its store — both are
#   could-not-look, and silence is the honest answer on a fresh clone, which is
#   every CI runner until CLOUD-877 gives the receipt a portable form. An id
#   PRESENT with the current patch identity absent from it is the finding: the
#   engine looked and there is no receipt. Present WITH it is clean, whatever the
#   review said.
#
#   READING THE OUTER MAP AS THE COULD-NOT-LOOK CHANNEL IS THE MISTAKE THIS
#   MODULE ALREADY MADE ONCE. An unlistable store leaves that map EMPTY, not
#   `null`, so a guard on the outer object refuses exactly the case it means to
#   abstain on.
#
#   TWO WAYS THIS OVER-OWES, BOTH STATED RATHER THAN DISCOVERED. `owed` is read
#   off a TIP diff over the working tree and `subject` is a MERGE-BASE diff over
#   committed bytes, so the two do not answer about the same range. On a stale
#   branch, code that landed on trunk reads as this branch's and a prose-only
#   branch can owe a review until it rebases — `verify` asserts the branch is
#   rebased on current `origin/main`, so on the path that matters they agree. And
#   the identity covers the WHOLE change, so a prose commit added to a branch that
#   also carries code moves the key and re-owes the review. Both err toward owing
#   a review that is not strictly due, which is the direction a completion gate
#   should fail in; neither can produce the other direction, which is a branch
#   landing unread.
#
#   THE CLEAN-TREE CONDITION IS NOWHERE, AND THAT IS A DECISION TWICE OVER. A
#   conjunct here would either duplicate `tree-clean` — which already owns tree
#   cleanliness for the landing path, and which nothing reaches `main` without
#   passing — or, read the other way round, let a dirty tree SILENCE this gate.
#   The mint carried one instead and it has been withdrawn: `git::uncommitted`
#   counts an uninitialised gitlink as changed, so `Ok(0)` was unsatisfiable in
#   this repository and the receipt could never have been written (CLOUD-1500).
#   A reviewer reads the working tree anyway, so refusing to record a dispatch
#   taken over uncommitted work would attest less than happened, not more.
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

# Whether the engine could look at the receipt store FOR THIS ID.
#
# PER-ID, NOT ON THE OUTER MAP, and that distinction is the whole three-valued
# read rather than a refinement of it. `minted::fields` inserts an entry for every
# declared row whose store it could LIST, and skips the row entirely when it could
# not — so an id ABSENT from the map is could-not-look, and an id PRESENT with no
# matching subject is the engine having looked and found nothing.
#
# THE FIRST DRAFT GUARDED ON `is_object(input.tree.minted)` AND HAD THE ARM
# EXACTLY BACKWARDS. An unlistable store leaves the map EMPTY rather than `null`,
# `is_object({})` holds, and the refusal then fired on every fresh clone and every
# CI runner — the arm this module's own METADATA says it abstains on, and the one
# `batten.toml` promises is honestly silent until CLOUD-877 gives the receipt a
# portable form. Caught by the code review this gate exists to demand, which is
# the only reason it is not in the tree.
#
# BOTH `is_object` CALLS ARE LOAD-BEARING. The outer one is what keeps this from
# indexing `null` — a hard evaluation FAULT in Rego rather than a silent miss —
# when no row declares a receipt at all.
looked_at(id) if {
	is_object(input.tree.minted)
	is_object(input.tree.minted[id])
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

# The path prefixes this repository treats as code for the purpose of owing a
# review.
#
# DECLARED HERE BECAUSE THE ROW'S `delta_sources` DOES NOT NARROW WHAT THIS
# MODULE SEES, which is the engine's shape rather than a mistake in the row.
# `rules.rs` builds ONE `base_delta` from the UNION of every row's globs and hands
# the same value to every module, so a row's own list only ever ADDS to what
# everybody reads — and six rows in this config declare `["**"]`. Without the
# narrowing below, a branch touching only `.github/workflows/*.yml` or
# `schema/*.json` would owe a code review. Caught by the code review this gate
# exists to demand.
#
# PREFIXES RATHER THAN A `[[pattern]]` ROW: this is a path SET, not a concept with
# one spelling, and `.claude/rules/policy-modules.md`'s registry is for the
# latter. A threshold or a path list spelled as a regex is the error that file
# records twice.
reviewable := {"crates/", "policy/", "mise-tasks/"}

# Whether a review is owed at all.
#
# GATED ON CODE, not on any change. `code-changed` is the subset whose non-comment
# remainder moved, so a prose-only branch owes nothing — and neither does a fresh
# clone or a fixture, which is the narrowing `review-dispatched` had to add after
# four `cli.rs` cases went red at once for wanting to exercise other rules.
owed if {
	some path in delta["code-changed"]
	some prefix in reviewable
	startswith(path, prefix)
}

# `batten.toml` is the policy authority every gate reads, so an edit to it is a
# change to what this repository refuses. A separate arm rather than a fourth
# prefix, because it is a FILE and the set above is a directory test — folding it
# in would make `batten.toml.example` reviewable by accident.
owed if {
	"batten.toml" in delta["code-changed"]
}

# Every declared receipt with nothing filed under this change.
#
# The keying stays the ENGINE's business: a receipt taken over other bytes lives
# under a different subject and never matches, so `absent from the map` already
# means `not reviewed as this now stands`. A module re-deriving that would be the
# second authority over an identity `git::branch_patch_id` already owns.
unattested contains id if {
	owed
	is_string(subject)
	some id in required
	looked_at(id)
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
# A CHANGE OUTSIDE THE REVIEWABLE PREFIXES OWES NOTHING. The row's own
# `delta_sources` cannot express this — the engine hands every module one delta
# built from the union of every row's globs — so without the prefix set a
# workflow-only or schema-only branch owes a code review.
test_a_change_outside_the_reviewable_prefixes_is_not_refused if {
	count(violation) == 0 with input as attested_over({
		"added": [],
		"edited": [".github/workflows/ci.yml"],
		"deleted": [],
		"code-changed": [".github/workflows/ci.yml"],
		"patch-id": "abc",
	})
}

# THE POLICY AUTHORITY IS REVIEWABLE ON ITS OWN ARM. An edit to `batten.toml` is a
# change to what this repository refuses.
test_an_edit_to_the_authority_is_refused if {
	some v in violation with input as attested_over({
		"added": [],
		"edited": ["batten.toml"],
		"deleted": [],
		"code-changed": ["batten.toml"],
		"patch-id": "abc",
	})
	v.verdict == "patch read never"
}

# AN UNLISTABLE STORE IS COULD-NOT-LOOK, and reading it as `looked` is the defect
# the code review caught: `minted::fields` leaves the id ABSENT when it cannot
# list, so the map is EMPTY rather than `null` and a guard on the outer object
# refuses every fresh clone and every CI runner.
test_an_unlistable_store_is_not_refused if {
	count(violation) == 0 with input as {"tree": {"base-delta": changed, "minted": {}}}
}

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
#MUTANT store-unreadable-refused|s@^\tlooked_at(id)$@\ttrue@|an_unlistable_store_is_could_not_look_and_never_a_refusal
