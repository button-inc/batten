# A worktree registration outlives the checkout it names (CLOUD-1424).
#
# `git worktree add` writes a registration under the common dir's `worktrees/`
# directory, and removing the worktree directory does not remove it. Nothing read
# that registry before this module, so a stranded row was invisible where it was
# created and surfaced somewhere else entirely — a later, unrelated command that
# resolves the registry and refuses over a path no reader recognises. The distance
# between cause and symptom is the whole harm; the state itself is trivial to
# clear once anyone knows it is there.
#
# THE PROSE WAS ALREADY IN THE TREE AND THE MECHANISM WAS NOT, which is
# non-negotiable rule 2's half a change. `crates/batten/src/semver.rs`'s
# `baseline_rustdoc` records the failure in a doc comment: a worktree keeps a
# registration outside the directory, so removing the scratch stranded a stale
# entry and the next run refused over a path that was no longer there. A gate is
# what that paragraph was missing.
#
# TWO LIVE PRODUCERS, so this is a class rather than one incident. `mise.toml`'s
# baseline scratch adds a detached worktree and clears it from a `trap ... EXIT`,
# which does not fire when the process is killed — and an agent harness kills a
# foreground command at ~2 minutes. Measured 2026-09-03: a reproduction worktree
# stranded in exactly that way in this container, and the recovery was hand-driven
# because no gate named the condition.
#
# WHAT THIS IS NOT. CLOUD-780 retired `worktree reclaim` — the crate's only
# destructive path — and priced the loss. Nothing here reverses that: this reports
# a registration and removes none, and the remedy is the reader's to run. What
# CLOUD-780 dropped for a different reason was the LISTING, because it was a
# `git worktree list` shell-out gix had no API for; gix answers it in process now,
# so the fact behind this module reinstates no spawn and
# `no_second_git_invoker_exists` stays terminal.

# METADATA
# description: |
#   Bound to the TREE surface: `scope = "tree"`, reading the registry the engine
#   resolved rather than the mediated `{call, facts}` shape.
#   THE BRACKETS ARE NOT STYLE: the schema file carries a hyphen, so the dotted
#   form is a parse error reported as `invalid schema reference`.
# schemas:
#   - input: schema["policy-input.schema"]
package batten.worktree

import rego.v1

rules contains "worktree-registration-live"

# THE FINDING. A registration whose directory is gone, and which nobody locked.
#
# `== false` RATHER THAN `not`, in both conjuncts, and it is the direction a miss
# has to fail in. Rego reads an absent key as undefined and `not undefined` HOLDS,
# so the negated spelling would refuse EVERY registration on an engine that
# stopped emitting the field, where the comparison refuses none. A gate that goes
# silent when its input changes shape is the recoverable failure; one that starts
# denying everything is how a guard gets switched off.
violation contains {
	"rule": "worktree-registration-live",
	"verdict": "worktree name absent",
	# `artifact` rather than `path`, because the registration's id is not a
	# repository path and the fact deliberately carries no path at all: a linked
	# worktree may live anywhere on the machine, so its base is read to decide
	# `present` and dropped at the boundary (non-negotiable rule 4). The id is
	# what `git worktree list` shows and what the remedy clears.
	"subjects": [{"artifact": registration.id}],
} if {
	some registration in input.tree["git-worktrees"].linked
	registration.present == false
	registration.locked == false
}

# THE COULD-NOT-LOOK ARM, and it is not decoration.
#
# The rule row declares `git = ["worktrees"]`, so `null` here cannot mean "nobody
# asked" — it means the engine asked and could not read the registry. Without this
# clause that reads exactly like a clean one, which is the class
# `mem:gate-could-not-look` records and CLOUD-1049 measured: a gate switched off by
# the state of one of its own inputs, at exit 0.
#
# An EMPTY `linked` list is deliberately NOT this arm. The main checkout keeps no
# registration, so a repository with no linked worktrees genuinely has nothing to
# report, and that is a third answer sitting between the two above.
#
# OVER `linked`, NOT OVER THE FACT, which is `spawn-adapters.rego`'s recorded
# lesson arriving a second time. `== null` was written here first and evaluates
# correctly under regorus — both tiers were green over it — but `opa check -s`
# refuses it: the schema declares `["object", "null"]`, the checker narrows the ref
# to the object arm, and the comparison is a `rego_type_error: match error`. So the
# build-time check and the runtime disagreed about a clause that worked, which is
# the skew `opa-tracks-regorus-compliance` exists to keep out.
#
# Asking for `linked` answers both, and keeps the third answer distinct: an absent
# key and a `null` both leave it undefined, while a registry that was read always
# carries the array — EMPTY when there is nothing to report, which is defined, so
# `not` is false and a repository with only its main checkout stays clean.
violation contains {
	"rule": "worktree-registration-live",
	"verdict": "worktree list unread",
	"subjects": [{"count": 0}],
} if {
	not input.tree["git-worktrees"].linked
}

test_a_registration_whose_directory_is_gone_is_refused if {
	some v in violation with input as {"tree": {"git-worktrees": {"linked": [{
		"id": "mainwt",
		"present": false,
		"locked": false,
	}]}}}
	v.verdict == "worktree name absent"
	v.subjects[0].artifact == "mainwt"
}

# THE ALLOW HALF, and it carries the whole precision claim: a live extra worktree
# is legitimate. A predicate refusing every registration would satisfy the deny
# above and make the gate unusable for anyone who works in a second checkout,
# which is what the class exists to protect rather than to punish.
test_a_live_registration_is_not_refused if {
	count(violation) == 0 with input as {"tree": {"git-worktrees": {"linked": [{
		"id": "review",
		"present": true,
		"locked": false,
	}]}}}
}

# A LOCK IS AN ANSWER SOMEBODY ALREADY GAVE. Git's own documented case is a
# checkout on removable storage, so an absent directory under a lock is the
# declared state rather than a stranded row.
test_a_locked_registration_with_no_directory_is_not_refused if {
	count(violation) == 0 with input as {"tree": {"git-worktrees": {"linked": [{
		"id": "on-the-usb-stick",
		"present": false,
		"locked": true,
	}]}}}
}

# THE THIRD ANSWER. An empty list is the registry read and holding nothing, which
# is what every repository with only a main checkout looks like — by far the
# commonest input, and the one a gate must be silent over.
test_no_linked_worktrees_is_not_a_finding if {
	count(violation) == 0 with input as {"tree": {"git-worktrees": {"linked": []}}}
}

test_a_registry_that_could_not_be_read_is_refused if {
	some v in violation with input as {"tree": {"git-worktrees": null}}
	v.verdict == "worktree list unread"
}

# ONE REGISTRATION, ONE FINDING, and the mixed input is what proves the predicate
# discriminates rather than reporting the whole list. Three rows, one of them
# stranded.
test_only_the_stranded_row_is_reported if {
	found := violation with input as {"tree": {"git-worktrees": {"linked": [
		{"id": "alive", "present": true, "locked": false},
		{"id": "stranded", "present": false, "locked": false},
		{"id": "parked", "present": false, "locked": true},
	]}}}
	count(found) == 1
	some v in found
	v.subjects[0].artifact == "stranded"
}

# THE MUTATION FLIPS THE PRESENCE CONJUNCT, so the predicate refuses the LIVE
# registration and spares the stranded one. It discriminates because the declared
# case carries both arms in one input: a case asserting only "some finding" would
# pass under it, since the mutant still produces exactly one.
#MUTANT-SUITE crates/batten/tests/it/worktree_registration.rs
#MUTANT presence-conjunct-flipped|s@\tregistration.present == false@\tregistration.present == true@|a_live_worktree_is_not_a_finding_and_a_stranded_one_is
