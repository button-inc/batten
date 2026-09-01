# METADATA
# description: |
#   Exactly one branch at a time spends a matrix; a lapsed lease authorises nobody.
#
#   A landing lease is how a fleet stops two branches buying overlapping CI for a
#   trunk only one of them can fast-forward onto. The loop that mints, swaps and
#   releases the lease lives outside the engine and stays there; this is the one
#   READ the loop performs before it spends anything.
#
#   THE FAIL-OPEN ASYMMETRY IS THE LOAD-BEARING HALF, AND IT IS CONSERVED HERE BY
#   THE MECHANISM RATHER THAN BY PROSE. The bash this replaces says it outright:
#   "a lease it cannot read stops EVERY job in the fleet, where waving one matrix
#   through costs one matrix." So every could-not-look on this page ALLOWS — an
#   absent record, an unparsed line, a verdict column the boundary could not
#   resolve, a clone with no branch. A port that quietly fails closed has
#   laundered a stop-the-world into a gate, which is the failure mode CLOUD-1269
#   names for this predicate specifically.
#
#   THE FRESHNESS COMPARISON IS THE BOUNDARY'S, NEVER THIS MODULE'S (CLOUD-1170,
#   CLOUD-1280). A lease expires, so deciding it needs a clock — and the engine
#   reads none, on either surface. What reaches Rego is a RESOLVED TOKEN: the
#   producer grades the lease with its own clock and reports the grade as an exit
#   status, the consumer's `[[recorder]]` maps that status to a word, and this
#   module compares words. `Rule::max_age` is the landed precedent — the
#   comparison happens where the subject is already being read — and the payoff is
#   that two evaluations over one tree cannot differ, which is byte-stability
#   obtained rather than asserted.
#
#   AN UNMAPPED STATUS IS COULD-NOT-LOOK, AND THAT IS WHERE THE ASYMMETRY IS
#   ACTUALLY ENFORCED. A producer that grades the lease may well fail CLOSED on an
#   unreachable remote, because a human reading a status wants to know it could
#   not look. The consumer's `status` table is what restores the open direction:
#   it maps the answering exit codes and leaves the could-not-look one unmapped,
#   the column records could-not-look, and the clause below does not hold.
#
#   NAMES NO BRANCH, NO REMOTE, NO PROGRAM AND NO RECORD (non-negotiable rule 1).
#   The record's own name is the consumer's, so this cannot read it by name and
#   does not try: it selects on the generic `lease` KIND every line of this shape
#   carries, which is a word about the practice rather than about a repository.
#
#   THE BRACKETS ARE NOT STYLE: the schema file carries a hyphen, so the dotted
#   form is a parse error reported as `invalid schema reference`.
#   THIS BLOCK IS YAML AND MUST STAY THE LAST COMMENT BLOCK BEFORE `package`.
# schemas:
#   - input: schema["policy-input.schema"]
package batten.landing_loop

import rego.v1

rules contains "lease-authorises-the-branch"

# The lease answers this branch wrote, IN WRITE ORDER.
#
# AN ARRAY COMPREHENSION RATHER THAN A `contains` SET, and the difference is a
# defect this module had first. A Rego set is unordered and de-duplicating, so
# "the last line" is not recoverable from one and two identical gradings collapse
# into one — which would silently turn the history this predicate reads into a
# bag. The comprehension preserves array order, and object iteration is key-sorted,
# so the reading is deterministic and §6's byte-stability survives.
#
# EVERY RECORD, NOT ONE NAMED RECORD. The record's name is the consumer's, so a
# preset naming it would be rule 1's violation shipped into every consumer's
# binary. The `lease` KIND column is what narrows instead — a word about the
# practice, true of every consumer that keeps a landing lease.
#
# FOUR COLUMNS EXACTLY, and the length test is what keeps a line of another shape
# from being read through a shifted lens: a record whose row was re-columned
# mid-branch leaves both shapes in the same file, and a FIVE-column line would
# otherwise answer as if it were this one.
#
# `-` IS THE COULD-NOT-LOOK SPELLING and reaches here as an ordinary token. It is
# never equal to anything the refusal below turns on, which is how a column the
# boundary could not resolve allows by construction rather than by a clause
# somebody remembered to write.
#
# THE `is_object` GUARD IS LOAD-BEARING RATHER THAN DEFENSIVE: the key is `null`
# when no row declared a recorder, and it is the FIRST statement so the walk below
# is never reached on one. It is written INLINE rather than as a defaulted helper
# rule — that spelling made regorus panic outright (`node_idx out of bounds`),
# which is a worse failure than the one being guarded against, since it takes the
# whole bundle down at load.
answers := [answer |
	is_object(input.tree.records)
	line := input.tree.records[_][_]
	columns := split(line, " ")
	count(columns) == 4
	columns[0] == "lease"
	answer := {
		"verdict": columns[1],
		"successor": columns[2],
		"branch": columns[3],
	}
]

# The lease this branch is standing under, where there is one to read.
#
# THE LAST LINE, BECAUSE THE RECORD IS A HISTORY. `recorder_records` returns every
# line in write order and never truncates, so a branch that has landed before
# carries yesterday's grade above today's. Reading the whole list would let a
# stale `held-elsewhere` refuse forever; reading the last one answers as of the
# most recent write, which is the bound this predicate has and states rather than
# hides. Undefined where there is no lease line at all, which allows.
latest := answer if {
	count(answers) > 0
	answer := answers[count(answers) - 1]
}

# Refused: the lease is live, it grades this clone as not the holder, and no
# reservation names this branch behind the holder.
#
# THE SUCCESSOR CLAUSE IS NOT OPTIONAL AND IT IS THE REASON THIS MODULE NEEDED A
# BRANCH PRIMITIVE AT ALL (CLOUD-369). A branch that reserved the slot behind the
# holder is buying the matrix that overlaps the holder's merge, so refusing it
# would cancel the very run the reservation exists to start — and the queue would
# be cold again with the mechanism intact and useless. A port omitting this clause
# denies where the bash allows, on the one row that costs a fleet its pipelining.
#
# `!=` RATHER THAN A NEGATED EQUALITY, so a `successor` of `-` — could-not-look,
# or simply no reservation — reads as *not this branch* and the refusal stands.
# That is the correct direction here and only here: the lease is already known
# live and known to name someone else, so the fail-open question was answered two
# clauses up. Reading an absent reservation as *possibly mine* would let every
# branch in the fleet spend on a lease none of them holds.
refused if {
	latest.verdict == "held-elsewhere"
	latest.branch != "-"
	latest.successor != latest.branch
}

# Pointer-only (non-negotiable rule 4): the branch that was REFUSED, which is a
# ref name the caller could read for itself. Never the lease body, never an
# expiry, and never a holder id — a holder id is minted per clone and means
# nothing to the thing spending the money, which is the whole reason the lease
# grades a BRANCH.
#
# THE HOLDER'S OWN BRANCH IS NOT AVAILABLE HERE AND IS NOT FAKED. The producer
# reports it only in the prose line a human reads, and parsing that would turn a
# message into an interface — the exact coupling the producer's own `peek` verb
# exists to avoid. So the pointer names the subject of the refusal rather than its
# cause, and a reader wanting the holder asks the producer.
violation contains {
	"rule": "lease-authorises-the-branch",
	"verdict": "lease grant other",
	"subjects": [{"artifact": latest.branch}],
} if {
	refused
}

# --- the load-time tier ------------------------------------------------------
#
# These pin the PREDICATE. They cannot pin that the ENGINE runs the producer, maps
# its status and writes the line — a `with input as` case fabricates the very
# shape the engine may be unable to produce, and here it would fabricate the GRADE
# the whole predicate turns on. `crates/batten/tests/it/policy_presets.rs` is the
# tier that runs this the way a consumer gets it, with the empty vocabulary.

#
# THE RECORD NAME IS DELIBERATELY ARBITRARY in every case below: this predicate
# must not read one by name, so a fixture naming a plausible one would let a
# module that DOES read it by name pass here.
#
# AND THE HELPER'S OWN NAME IS NOT `recorded`, WHICH IS NOT A STYLE CHOICE. A
# preset is several FILES in ONE package, so every rule and function here shares
# a namespace with its siblings — `graded-head-is-not-regraded.rego` already
# defines `recorded`, and defining a second one with a different body broke
# BOTH files' suites at once, including three cases in a module this change
# never touched. The failure reads as eleven unrelated test failures rather than
# as a collision, which is what makes it worth naming here.
lease_line(line) := {"tree": {"records": {"any-record-name": [line]}}}

test_a_live_lease_naming_another_branch_is_refused if {
	some v in violation with input as lease_line("lease held-elsewhere - mine")
	v.verdict == "lease grant other"
}

# THE ANTI-VACUITY MIRROR. Without it every case here is satisfied by a module
# that refuses unconditionally, which is not a gate (CLOUD-418).
test_a_lease_that_authorises_this_branch_is_clean if {
	count(violation) == 0 with input as lease_line("lease authorised - mine")
}

# THE THIRD CASE THE ASYMMETRY NEEDS, and it must be distinguishable from both of
# the two above. An unmapped exit status records `-`, which equals neither verdict
# token, so the refusal cannot hold — could-not-look ALLOWS.
test_a_lease_that_could_not_be_read_allows if {
	count(violation) == 0 with input as lease_line("lease - - mine")
}

# AN EXPIRED OR RELEASED LEASE IS AUTHORISED, NOT REFUSED, and this is the case
# the whole freshness mechanism exists for: the producer resolved it with its own
# clock and reported it as the authorising status, so no clock is needed here.
test_a_lapsed_lease_authorises_this_branch if {
	count(violation) == 0 with input as lease_line("lease authorised - mine")
}

# THE ADMITTED SUCCESSOR (CLOUD-369) — a live lease held elsewhere that has
# reserved the slot for THIS branch allows. Without the branch primitive this case
# cannot be written at all, and a module without it denies here.
test_a_reserved_successor_may_spend if {
	count(violation) == 0 with input as lease_line("lease held-elsewhere mine mine")
}

# A RESERVATION FOR SOMEBODY ELSE IS NOT THIS BRANCH'S, which is what stops the
# clause above from being satisfied by the mere presence of any reservation.
test_a_reservation_for_another_branch_does_not_admit_this_one if {
	some v in violation with input as lease_line("lease held-elsewhere theirs mine")
	v.rule == "lease-authorises-the-branch"
}

# A CLONE WITH NO BRANCH CANNOT BE COMPARED, so it allows. A detached HEAD is a
# state rather than an error, and the branch column records could-not-look.
test_a_clone_with_no_branch_allows if {
	count(violation) == 0 with input as lease_line("lease held-elsewhere - -")
}

# THE HISTORY, AND THE READING THAT MAKES IT SAFE. Yesterday's refusal sits above
# today's authorisation in the same file; a module reading the whole set refuses
# forever, and this case is what holds the last-line reading.
test_a_stale_refusal_does_not_outlive_its_lease if {
	count(violation) == 0 with input as {"tree": {"records": {"any-record-name": [
		"lease held-elsewhere - mine",
		"lease authorised - mine",
	]}}}
}

# A LINE OF ANOTHER SHAPE IS NOT A LEASE. The record store holds every recorder's
# lines, so a module selecting on position alone would read an unrelated row's
# columns through this lens.
test_another_recorders_line_is_not_read_as_a_lease if {
	count(violation) == 0 with input as lease_line("filed CLOUD-1 ready mine")
}

# COULD-NOT-LOOK, and without the `is_object` guard this case does not merely
# fail — it faults, taking the whole bundle with it.
test_could_not_look_does_not_fault if {
	count(violation) == 0 with input as {"tree": {"records": null}}
}
