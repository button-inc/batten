# METADATA
# description: |
#   A lap whose replay conflicted does not continue.
#
#   Landing is a loop and almost every step of it is automatable: fetch, replay,
#   verify, push, wait, fast-forward, and a refusal starts the next lap by
#   itself. Exactly ONE step needs a person, and it is this one. A replay that
#   conflicts is two authors having changed the same lines, and choosing between
#   them is a judgement no gate makes — which is why the whole loop is built to
#   keep this step SMALL rather than to remove it: frequent laps mean each
#   conflict arrives as one resolvable increment, and batching them is how a
#   branch diverges until it cannot land at all.
#
#   SO THE FAILURE THIS REFUSES IS NOT "A CONFLICT HAPPENED". Conflicts are
#   expected and are the mechanism working. What it refuses is a lap that
#   conflicted and CARRIED ON — pushing, spending a matrix, or fast-forwarding a
#   head whose replay never completed. A merge strategy makes that outcome
#   reachable and reports success while doing it, so the wrong behaviour here is
#   the one an implementer reaches for to make the loop "always succeed".
#
#   THE REPLAY AND THE LOOP STAY OUTSIDE. Only the decision is here: given what
#   the lap recorded, may it continue? Whoever drives the loop performs the
#   replay, records its outcome and decides what to do about a refusal, and this
#   module needs no clock, no working tree and no remote to answer.
#
#   EVERY RECORD, NOT ONE NAMED RECORD. The record's name is the consumer's, so a
#   preset naming it would ship non-negotiable rule 1's violation into every
#   consumer's binary. The `rebase` KIND column is what narrows instead — a word
#   about the practice, true of every consumer whose lap replays onto a moving
#   base.
#
#   FOUR COLUMNS EXACTLY, which keeps a line of another shape from being read
#   through a shifted lens: a record re-columned mid-branch leaves both shapes in
#   one file, and a five-column line would otherwise answer as if it were this
#   one.
#
#   `-` IS THE COULD-NOT-LOOK SPELLING and arrives as an ordinary token. It is
#   never equal to `conflicted`, so a column the boundary could not resolve
#   allows by construction rather than by a clause somebody remembered to write.
#
#   THE BRACKETS ARE NOT STYLE: the schema file carries a hyphen, so the dotted
#   form is a parse error reported as `invalid schema reference`.
#   THIS BLOCK IS YAML AND MUST STAY THE LAST COMMENT BLOCK BEFORE `package`.
# schemas:
#   - input: schema["policy-input.schema"]
package batten.landing_loop

import rego.v1

rules contains "rebase-conflict-stops-the-lap"

# The compiled tier is the one that runs this the way a consumer gets it, with
# the empty vocabulary, and CLOUD-1267 makes it the DECLARED suite rather than a
# `tests/<gate>.bats` no preset may have.
#
# TWO MUTATIONS ON ONE LINE, IN OPPOSITE DIRECTIONS, and that is the pair rather
# than a duplicate. `conflict-unread` makes the predicate never fire, which a
# deny case catches; `clean-lap-unpriced` makes it always fire, which only the
# anti-vacuity half catches. A module refusing everything and a module refusing
# nothing are both non-gates, and one mutation cannot reach both.
#MUTANT-SUITE crates/batten/tests/it/policy_presets.rs
#MUTANT conflict-unread|s@^\tlast_replay.verdict == "conflicted"$@\tfalse@|the_landing_loop_preset_stops_a_conflicted_lap_and_is_green_by_turns
#MUTANT clean-lap-unpriced|s@^\tlast_replay.verdict == "conflicted"$@\ttrue@|the_landing_loop_preset_stops_a_conflicted_lap_and_is_green_by_turns

# EVERY NAME HERE IS PREFIXED, AND THAT IS NOT STYLE. A preset's modules all
# declare `package batten.landing_loop`, so the four files share ONE namespace:
# the sibling reading the lease already binds `answers`, `latest` and `refused`,
# and the one reading the forge binds a `recorded/1` test helper. Re-binding any
# of them does not shadow, it COLLIDES. Measured while landing this module — all
# four obvious names were taken, and regorus did not report a redefinition: it
# panicked at
# `node_idx 114 out of bounds for module 0`, which reads as an engine fault
# rather than as the authoring mistake it is. Prefix, and the next module added
# to this preset can too.
#
# Every replay outcome this branch's lap recorded, in write order.
#
# A COMPREHENSION RATHER THAN A SET, for the reason the lease module records: a
# Rego set is unordered and de-duplicating, so "the last line" is not recoverable
# from one and two identical outcomes collapse into a single member. Object
# iteration is key-sorted and a comprehension preserves array order, so the
# reading is deterministic and house-style §6's byte-stability survives.
#
# THE `is_object` GUARD IS LOAD-BEARING RATHER THAN DEFENSIVE: the key is `null`
# when no row declared a recorder, `some .. in null` is a hard evaluation FAULT
# in Rego, and a fault takes the whole bundle down instead of missing quietly. It
# is written INLINE rather than as a defaulted helper rule, because that spelling
# made regorus panic outright.
replays := [answer |
	is_object(input.tree.records)
	line := input.tree.records[_][_]
	columns := split(line, " ")
	count(columns) == 4
	columns[0] == "rebase"
	answer := {
		"verdict": columns[1],
		"commit": columns[2],
		"path": columns[3],
	}
]

# The outcome of the lap standing now.
#
# THE LAST LINE, BECAUSE THE RECORD IS A HISTORY. A branch that has lapped before
# carries the earlier laps above this one, and a replay that conflicted on lap
# one and replayed cleanly on lap two has been resolved — reading the whole list
# would let that resolved conflict refuse forever. Undefined where no `rebase`
# line exists at all, which allows: a lap that has not replayed yet has nothing
# to have conflicted over.
last_replay := answer if {
	count(replays) > 0
	answer := replays[count(replays) - 1]
}

replay_conflicted if {
	last_replay.verdict == "conflicted"
}

# Refused, naming the path a reader opens first.
#
# THE FIRST PATH-BEARING SUBJECT IS THE FINDING'S OWN POINTER, so the order is a
# statement about where to look: the conflicted path leads, and the commit that
# would not replay follows it as an `artifact` rather than as the pointer. Both
# are identifiers the caller already holds. Pointer-only, non-negotiable rule 4:
# never a hunk, never a conflict marker, never a byte of either side's content —
# which is the whole of what a conflict actually consists of.
violation contains {
	"rule": "rebase-conflict-stops-the-lap",
	"verdict": "replay halt conflict",
	"subjects": [{"path": last_replay.path}, {"artifact": last_replay.commit}],
} if {
	replay_conflicted
	last_replay.path != "-"
}

# Refused with no path to name.
#
# A SEPARATE ARM RATHER THAN AN OPTIONAL KEY, because rule 4's subjects are
# tagged pointers and a class with nothing to point at OMITS the key rather than
# inventing one — emitting `{"path": "-"}` would hand a reader a path that does
# not exist. The two arms are mutually exclusive on the same column, so a
# conflicted lap yields exactly one finding either way.
violation contains {
	"rule": "rebase-conflict-stops-the-lap",
	"verdict": "replay halt conflict",
	"subjects": [{"artifact": last_replay.commit}],
} if {
	replay_conflicted
	last_replay.path == "-"
}

# --- the load-time tier ------------------------------------------------------
#
# These pin the PREDICATE. They cannot pin that the ENGINE builds a record the
# lap actually wrote — a `with input as` case fabricates the very shape the
# engine may be unable to produce, and here it would fabricate the COLUMN LAYOUT
# this module turns on. `crates/batten/tests/it/policy_presets.rs` is the tier
# that runs this the way a consumer gets it, with the empty vocabulary.

replay_record(lines) := {"tree": {"records": {"lap": lines}}}

test_a_conflicted_replay_is_refused if {
	some v in violation with input as replay_record(["rebase conflicted abc1234 shared.txt"])
	v.verdict == "replay halt conflict"
}

test_the_refusal_points_at_the_conflicted_path if {
	some v in violation with input as replay_record(["rebase conflicted abc1234 shared.txt"])
	v.subjects[0].path == "shared.txt"
	v.subjects[1].artifact == "abc1234"
}

# NO PATH TO NAME still refuses, and omits the key rather than pointing at `-`.
test_a_conflict_with_no_path_omits_the_pointer if {
	some v in violation with input as replay_record(["rebase conflicted abc1234 -"])
	count(v.subjects) == 1
	v.subjects[0].artifact == "abc1234"
}

# THE ANTI-VACUITY MIRROR. Without it every case above is satisfied by a module
# that refuses unconditionally, which is not a gate (CLOUD-418).
test_a_clean_replay_is_clean if {
	count(violation) == 0 with input as replay_record(["rebase replayed abc1234 -"])
}

# AN ALREADY-CURRENT BRANCH REPLAYED NOTHING, so there was nothing to conflict.
test_an_already_current_branch_is_clean if {
	count(violation) == 0 with input as replay_record(["rebase current abc1234 -"])
}

# A CONFLICT THE NEXT LAP RESOLVED IS RESOLVED. Reading the whole history rather
# than its last line would refuse this branch forever.
test_a_conflict_a_later_lap_resolved_is_clean if {
	count(violation) == 0 with input as replay_record([
		"rebase conflicted abc1234 shared.txt",
		"rebase replayed def5678 -",
	])
}

# COULD-NOT-LOOK ALLOWS, and it reaches here as an ordinary token rather than
# through a clause of its own.
test_an_unresolved_verdict_is_clean if {
	count(violation) == 0 with input as replay_record(["rebase - - -"])
}

# A LINE OF ANOTHER SHAPE IS NOT READ THROUGH THIS LENS.
test_a_five_column_line_is_skipped if {
	count(violation) == 0 with input as replay_record(["rebase conflicted abc1234 shared.txt extra"])
}

# ANOTHER PRACTICE'S RECORD IS NOT THIS ONE'S, which is what the kind column
# buys — the lease module reads four columns off the same store.
test_another_kinds_line_is_skipped if {
	count(violation) == 0 with input as replay_record(["lease conflicted abc1234 shared.txt"])
}

# A BRANCH THAT HAS NOT REPLAYED YET has nothing to have conflicted over.
test_no_rebase_line_at_all_is_clean if {
	count(violation) == 0 with input as replay_record([])
}

# COULD-NOT-LOOK OVER THE WHOLE STORE, and without the `is_object` guard this
# case does not merely fail — it FAULTS, taking the whole bundle with it.
test_an_absent_record_store_does_not_fault if {
	count(violation) == 0 with input as {"tree": {"records": null}}
}
