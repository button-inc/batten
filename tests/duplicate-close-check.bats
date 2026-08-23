#!/usr/bin/env bats
# subject: mise-tasks/duplicate-close-check.sh
# CLOUD-829. A duplicate close decided in the same operation as its target's close.
#
# The discriminating fixture is the MEASURED PAIR, not an invented one: CLOUD-777
# marked Done and CLOUD-817 closed as a Duplicate of it, both stamped
# `2026-08-21T02:37:51.492Z`. Every other case differs from it in exactly one way,
# which is what makes a refusal attributable to the clause it came from.

setup() {
	GATE="$BATS_TEST_DIRNAME/../mise-tasks/duplicate-close-check.sh"
	BOARD="$BATS_TEST_TMPDIR/board.json"
	: >"$BOARD"
}

# row <id> <canceledAt> <completedAt> <duplicateOf>  — `-` for null/absent
row() {
	local id=$1 cancel=${2:--} complete=${3:--} dup=${4:--}
	jq -nc --arg id "$id" --arg c "$cancel" --arg d "$complete" --arg dup "$dup" '{
	  id: $id,
	  canceledAt: (if $c == "-" then null else $c end),
	  completedAt: (if $d == "-" then null else $d end),
	  relations: {blockedBy: [], blocks: [], relatedTo: [],
	              duplicateOf: (if $dup == "-" then null else {id: $dup} end)}
	}' >>"$BOARD"
}

check() { run bash -c "'$GATE' <'$BOARD'"; }

OP=2026-08-21T02:37:51.492Z

# --- the measured pair --------------------------------------------------------

@test "a duplicate close in the same operation as its target's close is refused" {
	row CLOUD-777 - "$OP" -
	row CLOUD-817 "$OP" - CLOUD-777
	check
	[ "$status" -eq 1 ]
	# BOTH KEYS NAMED. A refusal naming only the closed row would leave a reader
	# unable to find the decision that was taken alongside it.
	[[ "$output" == *"CLOUD-817 duplicate-closed-with-its-target"* ]]
	[[ "$output" == *"CLOUD-777"* ]]
}

@test "the refusal demands a decision rather than judging who was right" {
	# The gate cannot know which row was correct, and the message must not read as
	# though it does — that is the line between a gate and a judge (CLOUD-93).
	row CLOUD-777 - "$OP" -
	row CLOUD-817 "$OP" - CLOUD-777
	check
	[[ "$output" == *"does not know which row was right"* ]]
	[[ "$output" == *"TWO decisions taken as one"* ]]
}

# --- the other direction (CLOUD-418): the ordinary case must pass --------------

@test "a duplicate close whose target completed days earlier passes" {
	# THE CASE A TOO-WIDE WINDOW BREAKS, and the reason the window is a bound rather
	# than "the target is completed". Closing a row as a duplicate of work that
	# finished last week is the ordinary, correct shape.
	row CLOUD-777 - 2026-08-14T09:00:00.000Z -
	row CLOUD-817 "$OP" - CLOUD-777
	check
	[ "$status" -eq 0 ]
	[[ "$output" != *"duplicate-closed-with-its-target"* ]]
}

@test "a duplicate close whose target is not completed at all passes" {
	row CLOUD-777 - - -
	row CLOUD-817 "$OP" - CLOUD-777
	check
	[ "$status" -eq 0 ]
}

@test "a set with no duplicates at all passes" {
	row CLOUD-1 - - -
	row CLOUD-2 - - -
	check
	[ "$status" -eq 0 ]
	[[ "$output" == *"no duplicate close shares an operation"* ]]
}

@test "a close one second outside the window passes, which is the stated bound" {
	# Not an endorsement of the boundary — the honest limit the gate's own header
	# names. Pinned so that widening the window is a deliberate change with a case
	# to update rather than a silent one.
	row CLOUD-777 - 2026-08-21T02:37:52.000Z -
	row CLOUD-817 "$OP" - CLOUD-777
	check
	[ "$status" -eq 0 ]
}

# --- could not look, never clean ----------------------------------------------

@test "a set with no duplicateOf key anywhere is could not look" {
	# The anti-vacuity term: a caller who projected the relation away gets zero
	# duplicates and would otherwise get an unconditional pass over a field the gate
	# never saw. Set-keyed, because the property is of the piped set.
	jq -nc '{id: "CLOUD-1", canceledAt: null, completedAt: null, relations: {blockedBy: []}}' >"$BOARD"
	check
	[ "$status" -eq 2 ]
	[[ "$output" == *"unjudgeable-duplicateof"* ]]
	[[ "$output" != *"no duplicate close shares"* ]]
}

@test "an explicit null duplicateOf is data, not an unjudgeable payload" {
	# The other half of that split: `null` is the tracker saying "not a duplicate",
	# and judging it is correct. Only an ABSENT key is could-not-look.
	row CLOUD-1 - - -
	check
	[ "$status" -eq 0 ]
	[[ "$output" != *"unjudgeable"* ]]
}

@test "a duplicate whose target was not piped is unjudgeable, never clean" {
	# The caller chose the closure. A target outside it is a question nobody asked —
	# the same reading `graph-check` takes of an edge leaving the piped set.
	row CLOUD-817 "$OP" - CLOUD-777
	check
	[ "$status" -eq 2 ]
	[[ "$output" == *"unjudgeable-duplicate-target (CLOUD-777 not in the piped set)"* ]]
}

@test "a duplicate close carrying no canceledAt is unjudgeable, never clean" {
	row CLOUD-777 - "$OP" -
	row CLOUD-817 - - CLOUD-777
	check
	[ "$status" -eq 2 ]
	[[ "$output" == *"unjudgeable-close-time"* ]]
}

@test "could not look outranks a refusal, so a half-read set is never exit 1" {
	# Both at once: one pair really is a same-operation close, and a second row's
	# target was never piped. The set has not been judged, and saying "a violation
	# was found" would imply it had — CLOUD-251's ordering.
	row CLOUD-777 - "$OP" -
	row CLOUD-817 "$OP" - CLOUD-777
	row CLOUD-818 "$OP" - CLOUD-999
	check
	[ "$status" -eq 2 ]
}

@test "empty stdin is exit 2, never a verdict" {
	run bash -c "printf '' | '$GATE'"
	[ "$status" -eq 2 ]
}

@test "stdin that is not a payload set is exit 2" {
	run bash -c "printf 'not json' | '$GATE'"
	[ "$status" -eq 2 ]
}

# --- rule 4 -------------------------------------------------------------------

@test "the report carries no line of either body" {
	# Pointer-only, and here it is load-bearing beyond the usual reason: the
	# sentence that made one row contradict the other is the content this gate
	# exists to protect, so echoing it would put it in a log.
	jq -nc --arg op "$OP" '{
	  id: "CLOUD-777", canceledAt: null, completedAt: $op,
	  description: "the acceptance is satisfied vacuously and nobody noticed",
	  relations: {blockedBy: [], duplicateOf: null}
	}' >"$BOARD"
	jq -nc --arg op "$OP" '{
	  id: "CLOUD-817", canceledAt: $op, completedAt: null,
	  description: "CLOUD-777 passes vacuously, which is the whole finding",
	  relations: {blockedBy: [], duplicateOf: {id: "CLOUD-777"}}
	}' >>"$BOARD"
	check
	[ "$status" -eq 1 ]
	[[ "$output" != *"vacuously"* ]]
	[[ "$output" != *"nobody noticed"* ]]
}

@test "the report is byte-stable across runs" {
	row CLOUD-777 - "$OP" -
	row CLOUD-817 "$OP" - CLOUD-777
	row CLOUD-810 "$OP" - CLOUD-777
	check
	local first="$output"
	check
	[ "$output" = "$first" ]
}
