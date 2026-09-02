# METADATA
# description: |
#   A lap acts on ONE answer from its wait, never on both.
#
#   The wait in a landing lap is a race, and the race is the economy rather than
#   an implementation detail. Two questions are asked at once — *is this commit
#   green?* and *is this commit still landable?* — and whichever answers first
#   decides, with the loser's answer VOIDED. The moment the base advances, the
#   run in flight is already spend for a verdict nobody will read; the push the
#   next lap makes supersedes it through the forge's own cancel-in-progress, so
#   nothing has to cancel it by hand.
#
#   WHAT GOES WRONG IS NOT LOSING THE RACE, IT IS READING BOTH SIDES. A lap that
#   waits for both, or that takes whichever answer it happens to notice, still
#   lands green work most of the time — so every case over the happy path passes
#   while the property is gone. The failure is only visible in what the lap
#   RECORDED: two answers where the design allows one.
#
#   THE RACE STAYS OUTSIDE AND THE ENTITLEMENT IS HERE. Running two pollers and
#   taking the first is a loop, with no clock and no verdict in it. Which answer
#   a lap may act on is a decision, and it is this one. So a consumer whose
#   landing bot races three questions rather than two changes its own module and
#   this one does not have to know.
#
#   EVERY RECORD, NOT ONE NAMED RECORD, for the reason its sibling states: the
#   record's name is the consumer's, and a preset naming it would ship
#   non-negotiable rule 1's violation into every consumer's binary. The `wait`
#   KIND column narrows instead — a word about the practice, true of every
#   consumer whose lap races a green question against a staleness one.
#
#   FOUR COLUMNS EXACTLY, so a line of another shape is not read through a
#   shifted lens, and `-` is the could-not-look spelling rather than an absence.
#
#   THE BRACKETS ARE NOT STYLE: the schema file carries a hyphen, so the dotted
#   form is a parse error reported as `invalid schema reference`.
#   THIS BLOCK IS YAML AND MUST STAY THE LAST COMMENT BLOCK BEFORE `package`.
# schemas:
#   - input: schema["policy-input.schema"]
package batten.landing_loop

import rego.v1

rules contains "lap-waits-on-one-answer"

# TWO MUTATIONS ON ONE CONJUNCT, IN OPPOSITE DIRECTIONS, which is the pair rather
# than a duplicate. `loser-read` makes the predicate never fire, so a lap that
# read both answers is admitted and only the deny half catches it;
# `single-answer-unpriced` makes it fire on every wait, which only the
# anti-vacuity half catches. Refusing nothing and refusing everything are both
# non-gates and no single mutation reaches both.
#
# EVERY NAME IS PREFIXED `wait_`, and that is not style — see the sibling
# module's header. A preset's modules share one `package`, so `answers`,
# `latest`, `refused`, `recorded/1`, `replays`, `last_replay` and
# `replay_conflicted` are all already bound, and re-binding one does not shadow:
# regorus answers it with `node_idx out of bounds`, which reads as an engine
# fault rather than the authoring mistake it is.
#MUTANT-SUITE crates/batten/tests/it/policy_presets.rs
#MUTANT loser-read|s@^\tcount(wait_answered) > 1$@\tfalse@|the_landing_loop_preset_refuses_a_lap_that_read_both_answers
#MUTANT single-answer-unpriced|s@^\tcount(wait_answered) > 1$@\ttrue@|the_landing_loop_preset_refuses_a_lap_that_read_both_answers

# Every wait outcome this lap recorded, in write order.
#
# A COMPREHENSION RATHER THAN A SET, and here that is load-bearing twice over
# rather than once: a set de-duplicates, so a lap that recorded the SAME arm
# twice would collapse to one member and read as a lap that answered once —
# which is the exact reading this module exists to refuse.
#
# The `is_object` guard is first because `some .. in null` is a hard evaluation
# FAULT in Rego, and a fault takes the whole bundle down rather than missing
# quietly.
wait_answers := [answer |
	is_object(input.tree.records)
	line := input.tree.records[_][_]
	columns := split(line, " ")
	count(columns) == 4
	columns[0] == "wait"
	answer := {
		"arm": columns[1],
		"verdict": columns[2],
		"sha": columns[3],
	}
]

# The arms that actually carried an answer.
#
# `-` IS COULD-NOT-LOOK AND IS NOT AN ANSWER, which is what keeps a lap whose
# poller could not reach the forge from reading as a lap that raced and won. A
# reading about the environment is not a reading about the lap.
#
# A SET HERE, DELIBERATELY, and it is the one place de-duplication is right: the
# question is *how many distinct arms answered*, so the same arm reporting twice
# — a retry, a re-read — is still one arm having answered. Counting the LINES
# there would refuse a lap that merely looked twice.
wait_answered contains arm if {
	some answer in wait_answers
	answer.verdict != "-"
	arm := answer.arm
}

# Refused: more than one arm answered, so the lap has two verdicts and the
# design gives it one.
#
# Pointer-only (non-negotiable rule 4): the arms that answered and the commit
# they answered about, never a check's log body and never the forge's payload.
# The arms are a closed vocabulary the consumer's own recorder writes, so naming
# them carries no content.
violation contains {
	"rule": "lap-waits-on-one-answer",
	"verdict": "wait read both",
	"subjects": [{"count": count(wait_answered)}, {"artifact": wait_subject}],
} if {
	count(wait_answered) > 1
}

# The commit the wait was about, where every answer agrees on one.
#
# UNDEFINED IS NOT AN OPTION HERE — the violation above reads this — so it falls
# back to the could-not-look token rather than leaving the rule unresolvable. A
# lap whose arms disagree about which commit they judged is a different defect
# and not this module's, so it reports `-` rather than picking one.
wait_subject := sha if {
	shas := {answer.sha | some answer in wait_answers; answer.verdict != "-"}
	count(shas) == 1
	some sha in shas
} else := "-"

# --- the load-time tier ------------------------------------------------------
#
# These pin the PREDICATE. `crates/batten/tests/it/policy_presets.rs` is the tier
# that proves the ENGINE builds what it reads, with the empty vocabulary, and it
# is where the declared mutations are scored.

wait_record(lines) := {"tree": {"records": {"lap": lines}}}

test_two_arms_answering_is_refused if {
	some v in violation with input as wait_record([
		"wait green success abc1234",
		"wait stale moved abc1234",
	])
	v.verdict == "wait read both"
}

test_the_refusal_counts_the_arms_and_names_the_commit if {
	some v in violation with input as wait_record([
		"wait green success abc1234",
		"wait stale moved abc1234",
	])
	v.subjects[0].count == 2
	v.subjects[1].artifact == "abc1234"
}

# THE ANTI-VACUITY MIRROR. Without it every case above is satisfied by a module
# that refuses every wait, which is not a gate (CLOUD-418).
test_one_arm_answering_is_clean if {
	count(violation) == 0 with input as wait_record(["wait green success abc1234"])
}

# THE LOSER IS VOIDED, AND THAT IS WHAT THE RECORD SHOWS. The lap raced, one arm
# answered and the other was abandoned unread — which is the design working, so
# it must not be refused.
test_a_voided_loser_is_clean if {
	count(violation) == 0 with input as wait_record([
		"wait green success abc1234",
		"wait stale - abc1234",
	])
}

# LOOKING TWICE IS NOT ANSWERING TWICE. One arm that re-read — a retry, a second
# poll — is still one arm, so counting LINES rather than arms would refuse a lap
# that did nothing wrong.
test_one_arm_answering_twice_is_still_one_answer if {
	count(violation) == 0 with input as wait_record([
		"wait green success abc1234",
		"wait green success abc1234",
	])
}

# A LAP THAT HAS NOT WAITED YET has nothing to have read twice.
test_no_wait_line_at_all_is_clean if {
	count(violation) == 0 with input as wait_record([])
}

# NEITHER ARM COULD LOOK, which is a statement about the forge rather than about
# the lap, and allows.
test_neither_arm_answering_is_clean if {
	count(violation) == 0 with input as wait_record([
		"wait green - abc1234",
		"wait stale - abc1234",
	])
}

# A line of another shape is not read through this lens.
test_a_five_column_wait_line_is_skipped if {
	count(violation) == 0 with input as wait_record([
		"wait green success abc1234 extra",
		"wait stale moved abc1234 extra",
	])
}

# Another practice's record is not this one's — the store holds every recorder's
# lines, and the sibling reading replays writes four columns to it too.
test_another_kinds_line_is_skipped if {
	count(violation) == 0 with input as wait_record([
		"rebase green success abc1234",
		"rebase stale moved abc1234",
	])
}

# COULD-NOT-LOOK OVER THE WHOLE STORE, and without the `is_object` guard this
# case does not merely fail — it FAULTS, taking the whole bundle with it.
test_an_absent_record_store_does_not_fault if {
	count(violation) == 0 with input as {"tree": {"records": null}}
}
