# An effective bound on a suspected feedback path (CLOUD-1344).
#
# THE HONEST CLAIM IS NARROWER THAN "LOOP DETECTION", and the header says so
# rather than letting a reader infer more. Termination is undecidable, and every
# quantity this engine can see is a monotonically growing count — there is no
# observable DECREASING measure here, so a ranking function buys nothing that
# threshold counting does not. What the literature does buy is the SHAPE of the
# declaration: disjunctive termination is why this is a SET of extractions with a
# set of thresholds rather than one number. These supply an effective bound on a
# SUSPECTED feedback path. They do not detect non-termination.
#
# THE MEASURED DEFECT is a feedback path reaching a costly action without an
# effective bound — IAL-Scan reports 91.9% precision over 68 such failures across
# 6,549 projects, and this repository has its own: CLOUD-1337's eleven duplicate
# watchers running 9h35m, found by a human reading `ps`, and CLOUD-821's 490
# self-manufactured wake-ups in one session of which 2 changed a decision.
#
# `agent-turn-run` IS THE FIRST MEMBER AND DELIBERATELY THE SIMPLEST: a trailing
# run of assistant turns carrying no tool call. It maps to OpenHands' monologue
# detector at 3+ consecutive messages. It needs no hashing at all — it reduces
# `Event::Turn`, which is already typed — so the fingerprinting argument belongs
# to the next row rather than this one.
#
# ADJACENCY IS WHAT DOES THE FALSE-POSITIVE WORK. A tool call breaks the run, so
# a session thinking between actions is not a session that has stopped acting;
# only three turns in a row with nothing done between them reach this. That is
# also what makes it non-monotonic, which is the property a later promotion to
# `deny` depends on: the run clears itself the moment the session acts, so a
# refusal here can never wedge a session the way a whole-stream total would.
#
# COULD-NOT-LOOK IS DECIDED IN THE ENGINE, NOT HERE. A host that records no turn
# boundaries answers nothing for this extraction and the key is absent, which Rego
# reads as does-not-hold. A per-module conjunct asking whether the host records
# turns would be a dead gate on every harness but the one its author tested, which
# is why `is_object` is the only guard this module carries.
#
# IT SHIPS AT `warn`. CLOUD-894 owns the declared firing-rate ceiling every
# predicate in this family must clear before promotion, and CLOUD-1352 makes a
# measured rate over this repository's own history a hard precondition. A
# `mediated_call` row at `deny` refuses every subsequent tool call once it fires,
# and no admission can clear it — `batten override request` and `spend` are
# themselves mediated calls — so promotion is a step taken once, on purpose, with
# a measurement behind it.
#MUTANT-SUITE crates/batten/tests/it/repetition.rs
# THE BRACKETS ARE ESCAPED, and were not (CLOUD-1445). `sed` read
# `["agent-turn-run"]` as a bracket expression — one character from the set those
# letters spell — so the pattern matched nothing, the staged copy was
# byte-identical, and the first sweep reported `inert-mutation`. The row below it
# names no bracket, applies, and was not reported: that pair is what located the
# cause in the escaping rather than in the predicate.
#MUTANT run-may-go-unbounded|s@^	input.facts.extracted\["agent-turn-run"\] >= threshold$@	false@|a_monologue_run_is_reported
#MUTANT threshold-may-slip|s@^threshold := 3$@threshold := 2@|two_turns_in_a_row_is_not_a_run

# METADATA
# description: |
#   Bound to the MEDIATED CALL: this row is `scope = "mediated_call"`, so it
#   reads `input.call` and `input.facts` and never the tree document.
#   THIS BLOCK IS YAML AND MUST STAY THE LAST COMMENT BLOCK BEFORE `package`.
# schemas:
#   - input: schema["policy-call.schema"]
package batten.repetition_without_progress

import rego.v1

rules contains "agent-turn-run"

# OpenHands' monologue threshold. Adopted rather than derived: CLOUD-1352 makes a
# replay over this repository's own history the precondition for promoting any
# member of this family, and until that exists this is the prior art's number
# rather than this consumer's. Said plainly so a later reader does not mistake it
# for a measurement.
threshold := 3

# A REAL COUNT, over a declared threshold. `is_object` is the null guard for the
# whole-transcript could-not-look states; the PER-EXTRACTION one needs no guard
# here, because an extraction this host cannot answer is absent from the map and
# an absent key is undefined, which does not hold.
violation contains {
	"rule": "agent-turn-run",
	"verdict": "turn run loose",
	"subjects": [{"count": input.facts.extracted["agent-turn-run"]}],
} if {
	is_object(input.facts.extracted)
	input.facts.extracted["agent-turn-run"] >= threshold
}

# The predicate's own tests. The SILENT cases carry the weight: this is a
# refusal, so a module firing on everything would satisfy the deny case while
# deciding nothing.

session(extracted) := {"call": {"command": "", "run-in-background": null}, "facts": {"extracted": extracted}}

test_a_monologue_run_is_reported if {
	some v in violation with input as session({"agent-turn-run": 3})
	v.verdict == "turn run loose"
}

# THE COUNT IS THE POINTER, never a span of session text — rule 4 decided in the
# finding's shape rather than by a filter downstream.
test_the_finding_carries_a_count_and_nothing_else if {
	some v in violation with input as session({"agent-turn-run": 7})
	v.subjects == [{"count": 7}]
}

# ONE BELOW THE THRESHOLD IS CLEAN. An off-by-one here moves the whole population
# the rule fires on.
test_two_turns_in_a_row_is_not_a_run if {
	count(violation) == 0 with input as session({"agent-turn-run": 2})
}

# THE ARM THAT MAKES ADJACENCY WORTH HAVING: a session that acts between turns
# has a trailing run of one however long it runs.
test_a_session_that_acts_between_turns_is_clean if {
	count(violation) == 0 with input as session({"agent-turn-run": 1})
}

# COULD NOT LOOK IS NOT INNOCENCE, and it is not guilt either.
test_no_transcript_is_not_a_clean_session if {
	count(violation) == 0 with input as session(null)
}

# THE PER-EXTRACTION STATE, which is this row's own (CLOUD-1344). A host that
# records other events but no turn boundaries answers nothing for this member, so
# the key is ABSENT rather than zero — and an absent key is undefined, which does
# not hold. A zero here would be a real count meaning the extractor ran.
test_a_host_that_records_no_turns_answers_could_not_look if {
	count(violation) == 0 with input as session({"tool-calls": 200})
}

# A COMPOUND COMMAND REACHES THE SAME VERDICT, and the case exists even though
# this predicate never reads the command line. CLOUD-857 measured a module that
# anchored on `input.call.command` denying `git push --force origin main` while
# allowing `cd /tmp && git push --force origin main`, with a green suite over it —
# so `policy test` refuses a mediated-call suite whose every case passes a bare
# command. Here it is a STANDING guarantee: the verdict is a function of the fact
# alone, and this is what would go red if a later revision started reading the
# command and anchored it wrongly.
test_a_compound_command_reaches_the_same_verdict if {
	some v in violation with input as {
		"call": {"command": "cd /tmp && mise run land", "run-in-background": null},
		"facts": {"extracted": {"agent-turn-run": 5}},
	}
	v.verdict == "turn run loose"
}
