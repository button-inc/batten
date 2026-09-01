# METADATA
# description: |
#   The successor shape for `finding-sink-check`'s question, and the
#   demonstration CLOUD-1172 owes.
#
#   THE PROGRAM THIS REPLACES reads the transcript to decide whether a finding
#   reached a durable sink. It could not migrate, because
#   `.claude/rules/policy-modules.md` is explicit that `input.call.transcript` is
#   the PATH and never a byte of the session — and the fact that would carry the
#   rest did not exist. `input.facts.extracted` is that fact, and it is
#   deliberately not the transcript.
#
#   WHAT REACHES THIS MODULE IS A COUNT, AND THE TYPE IS THE GUARANTEE. The
#   extractor set is closed and every member resolves to an integer over typed
#   events — a hook run's exit code, a result's own `is_error` flag — so no span
#   of session text can appear here even if this module asked for one. A
#   transcript holds every command, every file body and every prompt the session
#   touched, which is why rule 4 is decided in the fact's TYPE rather than in this
#   file's discipline.
#
#   THE PREDICATE IS THIS CONSUMER'S. That a turn ending with recorded refusals
#   still outstanding is worth flagging is this repository's judgement, and the
#   threshold is its own; the engine supplies the count.
#
#   COULD-NOT-LOOK IS THE COMMON CASE, NOT THE EDGE ONE (CLOUD-388: transcripts
#   die with their container). `null` covers four states — no transcript on the
#   envelope, a host that keeps none, one that would not parse, and nobody having
#   declared an extractor — and every one of them is DIFFERENT from an extractor
#   that ran and counted zero. This module refuses only on a real count, because
#   a gate that read `null` as "nothing was stranded" would report clean on every
#   host that never had a transcript at all. CLOUD-990 measured that false green
#   costing a session an hour.
#
#   THIS BLOCK IS YAML AND MUST STAY THE LAST COMMENT BLOCK BEFORE `package`.
# schemas:
#   - input: schema["policy-call.schema"]
package batten.denials_outlive_the_turn

import rego.v1

rules contains "denials-outlive-the-turn"

# The turn ended with refusals recorded and the agent stopping again.
#
# `stop-repeat` is the discriminator that keeps this from firing on an ordinary
# end of turn: a first stop after refusals is work concluding, and a REPEAT stop
# with refusals still in the session's record is the shape `finding-sink-check`
# exists to catch — a finding produced and then left behind.
violation contains {
	"rule": "denials-outlive-the-turn",
	"verdict": "turn deny held",
	"subjects": [{"count": input.facts.extracted.denials}],
} if {
	# GUARDED, and the guard is the whole could-not-look arm: `null` is the
	# common state here, and `null.denials` is undefined rather than zero.
	is_object(input.facts.extracted)
	input.facts.extracted.denials > 0
	input.call["stop-repeat"] == true
}

# --- the load-time tier ------------------------------------------------------
#
# These pin the PREDICATE. They cannot pin that the ENGINE reads a transcript at
# all, nor that a missing one is told apart from a clean session — a `with input
# as` case fabricates the very shape the engine may be unable to produce
# (CLOUD-845, CLOUD-857), and here it would fabricate the distinction the row
# turns on. `crates/batten/tests/extracted_facts.rs` is that tier.

stopped(extracted, repeat) := {
	"call": {"command": "", "stop-repeat": repeat},
	"facts": {"extracted": extracted},
}

test_a_repeat_stop_with_refusals_is_refused if {
	some v in violation with input as stopped({"denials": 2}, true)
	v.verdict == "turn deny held"
}

# A FIRST stop is work concluding, not a finding left behind.
test_a_first_stop_is_clean if {
	count(violation) == 0 with input as stopped({"denials": 2}, false)
}

# THE EXTRACTOR RAN AND COUNTED ZERO, which is a real answer and a real negative.
test_a_session_with_no_refusals_is_clean if {
	count(violation) == 0 with input as stopped({"denials": 0}, true)
}

# COULD-NOT-LOOK, and the case this module exists to keep apart from the one
# above: no transcript, a host that keeps none, one that would not parse, or
# nobody having declared an extractor. Reading it as "nothing was stranded" is
# the false green CLOUD-990 measured. Without the `is_object` guard this does not
# merely fail — it faults.
test_no_transcript_is_not_a_clean_session if {
	count(violation) == 0 with input as stopped(null, true)
}

# An id no row declared is ABSENT rather than zero, so a predicate over it does
# not hold — an undeclared extractor yields nothing.
test_an_undeclared_extractor_yields_nothing if {
	count(violation) == 0 with input as stopped({"turns": 9}, true)
}

# THE COMMAND CHANGES NOTHING, and asserting that is the point rather than a
# formality. `policy test` requires a mediated-call module to be exercised with a
# compound command, because CLOUD-857 measured a preset anchored on the first
# word of the whole LINE denying `git push --force` and allowing
# `cd /tmp && git push --force`. This predicate reads the session's counts and
# never the argv, so the compound case must reach the SAME verdict — and a later
# edit that started keying on the command would turn this red.
test_a_compound_command_reaches_the_same_verdict if {
	some v in violation with input as {
		"call": {"command": "cd /tmp && mise run land", "stop-repeat": true},
		"facts": {"extracted": {"denials": 2}},
	}
	v.verdict == "turn deny held"
}

#MUTANT-SUITE crates/batten/tests/it/extracted_facts.rs
#MUTANT-OWNER CLOUD-845|the tier this module names drives `input.facts.extracted` and never installs the module, so no case in it can turn red under a mutation of the predicate
#MUTANT extraction-unread|s@^\tis_object(input.facts.extracted)$@\tfalse@|a_declared_extractor_reaches_the_module
