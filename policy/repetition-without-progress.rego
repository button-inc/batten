# The measured doom-loop shape: the same call, again (CLOUD-1347).
#
# This is the shape every practitioner detector converges on. opencode keys on an
# identical `(name, args-hash)` within the last 3 calls; hermes-agent on one
# fingerprint 3+ times in a sliding window of 20; OpenHands on identical
# action-observation cycles at 4. It is also the shape measured in this
# repository twice — CLOUD-1337's eleven identical watchers over 9h35m, written by
# a session that had read and agreed with the prose forbidding them, and
# CLOUD-1341's poll, which arrived in 249 bursts whose longest run was 8.
#
# A rule an agent agrees with and then violates eleven times is the definition of
# a gate-shaped problem.
#
# TRAILING-RUN ADJACENCY IS THE DESIGN, NOT AN IMPLEMENTATION DETAIL, and it is
# what does the false-positive work. Any intervening DISTINCT call clears the run,
# so `mise run test` three times WITH EDITS BETWEEN is already false here without
# a carve-out, while the same call three times with nothing in between is not a
# thing a productive session does. The trap is measured rather than imagined:
# OpenHands' detector kills agents legitimately waiting on long-running processes
# and leaves them unrecoverable once flagged, and CLOUD-199 already set this
# repository's bar — a guard with false positives gets bypassed.
#
# THE THRESHOLD IS THE PRIOR ART'S, AND IT IS NOT YET THIS CONSUMER'S. Three is
# what opencode and hermes-agent use; CLOUD-1352 makes a measured firing rate over
# this repository's own history a hard precondition for promoting this row, and
# until that replay exists the number is adopted rather than derived. Said plainly
# here so a later reader does not mistake it for a measurement.
#
# NOT A `[[pattern]]` ROW, and not a preset. `.claude/rules/policy-modules.md`
# refuses a threshold spelled as a pattern outright, and a window or a count is a
# claim about one harness's call cadence rather than a concept with one spelling —
# so a preset carrying it would assert one cadence everywhere.
#
# WHAT THE FACT IS, AND WHY RULE 4 IS UNTOUCHED. Repetition needs identity to
# COMPUTE, not to express. `repeat-depth` is an integer: the fingerprint is
# computed inside `transcript.rs`, where `Event::ToolCall` already holds the whole
# argument object and already never renders it, and only the run length is
# projected. `Event::HookOutput`'s digest is the precedent in the same file —
# hashed and dropped in the same expression, so no caller can recover the bytes. A
# "last call fingerprint" token is explicitly refused: it would put a correlatable
# identity of session content on the policy input, and no predicate here wants one.
#
# IT SHIPS AT `warn`, AND THE ROW ABOVE IT IN THIS FILE IS WHY. A `mediated_call`
# row at `deny` refuses EVERY subsequent tool call once it fires, and no admission
# can clear it: `batten override request` and `spend` are themselves mediated
# calls, so requesting one requires making the call the deny refuses. A predicate
# in this family was landed at `deny` once and locked its own authoring session
# out, push included, with no in-session recovery. CLOUD-1352 owns the promotion
# and states its precondition.
#MUTANT-SUITE crates/batten/tests/it/repetition.rs
#MUTANT run-may-go-unpriced|s@^	input.facts.extracted["repeat-depth"] >= threshold$@	false@|a_trailing_run_of_identical_calls_is_reported
#MUTANT background-may-go-unread|s@^	input.call["run-in-background"] != true$@	true@|a_backgrounded_call_is_not_this_rules_business

# METADATA
# description: |
#   Bound to the MEDIATED CALL: this row is `scope = "mediated_call"`, so it
#   reads `input.call` and `input.facts` and never the tree document.
#   THIS BLOCK IS YAML AND MUST STAY THE LAST COMMENT BLOCK BEFORE `package`.
# schemas:
#   - input: schema["policy-call.schema"]
package batten.repetition_without_progress

import rego.v1

rules contains "identical-call-run"

# The prior art's number. See the header for why it is adopted rather than
# derived, and CLOUD-1352 for what would make it this consumer's.
threshold := 3

# A REAL COUNT, over a declared threshold. `is_object` is the null guard: an
# absent extractor object makes every field undefined, and Rego reads undefined as
# does-not-hold, so the arm goes quiet rather than reporting a session nobody
# could look at.
#
# `run-in-background` IS THREE-VALUED AND COMPARED WITH `!=`, following
# `run-shape.rego`. Most hosts send no such key, so reading absent as `false`
# would be a claim about all of them; an unknown-posture wait is the case to be
# strict about, and `!= true` is what keeps it in scope while excluding a call the
# host positively declared backgrounded.
violation contains {
	"rule": "identical-call-run",
	"verdict": "turn ask twice",
	"subjects": [{"count": input.facts.extracted["repeat-depth"]}],
} if {
	is_object(input.facts.extracted)
	input.facts.extracted["repeat-depth"] >= threshold
	input.call["run-in-background"] != true
}

# The predicate's own tests. The SILENT cases carry the weight here for the usual
# reason: this is a refusal, so a module that fired on everything would satisfy
# the deny case while deciding nothing.

session(extracted) := {"call": {"command": "", "run-in-background": null}, "facts": {"extracted": extracted}}

test_a_trailing_run_of_identical_calls_is_reported if {
	some v in violation with input as session({"repeat-depth": 3, "distinct-calls": 4})
	v.verdict == "turn ask twice"
}

# THE COUNT IS THE POINTER, never a tool name and never a span of the session —
# rule 4 decided in the finding's shape rather than by a filter downstream.
test_the_finding_carries_a_count_and_nothing_else if {
	some v in violation with input as session({"repeat-depth": 8, "distinct-calls": 4})
	v.subjects == [{"count": 8}]
}

# ONE BELOW THE THRESHOLD IS CLEAN. Stated as a case because an off-by-one here
# moves the whole population the rule fires on.
test_two_in_a_row_is_not_a_run if {
	count(violation) == 0 with input as session({"repeat-depth": 2, "distinct-calls": 9})
}

# THE ARM THAT MAKES ADJACENCY WORTH HAVING. A session that ran the same command
# many times WITH work between them has a trailing run of 1, however busy it was,
# so the edit-then-retest loop is false by construction rather than by carve-out.
test_a_productive_session_that_reruns_with_work_between_is_clean if {
	count(violation) == 0 with input as session({"repeat-depth": 1, "distinct-calls": 40})
}

# A BACKGROUNDED CALL IS NOT THIS RULE'S BUSINESS: a host that positively declares
# the call backgrounded has named the one posture this shape is allowed to take.
test_a_backgrounded_call_is_not_this_rules_business if {
	count(violation) == 0 with input as {
		"call": {"command": "mise run land", "run-in-background": true},
		"facts": {"extracted": {"repeat-depth": 9, "distinct-calls": 4}},
	}
}

# AND AN UNSTATED POSTURE IS STILL JUDGED, which is the other half of the
# three-valued read. `null` is what the engine emits where the host said nothing —
# `Field::RunInBackground`'s own answer, and most hosts say nothing — so reading
# it as backgrounded would switch the rule off almost everywhere. The key is
# supplied here rather than omitted for the reason the second tier exists: an
# absent key is a shape the engine does not produce, and a case built on one
# passes over a projection nobody fills.
test_an_unstated_posture_is_still_judged if {
	some v in violation with input as {
		"call": {"command": "mise run land", "run-in-background": null},
		"facts": {"extracted": {"repeat-depth": 9, "distinct-calls": 4}},
	}
	v.verdict == "turn ask twice"
}

# COULD NOT LOOK IS NOT INNOCENCE, and it is not guilt either.
test_no_transcript_is_not_a_clean_session if {
	count(violation) == 0 with input as session(null)
}

test_an_undeclared_extractor_yields_nothing if {
	count(violation) == 0 with input as session({"turns": 9})
}

# A COMPOUND COMMAND REACHES THE SAME VERDICT, and the case exists even though
# this predicate never reads the command line. CLOUD-857 measured a module that
# anchored on `input.call.command` denying `git push --force origin main` while
# allowing `cd /tmp && git push --force origin main`, with a green suite over it
# — so `policy test` refuses a mediated-call suite whose every case passes a bare
# command. Here the case is a STANDING guarantee rather than a repair: the verdict
# is a function of the fact and the posture alone, and this is what would go red
# if some later revision started reading the command and anchored it wrongly.
test_a_compound_command_reaches_the_same_verdict if {
	some v in violation with input as {
		"call": {"command": "cd /tmp && mise run land", "run-in-background": null},
		"facts": {"extracted": {"repeat-depth": 4, "distinct-calls": 4}},
	}
	v.verdict == "turn ask twice"
}
