# The unfiled deferral, as a module of its own (CLOUD-2241): a turn that ends by
# promising work to a later branch without naming the row that holds it.
#
# AGENTS.md: "each stops the fix, never the record: what you decline to fix, you
# file", and "a finding's home is an issue or a memory". Chat retains nothing
# across compaction, so a deferral that lives only in the final message is lost.
# Measured on PR #1132: "the remaining small fixes … in their own short
# branches", "the fix … goes on the next branch", "That ships on the next
# branch" — none filed until the operator objected.
#
# ITS OWN ROW, for `turn-ask.rego`'s reason: a `[[rule]]` spelled as its verdict
# must be that verdict's sole raiser.
#
# THE SCRUB IS `stop-posture.rego`'S FOUR SUBSTITUTIONS, COPIED, for the reason
# `turn-ask.rego` records: `policy test` loads each module as its own bundle. A
# quoted "next branch" is a report of a deferral, not one.
#
# THE KEY IS THE TRACKER'S OWN, read from `ready-issue-key` by id, so this module
# composes no second key expression. Any key anywhere in the message clears it:
# the gate asks whether the turn named a home, not which sentence did.
#
# A REFUSAL AT `Stop` IS ADVICE: `Stop` carries no verdict, so a `deny` here
# reaches the nudge channel and never refuses a turn.
#MUTANT-SUITE crates/batten/tests/it/stop_posture.rs
#MUTANT deferral-key-unchecked|s@^\tnot keyed$@\ttrue@|a_turn_deferring_unfiled_work_is_refused_at_stop

# METADATA
# description: |
#   Bound to the MEDIATED-CALL surface, as `stop-posture.rego` is.
#   THIS BLOCK IS YAML AND MUST STAY THE LAST COMMENT BLOCK BEFORE `package`.
# schemas:
#   - input: schema["policy-call.schema"]
package batten.turn_defer

import rego.v1

rules contains "turn ship unnamed"

# The turn's final text, or "" off a Stop (`null` is projected, not absent).
default message := ""

message := text if {
	text := input.call["final-message"]
	is_string(text)
}

elided := "ELIDED"

# Fenced blocks before code spans: a fence contains backticks.
scrubbed := s4 if {
	s1 := regex.replace(message, data.batten.patterns["md-fenced-block"], elided)
	s2 := regex.replace(s1, data.batten.patterns["md-code-span"], elided)
	s3 := regex.replace(s2, data.batten.patterns["md-quoted-span"], elided)
	s4 := regex.replace(s3, data.batten.patterns["md-block-quote"], elided)
}

# Every deferral in the scrubbed final message.
deferrals := count(regex.find_n(data.batten.patterns["deferral-promised"], scrubbed, -1))

# Whether the message names any row, scrubbed or not: a key inside a code span
# still names the home.
keyed if regex.match(data.batten.patterns["ready-issue-key"], message)

# A count and nothing else (rule 4).
violation contains {
	"rule": "turn ship unnamed",
	"verdict": "turn ship unnamed",
	"subjects": [{"count": deferrals}],
} if {
	deferrals > 0
	not keyed
}

# --- the module's own tier ----------------------------------------------------
#
# ONE PATTERN KEY BOUND PER `with`, NOT THE MAP, for `turn-ask.rego`'s measured
# reason: binding the map wholesale leaves the scrub undefined.

deferral_regex := `(?i)\b(next branch|follow-?up|follow up|later branch|separate branch|in a later|after landing|goes on the|ships on the)\b`

key_regex := `CLOUD-[0-9]+`

deferred(text) := v if {
	v := violation with input as {"call": {"final-message": text}}
		with data.batten.patterns["deferral-promised"] as deferral_regex
		with data.batten.patterns["ready-issue-key"] as key_regex
}

test_a_deferral_without_a_key_is_refused if {
	count(deferred("The remaining fix goes on the next branch.")) == 1
}

test_a_deferral_naming_its_row_passes if {
	count(deferred("The remaining fix goes on the next branch, filed as CLOUD-2241.")) == 0
}

test_a_message_with_no_deferral_passes if {
	count(deferred("Landed and pushed; CI is green and the row moved.")) == 0
}

test_a_quoted_deferral_is_a_report_of_one if {
	count(deferred("The gate names `ships on the next branch` as its example.")) == 0
}

test_not_a_stop_is_silent if {
	count(violation) == 0 with input as {"call": {"event": "pre-tool", "final-message": null}}
		with data.batten.patterns["deferral-promised"] as deferral_regex
		with data.batten.patterns["ready-issue-key"] as key_regex
}
