# The punt, as a module of its own (CLOUD-1954): a turn that ends by handing back
# a decision the agent's evidence already settles.
#
# AGENTS.md names the act: "a block reported as a decision; 'that's your call' on
# what your evidence settles; an action you are already authorized to take,
# offered". `deferral-check` reads PR bodies for the written form; nothing read the
# spoken one, and a chat line stores nothing, so the offer stops the human and
# leaves the work undone at once.
#
# ITS OWN ROW, NOT A SECOND VERDICT ON THE HEDGE'S. A `[[rule]]` spelled as its
# verdict must be that verdict's sole raiser, and renaming `prose report
# duplicate` to make room reads to `config-lint` as `rule-removed`. So this row is
# `turn ask early`, raised here and nowhere else.
#
# THE SCRUB IS `stop-posture.rego`'S FOUR SUBSTITUTIONS, COPIED, and the copy is
# measured rather than preferred: `import data.batten.stop_posture` was the first
# cut, and `policy test` loads each module as its own bundle, so the imported
# `scrubbed` was undefined and every firing case went silent. A quoted "your
# call" is a report OF a punt, not one, for the reason that module records.
#
# THE LITERALS ARE MEASURED, and their evidence and its thinness live on the
# `deferral-offered` `[[pattern]]` row beside the regex.
#
# A REFUSAL AT `Stop` IS ADVICE, as for the hedge: `Stop` carries no verdict, so a
# `deny` here reaches the nudge channel and never refuses a turn.
#MUTANT-SUITE crates/batten/tests/it/stop_posture.rs
#MUTANT deferral-unread|s@^\toffers > 0$@\tfalse@|a_decision_offered_back_reaches_the_host_advisory_channel

# METADATA
# description: |
#   Bound to the MEDIATED-CALL surface, as `stop-posture.rego` is.
#   THIS BLOCK IS YAML AND MUST STAY THE LAST COMMENT BLOCK BEFORE `package`.
# schemas:
#   - input: schema["policy-call.schema"]
package batten.turn_ask

import rego.v1

rules contains "turn ask early"

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

# Every offer in the scrubbed final message. MATCHES, NOT LINES, as for the hedge.
offers := count(regex.find_n(data.batten.patterns["deferral-offered"], scrubbed, -1))

# A count and nothing else (rule 4): quoting the offer back would be a mirror.
violation contains {
	"rule": "turn ask early",
	"verdict": "turn ask early",
	"subjects": [{"count": offers}],
} if {
	offers > 0
}

# --- the module's own tier ----------------------------------------------------
#
# Each firing case is a witnessed sentence from the #928 landing session. ONE
# PATTERN KEY IS BOUND, NOT THE MAP: the scrub reads the `md-*` patterns from the
# same map, and binding it wholesale leaves the scrub undefined and every case
# silent — measured, the first cut of these tests passed their silent half for
# exactly that reason.

punt_regex := "Your call, |(?i:waiting on your call|both your call|a checkpoint with you|once you run|restart the session)"

offered(text) := v if {
	v := violation with input as {"call": {"final-message": text}}
		with data.batten.patterns["deferral-offered"] as punt_regex
}

test_an_offer_back_is_named if {
	count(offered("**Your call, three ways:** grant it, move it, or wait.")) == 1
}

test_waiting_on_the_human_is_named if {
	count(offered("Stopping. Waiting on your call about the downgrade.")) == 1
}

# CLOUD-2117: the container's own step handed to the human, both witnessed on
# PR #1102. Nobody but the agent can run a command in its container.
test_a_command_handed_to_the_human_is_named if {
	count(offered("Once you run `BATTEN_VERSION=v0.0.202 ./install.sh` in `/home/user/batten`, I'll push.")) == 1
}

test_a_session_restart_handed_to_the_human_is_named if {
	count(offered("To unblock, either:\n- run `./install.sh`, or\n- restart the session, since start rebuilds it.")) == 1
}

test_the_agent_running_it_is_not_a_punt if {
	# THE NARROWNESS BOUNDARY: the agent reporting its own run is the work, not an offer.
	count(offered("I ran `batten engine update`, then pushed. Once it ran, the hook loaded.")) == 0
}

test_a_decision_already_made_is_not_a_punt if {
	# The measured false positives of bare `your call`: each reports a choice the
	# human already made.
	count(offered("Hence your call to retire it too. Per your call, it stays.")) == 0
}

test_a_clarifying_question_is_not_a_punt if {
	count(offered("Which of the two targets did you mean?")) == 0
}

test_a_quoted_offer_is_a_report_of_one if {
	count(offered("The gate names `Your call, three ways` as its example.")) == 0
}

test_a_clean_compound_turn_is_silent if {
	count(offered("Landed and pushed; CI is green && the row moved.")) == 0
}

test_not_a_stop_is_silent if {
	count(violation) == 0 with input as {"call": {"event": "pre-tool", "final-message": null}}
		with data.batten.patterns["deferral-offered"] as punt_regex
}
